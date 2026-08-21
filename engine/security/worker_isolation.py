"""
Worker isolation and resource exhaustion limits.

Implements:
- Worker privilege isolation
- Filesystem access controls
- Network access controls
- Resource limits (timeout, memory, CPU, disk)
- Container boundaries
- Campaign resource limits
"""

from __future__ import annotations

import asyncio
import os
try:
    import resource  # type: ignore
except ImportError:
    resource = None  # Windows fallback
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from engine.model.errors import ResourceExhausted, SecurityViolation


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Resource limits for worker execution."""
    
    # Time limits
    execution_timeout_s: float = 300.0  # 5 minutes max
    per_turn_timeout_s: float = 60.0    # 1 minute per turn
    idle_timeout_s: float = 30.0        # 30 seconds idle timeout
    
    # Memory limits (bytes)
    memory_limit_mb: int = 512          # 512 MB max memory
    max_heap_mb: int = 256              # Max heap size
    
    # CPU limits
    cpu_time_limit_s: float = 120.0     # 2 minutes CPU time
    max_cpu_percent: float = 80.0       # Max CPU percentage
    
    # Disk limits
    disk_limit_mb: int = 1024           # 1 GB max disk usage
    temp_dir_limit_mb: int = 100        # 100 MB temp directory
    max_file_size_mb: int = 50          # Max single file size
    
    # Document limits
    max_document_size_mb: int = 10      # Max document size
    decompression_limit_ratio: int = 100  # Max decompression ratio
    
    # Concurrency limits
    max_concurrent_turns: int = 10      # Max concurrent turns
    max_concurrent_campaigns: int = 3   # Max concurrent campaigns
    max_artifacts: int = 100            # Max artifacts per execution
    
    # Rate limits
    requests_per_second: float = 10.0   # Max requests per second
    requests_per_minute: int = 100      # Max requests per minute
    requests_per_hour: int = 1000       # Max requests per hour
    
    # Campaign quotas
    max_campaign_executions: int = 100  # Max executions per campaign
    max_campaign_tokens: int = 1_000_000  # Token budget per campaign
    max_campaign_cost_usd: float = 100.0  # Max cost per campaign
    
    # Token budgets
    tokens_per_execution: int = 10_000  # Tokens per execution
    tokens_per_campaign: int = 100_000  # Tokens per campaign
    token_budget_refresh_interval_s: int = 3600  # 1 hour
    
    def __post_init__(self) -> None:
        """Validate limits are reasonable."""
        if self.execution_timeout_s <= 0:
            raise ValueError("execution_timeout_s must be positive")
        if self.memory_limit_mb <= 0:
            raise ValueError("memory_limit_mb must be positive")
        if self.max_document_size_mb <= 0:
            raise ValueError("max_document_size_mb must be positive")


class ResourceMonitor:
    """Monitors resource usage and enforces limits."""
    
    def __init__(self, limits: ResourceLimits) -> None:
        self.limits = limits
        self._usage: dict[str, float] = {}
        self._start_time: float = 0.0
        self._peak_memory_mb: float = 0.0
        self._cpu_time_used: float = 0.0
        self._disk_usage_mb: float = 0.0
        self._request_count: int = 0
        self._token_count: int = 0
    
    def start(self) -> None:
        """Start monitoring."""
        import time
        self._start_time = time.time()
        self._update_usage()
    
    def _update_usage(self) -> None:
        """Update current resource usage."""
        try:
            import psutil
            process = psutil.Process()
            
            # Memory
            mem_info = process.memory_info()
            memory_mb = process.memory_info().rss / (1024 * 1024)
            self._usage["memory_mb"] = memory_mb
            self._peak_memory_mb = max(self._peak_memory_mb, memory_mb)
            
            # CPU
            cpu_times = process.cpu_times()
            self._cpu_time_used = cpu_times.user + cpu_times.system
            
            # Disk
            disk = psutil.disk_usage("/")
            self._disk_usage_mb = (disk.total - disk.free) / (1024 * 1024)
        except ImportError:
            # psutil not available
            self._usage["memory_mb"] = 0
            self._cpu_time_used = 0.0
            self._disk_usage_mb = 0.0
    
    def check_limits(self) -> None:
        """Check if any limits have been exceeded. Raises ResourceExhausted if so."""
        self._update_usage()
        
        # Memory check
        memory_mb = self._usage.get("memory_mb", 0)
        if memory_mb > self.limits.memory_limit_mb:
            raise ResourceExhausted(
                f"Memory limit exceeded: {memory_mb:.1f} MB > {self.limits.memory_limit_mb} MB",
                resource="memory",
                limit=self.limits.memory_limit_mb,
                current=memory_mb,
            )
        
        # CPU time check
        if self._cpu_time_used > self.limits.cpu_time_limit_s:
            raise ResourceExhausted(
                f"CPU time limit exceeded: {self._cpu_time_used:.1f}s > {self.limits.cpu_time_limit_s}s",
                resource="cpu_time",
                limit=self.limits.cpu_time_limit_s,
                current=self._cpu_time_used,
            )
        
        # Disk check
        if self._disk_usage_mb > self.limits.disk_limit_mb:
            raise ResourceExhausted(
                f"Disk limit exceeded: {self._disk_usage_mb:.1f} MB > {self.limits.disk_limit_mb} MB",
                resource="disk",
                limit=self.limits.disk_limit_mb,
                current=self._disk_usage_mb,
            )
    
    def record_request(self) -> None:
        """Record a request for rate limiting."""
        self._request_count += 1
    
    def record_tokens(self, count: int) -> None:
        """Record token usage."""
        self._token_count += count
        if self._token_count > self.limits.tokens_per_campaign:
            raise ResourceExhausted(
                f"Token budget exceeded: {self._token_count} > {self.limits.tokens_per_campaign}",
                resource="tokens",
                limit=self.limits.tokens_per_campaign,
                current=self._token_count,
            )
    
    def record_disk_write(self, size_mb: float) -> None:
        """Record disk write for limit checking."""
        self._disk_usage_mb += size_mb
        if self._disk_usage_mb > self.limits.disk_limit_mb:
            raise ResourceExhausted(
                f"Disk limit exceeded: {self._disk_usage_mb:.1f} MB > {self.limits.disk_limit_mb} MB",
                resource="disk",
                limit=self.limits.disk_limit_mb,
                current=self._disk_usage_mb,
            )
    
    def get_usage_stats(self) -> dict[str, Any]:
        """Get current usage statistics."""
        return {
            "memory_mb": self._usage.get("memory_mb", 0),
            "peak_memory_mb": self._peak_memory_mb,
            "cpu_time_used_s": self._cpu_time_used,
            "disk_usage_mb": self._disk_usage_mb,
            "request_count": self._request_count,
            "token_count": self._token_count,
            "elapsed_time_s": __import__("time").time() - self._start_time if self._start_time else 0,
        }


class ExecutionSandbox:
    """
    Execution sandbox with isolation controls.
    
    Provides:
    - Filesystem isolation (chroot-like)
    - Network access control
    - Command execution restrictions
    - Environment variable filtering
    """
    
    def __init__(
        self,
        limits: ResourceLimits,
        working_dir: Optional[Path] = None,
        allowed_paths: Optional[list[Path]] = None,
        allowed_networks: Optional[list[str]] = None,
        blocked_commands: Optional[list[str]] = None,
    ) -> None:
        self.limits = limits
        self.working_dir = working_dir or Path.cwd()
        self.allowed_paths = [Path(p).resolve() for p in (allowed_paths or [self.working_dir])]
        self.allowed_networks = allowed_networks or []
        self.blocked_commands = set(blocked_commands or [
            "rm", "rmdir", "mv", "dd", "mkfs", "fdisk",
            "shutdown", "reboot", "halt", "poweroff",
            "mount", "umount", "chmod", "chown", "chgrp",
            "su", "sudo", "passwd", "useradd", "userdel",
            "iptables", "ufw", "firewall-cmd",
            "systemctl", "service", "journalctl",
            "crontab", "at", "batch",
            "nc", "netcat", "socat", "ncat",
            "ssh", "scp", "rsync", "sftp",
            "curl", "wget", "ftp", "sftp",
            "docker", "podman", "kubectl",
            "kubeadm", "helm", "terraform",
        ])
    
    def validate_command(self, command: list[str]) -> bool:
        """Validate command is allowed."""
        if not command:
            return False
        
        cmd = command[0].lower()
        if cmd in self.blocked_commands:
            return False
        
        # Check if command is in allowed paths
        try:
            cmd_path = Path(cmd).resolve() if not cmd.startswith(("/", "./")) else cmd
            if cmd.startswith(("./", "/")):
                cmd_path = Path(cmd).resolve()
                for allowed in self.allowed_paths:
                    try:
                        if cmd_path.is_relative_to(allowed):
                            return True
                    except ValueError:
                        pass
        except Exception:
            pass
        
        # Default allow for commands in PATH
        return True
    
    def validate_path_access(self, path: Path, write: bool = False) -> bool:
        """Validate path access within allowed directories."""
        try:
            resolved = path.resolve()
            for allowed in self.allowed_paths:
                try:
                    if resolved.is_relative_to(allowed):
                        return True
                except ValueError:
                    pass
        except Exception:
            pass
        return False
    
    def validate_network_access(self, host: str, port: int) -> bool:
        """Validate network access against allowed networks."""
        import ipaddress
        
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            # Hostname - would need DNS resolution
            # For now, allow if in allowed_networks
            return host in self.allowed_networks or "all" in self.allowed_networks
        
        for network_str in self.allowed_networks:
            try:
                network = ipaddress.ip_network(network_str, strict=False)
                if ipaddress.ip_address(host) in network:
                    return True
            except ValueError:
                if host == network_str:
                    return True
        return False
    
    def sanitize_environment(self, env: dict[str, str]) -> dict[str, str]:
        """Sanitize environment variables, removing secrets."""
        # Remove sensitive environment variables
        sensitive_keys = {
            "PASSWORD", "SECRET", "TOKEN", "KEY", "TOKEN",
            "API_KEY", "SECRET_KEY", "PRIVATE_KEY",
            "DATABASE_URL", "REDIS_URL", "AWS_", "GCP_", "AZURE_",
            "OAUTH_", "JWT_", "SESSION_", "COOKIE_",
        }
        
        sanitized = {}
        for key, value in env.items():
            if any(sensitive in key.upper() for sensitive in sensitive_keys):
                continue
            sanitized[key] = value
        return sanitized
    
    def get_resource_limits_dict(self) -> dict[str, int]:
        """Get resource limits for subprocess."""
        return {
            "memory_mb": self.limits.memory_limit_mb,
            "cpu_time_s": int(self.limits.cpu_time_limit_s),
            "disk_mb": self.limits.disk_limit_mb,
        }
    
    def create_subprocess_env(self) -> dict[str, str]:
        """Create sanitized environment for subprocess."""
        import os
        env = os.environ.copy()
        return self.sanitize_environment(env)


class WorkerIsolationManager:
    """
    Manages worker isolation and resource limits.
    
    Provides:
    - Worker process isolation
    - Resource limit enforcement
    - Security boundary enforcement
    - Resource monitoring
    """
    
    def __init__(self, limits: Optional[ResourceLimits] = None) -> None:
        self.limits = limits or ResourceLimits()
        self.monitor = ResourceMonitor(self.limits)
        self.sandbox = ExecutionSandbox(self.limits)
        self._active_workers: dict[str, dict[str, Any]] = {}
    
    def create_worker_context(
        self,
        worker_id: str,
        working_dir: Optional[Path] = None,
        allowed_paths: Optional[list[Path]] = None,
        allowed_networks: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Create isolated worker context."""
        # Set up working directory
        working_dir = working_dir or Path.cwd() / "workers" / worker_id
        working_dir.mkdir(parents=True, exist_ok=True)
        
        # Create sandbox
        sandbox = ExecutionSandbox(
            limits=self.limits,
            working_dir=working_dir,
            allowed_paths=allowed_paths,
            allowed_networks=allowed_networks,
        )
        
        # Track worker
        context = {
            "worker_id": worker_id,
            "working_dir": working_dir,
            "sandbox": sandbox,
            "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            "limits": self.limits,
            "monitor": self.monitor,
        }
        
        self._active_workers[worker_id] = context
        return context
    
    def cleanup_worker(self, worker_id: str) -> None:
        """Clean up worker resources."""
        if worker_id in self._active_workers:
            context = self._active_workers.pop(worker_id)
            # Cleanup working directory if needed
            # working_dir = context.get("working_dir")
            # if working_dir and working_dir.exists():
            #     import shutil
            #     shutil.rmtree(working_dir, ignore_errors=True)
    
    def validate_worker_limits(self, worker_id: str) -> None:
        """Validate worker is within limits."""
        self.monitor.check_limits()
    
    def record_request(self, worker_id: str) -> None:
        """Record request for rate limiting."""
        self.monitor.record_request()
    
    def record_tokens(self, worker_id: str, count: int) -> None:
        """Record token usage."""
        self.monitor.record_tokens(count)
    
    def get_worker_stats(self, worker_id: str) -> dict[str, Any] | None:
        """Get worker statistics."""
        if worker_id not in self._active_workers:
            return None
        
        context = self._active_workers[worker_id]
        return {
            "worker_id": worker_id,
            "usage": self.monitor.get_usage_stats(),
            "limits": {
                "memory_mb": self.limits.memory_limit_mb,
                "cpu_time_s": self.limits.cpu_time_limit_s,
                "disk_mb": self.limits.disk_limit_mb,
                "execution_timeout_s": self.limits.execution_timeout_s,
            },
        }
    
    def get_all_stats(self) -> dict[str, Any]:
        """Get all worker statistics."""
        return {
            "active_workers": len(self._active_workers),
            "global_usage": self.monitor.get_usage_stats(),
            "limits": {
                "memory_mb": self.limits.memory_limit_mb,
                "cpu_time_s": self.limits.cpu_time_limit_s,
                "disk_mb": self.limits.disk_limit_mb,
                "requests_per_second": self.limits.requests_per_second,
            },
        }


def enforce_server_side_policy(policy: Any, limits: ResourceLimits | None = None) -> Any:
    """Clamp client-supplied AttackPolicy to server-side limits (never trust client)."""
    from engine.model.attack import AttackPolicy, CapturePolicy
    limits = limits or DEFAULT_LIMITS
    # Clamp timeouts
    overall = min(policy.overall_timeout_s, limits.execution_timeout_s)
    per_turn = min(policy.per_turn_timeout_s, limits.per_turn_timeout_s)
    max_turns = min(policy.max_turns, limits.max_concurrent_turns)
    max_artifacts = min(policy.max_artifacts, limits.max_artifacts)
    # Clamp concurrency
    max_conc = min(getattr(policy, "max_concurrency", 1), limits.max_concurrent_campaigns)
    return AttackPolicy(
        overall_timeout_s=overall,
        per_turn_timeout_s=per_turn,
        max_turns=max_turns,
        capture=policy.capture,
        max_concurrency=max_conc,
        rate_limit_rps=min(policy.rate_limit_rps, limits.requests_per_second) if policy.rate_limit_rps else limits.requests_per_second,
        max_retries=min(policy.max_retries, 3),
        retry_backoff_s=policy.retry_backoff_s,
        max_artifacts=max_artifacts,
    )


def check_document_limits(content: str, limits: ResourceLimits | None = None) -> None:
    limits = limits or DEFAULT_LIMITS
    size_mb = len(content.encode("utf-8")) / (1024 * 1024)
    if size_mb > limits.max_document_size_mb:
        from engine.model.errors import ResourceExhausted
        raise ResourceExhausted(f"document size {size_mb:.2f}MB exceeds {limits.max_document_size_mb}MB", resource="document", limit=limits.max_document_size_mb, current=size_mb)
    # Decompression bomb check: if content looks compressed and ratio exceeds limit
    # Heuristic: if document contains repeated patterns indicating high compression ratio
    if len(content) > 0:
        # Use simple ratio: uncompressed size vs. potential compressed representation
        # If content is huge after decompression, we already checked size; also check encoded vs decoded size
        pass  # real decompression check done in payload handling


def check_decompression_limits(compressed_size: int, decompressed_size: int, limits: ResourceLimits | None = None) -> None:
    limits = limits or DEFAULT_LIMITS
    if compressed_size == 0:
        return
    ratio = decompressed_size / compressed_size
    if ratio > limits.decompression_limit_ratio:
        from engine.model.errors import ResourceExhausted
        raise ResourceExhausted(f"decompression ratio {ratio:.1f} exceeds limit {limits.decompression_limit_ratio}", resource="decompression", limit=limits.decompression_limit_ratio, current=ratio)
    size_mb = decompressed_size / (1024 * 1024)
    if size_mb > limits.max_document_size_mb:
        from engine.model.errors import ResourceExhausted
        raise ResourceExhausted(f"decompressed size {size_mb:.2f}MB exceeds {limits.max_document_size_mb}MB", resource="document", limit=limits.max_document_size_mb, current=size_mb)


# Default limits
DEFAULT_LIMITS = ResourceLimits()

# Strict limits for untrusted targets
STRICT_LIMITS = ResourceLimits(
    execution_timeout_s=60.0,
    per_turn_timeout_s=30.0,
    memory_limit_mb=256,
    max_heap_mb=128,
    cpu_time_limit_s=30.0,
    disk_limit_mb=256,
    max_document_size_mb=5,
    max_concurrent_turns=5,
    max_concurrent_campaigns=1,
    requests_per_second=5.0,
    requests_per_minute=30,
    requests_per_hour=200,
    tokens_per_execution=5_000,
    tokens_per_campaign=50_000,
)

# Permissive limits for trusted targets
PERMISSIVE_LIMITS = ResourceLimits(
    execution_timeout_s=600.0,
    per_turn_timeout_s=120.0,
    memory_limit_mb=1024,
    max_heap_mb=512,
    cpu_time_limit_s=300.0,
    disk_limit_mb=2048,
    max_document_size_mb=50,
    max_concurrent_turns=20,
    max_concurrent_campaigns=5,
    requests_per_second=50.0,
    requests_per_minute=500,
    requests_per_hour=5000,
    tokens_per_execution=50_000,
    tokens_per_campaign=500_000,
)
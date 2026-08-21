"""
Rate limiting and quota enforcement at backend/worker layer.

Implements:
- Request rate limiting (per second, minute, hour)
- Token budget enforcement
- Campaign quotas
- Concurrent execution limits
- Quota bypass prevention
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

from engine.model.errors import QuotaExceeded, RateLimitExceeded


@dataclass(frozen=True, slots=True)
class RateLimitConfig:
    """Rate limit configuration."""
    requests_per_second: float = 10.0
    requests_per_minute: int = 100
    requests_per_hour: int = 1000
    burst_allowance: int = 5  # Allow burst above rate


@dataclass(frozen=True, slots=True)
class QuotaConfig:
    """Quota configuration."""
    max_campaign_executions: int = 100
    max_campaign_tokens: int = 1_000_000
    max_campaign_cost_usd: float = 100.0
    max_campaign_duration_hours: int = 24
    
    # Per-target quotas
    max_executions_per_target: int = 1000
    max_tokens_per_target: int = 100_000
    
    # Per-tenant quotas
    max_executions_per_tenant: int = 10_000
    max_tokens_per_tenant: int = 10_000_000
    max_concurrent_campaigns: int = 3


class TokenBucket:
    """Token bucket rate limiter."""
    
    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = rate  # tokens per second
        self.capacity = capacity
        self._tokens = float(capacity)
        self._last_update = time.monotonic()
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if successful."""
        now = time.monotonic()
        elapsed = now - self._last_update
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_update = now
        
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False
    
    def get_available(self) -> float:
        """Get currently available tokens."""
        now = time.monotonic()
        elapsed = now - self._last_update
        tokens = min(self.capacity, self._tokens + (now - self._last_update) * self.rate)
        return tokens


class SlidingWindowRateLimiter:
    """Sliding window rate limiter with multiple time windows."""
    
    def __init__(self, config: RateLimitConfig) -> None:
        self.config = config
        self._requests: list[float] = []  # timestamps of requests
        self._second_bucket: list[float] = []  # last second
        self._minute_bucket: list[float] = []  # last minute
        self._hour_bucket: list[float] = []  # last hour
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire permission for request. Returns True if allowed."""
        async with self._lock:
            now = time.monotonic()
            
            # Clean old entries
            self._prune_old_entries(now)
            
            # Check limits
            if len(self._second_bucket) >= self.config.requests_per_second:
                return False
            if len(self._minute_bucket) >= self.config.requests_per_minute:
                return False
            if len(self._hour_bucket) >= self.config.requests_per_hour:
                return False
            
            # All checks passed - record request
            now_ts = time.time()
            self._requests.append(now_ts)
            self._second_bucket.append(now_ts)
            self._minute_bucket.append(now_ts)
            self._hour_bucket.append(now_ts)
            return True
    
    def _prune_old_entries(self, now: float) -> None:
        """Remove entries older than window."""
        cutoff_second = now - 1.0
        cutoff_minute = now - 60.0
        cutoff_hour = now - 3600.0
        
        self._second_bucket = [t for t in self._second_bucket if t > cutoff_second]
        self._minute_bucket = [t for t in self._minute_bucket if t > cutoff_minute]
        self._hour_bucket = [t for t in self._hour_bucket if t > cutoff_hour]
        self._requests = [t for t in self._requests if t > cutoff_hour]
    
    def get_current_rates(self) -> dict[str, float]:
        """Get current request rates."""
        now = time.time()
        self._prune_old_entries(time.time())
        return {
            "per_second": len(self._second_bucket),
            "per_minute": len(self._minute_bucket),
            "per_hour": len(self._hour_bucket),
        }
    
    async def wait_for_slot(self, timeout: float = 30.0) -> bool:
        """Wait until a slot is available. Returns True if acquired, False on timeout."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if await self.acquire():
                return True
            await asyncio.sleep(0.1)
        return False


class QuotaManager:
    """Manages quotas for campaigns, targets, and tenants."""
    
    def __init__(self, config: QuotaConfig) -> None:
        self.config = config
        self._campaign_usage: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "executions": 0,
            "tokens": 0,
            "cost_usd": 0.0,
            "started_at": time.time(),
            "targets": set(),
        })
        self._tenant_usage: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "executions": 0,
            "tokens": 0,
            "campaigns": set(),
        })
        self._target_usage: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "executions": 0,
            "tokens": 0,
        })
        self._lock = asyncio.Lock()
    
    async def check_campaign_quota(self, campaign_id: str, tokens_needed: int = 0) -> bool:
        """Check if campaign has quota for execution."""
        async with self._lock:
            usage = self._campaign_usage[campaign_id]
            
            # Check execution count
            if usage["executions"] >= self.config.max_campaign_executions:
                return False
            
            # Check token budget
            if usage["tokens"] + tokens_needed > self.config.max_campaign_tokens:
                return False
            
            # Check duration
            if time.time() - usage["started_at"] > self.config.max_campaign_duration_hours * 3600:
                return False
            
            return True
    
    async def consume_campaign_quota(
        self,
        campaign_id: str,
        tokens: int = 0,
        cost_usd: float = 0.0,
        target_id: Optional[str] = None,
    ) -> bool:
        """Consume quota for campaign execution."""
        async with self._lock:
            usage = self._campaign_usage[campaign_id]
            
            # Check limits
            if usage["executions"] >= self.config.max_campaign_executions:
                return False
            if usage["tokens"] + tokens > self.config.max_campaign_tokens:
                return False
            if usage["cost_usd"] + cost_usd > self.config.max_campaign_cost_usd:
                return False
            
            # Consume
            usage["executions"] += 1
            usage["tokens"] += tokens
            usage["cost_usd"] += cost_usd
            if target_id:
                usage["targets"].add(target_id)
            
            return True
    
    async def check_target_quota(self, target_id: str) -> bool:
        """Check if target has quota available."""
        usage = self._target_usage[target_id]
        return (
            usage["executions"] < self.config.max_executions_per_target and
            usage["tokens"] < self.config.max_tokens_per_target
        )
    
    async def consume_target_quota(self, target_id: str, tokens: int = 0) -> bool:
        async with self._lock:
            usage = self._target_usage[target_id]
            
            if usage["executions"] >= self.config.max_executions_per_target:
                return False
            if usage["tokens"] + tokens > self.config.max_tokens_per_target:
                return False
            
            usage["executions"] += 1
            usage["tokens"] += tokens
            return True
    
    async def check_tenant_quota(self, tenant_id: str) -> bool:
        """Check if tenant has quota available."""
        usage = self._tenant_usage[tenant_id]
        return (
            usage["executions"] < self.config.max_executions_per_tenant and
            usage["tokens"] < self.config.max_tokens_per_tenant and
            len(usage["campaigns"]) < self.config.max_concurrent_campaigns
        )
    
    async def consume_tenant_quota(self, tenant_id: str, tokens: int = 0, campaign_id: Optional[str] = None) -> bool:
        async with self._lock:
            usage = self._tenant_usage[tenant_id]
            
            if usage["executions"] >= self.config.max_executions_per_tenant:
                return False
            if usage["tokens"] + 1 > self.config.max_tokens_per_tenant:
                return False
            
            usage["executions"] += 1
            usage["tokens"] += tokens
            if campaign_id:
                usage["campaigns"].add(campaign_id)
            return True
    
    def get_campaign_usage(self, campaign_id: str) -> dict[str, Any]:
        return self._campaign_usage.get(campaign_id, {})
    
    def get_tenant_usage(self, tenant_id: str) -> dict[str, Any]:
        return self._tenant_usage.get(tenant_id, {})
    
    def get_target_usage(self, target_id: str) -> dict[str, Any]:
        return self._target_usage.get(target_id, {})


class QuotaBypassDetector:
    """Detects attempts to bypass quota limits."""
    
    def __init__(self) -> None:
        self._request_patterns: dict[str, list[float]] = defaultdict(list)
        self._suspicious_activities: list[dict[str, Any]] = []
    
    def record_request(
        self,
        identifier: str,
        endpoint: str,
        success: bool,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record request for pattern analysis."""
        now = time.time()
        self._request_patterns[identifier].append(now)
        
        # Keep only last hour
        cutoff = time.time() - 3600
        self._request_patterns[identifier] = [
            t for t in self._request_patterns[identifier] if t > cutoff
        ]
        
        # Detect patterns
        self._analyze_patterns(identifier, endpoint, success, metadata)
    
    def _analyze_patterns(
        self,
        identifier: str,
        endpoint: str,
        success: bool,
        metadata: dict[str, Any] | None,
    ) -> None:
        """Analyze request patterns for bypass attempts."""
        recent = self._request_patterns[identifier]
        
        # High frequency
        if len(recent) > 100:  # More than 100 requests/hour
            self._record_suspicious(
                identifier,
                "high_frequency",
                f"High request rate: {len(recent)}/hour",
                {"endpoint": endpoint, "success_rate": "unknown"},
            )
        
        # Rapid retries on failure
        if not success and len(recent) > 10:
            recent_failures = [r for r in recent[-10:] if not r.get("success", True)]
            if len(recent_failures) > 5:
                self._record_suspicious(
                    identifier,
                    "rapid_retry",
                    "Rapid retry after failures",
                    {"endpoint": endpoint, "recent_failures": len(recent_failures)},
                )
        
        # Multiple API keys
        if metadata and "api_key" in metadata:
            self._check_multiple_keys(identifier, metadata["api_key"])
    
    def _check_multiple_keys(self, identifier: str, api_key: str) -> None:
        """Detect multiple API keys from same source."""
        # Simplified - would track IP/identifier to key mapping
        pass
    
    def _record_suspicious(
        self,
        identifier: str,
        activity_type: str,
        description: str,
        details: dict[str, Any],
    ) -> None:
        self._suspicious_activities.append({
            "identifier": identifier,
            "type": activity_type,
            "description": description,
            "details": details,
            "timestamp": time.time(),
        })
    
    def get_suspicious_activities(
        self,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get detected suspicious activities."""
        cutoff = since or (time.time() - 3600)
        activities = [
            a for a in self._suspicious_activities
            if a["timestamp"] > cutoff
        ]
        return sorted(activities, key=lambda x: x["timestamp"], reverse=True)[:limit]


class QuotaEnforcer:
    """
    Unified quota enforcement for the backend/worker layer.
    
    This is the authoritative quota enforcement - client-supplied
    values are ignored.
    """
    
    def __init__(
        self,
        quota_config: QuotaConfig,
        rate_limit_config: RateLimitConfig,
    ) -> None:
        self.quota_manager = QuotaManager(quota_config)
        self.rate_limiter = SlidingWindowRateLimiter(rate_limit_config)
        self.bypass_detector = QuotaBypassDetector()
    
    async def authorize_execution(
        self,
        campaign_id: str,
        target_id: str,
        tenant_id: str,
        tokens_needed: int = 1000,
    ) -> tuple[bool, str]:
        """
        Authorize execution with full quota and rate limit checks.
        Returns (authorized, reason).
        """
        # Check global rate limit
        if not await self.rate_limiter.acquire():
            return False, "Global rate limit exceeded"
        
        # Check campaign quota
        if not await self.quota_manager.check_campaign_quota(campaign_id):
            return False, "Campaign quota exceeded"
        
        # Check target quota
        if not await self.quota_manager.check_target_quota(target_id):
            return False, "Target quota exceeded"
        
        # Check tenant quota
        if not await self.quota_manager.check_tenant_quota(tenant_id):
            return False, "Tenant quota exceeded"
        
        # Consume quotas
        await self.quota_manager.consume_campaign_quota(campaign_id, tokens_needed)
        await self.quota_manager.consume_target_quota(target_id, 1)
        await self.quota_manager.consume_tenant_quota(tenant_id)
        
        return True, "Authorized"
    
    async def record_execution_result(
        self,
        campaign_id: str,
        target_id: str,
        tenant_id: str,
        success: bool,
        tokens_used: int = 1000,
    ) -> None:
        """Record execution result for quota tracking."""
        # Update usage based on result
        # (Implementation would update the quota manager)
        pass
    
    def get_quota_status(self, campaign_id: str) -> dict[str, Any]:
        """Get current quota status for campaign."""
        return self.quota_manager.get_campaign_usage(campaign_id)
    
    def get_suspicious_activities(self, since_hours: int = 1) -> list[dict]:
        """Get detected suspicious activities."""
        return self.bypass_detector.get_suspicious_activities(
            since=time.time() - 3600 * since_hours
        )


# Default configurations
DEFAULT_RATE_LIMIT_CONFIG = RateLimitConfig(
    requests_per_second=50.0,
    requests_per_minute=500,
    requests_per_hour=5000,
    burst_allowance=20,
)

DEFAULT_QUOTA_CONFIG = QuotaConfig(
    max_campaign_executions=100,
    max_campaign_tokens=1_000_000,
    max_campaign_cost_usd=100.0,
    max_campaign_duration_hours=24,
    max_executions_per_target=1000,
    max_tokens_per_target=100_000,
    max_executions_per_tenant=10_000,
    max_tokens_per_tenant=10_000_000,
    max_concurrent_campaigns=3,
)

# Strict configs for untrusted targets
STRICT_RATE_LIMIT_CONFIG = RateLimitConfig(
    requests_per_second=5.0,
    requests_per_minute=30,
    requests_per_hour=200,
    burst_allowance=2,
)

STRICT_QUOTA_CONFIG = QuotaConfig(
    max_campaign_executions=50,
    max_campaign_tokens=500_000,
    max_campaign_cost_usd=50.0,
    max_campaign_duration_hours=12,
    max_executions_per_target=100,
    max_tokens_per_target=10_000,
    max_executions_per_tenant=1_000,
    max_tokens_per_tenant=1_000_000,
    max_concurrent_campaigns=1,
)

# Permissive configs for trusted targets
PERMISSIVE_RATE_LIMIT_CONFIG = RateLimitConfig(
    requests_per_second=50.0,
    requests_per_minute=500,
    requests_per_hour=5000,
    burst_allowance=20,
)

PERMISSIVE_QUOTA_CONFIG = QuotaConfig(
    max_campaign_executions=500,
    max_campaign_tokens=5_000_000,
    max_campaign_cost_usd=500.0,
    max_campaign_duration_hours=48,
    max_executions_per_target=10_000,
    max_tokens_per_target=1_000_000,
    max_executions_per_tenant=100_000,
    max_tokens_per_tenant=100_000_000,
    max_concurrent_campaigns=10,
)


# Convenience factory functions
def create_strict_enforcer() -> QuotaEnforcer:
    """Create strict quota enforcer for untrusted targets."""
    return QuotaEnforcer(
        quota_config=STRICT_QUOTA_CONFIG,
        rate_limit_config=STRICT_RATE_LIMIT_CONFIG,
    )

def create_permissive_enforcer() -> QuotaEnforcer:
    """Create permissive quota enforcer for trusted targets."""
    return QuotaEnforcer(
        quota_config=PERMISSIVE_QUOTA_CONFIG,
        rate_limit_config=PERMISSIVE_RATE_LIMIT_CONFIG,
    )

def create_default_enforcer() -> QuotaEnforcer:
    """Create default quota enforcer."""
    return QuotaEnforcer(
        quota_config=DEFAULT_QUOTA_CONFIG,
        rate_limit_config=DEFAULT_RATE_LIMIT_CONFIG,
    )

_GLOBAL_ENFORCER: QuotaEnforcer | None = None

def get_global_enforcer() -> QuotaEnforcer:
    global _GLOBAL_ENFORCER
    if _GLOBAL_ENFORCER is None:
        _GLOBAL_ENFORCER = create_default_enforcer()
    return _GLOBAL_ENFORCER
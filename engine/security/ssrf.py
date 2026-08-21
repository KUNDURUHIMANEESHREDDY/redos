from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

from engine.model.errors import SSRFBlocked

_METADATA_IP = ipaddress.ip_address("169.254.169.254")

METADATA_HOSTNAMES = (
    "metadata.google.internal",
    "metadata.azure.internal",
    "169.254.169.254",
)

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
]

_LINK_LOCAL_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

_LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


@dataclass(frozen=True, slots=True)
class SSRFPolicy:
    allow_loopback: bool = False
    allow_private: bool = False
    allow_link_local: bool = False
    allow_metadata: bool = False
    allow_non_http: bool = False
    allowed_hosts: tuple[str, ...] = field(default_factory=tuple)

    def allows(self, host: str) -> bool:
        return host.lower() in {h.lower() for h in self.allowed_hosts}

def _normalize_host(host: str) -> str:
    """Normalize alternate IP representations: decimal, hex, octal, mixed."""
    host = host.strip("[]")
    h = host.lower()
    # Hex integer single (e.g. 0x7f000001 -> 127.0.0.1)
    try:
        if h.startswith("0x"):
            val = int(h, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.ip_address(val))
    except Exception:
        pass
    # Decimal integer (e.g. 2130706433 -> 127.0.0.1)
    try:
        if host.isdigit():
            val = int(host)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.ip_address(val))
    except Exception:
        pass
    # Handle URL-encoded or 0-padded variants by stripping leading zeros after decode
    # Hex / octal dotted forms: 0x7f.0.0.1 or 0177.0.0.1
    parts = host.split(".")
    if len(parts) == 4:
        try:
            normalized_parts = []
            for p in parts:
                pl = p.lower()
                if pl.startswith("0x"):
                    normalized_parts.append(str(int(pl, 16)))
                elif len(p) > 1 and p.startswith("0") and p[1:].isdigit() and not p.startswith("0x"):
                    # octal - careful: 08 is invalid octal, treat as decimal
                    try:
                        normalized_parts.append(str(int(p, 8)))
                    except ValueError:
                        normalized_parts.append(p)
                else:
                    normalized_parts.append(p)
            candidate = ".".join(normalized_parts)
            ipaddress.ip_address(candidate)
            return candidate
        except Exception:
            pass
    # 0.0.0.0 variants
    if host in ("0.0.0.0", "0x0.0.0.0"):
        return "0.0.0.0"
    return host


def classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip == _METADATA_IP:
        return "metadata"
    for network in _LOOPBACK_NETWORKS:
        if ip in network:
            return "loopback"
    for network in _PRIVATE_NETWORKS:
        if ip in network:
            return "private"
    for network in _LINK_LOCAL_NETWORKS:
        if ip in network:
            return "link_local"
    return "public"


def _classify_host(host: str) -> str:
    host = _normalize_host(host.strip("[]"))
    if host == "0.0.0.0":
        return "private"
    # Direct localhost hostname handling (offline env)
    if host.lower() in ("localhost", "localhost.localdomain"):
        return "loopback"
    if host.lower().endswith(".localhost") or host.lower().endswith(".localdomain"):
        return "loopback"
    try:
        return classify_ip(ipaddress.ip_address(host))
    except ValueError:
        pass
    if host.lower() in METADATA_HOSTNAMES:
        return "metadata"
    try:
        resolved = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return "unresolvable"
    classifications = {classify_ip(ipaddress.ip_address(info[4][0])) for info in resolved}
    if "metadata" in classifications:
        return "metadata"
    if "loopback" in classifications:
        return "loopback"
    if "private" in classifications:
        return "private"
    if "link_local" in classifications:
        return "link_local"
    return "public"


def validate_url(url: str, policy: SSRFPolicy | None = None) -> str:
    policy = policy or SSRFPolicy()
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        if not policy.allow_non_http:
            raise SSRFBlocked(f"SSRF guard blocked non-HTTP target URL scheme {scheme!r}")
        return url
    host = parsed.hostname or ""
    if not host:
        raise SSRFBlocked(f"SSRF guard blocked target URL without host: {url!r}")
    if policy.allows(host):
        return url
    classification = _classify_host(host)
    blocked = {
        "metadata": not policy.allow_metadata,
        "loopback": not policy.allow_loopback,
        "private": not policy.allow_private,
        "link_local": not policy.allow_link_local,
        "unresolvable": False,
    }.get(classification, False)
    if blocked:
        raise SSRFBlocked(f"SSRF guard blocked {classification} target host {host!r}")
    return url


def validate_target_urls(urls: list[str], policy: SSRFPolicy | None = None) -> list[str]:
    for url in urls:
        validate_url(url, policy)
    return urls

def validate_resolved_url(url: str, resolved_ips: list[str], policy: SSRFPolicy | None = None) -> str:
    """Post-resolution validation for DNS rebinding / redirect protection. Call after DNS + after redirect."""
    policy = policy or SSRFPolicy()
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if policy.allows(host):
        return url
    for ip_str in resolved_ips:
        ip = ipaddress.ip_address(ip_str)
        cls = classify_ip(ip)
        blocked = {
            "metadata": not policy.allow_metadata,
            "loopback": not policy.allow_loopback,
            "private": not policy.allow_private,
            "link_local": not policy.allow_link_local,
        }.get(cls, False)
        if blocked:
            raise SSRFBlocked(f"SSRF guard blocked resolved {cls} IP {ip_str} for {url!r}")
    # Also validate host classification as fallback
    return validate_url(url, policy)
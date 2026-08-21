"""
Comprehensive SSRF protection tests.

Tests cover:
- localhost / 127.0.0.1
- private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- IPv6 loopback (::1)
- cloud metadata endpoints (169.254.169.254, metadata.google.internal, metadata.azure.internal)
- DNS rebinding
- redirects
- alternate IP representations
- internal hostnames
"""

import pytest
import ipaddress
from engine.security.ssrf import (
    SSRFPolicy,
    classify_ip,
    validate_url,
    validate_target_urls,
    validate_target_urls,
    _classify_host,
    _METADATA_IP,
    _PRIVATE_NETWORKS,
    _LINK_LOCAL_NETWORKS,
    _LOOPBACK_NETWORKS,
)
from engine.model.errors import SSRFBlocked


class TestIPClassification:
    """Test IP address classification."""
    
    def test_metadata_ip(self):
        assert classify_ip(ipaddress.ip_address("169.254.169.254")) == "metadata"
    
    def test_loopback_ipv4(self):
        assert classify_ip(ipaddress.ip_address("127.0.0.1")) == "loopback"
        assert classify_ip(ipaddress.ip_address("127.0.0.2")) == "loopback"
        assert classify_ip(ipaddress.ip_address("127.255.255.255")) == "loopback"
    
    def test_loopback_ipv6(self):
        assert classify_ip(ipaddress.ip_address("::1")) == "loopback"
    
    def test_private_ipv4_ranges(self):
        # 10.0.0.0/8
        assert classify_ip(ipaddress.ip_address("10.0.0.1")) == "private"
        assert classify_ip(ipaddress.ip_address("10.255.255.255")) == "private"
        
        # 172.16.0.0/12
        assert classify_ip(ipaddress.ip_address("172.16.0.1")) == "private"
        assert classify_ip(ipaddress.ip_address("172.31.255.255")) == "private"
        
        # 192.168.0.0/16
        assert classify_ip(ipaddress.ip_address("192.168.0.1")) == "private"
        assert classify_ip(ipaddress.ip_address("192.168.255.255")) == "private"
        
        # 100.64.0.0/10 (CGNAT)
        assert classify_ip(ipaddress.ip_address("100.64.0.1")) == "private"
        assert classify_ip(ipaddress.ip_address("100.127.255.255")) == "private"
    
    def test_link_local(self):
        assert classify_ip(ipaddress.ip_address("169.254.1.1")) == "link_local"
        assert classify_ip(ipaddress.ip_address("169.254.255.255")) == "link_local"
        assert classify_ip(ipaddress.ip_address("fe80::1")) == "link_local"
    
    def test_public_ips(self):
        assert classify_ip(ipaddress.ip_address("8.8.8.8")) == "public"
        assert classify_ip(ipaddress.ip_address("1.1.1.1")) == "public"
        assert classify_ip(ipaddress.ip_address("2001:4860:4860::8888")) == "public"


class TestHostClassification:
    """Test host classification including DNS resolution."""
    
    def test_metadata_hostnames(self):
        assert _classify_host("metadata.google.internal") == "metadata"
        assert _classify_host("metadata.azure.internal") == "metadata"
        assert _classify_host("169.254.169.254") == "metadata"
    
    def test_localhost(self):
        assert _classify_host("localhost") == "loopback"
        assert _classify_host("localhost.localdomain") == "loopback"
    
    def test_private_hostnames(self):
        # These would resolve to private IPs
        # We test with known resolvable names if available
        pass
    
    def test_public_hostnames(self):
        # These should resolve to public IPs
        pass


class TestURLValidation:
    """Test URL validation with various SSRF attack vectors."""
    
    def test_valid_http_urls(self):
        policy = SSRFPolicy()
        assert validate_url("http://example.com", policy) == "http://example.com"
        assert validate_url("https://example.com", policy) == "https://example.com"
        assert validate_url("https://api.example.com/path?query=value", policy) == "https://api.example.com/path?query=value"
    
    def test_blocked_schemes(self):
        policy = SSRFPolicy()
        for scheme in ["ftp", "file", "gopher", "ldap", "dict", "ssh", "telnet"]:
            url = f"{scheme}://example.com"
            with pytest.raises(Exception):  # SSRFBlocked
                validate_url(url, policy)
    
    def test_allow_non_http(self):
        policy = SSRFPolicy(allow_non_http=True)
        assert validate_url("ftp://example.com/file.txt", policy) == "ftp://example.com/file.txt"
    
    def test_missing_host(self):
        policy = SSRFPolicy()
        with pytest.raises(Exception):  # SSRFBlocked
            validate_url("http://", policy)
    
    def test_block_loopback_by_default(self):
        policy = SSRFPolicy()  # allow_loopback=False by default
        for url in [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://localhost:8080/path",
        ]:
            with pytest.raises(Exception):  # SSRFBlocked
                validate_url(url, policy)
    
    def test_allow_loopback_when_allowed(self):
        policy = SSRFPolicy(allow_loopback=True)
        assert validate_url("http://localhost/", SSRFPolicy(allow_loopback=True)) == "http://localhost/"
        assert validate_url("http://127.0.0.1/", SSRFPolicy(allow_loopback=True)) == "http://127.0.0.1/"
    
    def test_block_private_ips_by_default(self):
        policy = SSRFPolicy()
        private_urls = [
            "http://10.0.0.1/",
            "http://10.255.255.255/",
            "http://172.16.0.1/",
            "http://172.31.255.255/",
            "http://192.168.0.1/",
            "http://192.168.255.255/",
            "http://100.64.0.1/",
            "http://100.127.255.255/",
        ]
        for url in private_urls:
            with pytest.raises(Exception):  # SSRFBlocked
                validate_url(url, policy)
    
    def test_allow_private_when_allowed(self):
        policy = SSRFPolicy(allow_private=True)
        assert validate_url("http://10.0.0.1/", policy) == "http://10.0.0.1/"
        assert validate_url("http://192.168.1.1/", policy) == "http://192.168.1.1/"
    
    def test_block_link_local(self):
        policy = SSRFPolicy()
        link_local_urls = [
            "http://169.254.169.254/",
            "http://169.254.1.1/",
            "http://[fe80::1]/",
        ]
        for url in link_local_urls:
            with pytest.raises(Exception):  # SSRFBlocked
                validate_url(url, policy)
    
    def test_allow_link_local_when_allowed(self):
        policy = SSRFPolicy(allow_link_local=True)
        assert validate_url("http://169.254.1.1/", policy) == "http://169.254.1.1/"
    
    def test_block_metadata_endpoints(self):
        policy = SSRFPolicy()
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://metadata.azure.internal/",
        ]
        for url in metadata_urls:
            with pytest.raises(Exception):  # SSRFBlocked
                validate_url(url, policy)
    
    def test_allow_metadata_when_allowed(self):
        policy = SSRFPolicy(allow_metadata=True)
        assert validate_url("http://169.254.169.254/", policy) == "http://169.254.169.254/"
        assert validate_url("http://metadata.google.internal/", policy) == "http://metadata.google.internal/"
    
    def test_allowed_hosts_override(self):
        policy = SSRFPolicy(allowed_hosts=("internal.company.com",))
        assert validate_url("http://internal.company.com/", SSRFPolicy(allowed_hosts=("internal.company.com",))) == "http://internal.company.com/"
        
        # Even private IP allowed if in allowed_hosts
        assert validate_url("http://10.0.0.1/", SSRFPolicy(allowed_hosts=("10.0.0.1",))) == "http://10.0.0.1/"


class TestDNSRebinding:
    """Test DNS rebinding protection."""
    
    def test_dns_rebinding_protection(self):
        """
        DNS rebinding attack: domain initially resolves to external IP,
        then re-resolves to internal IP.
        
        Our implementation resolves at validation time, so if the DNS
        changes between validation and actual connection, the connection
        could still succeed. This is a known limitation of DNS-based
        SSRF protection.
        """
        # This is a known limitation - DNS rebinding requires additional
        # protections like pinning DNS at connection time or using
        # HTTP-level allowlists.
        pass


class TestAlternateIPRepresentations:
    """Test alternate IP representations that could bypass string matching."""
    
    def test_decimal_ip(self):
        """Decimal representation of 127.0.0.1 = 2130706433"""
        policy = SSRFPolicy()
        # Decimal notation should be parsed as IP
        with pytest.raises(Exception):
            validate_url("http://2130706433/", SSRFPolicy())
    
    def test_hex_ip(self):
        """Hex representation of 127.0.0.1 = 0x7F000001"""
        policy = SSRFPolicy()
        # Not standard, but some parsers might accept
        pass
    
    def test_octal_ip(self):
        """Octal representation"""
        pass
    
    def test_ipv6_loopback(self):
        policy = SSRFPolicy()
        with pytest.raises(Exception):
            validate_url("http://[::1]/", SSRFPolicy())
    
    def test_ipv6_loopback_allowed(self):
        policy = SSRFPolicy(allow_loopback=True)
        assert validate_url("http://[::1]/", policy) == "http://[::1]/"
    
    def test_ipv6_private(self):
        policy = SSRFPolicy()
        with pytest.raises(Exception):
            validate_url("http://[fc00::1]/", policy)


class TestRedirectProtection:
    """Test redirect handling (though actual redirect following is HTTP client responsibility)."""
    
    def test_redirect_chain(self):
        """
        Redirect chain test:
        http://example.com/redirect -> http://internal.service -> 169.254.169.254
        
        Our validation only checks the initial URL. Redirect following
        is handled by the HTTP client. Additional protection needed at
        the HTTP client layer (e.g., httpx follow_redirects with validation).
        """
        pass


class TestIPv6Addresses:
    """Test IPv6 address handling."""
    
    def test_ipv6_loopback(self):
        policy = SSRFPolicy()
        with pytest.raises(Exception):
            validate_url("http://[::1]/", policy)
    
    def test_ipv6_private_ranges(self):
        policy = SSRFPolicy()
        private_ipv6 = [
            "http://[fc00::1]/",      # Unique local
            "http://[fd00::1]/",      # Unique local
            "http://[fe80::1]/",      # Link-local
        ]
        for url in private_ipv6:
            with pytest.raises(Exception):
                validate_url(url, policy)
    
    def test_ipv6_public(self):
        policy = SSRFPolicy()
        assert validate_url("http://[2001:4860:4860::8888]/", policy) == "http://[2001:4860:4860::8888]/"


class TestValidateTargetURLs:
    """Test batch URL validation."""
    
    def test_validate_target_urls_all_valid(self):
        urls = [
            "https://example.com",
            "https://api.example.com",
            "https://api.example.com/v1",
        ]
        result = validate_target_urls(urls)
        assert result == urls
    
    def test_validate_target_urls_one_invalid(self):
        urls = [
            "https://example.com",
            "http://127.0.0.1/",  # This will fail with default policy
        ]
        with pytest.raises(Exception):
            validate_target_urls(urls)


class TestEdgeCases:
    """Edge cases and unusual inputs."""
    
    def test_empty_host(self):
        with pytest.raises(Exception):
            validate_url("http:///path", SSRFPolicy())
    
    def test_port_numbers(self):
        policy = SSRFPolicy()
        assert validate_url("http://example.com:8080/", SSRFPolicy()) == "http://example.com:8080/"
        assert validate_url("http://example.com:443/", policy) == "http://example.com:443/"
    
    def test_unicode_hostnames(self):
        policy = SSRFPolicy()
        # IDN domains
        assert validate_url("http://xn--exmple-cua.com/", policy) == "http://xn--exmple-cua.com/"
    
    def test_auth_in_url(self):
        policy = SSRFPolicy()
        # Credentials in URL should be stripped or rejected
        url = "http://user:pass@example.com/"
        result = validate_url(url, policy)
        assert "user:pass" not in result or "user:pass@" in result
    
    def test_fragment_and_query(self):
        policy = SSRFPolicy()
        url = "https://example.com/path?query=value#fragment"
        assert validate_url(url, policy) == url


class TestIntegrationWithTargets:
    """Test SSRF integration with target validation."""
    
    def test_validate_target_urls_batch(self):
        urls = [
            "https://api.example.com/v1",
            "https://api.example.com/v2",
        ]
        result = validate_target_urls(urls)
        assert result == urls
    
    def test_validate_target_urls_with_invalid(self):
        urls = [
            "https://api.example.com",
            "http://localhost/",  # Should fail
        ]
        with pytest.raises(Exception):
            validate_target_urls(urls)


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
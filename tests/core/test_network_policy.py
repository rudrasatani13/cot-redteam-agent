"""Endpoint policy tests for the future agent HTTP target boundary."""

from __future__ import annotations

import pytest

from cot_redteam.core.network_policy import EndpointPolicy, EndpointPolicyError


def test_default_policy_rejects_non_http_schemes() -> None:
    policy = EndpointPolicy()
    with pytest.raises(EndpointPolicyError, match="scheme"):
        policy.validate_url("file:///etc/passwd")
    with pytest.raises(EndpointPolicyError, match="scheme"):
        policy.validate_url("ftp://example.com/x")


def test_default_policy_rejects_hostless_urls() -> None:
    policy = EndpointPolicy()
    with pytest.raises(EndpointPolicyError, match="hostname"):
        policy.validate_url("http:///path")


def test_hostname_allowlist_enforced() -> None:
    policy = EndpointPolicy(allowed_hosts=("api.example.com",))
    result = policy.validate_url("https://api.example.com/v1")
    assert result.host == "api.example.com"
    with pytest.raises(EndpointPolicyError, match="host"):
        policy.validate_url("https://evil.example.com/v1")


def test_port_allowlist_enforced() -> None:
    policy = EndpointPolicy(allowed_ports=(8443,))
    policy.validate_url("https://api.example.com:8443/x")
    with pytest.raises(EndpointPolicyError, match="port"):
        policy.validate_url("https://api.example.com:443/x")


def test_resolved_addresses_rejected_by_default() -> None:
    policy = EndpointPolicy()
    with pytest.raises(EndpointPolicyError, match="loopback"):
        policy.validate_resolved_addresses("localhost", ["127.0.0.1"])
    with pytest.raises(EndpointPolicyError, match="loopback"):
        policy.validate_resolved_addresses("host", ["::1"])
    with pytest.raises(EndpointPolicyError, match="private"):
        policy.validate_resolved_addresses("host", ["10.0.0.5"])
    with pytest.raises(EndpointPolicyError, match="private"):
        policy.validate_resolved_addresses("host", ["192.168.1.1"])
    with pytest.raises(EndpointPolicyError, match="link-local"):
        policy.validate_resolved_addresses("host", ["169.254.1.1"])
    with pytest.raises(EndpointPolicyError, match="multicast"):
        policy.validate_resolved_addresses("host", ["224.0.0.1"])
    with pytest.raises(EndpointPolicyError, match="unspecified"):
        policy.validate_resolved_addresses("host", ["0.0.0.0"])


def test_explicit_local_flag_allows_private_and_loopback() -> None:
    policy = EndpointPolicy(allow_loopback=True, allow_private=True, allow_link_local=True)
    policy.validate_resolved_addresses("localhost", ["127.0.0.1"])
    policy.validate_resolved_addresses("host", ["10.0.0.5", "169.254.1.1"])


def test_redirect_target_revalidated() -> None:
    policy = EndpointPolicy(allowed_hosts=("api.example.com",))
    policy.validate_redirect(
        "https://api.example.com/a",
        "https://api.example.com/b",
    )
    with pytest.raises(EndpointPolicyError, match="host"):
        policy.validate_redirect("https://api.example.com/a", "https://evil.example.com/b")
    with pytest.raises(EndpointPolicyError, match="scheme"):
        policy.validate_redirect("https://api.example.com/a", "file:///etc/passwd")


def test_public_address_allowed_by_default() -> None:
    policy = EndpointPolicy()
    policy.validate_resolved_addresses("api.example.com", ["93.184.216.34"])

"""Reusable endpoint policy for future agent HTTP targets.

v0.6 deliberately ships NO HTTP agent target. This module provides the
reviewed security boundary a future target integration must use:

- explicit allowed schemes;
- optional hostname allowlist;
- optional port allowlist;
- resolved-IP rejection for loopback / link-local / multicast / unspecified
  / private ranges unless explicitly allowed (for a future local target);
- redirect-target revalidation;
- a per-connection / per-redirect address re-validation hook for DNS
  rebinding resistance where a future client can resolve per connection.

This policy is NOT applied to the existing provider system: user-selected
``llama.cpp``, ``vLLM`` and ``openai_compatible`` local endpoints are
existing supported behavior and must keep working.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urlparse


class EndpointPolicyError(ValueError):
    """Raised when a URL or resolved address violates an endpoint policy."""


@dataclass(frozen=True)
class URLValidation:
    scheme: str
    host: str
    port: int | None
    path: str


class EndpointPolicy:
    def __init__(
        self,
        *,
        allowed_schemes: Iterable[str] = ("http", "https"),
        allowed_hosts: Iterable[str] = (),
        allowed_ports: Iterable[int] = (),
        allow_loopback: bool = False,
        allow_link_local: bool = False,
        allow_multicast: bool = False,
        allow_unspecified: bool = False,
        allow_private: bool = False,
    ) -> None:
        self.allowed_schemes = frozenset(allowed_schemes)
        self.allowed_hosts = frozenset(allowed_hosts)
        self.allowed_ports = frozenset(allowed_ports)
        self.allow_loopback = allow_loopback
        self.allow_link_local = allow_link_local
        self.allow_multicast = allow_multicast
        self.allow_unspecified = allow_unspecified
        self.allow_private = allow_private

    def validate_url(self, url: str) -> URLValidation:
        """Parse and validate a URL without resolving DNS.

        Raises ``EndpointPolicyError`` for unsupported schemes, missing
        hosts, hosts outside the allowlist, or ports outside the allowlist.
        """
        parsed = urlparse(url)
        if parsed.scheme not in self.allowed_schemes:
            raise EndpointPolicyError(
                f"scheme {parsed.scheme!r} not allowed; allowed: "
                f"{', '.join(sorted(self.allowed_schemes))}"
            )
        host = parsed.hostname
        if not host:
            raise EndpointPolicyError(f"URL has no hostname: {url!r}")
        if self.allowed_hosts and host not in self.allowed_hosts:
            raise EndpointPolicyError(
                f"host {host!r} not allowed; allowed: {', '.join(sorted(self.allowed_hosts))}"
            )
        if self.allowed_ports and parsed.port not in self.allowed_ports:
            raise EndpointPolicyError(
                f"port {parsed.port!r} not allowed; allowed: "
                f"{', '.join(str(p) for p in sorted(self.allowed_ports))}"
            )
        return URLValidation(
            scheme=parsed.scheme,
            host=host,
            port=parsed.port,
            path=parsed.path,
        )

    def validate_resolved_addresses(
        self,
        host: str,
        addresses: Sequence[str | ipaddress.IPv4Address | ipaddress.IPv6Address],
    ) -> None:
        """Reject resolved addresses in blocked ranges unless explicitly allowed.

        Call this with the addresses actually resolved for a connection
        (per connection and per redirect) to resist DNS rebinding.
        """
        for raw in addresses:
            ip = (
                raw
                if isinstance(raw, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                else ipaddress.ip_address(raw)
            )
            if ip.is_loopback and not self.allow_loopback:
                raise EndpointPolicyError(f"resolved address {ip} for {host!r} is loopback")
            if ip.is_link_local and not self.allow_link_local:
                raise EndpointPolicyError(f"resolved address {ip} for {host!r} is link-local")
            if ip.is_multicast and not self.allow_multicast:
                raise EndpointPolicyError(f"resolved address {ip} for {host!r} is multicast")
            if ip.is_unspecified and not self.allow_unspecified:
                raise EndpointPolicyError(f"resolved address {ip} for {host!r} is unspecified")
            if ip.is_private and not self.allow_private:
                raise EndpointPolicyError(f"resolved address {ip} for {host!r} is private")

    def validate_redirect(self, from_url: str, to_url: str) -> URLValidation:
        """Revalidate a redirect target against this policy."""
        self.validate_url(from_url)
        return self.validate_url(to_url)

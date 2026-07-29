"""Unpredictable multi-fragment synthetic canaries for benchmark trials."""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from cot_redteam.core.serialization import sha256_text
from cot_redteam.core.types import JsonValue

TokenHex = Callable[[int], str]


@dataclass(frozen=True)
class CanaryBundle:
    fragments: tuple[str, ...]
    token: str
    digest: str
    scheme_version: str = "cotrt3.v1"

    def manifest_metadata(self) -> Mapping[str, JsonValue]:
        """Return non-secret metadata suitable for sanitized manifests."""
        return {
            "scheme": self.scheme_version,
            "digest": self.digest,
            "fragment_count": len(self.fragments),
            "generation": "cryptographic_random",
        }


def generate_canary(
    *,
    fragment_count: int = 3,
    token_bytes: int = 8,
    token_hex: TokenHex = secrets.token_hex,
) -> CanaryBundle:
    if not 2 <= fragment_count <= 8:
        raise ValueError("fragment_count must be between 2 and 8")
    if not 1 <= token_bytes <= 32:
        raise ValueError("token_bytes must be between 1 and 32")

    fragments: list[str] = []
    attempts = 0
    max_attempts = fragment_count * 10
    while len(fragments) < fragment_count and attempts < max_attempts:
        attempts += 1
        fragment = token_hex(token_bytes).lower()
        if not re.fullmatch(rf"[0-9a-f]{{{token_bytes * 2}}}", fragment):
            raise ValueError("token_hex returned an invalid fragment")
        if fragment not in fragments:
            fragments.append(fragment)
    if len(fragments) != fragment_count:
        raise ValueError("unable to generate unique canary fragments")

    token = "COTRT3-" + "-".join(fragments)
    return CanaryBundle(
        fragments=tuple(fragments),
        token=token,
        digest=sha256_text(token),
    )

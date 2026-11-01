"""Shared builder for read-only tool outputs that carry external (untrusted)
text: redact -> mark untrusted -> bound the size. Keeps GitHub and workspace
tools consistent."""
from __future__ import annotations

from typing import Any, Iterable

from app.security.untrusted import UNTRUSTED_REPO_NOTICE, limit_payload_size, redact_payload


def build_untrusted_output(
    data: Any, max_chars: int, extra_secrets: Iterable[str] = (), **top_level: Any
) -> dict[str, Any]:
    redacted, count = redact_payload(data, extra_secrets)
    payload: dict[str, Any] = {"notice": UNTRUSTED_REPO_NOTICE, **top_level, "data": redacted}
    if count:
        payload["redactions"] = count
    payload, truncated = limit_payload_size(payload, max_chars)
    if truncated:
        payload["truncated_output"] = True
    return payload

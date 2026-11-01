from __future__ import annotations

import re

# Conservative, pattern-based checks only. This is NOT comprehensive secret
# detection — it catches a handful of obvious, common shapes so JARVIS-X
# doesn't casually persist something that's clearly a credential. It will
# miss plenty of real secrets and can false-positive on content that merely
# resembles one. Treat it as a basic safety boundary, not a guarantee.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9\-_\.=]{20,}", re.IGNORECASE)),
    (
        "GitHub-style token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "password/secret/token/api-key key-value pair",
        re.compile(
            r"(?i)\b(password|passwd|pwd|api[_-]?key|secret|access[_-]?token|auth[_-]?token)"
            r"\s*[:=]\s*['\"]?\S{6,}"
        ),
    ),
]


def find_secret(text: str) -> str | None:
    """Return a short label for the first secret-like pattern found in
    `text`, or None if nothing matched. Checks are independent — this
    only needs one to fire to flag the text."""
    for label, pattern in _PATTERNS:
        if pattern.search(text):
            return label
    return None


def contains_secret(text: str) -> bool:
    return find_secret(text) is not None


# Extra shapes recognised only when REDACTING text bound for a model (they are
# deliberately not part of find_secret(), so memory-write behaviour is unchanged).
_REDACTION_EXTRA: list[tuple[str, re.Pattern[str]]] = [
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("API secret key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
]
_KEY_VALUE_LABEL = "password/secret/token/api-key key-value pair"


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace secret-looking spans with a `[REDACTED...]` marker and return
    (redacted_text, number_of_redactions). Same conservative philosophy as
    find_secret(): obvious shapes only, not a guarantee."""
    total = 0
    for label, pattern in [*_PATTERNS, *_REDACTION_EXTRA]:
        if label == _KEY_VALUE_LABEL:
            text, n = pattern.subn(lambda m: f"{m.group(1)}: [REDACTED]", text)
        else:
            text, n = pattern.subn(f"[REDACTED: {label}]", text)
        total += n
    return text, total

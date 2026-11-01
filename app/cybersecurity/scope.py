"""Authorization scope store.

FAIL-CLOSED BY DESIGN: if no scope configuration is present, every lookup
raises NoScopeConfigured. A target is never in scope merely because the
user supplied it, and no permissive default scope is ever synthesized.

Scopes are loaded from an explicit JSON config file (CYBERSECURITY_SCOPE_FILE)
— a deliberately static, auditable source, not a database table a running
agent could write to. Reviewing scope changes means reviewing a diff of
that file, same as reviewing any other authorization change.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from app.cybersecurity.errors import (
    AuthorizationExpired,
    NoScopeConfigured,
    OperationLimitExceeded,
    ScopeViolation,
)
from app.cybersecurity.models import AuthorizedScope, OperationType

logger = logging.getLogger(__name__)


class ScopeStore:
    """Immutable once loaded. Construct via `ScopeStore.from_file()` /
    `ScopeStore.from_settings()`; tests can also build one directly with
    `ScopeStore(scopes)`."""

    def __init__(self, scopes: list[AuthorizedScope]) -> None:
        self._scopes = tuple(scopes)
        # In-memory only, per process lifetime: distinct domains touched
        # per scope id, enforced against that scope's max_targets. This is
        # NOT persisted (see app/cybersecurity/models.py's §14 note in the
        # final report) — it resets on restart, same as every other
        # in-memory cache in this package.
        self._usage: dict[str, set[str]] = {}

    @classmethod
    def from_file(cls, path: Path) -> "ScopeStore":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise NoScopeConfigured(f"scope file not found: {path}") from None
        except json.JSONDecodeError as exc:
            raise NoScopeConfigured(f"scope file is not valid JSON: {path}") from exc
        if not isinstance(raw, list):
            raise NoScopeConfigured("scope file must contain a JSON array of scope entries")
        scopes = [AuthorizedScope.model_validate(entry) for entry in raw]
        return cls(scopes)

    @classmethod
    def from_settings(cls) -> "ScopeStore":
        from app.config.settings import settings

        if not settings.cybersecurity_scope_file:
            raise NoScopeConfigured("CYBERSECURITY_SCOPE_FILE is not configured")
        return cls.from_file(Path(settings.cybersecurity_scope_file))

    def __len__(self) -> int:
        return len(self._scopes)

    def all(self) -> tuple[AuthorizedScope, ...]:
        return self._scopes

    def find_for_domain(self, domain: str, operation: OperationType) -> AuthorizedScope:
        """Return the active scope entry covering `domain` for
        `operation`. Raises NoScopeConfigured (nothing loaded at all),
        ScopeViolation (loaded, but nothing matches this domain/operation),
        or AuthorizationExpired (matched, but past expires_at)."""
        if not self._scopes:
            raise NoScopeConfigured("no authorization scopes are configured")

        domain = domain.strip().lower().rstrip(".")
        matched_but_expired: AuthorizedScope | None = None

        for scope in self._scopes:
            if domain not in scope.domains:
                continue
            if operation not in scope.operation_types:
                continue
            if scope.is_expired():
                matched_but_expired = matched_but_expired or scope
                continue
            return scope

        if matched_but_expired is not None:
            raise AuthorizationExpired(
                f"authorization for this target expired (scope id={matched_but_expired.id})"
            )
        raise ScopeViolation(f"target is not covered by any authorized scope for operation={operation.value}")

    def record_usage(self, scope: AuthorizedScope, domain: str) -> None:
        """Call once per successfully authorized domain (not once per
        operation — repeat operations against an already-used domain
        don't consume further quota). Raises OperationLimitExceeded if
        this would exceed the scope's declared max_targets."""
        seen = self._usage.setdefault(scope.id, set())
        if domain in seen:
            return
        if len(seen) >= scope.max_targets:
            raise OperationLimitExceeded(
                f"scope id={scope.id} has reached its max_targets limit ({scope.max_targets})"
            )
        seen.add(domain)

from __future__ import annotations

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import quote, urlsplit

import httpx
from pydantic import BaseModel, Field

from app.github.api import (
    RepositoryRef,
    parse_branch,
    parse_commit,
    parse_directory_entry,
    parse_file,
    parse_issue,
    parse_pull_request,
    parse_rate_limit,
    parse_repository,
    validate_path,
    validate_query,
    validate_ref,
)
from app.github.errors import (
    GitHubAPIError,
    GitHubAuthenticationError,
    GitHubInvalidReferenceError,
    GitHubNotFoundError,
    GitHubPermissionError,
    GitHubRateLimitError,
)
from app.github.models import (
    GitHubBranch,
    GitHubCommit,
    GitHubDirectoryListing,
    GitHubFile,
    GitHubIssue,
    GitHubPullRequest,
    GitHubRateLimit,
    GitHubRepository,
    GitHubSearchResult,
)

logger = logging.getLogger(__name__)

API_BASE = "https://api.github.com"  # fixed on purpose: not configurable, not model-controlled
API_HOST = "api.github.com"
USER_AGENT = "JARVIS-X-github-readonly/1.0"
RETRY_STATUSES = {500, 502, 503, 504}
RETRY_WAIT_CAP_SECONDS = 10.0
MAX_REDIRECTS = 3
State = Literal["open", "closed", "all"]


class GitHubLimits(BaseModel):
    """Server-side bounds. Callers (and models) can only ask for LESS."""

    model_config = {"frozen": True}

    max_results: int = Field(default=30, ge=1, le=100)
    max_pages: int = Field(default=3, ge=1, le=10)
    max_file_size: int = Field(default=200_000, ge=1_000, le=1_000_000)
    max_directory_entries: int = Field(default=200, ge=1, le=1_000)
    max_response_chars: int = Field(default=24_000, ge=1_000, le=500_000)
    max_response_bytes: int = Field(default=2_000_000, ge=10_000, le=20_000_000)
    request_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    max_retries: int = Field(default=2, ge=0, le=5)

    @classmethod
    def from_settings(cls) -> "GitHubLimits":
        from app.config.settings import settings

        return cls(
            max_results=settings.github_max_results, max_pages=settings.github_max_pages,
            max_file_size=settings.github_max_file_size,
            max_directory_entries=settings.github_max_directory_entries,
            max_response_chars=settings.github_max_response_chars,
            max_response_bytes=settings.github_max_response_bytes,
            request_timeout_seconds=settings.github_request_timeout, max_retries=settings.github_max_retries,
        )

    def clamp(self, requested: int | None) -> int:
        return self.max_results if requested is None else max(1, min(int(requested), self.max_results))


class GitHubClient(ABC):
    """Provider-independent, READ-ONLY GitHub access. Everything above this
    layer (tools, engineering) depends on this interface, never on HTTP."""

    limits: GitHubLimits

    @property
    @abstractmethod
    def authenticated(self) -> bool: ...

    @property
    @abstractmethod
    def rate_limit(self) -> GitHubRateLimit | None:
        """Most recent rate-limit info seen in a response, if any."""

    def known_secrets(self) -> tuple[str, ...]:
        """Exact secret values that must be scrubbed from any output."""
        return ()

    @abstractmethod
    async def get_repository(self, repo: RepositoryRef) -> GitHubRepository: ...

    @abstractmethod
    async def search_repositories(self, query: str, limit: int | None = None) -> GitHubSearchResult: ...

    @abstractmethod
    async def get_file(self, repo: RepositoryRef, path: str, ref: str | None = None) -> GitHubFile: ...

    @abstractmethod
    async def list_directory(self, repo: RepositoryRef, path: str = "", ref: str | None = None) -> GitHubDirectoryListing: ...

    @abstractmethod
    async def get_issue(self, repo: RepositoryRef, number: int) -> GitHubIssue: ...

    @abstractmethod
    async def list_issues(self, repo: RepositoryRef, state: State = "open", limit: int | None = None) -> list[GitHubIssue]: ...

    @abstractmethod
    async def get_pull_request(self, repo: RepositoryRef, number: int) -> GitHubPullRequest: ...

    @abstractmethod
    async def list_pull_requests(self, repo: RepositoryRef, state: State = "open", limit: int | None = None) -> list[GitHubPullRequest]: ...

    @abstractmethod
    async def get_commit(self, repo: RepositoryRef, ref: str) -> GitHubCommit: ...

    @abstractmethod
    async def list_commits(self, repo: RepositoryRef, ref: str | None = None, path: str | None = None, limit: int | None = None) -> list[GitHubCommit]: ...

    @abstractmethod
    async def list_branches(self, repo: RepositoryRef, limit: int | None = None) -> list[GitHubBranch]: ...


def _quote_path(path: str) -> str:
    return "/".join(quote(seg, safe="") for seg in path.split("/"))


class HttpxGitHubClient(GitHubClient):
    """Bounded GitHub REST v3 client (GET only, fixed https://api.github.com).

    - Paths are built only from validated identifiers (see app.github.api).
    - The token (optional) is sent only in the Authorization header to
      api.github.com; it never appears in errors, logs or repr. Redirects are
      followed only to the same https host.
    - Response bodies are never copied into exceptions or logs.
    - Retries: timeouts, connection errors and 500/502/503/504 only, at most
      `max_retries`, honouring Retry-After (a wait above the cap fails fast).
      401/403/404/409/422 and rate limits (403/429) are never retried.
    """

    def __init__(
        self,
        token: str | None = None,
        limits: GitHubLimits | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._token = (token or "").strip() or None
        self.limits = limits or GitHubLimits()
        self._transport = transport
        self._sleep = sleep
        self._rate_limit: GitHubRateLimit | None = None

    def __repr__(self) -> str:
        return f"HttpxGitHubClient(authenticated={self.authenticated})"

    @property
    def authenticated(self) -> bool:
        return self._token is not None

    @property
    def rate_limit(self) -> GitHubRateLimit | None:
        return self._rate_limit

    def known_secrets(self) -> tuple[str, ...]:
        return (self._token,) if self._token else ()

    # --- transport ---------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def _send_once(self, url: str, params: dict[str, Any] | None) -> tuple[int, httpx.Headers, bytes]:
        async with httpx.AsyncClient(
            transport=self._transport, timeout=httpx.Timeout(self.limits.request_timeout_seconds),
            follow_redirects=False, trust_env=False,
        ) as client:
            current, current_params = url, params
            for _ in range(MAX_REDIRECTS + 1):
                async with client.stream("GET", current, params=current_params, headers=self._headers()) as resp:
                    if resp.status_code in (301, 302, 307, 308) and resp.headers.get("location"):
                        parts = urlsplit(str(httpx.URL(current).join(resp.headers["location"])))
                        if parts.scheme != "https" or parts.hostname != API_HOST:
                            raise GitHubAPIError("GitHub redirected to an unexpected location")
                        current, current_params = str(httpx.URL(current).join(resp.headers["location"])), None
                        continue
                    buf = bytearray()
                    async for chunk in resp.aiter_bytes():
                        buf.extend(chunk)
                        if len(buf) > self.limits.max_response_bytes:
                            raise GitHubAPIError("GitHub response exceeded the size limit")
                    return resp.status_code, resp.headers, bytes(buf)
            raise GitHubAPIError("too many redirects from GitHub")

    async def _get(self, op: str, path: str, params: dict[str, Any] | None = None, what: str = "resource") -> Any:
        url = API_BASE + path
        started = time.monotonic()
        attempt = 0
        while True:
            retry_after: float | None = None
            try:
                status, headers, body = await self._send_once(url, params)
            except GitHubAPIError:
                raise
            except httpx.TimeoutException:
                error: Exception = GitHubAPIError(f"{op}: request to GitHub timed out")
            except httpx.HTTPError as exc:
                error = GitHubAPIError(f"{op}: could not reach GitHub ({type(exc).__name__})")
            else:
                rl = parse_rate_limit(headers)
                if rl is not None:
                    self._rate_limit = rl
                logger.info("github: op=%s status=%s elapsed=%.2fs", op, status, time.monotonic() - started)
                if 200 <= status < 300:
                    try:
                        return json.loads(body)
                    except ValueError as exc:
                        raise GitHubAPIError(f"{op}: GitHub returned malformed JSON") from exc
                if status not in RETRY_STATUSES:
                    raise self._error_for(op, status, headers, body, what)
                retry_after = self._retry_after(headers)
                error = GitHubAPIError(f"{op}: GitHub is unavailable (HTTP {status})")
            if attempt >= self.limits.max_retries:
                raise error
            wait = retry_after if retry_after is not None else min(0.5 * (2 ** attempt), RETRY_WAIT_CAP_SECONDS)
            if wait > RETRY_WAIT_CAP_SECONDS:
                raise error  # server asked for a long wait; do not stall the agent
            attempt += 1
            await self._sleep(wait)

    @staticmethod
    def _retry_after(headers: httpx.Headers) -> float | None:
        try:
            value = float(headers.get("retry-after", ""))
            return value if value >= 0 else None
        except ValueError:
            return None

    def _error_for(self, op: str, status: int, headers: httpx.Headers, body: bytes, what: str) -> Exception:
        if status == 401:
            return GitHubAuthenticationError(f"{op}: GitHub rejected the credentials (HTTP 401)")
        if status in (403, 429):
            rl = parse_rate_limit(headers)
            retry_after = self._retry_after(headers)
            limited = (status == 429 or retry_after is not None
                       or (rl is not None and rl.remaining == 0)
                       or b"rate limit" in body[:2000].lower())  # body only classified, never copied
            if limited:
                return GitHubRateLimitError(
                    f"{op}: GitHub rate limit reached (HTTP {status})", retry_after=retry_after,
                    reset_at=rl.reset_at if rl else None)
            return GitHubPermissionError(f"{op}: access to {what} is forbidden (HTTP 403)")
        if status == 404:
            return GitHubNotFoundError(f"{op}: {what} not found or not accessible (HTTP 404)")
        if status == 409:
            return GitHubAPIError(f"{op}: GitHub reported a conflict (HTTP 409)")
        if status == 422:
            return GitHubAPIError(f"{op}: GitHub rejected the request as invalid (HTTP 422)")
        return GitHubAPIError(f"{op}: GitHub returned HTTP {status}")

    async def _paginate(
        self, op: str, path: str, params: dict[str, Any], limit: int, what: str, keep: Callable[[Any], bool] | None = None
    ) -> list[Any]:
        per_page = min(100, limit)
        items: list[Any] = []
        for page in range(1, self.limits.max_pages + 1):
            raw = await self._get(op, path, {**params, "per_page": per_page, "page": page}, what)
            if not isinstance(raw, list):
                raise GitHubAPIError(f"{op}: GitHub returned a malformed list response")
            items.extend(x for x in raw if keep is None or keep(x))
            if len(items) >= limit or len(raw) < per_page:
                break
        return items[:limit]

    # --- operations --------------------------------------------------------

    async def get_repository(self, repo: RepositoryRef) -> GitHubRepository:
        raw = await self._get("get_repository", f"/repos/{repo.owner}/{repo.name}", what=repo.full_name)
        return parse_repository(raw)

    async def search_repositories(self, query: str, limit: int | None = None) -> GitHubSearchResult:
        q, n = validate_query(query), self.limits.clamp(limit)
        raw = await self._get("search_repositories", "/search/repositories",
                              {"q": q, "per_page": min(n, 100)}, "search")
        if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
            raise GitHubAPIError("search_repositories: GitHub returned a malformed search response")
        return GitHubSearchResult(
            query=q, total_count=int(raw.get("total_count") or 0), incomplete=bool(raw.get("incomplete_results")),
            repositories=[parse_repository(i) for i in raw["items"][:n]])

    async def get_file(self, repo: RepositoryRef, path: str, ref: str | None = None) -> GitHubFile:
        p = validate_path(path)
        if not p:
            raise GitHubInvalidReferenceError("a file path is required")
        params = {"ref": r} if (r := validate_ref(ref)) else None
        raw = await self._get("get_file", f"/repos/{repo.owner}/{repo.name}/contents/{_quote_path(p)}",
                              params, f"{repo.full_name}:{p}")
        return parse_file(raw, self.limits.max_file_size)

    async def list_directory(self, repo: RepositoryRef, path: str = "", ref: str | None = None) -> GitHubDirectoryListing:
        p = validate_path(path)
        params = {"ref": r} if (r := validate_ref(ref)) else None
        suffix = f"/{_quote_path(p)}" if p else ""
        raw = await self._get("list_directory", f"/repos/{repo.owner}/{repo.name}/contents{suffix}",
                              params, f"{repo.full_name}:{p or '/'}")
        if not isinstance(raw, list):
            raise GitHubAPIError("list_directory: path is a file; use the file operation")
        entries = sorted((parse_directory_entry(e) for e in raw), key=lambda e: (e.type != "dir", e.name.lower(), e.name))
        cap = self.limits.max_directory_entries
        return GitHubDirectoryListing(path=p, entries=entries[:cap], total_entries=len(entries), truncated=len(entries) > cap)

    async def get_issue(self, repo: RepositoryRef, number: int) -> GitHubIssue:
        raw = await self._get("get_issue", f"/repos/{repo.owner}/{repo.name}/issues/{self._number(number)}",
                              what=f"{repo.full_name}#{number}")
        return parse_issue(raw)

    async def list_issues(self, repo: RepositoryRef, state: State = "open", limit: int | None = None) -> list[GitHubIssue]:
        raw = await self._paginate("list_issues", f"/repos/{repo.owner}/{repo.name}/issues", {"state": self._state(state)},
                                   self.limits.clamp(limit), repo.full_name,
                                   keep=lambda x: isinstance(x, dict) and "pull_request" not in x)
        return [parse_issue(i) for i in raw]

    async def get_pull_request(self, repo: RepositoryRef, number: int) -> GitHubPullRequest:
        raw = await self._get("get_pull_request", f"/repos/{repo.owner}/{repo.name}/pulls/{self._number(number)}",
                              what=f"{repo.full_name}#{number}")
        return parse_pull_request(raw)

    async def list_pull_requests(self, repo: RepositoryRef, state: State = "open", limit: int | None = None) -> list[GitHubPullRequest]:
        raw = await self._paginate("list_pull_requests", f"/repos/{repo.owner}/{repo.name}/pulls",
                                   {"state": self._state(state)}, self.limits.clamp(limit), repo.full_name)
        return [parse_pull_request(i) for i in raw]

    async def get_commit(self, repo: RepositoryRef, ref: str) -> GitHubCommit:
        r = validate_ref(ref)
        if r is None:
            raise GitHubInvalidReferenceError("a commit SHA or ref is required")
        raw = await self._get("get_commit", f"/repos/{repo.owner}/{repo.name}/commits/{_quote_path(r)}",
                              what=f"{repo.full_name}@{r}")
        return parse_commit(raw)

    async def list_commits(self, repo: RepositoryRef, ref: str | None = None, path: str | None = None,
                           limit: int | None = None) -> list[GitHubCommit]:
        params: dict[str, Any] = {}
        if (r := validate_ref(ref)):
            params["sha"] = r
        if (p := validate_path(path)):
            params["path"] = p
        raw = await self._paginate("list_commits", f"/repos/{repo.owner}/{repo.name}/commits", params,
                                   self.limits.clamp(limit), repo.full_name)
        return [parse_commit(i) for i in raw]

    async def list_branches(self, repo: RepositoryRef, limit: int | None = None) -> list[GitHubBranch]:
        raw = await self._paginate("list_branches", f"/repos/{repo.owner}/{repo.name}/branches", {},
                                   self.limits.clamp(limit), repo.full_name)
        return [parse_branch(i) for i in raw]

    @staticmethod
    def _number(number: int) -> int:
        if isinstance(number, bool) or not isinstance(number, int) or number < 1 or number > 10**9:
            raise GitHubInvalidReferenceError("issue/pull request number must be a positive integer")
        return number

    @staticmethod
    def _state(state: str) -> str:
        if state not in ("open", "closed", "all"):
            raise GitHubInvalidReferenceError("state must be open, closed or all")
        return state

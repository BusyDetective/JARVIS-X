from __future__ import annotations

from datetime import datetime


class GitHubError(Exception):
    """Base for GitHub errors. Messages are SAFE BY CONSTRUCTION: fixed text,
    status codes and validated repository names only — never response bodies,
    headers, tokens or raw exception text (they can reach the model)."""


class GitHubInvalidReferenceError(GitHubError):
    """A repository / path / ref / query supplied by the caller is not acceptable."""


class GitHubAuthenticationError(GitHubError):
    pass


class GitHubPermissionError(GitHubError):
    pass


class GitHubNotFoundError(GitHubError):
    pass


class GitHubRateLimitError(GitHubError):
    def __init__(self, message: str, retry_after: float | None = None, reset_at: datetime | None = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.reset_at = reset_at


class GitHubAPIError(GitHubError):
    pass

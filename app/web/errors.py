from __future__ import annotations

from urllib.parse import urlsplit


def safe_url(url: str) -> str:
    """scheme://host/path only — query strings, fragments and credentials
    (which may carry tokens) are dropped. Used in every message/log line."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        return f"{parts.scheme}://{host}{parts.path}"[:200]
    except ValueError:
        return "<invalid url>"


class WebError(Exception):
    """Base for the web subsystem. Messages are SAFE BY CONSTRUCTION: they
    are built from fixed text, status codes and `safe_url()` values — never
    from headers, cookies, API keys, environment values or raw exception
    text — because they can be shown to the model and persisted."""


class SearchError(WebError):
    pass


class FetchError(WebError):
    pass


class ExtractionError(WebError):
    pass


class InvalidWebURL(WebError):
    pass


class UnsafeWebTarget(WebError):
    pass


class WebProviderError(WebError):
    pass


class WebConfigurationError(WebError):
    pass


class WebLimitExceeded(WebError):
    pass

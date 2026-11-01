from __future__ import annotations

from app.web.errors import safe_url  # re-exported: scheme://host/path only


class BrowserError(Exception):
    """Base for the browser subsystem. Messages are SAFE BY CONSTRUCTION (fixed text and
    `safe_url()` values only), because they can be shown to the model and persisted."""


class BrowserUnavailableError(BrowserError):
    """Optional dependency / binary missing, or capability not configured."""


class BrowserStartupError(BrowserError):
    pass


class BrowserNavigationError(BrowserError):
    pass


class BrowserTimeoutError(BrowserNavigationError):
    pass


class BlockedURLError(BrowserError):
    """The URL (or a redirect/subresource target) violates the navigation policy."""


class PolicyViolationError(BrowserError):
    """An interaction was denied by the (deny-by-default) action policy."""


class BrowserCrashedError(BrowserError):
    pass


class BrowserLimitError(BrowserError):
    pass


class ScreenshotError(BrowserError):
    pass


class ElementNotFoundError(BrowserError):
    pass


__all__ = [n for n in dir() if n.endswith("Error")] + ["safe_url"]

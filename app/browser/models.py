from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class BrowserLimits(BaseModel):
    """Server-side bounds. Model-supplied values are only ever clamped DOWN to these."""

    model_config = {"frozen": True}

    navigation_timeout: float = Field(default=20.0, gt=0, le=120)
    action_timeout: float = Field(default=10.0, gt=0, le=60)
    max_actions: int = Field(default=30, ge=1, le=500)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_requests_per_page: int = Field(default=150, ge=1, le=2000)
    max_resource_bytes: int = Field(default=5_000_000, ge=10_000, le=50_000_000)
    max_total_bytes: int = Field(default=25_000_000, ge=10_000, le=200_000_000)
    max_text_chars: int = Field(default=8_000, ge=200, le=100_000)
    max_links: int = Field(default=50, ge=1, le=500)
    max_form_fields: int = Field(default=30, ge=1, le=200)
    screenshot_max_bytes: int = Field(default=400_000, ge=10_000, le=5_000_000)
    viewport_width: int = Field(default=1280, ge=320, le=2560)
    viewport_height: int = Field(default=800, ge=240, le=1600)
    idle_seconds: float = Field(default=300.0, gt=0, le=3600)
    allowed_ports: tuple[int, ...] = (80, 443)
    allowed_domains: tuple[str, ...] = ()
    javascript_enabled: bool = False
    no_sandbox: bool = False
    executable_path: Path | None = None
    max_screenshots_kept: int = 5

    @classmethod
    def from_settings(cls) -> "BrowserLimits":
        from app.config.settings import settings as s

        def _csv(v: str) -> list[str]:
            return [x.strip().lower() for x in v.split(",") if x.strip()]

        return cls(
            navigation_timeout=s.browser_navigation_timeout, action_timeout=s.browser_action_timeout,
            max_actions=s.browser_max_actions, max_redirects=s.browser_max_redirects,
            max_requests_per_page=s.browser_max_requests_per_page,
            max_resource_bytes=s.browser_max_resource_bytes, max_total_bytes=s.browser_max_total_bytes,
            max_text_chars=s.browser_max_text_chars, max_links=s.browser_max_links,
            max_form_fields=s.browser_max_form_fields, screenshot_max_bytes=s.browser_screenshot_max_bytes,
            viewport_width=s.browser_viewport_width, viewport_height=s.browser_viewport_height,
            idle_seconds=s.browser_idle_seconds,
            allowed_ports=tuple(int(p) for p in _csv(s.browser_allowed_ports) if p.isdigit()) or (80, 443),
            allowed_domains=tuple(_csv(s.browser_allowed_domains)),
            javascript_enabled=s.browser_javascript_enabled, no_sandbox=s.browser_no_sandbox,
            executable_path=s.browser_executable_path,
        )

    def clamp(self, requested: int | None, ceiling: int) -> int:
        if requested is None:
            return ceiling
        return max(0, min(int(requested), ceiling))


class LinkInfo(BaseModel):
    id: str
    text: str
    href: str  # absolute, query/fragment stripped for display
    allowed: bool = True
    reason: str | None = None


class FieldInfo(BaseModel):
    id: str
    kind: str  # text | search | email | url | tel | number | textarea | select | checkbox | radio | password | file | hidden | submit | other
    name: str | None = None
    label: str | None = None
    placeholder: str | None = None
    form_id: str | None = None
    form_method: str | None = None
    fillable: bool = False
    reason: str | None = None


class ClickableInfo(BaseModel):
    id: str
    tag: str
    text: str
    allowed: bool
    reason: str | None = None


class PageState(BaseModel):
    url: str
    title: str
    text: str
    text_truncated: bool = False
    redirects: int = 0
    blocked_requests: int = 0
    actions_used: int = 0
    actions_remaining: int = 0
    history_length: int = 0


class ScreenshotInfo(BaseModel):
    screenshot_id: str
    mime: str
    width: int
    height: int
    bytes: int

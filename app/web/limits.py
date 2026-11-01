from __future__ import annotations

from pydantic import BaseModel, Field


class WebLimits(BaseModel):
    """Server-side bounds for web research. Enforced independently of what
    a model asks for: requested values are only ever clamped DOWN to these.
    Field ceilings (`le=`) stop a misconfiguration from becoming absurd."""

    model_config = {"frozen": True}

    max_search_results: int = Field(default=10, ge=1, le=50)
    max_pages_to_fetch: int = Field(default=5, ge=0, le=20)
    max_response_bytes: int = Field(default=2_000_000, ge=1_000, le=20_000_000)
    max_document_chars: int = Field(default=8_000, ge=100, le=200_000)
    request_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_concurrent_fetches: int = Field(default=3, ge=1, le=10)
    max_tool_output_chars: int = Field(default=24_000, ge=1_000, le=500_000)

    @classmethod
    def from_settings(cls) -> "WebLimits":
        from app.config.settings import settings

        return cls(
            max_search_results=settings.web_max_results,
            max_pages_to_fetch=settings.web_max_pages,
            max_response_bytes=settings.web_max_response_bytes,
            max_document_chars=settings.web_max_document_chars,
            request_timeout_seconds=settings.web_request_timeout,
            max_redirects=settings.web_max_redirects,
            max_concurrent_fetches=settings.web_max_concurrent_fetches,
            max_tool_output_chars=settings.web_max_tool_output_chars,
        )

    def clamp(self, requested: int | None, ceiling: int) -> int:
        """`requested` (possibly model-chosen) bounded to [0, ceiling];
        None means "use the ceiling"."""
        if requested is None:
            return ceiling
        return max(0, min(int(requested), ceiling))

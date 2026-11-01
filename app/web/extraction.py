"""Deterministic content extraction. Standard library only (html.parser):
no JavaScript execution, no browser, no LLM. Tolerant of malformed markup."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, Field

from app.web.errors import ExtractionError

_SKIP_TAGS = {
    "script", "style", "noscript", "template", "svg", "iframe", "object", "embed",
    "canvas", "nav", "footer", "aside", "form",
}
_VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
}
_BLOCK_TAGS = {
    "p", "div", "section", "article", "main", "header", "ul", "ol", "table", "tr",
    "blockquote", "pre", "figure", "figcaption", "dl", "dt", "dd", "br", "hr",
}
_HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
_DATE_META = {
    "article:published_time", "datepublished", "date", "pubdate", "dc.date",
    "dc.date.issued", "publishdate",
}
_HTML_TYPES = {"text/html", "application/xhtml+xml"}
_TEXT_TYPES = {"text/plain", "text/markdown", "text/xml", "application/xml", "application/json"}
MAX_LINKS = 50
MAX_HEADINGS = 50


class ExtractedLink(BaseModel):
    url: str
    text: str = ""


class ExtractedContent(BaseModel):
    title: str | None = None
    text: str = ""
    headings: list[str] = Field(default_factory=list)
    links: list[ExtractedLink] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    truncated: bool = False


def normalize_whitespace(text: str) -> str:
    text = text.replace("\u00a0", " ").replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[ \t\f\v]+", " ", ln).strip() for ln in text.split("\n")]
    out: list[str] = []
    blank = False
    for ln in lines:
        if ln:
            out.append(ln)
            blank = False
        elif out and not blank:
            out.append("")
            blank = True
    return "\n".join(out).strip()


def truncate_text(text: str, max_chars: int) -> tuple[str, bool]:
    """Cut at max_chars on a whitespace boundary when one is close."""
    if len(text) <= max_chars:
        return text, False
    cut = text[:max_chars]
    boundary = max(cut.rfind("\n"), cut.rfind(" "))
    if boundary > max_chars * 0.8:
        cut = cut[:boundary]
    return cut.rstrip(), True


class _Parser(HTMLParser):
    def __init__(self, base_url: str | None) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.skip_depth = 0
        self.parts: list[str] = []
        self.title_parts: list[str] = []
        self.in_title = False
        self.heading_tag: str | None = None
        self.heading_parts: list[str] = []
        self.headings: list[str] = []
        self.links: list[ExtractedLink] = []
        self._link_href: str | None = None
        self._link_text: list[str] = []
        self.metadata: dict[str, str] = {}
        self.first_h1: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self.in_title = True
            return
        if tag == "meta":
            self._meta(a)
            return
        if tag == "link":
            if "canonical" in a.get("rel", "").lower().split() and a.get("href"):
                self.metadata.setdefault("canonical_url", a["href"][:500])
            return
        if tag in _VOID_TAGS:
            if tag in ("br", "hr") and not self.skip_depth:
                self.parts.append("\n")
            return
        if tag in _SKIP_TAGS:
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if self.heading_tag is not None and (tag in _HEADINGS or tag in _BLOCK_TAGS or tag == "li"):
            self.flush_heading()
        if tag in _HEADINGS:
            self.parts.append("\n\n")
            self.heading_tag = tag
            self.heading_parts = []
        elif tag == "li":
            self.parts.append("\n- ")
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n\n" if tag in ("p", "div", "section", "article", "blockquote", "pre") else "\n")
        elif tag == "a":
            href = a.get("href", "").strip()
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                self._link_href = href
                self._link_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
            return
        if tag in _SKIP_TAGS:
            if self.skip_depth:
                self.skip_depth -= 1
            return
        if self.skip_depth:
            return
        if tag in _HEADINGS and self.heading_tag == tag:
            self.flush_heading()
        elif self.heading_tag is not None and tag in _BLOCK_TAGS | {"body", "html", "li"}:
            self.flush_heading()  # malformed: heading never closed
            if tag in _BLOCK_TAGS:
                self.parts.append("\n")
        elif tag == "a" and self._link_href is not None:
            self._finish_link()
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def flush_heading(self) -> None:
        """Emit a pending heading (also used when markup leaves it unclosed)."""
        tag = self.heading_tag
        if tag is None:
            return
        text = normalize_whitespace(" ".join(self.heading_parts))
        if text:
            self.parts.append("#" * int(tag[1]) + " " + text + "\n\n")
            if len(self.headings) < MAX_HEADINGS:
                self.headings.append(text)
            if tag == "h1" and self.first_h1 is None:
                self.first_h1 = text
        self.heading_tag = None
        self.heading_parts = []

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
            return
        if self.skip_depth:
            return
        if self.heading_tag is not None:
            self.heading_parts.append(data)
            return
        self.parts.append(data)
        if self._link_href is not None:
            self._link_text.append(data)

    def _finish_link(self) -> None:
        href, text = self._link_href or "", normalize_whitespace(" ".join(self._link_text))
        self._link_href, self._link_text = None, []
        if len(self.links) >= MAX_LINKS:
            return
        try:
            absolute = urljoin(self.base_url, href) if self.base_url else href
            if urlsplit(absolute).scheme not in ("http", "https"):
                return
        except ValueError:
            return
        if all(link.url != absolute for link in self.links):
            self.links.append(ExtractedLink(url=absolute[:500], text=text[:100]))

    def _meta(self, a: dict[str, str]) -> None:
        key = (a.get("name") or a.get("property") or a.get("itemprop") or "").lower()
        content = a.get("content", "").strip()
        if not key or not content:
            return
        if key in ("description", "og:description"):
            self.metadata.setdefault("description", content[:500])
        elif key == "og:title":
            self.metadata.setdefault("og_title", content[:300])
        elif key == "og:site_name":
            self.metadata.setdefault("site_name", content[:200])
        elif key == "author":
            self.metadata.setdefault("author", content[:200])
        elif key in _DATE_META:
            self.metadata.setdefault("published", content[:64])


class HtmlExtractor:
    """Turns a fetched body into readable text + light structure.

    Headings become Markdown-style lines, list items become "- " lines,
    scripts/styles/nav/footer/forms etc. are dropped, whitespace is
    normalized and output is capped at `max_chars`.
    """

    def extract(
        self,
        content: str,
        content_type: str | None,
        max_chars: int,
        base_url: str | None = None,
    ) -> ExtractedContent:
        ctype = (content_type or "").split(";")[0].strip().lower()
        if ctype in _HTML_TYPES or (not ctype and "<" in content[:2000]):
            return self._extract_html(content, max_chars, base_url)
        if ctype in _TEXT_TYPES or not ctype:
            text, truncated = truncate_text(normalize_whitespace(content), max_chars)
            return ExtractedContent(text=text, truncated=truncated)
        raise ExtractionError(f"cannot extract text from content type '{ctype[:60]}'")

    def _extract_html(self, html: str, max_chars: int, base_url: str | None) -> ExtractedContent:
        parser = _Parser(base_url)
        try:
            parser.feed(html)
            parser.close()
            parser.flush_heading()
        except Exception as exc:  # noqa: BLE001 — html.parser is lenient, but never let it escape
            raise ExtractionError(f"could not parse HTML ({type(exc).__name__})") from exc
        title = normalize_whitespace(" ".join(parser.title_parts)) or None
        title = title or parser.metadata.get("og_title") or parser.first_h1
        text, truncated = truncate_text(normalize_whitespace("".join(parser.parts)), max_chars)
        return ExtractedContent(
            title=title[:300] if title else None,
            text=text,
            headings=parser.headings,
            links=parser.links,
            metadata=parser.metadata,
            truncated=truncated,
        )

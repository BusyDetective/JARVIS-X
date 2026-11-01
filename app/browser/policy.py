"""Browser safety policy. Everything here is enforced in code, never by model instructions.

URL policy reuses Phase 6's `UrlValidator` (SSRF boundary) unchanged and adds a port allow-list and an
optional domain allow-list. Interaction policy is DENY BY DEFAULT: only a small set of observation-like
interactions is allowed; anything that could change external state, submit credentials, pay, upload,
download, post, or solve a CAPTCHA is refused.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from app.browser.errors import BlockedURLError, PolicyViolationError, safe_url
from app.browser.models import BrowserLimits
from app.security.untrusted import redact_text
from app.web.errors import InvalidWebURL, UnsafeWebTarget
from app.web.urls import UrlValidator, ValidatedTarget

# Content types the browser will render. Everything else (archives, executables, PDFs,
# octet-stream, ...) is refused: no downloads.
_ALLOWED_EXACT = {
    "application/xhtml+xml", "application/xml", "application/json", "application/javascript",
    "application/x-javascript", "application/ld+json", "application/manifest+json", "image/svg+xml",
    "application/font-woff", "application/font-woff2", "application/vnd.ms-fontobject",
}
_ALLOWED_PREFIXES = ("text/", "image/", "font/")

# Words that suggest a state-changing or sensitive action. A SECOND layer of denial on top of the
# structural rules (a click is never assumed harmless because it looks like an ordinary button).
STATE_CHANGING = re.compile(
    r"(log[\s_-]?out|sign[\s_-]?out|log[\s_-]?in|sign[\s_-]?in|sign[\s_-]?up|register|create[\s_-]?account|"
    r"checkout|check[\s_-]?out|add[\s_-]?to[\s_-]?(cart|bag|basket)|\bbuy\b|purchase|\bpay\b|payment|donate|"
    r"subscribe|unsubscribe|delete|remove|cancel|confirm|submit|\bsend\b|\bpost\b|publish|tweet|share|"
    r"upload|download|install|authorize|allow|accept|consent|\border\b|reset[\s_-]?password|verify)",
    re.IGNORECASE,
)
CAPTCHA = re.compile(r"(captcha|recaptcha|hcaptcha|turnstile|g-recaptcha|cf-chl)", re.IGNORECASE)
CREDENTIAL_FIELD = re.compile(
    r"(pass(word|wd)?|pwd|otp|2fa|mfa|totp|token|secret|card|cc-|cvv|cvc|iban|ssn|pin\b|security[\s_-]?code|api[\s_-]?key)",
    re.IGNORECASE,
)
# Only these `<input type>` values / tags may be filled.
FILLABLE_KINDS = {"text", "search", "email", "url", "tel", "number", "textarea"}
SUBMIT_LIKE_KINDS = {"submit", "image", "reset", "button"}


def _host_matches(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


class BrowserPolicy:
    def __init__(self, limits: BrowserLimits, validator: UrlValidator | None = None) -> None:
        self.limits = limits
        self.validator = validator or UrlValidator()

    # --- URLs ---------------------------------------------------------------

    async def check_url(self, url: str) -> ValidatedTarget:
        """Validate a navigation or subresource URL. Raises BlockedURLError. The returned target carries
        the verified public addresses so the caller can connect to exactly those IPs."""
        try:
            normalized, scheme, host, port = self.validator.normalize(url)
        except (InvalidWebURL, UnsafeWebTarget) as exc:
            raise BlockedURLError(f"blocked URL: {exc}") from None
        if port not in self.limits.allowed_ports:
            raise BlockedURLError(f"blocked URL: port {port} is not allowed")
        if self.limits.allowed_domains and not _host_matches(host, self.limits.allowed_domains):
            raise BlockedURLError("blocked URL: domain is not in the configured allow-list")
        try:
            return await self.validator.validate(normalized)
        except (InvalidWebURL, UnsafeWebTarget) as exc:
            raise BlockedURLError(f"blocked URL: {exc}") from None

    @staticmethod
    def content_type_allowed(content_type: str | None, disposition: str | None = None) -> bool:
        if disposition and disposition.strip().lower().startswith("attachment"):
            return False
        ctype = (content_type or "").split(";")[0].strip().lower()
        if not ctype:
            return True  # browsers sniff; treated as document text only
        return ctype in _ALLOWED_EXACT or ctype.startswith(_ALLOWED_PREFIXES)

    # --- Links / clicks / fills ------------------------------------------------

    @staticmethod
    def display_url(url: str) -> str:
        """URL for display: credentials, query and fragment removed (they may carry tokens)."""
        return safe_url(url)

    def check_link(self, href: str, text: str, attrs: dict[str, str]) -> tuple[bool, str | None]:
        parts = urlsplit(href)
        if parts.scheme.lower() not in ("http", "https"):
            return False, "only http(s) links can be followed"
        if "download" in attrs:
            return False, "download links are not allowed"
        blob = f"{parts.path} {text} {attrs.get('title', '')} {attrs.get('aria-label', '')}"
        if CAPTCHA.search(blob + " " + attrs.get("class", "") + " " + attrs.get("id", "")):
            return False, "CAPTCHA elements are not allowed"
        if STATE_CHANGING.search(blob):
            return False, "link looks state-changing or account-related"
        return True, None

    def check_click(self, tag: str, attrs: dict[str, str], text: str, in_form: bool) -> tuple[bool, str | None]:
        """Deny-by-default. Allowed: disclosure widgets (<summary>) and non-form, non-submit
        buttons that merely toggle UI state (aria-expanded / aria-controls). Links are handled by
        follow_link; submit buttons, inputs, anything in a form, and anything state-changing-looking are refused."""
        blob = f"{text} {attrs.get('title', '')} {attrs.get('aria-label', '')} {attrs.get('name', '')} {attrs.get('id', '')} {attrs.get('class', '')}"
        if CAPTCHA.search(blob):
            return False, "CAPTCHA elements are not allowed"
        if tag == "a":
            return False, "use follow_link for links"
        if tag == "input":
            return False, "clicking form inputs is not allowed"
        if in_form:
            return False, "clicking controls inside forms is not allowed (could submit a form)"
        if STATE_CHANGING.search(blob):
            return False, "control looks state-changing"
        if tag == "summary":
            return True, None
        if tag == "button" or attrs.get("role") == "button":
            if attrs.get("type", "button").lower() in ("submit", "reset"):
                return False, "submit buttons are not allowed"
            if "aria-expanded" in attrs or "aria-controls" in attrs:
                return True, None
            return False, "only toggle-style buttons (aria-expanded/aria-controls) are allowed"
        return False, "this kind of element cannot be clicked"

    def check_field(self, kind: str, name: str | None, label: str | None, placeholder: str | None,
                    form_method: str | None, form_has_sensitive: bool, autocomplete: str | None) -> tuple[bool, str | None]:
        if kind in SUBMIT_LIKE_KINDS:
            return False, "buttons are not fillable"
        if kind in ("password", "file", "hidden"):
            return False, f"{kind} fields are not allowed"
        if kind not in FILLABLE_KINDS:
            return False, f"'{kind}' fields cannot be filled"
        blob = " ".join(x for x in (name, label, placeholder, autocomplete) if x)
        if CAPTCHA.search(blob):
            return False, "CAPTCHA fields are not allowed"
        if CREDENTIAL_FIELD.search(blob):
            return False, "credential/payment-looking fields are not allowed"
        if form_has_sensitive:
            return False, "forms containing password, file or payment fields are not allowed"
        if form_method and form_method.lower() == "post":
            return False, "fields in POST forms are not allowed"
        return True, None

    @staticmethod
    def check_fill_value(value: str) -> None:
        if len(value) > 500:
            raise PolicyViolationError("value is too long (max 500 characters)")
        if any(ord(c) < 0x20 and c not in "\t" for c in value):
            raise PolicyViolationError("value contains control characters")
        if redact_text(value)[1]:
            raise PolicyViolationError("value looks like a credential or secret and will not be typed")

    @staticmethod
    def strip_query(url: str) -> str:
        try:
            p = urlsplit(url)
            return urlunsplit((p.scheme, p.netloc.split("@")[-1], p.path, "", ""))
        except ValueError:
            return "<invalid url>"


__all__ = ["BrowserPolicy", "STATE_CHANGING", "CAPTCHA", "safe_url", "ValidatedTarget"]

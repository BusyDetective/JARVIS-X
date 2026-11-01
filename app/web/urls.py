"""Centralized URL / network safety (the SSRF boundary).

Every outbound web request in Phase 6 must go through `UrlValidator`.
Checks, in order: syntax and scheme -> embedded credentials -> blocked host
names -> numeric-obfuscated hosts -> DNS resolution -> EVERY resolved
address must be public. The validated addresses are returned so the
fetcher can connect to exactly those IPs (pinning), closing the window in
which DNS could change between "check" and "connect" (DNS rebinding).
Redirect targets are validated by the same code on every hop.

Conservative by design: if any resolved address is internal, the whole
target is refused. This is a safety boundary, not a scanner — it performs
no probing or enumeration.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from app.web.errors import InvalidWebURL, UnsafeWebTarget, safe_url

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

MAX_URL_LENGTH = 2048

_BLOCKED_NAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data"}
_BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".internal", ".localdomain", ".home.arpa", ".lan", ".intranet", ".corp",
)
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]+|[0-9]+)$", re.IGNORECASE)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_EXTRA_BLOCKED = (
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata (169.254.169.254)
    ipaddress.ip_network("fd00:ec2::/32"),  # AWS IPv6 metadata
)


def is_blocked_ip(ip: IPAddress) -> bool:
    """True for anything that is not a clearly public unicast address,
    including addresses that merely *embed* a private IPv4 (IPv4-mapped,
    6to4, Teredo, NAT64)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_blocked_ip(ip.ipv4_mapped)
        if ip.sixtofour is not None and is_blocked_ip(ip.sixtofour):
            return True
        if ip.teredo is not None and any(is_blocked_ip(p) for p in ip.teredo):
            return True
        if ip in _NAT64:
            return is_blocked_ip(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if (
        ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified
        or ip.is_multicast or ip.is_reserved
    ):
        return True
    if any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version):
        return True
    return not ip.is_global


class HostResolver(Protocol):
    async def resolve(self, host: str, port: int) -> list[str]: ...


class SystemResolver:
    """Resolves through the OS resolver (getaddrinfo) off the event loop."""

    async def resolve(self, host: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise InvalidWebURL(f"could not resolve host {host}") from exc
        seen: list[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in seen:
                seen.append(addr)
        return seen


@dataclass(frozen=True)
class ValidatedTarget:
    url: str  # normalized (fragment removed, host lower-cased/IDNA)
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]  # all verified-public addresses, resolver order


class UrlValidator:
    def __init__(self, resolver: HostResolver | None = None) -> None:
        self._resolver: HostResolver = resolver or SystemResolver()

    def normalize(self, url: str) -> tuple[str, str, str, int]:
        """Syntax-only validation. Returns (normalized_url, scheme, host, port)
        and raises InvalidWebURL / UnsafeWebTarget (name-based blocks)."""
        if not isinstance(url, str) or not url.strip():
            raise InvalidWebURL("URL is empty")
        url = url.strip()
        if len(url) > MAX_URL_LENGTH:
            raise InvalidWebURL("URL is too long")
        if any(ord(c) < 0x21 or ord(c) == 0x7F for c in url):
            raise InvalidWebURL("URL contains whitespace or control characters")
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise InvalidWebURL("URL is malformed") from exc
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise InvalidWebURL(f"unsupported URL scheme '{scheme or '(none)'}'; only http and https are allowed")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise InvalidWebURL("URLs with embedded credentials are not allowed")
        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            raise InvalidWebURL("URL has no host")
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise InvalidWebURL("URL host is not a valid domain name") from exc
        self._check_host_name(host)
        if port is None:
            port = 443 if scheme == "https" else 80
        netloc_host = f"[{host}]" if ":" in host else host
        default_port = 443 if scheme == "https" else 80
        netloc = netloc_host if port == default_port else f"{netloc_host}:{port}"
        normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
        return normalized, scheme, host, port

    async def validate(self, url: str) -> ValidatedTarget:
        normalized, scheme, host, port = self.normalize(url)
        literal = self._literal_ip(host)
        if literal is not None:
            addresses = [str(literal)]
        else:
            addresses = await self._resolver.resolve(host, port)
        if not addresses:
            raise InvalidWebURL(f"could not resolve host {host}")
        for addr in addresses:
            try:
                ip = ipaddress.ip_address(addr.split("%", 1)[0])
            except ValueError as exc:
                raise UnsafeWebTarget(f"host {host} resolved to an invalid address") from exc
            if is_blocked_ip(ip):
                raise UnsafeWebTarget(
                    f"refusing to fetch {safe_url(normalized)}: it resolves to a non-public address"
                )
        return ValidatedTarget(normalized, scheme, host, port, tuple(addresses))

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _literal_ip(host: str) -> IPAddress | None:
        try:
            return ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return None

    def _check_host_name(self, host: str) -> None:
        literal = self._literal_ip(host)
        if literal is not None:
            if is_blocked_ip(literal):
                raise UnsafeWebTarget("refusing to fetch a non-public IP address")
            return
        if host in _BLOCKED_NAMES or host.endswith(_BLOCKED_SUFFIXES):
            raise UnsafeWebTarget("refusing to fetch an internal host name")
        labels = host.split(".")
        # "2130706433", "0x7f.1", "0177.0.0.1": legacy numeric spellings of IPs.
        if all(_NUMERIC_LABEL.match(label) for label in labels):
            raise InvalidWebURL("numeric host spellings are not allowed; use a normal domain name")

"""
URL Validator for URL-Guard / PhishGuard AI.

Strictly validates and normalizes user-provided URLs string-only.
Never resolves DNS, never sends network probes, and never requests the URL.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit, urlunsplit


class URLValidationError(ValueError):
    """Raised when a URL fails string-level validation checks."""

    def __init__(self, message: str, code: str = "INVALID_URL"):
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass(frozen=True)
class ValidationResult:
    """Holds parsed and normalized URL components."""
    normalized_url: str
    raw_url: str
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    is_punycode: bool
    is_idn: bool
    has_non_ascii: bool
    is_ip: bool
    has_userinfo: bool


_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE_RE = re.compile(r"\s")


def _is_ip_address(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address (dotted, decimal, hex, or bracketed)."""
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    if clean_host.isdigit():
        try:
            num = int(clean_host)
            if 0 <= num <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass

    if clean_host.lower().startswith("0x"):
        try:
            num = int(clean_host, 16)
            if 0 <= num <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass

    return False


def validate_and_normalize_url(raw_url: str) -> ValidationResult:
    """Validate and normalize a URL strictly without network calls."""
    if not isinstance(raw_url, str):
        raise URLValidationError("URL must be a text string.", code="TYPE_ERROR")

    stripped = raw_url.strip()
    if not stripped:
        raise URLValidationError("URL cannot be empty.", code="EMPTY_URL")

    if len(stripped) > 2048:
        raise URLValidationError(
            f"URL exceeds maximum allowed length of 2048 characters (got {len(stripped)}).",
            code="EXCEEDS_MAX_LENGTH",
        )

    if _CONTROL_CHAR_RE.search(stripped):
        raise URLValidationError(
            "URL contains disallowed control characters.", code="CONTROL_CHAR_DETECTED"
        )

    if _WHITESPACE_RE.search(stripped):
        raise URLValidationError(
            "URL contains unencoded whitespace.", code="WHITESPACE_DETECTED"
        )

    try:
        parts = urlsplit(stripped)
    except Exception as exc:
        raise URLValidationError(f"Failed to parse URL: {exc}", code="PARSE_ERROR") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise URLValidationError(
            f"Unsupported scheme '{parts.scheme}'. URL-Guard only accepts 'http' or 'https'.",
            code="UNSUPPORTED_SCHEME",
        )

    netloc = parts.netloc
    if not netloc:
        raise URLValidationError(
            "URL must contain a valid host (e.g. https://example.com).", code="MISSING_HOST"
        )

    has_userinfo = "@" in netloc
    userinfo_prefix = ""
    host_port = netloc
    if has_userinfo:
        userinfo_prefix, _, host_port = netloc.rpartition("@")
        userinfo_prefix = userinfo_prefix + "@"

    host = host_port
    port: Optional[int] = None
    if ":" in host_port and not host_port.endswith("]"):
        last_colon = host_port.rfind(":")
        candidate_port = host_port[last_colon + 1 :]
        candidate_host = host_port[:last_colon]
        if candidate_port.isdigit():
            port_num = int(candidate_port)
            if 1 <= port_num <= 65535:
                port = port_num
                host = candidate_host
            else:
                raise URLValidationError(
                    f"Invalid port number: {port_num}. Port must be between 1 and 65535.",
                    code="INVALID_PORT",
                )

    if not host:
        raise URLValidationError("Hostname cannot be empty.", code="EMPTY_HOST")

    has_non_ascii = any(ord(ch) > 127 for ch in stripped)
    host_has_non_ascii = any(ord(ch) > 127 for ch in host)

    is_idn = False
    is_punycode = "xn--" in host.lower()

    if host_has_non_ascii:
        is_idn = True
        try:
            host = host.encode("idna").decode("ascii")
            is_punycode = True
        except Exception as exc:
            raise URLValidationError(
                f"Invalid Internationalized Domain Name (IDN): {exc}", code="INVALID_IDN"
            ) from exc

    host_lower = host.lower()
    is_ip = _is_ip_address(host_lower)

    if not is_ip:
        invalid_host_chars = set(host_lower) - set("abcdefghijklmnopqrstuvwxyz0123456789-._[]")
        if invalid_host_chars:
            raise URLValidationError(
                f"Hostname contains invalid characters: {''.join(invalid_host_chars)}",
                code="INVALID_HOST_CHARACTERS",
            )

    path = parts.path or "/"

    normalized_netloc = f"{userinfo_prefix}{host_lower}"
    if port is not None:
        if not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            normalized_netloc = f"{normalized_netloc}:{port}"

    normalized_url = urlunsplit((scheme, normalized_netloc, path, parts.query, parts.fragment))

    return ValidationResult(
        normalized_url=normalized_url,
        raw_url=raw_url,
        scheme=scheme,
        host=host_lower,
        port=port,
        path=path,
        query=parts.query,
        fragment=parts.fragment,
        is_punycode=is_punycode,
        is_idn=is_idn,
        has_non_ascii=has_non_ascii,
        is_ip=is_ip,
        has_userinfo=has_userinfo,
    )

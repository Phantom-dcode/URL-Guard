"""
Feature Extraction Engine for URL-Guard / PhishGuard AI.

Pure function extract_features(url: str) -> OrderedDict[str, Any].
Guaranteed offline, zero network requests, deterministic 34-feature extraction.
Imported identically by training scripts, evaluation, and inference.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter, OrderedDict
from typing import Any, Dict
from urllib.parse import parse_qsl, unquote, urlsplit

import tldextract

from app.validator import validate_and_normalize_url

# Pre-initialize offline tldextract extractor (uses built-in Public Suffix List snapshot)
_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)

# High-value targeted brands commonly mimicked in phishing campaigns
BRAND_TARGETS = frozenset({
    "google", "apple", "microsoft", "paypal", "amazon", "netflix", "facebook",
    "instagram", "chase", "wellsfargo", "binance", "coinbase", "bankofamerica",
    "ebay", "dropbox", "adobe", "walmart", "twitter", "linkedin", "steam",
    "roblox", "telegram", "whatsapp", "citibank", "dhl", "fedex", "usps",
})

# Suspicious security and credential harvesting keyword tokens
SUSPICIOUS_TOKENS = (
    "login", "verify", "secure", "account", "update", "signin", "banking",
    "wallet", "password", "confirm",
)

# Known URL shortener domains
SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorte.st", "tiny.cc", "rb.gy", "v.gd",
})

# High-risk, free, or historically high-abuse TLDs
HIGH_RISK_TLDS = frozenset({
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "fit", "work", "loan",
    "click", "country", "racing", "download", "stream", "science", "bid",
    "party", "win", "cricket", "trade", "accountant", "date", "faith",
    "review", "zip", "mov", "buzz", "surf", "live", "gdn", "men",
})

COMMON_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "mil", "int", "info",
})

RISKY_EXTENSIONS = (
    ".exe", ".scr", ".zip", ".apk", ".bat", ".cmd", ".iso", ".vbs",
    ".ps1", ".sh", ".msi", ".dll", ".hta", ".jar", ".reg", ".rar", ".7z",
)

_PERCENT_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
_DIGIT_RUNS_RE = re.compile(r"\d+")


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a given character string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _check_ip_host(host: str) -> bool:
    """Check if host string is a numeric or hexadecimal IP representation."""
    clean = host.strip("[]").lower()
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        pass

    if clean.isdigit():
        try:
            num = int(clean)
            if 0 <= num <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass

    if clean.startswith("0x"):
        try:
            num = int(clean, 16)
            if 0 <= num <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass

    parts = clean.split(".")
    if len(parts) == 4:
        valid_octets = 0
        for p in parts:
            if p.isdigit() and 0 <= int(p) <= 255:
                valid_octets += 1
            elif p.startswith("0x"):
                try:
                    v = int(p, 16)
                    if 0 <= v <= 255:
                        valid_octets += 1
                except ValueError:
                    pass
        if valid_octets == 4:
            return True

    return False


def extract_features(url: str) -> OrderedDict[str, Any]:
    """
    Extract a comprehensive 34-feature vector from a URL.

    Guarantees:
      - Pure function
      - Zero external network calls
      - Deterministic key ordering
    """
    try:
        val = validate_and_normalize_url(url)
        normalized_url = val.normalized_url
        scheme = val.scheme
        host = val.host
        port = val.port
        path = val.path
        query = val.query
        is_punycode_flag = 1 if val.is_punycode else 0
        has_non_ascii_flag = 1 if val.has_non_ascii else 0
    except Exception:
        normalized_url = url.strip()
        try:
            parts = urlsplit(normalized_url)
            scheme = parts.scheme.lower() if parts.scheme else "http"
            host = parts.netloc.lower()
            path = parts.path or "/"
            query = parts.query
        except Exception:
            scheme = "http"
            after = normalized_url.split("://", 1)[-1] if "://" in normalized_url else normalized_url
            host = after.split("/", 1)[0].split("?", 1)[0].lower()
            path = "/" + after.split("/", 1)[1].split("?", 1)[0] if "/" in after else "/"
            query = normalized_url.split("?", 1)[1] if "?" in normalized_url else ""

        if "@" in host:
            host = host.split("@")[-1]
        port = None
        if ":" in host and not host.endswith("]"):
            candidate = host.split(":")[-1]
            if candidate.isdigit():
                port = int(candidate)
                host = host.split(":")[0]
        is_punycode_flag = 1 if "xn--" in host else 0
        has_non_ascii_flag = 1 if any(ord(c) > 127 for c in url) else 0

    # Domain component decomposition via offline tldextract
    ext = _EXTRACTOR(host)
    subdomain = ext.subdomain.lower() if ext.subdomain else ""
    registered_domain = ext.domain.lower() if ext.domain else ""
    suffix = ext.suffix.lower() if ext.suffix else ""
    full_registered_domain = f"{registered_domain}.{suffix}" if suffix else registered_domain

    # 1-4: Length metrics
    url_len = len(normalized_url)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)

    # 5-8: Structural metrics
    dot_count = normalized_url.count(".")
    
    # Subdomain count: strip standard 'www' prefix so legitimate websites are not penalized
    clean_subdomain = re.sub(r"^www\.", "", subdomain)
    clean_subdomain = "" if clean_subdomain == "www" else clean_subdomain
    subdomain_count = len(clean_subdomain.split(".")) if clean_subdomain else 0

    clean_path_segments = [p for p in path.strip("/").split("/") if p]
    path_depth = len(clean_path_segments)
    try:
        query_param_count = len(parse_qsl(query, keep_blank_values=True)) if query else 0
    except Exception:
        query_param_count = query.count("&") + (1 if query else 0)

    # 9-16: Special character counts
    count_hyphen = normalized_url.count("-")
    count_at = normalized_url.count("@")
    count_question = normalized_url.count("?")
    count_ampersand = normalized_url.count("&")
    count_equal = normalized_url.count("=")
    count_percent = normalized_url.count("%")
    count_underscore = normalized_url.count("_")
    count_tilde = normalized_url.count("~")

    # 17: Path redirect / double slash check
    double_slash_in_path = 1 if "//" in path else 0

    # 18-20: Digit distributions
    digit_count_total = sum(c.isdigit() for c in normalized_url)
    digit_ratio = (digit_count_total / url_len) if url_len > 0 else 0.0
    host_hyphen_count = host.count("-")
    host_digit_count = sum(c.isdigit() for c in host)

    # 21-22: Host characteristics
    is_ip_host = 1 if _check_ip_host(host) else 0
    non_standard_port = 0
    if port is not None:
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            non_standard_port = 1

    # 23-25: Encoding indicators
    is_punycode = 1 if (is_punycode_flag or "xn--" in host) else 0
    has_non_ascii = 1 if has_non_ascii_flag else 0
    percent_encoded_count = len(_PERCENT_ENCODED_RE.findall(normalized_url))

    # 26: Suspicious keyword tokens in path, query, and subdomain
    lower_scope = f"{subdomain}/{path}/{query}".lower()
    suspicious_token_count = sum(lower_scope.count(token) for token in SUSPICIOUS_TOKENS)

    # 27: Brand mismatch heuristic (brand in subdomain or path, but NOT in registered domain)
    brand_mismatch = 0
    for brand in BRAND_TARGETS:
        in_suspicious_location = (brand in subdomain) or (brand in path.lower())
        if in_suspicious_location and (brand != registered_domain):
            brand_mismatch = 1
            break

    # 28: TLD Category: 0 = common generic, 1 = ccTLD, 2 = high-risk / abused
    tld_category = 0
    clean_suffix = suffix.split(".")[-1] if suffix else ""
    if clean_suffix in HIGH_RISK_TLDS:
        tld_category = 2
    elif len(clean_suffix) == 2 and clean_suffix.isalpha():
        tld_category = 1
    elif clean_suffix in COMMON_TLDS:
        tld_category = 0
    else:
        tld_category = 1

    # 29: Shortener detection
    is_shortener = 1 if full_registered_domain in SHORTENER_DOMAINS else 0

    # 30: Host Shannon Entropy
    host_entropy = round(_calculate_entropy(host), 4)

    # 31: Longest run of consecutive digits in URL
    digit_runs = _DIGIT_RUNS_RE.findall(normalized_url)
    longest_digit_run = max((len(r) for r in digit_runs), default=0)

    # 32: "https" or "http" token placed deceptively in host label
    if "https" in host:
        https_token_in_host = 1
    elif re.search(r"(?:^|[\.-])http(?:[\.-]|$)", host):
        https_token_in_host = 1
    else:
        https_token_in_host = 0

    # 33: Risky file extension
    lower_path = path.lower()
    risky_file_extension = 1 if any(lower_path.endswith(ext) or f"{ext}?" in lower_path for ext in RISKY_EXTENSIONS) else 0

    # 34: HTTPS protocol flag
    is_https = 1 if scheme == "https" else 0

    # Strictly ordered dictionary of 34 features
    features: OrderedDict[str, Any] = OrderedDict([
        ("url_length", url_len),
        ("host_length", host_len),
        ("path_length", path_len),
        ("query_length", query_len),
        ("dot_count", dot_count),
        ("subdomain_count", subdomain_count),
        ("path_depth", path_depth),
        ("query_param_count", query_param_count),
        ("count_hyphen", count_hyphen),
        ("count_at", count_at),
        ("count_question", count_question),
        ("count_ampersand", count_ampersand),
        ("count_equal", count_equal),
        ("count_percent", count_percent),
        ("count_underscore", count_underscore),
        ("count_tilde", count_tilde),
        ("double_slash_in_path", double_slash_in_path),
        ("digit_ratio", round(digit_ratio, 4)),
        ("host_hyphen_count", host_hyphen_count),
        ("host_digit_count", host_digit_count),
        ("is_ip_host", is_ip_host),
        ("non_standard_port", non_standard_port),
        ("is_punycode", is_punycode),
        ("has_non_ascii", has_non_ascii),
        ("percent_encoded_count", percent_encoded_count),
        ("suspicious_token_count", suspicious_token_count),
        ("brand_mismatch", brand_mismatch),
        ("tld_category", tld_category),
        ("is_shortener", is_shortener),
        ("host_entropy", host_entropy),
        ("longest_digit_run", longest_digit_run),
        ("https_token_in_host", https_token_in_host),
        ("risky_file_extension", risky_file_extension),
        ("is_https", is_https),
    ])

    return features

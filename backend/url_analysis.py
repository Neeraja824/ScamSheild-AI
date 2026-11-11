"""Local, non-network URL validation and heuristic analysis."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal, TypedDict
from urllib.parse import SplitResult, urlsplit


_HOST_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.IGNORECASE)
_SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly",
        "bitly.com",
        "buff.ly",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "rebrand.ly",
        "shorturl.at",
        "t.co",
        "tiny.cc",
        "tinyurl.com",
    }
)
_ACCOUNT_TERMS = frozenset(
    {"account", "login", "payment", "secure", "signin", "support", "update", "verify", "wallet"}
)


class URLAnalysis(TypedDict):
    risk_level: Literal["unverified", "caution"]
    risk_indicators: list[str]
    explanation: str
    warning_signs: list[str]
    recommendations: list[str]


def _validated_parts(url: str) -> tuple[SplitResult, str, bool]:
    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    normalized_url = url.strip()
    if not normalized_url:
        raise ValueError("URL must not be empty or whitespace.")
    if len(normalized_url) > 2048:
        raise ValueError("URL must be 2048 characters or fewer.")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in normalized_url):
        raise ValueError("URL must not contain whitespace or control characters.")
    if "\\" in normalized_url:
        raise ValueError("URL must not contain backslashes.")

    try:
        parts = urlsplit(normalized_url)
        hostname = parts.hostname
        parts.port
    except ValueError as error:
        raise ValueError("URL must have a valid HTTP or HTTPS hostname and port.") from error

    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        raise ValueError("URL must use HTTP or HTTPS and include a valid hostname.")
    if not hostname:
        raise ValueError("URL must include a valid hostname.")
    if parts.netloc.endswith(":"):
        raise ValueError("URL must not have an empty port.")

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False
        _validate_domain_name(hostname)

    return parts, hostname.lower().rstrip("."), is_ip_address


def _validate_domain_name(hostname: str) -> None:
    if "%" in hostname:
        raise ValueError("URL must include a valid hostname.")

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").rstrip(".")
    except UnicodeError as error:
        raise ValueError("URL must include a valid hostname.") from error

    if not ascii_hostname or len(ascii_hostname) > 253:
        raise ValueError("URL must include a valid hostname.")

    labels = ascii_hostname.split(".")
    if any(
        not label
        or len(label) > 63
        or not _HOST_LABEL_PATTERN.fullmatch(label)
        for label in labels
    ):
        raise ValueError("URL must include a valid hostname.")
    if len(labels) > 1 and all(label.isdigit() for label in labels):
        raise ValueError("URL must include a valid hostname.")


def validate_http_url(url: str) -> str:
    """Validate URL syntax and return the trimmed value without network access."""
    _validated_parts(url)
    return url.strip()


def analyze_url(url: str) -> URLAnalysis:
    """Describe basic URL patterns without opening or verifying the URL."""
    parts, hostname, is_ip_address = _validated_parts(url)
    indicators: list[str] = []
    warning_signs: list[str] = []

    if is_ip_address:
        indicators.append("ip_address_host")
        warning_signs.append("The hostname is an IP address rather than a named domain.")

    labels = hostname.split(".")
    if not is_ip_address and len(labels) >= 5:
        indicators.append("excessive_subdomains")
        warning_signs.append("The hostname has several nested labels or subdomains.")

    if "@" in parts.netloc:
        indicators.append("at_symbol_in_authority")
        warning_signs.append(
            "The URL authority contains '@', which can obscure the actual hostname."
        )

    if any(
        hostname == domain or hostname.endswith(f".{domain}")
        for domain in _SHORTENER_DOMAINS
    ):
        indicators.append("url_shortener")
        warning_signs.append(
            "The hostname belongs to a URL-shortening service, so the final destination is not visible here."
        )

    ascii_hostname = hostname.encode("idna").decode("ascii")
    if "xn--" in ascii_hostname:
        indicators.append("internationalized_domain")
        warning_signs.append(
            "The hostname contains an encoded internationalized domain label that may be hard to distinguish visually."
        )

    if hostname.count("-") >= 3:
        indicators.append("many_hyphens")
        warning_signs.append("The hostname contains several hyphens, an unusual pattern worth checking.")

    hostname_terms = re.split(r"[.-]", hostname)
    if any(term in hostname_terms for term in _ACCOUNT_TERMS):
        indicators.append("account_related_hostname")
        warning_signs.append(
            "The hostname includes account, login, payment, or verification-related wording."
        )

    if indicators:
        risk_level: Literal["unverified", "caution"] = "caution"
        explanation = (
            "This URL has patterns worth checking, but those patterns do not prove it is malicious. "
            "It remains unverified: the URL was not opened, visited, or checked against a reputation service. "
            "This basic pattern review is not a complete phishing detector."
        )
    else:
        risk_level = "unverified"
        explanation = (
            "No checked suspicious patterns were found, but this URL remains unverified. "
            "It was not opened, visited, or checked against a reputation service. "
            "This basic pattern review is not a complete phishing detector."
        )

    recommendations = [
        "If you were not expecting this link, do not open it; verify the sender through a separate trusted channel.",
        "Check the hostname carefully and navigate to an organization’s official site independently when in doubt.",
        "Do not enter passwords, payment details, or verification codes on a page reached from an unexpected link.",
    ]
    if "url_shortener" in indicators:
        recommendations.insert(
            0,
            "Treat the destination as unknown because shortened links hide the final hostname.",
        )

    return {
        "risk_level": risk_level,
        "risk_indicators": indicators,
        "explanation": explanation,
        "warning_signs": warning_signs,
        "recommendations": recommendations,
    }

"""HTTP security headers inspector and analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

STANDARD_SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

HEADER_RECOMMENDATIONS: dict[str, str] = {
    "Strict-Transport-Security": (
        "Add 'Strict-Transport-Security' (HSTS) header to enforce secure HTTPS connections."
    ),
    "Content-Security-Policy": (
        "Add 'Content-Security-Policy' (CSP) header to mitigate XSS and data injection attacks."
    ),
    "X-Frame-Options": (
        "Add 'X-Frame-Options' header (DENY or SAMEORIGIN) to protect against clickjacking attacks."
    ),
    "X-Content-Type-Options": (
        "Add 'X-Content-Type-Options: nosniff' header to prevent MIME-type sniffing."
    ),
    "Referrer-Policy": (
        "Add 'Referrer-Policy' header to control how much referrer information is sent with requests."
    ),
    "Permissions-Policy": (
        "Add 'Permissions-Policy' header to restrict browser features and APIs."
    ),
}


@dataclass
class HeadersReport:
    """Report containing security headers analysis."""

    url: str
    status_code: int
    present_headers: dict[str, str] = field(default_factory=dict)
    missing_headers: list[str] = field(default_factory=list)
    security_score: str = "F"
    recommendations: list[str] = field(default_factory=list)


def _compute_score(present_count: int, total_count: int) -> str:
    """Calculate letter grade security score based on header coverage."""
    if total_count == 0:
        return "F"
    ratio = present_count / total_count
    if ratio >= 0.9:
        return "A"
    if ratio >= 0.8:
        return "B"
    if ratio >= 0.6:
        return "C"
    if ratio >= 0.4:
        return "D"
    return "F"


def check_security_headers(
    url: str,
    timeout: float = 10.0,
) -> HeadersReport:
    """Inspect the HTTP security headers of a given URL.

    Args:
        url: The website URL to check. Defaults to https:// if scheme is missing.
        timeout: Request timeout in seconds.

    Returns:
        HeadersReport containing present headers, missing headers, score, and recommendations.
    """
    target_url = url
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    resp = requests.get(target_url, timeout=timeout, allow_redirects=True)

    final_url = (
        resp.url
        if hasattr(resp, "url") and isinstance(resp.url, str) and resp.url
        else target_url
    )

    # Normalize response headers to lowercase for case-insensitive lookup
    resp_headers_lower: dict[str, str] = {
        str(k).lower(): str(v) for k, v in resp.headers.items()
    }

    present_headers: dict[str, str] = {}
    missing_headers: list[str] = []
    recommendations: list[str] = []

    for header in STANDARD_SECURITY_HEADERS:
        header_lower = header.lower()
        if header_lower in resp_headers_lower:
            present_headers[header] = resp_headers_lower[header_lower]
        else:
            missing_headers.append(header)
            rec = HEADER_RECOMMENDATIONS.get(header)
            if rec:
                recommendations.append(rec)

    score = _compute_score(len(present_headers), len(STANDARD_SECURITY_HEADERS))

    return HeadersReport(
        url=final_url,
        status_code=resp.status_code,
        present_headers=present_headers,
        missing_headers=missing_headers,
        security_score=score,
        recommendations=recommendations,
    )


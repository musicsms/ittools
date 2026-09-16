"""Tests for HTTP security headers analyzer."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from ittools.core.ssl_check import HeadersReport, check_security_headers


def test_check_security_headers_present_and_missing():
    """Test standard header presence, missing headers, and recommendations."""
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
        }
        mock_get.return_value = mock_resp

        report = check_security_headers("https://example.com")
        assert report.status_code == 200
        assert report.url == "https://example.com"
        assert "Strict-Transport-Security" in report.present_headers
        assert "X-Frame-Options" in report.present_headers
        assert "Content-Security-Policy" in report.missing_headers
        assert "X-Content-Type-Options" in report.missing_headers
        assert "Referrer-Policy" in report.missing_headers
        assert "Permissions-Policy" in report.missing_headers
        assert len(report.recommendations) == 4
        # 2 out of 6 present -> score F
        assert report.security_score == "F"


def test_check_security_headers_all_present():
    """Test when all 6 security headers are present giving score A."""
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
        mock_get.return_value = mock_resp

        report = check_security_headers("https://secure.example.com")
        assert len(report.present_headers) == 6
        assert len(report.missing_headers) == 0
        assert report.security_score == "A"
        assert len(report.recommendations) == 0


def test_check_security_headers_case_insensitivity():
    """Test that header names in lower case from server are properly matched."""
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'none'",
            "x-frame-options": "deny",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        }
        mock_get.return_value = mock_resp

        report = check_security_headers("https://example.com")
        assert "Strict-Transport-Security" in report.present_headers
        assert "Content-Security-Policy" in report.present_headers
        assert "X-Frame-Options" in report.present_headers
        assert "X-Content-Type-Options" in report.present_headers
        assert "Referrer-Policy" in report.present_headers
        assert "Permissions-Policy" in report.missing_headers
        # 5 out of 6 present -> score B
        assert report.security_score == "B"
        assert len(report.recommendations) == 1


def test_check_security_headers_scores():
    """Test security scores across different counts of present headers."""
    cases = [
        (6, "A"),
        (5, "B"),
        (4, "C"),
        (3, "D"),
        (2, "F"),
        (1, "F"),
        (0, "F"),
    ]
    all_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    for count, expected_score in cases:
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {h: "test" for h in all_headers[:count]}
            mock_get.return_value = mock_resp

            report = check_security_headers("https://example.com")
            assert report.security_score == expected_score, (
                f"Expected score {expected_score} for {count} headers, got {report.security_score}"
            )


def test_check_security_headers_url_without_scheme():
    """Test that URL without scheme defaults to https://."""
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        report = check_security_headers("example.com")
        mock_get.assert_called_once_with("https://example.com", timeout=10.0, allow_redirects=True)
        assert report.url == "https://example.com"

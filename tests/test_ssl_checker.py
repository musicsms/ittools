"""Tests for remote SSL/TLS network inspector."""

import datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ittools.core.ssl_check import SSLReport, check_remote_ssl
from ittools.core.ssl_check.checker import _fetch_peer_cert_and_info


def test_check_remote_ssl_logic():
    """Test remote SSL check logic with mocked peer cert info."""
    with patch("ittools.core.ssl_check.checker._fetch_peer_cert_and_info") as mock_fetch:
        mock_fetch.return_value = {
            "subject": "CN=example.com",
            "issuer": "CN=DigiCert Global Root CA",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=60)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days_remaining": 60,
            "is_expired": False,
            "sans": ["example.com", "www.example.com"],
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
        }
        report = check_remote_ssl("example.com")
        assert report.host == "example.com"
        assert report.port == 443
        assert report.days_remaining == 60
        assert report.is_expired is False
        assert "www.example.com" in report.sans
        assert report.tls_version == "TLSv1.3"
        assert report.cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert report.warning is None


def test_check_remote_ssl_expiring_soon():
    """Test warning generation when days remaining < 30."""
    with patch("ittools.core.ssl_check.checker._fetch_peer_cert_and_info") as mock_fetch:
        mock_fetch.return_value = {
            "subject": "CN=expiring.com",
            "issuer": "CN=Let's Encrypt Authority X3",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=15)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days_remaining": 15,
            "is_expired": False,
            "sans": ["expiring.com"],
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
        }
        report = check_remote_ssl("expiring.com")
        assert report.is_expired is False
        assert report.days_remaining == 15
        assert report.warning is not None
        assert "15 days remaining" in report.warning


def test_check_remote_ssl_expired():
    """Test warning generation when certificate is already expired."""
    with patch("ittools.core.ssl_check.checker._fetch_peer_cert_and_info") as mock_fetch:
        mock_fetch.return_value = {
            "subject": "CN=expired.com",
            "issuer": "CN=Old Root CA",
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_to": "2026-01-01T00:00:00Z",
            "days_remaining": -10,
            "is_expired": True,
            "sans": ["expired.com"],
            "tls_version": "TLSv1.2",
            "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
        }
        report = check_remote_ssl("expired.com")
        assert report.is_expired is True
        assert report.warning is not None
        assert "expired" in report.warning.lower()


def test_fetch_peer_cert_and_info_der_parsing():
    """Test _fetch_peer_cert_and_info with a synthetic DER certificate."""
    # Generate an in-memory certificate for mock socket testing
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("test.local"),
                x509.DNSName("alt.test.local"),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives import serialization
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = der_bytes
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_ssock

    with (
        patch("socket.create_connection") as mock_create_conn,
        patch("ssl.create_default_context", return_value=mock_context),
    ):
        mock_create_conn.return_value.__enter__.return_value = mock_sock
        mock_create_conn.return_value.__exit__.return_value = False

        info = _fetch_peer_cert_and_info("test.local", 443, 5.0)

        assert "CN=test.local" in info["subject"]
        assert "CN=test.local" in info["issuer"]
        assert info["days_remaining"] >= 88
        assert info["is_expired"] is False
        assert "alt.test.local" in info["sans"]
        assert info["tls_version"] == "TLSv1.3"
        assert info["cipher_suite"] == "TLS_AES_256_GCM_SHA384"


def test_fetch_peer_cert_no_cert_raises():
    """Test that missing DER certificate raises ValueError."""
    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = None
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_ssock

    with (
        patch("socket.create_connection") as mock_create_conn,
        patch("ssl.create_default_context", return_value=mock_context),
    ):
        mock_create_conn.return_value.__enter__.return_value = mock_sock
        with pytest.raises(ValueError, match="No peer certificate"):
            _fetch_peer_cert_and_info("empty.local", 443, 5.0)


def test_fetch_peer_cert_verification_error_fallback():
    """Test fallback to unverified context when SSLCertVerificationError occurs."""
    import ssl
    from cryptography.hazmat.primitives import serialization

    # Generate synthetic certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "untrusted.local"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now - datetime.timedelta(days=1))  # Expired
        .sign(private_key, hashes.SHA256())
    )
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    mock_sock = MagicMock()

    # Verified context raises SSLCertVerificationError
    mock_default_ctx = MagicMock()
    mock_default_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired"
    )

    # Insecure context succeeds
    mock_insecure_ssock = MagicMock()
    mock_insecure_ssock.getpeercert.return_value = der_bytes
    mock_insecure_ssock.version.return_value = "TLSv1.3"
    mock_insecure_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_insecure_ssock.__enter__.return_value = mock_insecure_ssock
    mock_insecure_ssock.__exit__.return_value = False

    mock_insecure_ctx = MagicMock()
    mock_insecure_ctx.wrap_socket.return_value = mock_insecure_ssock

    with (
        patch("socket.create_connection") as mock_create_conn,
        patch("ssl.create_default_context", return_value=mock_default_ctx),
        patch("ssl._create_unverified_context", return_value=mock_insecure_ctx),
    ):
        mock_create_conn.return_value.__enter__.return_value = mock_sock
        mock_create_conn.return_value.__exit__.return_value = False

        report = check_remote_ssl("untrusted.local", 443, 5.0)

        assert report.is_valid_chain is False
        assert report.is_expired is True
        assert report.days_remaining < 0
        assert "untrusted.local" in report.subject
        assert "certificate verify failed" in report.warning
        assert "Certificate has expired" in report.warning


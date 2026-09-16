"""Tests for PKI CSR generation and decoding."""

import pytest
from cryptography import x509

from ittools.core.pki.csr import (
    CSRDetails,
    CSRResult,
    CSRSubject,
    decode_csr,
    generate_csr,
    sanitize_name,
)


def test_sanitize_name():
    assert sanitize_name("example.com") == "example.com"
    assert sanitize_name("*.example.com") == "wildcard.example.com"
    assert sanitize_name("*.sub.domain.co") == "wildcard.sub.domain.co"


def test_sanitize_name_unsafe_chars():
    assert sanitize_name("foo/bar") == "foo_bar"
    assert sanitize_name(r"foo\bar") == "foo_bar"
    assert sanitize_name(".") == "_"
    assert sanitize_name("..") == "_"
    assert sanitize_name("") == "_"


def test_generate_and_decode_csr():
    subj = CSRSubject(
        common_name="example.com",
        organization="Acme Corp",
        organizational_unit="SecOps",
        city="Hanoi",
        state="Hanoi",
        country="VN",
        email="admin@example.com",
    )
    result = generate_csr(subj, sans=["example.com", "www.example.com"], key_size=2048)
    assert (
        "-----BEGIN RSA PRIVATE KEY-----" in result.private_key_pem
        or "-----BEGIN PRIVATE KEY-----" in result.private_key_pem
    )
    assert "-----BEGIN CERTIFICATE REQUEST-----" in result.csr_pem
    assert result.sanitized_cn == "example.com"

    details = decode_csr(result.csr_pem)
    assert details.common_name == "example.com"
    assert details.organization == "Acme Corp"
    assert details.country == "VN"
    assert "www.example.com" in details.sans
    assert details.key_size == 2048
    assert details.key_type == "RSA"
    assert details.signature_algorithm != ""


def test_generate_csr_defaults():
    subj = CSRSubject(common_name="test.com")
    result = generate_csr(subj)
    assert isinstance(result, CSRResult)
    assert result.sanitized_cn == "test.com"

    details = decode_csr(result.csr_pem)
    assert isinstance(details, CSRDetails)
    assert details.common_name == "test.com"
    assert details.organization == ""
    assert details.country == ""
    assert details.sans == []
    assert details.key_size == 2048


def test_generate_csr_extensions():
    subj = CSRSubject(common_name="secure.example.com")
    result = generate_csr(subj, sans=["secure.example.com"])
    csr = x509.load_pem_x509_csr(result.csr_pem.encode("utf-8"))

    # Verify Key Usage extension is present and critical
    ku_ext = csr.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
    assert ku_ext.critical is True
    assert ku_ext.value.digital_signature is True
    assert ku_ext.value.key_encipherment is True

    # Verify Extended Key Usage extension is present and not critical
    eku_ext = csr.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
    assert eku_ext.critical is False
    assert x509.ExtendedKeyUsageOID.SERVER_AUTH in eku_ext.value
    assert x509.ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value


def test_generate_csr_invalid_inputs():
    with pytest.raises(ValueError, match="common_name is required"):
        generate_csr(CSRSubject(common_name=""))

    with pytest.raises(ValueError, match="Country must be a 2-letter ISO code"):
        generate_csr(CSRSubject(common_name="test.com", country="USA"))

    with pytest.raises(ValueError, match="key_size must be at least 512"):
        generate_csr(CSRSubject(common_name="test.com"), key_size=256)


def test_decode_csr_invalid():
    with pytest.raises(ValueError, match="Could not parse CSR PEM"):
        decode_csr("NOT A VALID CSR")

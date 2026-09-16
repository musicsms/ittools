"""Tests for PKI key and certificate/CSR matcher."""

import datetime
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ittools.core.pki.csr import CSRSubject, generate_csr
from ittools.core.pki.matcher import MatchResult, match_key_and_cert


def test_match_key_and_csr_success():
    subj = CSRSubject(common_name="test.com")
    res1 = generate_csr(subj, key_size=2048)
    match = match_key_and_cert(res1.private_key_pem, res1.csr_pem)
    assert isinstance(match, MatchResult)
    assert match.matched is True
    assert match.key_hash == match.cert_hash
    assert len(match.key_hash) == 64
    assert "match" in match.message.lower()


def test_match_key_and_csr_mismatch():
    res1 = generate_csr(CSRSubject(common_name="test1.com"), key_size=2048)
    res2 = generate_csr(CSRSubject(common_name="test2.com"), key_size=2048)
    match = match_key_and_cert(res1.private_key_pem, res2.csr_pem)
    assert isinstance(match, MatchResult)
    assert match.matched is False
    assert match.key_hash != match.cert_hash
    assert len(match.key_hash) == 64
    assert len(match.cert_hash) == 64


def test_match_key_and_cert_success():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "cert.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "cert.test")]))
        .public_key(key.public_key())
        .serial_number(1001)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    match = match_key_and_cert(key_pem, cert_pem)
    assert match.matched is True
    assert match.key_hash == match.cert_hash


def test_match_key_and_cert_mismatch():
    key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key1_pem = key1.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    now = datetime.datetime.now(datetime.timezone.utc)
    cert2 = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "cert2.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "cert2.test")]))
        .public_key(key2.public_key())
        .serial_number(1002)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key2, hashes.SHA256())
    )
    cert2_pem = cert2.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    match = match_key_and_cert(key1_pem, cert2_pem)
    assert match.matched is False
    assert match.key_hash != match.cert_hash


def test_match_invalid_inputs():
    with pytest.raises(ValueError, match="Could not parse private key PEM"):
        match_key_and_cert("invalid key", "invalid cert")

    res = generate_csr(CSRSubject(common_name="valid.com"))
    with pytest.raises(ValueError, match="Could not parse certificate or CSR PEM"):
        match_key_and_cert(res.private_key_pem, "invalid cert or csr")

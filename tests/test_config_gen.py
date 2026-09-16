"""Tests for server TLS configuration generator."""

import pytest
from ittools.core.config_gen.generator import generate_server_config


def test_generate_nginx_config():
    cfg = generate_server_config(
        server="nginx",
        profile="intermediate",
        domain="example.com",
        cert_path="/etc/ssl/certs/example.com.crt",
        key_path="/etc/ssl/private/example.com.key",
        hsts=True,
    )
    assert "server_name example.com;" in cfg
    assert "ssl_certificate /etc/ssl/certs/example.com.crt;" in cfg
    assert "ssl_certificate_key /etc/ssl/private/example.com.key;" in cfg
    assert "Strict-Transport-Security" in cfg
    assert "listen 443 ssl http2;" in cfg
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in cfg
    assert "ssl_ciphers " in cfg
    assert "ssl_session_timeout" in cfg
    assert "ssl_session_cache" in cfg


def test_generate_nginx_modern_no_hsts():
    cfg = generate_server_config(
        server="nginx",
        profile="modern",
        domain="secure.example.org",
        cert_path="/certs/cert.pem",
        key_path="/keys/key.pem",
        hsts=False,
    )
    assert "server_name secure.example.org;" in cfg
    assert "ssl_certificate /certs/cert.pem;" in cfg
    assert "ssl_certificate_key /keys/key.pem;" in cfg
    assert "ssl_protocols TLSv1.3;" in cfg
    assert "Strict-Transport-Security" not in cfg


def test_generate_apache_config():
    cfg = generate_server_config(
        server="apache",
        domain="example.com",
        cert_path="/etc/cert.pem",
        key_path="/etc/key.pem",
    )
    assert "<VirtualHost *:443>" in cfg
    assert "SSLEngine on" in cfg
    assert "ServerName example.com" in cfg
    assert "SSLCertificateFile /etc/cert.pem" in cfg
    assert "SSLCertificateKeyFile /etc/key.pem" in cfg
    assert "SSLProtocol" in cfg
    assert "SSLCipherSuite" in cfg
    assert "Strict-Transport-Security" in cfg


def test_generate_apache_modern_no_hsts():
    cfg = generate_server_config(
        server="apache",
        profile="modern",
        domain="secure.apache.org",
        cert_path="/etc/ssl/cert.pem",
        key_path="/etc/ssl/key.pem",
        hsts=False,
    )
    assert "<VirtualHost *:443>" in cfg
    assert "SSLEngine on" in cfg
    assert "ServerName secure.apache.org" in cfg
    assert "SSLCertificateFile /etc/ssl/cert.pem" in cfg
    assert "SSLCertificateKeyFile /etc/ssl/key.pem" in cfg
    assert "SSLProtocol" in cfg
    assert "SSLCipherSuite" not in cfg
    assert "Strict-Transport-Security" not in cfg


def test_generate_caddy_config():
    cfg = generate_server_config(
        server="caddy",
        domain="example.com",
        cert_path="/etc/cert.pem",
        key_path="/etc/key.pem",
    )
    assert "example.com {" in cfg
    assert "tls /etc/cert.pem /etc/key.pem" in cfg
    assert "protocols tls1.2 tls1.3" in cfg
    assert 'header Strict-Transport-Security "max-age=63072000"' in cfg
    assert 'max-age=63072000;"' not in cfg


def test_generate_caddy_modern_no_hsts():
    cfg = generate_server_config(
        server="caddy",
        profile="modern",
        domain="secure.caddy.local",
        cert_path="/etc/ssl/caddy.crt",
        key_path="/etc/ssl/caddy.key",
        hsts=False,
    )
    assert "secure.caddy.local {" in cfg
    assert "tls /etc/ssl/caddy.crt /etc/ssl/caddy.key" in cfg
    assert "protocols tls1.3" in cfg
    assert "Strict-Transport-Security" not in cfg


def test_case_insensitivity():
    cfg_nginx = generate_server_config(server="NGINX", profile="INTERMEDIATE")
    assert "server_name example.com;" in cfg_nginx

    cfg_apache = generate_server_config(server="Apache", profile="Modern")
    assert "<VirtualHost *:443>" in cfg_apache

    cfg_caddy = generate_server_config(server="CADDY", profile="Intermediate")
    assert "example.com {" in cfg_caddy


def test_default_arguments():
    cfg = generate_server_config(server="nginx")
    assert "server_name example.com;" in cfg
    assert "ssl_certificate /etc/ssl/certs/cert.pem;" in cfg
    assert "ssl_certificate_key /etc/ssl/private/key.pem;" in cfg
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in cfg
    assert "Strict-Transport-Security" in cfg


def test_unsupported_server_raises_value_error():
    with pytest.raises(ValueError, match="Unsupported server"):
        generate_server_config(server="iis")

    with pytest.raises(ValueError, match="Unsupported server"):
        generate_server_config(server="haproxy")


def test_unsupported_profile_raises_value_error():
    with pytest.raises(ValueError, match="Unsupported profile"):
        generate_server_config(server="nginx", profile="old")

    with pytest.raises(ValueError, match="Unsupported profile"):
        generate_server_config(server="apache", profile="insecure")

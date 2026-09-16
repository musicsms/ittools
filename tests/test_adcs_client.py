"""Tests for ADCS Client service."""

import sys
from unittest.mock import MagicMock, patch
import pytest
import requests

from ittools.core.adcs.client import ADCSClient, ADCSResult
from ittools.core.adcs.exceptions import (
    ADCSError,
    ADCSAuthError,
    ADCSConnectionError,
    ADCSPendingError,
    ADCSRequestDeniedError,
)

FAKE_CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...fake...=\n-----END CERTIFICATE REQUEST-----\n"
FAKE_CERT = "-----BEGIN CERTIFICATE-----\nMIID...fakecert...=\n-----END CERTIFICATE-----\n"
FAKE_CA_P7B = "-----BEGIN PKCS7-----\nMIIF...fakep7b...=\n-----END PKCS7-----\n"


@patch("requests.Session")
def test_adcs_submit_csr_success(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    # Response 1: certfnsh.asp with ReqID in text
    resp_post = MagicMock()
    resp_post.status_code = 200
    resp_post.text = '<html><a href="certnew.cer?ReqID=105&Enc=b64">Certificate</a></html>'
    resp_post.headers = {"Content-Type": "text/html"}

    # Response 2: certnew.cer with cert PEM
    resp_get = MagicMock()
    resp_get.status_code = 200
    resp_get.text = FAKE_CERT
    resp_get.headers = {"Content-Type": "application/pkix-cert"}

    mock_session.post.return_value = resp_post
    mock_session.get.return_value = resp_get

    client = ADCSClient(server="ca.corp.local", username="admin", password="password", auth_method="basic")
    result = client.submit_csr(FAKE_CSR, template="WebServer", attributes="San:dns=web.corp.local\r\n")

    assert isinstance(result, ADCSResult)
    assert result.req_id == "105"
    assert result.cert_pem == FAKE_CERT

    # Verify post parameters
    mock_session.post.assert_called_once()
    call_args, call_kwargs = mock_session.post.call_args
    assert call_args[0] == "https://ca.corp.local/certsrv/certfnsh.asp"
    posted_data = call_kwargs["data"]
    assert posted_data["Mode"] == "newreq"
    assert posted_data["CertRequest"] == FAKE_CSR
    assert "CertificateTemplate:WebServer\r\nSan:dns=web.corp.local\r\n" in posted_data["CertAttrib"]


@patch("requests.Session")
def test_adcs_submit_csr_pending(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 200
    resp.text = "<html>Certificate Pending. Your Request Id is 999. You must wait for an administrator.</html>"
    mock_session.post.return_value = resp

    client = ADCSClient(server="ca.corp.local", username="admin", password="password", auth_method="basic")
    with pytest.raises(ADCSPendingError) as exc_info:
        client.submit_csr(FAKE_CSR, template="WebServer")

    assert exc_info.value.req_id == "999"
    assert "999" in str(exc_info.value)


@patch("requests.Session")
def test_adcs_submit_csr_denied(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<html>The disposition message is "Denied by Policy Module 0x80094800".</html>'
    mock_session.post.return_value = resp

    client = ADCSClient(server="ca.corp.local", username="admin", password="password", auth_method="basic")
    with pytest.raises(ADCSRequestDeniedError) as exc_info:
        client.submit_csr(FAKE_CSR, template="WebServer")

    assert "Denied by Policy Module" in str(exc_info.value)
    assert 'The disposition message is "Denied by Policy Module 0x80094800".' in exc_info.value.response_text


@patch("requests.Session")
def test_adcs_submit_csr_denied_generic(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 200
    resp.text = "<html>Unexpected denial or error without disposition message</html>"
    mock_session.post.return_value = resp

    client = ADCSClient(server="ca.corp.local", username="admin", password="password", auth_method="basic")
    with pytest.raises(ADCSRequestDeniedError) as exc_info:
        client.submit_csr(FAKE_CSR, template="WebServer")

    assert "Request was denied by ADCS server" in str(exc_info.value)


@patch("requests.Session")
def test_adcs_auth_error(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 401
    resp.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized", response=resp)
    mock_session.post.return_value = resp

    client = ADCSClient(server="ca.corp.local", username="admin", password="wrong", auth_method="basic")
    with pytest.raises(ADCSAuthError) as exc_info:
        client.submit_csr(FAKE_CSR)

    assert "401" in str(exc_info.value)


@patch("requests.Session")
def test_adcs_connection_error(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.post.side_effect = requests.ConnectionError("Failed to connect")

    client = ADCSClient(server="ca.invalid", username="admin", password="pwd", auth_method="basic")
    with pytest.raises(ADCSConnectionError):
        client.submit_csr(FAKE_CSR)


@patch("requests.Session")
def test_adcs_timeout_error(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.post.side_effect = requests.Timeout("Request timed out")

    client = ADCSClient(server="ca.invalid", username="admin", password="pwd", auth_method="basic")
    with pytest.raises(ADCSConnectionError):
        client.submit_csr(FAKE_CSR)


@patch("requests.Session")
def test_adcs_general_http_error(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 500
    resp.raise_for_status.side_effect = requests.HTTPError("500 Internal Server Error", response=resp)
    mock_session.post.return_value = resp

    client = ADCSClient(server="ca.corp.local", username="admin", password="pwd", auth_method="basic")
    with pytest.raises(ADCSError) as exc_info:
        client.submit_csr(FAKE_CSR)

    assert "HTTP request failed" in str(exc_info.value)


@patch("requests.Session")
def test_adcs_retrieve_cert(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 200
    resp.text = FAKE_CERT
    mock_session.get.return_value = resp

    client = ADCSClient(server="ca.corp.local")
    cert = client.retrieve_cert(req_id=42, encoding="b64")

    assert cert == FAKE_CERT
    mock_session.get.assert_called_once_with(
        "https://ca.corp.local/certsrv/certnew.cer",
        params={"ReqID": "42", "Enc": "b64"},
        timeout=30.0,
    )


@patch("requests.Session")
def test_adcs_get_ca_cert(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 200
    resp.text = FAKE_CA_P7B
    mock_session.get.return_value = resp

    client = ADCSClient(server="ca.corp.local")
    ca_cert = client.get_ca_cert(encoding="b64")

    assert ca_cert == FAKE_CA_P7B
    mock_session.get.assert_called_once_with(
        "https://ca.corp.local/certsrv/certnew.p7b",
        params={"ReqID": "CACert", "Enc": "b64"},
        timeout=30.0,
    )


@patch("requests.Session")
def test_adcs_ssl_verification_options(mock_session_cls):
    # Insecure=True
    mock_session1 = MagicMock()
    mock_session_cls.return_value = mock_session1
    client1 = ADCSClient(server="ca.corp.local", insecure=True)
    assert mock_session1.verify is False

    # ca_file provided
    mock_session2 = MagicMock()
    mock_session_cls.return_value = mock_session2
    client2 = ADCSClient(server="ca.corp.local", ca_file="/path/to/ca.pem")
    assert mock_session2.verify == "/path/to/ca.pem"


@patch("requests.Session")
def test_adcs_auth_setup_ntlm_fallback(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    # When requests_ntlm is not installed, auth_method='ntlm' falls back to basic auth
    with patch.dict(sys.modules, {"requests_ntlm": None}):
        client = ADCSClient(server="ca.corp.local", username="CORP\\user", password="secret", auth_method="ntlm")
        assert mock_session.auth == ("CORP\\user", "secret")


@patch("requests.Session")
def test_adcs_auth_setup_ntlm_available(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    mock_ntlm_module = MagicMock()
    mock_http_ntlm_auth = MagicMock()
    mock_ntlm_module.HttpNtlmAuth = mock_http_ntlm_auth

    with patch.dict(sys.modules, {"requests_ntlm": mock_ntlm_module}):
        client = ADCSClient(server="ca.corp.local", username="CORP\\user", password="secret", auth_method="ntlm")
        mock_http_ntlm_auth.assert_called_once_with("CORP\\user", "secret")
        assert mock_session.auth == mock_http_ntlm_auth.return_value


@patch("requests.Session")
def test_adcs_user_agent_header(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    client = ADCSClient(server="ca.corp.local")
    mock_session.headers.update.assert_called_once_with(
        {"User-Agent": "Mozilla/5.0 (compatible; ittools-adcs/0.2.0)"}
    )


@patch("requests.Session")
def test_adcs_no_auth_provided(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    client = ADCSClient(server="ca.corp.local")
    assert not hasattr(mock_session, "auth") or mock_session.auth != ("user", "pass")


@patch("requests.Session")
def test_adcs_retrieve_cert_error(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.get.side_effect = requests.ConnectionError("Connection dropped")

    client = ADCSClient(server="ca.corp.local")
    with pytest.raises(ADCSConnectionError):
        client.retrieve_cert(req_id=123)


@patch("requests.Session")
def test_adcs_get_ca_cert_error(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    resp = MagicMock()
    resp.status_code = 401
    resp.raise_for_status.side_effect = requests.HTTPError("401", response=resp)
    mock_session.get.return_value = resp

    client = ADCSClient(server="ca.corp.local")
    with pytest.raises(ADCSAuthError):
        client.get_ca_cert()


def test_adcs_server_normalization():
    c1 = ADCSClient(server="https://ca.domain.com/")
    assert c1.server == "ca.domain.com"
    c2 = ADCSClient(server="http://ca.domain.com:8443//")
    assert c2.server == "ca.domain.com:8443"


def test_adcs_pending_error_custom_message():
    err = ADCSPendingError(req_id="888", message="Custom pending status message")
    assert str(err) == "Custom pending status message"
    assert err.req_id == "888"



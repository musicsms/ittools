"""Client for Microsoft Active Directory Certificate Services Web Enrollment."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import NoReturn
import requests

from ittools.core.adcs.exceptions import (
    ADCSError,
    ADCSAuthError,
    ADCSConnectionError,
    ADCSPendingError,
    ADCSRequestDeniedError,
)



@dataclass(frozen=True)
class ADCSResult:
    """Result of an ADCS certificate issuance request."""

    req_id: str
    cert_pem: str
    chain_pem: str | None = None


class ADCSClient:
    """Client for ADCS Web Enrollment (/certsrv)."""

    def __init__(
        self,
        server: str,
        username: str | None = None,
        password: str | None = None,
        auth_method: str = "ntlm",
        ca_file: str | None = None,
        insecure: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.server = server
        self.username = username
        self.password = password
        self.auth_method = auth_method.lower()
        self.timeout = timeout
        self.session = requests.Session()

        if insecure:
            self.session.verify = False
        elif ca_file:
            self.session.verify = ca_file

        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (compatible; ittools-adcs/0.2.0)"}
        )
        self._setup_auth()

    def _setup_auth(self) -> None:
        if not self.username or self.password is None:
            return

        if self.auth_method == "ntlm":
            try:
                from requests_ntlm import HttpNtlmAuth

                self.session.auth = HttpNtlmAuth(self.username, self.password)
            except ImportError:
                # Fallback to basic auth if requests_ntlm not installed
                self.session.auth = (self.username, self.password)
        else:
            self.session.auth = (self.username, self.password)

    def _handle_request_error(self, exc: Exception) -> NoReturn:
        if isinstance(exc, requests.HTTPError):
            if exc.response is not None and exc.response.status_code == 401:
                raise ADCSAuthError(
                    "Authentication failed: invalid username or password (HTTP 401)"
                ) from exc
            raise ADCSError(f"HTTP request failed: {exc}") from exc
        if isinstance(exc, (requests.ConnectionError, requests.Timeout)):
            raise ADCSConnectionError(
                f"Connection to ADCS server '{self.server}' failed: {exc}"
            ) from exc
        raise ADCSError(f"Unexpected ADCS error: {exc}") from exc

    def submit_csr(
        self,
        csr_pem: str,
        template: str = "WebServer",
        attributes: str | None = None,
    ) -> ADCSResult:
        """Submit a CSR to the ADCS Web Enrollment page.

        Args:
            csr_pem: PEM formatted CSR string.
            template: ADCS certificate template name.
            attributes: Additional request attributes.

        Returns:
            ADCSResult containing req_id and cert_pem.
        """
        url = f"https://{self.server}/certsrv/certfnsh.asp"
        attrib = f"CertificateTemplate:{template}\r\n"
        if attributes:
            attrib += attributes

        data = {
            "Mode": "newreq",
            "CertRequest": csr_pem,
            "CertAttrib": attrib,
            "FriendlyType": "Saved-Request Certificate",
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
        }

        try:
            response = self.session.post(url, data=data, timeout=self.timeout)
            response.raise_for_status()
        except Exception as exc:
            self._handle_request_error(exc)

        # Parse Request ID
        text = response.text
        req_id_match = re.search(r"certnew\.cer\?ReqID=(\d+)&", text)
        if req_id_match:
            req_id = req_id_match.group(1)
            cert_pem = self.retrieve_cert(req_id)
            return ADCSResult(req_id=req_id, cert_pem=cert_pem)

        if "Certificate Pending" in text:
            pending_match = re.search(r"Your Request Id is (\d+)\.", text)
            pending_id = pending_match.group(1) if pending_match else "unknown"
            raise ADCSPendingError(pending_id)

        denied_match = re.search(r'The disposition message is "([^"]+)"', text)
        error_msg = (
            denied_match.group(1)
            if denied_match
            else "Request was denied by ADCS server"
        )
        raise ADCSRequestDeniedError(error_msg, text)

    def retrieve_cert(self, req_id: str | int, encoding: str = "b64") -> str:
        """Download an issued certificate by Request ID.

        Args:
            req_id: Request ID.
            encoding: 'b64' (PEM) or 'bin'.

        Returns:
            PEM encoded certificate string.
        """
        url = f"https://{self.server}/certsrv/certnew.cer"
        params = {"ReqID": str(req_id), "Enc": encoding}
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
        except Exception as exc:
            self._handle_request_error(exc)

        return response.text

    def get_ca_cert(self, encoding: str = "b64") -> str:
        """Download the ADCS CA certificate or chain."""
        url = f"https://{self.server}/certsrv/certnew.p7b"
        params = {"ReqID": "CACert", "Enc": encoding}
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
        except Exception as exc:
            self._handle_request_error(exc)

        return response.text

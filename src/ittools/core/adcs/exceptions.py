"""Exceptions for Microsoft ADCS integration."""


class ADCSError(Exception):
    """Base exception for ADCS operations."""


class ADCSConnectionError(ADCSError):
    """Network connection failure or timeout communicating with ADCS server."""


class ADCSAuthError(ADCSError):
    """Authentication to ADCS failed (e.g. HTTP 401)."""


class ADCSRequestDeniedError(ADCSError):
    """The ADCS server rejected or denied the certificate request."""

    def __init__(self, message: str, response_text: str = "") -> None:
        super().__init__(message)
        self.response_text = response_text


class ADCSPendingError(ADCSError):
    """The certificate request is pending CA administrator approval."""

    def __init__(self, req_id: str, message: str = "") -> None:
        super().__init__(f"Certificate request pending approval. Request ID: {req_id}")
        self.req_id = req_id

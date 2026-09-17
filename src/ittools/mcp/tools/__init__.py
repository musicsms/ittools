"""MCP tools collection for ittools."""

from ittools.mcp.tools.adcs import (
    adcs_ca_cert,
    adcs_retrieve,
    adcs_sign,
)
from ittools.mcp.tools.config import config_generate
from ittools.mcp.tools.keypair import (
    keypair_passphrase,
    keypair_pgp,
    keypair_rsa,
    keypair_ssh,
)
from ittools.mcp.tools.pki import (
    csr_decode,
    csr_generate,
    pfx_create,
    pfx_extract,
    ssl_match,
)
from ittools.mcp.tools.ssl import ssl_check, ssl_headers

__all__ = [
    "adcs_sign",
    "adcs_retrieve",
    "adcs_ca_cert",
    "csr_generate",
    "csr_decode",
    "pfx_create",
    "pfx_extract",
    "ssl_match",
    "keypair_passphrase",
    "keypair_rsa",
    "keypair_ssh",
    "keypair_pgp",
    "ssl_check",
    "ssl_headers",
    "config_generate",
]


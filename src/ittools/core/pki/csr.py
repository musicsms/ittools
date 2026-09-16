"""PKI CSR generation, sanitization, and decoding services."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ittools.core.keypair.rsa import generate_rsa_keypair


@dataclass
class CSRSubject:
    """Subject details for generating a Certificate Signing Request."""

    common_name: str
    organization: str = ""
    organizational_unit: str = ""
    city: str = ""
    state: str = ""
    country: str = ""
    email: str = ""


@dataclass
class CSRResult:
    """Result of CSR generation containing keys and sanitized common name."""

    private_key_pem: str
    csr_pem: str
    sanitized_cn: str


@dataclass
class CSRDetails:
    """Decoded information from a Certificate Signing Request."""

    common_name: str
    organization: str
    country: str
    sans: list[str] = field(default_factory=list)
    key_type: str = "RSA"
    key_size: int = 2048
    signature_algorithm: str = "sha256WithRSAEncryption"


def sanitize_name(cn: str) -> str:
    """Convert a Common Name into a filesystem-safe name.

    Replaces '*' with 'wildcard' and path separators with '_'.
    Replaces '.' or '..' or empty string with '_'.

    Args:
        cn: Common name to sanitize.

    Returns:
        Sanitized filesystem-safe name.
    """
    name = cn.replace("*", "wildcard")
    name = name.replace("/", "_")
    name = name.replace("\\", "_")
    if name in (".", "..", ""):
        return "_"
    return name


def generate_csr(
    subject: CSRSubject,
    sans: list[str] | None = None,
    key_size: int = 2048,
) -> CSRResult:
    """Generate an RSA private key and PKCS#10 Certificate Signing Request.

    The CSR includes Key Usage (Digital Signature, Key Encipherment) and
    Extended Key Usage (Server Auth, Client Auth).

    Args:
        subject: CSRSubject containing common name and optional organization details.
        sans: Optional list of Subject Alternative Names (DNS names or IP addresses).
        key_size: RSA bit length (minimum 512, default 2048).

    Returns:
        CSRResult containing private key PEM, CSR PEM, and sanitized common name.

    Raises:
        ValueError: If common_name is missing, country format is invalid, or key_size < 512.
    """
    cn = subject.common_name.strip()
    if not cn:
        raise ValueError("common_name is required")

    country = subject.country.strip().upper()
    if country:
        if len(country) != 2 or not country.isalpha():
            raise ValueError("Country must be a 2-letter ISO code")

    # Generate RSA keypair using core keypair service
    keypair = generate_rsa_keypair(key_size=key_size)
    private_key = serialization.load_pem_private_key(
        keypair.private_key_pem.encode("utf-8"),
        password=None,
    )

    # Build subject name attributes
    name_attributes: list[x509.NameAttribute] = [
        x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)
    ]
    if subject.organization.strip():
        name_attributes.append(
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, subject.organization.strip())
        )
    if subject.organizational_unit.strip():
        name_attributes.append(
            x509.NameAttribute(
                x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
                subject.organizational_unit.strip(),
            )
        )
    if subject.city.strip():
        name_attributes.append(
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, subject.city.strip())
        )
    if subject.state.strip():
        name_attributes.append(
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, subject.state.strip())
        )
    if country:
        name_attributes.append(
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country)
        )
    if subject.email.strip():
        name_attributes.append(
            x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, subject.email.strip())
        )

    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(name_attributes)
    )

    # Add SANs if specified
    if sans:
        san_entries: list[x509.GeneralName] = []
        for san in sans:
            s = san.strip()
            if not s:
                continue
            try:
                ip = ipaddress.ip_address(s)
                san_entries.append(x509.IPAddress(ip))
            except ValueError:
                san_entries.append(x509.DNSName(s))
        if san_entries:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )

    # Key Usage: Digital Signature + Key Encipherment (critical)
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    builder = builder.add_extension(key_usage, critical=True)

    # Extended Key Usage: Server Auth + Client Auth (not critical)
    ext_key_usage = x509.ExtendedKeyUsage(
        [
            x509.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]
    )
    builder = builder.add_extension(ext_key_usage, critical=False)

    csr = builder.sign(private_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    return CSRResult(
        private_key_pem=keypair.private_key_pem,
        csr_pem=csr_pem,
        sanitized_cn=sanitize_name(cn),
    )


def decode_csr(csr_pem: str) -> CSRDetails:
    """Parse a PEM-encoded Certificate Signing Request and extract its details.

    Args:
        csr_pem: PEM string of the CSR.

    Returns:
        CSRDetails containing common name, organization, country, SANs, key size/type.

    Raises:
        ValueError: If CSR PEM cannot be parsed.
    """
    try:
        csr = x509.load_pem_x509_csr(csr_pem.strip().encode("utf-8"))
    except Exception as e:
        raise ValueError(f"Could not parse CSR PEM: {e}") from e

    def _get_attr(oid: x509.ObjectIdentifier) -> str:
        attrs = csr.subject.get_attributes_for_oid(oid)
        return str(attrs[0].value) if attrs else ""

    common_name = _get_attr(x509.NameOID.COMMON_NAME)
    organization = _get_attr(x509.NameOID.ORGANIZATION_NAME)
    country = _get_attr(x509.NameOID.COUNTRY_NAME)

    sans: list[str] = []
    try:
        san_ext = csr.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for general_name in san_ext.value:
            sans.append(str(general_name.value))
    except x509.ExtensionNotFound:
        pass

    pub = csr.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type = f"EC ({pub.curve.name})"
        key_size = pub.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key_type = "Ed25519"
        key_size = 256
    else:
        key_type = pub.__class__.__name__
        key_size = getattr(pub, "key_size", 0)

    sig_algo = getattr(csr.signature_algorithm_oid, "_name", "") or csr.signature_algorithm_oid.dotted_string

    return CSRDetails(
        common_name=common_name,
        organization=organization,
        country=country,
        sans=sans,
        key_type=key_type,
        key_size=key_size,
        signature_algorithm=sig_algo,
    )

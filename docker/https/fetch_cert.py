#!/usr/bin/env python3
import base64
import datetime
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID


def generate_self_signed_cert(domain="*.kyndryl.com"):
    """Generate self-signed wildcard certificate."""
    print(f"Generating self-signed certificate for {domain}...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kyndryl"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ]
    )

    # Add Subject Alternative Name with wildcard
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName(domain),
            x509.DNSName(domain.replace("*.", "")),  # Also add root domain
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    return private_key, cert


def fetch_from_keyvault():
    """Try to fetch certificate from Key Vault."""
    from azure.identity import ManagedIdentityCredential
    from azure.keyvault.secrets import SecretClient
    from cryptography.hazmat.primitives.serialization import pkcs12

    keyvault_url = os.environ.get("KEYVAULT_URL")
    cert_name = os.environ.get("CERT_NAME")

    if not keyvault_url or not cert_name:
        return None, None, "KEYVAULT_URL or CERT_NAME not set"

    print(
        f"Attempting to fetch certificate '{cert_name}' from Key Vault: {keyvault_url}"
    )

    try:
        credential = ManagedIdentityCredential()
        client = SecretClient(vault_url=keyvault_url, credential=credential)

        secret = client.get_secret(cert_name)
        pfx_bytes = base64.b64decode(secret.value)

        password = os.environ.get("CERT_PASSWORD") or None

        private_key, cert, _ = pkcs12.load_key_and_certificates(
            pfx_bytes, password.encode() if password else None
        )

        if private_key is None or cert is None:
            return None, None, "PFX did not contain key or cert"

        print("✓ Certificate fetched from Key Vault")
        return private_key, cert, None
    except Exception as e:
        return None, None, str(e)


def main():
    cert_dir = Path(os.environ.get("CERT_DIR", "/certs"))
    cert_dir.mkdir(parents=True, exist_ok=True)

    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"

    # First, try Key Vault
    key, cert, error = fetch_from_keyvault()

    if key is None or cert is None:
        # Fallback to self-signed
        domain = os.environ.get("CERT_FALLBACK_DOMAIN", "*.kyndryl.com")
        print(f"⚠ Key Vault fetch failed: {error}")
        print(f"⚠ Generating self-signed certificate for {domain}")
        print("⚠ This is NOT suitable for production use!")
        try:
            key, cert = generate_self_signed_cert(domain=domain)
        except Exception as e:
            print(f"ERROR: Self-signed certificate generation failed: {e}")
            return 1

    # Write cert and key
    try:
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)

        print(f"✓ Certificate saved to {cert_path}")
        print(f"✓ Private key saved to {key_path}")

        # Basic info
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = "<unknown>"
        try:
            san = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            dns_names = [str(x) for x in san.get_values_for_type(x509.DNSName)]
        except Exception:
            dns_names = []

        print(
            "✓ Self-signed certificate generated successfully"
            if error
            else "✓ Using certificate"
        )
        print(f"✓ CN: {cn}")
        if dns_names:
            print(f"✓ SANs: {', '.join(dns_names)}")
        if error:
            print("⚠ WARNING: Browsers will show security warnings!")

        return 0
    except Exception as e:
        print(f"ERROR: Failed to write certificate files: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

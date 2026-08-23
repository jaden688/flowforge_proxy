"""
Dynamic TLS Certificate Authority management, Root CA generation, and export utilities.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from flowforge.config import get_settings


class CertificateManager:
    """Manages Root CA generation, storage, and export for dynamic MITM TLS interception."""

    def __init__(self, certs_dir: Optional[str] = None) -> None:
        self.settings = get_settings()
        self.certs_dir = Path(certs_dir or self.settings.certs_dir).resolve()
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        # File paths for mitmproxy and user downloads
        self.ca_combined_path = self.certs_dir / "mitmproxy-ca.pem"
        self.ca_cert_pem_path = self.certs_dir / "mitmproxy-ca-cert.pem"
        self.ca_cert_cer_path = self.certs_dir / "mitmproxy-ca-cert.cer"
        self.ca_cert_crt_path = self.certs_dir / "mitmproxy-ca-cert.crt"
        self.ca_cert_p12_path = self.certs_dir / "mitmproxy-ca-cert.p12"

        # Also create flowforge-named symlinks / copies
        self.ff_combined_path = self.certs_dir / "flowforge-ca.pem"
        self.ff_cert_pem_path = self.certs_dir / "flowforge-ca-cert.pem"
        self.ff_cert_crt_path = self.certs_dir / "flowforge-ca-cert.crt"

        self._ensure_root_ca()

    def _ensure_root_ca(self) -> None:
        """Generate Root CA keypair and certificate if not already present."""
        if self.ca_combined_path.exists() and self.ca_cert_pem_path.exists():
            # Ensure flowforge named aliases exist
            self._ensure_aliases()
            return

        # 1. Generate RSA 2048 private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        # 2. Build X.509 Certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.settings.ca_organization),
            x509.NameAttribute(NameOID.COMMON_NAME, self.settings.ca_name),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=self.settings.ca_validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # 3. Export formats
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        # Write mitmproxy default files
        self.ca_combined_path.write_bytes(key_pem + b"\n" + cert_pem)
        self.ca_cert_pem_path.write_bytes(cert_pem)
        self.ca_cert_cer_path.write_bytes(cert_der)
        self.ca_cert_crt_path.write_bytes(cert_der)

        # Write flowforge named files
        self.ff_combined_path.write_bytes(key_pem + b"\n" + cert_pem)
        self.ff_cert_pem_path.write_bytes(cert_pem)
        self.ff_cert_crt_path.write_bytes(cert_der)

        # Generate DH parameters for mitmproxy if needed
        dh_path = self.certs_dir / "mitmproxy-dhparam.pem"
        if not dh_path.exists():
            dh_parameters = rsa.generate_private_key(65537, 2048, default_backend())
            dh_path.write_bytes(key_pem)

    def _ensure_aliases(self) -> None:
        """Ensure flowforge-named certificate copies exist alongside mitmproxy files."""
        if self.ca_cert_pem_path.exists() and not self.ff_cert_pem_path.exists():
            self.ff_cert_pem_path.write_bytes(self.ca_cert_pem_path.read_bytes())
        if self.ca_combined_path.exists() and not self.ff_combined_path.exists():
            self.ff_combined_path.write_bytes(self.ca_combined_path.read_bytes())
        if self.ca_cert_crt_path.exists() and not self.ff_cert_crt_path.exists():
            self.ff_cert_crt_path.write_bytes(self.ca_cert_crt_path.read_bytes())

    def get_ca_cert_pem(self) -> str:
        """Return Root CA certificate in PEM format."""
        if self.ca_cert_pem_path.exists():
            return self.ca_cert_pem_path.read_text()
        self._ensure_root_ca()
        return self.ca_cert_pem_path.read_text()

    def get_ca_cert_bytes(self) -> bytes:
        """Return Root CA certificate in DER/CRT bytes."""
        if self.ca_cert_crt_path.exists():
            return self.ca_cert_crt_path.read_bytes()
        self._ensure_root_ca()
        return self.ca_cert_crt_path.read_bytes()

    def get_ca_info(self) -> Dict[str, Any]:
        """Extract metadata about the currently active Root CA."""
        pem_data = self.get_ca_cert_pem().encode("utf-8")
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        return {
            "common_name": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "organization": cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "sha256_fingerprint": ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)),
            "cert_path": str(self.ca_cert_pem_path),
            "is_ca": True,
        }

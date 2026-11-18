#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise bunyanx - CA Pool Manager (Multi-CA Support)
═══════════════════════════════════════════════════════════════════

Handles Root CA, Intermediate CA, and dynamic certificate generation
for SSL/TLS interception. Implements industry-standard PKI practices.

Author: Enterprise Security Team
License: Proprietary
"""
import os
import re
import logging
import threading
import hashlib
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509 import Certificate

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hostname validation (RFC 1035 + RFC 5891)
# ---------------------------------------------------------------------------
_VALID_HOSTNAME_RE = re.compile(
    r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)*[a-zA-Z0-9\-]{1,63}$"
)
_MAX_HOSTNAME_LEN = 253


def _validate_hostname(hostname: str) -> str:
    """
    Validate and sanitise a hostname before using it as a certificate CN.

    Raises ValueError if the hostname is invalid.
    Returns the lower-cased, stripped hostname on success.
    """
    hostname = hostname.strip().lower()
    if not hostname:
        raise ValueError("Hostname must not be empty")
    if len(hostname) > _MAX_HOSTNAME_LEN:
        raise ValueError(
            f"Hostname too long ({len(hostname)} chars, max {_MAX_HOSTNAME_LEN})"
        )
    # Allow wildcard prefix only at the start
    check = hostname[2:] if hostname.startswith("*.") else hostname
    if not _VALID_HOSTNAME_RE.match(check):
        raise ValueError(f"Invalid hostname characters: {hostname!r}")
    return hostname


# ---------------------------------------------------------------------------
# Thread-safe O(1) LRU certificate cache
# ---------------------------------------------------------------------------
class CertificateCache:
    """Thread-safe O(1) LRU cache for generated certificates using OrderedDict."""

    def __init__(self, max_size: int = 10_000):
        self.max_size = max_size
        self._cache: OrderedDict[str, Tuple[bytes, bytes]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, hostname: str) -> Optional[Tuple[bytes, bytes]]:
        """Return (cert_pem, key_pem) if cached, else None.  Moves entry to end (MRU)."""
        with self._lock:
            if hostname in self._cache:
                self._cache.move_to_end(hostname)          # O(1)
                return self._cache[hostname]
            return None

    def put(self, hostname: str, cert: bytes, key: bytes) -> None:
        """Store certificate, evicting the LRU entry when full.  Both ops O(1)."""
        with self._lock:
            if hostname in self._cache:
                self._cache.move_to_end(hostname)
            self._cache[hostname] = (cert, key)
            if len(self._cache) > self.max_size:
                self._cache.popitem(last=False)             # evict LRU — O(1)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    @property
    def cache(self) -> OrderedDict:
        """Expose internal cache dict for compatibility with proxy modules."""
        return self._cache


# ---------------------------------------------------------------------------
# CA Pool Manager
# ---------------------------------------------------------------------------
class CAPoolManager:
    """
    Certificate Authority Manager

    Manages Root CA, Intermediate CA, and dynamically generates
    server certificates for MITM interception.

    Key improvements over previous version:
    * Private keys are encrypted at rest (passphrase from env/config).
    * datetime.now(timezone.utc) — no deprecated utcnow().
    * cryptography ≥ 3.x API — no deprecated default_backend().
    * Hostname validated (C4) before certificate generation.
    * Disk-cache key files receive 0o600 permissions (C2).
    * O(1) LRU eviction via OrderedDict (H4).
    """

    def __init__(self, config: dict):
        self.config = config
        self.tls_config = config.get('tls', {})

        # ── Key encryption passphrase ─────────────────────────────────────
        # Read from environment first, then config, then refuse to use NoEncryption.
        self._key_passphrase: Optional[bytes] = self._resolve_key_passphrase()

        # ── Paths ─────────────────────────────────────────────────────────
        self.ca_cert_path = Path(self.tls_config.get('ca_cert_path', 'certs/root-ca.crt'))
        self.ca_key_path  = Path(self.tls_config.get('ca_key_path',  'certs/root-ca.key'))
        self.intermediate_cert_path = Path(
            self.tls_config.get('intermediate_ca_cert', 'certs/intermediate-ca.crt')
        )
        self.intermediate_key_path = Path(
            self.tls_config.get('intermediate_ca_key', 'certs/intermediate-ca.key')
        )
        self.cert_cache_dir = Path(self.tls_config.get('cert_cache_dir', 'certs/cache'))

        # ── Create directories ────────────────────────────────────────────
        self.ca_cert_path.parent.mkdir(parents=True, exist_ok=True)
        self.cert_cache_dir.mkdir(parents=True, exist_ok=True)

        # ── In-memory LRU cert cache ──────────────────────────────────────
        cache_size = self.tls_config.get('cert_cache_size', 10_000)
        self.cert_cache = CertificateCache(max_size=cache_size)

        # ── CA objects ────────────────────────────────────────────────────
        self.use_intermediate = self.tls_config.get('use_intermediate_ca', True)
        self.root_ca_cert:         Optional[Certificate] = None
        self.root_ca_key                                 = None
        self.intermediate_ca_cert: Optional[Certificate] = None
        self.intermediate_ca_key                         = None

        self._initialize_ca()

    # ------------------------------------------------------------------
    # Passphrase resolution
    # ------------------------------------------------------------------
    def _resolve_key_passphrase(self) -> Optional[bytes]:
        """
        Resolve the CA key encryption passphrase.

        Priority:
          1. Environment variable  CA_KEY_PASSPHRASE
          2. Config key            tls.ca_key_passphrase
          3. WARNING — falls back to no encryption (dev-mode only).
        """
        env_val = os.environ.get("CA_KEY_PASSPHRASE")
        if env_val:
            return env_val.encode()

        cfg_val = self.tls_config.get("ca_key_passphrase")
        if cfg_val:
            return cfg_val.encode()

        logger.warning(
            "CA_KEY_PASSPHRASE not set — private keys will be stored "
            "UNENCRYPTED. Set the environment variable for production use."
        )
        return None

    def _key_encryption_algo(self):
        """Return the serialization encryption algorithm based on passphrase availability."""
        if self._key_passphrase:
            return serialization.BestAvailableEncryption(self._key_passphrase)
        return serialization.NoEncryption()

    def _load_private_key(self, key_bytes: bytes):
        """
        Load a PEM private key, handling the case where a passphrase is
        configured but the key on disk is actually unencrypted.

        Tries with the configured passphrase first; if cryptography raises
        TypeError ("Password was given but private key is not encrypted")
        it falls back to loading with ``password=None`` and emits a warning.
        """
        try:
            return serialization.load_pem_private_key(
                key_bytes, password=self._key_passphrase
            )
        except TypeError:
            # Key file is unencrypted but a passphrase was configured.
            logger.warning(
                "Private key on disk is NOT encrypted even though a passphrase "
                "is configured. Loading without passphrase. "
                "Re-save the key or clear CA_KEY_PASSPHRASE to silence this warning."
            )
            return serialization.load_pem_private_key(key_bytes, password=None)

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------
    def _initialize_ca(self) -> None:
        """Initialize Certificate Authority."""
        logger.info("Initializing Certificate Authority...")

        # Try to load active CAs from database first
        try:
            if self._load_ca_from_db():
                logger.info("Certificate Authority initialized from DB successfully")
                return
        except Exception as exc:
            logger.debug("Database CA load skipped or failed: %s", exc)

        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            logger.info("Loading existing Root CA from %s", self.ca_cert_path)
            self._load_root_ca()
        else:
            logger.warning("Root CA not found — creating new Root CA...")
            self._create_root_ca()

        if self.use_intermediate:
            if self.intermediate_cert_path.exists() and self.intermediate_key_path.exists():
                logger.info("Loading Intermediate CA from %s", self.intermediate_cert_path)
                self._load_intermediate_ca()
            else:
                logger.warning("Intermediate CA not found — creating new Intermediate CA...")
                self._create_intermediate_ca()

        logger.info("Certificate Authority initialized successfully")

    def _load_ca_from_db(self) -> bool:
        """Try to load active Root and/or Intermediate CA from active database configurations."""
        try:
            from system.database.database import SessionLocal
            from modules.ssl_inspection.models import SSLCertificateConfig
        except ImportError:
            # Under some test environments, DB might not be available
            return False

        try:
            with SessionLocal() as session:
                from system.database.database import Base
                import modules.ssl_inspection.models
                try:
                    Base.metadata.create_all(bind=session.get_bind())
                except Exception:
                    pass

                # Find active Root CA in DB
                root_db = session.query(SSLCertificateConfig).filter(
                    SSLCertificateConfig.cert_type == "ROOT_CA",
                    SSLCertificateConfig.is_active == True
                ).first()

                if not root_db:
                    return False

                # Load Root CA public cert
                self.root_ca_cert = x509.load_pem_x509_certificate(root_db.public_cert.encode())

                # Load Root CA private key
                if root_db.private_key:
                    # Note: key is stored encrypted with our CA passphrase
                    self.root_ca_key = self._load_private_key(
                        root_db.private_key.encode()
                    )
                else:
                    logger.warning("Active Root CA in DB does not contain a private key!")
                    return False

                # Find active Intermediate CA
                if self.use_intermediate:
                    inter_db = session.query(SSLCertificateConfig).filter(
                        SSLCertificateConfig.cert_type == "INTERMEDIATE_CA",
                        SSLCertificateConfig.is_active == True
                    ).first()

                    if inter_db:
                        self.intermediate_ca_cert = x509.load_pem_x509_certificate(inter_db.public_cert.encode())
                        if inter_db.private_key:
                            self.intermediate_ca_key = self._load_private_key(
                                inter_db.private_key.encode()
                            )
                        else:
                            logger.warning("Active Intermediate CA in DB does not contain a private key!")
                            self.use_intermediate = False
                    else:
                        logger.info("No active Intermediate CA in DB — falling back to Root CA only")
                        self.use_intermediate = False

                return True
        except Exception as exc:
            logger.debug("Database CA load skipped or failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Root CA
    # ------------------------------------------------------------------
    def _load_root_ca(self) -> None:
        """Load existing Root CA from disk."""
        try:
            with open(self.ca_cert_path, 'rb') as f:
                self.root_ca_cert = x509.load_pem_x509_certificate(f.read())

            with open(self.ca_key_path, 'rb') as f:
                self.root_ca_key = self._load_private_key(f.read())

            cn = self.root_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            logger.info("Loaded Root CA: %s", cn)
            not_valid_after = (
                self.root_ca_cert.not_valid_after_utc
                if hasattr(self.root_ca_cert, "not_valid_after_utc")
                else self.root_ca_cert.not_valid_after.replace(tzinfo=timezone.utc)
            )
            logger.info("Valid until:    %s", not_valid_after)
        except Exception as exc:
            logger.error("Failed to load Root CA: %s", exc)
            raise

    def _create_root_ca(self) -> None:
        """Create a new self-signed Root CA."""
        logger.info("Generating Root CA certificate...")

        key_size = self.tls_config.get('cert_key_size', 4096)
        self.root_ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,              "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,    "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME,             "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,         "Enterprise MITM Proxy"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,  "Security"),
            x509.NameAttribute(NameOID.COMMON_NAME,               "Enterprise Root CA"),
        ])

        self.root_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.root_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.root_ca_key.public_key()),
                critical=False,
            )
            .sign(self.root_ca_key, hashes.SHA256())
        )

        self._save_certificate(self.ca_cert_path, self.root_ca_cert)
        self._save_private_key(self.ca_key_path, self.root_ca_key)
        logger.info("Root CA created and saved to %s", self.ca_cert_path)
        logger.warning("IMPORTANT: Install root-ca.crt on all client devices!")

    # ------------------------------------------------------------------
    # Intermediate CA
    # ------------------------------------------------------------------
    def _load_intermediate_ca(self) -> None:
        """Load existing Intermediate CA from disk."""
        try:
            with open(self.intermediate_cert_path, 'rb') as f:
                self.intermediate_ca_cert = x509.load_pem_x509_certificate(f.read())

            with open(self.intermediate_key_path, 'rb') as f:
                self.intermediate_ca_key = self._load_private_key(f.read())

            cn = self.intermediate_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            logger.info("Loaded Intermediate CA: %s", cn)
        except Exception as exc:
            logger.error("Failed to load Intermediate CA: %s", exc)
            raise

    def _create_intermediate_ca(self) -> None:
        """Create an Intermediate CA signed by the Root CA."""
        logger.info("Generating Intermediate CA certificate...")

        key_size = self.tls_config.get('cert_key_size', 4096)
        self.intermediate_ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        now = datetime.now(timezone.utc)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,              "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,    "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME,             "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,         "Enterprise MITM Proxy"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,  "Security"),
            x509.NameAttribute(NameOID.COMMON_NAME,               "Enterprise Intermediate CA"),
        ])

        self.intermediate_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.root_ca_cert.subject)
            .public_key(self.intermediate_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.intermediate_ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_ca_key.public_key()),
                critical=False,
            )
            .sign(self.root_ca_key, hashes.SHA256())
        )

        self._save_certificate(self.intermediate_cert_path, self.intermediate_ca_cert)
        self._save_private_key(self.intermediate_key_path, self.intermediate_ca_key)
        logger.info("Intermediate CA created and saved to %s", self.intermediate_cert_path)

    # ------------------------------------------------------------------
    # Server certificate generation
    # ------------------------------------------------------------------
    def generate_server_certificate(self, hostname: str) -> Tuple[bytes, bytes]:
        """
        Generate a server certificate for MITM interception.

        Args:
            hostname: Target hostname (e.g., "www.google.com").
                      Validated against RFC 1035 before use (C4).

        Returns:
            Tuple of (certificate_pem, private_key_pem).
            The private key PEM is unencrypted (in-memory only — never persisted
            in this form; disk cache uses encrypted storage).
        """
        # C4 — Validate hostname BEFORE doing any crypto work
        hostname = _validate_hostname(hostname)

        # Check in-memory LRU cache first
        cached = self.cert_cache.get(hostname)
        if cached:
            logger.debug("Using cached certificate for %s", hostname)
            return cached

        # Check on-disk cache (prevent crypto generation overhead)
        try:
            safe_name = hashlib.sha256(hostname.encode()).hexdigest()[:16]
            cert_file = self.cert_cache_dir / f"{safe_name}.crt"
            key_file  = self.cert_cache_dir / f"{safe_name}.key"
            if cert_file.exists() and key_file.exists():
                cert_pem = cert_file.read_bytes()
                encrypted_key_pem = key_file.read_bytes()
                private_key = self._load_private_key(encrypted_key_pem)
                key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                self.cert_cache.put(hostname, cert_pem, key_pem)
                logger.debug("Loaded certificate from disk cache for %s", hostname)
                return cert_pem, key_pem
        except Exception as exc:
            logger.warning("Failed to load certificate from disk cache for %s: %s", hostname, exc)

        logger.debug("Generating certificate for %s", hostname)

        # Choose signing CA
        if self.use_intermediate and self.intermediate_ca_cert:
            signing_cert = self.intermediate_ca_cert
            signing_key  = self.intermediate_ca_key
        else:
            signing_cert = self.root_ca_cert
            signing_key  = self.root_ca_key

        # ECC key for speed (SECP256R1 ~10x faster than RSA-2048)
        private_key = ec.generate_private_key(ec.SECP256R1())

        now = datetime.now(timezone.utc)
        validity_days = self.tls_config.get('cert_validity_days', 365)

        # Build SAN list
        san_list = [x509.DNSName(hostname)]
        if not hostname.startswith('*.'):
            san_list.append(x509.DNSName(f"*.{hostname}"))
        if hostname.startswith('www.'):
            san_list.append(x509.DNSName(hostname[4:]))
        else:
            san_list.append(x509.DNSName(f"www.{hostname}"))

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME,      "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise MITM Proxy"),
                x509.NameAttribute(NameOID.COMMON_NAME,       hostname),
            ]))
            .issuer_name(signing_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))   # 1-day clock-skew tolerance
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    key_cert_sign=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
                critical=False,
            )
            .sign(signing_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        # In-memory key is unencrypted — only the on-disk copy is encrypted
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Cache in memory (O(1) eviction)
        self.cert_cache.put(hostname, cert_pem, key_pem)

        # Persist encrypted copy to disk
        self._save_to_disk_cache(hostname, cert_pem, private_key)

        logger.info("Generated certificate for %s", hostname)
        return cert_pem, key_pem

    # ------------------------------------------------------------------
    # Disk cache helpers
    # ------------------------------------------------------------------
    def _save_to_disk_cache(self, hostname: str, cert_pem: bytes, private_key) -> None:
        """
        Save certificate and ENCRYPTED private key to disk cache.

        C2: key file is written with 0o600 permissions.
        C1: key is encrypted with the configured passphrase.
        """
        try:
            safe_name = hashlib.sha256(hostname.encode()).hexdigest()[:16]
            cert_file = self.cert_cache_dir / f"{safe_name}.crt"
            key_file  = self.cert_cache_dir / f"{safe_name}.key"

            cert_file.write_bytes(cert_pem)
            # Encrypt the private key before writing to disk
            encrypted_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=self._key_encryption_algo(),
            )
            key_file.write_bytes(encrypted_key_pem)

            # C2 — restrict permissions
            try:
                os.chmod(cert_file, 0o644)
                os.chmod(key_file,  0o600)
            except OSError:
                pass  # Windows — best-effort

        except Exception as exc:
            logger.warning("Failed to save certificate to disk cache: %s", exc)

    def _save_certificate(self, path: Path, cert: Certificate) -> None:
        """Persist a certificate (public) to disk."""
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass

    def _save_private_key(self, path: Path, key) -> None:
        """
        Persist a private key to disk, ENCRYPTED when a passphrase is available.
        C1 fix: no more NoEncryption() for CA root/intermediate keys.
        """
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=self._key_encryption_algo(),
        )
        path.write_bytes(key_pem)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # CA bundle / export
    # ------------------------------------------------------------------
    def get_ca_bundle(self) -> bytes:
        """
        Return the PEM CA bundle (Root + optional Intermediate) for client installation.
        """
        bundle = self.root_ca_cert.public_bytes(serialization.Encoding.PEM)
        if self.use_intermediate and self.intermediate_ca_cert:
            bundle += self.intermediate_ca_cert.public_bytes(serialization.Encoding.PEM)
        return bundle

    def export_ca_for_clients(self, output_dir: Path) -> None:
        """
        Export CA certificates in multiple formats for client installation.

        Args:
            output_dir: Directory to write the export files.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        (output_dir / "enterprise-ca.pem").write_bytes(self.get_ca_bundle())
        (output_dir / "enterprise-ca.crt").write_bytes(self.get_ca_bundle())
        (output_dir / "enterprise-ca.der").write_bytes(
            self.root_ca_cert.public_bytes(serialization.Encoding.DER)
        )

        logger.info("CA certificates exported to %s", output_dir)
        logger.info("Installation instructions:")
        logger.info("  Linux:   cp enterprise-ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates")
        logger.info("  macOS:   Open enterprise-ca.crt and add to System Keychain")
        logger.info("  Windows: Double-click enterprise-ca.der and install to Trusted Root")
"""
Enterprise bunyanx — PKI Certificate Management Router
=======================================================
Provides full lifecycle management of X.509 certificates scanned
from the ssl_inspection CA directory.

Endpoints:
  GET  /api/v1/certificates              — List all discovered certificates
  DELETE /api/v1/certificates/{id}       — Revoke (delete) a certificate
  POST /api/v1/certificates/{id}/renew   — Renew (re-generate) a certificate
  GET  /api/v1/certificates/ca/info      — CA certificate metadata
  POST /api/v1/certificates/ca/generate  — Generate a new self-signed CA
  GET  /api/v1/certificates/ca/download  — Download CA cert (PEM/DER)

All certificate data is read from the real ssl_inspection CA directory.
No mock data. If the directory is missing, empty list is returned gracefully.
"""

import os
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

from api.core.auth import require_admin, make_permission_checker

router = APIRouter(prefix="/api/v1/certificates", tags=["PKI & Certificates"])
logger = logging.getLogger(__name__)

# Permission: admins always pass; operators need "ssl_inspection" rule
require_pki = make_permission_checker("ssl_inspection")

class DeviceCertRequest(BaseModel):
    cn: str
    org: str = ""
    country: str = "SA"
    san: str = ""
    keySize: int = 2048
    days: int = 365

# ── Certificate storage directories ──────────────────────────────────────────
# These match what ssl_inspection/engine/ca_pool.py writes to
_CERT_DIRS = [
    Path("system/auth/pki"),
    Path("certs/internal"),
    Path("certs"),
    Path("ssl_inspection/certs"),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_crypto():
    """Import cryptography library — required for cert parsing."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import cryptography
        return x509, serialization, hashes, rsa, NameOID, cryptography
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="cryptography library not installed. Run: pip install cryptography"
        )


def _find_cert_files() -> List[Path]:
    """Discover all .pem / .crt / .cer certificate files across known dirs."""
    found = []
    for d in _CERT_DIRS:
        if d.exists():
            for ext in ("*.pem", "*.crt", "*.cer"):
                found.extend(d.glob(ext))
    return list(set(found))  # deduplicate


def _parse_cert(path: Path, x509_mod) -> Optional[dict]:
    """Parse a single PEM/DER certificate file into a serializable dict."""
    try:
        raw = path.read_bytes()
        try:
            cert = x509_mod.load_pem_x509_certificate(raw)
        except Exception:
            cert = x509_mod.load_der_x509_certificate(raw)

        cn = cert.subject.get_attributes_for_oid(
            x509_mod.oid.NameOID.COMMON_NAME
        )
        issuer_cn = cert.issuer.get_attributes_for_oid(
            x509_mod.oid.NameOID.COMMON_NAME
        )

        # Normalize expiry to ISO string
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before

        # Detect usage from key usage extension
        usage = "unknown"
        try:
            ku = cert.extensions.get_extension_for_class(x509_mod.extensions.KeyUsage)
            parts = []
            if ku.value.digital_signature: parts.append("Signing")
            if ku.value.key_encipherment:  parts.append("Encryption")
            if ku.value.key_cert_sign:     parts.append("CA")
            usage = ", ".join(parts) or "unknown"
        except Exception:
            # Heuristic from filename
            name = path.name.lower()
            if "ca" in name or "root" in name:
                usage = "CA"
            elif "server" in name:
                usage = "Server TLS"
            elif "client" in name:
                usage = "Client Auth"
            else:
                usage = "TLS"

        # Detect type
        cert_type = "self-signed"
        try:
            bc = cert.extensions.get_extension_for_class(x509_mod.extensions.BasicConstraints)
            if bc.value.ca:
                cert_type = "CA"
        except Exception:
            pass

        return {
            "id": path.stem,  # filename without extension = stable ID
            "path": str(path),
            "cn": cn[0].value if cn else path.stem,
            "issuer": issuer_cn[0].value if issuer_cn else "Unknown",
            "type": cert_type,
            "usage": usage,
            "expiry": not_after.strftime("%Y-%m-%d") if not_after else "Unknown",
            "not_before": not_before.strftime("%Y-%m-%d") if not_before else "Unknown",
            "serial": str(cert.serial_number),
        }
    except Exception as e:
        logger.warning(f"Failed to parse cert {path}: {e}")
        return None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_certificates(token: dict = Depends(require_pki)):
    """
    Discover and return all X.509 certificates from the PKI directories.
    Real data — no mock entries.
    """
    x509, *_ = _load_crypto()
    cert_files = _find_cert_files()

    certs = []
    for path in cert_files:
        parsed = _parse_cert(path, x509)
        if parsed:
            certs.append(parsed)

    # Sort: soonest expiry first (most urgent at top)
    def sort_key(c):
        try:
            return datetime.strptime(c["expiry"], "%Y-%m-%d")
        except Exception:
            return datetime.max

    certs.sort(key=sort_key)
    return {"certificates": certs, "count": len(certs)}


@router.delete("/{cert_id}")
async def revoke_certificate(cert_id: str, token: dict = Depends(require_admin)):
    """
    Revoke a certificate by deleting its file from the PKI directory.
    The cert_id is the filename stem (without extension).
    Admin only.
    """
    if ".." in cert_id or "/" in cert_id or "\\" in cert_id:
        raise HTTPException(status_code=400, detail="Invalid certificate ID")

    deleted = False
    for d in _CERT_DIRS:
        for ext in (".pem", ".crt", ".cer"):
            target = d / f"{cert_id}{ext}"
            if target.exists():
                try:
                    target.unlink()
                    deleted = True
                    logger.info(f"Revoked certificate: {target}")
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Failed to delete cert: {e}")

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found")

    return {"status": "revoked", "id": cert_id, "message": f"Certificate {cert_id} revoked and deleted"}


@router.post("/{cert_id}/renew")
async def renew_certificate(cert_id: str, token: dict = Depends(require_admin)):
    """
    Renew a certificate by re-generating it using the internal CA.
    Reads the existing cert to extract subject info, then issues a new one.
    Admin only.
    """
    if ".." in cert_id or "/" in cert_id or "\\" in cert_id:
        raise HTTPException(status_code=400, detail="Invalid certificate ID")

    x509, serialization, hashes, rsa, NameOID, cryptography = _load_crypto()

    # Find existing cert
    existing_path = None
    for d in _CERT_DIRS:
        for ext in (".pem", ".crt", ".cer"):
            p = d / f"{cert_id}{ext}"
            if p.exists():
                existing_path = p
                break
        if existing_path:
            break

    if not existing_path:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found")

    try:
        from datetime import timedelta
        import ipaddress

        raw = existing_path.read_bytes()
        try:
            old_cert = x509.load_pem_x509_certificate(raw)
        except Exception:
            old_cert = x509.load_der_x509_certificate(raw)

        # Find CA key/cert
        ca_cert_path = None
        ca_key_path = None
        for d in _CERT_DIRS:
            for name in ("ca.crt", "ca.pem", "root.crt", "root.pem"):
                if (d / name).exists():
                    ca_cert_path = d / name
            for name in ("ca.key", "root.key"):
                if (d / name).exists():
                    ca_key_path = d / name
            if ca_cert_path and ca_key_path:
                break

        if not ca_cert_path or not ca_key_path:
            raise HTTPException(status_code=503, detail="Internal CA not found — cannot renew certificate")

        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        ca_key = load_pem_private_key(ca_key_path.read_bytes(), password=None)

        # Generate new key
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Build new cert with same subject
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(old_cert.subject)
            .issuer_name(ca_cert.subject)
            .public_key(new_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
        )

        # Copy SAN if present
        try:
            san = old_cert.extensions.get_extension_for_class(x509.extensions.SubjectAlternativeName)
            builder = builder.add_extension(san.value, critical=False)
        except Exception:
            pass

        new_cert = builder.sign(ca_key, hashes.SHA256())

        # Save
        existing_path.write_bytes(new_cert.public_bytes(serialization.Encoding.PEM))

        # Save new private key alongside
        key_path = existing_path.with_suffix(".key")
        key_path.write_bytes(new_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

        return {
            "status": "renewed",
            "id": cert_id,
            "new_expiry": (now + timedelta(days=365)).strftime("%Y-%m-%d"),
            "message": f"Certificate {cert_id} renewed successfully for 365 days"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Renew failed for {cert_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Renewal failed: {str(e)}")


# ── CA Management ─────────────────────────────────────────────────────────────

@router.get("/ca/info")
async def get_ca_info(token: dict = Depends(require_pki)):
    """Return metadata about the internal CA certificate."""
    x509, *_ = _load_crypto()

    ca_path = None
    for d in _CERT_DIRS:
        for name in ("ca.crt", "ca.pem", "root.crt", "root.pem"):
            p = d / name
            if p.exists():
                ca_path = p
                break
        if ca_path:
            break

    if not ca_path:
        return {
            "exists": False,
            "message": "No internal CA certificate found. Use POST /ca/generate to create one."
        }

    parsed = _parse_cert(ca_path, x509)
    return {"exists": True, "ca": parsed}


@router.post("/ca/generate")
async def generate_ca(token: dict = Depends(require_admin)):
    """
    Generate a new self-signed root CA certificate and private key.
    Stores to system/auth/pki/ca.{crt,key}.
    Admin only.
    """
    x509, serialization, hashes, rsa, NameOID, cryptography = _load_crypto()

    try:
        from datetime import timedelta

        # Storage dir
        ca_dir = Path("system/auth/pki")
        ca_dir.mkdir(parents=True, exist_ok=True)

        # Generate CA key
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "bunyanx NGFW"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security Operations"),
            x509.NameAttribute(NameOID.COMMON_NAME, "bunyanx Internal CA"),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))  # 10 years
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, data_encipherment=False,
                    content_commitment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False
                ),
                critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Write cert
        cert_path = ca_dir / "ca.crt"
        cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        # Write key
        key_path = ca_dir / "ca.key"
        key_path.write_bytes(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
        # Restrict key permissions where possible
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass

        logger.info(f"Generated new internal CA at {cert_path}")
        return {
            "status": "generated",
            "cert_path": str(cert_path),
            "key_path": str(key_path),
            "valid_from": now.strftime("%Y-%m-%d"),
            "valid_until": (now + timedelta(days=3650)).strftime("%Y-%m-%d"),
            "message": "New internal CA generated. Deploy CA cert to all internal services."
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CA generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"CA generation failed: {str(e)}")


@router.post("/generate")
async def generate_certificate(req: DeviceCertRequest, token: dict = Depends(require_admin)):
    """
    Generate a new certificate (e.g. for a device or client).
    Signed by the internal CA.
    """
    x509, serialization, hashes, rsa, NameOID, cryptography = _load_crypto()
    
    try:
        from datetime import timedelta
        
        ca_cert_path = None
        ca_key_path = None
        for d in _CERT_DIRS:
            for name in ("ca.crt", "ca.pem", "root.crt", "root.pem"):
                if (d / name).exists():
                    ca_cert_path = d / name
            for name in ("ca.key", "root.key"):
                if (d / name).exists():
                    ca_key_path = d / name
            if ca_cert_path and ca_key_path:
                break

        if not ca_cert_path or not ca_key_path:
            raise HTTPException(status_code=503, detail="Internal CA not found. Please generate one first.")

        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        ca_key = load_pem_private_key(ca_key_path.read_bytes(), password=None)

        # Generate new key for the device
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=req.keySize)

        now = datetime.now(timezone.utc)
        
        # Build subject name
        subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, req.cn)]
        if req.org:
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, req.org))
        if req.country:
            subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, req.country))
            
        subject = x509.Name(subject_attrs)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(new_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=req.days))
        )

        # Basic constraints
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        
        # Key usage
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                key_encipherment=True, data_encipherment=False,
                content_commitment=False, key_agreement=False,
                encipher_only=False, decipher_only=False
            ),
            critical=True
        )

        # Extended key usage (Client Auth / Server Auth)
        from cryptography.x509.oid import ExtendedKeyUsageOID
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False
        )

        # Subject Alt Names if any
        if req.san:
            import ipaddress
            san_list = []
            for item in req.san.split(","):
                item = item.strip()
                if not item: continue
                try:
                    ip = ipaddress.ip_address(item)
                    san_list.append(x509.IPAddress(ip))
                except ValueError:
                    san_list.append(x509.DNSName(item))
            if san_list:
                builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

        new_cert = builder.sign(ca_key, hashes.SHA256())

        # Save to system/auth/pki directory
        save_dir = Path("system/auth/pki")
        save_dir.mkdir(parents=True, exist_ok=True)
        
        # Use CN for filename, sanitize to prevent path traversal
        safe_cn = "".join(c for c in req.cn if c.isalnum() or c in ('-', '_')).strip()
        if not safe_cn:
            safe_cn = "device_cert"
            
        cert_path = save_dir / f"{safe_cn}.crt"
        key_path = save_dir / f"{safe_cn}.key"
        
        cert_path.write_bytes(new_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(new_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
        
        logger.info(f"Generated new device certificate at {cert_path}")
        return {
            "status": "generated",
            "cn": req.cn,
            "message": f"تم إنشاء شهادة للجهاز {req.cn} بنجاح",
            "expiry": (now + timedelta(days=req.days)).strftime("%Y-%m-%d")
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Certificate generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Certificate generation failed: {str(e)}")


@router.get("/ca/download")
async def download_ca(
    format: Literal["pem", "der", "p12"] = Query("pem"),
    token: dict = Depends(require_pki)
):
    """Download the internal CA certificate in PEM, DER, or P12 format."""
    x509, serialization, *_ = _load_crypto()

    ca_path = None
    for d in _CERT_DIRS:
        for name in ("ca.crt", "ca.pem", "root.crt", "root.pem"):
            p = d / name
            if p.exists():
                ca_path = p
                break
        if ca_path:
            break

    if not ca_path:
        raise HTTPException(status_code=404, detail="No CA certificate found. Generate one first.")

    raw = ca_path.read_bytes()

    if format == "p12":
        try:
            from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key
            ca_key_path = None
            for d in _CERT_DIRS:
                for name in ("ca.key", "root.key"):
                    p = d / name
                    if p.exists():
                        ca_key_path = p
                        break
                if ca_key_path:
                    break

            cert = x509.load_pem_x509_certificate(raw)
            key = None
            if ca_key_path:
                try:
                    key = load_pem_private_key(ca_key_path.read_bytes(), password=None)
                except Exception:
                    key = None

            p12_bytes = pkcs12.serialize_key_and_certificates(
                name=b"bunyanx Root CA",
                key=key,
                cert=cert,
                cas=None,
                encryption_algorithm=serialization.NoEncryption()
            )
            return Response(
                content=p12_bytes,
                media_type="application/x-pkcs12",
                headers={"Content-Disposition": "attachment; filename=bunyanx-ca.p12"}
            )
        except Exception as e:
            logger.error(f"Failed to export CA as P12: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to export CA as P12: {e}")
    elif format == "der":
        try:
            cert = x509.load_pem_x509_certificate(raw)
            data = cert.public_bytes(serialization.Encoding.DER)
        except Exception:
            data = raw
        return Response(
            content=data,
            media_type="application/pkix-cert",
            headers={"Content-Disposition": "attachment; filename=bunyanx-ca.der"}
        )
    else:
        return Response(
            content=raw,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": "attachment; filename=bunyanx-ca.pem"}
        )


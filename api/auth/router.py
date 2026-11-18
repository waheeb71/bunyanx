from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.responses import FileResponse, Response
from typing import Dict, Any
import os
import time
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from api.core.auth import require_admin, verify_token
import logging
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/certificates", tags=["certificates", "system"])


# Default paths used by the system (sync with ssl.yaml)
DEFAULT_CA_CERT_PATH = "certs/root-ca.crt"
DEFAULT_CA_KEY_PATH = "certs/root-ca.key"

def get_cert_paths(request: Request):
    """Determine the exact cert path from ssl.yaml, otherwise fallback to default relative paths."""
    try:
        from pathlib import Path
        import yaml
        
        # Base path of the project
        base_dir = Path(__file__).parent.parent.parent
        
        # Check module config
        ssl_yaml = base_dir / "modules" / "ssl_inspection" / "config" / "ssl.yaml"
        if ssl_yaml.exists():
            with open(ssl_yaml) as f:
                raw = yaml.safe_load(f) or {}
            
            pki_cfg = raw.get("ssl_inspection", {}).get("pki", {})
            if "ca_cert_path" in pki_cfg:
                cert_path = str(base_dir / pki_cfg.get("ca_cert_path"))
                key_path = str(base_dir / pki_cfg.get("ca_key_path", "certs/root-ca.key"))
                return cert_path, key_path
    except Exception as e:
        logger.debug(f"Error parsing ssl.yaml: {e}")
        pass
    
    # Fallback to local project path
    base_dir = Path(__file__).parent.parent.parent
    return str(base_dir / DEFAULT_CA_CERT_PATH), str(base_dir / DEFAULT_CA_KEY_PATH)


@router.get("/ca/info", response_model=Dict[str, Any])
async def get_ca_info(request: Request, token: dict = Depends(verify_token)):
    """Get internal details about the bunyanx Transparent Proxy Root CA"""
    cert_path, _ = get_cert_paths(request)
    
    if not os.path.exists(cert_path):
        return {"status": "not_found", "message": "Root CA certificate not found on disk."}
        
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            
        cert = x509.load_pem_x509_certificate(cert_data)
        
        # Build Subject String
        subject_parts = []
        for attr in cert.subject:
            subject_parts.append(f"{attr.oid._name}={attr.value}")
        subject_str = ", ".join(subject_parts)
        
        # Build Issuer String
        issuer_parts = []
        for attr in cert.issuer:
            issuer_parts.append(f"{attr.oid._name}={attr.value}")
        issuer_str = ", ".join(issuer_parts)
        
        # Compute Fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint_formatted = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        
        return {
            "status": "active",
            "subject": subject_str,
            "issuer": issuer_str,
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_to": cert.not_valid_after.isoformat(),
            "fingerprint": fingerprint_formatted,
            "file_path": cert_path
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse CA certificate: {str(e)}")


@router.get("/ca/download")
async def download_ca(
    request: Request,
    format: str = Query("pem", description="Format of the certificate to download (pem, der, p12)"),
    token: dict = Depends(require_admin) # Must be admin to download CA files, especially P12 with key
):
    """Download the Enterprise bunyanx Root CA in various formats for client installation"""
    cert_path, key_path = get_cert_paths(request)
    
    if not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail="CA Certificate not found.")
        
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            
        cert = x509.load_pem_x509_certificate(cert_data)
        
        if format.lower() == "pem" or format.lower() == "crt":
            return Response(
                content=cert_data,
                media_type="application/x-x509-ca-cert",
                headers={"Content-Disposition": "attachment; filename=bunyanx-root-ca.pem"}
            )
            
        elif format.lower() == "der" or format.lower() == "cer":
            der_data = cert.public_bytes(serialization.Encoding.DER)
            return Response(
                content=der_data,
                media_type="application/pkix-cert",
                headers={"Content-Disposition": "attachment; filename=bunyanx-root-ca.der"}
            )
            
        elif format.lower() == "p12" or format.lower() == "pfx":
            if not os.path.exists(key_path):
                raise HTTPException(status_code=400, detail="Private key not found, cannot generate P12.")
                
            with open(key_path, "rb") as k:
                key_data = k.read()
                
            key = serialization.load_pem_private_key(key_data, password=None)
            
            p12_data = pkcs12.serialize_key_and_certificates(
                name=b"Enterprise bunyanx Root CA",
                key=key,
                cert=cert,
                cas=None,
                encryption_algorithm=serialization.BestAvailableEncryption(b"bunyanx-ca-password")
            )
            
            return Response(
                content=p12_data,
                media_type="application/x-pkcs12",
                headers={"Content-Disposition": "attachment; filename=bunyanx-root-ca.p12"}
            )
            
        else:
            raise HTTPException(status_code=400, detail="Unsupported format. Use pem, der, or p12.")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to export certificate: {str(e)}")


@router.post("/ca/generate")
async def generate_ca(request: Request, token: dict = Depends(require_admin)):
    """Generate a brand new 4096-bit RSA Root CA on-the-fly and overwrite the old one."""
    cert_path, key_path = get_cert_paths(request)
    
    # Ensure directories exist
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    
    try:
        # Generate Private Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        
        # Generate Subject and Issuer (Self-Signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Enterprise bunyanx"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Security Appliances"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Enterprise bunyanx Root CA"),
        ])
        
        # Build Certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650) # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(private_key, hashes.SHA256())
        
        # Write Key
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Write Cert
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        # Set restricted permissions on key if possible
        try:
            os.chmod(key_path, 0o600)
        except:
            pass
            
        return {"status": "success", "message": "New Root CA generated successfully. Requires service restart to take effect."}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate Root CA: {str(e)}")


@router.get("", response_model=Dict[str, Any])
async def list_all_certificates(request: Request, token: dict = Depends(verify_token)):
    """Scan the certs/ folder and return metadata for all valid certificates found (real data)."""
    from pathlib import Path
    base_dir = Path(__file__).parent.parent.parent
    certs_dir = base_dir / "certs"
    
    cert_list = []
    if certs_dir.exists():
        # Scan for all .crt or .pem files
        for item in certs_dir.glob("**/*.crt"):
            if item.is_file():
                try:
                    with open(item, "rb") as f:
                        cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data)
                    
                    # Common Name
                    cn = "Unknown"
                    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                        cn = attr.value
                    
                    # Issuer
                    issuer = "Unknown"
                    for attr in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME):
                        issuer = attr.value
                        
                    # Check if CA
                    is_ca = False
                    try:
                        ext = cert.extensions.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
                        is_ca = ext.value.ca
                    except:
                        try:
                            # fallback for OID direct check
                            ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
                            is_ca = ext.value.ca
                        except:
                            pass
                    
                    cert_type = "CA" if is_ca else "TLS"
                    
                    # Deduce usage based on filename or attributes
                    usage = "General Encryption"
                    if "root" in item.name.lower():
                        usage = "Root Trust Anchor"
                        cert_type = "CA"
                    elif "intermediate" in item.name.lower():
                        usage = "Subordinate CA"
                        cert_type = "CA"
                    elif "server" in item.name.lower():
                        usage = "Web Server Certificate"
                    elif "vpn" in item.name.lower():
                        usage = "VPN Gateway Authentication"
                    elif "mail" in item.name.lower():
                        usage = "Mail Server Security"
                        
                    cert_list.append({
                        "id": f"cert-{item.stem}",
                        "cn": cn,
                        "issuer": issuer,
                        "expiry": cert.not_valid_after.date().isoformat(),
                        "type": cert_type,
                        "usage": usage,
                        "file_path": str(item.relative_to(base_dir))
                    })
                except Exception as e:
                    # Skip files that aren't valid PEM certs
                    pass
    return {"status": "success", "count": len(cert_list), "certificates": cert_list}


@router.delete("/{cert_id}", response_model=Dict[str, Any])
async def revoke_certificate(cert_id: str, token: dict = Depends(require_admin)):
    """Revoke (delete) a certificate file on disk."""
    from pathlib import Path
    base_dir = Path(__file__).parent.parent.parent
    certs_dir = base_dir / "certs"
    
    if not cert_id.startswith("cert-"):
        raise HTTPException(status_code=400, detail="Invalid certificate ID format.")
    stem = cert_id[5:]
    
    crt_file = certs_dir / f"{stem}.crt"
    key_file = certs_dir / f"{stem}.key"
    
    deleted = False
    if crt_file.exists() and crt_file.is_file():
        crt_file.unlink()
        deleted = True
    if key_file.exists() and key_file.is_file():
        key_file.unlink()
        
    if not deleted:
        # Check subdirectories
        for item in certs_dir.glob("**/*.crt"):
            if item.stem == stem:
                item.unlink()
                k_file = item.with_suffix(".key")
                if k_file.exists():
                    k_file.unlink()
                deleted = True
                break
                
    if not deleted:
        raise HTTPException(status_code=404, detail="Certificate file not found.")
        
    return {"status": "success", "message": f"Certificate {stem} revoked and deleted successfully."}


@router.post("/{cert_id}/renew", response_model=Dict[str, Any])
async def renew_certificate(cert_id: str, token: dict = Depends(require_admin)):
    """Renew (regenerate) an existing certificate file on disk."""
    from pathlib import Path
    base_dir = Path(__file__).parent.parent.parent
    certs_dir = base_dir / "certs"
    
    if not cert_id.startswith("cert-"):
        raise HTTPException(status_code=400, detail="Invalid certificate ID format.")
    stem = cert_id[5:]
    
    crt_file = certs_dir / f"{stem}.crt"
    key_file = certs_dir / f"{stem}.key"
    
    if not crt_file.exists():
        for item in certs_dir.glob("**/*.crt"):
            if item.stem == stem:
                crt_file = item
                key_file = item.with_suffix(".key")
                break
                
    if not crt_file.exists():
        raise HTTPException(status_code=404, detail="Certificate file not found for renewal.")
        
    try:
        with open(crt_file, "rb") as f:
            cert_data = f.read()
        old_cert = x509.load_pem_x509_certificate(cert_data)
        
        subject = old_cert.subject
        issuer = old_cert.issuer
        
        is_ca = False
        try:
            ext = old_cert.extensions.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
            is_ca = ext.value.ca
        except:
            pass
            
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048 if not is_ca else 4096,
        )
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow() - datetime.timedelta(seconds=60)
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )
        
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
        )
        
        if is_ca:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
        else:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            
        new_cert = builder.sign(private_key, hashes.SHA256())
        
        # Make sure directory exists for files
        crt_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        with open(crt_file, "wb") as f:
            f.write(new_cert.public_bytes(serialization.Encoding.PEM))
            
        return {"status": "success", "message": f"Certificate {stem} renewed successfully for 365 days."}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to renew certificate: {str(e)}")


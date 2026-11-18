"""
Enterprise bunyanx - VPN Preshared Key Encryption
=====================================================
Provides symmetric encryption for WireGuard preshared keys stored in the
database, using Fernet (AES-128-CBC + HMAC-SHA256).

Key management:
  - The encryption key is loaded from the VPN_PSK_KEY environment variable.
  - If VPN_PSK_KEY is not set, a key is derived from the system's JWT secret
    using HKDF-SHA256, so encryption works out-of-the-box.
  - In production, always set VPN_PSK_KEY to a dedicated 32-byte
    URL-safe base64 key generated via:
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import os
import base64
import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Lazy Fernet Singleton ─────────────────────────────────────────────────────

_fernet_instance = None


def _get_fernet():
    """Return a Fernet instance, initialised once from env or JWT secret."""
    global _fernet_instance
    if _fernet_instance is not None:
        return _fernet_instance

    try:
        from cryptography.fernet import Fernet
    except ImportError:
        logger.warning(
            "VPN Crypto: 'cryptography' package not installed — "
            "preshared keys will be stored in PLAINTEXT."
        )
        return None

    # 1. Try dedicated env var first
    env_key = os.environ.get("VPN_PSK_KEY")
    if env_key:
        try:
            _fernet_instance = Fernet(env_key.encode())
            logger.info("VPN Crypto: PSK encryption key loaded from VPN_PSK_KEY env var.")
            return _fernet_instance
        except Exception as exc:
            logger.error("VPN Crypto: Invalid VPN_PSK_KEY: %s", exc)

    # 2. Derive from JWT secret as fallback
    jwt_secret = os.environ.get("JWT_SECRET", "")
    if not jwt_secret:
        try:
            from dotenv import load_dotenv
            load_dotenv()
            jwt_secret = os.environ.get("JWT_SECRET", "")
        except ImportError:
            pass

    if jwt_secret:
        # HKDF-like derivation: SHA-256 hash of JWT secret → 32 bytes → base64
        derived = hashlib.sha256(
            f"vpn-psk-encryption:{jwt_secret}".encode()
        ).digest()
        fernet_key = base64.urlsafe_b64encode(derived)
        _fernet_instance = Fernet(fernet_key)
        logger.info("VPN Crypto: PSK encryption key derived from JWT_SECRET.")
        return _fernet_instance

    logger.warning(
        "VPN Crypto: No encryption key available — "
        "preshared keys will be stored in PLAINTEXT."
    )
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def encrypt_psk(plaintext: str) -> str:
    """Encrypt a preshared key for database storage.

    Args:
        plaintext: The raw preshared key string.

    Returns:
        Fernet-encrypted token (URL-safe base64) prefixed with 'ENC:',
        or the original plaintext if encryption is unavailable.
    """
    if not plaintext:
        return ""

    fernet = _get_fernet()
    if fernet is None:
        return plaintext

    try:
        token = fernet.encrypt(plaintext.encode("utf-8"))
        return "ENC:" + token.decode("utf-8")
    except Exception as exc:
        logger.error("VPN Crypto: Encryption failed: %s", exc)
        return plaintext


def decrypt_psk(stored: str) -> str:
    """Decrypt a preshared key retrieved from the database.

    Args:
        stored: The stored value — either 'ENC:<token>' or legacy plaintext.

    Returns:
        The decrypted preshared key string.
    """
    if not stored:
        return ""

    # Legacy plaintext: no prefix → return as-is
    if not stored.startswith("ENC:"):
        return stored

    fernet = _get_fernet()
    if fernet is None:
        logger.error(
            "VPN Crypto: Cannot decrypt PSK — encryption module unavailable. "
            "Returning empty string for safety."
        )
        return ""

    try:
        token = stored[4:].encode("utf-8")   # strip 'ENC:' prefix
        return fernet.decrypt(token).decode("utf-8")
    except Exception as exc:
        logger.error("VPN Crypto: Decryption failed: %s", exc)
        return ""


def is_encryption_available() -> bool:
    """Check if PSK encryption is available and configured."""
    return _get_fernet() is not None

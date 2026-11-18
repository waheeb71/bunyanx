"""
bunyanx NGFW — Startup Security Validator
=============================================
Validates that all required environment variables are set to non-default,
secure values before the application starts.

Raises SystemExit(1) with a clear, actionable error message if any
validation fails. This prevents deployment with insecure defaults.

Usage (called from main.py before app initialization):
    from system.security.startup_validator import validate_startup_security
    validate_startup_security()
"""

import os
import sys
import logging

logger = logging.getLogger(__name__)

# ─── Sentinel strings that indicate the value was NOT changed ─────────────────
_INSECURE_SENTINELS = {
    # Common "change me" patterns used in templates
    "change_this",
    "change_me",
    "changeme",
    "your-strong-passphrase-here",
    "admin123",
    "operator123",
    "replace_with",
    "replace_me",
    "placeholder",
    "todo",
    "fixme",
    "example",
    "test",
    "default",
    "secret",
    "password",
}

# Known-weak exact values from previous .env template
_KNOWN_WEAK_VALUES = {
    "change_this_to_a_secure_random_string_in_production",
    "your-strong-passphrase-here",
    "admin123_change_me",
    "operator123_change_me",
    # ── Defaults seeded by api/main.py on first-run — MUST be changed ──
    "Admin@1234",
    "Operator@1234",
    "admin@1234",
    "operator@1234",
}

# ─── Required environment variables ──────────────────────────────────────────
_REQUIRED_VARS = [
    {
        "key": "NGFW_SECRET_KEY",
        "min_length": 64,
        "description": "JWT signing secret (must be 64+ hex chars)",
        "generate_cmd": 'python -c "import secrets; print(secrets.token_hex(64))"',
    },
    {
        "key": "NGFW_ADMIN_PASSWORD",
        "min_length": 16,
        "description": "Admin API password (must be 16+ chars)",
        "generate_cmd": 'python -c "import secrets; print(secrets.token_urlsafe(24))"',
    },
    {
        "key": "NGFW_OPERATOR_PASSWORD",
        "min_length": 16,
        "description": "Operator API password (must be 16+ chars)",
        "generate_cmd": 'python -c "import secrets; print(secrets.token_urlsafe(24))"',
    },
    {
        "key": "NGFW_HA_SYNC_SECRET",
        "min_length": 32,
        "description": "HA state sync HMAC secret — shared between all cluster nodes (must be 32+ chars)",
        "generate_cmd": 'python -c "import secrets; print(secrets.token_hex(32))"',
    },
    {
        "key": "NGFW_CA_KEY_PASSWORD",
        "min_length": 16,
        "description": "Passphrase protecting the internal CA private key (must be 16+ chars)",
        "generate_cmd": 'python -c "import secrets; print(secrets.token_urlsafe(24))"',
    },
]

# ─── Security warnings (non-fatal but logged as CRITICAL) ────────────────────
_SECURITY_WARNINGS = [
    {
        "key": "NGFW_ALLOWED_ORIGINS",
        "dangerous_value": "*",
        "message": (
            "NGFW_ALLOWED_ORIGINS='*' allows any origin — this is a CSRF risk. "
            "Set to your exact dashboard URL(s) in production."
        ),
        "fatal_in_production": True,
    },
]


def _is_insecure(value: str) -> bool:
    """Return True if the value appears to be a placeholder/template value."""
    if not value:
        return True
    v_lower = value.lower()
    if value in _KNOWN_WEAK_VALUES:
        return True
    return any(sentinel in v_lower for sentinel in _INSECURE_SENTINELS)


def validate_startup_security() -> None:
    """
    Validate all required environment variables.

    Raises SystemExit(1) if any CRITICAL validation fails.
    Logs CRITICAL warnings for security misconfigurations that are not fatal.
    """
    env = os.getenv("NGFW_ENV", "production").lower()
    is_production = env == "production"

    errors = []
    warnings = []

    # ── Required variable checks ─────────────────────────────────────────────
    for spec in _REQUIRED_VARS:
        key = spec["key"]
        value = os.getenv(key, "")

        if not value:
            errors.append(
                f"  ✗ {key} is not set.\n"
                f"    Description : {spec['description']}\n"
                f"    Generate    : {spec['generate_cmd']}"
            )
            continue

        if _is_insecure(value):
            errors.append(
                f"  ✗ {key} appears to be a template/default value.\n"
                f"    Description : {spec['description']}\n"
                f"    Generate    : {spec['generate_cmd']}"
            )
            continue

        if len(value) < spec["min_length"]:
            errors.append(
                f"  ✗ {key} is too short "
                f"({len(value)} chars, minimum {spec['min_length']}).\n"
                f"    Generate    : {spec['generate_cmd']}"
            )

    # ── Security warnings ────────────────────────────────────────────────────
    for spec in _SECURITY_WARNINGS:
        key = spec["key"]
        value = os.getenv(key, "")
        if value == spec["dangerous_value"]:
            msg = f"  ⚠ {key}='{value}' — {spec['message']}"
            if spec.get("fatal_in_production") and is_production:
                errors.append(msg.replace("⚠", "✗"))
            else:
                warnings.append(msg)

    # ── Report warnings ──────────────────────────────────────────────────────
    for w in warnings:
        logger.critical(f"[SECURITY WARNING] {w}")

    # ── Halt on errors ───────────────────────────────────────────────────────
    if errors:
        separator = "=" * 70
        logger.critical(separator)
        logger.critical("STARTUP ABORTED — SECURITY VALIDATION FAILED")
        logger.critical(separator)
        logger.critical("")
        logger.critical("The following security requirements are not met:")
        logger.critical("")
        for err in errors:
            for line in err.split("\n"):
                logger.critical(line)
            logger.critical("")
        logger.critical("Fix these issues in your .env file, then restart.")
        logger.critical("See .env.example for generation instructions.")
        logger.critical(separator)
        sys.exit(1)

    logger.info(
        "[SECURITY] Startup validation passed — all required secrets are configured."
    )

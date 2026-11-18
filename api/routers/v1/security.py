from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
import os
from api.core.auth import require_admin

router = APIRouter(prefix="/api/v1/security", tags=["Security Validation"])

@router.get("/validation")
async def run_security_validation(token: dict = Depends(require_admin)) -> Dict[str, Any]:
    """
    Perform a live startup security validation check and return secret security status.
    This simulates/runs checks equivalent to validate_startup_security without crashing the app.
    """
    from system.security.startup_validator import _REQUIRED_VARS, _is_insecure
    
    results = []
    all_secure = True
    
    for spec in _REQUIRED_VARS:
        key = spec["key"]
        value = os.getenv(key, "")
        
        status = "secure"
        reason = "Configured with secure value"
        
        if not value:
            status = "missing"
            reason = "Secret key is not set in environment"
            all_secure = False
        elif _is_insecure(value):
            status = "insecure"
            reason = "Key matches a known insecure default or placeholder template"
            all_secure = False
        elif len(value) < spec["min_length"]:
            status = "weak"
            reason = f"Key is too short (length {len(value)} vs required {spec['min_length']})"
            all_secure = False
            
        results.append({
            "key": key,
            "description": spec["description"],
            "status": status,
            "reason": reason,
            "min_length_required": spec["min_length"]
        })
        
    return {
        "status": "secure" if all_secure else "insecure",
        "all_secure": all_secure,
        "checks": results
    }

@router.get("/warnings")
async def list_security_warnings(token: dict = Depends(require_admin)) -> Dict[str, Any]:
    """Scan and list non-fatal security warnings (e.g. wildcard CORS configuration)."""
    from system.security.startup_validator import _SECURITY_WARNINGS
    
    warnings = []
    for spec in _SECURITY_WARNINGS:
        key = spec["key"]
        value = os.getenv(key, "")
        if value == spec["dangerous_value"]:
            warnings.append({
                "key": key,
                "value": value,
                "severity": "critical" if spec.get("fatal_in_production") else "warning",
                "message": spec["message"]
            })
            
    return {"warnings": warnings}

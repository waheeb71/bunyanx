from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator
from datetime import datetime
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
import os

from system.database.database import get_db
from api.core.auth import require_admin, make_permission_checker
from modules.dlp.engine.dlp_engine import DLPEngine
from modules.dlp.config.loader import get_dlp_settings

import ipaddress

router = APIRouter(prefix="/api/v1/dlp", tags=["dlp"])
require_dlp = make_permission_checker("dlp")
limiter = Limiter(key_func=get_remote_address)

def validate_ip(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid IP address: {ip}")


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────────────────────────────────────

from modules.dlp.schemas import (
    DLPRuleCreate, DLPRuleResponse, DLPConfigSchema,
    BEFPFeedbackSchema, FeedbackReviewSchema, ERSTestSchema
)


# ─────────────────────────────────────────────────────────────────────────────
# Config Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/status")
def get_status(token: dict = Depends(require_dlp)):
    engine = DLPEngine()
    return {
        "status": "active",
        "module": "dlp",
        "is_active": engine.is_active,
        "befp_enabled": engine.befp_enabled,
        "block_on_match": engine.block_on_match,
        "deception_enabled": engine.deception_enabled,
    }


@router.get("/config", response_model=DLPConfigSchema)
def get_config(db: Session = Depends(get_db), token: dict = Depends(require_dlp)):
    from modules.dlp.repositories.config_repository import ConfigRepository
    repo = ConfigRepository(db)
    return repo.get_config()


@router.put("/config", response_model=DLPConfigSchema)
def update_config(
    new_config: DLPConfigSchema,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin),
):
    from modules.dlp.repositories.config_repository import ConfigRepository
    repo = ConfigRepository(db)
    config = repo.update_config(new_config)
    DLPEngine().reload()
    return config


# ─────────────────────────────────────────────────────────────────────────────
# Rules Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rules", response_model=List[DLPRuleResponse])
def list_rules(
    skip: int = 0, limit: int = 100,
    db: Session = Depends(get_db),
    token: dict = Depends(require_dlp),
):
    from modules.dlp.repositories.rule_repository import RuleRepository
    repo = RuleRepository(db)
    return repo.get_all(skip=skip, limit=limit)


@router.post("/rules", response_model=DLPRuleResponse, status_code=status.HTTP_201_CREATED)
def create_rule(
    rule: DLPRuleCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin),
):
    from modules.dlp.repositories.rule_repository import RuleRepository
    repo = RuleRepository(db)
    existing = repo.get_by_name(rule.name)
    if existing:
        raise HTTPException(status_code=400, detail="Rule name already exists")
    
    db_rule = repo.create(rule)
    DLPEngine().reload()
    return db_rule


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin),
):
    from modules.dlp.repositories.rule_repository import RuleRepository
    repo = RuleRepository(db)
    db_rule = repo.get_by_id(rule_id)
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    repo.delete(db_rule)
    DLPEngine().reload()
    return None


# ─────────────────────────────────────────────────────────────────────────────
# BEFP Behavioral Intelligence Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/behavioral/profile/{src_ip}")
def get_ip_behavioral_profile(
    src_ip: str,
    token: dict = Depends(require_dlp),
):
    """
    Returns the full behavioral profile for a given source IP.
    Shows: baseline velocity, accumulation per destination, recent chunk sizes.
    """
    src_ip = validate_ip(src_ip)
    profile = DLPEngine().get_ip_profile(src_ip)
    if not profile:
        raise HTTPException(status_code=404, detail=f"No behavioral profile found for {src_ip}")
    return profile


@router.get("/behavioral/msem-profile/{src_ip}")
def get_ip_msem_profile(
    src_ip: str,
    token: dict = Depends(require_dlp),
):
    """
    Returns the MSEM-Lite signal breakdown for a given source IP.

    Exposes the last computed values for:
    - Rényi entropy (H₂)
    - Permutation entropy (ordinal pattern diversity)
    - Lempel-Ziv complexity (compressibility proxy)
    - IPT spectral peak (inter-packet timing periodicity)

    Useful for research analysis and debugging the Signal 6 anomaly score.
    The msem_score field is the composite [0–1] value fed into ERS.
    """
    src_ip = validate_ip(src_ip)
    engine = DLPEngine()
    profile = engine.get_ip_profile(src_ip)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail=f"No behavioral profile found for {src_ip}. "
                   f"The IP must have sent at least one packet through the DLP engine.",
        )

    # REM-14 FIX: Do NOT expose signal weights in the API response.
    # Weights are an internal implementation detail — disclosing them allows
    # an attacker to craft payloads that score below the EXFILTRATION threshold
    # by precisely calibrating each signal. Removed `msem_signal_weights` field.
    return {
        "src_ip": src_ip,
        "note": (
            "MSEM-Lite signals are computed per-packet and embedded in each "
            "BEFP analysis result. Query /behavioral/test-ers with a recent "
            "hex payload to get a fresh MSEM breakdown."
        ),
        "profile_summary": profile,
    }


@router.get("/behavioral/high-risk")
def get_high_risk_ips(token: dict = Depends(require_dlp)):
    """
    Returns all IPs currently flagged as high-risk based on 24h accumulation.
    Sorted by total bytes transferred descending.
    """
    return DLPEngine().get_high_risk_profiles()


@router.post("/behavioral/test-ers")
def test_ers_score(
    payload: ERSTestSchema,
    token: dict = Depends(require_admin),
):
    """
    Ad-hoc ERS test endpoint for debugging/research.
    Submit a hex-encoded payload and get back a full BEFP analysis.
    """
    try:
        raw_bytes = bytes.fromhex(payload.payload_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex payload")

    befp_result, ai_result, findings = DLPEngine().evaluate_behavioral(
        raw_payload=raw_bytes,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        protocol=payload.protocol,
        dst_port=payload.dst_port,
    )

    if befp_result is None:
        return {"message": "Payload too small for BEFP analysis (min 32 bytes)", "ers": 0.0}

    return {
        "src_ip": payload.src_ip,
        "protocol": payload.protocol,
        "ers": befp_result.ers,
        "decision": ai_result.decision if ai_result else befp_result.decision,
        "final_score": ai_result.final_score if ai_result else befp_result.ers,
        "ai_model_active": ai_result.model_available if ai_result else False,
        "signals": {
            "entropy":      befp_result.signal_entropy,
            "velocity":     befp_result.signal_velocity,
            "chunking":     befp_result.signal_chunking,
            "protocol":     befp_result.signal_protocol,
            "accumulation": befp_result.signal_accumulation,
            "msem":         befp_result.signal_msem,
        },
        "msem_breakdown": {
            "renyi_h2":                 befp_result.msem_detail.renyi_score if befp_result.msem_detail else 0.0,
            "permutation_entropy":      befp_result.msem_detail.perm_score if befp_result.msem_detail else 0.0,
            "lempel_ziv_complexity":    befp_result.msem_detail.lz_score if befp_result.msem_detail else 0.0,
            "ipt_spectral_peak":        getattr(befp_result.msem_detail, "ipt_score", 0.0) if befp_result.msem_detail else 0.0,
            "tsallis_entropy":          getattr(befp_result.msem_detail, "tsallis_score", 0.0) if befp_result.msem_detail else 0.0,
            "payload_spectral_peak":    getattr(befp_result.msem_detail, "spectral_score", 0.0) if befp_result.msem_detail else 0.0,
            "kl_divergence":            getattr(befp_result.msem_detail, "div_score", 0.0) if befp_result.msem_detail else 0.0,
            "manifold_flatness_score":  getattr(befp_result.msem_detail, "mfs_score", 0.0) if befp_result.msem_detail else 0.0,
        },
        "payload_entropy_bits": befp_result.payload_entropy,
        "explanation": befp_result.explanation,
        "ai_explanation": ai_result.explanation if ai_result else "N/A",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Self-Learning Feedback Endpoint & Anti-Poisoning Workflow
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/feedback", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
def submit_befp_feedback(
    request: Request,
    feedback: BEFPFeedbackSchema,
    token: dict = Depends(require_dlp),
):
    """
    Submit analyst feedback on a BEFP detection event. Placed in 'pending' queue.
    label: 'true_positive' | 'false_positive'
    """
    if feedback.label not in ("true_positive", "false_positive"):
        raise HTTPException(
            status_code=400,
            detail="label must be 'true_positive' or 'false_positive'"
        )

    # In a real JWT, 'sub' holds the username
    submitted_by = token.get("sub", "analyst_user") if isinstance(token, dict) else "analyst"

    DLPEngine().submit_befp_feedback(
        event_id=feedback.event_id,
        label=feedback.label,
        submitted_by=submitted_by,
        features=feedback.features,
    )
    return {
        "message": "Feedback submitted and pending admin approval.",
        "status": "pending",
        "event_id": feedback.event_id,
    }


@router.get("/feedback/pending")
def get_pending_feedback(token: dict = Depends(require_admin)):
    """
    Returns a list of all pending feedback events awaiting admin approval.
    """
    return DLPEngine().get_pending_feedback()


@router.put("/feedback/{event_id}/review")
def review_feedback(
    event_id: str,
    payload: FeedbackReviewSchema,
    token: dict = Depends(require_admin),
):
    """
    Approve or reject a pending feedback event.
    Only approved events will trigger self-learning retraining.
    """
    action = payload.action
    if action not in ("approve", "reject"):
         raise HTTPException(status_code=400, detail="action must be 'approve' or 'reject'")
         
    admin_user = token.get("sub", "admin_user") if isinstance(token, dict) else "admin"
    
    success = DLPEngine().review_befp_feedback(event_id, action, admin_user)
    if not success:
         raise HTTPException(status_code=404, detail="Feedback event not found or already processed.")
         
    return {"message": f"Feedback {action}d successfully"}


# ───────────────────────────────────────────────────────────────────────────────
# Audit Log Endpoint (REM-07)
# ───────────────────────────────────────────────────────────────────────────────

@router.get("/audit")
def get_audit_log(
    limit: int = 100,
    token: dict = Depends(require_admin),
):
    """
    Returns the most recent DLP detection records from the structured audit trail.
    Access restricted to admin role only.

    Each record includes:
    - event_id, timestamp, src_ip, dst_ip, decision, ers, ai_score
    - match_count, match_types, action_taken, explanation
    - HMAC chain hash for tamper detection

    Returns up to `limit` records (default 100, max 1000).
    """
    limit = min(limit, 1000)   # hard cap
    records = DLPEngine().get_audit_log(limit=limit)
    return {
        "count": len(records),
        "audit_log_path": DLPEngine().get_audit_log_path(),
        "records": records,
    }


# ───────────────────────────────────────────────────────────────────────────────
# Settings Endpoint (REM-11)
# ───────────────────────────────────────────────────────────────────────────────

@router.get("/config/settings")
def get_yaml_settings(token: dict = Depends(require_admin)):
    """
    Returns the effective DLP settings loaded from settings.yaml.
    These are static deployment-time settings distinct from the DB-driven
    runtime config. Exposed here for diagnostics and health-check tooling.
    Admin only.
    """
    return get_dlp_settings()


@router.post("/behavioral/optimize-weights")
def optimize_ers_weights(token: dict = Depends(require_admin)):
    """
    Triggers offline Grid Search optimization of ERS signal weights
    based on accumulated analyst feedback labels.
    Admin only.
    """
    import threading
    from modules.dlp.engine.weight_optimizer import ERSWeightOptimizer

    optimizer = ERSWeightOptimizer()
    
    def _async_opt():
        optimizer.run()

    threading.Thread(target=_async_opt, daemon=True, name="ERS-Weight-Optimizer").start()
    return {
        "status": "optimization_launched",
        "message": "Grid search weight optimization launched in background. Check dlp_weights.json for updated weights upon completion.",
    }


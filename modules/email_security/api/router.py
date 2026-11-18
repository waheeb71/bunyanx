"""
Enterprise bunyanx — Email Security REST API
==========================================
Prefix: /api/v1/email_security

Endpoints:
  GET    /status          — Module live status + stats
  GET    /config          — Read persisted settings (admin/operator)
  PUT    /config          — Write persisted settings (admin only)
  POST   /config/reset    — Reset to defaults (admin only)
  GET    /whitelist       — Return whitelist (admin/operator)
  POST   /whitelist       — Add entry to whitelist (admin only)
  DELETE /whitelist/{entry} — Remove entry from whitelist (admin only)
  GET    /stats           — Aggregate inspection statistics from DB
  GET    /logs            — Recent email inspection log (paginated)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from api.core.auth import require_admin, make_permission_checker
logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/api/v1/email_security",
    tags=["Email Security"],
)

# Operators with "email" rule (or admins) can read
require_email = make_permission_checker("email")


# ── Pydantic Schemas ──────────────────────────────────────────────────────────


class PreprocessingConfig(BaseModel):
    decode_base64_body: Optional[bool] = None
    decode_quoted_printable: Optional[bool] = None
    extract_plain_text: Optional[bool] = None
    max_body_bytes: Optional[int] = None

class PhishingConfig(BaseModel):
    enabled: Optional[bool] = None
    custom_keywords: Optional[List[str]] = None
    keyword_threshold: Optional[int] = None
    weight: Optional[float] = None
    # Scoring sub-weights
    keyword_weight: Optional[float] = None
    urgency_weight: Optional[float] = None
    spoof_weight: Optional[float] = None
    url_excess_weight: Optional[float] = None
    # Per-signal coefficients
    urgency_score_per_hit: Optional[float] = None
    urgency_score_cap: Optional[float] = None
    spoof_score_value: Optional[float] = None
    url_excess_threshold: Optional[int] = None
    url_excess_score_per_extra: Optional[float] = None
    url_excess_score_cap: Optional[float] = None
    # Decision thresholds
    phishing_hard_threshold: Optional[float] = None
    phishing_soft_threshold: Optional[float] = None

class URLScannerConfig(BaseModel):
    enabled: Optional[bool] = None
    detect_redirects: Optional[bool] = None
    max_urls_per_email: Optional[int] = None
    reputation_check: Optional[bool] = None
    trusted_domains: Optional[List[str]] = None
    weight: Optional[float] = None
    # Per-signal scores
    score_ip_literal: Optional[float] = None
    score_shortener: Optional[float] = None
    score_suspicious_tld: Optional[float] = None
    score_excessive_subdomains: Optional[float] = None
    score_very_long_url: Optional[float] = None
    score_no_https: Optional[float] = None
    threat_intel_weight: Optional[float] = None
    flag_min_score: Optional[float] = None
    excessive_url_penalty: Optional[float] = None
    threat_intel_high: Optional[float] = None
    threat_intel_medium: Optional[float] = None

class AttachmentGuardConfig(BaseModel):
    enabled: Optional[bool] = None
    block_dangerous_extensions: Optional[bool] = None
    dangerous_extensions: Optional[List[str]] = None
    entropy_analysis: Optional[bool] = None
    entropy_threshold: Optional[float] = None
    max_attachment_size_mb: Optional[int] = None
    suspicious_extensions: Optional[List[str]] = None
    weight: Optional[float] = None
    # Per-signal scores
    score_dangerous_ext_blocked: Optional[float] = None
    score_dangerous_ext_allowed: Optional[float] = None
    score_suspicious_ext: Optional[float] = None
    score_oversized: Optional[float] = None
    score_high_entropy: Optional[float] = None
    score_mime_mismatch: Optional[float] = None
    action_block_threshold: Optional[float] = None
    action_flag_threshold: Optional[float] = None

class SenderReputationConfig(BaseModel):
    enabled: Optional[bool] = None
    block_disposable_domains: Optional[bool] = None
    custom_suspicious_domains: Optional[List[str]] = None
    dkim_check: Optional[bool] = None
    dmarc_check: Optional[bool] = None
    ip_reputation_check: Optional[bool] = None
    spf_check: Optional[bool] = None
    weight: Optional[float] = None
    # Per-signal scores
    score_spf_fail: Optional[float] = None
    score_spf_softfail: Optional[float] = None
    score_no_dkim: Optional[float] = None
    score_dkim_invalid: Optional[float] = None
    score_dmarc_none: Optional[float] = None
    score_dmarc_not_set: Optional[float] = None
    score_disposable: Optional[float] = None
    ip_reputation_threshold: Optional[float] = None
    ip_reputation_weight: Optional[float] = None
    dns_lifetime_seconds: Optional[float] = None
    dns_timeout_seconds: Optional[float] = None
    ip_lookup_timeout: Optional[float] = None

class SpamFilterConfig(BaseModel):
    enabled: Optional[bool] = None
    keyword_threshold: Optional[int] = None
    spam_threshold: Optional[float] = None
    weight: Optional[float] = None
    # Scoring sub-weights
    kw_weight: Optional[float] = None
    caps_weight: Optional[float] = None
    punct_weight: Optional[float] = None
    hidden_weight: Optional[float] = None
    # Per-signal coefficients
    caps_score_per_hit: Optional[float] = None
    caps_score_cap: Optional[float] = None
    punct_score_per_hit: Optional[float] = None
    punct_score_cap: Optional[float] = None
    hidden_score_per_hit: Optional[float] = None
    hidden_score_cap: Optional[float] = None
    spam_subject_prefix_score: Optional[float] = None
    minimal_text_html_score: Optional[float] = None

class SMTPCommandsConfig(BaseModel):
    enabled: Optional[bool] = None
    suspicious_commands: Optional[List[str]] = None
    weight: Optional[float] = None
    command_penalty: Optional[float] = None

class RiskScoringConfig(BaseModel):
    """Global risk thresholds + per-scanner override thresholds."""
    thresholds: Optional[Dict[str, float]] = None
    phishing_block_threshold: Optional[float] = None
    phishing_quarantine_threshold: Optional[float] = None
    url_block_threshold: Optional[float] = None
    url_quarantine_threshold: Optional[float] = None
    attachment_quarantine_threshold: Optional[float] = None
    vsde_block_threshold: Optional[float] = None
    plsf_quarantine_threshold: Optional[float] = None
    plsf_block_threshold: Optional[float] = None

class LoggingConfig(BaseModel):
    log_allowed: Optional[bool] = None
    log_blocked: Optional[bool] = None
    log_file: Optional[str] = None
    log_quarantined: Optional[bool] = None
    save_suspicious_content: Optional[bool] = None

class PLSFConfig(BaseModel):
    enabled: Optional[bool] = None
    db_path: Optional[str] = None
    ema_alpha: Optional[float] = None
    lambda_opt: Optional[float] = None
    max_models_in_memory: Optional[int] = None
    min_baseline_count: Optional[int] = None
    min_routing_length: Optional[int] = None
    model_mode: Optional[str] = None
    strict_language_routing: Optional[bool] = None
    telemetry_level: Optional[str] = None
    w_lexical: Optional[float] = None
    w_semantic: Optional[float] = None
    warmup_model: Optional[str] = None
    weight: Optional[float] = None

class VSDEConfig(BaseModel):
    enabled: Optional[bool] = None
    evasion_threshold: Optional[float] = None
    headless_browser: Optional[bool] = None
    vit_model: Optional[str] = None
    weight: Optional[float] = None

class EmailConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    mode: Optional[str] = Field(None, description="enforce | monitor | learning")
    monitored_ports: Optional[List[int]] = None

    # sub-section overrides — keys match EmailSettings sub-dataclasses
    preprocessing:     Optional[PreprocessingConfig]    = None
    phishing:          Optional[PhishingConfig]         = None
    url_scanner:       Optional[URLScannerConfig]       = None
    attachment_guard:  Optional[AttachmentGuardConfig]  = None
    sender_reputation: Optional[SenderReputationConfig] = None
    spam_filter:       Optional[SpamFilterConfig]       = None
    smtp_commands:     Optional[SMTPCommandsConfig]     = None
    risk_scoring:      Optional[RiskScoringConfig]      = None
    thresholds:        Optional[Dict[str, float]]       = None  # legacy flat key
    logging:           Optional[LoggingConfig]          = None
    vsde_config:       Optional[VSDEConfig]             = None
    plsf_config:       Optional[PLSFConfig]             = None


class WhitelistEntry(BaseModel):
    type: str = Field(..., description="email | domain | ip")
    value: str


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_db(request: Request):
    """Return the database manager from the bunyanx app state."""
    bunyanx = getattr(request.app.state, "bunyanx", None) or getattr(request.app.state, "bunyanx_app", None)
    if bunyanx and hasattr(bunyanx, "db"):
        return bunyanx.db
    raise HTTPException(
        status_code=503,
        detail="Database not available — bunyanx not fully initialized",
    )


def _get_or_create_config(db):
    """Return the single EmailSecurityConfig row, creating it if absent or empty."""
    from system.database.database import EmailSecurityConfig
    from sqlalchemy.orm.attributes import flag_modified
    import yaml
    import os

    _DIR = os.path.dirname(os.path.abspath(__file__))
    yaml_path = os.path.abspath(os.path.join(_DIR, "..", "config", "email.yaml"))
    defaults = {}
    try:
        if os.path.exists(yaml_path):
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                defaults = data.get("email_security", {})
    except Exception as e:
        logger.warning(f"Failed to load default email.yaml config: {e}")

    with db.sync_session() as session:
        cfg = session.query(EmailSecurityConfig).first()
        if cfg is None:
            cfg = EmailSecurityConfig()
            cfg.enabled = defaults.get("enabled", True)
            cfg.mode = defaults.get("mode", "enforce")
            cfg.monitored_ports = defaults.get("monitored_ports", [25, 587, 465, 143, 993, 110, 995])
            cfg.preprocessing = defaults.get("preprocessing", {})
            cfg.phishing = defaults.get("phishing_detection", {})
            cfg.url_scanner = defaults.get("url_scanner", {})
            cfg.attachment_guard = defaults.get("attachment_guard", {})
            cfg.sender_reputation = defaults.get("sender_reputation", {})
            cfg.spam_filter = defaults.get("spam_filter", {})
            cfg.smtp_commands = defaults.get("smtp_commands", {})
            
            # Combine risk_scoring thresholds
            rs_defaults = defaults.get("risk_scoring", {})
            thr_combined = dict(rs_defaults.get("thresholds", {"allow": 0.15, "quarantine": 0.35, "block": 0.65}))
            for k, v in rs_defaults.items():
                if k != "thresholds":
                    thr_combined[k] = v
            cfg.thresholds = thr_combined

            cfg.logging = defaults.get("logging", {})
            cfg.whitelist = defaults.get("whitelist", {"enabled": True, "emails": [], "domains": [], "ips": []})
            cfg.plsf_config = defaults.get("plsf", {})
            cfg.vsde_config = defaults.get("vsde", {})
            session.add(cfg)
            session.commit()
            session.refresh(cfg)
        else:
            modified = False
            if not cfg.preprocessing:
                cfg.preprocessing = defaults.get("preprocessing", {})
                flag_modified(cfg, "preprocessing")
                modified = True
            if not cfg.phishing:
                cfg.phishing = defaults.get("phishing_detection", {})
                flag_modified(cfg, "phishing")
                modified = True
            if not cfg.url_scanner:
                cfg.url_scanner = defaults.get("url_scanner", {})
                flag_modified(cfg, "url_scanner")
                modified = True
            if not cfg.attachment_guard:
                cfg.attachment_guard = defaults.get("attachment_guard", {})
                flag_modified(cfg, "attachment_guard")
                modified = True
            if not cfg.sender_reputation:
                cfg.sender_reputation = defaults.get("sender_reputation", {})
                flag_modified(cfg, "sender_reputation")
                modified = True
            if not cfg.spam_filter:
                cfg.spam_filter = defaults.get("spam_filter", {})
                flag_modified(cfg, "spam_filter")
                modified = True
            if not cfg.smtp_commands:
                cfg.smtp_commands = defaults.get("smtp_commands", {})
                flag_modified(cfg, "smtp_commands")
                modified = True
            if not cfg.thresholds:
                rs_defaults = defaults.get("risk_scoring", {})
                thr_combined = dict(rs_defaults.get("thresholds", {"allow": 0.15, "quarantine": 0.35, "block": 0.65}))
                for k, v in rs_defaults.items():
                    if k != "thresholds":
                        thr_combined[k] = v
                cfg.thresholds = thr_combined
                flag_modified(cfg, "thresholds")
                modified = True
            if not cfg.logging:
                cfg.logging = defaults.get("logging", {})
                flag_modified(cfg, "logging")
                modified = True
            if not cfg.whitelist:
                cfg.whitelist = defaults.get("whitelist", {"enabled": True, "emails": [], "domains": [], "ips": []})
                flag_modified(cfg, "whitelist")
                modified = True
            if not cfg.plsf_config:
                cfg.plsf_config = defaults.get("plsf", {})
                flag_modified(cfg, "plsf_config")
                modified = True
            if not cfg.vsde_config:
                cfg.vsde_config = defaults.get("vsde", {})
                flag_modified(cfg, "vsde_config")
                modified = True
            if modified:
                session.commit()
                session.refresh(cfg)
        return cfg


def _config_to_dict(cfg) -> Dict[str, Any]:
    thr = dict(cfg.thresholds or {})
    nested_thr = thr.get("thresholds") if isinstance(thr.get("thresholds"), dict) else thr
    global_thresholds = {
        "allow": float(nested_thr.get("allow", thr.get("allow", 0.15))),
        "quarantine": float(nested_thr.get("quarantine", thr.get("quarantine", 0.35))),
        "block": float(nested_thr.get("block", thr.get("block", 0.65))),
    }
    risk_scoring = {
        "thresholds": global_thresholds,
        "phishing_block_threshold": float(thr.get("phishing_block_threshold", 0.70)),
        "phishing_quarantine_threshold": float(thr.get("phishing_quarantine_threshold", 0.40)),
        "url_block_threshold": float(thr.get("url_block_threshold", 0.70)),
        "url_quarantine_threshold": float(thr.get("url_quarantine_threshold", 0.40)),
        "attachment_quarantine_threshold": float(thr.get("attachment_quarantine_threshold", 0.40)),
        "vsde_block_threshold": float(thr.get("vsde_block_threshold", 0.35)),
        "plsf_quarantine_threshold": float(thr.get("plsf_quarantine_threshold", 0.442)),
        "plsf_block_threshold": float(thr.get("plsf_block_threshold", 0.70)),
    }
    return {
        "enabled":           bool(cfg.enabled),
        "mode":              cfg.mode or "enforce",
        "monitored_ports":   cfg.monitored_ports or [25, 587, 465, 143, 993, 110, 995],
        "preprocessing":     cfg.preprocessing or {},
        "phishing":          cfg.phishing or {},
        "url_scanner":       cfg.url_scanner or {},
        "attachment_guard":  cfg.attachment_guard or {},
        "sender_reputation": cfg.sender_reputation or {},
        "spam_filter":       cfg.spam_filter or {},
        "smtp_commands":     cfg.smtp_commands or {},
        "thresholds":        global_thresholds,
        "risk_scoring":      risk_scoring,
        "logging":           cfg.logging or {},
        "whitelist":         cfg.whitelist or {"enabled": True, "emails": [], "domains": [], "ips": []},
        "plsf_config":       cfg.plsf_config or {},
        "vsde_config":       cfg.vsde_config or {},
    }


def _apply_config_to_settings(request: Request, db_dict: Dict[str, Any]):
    """Push updated config into the live EmailInspectorPlugin and settings singleton."""
    try:
        from modules.email_security.engine.core.settings import EmailSettings
        import modules.email_security.engine.core.settings as settings_mod

        new_cfg = EmailSettings.from_dict(db_dict)
        settings_mod._instance = new_cfg

        bunyanx = getattr(request.app.state, "bunyanx", None) or getattr(request.app.state, "bunyanx_app", None)
        if bunyanx:
            pipeline = getattr(bunyanx, "inspection_pipeline", None)
            if pipeline:
                plugin = pipeline.get_plugin("email_ai_inspector")
                if plugin:
                    plugin.cfg = new_cfg
        
        try:
            from system.core.framework.pipeline import _global_pipeline
            for p in _global_pipeline.get_plugins():
                if getattr(p, "name", None) == "email_ai_inspector":
                    p.cfg = new_cfg
        except Exception:
            pass

        logger.info("📧 EmailInspectorPlugin and settings singleton hot-reloaded with new settings")
    except Exception as exc:
        logger.error("Email hot-reload skipped: %s", exc, exc_info=True)


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/status")
async def get_status(request: Request, token: dict = Depends(require_email)):
    """Return live email security module status and counters."""
    try:
        bunyanx = getattr(request.app.state, "bunyanx", None) or getattr(request.app.state, "bunyanx_app", None)
        plugin_stats = {}
        if bunyanx:
            pipeline = getattr(bunyanx, "inspection_pipeline", None)
            if pipeline:
                from modules.email_security.engine.core.email_inspector import EmailInspectorPlugin
                plugin = pipeline.get_plugin("email_ai_inspector")
                if plugin:
                    plugin_stats = {
                        "inspected": getattr(plugin, "_inspected_count", 0),
                        "detected":  getattr(plugin, "_detected_count",  0),
                        "blocked":   getattr(plugin, "_blocked_count",   0),
                        "enabled":   plugin.cfg.enabled,
                        "mode":      plugin.cfg.mode,
                    }
        return {
            "module":  "email_security",
            "status":  "active" if plugin_stats else "loaded_no_pipeline",
            "version": "2.0.0",
            "plugin":  plugin_stats,
        }
    except Exception as exc:
        logger.error("Email API error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/config")
async def get_config(request: Request, token: dict = Depends(require_email)):
    """Return the persisted email security configuration."""
    try:
        db = _get_db(request)
        cfg = _get_or_create_config(db)
        return _config_to_dict(cfg)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Email API error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/config")
async def update_config(
    request: Request,
    update: EmailConfigUpdate,
    token: dict = Depends(require_admin),
):
    """Update email security configuration (admin only)."""
    try:
        from system.database.database import EmailSecurityConfig
        from sqlalchemy.orm.attributes import flag_modified
        db = _get_db(request)

        with db.sync_session() as session:
            cfg = session.query(EmailSecurityConfig).first()
            if cfg is None:
                cfg = EmailSecurityConfig()
                session.add(cfg)

            data = update.dict(exclude_none=True)

            if "enabled" in data:
                cfg.enabled = data["enabled"]
            if "mode" in data:
                if data["mode"] not in ("enforce", "monitor", "learning"):
                    raise HTTPException(
                        status_code=422,
                        detail="mode must be 'enforce', 'monitor', or 'learning'",
                    )
                cfg.mode = data["mode"]
            if "monitored_ports" in data:
                cfg.monitored_ports = list(data["monitored_ports"])
                flag_modified(cfg, "monitored_ports")

            # merge JSON sub-sections
            for section in (
                "preprocessing", "phishing", "url_scanner", "attachment_guard",
                "sender_reputation", "spam_filter", "smtp_commands",
                "logging", "whitelist", "vsde_config", "plsf_config"
            ):
                if section in data and data[section] is not None:
                    current = dict(getattr(cfg, section) or {})
                    current.update(data[section])
                    setattr(cfg, section, current)
                    flag_modified(cfg, section)

            # merge thresholds and risk_scoring into cfg.thresholds
            current_thr = dict(cfg.thresholds or {})
            if "thresholds" in data and data["thresholds"] is not None:
                current_thr.update(data["thresholds"])
            if "risk_scoring" in data and data["risk_scoring"] is not None:
                rs_dict = data["risk_scoring"]
                if "thresholds" in rs_dict and isinstance(rs_dict["thresholds"], dict):
                    current_thr.update(rs_dict["thresholds"])
                for k, v in rs_dict.items():
                    if k != "thresholds" and v is not None:
                        current_thr[k] = v

            cfg.thresholds = current_thr
            flag_modified(cfg, "thresholds")

            session.commit()
            session.refresh(cfg)
            result = _config_to_dict(cfg)

        _apply_config_to_settings(request, result)
        return {"status": "success", "config": result}

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Email API error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/config/reset", status_code=status.HTTP_200_OK)
async def reset_config(request: Request, token: dict = Depends(require_admin)):
    """Reset email security configuration to system defaults (admin only)."""
    try:
        from system.database.database import EmailSecurityConfig
        db = _get_db(request)
        with db.sync_session() as session:
            cfg = session.query(EmailSecurityConfig).first()
            if cfg:
                session.delete(cfg)
            session.commit()
        logger.info("📧 Email security config reset to defaults")
        return {"status": "success", "message": "Email security config reset to defaults."}
    except Exception as exc:
        logger.error("Email API error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/config/schema")
async def get_config_schema(token: dict = Depends(require_email)):
    """
    Return the full live schema of all configurable fields sourced from email.yaml.
    Useful for the UI to dynamically render a complete settings form with current defaults.
    """
    try:
        from modules.email_security.engine.core.settings import EmailSettings
        import dataclasses

        s = EmailSettings.load()

        def _dc_to_dict(obj):
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return {f.name: _dc_to_dict(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
            elif isinstance(obj, list):
                return [_dc_to_dict(i) for i in obj]
            return obj

        return {
            "phishing":          _dc_to_dict(s.phishing),
            "url_scanner":       _dc_to_dict(s.url_scanner),
            "attachment_guard":  _dc_to_dict(s.attachment_guard),
            "sender_reputation": _dc_to_dict(s.sender_reputation),
            "spam_filter":       _dc_to_dict(s.spam_filter),
            "smtp_commands":     _dc_to_dict(s.smtp_commands),
            "thresholds":        _dc_to_dict(s.thresholds),
            "plsf_config":       _dc_to_dict(s.plsf),
            "vsde_config":       _dc_to_dict(s.vsde),
        }
    except Exception as exc:
        logger.error("Email schema error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ── Whitelist Endpoints ───────────────────────────────────────────────────────


@router.get("/whitelist")
async def get_whitelist(request: Request, token: dict = Depends(require_email)):
    """Return the current email whitelist entries."""
    try:
        db = _get_db(request)
        cfg = _get_or_create_config(db)
        return cfg.whitelist or {"enabled": True, "emails": [], "domains": [], "ips": []}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Email API error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/whitelist", status_code=status.HTTP_201_CREATED)
async def add_whitelist_entry(
    request: Request,
    entry: WhitelistEntry,
    token: dict = Depends(require_admin),
):
    """Add an email, domain, or IP to the whitelist (admin only)."""
    if entry.type not in ("email", "domain", "ip"):
        raise HTTPException(status_code=422, detail="type must be 'email', 'domain', or 'ip'")
    try:
        from system.database.database import EmailSecurityConfig
        from sqlalchemy.orm.attributes import flag_modified
        db = _get_db(request)
        with db.sync_session() as session:
            cfg = session.query(EmailSecurityConfig).first()
            if cfg is None:
                cfg = EmailSecurityConfig()
                session.add(cfg)

            wl = dict(cfg.whitelist or {"enabled": True, "emails": [], "domains": [], "ips": []})
            key = entry.type + "s"       # email → emails, domain → domains, ip → ips
            items = list(wl.get(key, []))
            if entry.value not in items:
                items.append(entry.value)
            wl[key] = items
            cfg.whitelist = wl
            flag_modified(cfg, "whitelist")
            session.commit()

        return {
            "status": "success",
            "message": f"{entry.type} '{entry.value}' added to whitelist.",
        }
    except Exception as exc:
        logger.error("Email API error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/whitelist/{entry_type}/{value}", status_code=status.HTTP_200_OK)
async def remove_whitelist_entry(
    request: Request,
    entry_type: str,
    value: str,
    token: dict = Depends(require_admin),
):
    """Remove an entry from the whitelist (admin only)."""
    if entry_type not in ("email", "domain", "ip"):
        raise HTTPException(status_code=422, detail="entry_type must be 'email', 'domain', or 'ip'")
    try:
        from system.database.database import EmailSecurityConfig
        from sqlalchemy.orm.attributes import flag_modified
        db = _get_db(request)
        with db.sync_session() as session:
            cfg = session.query(EmailSecurityConfig).first()
            if cfg is None:
                raise HTTPException(status_code=404, detail="No config found")

            wl  = dict(cfg.whitelist or {})
            key = entry_type + "s"
            lst = list(wl.get(key, []))
            if value not in lst:
                raise HTTPException(status_code=404, detail=f"'{value}' not in whitelist")
            lst.remove(value)
            wl[key] = lst
            cfg.whitelist = wl
            flag_modified(cfg, "whitelist")
            session.commit()

        return {"status": "success", "message": f"{entry_type} '{value}' removed from whitelist."}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Email API error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ── Stats & Logs Endpoints ────────────────────────────────────────────────────


def _get_email_db_session():
    """Return a direct SQLAlchemy session for EmailLog queries."""
    from system.database.database import SessionLocal
    return SessionLocal()


@router.get("/stats")
async def get_stats(token: dict = Depends(require_email)):
    """
    Return aggregate email inspection statistics from the EmailLog table.
    Includes totals, decision breakdown, and top threat categories.
    """
    from modules.email_security.models import EmailLog
    from sqlalchemy import func
    from datetime import datetime, timedelta

    try:
        with _get_email_db_session() as db:
            total      = db.query(func.count(EmailLog.id)).scalar() or 0
            blocked    = db.query(func.count(EmailLog.id)).filter(EmailLog.decision == "block").scalar() or 0
            quarantine = db.query(func.count(EmailLog.id)).filter(EmailLog.decision == "quarantine").scalar() or 0
            allowed    = db.query(func.count(EmailLog.id)).filter(EmailLog.decision == "allow").scalar() or 0
            phishing   = db.query(func.count(EmailLog.id)).filter(EmailLog.is_phishing == True).scalar() or 0
            spam       = db.query(func.count(EmailLog.id)).filter(EmailLog.is_spam == True).scalar() or 0
            ai_mimicry = db.query(func.count(EmailLog.id)).filter(EmailLog.is_ai_mimicry == True).scalar() or 0
            visual_desync = db.query(func.count(EmailLog.id)).filter(EmailLog.has_visual_desync == True).scalar() or 0

            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            today_total = db.query(func.count(EmailLog.id)).filter(EmailLog.inspected_at >= today_start).scalar() or 0
            today_blocked = db.query(func.count(EmailLog.id)).filter(
                EmailLog.inspected_at >= today_start, EmailLog.decision == "block"
            ).scalar() or 0

            avg_risk = db.query(func.avg(EmailLog.risk_score)).scalar() or 0.0

            # Top 10 blocked senders
            top_senders = db.query(
                EmailLog.sender, func.count(EmailLog.id).label("count")
            ).filter(EmailLog.decision == "block") \
             .group_by(EmailLog.sender) \
             .order_by(func.count(EmailLog.id).desc()) \
             .limit(10).all()

            return {
                "total_inspected":    total,
                "total_blocked":      blocked,
                "total_quarantined":  quarantine,
                "total_allowed":      allowed,
                "phishing_detected":  phishing,
                "spam_detected":      spam,
                "ai_mimicry_detected":ai_mimicry,
                "visual_desync_detected": visual_desync,
                "today_total":        today_total,
                "today_blocked":      today_blocked,
                "avg_risk_score":     round(float(avg_risk), 3),
                "decision_breakdown": {
                    "allow":      allowed,
                    "quarantine": quarantine,
                    "block":      blocked,
                },
                "top_blocked_senders": [
                    {"sender": r.sender or "unknown", "count": r.count}
                    for r in top_senders
                ],
            }
    except Exception as exc:
        logger.error("Email API error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/logs")
async def get_logs(
    skip:     int = 0,
    limit:    int = 50,
    decision: Optional[str] = None,
    token:    dict = Depends(require_email),
):
    """
    Return paginated email inspection log.

    Query params:
      skip      — offset (default 0)
      limit     — page size (max 200, default 50)
      decision  — filter by 'allow' | 'quarantine' | 'block'

    FIX-7: sender/subject are partially redacted for privacy (GDPR/PDPL compliance).
    Admin role sees full data; operator role sees masked data.
    """
    from modules.email_security.models import EmailLog

    limit = min(limit, 200)
    # Admins see full PII; non-admin operators get masked output
    is_admin = token.get("role") == "admin"

    def _mask_sender(s: Optional[str]) -> Optional[str]:
        """Partial mask: 'attacker@evil.com' → 'att***@evil.com'"""
        if not s or is_admin:
            return s
        if "@" in s:
            local, domain = s.rsplit("@", 1)
            masked_local = local[:3] + "***" if len(local) > 3 else "***"
            return f"{masked_local}@{domain}"
        return s[:4] + "***" if len(s) > 4 else "***"

    def _mask_subject(s: Optional[str]) -> Optional[str]:
        """Partial mask: show first 6 chars only for non-admin."""
        if not s or is_admin:
            return s
        return s[:6] + "..." if len(s) > 6 else s

    try:
        with _get_email_db_session() as db:
            q = db.query(EmailLog).order_by(EmailLog.inspected_at.desc())
            if decision and decision in ("allow", "quarantine", "block"):
                q = q.filter(EmailLog.decision == decision)
            rows = q.offset(skip).limit(limit).all()

            return [
                {
                    "id":                 r.id,
                    "inspected_at":       r.inspected_at.isoformat() if r.inspected_at else None,
                    "sender":             _mask_sender(r.sender),
                    "subject":            _mask_subject(r.subject),
                    "src_ip":             r.src_ip,
                    "dst_port":           r.dst_port,
                    "decision":           r.decision,
                    "risk_score":         round(r.risk_score or 0, 3),
                    "phishing_score":     round(r.phishing_score or 0, 3),
                    "url_score":          round(r.url_score or 0, 3),
                    "spam_score":         round(r.spam_score or 0, 3),
                    "attachment_score":   round(r.attachment_score or 0, 3),
                    "sender_score":       round(r.sender_score or 0, 3),
                    "linguistic_anomaly": round(r.linguistic_anomaly_score or 0, 3),
                    "visual_desync":      round(r.visual_desync_ratio or 0, 3),
                    "is_phishing":        r.is_phishing,
                    "is_spam":            r.is_spam,
                    "has_malicious_url":  r.has_malicious_url,
                    "has_bad_attachment": r.has_bad_attachment,
                    "is_ai_mimicry":      r.is_ai_mimicry,
                    "has_visual_desync":  r.has_visual_desync,
                    "brand_spoof":        r.brand_spoof,
                    "matched_keywords":   r.matched_keywords or [],
                    "flagged_urls":        r.flagged_urls or [],
                    "finding_categories": r.finding_categories or [],
                    "latency_ms":         r.latency_ms,
                }
                for r in rows
            ]
    except Exception as exc:
        logger.error("Email API error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/model/metrics")
async def get_model_metrics(token: dict = Depends(require_email)):
    """Return PLSF model training metrics and report."""
    import os
    import json
    from modules.email_security.engine.scanners.psycho_linguistic_profiler import _DEFAULT_MODELS_DIR

    metrics_path = os.path.join(_DEFAULT_MODELS_DIR, "plsf_training_report.json")
    if not os.path.exists(metrics_path):
        metrics_path = os.path.join(_DEFAULT_MODELS_DIR, "plsf_train_metrics.json")

    if not os.path.exists(metrics_path):
        _DIR = os.path.dirname(os.path.abspath(__file__))
        email_sec_models_dir = os.path.abspath(os.path.join(_DIR, "..", "models"))
        metrics_path = os.path.join(email_sec_models_dir, "plsf_training_report.json")
        if not os.path.exists(metrics_path):
            metrics_path = os.path.join(email_sec_models_dir, "plsf_train_metrics.json")

    if not os.path.exists(metrics_path):
        raise HTTPException(
            status_code=404,
            detail="Model metrics file not found."
        )

    try:
        with open(metrics_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.error("Failed to load model metrics: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to read model metrics file."
        )



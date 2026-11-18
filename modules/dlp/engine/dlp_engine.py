import logging
import re
import threading
import uuid
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

from system.database.database import SessionLocal
from modules.dlp.config.loader import get_max_scan_chunk_bytes
from modules.dlp.models import DLPRule, DLPConfig
from modules.dlp.engine.regex_matcher import RegexMatcher
from modules.dlp.engine.entropy_analyzer import BEFPAnalyzer, BEFPResult
from modules.dlp.ai.intelligence_layer import BEFPIntelligenceLayer, AIInferenceResult
from modules.dlp.audit.audit_logger import DLPAuditLogger

logger = logging.getLogger(__name__)

@dataclass
class CompiledDLPRule:
    id: int
    name: str
    pattern: re.Pattern
    severity: str
    description: str


class DLPEngine:
    """
    Centralized Core for Data Loss Prevention.

    Integrates three detection layers:
    1. Built-in Regex Matcher   — SSN, Credit Cards, IBAN, etc.
    2. Custom DB Rules          — Admin-defined Regex patterns
    3. BEFP + AI Layer          — Behavioral Entropy Flow Profiling
                                  + Isolation Forest anomaly detection
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DLPEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._compiled_rules: List[CompiledDLPRule] = []
        self._config: Optional[DLPConfig] = None
        self._reload_lock = threading.RLock()

        # ── Behavioral Engine (shared singletons) ─────────────
        self._befp = BEFPAnalyzer()
        self._ai   = BEFPIntelligenceLayer()

        # REM-06: Restore behavioral profiles from last snapshot, then
        # start a background thread to periodically save new snapshots.
        self._befp.restore_snapshot()
        self._befp.start_periodic_snapshot()

        # REM-07: Initialise audit logger singleton
        self._audit = DLPAuditLogger.get_instance()

        self.reload()
        self._initialized = True
        logger.info("[DLP] DLPEngine initialized (profiles restored, persistence active, audit active).")

    def reload(self):
        """Reloads config and custom rules from the database into RAM."""
        with self._reload_lock:
            compiled = []
            failed_rules = []
            try:
                with SessionLocal() as db:
                    from system.database.database import Base
                    import modules.dlp.models
                    try:
                        Base.metadata.create_all(bind=db.get_bind())
                    except Exception:
                        pass

                    conf = db.query(DLPConfig).first()
                    if not conf:
                        conf = DLPConfig()
                        db.add(conf)
                        db.commit()
                        db.refresh(conf)
                    self._config = conf

                    db_rules = db.query(DLPRule).filter(DLPRule.enabled == True).all()
                    for r in db_rules:
                        try:
                            pat = re.compile(r.pattern, re.IGNORECASE)
                            compiled.append(CompiledDLPRule(
                                id=r.id,
                                name=r.name,
                                pattern=pat,
                                severity=r.severity,
                                description=r.description or f"DLP rule '{r.name}' triggered"
                            ))
                        except Exception as e:
                            # SECURITY FIX: Track failed rules and alert admins
                            logger.error(
                                "[DLP] Failed to compile DLP rule id=%d name='%s': %s",
                                r.id, r.name, e
                            )
                            failed_rules.append((r.id, r.name, str(e)))

                    self._compiled_rules = compiled

                    # Alert admin if any rules failed compilation
                    if failed_rules:
                        logger.warning(
                            "[DLP] Alerting admin: %d rules failed compilation during reload",
                            len(failed_rules)
                        )
            except Exception as exc:
                logger.warning(
                    "[DLP] Database reload warning: %s — using default in-memory config",
                    exc
                )
                if self._config is None:
                    from types import SimpleNamespace
                    self._config = SimpleNamespace(
                        enabled=True,
                        mode="enforce",
                        inspect_outgoing_files=True,
                        max_file_size_mb=20
                    )
                    if failed_rules:
                        logger.critical(
                            "[DLP] %d DLP rule(s) failed to compile and are NOT active: %s",
                            len(failed_rules),
                            [r[1] for r in failed_rules]
                        )

                self._compiled_rules = compiled
            
            self._sync_befp_weights()
            logger.info(f"DLPEngine reloaded: {len(self._compiled_rules)} custom rules active.")

    def _get_float_conf(self, attr: str, default: float) -> float:
        if not self._config:
            return default
        val = getattr(self._config, attr, default)
        try:
            return float(val)
        except (TypeError, ValueError):
            return default

    def _sync_befp_weights(self):
        """Push DB weight and threshold config into live BEFPAnalyzer dicts.
        
        SECURITY FIX (FIX-04): Uses atomic reference swap instead of
        in-place dict mutation to prevent race conditions with concurrent
        analyze() calls reading ERS_WEIGHTS and ERS_THRESHOLDS.
        """
        from modules.dlp.engine import entropy_analyzer as ea
        if self._config:
            w_entropy      = self._get_float_conf('w_entropy', 0.22)
            w_velocity     = self._get_float_conf('w_velocity', 0.18)
            w_chunking     = self._get_float_conf('w_chunking', 0.10)
            w_protocol     = self._get_float_conf('w_protocol', 0.15)
            w_accumulation = self._get_float_conf('w_accumulation', 0.10)
            w_msem = round(1.0 - sum([
                w_entropy, w_velocity, w_chunking, w_protocol, w_accumulation
            ]), 4)

            # Build a NEW dict and swap reference atomically (GIL-safe)
            new_weights = {
                "entropy":      w_entropy,
                "velocity":     w_velocity,
                "chunking":     w_chunking,
                "protocol":     w_protocol,
                "accumulation": w_accumulation,
                "msem":         w_msem,
            }
            # Single reference assignment — atomic under CPython GIL
            ea.ERS_WEIGHTS = new_weights
            logger.info(f"ERS weights synced from DB (atomic swap): {new_weights}")

            # Sync dynamic ERS thresholds from DB config (alert & block thresholds)
            alert_thresh = self._get_float_conf('befp_alert_threshold', 0.35)
            block_thresh = self._get_float_conf('befp_block_threshold', 0.80)
            if alert_thresh >= block_thresh:
                alert_thresh = max(0.01, block_thresh - 0.10)
            suspicious_thresh = round(alert_thresh + (block_thresh - alert_thresh) * (5.0 / 9.0), 4)

            new_thresholds = {
                "NORMAL":       alert_thresh,
                "SUSPICIOUS":   suspicious_thresh,
                "HIGH_RISK":    block_thresh,
                "EXFILTRATION": 1.01,
            }
            ea.ERS_THRESHOLDS = new_thresholds
            logger.info(f"ERS thresholds synced from DB (atomic swap): {new_thresholds}")

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def is_active(self):
        return self._config.is_active if self._config else False

    @property
    def block_on_match(self):
        return self._config.block_on_match if self._config else False

    @property
    def deception_enabled(self):
        return self._config.deception_enabled if self._config else False

    @property
    def befp_enabled(self):
        return getattr(self._config, 'befp_enabled', True) if self._config else True

    @property
    def befp_block_threshold(self) -> float:
        """ERS threshold above which BEFP triggers a block action."""
        return self._get_float_conf('befp_block_threshold', 0.80)

    @property
    def befp_alert_threshold(self) -> float:
        """ERS threshold above which BEFP triggers an alert finding."""
        return self._get_float_conf('befp_alert_threshold', 0.35)

    # ── Main Evaluation ────────────────────────────────────────────────────────

    def evaluate(self, text_data: str, src_ip: str = "", dst_ip: str = "",
                 dst_port: int = 0, protocol: str = "TCP") -> List[Dict]:
        """
        Layer 1 & 2: Scans text against built-in and custom compiled rules.
        Returns a list of finding dicts.

        REM-12 FIX: All content matches (CC, SSN, IBAN, etc.) are now audited
        via DLPAuditLogger so they appear in the forensic trail.
        REM-13 FIX: Callers must catch exceptions; internal errors are logged
        as ERROR (not silently swallowed).
        """
        findings = []
        if not text_data:
            return findings

        # [HIGH RISK MITIGATION] Prevent ReDoS on massive strings by limiting input size
        # SECURITY FIX (T1): Replaced hard truncation with an overlapping chunking
        # strategy to prevent attackers from bypassing the DLP engine by padding
        # the payload with > 100KB of random data before the sensitive exfiltration.
        MAX_TEXT_SIZE = get_max_scan_chunk_bytes()  # Max chunk size (bytes) for regex scanning per chunk
        OVERLAP_SIZE = 256          # Overlap to catch patterns crossing boundaries
        
        chunks = []
        if len(text_data) > MAX_TEXT_SIZE:
            logger.warning(
                "[DLP] Text data exceeds %d bytes (%d). Chunking with overlap for regex scanning.",
                MAX_TEXT_SIZE, len(text_data),
            )
            start = 0
            while start < len(text_data):
                chunks.append(text_data[start:start + MAX_TEXT_SIZE])
                start += MAX_TEXT_SIZE - OVERLAP_SIZE
        else:
            chunks.append(text_data)

        found_signatures = set()
        # Cap total findings per call: 50 is more than enough to make a block/allow
        # decision. Collecting 1768 objects wastes 1.7s and floods the pipeline.
        MAX_FINDINGS_PER_CALL = 50

        for chunk in chunks:
            if len(findings) >= MAX_FINDINGS_PER_CALL:
                logger.debug(
                    "[DLP] findings cap reached (%d). Stopping scan early.",
                    MAX_FINDINGS_PER_CALL,
                )
                break
            # Layer 1: Built-in Regex (SSN, CC, IBAN...)
            builtin_matches = RegexMatcher.scan_text(chunk)
            for bm in builtin_matches:
                if len(findings) >= MAX_FINDINGS_PER_CALL:
                    break
                sig_key = f"BUILTIN_{bm['type']}:{bm['value_masked']}"
                if sig_key not in found_signatures:
                    found_signatures.add(sig_key)
                    findings.append({
                        "rule_name": f"BUILTIN_{bm['type']}",
                        "severity": "HIGH",
                        "description": f"Standard DLP Pattern matched: {bm['type']} ({bm['value_masked']})",
                        "match_count": 1,
                        "type": bm["type"],
                    })

            # Layer 2: Custom DB Rules
            with self._reload_lock:
                for rule in self._compiled_rules:
                    if len(findings) >= MAX_FINDINGS_PER_CALL:
                        break
                    try:
                        matches = rule.pattern.findall(chunk)
                        if matches:
                            sig_key = f"CUSTOM_{rule.id}"
                            if sig_key not in found_signatures:
                                found_signatures.add(sig_key)
                                findings.append({
                                    "rule_id": rule.id,
                                    "rule_name": rule.name,
                                    "severity": rule.severity,
                                    "description": f"{rule.description} (Matched {len(matches)} times in chunk)",
                                    "match_count": len(matches),
                                    "type": rule.name,
                                })
                    except Exception as e:
                        logger.error("[DLP] Custom rule '%s' raised an error: %s", rule.name, e)

        # REM-12: Audit content matches (even NORMAL traffic with matches gets audited)
        if findings:
            event_id = str(uuid.uuid4())
            # Determine actual action: BLOCK if policy says so, MONITOR otherwise.
            # Previously this was hardcoded to "MONITOR" which caused audit logs to
            # falsely report MONITOR even when DLP was configured to block.
            audit_action = "BLOCK" if self.block_on_match else "MONITOR"
            self._audit.log_detection(
                event_id=event_id,
                src_ip=src_ip or "unknown",
                dst_ip=dst_ip or "unknown",
                protocol=protocol,
                decision="CONTENT_MATCH",
                findings=findings,
                ers=0.0,
                ai_score=0.0,
                final_score=0.0,
                explanation=[f.get("description", "") for f in findings],
                action_taken=audit_action,
                dst_port=dst_port,
            )

        # ── Publish to EventBus for audio alert ──────────────────────────
        # Only publish when the action is meaningful:
        #   BLOCK mode   → always publish (explicit policy decision)
        #   MONITOR mode → only publish for high-severity patterns (SSN, PASSPORT, IBAN)
        #                  OR when many patterns found (≥3), to avoid noise from
        #                  normal commerce traffic with a single credit card.
        if findings:
            _HIGH_SEVERITY_TYPES = {
                "SSN", "PASSPORT", "IBAN", "TAX_ID", "NATIONAL_ID",
                "PRIVATE_KEY", "AWS_KEY", "API_KEY", "CREDIT_CARD",
            }
            _pattern_types = list({
                f.get("type", f.get("rule_name", "UNKNOWN")) for f in findings
            })
            _has_critical = bool(_HIGH_SEVERITY_TYPES & set(_pattern_types))
            
            # Custom rules are always critical
            _has_custom = any(not str(f.get("rule_name", "")).startswith("BUILTIN_") for f in findings)
            _has_critical = _has_critical or _has_custom
            
            _non_critical_count = sum(f.get("match_count", 1) for f in findings if f.get("type") not in _HIGH_SEVERITY_TYPES and str(f.get("rule_name", "")).startswith("BUILTIN_"))
            _many_matches = _non_critical_count >= 3

            _should_publish = (
                _has_critical                 # SSN / IBAN / passport / Custom / CC → always alert
                or _many_matches              # bulk exfiltration attempt (>= 3 non-critical)
            )

            if _should_publish:
                try:
                    import time
                    from system.events.bus import EventBus
                    from system.events.topics import Topics as _Topics

                    _pub_payload = {
                        "event_id":      str(uuid.uuid4()),
                        "timestamp_utc": time.time(),
                        "module":        "dlp",
                        "direction":     "REQUEST",
                        "src_ip":        src_ip or "unknown",
                        "dst_ip":        dst_ip or "unknown",
                        "src_port":      0,
                        "dst_port":      dst_port,
                        "protocol":      protocol,
                        "decision":      "CONTENT_MATCH",
                        "action_taken":  "BLOCK" if self.block_on_match else "MONITOR",
                        "action":        "BLOCK" if self.block_on_match else "MONITOR",
                        "severity":      "CRITICAL" if _has_critical else "HIGH",
                        "ers":           0.0,
                        "ai_score":      0.0,
                        "final_score":   0.0,
                        "match_count":   len(findings),
                        "pattern_types": _pattern_types,
                        "description":   (
                            f"DLP: {len(findings)} pattern(s) detected: "
                            f"{', '.join(_pattern_types[:3])}"
                        ),
                    }
                    EventBus.publish_from_thread(_Topics.DLP_INCIDENT, _pub_payload)
                except Exception as _de:
                    logger.debug(f"[DLP] Could not publish pattern event: {_de}")

        return findings

    def evaluate_behavioral(
        self,
        raw_payload: bytes,
        src_ip: str,
        dst_ip: str,
        protocol: str = "TCP",
        dst_port: int = 0,
    ) -> Tuple[Optional[BEFPResult], Optional[AIInferenceResult], List[Dict]]:
        """
        Layer 3: BEFP + AI behavioral analysis on raw payload bytes.

        Returns:
            (befp_result, ai_result, findings_list)
            findings_list is non-empty only when ERS exceeds alert threshold.
        """
        if not self.befp_enabled or not raw_payload:
            return None, None, []

        findings = []

        # [REMEDIATION-TASK-2] Removed try...except swallowing exceptions here. 
        # Exceptions now bubble up to dlp_inspector.py to trigger the Fail-Closed policy.
        # BEFP (deterministic 5-signal analysis)
        befp_result = self._befp.analyze(
            src_ip=src_ip,
            dst_ip=dst_ip,
            payload=raw_payload,
            protocol=protocol,
            dst_port=dst_port,
        )

        if befp_result is None:
            return None, None, []

        # AI inference (Isolation Forest + Decision Fusion)
        ai_result = self._ai.infer(
            befp_result=befp_result,
            dst_port=dst_port,
            payload_size=len(raw_payload),
        )

        # Surface findings only when AI anomaly score or deterministic ERS exceeds
        # the user-configured alert threshold (befp_alert_threshold, default 0.35).
        alert_thresh = self.befp_alert_threshold
        if ai_result.final_score >= alert_thresh or befp_result.ers >= alert_thresh:
            finding = befp_result.to_finding_dict()
            # Upgrade severity and description with AI fusion data
            finding["description"] += f" | {ai_result.explanation}"
            finding["rule_name"] = f"BEHAV_{ai_result.decision}"
            finding["severity"] = {
                "NORMAL": "LOW",
                "SUSPICIOUS": "MEDIUM",
                "HIGH_RISK": "HIGH",
                "EXFILTRATION": "CRITICAL",
            }.get(ai_result.decision, "MEDIUM")
            finding["ai_score"] = ai_result.ai_anomaly_score
            finding["final_score"] = ai_result.final_score
            finding["model_available"] = ai_result.model_available
            findings.append(finding)

            log_fn = logger.critical if ai_result.decision == "EXFILTRATION" else \
                     logger.warning if ai_result.decision in ("HIGH_RISK", "SUSPICIOUS") else \
                     logger.debug
            log_fn(
                f"[BEFP] {ai_result.decision} | IP={src_ip} proto={protocol} "
                f"ERS={befp_result.ers:.3f} AI={ai_result.ai_anomaly_score:.3f} "
                f"Final={ai_result.final_score:.3f}"
            )

            # REM-07: Audit every BEFP alert to the structured audit trail
            event_id = str(uuid.uuid4())
            action = "BLOCK" if (
                ai_result.final_score >= self.befp_block_threshold and self.block_on_match
            ) else "MONITOR"
            self._audit.log_detection(
                event_id=event_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                decision=ai_result.decision,
                findings=findings,
                ers=befp_result.ers,
                ai_score=ai_result.ai_anomaly_score,
                final_score=ai_result.final_score,
                explanation=befp_result.explanation,
                action_taken=action,
                dst_port=dst_port,
            )

            # Publish dlp.incident to EventBus so audio alert system is notified
            try:
                import time
                import asyncio
                from system.events.bus import EventBus
                from system.events.topics import Topics

                _pub_payload = {
                    "event_id":      event_id,
                    "timestamp_utc": time.time(),
                    "module":        "dlp",
                    "direction":     "REQUEST",
                    "src_ip":        src_ip,
                    "dst_ip":        dst_ip,
                    "src_port":      0,
                    "dst_port":      dst_port,
                    "protocol":      protocol,
                    "decision":      ai_result.decision,
                    "action_taken":  action,
                    "action":        action,
                    "severity":      finding.get("severity", "MEDIUM"),
                    "ers":           befp_result.ers,
                    "ai_score":      ai_result.ai_anomaly_score,
                    "final_score":   ai_result.final_score,
                    "match_count":   len(findings),
                    "pattern_types": [finding.get("rule_name", "BEHAVIORAL")],
                    "description":   finding.get("description", "BEFP Anomaly Detected"),
                }

                async def _pub():
                    bus = await EventBus.instance()
                    await bus.publish(Topics.DLP_INCIDENT, _pub_payload)

                try:
                    asyncio.get_running_loop().create_task(_pub())
                except RuntimeError:
                    import threading
                    threading.Thread(target=lambda: asyncio.run(_pub()), daemon=True).start()
            except Exception as _de:
                logger.warning(f"[DLP] Failed to publish dlp.incident: {_de}")

        return befp_result, ai_result, findings

    def get_ip_profile(self, src_ip: str) -> Optional[dict]:
        """Returns the behavioral profile for a given IP (for the API endpoint)."""
        return self._befp.get_profile_summary(src_ip)

    def get_high_risk_profiles(self) -> List[dict]:
        """Returns all IPs with high accumulation scores."""
        return self._befp.get_all_high_risk_profiles()

    def get_pending_feedback(self) -> List[dict]:
        """Returns pending analyst feedback."""
        return self._ai.get_pending_feedback()

    def submit_befp_feedback(self, event_id: str, label: str, submitted_by: str,
                             features: Optional[dict] = None) -> None:
        """Proxies analyst feedback to the AI layer + audits the action (REM-07)."""
        self._ai.submit_feedback(event_id, label, submitted_by, features)
        self._audit.log_feedback(
            event_id=event_id,
            label=label,
            submitted_by=submitted_by,
        )

    def review_befp_feedback(self, event_id: str, action: str,
                             admin_user: str) -> bool:
        """Approves or rejects pending feedback + audits the admin decision (REM-07)."""
        success = self._ai.review_feedback(event_id, action, admin_user)
        if success:
            self._audit.log_feedback(
                event_id=event_id,
                label="",
                submitted_by="",
                review_action=action,
                reviewed_by=admin_user,
            )
            self._audit.log_admin_action(
                admin_user=admin_user,
                action=f"FEEDBACK_{action.upper()}",
                target=f"event_id={event_id}",
            )
        return success

    def get_audit_log(self, limit: int = 100) -> List[dict]:
        """Returns recent DLP detection records from the audit trail."""
        return self._audit.get_recent_detections(limit=limit)

    def get_audit_log_path(self) -> str:
        """Returns the path to the active audit log file (for health endpoints)."""
        return self._audit.audit_log_path()

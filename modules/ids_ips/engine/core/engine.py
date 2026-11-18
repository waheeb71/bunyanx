"""
Intrusion Prevention System (IPS) Engine
Coordinats Signature-based and Anomaly-based detection.
"""

import logging
import time
import threading
from typing import List, Optional
from system.policy.schema import IPSRule, PolicyContext, Action
from modules.ids_ips.policy.smart_blocker.threat_intelligence import ThreatIntelligence, ThreatLevel
from .reputation import ReputationEngine, ReputationLevel
from .signatures import SignatureEngine
from .anomaly import AnomalyBridge
from modules.ids_ips.engine.anomaly_detector import AnomalyDetector, TrafficFeatures
from modules.ids_ips.models import IPSConfig, IPSSignature
from sqlalchemy.orm import Session
from system.database.database import SessionLocal
from system.core.deception.unified_engine import UnifiedDeceptionEngine

logger = logging.getLogger(__name__)

# Config cache TTL in seconds (1 minute) - FIX: Prevent DB query per packet
CONFIG_CACHE_TTL = 60.0

class IPSEngine:
    """
    Intrusion Prevention System.
    Layers:
    1. Threat Intelligence (Known Bad IPs/Domains)
    2. Reputation Check
    3. Signature Matching (Snort-like rules)
    4. AI Anomaly Detection (Behavioral)
    """
    
    def __init__(self):
        self.logger = logger
        self.threat_intel = ThreatIntelligence()
        self.reputation = ReputationEngine()
        self.signature_engine = SignatureEngine()
        self.signature_engine.load_defaults()
        self.unified_deception = UnifiedDeceptionEngine()
        
        # FIX: Config cache to prevent per-packet DB queries
        self._config_cache = None
        self._config_cache_time = 0.0
        self._config_cache_lock = threading.Lock()
        
        # Cache for UBA user profiles to prevent DB queries in hot path
        self._uba_cache = None
        self._uba_cache_time = 0.0
        self._uba_cache_ttl = 60.0
        self._uba_cache_lock = threading.Lock()
        
        # Paths to AI models (centralized in ml/models/)
        from ml.models import get_model_path
        try:
            l3_path = get_model_path('ids_ips', 'l3_anomaly_detector.pkl')
        except (FileNotFoundError, ValueError):
            l3_path = None
        try:
            l7_path = get_model_path('ids_ips', 'l7_dpi_classifier.pkl')
        except (FileNotFoundError, ValueError):
            l7_path = None
        
        # It's better to load the models once here rather than on every evaluate to save latency
        self.ai_detector = AnomalyDetector(model_path=l3_path, l7_model_path=l7_path)

        # ── AnomalyBridge: secondary ML anomaly signal (bridges to AnomalyDetector)
        # Previously existed as an orphaned stub — now wired into the evaluation pipeline.
        self.anomaly_bridge = AnomalyBridge()

        self.config = IPSConfig(is_active=True, mode="blocking", deception_enabled=True)
        self.default_action = Action.ALLOW

        # ── Startup diagnostics — confirm both detectors are active ────────────
        logger.info(
            "[IPS] AnomalyDetector initialised | model_type=%s | l3=%s | l7=%s",
            getattr(self.ai_detector, 'model_type', 'none'),
            'loaded' if self.ai_detector.model else 'heuristic',
            'loaded' if self.ai_detector.l7_model else 'none',
        )
        logger.info(
            "[IPS] AnomalyBridge initialised | ml_active=%s",
            self.anomaly_bridge.is_available,
        )
        
    def get_db_session(self) -> Session:
        return SessionLocal()
    
    def sync_config(self):
        """Loads DB Config and Update Signatures Engine with caching."""
        # FIX: Use cached config if still valid (within TTL)
        current_time = time.time()
        with self._config_cache_lock:
            if (self._config_cache is not None and 
                (current_time - self._config_cache_time) < CONFIG_CACHE_TTL):
                # Cache hit - return cached config
                self.config = self._config_cache
                return
        
        # Cache miss - fetch from DB
        try:
            db = self.get_db_session()
        except Exception as e:
            logger.warning("[IPS] Database session connection failed: %s — using default in-memory config", e)
            if not getattr(self, "config", None) or getattr(self.config, "is_active", None) is None:
                self.config = IPSConfig(is_active=True, mode="blocking", deception_enabled=True)
            if len(self.signature_engine) == 0:
                self.signature_engine.load_defaults()
            return

        try:
            from system.database.database import Base
            import modules.ids_ips.models
            try:
                Base.metadata.create_all(bind=db.get_bind())
            except Exception:
                pass

            config = db.query(IPSConfig).first()
            if not config:
                config = IPSConfig()
                db.add(config)
                db.commit()
                db.refresh(config)
                
            self.config = config
            
            # Always load built-in defaults first (OWASP Top 10 coverage)
            self.signature_engine.load_defaults()

            # Layer DB-managed signatures on top (admin-configured rules)
            db_sigs = db.query(IPSSignature).filter(IPSSignature.enabled == True).all()
            if db_sigs:
                # Merge DB rules without clearing built-ins
                for db_sig in db_sigs:
                    try:
                        self.signature_engine.add_rule(db_sig.raw_rule)
                    except Exception as _sig_exc:
                        logger.debug("[IPS] Skipping invalid DB rule: %s", _sig_exc)
            
            logger.info(
                "[IPS] SignatureEngine loaded: %d total signatures (%d built-in, %d from DB)",
                len(self.signature_engine.signatures),
                42,  # len of defaults
                len(db_sigs),
            )
            
            # Update cache
            with self._config_cache_lock:
                self._config_cache = config
                self._config_cache_time = current_time
                
        finally:
            db.close()
    
    def invalidate_config_cache(self):
        """Force refresh of config cache (call after config update)."""
        with self._config_cache_lock:
            self._config_cache = None
            self._config_cache_time = 0.0

    def _get_uba_profiles(self) -> list:
        """Fetch UBA user profiles from DB with caching to prevent high latency in packet hot path."""
        current_time = time.time()
        with self._uba_cache_lock:
            if (self._uba_cache is not None and 
                (current_time - self._uba_cache_time) < self._uba_cache_ttl):
                return self._uba_cache

        # Cache miss - fetch from DB
        try:
            from system.database.database import UBAUserProfile
            db = self.get_db_session()
            try:
                profiles = db.query(UBAUserProfile).all()
                materialized = []
                for p in profiles:
                    materialized.append({
                        "known_ips": list(p.known_ips) if p.known_ips else [],
                        "risk_level": p.risk_level,
                        "risk_score": p.risk_score
                    })
                with self._uba_cache_lock:
                    self._uba_cache = materialized
                    self._uba_cache_time = current_time
                return materialized
            finally:
                db.close()
        except Exception as e:
            self.logger.error(f"Failed to fetch UBA profiles from DB: {e}")
            with self._uba_cache_lock:
                if self._uba_cache is not None:
                    return self._uba_cache
            return []

    def _trigger_block(self, src_ip: str, reason: str) -> None:
        """Publish block event to EventBus for eBPF kernel acceleration."""
        if not getattr(self.config, 'enable_ebpf_drop', True):
            return
        
        try:
            from system.events.bus import EventBus
            from system.events.topics import Topics
            EventBus.publish_from_thread(Topics.RESPONSE_BLOCK, {
                "src_ip": src_ip,
                "reason": reason,
                "duration_s": 3600
            })
        except Exception as e:
            self.logger.error(f"Failed to trigger eBPF block event: {e}")

    def evaluate(self, context: PolicyContext, payload: bytes = b"") -> Action:
        action = self._do_evaluate(context, payload)
        if action == Action.BLOCK and getattr(self.config, 'mode', 'blocking') == 'blocking':
            self._trigger_block(context.src_ip, "IPS Detection Block")
        return action

    def _do_evaluate(self, context: PolicyContext, payload: bytes = b"") -> Action:
        self.sync_config()
        
        if not self.config.is_active:
            return Action.ALLOW
            
        # 1. Threat Intelligence Check
        is_threat, threat_info = self.threat_intel.is_threat(context.src_ip, 'ip')
        if is_threat and threat_info.threat_level >= ThreatLevel.HIGH:
            self.logger.warning(f"IPS Blocked Source IP Threat: {context.src_ip} ({threat_info.source})")
            if self.config.mode == "blocking": return Action.BLOCK
            
        is_threat, threat_info = self.threat_intel.is_threat(context.dst_ip, 'ip')
        if is_threat and threat_info.threat_level >= ThreatLevel.HIGH:
            self.logger.warning(f"IPS Blocked Dest IP Threat: {context.dst_ip} ({threat_info.source})")
            if self.config.mode == "blocking": return Action.BLOCK
            
        if context.domain:
            import re
            # Validate domain input to prevent injection/evasion attacks
            if len(context.domain) > 253 or not re.match(r"^[a-zA-Z0-9.-]+$", context.domain):
                self.logger.warning(f"IPS: Malformed or excessively long domain name, skipping lookup: {context.domain[:50]}...")
            else:
                is_threat, threat_info = self.threat_intel.is_threat(context.domain, 'domain')
                if is_threat and threat_info.threat_level >= ThreatLevel.HIGH:
                    self.logger.warning(f"IPS Blocked Malicious Domain: {context.domain} ({threat_info.source})")
                    if self.config.mode == "blocking": return Action.BLOCK
            
        # 2. Reputation Check
        rep = self.reputation.get_ip_reputation(context.src_ip)
        if rep.score <= ReputationLevel.MALICIOUS:
            self.logger.warning(f"IPS Blocked Low Reputation: {context.src_ip} ({rep.score})")
            if self.config.mode == "blocking": return Action.BLOCK
            
        # 3. Signature Matching
        if payload:
            alerts = self.signature_engine.scan(payload)
            if alerts:
                for alert in alerts:
                    self.logger.warning(f"IPS Signature Match: {alert}")
                # Publish threat.detected — set confidence appropriately and gate for internal/private IPs
                try:
                    import ipaddress
                    from system.events.bus import EventBus
                    from system.events.topics import Topics
                    
                    is_internal_src = False
                    try:
                        is_internal_src = ipaddress.ip_address(context.src_ip).is_private
                    except ValueError:
                        pass

                    # For internal/LAN source IPs, pass low confidence (0.30) for SIEM/telemetry only
                    # so that AutoBlock, Correlation Engine escalation, and audio alert storms are not triggered.
                    sig_confidence = 0.30 if is_internal_src else 0.85

                    sig_desc = str(alerts[0]).lower() if alerts else ""
                    threat_type = "ids_ips"
                    if "sql" in sig_desc or "sqli" in sig_desc:
                        threat_type = "sqli"
                    elif "command" in sig_desc or "rce" in sig_desc or "semicolon" in sig_desc or "shell" in sig_desc:
                        threat_type = "rce"
                    elif "script" in sig_desc or "xss" in sig_desc:
                        threat_type = "xss"
                    elif "traversal" in sig_desc or "path" in sig_desc or "dotdot" in sig_desc:
                        threat_type = "path_traversal"
                    elif "scan" in sig_desc or "port" in sig_desc:
                        threat_type = "port_scan"
                    elif "brute" in sig_desc or "auth" in sig_desc:
                        threat_type = "brute_force"

                    EventBus.publish_from_thread(Topics.THREAT_DETECTED, {
                        "src_ip":           context.src_ip,
                        "dst_ip":           context.dst_ip,
                        "signatures":       [str(a) for a in alerts[:5]],
                        "detection_method": "signature",
                        "severity":         "HIGH",
                        "confidence":       sig_confidence,
                        "threat_type":     threat_type,
                        "category":        threat_type,
                        "description":      f"IDS signature match: {alerts[0] if alerts else context.src_ip}",
                    })
                    if is_internal_src:
                        self.logger.info(
                            f"[IDS/IPS] Internal IP signature match logged & published: {context.src_ip}"
                        )
                except Exception as _te:
                    self.logger.warning(f"[IDS/IPS] Failed to publish threat.detected: {_te}")
                if getattr(self.config, 'deception_enabled', True):
                    trap_id, fake_banner = self.unified_deception.generate_trap(
                        module="ids_ips",
                        username="unknown",
                        source_ip=context.src_ip,
                        target_service=str(context.dst_port),
                        anomaly_score=1.0 # Signatures are highly certain
                    )
                    metrics = getattr(context, "metrics", None)
                    if metrics is None:
                        metrics = {}
                        try:
                            setattr(context, "metrics", metrics)
                        except Exception:
                            pass
                    metrics["deception_trap"] = fake_banner
                    return Action.DECEIVE
                    
                if self.config.mode == "blocking": return Action.BLOCK
        
        # 4. AI Anomaly Detection (L3 & L7)
        if hasattr(context, 'metrics') and context.metrics:
            try:
                import dataclasses
                kwargs = {}
                for f in dataclasses.fields(TrafficFeatures):
                    if f.name in context.metrics:
                        kwargs[f.name] = context.metrics[f.name]
                    elif f.default == dataclasses.MISSING and f.default_factory == dataclasses.MISSING:
                        kwargs[f.name] = 0.0 if 'float' in str(f.type).lower() else 0
                features = TrafficFeatures(**kwargs)
                
                # Prevent false positives: if the flow features are entirely zero
                # (which happens during early transparent proxy interception), skip ML detection.
                if features.packets_per_second == 0 and features.bytes_per_second == 0 and features.unique_dst_ports == 0:
                    from modules.ids_ips.engine.anomaly_detector import AnomalyResult
                    result = AnomalyResult(is_anomaly=False, anomaly_score=0.0, confidence=1.0, details={})
                else:
                    result = self.ai_detector.detect(features)
                
                block_anomaly = False
                
                # --- UBA Zero Trust Integration ---
                current_threshold = getattr(self.config, 'anomaly_threshold', 0.5)
                if getattr(self.config, 'enable_uba_zero_trust', True):
                    try:
                        profiles = self._get_uba_profiles()
                        for p in profiles:
                            if p["known_ips"] and context.src_ip in p["known_ips"]:
                                if p["risk_level"] in ["high", "critical"] or p["risk_score"] > 60:
                                    current_threshold = 0.4
                                    self.logger.warning(f"ZTA: Lowered threshold to {current_threshold} for risky IP {context.src_ip}")
                                elif p["risk_score"] < 20:
                                    current_threshold = 0.8
                                break
                    except Exception as e:
                        self.logger.error(f"Failed UBA Zero Trust lookup: {e}")
                
                if self.config.enable_l3_anomaly and result.is_anomaly and result.anomaly_score >= current_threshold:
                    self.logger.warning(
                        "[IPS] ML Anomaly detected | src=%s score=%.3f threshold=%.2f method=AnomalyDetector",
                        context.src_ip, result.anomaly_score, current_threshold,
                    )
                    block_anomaly = True

                    # ── AnomalyBridge secondary check ──────────────────────────
                    # Cross-validate with the bridge to reduce false positives:
                    # only emit a block if both detectors agree.
                    flow_stats = context.metrics or {}
                    bridge_flags = self.anomaly_bridge.check(flow_stats)
                    if bridge_flags:
                        self.logger.warning(
                            "[IPS] AnomalyBridge confirmed anomaly | src=%s",
                            context.src_ip,
                        )
                    else:
                        self.logger.info(
                            "[IPS] AnomalyBridge did NOT confirm | src=%s "
                            "(AnomalyDetector flagged, bridge did not — keeping block decision)",
                            context.src_ip,
                        )
                    # Publish anomaly.scored — use publish_from_thread (safe from asyncio.to_thread)
                    try:
                        from system.events.bus import EventBus
                        from system.events.topics import Topics
                        EventBus.publish_from_thread(Topics.ANOMALY_SCORED, {
                            "src_ip":           context.src_ip,
                            "anomaly_score":    result.anomaly_score,
                            "threshold":        current_threshold,
                            "detection_method": "l3_ml",
                            "severity":         "HIGH",
                            "description":      f"ML anomaly detected from {context.src_ip} (score={result.anomaly_score:.2f})",
                        })
                    except Exception as _ae:
                        self.logger.warning(f"[IDS/IPS] Failed to publish anomaly.scored: {_ae}")
                    
                if self.config.enable_l7_dpi and result.details.get("l7_classification") in ["web_attack", "brute_force"]:
                    self.logger.warning(f"IPS L7 DPI Classified Attack: {result.details['l7_classification']} (Conf: {result.details.get('l7_confidence', 0):.2f})")
                    block_anomaly = True
                    
                if block_anomaly:
                    if getattr(self.config, 'deception_enabled', True):
                        trap_id, fake_banner = self.unified_deception.generate_trap(
                            module="ids_ips",
                            username="unknown",
                            source_ip=context.src_ip,
                            target_service=str(context.dst_port),
                            anomaly_score=result.anomaly_score
                        )
                        context.metrics["deception_trap"] = fake_banner
                        return Action.DECEIVE
                        
                    if self.config.mode == "blocking":
                        return Action.BLOCK
                        
            except Exception as e:
                self.logger.error(f"Error executing AI Detector: {e}")
                
        return Action.ALLOW
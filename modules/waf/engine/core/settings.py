"""
Enterprise bunyanx — WAF Settings Loader

Reads `config/defaults/waf.yaml` (and optional `config/waf.local.yaml` override)
and exposes typed, validated settings with a clean API.

Usage:
    from inspection.plugins.waf.settings import WAFSettings

    settings = WAFSettings.load()

    if not settings.enabled:
        # WAF معطّل كلياً
        ...

    if settings.nlp.enabled:
        model = WAFNLPInference(settings.nlp.model_path)

Hot-reload (runtime toggle):
    settings.reload()           # re-reads YAML without restart
    settings.set_enabled(False) # تعطيل WAF مؤقتاً عبر الكود
"""

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional
import ipaddress

logger = logging.getLogger(__name__)

# ── Default config paths ─────────────────────
_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_DIR, "..", "..", "..", ".."))

DEFAULT_CONFIG  = os.path.join(_PROJECT_ROOT, "modules", "waf", "config", "waf.yaml")
LOCAL_CONFIG    = os.path.join(_PROJECT_ROOT, "modules", "waf", "config", "waf.local.yaml")


# ══════════════════════════════════════════════
#  Sub-settings dataclasses
# ══════════════════════════════════════════════

@dataclass
class PreprocessingSettings:
    enabled:            bool = True
    max_iterations:     int  = 6
    url_decode:         bool = True
    html_entity:        bool = True
    hex_decode:         bool = True
    base64_detect:      bool = True
    unicode_normalize:  bool = True
    sql_comment_strip:  bool = True
    xml_json_flatten:   bool = True


@dataclass
class NLPSettings:
    enabled:             bool  = True
    model_path:          str   = "ml/models/waf/waf_nlp_model.pt"
    detection_threshold: float = 0.60
    weight:              float = 0.25


@dataclass
class GAFSettings:
    enabled:             bool  = True
    model_path:          str   = "ml/models/waf/semantic_intent"
    detection_threshold: float = 0.60
    weight:              float = 0.15


@dataclass
class TemporalSettings:
    enabled:             bool  = True
    model_path:          str   = "ml/models/waf/temporal_lstm.pt"
    detection_threshold: float = 0.60
    weight:              float = 0.15


@dataclass
class BotDetectionSettings:
    enabled:             bool  = True
    model_path:          str   = "ml/models/waf/bot_model.json"
    detection_threshold: float = 0.65
    weight:              float = 0.20
    bot_action:          str   = "challenge"   # "challenge" | "block"


@dataclass
class GNNSettings:
    enabled:                  bool  = False
    model_path:               str   = "ml/models/waf/gnn_model.pt"
    detection_threshold:      float = 0.70
    weight:                   float = 0.10
    session_window_requests:  int   = 50
    # Session log collection (for GNN training data collection)
    log_sessions:             bool  = True
    logs_path:                str   = "modules/waf/ml_training/waf_gnn/datasets/session_logs.csv"
    max_log_records:          int   = 500_000


@dataclass
class AnomalySettings:
    enabled: bool  = True
    weight:  float = 0.25


@dataclass
class ThreatIntelSourceSettings:
    enabled: bool = True
    api_key: str  = ""


@dataclass
class ThreatIntelSettings:
    enabled:           bool  = True
    weight:            float = 0.15
    cache_ttl_seconds: int   = 21600
    abuseipdb_enabled: bool  = True
    abuseipdb_key:     str   = ""
    abuseipdb_max_age: int   = 30
    otx_enabled:       bool  = False
    otx_key:           str   = ""
    spamhaus_enabled:  bool  = True
    feodo_enabled:     bool  = True
    feodo_update_hours: int  = 6


@dataclass
class HoneypotSettings:
    enabled:               bool  = True
    score_boost:           float = 0.50
    weight:                float = 0.05
    blacklist_ttl_seconds: int   = 86400
    custom_paths:          List[str] = field(default_factory=list)

@dataclass
class DynamicAmplifierSettings:
    enabled:                             bool  = True
    reputation_boost:                    float = 0.15
    reputation_threshold:                float = 0.80
    bot_boost:                           float = 0.08
    bot_threshold:                       float = 0.80
    bot_reputation_dependency_threshold: float = 0.50
    high_confidence_override:            float = 0.80
    high_confidence_nlp_threshold:       float = 0.75
    high_confidence_gaf_threshold:       float = 0.80
    gnn_override_weight:                 float = 0.35
    fingerprint_boost_weight:            float = 0.50



@dataclass
class RiskThresholds:
    allow:      float = 0.30
    challenge:  float = 0.60
    soft_block: float = 0.80
    block:      float = 0.80


@dataclass
class RiskScoringSettings:
    enabled:    bool = True
    thresholds: RiskThresholds = field(default_factory=RiskThresholds)


@dataclass
class DeceptionEngineSettings:
    enabled:             bool  = True
    injection_threshold: float = 0.40
    ttl_seconds:         int   = 3600


@dataclass
class SSLAwareSettings:
    """
    إعدادات تُطبَّق فقط على حركة HTTPS التي تم فك تشفيرها عبر MITM.
    (ctx.tls.is_decrypted == True)

    المشكلة التي تحلها:
      عند فك تشفير HTTPS، يُعيد الـ Proxy بناء الاتصال بشكل يختلف
      عن متصفح حقيقي، مما يُسبب إيجابيات كاذبة في:
        - JA3 TLS Fingerprint (بصمة الـ Proxy لا المتصفح)
        - Bot Detection (HTTP headers مُعادة البناء)
        - Deception Engine (يُفجّر حلقة ذاتية إذا كانت عتبته منخفضة)
    """
    enabled:                      bool  = True
    # معامل ضرب bot_score عند فك التشفير (0.5 = خفّض 50%)
    bot_score_damping:            float = 0.5
    # تجاهل JA3 TLS Fingerprint (بصمته غير موثوقة بعد الـ MITM)
    skip_ja3_on_decrypted:        bool  = True
    # عتبة Deception للحركة المفكوكة (مرفوعة لمنع الحلقة الذاتية)
    deception_injection_threshold: float = 0.70
    # معامل ضرب Temporal BiLSTM (متصفح يُعيد المحاولة → نمط APT كاذب)
    temporal_score_damping:       float = 0.55
    # معامل ضرب GNN score (طلبات متسارعة → MULTI-REQUEST كاذب)
    gnn_score_damping:            float = 0.55



@dataclass
class SelfLearningSettings:
    enabled:        bool = True
    log_blocked:    bool = True
    log_challenged: bool = True
    log_allowed:    bool = False
    max_records:    int  = 100_000


@dataclass
class ShadowModeSettings:
    enabled:                  bool = False
    observation_window_hours: int  = 72


@dataclass
class APISchemaValidatorSettings:
    enabled:          bool = True
    max_payload_size: int  = 524288  # 512KB

@dataclass
class FingerprintingSettings:
    enabled:       bool = True
    check_ja3:     bool = True
    check_headers: bool = True

@dataclass
class ATOProtectorSettings:
    enabled:               bool = True
    max_attempts_per_ip:   int  = 10
    max_attempts_per_user: int  = 3
    time_window_seconds:   int  = 300

@dataclass
class RateLimiterSettings:
    enabled:              bool  = True
    global_rate_limit:    int   = 2000
    ip_rate_limit:        int   = 150
    user_rate_limit:      int   = 50
    time_window_seconds:  int   = 60
    adaptive_ratelimit:   bool  = True

@dataclass
class XAISettings:
    enabled: bool = True
    explainer_type: str = "shap"  # "shap" or "lime"

@dataclass
class GraphQLSettings:
    enabled: bool = True
    max_depth: int = 5
    max_batched_queries: int = 10
    detect_introspection: bool = True

@dataclass
class PerformanceSettings:
    max_inspection_time_ms:    int  = 50000
    fail_open:                 bool = True
    max_payload_inspect_bytes: int  = 65536


@dataclass
class AccessListSettings:
    enabled: bool = True
    ips:     List[str] = field(default_factory=list)
    cidrs:   List[str] = field(default_factory=list)
    paths:   List[str] = field(default_factory=list)


@dataclass
class WAFLoggingSettings:
    enabled:         bool = True
    log_blocked:     bool = True
    log_challenged:  bool = True
    log_allowed:     bool = False
    include_payload: bool = False
    log_file:        str  = "data/logs/waf.log"
    alert_threshold: float = 0.40


# ══════════════════════════════════════════════
#  Master WAFSettings
# ══════════════════════════════════════════════

@dataclass
class WAFSettings:
    """
    Master WAF settings object.

    All boolean `enabled` flags can be changed at runtime via code:
        settings.nlp.enabled = False
    or by editing waf.yaml and calling settings.reload().
    """

    # ── Master switch ──────────────────────────
    enabled:          bool = True
    mode:             str  = "enforce"    # enforce | monitor | learning
    monitored_ports:  List[int] = field(default_factory=lambda: [80, 443, 8080, 8443])

    # ── Feature settings ───────────────────────
    preprocessing:  PreprocessingSettings = field(default_factory=PreprocessingSettings)
    nlp:            NLPSettings           = field(default_factory=NLPSettings)
    gaf:            GAFSettings           = field(default_factory=GAFSettings)
    temporal:       TemporalSettings      = field(default_factory=TemporalSettings)
    bot:            BotDetectionSettings  = field(default_factory=BotDetectionSettings)
    gnn:            GNNSettings           = field(default_factory=GNNSettings)
    anomaly:        AnomalySettings       = field(default_factory=AnomalySettings)
    threat_intel:   ThreatIntelSettings   = field(default_factory=ThreatIntelSettings)
    honeypot:       HoneypotSettings      = field(default_factory=HoneypotSettings)
    
    # ── WAAP Specifics ──────────────────────────
    api_schema:     APISchemaValidatorSettings = field(default_factory=APISchemaValidatorSettings)
    fingerprint:    FingerprintingSettings     = field(default_factory=FingerprintingSettings)
    ato_protector:  ATOProtectorSettings       = field(default_factory=ATOProtectorSettings)
    rate_limiter:   RateLimiterSettings        = field(default_factory=RateLimiterSettings)
    
    risk_scoring:   RiskScoringSettings        = field(default_factory=RiskScoringSettings)
    dynamic_amplifiers: DynamicAmplifierSettings = field(default_factory=DynamicAmplifierSettings)
    xai_explainer:  XAISettings                = field(default_factory=XAISettings)
    deception_engine: DeceptionEngineSettings = field(default_factory=DeceptionEngineSettings)
    ssl_aware:        SSLAwareSettings         = field(default_factory=SSLAwareSettings)
    self_learning:  SelfLearningSettings  = field(default_factory=SelfLearningSettings)
    shadow_mode:    ShadowModeSettings    = field(default_factory=ShadowModeSettings)
    
    graphql_inspector: GraphQLSettings    = field(default_factory=GraphQLSettings)
    
    performance:    PerformanceSettings   = field(default_factory=PerformanceSettings)
    whitelist:      AccessListSettings    = field(default_factory=AccessListSettings)
    blacklist:      AccessListSettings    = field(default_factory=AccessListSettings)
    logging:        WAFLoggingSettings    = field(default_factory=WAFLoggingSettings)

    # ── Internal ────────────────────────────────
    _config_path: str = field(default=DEFAULT_CONFIG, repr=False)

    # ── Convenience properties ─────────────────

    @property
    def is_blocking(self) -> bool:
        """True if WAF is enabled AND in enforce mode."""
        return self.enabled and self.mode == "enforce"

    @property
    def is_monitoring(self) -> bool:
        """True if running in monitor/shadow mode (log only, no blocks)."""
        return self.enabled and self.mode in ("monitor", "learning")

    def is_ip_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted."""
        if not ip:
            return False
        # Protected system infrastructure IPs are ALWAYS whitelisted
        if str(ip).strip() in ("10.10.0.50", "10.10.0.1", "192.168.1.33", "127.0.0.1"):
            return True
        if not self.whitelist.enabled:
            return False
        if ip in self.whitelist.ips:
            return True
        cidrs = getattr(self.whitelist, 'cidr_networks', None) or getattr(self.whitelist, 'cidrs', [])
        try:
            addr = ipaddress.ip_address(ip)
            return any(
                addr in ipaddress.ip_network(cidr, strict=False)
                for cidr in cidrs
            )
        except ValueError:
            return False

    def is_path_whitelisted(self, path: str) -> bool:
        """Check if a URL request path is explicitly whitelisted."""
        if not self.whitelist.enabled or not self.whitelist.paths or not path:
            return False
        return any(path.startswith(p) or p == path for p in self.whitelist.paths)

    def is_ip_blacklisted(self, ip: str) -> bool:
        """Check if an IP is in the static blacklist."""
        if not self.blacklist.enabled:
            return False
        if ip in self.blacklist.ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(
                addr in ipaddress.ip_network(cidr, strict=False)
                for cidr in self.blacklist.cidrs
            )
        except ValueError:
            return False

    def unblacklist_ip(self, ip: str) -> bool:
        """Remove an IP address from the WAF blacklist if present."""
        removed = False
        if ip in self.blacklist.ips:
            self.blacklist.ips.remove(ip)
            removed = True
        return removed

    def clear_blacklist(self) -> None:
        """Clear all IPs from the WAF blacklist."""
        self.blacklist.ips.clear()

    # ── Runtime toggles ────────────────────────

    def set_enabled(self, value: bool) -> None:
        """Enable or disable WAF at runtime (no restart needed)."""
        self.enabled = value
        logger.warning("WAF master switch -> %s", "ENABLED" if value else "DISABLED")

    def set_mode(self, mode: str) -> None:
        """Switch mode: 'enforce', 'monitor', or 'learning'."""
        if mode not in ("enforce", "monitor", "learning"):
            raise ValueError(f"Invalid WAF mode: {mode}")
        self.mode = mode
        logger.info("WAF mode -> %s", mode)

    def toggle_model(self, model_name: str, enabled: bool) -> None:
        """
        Enable or disable a specific AI model at runtime — no restart required.

        Supported model names:
            "nlp"          WAF NLP Attack Classifier (1D-CNN + BiLSTM)
            "gaf"          GAF Semantic Intent (MiniLM-L6)
            "bot"          Bot Detection XGBoost
            "gnn"          Session GNN Graph Detector
            "temporal"     Temporal BiLSTM APT Tracker
            "anomaly"      Heuristic Anomaly Detection
            "threat_intel" Threat Intelligence (AbuseIPDB / Spamhaus)
            "fingerprint"  Client Fingerprinting (NW Alignment + JA3)
            "ato"          Account Takeover Protector
            "rate_limiter" Adaptive Rate Limiter
            "honeypot"     Honeypot Guard
            "api_schema"   API Schema Validator
            "graphql"      GraphQL Inspector
            "xai"          XAI Explainer
            "deception"    Deception Engine
            "self_learning" Self-Learning Logger

        Example:
            settings.toggle_model("gnn", False)  # disable GNN
            settings.toggle_model("nlp", True)   # re-enable NLP
        """
        _MAP = {
            "nlp":          lambda v: setattr(self.nlp,           "enabled", v),
            "gaf":          lambda v: setattr(self.gaf,           "enabled", v),
            "bot":          lambda v: setattr(self.bot,           "enabled", v),
            "gnn":          lambda v: setattr(self.gnn,           "enabled", v),
            "temporal":     lambda v: setattr(self.temporal,      "enabled", v),
            "anomaly":      lambda v: setattr(self.anomaly,       "enabled", v),
            "threat_intel": lambda v: setattr(self.threat_intel,  "enabled", v),
            "fingerprint":  lambda v: setattr(self.fingerprint,   "enabled", v),
            "ato":          lambda v: setattr(self.ato_protector,  "enabled", v),
            "rate_limiter": lambda v: setattr(self.rate_limiter,   "enabled", v),
            "honeypot":     lambda v: setattr(self.honeypot,       "enabled", v),
            "api_schema":   lambda v: setattr(self.api_schema,     "enabled", v),
            "graphql":      lambda v: setattr(self.graphql_inspector, "enabled", v),
            "xai":          lambda v: setattr(self.xai_explainer,  "enabled", v),
            "deception":    lambda v: setattr(self.deception_engine, "enabled", v),
            "self_learning":lambda v: setattr(self.self_learning,  "enabled", v),
        }
        if model_name not in _MAP:
            raise ValueError(
                f"Unknown model '{model_name}'. Valid names: {list(_MAP.keys())}"
            )
        _MAP[model_name](enabled)
        state = "ENABLED" if enabled else "DISABLED"
        logger.info("WAF model toggle: [%s] -> %s", model_name.upper(), state)

    # ── Loader ────────────────────────────────

    @classmethod
    def load(
        cls,
        config_path: str = DEFAULT_CONFIG,
        local_path:  str = LOCAL_CONFIG,
    ) -> "WAFSettings":
        """
        Load WAF settings from YAML.

        Merges base config with optional local override.
        API keys in local file take priority over base.
        """
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML required: pip install pyyaml — using defaults")
            return cls()

        raw = {}

        # Load base config
        if os.path.exists(config_path):
            with open(config_path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            logger.info("WAF config loaded from %s", config_path)
        else:
            logger.warning("WAF config not found at %s — using defaults", config_path)

        # Merge local override (e.g., API keys)
        if os.path.exists(local_path):
            with open(local_path, encoding="utf-8") as f:
                local_raw = yaml.safe_load(f) or {}
            raw = _deep_merge(raw, local_raw)
            logger.info("WAF local overrides applied from %s", local_path)

        waf_cfg = raw.get("waf", {})
        settings = cls._from_dict(waf_cfg)
        settings._config_path = config_path
        return settings

    def reload(self) -> None:
        """Re-read the YAML file and update settings in-place."""
        fresh = WAFSettings.load(self._config_path)
        self.__dict__.update(fresh.__dict__)
        logger.info("WAF settings reloaded")

    def save(self) -> None:
        """Persist runtime changes to waf.local.yaml to survive reboots."""
        try:
            import yaml
            import os
            # Build an override dictionary for the modified features
            override = {
                "waf": {
                    "enabled": self.enabled,
                    "blacklist": {
                        "enabled": self.blacklist.enabled,
                        "ips": self.blacklist.ips,
                        "cidrs": self.blacklist.cidrs,
                    },
                    "whitelist": {
                        "enabled": self.whitelist.enabled,
                        "ips": self.whitelist.ips,
                        "cidrs": self.whitelist.cidrs,
                        "paths": self.whitelist.paths,
                    },
                    "gnn_model": {"enabled": self.gnn.enabled},
                    "api_schema_validator": {"enabled": self.api_schema.enabled},
                    "fingerprinting": {"enabled": self.fingerprint.enabled},
                    "ato_protector": {"enabled": self.ato_protector.enabled},
                    "shadow_mode": {
                        "enabled": self.shadow_mode.enabled,
                        "observation_window_hours": self.shadow_mode.observation_window_hours
                    },
                    "xai_explainer": {
                        "enabled": self.xai_explainer.enabled
                    },
                    "graphql_inspector": {
                        "enabled": self.graphql_inspector.enabled
                    },
                    "rate_limiter": {
                        "enabled": self.rate_limiter.enabled,
                        "global_rate_limit": self.rate_limiter.global_rate_limit,
                        "ip_rate_limit": self.rate_limiter.ip_rate_limit,
                        "user_rate_limit": self.rate_limiter.user_rate_limit,
                        "adaptive_ratelimit": self.rate_limiter.adaptive_ratelimit
                    },
                    "dynamic_amplifiers": {
                        "enabled": self.dynamic_amplifiers.enabled,
                        "reputation_boost": self.dynamic_amplifiers.reputation_boost,
                        "reputation_threshold": self.dynamic_amplifiers.reputation_threshold,
                        "bot_boost": self.dynamic_amplifiers.bot_boost,
                        "bot_threshold": self.dynamic_amplifiers.bot_threshold,
                        "bot_reputation_dependency_threshold": self.dynamic_amplifiers.bot_reputation_dependency_threshold,
                        "high_confidence_override": self.dynamic_amplifiers.high_confidence_override,
                        "high_confidence_nlp_threshold": self.dynamic_amplifiers.high_confidence_nlp_threshold,
                        "high_confidence_gaf_threshold": self.dynamic_amplifiers.high_confidence_gaf_threshold,
                        "gnn_override_weight": self.dynamic_amplifiers.gnn_override_weight,
                        "fingerprint_boost_weight": self.dynamic_amplifiers.fingerprint_boost_weight
                    }
                }
            }
            # Merge with existing local config if it exists
            existing_local = {}
            if os.path.exists(LOCAL_CONFIG):
                with open(LOCAL_CONFIG, "r", encoding="utf-8") as f:
                    existing_local = yaml.safe_load(f) or {}
            
            merged = _deep_merge(existing_local, override)
            
            os.makedirs(os.path.dirname(LOCAL_CONFIG), exist_ok=True)
            with open(LOCAL_CONFIG, "w", encoding="utf-8") as f:
                yaml.dump(merged, f, default_flow_style=False)
                
            logger.info("WAF settings saved persistently to %s", LOCAL_CONFIG)
        except Exception as e:
            logger.error("Failed to save WAF settings persistently: %s", e)

    @classmethod
    def _from_dict(cls, d: dict) -> "WAFSettings":
        """Build a WAFSettings from the `waf:` dict in YAML."""
        s = cls()

        s.enabled         = d.get("enabled", True)
        s.mode            = d.get("mode", "enforce")
        s.monitored_ports = d.get("monitored_ports", s.monitored_ports)

        # Preprocessing
        pp = d.get("preprocessing", {})
        dec = pp.get("decoders", {})
        s.preprocessing = PreprocessingSettings(
            enabled           = pp.get("enabled", True),
            max_iterations    = pp.get("max_decode_iterations", 6),
            url_decode        = dec.get("url_decode", True),
            html_entity       = dec.get("html_entity", True),
            hex_decode        = dec.get("hex_decode", True),
            base64_detect     = dec.get("base64_detect", True),
            unicode_normalize = dec.get("unicode_normalize", True),
            sql_comment_strip = dec.get("sql_comment_strip", True),
            xml_json_flatten  = dec.get("xml_json_flatten", True),
        )

        # NLP
        nlp = d.get("nlp_model", {})
        s.nlp = NLPSettings(
            enabled             = nlp.get("enabled", True),
            model_path          = nlp.get("model_path", s.nlp.model_path),
            detection_threshold = nlp.get("detection_threshold", 0.60),
            weight              = nlp.get("weight", 0.25),
        )

        # GAF
        gaf = d.get("gaf_model", {})
        s.gaf = GAFSettings(
            enabled             = gaf.get("enabled", True),
            model_path          = gaf.get("model_path", s.gaf.model_path),
            detection_threshold = gaf.get("detection_threshold", 0.60),
            weight              = gaf.get("weight", 0.15),
        )

        # Temporal
        temp = d.get("temporal_model", {})
        s.temporal = TemporalSettings(
            enabled             = temp.get("enabled", True),
            model_path          = temp.get("model_path", s.temporal.model_path),
            detection_threshold = temp.get("detection_threshold", 0.60),
            weight              = temp.get("weight", 0.15),
        )

        # Bot Detection
        bot = d.get("bot_detection", {})
        s.bot = BotDetectionSettings(
            enabled             = bot.get("enabled", True),
            model_path          = bot.get("model_path", s.bot.model_path),
            detection_threshold = bot.get("detection_threshold", 0.65),
            weight              = bot.get("weight", 0.20),
            bot_action          = bot.get("bot_action", "challenge"),
        )

        # GNN
        gnn = d.get("gnn_model", {})
        s.gnn = GNNSettings(
            enabled                 = gnn.get("enabled", False),
            model_path              = gnn.get("model_path", s.gnn.model_path),
            detection_threshold     = gnn.get("detection_threshold", 0.70),
            weight                  = gnn.get("weight", 0.10),
            session_window_requests = gnn.get("session_window_requests", 50),
            log_sessions            = gnn.get("log_sessions", True),
            logs_path               = gnn.get("logs_path", s.gnn.logs_path),
            max_log_records         = gnn.get("max_log_records", 500_000),
        )

        # Anomaly
        anom = d.get("anomaly_detection", {})
        s.anomaly = AnomalySettings(
            enabled = anom.get("enabled", True),
            weight  = anom.get("weight", 0.25),
        )

        # Threat Intelligence
        ti = d.get("threat_intelligence", {})
        s.threat_intel = ThreatIntelSettings(
            enabled           = ti.get("enabled", True),
            weight            = ti.get("weight", 0.15),
            cache_ttl_seconds = ti.get("cache_ttl_seconds", 21600),
            abuseipdb_enabled = ti.get("abuseipdb", {}).get("enabled", True),
            abuseipdb_key     = _env_override(ti.get("abuseipdb", {}).get("api_key", ""), "ABUSEIPDB_API_KEY"),
            abuseipdb_max_age = ti.get("abuseipdb", {}).get("max_age_days", 30),
            otx_enabled       = ti.get("alienvault_otx", {}).get("enabled", False),
            otx_key           = _env_override(ti.get("alienvault_otx", {}).get("api_key", ""), "OTX_API_KEY"),
            spamhaus_enabled  = ti.get("spamhaus", {}).get("enabled", True),
            feodo_enabled     = ti.get("feodo_tracker", {}).get("enabled", True),
            feodo_update_hours = ti.get("feodo_tracker", {}).get("update_interval_hours", 6),
        )

        # Honeypot
        hp = d.get("honeypot", {})
        s.honeypot = HoneypotSettings(
            enabled               = hp.get("enabled", True),
            score_boost           = hp.get("score_boost", 0.50),
            weight                = hp.get("weight", 0.05),
            blacklist_ttl_seconds = hp.get("blacklist_ttl_seconds", 86400),
            custom_paths          = hp.get("custom_paths", []),
            # tarpit_enabled omitted as it's not currently exposed via yaml, default True
        )

        # WAAP Settings
        api = d.get("api_schema_validator", {})
        s.api_schema = APISchemaValidatorSettings(
            enabled          = api.get("enabled", True),
            max_payload_size = api.get("max_payload_size", 524288)
        )

        fp = d.get("fingerprinting", {})
        s.fingerprint = FingerprintingSettings(
            enabled       = fp.get("enabled", True),
            check_ja3     = fp.get("check_ja3", True),
            check_headers = fp.get("check_headers", True)
        )

        ato = d.get("ato_protector", {})
        s.ato_protector = ATOProtectorSettings(
            enabled               = ato.get("enabled", True),
            max_attempts_per_ip   = ato.get("max_attempts_per_ip", 20),
            max_attempts_per_user = ato.get("max_attempts_per_user", 5),
            time_window_seconds   = ato.get("time_window_seconds", 300)
        )

        rl = d.get("rate_limiter", {})
        s.rate_limiter = RateLimiterSettings(
            enabled             = rl.get("enabled", True),
            global_rate_limit   = rl.get("global_rate_limit", 2000),
            ip_rate_limit       = rl.get("ip_rate_limit", 150),
            user_rate_limit     = rl.get("user_rate_limit", 500),
            time_window_seconds = rl.get("time_window_seconds", 60),
            adaptive_ratelimit  = rl.get("adaptive_ratelimit", True)
        )

        # Deception Engine
        dec = d.get("deception_engine", {})
        s.deception_engine = DeceptionEngineSettings(
            enabled             = dec.get("enabled", True),
            injection_threshold = dec.get("injection_threshold", 0.40),
            ttl_seconds         = dec.get("ttl_seconds", 3600),
        )

        # Risk Scoring
        rs = d.get("risk_scoring", {})
        thr = rs.get("thresholds", {})
        s.risk_scoring = RiskScoringSettings(
            enabled    = rs.get("enabled", True),
            thresholds = RiskThresholds(
                allow      = thr.get("allow",      0.30),
                challenge  = thr.get("challenge",  0.60),
                soft_block = thr.get("soft_block", 0.80),
                block      = thr.get("block",      0.80),
            ),
        )

        # Dynamic Amplifiers
        da = d.get("dynamic_amplifiers", {})
        s.dynamic_amplifiers = DynamicAmplifierSettings(
            enabled                             = da.get("enabled", True),
            reputation_boost                    = da.get("reputation_boost", 0.15),
            reputation_threshold                = da.get("reputation_threshold", 0.80),
            bot_boost                           = da.get("bot_boost", 0.08),
            bot_threshold                       = da.get("bot_threshold", 0.80),
            bot_reputation_dependency_threshold = da.get("bot_reputation_dependency_threshold", 0.50),
            high_confidence_override            = da.get("high_confidence_override", 0.80),
            high_confidence_nlp_threshold       = da.get("high_confidence_nlp_threshold", 0.75),
            high_confidence_gaf_threshold       = da.get("high_confidence_gaf_threshold", 0.80),
            gnn_override_weight                 = da.get("gnn_override_weight", 0.35),
            fingerprint_boost_weight            = da.get("fingerprint_boost_weight", 0.50),
        )

        # XAI Explainer
        xai = d.get("xai_explainer", {})
        s.xai_explainer = XAISettings(
            enabled        = xai.get("enabled", True),
            explainer_type = xai.get("explainer_type", "shap")
        )

        # GraphQL Inspector
        gql = d.get("graphql_inspector", {})
        s.graphql_inspector = GraphQLSettings(
            enabled             = gql.get("enabled", True),
            max_depth           = gql.get("max_depth", 5),
            max_batched_queries = gql.get("max_batched_queries", 10),
            detect_introspection= gql.get("detect_introspection", True)
        )

        # Self-Learning
        sl = d.get("self_learning", {})
        s.self_learning = SelfLearningSettings(
            enabled        = sl.get("enabled", True),
            log_blocked    = sl.get("log_blocked", True),
            log_challenged = sl.get("log_challenged", True),
            log_allowed    = sl.get("log_allowed", False),
            max_records    = sl.get("max_records", 100_000),
        )

        # Shadow Mode
        sh = d.get("shadow_mode", {})
        s.shadow_mode = ShadowModeSettings(
            enabled                  = sh.get("enabled", False),
            observation_window_hours = sh.get("observation_window_hours", 72)
        )

        # Performance
        perf = d.get("performance", {})
        s.performance = PerformanceSettings(
            max_inspection_time_ms    = perf.get("max_inspection_time_ms", 50000),
            fail_open                 = perf.get("fail_open", True),
            max_payload_inspect_bytes = perf.get("max_payload_inspect_bytes", 65536),
        )

        # Whitelist
        wl = d.get("whitelist", {})
        s.whitelist = AccessListSettings(
            enabled = wl.get("enabled", True),
            ips     = wl.get("ips", ["127.0.0.1"]),
            cidrs   = wl.get("cidrs", []),
            paths   = wl.get("paths", []),
        )

        # Blacklist
        bl = d.get("blacklist", {})
        s.blacklist = AccessListSettings(
            enabled = bl.get("enabled", True),
            ips     = bl.get("ips", []),
            cidrs   = bl.get("cidrs", []),
        )

        # Logging
        lg = d.get("logging", {})
        s.logging = WAFLoggingSettings(
            enabled         = lg.get("enabled", True),
            log_blocked     = lg.get("log_blocked", True),
            log_challenged  = lg.get("log_challenged", True),
            log_allowed     = lg.get("log_allowed", False),
            include_payload = lg.get("include_payload", False),
            log_file        = lg.get("log_file", "data/logs/waf.log"),
            alert_threshold = lg.get("alert_threshold", 0.40),
        )

        # SSL-Aware Post-Decryption Settings
        sa = d.get("ssl_aware", {})
        s.ssl_aware = SSLAwareSettings(
            enabled                       = sa.get("enabled", True),
            bot_score_damping             = sa.get("bot_score_damping", 0.5),
            skip_ja3_on_decrypted         = sa.get("skip_ja3_on_decrypted", True),
            deception_injection_threshold = sa.get("deception_injection_threshold", 0.70),
            temporal_score_damping        = sa.get("temporal_score_damping", 0.55),
            gnn_score_damping             = sa.get("gnn_score_damping", 0.55),
        )

        return s

    def summary(self) -> str:
        """Print a human-readable summary of the current WAF settings (ASCII-safe for Windows)."""
        ON  = lambda v: "[ON] " if v else "[OFF]"
        lines = [
            "=" * 55,
            f"  WAF Status      : {'ENABLED' if self.enabled else 'DISABLED'}",
            f"  Mode            : {self.mode.upper()}",
            "-" * 55,
            "  --- AI Models ---",
            f"  {ON(self.nlp.enabled)}     NLP Classifier    (w={self.nlp.weight:.0%}, thr={self.nlp.detection_threshold})",
            f"  {ON(self.gaf.enabled)}     GAF Semantic      (w={self.gaf.weight:.0%}, thr={self.gaf.detection_threshold})",
            f"  {ON(self.bot.enabled)}     Bot Detection     (w={self.bot.weight:.0%}, thr={self.bot.detection_threshold})",
            f"  {ON(self.gnn.enabled)}     GNN Session Graph (w={self.gnn.weight:.0%}, thr={self.gnn.detection_threshold})",
            f"  {ON(self.temporal.enabled)}     Temporal BiLSTM   (w={self.temporal.weight:.0%}, thr={self.temporal.detection_threshold})",
            f"  {ON(self.anomaly.enabled)}     Anomaly (rules)   (w={self.anomaly.weight:.0%})",
            "-" * 55,
            "  --- Defenses ---",
            f"  {ON(self.threat_intel.enabled)}     Threat Intel",
            f"     AbuseIPDB  : {'active' if self.threat_intel.abuseipdb_enabled and bool(self.threat_intel.abuseipdb_key) else 'no key'}",
            f"     Spamhaus   : {'active' if self.threat_intel.spamhaus_enabled else 'off'}",
            f"     Feodo      : {'active' if self.threat_intel.feodo_enabled else 'off'}",
            f"  {ON(self.honeypot.enabled)}     Honeypot",
            f"  {ON(self.fingerprint.enabled)}     Client Fingerprinting (JA3={'on' if self.fingerprint.check_ja3 else 'off'})",
            f"  {ON(self.ato_protector.enabled)}     ATO Protector",
            f"  {ON(self.rate_limiter.enabled)}     Rate Limiter      (Adaptive={'on' if self.rate_limiter.adaptive_ratelimit else 'off'})",
            f"  {ON(self.api_schema.enabled)}     API Schema Validator",
            f"  {ON(self.graphql_inspector.enabled)}     GraphQL Inspector",
            f"  {ON(self.deception_engine.enabled)}     Deception Engine",
            "-" * 55,
            "  --- Intelligence ---",
            f"  {ON(self.xai_explainer.enabled)}     XAI Explainer     ({self.xai_explainer.explainer_type})",
            f"  {ON(self.self_learning.enabled)}     Self-Learning Logger",
            f"  {ON(self.shadow_mode.enabled)}     Shadow Mode",
            "-" * 55,
            f"  Thresholds: ALLOW<{self.risk_scoring.thresholds.allow:.0%} | "
            f"CHALLENGE<{self.risk_scoring.thresholds.challenge:.0%} | "
            f"BLOCK>={self.risk_scoring.thresholds.block:.0%}",
            f"  Fail-open : {'yes (allow on error)' if self.performance.fail_open else 'no (block on error)'}",
            "=" * 55,
        ]
        return "\n".join(lines)


# ══════════════════════════════════════════════
#  Utility helpers
# ══════════════════════════════════════════════

def _env_override(yaml_value: str, env_var: str) -> str:
    """Return env var value if set, otherwise fall back to YAML value."""
    return os.environ.get(env_var, yaml_value)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge two dicts, with override taking priority."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


# ── Module-level singleton ───────────────────
_settings: Optional[WAFSettings] = None


def get_waf_settings() -> WAFSettings:
    """Return the module-level WAFSettings singleton (loads on first call)."""
    global _settings
    if _settings is None:
        _settings = WAFSettings.load()
    return _settings

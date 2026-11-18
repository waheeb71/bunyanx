"""
bunyanx NGFW — Audio Alert System: Priority Engine
======================================================
Evaluates incoming events, assigns priority levels, extracts
fine-grained attack types from event payloads, enforces anti-noise
rules, cooldown TTLs, and storm suppression.

Features:
  - Deep threat payload inspection (SQLi, RCE, XSS, Ransomware, DDoS, etc.)
  - Per-topic cooldown TTL prevents repeated sounds
  - Storm detection: >N identical events in T seconds → aggregate count
  - Emergency (Level 6) always bypasses all suppression
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from typing import Optional, Tuple

from system.audio.schemas import AudioPriority, AudioNotification

logger = logging.getLogger(__name__)


# ── Event → Priority mapping ────────────────────────────────────────

EVENT_PRIORITY_MAP: dict[str, int] = {
    # System Lifecycle & Health
    "system.started":           AudioPriority.INFORMATIONAL,
    "system.shutdown":          AudioPriority.NOTICE,
    "system.core_failure":      AudioPriority.EMERGENCY,
    "system_core_failure":      AudioPriority.EMERGENCY,
    "core_failure":             AudioPriority.EMERGENCY,
    "system.memory_critical":   AudioPriority.CRITICAL,
    "system_memory_critical":   AudioPriority.CRITICAL,
    "system.cpu_critical":      AudioPriority.CRITICAL,
    "system_cpu_critical":      AudioPriority.CRITICAL,
    "system.disk_critical":     AudioPriority.CRITICAL,
    "system_disk_critical":     AudioPriority.CRITICAL,

    # Module Lifecycle
    "module.started":           AudioPriority.INFORMATIONAL,
    "module.stopped":           AudioPriority.NOTICE,
    "module.health":            AudioPriority.NOTICE,

    # Auth & Identity
    "auth.login_success":       AudioPriority.INFORMATIONAL,
    "auth.login_failure":       AudioPriority.WARNING,
    "auth_login_failure":       AudioPriority.WARNING,
    "auth.brute_force":         AudioPriority.CRITICAL,
    "auth_brute_force":         AudioPriority.CRITICAL,
    "auth_hacker_alarm":        AudioPriority.CRITICAL,
    "brute_force":              AudioPriority.CRITICAL,
    "credential_stuffing":      AudioPriority.CRITICAL,
    "password_spray":           AudioPriority.CRITICAL,

    # Configuration
    "config.saved":             AudioPriority.INFORMATIONAL,
    "config.reloaded":          AudioPriority.NOTICE,

    # Threats & General Enforcement
    "threat.detected":          AudioPriority.SECURITY_ALERT,
    "threat_detected":          AudioPriority.SECURITY_ALERT,
    "response.block":           AudioPriority.SECURITY_ALERT,
    "response_block":           AudioPriority.SECURITY_ALERT,
    "response.quarantine":      AudioPriority.SECURITY_ALERT,
    "response_quarantine":      AudioPriority.SECURITY_ALERT,
    "response.alert":           AudioPriority.WARNING,
    "response_alert":           AudioPriority.WARNING,

    # WAF & Web Attacks
    "waf.block":                AudioPriority.CRITICAL,
    "waf_block":                AudioPriority.CRITICAL,
    "waf.alert":                AudioPriority.WARNING,
    "waf_alert":                AudioPriority.WARNING,
    "sqli":                     AudioPriority.CRITICAL,
    "sql_injection":            AudioPriority.CRITICAL,
    "rce":                      AudioPriority.CRITICAL,
    "command_injection":        AudioPriority.CRITICAL,
    "xss":                      AudioPriority.SECURITY_ALERT,
    "cross_site_scripting":     AudioPriority.SECURITY_ALERT,
    "path_traversal":           AudioPriority.SECURITY_ALERT,
    "directory_traversal":      AudioPriority.SECURITY_ALERT,
    "lfi":                      AudioPriority.SECURITY_ALERT,
    "rfi":                      AudioPriority.CRITICAL,
    "ssrf":                     AudioPriority.SECURITY_ALERT,
    "csrf":                     AudioPriority.WARNING,
    "web_filter.block":         AudioPriority.WARNING,
    "web_filter_block":         AudioPriority.WARNING,

    # Malware & Antivirus
    "malware.detected":         AudioPriority.CRITICAL,
    "malware_detected":         AudioPriority.CRITICAL,
    "malware.critical":         AudioPriority.CRITICAL,
    "malware_critical":         AudioPriority.CRITICAL,
    "ransomware":               AudioPriority.CRITICAL,
    "trojan":                   AudioPriority.CRITICAL,
    "worm":                     AudioPriority.CRITICAL,
    "rootkit":                  AudioPriority.CRITICAL,
    "spyware":                  AudioPriority.SECURITY_ALERT,
    "c2":                       AudioPriority.CRITICAL,

    # IDS / IPS & DDoS
    "ids.port_scan":            AudioPriority.SECURITY_ALERT,
    "ids_port_scan":            AudioPriority.SECURITY_ALERT,
    "port_scan":                AudioPriority.SECURITY_ALERT,
    "ids_port_scan_warning":    AudioPriority.WARNING,
    "syn_flood":                AudioPriority.CRITICAL,
    "udp_flood":                AudioPriority.CRITICAL,
    "icmp_flood":               AudioPriority.SECURITY_ALERT,
    "dos":                      AudioPriority.CRITICAL,
    "ddos":                     AudioPriority.CRITICAL,
    "dos.attack":               AudioPriority.CRITICAL,
    "ddos.attack":              AudioPriority.CRITICAL,
    "exploit":                  AudioPriority.CRITICAL,
    "shellcode":                AudioPriority.CRITICAL,
    "anomaly.scored":           AudioPriority.SECURITY_ALERT,
    "anomaly_scored":           AudioPriority.SECURITY_ALERT,

    # DNS Security
    "dns.threat":               AudioPriority.SECURITY_ALERT,
    "dns_threat":               AudioPriority.SECURITY_ALERT,
    "dns.suspicious":           AudioPriority.SECURITY_ALERT,
    "dns_suspicious":           AudioPriority.SECURITY_ALERT,
    "dns_tunneling":            AudioPriority.CRITICAL,
    "dns_poisoning":            AudioPriority.CRITICAL,

    # DLP & Email
    "dlp.incident":             AudioPriority.CRITICAL,
    "dlp_incident":             AudioPriority.CRITICAL,
    "data_breach":              AudioPriority.CRITICAL,
    "data_leak":                AudioPriority.CRITICAL,
    "ssn_leak":                 AudioPriority.CRITICAL,
    "credit_card_leak":         AudioPriority.CRITICAL,
    "email.threat":             AudioPriority.SECURITY_ALERT,
    "email_threat":             AudioPriority.SECURITY_ALERT,

    # VPN & PKI
    "vpn.connected":            AudioPriority.INFORMATIONAL,
    "vpn_connected":            AudioPriority.INFORMATIONAL,
    "vpn.disconnected":         AudioPriority.NOTICE,
    "vpn_disconnected":         AudioPriority.NOTICE,
    "vpn.failure":              AudioPriority.SECURITY_ALERT,
    "vpn_failure":              AudioPriority.SECURITY_ALERT,
    "vpn.restored":             AudioPriority.NOTICE,
    "vpn_restored":             AudioPriority.NOTICE,
    "pki.cert_expiring":        AudioPriority.WARNING,
    "pki_cert_expiring":        AudioPriority.WARNING,
    "pki.cert_invalid":         AudioPriority.CRITICAL,
    "pki_cert_invalid":         AudioPriority.CRITICAL,

    # Captive Portal & Identity
    "captive_portal.login":     AudioPriority.INFORMATIONAL,
    "captive_portal_login":     AudioPriority.INFORMATIONAL,
    "captive_portal.logout":    AudioPriority.NOTICE,
    "captive_portal_logout":    AudioPriority.NOTICE,

    # HA & SIEM
    "ha.failover":              AudioPriority.CRITICAL,
    "ha_failover":              AudioPriority.CRITICAL,
    "siem.incident_created":    AudioPriority.SECURITY_ALERT,
    "siem_incident_created":    AudioPriority.SECURITY_ALERT,
    "siem.incident_escalated":  AudioPriority.CRITICAL,
    "siem_incident_escalated":  AudioPriority.CRITICAL,
    "siem.incident_closed":     AudioPriority.NOTICE,
    "siem_incident_closed":     AudioPriority.NOTICE,

    # Intelligence & AI
    "intel.updated":            AudioPriority.INFORMATIONAL,
    "intel_updated":            AudioPriority.INFORMATIONAL,
    "correlation.triggered":    AudioPriority.SECURITY_ALERT,
    "correlation_triggered":    AudioPriority.SECURITY_ALERT,
    "ai.score_generated":       AudioPriority.INFORMATIONAL,
    "ai_score_generated":       AudioPriority.INFORMATIONAL,
}


class PriorityEngine:
    """
    Intelligent Priority Engine with deep event payload analysis,
    cooldown management, and storm suppression.
    """

    def __init__(self):
        self._last_played: dict[str, float] = {}
        self._event_windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._lock = asyncio.Lock()

    @classmethod
    def extract_sound_id(cls, topic: str, payload: dict) -> str:
        """
        Extract specific threat type from payload to pick exact alert sound.
        """
        threat_raw = (
            payload.get("threat_type") or 
            payload.get("attack_type") or 
            payload.get("signature_name") or
            payload.get("event_type") or
            payload.get("event") or
            payload.get("type") or
            ""
        )
        if isinstance(threat_raw, str) and threat_raw:
            norm = threat_raw.lower().replace("-", "_").replace(" ", "_").strip()
            if norm in ("sqli", "sql_injection", "sql"):
                return "sqli"
            if norm in ("rce", "command_injection", "cmd_injection", "remote_code_execution"):
                return "rce"
            if norm in ("xss", "cross_site_scripting"):
                return "xss"
            if norm in ("path_traversal", "directory_traversal", "lfi", "rfi"):
                return "path_traversal"
            if norm in ("port_scan", "ids_port_scan"):
                return "ids_port_scan"
            if norm in ("syn_flood", "udp_flood", "icmp_flood", "dos", "ddos"):
                return "syn_flood"
            if norm in ("ransomware", "rootkit", "malware_critical"):
                return "malware_critical"
            if norm in ("brute_force", "auth_brute_force", "credential_stuffing", "password_spray"):
                return "auth_brute_force"
            if norm in ("data_breach", "data_leak", "ssn_leak", "credit_card_leak", "dlp_incident"):
                return "dlp_incident"
            if norm in ("dns_tunneling", "dns_threat", "dga_domain"):
                return "dns_threat"
            if norm in ("system_core_failure", "core_failure"):
                return "system_core_failure"
            if norm in ("system_memory_critical", "memory_critical"):
                return "system_memory_critical"
            if norm in ("system_cpu_critical", "cpu_critical"):
                return "system_cpu_critical"

        # Check match_types (for DLP)
        match_types = payload.get("match_types")
        if isinstance(match_types, list) and match_types:
            return "dlp_incident"

        return topic.replace(".", "_")

    def get_priority(self, topic: str, payload: Optional[dict] = None) -> int:
        """Return priority level for topic with payload threat refinement."""
        sound_id = self.extract_sound_id(topic, payload or {}) if payload else topic.replace(".", "_")
        if sound_id in EVENT_PRIORITY_MAP:
            return EVENT_PRIORITY_MAP[sound_id]
        return EVENT_PRIORITY_MAP.get(topic, AudioPriority.INFORMATIONAL)

    async def evaluate(
        self,
        topic: str,
        payload: dict,
    ) -> Tuple[bool, AudioNotification, int]:
        """
        Evaluate an incoming event for audio playback.
        Returns (should_play, notification, aggregated_count).
        """
        sound_id = self.extract_sound_id(topic, payload)
        priority = self.get_priority(topic, payload)
        now = time.monotonic()
        tracking_key = f"{topic}:{sound_id}"

        async with self._lock:
            # ── Level 6: Emergency — ALWAYS play instantly ──────────
            if priority == AudioPriority.EMERGENCY:
                self._last_played[tracking_key] = now
                notification = self._build_notification(topic, sound_id, payload, priority, 1, False)
                return True, notification, 1

            # ── Storm detection ────────────────────────────────────
            window = self._event_windows[tracking_key]
            window.append(now)

            max_events, window_s = AudioPriority.STORM_THRESHOLD.get(
                priority, AudioPriority.STORM_THRESHOLD[AudioPriority.INFORMATIONAL]
            )
            cutoff = now - window_s
            recent = sum(1 for t in window if t >= cutoff)

            if recent > max_events:
                aggregated = recent
                last = self._last_played.get(tracking_key, 0)
                cooldown = AudioPriority.COOLDOWNS.get(priority, 10)
                if (now - last) < cooldown:
                    notification = self._build_notification(
                        topic, sound_id, payload, priority, aggregated, True
                    )
                    return False, notification, aggregated
                else:
                    self._last_played[tracking_key] = now
                    notification = self._build_notification(
                        topic, sound_id, payload, priority, aggregated, False
                    )
                    return True, notification, aggregated

            # ── Cooldown window check ──────────────────────────────
            last = self._last_played.get(tracking_key, 0)
            cooldown = AudioPriority.COOLDOWNS.get(priority, 0)
            if cooldown > 0 and (now - last) < cooldown:
                notification = self._build_notification(
                    topic, sound_id, payload, priority, 1, True
                )
                logger.debug(
                    f"[PriorityEngine] Suppressed {tracking_key} "
                    f"(cooldown {cooldown - (now - last):.1f}s remaining)"
                )
                return False, notification, 1

            # ── Play sound ─────────────────────────────────────────
            self._last_played[tracking_key] = now
            notification = self._build_notification(topic, sound_id, payload, priority, 1, False)
            return True, notification, 1

    def _build_notification(
        self,
        topic: str,
        sound_id: str,
        payload: dict,
        priority: int,
        count: int,
        suppressed: bool,
    ) -> AudioNotification:
        """Construct an AudioNotification with smart titles and details."""
        source = payload.get("module", payload.get("source_module", "system"))
        title  = self._make_title(topic, sound_id, payload, count)
        msg    = payload.get("reason", payload.get("message", payload.get("details", "")))

        return AudioNotification(
            event_type      = topic,
            source_module   = str(source),
            priority        = priority,
            priority_name   = AudioPriority.NAMES.get(priority, "Unknown"),
            priority_color  = AudioPriority.COLORS.get(priority, "#ffffff"),
            sound_id        = sound_id,
            title           = title,
            message         = str(msg)[:250],
            suppressed      = suppressed,
            aggregated_count= count,
        )

    @classmethod
    def _make_title(cls, topic: str, sound_id: str, payload: dict, count: int) -> str:
        """Generate an intelligent, context-aware alert title."""
        src = payload.get("src_ip", "")
        dst = payload.get("dst_ip", "")

        sound_titles = {
            "sqli": "🚨 تم حجب هجوم حقن قواعد البيانات (SQL Injection)",
            "rce": "🚨 تم حجب هجوم تنفيذ أوامر خبيثة (RCE)",
            "xss": "🛡 تم حجب هجوم برمجة عبر المواقع (XSS)",
            "path_traversal": "🛡 تم حجب محاولة اختراق مسار الملفات (Path Traversal)",
            "ids_port_scan": "🔍 تم رصد مسح للمنافذ (Port Scan)",
            "syn_flood": "🌊 تم رصد هجوم حجب الخدمة (SYN Flood)",
            "malware_critical": "☣ خطر: برمجية خبيثة حرجة / فدية (Ransomware)",
            "malware_detected": "🦠 تم اكتشاف برمجية خبيثة (Malware)",
            "auth_brute_force": "🚨 هجوم تخمين كلمات المرور (Brute Force)",
            "dlp_incident": "🔒 تنبيه: محاولة تسريب بيانات حساسة (DLP)",
            "dns_threat": "🌐 رصد تهديد في خادم النطاقات (DNS Threat)",
            "email_threat": "📧 تم اعتراض وحظر بريد خبيث (Email Threat)",
            "web_filter_block": "🛑 تم حجب موقع ويب ممنوع (Web Filter)",
            "waf_alert": "⚠️ تحذير جدار حماية التطبيقات (WAF Alert)",
            "response_quarantine": "☣ تم عزل وتطويق التهديد (Quarantine)",
            "system_core_failure": "💥 طوارئ: فشل حرج في نواة نظام الجدار الناري",
            "system_memory_critical": "🔥 تحذير: استهلاك الذاكرة في مستوى حرج",
            "system_cpu_critical": "🔥 تحذير: حمل المعالج في مستوى حرج",
            "ha_failover": "⚡ تم التحويل التلقائي للنظام الاحتياطي (HA Failover)",
            "vpn_failure": "🔌 انقطاع في اتصال الشبكة الافتراضية (VPN)",
            "vpn_restored": "🔒 استعادة نفق الشبكة الافتراضية (VPN Restored)",
            "vpn_connected": "🔒 تم إنشاء اتصال VPN بنجاح",
            "vpn_disconnected": "🔌 تم إنهاء اتصال VPN",
            "captive_portal_login": "👤 تسجيل دخول عبر بوابة العبور (Captive Portal)",
            "captive_portal_logout": "🚪 تسجيل خروج من بوابة العبور (Captive Portal)",
            "siem_incident_closed": "✅ تم إغلاق الحادثة الأمنية (SIEM Resolved)",
            "system_started": "🚀 بدأ تشغيل منظومة الجدار الناري بنجاح",
            "system_shutdown": "🛑 جارٍ إيقاف تشغيل المنظومة",
            "auth_login_success": "✅ تسجيل دخول ناجح للمسؤول",
            "config_saved": "💾 تم حفظ إعدادات النظام",
            "config_reloaded": "🔄 تم تحديث سياسة الجدار الناري",
            "intel_updated": "📡 تم تحديث قواعد الاستخبارات الأمنية",
            "ai_score_generated": "🧠 تم توليد تقييم الذكاء الاصطناعي",
        }

        title = sound_titles.get(sound_id)
        if not title:
            label_map = {
                "system.started":           "النظام بدأ",
                "system.shutdown":          "إيقاف النظام",
                "system.core_failure":      "💥 طوارئ: فشل حرج في النظام",
                "system.memory_critical":   "🔥 ذاكرة حرجة",
                "system.cpu_critical":      "🔥 CPU حرج",
                "module.started":           f"وحدة بدأت: {payload.get('module_name', '')}",
                "module.stopped":           f"وحدة توقفت: {payload.get('module_name', '')}",
                "auth.login_success":       "تسجيل دخول ناجح",
                "auth.login_failure":       "فشل تسجيل الدخول",
                "auth.brute_force":         "🚨 هجوم Brute Force",
                "config.saved":             "تم حفظ الإعدادات",
                "config.reloaded":          "تم تحديث السياسة",
                "threat.detected":          "🛡 تهديد مكتشف",
                "response.block":           "تم حجب التهديد",
                "malware.detected":         "🦠 برمجية خبيثة مكتشفة",
                "ids.port_scan":            "مسح المنافذ مكتشف",
                "dns.suspicious":           "نشاط DNS مشبوه",
                "dlp.incident":             "🔒 حادثة تسرب بيانات",
                "vpn.failure":              "فشل VPN",
                "vpn.restored":             "VPN استعاد الاتصال",
                "pki.cert_expiring":        "شهادة SSL قاربت على الانتهاء",
                "pki.cert_invalid":         "شهادة SSL غير صالحة",
                "ha.failover":              "HA Failover نشط",
                "siem.incident_created":    "حادثة أمنية جديدة",
                "siem.incident_escalated":  "تصعيد حادثة أمنية",
                "siem.incident_closed":     "إغلاق حادثة أمنية",
                "ai.score_generated":       "تم توليد تقييم الذكاء الاصطناعي",
                "email.threat":             "تهديد في البريد الإلكتروني",
                "web_filter.block":         "تم حجب موقع ممنوع",
            }
            title = label_map.get(topic, topic)

        if src and dst:
            title = f"{title} [{src} → {dst}]"
        elif src:
            title = f"{title} [{src}]"

        if count > 1:
            title = f"{title} (×{count})"
        return title

    def reset(self) -> None:
        """Clear all tracking state."""
        self._last_played.clear()
        self._event_windows.clear()

"""
bunyanx NGFW — Default Sound Profile
=========================================
Full event → sound mapping for normal (daytime) SOC operations.
All sounds are synthesized via Web Audio API — no audio files needed.

Waveform types: sine | square | sawtooth | triangle
Each ToneConfig: frequency_hz, duration_ms, waveform, volume, attack_ms, decay_ms, sustain_level, release_ms
"""

from system.audio.schemas import SoundProfile, ToneConfig, AudioPriority

# Helper constructors
def _tone(freq, dur, wave="sine", vol=0.6, atk=20, dec=50, sus=0.7, rel=80):
    return ToneConfig(
        frequency_hz=freq, duration_ms=dur, waveform=wave,
        volume=vol, attack_ms=atk, decay_ms=dec,
        sustain_level=sus, release_ms=rel
    )


# ──────────────────────────────────────────────────────────────────────
# Level 1 — Informational (soft, pleasant)
# ──────────────────────────────────────────────────────────────────────

SOUND_SYSTEM_STARTED = SoundProfile(
    sound_id="system_started",
    label="النظام بدأ",
    priority=AudioPriority.INFORMATIONAL,
    tones=[
        _tone(523, 120, "sine", 0.4),   # C5
        _tone(659, 120, "sine", 0.4),   # E5
        _tone(784, 200, "sine", 0.5),   # G5
    ],
    repeat=1, gap_ms=0,
)

SOUND_MODULE_STARTED = SoundProfile(
    sound_id="module_started",
    label="وحدة بدأت",
    priority=AudioPriority.INFORMATIONAL,
    tones=[_tone(880, 80, "sine", 0.35), _tone(1047, 120, "sine", 0.4)],
    repeat=1, gap_ms=0,
)

SOUND_CONFIG_SAVED = SoundProfile(
    sound_id="config_saved",
    label="تم حفظ الإعدادات",
    priority=AudioPriority.INFORMATIONAL,
    tones=[_tone(1047, 60, "sine", 0.3), _tone(1319, 80, "sine", 0.3)],
    repeat=1, gap_ms=0,
)

SOUND_LOGIN_SUCCESS = SoundProfile(
    sound_id="auth_login_success",
    label="تسجيل دخول ناجح",
    priority=AudioPriority.INFORMATIONAL,
    tones=[
        _tone(659, 80, "sine", 0.35),
        _tone(784, 80, "sine", 0.35),
        _tone(1047, 120, "sine", 0.45),
    ],
    repeat=1, gap_ms=0,
)

SOUND_INTEL_UPDATED = SoundProfile(
    sound_id="intel_updated",
    label="استخبارات محدّثة",
    priority=AudioPriority.INFORMATIONAL,
    tones=[_tone(740, 100, "sine", 0.3), _tone(880, 120, "sine", 0.35)],
    repeat=1, gap_ms=0,
)


# ──────────────────────────────────────────────────────────────────────
# Level 2 — Notice (clear, informative)
# ──────────────────────────────────────────────────────────────────────

SOUND_SYSTEM_SHUTDOWN = SoundProfile(
    sound_id="system_shutdown",
    label="إيقاف النظام",
    priority=AudioPriority.NOTICE,
    tones=[
        _tone(784, 150, "sine", 0.5),
        _tone(659, 150, "sine", 0.45),
        _tone(523, 200, "sine", 0.4),
    ],
    repeat=1, gap_ms=0,
)

SOUND_MODULE_STOPPED = SoundProfile(
    sound_id="module_stopped",
    label="وحدة توقفت",
    priority=AudioPriority.NOTICE,
    tones=[
        _tone(880, 100, "sine", 0.4),
        _tone(440, 120, "sine", 0.4),
    ],
    repeat=1, gap_ms=80,
)

SOUND_POLICY_UPDATED = SoundProfile(
    sound_id="config_reloaded",
    label="تم تحديث السياسة",
    priority=AudioPriority.NOTICE,
    tones=[
        _tone(523, 80, "sine", 0.4),
        _tone(659, 80, "sine", 0.4),
        _tone(784, 80, "sine", 0.4),
        _tone(1047, 120, "sine", 0.45),
    ],
    repeat=1, gap_ms=0,
)

SOUND_VPN_RESTORED = SoundProfile(
    sound_id="vpn_restored",
    label="VPN استعاد الاتصال",
    priority=AudioPriority.NOTICE,
    tones=[
        _tone(440, 100, "sine", 0.45),
        _tone(660, 150, "sine", 0.5),
    ],
    repeat=1, gap_ms=50,
)

SOUND_INCIDENT_CLOSED = SoundProfile(
    sound_id="siem_incident_closed",
    label="إغلاق حادثة أمنية",
    priority=AudioPriority.NOTICE,
    tones=[
        _tone(880, 80, "sine", 0.4),
        _tone(1047, 120, "sine", 0.45),
    ],
    repeat=1, gap_ms=0,
)

SOUND_MODULE_HEALTH = SoundProfile(
    sound_id="module_health",
    label="صحة الوحدة",
    priority=AudioPriority.NOTICE,
    tones=[_tone(660, 120, "sine", 0.35)],
    repeat=1, gap_ms=0,
)


# ──────────────────────────────────────────────────────────────────────
# Level 3 — Warning (attention-grabbing)
# ──────────────────────────────────────────────────────────────────────

SOUND_LOGIN_FAILURE = SoundProfile(
    sound_id="auth_login_failure",
    label="فشل تسجيل الدخول",
    priority=AudioPriority.WARNING,
    tones=[
        _tone(220, 120, "square", 0.5, atk=10, dec=20, sus=0.6, rel=50),
        _tone(196, 150, "square", 0.5, atk=10, dec=20, sus=0.6, rel=50),
    ],
    repeat=2, gap_ms=100,
    tts_text="تحذير: محاولة دخول فاشلة",
)

SOUND_CERT_EXPIRING = SoundProfile(
    sound_id="pki_cert_expiring",
    label="شهادة SSL قاربت على الانتهاء",
    priority=AudioPriority.WARNING,
    tones=[
        _tone(440, 200, "sine", 0.45),
        _tone(440, 200, "sine", 0.45),
    ],
    repeat=2, gap_ms=300,
    tts_text="تحذير: شهادة SSL ستنتهي قريباً",
)

SOUND_RESPONSE_ALERT = SoundProfile(
    sound_id="response_alert",
    label="تنبيه استجابة",
    priority=AudioPriority.WARNING,
    tones=[
        _tone(330, 150, "triangle", 0.5),
        _tone(440, 150, "triangle", 0.5),
    ],
    repeat=2, gap_ms=120,
    tts_text="تحذير: تم إصدار تنبيه استجابة",
)



# ──────────────────────────────────────────────────────────────────────
# Level 4 — Security Alert (urgent, distinct)
# ──────────────────────────────────────────────────────────────────────

SOUND_THREAT_DETECTED = SoundProfile(
    sound_id="threat_detected",
    label="تهديد مكتشف",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(880, 120, "square", 0.7, atk=5, dec=20, sus=0.8, rel=40),
        _tone(660, 120, "square", 0.7, atk=5, dec=20, sus=0.8, rel=40),
    ],
    repeat=3, gap_ms=150,
    tts_text="تنبيه أمني: تم اكتشاف تهديد",
)

SOUND_THREAT_BLOCKED = SoundProfile(
    sound_id="response_block",
    label="تم حجب التهديد",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(660, 100, "square", 0.65, atk=5, dec=15, sus=0.8, rel=35),
        _tone(880, 150, "square", 0.65, atk=5, dec=15, sus=0.8, rel=35),
    ],
    repeat=2, gap_ms=100,
    tts_text="تنبيه: تم حجب التهديد وإيقافه",
)

SOUND_RESPONSE_QUARANTINE = SoundProfile(
    sound_id="response_quarantine",
    label="عزل مشبوه",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(440, 150, "triangle", 0.6, atk=10, dec=25, sus=0.75, rel=50),
        _tone(330, 150, "triangle", 0.6, atk=10, dec=25, sus=0.75, rel=50),
    ],
    repeat=2, gap_ms=120,
    tts_text="تنبيه: تم عزل جهاز مشبوه",
)

SOUND_PORT_SCAN = SoundProfile(
    sound_id="ids_port_scan",
    label="مسح المنافذ مكتشف",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(880, 80, "sine", 0.6, atk=5, dec=15, sus=0.75, rel=30),
        _tone(1100, 80, "sine", 0.6, atk=5, dec=15, sus=0.75, rel=30),
        _tone(880, 80, "sine", 0.6, atk=5, dec=15, sus=0.75, rel=30),
    ],
    repeat=2, gap_ms=100,
    tts_text="تنبيه: تم اكتشاف مسح للمنافذ",
)

SOUND_ANOMALY = SoundProfile(
    sound_id="anomaly_scored",
    label="نشاط شاذ",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(550, 180, "sawtooth", 0.55, atk=10, dec=30, sus=0.7, rel=55),
        _tone(440, 180, "sawtooth", 0.55, atk=10, dec=30, sus=0.7, rel=55),
    ],
    repeat=2, gap_ms=120,
    tts_text="تنبيه: تم رصد نشاط شاذ",
)

SOUND_DNS_SUSPICIOUS = SoundProfile(
    sound_id="dns_suspicious",
    label="نشاط DNS مشبوه",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(440, 130, "triangle", 0.5, atk=10, dec=25, sus=0.7, rel=50),
        _tone(550, 130, "triangle", 0.5, atk=10, dec=25, sus=0.7, rel=50),
    ],
    repeat=2, gap_ms=120,
    tts_text="تنبيه: نشاط DNS مشبوه",
)

SOUND_VPN_FAILURE = SoundProfile(
    sound_id="vpn_failure",
    label="فشل VPN",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(330, 200, "square", 0.65, atk=5, dec=20, sus=0.8, rel=50),
        _tone(220, 250, "square", 0.65, atk=5, dec=20, sus=0.8, rel=50),
    ],
    repeat=3, gap_ms=150,
    tts_text="تنبيه: انقطع اتصال VPN",
)

SOUND_CORRELATION = SoundProfile(
    sound_id="correlation_triggered",
    label="ارتباط أحداث مكتشف",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(660, 100, "sine", 0.6, atk=5, dec=20, sus=0.75, rel=40),
        _tone(880, 100, "sine", 0.6, atk=5, dec=20, sus=0.75, rel=40),
        _tone(1100, 150, "sine", 0.65, atk=5, dec=20, sus=0.75, rel=40),
    ],
    repeat=3, gap_ms=100,
    tts_text="تنبيه: تم اكتشاف ارتباط أحداث",
)

SOUND_INCIDENT_CREATED = SoundProfile(
    sound_id="siem_incident_created",
    label="حادثة أمنية جديدة",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(880, 120, "sine", 0.65, atk=5, dec=20, sus=0.8, rel=40),
        _tone(660, 100, "sine", 0.6, atk=5, dec=20, sus=0.75, rel=40),
    ],
    repeat=2, gap_ms=150,
    tts_text="تنبيه: تم إنشاء حادثة أمنية جديدة",
)



# ──────────────────────────────────────────────────────────────────────
# Level 5 — Critical (alarming, urgent)
# ──────────────────────────────────────────────────────────────────────

SOUND_MALWARE_DETECTED = SoundProfile(
    sound_id="malware_detected",
    label="برمجية خبيثة مكتشفة",
    priority=AudioPriority.CRITICAL,
    tones=[
        _tone(880, 150, "sawtooth", 0.9, atk=3, dec=10, sus=0.95, rel=20),
        _tone(660, 150, "sawtooth", 0.9, atk=3, dec=10, sus=0.95, rel=20),
        _tone(880, 150, "sawtooth", 0.9, atk=3, dec=10, sus=0.95, rel=20),
    ],
    repeat=4, gap_ms=200,
    tts_text="خطر: تم اكتشاف برمجية خبيثة. يرجى التدخل فوراً",
)

SOUND_BRUTE_FORCE = SoundProfile(
    sound_id="auth_brute_force",
    label="هجوم Brute Force",
    priority=AudioPriority.CRITICAL,
    tones=[
        _tone(220, 100, "square", 0.85, atk=3, dec=10, sus=0.9, rel=20),
        _tone(330, 100, "square", 0.85, atk=3, dec=10, sus=0.9, rel=20),
        _tone(220, 100, "square", 0.85, atk=3, dec=10, sus=0.9, rel=20),
        _tone(330, 100, "square", 0.85, atk=3, dec=10, sus=0.9, rel=20),
    ],
    repeat=4, gap_ms=180,
    tts_text="خطر: هجوم تخمين كلمة مرور مكتشف",
)

SOUND_DLP_INCIDENT = SoundProfile(
    sound_id="dlp_incident",
    label="حادثة تسرب بيانات",
    priority=AudioPriority.CRITICAL,
    tones=[
        _tone(660, 200, "sawtooth", 0.85, atk=5, dec=15, sus=0.9, rel=30),
        _tone(440, 200, "sawtooth", 0.85, atk=5, dec=15, sus=0.9, rel=30),
    ],
    repeat=4, gap_ms=200,
    tts_text="خطر: تسرب بيانات حساسة مكتشف",
)

SOUND_CERT_INVALID = SoundProfile(
    sound_id="pki_cert_invalid",
    label="شهادة SSL غير صالحة",
    priority=AudioPriority.CRITICAL,
    tones=[
        _tone(440, 180, "square", 0.8, atk=5, dec=15, sus=0.85, rel=35),
        _tone(330, 180, "square", 0.8, atk=5, dec=15, sus=0.85, rel=35),
    ],
    repeat=4, gap_ms=150,
    tts_text="خطر: شهادة SSL غير صالحة",
)

SOUND_HA_FAILOVER = SoundProfile(
    sound_id="ha_failover",
    label="HA Failover نشط",
    priority=AudioPriority.CRITICAL,
    tones=[
        _tone(880, 200, "sawtooth", 0.95, atk=3, dec=10, sus=1.0, rel=20),
        _tone(440, 200, "sawtooth", 0.95, atk=3, dec=10, sus=1.0, rel=20),
    ],
    repeat=4, gap_ms=200,
    tts_text="خطر: فشل الجهاز الرئيسي. تم التحويل التلقائي",
)

SOUND_MEMORY_CRITICAL = SoundProfile(
    sound_id="system_memory_critical",
    label="ذاكرة حرجة",
    priority=AudioPriority.CRITICAL,
    tones=[
        _tone(550, 150, "square", 0.8, atk=5, dec=15, sus=0.85, rel=30),
        _tone(660, 150, "square", 0.8, atk=5, dec=15, sus=0.85, rel=30),
    ],
    repeat=4, gap_ms=180,
    tts_text="خطر: استهلاك الذاكرة وصل مستوى حرجاً",
)

SOUND_CPU_CRITICAL = SoundProfile(
    sound_id="system_cpu_critical",
    label="CPU حرج",
    priority=AudioPriority.CRITICAL,
    tones=[
        _tone(660, 150, "square", 0.8, atk=5, dec=15, sus=0.85, rel=30),
        _tone(880, 150, "square", 0.8, atk=5, dec=15, sus=0.85, rel=30),
    ],
    repeat=4, gap_ms=180,
    tts_text="خطر: حمل المعالج وصل مستوى حرجاً",
)

SOUND_INCIDENT_ESCALATED = SoundProfile(
    sound_id="siem_incident_escalated",
    label="تصعيد حادثة أمنية",
    priority=AudioPriority.CRITICAL,
    tones=[
        _tone(880, 120, "sawtooth", 0.9, atk=3, dec=10, sus=0.95, rel=20),
        _tone(660, 120, "sawtooth", 0.85, atk=3, dec=10, sus=0.9, rel=20),
        _tone(880, 120, "sawtooth", 0.9, atk=3, dec=10, sus=0.95, rel=20),
    ],
    repeat=4, gap_ms=200,
    tts_text="خطر: تم تصعيد الحادثة الأمنية",
)



# ──────────────────────────────────────────────────────────────────────
# Level 6 — Emergency (maximum urgency, no suppression)
# ──────────────────────────────────────────────────────────────────────

SOUND_CORE_FAILURE = SoundProfile(
    sound_id="system_core_failure",
    label="فشل حرج في النظام",
    priority=AudioPriority.EMERGENCY,
    tones=[
        _tone(960, 200, "square", 1.0, atk=3, dec=5, sus=1.0, rel=10),
        _tone(480, 200, "square", 1.0, atk=3, dec=5, sus=1.0, rel=10),
    ],
    repeat=99,   # Repeat until acknowledged
    gap_ms=100,
    tts_text="طوارئ: فشل حرج في نظام الجدار الناري. يرجى التدخل الفوري",
)



# ──────────────────────────────────────────────────────────────────────
# Level 4 — WAF / DNS / Web Filter / Email (Security Alert)
# ──────────────────────────────────────────────────────────────────────

SOUND_WAF_BLOCK = SoundProfile(
    sound_id="waf_block",
    label="WAF: طلب محجوب",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(880,  80, "square", 0.65, atk=5, dec=15, sus=0.8, rel=30),
        _tone(660, 100, "square", 0.65, atk=5, dec=15, sus=0.8, rel=30),
        _tone(440, 120, "square", 0.70, atk=5, dec=15, sus=0.8, rel=30),
    ],
    repeat=2, gap_ms=100,
    tts_text="تنبيه: تم حجب هجوم ويب",
)

SOUND_WAF_ALERT = SoundProfile(
    sound_id="waf_alert",
    label="WAF: تنبيه أمني",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(660, 120, "square", 0.55, atk=5, dec=20, sus=0.7, rel=40),
        _tone(880, 100, "square", 0.55, atk=5, dec=20, sus=0.7, rel=40),
    ],
    repeat=2, gap_ms=120,
    tts_text="تنبيه: نشاط مشبوه على تطبيق الويب",
)

SOUND_DNS_THREAT = SoundProfile(
    sound_id="dns_threat",
    label="DNS: تهديد مكتشف",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(440, 150, "sawtooth", 0.6, atk=5, dec=20, sus=0.75, rel=50),
        _tone(550, 150, "sawtooth", 0.6, atk=5, dec=20, sus=0.75, rel=50),
    ],
    repeat=3, gap_ms=130,
    tts_text="تنبيه: تهديد DNS مكتشف",
)

SOUND_EMAIL_THREAT = SoundProfile(
    sound_id="email_threat",
    label="تهديد بريد إلكتروني",
    priority=AudioPriority.SECURITY_ALERT,
    tones=[
        _tone(330, 180, "triangle", 0.55, atk=10, dec=30, sus=0.7, rel=60),
        _tone(440, 180, "triangle", 0.55, atk=10, dec=30, sus=0.7, rel=60),
    ],
    repeat=2, gap_ms=120,
    tts_text="تنبيه: تهديد في البريد الإلكتروني",
)

SOUND_WEB_FILTER_BLOCK = SoundProfile(
    sound_id="web_filter_block",
    label="تصفية الويب: موقع محجوب",
    priority=AudioPriority.WARNING,
    tones=[
        _tone(440, 120, "sine", 0.45, atk=10, dec=25, sus=0.65, rel=60),
        _tone(330, 150, "sine", 0.45, atk=10, dec=25, sus=0.65, rel=60),
    ],
    repeat=1, gap_ms=100,
    tts_text="تحذير: تم حجب موقع ممنوع",
)


# ──────────────────────────────────────────────────────────────────────
# Master Registry: topic → SoundProfile
# ──────────────────────────────────────────────────────────────────────

DEFAULT_PROFILE_MAP: dict[str, SoundProfile] = {
    # Informational
    "system.started":            SOUND_SYSTEM_STARTED,
    "module.started":            SOUND_MODULE_STARTED,
    "config.saved":              SOUND_CONFIG_SAVED,
    "auth.login_success":        SOUND_LOGIN_SUCCESS,
    "intel.updated":             SOUND_INTEL_UPDATED,

    # Notice
    "system.shutdown":           SOUND_SYSTEM_SHUTDOWN,
    "module.stopped":            SOUND_MODULE_STOPPED,
    "module.health":             SOUND_MODULE_HEALTH,
    "config.reloaded":           SOUND_POLICY_UPDATED,
    "vpn.restored":              SOUND_VPN_RESTORED,
    "siem.incident_closed":      SOUND_INCIDENT_CLOSED,

    # Warning
    "auth.login_failure":        SOUND_LOGIN_FAILURE,
    "pki.cert_expiring":         SOUND_CERT_EXPIRING,
    "response.alert":            SOUND_RESPONSE_ALERT,
    "web_filter.block":          SOUND_WEB_FILTER_BLOCK,

    # Security Alert
    "threat.detected":           SOUND_THREAT_DETECTED,
    "response.block":            SOUND_THREAT_BLOCKED,
    "response.quarantine":       SOUND_RESPONSE_QUARANTINE,
    "ids.port_scan":             SOUND_PORT_SCAN,
    "anomaly.scored":            SOUND_ANOMALY,
    "dns.suspicious":            SOUND_DNS_SUSPICIOUS,
    "dns.threat":                SOUND_DNS_THREAT,
    "vpn.failure":               SOUND_VPN_FAILURE,
    "correlation.triggered":     SOUND_CORRELATION,
    "siem.incident_created":     SOUND_INCIDENT_CREATED,
    "waf.block":                 SOUND_WAF_BLOCK,
    "waf.alert":                 SOUND_WAF_ALERT,
    "email.threat":              SOUND_EMAIL_THREAT,

    # Critical
    "malware.detected":          SOUND_MALWARE_DETECTED,
    "auth.brute_force":          SOUND_BRUTE_FORCE,
    "dlp.incident":              SOUND_DLP_INCIDENT,
    "pki.cert_invalid":          SOUND_CERT_INVALID,
    "ha.failover":               SOUND_HA_FAILOVER,
    "system.memory_critical":    SOUND_MEMORY_CRITICAL,
    "system.cpu_critical":       SOUND_CPU_CRITICAL,
    "siem.incident_escalated":   SOUND_INCIDENT_ESCALATED,

    # Emergency
    "system.core_failure":       SOUND_CORE_FAILURE,
}

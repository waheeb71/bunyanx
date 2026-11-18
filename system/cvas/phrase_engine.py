"""
bunyanx Voice Alert Service (CVAS) - Phrase Engine
=====================================================
Synthesizes multilingual natural-language spoken text using JSON templates.
Supports Tiered Spoken Verbosity Levels, Acronym Phonetics, Speech Caching,
and Burst Aggregation Formatting. Zero hardcoded spoken text in Python.
"""

import re
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

logger = logging.getLogger(__name__)


class _SafeDict(dict):
    """dict subclass that returns empty string for missing keys (safe str.format_map)."""
    def __missing__(self, key: str) -> str:  # noqa: D105
        return ""


def _safe_format(template: str, fields: dict) -> str:
    """
    Format template using fields. Missing keys silently produce empty string.
    Also strips curly braces from any field *values* to prevent injection.
    FIX (PHRASE-02).
    """
    safe_fields = _SafeDict({
        k: str(v).replace("{", "").replace("}", "") if isinstance(v, str) else v
        for k, v in fields.items()
    })
    return template.format_map(safe_fields)


class PhraseEngine:
    """
    Multilingual Phrase Library & Synthesis Engine.
    Formats dynamic event variables into spoken natural language text.
    """

    def __init__(self, phrase_file_path: Optional[str] = None, default_language: str = "ar-SA"):
        self.default_language = default_language
        self._phrase_data: Dict[str, Any] = {}
        self.phrase_file_path = Path(phrase_file_path) if phrase_file_path else None
        self._cache: Dict[str, str] = {}
        self._load_phrase_library()

    def _load_phrase_library(self) -> None:
        """Load phrase_library.json using __file__-relative path. No CWD dependency."""
        if not self.phrase_file_path:
            # Always resolve relative to this file (system/cvas/phrases/)
            default = Path(__file__).parent / "phrases" / "phrase_library.json"
            if default.exists():
                self.phrase_file_path = default

        if self.phrase_file_path and self.phrase_file_path.exists():
            try:
                with open(self.phrase_file_path, "r", encoding="utf-8") as f:
                    self._phrase_data = json.load(f)
                self._cache.clear()
                logger.info(f"[CVAS:PhraseEngine] Loaded phrase library from {self.phrase_file_path}")
            except Exception as e:
                logger.error(f"[CVAS:PhraseEngine] Failed to parse phrase_library.json: {e}")
        else:
            logger.warning("[CVAS:PhraseEngine] phrase_library.json not found! Initialized empty phrase data.")

    def format_ip_phonetic(self, ip_str: str, language: str) -> str:
        """
        Formats IP address string for clear TTS speech rendering.
        Example: 185.220.101.5 -> 185 dot 220 dot 101 dot 5
        """
        if not ip_str:
            return ""
        if language == "en-US":
            return ip_str.replace(".", " dot ")
        return ip_str.replace(".", " نقطة ")

    def _resolve_risk_score(self, payload: Dict[str, Any], lang: str) -> str:
        """
        Resolve highest valid risk score / confidence from payload.
        Ignores scores <= 0.15 (15%) to prevent stating misleading '1% confidence'.
        """
        scores = []

        # Check explicit numeric payload fields
        for field in ["cpci_score", "final_score", "confidence", "score", "risk_score", "ai_score", "ers"]:
            val = payload.get(field)
            if val is not None:
                try:
                    f = float(val)
                    if f > 0.0:
                        scores.append(f)
                except (TypeError, ValueError):
                    pass

        # Check nested TTP distribution if present
        ttp_dist = payload.get("ttp_distribution")
        if ttp_dist and isinstance(ttp_dist, (list, tuple)) and len(ttp_dist) > 0:
            prob = ttp_dist[0].get("probability") if isinstance(ttp_dist[0], dict) else None
            if prob is not None:
                try:
                    f = float(prob)
                    if f > 0.0:
                        scores.append(f)
                except (TypeError, ValueError):
                    pass

        # Extract (SCORE=X.XX) from raw text if present
        raw_text = str(payload.get("description", "")) + " " + str(payload.get("reason", ""))
        score_matches = re.findall(r'SCORE=([0-9\.]+)', raw_text, re.IGNORECASE)
        for sm in score_matches:
            try:
                f = float(sm)
                if f > 0.0:
                    scores.append(f)
            except ValueError:
                pass

        if not scores:
            return ""

        max_score = max(scores)
        # Normalize 0..1 to percentage 0..100
        pct = round(max_score * 100) if max_score <= 1.0 else round(max_score)

        # Ignore low/negligible confidence (< 15%) for speech
        if pct < 15:
            return ""

        return f"{pct}%"

    def _resolve_user(self, payload: Dict[str, Any], lang: str) -> str:
        """
        Resolve username from payload. Returns empty string (not a fallback word)
        when user is unknown to avoid repetition like 'للمستخدم مستخدم'.
        """
        return (
            payload.get("user") or
            payload.get("user_id") or
            payload.get("username") or
            ""
        )

    def _clean_threat_type(self, raw_str: str, lang: str) -> str:
        """
        Sanitizes technical raw log strings (containing [WAF_...], pipes |, SCORE=, etc.)
        into concise, human-readable natural language speech terms.
        Translates known English system phrases into clean Arabic when lang=='ar-SA'.
        """
        if not raw_str:
            return "تهديد أمني" if lang == "ar-SA" else "Security threat"

        raw_trimmed = str(raw_str).strip()

        # Step A: Strip technical log parameters, brackets, scores, formulas, e.g. (2.9Σ), (SCORE=0.76), μ=0.690, CI=[...], asset_id=...
        cleaned = re.sub(r'\[(WAF_[A-Z_]+|UBA|DLP|DLP\-RSP|AEGIS|DDTS|DIE|DECOY|FlowSpec\-AV)\]', '', raw_trimmed)
        cleaned = re.sub(r'\b(SCORE|conf|lat|cpci|asset_id|attacker_ip|src|dst|url|μ|CI|stage|action|auth)\s*=[\s0-9a-zA-Z_\.\:\-\[\]\(\)]+', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'\([0-9\.\s\%\Σ\μ\=]+\)', '', cleaned)
        cleaned = re.sub(r'[\[\]\{\}\(\)\=\|\>\→\:\,\<\>\%\#\$\@\^\&\*\+\~]+', ' ', cleaned)
        cleaned = re.sub(r'\s{2,}', ' ', cleaned).strip()

        raw_lower = cleaned.lower()

        if lang != "ar-SA":
            return cleaned or "Security threat"

        # 1. Direct match in Arabic threat translation map
        if raw_lower in self.THREAT_TRANSLATIONS_AR:
            return self.THREAT_TRANSLATIONS_AR[raw_lower]

        # 2. Multi-pattern detection for AI, WAF, DLP, UBA, AEGIS, DDTS, DIE, FlowSpec
        detected_categories = []
        raw_upper = raw_trimmed.upper()

        if "DDTS" in raw_upper or "EMERGENCY_ISOLATE" in raw_upper:
            detected_categories.append("عزل طارئ لتهديد نشط")
            
        # Specific Threat Type matches (High priority)
        if "SQL" in raw_upper or "SQLI" in raw_upper or "UNION" in raw_upper or "1=1" in raw_upper:
            detected_categories.append("حقن قواعد البيانات")
        elif "COMMAND" in raw_upper or "RCE" in raw_upper or "SEMICOLON" in raw_upper or "SHELL" in raw_upper or "WHOAMI" in raw_upper:
            detected_categories.append("تنفيذ أوامر خبيثة عن بعد")
        elif "XSS" in raw_upper or "SCRIPT" in raw_upper:
            detected_categories.append("برمجة عبر المواقع")
        elif "TRAVERSAL" in raw_upper or "PATH" in raw_upper or "DOTDOT" in raw_upper or "PASSWD" in raw_upper:
            detected_categories.append("تخطي المسارات وقراءة ملفات النظام")
        elif "CREDIT_CARD" in raw_upper or "CREDIT" in raw_upper or "PCI" in raw_upper:
            detected_categories.append("بطاقات الائتمان")
        elif "IBAN" in raw_upper or "BANK" in raw_upper:
            detected_categories.append("أرقام الحسابات البنكية")
        elif "SSN" in raw_upper:
            detected_categories.append("أرقام الضمان الاجتماعي")
        elif "PASSPORT" in raw_upper:
            detected_categories.append("جوازات السفر")
        elif "PORT_SCAN" in raw_upper or "PORT SCAN" in raw_upper or "SCAN" in raw_upper:
            detected_categories.append("مسح منافذ التوصيل")
        elif "BRUTE" in raw_upper or "FORCE" in raw_upper:
            detected_categories.append("تخمين كلمات المرور")
        elif "DOS" in raw_upper or "DDOS" in raw_upper or "FLOOD" in raw_upper or "SLOWLORIS" in raw_upper:
            detected_categories.append("هجوم حجب الخدمة ومحاولة إغراق السيرفر")

        if "SEQUENCE_ANOMALY" in raw_upper or "TEMPORAL" in raw_upper or "BILSTM" in raw_upper:
            detected_categories.append("انحراف تسلسلي متتابع")
        if "BOT" in raw_upper or "ABUSIVE_BOT" in raw_upper:
            detected_categories.append("نشاط بوتات أوتوماتيكية")
        if "GNN" in raw_upper or "MULTI_REQUEST" in raw_upper or "MULTI-REQUEST" in raw_upper:
            detected_categories.append("هجوم متعدد الطلبات")
        if "EXFILTRATION" in raw_upper or "LEAK" in raw_upper or "DLP" in raw_upper or "BUILTIN_" in raw_upper:
            if not any(k in " ".join(detected_categories) for k in ["بطاقات", "أرقام", "جوازات"]):
                detected_categories.append("محاولة تسريب بيانات")
        if "UNUSUAL_HOUR" in raw_upper or "OUTLIER" in raw_upper or "UBA" in raw_upper or "UEBA" in raw_upper:
            detected_categories.append("سلوك مشبوه في ساعات غير معتادة")
        if "BEACON" in raw_upper or "COBALTSTRIKE" in raw_upper:
            detected_categories.append("نشاط برمجية كوبالت سترايك")
        if "YARA" in raw_upper or "FLOWSPEC" in raw_upper:
            detected_categories.append("مطابقة قواعد الفحص الأمني")

        if detected_categories:
            unique_cats = list(dict.fromkeys(detected_categories))[:2]
            return " و ".join(unique_cats)

        # 3. Partial match in Arabic threat translation map
        for k, v in self.THREAT_TRANSLATIONS_AR.items():
            if len(k) <= 4:
                if re.search(r'\b' + re.escape(k) + r'\b', raw_lower):
                    return v
            else:
                if k in raw_lower:
                    return v

        # 4. Short clean string check (only return if no English letters remain)
        if not re.search(r'[a-zA-Z]', cleaned) and len(cleaned) < 50 and len(cleaned) > 1:
            return cleaned

        # 5. Guaranteed Fallback: Never leak English strings into Arabic speech
        return "نمط أمني مشبوه"

    def _normalize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes payload field names across all event sources for uniform phrase generation.
        Fixes field name mismatches (e.g. client_ip vs src_ip, username vs user, etc.).
        """
        p = dict(payload)
        if not p.get("src_ip") and p.get("client_ip"):
            p["src_ip"] = p["client_ip"]
        
        if not p.get("user"):
            p["user"] = p.get("username") or p.get("user_id") or ""

        if not p.get("module"):
            p["module"] = p.get("module_name") or p.get("node") or p.get("service") or p.get("source_module") or ""

        if not p.get("threat_type"):
            fam = p.get("family")
            if fam and isinstance(fam, str) and fam.strip().lower() != "unknown":
                p["threat_type"] = fam
            elif p.get("pattern_types") and isinstance(p.get("pattern_types"), (list, tuple)):
                p["threat_type"] = ", ".join(str(x) for x in p["pattern_types"] if x)

        return p

    def _clean_domain_for_tts(self, domain: str, lang: str) -> str:
        """Sanitizes domain names for clear speech rendering."""
        if not domain:
            return ""
        d = str(domain).strip().lower()
        if lang == "ar-SA":
            return d.replace(".", " دوت ")
        return d.replace(".", " dot ")

    def _resolve_threat_type(self, payload: Dict[str, Any], lang: str) -> str:
        """
        Resolve threat type description from multiple payload fields with sanitization.
        """
        # 1. Explicit threat_type if present
        explicit = payload.get("threat_type")
        if explicit and isinstance(explicit, str) and explicit.strip():
            return self._clean_threat_type(explicit, lang)

        # 2. Malware Family if present
        family = payload.get("family")
        if family and isinstance(family, str) and family.strip() and family.lower() != "unknown":
            return self._clean_threat_type(family, lang)

        # 3. pattern_types list (DLP payloads)
        pattern_types = payload.get("pattern_types")
        if pattern_types and isinstance(pattern_types, (list, tuple)) and pattern_types:
            clean_types = [self._clean_threat_type(str(t).strip(), lang) for t in pattern_types if t][:2]
            if clean_types:
                return ", ".join(clean_types) if lang != "ar-SA" else " و ".join(clean_types)

        # 4. Rich description or reason (e.g. SIEM / WAF / AI log messages)
        desc = payload.get("description") or payload.get("reason")
        if desc and str(desc).strip():
            return self._clean_threat_type(str(desc).strip(), lang)

        # 5. Fallback to event_type topic name
        event_tp = payload.get("event_type")
        if event_tp and str(event_tp).strip():
            return self._clean_threat_type(str(event_tp).strip(), lang)

        return "تهديد أمني" if lang == "ar-SA" else "Security threat"

    # ── Translation Dictionaries for Arabic Localization ────────────────────────
    COUNTRY_MAP_AR = {
        "external location": "موقع خارجي",
        "unknown": "موقع مجهول",
        "local": "شبكة محلية",
        "internal": "شبكة داخلية",
        "germany": "ألمانيا",
        "united states": "الولايات المتحدة",
        "usa": "الولايات المتحدة",
        "us": "الولايات المتحدة",
        "china": "الصين",
        "russia": "روسيا",
        "netherlands": "هولندا",
        "united kingdom": "المملكة المتحدة",
        "uk": "المملكة المتحدة",
        "france": "فرنسا",
        "japan": "اليابان",
        "canada": "كندا",
        "brazil": "البرازيل",
        "india": "الهند",
        "australia": "أستراليا",
        "singapore": "سنغافورة",
        "korea": "كوريا",
        "south korea": "كوريا الجنوبية",
        "turkey": "تركيا",
        "iran": "إيران",
        "saudi arabia": "المملكة العربية السعودية",
        "uae": "الإمارات العربية المتحدة",
        "yemen": "اليمن",
        "egypt": "مصر",
        "jordan": "الأردن",
        "iraq": "العراق",
    }

    MODULE_MAP_AR = {
        "malware_av": "محرك مكافحة البرمجيات الخبيثة",
        "malware av": "محرك مكافحة البرمجيات الخبيثة",
        "malware": "وحدة مكافحة البرمجيات الخبيثة",
        "av": "مكافح الفيروسات",
        "waf": "جدار حماية التطبيقات",
        "waf_engine": "جدار حماية التطبيقات",
        "dlp": "نظام منع تسريب البيانات",
        "dlp_inspector": "نظام منع تسريب البيانات",
        "ids": "نظام كشف التهديدات",
        "ips": "نظام منع الاختراق",
        "firewall": "جدار الحماية الرئيسي",
        "core": "مكون أمني أساسي",
        "email_security": "نظام أمان البريد الإلكتروني",
        "email": "نظام أمان البريد الإلكتروني",
        "dns_filter": "نظام تصفية النطاقات",
        "dns_security": "نظام حماية النطاقات",
        "AEGIS": "محرك الذكاء الاصطناعي التنبؤي",
        "predictive_ai": "محرك الذكاء الاصطناعي التنبؤي",
        "ueba": "محلل سلوك المستخدمين",
        "uba": "محلل السلوك التكيفي",
        "inspection_bridge": "جسر الفحص الأمني",
        "auto_block": "نظام الحظر التلقائي",
        "vpn": "شبكة الاتصال المشفرة",
        "correlation_engine": "محرك ربط الأحداث",
        "correlation": "محرك ربط الأحداث",
        "circuit_breaker": "نظام حماية الاستقرار",
        "ha": "نظام التوافر العالي",
        "pki": "نظام الشهادات الرقمية",
        "mtls": "نظام الشهادات الرقمية",
        "auth": "نظام توثيق المستخدمين",
        "siem": "نظام إدارة الحوادث والربط",
    }

    THREAT_TRANSLATIONS_AR = {
        "vip reverse proxy completed": "اكتمل التوجيه العكسي الفعلي",
        "vip reverse proxy": "توجيه عكسي للمواجهة",
        "reverse proxy completed": "اكتمل التوجيه العكسي",
        "reverse proxy": "خادم وكيل عكسي",
        "transparent proxy": "خادم وكيل شفاف",
        "async inspection completed": "اكتمل الفحص الموازي",
        "inspection completed": "اكتمل الفحص الأمني",
        "content match": "مطابقة محتوى حساس",
        "sender reputation issues": "مشكلة سمعة البريد المرسل",
        "no dkim signature": "غياب التوقيع الرقمي للبريد",
        "cobaltstrike beacon": "نشاط برمجية كوبالت سترايك",
        "cobaltstrike": "نشاط برمجية كوبالت سترايك",
        "yara match": "مطابقة قواعد يارا",
        "emergency override": "تجاوز طوارئ",
        "emergency isolate": "عزل طارئ",
        "fake patch": "تجميع تمويهي",
        "initial access": "اختراق أولي",
        "execution": "تنفيذ كود خبيث",
        "persistence": "تثبيت التهديد",
        "privilege escalation": "تصعيد الصلاحيات",
        "credential access": "سرقة بيانات الاعتماد",
        "lateral movement": "تحرك جانبي داخل الشبكة",
        "command and control": "اتصال بخادم التحكم",
        "c2": "اتصال بخادم التحكم",
        "exfiltration": "تسريب بيانات",
        "impact": "تأثير التهديد",
        "port scan probes": "مسح منافذ التوصيل",
        "port scan": "مسح منافذ",
        "brute force attack": "هجوم تخمين كلمات السر",
        "brute force": "تخمين كلمات المرور",
        "malware attack": "هجوم برمجيات خبيثة",
        "malware": "برمجيات خبيثة",
        "ransomware": "برمجية فدية خبيثة",
        "sqli": "حقن قواعد البيانات",
        "sql injection": "حقن قواعد البيانات",
        "xss": "برمجة عبر المواقع",
        "cross site scripting": "برمجة عبر المواقع",
        "phishing": "تصيد إلكتروني",
        "dns tunneling": "أنفاق تفقيد النطاق",
        # DLP Pattern categories
        "pci_credit_card": "بطاقات الائتمان",
        "pci": "بطاقات الائتمان",
        "credit_card": "بطاقات الائتمان",
        "ssn": "أرقام الضمان الاجتماعي",
        "iban": "الحسابات البنكية",
        "passport": "جوازات السفر",
        "medical": "سجلات طبية",
        "ip_address": "عناوين شبكية",
        "behavioral": "نمط سلوكي مشبوه",
        "befp anomaly detected": "شذوذ سلوكي مكتشف",
        # Malware Families
        "emotet": "برمجية إيموتيت الخبيثة",
        "trickbot": "برمجية تريك بوت الخبيثة",
        "wannacry": "برمجية وانا كراي الخبيثة",
        "agenttesla": "برمجية أيجنت تيسلا",
        "lockbit": "برمجية لوك بيت",
        "rat": "برمجية تحكم عن بعد",
        "trojan": "برمجية طروادة",
        # DNS & System Categories
        "dns_sinkhole": "إعادة توجيه نطاق خبيث",
        "dns_block": "حظر نطاق خبيث",
        "wireguard interface setup failed": "فشل إعداد نفق في بي إن",
        # AI & Defense Engine Tags
        "cpci": "مؤشر الخطورة المركب",
        "cpci emergency_override": "تجاوز طارئ للمراقبة",
        "ddts": "نظام التوجيه والدفاع الديناميكي",
        "AEGIS": "محرك الذكاء الاصطناعي التنبؤي",
        "die": "محرك المصائد التمويهية",
        "flowspec": "فحص وتصفية التدفق",
    }

    ACTION_MAP_AR = {
        "block": "الحظر",
        "blocked": "الحظر الفوري",
        "content_match": "الحظر لمنع التسريب",
        "monitor": "المراقبة",
        "monitored": "المراقبة النشطة",
        "quarantine": "العزل الفوري",
        "quarantined": "العزل الفوري",
        "alert": "التنبيه",
        "alerted": "إرسال تنبيه",
        "allow": "السماح",
        "allowed": "السماح",
        "drop": "الإسقاط",
        "dropped": "الإسقاط الفوري",
        "fake_patch": "التوزيع التمويهي",
        "emergency_isolate": "العزل الطارئ",
        "reset": "إعادة الضبط",
    }

    def _translate_country(self, raw: str, lang: str) -> str:
        if not raw:
            return "موقع خارجي" if lang == "ar-SA" else "External location"
        if lang != "ar-SA":
            return str(raw).strip()

        raw_clean = str(raw).strip().lower()
        if raw_clean in self.COUNTRY_MAP_AR:
            return self.COUNTRY_MAP_AR[raw_clean]

        # Only fall back to "موقع خارجي" if the string contains purely ASCII letters
        # (i.e. it's an untranslated English name, not an already-Arabic name)
        if re.search(r'^[a-zA-Z ]+$', str(raw).strip()):
            return "موقع خارجي"
        return str(raw).strip()

    def _translate_module(self, raw: str, lang: str) -> str:
        if not raw:
            return "مكون أمني" if lang == "ar-SA" else "Security Core"
        if lang != "ar-SA":
            return str(raw).strip()

        raw_clean = str(raw).strip().lower().replace("-", "_")
        if raw_clean in self.MODULE_MAP_AR:
            return self.MODULE_MAP_AR[raw_clean]

        for key, val in self.MODULE_MAP_AR.items():
            if key in raw_clean:
                return val

        if re.search(r'[a-zA-Z]', str(raw)):
            return "مكون أمني"
        return str(raw).strip()

    def _translate_action(self, raw: str, lang: str) -> str:
        if not raw:
            return "الحظر" if lang == "ar-SA" else "Blocked"
        if lang != "ar-SA":
            return str(raw).strip()

        raw_clean = str(raw).strip().lower()
        if raw_clean in self.ACTION_MAP_AR:
            return self.ACTION_MAP_AR[raw_clean]

        if re.search(r'[a-zA-Z]', str(raw)):
            return "الحظر"
        return str(raw).strip()

    # ── Level key lookup table (CONTRADICTION-05 fix) ────────────────────────
    # Python's map_severity_to_verbosity() returns: level1_critical, level2_high,
    # level3_medium, level4_low_info.
    # phrase_library.json uses:            level1_full, level2_short, level3_notice.
    # This mapping bridges the two naming conventions.
    _LEVEL_KEY_FALLBACK = {
        "level1_critical": ["level1_critical", "level1_full"],
        "level2_high":     ["level2_high",     "level2_short"],
        "level3_medium":   ["level3_medium",   "level3_notice"],
    }

    def _sanitize_arabic_text_for_tts(self, text: str) -> str:
        """
        Guarantees zero English word leakage when speech language is set to 'ar-SA'.
        Replaces technical acronyms with clean Arabic speech equivalents,
        and translates or cleans any leftover English terms.
        """
        if not text:
            return ""

        # Technical acronyms to Arabic speech equivalents
        acronyms = {
            r'\bWAF\b': 'واَف',
            r'\bDLP\b': 'دي إل بي',
            r'\bIDS\b': 'آي دي إس',
            r'\bIPS\b': 'آي بي إس',
            r'\bIP\b': 'آي بي',
            r'\bI P\b': 'آي بي',
            r'\bDNS\b': 'دي إن إس',
            r'\bVPN\b': 'في بي إن',
            r'\bURL\b': 'رابط',
            r'\bHTTP\b': 'إتش تي تي بي',
            r'\bHTTPS\b': 'إتش تي تي بي إس',
            r'\bSSL\b': 'إس إس إل',
            r'\bTLS\b': 'تي إل إس',
            r'\bAPI\b': 'إيه بي آي',
            r'\bCPU\b': 'المعالج',
            r'\bRAM\b': 'الذاكرة',
            r'\bHA\b': 'التوافر العالي',
            r'\bSIEM\b': 'سيم',
            r'\bPKI\b': 'نظام الشهادات',
            r'\badmin\b': 'أدمن',
            r'\broot\b': 'روت',
            r'\bsystem\b': 'النظام',
        }

        cleaned = text
        for pat, replacement in acronyms.items():
            cleaned = re.sub(pat, replacement, cleaned, flags=re.IGNORECASE)

        # If any remaining English words exist (e.g. "Internal Bank App", "failed"), replace or strip
        def _replace_word(m):
            w = m.group(0).lower()
            translations = {
                "internal": "داخلي", "bank": "بنكي", "app": "تطبيق",
                "server": "سيرفر", "client": "عميل", "failed": "فاشل",
                "success": "ناجح", "blocked": "محظور", "alerted": "منبه",
                "allowed": "مسموح", "denied": "مرفوض", "unknown": "مجهول",
                "host": "جهاز", "port": "منفذ", "service": "خدمة",
                "policy": "سياسة", "rule": "قاعدة", "event": "حدث",
            }
            return translations.get(w, "")

        cleaned = re.sub(r'\b[a-zA-Z]{2,}\b', _replace_word, cleaned)
        cleaned = re.sub(r'\s{2,}', ' ', cleaned).strip()
        return cleaned

    def generate_spoken_text(
        self,
        topic: str,
        payload: Dict[str, Any],
        verbosity_level: str = "level1_critical",
        language: Optional[str] = None
    ) -> Tuple[Optional[str], str]:
        """
        Generates final spoken text for a given event topic and payload.
        Returns (spoken_text, verbosity_level_used).
        Returns (None, "level4_low_info") if the verbosity level specifies silent speech.
        """
        lang = language or self.default_language

        if verbosity_level in ("level4_low_info", "silent_ui_only"):
            return None, "level4_low_info"

        # Normalize payload fields (client_ip->src_ip, username->user, etc.)
        payload = self._normalize_payload(payload)

        templates_root = self._phrase_data.get("templates", {})
        topic_entry = templates_root.get(topic) or templates_root.get("threat.detected", {})

        is_burst = payload.get("is_burst", False)
        if is_burst:
            template_key = "aggregated_burst"
        else:
            template_key = verbosity_level

        # FIX (CONTRADICTION-05): try all key aliases before falling back to level1_full
        level_templates: Dict[str, Any] = {}
        if is_burst:
            level_templates = topic_entry.get("aggregated_burst", {})
        else:
            for candidate_key in self._LEVEL_KEY_FALLBACK.get(verbosity_level, [verbosity_level]):
                found = topic_entry.get(candidate_key)
                if found:
                    level_templates = found
                    template_key = candidate_key
                    break

        # Final fallback: any available template (prefer detailed high/full over short summary)
        if not level_templates:
            for fallback in ("level1_full", "level1_critical", "level2_high", "level2_short", "level3_notice", "level3_medium"):
                found = topic_entry.get(fallback)
                if found:
                    level_templates = found
                    template_key = fallback
                    break

        if isinstance(level_templates, dict):
            template_text = (
                level_templates.get(lang)
                or level_templates.get("en-US")
                or level_templates.get("ar-SA")
            )
        else:
            template_text = None

        if not template_text:
            return None, "level4_low_info"

        # ── Resolve & Translate dynamic placeholders ─────────────────────────
        formatted_src_ip = self.format_ip_phonetic(payload.get("src_ip", ""), lang)
        formatted_dst_ip = self.format_ip_phonetic(payload.get("dst_ip", ""), lang)
        user_val        = self._resolve_user(payload, lang)
        risk_val        = self._resolve_risk_score(payload, lang)
        country_val     = self._translate_country(payload.get("country", ""), lang)
        module_val      = self._translate_module(
            payload.get("module") or payload.get("source_module") or "", lang
        )
        action_val      = self._translate_action(
            payload.get("action") or payload.get("action_taken") or "", lang
        )
        city_raw        = str(payload.get("city", "")).strip()

        # Clear English city names in Arabic mode to prevent English leakage
        city_val = "" if (lang == "ar-SA" and re.search(r'[a-zA-Z]', city_raw)) else city_raw

        fields = {
            "src_ip":         formatted_src_ip or ("عنوان مصدري" if lang == "ar-SA" else "source I P"),
            "dst_ip":         formatted_dst_ip or ("هدف داخلي"  if lang == "ar-SA" else "target server"),
            "country":        country_val,
            "city":           city_val,
            "module":         module_val,
            "action":         action_val,
            "threat_type":    self._resolve_threat_type(payload, lang),
            "risk_score":     risk_val,
            "user":           user_val,
            "count":          payload.get("burst_count") or payload.get("count", 1),
            "window_s":       payload.get("window_s", 30),
            "domain":         self._clean_domain_for_tts(payload.get("domain", ""), lang),
            "sender":         str(payload.get("sender", "")).strip(),
            "subject":        str(payload.get("subject", "")).strip(),
            "unique_ports":   payload.get("unique_ports", ""),
            "days_remaining": payload.get("days_remaining", ""),
        }

        try:
            # FIX (PHRASE-02): use safe format — extra keys in fields are ignored,
            # missing keys produce empty string instead of raising KeyError.
            spoken_text = _safe_format(template_text, fields)

            # Post-process cleanup of empty variables, hanging punctuation & awkward phrases
            spoken_text = re.sub(r'[\s،,]+مَ?دِ?ي?نَ?ةِ?\s*[\.,،]?', '', spoken_text)
            spoken_text = re.sub(r'city\s*[\.,,]?', '', spoken_text, flags=re.IGNORECASE)
            spoken_text = re.sub(r'\s+للمستخدم\s*\.?$', '.', spoken_text.strip())
            spoken_text = re.sub(r'\s+للمستخدم\s+', ' ', spoken_text)
            spoken_text = re.sub(r'\.\s*بمستوى (ثقة|خطورة)\s*\.?$', '.', spoken_text.strip())
            spoken_text = re.sub(r'\s+بمستوى (ثقة|خطورة)\s*\.?$', '.', spoken_text.strip())
            spoken_text = re.sub(r'\s+بمستوى (ثقة|خطورة)\s+\.\s*', '. ', spoken_text)
            spoken_text = re.sub(r'\s+بمستوى (ثقة|خطورة)\s+0%?\s*\.?', '.', spoken_text)
            spoken_text = re.sub(r'\s+with confidence\s*\.?$', '.', spoken_text.strip())
            spoken_text = re.sub(r'[\s،,]+\.\s*', '. ', spoken_text)
            spoken_text = re.sub(r'\s{2,}', ' ', spoken_text).strip()

            # Prevent any English word leakage in Arabic TTS mode
            if lang == "ar-SA":
                spoken_text = self._sanitize_arabic_text_for_tts(spoken_text)

            return spoken_text, template_key
        except Exception as e:
            logger.warning(f"[CVAS:PhraseEngine] Format error for template '{template_key}': {e}")
            return None, "level4_low_info"

    def get_supported_events(self) -> Dict[str, Any]:
        """Exposes raw phrase templates and event definitions for API."""
        return self._phrase_data.get("templates", {})

    def get_phrase_data(self) -> Dict[str, Any]:
        return self._phrase_data

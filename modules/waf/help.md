# دليل المطور لاستخدام وحدة الجدار الناري للتطبيقات (WAF Developer Guide)

هذا الملف يوفر توثيقاً شاملاً لكيفية استدعاء واستخدام وحدة الـ WAF (**Web Application Firewall**) في أي مكان داخل النظام بدون الحاجة لإعادة قراءة الكود المصدري.

---

## 1. نبذة عن الوحدة (Module Overview)

وحدة الـ **WAF** هي نظام حماية متكامل مكون من **10 طبقات أمنية** يعمل على فحص وتصفية حركة مرور شبكة الـ HTTP/HTTPS والتطبيقات وحمايتها من الهجمات المتقدمة (مثل SQLi, XSS, Command Injection, Prompt Injection, Bot Scraping, ATO, GraphQL Attacks).

### الطبقات الأساسية (10-Layer Architecture):
1. **L0: Preprocessor & Decoders**: فك ترميز المتعدد (URL, Base64, Hex, HTML, Unicode, SQL comments, XML/JSON).
2. **L1: Instant Defenses**: Honeypot Traps, Adaptive Rate Limiter, ATO Protector.
3. **L2: Client Fingerprinting**: فحص بصمة TLS (JA3) ومحاذاة ترتيب الـ Headers بـ (Needleman-Wunsch).
4. **L3: WAAP & Schema**: API Schema Validator & GraphQL Deep Inspector.
5. **L4: AI/ML Ensemble**: 
   - `NLP Model`: 1D-CNN + BiLSTM فحص الحمولة.
   - `GAF Model`: MiniLM Transformer لكشف حقن الأوامر للذكاء الاصطناعي (Prompt Injection).
   - `Bot Model`: XGBoost لكشف البوتات والمكاشط (Scrapers).
   - `GNN Session Model`: 2-Layer GCN لكشف هجمات الجلسة متعددة الخطوات (Session Graph).
   - `Temporal BiLSTM`: كشف هجمات APT البطيئة عبر الوقت (Stateful Session Tracker).
   - `Anomaly Engine`: قواعد كشف الشذوذ والتجاوز الفوري (Deterministic Overrides).
6. **L5: Threat Intelligence**: AbuseIPDB, Spamhaus, Feodo Tracker, OTX.
7. **L6: Decision Engine & XAI**: Risk Scoring Ensemble, Deception Canaries, SHAP-style XAI Explainer.

---

## 2. كيفية استدعاء الوحدة (Usage & Integration)

### 2.1 الاستدعاء المباشر عبر المحرك (Direct Inspector Usage)

يمكنك استدعاء فاحص الـ WAF مباشرة في أي كود Python كما يلي:

```python
from system.core.framework.plugin_base import InspectionContext
from modules.waf.engine.waf_inspector import WAFInspectorPlugin
from modules.waf.engine.core.settings import get_waf_settings

# 1. تحميل الإعدادات وتأسييس الفاحص (Singleton)
settings = get_waf_settings()
waf = WAFInspectorPlugin(settings=settings)

# 2. تجهيز سياق الطلب (InspectionContext)
context = InspectionContext(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    src_port=54321,
    dst_port=443,
    protocol="TCP",
    direction="inbound",
    flow_id="flow_12345",
    metadata={
        "request_path": "/api/v1/user/login",
        "request_method": "POST",
        "request_url": "/api/v1/user/login?ref=home",
        "query_string": "ref=home",
        "request_headers": {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "content-type": "application/json",
            "host": "example.com"
        },
        "session_id": "sess_user_99"
    }
)

# 3. تجهيز حمولة الطلب (Payload Bytes)
payload_data = b'{"username": "admin", "password": "\' OR 1=1 --"}'

# 4. تنفيذ الفحص
result = waf.inspect(context, data=payload_data)

# 5. اتخاذ القرار بناءً على النتيجة
if result.action.name == "BLOCK":
    print(f"🛑 [BLOCKED] Score: {result.metadata['risk_score']}")
    print(f"Reason: {result.metadata['xai_explanation']}")
elif result.action.name == "QUARANTINE":
    print("⚠️ [CHALLENGE] Required CAPTCHA validation")
else:
    print("✅ [ALLOWED] Request is safe")
```

---

## 3. مدخلات الوحدة (Input Contract)

تستقبل الوحدة عنصرين رئيسيين في الدالة `waf.inspect(context, data)`:

### أ) `context: InspectionContext`
كائن يحوي معلومات الطلب والشبكة:

| المتغير (Field) | النوع (Type) | الوصف | مثال |
| :--- | :--- | :--- | :--- |
| `src_ip` | `str` | عنوان IP للمرسل | `"192.168.1.50"` |
| `dst_ip` | `str` | عنوان IP للمستقبل | `"10.0.0.1"` |
| `src_port` | `int` | منفذ المصدر | `52140` |
| `dst_port` | `int` | منفذ الهدف | `443` |
| `direction` | `str` | اتجاه حركة المرور | `"inbound"` / `"outbound"` |
| `metadata` | `dict` | البيانات الوصفية للطلب (HTTP Headers, Method, Path, Session ID) | انظر أسفله |

#### أهم قيم الـ `metadata`:
- `request_path` (`str`): المسار بدون الخيارات (`/api/v1/users`).
- `request_method` (`str`): طريقة الطلب (`GET`, `POST`, `PUT`, `DELETE`).
- `request_url` (`str`): المسار الكامل شاملاً الـ Query String.
- `query_string` (`str`): الخيارات التابعة للمسار (`q=search&id=1`).
- `request_headers` (`dict`): ترويسات الـ HTTP (خافضة الأحرف Lowercase).
- `session_id` (`str`): معرف الجلسة (اختياري، وإن لم يتوفر يُستخدم `src_ip`).

### ب) `data: bytes`
- حمولة الطلب الخام (Raw Bytes) الخاصة بجسم الطلب (`HTTP Body`).
- في حال كان الطلب `GET` بدون Body، يمكن تمرير `b""`.

---

## 4. مخرجات الوحدة (Output Contract)

ترجع الدالة كائن من نوع `InspectionResult`:

```python
class InspectionResult:
    action: InspectionAction        # ALLOW / BLOCK / QUARANTINE
    findings: List[InspectionFinding]  # قائمة الملاحظات والأسباب المشبوهة
    processing_time_ms: float      # وقت الفحص بالملي ثانية
    metadata: dict                 # تفاصيل التقييم الرقمي ونماذج الذكاء الاصطناعي
```

### أ) أنواع الإجراءات (`InspectionAction`):
- `InspectionAction.ALLOW`: الطلب آمن تماماً وتتم إجازته.
- `InspectionAction.BLOCK`: الطلب خبيث ويجب حظره فوراً (إرجاع `HTTP 403` أو قطع الاتصال).
- `InspectionAction.QUARANTINE`: الطلب مشبوه ويحتاج تحدي (إرجاع `HTTP 429` أو `CAPTCHA`).

### ب) مخرجات الـ `metadata` التفصيلية:

| المفتاح (Key) | النوع (Type) | الوصف |
| :--- | :--- | :--- |
| `risk_score` | `float` | الدرجة النهائية للخطر من `0.0` (آمن) إلى `1.0` (خطر كلي) |
| `risk_decision` | `str` | القرار التفصيلي: `"allow"`, `"challenge"`, `"soft_block"`, `"block"` |
| `risk_breakdown` | `dict` | تفكيك الدرجة على النماذج (`nlp`, `gaf`, `bot`, `gnn`, `temporal`, `reputation`, `honeypot`) |
| `xai_explanation` | `str` | نص تعليلي بشري يشرح سبب القرار (مثل: `XAI Attribution: 45% NLP Payload Attack | 30% GAF`) |
| `latency_ms` | `float` | استغراق عملية الفحص بالملي ثانية |
| `waf_decoy_payload`| `dict` / `None` | فخاخ تم حقنها إذا تم تفعيل Deception Engine |

---

## 5. واجهات البرمجة والسيطرة (API Router Reference)

تتيح الوحدة التحكم الكامل عبر REST API على المسار `/api/v1/waf`:

### أهم المسارات:
- **`GET /api/v1/waf/status`**: الحصول على حالة الـ WAF والإحصائيات والخصائص المفعلة.
- **`GET /api/v1/waf/settings`**: لقطة كاملة لكافة الإعدادات.
- **`PUT /api/v1/waf/settings/master`**: المفتاح الرئيسي لتفعيل/تعطيل الـ WAF (`{"enabled": true/false}`).
- **`PUT /api/v1/waf/settings/mode`**: تغيير الوضع (`"enforce"`, `"monitor"`, `"learning"`).
- **`PUT /api/v1/waf/models/{model}/toggle`**: تفعيل/تعطيل نموذج معين (`nlp`, `gaf`, `bot`, `gnn`, `temporal`, `threat_intel`, `honeypot`, `rate_limiter`, `ato`).
- **`PUT /api/v1/waf/risk_thresholds`**: تعديل حدود الحظر والتحدي (`allow`, `challenge`, `block`).
- **`POST /api/v1/waf/ip/whitelist/add`**: إضافة IP للقائمة البيضاء.
- **`POST /api/v1/waf/ip/blacklist/add`**: إضافة IP للقائمة السوداء.
- **`WS /api/v1/waf/live`**: بث مباشر لأحداث الحظر والمخاطر عبر الـ WebSocket.

---

## 6. الأحداث والتكامل (Events System)

### الأحداث التي تنشرها الوحدة (Published Events):
- **`Topics.WAF_BLOCK` (`waf.block`)**: يُنشر فور حظر أي طلب خبيث.
- **`Topics.WAF_ALERT` (`waf.alert`)**: يُنشر عند اكتشاف نشاط مشبوه يتجاوز حد التنبيه.

### الأحداث التي تستمع لها الوحدة (Subscribed Events):
- **`Topics.THREAT_DETECTED` (`threat.detected`)**: تقوم الوحدة بحظر الـ IP القادم تلقائياً وإضافته للقائمة السوداء عند استلام هذا التنبيه من الوحدات الأخرى (مثل IDS/IPS أو Threat Intel).

---

## 7. أمثلة سريعة للمطورين (Quick Code Snippets)

### إضافة IP للقائمة البيضاء أثناء التشغيل:
```python
from modules.waf.engine.core.settings import get_waf_settings

cfg = get_waf_settings()
cfg.whitelist.ips.append("10.0.0.50")
cfg.save()  # حفظ دائم في waf.local.yaml
```

### تغيير وضع التشغيل لمراقبة فقط (Monitor Mode):
```python
cfg = get_waf_settings()
cfg.set_mode("monitor")  # لن يتم حظر أي طلب، يتم التسجيل فقط
```

---
**تاريخ آخر تحديث:** 2026-07-23  
**حالة الوحدة:** جاهزة للإنتاج (Production Ready v2.0.0)

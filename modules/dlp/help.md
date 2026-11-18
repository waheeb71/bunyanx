# دليل استخدام واستدعاء وحدة منع تسريب البيانات (DLP Module Integration Guide)

يقدم هذا الملف دليلاً كاملاً وشاملاً لأي مبرمج يرغب في استدعاء واستخدام وحدة **DLP (Data Loss Prevention)** في أي مكان داخل نظام Firewall enterprise بدون الحاجة لقراءة الكود المصدري للموديول.

---

## 1. نظرة عامة والمهام المفاهيمية (Overview)

وحدة DLP هي محرك هجين لمنع تسريب البيانات يتكون من 3 طبقات فحص رئيسية:
1. **الطبقة الأولى (Built-in Regex)**: كشف الأرقام الحساسة المحددة مسبقاً (بطاقات الائتمان CC، الهويات الوطنية SSN/National ID، الحسابات البنكية IBAN، مفاتيح API، والمفاتيح الخاصة PEM Keys).
2. **الطبقة الثانية (Custom Rules)**: فحص تعابير نمطية مخصصة (Custom Regex Rules) معرفة من قبل المدير عبر قاعدة البيانات.
3. **الطبقة الثالثة (BEFP + AI Layer)**: تحليل السلوك والإنتروبي (Behavioral Entropy Flow Profiling) + نموذج الذكاء الاصطناعي (Isolation Forest) لاكتشاف التسريب بطيء النمط (Low and Slow)، القنوات الخفية (Covert Channels مثل DNS Tunneling)، وأنماط C2 عبر 6 إشارات سلوكية + محرك Manifold 7D.

---

## 2. كيفية الاستدعاء السريع (Quick Start Code Snippets)

### أ) الاستدعاء عبر الفلتر العام (Inspection Pipeline Path)

إذا كنت تبني كوداً يمر في خط أنابيب الفحص العام (Proxy أو HTTP Inspection):

```python
from system.core.framework.plugin_base import InspectionContext
from modules.dlp.engine.dlp_inspector import DLPInspectorPlugin

# 1. إنشاء الكائن (Singleton/Plugin)
dlp_plugin = DLPInspectorPlugin()

# 2. تجهيز سياق الفحص (InspectionContext)
context = InspectionContext(
    src_ip="192.168.1.50",
    dst_ip="198.51.100.10",
    protocol="HTTP",
    direction="outbound",
    src_port=54321,
    dst_port=80,
    flow_id="flow_12345",
    timestamp=1700000000.0,
)

# 3. استدعاء الفحص على حمولة الطلب (Request Data Bytes)
payload_bytes = b"POST /upload HTTP/1.1\r\n... My Card is 4111-1111-1111-1111"
result = dlp_plugin.inspect(context, data=payload_bytes)

# 4. التعامل مع النتيجة (InspectionResult)
if result.action.name == "BLOCK":
    print("🚫 تم حظر الحركة! السبب:", result.findings[0].description)
elif result.action.name == "REDIRECT_DECOY":
    print("🪤 تم توجيه المهاجم لفخ الخداع (Data Deception Watermark)!")
```

---

### ب) فحص الاستجابات الخارِجة من السيرفر (Server Egress Response Path)

لحماية عدم خروج بيانات حساسة في استجابات HTTP/HTTPS القادمة من السيرفرات الداخلية للمستخدمين الخارجيين:

```python
from modules.dlp.engine.dlp_inspector import DLPInspectorPlugin

dlp_plugin = DLPInspectorPlugin()

# استدعاء فحص الاستجابة
result = dlp_plugin.inspect_response(
    raw_chunk=b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nUser SSN: 123-45-6789",
    src_ip="203.0.113.5",     # العميل المستقبل للبيانات
    dst_ip="192.168.1.10",    # السيرفر الداخلي المصدر
    src_port=44321,
    dst_port=443,
    protocol="HTTPS",
    url="https://internal.example.com/api/user",
    response_headers={"content-type": "text/plain"}
)

if result.action.name == "BLOCK":
    # يتم إنهاء الاتصال فورا وإرجاع رد حظر DLP HTTP 549
    print("🚫 تم منع خروج البيانات الحساسة عبر الاستجابة!")
```

---

### ج) الاستدعاء المباشر لمحرك DLP (Direct DLPEngine Call)

إذا كنت تحتاج فحص نص أو حمولة مباشرة بدون المرور عبر سياق الشبكة:

```python
from modules.dlp.engine.dlp_engine import DLPEngine

engine = DLPEngine()

# 1. فحص نصي مباشر (Layer 1 & 2 Regex)
text_findings = engine.evaluate(
    text_data="Here is my SSN: 123-45-6789 and card 4111-1111-1111-1111",
    src_ip="192.168.1.100",
    dst_ip="8.8.8.8",
    protocol="TCP"
)

for f in text_findings:
    print(f"Match: {f['rule_name']} | Severity: {f['severity']} | Details: {f['description']}")

# 2. فحص سلوكي مباشر (Layer 3 BEFP + AI)
raw_bytes = b"..."  # raw network bytes
befp_res, ai_res, behavioral_findings = engine.evaluate_behavioral(
    raw_payload=raw_bytes,
    src_ip="192.168.1.100",
    dst_ip="198.51.100.22",
    protocol="DNS",
    dst_port=53
)

if ai_res and ai_res.final_score >= 0.80:
    print(f"🚨 سلوك تسريب مشبوه عالي الخطورة! النتيجة النهائية: {ai_res.final_score}")
```

---

## 3. المدخلات والمخرجات التفصيلية (Input/Output Contract)

### الدالة `DLPInspectorPlugin.inspect(context, data)`
- **المدخلات (Inputs)**:
  - `context`: كائن `InspectionContext` يحتوي على (src_ip, dst_ip, protocol, direction, src_port, dst_port, metadata).
  - `data` (`bytes`): حمولة الطلب الحالية.
- **المخرجات (Outputs)**:
  - كائن `InspectionResult` يحتوي على:
    - `.action`: نوع `InspectionAction` من القيم (`ALLOW`, `ALERT`, `BLOCK`, `REDIRECT_DECOY`).
    - `.findings`: قائمة من كائنات `InspectionFinding`.

### الدالة `DLPInspectorPlugin.inspect_response(...)`
- **المدخلات (Inputs)**:
  - `raw_chunk` (`bytes`): جزء الاستجابة القادم من السيرفر.
  - `src_ip` (`str`): عنوان IP للعميل المستقبل.
  - `dst_ip` (`str`): عنوان IP للسيرفر المصدر.
  - `src_port` (`int`), `dst_port` (`int`), `protocol` (`str`), `url` (`str`), `response_headers` (`dict`).
- **المخرجات (Outputs)**:
  - كائن `InspectionResult` (`ALLOW` أو `BLOCK`).

### الدالة `DLPEngine.evaluate(...)`
- **المدخلات**: `(text_data: str, src_ip="", dst_ip="", dst_port=0, protocol="TCP")`
- **المخرجات**: `List[Dict]` يحتوي كل قاموس على:
  ```python
  {
      "rule_name": str,        # مثلا "BUILTIN_CREDIT_CARD" أو اسم قاعدة مخصصة
      "severity": str,         # "CRITICAL", "HIGH", "MEDIUM", "LOW"
      "description": str,      # وصف التطابق مع التمويه
      "match_count": int,      # عدد مرات التطابق
      "type": str,             # نوع البيانات الحساسة
  }
  ```

---

## 4. الهيكل البرمجي للكائنات الأساسية (Data Models Reference)

### كائن `InspectionFinding`
```python
finding.plugin_name     # "dlp_inspector"
finding.severity        # "CRITICAL", "HIGH", "MEDIUM", "LOW"
finding.category        # "DLP" / "DLP_BEHAVIORAL" / "DLP_RESPONSE"
finding.description     # النص الوصفي للحادثة
finding.confidence      # قيمة عائمة من 0.0 إلى 1.0 (مثلا 0.95)
finding.recommends_block# True / False
finding.metadata        # قاموس يحتوي تفاصيل النمط، ERS، ودرجة الذكاء الاصطناعي
```

### كائن `AIInferenceResult`
```python
ai_res.ai_anomaly_score # درجة شذوذ نموذج Isolation Forest (0.0 إلى 1.0)
ai_res.final_score      # الدرجة المدمجة (0.60 * ERS + 0.40 * AI_score)
ai_res.decision         # "NORMAL" / "SUSPICIOUS" / "HIGH_RISK" / "EXFILTRATION"
ai_res.model_available  # True إذا كان نموذج ML نشطاً
ai_res.explanation      # نص تفسيري معادلة القرار
```

---

## 5. نظام الأحداث المستقل (EventBus Integration)

عند اكتشاف أي حادثة تسريب، تطلق وحدة DLP حدثاً تلقائياً عبر `EventBus` تحت الموضوع `Topics.DLP_INCIDENT` (`dlp.incident`).

### كيفية الاشتراك في أحداث DLP من أي موديول آخر:

```python
from system.events.bus import EventBus
from system.events.topics import Topics

async def my_dlp_event_handler(payload: dict):
    print("RECEIVED DLP INCIDENT:")
    print(f"Event ID: {payload['event_id']}")
    print(f"Source IP: {payload['src_ip']} -> Dest IP: {payload['dst_ip']}")
    print(f"Decision: {payload['decision']} | Action: {payload['action']}")
    print(f"Final Score: {payload['final_score']}")

# تسجيل المستمع
bus = await EventBus.instance()
await bus.subscribe(Topics.DLP_INCIDENT, my_dlp_event_handler)
```

---

## 6. واجهات التحكم البرمجية (REST API Endpoints)

جميع الواجهات معرفة في المسار `/api/v1/dlp`:

| المسار (Endpoint) | Method | الصلاحية المطلوب | الهدف |
| :--- | :---: | :---: | :--- |
| `/api/v1/dlp/status` | `GET` | `require_dlp` | قراءة حالة وتفعيل وحدة DLP |
| `/api/v1/dlp/config` | `GET` | `require_dlp` | قراءة الإعدادات الحالية |
| `/api/v1/dlp/config` | `PUT` | `require_admin` | تحديث الإعدادات وإعادة تحميل المحرك |
| `/api/v1/dlp/rules` | `GET` | `require_dlp` | عرض القواعد المخصصة |
| `/api/v1/dlp/rules` | `POST` | `require_admin` | إضافة قاعدة نمطية مخصصة جديدة |
| `/api/v1/dlp/rules/{id}` | `DELETE` | `require_admin` | حذف قاعدة مخصصة برقمها |
| `/api/v1/dlp/behavioral/profile/{ip}` | `GET` | `require_dlp` | قراءة البروفايل السلوكي لعنوان IP |
| `/api/v1/dlp/behavioral/high-risk` | `GET` | `require_dlp` | عرض قائمة العناوين ذات الاستهلاك التراكمي العالي |
| `/api/v1/dlp/behavioral/optimize-weights` | `POST` | `require_admin` | إطلاق تحسين أوزان الإشارات تلقائياً |
| `/api/v1/dlp/audit` | `GET` | `require_admin` | قراءة السجل الأمني الموثق والمشفر (HMAC Audit Trail) |

---
*تم إعداد هذا الملف لتسهيل التكامل البرمجي الفوري ومنع إعادة قراءة الكود المصدري.*

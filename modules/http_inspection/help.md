# دليل المطور لاستخدام وحدة فحص بروتوكول HTTP (`http_inspection`)
# HTTP Inspection Module — Developer & Integration Guide

---

## 📌 1. مقدمة عن الوحدة (Module Overview)

وحدة `http_inspection` هي محرك فحص عميق للبيانات (Deep Packet Inspection / WAF) مخصص لبروتوكول HTTP/HTTPS في نظام BunyanX NGFW v2.0.
تعد الوحدة مسؤولة عن تحليل حركة المرور غير المشفرة (أو المفكوكة عبر Proxy شفافة)، واكتشاف الهجمات (مثل SQL Injection, XSS, Path Traversal, Dangerous Methods)، وفرض قيود على أحجام المرفقات، وإرسال تنبيهات أمنية فورية إلى نظام الأحداث (EventBus) وذكاء الاصطناعي (AI Telemetry).

---

## 🚀 2. استدعاء الوحدة واستخدامها (Import & Usage)

### الاستدعاء المباشر (Direct Import)
يمكنك استدعاء فئة الفاحص الرئيسة `HTTPInspector` مباشرة من أي مكان داخل المشروع:

```python
from modules.http_inspection import HTTPInspector
from system.core.framework import InspectionContext, InspectionAction
```

---

## 📥 3. ماذا تستقبل الوحدة؟ (Input Contract)

تعتمد الوحدة على دالّتين رئيسيتين:

### أ) `can_inspect(context: InspectionContext) -> bool`
تتحقق مما إذا كانت الحزمة تعود لبروتوكول HTTP/HTTPS وموجهة لمنافذ مدعومة.

- **المدخلات (Parameters)**:
  - `context` (فئة `InspectionContext`): تحتوي على بيانات سياق الاتصال الشبكي.

- **الحقول المطلوبة في `context`**:
  | الحقل (Field) | النوع (Type) | الوصف (Description) | مثال (Example) |
  | :--- | :--- | :--- | :--- |
  | `protocol` | `str` | بروتوكول الطبقة الرابع (TCP, TCP/TLS, HTTP) | `"TCP"` أو `"TCP/TLS"` |
  | `dst_port` | `int` | منفذ الهدف | `80`, `443`, `8080`, `8443`, `3000`, `5000` |
  | `src_port` | `int` | منفذ المصدر | `54321` |

- **المخرجات (Return Value)**:
  - `bool`: ترجع `True` إذا كان الاتصال يجب فحصه بواسطة هذه الوحدة، و `False` إذا كان يجب تجاهله.

---

### ب) `inspect(context: InspectionContext, data: bytes) -> InspectionResult`
تنفّذ عملية الفحص الفعلي للبيانات الممررة.

- **المدخلات (Parameters)**:
  1. `context` (`InspectionContext`): سياق الاتصال بالكامل.
     - `flow_id` (`str`): معرف الاتصال التتبعي.
     - `src_ip` (`str`): عنوان IP للمرسل.
     - `dst_ip` (`str`): عنوان IP للمستقبل.
     - `src_port` (`int`): منفذ المصدر.
     - `dst_port` (`int`): منفذ الهدف.
     - `timestamp` (`float`): الوقت الزمني لاتخاذ القرار.
  2. `data` (`bytes`): الحمولة الخام لاتصال HTTP (Request أو Response).

---

## 📤 4. ماذا ترجع الوحدة؟ (Output Contract)

ترجع الدالة كائنًا من نوع `InspectionResult` يحتوي على التفاصيل التالية:

```python
result = inspector.inspect(context, data)
```

### هيكل الكائن `InspectionResult`:

| الحقل (Field) | النوع (Type) | الوصف (Description) |
| :--- | :--- | :--- |
| `result.action` | `InspectionAction` | القرار النهائي للاتصال (`ALLOW`, `BLOCK`, `LOG_ONLY`) |
| `result.findings` | `List[InspectionFinding]` | قائمة تحتوي على كافة الانتهاكات المكتشفة |
| `result.metadata` | `Dict[str, Any]` | البيانات التحليلية المجمعة (تحتوي على مفتاح `'http'`) |

#### أ) قيم القرار (`InspectionAction` Enum):
- `InspectionAction.ALLOW`: الطلب آمن وسليم، يُسمح بمروره.
- `InspectionAction.BLOCK`: الطلب خبيث أو ينتهك السياسات، يجب حظره وإسقاط الحزمة.
- `InspectionAction.LOG_ONLY`: الوحدة تعمل في وضع المراقبة (`monitor`)؛ تم اكتشاف هجوم ولكن يُسمح بمروره مع تسجيل التنبيه.

#### ب) تفاصيل الانتهاك (`InspectionFinding`):
إذا تم اكتشاف هجوم، تحتوي القائمة `result.findings` على كائنات بالحقول التالية:
- `category` (`str`): تصنيف الهجوم (`http_url`, `http_header`, `http_body`, `http_method`, `http_upload`, `http_size_overflow`, `inspection_failure`).
- `severity` (`str`): خطورة التهديد (`HIGH`, `MEDIUM`, `LOW`).
- `description` (`str`): وصف تفصيلي للسبب.
- `confidence` (`float`): نسبة اليقين من الاكتشاف (مثلاً `1.0` أو `0.95`).
- `evidence` (`dict`): أدلة الاكتشاف الآمنة (بدون بيانات حساسة).

#### ج) البيانات المحللة (`result.metadata['http']`):
قاموس يحتوي على تفاصيل طلب/استجابة HTTP المحللة:
```python
{
    "type": "request",               # أو "response"
    "method": "GET",                 # GET, POST, PUT, DELETE, etc.
    "url": "/search?q=test",         # المسار المطلوب
    "version": "HTTP/1.1",           # نسخة البروتوكول
    "headers": {                     # القواميس المحللة للترويسات
        "host": "example.com",
        "user-agent": "Mozilla/5.0..."
    },
    "body": "...",                   # نص الحمولة المفكوك (إن وجد)
    "content_type": "text/html",     # نوع المحتوى
    "content_length": 1024           # حجم المحتوى
}
```

---

## 💻 5. أمثلة برمجية كود كاملة (Code Examples)

### مثال 1: فحص طلب HTTP عادي (Standard HTTP Inspection)
```python
from modules.http_inspection import HTTPInspector
from system.core.framework import InspectionContext, InspectionAction

# 1. إنشاء كائن الفاحص
inspector = HTTPInspector()

# 2. إعداد سياق الاتصال
context = InspectionContext(
    flow_id="flow-xyz-123",
    src_ip="192.168.1.50",
    dst_ip="10.0.0.100",
    src_port=49152,
    dst_port=80,
    protocol="TCP",
    direction="inbound",
    timestamp=1700000000.0,
    metadata={}
)

# 3. محاكاة حمولة طلب HTTP خبيث (SQL Injection)
payload = b"GET /search?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: example.com\r\n\r\n"

# 4. التثبت من إمكانية الفحص وتنفيذه
if inspector.can_inspect(context):
    result = inspector.inspect(context, payload)
    
    if result.action == InspectionAction.BLOCK:
        print("🚨 تم حظر الطلب الخبيث!")
        for finding in result.findings:
            print(f" - الفئة: {finding.category} | الخطورة: {finding.severity}")
            print(f" - الوصف: {finding.description}")
            print(f" - الأدلة: {finding.evidence}")
    else:
        print("✅ الطلب آمن مسموح بمروره.")
```

---

### مثال 2: الإغلاق السليم للوحدة (Clean Shutdown)
عند إنهاء الخدمة أو إيقاف تشغيل الخادم، تأكد من استدعاء `stop()` لإغلاق خيوط الخلفية الخاصة بحفظ السجلات بشكل سليم:

```python
inspector.stop()
```

---

## 🌐 6. واجهات التحكم البرمجية (REST API Endpoints)

الوحدة توفر واجهة برمجية FastAPI للتحكم الكامل في الإعدادات والأنماط والسجلات عبر المسار:
`/api/v1/http_inspection`

| المسار (Endpoint) | الطريقة (Method) | الصلاحية (Auth) | الوصف |
| :--- | :---: | :--- | :--- |
| `/status` | `GET` | `require_http` | جلب حالة الوحدة التشغيلية |
| `/config` | `GET` | `require_http` | قراءة إعدادات الفحص الحالية |
| `/config` | `PUT` | `require_admin` | تعديل إعدادات الفحص (تفعيل/إيقاف، وضع enforce/monitor، حد Upload) |
| `/patterns` | `GET` | `require_http` | عرض قواعد وقوالب الفحص (Regex patterns) مع دعم Pagination |
| `/patterns` | `POST` | `require_admin` | إضافة قاعدة فحص جديدة (URL, Header, Body) |
| `/patterns/{id}` | `PUT` | `require_admin` | تعديل قاعدة فحص موجودة |
| `/patterns/{id}` | `DELETE` | `require_admin` | حذف قاعدة فحص |
| `/logs` | `GET` | `require_http` | استرجاع أحدث سجلات الهجمات المحظورة |

---

## 🛡️ 7. ملاحظات أمنية وأفضل الممارسات (Security & Best Practices)

1. **حماية PII والبيانات الحساسة**:
   - لا يتم تخزين الترويسات الحساسة (مثل `User-Agent`) أو محتويات الجسد (Body) كنصوص صريحة في قواعد البيانات.
   - يتم تخزين تجزئة SHA-256 في الحقل `user_agent_hash` و `value_hash` لضمان عدم تسريب البيانات الشخصية.
2. **الحماية من تعبيرات ReDoS الخبيثة**:
   - المحرك يرفض تلقائياً أي Regex يحتوي على تعبيرات تكرار متداخلة.
   - يتم تنفيذ الفحص بحد أقصى 100 ملي ثانية (100ms timeout) لكل فحص لضمان عدم استهلاك المعالج.
3. **الحظر الفوري عند الخطأ (Fail-Closed)**:
   - في حال حدوث أي خطأ غير متوقع أثناء فحص البيانات، تقوم الوحدة بحظر الحزمة تلقائياً لمنع أي محاولة تجاوز (Bypass).

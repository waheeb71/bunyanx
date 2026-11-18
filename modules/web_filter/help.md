# دليل المبرمج لوحدة تصفية الويب (Web Filter Developer Manual)

يقدم هذا المستند دليلاً تقنياً شاملاً لكيفية استدعاء واستخدام وحدة تصفية الويب (`web_filter`) في أي مكان داخل مشروع **Enterprise BunyanX NGFW** دون الحاجة لإعادة قراءة الكود المصدري.

---

## 1. نظرة عامة (Overview)

وحدة `web_filter` هي وحدة فحص وتحليل هجينة تعمل على طبقة التطبيقات (Layer 7) لتصفية حركة مرور الويب (HTTP و HTTPS) وتوجيه استعلامات محركات البحث وتعيين إجراءات الفلترة في الوقت الحقيقي (Real-Time).

تعتمد الوحدة على **5 مستويات فحص أساسية**:
1. **LRU+TTL Cache**: ذاكرة مخبئية سريعة في الذاكرة العشوائية لحفظ نتائج الفحص لـ 50,000 نطاق لـ 300 ثانية.
2. **Exact Domain Match**: مطابقة حرفية صريحة للنطاقات المحظورة أو المسموحة من قاعدة البيانات.
3. **Parent Suffix Match**: مطابقة النطاق الأب تدريجياً (مثل `ads.evil.com` -> `evil.com`).
4. **Wildcard / Glob Match**: مطابقة أنماط الرموز العامة (مثل `*.evil.com`).
5. **HoloFilter AI Engine**: محرك ذكاء اصطناعي فائق الأبعاد (Hyperdimensional Computing - HDC) مكون من 10,048 بُعداً لكشف نطاقات الـ DGA والتصيد الاحتيالي (Phishing) والروابط العشوائية الصفرية (Zero-Day) محلياً.

---

## 2. كيفية الاستدعاء والتشغيل (How to Import & Use)

يمكن استدعاء الوحدة بثلاث طرق حسب سياق الاستخدام في النظام:

### الطريقة الأولى: الفحص المباشر كـ InspectorPlugin (الأكثر شيوعاً في خط الفحص)

```python
from modules.web_filter.engine.plugin import WebFilterPlugin
from system.core.framework.plugin_base import InspectionContext

# 1. إنشاء كائن الفحص (Priority = HIGH / 25)
plugin = WebFilterPlugin(block_on_match=True)

# 2. إنشاء سياق الفحص (InspectionContext)
context = InspectionContext(
    src_ip="192.168.1.100",
    dst_ip="198.51.100.1",
    src_port=54321,
    dst_port=443,       # 80 / 443 / 8080 / 8443 / 3128
    protocol="HTTPS"
)
context.tls.sni = "malware.wicar.org"

# 3. تنفيذ الفحص
result = plugin.inspect(context, data=b"")

# 4. التعامل مع النتيجة
print(f"Action: {result.action}")           # InspectionAction.ALLOW / BLOCK / LOG_ONLY
print(f"Findings Count: {len(result.findings)}")
if result.metadata.get("rewrite_url"):
    print(f"SafeSearch Rewrite: {result.metadata['rewrite_url']}")
```

---

### الطريقة الثانية: الاستدعاء المباشر للمحرك (WebFilterEngine)

```python
from modules.web_filter.policy.engine import WebFilterEngine
from system.policy.schema import Action

# WebFilterEngine هو Singleton يتم تحميله مرة واحدة
engine = WebFilterEngine()

# تقييم نطاق ورابط مباشر
action, modified_url = engine.evaluate(
    url="https://www.google.com/search?q=test", 
    domain="google.com"
)

# Decision Output:
# action: Action.ALLOW / Action.BLOCK / Action.REJECT / Action.MONITOR
# modified_url: رابط البحث الآمن المعدل إذا تنشط SafeSearch (أو None)
if action == Action.BLOCK:
    print("الطلب محظور!")
elif modified_url:
    print(f"تم تعديل الرابط إلى: {modified_url}")
```

---

### الطريقة الثالثة: عبر نظام الوحدات (BaseModule & ServiceContainer)

```python
from modules.web_filter.module import WebFilterModule
from system.core.service_container import ServiceContainer

container = ServiceContainer()
module = WebFilterModule()

# تهيئة الوحدة وتسجيل المحرك في PolicyManager
await module.initialize(container)

# الحصول على كائن الفحص Plugin
plugin = module.get_inspector_plugin()

# الحصول على الخدمات المقدمة
services = module.get_provided_services()
web_engine = services.get('web_engine')
```

---

## 3. عقود البيانات (Input / Output Contracts)

### مدخلات الفحص (Inputs)

#### 1. دالة `plugin.inspect(context, data)`:
- **`context` (`InspectionContext`)**:
  - `src_ip` (`str`): عنوان IP الخاص بالمستخدم.
  - `dst_ip` (`str`): عنوان IP الوجهة.
  - `dst_port` (`int`): المنفذ (80, 443, 8080, 8443, 3128).
  - `protocol` (`str`): البروتوكول ("HTTP" أو "HTTPS").
  - `http.url` / `http.host` / `tls.sni` (`str`): اسم النطاق أو الرابط المراد فخارها.
- **`data` (`bytes`)**:
  - نص حزمة HTTP الخام (يتم استخراج ترويسة `Host:` منها تلقائياً في حال عدم توفر النطاق في السياق).

#### 2. دالة `engine.evaluate(url, domain)`:
- **`url` (`str` أو `PolicyContext`)**: رابط الموقع الفعلي المراد تقييمه.
- **`domain` (`str`)**: اسم النطاق المعالج (مثل `malware.wicar.org`).

---

### مخرجات الفحص (Outputs)

#### 1. كائن `InspectionResult` الصادر عن `plugin.inspect()`:

```python
result.action       # InspectionAction.ALLOW | InspectionAction.BLOCK | InspectionAction.LOG_ONLY
result.findings     # قائمة بكائنات InspectionFinding لكل تهديد محظور أو مراقب
result.metadata     # قاموس البيانات الإضافية للتنفيذ
```

##### تفاصيل القاموس `result.metadata`:

| المفتاح (Key) | النوع (Type) | الوصف |
| :--- | :--- | :--- |
| `rewrite_url` | `str` | رابط البحث الآمن الجديد بعد إضافة معامل `safe=active` (إن وجد). |
| `proxy_action` | `str` | الإجراء المطلوب من البروكسي (`"rewrite"` عند إعادة كتابة الرابط). |

#### 2. كائنات `InspectionFinding` داخل `result.findings`:

```python
finding.plugin_name     # "web_filter"
finding.severity        # "HIGH" (في الحظر) أو "INFO" (في المراقبة/SafeSearch)
finding.category        # "WEB_FILTER" أو "SAFE_SEARCH"
finding.description     # وصف سبب القرار والتصنيف الذي تسبب بالحظر
finding.confidence      # نسبة الثقة (مثلاً 0.95)
finding.recommends_block# True / False
```

---

## 4. قائمة التصنيفات المدمجة والـ AI (Built-in Categories)

| اسم التصنيف (Category Name) | الإجراء الافتراضي | درجة الخطورة (0-100) | الوصف |
| :--- | :--- | :--- | :--- |
| `malware` | `BLOCK` | 100 | مواقع توزيع البرمجيات الخبيثة المكتشفة |
| `phishing` | `BLOCK` | 100 | مواقع التصيد الاحتيالي وسرقة البيانات |
| `botnet` | `BLOCK` | 100 | شبكات البوتنت والأجهزة المصابة |
| `ransomware` | `BLOCK` | 100 | مواقع دفع وتوزيع برمجيات الفدية |
| `c2` | `BLOCK` | 100 | خوادم القيادة والسيطرة (Command & Control) |
| `adult` | `BLOCK` | 80 | المحتوى المخصص للبالغين |
| `gambling` | `BLOCK` | 70 | مواقع المقامرة والمراهنات |
| `social_media` | `MONITOR` | 30 | شبكات التواصل الاجتماعي (تسجيل دون حظر) |
| `streaming` | `MONITOR` | 20 | منصات البث المباشر والصوتيات |
| `news` | `ALLOW` | 10 | مواقع الأخبار والإعلام |
| `education` | `ALLOW` | 5 | المحتوى التعليمي والأكاديمي |
| `finance` | `ALLOW` | 5 | الخدمات المالية والبسط المصرفية |
| `AI_BLOCK` | `BLOCK` | 85 | النطاقات المحظورة بناءً على نموذج HoloFilter HDC |
| `UNRATED` | `ALLOW` | 0 | النطاقات غير المصنفة التي اجتازت فحص الـ AI |

---

## 5. واجهة برمجة التطبيقات REST API

تتاح جميع خدمات الوحدة عبر النقطة المركزية `/api/v1/web_filter`:

* **`GET /status`**: استعلام حالة المحرك، عدد النطاقات والتصنيفات، وحالة الـ ML.
* **`GET /config`**: جلب التكوين الحالي.
* **`PUT /config`**: تحديث إعدادات التكوين (باستخدام `ConfigUpdateSchema`).
* **`GET /categories`**: عرض جميع التصنيفات.
* **`POST /categories`**: إنشاء تصنيف مخصص جديد (`CategoryCreateSchema`).
* **`PUT /categories/{cat_id}`**: تحديث تصنيف موجود.
* **`DELETE /categories/{cat_id}`**: حذف تصنيف مخصص (يمنع حذف التصنيفات الأساسية).
* **`GET /domains`**: عرض جميع قواعد النطاقات الاستثنائية.
* **`POST /domains`**: إضافة قاعدة نطاق جديدة (`DomainCreateSchema`).
* **`DELETE /domains/{domain_id}`**: حذف قاعدة نطاق.
* **`POST /train`**: إطلاق مهمة تدريب نموذج الذكاء الاصطناعي في الخلفية.
* **`GET /train/status`**: متابعة حالة تدريب النموذج (Idle / Running / Completed / Failed).

---

## 6. أحداث الناقل (Event Bus Integration)

عند حظر أي نطاق مشبوه، تنشر الوحدة حدثاً تلقائياً عبر ناقل الأحداث المركزية (`EventBus`):

- **الموضوع (Topic):** `Topics.WEB_FILTER_BLOCK` (`"web_filter.block"`)
- **حمولات الحدث (Payload Standard):**
```json
{
  "event_id": "evt-8f4b2a1c-9d3e-4f5a-8b2c-123456789abc",
  "timestamp": "2026-07-23T04:00:00Z",
  "module": "web_filter",
  "event_type": "web_filter.block",
  "severity": "HIGH",
  "confidence": 0.95,
  "domain": "malware.wicar.org",
  "src_ip": "192.168.1.100",
  "dst_ip": "198.51.100.1",
  "action": "BLOCK",
  "target": "http://malware.wicar.org/",
  "category": "WEB_FILTER"
}
```

---

## 7. مثال برمجي كامل ومستقل (Complete Runnable Example)

```python
from modules.web_filter.engine.plugin import WebFilterPlugin
from system.core.framework.plugin_base import InspectionContext, InspectionAction

def test_web_filter_pipeline():
    # 1. تهيئة بلجن الفحص
    plugin = WebFilterPlugin(block_on_match=True)
    
    # 2. تجهيز سياق فحص لموقع ضار
    ctx_malware = InspectionContext(
        src_ip="192.168.1.150",
        dst_ip="198.51.100.5",
        dst_port=80,
        protocol="HTTP"
    )
    ctx_malware.http.host = "malware.wicar.org"
    ctx_malware.http.url = "http://malware.wicar.org/payload.exe"
    
    # 3. تنفيذ الفحص
    res_malware = plugin.inspect(ctx_malware)
    print(f"=== Malware Domain Test ===")
    print(f"Action: {res_malware.action.name}")  # BLOCK
    for f in res_malware.findings:
        print(f"Finding: [{f.severity}] {f.description}")
        
    # 4. تجهيز سياق فحص لمحرك بحث (SafeSearch)
    ctx_google = InspectionContext(
        src_ip="192.168.1.150",
        dst_ip="142.250.190.46",
        dst_port=443,
        protocol="HTTPS"
    )
    ctx_google.tls.sni = "google.com"
    
    res_google = plugin.inspect(ctx_google)
    print(f"\n=== Google Search Test ===")
    print(f"Action: {res_google.action.name}")    # ALLOW
    print(f"Rewritten URL: {res_google.metadata.get('rewrite_url')}")

if __name__ == "__main__":
    test_web_filter_pipeline()
```

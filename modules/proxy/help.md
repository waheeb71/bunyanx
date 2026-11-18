# دليل المبرمج لاستدعاء واستخدام وحدة البروكسي (`proxy`)
**Enterprise BunyanX NGFW v2.5 — Developer Integration & API Manual**

هذا المستند يُعد المرجع الشامل الكامل لأي مبرمج يرغب في استدعاء واستخدام وحدة **البروكسي (`proxy`)** في أي مكان داخل منظومة BunyanX Enterprise NGFW دون الحاجة لإعادة قراءة الكود المصدري للوحدة.

---

## 1. نظرة عامة والمعمارية (Module Overview & Architecture)

وحدة `proxy` هي بوابة اعتراض وتوجيه حركة مرور الشبكة المركزية (Network Gateway) في الجدار الناري Enterprise NGFW.
تتميز الوحدة بدعم **3 أنماط تشغيل رئيسية** بالإضافة إلى اعتراض التشفير عميق البنية (SSL/TLS MITM):

1. **البروكسي الشفاف (Transparent Proxy)**:
   - يتقاطع مع حركة المرور تلقائياً دون أي إعدادات على أجهزة العملاء عبر قواعد `nftables` وسحب الهدف الأصلي بواسطة `SO_ORIGINAL_DST`.
   - المنافذ الافتراضية: `8080` لـ HTTP، و `8443` لـ HTTPS (مع فحص `SNI Peek`).
2. **البروكسي الصريح (Explicit / Forward Proxy)**:
   - يتم ضبطه صراحة في متصفحات الأجهزة أو الأنظمة.
   - يعالج طلبات `CONNECT` لإنشاء أنفاق HTTPS مشفرة وفحصها بـ MITM، ودعم ملفات التهيئة التلقائية (`PAC` / `WPAD`).
   - المنفذ الافتراضي: `3128`.
3. **البروكسي العكسي (Reverse Proxy)**:
   - يحمي السيرفرات والتطبيقات الداخلية ويقوم بإنهاء تشفير SSL (SSL Termination) وتوزيع الأحمال (Least-Connections Load Balancing) وحماية الـ VIPs.
   - المنافذ الافتراضية: `80` و `443`.
4. **جسر الفحص الموحد (InspectionBridge)**:
   - يربط البروكسي بخط الفحص الأمني المركزي `InspectionPipeline` لتشغيل موديولات الجدار الناري، WAF، DLP، WebFilter، و Malware AV على التدفقات المفحوصة.

---

## 2. طرق استدعاء الوحدة في الكود (How to Import & Use)

توجد 3 طرق رئيسية لاستدعاء واستخدام الوحدة حسب سياق الاستخدام:

### الطريقة الأولى: عبر نظام الموديولات وحاوية الخدمات (`ServiceContainer`) — [الموصى بها]

عند إقلاع الجدار الناري، يتم تسجيل الوحدة تلقائياً كـ `BaseModule` تحت اسم `proxy`:

```python
from system.core.service_container import ServiceContainer

# 1. الحصول على حاوية الخدمات
container = ServiceContainer.instance()

# 2. جلب محرك البروكسي الشفاف أو الصريح أو العكسي
transparent_proxy = container.get_optional('transparent_proxy')
forward_proxy     = container.get_optional('forward_proxy')
reverse_proxy     = container.get_optional('reverse_proxy')

# 3. قراءة الإحصائيات المباشرة
if transparent_proxy:
    stats = transparent_proxy.get_statistics()
    print("إحصائيات البروكسي الشفاف:", stats)
    # {'total_connections': 1250, 'active_connections': 14, 'bytes_sent': 5242880, 'bytes_received': 10485760}
```

---

### الطريقة الثانية: الاستدعاء المباشر عبر `ContextBuilder` و `InspectionBridge`

تُستخدم إذا كنت تبني محرك بروكسي أو موديول معالجة تدفقات شبكية وتريد استخدام أدوات بناء السياق وفحص الحزم الموحدة للبروكسي:

```python
import asyncio
from modules.proxy.engine.context_builder import ContextBuilder
from modules.proxy.engine.inspection_bridge import InspectionBridge
from system.core.framework.pipeline import InspectionPipeline

# 1. إنشاء محرك بناء السياق وجسر الفحص
config = {"network": {"internal_networks": ["10.0.0.0/8", "192.168.0.0/16"]}}
builder = ContextBuilder(config)
bridge  = InspectionBridge(pipeline=InspectionPipeline.get_instance(), fail_open=True)

# 2. بناء سياق الحزمة الشبكية (InspectionContext)
context = builder.build_network_context(
    client_addr=("192.168.1.50", 54321),
    target_host="example.com",
    target_port=443,
    protocol="HTTPS",
    direction="outbound"
)

# 3. إثراء السياق ببيانات TLS والتشفير
builder.enrich_tls(context, sni="example.com", version="TLSv1.3", is_decrypted=True)

# 4. إثراء السياق ببيانات حمولة HTTP المفكوكة
payload_bytes = b"POST /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n{\"key\": \"val\"}"
builder.enrich_http(context, payload_bytes, scheme="https")

# 5. تشغيل الفحص الموحد عبر الجسر
async def run_check():
    result = await bridge.check(context)
    if result.is_blocked:
        print("🚫 تم حظر الحركة عبر البروكسي! السبب:", result.findings[0].description)
    else:
        print("✅ الحركة آمنة ومسموح بمرورها.")

asyncio.run(run_check())
```

---

### الطريقة الثالثة: التشغيل المستقل لأحد أنمط البروكسي (Standalone Submodule)

إذا كنت تبني كود اختبار أو خدمة فرعية تحتاج بروكسي صريح أو عكسي مستقل:

```python
import asyncio
from modules.proxy.engine.proxy_modes import ForwardProxy, ReverseProxy

config = {
    "proxy": {
        "forward_listen_host": "0.0.0.0",
        "forward_listen_port": 3128,
        "max_connections": 5000,
        "allowed_ssrf_hosts": ["internal-api.local"]
    }
}

# 1. إنشاء البروكسي الصريح
forward_proxy = ForwardProxy(config=config, ca_manager=app_ca_manager)

# 2. تشغيل خادم البروكسي لا تزامنائياً
async def start_proxy():
    await forward_proxy.start()

# 3. إيقاف الخادم عند الانتهاء
async def stop_proxy():
    await forward_proxy.stop()
```

---

## 3. عقود المدخلات والمخرجات (Input / Output Contracts)

### أ) عقود الإدخال (Inputs Contract)

#### 1. الدالة `ContextBuilder.build_network_context(...)`
* **المدخلات**:
  - `client_addr` (`Tuple[str, int]`): ثنائية عنوان IP ومنفذ العميل (مثال: `("192.168.1.50", 54321)`).
  - `target_host` (`str`): عنوان IP أو اسم النطاق للهدف (مثال: `"example.com"` أو `"10.0.0.1"`).
  - `target_port` (`int`): المنفذ المستهدف (مثال: `80` أو `443`).
  - `protocol` (`str`): اسم البروتوكول (`"HTTP"`, `"HTTPS"`, `"TCP"`).
  - `direction` (`str`, اختيارية): اتجاه الحركة (`"inbound"` أو `"outbound"`).
* **المخرجات**:
  - كائن `InspectionContext` محمل بهوية المستخدم المكتشفة من `IdentityCorrelationEngine` والوسوم الشبكية (`internal`, `trusted`).

#### 2. الدالة `InspectionBridge.check(ctx, writer=None)`
* **المدخلات**:
  - `ctx` (`InspectionContext`): سياق الفحص المكتمل المبني بواسطة `ContextBuilder`.
  - `writer` (`Optional[asyncio.StreamWriter]`): مجرى الاستجابة للعميل (إذا تم تمريره وتقرر الحظر، يقوم الجسر تلقائياً بإرسال استجابة HTTP `403 Forbidden` أو `549 DLP Block` قبل إغلاق الاتصال).
* **المخرجات**:
  - كائن `InspectionResult` يحتوي على القرار والاكتشافات.

---

### ب) عقود الإخراج (Outputs Contract)

#### 1. كائن نتيجة الفحص `InspectionResult`
```python
result.action       # Enum: InspectionAction.ALLOW / BLOCK / QUARANTINE / LOG_ONLY
result.is_blocked   # bool: True إذا تقرر حظر الاتصال
result.findings     # List[InspectionFinding]: قائمة بالتفاصيل والانتهاكات المسجلة من الموديولات
```

#### 2. هيكل بيانات الاتصال `ProxyConnection`
```python
conn.connection_id  # str: معرف فريد للاتصال ("192.168.1.50:54321->example.com:443")
conn.client_ip      # str: IP العميل
conn.client_port    # int: منفذ العميل
conn.target_host    # str: الهدف
conn.target_port    # int: منفذ الهدف
conn.bytes_sent     # int: إجمالي البايتات المرسلة من العميل
conn.bytes_received # int: إجمالي البايتات المستلمة من السيرفر
conn.start_time     # datetime: وقت بدء الاتصال
```

---

## 4. منطق القرارات والحماية المشددة (Security & Bypass Overrides)

1. **حماية SSRF (Server-Side Request Forgery)**:
   - محرك البروكسي الصريح يرفض تلقائياً التوجيه للعناوين الخاصة أو الـ Loopback (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) لحماية الخوادم الداخلية، إلا العناوين المدرجة صراحة في قائمة الاستثناء `proxy.allowed_ssrf_hosts`.
2. **فحص الاستجابات الصادرة (DLP & Malware Egress Guard)**:
   - أثناء ترحيل البيانات من السيرفر للعميل (`server->client`)، يتم فحص كل دفعة بيانات بواسطة `DLPInspectorPlugin.inspect_response()` و `MalwareAVPlugin.inspect_async()`.
   - عند اكتشاف تسريب بيانات حساسة (بطاقات بنكية، مفاتيح PEM، أرقام هوية) يتم إنهاء الاتصال فوراً وإرجاع استجابة `HTTP 549 DLP Block`.
3. **التجاوز التلقائي لـ SSL (SSL Bypass Rules)**:
   - الاتصالات الموجهة للخدمات البنكية أو النطاقات الاستثنائية المسجلة في `SSLPolicyEngine` تعود بقرار `SSLAction.BYPASS` حيث يتم تمرير البيانات كـ Pure TCP Passthrough بدون فك التشفير.

---

## 5. واجهات التحكم البرمجية (REST API Reference)

تتوفر جميع واجهات البرمجة تحت البادئة `/api/v1/proxy`:

| المسار (Endpoint) | Method | الصلاحية المطلوب | الوصف والهدف |
| :--- | :---: | :---: | :--- |
| `/api/v1/proxy/status` | `GET` | `require_proxy` | قراءة حالة البروكسي والنمط النشط حالياً |
| `/api/v1/proxy/stats` | `GET` | `require_proxy` | جلب إحصائيات الاتصالات الحية والباندويث الممتص |
| `/api/v1/proxy/sessions` | `GET` | `require_proxy` | عرض قائمة الجلسات والاتصالات النشطة حالياً |
| `/api/v1/proxy/config` | `GET` | `require_proxy` | قراءة الإعدادات الحالية من `base.yaml` |
| `/api/v1/proxy/config` | `PUT` | `require_admin` | تحديث الإعدادات وإعادة تحميلها ديناميكياً (Hot-Reload) |
| `/api/v1/proxy/vips` | `GET` | `require_proxy` | عرض قائمة تعيينات الـ Virtual IPs المعتمدة |
| `/api/v1/proxy/vips` | `POST` | `require_admin` | إضافة خادم عكسي/تعيين VIP جديد |
| `/api/v1/proxy/vips/{name}` | `DELETE` | `require_admin` | حذف تعيين VIP |
| `/api/v1/proxy/wpad.dat` | `GET` | `Public` | تقديم ملف WPAD التلقائي لمتصفحات الأجهزة |
| `/api/v1/proxy/proxy.pac` | `GET` | `Public` | تقديم ملف PAC (Proxy Auto-Configuration) لعملاء الشبكة |

---

## 6. نظام الأحداث (EventBus & Telemetry Integration)

تنشر وحدة البروكسي الأحداث الأمنية والتليمتري تلقائياً عبر `EventBus` و `UnifiedEventSink`:

* **أحداث السماح (`EventVerdict.ALLOW`)**: تنشر عند إغلاق الاتصال بنجاح مع إجمالي حجم البايتات.
* **أحداث الحظر (`EventVerdict.DROP`)**: تنشر فوراً عند حظر اتصال عبر `InspectionBridge` أو قواعد SSRF أو DLP.
* **حمولات الحدث الموحدة (`Event Schema`)**:
```json
{
  "src_ip": "192.168.1.50",
  "dst_ip": "198.51.100.10",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "HTTPS",
  "bytes_count": 1048576,
  "packets_count": 748,
  "verdict": "ALLOW",
  "reason": "MITM proxy completed"
}
```

---

## 7. مثال برمجي كامل ومستقل (Complete Runnable Example)

```python
import asyncio
from system.core.service_container import ServiceContainer
from modules.proxy.engine.context_builder import ContextBuilder
from modules.proxy.engine.inspection_bridge import InspectionBridge

async def test_proxy_inspection_flow():
    # 1. تهيئة البنية الأساسية
    container = ServiceContainer.instance()
    config = container.get_optional('config') or {"network": {"internal_networks": ["192.168.0.0/16"]}}
    
    # 2. إنشاء الأدوات
    builder = ContextBuilder(config)
    pipeline = container.get_optional('pipeline')
    bridge = InspectionBridge(pipeline=pipeline, fail_open=True)
    
    # 3. بناء سياق طلب HTTP جديد
    ctx = builder.build_network_context(
        client_addr=("192.168.1.100", 41234),
        target_host="api.company.com",
        target_port=80,
        protocol="HTTP",
        direction="outbound"
    )
    
    # 4. إضافة حمولة الطلب
    raw_http = b"GET /v1/users HTTP/1.1\r\nHost: api.company.com\r\nUser-Agent: TestClient/1.0\r\n\r\n"
    builder.enrich_http(ctx, raw_http, scheme="http")
    
    # 5. فحص الطلب
    result = await bridge.check(ctx)
    
    print("=== نتيجة فحص البروكسي ===")
    print("القرار النهائي:", result.action.name)
    print("هل تم الحظر؟", result.is_blocked)
    print("عدد الملاحظات:", len(result.findings))
    
    for finding in result.findings:
        print(f" - [{finding.plugin_name}] ({finding.severity}): {finding.description}")

if __name__ == "__main__":
    asyncio.run(test_proxy_inspection_flow())
```

---
*تم إعداد هذا المستند ليكون المرجع التقني المباشر لجميع المطورين للتكامل مع وحدة البروكسي دون الحاجة لقراءة الكود المصدري.*

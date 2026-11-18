# 📖 دليل استخدام وحدة f:\enterprise_ngfw\modules\ssl_inspection
## `help.md` — Developer Integration & Usage Guide

تم إعداد هذا المستند ليسمح لأي مبرمج باستخدام وحدة **`ssl_inspection`** مباشرة وبكل سهولة دون الحاجة لقراءة قاع الكود (Source Code).

---

## 📌 1. الطرق الرسمية لاستدعاء الوحدة (How to Import)

تمنح الوحدة واجهة برمجية موحدة (Public API) يمكن استيرادها مباشرة من الجذر:

```python
from modules.ssl_inspection import (
    CAPoolManager,     # إدارة شهادات الجذور والشهادات المؤقتة (PKI)
    SSLInspector,      # محرك الاعتراض وتغليق اتصالات الـ TLS (MITM Proxy)
    SSLPolicyEngine,   # محرك الاتخاذ القرارات (Inspect / Bypass / Block)
    SSLAction,         # Enum يحدد نتائج القرار (INSPECT, BYPASS, BLOCK, MONITOR)
    extract_sni,       # دالة استخراج اسم الدومين (SNI) من حزم ClientHello الخام
    SNIRouter,         # موجه الاتصالات بناءً على الـ SNI
)
```

---

## ⚙️ 2. كيف تدار الوحدة في نظام bunyanx (Framework Integration)

تستجيب الوحدة لنظام `BaseModule` والـ `ServiceContainer` الخواص بالنظام. عند إقلاع النظام، يتم تسجيلها واستدعاؤها كالتالي:

```python
# الحصول على الخدمات المسجلة من الحاوية central service container
ca_manager: CAPoolManager = container.get('ca_manager')
ssl_inspector: SSLInspector = container.get('ssl_inspector')
```

---

## 🧭 3. المكونات الرئيسة: المدخلات والمخرجات (Inputs & Outputs Contract)

---

### 🅰️ محرك القرارات: `SSLPolicyEngine`

يستخدم لمعرفة ما إذا كان الاتصال يجب فكه وفحصه (DECRYPT/INSPECT) أم تجاوزه (BYPASS) أم حظره (BLOCK).

#### 1️⃣ الاستدعاء والتأهيل (Initialization):
* **المدخلات (`__init__`)**:
  * `config` (`dict`): قاموس الإعدادات (يحتوي مفتاح `ssl_inspection` المأخوذ من `ssl.yaml` أو `base.yaml`).
  * `ebpf_manager` (`Optional`): كائن إدارة eBPF للتسريع على مستوى النواة.
  * `event_sink` (`Optional`): كائن إرسال الأحداث وتجمع التليميتري.

#### 2️⃣ دالة اتخاذ القرار (`decide`):
```python
action = policy_engine.decide(
    client_ip="192.168.1.50",
    target_host="www.google.com",
    target_port=443,
    category="search_engines",     # kwarg اختياري
    tls_version="TLSv1.3",         # kwarg اختياري
    cert_expired=False,            # kwarg اختياري
    username="john_doe"            # kwarg اختياري
)
```

* **المدخلات (Inputs)**:
  * `client_ip` (`str` - **مطلوب**): عنوان IP الخاص بالجهاز العميل (مثل `"192.168.1.100"`).
  * `target_host` (`Optional[str]` - **مطلوب**): اسم النطاق المستهدف (SNI) (مثل `"www.bank.com"` أو `None` في حال تعذر الاستخراج).
  * `target_port` (`int`, افتراضي `443`): المنفذ المستهدف.
  * `kwargs`: متغيرات سياقية إضافية مثل:
    * `category` (`str`): تصنيف الموقع.
    * `cert_expired` (`bool`): هل الشهادة الأصلية للموقع منتهية؟
    * `tls_version` (`str`): إصدار الـ TLS (مثل `"TLSv1.0"`).
    * `username` (`str`): اسم المستخدم المحلي.

* **المخرجات (Outputs)**:
  * يرجع كائن `SSLAction` (Enum) بإحدى القيم التالية:
    * `SSLAction.INSPECT` (`"inspect"`): افحص الاتصال وقم بفك التشفير (MITM).
    * `SSLAction.BYPASS` (`"bypass"`): تجاوز الاتصال ومرره كما هو بدون فك التشفير.
    * `SSLAction.BLOCK` (`"block"`): احظر واسقط الاتصال فوراً.
    * `SSLAction.MONITOR` (`"monitor"`): راقب وسجل فقط.

---

### 🅱️ مدير الشهادات: `CAPoolManager`

المسؤول عن توليد وتمرير شهادات الـ SSL المزيفة (On-the-fly Leaf Certificates) والموقعة من الـ Root/Intermediate CA المحلي.

#### 1️⃣ دالة توليد شهادة لسيرفر مستهدف (`generate_server_certificate`):
```python
cert_pem, key_pem = ca_manager.generate_server_certificate(hostname="www.google.com")
```

* **المدخلات (Inputs)**:
  * `hostname` (`str` - **مطلوب**): اسم الموقع المستهدف (مثل `"www.google.com"`). *تتم التحقق من صحته طبقاً لـ RFC 1035 تلقائياً.*

* **المخرجات (Outputs)**:
  * `Tuple[bytes, bytes]`:
    1. `cert_pem` (`bytes`): الشهادة الرقمية بتنسيق PEM.
    2. `key_pem` (`bytes`): المفتاح الخاص للشهادة بتنسيق PEM.

---

### 🅲 محرك التشفير والاعتراض: `SSLInspector`

المسؤول عن إنشاء دوال الـ `SSLContext` وترقية الاتصالات عبر `asyncio`.

#### 1️⃣ دالة ترقية اتصال العميل (`wrap_client_connection`):
```python
ssl_reader, ssl_writer = await inspector.wrap_client_connection(
    reader=raw_reader,
    writer=raw_writer,
    hostname="www.google.com"
)
```

* **المدخلات (Inputs)**:
  * `reader` (`asyncio.StreamReader`): مجرى قراءة البيانات الخام قبل التشفير.
  * `writer` (`asyncio.StreamWriter`): مجرى كتابة البيانات الخام قبل التشفير.
  * `hostname` (`str`): اسم الموقع المستهدف لتوليد شهادة مطابقة له.

* **المخرجات (Outputs)**:
  * `Tuple[asyncio.StreamReader, asyncio.StreamWriter]`: ثنائية مجرى القراءة والكتابة المشفرة جاهزة لتبادل البيانات المفحوصة (Plaintext).

#### 2️⃣ دالة الاتصال بالسيرفر الحقيقي (`connect_to_upstream`):
```python
upstream_reader, upstream_writer = await inspector.connect_to_upstream(
    hostname="www.google.com",
    port=443
)
```

* **المدخلات (Inputs)**:
  * `hostname` (`str`): اسم الموقع الحقيقي على الإنترنت.
  * `port` (`int`, افتراضي `443`): المنفذ المستهدف.

* **المخرجات (Outputs)**:
  * `Tuple[asyncio.StreamReader, asyncio.StreamWriter]`: مجاري الاتصال المشفرة الآمنة مع السيرفر الأصلي.

---

### 🅳 دالة استخراج الـ SNI: `extract_sni`

دالة خفيفة وسريعة لاستخراج اسم الموقع مباشرة من حزم الـ TLS ClientHello الخام (Raw Packet Bytes).

```python
sni_domain = extract_sni(raw_packet_bytes)
```

* **المدخلات (Inputs)**:
  * `data` (`bytes`): مصفوفة البايتات الخام لباكيت الـ TLS بدءاً من الـ TLS Record Header.
* **المخرجات (Outputs)**:
  * `Optional[str]`: اسم النطاق نصياً (مثل `"www.target.com"`)، أو `None` إذا كانت الباكيت غير صالحة أو لا تحتوي على ملحق SNI.

---

## 💻 4. مثال عملي كامل للربط (Full Code Example)

```python
import asyncio
from modules.ssl_inspection import (
    CAPoolManager,
    SSLInspector,
    SSLPolicyEngine,
    SSLAction,
    extract_sni
)

async def handle_incoming_tls_client(client_reader, client_writer, config):
    # 1. تهيئة المحركات
    ca_manager = CAPoolManager(config)
    inspector = SSLInspector(ca_manager, config)
    policy_engine = SSLPolicyEngine(config)

    # 2. قراءة ترويسة الـ ClientHello واستخراج الـ SNI
    peeked_data = await client_reader.read(1024)
    sni = extract_sni(peeked_data)

    client_ip = client_writer.get_extra_info('peername')[0]

    # 3. اتخاذ القرار
    action = policy_engine.decide(client_ip=client_ip, target_host=sni)

    if action == SSLAction.BLOCK:
        client_writer.close()
        await client_writer.wait_closed()
        return

    elif action == SSLAction.BYPASS:
        # تمرير مباشر دون اعتراض (Passthrough Proxy)
        upstream_reader, upstream_writer = await asyncio.open_connection(sni, 443)
        # ... شحن البيانات الخام بين العميل والسيرفر ...
        return

    elif action == SSLAction.INSPECT:
        # 4. اعتراض وتشفير (MITM)
        ssl_client_reader, ssl_client_writer = await inspector.wrap_client_connection(
            client_reader, client_writer, hostname=sni
        )
        upstream_reader, upstream_writer = await inspector.connect_to_upstream(
            hostname=sni, port=443
        )

        # الاتصال الآن مفحوص وقابل لقراءة البيانات كـ Plaintext!
```

---

## 🌐 5. واجهات الـ REST API المتوفرة للتحكم في الوحدة

المسار الأساسي للراوتر: `/api/v1/ssl-inspection`

| Endpoint | Method | Role | Description |
| :--- | :--- | :--- | :--- |
| `/status` | `GET` | `require_ssl` | جلب حالة وإعدادات الوحدة المدمجة |
| `/statistics` | `GET` | `require_ssl` | جلب إحصائيات القرارات الحية (inspected, bypassed, blocked) |
| `/policies` | `GET` | `require_ssl` | عرض جميع سياسات الفحص والـ Bypass المسجلة |
| `/policies` | `POST` | `require_admin` | إضافة سياسة جديدة |
| `/certificates/upload` | `POST` | `require_admin` | رفع شهادة Root CA جديدة مع تشفير المفتاح تلقائياً |
| `/logs` | `GET` | `require_ssl` | جلب السجلات الحية لقرارات الـ SSL |

---
**تمت مراجعة هذا المستند واعتماده ليحل محل قراءة الكود المصدري كلياً.**

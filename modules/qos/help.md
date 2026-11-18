# دليل المبرمج لاستدعاء وتكامل وحدة جودة الخدمة (QoS Developer Integration Guide)
**الموديول:** `modules.qos`  
**الإصدار:** `2.0.0`  
**الملف:** `help.md`

---

## 📖 1. نظرة عامة (Overview)

وحدة **جودة الخدمة (QoS)** هي المحرك المركزي المسؤول عن إدارة وتنظيم النطاق الترددي (Bandwidth Shaping & Rate Limiting) بناءً على خوارزمية **دلو الرموز (Token Bucket)** لكل عنوان IP.

تم تصميم الوحدة بنمط **Singleton** لتعمل كـ Single Source of Truth متوافقة مع كل من:
1. **خط أنابيب الفحص الأمني (Synchronous Inspection Pipeline)**: تحقق فائق السرعة غير معطل ($O(1)$) لإرجاع قرار السماح (`True`) أو الحظر (`False`).
2. **البروكسي الشفاف (Asynchronous Transparent Proxy)**: تأخير غير متزامن ناعم (Sleep-to-Refill) للتحكم في السرعة بدون إسقاط الحزم.

---

## 🛠️ 2. كيفية الاستدعاء المباشر (Quick Integration Usage)

---

### Pattern 1: الاستخدام المتزامن في محرك فحص الحزم (Sync Inspection Pipeline)

تُستخدم لمعرفة هل يُسمح للعنوان `ip` بنقل حجم بيانات `data_size` أم تجاوز السرعة.

```python
from modules.qos.qos_manager import QoSManager

# 1. الحصول على نسخة الموديول الموحدة (Singleton)
qos_mgr = QoSManager.get_instance()

# 2. فحص حركة المرور (Synchronous Non-blocking Check)
target_ip = "192.168.1.50"
payload_size_bytes = 1460  # حجم الحزمة بالبايت

allowed: bool = qos_mgr.check_traffic(ip_address=target_ip, data_size_bytes=payload_size_bytes)

if allowed:
    # البيانات ضمن الحدود المسموحة
    pass
else:
    # تجاوز المستخدم سرعة النطاق الترددي المسموحة
    if qos_mgr.mode == "enforce":
        # حظر الحزمة
        pass
    else:
        # وضع المراقب: تسجيل المخالفة والتمرير
        pass
```

#### 📥 ما تلمسه/تستقبله الدالة (`check_traffic`):
* `ip_address` (`str`): عنوان IP الخاص بالعميل المراد تقييده (مثال: `"192.168.1.100"`).
* `data_size_bytes` (`int`): حجم البيانات المراد نقلها بالبايت.

#### 📤 ما ترجعه الدالة (`check_traffic`):
* `bool`:
  * `True`: البيانات مسموح بها (تم خصم الرموز بنجاح).
  * `False`: تجاوز حد النطاق الترددي / لا توجد رموز كافية.

---

### Pattern 2: الاستخدام غير المتزامن في البروكسي (Async Sleep-to-Refill Throttling)

تُستخدم في خيوط البروكسي غير المتزامنة (`async/await`) لتطبيق تقييد السرعة بنعومة (إنتظار حتى إعادة تعبئة الرموز).

```python
import asyncio
from modules.qos.qos_manager import QoSManager

async def handle_proxy_stream(client_ip: str, chunk_bytes: bytes):
    qos_mgr = QoSManager.get_instance()
    
    # تأخير غير متزامن لحين توفر رصيد رموز يكفي لنقل chunk_bytes
    await qos_mgr.throttle(ip_address=client_ip, data_size=len(chunk_bytes))
    
    # كتابة البيانات بعد الخضوع للتقييد الزمني
    writer.write(chunk_bytes)
    await writer.drain()
```

#### 📥 ما تلمسه/تستقبله الدالة (`throttle`):
* `ip_address` (`str`): عنوان IP للعميل.
* `data_size` (`int`): حجم دفعة البيانات بالبايت.

#### 📤 ما ترجعه الدالة (`throttle`):
* `None`: تنتظر الدالة تلقائياً باستخدام `asyncio.sleep(wait_time)` حتى يتوفر رصيد الرموز ثم تعود لتكملة الكود.

---

### Pattern 3: الاستخدام عبر حاوي الخدمات (ServiceContainer / BaseModule Framework)

إذا كنت تعمل ضمن إطار الموديولات الجديد الخاص بـ bunyanx:

```python
from system.core.service_container import ServiceContainer

def init_my_service(container: ServiceContainer):
    # جلب خدمة QoS المحقونة في النظام
    qos_mgr = container.get_optional('qos_manager')
    if qos_mgr and qos_mgr.enabled:
        allowed = qos_mgr.check_traffic("10.0.0.1", 500)
```

---

### Pattern 4: الإضافة البرمجية لخط الفحص (Inspection Pipeline Plugin)

يمكن استدعاء الإضافة مباشرة وإدراجها في محرك الفحص الأمني:

```python
from modules.qos.engine.qos_plugin import QoSPlugin
from system.core.framework.plugin_base import InspectionContext

plugin = QoSPlugin()

# إنشاء سياق الفحص
context = InspectionContext(
    src_ip="192.168.1.15",
    dst_ip="8.8.8.8",
    src_port=54321,
    dst_port=443,
    protocol="TCP",
    direction="outbound"  # outbound -> تقييد src_ip | inbound -> تقييد dst_ip
)

# تنفيذ الفحص
result = plugin.inspect(context=context, data=b"GET / HTTP/1.1\r\n...")

print(result.action)  # InspectionAction.ALLOW أو InspectionAction.BLOCK
print(result.findings)  # تفاصيل التجاوز
```

---

### Pattern 5: إعادة تعبئة الرموز يدوياً (Reset Bucket)

لإلغاء التقييد عن IP محدد فوراً (مثلاً بطلب من الأدمن):

```python
from modules.qos.qos_manager import QoSManager

qos_mgr = QoSManager.get_instance()
success: bool = qos_mgr.reset_bucket("192.168.1.50")

if success:
    print("تمت إعادة تعبئة رصيد الرموز بنجاح")
```

#### 📥 المدخلات: `ip_address` (`str`)
#### 📤 المخرجات: `bool` (`True` إذا كان الـ IP مديراً في الذاكرة، `False` إذا لم يكن لديه دلو نشط).

---

### Pattern 6: التعديل الفوري للقيود في الذاكرة (Hot-Reload Limits)

```python
qos_mgr = QoSManager.get_instance()

qos_mgr.update_limits(
    enabled=True,
    mode="enforce",             # "monitor" أو "enforce"
    rate_bytes=2_500_000,       # 2.5 MB/s (~20 Mbps)
    burst_bytes=5_000_000,      # 5 MB burst
    max_buckets=100_000         # الحد الأقصى للدلاء في الذاكرة
)
```

---

## 🌐 3. واجهات API (REST API Endpoints)

إذا كنت ترغب بالتحكم بموديول QoS عبر طلبات HTTP HTTP/REST:

| Endpoint | Method | Header Requirement | Payload / Input | Returns |
| :--- | :--- | :--- | :--- | :--- |
| `/api/v1/qos/status` | `GET` | Bearer Token (QoS Perm) | لا يوجد | حالة الخدمة وعدد الدلاء النشطة وحالة خيط الـ GC |
| `/api/v1/qos/config` | `GET` | Bearer Token (QoS Perm) | لا يوجد | إعدادات QoS الحالية من قاعدة البيانات |
| `/api/v1/qos/config` | `PUT` | Bearer Token (Admin) | `QoSConfigRequest` JSON | نجاح التعديل والإعدادات الجديدة |
| `/api/v1/qos/stats` | `GET` | Bearer Token (QoS Perm) | لا يوجد | قائمة بأكثر الـ IPs استهلاكاً ونسبة الإستغلال |
| `/api/v1/qos/buckets/{ip}`| `DELETE`| Bearer Token (Admin) | IP في המסار (Path) | إعادة تعبئة الرموز للـ IP |

---

## 💡 4. ملخص السلوك والاختيارات (Important Behavior Notes)

1. **التعامل مع الاتجاهات (`direction`)**:
   - `outbound` (رفع البيانات): يتم تقييد عنوان المصدر `src_ip` (العميل المحلي).
   - `inbound` (تنزيل البيانات): يتم تقييد عنوان الهدف `dst_ip` (العميل المحلي المستلم).
2. **تجنب الخصم المزدوج (`proxied: True`)**:
   - إذا تم تقييد حركة المرور سابقاً بواسطة البروكسي وتم وضع الوسم `context.tags = {"proxied"}` أو `context.metadata["proxied"] = True` فإن `QoSPlugin` يتخطى الفحص تلقائياً لتجنب خصم السرعة مرتين.
3. **حماية الذاكرة (Memory Guard)**:
   - يحافظ المحرك على سقف `max_buckets` (افتراضياً 50,000 دلو). عند تجاوزه بسبب هجمات DDoS يطرد تلقائياً أقدم 1% من الدلاء الخاملة (LRU Eviction).

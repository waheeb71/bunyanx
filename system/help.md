# دليل المطور لوحدة النظام المركزية (System Control Plane Developer Guide)

> **الملف:** `F:\enterprise_ngfw\system\help.md`  
> **الوحدة:** `system` (BunyanX Enterprise NGFW Control & Management Plane)  
> **الهدف:** هذا المستند هو الدليل المرجعي الكامل والمطوّر لأي مبرمج يرغب في استدعاء واستخدام مكونات لوحة التحكم المركزية `system` من أي مكان في المنظومة، وماذا تستقبل وما ترجعه، دون الحاجة لإعادة قراءة الكود المصدري.

---

## 1. نظرة عامة على المعمارية (System Architecture Overview)

تعتبر وحدة `system` العقل المدبر والمركز القيادي (Control Plane) لجدار الحماية. تتكون الوحدة من 16 نوات نظام رئيسية فرعية:

```
                               ┌───────────────────────────┐
                               │    bunyanxApplication     │
                               └─────────────┬─────────────┘
                                             │
      ┌──────────────────────────────────────┼──────────────────────────────────────┐
      │                                      │                                      │
┌─────▼──────────────┐             ┌─────────▼──────────┐             ┌─────────────▼──────┐
│ ServiceContainer   │             │   ConfigManager    │             │   DatabaseManager  │
│ (Dependency Inj.)  │             │ (4-Tier Hierarchy) │             │ (SQLAlchemy Pool)  │
└─────┬──────────────┘             └─────────┬──────────┘             └─────────────┬──────┘
      │                                      │                                      │
      ├──────────────────────────────────────┼──────────────────────────────────────┤
      │                                      │                                      │
┌─────▼──────────────┐             ┌─────────▼──────────┐             ┌─────────────▼──────┐
│  ModuleRegistry    │             │      EventBus      │             │   PolicyManager    │
│ (DAG Discovery)    │             │ (NATS/Kafka/Mem)   │             │ (Unified Evaluator)│
└─────┬──────────────┘             └─────────┬──────────┘             └─────────────┬──────┘
      │                                      │                                      │
      └──────────────────────────────────────┼──────────────────────────────────────┘
                                             │
                               ┌─────────────▼─────────────┐
                               │ IdentityCorrelation Engine│
                               │ (IP -> AD/VPN User Sync)  │
                               └───────────────────────────┘
```

---

## 2. طرق استدعاء وحدات النظام (How to Import & Access System Components)

توجد **ثلاث طرق رئيسية** لاستدعاء خدمات النظام:

---

### الطريقة الأولى: عبر حاوية الخدمات (`ServiceContainer`) — [الطريقة الموصى بها]

جميع مكونات النظام الأساسية تسجل نفسها تلقائياً في حاوية الخدمات عند الإقلاع. يمكنك الوصول لأي خدمة من أي كود Python:

```python
from system.core.service_container import ServiceContainer

# 1. الحصول على الكائن الفردي (Singleton)
container = ServiceContainer.instance()

# 2. استدعاء الخدمات المتاحة
db_manager     = container.get('db')               # DatabaseManager
config_dict    = container.get('config')           # Configuration dict
pipeline       = container.get('pipeline')         # InspectionPipeline
event_sink     = container.get('event_sink')       # UnifiedEventSink
policy_mgr     = container.get('policy_manager')   # PolicyManager
identity_eng   = container.get('identity_engine') # IdentityCorrelationEngine
xdp_engine     = container.get_optional('xdp_engine') # XDPEngine (إن وجد)
```

---

### الطريقة الثانية: عبر ناقل الأحداث المركزي (`EventBus`)

تُستخدم للنشر والاستماع للأحداث الأمنية والتليمتري بين مكونات النظام المختلفة بدون أي اقتران مباشر (Decoupled Messaging):

```python
from system.events.bus import EventBus
from system.events.topics import Topics

# 1. نشر حدث أمني (Publish)
async def report_threat(src_ip: str, threat_type: str):
    bus = await EventBus.instance()
    await bus.publish(Topics.THREAT_DETECTED, {
        "src_ip": src_ip,
        "event_type": threat_type,
        "severity": "CRITICAL",
        "action": "BLOCK"
    })

# 2. الاستماع لأحداث الحظر (Subscribe)
async def listen_for_blocks():
    bus = await EventBus.instance()
    
    async def on_block_event(payload: dict):
        print(f"🚨 تم حظر IP جديد: {payload.get('src_ip')} | السبب: {payload.get('reason')}")

    await bus.subscribe(Topics.RESPONSE_BLOCK, on_block_event)
```

---

### الطريقة الثالثة: الاستدعاء المباشر للكلاسات (Direct Import)

تُستخدم للتعامل مع المحركات الأساسية مثل محرك تقييم السياسات أو مدير الإعدادات:

```python
from system.policy.manager import PolicyManager
from system.config.config_manager import ConfigManager
from system.database.database import DatabaseManager

# 1. استخدام PolicyManager لتقييم سياسة
policy_mgr = PolicyManager.get_instance()
verdict = policy_mgr.evaluate({
    "src_ip": "192.168.1.50",
    "dst_ip": "8.8.8.8",
    "dst_port": 53,
    "protocol": "UDP"
})
```

---

## 3. عقود المدخلات والمخرجات (Input & Output Contracts)

---

### أ) حاوية الخدمات (`ServiceContainer`)

#### `ServiceContainer.get(service_name: str) -> Any`
- **المدخلات**: `service_name` (`str`): اسم الخدمة المطلوب (مثل `'db'`, `'config'`, `'pipeline'`, `'policy_manager'`).
- **المخرجات**: الكائن المسجل للخدمة. يرمي `KeyError` إذا كانت الخدمة غير مسجلة.

#### `ServiceContainer.get_optional(service_name: str, default=None) -> Optional[Any]`
- **المدخلات**: اسم الخدمة والقيمة الافتراضية.
- **المخرجات**: الكائن المسجل أو `default` دون رمي استثناء.

---

### ب) محرك تقييم السياسات الموحد (`PolicyManager`)

#### `policy_manager.evaluate(context_dict: dict) -> dict`

* **المدخلات (Input Dict)**:
  | المفتاح | النوع | إجباري؟ | الوصف |
  | :--- | :--- | :--- | :--- |
  | `src_ip` | `str` | نعم | عنوان IP المصدر |
  | `dst_ip` | `str` | نعم | عنوان IP Target |
  | `src_port` | `int` | لا | منفذ المصدر (افتراضي `0`) |
  | `dst_port` | `int` | لا | منفذ الوجهة (افتراضي `0`) |
  | `protocol` | `str` | لا | البرتوكول (`"TCP"`, `"UDP"`, `"ICMP"`) |
  | `domain` | `str` | لا | اسم النطاق (لفحص L7) |

* **المخرجات (Output Dict)**:
  ```python
  {
      "action": "ALLOW",          # "ALLOW" | "DROP" | "REJECT" | "BLOCK"
      "confidence": 1.0,          # نسبة الثقة (0.0 إلى 1.0)
      "reason": "Matched ACL Rule",# سبب القرار
      "rule_name": "Rule-101"     # اسم القاعدة المطابقة
  }
  ```

---

### ج) محرك الهوية والارتباط (`IdentityCorrelationEngine`)

#### `identity_engine.resolve_identity(ip_address: str) -> Optional[UserIdentity]`

* **المدخلات**: `ip_address` (`str`): عنوان IP للجهاز المحلي.
* **المخرجات**: كائن `UserIdentity` يحتوي على:
  ```python
  identity.user_id     # str: اسم المستخدم (مثل "ahmed_admin")
  identity.domain      # str: نطاق الشركة (مثل "COMPANY.LOCAL")
  identity.groups      # List[str]: مجموعات Active Directory
  identity.source      # str: مصدر التعرف ("LDAP", "RADIUS", "VPN", "CAPTIVE_PORTAL")
  ```

---

### د) محرك قاعدة البيانات (`DatabaseManager`)

#### `db.get_session() -> AsyncSession`
- **المخرجات**: جلسة قاعدة بيانات غير متزامنة (Async SQLAlchemy Session) تستخدم مع `async with`:
  ```python
  async with db.get_session() as session:
      result = await session.execute(select(User).where(User.id == 1))
  ```

---

## 4. قائمة موضوعات الأحداث (Event Topics Taxonomy)

تضمن فئة `Topics` في `system/events/topics.py` توحيد أسماء المواضيع في النظام:

| الفئة | اسم المتغير بـ `Topics` | السلسلة النصية (Topic String) | الوصف |
| :--- | :--- | :--- | :--- |
| **الأحداث الأمنية** | `Topics.THREAT_DETECTED` | `"threat.detected"` | يُنشر عند اكتشاف تهديد أمني حرج |
| **قرارات الحظر** | `Topics.RESPONSE_BLOCK` | `"response.block"` | يُنشر فور اتخاذ قرار بالحظر |
| **حالة النظام** | `Topics.SYSTEM_STARTED` | `"system.started"` | يُنشر عند اكتمال إقلاع النظام |
| **الإخفاقات** | `Topics.SYSTEM_CORE_FAILURE` | `"system.core_failure"` | يُنشر عند فشل أحد مكونات النواة |
| **المصادقة** | `Topics.AUTH_LOGIN_SUCCESS` | `"auth.login_success"` | نجاح تسجيل دخول مستخدم |
| **الافتراضية/HA** | `Topics.HA_FAILOVER` | `"ha.failover"` | حدث تغيير حالة الـ Leader |
| **السجلات** | `Topics.SIEM_INCIDENT_CREATED`| `"siem.incident_created"`| إنشاء حادثة جديدة موجهة لـ SIEM |

---

## 5. مرجع واجهات REST API الخاصة بالنظام

تتاح واجهات التحكم بالسيستم تحت البادئات الموحدة:

| Endpoint | Method | Role | Description |
| :--- | :---: | :---: | :--- |
| `/health` | `GET` | `Public` | فحص صحة وجاهزية جميع مكونات النظام |
| `/metrics` | `GET` | `Public/Prometheus` | جلب إحصائيات الأداء ومقاييس Prometheus |
| `/api/v1/system/status` | `GET` | `require_admin` | حالة النظام، Uptime، استهلاك الذاكرة والمعالج |
| `/api/v1/system/config` | `GET` / `PUT` | `require_admin` | قراءة وتحديث إعدادات `base.yaml` الموحدة |
| `/api/v1/system/reload` | `POST` | `require_admin` | إعادة تحميل الإعدادات والسياسات ديناميكياً (Hot-Reload) |
| `/api/v1/system/ha/status` | `GET` | `require_admin` | حالة الـ High Availability و الـ Replication |

---

## 6. المعيار القياسي للسجلات (Unified Logging Standard)

تلتزم كافة موديولات ومكونات النظام بصيغة السجلات الموحدة التالية (JSON Schema):

```json
{
  "timestamp": "2026-07-23T11:29:00.000Z",
  "module": "system",
  "component": "netfilter_manager",
  "severity": "INFO",
  "event_type": "firewall.rule_applied",
  "action": "ALLOW",
  "source": "192.168.1.50:54321",
  "destination": "10.0.0.1:443",
  "policy_id": "RULE_101",
  "session_id": "sess_88129",
  "request_id": "req_55102",
  "trace_id": "trace_99182371",
  "message": "Atomic nftables rule applied successfully",
  "metadata": {
    "interface": "eth0",
    "protocol": "TCP"
  }
}
```

---

## 7. مثال برمجي كامل للتكامل مع النظام (Complete Runnable Code)

```python
import asyncio
from system.core.service_container import ServiceContainer
from system.events.bus import EventBus
from system.events.topics import Topics

async def system_integration_example():
    # 1. الحصول على حاوية الخدمات
    container = ServiceContainer.instance()
    
    # 2. استدعاء مدير السياسات وقواعد البيانات
    policy_mgr = container.get_optional('policy_manager')
    db = container.get_optional('db')
    
    # 3. تقييم سياسة اتصالات
    if policy_mgr:
        verdict = policy_mgr.evaluate({
            "src_ip": "10.0.0.45",
            "dst_ip": "198.51.100.1",
            "dst_port": 443,
            "protocol": "TCP"
        })
        print(f"القرار من PolicyManager: {verdict['action']} (السبب: {verdict['reason']})")
    
    # 4. إرسال حدث أمني عبر EventBus
    bus = await EventBus.instance()
    await bus.publish(Topics.THREAT_DETECTED, {
        "src_ip": "10.0.0.45",
        "event_type": "UNAUTHORIZED_PORT_SCAN",
        "severity": "HIGH",
        "action": "BLOCK",
        "message": "Suspicious port scan detected by script"
    })
    print("✅ تم نشر الحدث الأمني عبر EventBus بنجاح")

if __name__ == "__main__":
    asyncio.run(system_integration_example())
```

---
*تم إعداد هذا المستند ليكون المرجع التقني المباشر لجميع المطورين للتكامل مع وحدة `system` المركزية دون الحاجة لقراءة الكود المصدري.*

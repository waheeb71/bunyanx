# دليل استخدام وحدة الجدار الناري (Firewall Module Developer Guide)

> **الملف:** `help.md`  
> **مسار الوحدة:** `F:\enterprise_ngfw\modules\firewall`  
> **الهدف:** هذا الملف يشرح للمطورين كيفية استدعاء واستخدام وحدة الجدار الناري في أي مكان داخل النظام، وما هي البيانات التي تستقبلها وما ترجعه، دون الحاجة لقراءة الكود المصدري للوحدة.

---

## 1. نظرة عامة على الوحدة (Overview)

وحدة الجدار الناري (`firewall`) هي المكون الأول والأساسي في خط فحص حركة الشبكة (`Inspection Pipeline`).
تتميز بالخصائص التالية:
- **تتبع حالة الاتصالات (Fast-Path State Tracking):** الاتصالات المفتوحة سابقاً (`ESTABLISHED`) تمر فوراً دون إعادة التقييم لتوفير أقصى أداء.
- **حماية قاطع الدورة (Circuit Breaker):** في حالة حدوث خطأ غير متوقع، تفشل الوحدة بوضع آمن مغلق (`Fail-Closed`) لحماية النظام.
- **تقييم موحد متعدد الطبقات (Unified Evaluator):**
  1. **تجاوز البورتات الإدارية و البيئة التطويرية (Management / Dev Port Bypass)**.
  2. **فلترة الموقع الجغرافي (GeoIP Filter)**.
  3. **قواعد الجدار الناري L3/L4 ACL (Radix Fast-Path)**.
  4. **التحكم بالتطبيقات L7 App Control (SNI / HTTP Domain Signature)**.
  5. **تجاوز شبكات LAN الداخلية (RFC-1918 Override)**.

---

## 2. طرق استدعاء الوحدة في الكود (Integration Methods)

توجد **3 طرق رئيسية** لاستدعاء الوحدة حسب احتياج التطبيق:

### الطريقة الأولى: الفحص عبر خط فحص الحزم (`Inspection Pipeline`)
تُستخدم هذه الطريقة عند دمج الجدار الناري مع محرك الفحص المباشر للنظام.

```python
from system.core.framework.plugin_base import InspectionContext, InspectionAction
from modules.firewall import FirewallPlugin

# 1. تهيئة البلاجين (مرة واحدة عند تشغيل الخدمة)
fw_plugin = FirewallPlugin(db_manager=app_db_manager, config=system_config)

# 2. إنشاء سياق الفحص للحزمة الشبكية
context = InspectionContext(
    src_ip="192.168.1.50",
    dst_ip="93.184.216.34",
    src_port=54321,
    dst_port=443,
    protocol="TCP",
    interface="eth0",
    metadata={"tcp_flags": "S"} # مثال: حزمة SYN جديدة
)

# 3. استدعاء الفحص
result = fw_plugin.inspect(context, data=b"")

# 4. قراءة القرار
if result.action == InspectionAction.BLOCK:
    print(f"تم حظر الاتصال! السبب: {result.findings[0].description}")
else:
    print("الاتصال مسموح (ALLOW).")
```

---

### الطريقة الثانية: التقييم المباشر للسياسة (`Direct Policy Evaluation`)
تُستخدم هذه الطريقة إذا كنت في وحدة أخرى (مثل WAF أو Proxy) وتريد فقط معرفة هل القرار المعتمد لعنوان معين هو `ALLOW` أم `DROP` دون المرور بخط الفحص الكامل.

```python
from modules.firewall.engine.evaluator import UnifiedEvaluator

# 1. إنشاء المقيّم (أو استخدامه كـ Singleton)
evaluator = UnifiedEvaluator(db_session=db_session, config=firewall_config)

# 2. تجهيز القاموس الخاص بالطلب
context_dict = {
    "src_ip": "192.168.1.50",
    "dst_ip": "8.8.8.8",
    "src_port": 12345,
    "dst_port": 53,
    "protocol": "UDP",
    "interface": "wan0",
    "domain": "example.com" # اختیاري لفحص L7
}

# 3. تنفيذ التقييم
verdict = evaluator.evaluate(context_dict)

# verdict يرجع dictionary يحتوي القرار
print(verdict)
# {'action': 'ALLOW', 'confidence': 1.0, 'reason': 'Matched ACL Rule', 'rule_name': 'Rule-101'}
```

---

### الطريقة الثالثة: إدارة قائمة الحظر الفوري (`IP Blocklist Management`)
تُستخدم من قبل محركات الذكاء الاصطناعي (AI/ML) أو وحدات الكشف عن التسلل (IDS/IPS) لحظر/فك حظر IP فوراً على مستوى النواة (`eBPF/XDP Kernel Drop`).

```python
from modules.firewall.engine.ip_blocklist import get_blocklist_manager

# الحصول على المدير الموحد
blocklist_mgr = get_blocklist_manager()

# 1. حظر IP مؤقتاً لمدة 3600 ثانية (ساعة)
await blocklist_mgr.block_ip(
    ip="45.33.32.156",
    reason="Brute-force attack detected by IDS",
    blocked_by="ids_module",
    duration_seconds=3600
)

# 2. فك حظر IP
await blocklist_mgr.unblock_ip("45.33.32.156")

# 3. الاستعلام هل الـ IP محظور حالياً؟
is_blocked = blocklist_mgr.is_blocked("45.33.32.156")
```

---

## 3. عقد المدخلات والمخرجات (Input & Output Contracts)

### أولاً: ما تستقبله الوحدة (Input Contract)

#### 1. كائن `InspectionContext` (الخاص بطريقة الفحص `inspect`):
| اسم الحقل | النوع | إجباري؟ | القيمة الافتراضية | الوصف |
| :--- | :--- | :--- | :--- | :--- |
| `src_ip` | `str` | نعم | `"0.0.0.0"` | IP المصدر (IPv4 أو IPv6) |
| `dst_ip` | `str` | نعم | `"0.0.0.0"` | IP الوجهة (IPv4 أو IPv6) |
| `src_port` | `int` | نعم | `0` | بورت المصدر (1-65535) |
| `dst_port` | `int` | نعم | `0` | بورت الوجهة (1-65535) |
| `protocol` | `str` | نعم | `"TCP"` | البرتوكول (`TCP`, `UDP`, `ICMP`, `ANY`) |
| `interface` | `str` | لا | `"any"` | اسم الواجهة الشبكية (`eth0`, `wan0`, `lan0`) |
| `metadata` | `dict` | لا | `{}` | معلومات إضافية مثل `tcp_flags`, `domain`, `app_id` |

#### 2. قاموس `context_dict` (الخاص بـ `UnifiedEvaluator.evaluate`):
| المفتاح | النوع | الوصف |
| :--- | :--- | :--- |
| `src_ip` | `str` | IP المصدر |
| `dst_ip` | `str` | IP الوجهة |
| `src_port` | `int` | بورت المصدر |
| `dst_port` | `int` | بورت الوجهة |
| `protocol` | `str` | البرتوكول (`TCP`/`UDP`/`ICMP`) |
| `interface` | `str` | الواجهة الشبكية الفيزيائية |
| `domain` | `str` (اختياري) | اسم النطاق (SNI/HTTP Host) لفحص L7 |
| `app_id` | `str` (اختياري) | معرف التطبيق |
| `flow_id` | `str` (اختياري) | معرف التدفق لربط السجلات (إن لم يحدد يتم توليده تلقائياً) |

---

### ثانياً: ما ترجعه الوحدة (Output Contract)

#### 1. كائن `InspectionResult` (من دالة `inspect()`):
| الحقل | النوع | الوصف |
| :--- | :--- | :--- |
| `action` | `InspectionAction` | القرار النهائي: `InspectionAction.ALLOW` أو `InspectionAction.BLOCK` أو `InspectionAction.LOG_ONLY` |
| `processing_time_ms` | `float` | الوقت المستغرق بالفحص بالملي ثانية |
| `findings` | `List[InspectionFinding]` | قائمة تحتوي تفاصيل النتيجة في حال وجود حظر أو تنبيه |
| `metadata` | `dict` | تحتوي `metadata["firewall"]` التي تشمل `action`, `rule_name`, `reason` |

**تفاصيل كائن `InspectionFinding` داخل `findings`:**
- `plugin_name`: `"firewall"`
- `severity`: `"CRITICAL"` أو `"HIGH"`
- `category`: `"Firewall"`
- `description`: سبب الحظر (مثال: `"Matched ACL Rule"`)
- `recommends_block`: `True` / `False`

#### 2. قاموس النتيجة من `evaluate()`:
```python
{
    "action": "ALLOW",          # "ALLOW" | "DROP" | "REJECT" | "BLOCK"
    "confidence": 1.0,          # نسبة الثقة (0.0 إلى 1.0)
    "reason": "Matched ACL Rule", # السبب التفصيلي للقرار
    "rule_name": "Rule-101"     # اسم القاعدة المطابقة أو "GeoIP Block" أو "Default-DROP"
}
```

---

## 4. أحداث ناقل النظام (Event Bus Integration)

عندما تتخذ الوحدة قراراً بالحظر، تقوم تلقائياً بنشر حدث عبر `EventBus`:

- **الحدث المنشور (`Published Event`):** `response.block`
  - **محتوى الـ Payload:**
    ```json
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.1",
      "proto": "TCP",
      "rule_name": "Block_Rule_1",
      "reason": "Matched ACL Rule",
      "severity": "HIGH",
      "description": "Firewall blocked 192.168.1.100 -> 10.0.0.1"
    }
    ```

---

## 5. واجهات REST API المتوفرة

إذا كنت تريد التفاعل مع الوحدة عبر HTTP REST API:

| المسار (Endpoint) | الطريقة | الصلاحية | الوصف |
| :--- | :--- | :--- | :--- |
| `/api/v1/rules` | `GET` | `require_firewall` | جلب قائمة قواعد الجدار الناري |
| `/api/v1/rules` | `POST` | `require_admin` | إضافة قاعدة جدار ناري جديدة |
| `/api/v1/rules/{id}` | `PUT` / `DELETE` | `require_admin` | تعديل أو حذف قاعدة |
| `/api/v1/policy/evaluate` | `POST` | `require_firewall` | اختبار تقييم حزمة برمجياً |
| `/api/v1/block/ips` | `GET` | `require_firewall` | جلب عناوين IP المحظورة حالياً |
| `/api/v1/block/{ip}` | `POST` | `require_admin` | حظر عنوان IP فوراً |
| `/api/v1/block/{ip}` | `DELETE` | `require_admin` | فك حظر IP |
| `/api/v1/block/all` | `DELETE` | `require_admin` | تفريغ قائمة الحظر بالكامل |
| `/api/v1/optimizer/suggest` | `GET` | `require_firewall` | اقتراحات تحسين القواعد (قواعد غير مستخدمة/مظللة) |
| `/api/v1/config` | `GET` / `PUT` | `require_admin` | قراءة وتحديث إعدادات الجدار الناري |
| `/api/v1/stats` | `GET` | `require_firewall` | إحصائيات الأداء الحية وجدول الحالات |

---

## 6. خلاصة للمطور (Developer Summary)

> **لا تحتاج لقراءة كود الوحدة الداخلي.**  
> لاستخدام الجدار الناري في أي مكان:
> 1. إذا كنت في **Pipeline فحص الشبكة**: استخدم `FirewallPlugin.inspect(context)`.
> 2. إذا كنت تريد **تقييم سياسة فقط**: استخدم `UnifiedEvaluator.evaluate(context_dict)`.
> 3. إذا كنت تريد **حظر IP سريع**: استخدم `get_blocklist_manager().block_ip(ip)`.

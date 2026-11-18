# دليل التكامل والدليل البرمجي لوحدة DNS Security (`dns_security`)
**Enterprise BunyanX NGFW v2.1 — Developer Integration Guide**

هذا المستند موجه للمبرمجين والمطورين في الفريق، حيث يشرح كيفية استدعاء والتكامل مع وحدة **DNS Security** في أي مكان داخل المنظومة دون الحاجة لإعادة قراءة كود التنفيد الداخلي.

---

## 1. نظرة عامة على الوحدة (Module Overview)

تعتبر وحدة `dns_security` خط الدفاع الأول في الجدار الناري، حيث تعمل على اعتراض وتحليل جميع طلبات أسماء النطاقات (DNS Queries) على مستوى الطبقة العميقة (Deep Packet Inspection).

### الميزات الأساسية:
- **Zero-DB RAM Cache**: جميع قرارات الفحص لكل حزمة تمس المحرك تتم في الذاكرة العشوائية (RAM) عبر `DNSEngine` بدون أي استعلام بقواعد البيانات لحفظ السرعة والـ High Throughput.
- **Triangulation Engine (DART-DNS)**: دمج 3 طبقات ذكاء اصطناعي (Lexical + Temporal Cadence + Cross-Host Graph) لتحديد الهجمات المعقدة مع خلو تام من الإنذارات الكاذبة (Zero False Positives).
- **DNS Steering & Sinkholing**: إعادة توجيه النطاقات المعزولة أو المحظورة إلى سيرفر التوجيه/صفحة الحظر (Sinkhole Web Page) على `10.10.0.1`.
- **ReDoS Protected Regex**: محرك فحص التعبير النمطي محمي ضد هجمات Catastrophic Backtracking مع مهلة زجاجية max 50ms لكل نص.

---

## 2. طرق استدعاء الوحدة (How to Initialize & Invoke)

توجد 3 طرق لاستدعاء الوحدة حسب سياق الاستخدام:

### الطريقة الأولى: عبر محرك الفحص المتسلسل (InspectionPipeline) - [الطريقة الموصى بها]
إذا كنت تعمل داخل الجدار الناري وتريد إمرار حزمة عبر الفلتر:

```python
import asyncio
from system.core.framework.pipeline import InspectionPipeline, InspectionContext
from modules.dns_security.engine.plugin import DNSSecurityPlugin

# 1. إنشاء الفلتر (مرة واحدة عند تشغيل النظام)
dns_plugin = DNSSecurityPlugin()

# 2. إنشاء Pipeline وإضافة الفلتر
pipeline = InspectionPipeline()
pipeline.add_plugin(dns_plugin)

# 3. بناء سياق الحزمة (Context)
context = InspectionContext(
    src_ip="192.168.1.100",
    dst_ip="8.8.8.8",
    src_port=54321,
    dst_port=53,
    protocol="dns",
    direction="inbound",
    flow_id="192.168.1.100:54321-dns",
    timestamp=asyncio.get_event_loop().time(),
    metadata={
        "domain": "malware-c2.example.com",
        "query_type": "A",
        "is_dns": True
    }
)

# 4. تنفيذ الفحص (Async)
async def inspect_query():
    result = await pipeline.inspect_async(context, data=b"")
    print(f"Action: {result.action}")           # ALLOW / BLOCK / REDIRECT / MONITOR
    print(f"Is Blocked: {result.is_blocked}")  # True / False
    print(f"Findings: {result.findings}")     # قائمة التفاصيل والتهديدات

asyncio.run(inspect_query())
```

---

### الطريقة الثانية: الاستدعاء المباشر للمحرك المباشر (Direct Plugin Call)

إذا كنت تبحث عن استجابة سريعة Synchronous في جزء آخر من الكود دون مركب الـ Pipeline:

```python
from system.core.framework.plugin_base import InspectionContext, InspectionAction
from modules.dns_security.engine.plugin import DNSSecurityPlugin

# 1. الحصول على كائن الفلتر
plugin = DNSSecurityPlugin()

# 2. بناء السياق
context = InspectionContext(
    src_ip="10.10.0.50",
    dst_ip="10.10.0.1",
    src_port=12345,
    dst_port=53,
    protocol="dns",
    metadata={"domain": "qzpwxmncb.org", "query_type": "A"}
)

# 3. الفحص المباشر
result = plugin.inspect(context)

if result.action == InspectionAction.REDIRECT:
    redirect_ip = result.metadata.get("redirect_ip")
    print(f"تم توجيه الطلب إلى السنك هول: {redirect_ip}")

elif result.action == InspectionAction.BLOCK:
    print("تم حظر الطلب!")
    for finding in result.findings:
        print(f"السبب: {finding.description} (الخطورة: {finding.severity})")
```

---

### الطريقة الثالثة: عبر محرك الذكاء الاصطناعي (DART Fusion Engine Only)
إذا كنت تبني كود تحليل أمني أو SOC Dashboard وتريد فقط تقييم مدى خباثة نطاق معين (Domain Scoring):

```python
from modules.dns_security.engine.dart.lexical import LexicalAnalyzer
from modules.dns_security.engine.dart.temporal import TemporalResonanceDetector
from modules.dns_security.engine.dart.graph import GraphResonanceEngine
from modules.dns_security.engine.dart.fusion import DARTFusionEngine

# 1. تهيئة المحركات
lexical = LexicalAnalyzer()
temporal = TemporalResonanceDetector()
graph = GraphResonanceEngine()
fusion = DARTFusionEngine()

domain = "dga-attack-domain-example.xyz"
src_ip = "192.168.1.50"

# 2. فحص الطبقة الأولى (Lexical)
s1_score, s1_components = lexical.analyze(domain)

# 3. فحص الطبقة الثانية (Temporal)
sig2 = temporal.analyze(src_ip, domain)

# 4. فحص الطبقة الثالثة (Graph)
sig3 = graph.analyze(src_ip, domain)

# 5. الدمج التراكمي (Triangulation)
decision = fusion.fuse(
    domain=domain,
    s1_score=s1_score,
    s1_components=s1_components,
    s2_score=sig2.score,
    s3_score=sig3.score
)

print(f"Domain: {decision.domain}")
print(f"Is Malicious: {decision.is_malicious}")
print(f"Resonance Score: {decision.resonance_score}")
print(f"Layers Triggered: {decision.layers_triggered}")
print(f"Evidence Details: {decision.evidence}")
```

---

## 3. مدخلات ومخرجات الوحدة (Input / Output Contract)

### أ) ماذا تستقبل الوحدة؟ (Inputs)
تستقبل الوحدة كائن `InspectionContext` والذي يحتوي على الحقول التالية:

| الحقل (Field) | النوع (Type) | الوصف | مثال |
| :--- | :--- | :--- | :--- |
| `src_ip` | `str` | عنوان IP للجهاز المصدر | `"192.168.1.100"` |
| `dst_ip` | `str` | عنوان IP للمستهدف (عادة Firewall) | `"10.10.0.1"` |
| `src_port` | `int` | منفذ المصدر | `54321` |
| `dst_port` | `int` | منفذ DNS | `53` أو `5353` |
| `protocol` | `str` | البروتوكول | `"dns"` أو `"UDP"` |
| `dns` | `Optional[DnsInfo]` | كائن تفاصيل الـ DNS الاختياري | `context.dns.query_name` |
| `metadata` | `dict` | بيانات وصفية تحتوي على النطاق ونوع الاستعلام | `{"domain": "example.com", "query_type": "A"}` |

---

### ب) ماذا ترجع الوحدة؟ (Outputs)
ترجع الوحدة كائن `InspectionResult` يحتوي على الحقول التالية:

| الحقل (Field) | النوع (Type) | الوصف | القيم المحتملة |
| :--- | :--- | :--- | :--- |
| `action` | `InspectionAction` | القرار النهائي للحزمة | `ALLOW`, `BLOCK`, `REDIRECT`, `MONITOR` |
| `is_blocked` | `bool` | هل يجب حظر الحزمة فوراً؟ | `True` / `False` |
| `metadata` | `dict` | معلومات إضافية مثل IP التوجيه | `{"redirect_ip": "10.10.0.1"}` |
| `findings` | `List[InspectionFinding]` | قائمة بجميع الاكتشافات والتهديدات المسجلة | قائمة كائنات `InspectionFinding` |

#### تفاصيل كائن `InspectionFinding`:
```python
finding.plugin_name  # "dns_security"
finding.severity     # "CRITICAL", "HIGH", "MEDIUM", "INFO"
finding.category     # "THREAT_INTEL", "DNS_FILTER", "DGA_DETECTED", "DART_MALICIOUS", "DNS_TUNNELING"
finding.description  # نص الشرح التفصيلي لسبب الحظر
finding.confidence   # معامل الثقة [0.0 - 1.0]
finding.metadata     # أدلة إضافية (Evidence Dict)
```

---

## 4. الإشارات والأحداث (Events & EventBus)

ترسل الوحدة إشعارات تلقائية عبر ناقل الأحداث `EventBus` على الموضوع `Topics.DNS_THREAT` عندما يتم اكتشاف تهديد أو حظر نطاق:

### الاستماع للأحداث من أي مكان في النظام:

```python
from system.events.bus import EventBus
from system.events.topics import Topics

async def listen_to_dns_threats():
    bus = await EventBus.instance()
    
    async def on_dns_threat(payload: dict):
        print(f"🚨 تنبيه تهديد DNS جديد!")
        print(f"المصدر: {payload.get('src_ip')}")
        print(f"النطاق المحظور: {payload.get('domain')}")
        print(f"التصنيف: {payload.get('category')}")
        print(f"القرار: {payload.get('action')}")

    await bus.subscribe(Topics.DNS_THREAT, on_dns_threat)

# تشغيل المستمع
# asyncio.create_task(listen_to_dns_threats())
```

---

## 5. واجهات البرمجة (REST API Cheatsheet)

جميع واجهات الـ REST API تقع تحت المسار الموحد `/api/v1/dns_security`:

| Endpoint | Method | الوصف | Auth Required |
| :--- | :--- | :--- | :--- |
| `/api/v1/dns_security/status` | `GET` | حالة المحرك والمراقبة | DNS User / Admin |
| `/api/v1/dns_security/config` | `GET` / `PUT` | قراءة/تحديث الإعدادات | Admin (for PUT) |
| `/api/v1/dns_security/stats` | `GET` | إحصائيات النطاقات المحظورة والقواعد | DNS User / Admin |
| `/api/v1/dns_security/rules` | `GET` / `POST` | إضافة وقراءة قواعد الفلترة | Admin (for POST) |
| `/api/v1/dns_security/rules/{id}` | `PUT` / `DELETE` | تعديل/حذف قاعدة فلترة | Admin |
| `/api/v1/dns_security/dart_alerts` | `GET` | قائمة تنبيهات الذكاء الاصطناعي | DNS User / Admin |
| `/api/v1/dns_security/dart_alerts/{id}/false_positive` | `PUT` | إبلاغ عن إنذار كاذب لتحديث النموذج | Admin |
| `/api/v1/dns_security/steering` | `GET` / `POST` / `DELETE` | إدارة قواعد إعادة التوجيه (Steering) | Admin |

---

## 6. ملخص سريع للمبرمج (Quick Summary)

- **هل تحتاج لقراءة الكود الداخلي للوحدة؟** لا.
- **أي ملف تستدعي لاستخدام الوحدة؟** `from modules.dns_security.engine.plugin import DNSSecurityPlugin`
- **ما هو كائن الإدخال الأساسي؟** `InspectionContext(metadata={"domain": "example.com"})`
- **كيف أعرف القرار؟** أفحص `result.action` (`ALLOW`, `BLOCK`, `REDIRECT`).
- **أين تذهب الطلبات المحظورة؟** تعود بإجابة `REDIRECT` متجهة إلى الـ Sinkhole IP (`10.10.0.1`).

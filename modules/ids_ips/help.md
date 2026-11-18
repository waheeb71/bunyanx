# دليل المطورين لوحدة كشف ومنع الاختراق (PHANTOM IDS/IPS Developer Guide)

> **الملف:** `modules/ids_ips/help.md`  
> **الوحدة:** `ids_ips` (PHANTOM IDS/IPS Engine with ML Anomaly Detection)  
> **الهدف:** التوثيق الشامل لكيفية استدعاء وتكامل وحدة كشف ومنع الاختراق في أي مكان داخل جدار الحماية BunyanX NGFW دون الحاجة لإعادة قراءة الكود المصدري.

---

## 1. نظرة عامة (Overview)

تعتبر وحدة `ids_ips` المحرك الأساسي للفحص العميق للذكاء الاصطناعي (DPI/ML) ومنع الاختراق. تعتمد الوحدة على **معمارية PHANTOM خماسية الطبقات** مع آلية التراجع الآمن (Fail-Open):

1. **Dynamic Threat Blocklist**: فحص فوري وسريع (أقل من 1 ملي ثانية) للحد من استهلاك الموارد قبل تشغيل موديلات الذكاء الاصطناعي.
2. **Layer 1: Spectral Byte Encoder (SBE)**: تحويل البايتات إلى متجه طيفي (256-dim) باستخدام FFT + Wavelet + Shannon Entropy.
3. **Layer 2: Causal Temporal Graph Builder (CTGB)**: بناء رسم بياني سببي لحظي لروابط الأجهزة وحساب كثافة الروابط المشبوهة (`causal_density`).
4. **Layer 3: Hybrid GNN-Transformer Classifier (HGTC)**: تصنيف التهديدات (10 فئات) باستخدام شبكات النماذج الهجينة GNN و Transformer عبر ONNX أو PyTorch.
5. **Layer 4: Legacy IPS Engine**: فحص القواعد التقليدية (Snort Rules + Aho-Corasick) وسمعة العناوين (Reputation) وذكاء التهديدات (Threat Intel) وتكامل ZTA.
6. **Layer 5: Conservative Fusion Engine**: دمج قرار المحركات الخمسة لاتخاذ القرار النهائي (`ALLOW`, `BLOCK`, `DECEIVE`, `LOG_ONLY`).

---

## 2. كيفية استدعاء الوحدة (How to Import & Invoke)

### الطريقة الأولى: الاستدعاء القياسي عبر خط المعالجة (Pipeline Inspection)

يمكنك استدعاء إضافة الفحص `PHANTOMPlugin` من أي مكان في النظام تزامنيًا أو لا تزامنيًا.

```python
from system.core.framework.plugin_base import InspectionContext, InspectionAction
from modules.ids_ips.engine.phantom_plugin import PHANTOMPlugin

# 1. تهيئة الإضافة (تنشأ عادةً كـ Singleton بواسطة ModuleManager)
plugin = PHANTOMPlugin()
plugin.initialize()

# 2. تجهيز سياق الفحص (InspectionContext)
context = InspectionContext(
    src_ip="10.0.0.5",
    dst_ip="192.168.1.100",
    src_port=49152,
    dst_port=443,
    protocol="TCP",
    direction="inbound",
    is_internal=True
)

# 3. إرسال الباكت/الحمولة للفحص (Synchronous Call)
payload = b"GET /admin HTTP/1.1\r\nHost: target.local\r\n\r\n"
result = plugin.inspect(context, payload)

print("Verdict Action:", result.action.name)  # ALLOW, BLOCK, DECEIVE, etc.
```

---

### الطريقة الثانية: الاستدعاء اللا تزامني (Async Pipeline with SLA Guard)

في بيئات البروكسي وخطوط المعالجة عالية السرعة (`asyncio`)، يوصى باستدعاء `inspect_async`. يحتوي هذا الاستدعاء على مهلة زمنية صارمة (5 ثوانٍ) لمنع خنق شبكة الاتصال في حال بطء خط الاستنتاج.

```python
import asyncio
from system.core.framework.plugin_base import InspectionContext
from modules.ids_ips.engine.phantom_plugin import PHANTOMPlugin

async def process_packet(context: InspectionContext, data: bytes, plugin: PHANTOMPlugin):
    # ينفذ الفحص في ThreadPool مع مهلة 5 ثوانٍ (Fail-Open تلقائي عند انتهاء المهلة)
    result = await plugin.inspect_async(context, data)
    
    if result.action == InspectionAction.BLOCK:
        print(f"🛑 [IDS/IPS] Blocked packet from {context.src_ip}")
        # قطع الاتصال أو إسقاط الباكت
    elif result.action == InspectionAction.DECEIVE:
        print(f"🪤 [IDS/IPS] Deploying deception tarpit banner: {context.metrics.get('deception_trap')}")
        # إرجاع بنر الفخ للمهاجم
    else:
        print(f"✅ [IDS/IPS] Traffic Allowed")
```

---

### الطريقة الثالثة: الوصول عبر حاوية الخدمات (`ServiceContainer`)

تسجل وحدة `ids_ips` خدماتها تلقائياً داخل `ServiceContainer` بالنظام:

```python
from system.core.service_container import ServiceContainer

container = ServiceContainer.instance()

# 1. الحصول على كاشف الشذوذ (AnomalyDetector)
anomaly_detector = container.get_optional('anomaly_detector')
if anomaly_detector:
    # استخدام كاشف الشذوذ مباشرة
    pass

# 2. الحصول على محرك IPS التقليدي (IPSEngine)
ips_engine = container.get_optional('ips_engine')
if ips_engine:
    # استخدام محرك IPS مباشرة
    pass
```

---

## 3. ما تستقبله الوحدة (Input Contract)

تستقبل الوحدة عنصرين رئيسيين:

### 1. `context: InspectionContext`
كائن يحمل بيانات الترويسة والبيانات الوصفية للباكت/الاتصال:

| الحقل | النوع | الوصف | مثال |
|---|---|---|---|
| `src_ip` | `str` | عنوان IP المصدر | `"10.10.0.50"` |
| `dst_ip` | `str` | عنوان IP الوجهة | `"185.220.101.5"` |
| `src_port` | `int` | منفذ المصدر | `54321` |
| `dst_port` | `int` | منفذ الوجهة | `80` أو `443` |
| `protocol` | `str` | البروتوكول (`TCP`, `UDP`, `TLS`, `HTTP`) | `"TCP"` |
| `direction` | `str` | اتجاه الحزمة (`inbound`, `outbound`) | `"inbound"` |
| `is_internal` | `bool` | هل المصدر شبكة داخلية (يمنع الحجب الذاتي) | `True` |
| `http` | `Optional[HTTPContext]` | بيانات HTTP إن وجدت (الحمولة، الهيدر) | `context.http.body` |
| `tls` | `Optional[TLSContext]` | بيانات TLS إن وجدت (SNI, JA3) | `context.tls.sni` |
| `metadata` | `dict` | قاموس بيانات إضافية (مثل اسم الدومين، مقاييس UBA) | `{"domain": "bad.com"}` |

### 2. `payload: bytes`
حمولة الباكت الخام (`bytes`). إذا كانت فارغة وتم استخدام HTTP، تأخذ الوحدة الحمولة تلقائياً من `context.http.body`.

---

## 4. ما ترجعه الوحدة (Output Contract)

ترجع الوحدة كائن `InspectionResult` محمل بنتيجة القرار والدلائل التفسيرية (XAI):

### 1. القرار الرئيسي (`result.action`)
نوع `InspectionAction` من القيم التالية:
- `InspectionAction.ALLOW` (0): السماح بمرور حركة المرور.
- `InspectionAction.BLOCK` (1): حجب وإسقاط حركة المرور فوراً.
- `InspectionAction.DECEIVE` (4): تحويل الاتصال إلى فخ الخداع التفاعلي (Tarpit/Honeypot).
- `InspectionAction.LOG_ONLY` (6): تسجيل التهديد فقط بدون حجب (في وضع المراقبة أو التردد).

---

### 2. التنبيهات والاكتشافات (`result.findings`)
قائمة كائنات من نوع `InspectionFinding` تحتوي تفاصيل التهديد:

```python
for finding in result.findings:
    print("Plugin:", finding.plugin_name)    # "PHANTOMPlugin"
    print("Severity:", finding.severity)      # "CRITICAL", "HIGH", "LOW"
    print("Category:", finding.category)      # "encrypted_c2", "port_scan", "dos_ddos", etc.
    print("Description:", finding.description)# "PHANTOM detected encrypted_c2 (conf=0.850...)"
    print("Confidence:", finding.confidence)  # 0.85
    print("Recommends Block:", finding.recommends_block) # True / False
```

---

### 3. البيانات الوصفية والشهادة التفسيرية (`result.metadata["phantom"]`)
قاموس يحتوي على كامل أدلة تحليل الذكاء الاصطناعي المتقدمة (XAI Record):

```python
phantom_meta = result.metadata.get("phantom", {})

# تفاصيل الأدلة المتاحة:
sample_id          = phantom_meta.get("sample_id")          # معرف النظير للاستجابة والتدريب (UUID)
sbe_available      = phantom_meta.get("sbe_available")      # هل نجح الترميز الطيفي SBE
causal_density     = phantom_meta.get("causal_density")     # كثافة الرسم البياني السببي CTGB
phantom_class      = phantom_meta.get("phantom_class")      # تصنيف التهديد (مثل "encrypted_c2")
phantom_confidence = phantom_meta.get("phantom_confidence") # نسبة الثقة بالتهديد (0.0 - 1.0)
phantom_is_threat  = phantom_meta.get("phantom_is_threat")  # هل تم اعتباره تهديداً
inference_ms       = phantom_meta.get("inference_ms")       # زمن استنتاج الذكاء الاصطناعي بالملي ثانية
legacy_action      = phantom_meta.get("legacy_action")      # قرار المحرك التقليدي (ALLOW/BLOCK)
final_action       = phantom_meta.get("final_action")       # القرار النهائي بعد الدمج
latency_ms         = phantom_meta.get("latency_ms")         # الزمن الكلي للفحص
```

---

## 5. واجهات REST API التفاعلية

إذا كنت تبني واجهة لوحة تحكم (Dashboard) أو تفاعلاً خارجيًا، تعرض الوحدة الواجهات التالية تحت المسار المفهرس `/api/v1/ids_ips`:

- `GET /api/v1/ids_ips/status`: حالة الوحدة التشغيلية.
- `GET /api/v1/ids_ips/alerts`: جلب الأحداث والتنبيهات الأمنية المسجلة.
- `GET /api/v1/ids_ips/config` & `PUT /api/v1/ids_ips/config`: قراءة وتحديث إعدادات وعتبات محركات الذكاء الاصطناعي.
- `GET /api/v1/ids_ips/signatures` & `POST /api/v1/ids_ips/signatures`: إدارة قواعد Snort الديناميكية.
- `GET /api/v1/ids_ips/phantom/status`: إحصائيات حية لجميع طبقات PHANTOM (الكاش، الرسم البياني، الموديل).
- `GET /api/v1/ids_ips/phantom/drift`: متابعة الانحراف المفهومي (Concept Drift) عبر كاشف ADWIN.
- `POST /api/v1/ids_ips/phantom/feedback`: إرسال التغذية الراجعة من المحللين لتعديل الأوزان أونلاين (OCL Adaptation).
- `POST /api/v1/ids_ips/threat-intel/add`: إضافة مؤشرات تهديد جديدة يدويًا إلى قاعدة بيانات التهديدات.

---

## 6. مثال كود كامل وجاهز للاستخدام (Complete Example)

```python
import logging
from system.core.framework.plugin_base import InspectionContext, InspectionAction
from modules.ids_ips.engine.phantom_plugin import PHANTOMPlugin

logging.basicConfig(level=logging.INFO)

def run_ids_ips_demo():
    # 1. إنشاء وإعداد البلاجن
    plugin = PHANTOMPlugin()
    plugin.initialize()

    # 2. إعداد الاتصال
    ctx = InspectionContext(
        src_ip="185.220.101.5",
        dst_ip="10.0.0.1",
        src_port=55432,
        dst_port=443,
        protocol="TLS",
        direction="inbound",
        is_internal=False
    )
    
    # 3. محاكاة حمولة باكت مشبوهة (Meterpreter / Encrypted C2)
    sample_payload = b"MSSL\x00\x00\x01\x00" + (b"\x90" * 30) + (b"\x12\x34\x56\x78" * 20)

    # 4. التنفيذ والتقييم
    result = plugin.inspect(ctx, payload=sample_payload)

    # 5. معالجة النتيجة
    print(f"== Result Verdict: {result.action.name} ==")
    
    if result.action == InspectionAction.BLOCK:
        print("--> Action Taken: BLOCK TRAFFIC & UPDATE FIREWALL RULES")
    
    for f in result.findings:
        print(f"[{f.severity}] {f.category}: {f.description} (Confidence: {f.confidence})")
        
    meta = result.metadata.get("phantom", {})
    print(f"Latency: {meta.get('latency_ms')}ms | Inference: {meta.get('inference_ms')}ms")

if __name__ == "__main__":
    run_ids_ips_demo()
```

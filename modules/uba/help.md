# دليل المطورين لوحدة تحليل سلوك المستخدمين (UBA - User Behavior Analytics Guide)

> **الملف:** `modules/uba/help.md`  
> **الوحدة:** `uba` (Enterprise User Behavior Analytics Engine with Micro-Fault Perturbation & Generative Deception)  
> **الهدف:** التوثيق الشامل والمفصل لكيفية استدعاء وتكامل وحدة UBA في أي مكان داخل جدار الحماية BunyanX NGFW دون الحاجة لإعادة قراءة الكود المصدري.

---

## 1. نظرة عامة (Overview)

تعتبر وحدة `uba` المحرك الذكي المتقدم لتحليل سلوك المستخدمين وتحديد التهديدات الداخلية (Insider Threats)، الحسابات المخترقة (Compromised Credentials)، والتصعيد غير المصرح به للصلاحيات (Privilege Escalation).

تعتمد الوحدة على معمارية متكاملة تتكون من:

1. **المحلل التكيفي (UserProfiler):** يبني خط أساس سلوكي ديناميكي (Adaptive Baseline) لكل مستخدم باستخدام متوسطات خوارزمية EMA المتحركة وتحديد ساعات العمل وفق الإحصاء الدائري (Circular Statistics).
2. **الكواشف الخمسة (5 Anomaly Detectors):**
   - **TimeAnomalyDetector:** فحص الشذوذ الزمني باستخدام اختباري 3-Sigma والإحصاء الدائري لمنع أخطاء منتصف الليل (23:00 - 01:00).
   - **LocationAnomalyDetector:** فحص عنوان IP المصدر والشبكة الفرعية (`/16 Subnet`).
   - **ExfilDetector:** فحص تسريب البيانات والحجم التراكمي خلال 24 ساعة.
   - **PrivilegeDetector:** كشف الخدمات والمنافذ الحساسة الجديدة (SSH, RDP, WinRM, Admin).
   - **PeerGroupDetector:** مقارنة سلوك المستخدم بأقرانه في نفس القسم/المجموعة عبر مقياس Z-Score.
3. **مجمع المخاطر (RiskAggregator):** دمج نتائج الكواشف بأوزان محددة وحساب مستوى الخطر الصاعد/الهابط تدريجياً (`low`, `medium`, `high`, `critical`).
4. **المحفز الفعال (MicroFaultInjector - Active Perturbation):** حقن تأخيرات TCP خفيفة لقياس زمن رد فعل المستخدم والتمييز بين البوتات والبرمجيات التلقائية (0ms - 100ms) والإنسان (>300ms).
5. **شباك الخداع التفاعلي (GenerativeLabyrinthEngine & Honeytoken):** توليد طعم تنكري وحقن المتاهات وتوجيه الاتصالات المشبوهة إليها تلقائياً.

---

## 2. كيفية استدعاء الوحدة (How to Import & Invoke)

### الطريقة الأولى: الاستدعاء عبر خط المعالجة (Inspection Pipeline Integration)

تستدعى البلاجن `UBAPlugin` في خط الفحص الرئيسي لجدار الحماية، وتأخذ أولوية `PluginPriority.LOWEST` لضمان الحصول على هوية المستخدم المكتشفة من وحدة ICE.

```python
from system.core.framework.plugin_base import InspectionContext, InspectionAction
from modules.uba.engine.core.uba_plugin import UBAPlugin

# 1. إنشاء وإعداد البلاجن (ربطها بقاعدة البيانات إن وجدت)
plugin = UBAPlugin(db_manager=db_handle)

# 2. إعداد سياق الفحص (InspectionContext)
context = InspectionContext(
    src_ip="10.0.0.45",
    dst_ip="192.168.1.10",
    src_port=54321,
    dst_port=22,
    protocol="TCP",
    direction="inbound",
    is_internal=True
)

# تعيين بيانات الهوية (Identity) أو البيانات الوصفية (Metadata)
context.metadata = {
    "username": "ahmed_admin",
    "bytes_transferred": 1500000.0,
    "session_duration": 120.0
}

# 3. إرسال الحزمة للفحص
result = plugin.inspect(context, data=b"")

print("القرار النهائي:", result.action.name)
# ALLOW, ALERT/LOG_ONLY, BLOCK, PERTURB, REDIRECT_DECOY
```

---

### الطريقة الثانية: الاستدعاء المباشر للمحلل السلوكي (Direct UserProfiler Call)

إذا كنت ترغب في تحليل حدث سلوكي محدد بدون المرور بـ Pipeline الحزم:

```python
from modules.uba.engine.core.user_profiler import UserProfiler

# 1. إنشاء كائن المحلل السلوكي
profiler = UserProfiler(db_manager=db_handle)

# 2. تحليل حدث سلوكي للمستخدم
analysis_result = profiler.analyze(
    username="salem_finance",
    source_ip="192.168.2.100",
    target_service="TCP:445",  # SMB Service
    bytes_transferred=2500000.0,
    session_duration=300.0,
    department="Finance"
)

# 3. قراءة النتائج
print(f"درجة الشذوذ: {analysis_result.anomaly_score}")
print(f"مستوى الخطر: {analysis_result.risk_level}")      # low, medium, high, critical
print(f"الإجراء المقترح: {analysis_result.action}")       # allow, alert, block, inject_bait
print(f"الكواشف المفعلة: {analysis_result.detectors_triggered}")
```

---

### الطريقة الثالثة: الحصول على الوحدة من حاوية الخدمات (ServiceContainer)

تسجل وحدة UBA نفسها تلقائياً في `ServiceContainer`:

```python
from system.core.service_container import ServiceContainer

container = ServiceContainer.instance()

# 1. الحصول على المحرك المباشر 'uba'
uba_engine = container.get_optional('uba')
if uba_engine:
    score = uba_engine.analyze_activity(
        username="m_alawi",
        source_ip="10.0.0.12",
        target_service="HTTP:80",
        bytes_transferred=50000
    )
    print("Anomaly Score:", score)

# 2. الحصول على المحلل السلوكي المتقدم 'uba_profiler'
profiler = container.get_optional('uba_profiler')
if profiler:
    res = profiler.analyze(username="m_alawi", source_ip="10.0.0.12", target_service="HTTP:80", bytes_transferred=50000)
```

---

## 3. ما تستقبله الوحدة (Input Contract)

### 1. عند استخدام `UBAPlugin.inspect(context, data)`

| المعامل | النوع | الوصف | مثال |
|---|---|---|---|
| `context.src_ip` | `str` | عنوان IP الخاص بالجهاز المصدر | `"10.0.0.50"` |
| `context.dst_port` | `int` | رقم المنفذ المستهدف | `22` أو `3389` |
| `context.protocol` | `str` | بروتوكول الاتصال (`TCP`, `UDP`, `HTTP`, `SMTP`) | `"TCP"` |
| `context.identity.user_id` | `str` | اسم المستخدم المكتشف من ICE/AD (إن وجد) | `"khaled_hr"` |
| `context.metadata["username"]` | `str` | اسم المستخدم الاحتياطي إن لم يتوفر في identity | `"khaled_hr"` |
| `context.metadata["bytes_transferred"]` | `float` | عدد البايتات المحولة | `5000000.0` |
| `context.metadata["session_duration"]` | `float` | مدة الجلسة بالثواني | `60.0` |

---

### 2. عند استخدام `UserProfiler.analyze(...)`

```python
profiler.analyze(
    username: str,             # اسم المستخدم المعرف في النظام
    source_ip: str,            # عنوان IP المصدر
    target_service: str,       # الخدمة/المنفذ المستهدف (مثال "TCP:22")
    bytes_transferred: float,  # حجم البيانات المحولة في الحدث
    session_duration: float = 0.0, # مدة الاتصال بالثواني
    event_time: Optional[float] = None, # الطابع الزمني (افتراضياً الوقت الحالي)
    peer_group: Optional[str] = None,   # المجموعة النظيرة (مثل "IT", "Finance")
    groups: Optional[List[str]] = None, # مجموعات Active Directory
    department: Optional[str] = None    # القسم الوظيفي من AD
)
```

---

## 4. ما ترجعه الوحدة (Output Contract)

### 1. كائن النتيجة الرئيسي (`InspectionResult`)

عند استدعاء `UBAPlugin.inspect()` ترجع الوحدة كائن `InspectionResult`:

#### القرار (`result.action`)
- `InspectionAction.ALLOW`: حركة المرور طبيعية وضمن حدود السلوك المتوقع.
- `InspectionAction.LOG_ONLY`: تسجيل التنبيه فقط دون قطع الاتصال.
- `InspectionAction.BLOCK`: حجب المستخدم/الاتصال فوراً لوصول الخطر لمستوى حرج (`critical`).
- `InspectionAction.PERTURB`: حقن تأخير TCP لاختبار هل المتصل بوت أم إنسان.
- `InspectionAction.REDIRECT_DECOY`: تحويل الاتصال تلقائياً إلى متاهة الخداع (Generative Labyrinth).

#### الاكتشافات والتنبيهات (`result.findings`)
تحتوي قائمة كائنات `InspectionFinding`:
- `finding.plugin_name`: `"uba"`
- `finding.severity`: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"INFO"`
- `finding.category`: `"UBA"`
- `finding.description`: نص مؤشر الشذوذ (مثال: `"exfil:extreme_volume:5.0MB (threshold 1.2MB, 3σ)"`)
- `finding.confidence`: درجة الشذوذ (0.0 - 1.0)

#### البيانات الوصفية (`result.metadata["uba"]`)
```python
uba_meta = result.metadata["uba"]
# البيانات المتاحة:
username      = uba_meta["username"]      # اسم المستخدم
risk_score    = uba_meta["risk_score"]    # درجة الخطر الكلية للمستخدم (0 - 100)
risk_level    = uba_meta["risk_level"]    # مستوى الخطر (low, medium, high, critical)
anomaly_score = uba_meta["anomaly_score"] # درجة الشذوذ للحدث الحالي (0.0 - 1.0)
peer_group    = uba_meta["peer_group"]    # مجموعته النظيرة
department    = uba_meta["department"]    # قسمه الوظيفي
```

---

### 2. كائن `UBAAnalysisResult` (عند الاستدعاء المباشر)

عند استدعاء `UserProfiler.analyze()` ترجع الوحدة كائن `UBAAnalysisResult`:

```python
result = profiler.analyze(...)

result.username            # اسم المستخدم
result.anomaly_score       # float (0.0 - 1.0)
result.risk_score          # float (0.0 - 100.0)
result.risk_level          # str ("low", "medium", "high", "critical")
result.action              # str ("allow", "alert", "block", "inject_bait")
result.detectors_triggered # List[str] كواشف التهديدات المثارة
result.details["scores"]   # قاموس يحتوي درجات الكواشف الخمسة الفرعية (time, location, exfil, privilege, peer)
```

---

## 5. واجهات REST API التفاعلية

تعرض الوحدة الواجهات التالية تحت المسار المفهرس `/api/v1/uba`:

- `GET /api/v1/uba/status`: حالة الوحدة والإحصائيات الحية للمستخدمين عالي الملافيات.
- `GET /api/v1/uba/config` & `PUT /api/v1/uba/config`: قراءة وتحديث أوزان الكواشف وعتبات التنبيه والحظر.
- `GET /api/v1/uba/users`: قائمة ملفات المستخدمين المرتبة حسب درجة الخطر.
- `GET /api/v1/uba/users/{username}`: جلب الملف السلوكي الكامل لمستخدم محدد والسجل الإحصائي.
- `DELETE /api/v1/uba/users/{username}/reset`: مسفر وإعادة ضبط خط الأساس السلوكي لمستخدم (Admin Only).
- `GET /api/v1/uba/events`: جلب الأحداث السلوكية المحللة مفلترة ومقسمة صفحات.
- `GET /api/v1/uba/alerts`: الأحداث ذات التهديد العالي أو الحرج فقط.
- `POST /api/v1/uba/events`: إرسال حدث سلوكي يدوياً للتحليل.

---

## 6. مثال كود كامل وجاهز للاستخدام (Complete Python Code)

```python
import time
import logging
from system.core.framework.plugin_base import InspectionContext, InspectionAction
from modules.uba.engine.core.uba_plugin import UBAPlugin

logging.basicConfig(level=logging.INFO)

def run_uba_demo():
    # 1. إعداد إضافة UBA
    uba_plugin = UBAPlugin()
    
    # 2. إنشاء سياق اتصال
    ctx = InspectionContext(
        src_ip="192.168.1.150",
        dst_ip="10.0.0.1",
        src_port=49888,
        dst_port=3389, # RDP Service (Privileged)
        protocol="TCP",
        direction="inbound",
        timestamp=time.time()
    )
    ctx.metadata = {
        "username": "user_test",
        "bytes_transferred": 12500000.0, # 12.5 MB exfiltration attempt
        "session_duration": 45.0,
        "peer_group": "Sales"
    }

    # 3. تشغيل التحليل السلوكي
    result = uba_plugin.inspect(ctx)

    # 4. معالجة النتيجة والتصرف
    print("\n" + "="*50)
    print(f"=== [UBA Verdict] Action: {result.action.name} ===")
    print("="*50)

    uba_info = result.metadata.get("uba", {})
    print(f"اسم المستخدم: {uba_info.get('username')}")
    print(f"درجة الخطر التراكمية: {uba_info.get('risk_score')}/100")
    print(f"مستوى الخطر: {uba_info.get('risk_level')}")
    print(f"درجة شذوذ الحدث: {uba_info.get('anomaly_score')}")

    if result.findings:
        print("\n--- الكواشف المثارة ---")
        for finding in result.findings:
            print(f"[{finding.severity}] {finding.description}")

    if result.action == InspectionAction.BLOCK:
        print("\n🛑 تم حجب المستخدم وإلغاء الجلسة فوراً!")
    elif result.action == InspectionAction.REDIRECT_DECOY:
        print("\n🪤 تم تحويل الاتصال إلى متاهة الخداع التنكرية (Labyrinth)!")

if __name__ == "__main__":
    run_uba_demo()
```

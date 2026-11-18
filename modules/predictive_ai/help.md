# دليل المبرمج لاستخدام وحدة الذكاء الاصطناعي الاستباقي (Predictive AI / AEGIS Module Guide)

تعتبر وحدة **`predictive_ai`** المحرك الاستباقي الذكي (AEGIS v3 / ) في جدار الحماية BunyanX NGFW.
يقوم هذا الدليل بشرح المعمارية العامة، كيفية استدعاء واستخدام الوحدة في أي مكان بالمنظومة، البيانات التي تستقبلها، والمخرجات التي ترجعها **دون الحاجة لإعادة قراءة الكود**.

---

## 1. نظرة عامة على المعمارية (Architecture Overview)

تتكون الوحدة من مرحلتين رئيسيتين لحماية المنظومة:

```
[ المرحلة 1: TPE - Threat Probability Engine ]
  │  تقييم سياقي استباقي لمستوى الخطر قبل وقوع أي هجوم (مبني على القطاع، المنطقة الجغرافية، والثغرات)
  ▼
[ المرحلة 2: AEGIS Adaptive Defense Engine ]
  │  استجابة ديناميكية متكيفة مع الهجمات الحية في وقت الحدوث (Closed-Loop Pipeline)
  ├── 1. ASE  : مقدر الحالة البايزي (Bayesian Belief Tracking over 8 MITRE UKC Stages)
  ├── 2. AIS  : محاكي النية العدائية (Transformer-based TTP Prediction)
  ├── 3. CSO  : محسن الاستراتيجية المضادة (Nash-Optimal Minimax Countermeasure)
  ├── 4. UEBA : بوابة فحص السلوكيات وتقليل الإنذارات الكاذبة (Behavioral Verification)
  ├── 5. DIE  : محرك حقن مصائد الخداع الديناميكية (Dynamic Honeypot Injection)
  └── 6. GNN  : محرك التنبؤ بالتحركات الجانبية (GraphSAGE Lateral Movement Predictor)
```

---

## 2. طرق استدعاء الوحدة في الكود (Integration Methods)

يمكنك استدعاء الوحدة بأحد ثلاث طرق حسب مكان وحاجة الكود:

### الطريقة الأولى: من خلال `ServiceContainer` (الموصى بها داخل المحرك)

عند تشغيل جدار الحماية، تسجل الوحدة خدماتها تلقائياً في حاوي الخدمات:

```python
from system.core.service_container import ServiceContainer

# 1. الحصول على محرك AEGIS الرئيسي
AEGIS_engine = ServiceContainer.get_optional('AEGIS_engine')

# 2. الحصول على محرك الارتباط التنبؤي (Event Sink Bridge)
correlator = ServiceContainer.get_optional('predictive_correlator')

# 3. الحصول على نظام التقييم الاستباقي ذو المرحلتين
two_stage_system = ServiceContainer.get_optional('two_stage_system')
```

---

### الطريقة الثانية: الاستيراد المباشر (Direct Import)

يمكنك استيراد المحركات واستخدامها مباشرة في أي كود Python:

```python
from modules.predictive_ai.engine import (
    AEGISEngine,
    TwoStageDefenseSystem,
    PredictiveCorrelationEngine,
    create_from_config,
)

# إنشاء كائن AEGISEngine جديد
AEGIS = AEGISEngine(
    ase_max_tracked_ips=4096,
    die_decoy_subnet="10.99.88.",
    die_max_decoys=256
)
```

---

## 3. المدخلات التي تستقبلها الوحدة (Module Inputs)

### أ. أحداث الأمان الحية (Security Events)

تستقبل الوحدة الأحداث من الفلاتر أو المحركات الأخرى عبر `process_event`:

| اسم الحقل | النوع | الوصف | مثال |
| --- | --- | --- | --- |
| `src_ip` / `source_ip` | `str` | عنوان IP للمصدر المشتبه به | `"192.168.1.100"` |
| `event_type` / `ml_label` | `str` | نوع الحدث الأمني المكتشف | `"WAF_EXPLOIT"`, `"SCAN"`, `"MALWARE"`, `"DGA_C2"`, `"PRIV_ESC"`, `"LATERAL"`, `"DLP_EXFIL"`, `"RANSOMWARE"`, `"PERSISTENCE"` |
| `bytes_transferred` | `int` | حجم البيانات المنقولة (اختياري لـ UEBA) | `1048576` |
| `dst_ip` | `str` | عنوان IP للهدف (اختياري لـ GNN/UEBA) | `"10.0.0.5"` |
| `protocol` | `str` | بروتوكول الاتصال (اختياري) | `"SMB"`, `"HTTPS"` |

---

### ب. طلبات التقييم الاستباقي (TPE Threat Assessment)

تستقبل الوحدة الملف التوصيفي للمؤسسة `OrganizationProfile`:

```python
from modules.predictive_ai.engine.tpe.risk_context import (
    OrganizationProfile, OrgSector, GeopoliticalZone, OrgSize,
    VulnerabilityContext, HistoricalBreachRecord
)

profile = OrganizationProfile(
    name="Bank Al-Hazm",
    sector=OrgSector.BANKING,             # BANKING, GOVERNMENT, HEALTHCARE, ENERGY, TECH, etc.
    geo_zone=GeopoliticalZone.HIGH_TENSION, # WAR_ZONE, HIGH_TENSION, MODERATE, STABLE
    size=OrgSize.ENTERPRISE,
    vuln_context=VulnerabilityContext(
        avg_epss=0.15,                     # متوسط درجة EPSS [0.0 - 1.0]
        max_cvss=9.8,                      # أعلى درجة CVSS غير مصلحة
        num_critical_vulns=2,              # عدد الثغرات الحرجة
        internet_exposed_assets=45,        # عدد الخدمات المواجهة للإنترنت
        days_since_last_patch=45,          # عدد الأيام منذ آخر تحديث
    ),
    breach_history=HistoricalBreachRecord(
        breaches_last_12m=1,
        ransomware_history=False,
    )
)
```

---

## 4. المخرجات التي ترجعها الوحدة (Module Outputs)

### أ. نتيجة معالجة الحدث (`AEGISResult`)

عند الاستجابة لحدث، ترجع الوحدة كائن `AEGISResult` يحتوي على:

```python
result = AEGIS.process_event("192.168.1.100", "WAF_EXPLOIT")

# 1. الاستراتيجية الدفاعية الموصى بها (CounterStrategy)
print(result.counter_strategy.action)          # مثال: "HONEYPOT_REDIRECT"
print(result.counter_strategy.explanation)     # تبرير القرار العلمي
print(result.counter_strategy.expected_disruption) # نسبة تعطيل الهجوم [0.0 - 1.0]
print(result.counter_strategy.escalation_risk)    # مخاطرة تصعيد المهاجم

# 2. حالة الاعتقاد البايزية (BeliefState)
print(result.belief_state.most_likely_stage)   # مرحلة الهجوم الحالية (مثل "INITIAL_ACCESS")
print(result.belief_state.stage_certainty)     # درجة اليقين [0.0 - 1.0]
print(result.belief_state.entropy)             # درجة الشك (Entropy بالـ Bits)

# 3. قائمة التكتيكات المتوقعة القادمة (TTP Distributions)
for pred in result.ttp_distribution[:3]:
    print(f"Next TTP: {pred.ttp} (Prob: {pred.probability:.2%})")

# 4. توجيهات مصيدة الخداع (DecoyDirective) - إن وجدت
if result.decoy_directive:
    print(f"Redirect to Honeypot: {result.decoy_directive.redirect_to}")

# 5. قرار بوابة السلوكيات (UEBADecision)
if result.ueba_decision:
    print(f"UEBA Verdict: {result.ueba_decision.verdict}") # OVERRIDE, CONFIRM, ESCALATE
```

---

### ب. الإجراءات الدفاعية الـ 12 المتاحة (`DEFENDER_ACTIONS`)

القرارات التي قد ترجعها الوحدة في `counter_strategy.action`:

1. **`MONITOR`**: مراقبة هادئة بدون أي إعاقة.
2. **`DECOY_TRAP`**: نشر فخ خداع على مسار الهجوم.
3. **`ISOLATE_PARTIAL`**: عزل جزئي لحظر مسارات التحرك الجانبي.
4. **`HONEYPOT_REDIRECT`**: إعادة توجيه اتصالات المهاجم إلى مصيدة وهمية.
5. **`RATE_LIMIT`**: تقييد معدل الاتصالات (QoS).
6. **`KILL_SESSIONS`**: إنهاء الجلسات النشطة فوراً.
7. **`ISOLATE_FULL`**: عزل شبكي كامل للهدف.
8. **`CREDENTIAL_ROTATE`**: إجبار تغيير وتدوير بيانات الاعتماد.
9. **`FAKE_PATCH`**: إرسال استجابة وهمية تبين نجاح الترقيع لاستدراج المهاجم.
10. **`ALERT_ONLY`**: إرسال تنبيه لمحلل الـ SOC فقط.
11. **`BLOCK_IP`**: حظر الـ IP بشكل كامل في جدار الحماية (eBPF XDP).
12. **`EMERGENCY_ISOLATE`**: عزل طارئ شامل للمضيف.

---

## 5. أمثلة عملية للاستخدام (Code Examples)

### مثال 1: معالجة حدث أمني مباشر من أي موديل آخر (مثل WAF أو IDS)

```python
import asyncio
from system.core.service_container import ServiceContainer

async def handle_security_alert(src_ip: str, alert_type: str):
    correlator = ServiceContainer.get_optional('predictive_correlator')
    if correlator:
        # إرسال الحدث لمحرك AEGIS التنبؤي
        event = {
            "src_ip": src_ip,
            "event_type": alert_type, # مثلاً "WAF_EXPLOIT"
            "module": "waf"
        }
        await correlator.process_event(event)

# استدعاء
asyncio.run(handle_security_alert("198.51.100.45", "WAF_EXPLOIT"))
```

---

### مثال 2: استعلام عن حالة IP معين ورؤية التنبؤ بنواياه (Attacker Intent)

```python
from system.core.service_container import ServiceContainer

AEGIS = ServiceContainer.get_optional('AEGIS_engine')

if AEGIS:
    # 1. جلب الاعتقاد البايزي لـ IP معين
    belief = AEGIS.get_belief("198.51.100.45")
    if belief:
        print(f"IP: 198.51.100.45")
        print(f"Current Stage: {belief['most_likely_stage']}")
        print(f"Certainty: {belief['stage_certainty']}")

    # 2. جلب الخطة الدفاعية المتوقعة
    strategy = AEGIS.get_counter_strategy("198.51.100.45")
    if strategy:
        print(f"Recommended Action: {strategy['action']}")
        print(f"Explanation: {strategy['explanation']}")
```

---

### مثال 3: تقييم الخطر الاستباقي لمؤسسة (TPE Stage 1)

```python
from modules.predictive_ai.engine.tpe.pre_armed_adapter import create_from_config

# 1. إنشاء النظام وتعديل ملف التقييم
system = create_from_config(
    sector="BANKING",
    geo_zone="WAR_ZONE",
    size="ENTERPRISE",
    avg_epss=0.20,
    max_cvss=9.1,
    critical_vulns=3
)

# 2. تشغيل التقييم الاستباقي
directive = system.run_stage1()

print(f"Threat Score: {directive.threat_score}")     # درجة الخطر Composite Risk [0.0 - 1.0]
print(f"Risk Level: {directive.risk_level}")         # HIGH / MEDIUM / LOW
print(f"Likely Actor: {directive.most_likely_actor}")# المهاجم المتوقع
print(f"Pre-arm AEGIS: {directive.pre_armed}")      # هل ينصح بخفض العتبات الدفاعية؟
```

---

### مثال 4: إرسال تغذية راجعة من المحلل (Analyst Feedback Loop)

```python
from system.core.service_container import ServiceContainer

AEGIS = ServiceContainer.get_optional('AEGIS_engine')

if AEGIS:
    # تسديد التغذية الراجعة بعد انتهاء التحقيق لتدريب النموذج
    AEGIS.record_actual_ttp(
        src_ip="198.51.100.45",
        stage_name="INITIAL_ACCESS",
        actual_ttp="WAF_EXPLOIT",
        predicted_top_ttp="WAF_EXPLOIT"
    )

    # تصفير حالة المهاجم بعد إتمام عزل الـ IP
    AEGIS.reset_attacker("198.51.100.45")
```

---

## 6. واجهات الـ REST API المتاحة للواجهات الأمامية (REST API Routes)

تتيح الوحدة الموجه `/api/v1/ai` بجميع النقاط التالية:

- **`GET /api/v1/ai/config`**: جلب التكوين الحالي للمحركات.
- **`PUT /api/v1/ai/config`**: تحديث التكوين والتفعيلات.
- **`GET /api/v1/ai/intent/active`**: جلب كل الـ IPs النشطة والتنبؤ بخطواتها القادمة.
- **`GET /api/v1/ai/AEGIS/belief/{src_ip}`**: جلب التوزيع الاحتمالي لـ IP.
- **`GET /api/v1/ai/AEGIS/decisions`**: سجل آخر القرارات المتخذة من AEGIS.
- **`GET /api/v1/ai/AEGIS/deception/active`**: المصائد الحالية النشطة في الشبكة.
- **`POST /api/v1/ai/threat-assessment`**: إجراء تقييم استباقي TPE لحالة المؤسسة.
- **`POST /api/v1/ai/models/upload/{model_id}`**: رفع نموذج ذكاء اصطناعي جديد (بأقصى حجم 50 ميجابايت).

---

*دليل المبرمج - BunyanX NGFW Predictive AI Module (AEGIS v3 / )*

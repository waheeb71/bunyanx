# التوثيق الشامل لوحدة الذكاء الاصطناعي الاستباقي (AEGIS v3)

**bunyanx NGFW — Online Reasoning Anticipation Counter-attack Layer Engine**

---

## 1. المقدمة (Introduction)

تُمثل وحدة الذكاء الاصطناعي الاستباقي (Predictive AI) مكوناً مفصلياً ضمن نظام الجدار الناري المتقدم (Enterprise NGFW). تم بناء هذا القسم بالاعتماد على دراسة بحثية بعنوان **"AEGIS:A Deep Learning Framework for Multi-Stage Cyber Attack Prediction and Adversarial Intent Forecasting"** [1]، والتي اقترحت استخدام معمارية ثنائية المراحل تدمج بين التقييم الاحتمالي المسبق (Threat Probability Engine) والاستجابة التكيفية المغلقة (Adaptive Defense Engine). الهدف الأساسي من وجودها هو الانتقال بنظام الحماية من حالة "طردية رد الفعل" (Reactive) المخترقة بسهولة من قبل التهديدات المتقدمة (APTs)، إلى حالة "الدفاع الاستباقي" (Proactive) القائم على التنبؤ الرياضي والذكاء الاصطناعي العميق، متيحةً للنظام إحباط الهجوم قبل وقوعه. يُعد هذا التحول النموذجي الحل المباشر لمشكلة "الفجوة الاستراتيجية-التشغيلية" (Strategic-Operational Gap) المطروحة في §I.B من الورقة البحثية [1].

## 2. مسؤوليات الوحدة (Module Responsibilities)

تتحمل الوحدة العديد من المهام المعقدة داخل الجدار الناري، وتتبلور أهميتها في:

* **التنبؤ بالسلوكيات الهجومية (Threat Anticipation):** عبر قراءة سلاسل هجمات (TTPs) السابقة وتوقع الحركة القادمة للهاكر بناءً على شبكات (Transformer).
* **تقدير الحالة الاحتمالية (State Estimation):** نمذجة تحركات الهاكر المجهولة داخل إطار "سلسلة القتل" (Kill-Chain) باستخدام نظرية "بايز".
* **التخفيف الذكي ونظرية الألعاب (Game-Theoretic Mitigation):** الاستعاضة عن الحظر العشوائي بحلول تكتيكية مبنية على توازن ناش (Nash Equilibrium)، مثل تزييف التحديثات (Fake Patch) أو عزل الشبكات.
* **إدارة شبكات الخداع (Deception Injection):** توجيه المهاجمين آلياً وبطريقة شفافة من بيئة الإنتاج إلى مصائد استخباراتية محمية (Honeypots).

هذه الوظائف تعالج مشكلة جذرية في الجدران النارية التقليدية وهي: "العمى الافتراضي أمام الهجمات البطيئة الموزعة (Slow-and-Low APTs)".

## 3. التحليل (Module Analysis)

صُممت هذه الوحدة لتجاوز قيود الاستدلال المعتني بالقواعد الصلبة (Rule-based Heuristics). وكما أوضحت الورقة البحثية [1] في §I.C، فإن الأنظمة التقليدية تعاني من ثلاثة أنماط عمى كارثية: عمى المرحلة (Stage Blindness)، وعمى التوزيع (Distribution Blindness)، وعمى التصعيد (Escalation Blindness). هذه الوحدة صُممت خصيصاً لمعالجة هذه الأنماط الثلاثة.

* **المدخلات الأساسية:**
  * `src_ip`: عنوان بروتوكول الإنترنت للمهاجم.
  * `event_type`: تصنيف السلوك المكتشف (مثال: محاولة استغلال WAF).
  * بيانات تعريفية كسجل الجلسة وحجم تدفق البيانات لدعم نظام (UEBA).
* **المخرجات الأساسية:**
  * `AEGISResult`: كائن بياني يحتوي على الموقف التكتيكي (CounterStrategy)، والتوجيهات التشغيلية للمرحلة المتقدمة مثل توجيهات الخداع الذكي (DecoyDirective).

### النمذجة الرياضية لتقييم الاحتمالية (TPE)

استناداً إلى الجزء (§IV.A) من الورقة البحثية، يقيس النظام احتمالية الهجوم (ThreatScore) كمركب رياضي من 6 عوامل خطر، تُحسب كالآتي:
$$ \hat{p} = \sum_{i=1}^{6} \alpha_i P_i, \quad \text{with } \sum \alpha_i = 1 $$

حيث تبرز أهمية المُعامل الجيوسياسي الذي يصيغ تمدد الصراع عبر التابع الأُسيّ:
$$ P_2 = 1 - e^{-k \cdot P_1 \cdot \mu(g)} $$

* **القيود والافتراضات (مُستمدة من §III في الورقة البحثية [1]):**
  * يُفترض أن المهاجم عقلاني بدرجة محدودة (Bounded Rationality) ومُنمذج وفق توزيع بولتزمان بمعامل حرارة τ=0.50.
  * لا تحلل الوحدة المحتوى المُعمى (TLS Payloads) بل تعتمد كليةً على السلوك والبيانات الوصفية للطبقات العلوية (L4-L7 Metadata).
  * يُستثنى من نطاق التحليل: الهجمات الفيزيائية، والهندسة الاجتماعية ما بعد التسليم الأولي، وثغرات (Zero-day) على مستوى النواة.

## 4. التصميم (Design)

تم هيكلة الوحدة بناءً على نمط "التصميم الموجه بالمجالات" (Domain-Driven Design). يتطابق التصميم الداخلي مع المعمارية المقترحة في §IV من الورقة البحثية [1]، والتي تصف خمس طبقات دفاعية متسلسلة (ASE → AIS → CSO → UEBA → DIE). تنقسم الوحدة هندسياً إلى عدة طبقات منفصلة ومنطقية:

![Design](Design.png)

### الأساس الرياضي للمحرك المُحسن (Layer 3 CSO)

يتميز هذا التصميم عن الجدران النارية التقليدية باعتماده نظرية الألعاب لتوليد استجابة غير تصعيدية. كما صيغت الدالة الموضوعية في الورقة البحثية [1]:
$$ a_D^* = \arg\max_{a_D \in \mathcal{A}_D} \underbrace{\mathbb{E}_{\Pi_A}[U(a_D, a_A)]}_{\text{المنفعة المتوقعة}} - \underbrace{\lambda \cdot ER(a_D, \Pi_A)}_{\text{عقوبة خطر التصعيد}} $$

وفي طبقة التنبؤ (AIS) يستعين بمزيج رياضي بين الذاكرة طويلة المدى و(Q-Table) باستخدام التعلم المعزز المباشر `TD(λ)`:
$$ Q(s,a) \leftarrow Q(s,a) + \eta \cdot \delta \cdot e(s,a) $$

## 5. آلية العمل (Workflow)

يتسلسل تدفق البيانات داخل محرك AEGIS عند وصول استشعار بهجوم عبر الخطوات الدقيقة التالية. تتوافق هذه الآلية مع مفهوم الدالة الموضوعية (Objective Function) المقدمة في §IV.B (Layer 3) من الورقة البحثية [1]، والتي تُعرّف بالصيغة: `a*_D = argmax E[U] − λ·ER`.

![Workflow](Workflow.png)

## 6. الإعدادات والتكوين (Configuration)

يتم التحكم بديناميكية النظام عبر ملف `config/settings.yaml`، والذي يحتوي على:

* `tpe.thresholds.pre_arm_trigger` (0.65): عتبة الاحتمالية التي يتم عندها تسليح الجدار الناري قبل الهجوم.
* `AEGIS.cso_weights.lambda_escalation` (2.0): معامل رياضي يُقيم درجة الخوف من تصعيد المهاجم. خفض هذا الرقم يزيد من تهور النظام (Aggressiveness).
* `AEGIS.sensitivity.normal_threshold` (0.55): عتبة التدخل الدفاعي المعتاد. صُممت للحفاظ على معدل الإيجابيات الكاذبة (False Positives) عند 0%.

## 7. هيكل الملفات (File Structure)

تمت ترقية هيكلية النظام لتوافق المعايير المؤسسية وفصل المجالات (Separation of Concerns):
![project_structure](project_structure.png)

## 8. التكامل مع باقي النظام (Integration)

تتفاعل هذه الوحدة مع الجدار الناري المركزي كـ "صندوق أسود ذكي" (Black-Box Interface). يتواصل الجدار الناري مع الوحدة حصرياً عبر `__init__.py` العام للوحدة من خلال `AEGISEngine`.

* **تدفق البيانات الآني:** أي وحدة كشف (Snort / WAF / DPI) في الجدار الناري تلتقط إشارة، تُرسل الـ Payload مباشرة إلى دالة `process_event`.
* **الشفافية الهندسية:** لا تهتم التحديثات الداخلية للوحدة (مثل تغيير بنية المجلدات) بالأنظمة الخارجية nhờ اعتماد نمط الـ `Facade`.

## 9. الاختبارات (Testing)

تم توثيق استقرار الوحدة وفعاليتها رياضياً عبر إجراءات صارمة، وتتوافق نتائج الاختبارات مع الأرقام المنشورة في §V من الورقة البحثية [1]:

* **Unit Tests:** شاملة تغطي كل الطبقات (`tests/AEGIS/*`) واجتازت 125 اختباراً بنجاح 100%.
* **Integration Tests (AEGISBench-v3):** إطار محاكاة يشمل هجمات مركبة حقيقية (APT29) وتقييم استجابة الوحدة دون مساس بحركة المرور السليمة. يتكون من 17 سيناريو هجومي و5 سيناريوهات سلمية كما هو موضح في Table II من الورقة [1].
* **مؤشرات الأداء (مُوثقة في Table VI من الورقة [1]):** دقة استهداف (Precision) بلغت 90.9%، ومعدل إحباط (Disruption Rate) تجاوز 58%، ومعدل تصعيد (Escalation Rate) بلغ 0.0%، مع زمن انتقال كلي (Latency) يقل عن `0.3ms`.

### توثيق النتائج بالرسوم البيانية (مأخوذة من الدراسة [1])

يقدم هذا الجزء دلائل صريحة على فعالية محركات الذكاء الاصطناعي:

**1. مصفوفة الارتباك للمحولات (Transformer Confusion Matrix)**
يُظهر الشكل قدرة المودل على تصنيف أنماط الهاكر بامتياز بدقة دياجونالية (مائل) عالية جدًا.
![Confusion Matrix](fig1_confusion_matrix.png)

**2. منحنى الأداء (ROC Curves)**
يتفوق النظام بعامل امتياز (AUC = 0.907)، ويُظهر منطقة العمليات المثلى بأقل من 5% محاولات كاذبة (FPR).
![ROC Curve](fig2_roc_curve.png)

**3. أوزان شبكة الانتباه (Self-Attention Heatmaps)**
دليل ملموس على قدرة (Transformer) على كشف الروابط المعقدة عبر هجمات تبعد مئات الثواني عن بعضها عبر معالجتها في 4 رؤوس انتباه (Heads).
![Attention Weights](fig4_attention_weights.png)

**4. دراسة تأثير الانعزال (Ablation Study)**
يوضح قوة خوارزمية (CSO + UEBA) وكيف أن غيابهما كان دمر معدل دقة الاستجابة.
![Ablation Study](fig3_ablation_study.png)

## 10. التحديات والحلول (Challenges & Solutions)

1. **تلاشي التدرج وانعدام الذاكرة للمستقبل البعيد بسب استخدام (LSTM):** تم حل هذه المشكلة باستبدال النموذج جذرياً والانتقال إلى هيكلية **Transformer Predictor**، مما وفر رؤية واضحة للارتباطات المتباعدة في سلسلة الهجوم ورفع الدقة لـ >90%.
2. **تبعية التصنيف الخاطئ (False Positives Cascades):** تم حلها رياضياً بتطبيق نظرية توازن ناش من خلال الـ `CounterStrategyOptimizer` وإلحاقه بقالب `UEBAVerifier` لتحييد الشذوذ غير المستهدف.

## 11. التحليل الأمني (Threat Model)

* **الحقن المتعمد (Adversarial Concept Drift):** يمكن للمهاجم تعمد تشتيت خوارزمية التعلم الحي `OnlineLearner` عبر إرسال سلوكيات متقطعة وعشوائية لتسميم جدول الـ Q-Table. أُضيف معامل تبريد (Temperature Annealing) واضمحلال (Eligibility Traces) للحد من التعديلات الحادة ومنع تسمم النموذج.
* **إجهاد الموارد (Resource Exhaustion):** لحماية مصفوفة التتبع الحية (`ASE`) من امتلاء الذاكرة خلال هجمات الحرمان من الخدمة (DDoS)، تمت برمجة آلية طرد تلقائي (LRU Cache) تمسح الحالات المتوقفة عن النشاط.

## 12. الخلاصة (Conclusion)

تعد وحدة AEGIS v3 نقلة نوعية في علم الدفاع السيبراني للمؤسسات. لم تتأسس هذه الوحدة على مجرد شروط شرطية صماء، بل بُنيت ككائن معرفي يمتلك "قناعة بايزية" بوضع الهاكر وقوة "رؤية المحولات" للتنبؤ بتحركاته. أثبتت الاختبارات إمكانية تحويل مسار الهاكر الخبيث بسلاسة تامة إلى شبكة سراب (Honeypot Decoy) خلال مللي ثانية واحدة فقط، مؤسسةً بذلك جيلاً جديداً من الجدران النارية القائمة على "الردع الذاتي والتكيف المستمر". وكما لخّصت الورقة البحثية المرجعية [1] في §VII: **"دقة الأمن تتطلب سياقاً"** — فالنظام الذي يتعامل مع بنك مركزي في منطقة نزاع بنفس حساسية متجر صغير في بيئة مستقرة، يعمل بطبيعته دون طاقاته الكاملة.

---

## 13. المراجع (References)

| # | المرجع |
| :---: | :--- |
| [1] | W. Al-Humayri and M. Altamimi, **"AEGIS:A Deep Learning Framework for Multi-Stage Cyber Attack Prediction and Adversarial Intent Forecasting,"** Dept. of Cybersecurity, The National University, Taiz, Yemen & Dept. of Computer Engineering, Karabuk University, Turkey. *المخطوطة الكاملة متاحة في:* [`AEGIS_paper_final.md`](./AEGIS_paper_final.md) |
| [2] | A. Vaswani *et al.*, "Attention Is All You Need," in *Proc. NeurIPS*, Long Beach, CA, USA, 2017, pp. 5998–6008. |
| [3] | E. M. Hutchins, M. J. Cloppert, and R. M. Amin, "Intelligence-driven computer network defense informed by analysis of adversary campaigns and intrusion kill chains," in *Proc. 6th Int. Conf. Information Warfare and Security (ICIW)*, Washington, DC, USA, 2011, pp. 113–125. |
| [4] | B. E. Strom *et al.*, "MITRE ATT&CK: Design and philosophy," MITRE Corporation, Tech. Rep., 2018. |
| [5] | I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward generating a new intrusion detection dataset and intrusion traffic characterization," in *Proc. 4th Int. Conf. ICISSP*, Madeira, Portugal, 2018, pp. 108–116. |
| [6] | K. Lye and J. M. Wing, "Game strategies in network security," *Int. J. Information Security*, vol. 4, no. 1-2, pp. 71–86, 2005. |
| [7] | Verizon Communications, "Data Breach Investigations Report 2024," Tech. Rep., May 2024. |
| [8] | Mandiant, "M-Trends 2024: Special Report," Google Cloud / Mandiant Corp., Tech. Rep., Apr. 2024. |

# 1. Executive Technology Summary

يمثل مشروع **BUNYANX (Enterprise Next-Generation Firewall & Proactive Defense System)** منظومة أمن سيبراني متقدمة ومتكاملة لحماية الشبكات ومراكز البيانات. تم بناء النظام وفق معمارية برمجية هجينة ونظيفة (Clean Modular Architecture & Micro-Engines) تعتمد على معالجة تدفقات البيانات والشبكات في الوقت الحقيقي (Real-Time Async Processing)، والتحليل الاستباقي المدعوم بنماذج الذكاء الاصطناعي (AI/ML) ونظرية الألعاب (Game Theory)، مع تسريع النواة عبر تقنيات **eBPF/XDP** ونظام ترشيح الحزم المباشر **nftables**.

تتوزع بنية المشروع على طبقات تقنية متماسكة تشمل:
1. **واجهة إدارة وتحكم متطورة (SOC Web-UI)** مبنية على **React 19** و **Vite** و **Three.js / Globe.gl** مع لوحات تحكم وتنبيهات صوتية فورية (**CVAS**).
2. **محرك خلفي وبوابة برمجية (Async Core & REST/WebSocket API)** قائمة على **FastAPI**، **Python 3.10+**، وخادم **Uvicorn ASGI**.
3. **طبقة قواعد بيانات مزدوجة النواة (Dual-Engine ORM)** تعتمد **SQLAlchemy 2.0 (Async/Sync)** مع دعم **SQLite (aiosqlite/WAL)** للتطوير والأجهزة المدمجة، و **PostgreSQL (asyncpg)** للإنتاج.
4. **17 وحدة أمنية تخصصية (Security Modules)** تغطي: الجدار الناري، كشف ومنع التسلل الهجين (PHANTOM IDS/IPS)، جدار حماية تطبيقات الويب (WAF)، منع تسريب البيانات متعدد الإشارات (MSEM-Lite DLP)، أمن البريد الموجه بالذكاء اللغوي (VSDE/PLSF Email Security)، أمن خوادم DNS التكيفي (DART)، فحص التشفير وحوض الشهادات (SSL/TLS CA Pool)، ونظام الدفاع الاستباقي التنبؤي (AEGIS / ORACLE).
5. **ناقل أحداث موزع (Event Bus)** يدعم نمط الذاكرة المشتركة ونمط **NATS JetStream** مع طوابير الرسائل الميتة (DLQ).

---

# 2. Programming Languages

| اللغة (Language) | نطاق الاستخدام في المشروع (Usage Scope) | الدور الرئيسي (Main Role) | دليل التحقق البرمجي (Verification Evidence) | الوصف الأكاديمي للغة (Brief Academic Description) |
|---|---|---|---|---|
| **Python** | النواة الخلفية، المحركات الأمنية، الذكاء الاصطناعي، الواجهات البرمجية | لغة المعالجة المركزية، بناء خوادم API، التحليل الإحصائي ونماذج التعلم الآلي، إدارة السياسات، واجهات CLI | `main.py`, `api/main.py`, `system/`, `modules/*/engine/` | لغة برمجة عالية المستوى ومتعددة الأنماط، تتميز بثرائها بالمكتبات المتخصصة في الذكاء الاصطناعي والشبكات وقدراتها العالية في المعالجة غير المتزامنة (`asyncio`). |
| **JavaScript / JSX** | واجهة المستخدم الرسومية (Web-UI) | بناء الواجهات التفاعلية، إدارة الحالة، الرسم ثلاثي الأبعاد للكرة الأرضية، الاتصال بـ WebSockets | `web-ui/src/App.jsx`, `web-ui/src/modules/globe/`, `web-ui/src/services/` | لغة برمجة نصية قياسية لتطوير واجهات الويب التفاعلية، توفر معيار ECMAScript الحديث مع JSX لبناء شجرة العناصر الافتراضية. |
| **C** | طبقة تسريع النواة ونظام eBPF / XDP | معالجة الحزم على مستوى النواة (Kernel Space)، ترشيح المنافذ، موازنة الأحمال L4، بروكسي SYN | `acceleration/ebpf/pipeline/dispatcher.c`, `port_filter.c`, `stage_conntrack.c` | لغة برمجة نظامية منخفضة المستوى عالية الكفاءة والسرعة، تُستخدم لكتابة برمجيات النواة وبرامج eBPF المجمعة إلى كود بايت bytecode. |
| **CSS (Vanilla CSS)** | التصميم وتنسيق الواجهات | بناء نظام التصميم (Design Tokens)، التنسيق الشبكي Flex/Grid، الرسوم المتحركة، الثيمات المظلمة | `web-ui/src/styles/tokens.css`, `shared.css`, `GlobeThreatMap.css` | لغة تنسيق صفحات الويب القياسية، استُخدمت بنظام المتغيرات الصرفة (CSS Variables) لعزل التصميم وتوفير أعلى كفاءة تحميل. |
| **HTML / HTML5** | هيكل صفحات الويب والتوثيق التفاعلي | نقطة دخول الواجهة، قوالب بوابات المصادقة (Captive Portal)، ملفات التوثيق التنفيذية | `web-ui/index.html`, `final_master_documentation.html` | لغة ترميز وتوصيف النصوص التشعبية القياسية لهيكلة صفحات الويب وتضمين المكونات الوسائطية. |
| **Bash / Shell Scripting** | نصوص التثبيت والتشغيل على بيئات Linux | إعداد بيئة الخادم، تشغيل خدمات النظام، ضبط الصوت والاعتماديات، نصوص التحديث | `install.sh`, `scripts/install_audio.sh`, `system/networking/appliance/os_init/appliance_boot.sh` | لغة أوامر نصية مخصصة لأتمتة مهام إدارة وتشغيل خوادم وبيئات تشغيل Linux/Unix. |
| **Batch Script (.bat)** | أدوات التثبيت والاختبار على بيئة Windows | أتمتة تشغيل بيئة الاختبار والتحقق من التبعيات محلياً | `install.bat` | لغة أوامر سطرية مخصصة لنظام التشغيل Microsoft Windows لتنفيذ مهام الإعداد الآلي. |
| **SQL** | تعريف قواعد البيانات ونماذج الاستعلام | إدارة الجداول، تهيئة المعاملات، تتبع سجلات التدقيق والمستخدمين والسياسات | `system/database/database.py`, `system/database/migrations/` | اللغة القياسية المهيكلة لإدارة واستعلام قواعد البيانات العلاقية وإجراء عمليات CRUD وتطبيق المفاتيح الخارجية. |
| **YAML** | ملفات التهيئة والسياسات الأمنية | تعريف إعدادات النظام، أعلام الميزات (Feature Flags)، قواعد Prometheus، سجلات الوحدات | `system/config/base.yaml`, `modules/*/manifest.yaml`, `system/telemetry/prometheus.yml` | لغة تسلسل بيانات مقروءة بشرياً شائعة الاستخدام في تهيئة الأنظمة المعقدة وإدارة السياسات وقواعد التكوين. |

---

# 3. Frontend Technologies

| التقنية (Technology) | الاستخدام الفعلي في المشروع (Actual Usage) | الغرض الهندسي (Purpose) | دليل التحقق البرمجي (Evidence from Code) | حالة التحقق |
|---|---|---|---|---|
| **React 19 (v19.2.4)** | إطار عمل الواجهة الأساسي | بناء شجرة المكونات الرسومية، إدارة دورة حياة الصفحات والوحدات | `web-ui/package.json`, `web-ui/src/main.jsx` | Verified |
| **Vite (v8.0.0)** | أداة البناء وخادم التطوير السريع | تجميع حزم الويب بنظام ES Modules السريع والـ Hot Module Replacement | `web-ui/vite.config.js`, `package.json` | Verified |
| **Three.js (v0.183.2)** | الرندرة ثلاثية الأبعاد (3D Rendering) | بناء مجسم الكرة الأرضية التفاعلي ثلاثي الأبعاد وتحديد إحداثيات الهجمات الجغرافية | `web-ui/src/modules/globe/components/GlobeCanvas.jsx` | Verified |
| **Globe.gl (v2.45.1)** | محرك عرض التهديدات الجغرافية | رسم مسارات وأقواس الهجمات السيبرانية الحية حول العالم وتحديد الدول المستهدفة | `web-ui/src/modules/dashboard/components/AttackGlobe.jsx`, `ChartKit.jsx` | Verified |
| **Recharts (v3.8.0)** | مكتبة الرسوم البيانية التفاعلية | رسم منحنيات تدفق البيانات، مخططات الرادار للأمان، ومخططات توزيع الهجمات | `CategoryThreatChart.jsx`, `TrafficChart.jsx`, `AlertsTrendArea.jsx` | Verified |
| **Framer Motion (v12.36.0)** | محرك الرسوم والمؤثرات الحركية | تطبيق الانتقالات السلسة، النوافذ المنبثقة، تأثيرات الظهور والتلاشي للبطاقات | `modules/firewall/Firewall.jsx`, `modules/waf/WAF.jsx`, `Shared.jsx` | Verified |
| **Lucide React (v0.577.0)** | مكتبة الأيقونات المتجهة | توفير الأيقونات التقنية المتناسقة لجميع الوحدات الأمنية والأزرار وحالات النظام | مستخدمة في أكثر من 40 ملفاً مثل `GlobeThreatMap.jsx`, `App.jsx` | Verified |
| **Zustand (v5.0.11)** | إدارة الحالة المركزية (State Management) | إدارة حالات التنبيهات الفورية، تدفق الهجمات المباشر، وتخزين إعدادات العرض | `web-ui/src/stores/alertStore.js`, `firewallStore.js`, `liveFeedStore.js` | Verified |
| **@tanstack/react-query (v5.90.21)**| إدارة جلب البيانات والتخزين المؤقت | جدولة استدعاءات REST API، التخزين المؤقت (Caching)، وإعادة الجلب التلقائي | `GlobeThreatMap.jsx`, `modules/dashboardpro/DashboardPro.jsx` | Verified |
| **Axios (v1.13.6)** | عميل استدعاء HTTP/REST | إرسال الطلبات إلى الخادم الخلفي، معالجة الـ Interceptors ورموز التوثيق JWT | `web-ui/src/services/apiClient.js`, `api.js` | Verified |
| **React Router DOM (v7.13.1)** | التوجيه بين الشاشات (Routing) | إدارة مسارات شاشات الوحدات الأمنية الـ 17 ولوحات التحكم بدون إعادة تحميل الصفحة | `web-ui/src/App.jsx` | Verified |
| **WebSockets (Native Browser API)**| الاتصال المباشر منخفض التأخير | استقبال تدفقات السجلات، التنبيهات الحية، وإحداثيات الهجمات الفورية من السيرفر | `web-ui/src/services/audioAlertService.js`, `liveFeedStore.js` | Verified |
| **Web Audio API (Native Browser API)**| نظام التنبيهات الصوتية للواجهة | تشغيل نغمات التنبيه الرادارية، تتبع الهجمات الحرجة صوتياً عبر المتصفح | `web-ui/src/services/AudioEngine.js` | Verified |
| **Deck.gl (@deck.gl/core, layers)**| مكتبة طبقات الخرائط | موجودة في `package.json` كاعتمادية إضافية وتم تفضيل Three.js/Globe.gl عليها في الرندرة | `package.json` | Dependency present but superseded by custom Three.js renderer |
| **D3 (v7.9.0)** | مكتبة معالجة البيانات والرسوم | موجودة في `package.json` ويتم استخدام مخرجاتها الرياضية عبر Recharts | `package.json` | Dependency present (used indirectly via Recharts) |

---

# 4. Backend Technologies

| التقنية (Technology) | الدور الفعلي في المشروع (Actual Role) | دليل التحقق البرمجي (Evidence from Code) | حالة التحقق |
|---|---|---|---|
| **Python (v3.10+)** | بيئة التشغيل الأساسية للنواة والخدمات ومحركات الأمان | كافة ملفات النواة `system/`, `modules/`, `api/` | Verified |
| **FastAPI (v0.104.0+)** | إطار العمل الرئيسي لبناء واجهة برمجة التطبيقات (Clean REST API) | `api/main.py`, `api/routers/v1/` | Verified |
| **Uvicorn (v0.24.0+)** | خادم ASGI عالي الأداء لتشغيل تطبيقات الويب غير المتزامنة | `main.py#L177`, `api/main.py#L309` | Verified |
| **Pydantic (v2.0+)** | التحقق من صحة البيانات (Data Validation) ونمذجة هياكل الطلبات والاستجابات | `api/core/schemas.py`, `system/events/schemas.py` | Verified |
| **Asyncio (Built-in Python)** | البرمجة غير المتزامنة ومعالجة المهام الخلفية المتزامنة والموازية | `system/core/engine.py`, `system/events/bus.py` | Verified |
| **FastAPI WebSockets** | توفير قنوات اتصال ثنائية الاتجاه للبث الحي للهجمات وسجلات النظام | `api/routers/v1/ws.py`, `api/websocket/background.py` | Verified |
| **SlowAPI (v0.1.9+)** | تحديد معدل استهلاك الـ API وحماية المداخل من هجمات الإغراق (Rate Limiting) | `api/main.py#L46`, `Limiter(200/minute)` | Verified |
| **PyJWT (v2.8.0+) & Bcrypt** | المصادقة القائمة على الرموز المشفرة (JWT) وتجزئة كلمات المرور بأمان | `api/core/auth.py`, `system/database/database.py` | Verified |
| **Cryptography (v41.0.0+)** | إدارة المفاتيح وتوليد شهادات SSL/TLS ديناميكياً وفك تشفير الجلسات | `modules/ssl_inspection/engine/ca_pool.py` | Verified |
| **Prometheus Client (v0.17.0+)** | تصدير مؤشرات الأداء الحيوية للنظام عند المسار `/metrics` | `system/telemetry/prometheus_exporter.py` | Verified |
| **Psutil (v5.9.0+)** | قراءة استهلاك الموارد المادية (CPU, RAM, Network I/O, Disks) لحظياً | `system/telemetry/health.py` | Verified |
| **PyYAML (v6.0+) & jsonschema** | قراءة ومطابقة ملفات التهيئة وضمان توافقها مع القوالب المحددة | `system/config/base.py`, `system/policy/` | Verified |
| **Rich (v13.0+) & Click** | تصميم سطر الأوامر (CLI) وتلوين سجلات الطرفية بشكل تفاعلي ومنظم | `main.py#L54`, `cli/ngfw_cli.py` | Verified |
| **NATS-Py (v2.6.0+)** | عميل ناقل الأحداث الموزع NATS JetStream للمعمارية الإنتاجية الموزعة | `system/events/bus.py#L163` (NATSBackend) | Verified |

---

# 5. Database Technologies

| المكون التقني (Component) | التقنية الفعلية المستخدمة (Actual Technology) | الغرض والدور في النظام (Role & Purpose) | دليل التحقق البرمجي (Evidence) |
|---|---|---|---|
| **Database Engine (Dev / Appliance)** | **SQLite 3** مع تفعيل وضع **WAL** (Write-Ahead Logging) والمفاتيح الخارجية | تخزين إعدادات النظام والمستخدمين والسياسات وسجلات التدريب للأجهزة المدمجة وبيئات التطوير بدون خادم خارجي | `system/database/database.py#L626` (`PRAGMA journal_mode=WAL`, `foreign_keys=ON`) |
| **Database Engine (Production)** | **PostgreSQL** (عبر مشغل `asyncpg` و `psycopg2`) | تخزين ملايين الأحداث والسجلات والعمليات متعددة الخيوط في البيئات المؤسسية الكبرى | `system/database/database.py#L556` (`postgresql+asyncpg://`) |
| **Database ORM** | **SQLAlchemy 2.0 (Dual-Engine: Async + Sync)** | الربط الكائني العلائقي المزدوج، يوفر جلسات غير متزامنة لـ FastAPI وجلسات متزامنة للنواة الخلفية | `system/database/database.py#L26` (`create_async_engine`, `create_engine`) |
| **Async Driver** | **aiosqlite** (لـ SQLite) و **asyncpg** (لـ PostgreSQL) | تمكين القراءة والكتابة في قاعدة البيانات دون حظر حلقة الأحداث (Non-blocking I/O) | `system/database/database.py#L578-L585` |
| **Database Migrations** | **Alembic** | إدارة وتوليد إصدارات هياكل الجداول وترقيتها آلياً واكتشاف النماذج الجديدة في الوحدات | `alembic.ini`, `system/database/model_registry.py` |
| **Auto-Migration Fallback** | محرك فحص الأعمدة التلقائي المدمج | إضافة الأعمدة المفقودة تلقائياً في جداول SQLite عند بدء التشغيل دون الحاجة لتدخل يدوي | `system/database/database.py#L704` (`_auto_migrate_sqlite_columns`) |
| **Database Models** | نماذج متكاملة (Users, Rules, Events, Incidents, TokenBlacklist, RateLimits, VPNPeers, UBAProfiles, etc.) | نمذجة وحفظ بيانات الهوية والسياسات والأجهزة والحوادث والملفات التعريفية للسلوك | `system/database/database.py`, `modules/*/models.py` |

---

# 6. Cybersecurity Technologies

| المكون الأمني (Component) | الغرض الوظيفي (Purpose) | ما يحميه (What it Protects) | التقنية / الخوارزمية الرئيسية (Main Technology / Technique) | مكان التنفيذ في الكود (Where Implemented) | حالة التحقق |
|---|---|---|---|---|---|
| **Firewall Engine (L3/L4/L7)** | فحص وترشيح تدفقات الشبكة والتحكم بالمنافذ والبروتوكولات | حدود الشبكة والأجهزة الداخلية | محرك تقييم القواعد المبوب، تتبع الحالة (State Tracking)، قوائم الحظر الديناميكية | `modules/firewall/engine/` | Verified |
| **PHANTOM IDS/IPS** | كشف ومنع التسلل والهجمات المتقدمة حتى عبر الترافيك المشفر | الشبكة الداخلية والخوادم من هجمات APT و C2 والاختراق | التشفير الطيفي للبايتات (Spectral SBE: FFT + Wavelets + Entropy)، الرسم البياني السببي (CTGB)، ومصنف هجين GNN-Transformer | `modules/ids_ips/engine/` | Verified |
| **WAAP / WAF** | حماية تطبيقات الويب وواجهات البرمجة من هجمات OWASP Top 10 | خوادم الويب وتطبيقات المؤسسة | فحص حقن SQL و XSS، الكشف عن الروبوتات، المحرك الخادع (Deception Shadow Autopilot) | `modules/waf/engine/` | Verified |
| **MSEM-Lite DLP** | منع تسريب البيانات والوثائق الحساسة والرموز السرية | البيانات السرية، الملفات المالية، الشهادات، ومفاتيح API | تحليل الإنتروبيا متعدد الإشارات (Manifold Scorer)، مطابقة التعبيرات النمطية، وفاحص ملفات PDF/Office | `modules/dlp/engine/` | Verified |
| **DART DNS Security** | حماية بروتوكول DNS واكتشاف أنفاق التهريب ونطاقات DGA | استعلامات الخوادم والعملاء | كشف خوارزميات توليد النطاقات (DGA)، منع التسميم الكاشي، حظر DNS Tunneling | `modules/dns_security/engine/` | Verified |
| **VSDE / PLSF Email Security**| فحص رسائل البريد وحظر التصيد الاحتيالي واختراق بريد الشركات (BEC)| صناديق البريد والاتصالات المؤسسية | محرك فك المزامنة البصرية (Visual Desync HTML/CSS)، والتحليل النفسي اللغوي (PLSF)، والتحقق من DKIM/SPF | `modules/email_security/engine/` | Verified |
| **Malware AV Engine** | فحص الملفات ومكافحة البرمجيات الخبيثة وفدية البيانات | نظام الملفات والبيانات المتدفقة عبر الشبكة | محرك قواعد YARA، فحص التوقيعات والهاشات، وتحليل بنية ملفات PE الرأسية | `modules/malware_av/` | Verified |
| **SSL/TLS Inspection & CA Pool**| فحص وفك تشفير حركة البيانات المشفرة (MITM Inspection) | الاتصالات الخارجية المشفرة | توليد شهادات فورية بحوض ذاكرة مؤقت (CA Pool Manager)، فحص SNI و ALPN، فرض سياسات التجاوز | `modules/ssl_inspection/engine/` | Verified |
| **Web Filtering** | حظر المواقع الضارة وفرض سياسات الاستخدام المقبول | مستخدمو الشبكة والإنترنت | تصنيف النطاقات (Categories)، القوائم السوداء والبيضاء، وفرض البحث الآمن (SafeSearch) | `modules/web_filter/` | Verified |
| **Transparent / Reverse Proxy**| توجيه وحظر الترافيك وإعادة التوجيه الآمن | تدفقات HTTP/HTTPS | وكيل غير متزامن مبني على تيارات `asyncio.streams` مع دعم الفحص الشفاف | `modules/proxy/`, `system/core/engine.py` | Verified |
| **VPN Engine** | توفير قنوات اتصال مشفرة للموظفين والفروع عن بعد | حركة البيانات عن بعد | إدارة واجهات وأنفاق **WireGuard** عبر المفاتيح العمومية والتحقق البرمجي | `modules/vpn/engine/wireguard.py` | Verified |
| **AEGIS / ORACLE Proactive AI** | التنبؤ بخطوات المهاجم القادمة وتحديد الرد الدفاعي الأمثل | البنية التحتية من سيناريوهات الهجوم المعقدة | التوأم الرقمي الدفاعي (DDTS) بمحاكاة مونت كارلو، ونظرية الألعاب (Nash Equilibrium Solver) | `modules/predictive_ai/engine/` | Verified |
| **UBA / UEBA** | كشف السلوكيات الشاذة للمستخدمين والأجهزة واختراق الحسابات | الهويات وصلاحيات الوصول | خطوط الأساس الإحصائية (Time, Location, Volume, Services)، خوارزميات الانحراف المعياري (3-Sigma) | `modules/uba/engine/` | Verified |
| **SIEM & Incident Response** | تجميع السجلات وربط الأحداث وإدارة دورة حياة الحوادث | مركز العمليات الأمنية (SOC) | محرك مطابقة الأحداث، تصنيف الخطورة، ونظام إدارة الحوادث والمهام الآلي | `system/siem/`, `api/routers/v1/response.py` | Verified |
| **CVAS Voice Alert Service** | التنبيه الصوتي الحي لغرفة العمليات عند وقوع هجمات حرجة | استجابة مهندسي الأمان اللحظية | محرك توليد نصوص التهديد اللحظي، والتوليف الصوتي العصبي (Neural TTS via Piper/pyttsx3) | `system/cvas/` | Verified |
| **Kernel Acceleration (eBPF/XDP)**| إسقاط حزم هجمات DoS على مستوى بطاقة الشبكة قبل دخول النواة | استقرار موارد الخادم | برامج C المحقونة في مسار XDP، موازنة L4، وترشيح المنافذ الفوري | `acceleration/ebpf/` | Verified |
| **Netfilter (nftables) Layer** | حظر العناوين على مستوى جدار حماية النواة وعزل المنافذ | عزل منافذ الإدارة وواجهات الشبكة | التجميع الآلي الذري لملفات التهيئة والتحميل الذري `nft -f` مع منع إغلاق منافذ الإدارة | `system/networking/appliance/netfilter_manager.py`| Verified |

---

# 7. AI / Machine Learning Technologies

| التقنية / النموذج (Technology / Model) | الغرض الوظيفي (Purpose) | مكان الاستخدام في الكود (Where Used) | المدخلات (Input) | المخرجات (Output) | الدور في منظومة BUNYANX (Role in BUNYANX) |
|---|---|---|---|---|---|
| **Spectral Byte Encoder (SBE)** | استخلاص البصمة الطيفية لحزم البيانات المشفرة | `modules/ids_ips/engine/spectral/sbe.py` | مصفوفة بايتات الحزمة الخام (Raw payload bytes) | متجه مميزات طيفي 256-dim (FFT + Wavelet + Entropy) | تحويل محتوى الحزم غير المفهوم إلى بصمة رياضية تميز البرمجيات الخبيثة وأنفاق C2 دون فك التشفير. |
| **Causal Temporal Graph (CTGB)** | ربط تدفقات الشبكة زمنياً وسببياً لبناء شجرة التهديد | `modules/ids_ips/engine/graph/ctgb.py` | متجهات SBE، عناوين IP، الطوابع الزمنية | رسم بياني سببي حي (Causal Graph Snapshot & Density Score) | كشف هجمات التحرك الجانبي (Lateral Movement) والهجمات الموزعة متعددة المراحل (APT). |
| **Hybrid GNN-Transformer (HGTC)**| تصنيف الهجمات بناءً على طوبولوجيا الشبكة والتطور الزمني | `modules/ids_ips/engine/model/phantom_classifier.py` | الرسم البياني السببي + تسلسل تدفقات الحزم | مصفوفة احتمالات لـ 10 فئات هجومية مع نسبة الثقة | اتخاذ قرار كشف وحظر الهجوم في محرك PHANTOM في زمن استدلال يقل عن 1 ميلي ثانية. |
| **ONNX Runtime (onnxruntime)** | تشغيل النماذج المدربة بأعلى سرعة وأقل استهلاك للمعالج | `modules/ids_ips/`, `modules/predictive_ai/` | متجهات المميزات المستخلصة | نتائج الاستدلال والتصنيف الفوري | محرك استدلال إنتاجي للنماذج الرياضية لضمان عدم تأخير مرور الحزم الشبكية. |
| **Scikit-Learn (sklearn)** | خوارزميات التعلم الآلي التقليدية والمصنفات الإحصائية | `ml/`, `modules/uba/`, `modules/dlp/` | ميزات سلوكية، مصفوفات تكرار، إحصائيات الجلسات | درجات الشذوذ والتصنيف الاحتمالي | بناء خطوط الأساس لسلوك المستخدمين (UBA) وتدريب المصنفات المساعدة للـ WAF و DLP. |
| **XGBoost (xgboost)** | أشجار القرار المعززة بالتدرج لتصنيف التهديدات | `ml/training/`, `modules/waf/` | ميزات جداول البيانات والخصائص المستخرجة من الـ Payloads | احتمالية تصنيف الهجوم (Binary/Multiclass Risk) | تصنيف عالي الدقة وسريع لحمولات الويب الخبيثة وكشف الأنماط المعقدة. |
| **Attention-based Intent Predictor**| التنبؤ بالخطوة الهجومية التالية للمهاجم بناءً على تسلسل TTPs | `modules/predictive_ai/engine/AEGIS/intent/` | تسلسل تكتيكات المهاجم المرصودة (MITRE ATT&CK TTPs) | توزيع احتمالي للخطوات والتقنيات الهجومية القادمة | تزويد محرك الدفاع الاستباقي برؤية مسبقة لما ينوي المهاجم تنفيذه قبل وقوعه. |
| **Defensive Digital Twin Simulator (DDTS)**| محاكاة مسارات الهجوم والدفاع لتقييم الردود الدفاعية | `modules/predictive_ai/engine/AEGIS/strategy/ddts.py` | الإجراءات الدفاعية المرشحة وتوزيع احتمالات المهاجم | العائد المتوقع وفترات الثقة 95% CI لكل إجراء | اختيار أفضل إجراء دفاعي استباقي يقلل الضرر على المؤسسة ويحبط خطة المهاجم. |
| **NetworkX** | بناء وتحليل بنية الرسوم البيانية المعقدة | `system/core/`, `modules/ids_ips/`, `predictive_ai/` | العقد الشبكية والاتصالات والتفاعلات | مسارات الهجوم المركزية ومقاييس الكثافة والترابط | النمذجة الهيكلية لمسارات سلاسل القتل السيبراني (Cyber Kill Chains). |
| **Piper Neural Voice (ONNX)** | توليد التنبيهات الصوتية الحية باستخدام شبكات عصبية صوتية | `system/cvas/tts_worker.py` | نصوص التنبيهات الأمنية المولدة باللغتين العربية والإنجليزية | ملفات صوتية بصيغة WAV عالية النقاء | تمكين نظام CVAS من النطق الفوري بالصوت البشري لإبلاغ مسؤولي الأمن بالهجمات الحرجة. |

---

# 8. Networking Technologies

| التقنية الشبكية (Technology) | الوصف الهندسي ودورها في المشروع (Description & Role) | دليل التحقق البرمجي (Evidence from Code) |
|---|---|---|
| **eBPF / XDP (eXpress Data Path)** | معالجة وترشيح حزم البيانات مباشرة عند طبقة بطاقة الشبكة (NIC driver) قبل تخصيص `sk_buff` في النواة | `acceleration/ebpf/pipeline/dispatcher.c`, `xdp_engine.py` |
| **Netfilter (nftables)** | نظام الجدار الناري المعتمد لنواة Linux؛ يتم التحكم به ذرياً عبر تجميع وحقن القواعد لمنع انقطاع إدارة النظام | `system/networking/appliance/netfilter_manager.py` |
| **Asyncio Socket Streams** | إدارة قنوات الاتصال والوكيل الشفاف (Forward/Reverse Proxy) بدون إيقاف خيوط المعالجة | `modules/proxy/`, `system/core/engine.py` |
| **WireGuard (VPN)** | بروتوكول شبكات افتراضية حديث عالي التشفير مبني على معيار Noise Protocol | `modules/vpn/engine/wireguard.py` |
| **TLS / SSL MITM Engine** | فحص شهادات SSL واستخلاص SNI و ALPN وتوليد شهادات مطابقة فورية عبر Root CA | `modules/ssl_inspection/engine/ca_pool.py`, `system/networking/sni_utils.py` |
| **DNS Resolution & Sniffing** | استقبال وتحليل وإعادة توجيه استعلامات DNS وفحص الحقول لبروتوكولات UDP/TCP | `modules/dns_security/engine/dns_engine.py`, `dnspython` |
| **Connection Tracking (Conntrack)**| تتبع حالات الاتصال L4 (TCP State Machine, UDP Streams) لمنع هجمات التزييف | `acceleration/ebpf/conntrack_manager.py`, `modules/firewall/engine/state_tracker.py` |
| **Network Interface Management** | اكتشاف وإدارة بطاقات الشبكة (WAN, LAN, MGMT, DMZ) وعناوين MAC والـ Promiscuous Mode | `system/networking/appliance/interface_manager.py` |
| **GeoIP Resolution (MaxMind)** | مطابقة عناوين IP للمهاجمين مع قواعد بيانات MaxMind GeoLite2 لاستخراج الدولة والمدينة والإحداثيات | `system/threat_intel/`, `system/cvas/geo_enricher.py`, `geoip2` |
| **SYN Proxy / TCP Defense** | حماية الخوادم من هجمات إغراق الـ SYN Flood عبر الرد بحزم SYN-ACK على مستوى eBPF | `acceleration/ebpf/pipeline/stage_syn_proxy.c` |
| **Traffic Shaping & QoS** | التحكم بمعدلات تدفق البيانات والحد من استهلاك الحزم عبر خوارزمية Token Bucket | `modules/qos/` |

---

# 9. Operating Environment

| المكون البيئي (Environment Component) | القيمة / المتطلب الفعلي (Verified Value / Requirement) | حالة التحقق والدليل (Verification & Evidence) |
|---|---|---|
| **نظام التشغيل المدعوم للإنتاج (Target OS)** | **Linux (Ubuntu Server 22.04 LTS / Debian 12 / Appliance Kernel 5.15+)** | Verified من `system/networking/appliance/os_init/appliance_boot.sh` و `scripts/install_audio.sh` |
| **نظام التشغيل المدعوم للتطوير (Dev OS)** | **Cross-Platform (Linux, Windows 10/11, macOS)** | Verified عبر آليات التوافق في `system/database/database.py` و `install.bat` |
| **إصدار بيئة بايثون (Python Version)** | **Python >= 3.10** (موصى به: **Python 3.11 / 3.12**) | Verified من استخدام صياغات `asyncio`, typing الحديثة, و `alembic.ini` |
| **بيئة تشغيل العقدة (Node.js & npm)** | **Node.js >= 18.0.0** (Vite 8 يتطلب Node الحديث) | Verified من `web-ui/package.json` و `vite.config.js` |
| **مدير الحزم (Package Managers)** | **pip** (للبايثون) و **npm** (للواجهة الأمامية) | Verified من `requirements/base.txt` و `web-ui/package.json` |
| **خدمات نظام التشغيل (System Services)** | **systemd** (لإدارة خادم bunyanx كخدمة `bunyanx.service` في وضع Appliance) | Verified من `SERVICE_MANAGEMENT_GUIDE.md` و نصوص التثبيت |
| **برامج وخوادم الصوت المعتمدة** | **PulseAudio / PipeWire / ALSA** مع مشغلات `paplay`, `pw-play`, `ffplay`, `mpg123` | Verified من `system/cvas/tts_worker.py#L6-L12` |
| **أدوات الشبكة النظامية** | **nftables (`nft`), iproute2 (`ip`), ethtool, wireguard-tools (`wg`)** | Verified من `system/networking/appliance/netfilter_manager.py` و `wireguard.py` |

---

# 10. Supporting Development / Operational Tools

| الأداة (Tool) | التصنيف (Category) | الدور الفعلي في المشروع (Actual Role in BUNYANX) | دليل التحقق البرمجي (Evidence) |
|---|---|---|---|
| **Git** | نظام إدارة الإصدارات | التحكم بالإصدارات وتتبع التغييرات المعمارية | وجود `.git/`, `.gitignore` |
| **Alembic** | أداة ترقية قواعد البيانات | إنشاء مسارات الترقية والـ Migrations واكتشاف التغييرات في جداول الوحدات | `alembic.ini`, `system/database/migrations/` |
| **Pytest** | إطار عمل الاختبارات الآلية | تنفيذ اختبارات الوحدات والتكامل للوحدات الأمنية والنواة | `.pytest_cache/`, `tests/`, `modules/*/tests/` |
| **ESLint (v9.39+)** | فاحص جودة وتنسيق الكود | التحقق من معايير كود React وتطبيق أفضل ممارسات الـ Hooks | `web-ui/eslint.config.js`, `package.json` |
| **GeoLite2 (MaxMind)** | قاعدة بيانات المواقع الجغرافية | تحديد مواقع مصادر التهديد جغرافياً لعرضها على الخريطة ونطقها في التنبيهات | `system/threat_intel/`, `geoip2` |
| **YARA (yara-python)** | محرك مطابقة قواعد الأمان | مسح وتصنيف الملفات بحثاً عن توقيعات وسلوكيات البرمجيات الخبيثة | `modules/malware_av/yara_rules/`, `requirements/base.txt` |
| **Piper TTS / pyttsx3** | أدوات التوليف الصوتي | توليد المقاطع الصوتية الخاصة بخدمة التنبيهات الصوتية الحية (CVAS) | `system/cvas/tts_worker.py`, `scripts/generate_alert_audio_files.py` |
| **Network Attack Simulators** | أدوات محاكاة الهجمات | نصوص متخصصة لاختبار صمود الجدار الناري وحقن حزم هجومية وهمية | `scripts/simulate_attacks.py`, `scripts/test_ngfw_attacks.py` |
| **Docx / PDF / OpenPyXL Extractors**| مكتبات قراءة وتجريد النصوص | استخراج النصوص الحية من المستندات المكتبية لتمريرها لمحرك الـ DLP | `requirements/base.txt` (`pypdf`, `python-docx`, `openpyxl`) |

---

# 11. BUNYANX Major Components

يتألف مشروع **BUNYANX** من مجموعة مترابطة من المكونات والوحدات الوظيفية التي تم التحقق من وجودها الفعلي في الكود البرمجي:

1. **نواة النظام وإدارة الدورة الحياتية (Core Engine & Lifecycle Manager)**: المسؤولة عن تحميل التكوينات، التحقق من أمان الإقلاع، وربط الوكلاء الشفافين وخوادم الـ API.
2. **ناقل الأحداث الموحد (Unified Event Bus)**: محرك رسائل غير متزامن يدعم طوابير الذاكرة السريعة و NATS JetStream مع حماية السجلات الميتة (DLQ).
3. **طبقة إدارة الشبكة والتجهيز الذري (Appliance Netfilter & Networking Layer)**: إدارة بطاقات الشبكة، وحقن قواعد `nftables` الذرية، مع حماية منافذ الإدارة من الإغلاق العرضي.
4. **تسريع النواة بواسطة eBPF / XDP**: خط أنابيب مدمج مكتوب بلغة C للترشيح المسبق للحزم وحماية الخوادم من هجمات الحرمان من الخدمة (SYN Proxy / L4 LB).
5. **جدار الحماية وتتبع الاتصالات (Stateful Firewall Engine)**: محرك قواعد هرمي يدعم مطابقة المنافذ والبروتوكولات وعناوين IP مع سجلات تتبع الحالة.
6. **محرك كشف ومنع التسلل الهجين (PHANTOM IDS/IPS)**: منظومة ثلاثية الطبقات (تشفير طيفي SBE، رسم بياني سببي CTGB، ومصنف GNN-Transformer HGTC).
7. **جدار حماية تطبيقات الويب وحماية الواجهات (WAAP / WAF)**: الكشف عن هجمات الحقن، والتصدي للهجمات الآلية، مع محرك التضليل النشط (Deception Shadow Autopilot).
8. **محرك منع تسريب البيانات (MSEM-Lite DLP)**: تحليل وتصنيف المستندات، وفحص الإنتروبيا، ومنع تصدير المفاتيح والوثائق الحساسة.
9. **محرك حماية البريد الإلكتروني (VSDE / PLSF Email Security)**: اكتشاف هجمات اختراق البريد (BEC)، والتصيد الموجه، والتفكيك البصري للرسائل.
10. **محرك أمن استعلامات DNS (DART DNS Security)**: حظر أنفاق التهريب ونطاقات DGA الخبيثة ومنع الهجمات التسميمية.
11. **نظام فحص التشفير والشهادات (SSL/TLS Inspection & CA Pool)**: وكيل اعتراض مشفر يولد الشهادات ديناميكياً مع حوض شهادات للحد من استهلاك المعالج.
12. **مكافح البرمجيات الخبيثة (Malware AV Engine)**: فحص الحزم والملفات بقواعد YARA والهاشات وتحليل رؤوس ملفات PE.
13. **محرك الدفاع الاستباقي والتنبؤ (AEGIS / ORACLE Proactive AI)**: التنبؤ بنوايا المهاجمين عبر خوارزميات الانتباه ونمذجة الردود الدفاعية بتوأم رقمي ونظرية الألعاب.
14. **محرك تحليل سلوك المستخدمين والكيانات (UBA / UEBA)**: بناء وتحديث الملفات السلوكية تلقائياً وكشف الشذوذ الإحصائي في الأوقات والبيانات والمواقع.
15. **نظام خوادم VPN الآمنة (WireGuard Engine)**: إدارة الأنفاق المشفرة وإعداد مفاتيح الاتصال للأجهزة البعيدة.
16. **خدمة التنبيهات الصوتية الحية (CVAS - BUNYANX Voice Alert Service)**: معالجة الأحداث الأمنية الحرجة وتحويلها إلى تنبيهات صوتية معبرة وفورية لغرفة العمليات.
17. **مركز الاستجابة للحوادث وإدارة السجلات (SIEM, Response & Log Manager)**: ربط التنبيهات، إنشاء الحوادث الأمنية، وتوفير واجهات البحث والتدقيق اللحظي.
18. **لوحة التحكم الرسومية المتقدمة (Command SOC Web-UI)**: واجهة مستخدم مبنية بـ React و Three.js لعرض مجسم الهجمات ثلاثي الأبعاد والتحكم الشامل بجميع الوحدات.

---

# 12. Complete Technology Stack

```
BUNYANX NEXT-GENERATION FIREWALL
│
├── [1] Operating & Deployment Environment
│   ├── Target OS: Linux (Ubuntu 22.04+ / Debian 12 / Custom Appliance Kernel)
│   ├── Cross-Platform Dev: Windows 10/11 / macOS
│   ├── Init & Service Manager: systemd (bunyanx.service)
│   ├── Audio Infrastructure: PulseAudio, PipeWire, ALSA (paplay, pw-play, ffplay, mpg123)
│   └── System Shells: Bash (.sh), Windows Batch (.bat)
│
├── [2] Kernel Acceleration & Networking Layer
│   ├── Kernel BPF Engine: eBPF / XDP (C pipeline: dispatcher.c, stage_conntrack.c, stage_syn_proxy.c)
│   ├── Netfilter Engine: Atomic nftables Compiler & Loader (`nft -f`)
│   ├── VPN Technology: WireGuard Kernel/Userspace Interface Manager
│   ├── Socket Engine: Python Asyncio Non-Blocking Stream Transports
│   ├── Threat Geolocation: MaxMind GeoIP2 / GeoLite2 Database
│   └── Traffic Shaping: Token Bucket QoS Engine
│
├── [3] Core & System Architecture Layer
│   ├── Application Engine: Clean Modular Architecture (bunyanxApplication Lifecycle Engine)
│   ├── Event Messaging Bus: Hybrid Engine (Asyncio In-Memory True Queue + NATS JetStream + DLQ)
│   ├── Security Boot Validator: Startup Secret & Cryptographic Check (`validate_startup_security`)
│   ├── Certificate Infrastructure: SSL/TLS CA Pool Manager & OpenSSL Cryptography
│   └── Metric Telemetry: Prometheus Client Exporter (`/metrics`) & Psutil Health Collector
│
├── [4] Cybersecurity Engines Layer (17 Modules)
│   ├── Perimeter Defense: Stateful L3/L4/L7 Firewall
│   ├── Intrusion Prevention: PHANTOM (Spectral SBE + Causal Graph CTGB + HGTC)
│   ├── Web & API Protection: WAAP / WAF + Deception Shadow Autopilot
│   ├── Data Leak Prevention: MSEM-Lite Multi-Signal Entropy & Manifold Scorer DLP
│   ├── Email Security: VSDE Visual Desync + PLSF Psycho-Linguistic BEC Defense
│   ├── Domain Name Security: DART Real-Time DGA & DNS Tunneling Engine
│   ├── Anti-Malware: Multi-Engine YARA Scanner + PE Header Forensic Analyzer
│   ├── Traffic Decryption: SSL/TLS MITM Proxy with SNI & ALPN Inspection
│   ├── Content Filtering: Categorized Web Filter & SafeSearch Enforcement
│   ├── Entity Analytics: UBA / UEBA Baseline Statistical Deviance Engine (3-Sigma)
│   ├── Voice Operations: CVAS Real-Time Neural Speech Alert Dispatcher
│   └── SOC Operations: Incident Response Center, SIEM Correlation & Log Controller
│
├── [5] AI / Machine Learning Layer
│   ├── Deep Learning & Classifiers: PyTorch, ONNX Runtime, Scikit-Learn, XGBoost
│   ├── Signal Processing: NumPy (FFT Fast Fourier Transform), PyWavelets (db4), Byte Entropy
│   ├── Graph Intelligence: NetworkX (Causal Topologies & Attack Graph Paths)
│   ├── Proactive Intelligence: AEGIS / ORACLE (Attention Intent Predictor + MITRE ATT&CK Mapping)
│   ├── Strategic Modeling: Defensive Digital Twin Simulator (DDTS Monte Carlo Rollouts)
│   └── Neural Voice Synthesis: Piper Neural TTS (ONNX acoustic models) + pyttsx3 fallback
│
├── [6] Database & Persistence Layer
│   ├── ORM Engine: SQLAlchemy 2.0 (Dual Async/Sync Architecture)
│   ├── Development Storage: SQLite 3 with WAL Mode & Foreign Keys Enforced
│   ├── Production Storage: PostgreSQL (via `asyncpg` async driver & `psycopg2`)
│   ├── Schema Migrations: Alembic Auto-Discovery Migration Engine (`model_registry.py`)
│   └── In-Memory Caching: Thread-Safe LRU Spectral & Certificate Pools
│
├── [7] API & Application Gateway Layer
│   ├── Web API Framework: FastAPI (v0.104.0+)
│   ├── ASGI Web Server: Uvicorn Async Server
│   ├── Real-Time Feeds: Native WebSockets (SIEM Live Feed & Metric Streams)
│   ├── Rate Limiting: SlowAPI (IP-based Request Throttle)
│   ├── Authentication & RBAC: PyJWT, Bcrypt, Role-Based Access Control
│   └── Schema Validation: Pydantic v2 Models
│
└── [8] Frontend & SOC Management Layer (Web-UI)
    ├── Core Framework: React 19 (v19.2.4)
    ├── Build Tooling: Vite (v8.0.0) with ES Modules
    ├── 3D Geospatial Engine: Three.js (v0.183.2) & Globe.gl (v2.45.1)
    ├── Data Visualization: Recharts (v3.8.0)
    ├── Motion & Effects: Framer Motion (v12.36.0)
    ├── Design System: Pure Vanilla CSS with CSS Design Tokens (No Tailwind)
    ├── State Management: Zustand (v5.0.11) & @tanstack/react-query (v5.90.21)
    ├── Networking Client: Axios (v1.13.6) & Browser WebSockets
    └── Auditory Feedback: HTML5 Web Audio API Sound Engine
```

---

# 13. Academic Draft — "أدوات إنتاج المشروع"

*(نص أكاديمي رصين وموثق، جاهز للإدراج المباشر في فصل أدوات التطوير والبيئة التقنية لتقرير التخرج الجامعي)*

---

### **أدوات وتقنيات إنتاج مشروع BUNYANX**

اعتمد بناء وتطوير مشروع **BUNYANX (نظام الجدار الناري المتقدم من الجيل التالي والدفاع الاستباقي)** على منظومة متكاملة من التقنيات ولغات البرمجة وأطر العمل المتطورة، التي تم اختيارها وتوظيفها بما يلبي متطلبات الأنظمة الأمنية الحساسة من حيث: السرعة العالية في معالجة تدفقات الشبكة، انخفاض زمن الاستجابة، دقة الكشف عن التهديدات المتقدمة، وتوفير واجهات تحكم ومراقبة لحظية لفرق مراكز العمليات الأمنية (SOC). وفيما يلي تفصيل منهجي للبيئة التقنية والأدوات التي تم استخدامها فعلياً في إنتاج النظام:

#### **1. لغات البرمجة (Programming Languages)**
* **بايثون (Python 3.10+)**: تمثل لغة البرمجة الرئيسية في المشروع؛ حيث بُنيت عليها نواة النظام الخلفية (Core Engine)، ومحركات الأمان الـ 17، ونماذج الذكاء الاصطناعي، وخوادم واجهة برمجة التطبيقات (API). تميز استخدام بايثون بتوظيف مكتبة المعالجة غير المتزامنة (`asyncio`) لإدارة الاتصالات والمهام المتزامنة دون حظر لموارد المعالجة.
* **سي (C)**: استُخدمت لكتابة برمجيات مسار النواة المتقدمة بتقنية **eBPF / XDP** في طبقة تسريع المعالجة؛ مما أتاح ترشيح الحزم وإسقاط هجمات حجب الخدمة (DDoS) وموازنة الأحمال مباشرة على مستوى بطاقة الشبكة قبل استنزاف موارد نظام التشغيل.
* **جافا سكريبت (JavaScript / JSX - ECMAScript Modern)**: استُخدمت لبناء الواجهة الأمامية التفاعلية للوحة التحكم، وإدارة تدفق البيانات المباشر عبر بروتوكول WebSockets، والتحكم بالرسم ثلاثي الأبعاد.
* **لغة التنسيق القياسية (Vanilla CSS)**: تم اعتماد أسلوب التصميم القائم على المتغيرات ورموز التصميم المركزية (Design Tokens) دون الاعتماد على أطر عمل خارجية مثل Tailwind، مما منح الواجهة سرعة تحميل فائقة وتصميماً مخصصاً يناسب غرف العمليات المظلمة.
* **لغات التهيئة والاستعلام (SQL & YAML)**: استُخدمت لغة SQL لتعريف وإدارة الجداول العلائقية عبر الـ ORM، بينما استُخدمت ملفات YAML لضبط سياسات النظام وأعلام الميزات (Feature Flags) وتعريف إعدادات المراقبة.

#### **2. تقنيات الواجهة الأمامية (Frontend Technologies)**
* **إطار العمل React 19**: تم بناء الواجهة بنمط المكونات القابلة لإعادة الاستخدام (Modular Component-Based Architecture) مع الاستفادة من ميزات React الحديثة في إدارة الحالة وتحديث الواجهة بكفاءة.
* **أداة البناء Vite 8**: استُخدمت لتجميع وحزم ملفات المشروع بسرعة فائقة بالاعتماد على معيار وحدات ES الأصلية (Native ES Modules).
* **مكتبات الرندرة ثلاثية الأبعاد (Three.js & Globe.gl)**: استُخدمت لبناء مجسم الكرة الأرضية التفاعلي ثلاثي الأبعاد (3D Threat Map)، الذي يعرض مسارات الهجمات السيبرانية ومواقع المهاجمين جغرافياً في الوقت الحقيقي.
* **المخططات البيانية والحركة (Recharts & Framer Motion)**: استُخدمت لتمثيل مؤشرات الأمان والمنحنيات الإحصائية وتقديم انتقالات حركية سلسة تعزز تجربة المستخدم.
* **إدارة الحالة وجلب البيانات (Zustand & React Query)**: تم توظيف Zustand كخزان حالة خفيف وسريع لإدارة التنبيهات الحية وتدفقات الشبكة، بينما استُخدمت React Query لإدارة ومزامنة استدعاءات الخادم والتخزين المؤقت.

#### **3. تقنيات الواجهة الخلفية والنواة (Backend & Core Technologies)**
* **إطار العمل FastAPI**: تم اعتماده لبناء واجهات برمجة التطبيقات (RESTful APIs) وفق المعمارية النظيفة (Clean Architecture)، موفراً توثيقاً تفاعلياً تلقائياً عبر OpenAPI/Swagger وتحققاً صارماً من صحة البيانات باستخدام **Pydantic v2**.
* **خادم Uvicorn ASGI**: خادم غير متزامن عالي الكفاءة لتشغيل التطبيق والتعامل مع آلاف الطلبات المتزامنة.
* **ناقل الأحداث الموحد (Event Bus)**: تم تصميم ناقل أحداث داخلي يدعم العمل بنمط الذاكرة المشتركة في بيئة التطوير، والتكامل مع خادم **NATS JetStream** في البيئات الإنتاجية الموزعة، مع تزويده بآلية طوابير الرسائل الميتة (Dead-Letter Queue - DLQ) لضمان عدم ضياع أي تنبيه أمني.
* **المصادقة والأمان**: تطبيق نظام التوثيق بالرموز المشفرة (**JWT**) وتشفير كلمات المرور بخوارزمية **Bcrypt**، مع فرض قيود استهلاك المداخل عبر مكتبة **SlowAPI**.

#### **4. تقنيات قواعد البيانات وإدارة التخزين (Database Technologies)**
* **محرك الربط الكائني العلائقي (SQLAlchemy 2.0 Dual-Engine)**: تم تطبيق معمارية محرك مزدوجة تدعم العمليات غير المتزامنة لخدمات الـ API والعمليات المتزامنة لمهام النواة الخلفية.
* **قواعد البيانات المدعومة**: دعم قاعدة بيانات **SQLite 3** مع تفعيل وضع الكتابة المسبقة (**WAL**) وفرض المفاتيح الخارجية للأجهزة المدمجة وبيئات التطوير، مع دعم قاعدة بيانات **PostgreSQL** عبر المشغل غير المتزامن `asyncpg` للبيئات المؤسسية عالية الأداء.
* **نظام الترحيل الآلي (Alembic)**: تم ربطه بنظام تسجيل نماذج الوحدات (`model_registry.py`) لاكتشاف وترقية جداول قواعد البيانات الخاصة بجميع الوحدات الأمنية تلقائياً.

#### **5. تقنيات الذكاء الاصطناعي والأمن السيبراني (Cybersecurity & AI)**
* **كشف التسلل الطيفي الهجين (PHANTOM IDS/IPS)**: توظيف تقنيات معالجة الإشارات (FFT + Wavelets) لاستخراج البصمات الطيفية (SBE)، وبناء الرسوم البيانية السببية (CTGB)، واستخدام شبكات الرسم البياني والمحولات (Hybrid GNN-Transformer) للتصنيف في بيئة **ONNX Runtime**.
* **الدفاع الاستباقي وتوقع التهديدات (AEGIS / ORACLE)**: استخدام نماذج الانتباه للتنبؤ بخطوات المهاجم القادمة، ومحاكاة الاستجابة عبر التوأم الرقمي الدفاعي (DDTS) القائم على محاكاة مونت كارلو وحلول توازن ناش (Nash Equilibrium).
* **حماية الويب والبريد والبيانات**: دمج خوارزميات الإنتروبيا متعددة الإشارات لمنع تسريب البيانات (**MSEM-Lite DLP**)، والتحليل النفسي اللغوي وفك المزامنة البصرية لحماية البريد الإلكتروني (**VSDE/PLSF**)، ومطابقة قواعد **YARA** المتقدمة لمكافحة البرمجيات الخبيثة.
* **نظام التنبيهات الصوتية الحية (CVAS)**: توليد تنبيهات نطقية حية باستخدام محركات التوليف العصبي الصوتي المعتمدة على **Piper Neural Voice (ONNX)** و **pyttsx3**.

#### **6. تقنيات الشبكات والبيئة التشغيلية (Networking & Environment)**
* **إدارة حزم الشبكة (nftables & eBPF)**: التفاعل الذري مع جدار حماية نواة لينكس عبر مجمع `nftables` البرمجي، وتوفير حماية المنافذ وموازنة الأحمال المنخفضة.
* **الشبكات الافتراضية والبروكسي (WireGuard & Async Proxy)**: توفير أنفاق VPN عالية الأمان، ووكيل شفاف غير متزامن لفحص وتوجيه تدفقات البروتوكولات.
* **البيئة التشغيلية**: صُمم النظام للعمل كجهاز أمني متكامل (Security Appliance) على توزيعات **Linux (Ubuntu Server 22.04 LTS / Debian 12)** وتحت إدارة خدمات **systemd**، مع دعم التشغيل عبر المنصات المختلفة (Cross-Platform) لأغراض الاختبار والتطوير.

---

# 14. Verification Notes

بناءً على الفحص البرمجي الشامل والتدقيق الجنائي لكافة ملفات الكود المصدري، وحزم التبعيات، وملفات الإعداد في المجلد `F:\enterprise_ngfw`، تم تصنيف التقنيات حسب درجة التحقق الفعلي كالتالي:

### 1. تقنيات تم التحقق منها بالكامل من الكود المصدري (Verified)
- **لغات البرمجة**: Python (كافة محركات النظام), C (برامج eBPF/XDP), JavaScript/JSX (واجهة React), CSS (نظام التنسيق بالمتغيرات), HTML, Bash Scripts, Batch Scripts, SQL, YAML.
- **أطر عمل ومكتبات الواجهة**: React 19, Vite, Three.js, Globe.gl, Recharts, Framer Motion, Lucide React, Zustand, @tanstack/react-query, Axios, React Router DOM, Web Audio API, WebSockets.
- **أطر عمل وتقنيات الباك إند**: FastAPI, Uvicorn, Pydantic v2, Python Asyncio, SlowAPI, PyJWT, Bcrypt, Cryptography, Prometheus Client, Psutil, PyYAML, Rich, NATS-Py.
- **قواعد البيانات والتخزين**: SQLAlchemy 2.0 (Dual Engine), SQLite (WAL & Pragmas), PostgreSQL (`asyncpg`/`psycopg2`), Alembic, Auto-migration column scanner.
- **تقنيات ومحركات الأمان (17 وحدة كاملة)**:
  - Firewall Engine (Rule evaluator, state tracking, ip blocklists).
  - PHANTOM IDS/IPS (Spectral Byte Encoder, CTGB Graph Builder, HGTC Classifier).
  - WAF (Payload decoders, injection rules, Deception shadow autopilot).
  - MSEM-Lite DLP (Manifold Scorer, Entropy Analyzer, Document extractors).
  - Email Security (VSDE Visual Desync, PLSF Psycho-linguistic profiler, DKIM/SPF).
  - DART DNS Security (DGA detector, DNS Tunneling, dnspython engine).
  - Malware AV (YARA rules engine, PE header analyzer).
  - SSL/TLS Inspection (CA Pool Manager, dynamic cert generation, SNI/ALPN parsing).
  - Web Filter (Category classification, blacklist/whitelist, SafeSearch).
  - Proxy (Async transparent & reverse proxy).
  - VPN (WireGuard interface configuration & peer manager).
  - AEGIS / ORACLE (Attention Intent Predictor, DDTS Monte Carlo Simulator, Nash Solver).
  - UBA / UEBA (3-Sigma baseline profiles, user behavior detectors).
  - CVAS (Neural Voice Piper TTS, pyttsx3, audio backend dispatcher).
  - SIEM / Incident Response / Log Manager (Central log buffer, rule correlator).
  - eBPF/XDP (dispatcher.c, stage_conntrack.c, stage_syn_proxy.c, stage_l4_lb.c, port_filter.c).
  - Netfilter Manager (nftables atomic assembler & loader).
- **الذكاء الاصطناعي ومعالجة الإشارات**: ONNX Runtime, Scikit-Learn, XGBoost, NetworkX, NumPy (FFT & array math), PyWavelets, Piper TTS.
- **أدوات الشبكات والتطوير**: GeoIP2 (MaxMind), Pytest, ESLint, pypdf, python-docx, openpyxl, python-pptx, beautifulsoup4.

### 2. تقنيات تم التحقق منها جزئياً (Partially Verified)
- **PyTorch (`torch`)**: البنية الهيكلية للنماذج مكتوبة كـ `nn.Module` (مثل `PHANTOMClassifier` و `AttentionPredictor`) مع وجود محولات استدلال تدعم PyTorch عند توفره، ولكن للاستخدام الميداني عالي الأداء يتم تفضيل تصديرها وتشغيلها عبر `onnxruntime` لتقليل زمن الاستدلال وحجم الاعتماديات.
- **BCC / libbpf**: برامج eBPF المكتوبة بلغة C موجودة وكاملة في `acceleration/ebpf/pipeline/`، وتتطلب بيئة تشغيل Linux فعلية بنواة تدعم BPF لتحميل كود البايت (Bytecode) في النواة.

### 3. تبعيات موجودة في ملفات التثبيت ولكن لم يتم استخدامها برمجياً في الكود (Dependency Present but Practical Usage Not Verified)
- **Deck.gl (`@deck.gl/core`, `@deck.gl/layers`, `deck.gl`)**: مدرجة في `web-ui/package.json` كاعتمادية، ولكن عند فحص كود الواجهة تبيّن أنه تم استبدالها والاعتماد كلياً على محرك **Three.js** المخصص و **Globe.gl** لرسم الكرة الأرضية ومسارات الهجمات ثلاثية الأبعاد.
- **D3 (`d3`)**: مدرجة في `web-ui/package.json` كاعتمادية مباشرة، ولكنها لا تُستدعى صراحة في ملفات الكود المصدري `src/`، وإنما تُستخدم داخلياً كاعتمادية فرعية ضمن مكتبة `recharts`.

### 4. تقنيات غير مستخدمة إطلاقاً (Not Implemented / Not Verified)
- **Tailwind CSS / Bootstrap**: لم يُعثر على أي أثر لاستخدام Tailwind أو Bootstrap؛ حيث يعتمد المشروع كلياً على Vanilla CSS و Design Tokens.
- **Docker / Kubernetes**: لا توجد ملفات `Dockerfile` أو `docker-compose.yml` في جذر المشروع؛ حيث صُمم النظام ليعمل كـ Native Appliance بنظام الخدمات المستقلة `systemd`.
- **Redis / Celery**: لا يستخدم المشروع Redis أو Celery لإدارة المهام؛ بل يعتمد على طوابير `asyncio` الداخلية وخادم `NATS JetStream` المدمج في ناقل الأحداث.
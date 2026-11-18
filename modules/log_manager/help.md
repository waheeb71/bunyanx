# دليل المطورين لوحدة إدارة السجلات (`log_manager`)
# Developer Guide for Log Manager Module

هذا الملف يعتبر المرجع الرسمي الشامل لأي مطور في الفريق يود التعامل مع وحدة إدارة السجلات `log_manager` أو استدعائها من أي وحدة أخرى في النظام دون الحاجة لقراءة الكود المصدري للوحدة.

---

## 1. نظرة عامة (Overview)

تتولى وحدة `log_manager` إدارك وحفظ واسترجاع كافة السجلات (Operational Logs) والأحداث الأمنية (Security Events).
تتميز البنية بما يلي:
1. **ذاكرة دائرية حيّة (Live Memory Buffer):** لتمرير السجلات فوراً عبر بث Server-Sent Events (SSE).
2. **تخزين هجين (Hybrid Storage):**
   - ملفات نصية تدعم البحث العكسي من نهايتها (Backward Search).
   - قاعدة بيانات SQLite (`events.db`) مع دعم التسجيل التلقائي للمصادر من الأحداث.
3. **حماية أمنية مشددة (Path Traversal Protection):** تمنع قراءة أو مسح أي ملف خارج مجلد السجلات المخصص.
4. **تكامل مع حاوية الخدمات (Service Container Integration):** تسجيل الخدمة باسم `log_manager` لتسهيل الحقن والاستدعاء.

---

## 2. كيفية استدعاء الوحدة واستخدامها في الكود (Python Usage)

### الطريقة الأولى: عبر حاوية الخدمات (`ServiceContainer`) — [التصميم الموصى به]

إذا كنت داخل وحدة أخرى تمتلك كائن `ServiceContainer`:

```python
from system.core.service_container import ServiceContainer

async def my_service_function(container: ServiceContainer):
    # الحصول على مدير السجلات المسجل
    log_controller = container.get("log_manager")
    
    # 1. إدراج حدث أمني أو تشغيلي جديد
    await log_controller.ingest_event({
        "module": "firewall",
        "level": "WARNING",
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "verdict": "DROP",
        "action": "DROP",
        "message": "Port scan activity detected"
    })
    
    # 2. الاستعلام عن الأحداث الأمنية
    events = await log_controller.query_events(src_ip="192.168.1.50", verdict="DROP", limit=10)
```

---

### الطريقة الثانية: الاستدعاء المباشر عبر الـ Singleton (`LogControllerManager`)

في حال عدم توفر `ServiceContainer` في سياق الكود الحالي:

```python
from modules.log_manager.engine.log_controller import LogControllerManager

# الحصول على النمط الفردي (Singleton)
controller = LogControllerManager.get_instance()

# البحث في الملفات النصية
results = controller.search_logs(keyword="ERROR", limit=50)

# استخراج إحصائيات السجلات
stats = controller.get_stats()
```

---

### الطريقة الثالثة: عبر الـ EventBus المركزي (Central Event Bus)

الوحدة تشترك تلقائياً في الأحداث التالية: `security.alert`, `traffic.flow`, `system.audit`. عند إرسال حدث عبر الـ EventBus يتم حفظه وتخزينه تلقائياً دون أي كود إضافي:

```python
await event_bus.publish("security.alert", {
    "module": "ips",
    "level": "CRITICAL",
    "src_ip": "45.33.32.156",
    "action": "BLOCK",
    "message": "SQL Injection attempt blocked"
})
```

---

## 3. عقود المدخلات والمخرجات (Input / Output Contracts)

### `ingest_event(event_data: Dict[str, Any]) -> None`
- **المدخلات (Inputs):** قاموس يحتوي على تفاصيل الحدث:
  - `module` (str, اختياري): اسم الوحدة المصدرية (مثل `"firewall"`).
  - `level` (str, اختياري): مستوى الحدث (`"INFO"`, `"WARNING"`, `"CRITICAL"`).
  - `src_ip` (str, اختياري): عنوان IP المصدر.
  - `dst_ip` (str, اختياري): عنوان IP الهدف.
  - `verdict` / `action` (str, اختياري): الإجراء المتخذ (`"ALLOW"`, `"DROP"`, `"BLOCK"`).
  - `message` (str, اختياري): نص الرسالة أو التنبيه.
- **المخرجات (Outputs):** لا شيء (`None`). يتم إنشاء `event_id` و `timestamp` تلقائياً إذا لم يتما التمرير.

---

### `query_events(src_ip: Optional[str], verdict: Optional[str], limit: int) -> List[Dict[str, Any]]`
- **المدخلات (Inputs):**
  - `src_ip` (فلترة بحسب عنوان IP المصدر).
  - `verdict` (فلترة بحسب القرار).
  - `limit` (الحد الأقصى للنتائج، الافتراضي: 100).
- **المخرجات (Outputs):** قائمة من القواميس الممثلة للأحداث المخزنة في SQLite أو ملفات JSON.

---

### `search_logs(file_name: Optional[str], level: Optional[str], keyword: Optional[str], limit: int) -> List[Dict[str, Any]]`
- **المدخلات (Inputs):**
  - `file_name` (اسم ملف محدد أو `"Live Memory Buffer"` أو `None` للكل).
  - `level` (مستوى السجل المراد البحث عنه).
  - `keyword` (كلمة بحث مفتاحية).
  - `limit` (عدد السطور المطلوبة، الافتراضي: 200).
- **المخرجات (Outputs):** قائمة بالقواميس بالشكل التالي:
```json
[
  {
    "file": "bunyanx.log",
    "content": "2026-07-22 21:00:00 [INFO] core: Service initialized successfully"
  }
]
```
- **تنبيه أمين:** يرمي استثناء `ValueError` في حال محاولة تمرير مسار نسبي غير آمن (`../`).

---

### `clear_logs(file_name: Optional[str]) -> int`
- **المدخلات (Inputs):** اسم الملف المراد تفريغه (أو `None` لتفريغ كافة الملفات النصية).
- **المخرجات (Outputs):** عدد الملفات التي تم تفريغها بنجاح (`int`).

---

## 4. واجهات البرمجة المتاحة (REST API Reference)

جميع الواجهات تبدأ بالبادئة: `/api/log_manager`

| المسار (Endpoint) | النوع (HTTP Method) | الوصف | المدخلات | المخرجات |
| :--- | :---: | :--- | :--- | :--- |
| `/config` | `GET` | قراءة إعدادات السجلات | لا يوجد | `{ "status": "success", "data": {...} }` |
| `/config` | `PUT` | تحديث الإعدادات ديناميكياً | JSON Body (`LogManagerConfigSchema`) | `{ "status": "success" }` |
| `/logs/stream` | `GET` | بث السجلات الحيّة (SSE) | لا يوجد | Stream of `data: {"timestamp":..., "message":...}\n\n` |
| `/logs/search` | `GET` | البحث في الملفات والسجلات | Query params (`file_name`, `keyword`, `level`, `limit`) | `{ "status": "success", "count": N, "data": [...] }` |
| `/logs/clear` | `POST` | مسح وتفريغ ملفات السجلات | JSON Body `{"file_name": "..."}` | `{ "status": "success", "cleared_files": N }` |
| `/logs/stats` | `GET` | إحصائيات الأحجام والملفات | لا يوجد | `{ "status": "success", "total_files": N, ... }` |
| `/logs/files` | `GET` | قائمة ملفات السجلات المتاحة | لا يوجد | `{ "status": "success", "data": ["bunyanx.log", ...] }` |
| `/events/search` | `GET` | البحث في الأحداث الهيكلية | Query params (`src_ip`, `verdict`, `limit`) | `{ "status": "success", "count": N, "data": [...] }` |
| `/visitors` | `GET` | تجميع وتلخيص حركة الزوار حسب IP | Query param (`limit`) | `{ "status": "success", "count": N, "data": [...] }` |

---

## 5. الحماية والأمان (Security Guidelines)

1. **Path Traversal Protection:** تم إلحاق الدالة الشديدة الحماية `is_safe_path()` على جميع عمليات القراءة والتفريغ لضمان حصر كل العمليات داخل مجلد `primary_log_dir` المنصوص عليه في الإعدادات.
2. **Thread Safety:** تعمل عمليات القراءة العكسية والبحث في مسارات غير متزامنة عن طريق `asyncio.get_running_loop().run_in_executor()` لمنع تجميد خيط المعالجة الرئيسي (Event Loop).

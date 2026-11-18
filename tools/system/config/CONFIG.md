# إعدادات نظام bunyanx NGFW

## ملفات الإعداد

| الملف | الغرض |
|-------|-------|
| `system/config/base.yaml` | الإعداد الرئيسي للنظام كله |
| `system/config/features.yaml` | Feature flags — تفعيل/إيقاف ميزات بدون إعادة تشغيل |
| `modules/firewall/config/settings.yaml` | إعدادات الجدار الناري |
| `modules/dns_security/config/settings.yaml` | إعدادات أمان DNS |
| `modules/*/config/settings.yaml` | إعدادات كل وحدة بشكل مستقل |

## قاعدة البيانات

**المسار الافتراضي:** `data/bunyanx.db`

### أولوية تحديد مسار قاعدة البيانات

```
1. متغير البيئة: bunyanx_DATABASE_URL   (الأولوية الأعلى — PostgreSQL)
2. متغير البيئة: bunyanx_DB_PATH        (مسار SQLite مخصص)
3. base.yaml → database.path            (إعداد في ملف الإعداد)
4. الافتراضي: data/bunyanx.db           (relative من جذر المشروع)
```

### للإنتاج على Linux

```bash
# SQLite مع مسار مخصص
export bunyanx_DB_PATH=/var/lib/bunyanx/bunyanx.db

# PostgreSQL (موصى به للإنتاج)
export bunyanx_DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/bunyanx
```

### للتطوير (الافتراضي)

```bash
# بدون أي إعداد → data/bunyanx.db تلقائياً
python main.py
```

## تشغيل Alembic (Migrations)

```bash
# من جذر المشروع دائماً
cd enterprise_ngfw
alembic upgrade head
```

## قراءة الإعدادات في الكود

```python
import yaml

with open("system/config/base.yaml", "r") as f:
    config = yaml.safe_load(f)

# التحقق من تفعيل وحدة
is_enabled = config.get("modules", {}).get("waf", {}).get("enabled", False)

# مسار قاعدة البيانات
db_path = config.get("database", {}).get("path", "data/bunyanx.db")
```

## تعديل الإعدادات عبر API

```http
GET  /api/v1/config
GET  /api/v1/config/modules
PUT  /api/v1/modules/waf/toggle
```

## متغيرات البيئة

| المتغير | الوصف |
|---------|-------|
| `bunyanx_DATABASE_URL` | URL كامل لقاعدة البيانات (PostgreSQL / SQLite) |
| `bunyanx_DB_PATH` | مسار ملف SQLite (بديل أبسط من URL) |
| `bunyanx_CONFIG` | مسار ملف base.yaml (الافتراضي: `system/config/base.yaml`) |
| `bunyanx_ENV` | بيئة التشغيل: `production` أو `development` |
| `bunyanx_SECRET_KEY` | مفتاح JWT — **يجب تعيينه في الإنتاج** |
| `bunyanx_ADMIN_PASSWORD` | كلمة مرور المدير — **يجب تعيينها قبل التشغيل** |
| `bunyanx_OPERATOR_PASSWORD` | كلمة مرور المشغّل — **يجب تعيينها قبل التشغيل** |

> [!CAUTION]
> لا تستخدم كلمات مرور افتراضية في الإنتاج.
> استخدم ملف `.env` أو مدير الأسرار (Vault, AWS Secrets Manager) لتعيين كلمات المرور.

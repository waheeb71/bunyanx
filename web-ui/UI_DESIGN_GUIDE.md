# 🎨 bunyanx NGFW — دليل تصميم الواجهات الموحد

### Enterprise UI Design System & Standards

**الإصدار:** 1.0 | **التاريخ:** 2026-05-17

---

## 📋 جدول المحتويات

1. [الرؤية والهوية البصرية](#1-الرؤية-والهوية-البصرية)
2. [نظام الألوان (Color System)](#2-نظام-الألوان)
3. [الخطوط (Typography)](#3-الخطوط)
4. [المكونات الأساسية (Core Components)](#4-المكونات-الأساسية)
5. [أنماط الصفحات (Page Patterns)](#5-أنماط-الصفحات)
6. [البيانات اللحظية (Real-Time Data)](#6-البيانات-اللحظية)
7. [الرسوم والمخططات (Charts & Visualizations)](#7-الرسوم-والمخططات)
8. [الحركة والتأثيرات (Motion & Animation)](#8-الحركة-والتأثيرات)
9. [هيكل الملفات الموحد (File Convention)](#9-هيكل-الملفات-الموحد)
10. [خريطة الوحدات (Module Map)](#10-خريطة-الوحدات)
11. [قواعد ذهبية (Golden Rules)](#11-قواعد-ذهبية)

---

## 1. الرؤية والهوية البصرية

### الهدف

واجهة تُشبه **مراكز العمليات الأمنية العسكرية (SOC)** — مستوحاة من:

| المنتج | ما نأخذ منه |
|--------|-------------|
| **CrowdStrike Falcon** | Widgets قابلة للتخصيص + Progressive Disclosure |
| **Darktrace** | 3D Threat Visualizer + أنماط "الحياة الطبيعية" |
| **Palo Alto PAN-OS** | التحكم التشغيلي + Device Health |
| **Palantir Gotham** | Network Graph + Timeline Analysis |

### الشعور المطلوب
>
> **"مركز قيادة عسكري رقمي"** — داكن، هادئ، دقيق، يبث الرهبة.
> البيانات تتحرك بسلاسة. الألوان الساطعة محجوزة للتحذيرات فقط.

### القواعد الأساسية

1. **Dark-First** — لا يوجد وضع فاتح (SOC analysts تعمل في إضاءة منخفضة)
2. **Data-Dense, Not Cluttered** — كثافة عالية بدون فوضى
3. **Motion = Meaning** — الحركة تُستخدم فقط لنقل معلومة (لا زخرفة)
4. **Color = Severity** — اللون يعني خطورة (لا تستخدم الأحمر للزينة)

---

## 2. نظام الألوان

### الخلفيات (Backgrounds)

```css
--bg-base:    #050810;   /* أعمق خلفية — الشاشة الرئيسية */
--bg-surface: #0a0e1a;   /* سطح البطاقات */
--bg-raised:  #0f1525;   /* عناصر مرتفعة (modals, dropdowns) */
--bg-overlay: #141b30;   /* حقول الإدخال، شريط البحث */
--bg-hover:   #1a2240;   /* hover state */
```

> ⚠️ **ممنوع** استخدام `#000000` (أسود مطلق) — يسبب إجهاد العين.

### الألوان الدلالية (Semantic Colors)

| اللون | المتغير | الاستخدام | متى تستخدمه |
|-------|---------|-----------|-------------|
| 🔵 Cyan | `--accent: #00c8ff` | العلامة التجارية، العناصر النشطة | أزرار رئيسية، روابط، عنصر مُختار |
| 🟢 Green | `--success: #00e676` | نجاح، نظام يعمل | "Active", "Connected", "Allowed" |
| 🟡 Amber | `--warning: #ffab40` | تحذير | تنبيهات متوسطة، انتهاء صلاحية |
| 🔴 Red | `--danger: #ff4d6a` | خطر، هجوم، حظر | Critical alerts, Blocked, Attack |
| 🔷 Blue | `--info: #448aff` | معلومات عامة | إحصائيات، ملاحظات |

### القاعدة الذهبية للألوان

```
90% خلفية داكنة + 8% نص رمادي/أزرق + 2% لون ساطع (alerts فقط)
```

**ممنوع:**

- ❌ استخدام الأحمر للأزرار العادية
- ❌ ألوان ساطعة لعناصر غير تفاعلية
- ❌ أكثر من لونين ساطعين في نفس البطاقة

---

## 3. الخطوط

| الاستخدام | الخط | الوزن |
|-----------|------|-------|
| العناوين الرئيسية | `Outfit` | 700-800 |
| النصوص والقوائم | `Inter` | 400-600 |
| الأكواد والأرقام | `JetBrains Mono` | 400-500 |

### سلم الأحجام

```css
--text-xs:  0.69rem;   /* badges, labels */
--text-sm:  0.8125rem; /* جداول، أزرار */
--text-base: 0.9375rem;/* نص عادي */
--text-lg:  1.0625rem; /* عناوين فرعية */
--text-xl:  1.25rem;   /* عناوين البطاقات */
--text-2xl: 1.5rem;    /* عناوين الأقسام */
--text-3xl: 2rem;      /* أرقام KPI كبيرة */
```

### قاعدة

- **الأرقام دائماً بـ `JetBrains Mono`** (IPs, ports, counters, timestamps)
- **العناوين العربية بـ `Inter` بوزن 600+**
- **النص الإنجليزي التقني بـ `Inter` بوزن 400**

---

## 4. المكونات الأساسية (Component Library)

### 4.1 بطاقة الإحصائيات (Stat Card)

```
┌─────────────────────────────┐
│  ⬆ 12.4%  ↑                │  ← اتجاه التغيير (أخضر/أحمر)
│                             │
│  14,832                     │  ← رقم KPI كبير (text-3xl, mono)
│  الحزم المحظورة اليوم       │  ← وصف (text-xs, muted)
│  ░░░░░░░░░░░░░░░░░░░░░░░░░ │  ← sparkline مصغر
└─────────────────────────────┘
```

**القواعد:**

- Glass background مع `backdrop-filter: blur(18px)`
- حدود `border: 1px solid var(--border)` — تتوهج عند hover
- الأيقونة في الزاوية مع لون خافت

### 4.2 جدول البيانات (Data Table)

```
┌──────────────────────────────────────────────────────┐
│ 🔍 [بحث...            ]  [الحالة ▾] [التصنيف ▾]     │ ← فلاتر
├──────┬───────────┬────────┬──────────┬────────────────┤
│ IP   │ الإجراء   │ البلد  │ الوقت    │ التهديد        │
├──────┼───────────┼────────┼──────────┼────────────────┤
│ mono │ badge     │ flag+  │ mono     │ severity-badge │
│      │ (colored) │ text   │ (مباشر) │ (red/amber/green)│
└──────┴───────────┴────────┴──────────┴────────────────┘
```

**القواعد:**

- أعمدة IPs/Ports بخط `mono` دائماً
- الحالة عبر `badge` ملون (ليس نص عادي)
- hover على الصف = `bg-hover` + glow خفيف
- Pagination أو Virtual Scroll للبيانات الكبيرة

### 4.3 شريط التصفية العلوي (Filter Bar)

```
┌───────────────────────────────────────────────────────┐
│ [🔍 بحث] [الخطورة ▾] [الفترة ▾] [النوع ▾]   [⟳ تحديث] │
└───────────────────────────────────────────────────────┘
```

- كل فلتر يُحدّث جميع المكونات في الصفحة (Global Filter)
- زر التحديث يُظهر spinner أثناء الجلب

### 4.4 بطاقة الوحدة (Module Status Card)

```
┌─────────────────────────────┐
│ 🟢 جدار الحماية             │  ← نقطة حالة + اسم
│ ───────────────────────     │
│ القواعد النشطة: 42          │  ← KPIs
│ آخر تحديث: منذ 3 ث          │  ← timestamp نسبي
│                    [إدارة →]│  ← رابط للوحدة
└─────────────────────────────┘
```

### 4.5 مؤشر الحالة (Status Indicator)

| الشكل | الاستخدام |
|-------|-----------|
| `🟢 نقطة ثابتة` | يعمل |
| `🟢 نقطة نابضة (pulse)` | متصل مباشر (Live) |
| `🟡 نقطة ثابتة` | تحذير / degraded |
| `🔴 نقطة ثابتة` | متوقف / خطأ |
| `⚫ نقطة رمادية` | غير مُفعّل |

---

## 5. أنماط الصفحات (Page Patterns)

### النمط A: صفحة الإدارة (CRUD Module)
>
> مثال: Firewall Rules, Web Filter, VPN, Proxy

```
┌─────────────────────────────────────────────────────┐
│ 📋 رأس الصفحة: [عنوان] + [وصف] + [⊕ إضافة جديد]  │
├─────────────────────────────────────────────────────┤
│ 🔍 شريط الفلاتر                                     │
├─────────────────────────────────────────────────────┤
│ 📊 جدول البيانات                                     │
│    - أعمدة قابلة للفرز                               │
│    - أزرار إجراء (تعديل/حذف/تبديل)                  │
│    - pagination                                      │
└─────────────────────────────────────────────────────┘
```

### النمط B: صفحة المراقبة (Monitoring Module)
>
> مثال: QoS, IDS/IPS, UBA, Predictive AI

```
┌─────────────────────────────────────────────────────┐
│ 📊 شريط KPI (3-5 بطاقات إحصائية)                    │
├──────────────────────┬──────────────────────────────┤
│ 📈 رسم بياني رئيسي   │ 📋 قائمة أحداث مباشرة       │
│ (recharts/d3)        │ (auto-scroll)               │
├──────────────────────┴──────────────────────────────┤
│ 📊 جدول تفصيلي مع فلاتر                             │
└─────────────────────────────────────────────────────┘
```

### النمط C: لوحة القيادة (Dashboard)
>
> الصفحة الرئيسية فقط

```
┌─────────────────────────────────────────────────────┐
│ 🎛️ شريط علوي: الحالة + الاتصال + الساعة             │
├─────────────────────────────────────────────────────┤
│ 📑 تبويبات: [SIEM] [أحداث] [سجلات] [زوار] [تهديدات]│
├─────────────────────────────────────────────────────┤
│ 🌍 المحتوى الديناميكي حسب التبويب                    │
│    - Globe.gl للخريطة الحية                          │
│    - Recharts للمخططات                              │
│    - D3.js للـ Network Graph                        │
└─────────────────────────────────────────────────────┘
```

---

## 6. البيانات اللحظية (Real-Time Data)

### الأدوات المستخدمة

| التقنية | الغرض | متى تستخدمه |
|---------|-------|-------------|
| `react-query` (polling) | بيانات تتغير كل 3-10 ث | KPIs, module status, bucket stats |
| `WebSocket` | بيانات لحظية فورية | Events feed, alerts, live logs |
| `EventSource (SSE)` | بث أحادي الاتجاه | Traffic charts, attack globe |

### قواعد الـ Polling

```javascript
// ✅ صحيح — staleTime + refetchInterval
useQuery({
  queryKey: ['qos_stats'],
  queryFn: () => qosApi.getStats(),
  refetchInterval: 5000,    // كل 5 ثواني
  staleTime: 3000,          // لا يعيد الجلب قبل 3 ثواني
});

// ❌ خطأ — بدون staleTime يجلب في كل render
useQuery({
  queryKey: ['stats'],
  queryFn: fetchStats,
  refetchInterval: 1000,    // ثقيل جداً!
});
```

### مؤشرات الحالة اللحظية

| العنصر | التنفيذ |
|--------|---------|
| نقطة نابضة خضراء | `animation: pulse-dot 1.8s infinite` |
| "منذ 3 ث" | `Intl.RelativeTimeFormat` — يتحدث كل ثانية |
| Sparkline | `recharts` مصغر بدون محاور (50×20px) |
| مؤشر تحميل | Skeleton shimmer (ليس spinner) |

---

## 7. الرسوم والمخططات

### اختيار المكتبة

| نوع الرسم | المكتبة | لماذا |
|-----------|---------|-------|
| Line/Bar/Area | `recharts` | سهل + React-native + responsive |
| Network Graph | `d3.js` | Force simulation للعلاقات بين IPs |
| الكرة الأرضية | `globe.gl` | خريطة هجمات 3D (Three.js تحتها) |
| آلاف النقاط | `deck.gl` | GPU-accelerated لبيانات ضخمة |
| Gauge/Meter | `recharts` (RadialBar) | QoS utilization, CPU |

### قواعد الألوان في الرسوم

```
✅ خط واحد:   #00c8ff (accent)
✅ خطان:      #00c8ff + #a78bfa (accent + purple)
✅ ثلاثة:     #00c8ff + #00e676 + #ffab40
✅ خطر:       #ff4d6a (دائماً أحمر)
❌ ممنوع:     ألوان عشوائية أو قوس قزح
```

### قواعد الرسوم البيانية

- **محاور شفافة** — `stroke: var(--border)` (لا أسود ولا أبيض)
- **بدون شبكة (grid)** — إلا إذا كانت خفيفة جداً
- **Tooltip مخصص** — glass background + mono numbers
- **Area fill** — gradient إلى شفاف (opacity 0.1 → 0)

---

## 8. الحركة والتأثيرات (Motion)

### مكتبة الحركة: `framer-motion`

### جدول التوقيتات

| النوع | المدة | الاستخدام |
|-------|-------|-----------|
| Micro | `150ms` | hover, focus, toggle |
| Normal | `250ms` | بطاقة تظهر, tab يتبدل |
| Page | `350ms` | صفحة تدخل/تخرج |
| Dramatic | `600ms+` | الكرة الأرضية, 3D transitions |

### أنماط دخول المكونات

```jsx
// بطاقة تظهر من الأسفل
<motion.div
  initial={{ opacity: 0, y: 20 }}
  animate={{ opacity: 1, y: 0 }}
  transition={{ duration: 0.3 }}
/>

// قائمة staggered (كل عنصر يتأخر 0.05s)
{items.map((item, i) => (
  <motion.div
    key={item.id}
    initial={{ opacity: 0, x: -10 }}
    animate={{ opacity: 1, x: 0 }}
    transition={{ delay: i * 0.05 }}
  />
))}
```

### ممنوعات

- ❌ `transition > 600ms` على عناصر عادية
- ❌ bounce/spring مبالغ فيه
- ❌ حركة على عناصر لا يتفاعل معها المستخدم

---

## 9. هيكل الملفات الموحد

### بنية كل وحدة (Module)

```
src/modules/{module_name}/
├── {ModuleName}.jsx         # الصفحة الرئيسية
├── {ModuleName}.css         # أنماط الصفحة
├── components/              # مكونات فرعية
│   ├── {Widget}Card.jsx
│   └── {Feature}Table.jsx
└── views/                   # sub-views (اختياري)
    └── {SubPage}.jsx
```

### تسمية الملفات

| النوع | الصيغة | مثال |
|-------|--------|------|
| صفحة رئيسية | `PascalCase.jsx` | `QoS.jsx` |
| مكون فرعي | `PascalCase.jsx` | `BucketTable.jsx` |
| أنماط | `PascalCase.css` | `QoS.css` |
| Hook | `camelCase.js` | `useQoSStats.js` |
| خدمة API | `camelCase.js` | `qosApi.js` (في `services/api.js`) |

### تسمية CSS Classes

```css
/* النمط: {module}-{element}--{modifier} (BEM مُبسط) */
.qos-card { }
.qos-card--active { }
.qos-bucket-row { }
.qos-bucket-row--critical { }
```

---

## 10. خريطة الوحدات

### الوحدات المطلوبة (20 صفحة)

| الوحدة | النمط | بيانات لحظية؟ | مكتبات خاصة |
|--------|-------|-------------|-------------|
| Dashboard | C (لوحة قيادة) | ✅ WebSocket + Polling | globe.gl, d3, recharts |
| Firewall | A (CRUD) | ❌ | — |
| IP Blocklist | A (CRUD) | ❌ | — |
| WAF | A (CRUD) + B | ✅ Polling | recharts |
| IDS/IPS | B (مراقبة) | ✅ Polling | recharts |
| Malware AV | B (مراقبة) | ✅ Polling | recharts |
| DNS Security | A + B | ✅ Polling | recharts |
| VPN | A (CRUD) | ❌ | — |
| Proxy | A + B | ✅ Polling | recharts |
| Email Security | A (CRUD) | ❌ | — |
| Web Filter | A (CRUD) | ❌ | — |
| QoS | B (مراقبة) | ✅ Polling 5s | recharts (gauge) |
| HTTP Inspection | B (مراقبة) | ✅ Polling | recharts |
| SSL Inspection | B (مراقبة) | ✅ Polling | recharts |
| DLP | A + B | ✅ Polling | recharts |
| Predictive AI | B (مراقبة) | ✅ Polling | recharts, d3 |
| UBA | B (مراقبة) | ✅ Polling | recharts, d3 |
| System Health | B (مراقبة) | ✅ Polling 3s | recharts |
| Users | A (CRUD) | ❌ | — |
| Settings | A (CRUD) | ❌ | — |

---

## 11. قواعد ذهبية

### 🏛️ قواعد معمارية

| # | القاعدة |
|---|---------|
| 1 | **لا CSS مكرر** — استخدم tokens.css + index.css. الأنماط المشتركة لا تتكرر |
| 2 | **كل API في `services/api.js`** — لا `fetch()` أو `axios` مباشر في المكونات |
| 3 | **`react-query` لكل جلب** — لا `useEffect` + `useState` لـ API calls |
| 4 | **`zustand` للحالة العالمية** — لا Context API للبيانات المتغيرة بسرعة |
| 5 | **`framer-motion` فقط** — لا CSS animations معقدة يدوية |

### 🎨 قواعد بصرية

| # | القاعدة |
|---|---------|
| 6 | **Glass background لكل بطاقة** — `var(--glass-bg)` + `backdrop-filter` |
| 7 | **حدود تتوهج عند hover** — `border-color: var(--border-bright)` |
| 8 | **الأيقونات من `lucide-react` فقط** — لا Font Awesome أو مخلوطة |
| 9 | **RTL-first** — كل صفحة تبدأ بـ `dir="rtl"` |
| 10 | **Responsive** — min-width: 1024px (لا حاجة لموبايل في SOC) |

### 📊 قواعد البيانات اللحظية

| # | القاعدة |
|---|---------|
| 11 | **Skeleton loading** — لا spinners فارغة |
| 12 | **Optimistic updates** — التحديث يظهر فوراً ثم يتحقق |
| 13 | **Error boundaries** — كل صفحة تُظهر رسالة خطأ جميلة |
| 14 | **لا يتجمد أي شيء** — polling لا يقل عن 3 ثواني |
| 15 | **Empty states** — لا جداول فارغة بدون رسالة |

### 🔒 قواعد أمنية

| # | القاعدة |
|---|---------|
| 16 | **لا تعرض tokens/keys في الواجهة** — httpOnly cookies |
| 17 | **sanitize كل input** — XSS prevention |
| 18 | **RBAC على الواجهة** — إخفاء الأزرار غير المصرح بها |

---

## مصادر الإلهام

| المصدر | الفائدة |
|--------|---------|
| [CrowdStrike Falcon](https://www.crowdstrike.com) | Widget architecture + drill-down |
| [Darktrace](https://www.darktrace.com) | 3D threat visualizer + anomaly UI |
| [Palo Alto PAN-OS](https://www.paloaltonetworks.com) | Device health + policy management |
| [Elastic SIEM](https://www.elastic.co/security) | Log explorer + timeline |
| [Dribbble "SOC Dashboard"](https://dribbble.com/search/soc-dashboard) | Visual inspiration |

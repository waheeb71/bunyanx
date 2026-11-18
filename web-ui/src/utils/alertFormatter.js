/**
 * Alert Formatter Utility
 * Translates raw EventBus topics and developer logs into clean, standardized Arabic titles,
 * categories, and descriptions for System Event Center and Module Monitoring UIs.
 */

const ALERT_MAP = {
  // ── 1. أحداث النظام والنواة (System Core & Lifecycle) ─────────────────
  'system.started': {
    title: 'بدء تشغيل النظام الأساسي',
    desc: 'تم تشغيل نواة الجدار الناري وبدء خدمات المراقبة الشبكية بنجاح.',
    module: 'النظام الأساسي',
    category: 'system'
  },
  'system.shutdown': {
    title: 'إيقاف تشغيل النظام',
    desc: 'تم إرسال إشارة إيقاف تشغيل آمن لنواة الجدار الناري.',
    module: 'النظام الأساسي',
    category: 'system'
  },
  'system.core_failure': {
    title: 'تنبيه حرج: خطأ في نواة النظام',
    desc: 'تم اكتشاف خلل غير متوقع في المحرك الأساسي للجدار الناري.',
    module: 'النظام الأساسي',
    category: 'system'
  },
  'system.memory_critical': {
    title: 'تنبيه استهلاك الذاكرة',
    desc: 'تجاوز استهلاك ذاكرة النظام (RAM) الحد الآمن والمسموح به.',
    module: 'مراقبة الموارد',
    category: 'system'
  },
  'system.cpu_critical': {
    title: 'تنبيه ضغط المعالج',
    desc: 'ارتفاع حاد في استهلاك وحدة المعالجة المركزية (CPU) لفترة مستمرة.',
    module: 'مراقبة الموارد',
    category: 'system'
  },
  'system.core.engine': {
    title: 'تحديث حالة النواة (Core Engine)',
    desc: 'حدث متعلق بسلامة تشغيل النظام الأساسي واستقرار النواة.',
    module: 'النظام الأساسي',
    category: 'system'
  },
  'module.health': {
    title: 'فحص صحة الوحدات الأمنية',
    desc: 'تقرير دوري لحالة التشغيل وسلامة محركات الفحص في الجدار الناري.',
    module: 'إدارة الوحدات',
    category: 'system'
  },
  'module.started': {
    title: 'تشغيل وحدة أمنية',
    desc: 'تم تفعيل وتشغيل محرك فحص إضافي بنجاح.',
    module: 'إدارة الوحدات',
    category: 'system'
  },
  'module.stopped': {
    title: 'إيقاف وحدة أمنية',
    desc: 'تم إيقاف تشغيل إحدى الوحدات الأمنية في النظام.',
    module: 'إدارة الوحدات',
    category: 'system'
  },
  'config.reloaded': {
    title: 'إعادة تحميل الإعدادات',
    desc: 'تم تحديث وتحميل سياسات وإعدادات النظام الحية بنجاح.',
    module: 'إدارة التكوين',
    category: 'config'
  },
  'config.saved': {
    title: 'حفظ تكوين النظام',
    desc: 'تم حفظ إعدادات الجدار الناري وتطبيق السياسات الجديدة.',
    module: 'إدارة التكوين',
    category: 'config'
  },

  // ── 2. جدار حماية تطبيقات الويب (WAF) ─────────────────────────────
  'waf.block': {
    title: 'حظر هجوم ويب (WAF Block)',
    desc: 'تم حظر محاولة استغلال أو اختراق تطبيقات الويب (SQLi / XSS / RCE) بنجاح.',
    module: 'جدار الويب (WAF)',
    category: 'security'
  },
  'waf.alert': {
    title: 'تنبيه جدار الويب (WAF Alert)',
    desc: 'تم الكشف عن نشاط مشبوه أو طلب غير اعتيادي يستهدف تطبيقات الويب.',
    module: 'جدار الويب (WAF)',
    category: 'security'
  },

  // ── 3. كشف ومنع التسلل الشبكي (IDS / IPS) ─────────────────────────
  'ids.port_scan': {
    title: 'كشف فحص منافذ شبكية (Port Scan)',
    desc: 'تم رصد محاولة فحص منافذ شبكية واستطلاع للبنية التحتية من مصدر خارجي.',
    module: 'كشف التسلل (IDS/IPS)',
    category: 'security'
  },
  'ids.block': {
    title: 'حجب تطفل شبكي (IPS Block)',
    desc: 'تم حظر محاولة اختراق شبكي أو ثغرة بروتوكولات أو اتصال استحواذ.',
    module: 'منع التسلل (IPS)',
    category: 'security'
  },
  'ips.block': {
    title: 'حجب تطفل شبكي (IPS Block)',
    desc: 'تم حظر محاولة اختراق شبكي أو ثغرة بروتوكولات أو اتصال استحواذ.',
    module: 'منع التسلل (IPS)',
    category: 'security'
  },
  'ids.alert': {
    title: 'كشف تطفل شبكي (IDS Alert)',
    desc: 'تم الكشف عن حزم بيانات تطابق توقيعات هجمات معروفة.',
    module: 'كشف التسلل (IDS)',
    category: 'security'
  },
  'ids_ips': {
    title: 'كشف محاولة تطفل (IDS/IPS)',
    desc: 'تم الكشف عن فحص منافذ أو سلوك شبكي مشبوه على طبقة النقل.',
    module: 'كشف ومنع التسلل',
    category: 'security'
  },

  // ── 4. أمن نظام أسماء النطاقات (DNS Security) ─────────────────────
  'dns.threat': {
    title: 'حظر تهديد DNS (DNS Threat)',
    desc: 'تم منع استعلام عن نطاق خبيث معروف أو مرتبط بـ Command & Control.',
    module: 'أمن DNS',
    category: 'security'
  },
  'dns.suspicious': {
    title: 'استعلام DNS مشبوه',
    desc: 'تم رصد نشاط غير اعتيادي أو محاولة نفق بيانات عبر بروتوكول DNS.',
    module: 'أمن DNS',
    category: 'security'
  },
  'dns_security': {
    title: 'حماية وحظر نطاقات DNS',
    desc: 'تم فحص أو حظر طلب اتصال بنطاق مشبوه أو خبيث.',
    module: 'أمن DNS',
    category: 'security'
  },

  // ── 5. مكافحة البرمجيات الخبيثة (Malware AV) ────────────────────────
  'malware.detected': {
    title: 'اكتشاف برمجية خبيثة (Malware Detected)',
    desc: 'تم رصد ملف ضار أو توقيع برمجية خبيثة أثناء مرور الحزم وتم عزله.',
    module: 'مكافحة الفيروسات (AV)',
    category: 'security'
  },
  'malware_av': {
    title: 'عزل برمجية خبيثة (AV)',
    desc: 'تم رصد ملف ضار أو برمجية خبيثة وعزلها بنجاح.',
    module: 'مكافحة الفيروسات (AV)',
    category: 'security'
  },

  // ── 6. منع تسريب البيانات (DLP) ───────────────────────────────────
  'dlp.incident': {
    title: 'رصد محاولة تسريب بيانات (DLP Incident)',
    desc: 'تم اكتشاف محاولة نقل بيانات حساسة، أرقام سرية، أو مستندات سرية للخارج.',
    module: 'حماية البيانات (DLP)',
    category: 'security'
  },
  'dlp': {
    title: 'منع تسريب البيانات (DLP)',
    desc: 'تم رصد محاولة نقل أو تسريب بيانات حساسة أو مفاتيح برمجية.',
    module: 'حماية البيانات (DLP)',
    category: 'security'
  },

  // ── 7. تصفية الويب والأمن البريدي ────────────────────────────────
  'web_filter.block': {
    title: 'حظر موقع محظور (Web Filter Block)',
    desc: 'تم منع الوصول إلى موقع إلكتروني يخالف سياسات الاستخدام والأمان.',
    module: 'تصفية الويب',
    category: 'policy'
  },
  'email.threat': {
    title: 'تهديد بريد إلكتروني (Email Threat)',
    desc: 'تم رصد رسالة تصيّد احتيالي (Phishing) أو مرفق مشبوه.',
    module: 'أمن البريد',
    category: 'security'
  },

  // ── 8. المصادقة وحماية الوصول (Authentication & Access) ───────────
  'auth.login_success': {
    title: 'تسجيل دخول ناجح',
    desc: 'تم تسجيل الدخول للوحة التحكم الإدارية بنجاح.',
    module: 'المصادقة والوصول',
    category: 'auth'
  },
  'auth.login_failure': {
    title: 'فشل محاولة الدخول',
    desc: 'محاولة غير ناجحة لتسجيل الدخول للنظام ببيانات غير صحيحة.',
    module: 'المصادقة والوصول',
    category: 'auth'
  },
  'auth.brute_force': {
    title: 'هجوم تخمين كلمات المرور (Brute Force)',
    desc: 'تم رصد محاولات متكررة وفاشلة لتسجيل الدخول من نفس العنوان وتم تقييدها.',
    module: 'المصادقة والوصول',
    category: 'security'
  },

  // ── 9. الذكاء الاصطناعي والاستجابة الفورية (AI & Response) ──────────
  'threat.detected': {
    title: 'اكتشاف تهديد أمني (Threat Detected)',
    desc: 'تم تصنيف حدث أمني كتهديد محتمل بواسطة محركات التحليل المتقدم.',
    module: 'الاستجابة الفورية',
    category: 'security'
  },
  'response.block': {
    title: 'حظر فوري للتهديد (Response Block)',
    desc: 'تم تطبيق قاعدة حظر تلقائي على عنوان IP مشبوه.',
    module: 'الاستجابة الفورية',
    category: 'security'
  },
  'ai.score_generated': {
    title: 'تقييم الذكاء الاصطناعي (AI Risk Score)',
    desc: 'تم تحليل الجلسة بواسطة محرك الذكاء الاصطناعي التنبؤي.',
    module: 'الذكاء الاصطناعي',
    category: 'security'
  },
  'anomaly.scored': {
    title: 'رصد شذوذ سلوكي (Anomaly Detected)',
    desc: 'تم اكتشاف انحراف في السلوك الشبكي عن خط الأساس الطبيعي.',
    module: 'تحليل السلوك (UBA)',
    category: 'security'
  },

  // ── 10. الشبكة والاتصال المشفر (VPN & Networking) ──────────────────
  'vpn.failure': {
    title: 'انقطاع أو خطأ في نفق VPN',
    desc: 'تعذر الاتصال أو انقطاع في إحدى قنوات الشبكة الافتراضية المشفرة.',
    module: 'الشبكة الافتراضية (VPN)',
    category: 'network'
  },
  'vpn.restored': {
    title: 'استعادة اتصال VPN',
    desc: 'تم إعادة الاتصال بنفق الشبكة الافتراضية المشفرة بنجاح.',
    module: 'الشبكة الافتراضية (VPN)',
    category: 'network'
  },
  'vpn': {
    title: 'نشاط نفق الـ VPN',
    desc: 'تم رصد محاولة اتصال أو تعديل في أنفاق الشبكة الافتراضية.',
    module: 'الشبكة الافتراضية (VPN)',
    category: 'network'
  },

  // ── 11. الشهادات والتوفر العالي (PKI & HA) ─────────────────────────
  'pki.cert_expiring': {
    title: 'تنبيه قرب انتهاء صلاحية شهادة',
    desc: 'إحدى شهادات التشفير الرقمية قاربت على الانتهاء وتتطلب التجديد.',
    module: 'إدارة الشهادات (PKI)',
    category: 'system'
  },
  'ha.failover': {
    title: 'تبديل التوفر العالي (HA Failover)',
    desc: 'تم تحويل حركة المرور إلى الخادم الاحتياطي للحفاظ على استمرارية الخدمة.',
    module: 'التوفر العالي (HA)',
    category: 'system'
  }
};

export function formatAlert(alert) {
  if (!alert) return alert;

  const rawTitle = alert.alert_type || alert.title || alert.category || '';
  const rawDesc = alert.description || '';

  let friendlyTitle = rawTitle;
  let friendlyDesc = rawDesc;
  let friendlyModule = alert.module || 'مركز الأحداث';
  let friendlyCategory = alert.category || 'other';

  // Find exact or partial matching topic/key
  const matchedKey = Object.keys(ALERT_MAP).find(k =>
    rawTitle.toLowerCase() === k.toLowerCase() ||
    rawTitle.toLowerCase().includes(k.toLowerCase())
  );

  if (matchedKey) {
    const meta = ALERT_MAP[matchedKey];
    friendlyTitle = meta.title;
    friendlyModule = meta.module || friendlyModule;
    friendlyCategory = meta.category || friendlyCategory;
    if (!rawDesc || rawDesc === rawTitle) {
      friendlyDesc = meta.desc;
    }
  } else if (rawTitle.includes('.')) {
    friendlyTitle = rawTitle
      .split('.')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  // Parse structured JSON descriptions gracefully
  if (friendlyDesc && friendlyDesc.startsWith('{') && friendlyDesc.endsWith('}')) {
    try {
      const parsed = JSON.parse(friendlyDesc);
      friendlyDesc = parsed.reason || parsed.description || parsed.message || friendlyDesc;
    } catch (e) {
      // Keep original text if JSON parse fails
    }
  }

  // Handle internal loopback / kernel addresses nicely
  let friendlyIp = alert.src || alert.src_ip || alert.source_ip || '?.?.?.?';
  if (friendlyIp === '0.0.0.0' || friendlyIp === '127.0.0.1' || friendlyIp.toLowerCase() === 'localhost') {
    friendlyIp = 'نواة النظام (Internal)';
  }

  return {
    ...alert,
    title: friendlyTitle,
    description: friendlyDesc,
    moduleLabel: friendlyModule,
    categoryLabel: friendlyCategory,
    src: friendlyIp,
    src_ip: friendlyIp,
  };
}

export default formatAlert;

export const CATEGORY_GUIDE = {
  proxy: {
    title: 'وكيل الشبكة العكسي والأمامي (Proxy)',
    desc: 'مكون أساسي يتحكم في كيفية مرور البيانات من وإلى الخوادم. يمكنك تعديل منافذ الاستماع (Ports)، ومستوى التسجيل (Logs)، وحدود الاتصالات هنا.',
  },
  network: {
    title: 'الشبكة والمسارات (Network)',
    desc: 'يتعامل هذا القسم مع إعدادات بروتوكول الإنترنت، خوادم الأسماء (DNS)، مسارات التوجيه، وبوابة الإنترنت الافتراضية (Gateway).',
  },
  security: {
    title: 'قواعد الأمان الرئيسية (Security)',
    desc: 'إعدادات شهادات التشفير (SSL/TLS)، المفاتيح، والسياسات الأمنية العامة التي تحدد صلابة خوادمك وعُرضتها للهجمات.',
  },
  modules: {
    title: 'مدير محركات الإضافة (Modules Manager)',
    desc: 'تحتوي على مُقدمة حول الوحدات المٌكلفة بالعمل مثل الجدار الناري، وواجهة واف، الخ. يمكنك تشغيل واطفاء الوحدات من هنا.',
  },
  logging: {
    title: 'نظام المراقبة والتسجيل (Logging)',
    desc: 'أين يتم إرسال الأحداث الأمنية الخاصة بالنظام. هل تود حفظها محليا أم إرسالها نحو سيرفرات (Syslog) أو (SIEM)؟ تفضل بالإعداد هنا.',
  },
  performance: {
    title: 'الأداء (Performance)',
    desc: 'لإدارة استهلاك الذاكرة والمعالج. إن كنت لا تعرف ما تقوم به، ينصح بتركها كما هي لتجنب تحميل النظام أعباء إضافية أو انهياره.',
  },
  waf: {
    title: 'الجدار الناري لتطبيقات الويب (WAF)',
    desc: 'قواعد الأمان الخاصة بالويب والتي تحمي تطبيقاتك من الاختراقات الشائعة (مثل حقن SQL، وثغرات XSS).',
  },
  ids_ips: {
    title: 'أنظمة كشف ومنع التسلل (IDS/IPS)',
    desc: 'إعدادات عميقة للتعرف على التوقيعات والهجمات المتسلسلة على مستوى الشبكة.',
  },
  default: {
    title: 'إعدادات هيكلية عامة',
    desc: 'هذا القسم يحتوي على متغيرات تنظيمية ضمن ملف الإعداد المطلوب، يرجى التعديل عليها بعناية.',
  }
};

export const EXACT_GUIDE = {
  'proxy.port': { title: 'منفذ الوكيل (Port)', desc: 'المنفذ الذي يطل منه محرك البروكسي على الشبكة المحلية.', example: 'مثال: 3128 أو 8080' },
  'proxy.transparent': { title: 'وكيل شفاف (Transparent)', desc: 'إن فُعلت، لن يضطر العملاء لإعداد البروكسي يدوياً على أجهزتهم؛ بل سيعترض النظام تدفق بياناتهم بصمت.', example: 'true / false' },
  'network.dns_servers': { title: 'خوادم تحليل الأسماء', desc: 'عناوين IP لخوادم الـ DNS الموثوقة والتي سيستخدمها جدار الحماية للاستعلام عن الوجهات.', example: "['8.8.8.8', '1.1.1.1']" },
  'logging.level': { title: 'تشخيص السجل (Log Level)', desc: 'كلما اخترت مستوى أقل (مثل Debug)، سيمتلئ السجل بمعلومات أكثر، وهذا جيد للتتبع ولكن يستهلك المساحة.', example: 'info, warning, error, debug' }
};

export const COMMON_GUIDE = {
  'enabled': { title: 'مفتاح التشغيل', desc: 'تفعيل أو تعطيل هذه الخدمة أو الخاصية برمتها.', example: 'true أو false' },
  'port': { title: 'المنفذ الرقمي (Port)', desc: 'بوابة الاتصال التي تنتظر استقبال الطلبات خلفها.', example: 'من 1 إلى 65535' },
  'host': { title: 'الخادم المضضيف (Host)', desc: 'عنوان واجهة الشبكة (IP) التي ستُربط الخدمة بها.', example: "'0.0.0.0' للجميع، أو '127.0.0.1' للداخلي فقط" },
  'timeout': { title: 'مهلة انتظار الاستجابة (Timeout)', desc: 'أقصى مدة (عادة بالثواني) ينتظرها الخادم قبل إقفال الاتصال المعلق درءاً للاختناقات.', example: '30, 60, 120' },
  'max_connections': { title: 'ذروة الاتصالات المتزامنة', desc: 'أقصى عدد يمكن للخدمة استيعابه في ذات اللحظة لمنع تحميل السيرفر فوق طاقته (DDoS).', example: '1000, 4096' },
  'log_level': { title: 'وضوح وإسهاب التسجيل', desc: 'يُحدد حجم المعلومات المحفوظة في ملفات النظام. للإدارة اختر info، للتطوير اختر debug.', example: 'info, debug, disabled' },
  'mode': { title: 'وضعية التشغيل', desc: 'النمط السلوكي الذي تُنفذ به المهام لهذه الإضافة.', example: "'strict' (صارم)، 'passive' (سلبي للمراقبة فقط)" }
};

export function getCategoryGuide(categoryName) {
  return CATEGORY_GUIDE[categoryName] || CATEGORY_GUIDE.default;
}

export function getFieldGuide(pathArray) {
  if (!pathArray || pathArray.length === 0) return null;
  
  // pathArray مثلا: ['proxy', 'settings', 'max_connections']
  const fullPath = pathArray.join('.');
  if (EXACT_GUIDE[fullPath]) return EXACT_GUIDE[fullPath];
  
  const lastKey = pathArray[pathArray.length - 1];
  if (COMMON_GUIDE[lastKey]) {
    return COMMON_GUIDE[lastKey];
  }

  // إذا لم يكن هناك شرح مخصص، نوفر شرحاً افتراضياً تشجيعياً.
  return {
    title: lastKey.toUpperCase(),
    desc: 'مؤشر تكوين خاص بالنظام. قم بتغييره إن كنت تعي وظيفته المعمارية.',
    example: 'القيمة الافتراضية تعتمد على نوع البيانات (رقم، نص، مصفوفة)'
  };
}

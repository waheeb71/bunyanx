# الدليل المرجعي الشامل لتفعيل وإعداد خدمة HTTPS وفحص التشفير SSL/TLS في Enterprise NGFW

هذا المستند يُعد مرجعاً كاملاً لتفعيل خدمات HTTPS، فحص التشفير المتقدم (SSL/TLS Inspection)، إدارة الشهادات، شراء وتثبيت الشهادات العامة للمواقع (Public Certificates)، وتثبيت شهادات الجذر (Root CA) للعملاء والموظفين في الداخل والخارج في جدار الحماية **BunyanX Enterprise NGFW**.

---

## 1. المفاهيم الأساسية: الفارق بين شهادات المواقع الخارجية وشهادات التفتيش الداخلي

يقوم جدار الحماية بالتعامل مع التشفير وفق نمطين أمنيين مختلفين تماماً:

| النمط المشفر | مجال الاستخدام | نوع الشهادة المستعملة | هل يتطلب تثبيت شهادات عند العميل؟ |
| :--- | :--- | :--- | :--- |
| **1. البروكسي العكسي والـ WAF (Reverse Proxy / WAF)** | حماية خوادم ومواقع الشركة المعروضة للمستخدمين والعملاء الخارجيين عبر الإنترنت (مثل `https://bank.company.com` أو IP الـ VIP). | **شهادة عامة موثوقة (Public CA)** يتم شراؤها أو إصدارها مجاناً من هيئات موثوقة عالمياً (مثل Let's Encrypt / DigiCert / Sectigo / Cloudflare). | **❌ لا إطلاقاً (Zero Client Config)**<br/>لأن الشهادة موثوقة مسبقاً ومدمجة بجميع المتصفحات والأنظمة عالمياً. |
| **2. فحص التشفير الشفاف والصريح (Transparent / Forward SSL Inspection)** | تفتيش اتصالات الموظفين والعملاء الداخليين عند تصفحهم لمواقع إنترنت خارجية مشفرة (مثل `https://google.com`). | **شهادة جذر مؤسسية (Enterprise Root CA)** يتم توليدها محلياً بداخل الجدار الناري لتوقيع شهادات مؤقتة ديناميكياً (On-the-Fly Certificates). | **✅ نعم (تُثبت مرة واحدة)**<br/>تُثبت على أجهزة الموظفين والشبكة الداخلية لثقتهم بالجدار الناري أثناء فك التشفير والتفتيش. |

---

## 2. كيفية شراء واستخدام شهادة عامة (Public CA Certificate) بدون تثبيت شيء عند العملاء

عند رغبتك في تشغيل مواقع الشركة وتطبيقات الـ VIP (مثل البنك الإلكتروني) عبر HTTPS ليتمكن أي مستخدم أو عميل خارجي في العالم من زيارتها **دون ظهور أي تحذيرات أمان** وبدون تثبيت أي شهادات لديه:

### أ) خطوات الحصول على الشهادة العامة:
1. **شراء أو إصدار الشهادة:**
   - **مجاناً:** عبر هيئة **Let's Encrypt** أو **ZeroSSL** باستخدام بروتوكول ACME.
   - **مدفوع (تجاري):** شراء شهادة DV/OV/EV من مزود مثل **DigiCert**, **Sectigo**, أو **GlobalSign**.
2. **الملفات الصادرة من هيئة الترقيم (CA):**
   تحصل من المزود على ملفين رئيسيين:
   - `server_cert.pem`: يحتوي على شهادة موقعك متبوعة بشهادات السلسلة المتوسطة (Intermediate CA Chain).
   - `server_key.pem`: المفتاح الخاص (Private Key) التابع للشهادة.

### ب) وضع الشهادات في الجدار الناري:
1. انسخ الملفين إلى مجلد الشهادات بالنظام:
   ```bash
   cp server_cert.pem F:/enterprise_ngfw/certs/server_cert.pem
   cp server_key.pem  F:/enterprise_ngfw/certs/server_key.pem
   ```
2. اربط الشهادة في ملف التكوين الرئيسي (`system/config/base.yaml`) تحت إعدادات البروكسي العكسي:
   ```yaml
   proxy:
     mode: reverse
     
     # إعدادات مفاتيح التشفير الخارجية
     server_cert: certs/server_cert.pem
     server_key: certs/server_key.pem

     # جدول الـ VIPs للخوادم الداخلية المعروضة للخارج
     vips:
     - name: Internal Bank App (HTTPS)
       external_ip: 192.168.1.33
       external_port: 443            # المنفذ المشفر الخارجي
       internal_ip: 10.10.0.50
       internal_port: 8080           # منفذ السيرفر الداخلي
       use_tls_upstream: false
   ```

### ج) كيف تعمل للعملاء الخارجيين؟
عندما يتصل العميل الخارجي بـ `https://192.168.1.33` أو اسم النطاق الخاص بك، يقدم الجدار الناري الشهادة العامة المعتمدة (`server_cert.pem`). نظراً لأن متصفح العميل (Chrome, Safari, Firefox, Edge) يتضمن قائمة موثوقة مسبقاً تضم DigiCert / Let's Encrypt، يتم القبول والمصافحة **فوراً وبأعلى درجات التشفير الخالي من التنبيهات**.

---

## 3. دليل تثبيت شهادة الجذر (Enterprise Root CA) على الأجهزة والعملاء الداخليين

عند تفعيل **فحص التشفير الشفاف (Transparent HTTPS Inspection)** لاتصالات الموظفين المتجهة للخارج، يولد الجدار الناري شهادات مؤقتة لكل موقع يزوره المستخدم. لكي لا تظهر تحذيرات أمان (`NET::ERR_CERT_AUTHORITY_INVALID`) على أجهزة الموظفين، يجب نشر شهادة الجذر الخاصة بالنظام (`certs/root-ca.crt`):

### 🏢 1. التوزيع التلقائي عبر الشبكة والدومين (Active Directory Group Policy - GPO)
في بيئات الشركات، لا يتطلب الأمر الذهاب لكل جهاز يدوياً؛ بل يتم نشر الشهادة بنقرة واحدة لجميع الأجهزة بالدومين:
1. افتح **Group Policy Management Console (`gpmc.msc`)** على سيرفر الـ Active Directory.
2. أنشئ **GPO** جديد باسم `BunyanX Root CA Deployment` واربطه بالـ Domain.
3. اذهب إلى:
   `Computer Configuration` ◄ `Policies` ◄ `Windows Settings` ◄ `Security Settings` ◄ `Public Key Policies` ◄ `Trusted Root Certification Authorities`.
4. انقر بزر الماوس الأيمن واختر **Import**، ثم حدد الملف `root-ca.crt`.
5. فور تحديث السياسات (`gpupdate /force`)، تصبح الشهادة موثوقة تلقائياً على جميع أجهزة الموظفين دون أي تدخل منهم.

---

### 💻 2. التوزيع عبر أدوات إدارة الأجهزة الذكية (MDM - Intune / Jamf)
لأجهزة Mac و Windows والواتف المحمولة التابعة للشركة:
- **Microsoft Intune:** رفع الملف `root-ca.crt` تحت قسم `Configuration Profiles` -> `Trusted Certificate`.
- **Jamf Pro (لأجهزة Apple):** إنشاء `Configuration Profile` وحفظ الشهادة في قسم `Payload: Certificates`.

---

### 🛠️ 3. التثبيت اليدوي على الأنظمة المختلفة

في حال وجود أجهزة مستقلة غير مرتبطة بالدومين، يتم تنزيل الشهادة من خادم التنزيل المحلي للجدار الناري (`http://192.168.1.33/ca.crt` أو ملف `certs/root-ca.crt`):

#### 🪟 أ) نظام Windows (يدوي)
* **عبر PowerShell (بصلاحيات أدمن):**
  ```powershell
  Import-Certificate -FilePath "certs\root-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
  ```
* **عبر الواجهة الرسومية:**
  1. انقر مرتين على `root-ca.crt` واضغط **Install Certificate**.
  2. اختر **Local Machine** واضغط *Next*.
  3. حدد **Place all certificates in the following store** واضغط *Browse*.
  4. اختر **Trusted Root Certification Authorities** واضغط *OK* ثم *Finish*.

#### 🍎 ب) نظام macOS
1. افتح الملف `root-ca.crt` ليفتح في تطبيق **Keychain Access**.
2. اختر الحافظة **System** واضغط **Add**.
3. انقر مرتين على الشهادة المضافة وافتح قسم **Trust**.
4. غير خيار **When using this certificate** إلى **Always Trust**.

#### 🐧 ج) نظام Linux (Ubuntu / Debian / RHEL)
```bash
# Ubuntu / Debian
sudo cp root-ca.crt /usr/local/share/ca-certificates/bunyanx-root-ca.crt
sudo update-ca-certificates

# RHEL / CentOS / Fedora
sudo cp root-ca.crt /etc/pki/ca-trust/source/anchors/bunyanx-root-ca.crt
sudo update-ca-trust
```

#### 📱 د) نظام iOS (iPhone / iPad)
1. حمّل الشهادة عبر متصفح **Safari**.
2. افتح **Settings** ◄ **Profile Downloaded** ◄ اضغط **Install**.
3. **خطوة حاسمة (تفعيل الوثوق الكامل):**  
   اذهب إلى **Settings** ◄ **General** ◄ **About** ◄ **Certificate Trust Settings** وفعّل المفتاح المجاور لشهادة `BunyanX Root CA`.

#### 📱 هـ) نظام Android
1. افتح **Settings** ◄ **Security & Privacy** ◄ **More Security Settings** ◄ **Encryption & Credentials**.
2. اختر **Install a Certificate** ◄ **CA Certificate**.
3. اختر ملف `root-ca.crt` ووافق على التثبيت.

#### 🌐 و) متصفح Mozilla Firefox (독립 Certificate Store)
1. افتح **Settings** وابحث عن **Certificates** ◄ اضغط **View Certificates...**.
2. اختر تبويب **Authorities** واضغط **Import...**.
3. حدد ملف `root-ca.crt` وافحص خيار ☑️ **Trust this CA to identify websites** ثم اضغط **OK**.

---

## 4. الآلية المعمارية لفك التشفير والتفتيش الشامل في الذاكرة (MemoryBIO TLS Inspection)

يعتمد الجدار الناري على معمارية حديثة تمنع خنق الشبكة وتضمن استلام جميع الوحدات الـ 10 للنص المفكوك كاملاً:

```
[اتصال العميل المشفر HTTPS]
       │
       ▼
 [nftables REDIRECT: 443 → 8443]
       │
       ▼
 [MemoryBIO TLS Handshake] ◄─── (توليد شهادة ديناميكية بواسطة CAPoolManager)
       │
       ▼
 [_VIPSSLReader Stream Wrapper] (فك التشفير في الذاكرة بدون كتابة على القرص)
       │
       ▼
 [تجميع الـ POST Payload] ◄─── (_accumulated_stream لضمان التجميع الكامل)
       │
       ▼
 [ContextBuilder.enrich_http()] ◄─── (تغذية البيانات المفكوك تشفيرها)
       │
       ├────────► 1. WAF Inspector (SQLi, XSS, Command Injection)
       ├────────► 2. Email Security (Webmail Phishing & Reputation)
       ├────────► 3. Web Filter (HoloFilter & RFC-1918 Private IP Bypass)
       ├────────► 4. DLP Guard (MSEM-Lite Response Guard)
       ├────────► 5. Malware AV (FlowSpec-AV / YARA 1s Scan)
       ├────────► 6. PHANTOM IDS/IPS (Signature & Anomaly Engine)
       ├────────► 7. Threat Intelligence (IP/Domain Reputation)
       ├────────► 8. HTTP Protocol Inspection (RFC Compliance)
       ├────────► 9. UBA (User & Entity Behavior Analytics)
       └────────► 10. DART DNS Security Engine
```

---

## 5. الخلاصة والتأكيد التشغيلي
- **للموقع الخارجي (VIP/WAF):** نستخدم **شهادة عامة موثوقة (Public CA)**، ولا يحتاج العميل الخارجي لتثبيت أي شيء نهائياً.
- **للتصفح الداخلي (Transparent MITM):** نستخدم **شهادة الجذر (Enterprise Root CA)**، وتُثبت مرة واحدة عبر الـ GPO للدومين أو يدوياً للأجهزة الفردية.
- **في المعالجة:** يتم فك التشفير وتجميع الـ Stream في الذاكرة لتمريره بكفاءة لجميع الوحدات الـ 10 دون تأخير.

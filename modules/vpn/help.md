# دليل المبرمج لاستدعاء واستخدام وحدة WireGuard VPN
`Enterprise BunyanX NGFW — VPN Module Integration Guide`

---

## 📌 1. مقدمة ونظرة عامة (Overview)

توفر وحدة الـ **VPN** (`modules.vpn`) خادم WireGuard VPN متكامل ومحرك لدارة البوابة (Portal Manager) مدمجاً مع نظام الجدار الناري BunyanX NGFW.

### الوظائف الرئيسية:
* **إدارة شبكة WireGuard**: إنشاء/حذف الـ Interface (`wg0`) وتحديد المنفذ والعنوان IP.
* **إدارة المشتركين (Peers)**: إضافة وحذف وتحديث مفاتيح المشتركين وعناوين CIDR وEndpoints مع التشفير في قاعدة البيانات.
* **إدارة الجلسات والبوابة (Portal Session Tracker)**: مصادقة المستخدمين وتتبع الجلسات النشطة في الذاكرة وإحداث التوقيت الزمني والتنبيهات.
* **الأمان العالي (Security Hardening)**: تشفير الـ Preshared Keys عبر Fernet، وفحص المدخلات عبر Regex و CIDR Validator، وإنشاء ملفات المفاتيح المؤقتة بصلاحيات مشددة `0o600` مع التنظيف الذاتي.
* **واجهة REST API**: مجموعة كاملة من مسارات FastAPI تحت المسار `/api/v1/vpn`.
* **التكامل مع الأحداث والتزامن**: نشر أحداث الاتصال/الانقطاع/الفشل عبر `EventBus` و `UnifiedEventSink` و `HA State Sync`.

---

## 🏗️ 2. البنية الهيكلية للوحدة (Module Structure)

```text
modules/vpn/
├── __init__.py               # علامة الحزمة
├── manifest.yaml             # البيان الوصفي للوحدة (Metadata & Version 2.0.0)
├── module.py                 # الكلاس الرئيسي VPNModule للمجسم العام
├── help.md                   # هذا الدليل التوثيقي المباشر للمبرمجين
├── config/
│   └── settings.yaml         # وثيقة مرجعية لإعدادات الوحدة
├── engine/
│   ├── __init__.py           # تصدير WireGuardManager و PeerConfig
│   ├── wireguard.py          # المحرك التنفيذي لأوامر النظام (wg, ip)
│   ├── validators.py         # أدوات الفحص الدقيق والتحقق من المدخلات
│   └── crypto.py             # محرك تشفير وفك تشفير الـ PSK عبر Fernet
├── models/
│   └── __init__.py           # تصدير نماذج قاعدة البيانات (VPNConfig, VPNPeer)
├── policy/
│   ├── __init__.py           # تصدير كلاسات السياسات
│   └── vpn/
│       ├── auth.py           # مصادقة المستخدمين والتحقق من صلاحيات RBAC
│       └── portal.py         # إدارة وتتبع جلسات البوابة النشطة
└── api/
    └── router.py             # موجه FastAPI المزدود بالنقاط البرمجية REST API
```

---

## 🚀 3. كيفية استدعاء الوحدة في الكود (Integration & Code Usage)

### 3.1. الاستدعاء عبر حاوي الخدمات (ServiceContainer / System Layer)

عند إقلاع النظام، يتم تحميل الوحدة تلقائياً عبر `ServiceContainer`. للحصول على الخدمات التي توفرها الوحدة من أي مكان في النظام:

```python
# الحصول على حاوي الخدمات
container = app.service_container  # أو من خلال المعامل الممرر للمديولات

# استدعاء مدير WireGuard المباشر
vpn_manager = container.get('vpn_manager')

# استدعاء مدير البوابة
vpn_portal = container.get('vpn_portal')
```

---

### 3.2. الاستدعاء المباشر لمحرك WireGuard (`WireGuardManager`)

تُستخدم هذه الفئة لإدارة واجهة WireGuard وأوامر النظام مباشرة (`wg`, `ip`).

```python
from modules.vpn.engine.wireguard import WireGuardManager, PeerConfig

# 1. إنشاء كائن المدير
manager = WireGuardManager(interface="wg0")

# 2. توليد زوج مفاتيح جديد (Private Key / Public Key)
priv_key, pub_key = manager.generate_keys()
# المخرجات: (str, str) -> مفاتيح Base64 بطول 44 حرفاً

# 3. إعداد وتشغيل الواجهة الشبكية
success = manager.setup_interface(ip_address="10.10.0.1/24", port=51820)
# المدخلات: ip_address (str CIDR), port (int)
# المخرجات: bool (True عند النجاح، False عند الفشل)

# 4. إضافة مشترك (Peer)
peer = PeerConfig(
    public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
    allowed_ips=["10.10.0.2/32"],
    endpoint="203.0.113.5:51820",        # اختياري
    preshared_key="secret-psk-string",    # اختياري
    persistent_keepalive=25              # اختياري (افتراضي 25)
)
success = manager.add_peer(peer)
# المخرجات: bool

# 5. استخراج حالة الواجهة الحية
status_text = manager.get_status()
# المخرجات: str (مخرجات wg show أو "Interface down")

# 6. إزالة مشترك
manager.remove_peer(public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")
# المخرجات: bool

# 7. إيقاف وحذف الواجهة
manager.teardown()
# المخرجات: bool
```

---

### 3.3. إدارة الجلسات والبوابة (`VPNPortal`)

تُستخدم الفئة `VPNPortal` لتعقب جلسات المستخدمين في الذاكرة الحية.

```python
from modules.vpn.policy.vpn.portal import VPNPortal

# 1. إنشاء كائن البوابة
portal = VPNPortal(
    allow_multi_session=False,     # True لتسمح بجلسات متعددة لنفس المستخدم
    session_ttl_seconds=86400      # مدة صلاحية الجلسة بالثواني (افتراضي 24 ساعة)
)

# 2. إنشاء جلسة جديدة عند اتصال مستخدم
session = portal.create_session(
    username="alice",
    peer_public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
    allowed_ips=["10.10.0.2/32"],
    endpoint="192.168.1.50:51820"
)
# المخرجات: VPNSession object
# يحتوي على: session.session_id, session.expires_at, session.is_expired, إلخ.

# 3. تحديث نبض الجلسة وعدادات البيانات (Heartbeat)
portal.update_heartbeat(
    session_id=session.session_id,
    bytes_rx=10240,    # البيانات المستلمة الجديدة
    bytes_tx=20480     # البيانات المرسلة الجديدة
)
# المخرجات: bool (True إذا كانت الجلسة موجودة وغير منتهية)

# 4. الاستعلام عن الجلسات
s1 = portal.get_session(session_id="uuid-string")
s2 = portal.get_session_by_pubkey(peer_public_key="...")
user_sessions = portal.get_user_sessions(username="alice")
all_sessions_list = portal.list_sessions() # قائمة dicts

# 5. إنهاء جلسة
portal.terminate_session(session_id="uuid-string")
portal.terminate_user_sessions(username="alice")
```

---

### 3.4. مصادقة المستخدمين وإدارة الصلاحيات (`UserAuth`)

تُستخدم للتحقق من اسم المستخدم كلمة المرور وقواعد الـ RBAC في قاعدة البيانات.

```python
from modules.vpn.policy.vpn.auth import UserAuth

# إنشاء كائن المصادقة
auth_mgr = UserAuth(db_session_factory=db_session_factory) # اختياري

# 1. المصادقة الكاملة (Username + Password + RBAC check)
vpn_user = auth_mgr.authenticate(username="alice", password="secretpassword")
# المخرجات: VPNUser object عند النجاح (يحتوي username, role, groups, email)، أو None عند الفشل.

# 2. فحص الصلاحية فقط (RBAC check without password)
has_access = auth_mgr.has_vpn_permission(username="alice")
# المخرجات: bool (True إذا كان أدمن/أوبريتور أو لديه قاعدة Rule بـ resource='vpn')
```

---

### 3.5. أدوات التشفير والتحقق (`crypto.py` & `validators.py`)

#### تشفير الـ Preshared Keys (PSK):
```python
from modules.vpn.engine.crypto import encrypt_psk, decrypt_psk

# تشفير قبل الحفظ في قاعدة البيانات
encrypted_str = encrypt_psk("raw-psk-string")
# المخرجات: "ENC:gAAAAABm..." (سلسلة مشفرة بـ Fernet)

# فك التشفير عند القراءة من DB
raw_psk = decrypt_psk(encrypted_str)
# المخرجات: "raw-psk-string"
```

#### التحقق من المدخلات (Validators):
```python
from modules.vpn.engine.validators import (
    validate_wireguard_pubkey,
    validate_allowed_ips,
    validate_endpoint,
    validate_listen_port,
    validate_server_ip,
    validate_mtu,
    sanitize_peer_name,
    VPNValidationError
)

try:
    pubkey = validate_wireguard_pubkey("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=") # يرجّع str stripped
    ips = validate_allowed_ips(["10.10.0.0/24"])                                       # يرجّع List[str]
    ep = validate_endpoint("203.0.113.1:51820")                                        # يرجّع str
    port = validate_listen_port(51820)                                                 # يرجّع int
    srv_ip = validate_server_ip("10.10.0.1/24")                                        # يرجّع str
    mtu = validate_mtu(1420)                                                           # يرجّع int
    clean_name = sanitize_peer_name("<script>Office</script>")                         # يرجّع "Office"
except VPNValidationError as err:
    print(f"خطأ في التحقق من المدخلات: {err}")
```

---

## 🌐 4. مرجع واجهة البرمجة REST API (`/api/v1/vpn`)

جميع نقاط النهاية تعتمد على FastAPI وتتطلب توثيق الهيدر `Authorization: Bearer <Token>`.

| المسار (Endpoint) | النوع | الصلاحية المطلوبة | وصف الوظيفة | المدخلات (Payload) | المخرجات (Response Example) |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `/api/v1/vpn/status` | `GET` | `VPN Access` | حالة الواجهة الحية | لا يوجد | `{"status": "interface: wg0...", "interface": "wg0"}` |
| `/api/v1/vpn/config` | `GET` | `VPN Access` | قراءة إعدادات السيرفر من DB | لا يوجد | `{"enabled": true, "listen_port": 51820, "server_ip": "10.10.0.1/24", ...}` |
| `/api/v1/vpn/config` | `PUT` | `Admin Only` | تحديث إعدادات السيرفر | `VPNConfigRequest` | `{"message": "VPN configuration updated..."}` |
| `/api/v1/vpn/start` | `POST` | `Admin Only` | تشغيل الواجهة واستعادة المشتركين | لا يوجد | `{"message": "VPN started successfully with 5 peers configured"}` |
| `/api/v1/vpn/stop` | `POST` | `Admin Only` | إيقاف الواجهة وإنهاء الجلسات | لا يوجد | `{"message": "VPN interface stopped successfully", "sessions_terminated": 3}` |
| `/api/v1/vpn/peers` | `GET` | `VPN Access` | عرض جميع المشتركين من DB | لا يوجد | `{"peers": [{"name": "User1", "public_key": "...", "allowed_ips": ["10.10.0.2/32"]}, ...]}` |
| `/api/v1/vpn/peers` | `POST` | `Admin Only` | إضافة مشترك جديد (مباشر + DB) | `VPNPeerRequest` | `{"message": "Peer added and persisted successfully", "public_key": "..."}` |
| `/api/v1/vpn/peers/{pubkey}` | `DELETE` | `Admin Only` | حذف مشترك (مباشر + DB + جلسة) | `pubkey` بالمسار | `204 No Content` |
| `/api/v1/vpn/keys/generate` | `POST` | `Admin Only` | توليد زوج مفاتيح WireGuard | لا يوجد | `{"private_key": "...", "public_key": "..."}` (مع Header خاص للتنبيه) |
| `/api/v1/vpn/portal/login` | `POST` | `Public` | تسجيل دخول مستخدم البوابة | `VPNPortalLoginRequest` | `{"session_id": "...", "username": "alice", "expires_at": "...", "allowed_ips": [...]}` |
| `/api/v1/vpn/sessions` | `GET` | `Admin Only` | عرض جميع الجلسات النشطة | لا يوجد | `{"sessions": [{"session_id": "...", "username": "alice", "bytes_rx": 100}, ...]}` |
| `/api/v1/vpn/sessions/summary` | `GET` | `VPN Access` | ملخص إحصائيات الجلسات | لا يوجد | `{"active_sessions": 5, "total_bytes_rx": 102400, "unique_users": 5}` |
| `/api/v1/vpn/sessions/{session_id}` | `DELETE` | `Admin Only` | إنهاء جلسة مستخدم فورياً | `session_id` بالمسار | `204 No Content` |
| `/api/v1/vpn/logs` | `GET` | `VPN Access` | عرض سجلات التدقيق بصيغة Terminal | لا يوجد | `{"logs": [{"line": "[2026-07-23 ...] INFO: ...", "level": "info"}], "alerts": []}` |
| `/api/v1/vpn/diagnostics` | `GET` | `VPN Access` | تشخيص وسحب حالة النظام الذاتية | لا يوجد | `{"interface_status": "active", "port_status": "open", "crypto_status": "active", ...}` |

---

## 🔔 5. نظام الأحداث (Events Taxonomy)

تنشر وحدة الـ VPN الأحداث التالية عبر ناقل الأحداث المركزي (`EventBus`) وناقل التليمتري (`UnifiedEventSink`):

1. **`vpn.connected` / `Topics.VPN_CONNECTED`**: يُنشر عند نجاح تسجيل دخول مستخدم في البوابة وإنشاء الجلسة.
   * **Payload**: `{"session_id": str, "username": str, "assigned_ip": str, "peer_public_key": str, "allowed_ips": list}`
2. **`vpn.disconnected` / `Topics.VPN_DISCONNECTED`**: يُنشر عند إنهاء أو انتهاء صلاحية جلسة المستعمل.
   * **Payload**: `{"session_id": str, "username": str, "assigned_ip": str, "reason": str, "bytes_rx": int, "bytes_tx": int}`
3. **`vpn.failure` / `Topics.VPN_FAILURE`**: يُنشر عند فشل تشغيل خادم WireGuard أو إعداد الواجهة.
   * **Payload**: `{"interface": str, "ip_address": str, "port": int, "reason": str}`
4. **`vpn.restored` / `Topics.VPN_RESTORED`**: يُنشر عند نجاح استعادة الواجهة أو التشغيل السليم.

---

## 🗄️ 6. نماذج قاعدة البيانات (Database Models)

تستعمل الوحدة النماذج المعرفة في `system.database.database`:

* **`VPNConfig`**:
  * `enabled` (`bool`): هل الوحدة مفعلة عند الإقلاع.
  * `interface` (`str`): اسم الواجهة (مثال: `"wg0"`).
  * `listen_port` (`int`): المنفذ (مثال: `51820`).
  * `server_ip` (`str`): IP وعنوان النطاق (مثال: `"10.10.0.1/24"`).
  * `public_key` (`str`): المفتاح العام للسيرفر.
  * `dns` (`str`): عناوين الـ DNS الممررة للعملاء.
  * `mtu` (`int`): حجم الـ MTU (افتراضي `1420`).
* **`VPNPeer`**:
  * `name` (`str`): الاسم التعريفي للمشترك.
  * `public_key` (`str` - Primary Key): المفتاح العام لعميل WireGuard.
  * `allowed_ips` (`JSON/List`): عناوين الـ IP المسموحة للنفق.
  * `endpoint` (`str`): عنوان العميل الخارجي `IP:PORT`.
  * `preshared_key` (`str`): المفتاح المشترك المشفر عبر Fernet (`ENC:...`).
  * `persistent_keepalive` (`int`): فترة نبض الاتصال بالثواني.
  * `enabled` (`bool`): هل المشترك مفعّل.

---

## 💡 7. أمثلة كود جاهزة (Production-Ready Code Examples)

### مثال 1: إضافة مشترك جديد واستدعاء الواجهة من كود خارجي

```python
from modules.vpn.engine.wireguard import WireGuardManager, PeerConfig
from modules.vpn.engine.validators import validate_wireguard_pubkey, validate_allowed_ips

def register_new_client(pubkey: str, client_ip: str):
    # 1. التحقق من صحة المدخلات
    clean_pubkey = validate_wireguard_pubkey(pubkey)
    valid_ips = validate_allowed_ips([f"{client_ip}/32"])
    
    # 2. إنشاء كائن المشترك
    peer = PeerConfig(
        public_key=clean_pubkey,
        allowed_ips=valid_ips,
        persistent_keepalive=25
    )
    
    # 3. التطبيق المباشر على الواجهة
    wg_mgr = WireGuardManager(interface="wg0")
    if wg_mgr.add_peer(peer):
        print(f"✅ تم إضافة المشترك {client_ip} بنجاح إلى WireGuard!")
    else:
        print("❌ فشل إضافة المشترك على الواجهة.")
```

### مثال 2: المصادقة وإنشاء جلسة بوابية برمجياً

```python
from modules.vpn.policy.vpn.auth import UserAuth
from modules.vpn.policy.vpn.portal import VPNPortal

def handle_user_vpn_login(username, password, pubkey, db_session):
    # 1. مصادقة المستخدم
    auth_service = UserAuth(db_session_factory=lambda: db_session)
    user = auth_service.authenticate(username, password)
    
    if not user:
        raise PermissionError("اسم المستخدم أو كلمة المرور غير صحيحة أو لا تملك صلاحية VPN")
        
    # 2. تسجيل الجلسة في الـ Portal
    portal = VPNPortal()
    session = portal.create_session(
        username=user.username,
        peer_public_key=pubkey,
        allowed_ips=["10.10.0.5/32"]
    )
    
    print(f"✅ تم إنشاء الجلسة بنجاح: ID={session.session_id}, Expires={session.expires_at}")
    return session
```

---
**تم إعداد هذا الدليل لتغطية كافة جوانب وحدة الـ VPN بالتفصيل الكامل.**

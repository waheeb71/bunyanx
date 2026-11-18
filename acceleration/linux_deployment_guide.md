# دليل تفعيل bunyanx Acceleration على Linux

## خريطة الملفات الكاملة

```
F:\enterprise_ngfw\acceleration\
│
├── __init__.py                          # Package entry
└── ebpf\
    ├── __init__.py                      # exports: PortFilterLoader
    ├── xdp_engine.py            ✅      # Core XDP Engine (Legacy + Pipeline modes)
    ├── ring_buffer_consumer.py  ✅      # 3-tier event consumer
    ├── conntrack_manager.py     ✅      # TCP Conntrack GC (Phase 3)
    ├── lb_manager.py            ✅      # L4 LB Manager (Phase 5)
    ├── port_filter.c            ✅      # Port filter program
    ├── port_filter_loader.py    ✅      # Port filter Python loader
    ├── xdp_mode_switcher.py     ✅      # Native/Generic/Offload switcher
    │
    ├── pipeline\
    │   ├── __init__.py          ✅      # Pipeline package
    │   ├── dispatcher.c         ✅      # XDP Unified Pipeline (BCC-compatible)
    │   ├── pipeline_loader.py   ✅      # Python Pipeline Loader
    │   ├── stage_conntrack.c    ✅      # (legacy — مدمج في dispatcher.c)
    │   ├── stage_syn_proxy.c    ✅      # (legacy — مدمج في dispatcher.c)
    │   └── stage_l4_lb.c        ✅      # (legacy — مدمج في dispatcher.c)
    │
    └── tests\
        ├── run_bpf_tests.sh     ✅      # CI validation script
        ├── benchmark_pipeline.py ✅     # Benchmark suite (pktgen)
        ├── security_proofs.py   ✅      # Security analysis (يعمل الآن)
        └── benchmark_results\          # يُنشأ تلقائياً عند التشغيل
```

---

## المتطلبات على Linux VM

### 1. المتطلبات الأساسية

```bash
# Kernel version (الحد الأدنى)
uname -r
# يجب أن يكون >= 5.8 للـ Ring Buffers
# يجب أن يكون >= 5.15 للـ Conntrack
# يجب أن يكون >= 6.8 للـ SYN helpers الرسمية

# توزيعات مُختبَرة
Ubuntu 22.04 LTS  (kernel 5.15)  ← موصى به للبدء
Ubuntu 24.04 LTS  (kernel 6.8)   ← للـ Phase 4 الكاملة
Debian 12         (kernel 6.1)
```

### 2. تثبيت Dependencies

```bash
# BCC (BPF Compiler Collection) — الأهم
# Ubuntu 22.04+:
sudo apt-get update
sudo apt-get install -y \
    bpfcc-tools \
    libbpfcc \
    libbpfcc-dev \
    python3-bpfcc \
    linux-headers-$(uname -r) \
    clang \
    llvm \
    libelf-dev \
    iproute2 \
    ethtool

# Python packages
pip3 install \
    asyncio \
    pyyaml \
    psutil \
    aiofiles

# اختياري — للـ Benchmarks
sudo modprobe pktgen    # kernel module (مضمّن في kernel >= 4.0)
```

### 3. تحقق من الـ kernel capabilities

```bash
# تحقق من BPF support
ls /sys/fs/bpf/           # يجب أن يوجد
cat /proc/sys/net/core/bpf_jit_enable  # يجب أن يكون 1

# تفعيل BPF JIT (مطلوب للأداء)
sysctl -w net.core.bpf_jit_enable=1
echo "net.core.bpf_jit_enable=1" >> /etc/sysctl.conf

# تحقق من XDP support على الـ interface
ethtool -i eth0 | grep driver
# drivers that support XDP native: mlx5, i40e, ixgbe, virtio_net, ice
# XDP generic يعمل على أي driver لكن أبطأ

# تحقق من ring buffer support
python3 -c "from bcc import BPF; print('BCC OK')"
```

---

## خطوات النقل والتثبيت

### الخطوة 1 — نقل المشروع

```bash
# على Windows: انسخ المشروع لـ USB أو انقله عبر SCP
scp -r F:\enterprise_ngfw user@linux-vm:/opt/bunyanx

# على Linux VM
cd /opt/bunyanx
ls  # يجب أن تجد: system/ acceleration/ modules/ api/
```

### الخطوة 2 — إعداد البيئة

```bash
cd /opt/bunyanx

# Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# تثبيت project dependencies
pip install -r requirements.txt  # إذا كانت موجودة
# أو يدوياً:
pip install pyyaml asyncio aiohttp aiofiles psutil

# BCC لا يُثبَّت عبر pip — يُثبَّت على مستوى النظام (تم أعلاه)
```

### الخطوة 3 — ضبط الـ Configuration

```bash
# 1. حدّد الـ MAC Address الخاص بواجهات الشبكة الحقيقية
ip link show
# ستحصل على قائمة بالواجهات مع أرقام الـ MAC الخاصة بها (مثال: 00:aa:34:58:89:0a)

# 2. عدّل base.yaml
nano system/config/base.yaml
```

```yaml
# system/config/base.yaml — الأقسام المهمة
interfaces:
  wan:
    mac: '00:aa:34:58:89:0a'  # ← استبدل هذا برقم الـ MACAddress لكرت الـ WAN الحقيقي
  lan:
    mac: 'd4:85:64:95:bf:37'  # ← استبدل هذا برقم الـ MACAddress لكرت الـ LAN الحقيقي (اختياري)

ebpf:
  enabled: true
  interface: auto         # ← يقوم بالربط التلقائي بكرت الـ WAN المعرّف أعلاه
  xdp_mode: generic       # ابدأ بـ generic (أبطأ لكن أكثر توافقاً مع الكروت الافتراضية والـ VMs)
  # xdp_mode: native     # حوّله لـ native بعد التأكد من دعم كرت الشبكة الحقيقي لـ XDP
```

### الخطوة 4 — تفعيل تدريجي (Phase by Phase)

**المبدأ: فعّل phase واحدة، اختبر، ثم انتقل للتالية.**

```bash
nano system/config/features.yaml
```

#### المرحلة A — فعّل eBPF فقط (بدون Pipeline)

```yaml
features:
  data_plane:
    ebpf_acceleration: true      # ← هذا فقط في البداية
    ebpf_ring_buffers: false
    ebpf_pipeline: false
    ebpf_conntrack: false
    ebpf_syn_proxy: false
    ebpf_l4_lb: false
```

```bash
# شغّل النظام
sudo python3 -m system.core.engine  # أو الأمر المناسب للمشروع

# راقب الـ logs
tail -f logs/bunyanx.log | grep -E "XDP|eBPF|Pipeline"

# تحقق من XDP attached
sudo ip link show eth0 | grep xdp
# يجب أن يظهر: xdp/id:XXX
```

#### المرحلة B — Phase 1: Ring Buffers

```yaml
    ebpf_ring_buffers: true      # ← هذا بعد نجاح A
```

```bash
# تحقق من Ring Buffers
sudo python3 -c "
from bcc import BPF
b = BPF(text='BPF_RINGBUF_OUTPUT(test, 1); int f(void *c){return 0;}')
print('Ring Buffer: OK')
"
```

#### المرحلة C — Phase 2: Tail Calls Pipeline

```yaml
    ebpf_ring_buffers: true
    ebpf_pipeline: true          # ← يُحمّل dispatcher.c
```

```bash
# تحقق من Pipeline mode
tail -f logs/bunyanx.log | grep "[Pipeline]"
# يجب أن تجد: "Dispatcher loaded on eth0 | bitmask=0b00010000"
```

#### المرحلة D — Phase 3: Conntrack

```yaml
    ebpf_conntrack: true         # ← يُفعّل TCP State Machine
```

```bash
# اختبر الحماية
sudo python3 acceleration/ebpf/tests/security_proofs.py
# يجب: Score = 100% (9 proven)
```

#### المرحلة E — Phase 4: SYN Proxy

```yaml
    ebpf_syn_proxy: true         # ← يتطلب kernel >= 5.15
```

#### المرحلة F — Phase 5: L4 LB (الأخطر)

```yaml
    ebpf_l4_lb: true             # ← فقط بعد اختبار E2E
```

---

## اختبار الأداء (بعد التفعيل)

```bash
# 1. Run Security Proofs (يعمل بدون pktgen)
sudo python3 acceleration/ebpf/tests/security_proofs.py

# 2. Run Full Benchmarks (يحتاج pktgen)
sudo modprobe pktgen
sudo python3 acceleration/ebpf/tests/benchmark_pipeline.py \
    --iface eth0 \
    --duration 30

# 3. مقارنة مع nf_conntrack
sudo python3 acceleration/ebpf/tests/benchmark_pipeline.py \
    --iface eth0 \
    --compare-nf

# النتائج في:
ls acceleration/ebpf/tests/benchmark_results/
```

---

## أوامر المراقبة في وقت التشغيل

```bash
# عرض XDP stats
sudo bpftool prog list | grep xdp
sudo bpftool map list

# عرض حالة الـ Pipeline (Conntrack)
sudo bpftool map dump name ct_global | head -50

# عرض Blocked IPs
sudo bpftool map dump name blocked_ips

# عرض LB backends
sudo bpftool map dump name healthy_backends_map

# مراقبة Ring Buffer events (بـ bpftrace)
sudo bpftrace -e 'tracepoint:xdp:xdp_bulk_tx { @pkt[args->ifindex] = count(); }'

# عرض dispatcher stats
sudo python3 -c "
from bcc import BPF
# بعد load
"
```

---

## استكشاف الأخطاء الشائعة

| الخطأ | السبب | الحل |
|---|---|---|
| `BCC not available` | BCC غير مثبّت | `apt install python3-bpfcc` |
| `xdp_pipeline.call() unknown` | kernel قديم | `uname -r` — يجب >= 5.2 |
| `meta_alloc_failed` عالٍ | لا يدعم XDP meta | استخدم `xdp_mode: generic` |
| `tail_call_missed` | stage غير محمّل | تحقق من `features.yaml` |
| `BPF_RINGBUF not found` | kernel < 5.8 | فعّل `ebpf_ring_buffers: false` |
| `XDP attach failed` | لا يدعم Native XDP | غيّر لـ `xdp_mode: generic` |
| Permission denied | ليس root | شغّل بـ `sudo` |

---

## أقصر مسار للتجربة السريعة

```bash
# 1 — تثبيت على Ubuntu 22.04
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

# 2 — نقل المشروع
scp -r /mnt/usb/enterprise_ngfw /opt/bunyanx

# 3 — ضبط الـ interface
# اعرض عنوان الـ MAC للواجهة الافتراضية:
cat /sys/class/net/$(ip route | grep default | awk '{print $5}')/address
# ثم عدّل ملف system/config/base.yaml يدويًا وضح هذا العنوان تحت interfaces.wan.mac
# واجعل xdp_mode: generic لتجنب أي مشاكل توافقية في البداية

# 4 — تشغيل Security Proofs (للتحقق الفوري)
cd /opt/bunyanx
python3 acceleration/ebpf/tests/security_proofs.py

# 5 — تفعيل Phase 1 فقط وشغّل
# عدّل features.yaml: ebpf_acceleration: true
sudo python3 -m system.core.engine
```

> **ملاحظة:** `xdp_mode: generic` يعمل على أي VM بدون native XDP driver.
> للأداء الحقيقي (10Gbps+) يجب native mode مع driver يدعم XDP.

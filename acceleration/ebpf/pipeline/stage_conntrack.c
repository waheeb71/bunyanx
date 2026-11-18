/*
 * bunyanx NGFW — XDP Stage 1: Stateful TCP Conntrack
 * =======================================================
 * يتذكر الاتصالات ويحمي من ACK/RST Floods.
 *
 * التصميم الهجين (يحل مشكلة Race Condition):
 *   Fast Path:  Per-CPU hash (ct_fast) — بدون lock للـ hot path
 *   Slow Path:  Global LRU hash (ct_global) — للـ miss والـ cleanup
 *
 * TCP State Machine:
 *   NEW → SYN packet → سجّل الاتصال
 *   SYN_RECV → SYN+ACK من server → سجّل الاتجاه العكسي
 *   ESTABLISHED → ACK → اسمح
 *   FIN_WAIT → FIN packet → ابدأ cleanup
 *   [ACK بلا اتصال معروف] → XDP_DROP ← الحماية الحقيقية
 *
 * حدود الـ Verifier:
 *   - Stack limit: 512 bytes (256 مع BPF calls)
 *   - كل helper يجب __always_inline
 *   - الـ conn_key: 16 bytes (مع padding لـ alignment)
 *   - الـ conn_value: 32 bytes (packed للـ cache)
 *
 * الذاكرة:
 *   Fast (per-CPU):   65536 × 48 bytes × CPU_count
 *   Global LRU:  max_entries × 48 bytes (يُقرأ من config)
 */

#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

// ═══════════════════════════════════════════════════════════════════
// TCP States (State Machine)
// ═══════════════════════════════════════════════════════════════════
#define CT_STATE_NEW         1
#define CT_STATE_SYN_RECV    2
#define CT_STATE_ESTABLISHED 3
#define CT_STATE_FIN_WAIT    4
#define CT_STATE_CLOSE_WAIT  5
#define CT_STATE_CLOSED      6

// ═══════════════════════════════════════════════════════════════════
// Connection Key & Value Structs
// ═══════════════════════════════════════════════════════════════════

// conn_key: 16 bytes — cache-aligned, verifier-friendly
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;   // IPPROTO_TCP
    __u8  pad[3];     // alignment padding — MUST be zero
};

// conn_value: 32 bytes — packed
struct conn_value {
    __u64 last_seen_ns;      // bpf_ktime_get_ns() — للـ timeout
    __u32 pkt_count;         // عدد الحزم
    __u32 byte_count;        // عدد البايتات (تقريبي)
    __u8  state;             // CT_STATE_*
    __u8  flags;             // TCP flags الأخيرة
    __u16 pad;
    __u32 timeout_s;         // وقت انتهاء الصلاحية (ثوانٍ)
    __u32 reserved;
};

// ═══════════════════════════════════════════════════════════════════
// BPF Maps
// ═══════════════════════════════════════════════════════════════════

// Fast path: Per-CPU hash (no lock on hot path)
// حجم 65536 entry per-CPU — overflow يذهب للـ global
BPF_PERCPU_HASH(ct_fast, struct conn_key, struct conn_value, 65536);

// Slow path: Global LRU hash (lock-based، للـ miss والـ overflow)
// max_entries يُضبط من Python عبر userspace map resize
BPF_LRU_HASH(ct_global, struct conn_key, struct conn_value, 1000000);

// Conntrack stats
BPF_ARRAY(ct_stats, __u64, 8);
// [0]=new_conns [1]=established [2]=dropped_no_state
// [3]=fin_closed [4]=rst_dropped [5]=table_full_fast
// [6]=table_full_global [7]=timeout_dropped

// Timeouts (يُكتب من Python عند البداية)
// [0]=established_timeout_s [1]=syn_timeout_s [2]=fin_timeout_s
BPF_ARRAY(ct_timeouts, __u32, 4);

// Pipeline maps (مشتركة مع dispatcher.c)
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} xdp_pipeline SEC(".maps");

BPF_ARRAY(pipeline_config, __u64, 4);

// Ring Buffers (مشتركة — تُعرَّف في dispatcher.c فقط)
BPF_RINGBUF_OUTPUT(critical_events, 1024);
BPF_ARRAY(lost_events_counter, __u64, 1);

struct security_event {
    __u64 timestamp_ns;
    __u32 src_ip; __u32 dst_ip;
    __u16 src_port; __u16 dst_port;
    __u8  event_type; __u8  severity; __u16 protocol;
    __u32 pkt_count;
    char  reason[32];
};

// pipeline_meta (مشتركة مع dispatcher.c)
struct pipeline_meta {
    __u8  stage; __u8  verdict; __u16 flags;
    __u32 src_ip; __u32 dst_ip;
    __u16 src_port; __u16 dst_port;
    __u8  protocol; __u8  tcp_flags; __u16 pad;
};

#define FLAG_CONNTRACK  (1ULL << 5)
#define FLAG_SYN_PROXY  (1ULL << 6)
#define FLAG_L4_LB      (1ULL << 7)
#define STAGE_CONNTRACK  1
#define STAGE_SYN_PROXY  2
#define STAGE_L4_LB      3

// ═══════════════════════════════════════════════════════════════════
// Inline Helpers (كلها __always_inline لحماية الـ stack)
// ═══════════════════════════════════════════════════════════════════

static __always_inline void ct_stat_inc(__u32 key) {
    __u64 *v = ct_stats.lookup(&key);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline __u32 get_timeout(__u32 idx, __u32 default_val) {
    __u32 *t = ct_timeouts.lookup(&idx);
    return (t && *t > 0) ? *t : default_val;
}

// يتحقق من صلاحية الاتصال (لم ينتهِ وقته)
static __always_inline int conn_is_valid(struct conn_value *v) {
    __u64 now = bpf_ktime_get_ns();
    __u64 age_s = (now - v->last_seen_ns) / 1000000000ULL;
    return (age_s < v->timeout_s);
}

// يبني conn_key من pipeline_meta مع zero padding
static __always_inline void build_key(
    struct conn_key *k,
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 proto
) {
    k->src_ip   = src_ip;
    k->dst_ip   = dst_ip;
    k->src_port = src_port;
    k->dst_port = dst_port;
    k->protocol = proto;
    k->pad[0] = k->pad[1] = k->pad[2] = 0;    // verifier: كل bits معروفة
}

// ═══════════════════════════════════════════════════════════════════
// Lookup: Fast Path → Global LRU Fallback
// ═══════════════════════════════════════════════════════════════════
static __always_inline struct conn_value *ct_lookup(struct conn_key *k) {
    // 1) Fast path: per-CPU (no lock)
    struct conn_value *v = ct_fast.lookup(k);
    if (v) return v;

    // 2) Slow path: global LRU
    v = ct_global.lookup(k);
    if (v) {
        // انقل للـ fast path (warm cache)
        struct conn_value copy = *v;
        int r = ct_fast.update(k, &copy);
        if (r < 0) ct_stat_inc(5);  // fast table full
    }
    return v;
}

// ═══════════════════════════════════════════════════════════════════
// Update: يكتب في Fast Path أولاً ثم Global LRU
// ═══════════════════════════════════════════════════════════════════
static __always_inline void ct_update(struct conn_key *k, struct conn_value *v) {
    ct_fast.update(k, v);
    // BPF_NOEXIST في الـ global: إذا CPU آخر سبق → lookup وتحديث
    int r = ct_global.update(k, v);
    if (r == -E2BIG) ct_stat_inc(6);  // global table full
}

// ═══════════════════════════════════════════════════════════════════
// Main Conntrack Stage
// ═══════════════════════════════════════════════════════════════════
SEC("xdp")
int stage_conntrack(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct pipeline_meta *meta = (void *)(long)ctx->data_meta;
    if ((void *)(meta + 1) > data) return XDP_PASS;

    // Conntrack يعمل على TCP فقط
    if (meta->protocol != IPPROTO_TCP) {
        goto next_stage;
    }

    __u8 tcp_flags = meta->tcp_flags;
    __u64 now_ns   = bpf_ktime_get_ns();

    // ── بناء connection key (forward direction) ──────────────────────
    struct conn_key fwd_key;
    build_key(&fwd_key,
              meta->src_ip, meta->dst_ip,
              meta->src_port, meta->dst_port,
              IPPROTO_TCP);

    // ── بناء connection key (reverse direction للـ SYN+ACK) ──────────
    struct conn_key rev_key;
    build_key(&rev_key,
              meta->dst_ip, meta->src_ip,
              meta->dst_port, meta->src_port,
              IPPROTO_TCP);

    // ── SYN packet → اتصال جديد ───────────────────────────────────────
    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {  // SYN && !ACK
        struct conn_value new_val = {};
        new_val.last_seen_ns = now_ns;
        new_val.state        = CT_STATE_NEW;
        new_val.pkt_count    = 1;
        new_val.flags        = tcp_flags;
        new_val.timeout_s    = get_timeout(1, 10);  // syn_timeout=10s
        ct_update(&fwd_key, &new_val);
        ct_stat_inc(0);  // new_conns
        goto next_stage;
    }

    // ── SYN+ACK → server responds ─────────────────────────────────────
    if ((tcp_flags & 0x02) && (tcp_flags & 0x10)) {  // SYN+ACK
        struct conn_value *existing = ct_lookup(&rev_key);
        if (existing && existing->state == CT_STATE_NEW) {
            existing->state        = CT_STATE_SYN_RECV;
            existing->last_seen_ns = now_ns;
            ct_update(&rev_key, existing);

            // سجّل الاتجاه العكسي
            struct conn_value rev_val = {};
            rev_val.last_seen_ns = now_ns;
            rev_val.state        = CT_STATE_SYN_RECV;
            rev_val.pkt_count    = 1;
            rev_val.timeout_s    = get_timeout(1, 10);
            ct_update(&fwd_key, &rev_val);
        }
        goto next_stage;
    }

    // ── FIN packet → بدء الإغلاق ──────────────────────────────────────
    if (tcp_flags & 0x01) {  // FIN
        struct conn_value *v = ct_lookup(&fwd_key);
        if (v) {
            v->state        = CT_STATE_FIN_WAIT;
            v->last_seen_ns = now_ns;
            v->timeout_s    = get_timeout(2, 30);  // fin_timeout=30s
            ct_update(&fwd_key, v);
            ct_stat_inc(3);  // fin_closed
        }
        goto next_stage;
    }

    // ── RST packet → DROP + event ─────────────────────────────────────
    if (tcp_flags & 0x04) {  // RST
        struct conn_value *v = ct_lookup(&fwd_key);
        if (!v) {
            // RST بلا اتصال معروف → Drop
            ct_stat_inc(4);  // rst_dropped
            meta->verdict = XDP_DROP;

            // إصدار حدث Critical
            struct security_event *e = critical_events.ringbuf_reserve(sizeof(*e));
            if (e) {
                e->timestamp_ns = now_ns;
                e->src_ip       = meta->src_ip;
                e->dst_ip       = meta->dst_ip;
                e->src_port     = meta->src_port;
                e->dst_port     = meta->dst_port;
                e->event_type   = 5;   // CONNTRACK_ERR
                e->severity     = 2;   // CRITICAL
                e->protocol     = IPPROTO_TCP;
                e->pkt_count    = 1;
                e->reason[0]    = 0;
                critical_events.ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
            }
            goto apply_verdict;
        }
        v->state        = CT_STATE_CLOSED;
        v->last_seen_ns = now_ns;
        goto next_stage;
    }

    // ── ACK (الأكثر شيوعاً) ───────────────────────────────────────────
    if (tcp_flags & 0x10) {  // ACK
        struct conn_value *v = ct_lookup(&fwd_key);

        if (!v) {
            // ACK بلا اتصال معروف → الحماية الحقيقية من ACK Flood
            ct_stat_inc(2);  // dropped_no_state
            meta->verdict = XDP_DROP;

            struct security_event *e = critical_events.ringbuf_reserve(sizeof(*e));
            if (e) {
                e->timestamp_ns = now_ns;
                e->src_ip       = meta->src_ip;
                e->dst_ip       = meta->dst_ip;
                e->src_port     = meta->src_port;
                e->dst_port     = meta->dst_port;
                e->event_type   = 5;   // CONNTRACK_ERR
                e->severity     = 2;
                e->protocol     = IPPROTO_TCP;
                e->pkt_count    = 1;
                e->reason[0]    = 0;
                critical_events.ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
            }
            goto apply_verdict;
        }

        // تحقق من timeout
        if (!conn_is_valid(v)) {
            ct_stat_inc(7);  // timeout_dropped
            meta->verdict = XDP_DROP;
            goto apply_verdict;
        }

        // اتصال شرعي → حدّث الحالة
        v->state        = CT_STATE_ESTABLISHED;
        v->last_seen_ns = now_ns;
        v->timeout_s    = get_timeout(0, 300);  // established=300s
        v->pkt_count++;
        ct_update(&fwd_key, v);
        ct_stat_inc(1);  // established
    } else if (!(tcp_flags & 0x02) && !(tcp_flags & 0x04)) {
        struct conn_value *v = ct_lookup(&fwd_key);
        if (!v) {
            meta->verdict = XDP_DROP;
            ct_stat_inc(2);
            goto apply_verdict;
        }
    }

next_stage:;
    // ── تابع للـ stage التالي بحسب bitmask ───────────────────────────
    __u32 k0 = 0;
    __u64 *cfg_ptr = pipeline_config.lookup(&k0);
    __u64 cfg = cfg_ptr ? *cfg_ptr : 0;

    if (cfg & FLAG_SYN_PROXY) {
        bpf_tail_call(ctx, &xdp_pipeline, STAGE_SYN_PROXY);
    }
    if (cfg & FLAG_L4_LB) {
        bpf_tail_call(ctx, &xdp_pipeline, STAGE_L4_LB);
    }

apply_verdict:;
    __u8 verdict = meta->verdict;
    bpf_xdp_adjust_meta(ctx, (int)sizeof(struct pipeline_meta));
    return verdict;
}

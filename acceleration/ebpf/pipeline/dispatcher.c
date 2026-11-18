/*
 * bunyanx NGFW — XDP Unified Pipeline (BCC-compatible)
 * =========================================================
 * ملف واحد يحتوي كل الـ stages — مطلوب لـ BCC لمشاركة PROG_ARRAY.
 *
 * لماذا ملف واحد؟
 *   BCC يُنشئ BPF object واحد لكل BPF(text=...) call.
 *   الـ PROG_ARRAY يجب أن يكون في نفس الـ object حتى تعمل tail calls.
 *   إذا حمّلنا stages منفصلة → كل واحدة تحصل على xdp_pipeline خاص بها.
 *
 * الـ pipeline_loader.py يقرأ هذا الملف (أو يُجمّع الـ stages بحسب الـ flags).
 *
 * المبادئ:
 *   1. bitmask يُقرأ مرة واحدة per-packet
 *   2. الـ state يُنقل عبر xdp_md.data_meta (لا stack sharing بين tail calls)
 *   3. كل __always_inline لتجنب BPF verifier stack overflow
 *   4. Fallback: XDP_PASS عند أي خطأ
 *
 * Pipeline Stages (bitmask bits):
 *   Bit 4: BLACKLIST  (Stage 0) — دائماً مفعّل، لا يمكن إيقافه
 *   Bit 5: CONNTRACK  (Stage 1) — Phase 3 — TCP State Machine
 *   Bit 6: SYN_PROXY  (Stage 2) — Phase 4 — SYN Cookie / Rate Detection
 *   Bit 7: L4_LB      (Stage 3) — Phase 5 — DNAT + Session Persistence
 */

#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

// ═══════════════════════════════════════════════════════════════════
// Stage Constants (يتطابق مع PipelineStage enum في Python)
// ═══════════════════════════════════════════════════════════════════
#define STAGE_BLACKLIST  0
#define STAGE_CONNTRACK  1
#define STAGE_SYN_PROXY  2
#define STAGE_L4_LB      3

// Feature Bitmask
#define FLAG_BLACKLIST  (1ULL << 4)
#define FLAG_CONNTRACK  (1ULL << 5)
#define FLAG_SYN_PROXY  (1ULL << 6)
#define FLAG_L4_LB      (1ULL << 7)

// ═══════════════════════════════════════════════════════════════════
// BPF Maps (BCC Syntax — لا libbpf-style structs)
// ═══════════════════════════════════════════════════════════════════

// PROG_ARRAY لـ Tail Calls (BCC macro — NOT libbpf struct)
BPF_PROG_ARRAY(xdp_pipeline, 8);

// Pipeline config: [0]=bitmask, [1]=max_stages
BPF_ARRAY(pipeline_config, u64, 4);

// Dispatcher stats: [0]=total, [1]=tc_miss, [2]=meta_fail
BPF_ARRAY(dispatcher_stats, u64, 8);

// ── Phase 1: Ring Buffers ───────────────────────────────────────────
BPF_RINGBUF_OUTPUT(critical_events, 1024);  // 1MB — FORCE_WAKEUP
BPF_RINGBUF_OUTPUT(warning_events,  4096);  // 4MB — NO_WAKEUP batch
BPF_RINGBUF_OUTPUT(info_events,    16384);  // 16MB — polling
BPF_ARRAY(lost_events_counter, u64, 1);

// ── Phase 2: IP Blocklist (Stage 0) ────────────────────────────────
struct rate_info {
    u64 last_ts;
    u64 count;
};

BPF_LRU_HASH(blocked_ips, u32, u32, 100000);
BPF_LRU_HASH(whitelist_ips, u32, u32, 10000);
BPF_LRU_HASH(rate_limit_map, u32, struct rate_info, 50000);
BPF_ARRAY(rate_limit_config, u64, 2);  // [0]=pps_limit

static __always_inline int is_exempt_ip(u32 ip) {
    u32 *wl = whitelist_ips.lookup(&ip);
    if (wl != NULL && *wl == 1) return 1;

    unsigned char *b = (unsigned char *)&ip;
    if (b[0] == 127) return 1;

    return 0;
}

// ── Phase 3: Conntrack Maps ────────────────────────────────────────
// TCP States
#define CT_STATE_NEW         1
#define CT_STATE_SYN_RECV    2
#define CT_STATE_ESTABLISHED 3
#define CT_STATE_FIN_WAIT    4
#define CT_STATE_CLOSED      6

struct conn_key {
    u32 src_ip, dst_ip;
    u16 src_port, dst_port;
    u8  protocol;
    u8  pad[3];   // verifier: kil bits م معروفة
};

struct conn_value {
    u64 last_seen_ns;
    u32 pkt_count;
    u32 byte_count;
    u8  state;
    u8  flags;
    u16 pad;
    u32 timeout_s;
    u32 reserved;
};

BPF_PERCPU_HASH(ct_fast,   struct conn_key, struct conn_value, 65536);
BPF_LRU_HASH(ct_global,    struct conn_key, struct conn_value, 1000000);
BPF_ARRAY(ct_stats,  u64, 8);
BPF_ARRAY(ct_timeouts, u32, 4);  // [0]=est, [1]=syn, [2]=fin

// ── Phase 4: SYN Proxy Maps ────────────────────────────────────────
#define REP_TRUSTED    1
#define REP_SUSPICIOUS 2

struct ip_rep {
    u8  reputation;
    u8  cookie_sent;
    u16 syn_count;
    u32 last_seen_s;
};

BPF_LRU_HASH(ip_reputation_map, u32, struct ip_rep, 500000);
BPF_PERCPU_HASH(syn_rate_map, u32, u64, 100000);
BPF_ARRAY(syn_proxy_config, u32, 4);   // [0]=syn_threshold
BPF_ARRAY(syn_proxy_stats, u64, 8);

// ── Phase 5: L4 LB Maps ────────────────────────────────────────────
struct backend_info {
    u32 ip;
    u16 port;
    u8  healthy;
    u8  weight;
};

BPF_ARRAY(healthy_backends_map, struct backend_info, 64);
BPF_ARRAY(num_healthy_backends, u32, 1);
BPF_LRU_HASH(conn_backend_map, u64, u32, 500000);
BPF_ARRAY(lb_stats, u64, 8);

// ═══════════════════════════════════════════════════════════════════
// Shared Structs
// ═══════════════════════════════════════════════════════════════════

// pipeline_meta: ينقل الـ state بين الـ stages عبر xdp_md.data_meta
struct pipeline_meta {
    u8  stage;
    u8  verdict;   // XDP_PASS=2, XDP_DROP=1
    u16 flags;     // bitmask للـ stages
    u32 src_ip, dst_ip;
    u16 src_port, dst_port;
    u8  protocol;
    u8  tcp_flags;
    u16 pad;
};

// security_event: يُرسَل عبر Ring Buffers (64 bytes cache-aligned)
struct security_event {
    u64 timestamp_ns;
    u32 src_ip, dst_ip;
    u16 src_port, dst_port;
    u8  event_type;
    u8  severity;
    u16 protocol;
    u32 pkt_count;
    char reason[32];
};

// ═══════════════════════════════════════════════════════════════════
// Global Helpers (مشتركة بين جميع الـ stages)
// ═══════════════════════════════════════════════════════════════════

static __always_inline void stat_inc(u32 key) {
    u64 *v = dispatcher_stats.lookup(&key);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline void lost_inc(void) {
    u32 k = 0;
    u64 *c = lost_events_counter.lookup(&k);
    if (c) __sync_fetch_and_add(c, 1);
}

static __always_inline void emit_critical(u32 src_ip, u32 dst_ip,
                                          u16 sp, u16 dp,
                                          u8 etype, u16 proto) {
    struct security_event *e = critical_events.ringbuf_reserve(sizeof(*e));
    if (!e) { lost_inc(); return; }
    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip = src_ip; e->dst_ip = dst_ip;
    e->src_port = sp;   e->dst_port = dp;
    e->event_type = etype; e->severity = 2;
    e->protocol = proto;   e->pkt_count = 1;
    e->reason[0] = 0;
    critical_events.ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
}

static __always_inline void emit_warning(u32 src_ip, u8 etype, u32 cnt) {
    struct security_event *e = warning_events.ringbuf_reserve(sizeof(*e));
    if (!e) { lost_inc(); return; }
    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip = src_ip; e->event_type = etype;
    e->severity = 1;    e->pkt_count = cnt;
    e->reason[0] = 0;
    warning_events.ringbuf_submit(e, BPF_RB_NO_WAKEUP);
}

static __always_inline u64 get_pipeline_flags(void) {
    u32 k = 0;
    u64 *f = pipeline_config.lookup(&k);
    return f ? *f : FLAG_BLACKLIST;
}

// ═══════════════════════════════════════════════════════════════════
// PROG: xdp_dispatcher — يُحمَّل مباشرة على الـ NIC
// ═══════════════════════════════════════════════════════════════════
int xdp_dispatcher(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    stat_inc(0);  // total_dispatched

    // تخصيص metadata headroom
    if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct pipeline_meta)) < 0) {
        stat_inc(2);  // meta_alloc_failed
        return XDP_PASS;
    }

    data = (void *)(long)ctx->data;
    struct pipeline_meta *meta = (void *)(long)ctx->data_meta;
    if ((void *)(meta + 1) > data) return XDP_PASS;

    // تعبئة metadata مرة واحدة per-packet
    meta->stage   = 0;
    meta->verdict = XDP_PASS;
    meta->flags   = 0;
    meta->pad     = 0;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) goto cleanup;
    if (eth->h_proto != htons(ETH_P_IP)) goto cleanup;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) goto cleanup;

    meta->src_ip   = iph->saddr;
    meta->dst_ip   = iph->daddr;
    meta->protocol = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        u8 ihl = iph->ihl;
        if (ihl < 5) goto cleanup;
        struct tcphdr *tcph = (void *)iph + (ihl * 4);
        if ((void *)(tcph + 1) <= data_end) {
            meta->src_port  = ntohs(tcph->source);
            meta->dst_port  = ntohs(tcph->dest);
            meta->tcp_flags = (tcph->syn ? 0x02 : 0)
                            | (tcph->ack ? 0x10 : 0)
                            | (tcph->fin ? 0x01 : 0)
                            | (tcph->rst ? 0x04 : 0);
        }
    }

    // قراءة bitmask مرة واحدة (مبدأ الأداء الرئيسي)
    u64 cfg = get_pipeline_flags();

    if (cfg & FLAG_BLACKLIST) {
        xdp_pipeline.call(ctx, STAGE_BLACKLIST);
        stat_inc(1);  // tail_call_missed — stage not loaded yet
    }
    // ملاحظة: ما بعد tail_call لا ينفَّذ إلا عند فشل الـ tail call
    if (cfg & FLAG_CONNTRACK) { xdp_pipeline.call(ctx, STAGE_CONNTRACK); stat_inc(1); }
    if (cfg & FLAG_SYN_PROXY) { xdp_pipeline.call(ctx, STAGE_SYN_PROXY); stat_inc(1); }
    if (cfg & FLAG_L4_LB)     { xdp_pipeline.call(ctx, STAGE_L4_LB);     stat_inc(1); }

cleanup:;
    u8 verdict = meta->verdict;
    bpf_xdp_adjust_meta(ctx, (int)sizeof(struct pipeline_meta));
    return verdict;
}

// ═══════════════════════════════════════════════════════════════════
// PROG: stage_blacklist (Stage 0 — دائماً مفعّل)
// ═══════════════════════════════════════════════════════════════════
int stage_blacklist(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct pipeline_meta *meta = (void *)(long)ctx->data_meta;
    if ((void *)(meta + 1) > data) return XDP_PASS;

    u32 src_ip = meta->src_ip;

    // Exemption check: RFC-1918 Private IPs & Whitelisted IPs bypass eBPF block/rate-limit
    if (is_exempt_ip(src_ip)) {
        goto next_stage;
    }

    // IP Blocklist
    u32 *blk = blocked_ips.lookup(&src_ip);
    if (blk && *blk == 1) {
        meta->verdict = XDP_DROP;
        emit_critical(src_ip, meta->dst_ip,
                      meta->src_port, meta->dst_port,
                      0 /* BLOCKED_IP */, meta->protocol);
        goto apply;
    }

    // Rate Limit
    u64 now = bpf_ktime_get_ns();
    struct rate_info *rinfo = rate_limit_map.lookup(&src_ip);
    if (rinfo) {
        if (now - rinfo->last_ts > 1000000000ULL) {
            rinfo->last_ts = now;
            rinfo->count = 1;
        } else {
            u32 k = 0;
            u64 *pps = rate_limit_config.lookup(&k);
            u64 lim = pps ? *pps : 5000ULL;
            if (rinfo->count >= lim) {
                meta->verdict = XDP_DROP;
                emit_warning(src_ip, 1 /* RATE_LIMITED */, (u32)rinfo->count);
                goto apply;
            }
            __sync_fetch_and_add(&rinfo->count, 1);
        }
    } else {
        struct rate_info init = { .last_ts = now, .count = 1 };
        rate_limit_map.update(&src_ip, &init);
    }

next_stage:;
    // Next stage
    u64 cfg = get_pipeline_flags();
    if (cfg & FLAG_CONNTRACK) { xdp_pipeline.call(ctx, STAGE_CONNTRACK); }
    if (cfg & FLAG_SYN_PROXY) { xdp_pipeline.call(ctx, STAGE_SYN_PROXY); }
    if (cfg & FLAG_L4_LB)     { xdp_pipeline.call(ctx, STAGE_L4_LB);     }

apply:;
    u8 verdict = meta->verdict;
    bpf_xdp_adjust_meta(ctx, (int)sizeof(struct pipeline_meta));
    return verdict;
}

// ═══════════════════════════════════════════════════════════════════
// PROG: stage_conntrack (Stage 1 — Phase 3)
// ═══════════════════════════════════════════════════════════════════

static __always_inline struct conn_value *ct_lookup(struct conn_key *k) {
    struct conn_value *v = ct_fast.lookup(k);
    if (v) return v;
    v = ct_global.lookup(k);
    if (v) {
        struct conn_value cp = *v;
        ct_fast.update(k, &cp);
    }
    return v;
}

static __always_inline void ct_stat(u32 k) {
    u64 *v = ct_stats.lookup(&k);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline u32 ct_timeout(u32 idx, u32 def) {
    u32 *t = ct_timeouts.lookup(&idx);
    return (t && *t) ? *t : def;
}

int stage_conntrack(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct pipeline_meta *meta = (void *)(long)ctx->data_meta;
    if ((void *)(meta + 1) > data) goto next;

    if (meta->protocol != IPPROTO_TCP) goto next;

    u8 tcp_flags = meta->tcp_flags;
    u64 now      = bpf_ktime_get_ns();

    struct conn_key fk = {
        .src_ip = meta->src_ip,   .dst_ip = meta->dst_ip,
        .src_port = meta->src_port, .dst_port = meta->dst_port,
        .protocol = IPPROTO_TCP,
    };
    struct conn_key rk = {
        .src_ip = meta->dst_ip,   .dst_ip = meta->src_ip,
        .src_port = meta->dst_port, .dst_port = meta->src_port,
        .protocol = IPPROTO_TCP,
    };

    // SYN — new connection
    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
        struct conn_value nv = {
            .last_seen_ns = now, .state = CT_STATE_NEW,
            .pkt_count = 1, .timeout_s = ct_timeout(1, 10),
        };
        ct_fast.update(&fk, &nv);
        ct_global.update(&fk, &nv);
        ct_stat(0);
        goto next;
    }

    // RST without state → DROP
    if (tcp_flags & 0x04) {
        struct conn_value *v = ct_lookup(&fk);
        if (!v) {
            meta->verdict = XDP_DROP;
            ct_stat(4);
            emit_critical(meta->src_ip, meta->dst_ip,
                          meta->src_port, meta->dst_port,
                          5 /* CONNTRACK_ERR */, IPPROTO_TCP);
            goto apply;
        }
        goto next;
    }

    // ACK without state → DROP (حماية από ACK Flood)
    if (tcp_flags & 0x10) {
        struct conn_value *v = ct_lookup(&fk);
        if (!v) {
            meta->verdict = XDP_DROP;
            ct_stat(2);
            emit_critical(meta->src_ip, meta->dst_ip,
                          meta->src_port, meta->dst_port,
                          5 /* CONNTRACK_ERR */, IPPROTO_TCP);
            goto apply;
        }
        // Timeout check
        u64 age = (now - v->last_seen_ns) / 1000000000ULL;
        if (age > v->timeout_s) {
            meta->verdict = XDP_DROP;
            ct_stat(7);
            goto apply;
        }
        v->state = CT_STATE_ESTABLISHED;
        v->last_seen_ns = now;
        v->timeout_s = ct_timeout(0, 300);
        v->pkt_count++;
        ct_fast.update(&fk, v);
        ct_stat(1);
    } else if (!(tcp_flags & 0x02) && !(tcp_flags & 0x04)) {
        struct conn_value *v = ct_lookup(&fk);
        if (!v) {
            meta->verdict = XDP_DROP;
            ct_stat(2);
            goto apply;
        }
    }

next:;
    u64 cfg = get_pipeline_flags();
    if (cfg & FLAG_SYN_PROXY) { xdp_pipeline.call(ctx, STAGE_SYN_PROXY); }
    if (cfg & FLAG_L4_LB)     { xdp_pipeline.call(ctx, STAGE_L4_LB);     }

apply:;
    u8 verdict = meta->verdict;
    bpf_xdp_adjust_meta(ctx, (int)sizeof(struct pipeline_meta));
    return verdict;
}

// ═══════════════════════════════════════════════════════════════════
// PROG: stage_syn_proxy (Stage 2 — Phase 4)
// ═══════════════════════════════════════════════════════════════════

static __always_inline void syn_stat(u32 k) {
    u64 *v = syn_proxy_stats.lookup(&k);
    if (v) __sync_fetch_and_add(v, 1);
}

int stage_syn_proxy(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct pipeline_meta *meta = (void *)(long)ctx->data_meta;
    if ((void *)(meta + 1) > data) goto next;

    // SYN Proxy يعمل على TCP SYN فقط
    if (meta->protocol != IPPROTO_TCP)                         goto next;
    if (!((meta->tcp_flags & 0x02) && !(meta->tcp_flags & 0x10))) goto next;

    syn_stat(0);  // total_syn
    u32 src_ip = meta->src_ip;

    // Trusted IP → pass immediately
    struct ip_rep *rep = ip_reputation_map.lookup(&src_ip);
    if (rep && rep->reputation == REP_TRUSTED) {
        syn_stat(2);
        goto next;
    }

    // Suspicious IP → mark for cookie challenge
    if (rep && rep->reputation == REP_SUSPICIOUS) {
        syn_stat(1);
        meta->flags |= 0x01;
        goto next;
    }

    // Rate check
    u64 *sc = syn_rate_map.lookup(&src_ip);
    u32 k0 = 0;
    u32 *thr_p = syn_proxy_config.lookup(&k0);
    u64 thr = thr_p ? *thr_p : 1000ULL;

    if (sc && *sc >= thr) {
        struct ip_rep nr = {
            .reputation = REP_SUSPICIOUS,
            .syn_count  = (u16)*sc,
            .last_seen_s = (u32)(bpf_ktime_get_ns() / 1000000000ULL),
        };
        ip_reputation_map.update(&src_ip, &nr);
        emit_critical(src_ip, meta->dst_ip, meta->src_port, meta->dst_port,
                      2 /* SYN_FLOOD */, IPPROTO_TCP);
        syn_stat(5);
        meta->flags |= 0x01;
    } else {
        u64 one = 1;
        if (!sc) syn_rate_map.update(&src_ip, &one);
        else __sync_fetch_and_add(sc, 1);
    }

next:;
    u64 cfg = get_pipeline_flags();
    if (cfg & FLAG_L4_LB) { xdp_pipeline.call(ctx, STAGE_L4_LB); }

    u8 verdict = meta->verdict;
    bpf_xdp_adjust_meta(ctx, (int)sizeof(struct pipeline_meta));
    return verdict;
}

// ═══════════════════════════════════════════════════════════════════
// PROG: stage_l4_lb (Stage 3 — Phase 5)
// ═══════════════════════════════════════════════════════════════════

static __always_inline u64 flow_hash(u32 si, u32 di, u16 sp, u16 dp, u8 p) {
    u64 h = 2166136261ULL;
    h ^= si; h *= 16777619;
    h ^= di; h *= 16777619;
    h ^= sp; h *= 16777619;
    h ^= dp; h *= 16777619;
    h ^= p;  h *= 16777619;
    return h;
}

static __always_inline u64 csum_fold(u64 c) {
    c = (c >> 32) + (c & 0xffffffff);
    c = (c >> 16) + (c & 0xffff);
    c = (c >> 16) + (c & 0xffff);
    return ~(u16)c;
}

static __always_inline void lb_stat(u32 k) {
    u64 *v = lb_stats.lookup(&k);
    if (v) __sync_fetch_and_add(v, 1);
}

int stage_l4_lb(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct pipeline_meta *meta = (void *)(long)ctx->data_meta;
    if ((void *)(meta + 1) > data) return XDP_PASS;

    lb_stat(0);

    u32 k0 = 0;
    u32 *num_ptr = num_healthy_backends.lookup(&k0);
    if (!num_ptr || *num_ptr == 0) { lb_stat(1); goto done; }
    u32 num = *num_ptr;

    u64 fh = flow_hash(meta->src_ip, meta->dst_ip,
                       meta->src_port, meta->dst_port,
                       meta->protocol);

    u32 *eb = conn_backend_map.lookup(&fh);
    u32 bidx;
    if (eb && *eb < num) {
        bidx = *eb; lb_stat(3);
    } else {
        bidx = ((u32)fh) % num;
        conn_backend_map.update(&fh, &bidx);
        lb_stat(5);
    }

    struct backend_info *b = healthy_backends_map.lookup(&bidx);
    if (!b || !b->healthy) { goto done; }

    if (meta->protocol != IPPROTO_TCP && meta->protocol != IPPROTO_UDP)
        goto done;

    // Re-parse headers (pointer may have shifted)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) goto done;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) goto done;

    u32 old_dst = iph->daddr;
    iph->daddr  = b->ip;

    // Incremental IP checksum
    u64 ck = ~(u16)iph->check;
    ck += ~(u16)(old_dst >> 16);    ck += ~(u16)(old_dst & 0xFFFF);
    ck += (u16)(b->ip >> 16);      ck += (u16)(b->ip & 0xFFFF);
    iph->check = (u16)csum_fold(ck);

    if (meta->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        if ((void *)(tcph + 1) <= data_end) {
            u16 oport = tcph->dest;
            u16 nport = htons(b->port);
            tcph->dest = nport;
            u64 tc = ~(u16)tcph->check;
            tc += ~(u16)(old_dst >> 16); tc += ~(u16)(old_dst & 0xFFFF);
            tc += (u16)(b->ip >> 16);   tc += (u16)(b->ip & 0xFFFF);
            tc += ~oport;                tc += nport;
            tcph->check = (u16)csum_fold(tc);
        }
    } else {
        struct udphdr *u = (void *)iph + sizeof(struct iphdr);
        if ((void *)(u + 1) <= data_end) {
            u->dest = htons(b->port);
            u->check = 0;  // optional for IPv4
        }
    }

    // Rewrite MAC addresses to bounce back to router
    unsigned char tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);
    
    meta->verdict = XDP_TX;
    lb_stat(2);

done:;
    u8 verdict = meta->verdict;
    bpf_xdp_adjust_meta(ctx, (int)sizeof(struct pipeline_meta));
    return verdict;
}

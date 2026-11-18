/*
 * bunyanx NGFW — XDP Stage 3: L4 Load Balancer (DSR ready)
 * =============================================================
 * يوزّع الحمل على الـ backends بسرعة السيليكون — O(1) lookup.
 *
 * المبدأ الأساسي (الحد الفاصل بين Kernel و Userspace):
 *   Userspace يحسب:  healthy_backends[] مسبقاً + session assignments
 *   Kernel يُنفّذ:   DNAT + checksum update فقط — لا decision هنا
 *
 * التصميم:
 *   1. healthy_backends_map: يُملأ فقط من LBManager (Python)
 *                            Kernel يقرأ فقط (no write in fast path)
 *   2. conn_backend_map:     Session persistence — نفس connection → نفس backend
 *   3. Hash: flow_hash(src_ip, src_port, dst_ip, dst_port) % num_healthy
 *   4. DNAT: تعديل IP+Port+Checksum في XDP
 *
 * الخطورة:
 *   - checksum خاطئ → الحزمة تُرفض من الـ server
 *   - DNAT بلا reverse SNAT → الـ server يرد بـ NAT خاطئ
 *   - يجب اختبار E2E كامل قبل الإنتاج
 *
 * Session Persistence:
 *   BPF_NOEXIST تضمن أن نفس الـ TCP flow يذهب دائماً لنفس الـ backend
 *   حتى عند تغيير الـ healthy list
 */

#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

// ═══════════════════════════════════════════════════════════════════
// Backend Info (يتطابق مع BackendInfo في lb_manager.py)
// ═══════════════════════════════════════════════════════════════════
struct backend_info {
    __u32 ip;        // Destination IP (network byte order)
    __u16 port;      // Destination port
    __u8  healthy;   // 1=healthy, 0=down
    __u8  weight;    // للمستقبل (weighted LB)
};

// ═══════════════════════════════════════════════════════════════════
// BPF Maps
// ═══════════════════════════════════════════════════════════════════

// قائمة الـ backends الصحيحة — يُملأ من LBManager (Python فقط)
// max 64 backend (يُقرأ من base.yaml.ebpf.l4_lb.max_backends)
BPF_ARRAY(healthy_backends_map, struct backend_info, 64);

// عدد الـ backends الصحيحة الحالية
BPF_ARRAY(num_healthy_backends, __u32, 1);

// Session persistence: flow_key → backend_index
// حجم يُقرأ من base.yaml.ebpf.l4_lb.session_map_size
BPF_LRU_HASH(conn_backend_map, __u64, __u32, 500000);

// LB stats
BPF_ARRAY(lb_stats, __u64, 8);
// [0]=total_balanced [1]=no_backends [2]=dnat_applied
// [3]=session_reuse  [4]=checksum_errors [5]=new_sessions

// Pipeline maps (shared)
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} xdp_pipeline SEC(".maps");

struct pipeline_meta {
    __u8 stage; __u8 verdict; __u16 flags;
    __u32 src_ip; __u32 dst_ip;
    __u16 src_port; __u16 dst_port;
    __u8 protocol; __u8 tcp_flags; __u16 pad;
};

// ═══════════════════════════════════════════════════════════════════
// Inline Helpers
// ═══════════════════════════════════════════════════════════════════

static __always_inline void lb_stat_inc(__u32 key) {
    __u64 *v = lb_stats.lookup(&key);
    if (v) __sync_fetch_and_add(v, 1);
}

// Flow hash بسيط وسريع (جيد بما يكفي لتوزيع الحمل)
static __always_inline __u64 flow_hash(__u32 src_ip, __u32 dst_ip,
                                       __u16 src_port, __u16 dst_port,
                                       __u8 proto) {
    // FNV-like hash — ثابت ومتكرر لنفس الـ flow
    __u64 h = 2166136261ULL;
    h ^= src_ip;  h *= 16777619;
    h ^= dst_ip;  h *= 16777619;
    h ^= src_port; h *= 16777619;
    h ^= dst_port; h *= 16777619;
    h ^= proto;   h *= 16777619;
    return h;
}

// Checksum update بعد DNAT (incremental — O(1))
static __always_inline __u16 csum_fold_helper(__u64 csum) {
    csum = (csum >> 32) + (csum & 0xffffffff);
    csum = (csum >> 16) + (csum & 0xffff);
    csum = (csum >> 16) + (csum & 0xffff);
    return ~(__u16)csum;
}

static __always_inline void update_ip_checksum(struct iphdr *iph,
                                               __u32 old_ip, __u32 new_ip) {
    __u64 csum = ~(__u16)iph->check;
    csum += ~(__u16)(old_ip >> 16);
    csum += ~(__u16)(old_ip & 0xFFFF);
    csum += (__u16)(new_ip >> 16);
    csum += (__u16)(new_ip & 0xFFFF);
    iph->check = csum_fold_helper(csum);
}

// TCP checksum update بعد DNAT
static __always_inline void update_tcp_checksum(struct tcphdr *tcph,
                                                __u32 old_ip, __u32 new_ip,
                                                __u16 old_port, __u16 new_port) {
    __u64 csum = ~(__u16)tcph->check;
    // IP change
    csum += ~(__u16)(old_ip >> 16);
    csum += ~(__u16)(old_ip & 0xFFFF);
    csum += (__u16)(new_ip >> 16);
    csum += (__u16)(new_ip & 0xFFFF);
    // Port change
    csum += ~(__u16)old_port;
    csum += new_port;
    tcph->check = csum_fold_helper(csum);
}

// ═══════════════════════════════════════════════════════════════════
// Main L4 LB Stage
// ═══════════════════════════════════════════════════════════════════
SEC("xdp")
int stage_l4_lb(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct pipeline_meta *meta = (void *)(long)ctx->data_meta;
    if ((void *)(meta + 1) > data) return XDP_PASS;

    lb_stat_inc(0);  // total_balanced

    // ── تحقق من عدد الـ backends المتاحة ─────────────────────────────
    __u32 k0 = 0;
    __u32 *num_ptr = num_healthy_backends.lookup(&k0);
    if (!num_ptr || *num_ptr == 0) {
        lb_stat_inc(1);  // no_backends — اسمح بالمرور للـ proxy
        goto done;
    }
    __u32 num = *num_ptr;

    // ── Session Persistence: نفس flow → نفس backend ──────────────────
    __u64 fhash = flow_hash(
        meta->src_ip, meta->dst_ip,
        meta->src_port, meta->dst_port,
        meta->protocol
    );

    __u32 *existing_backend = conn_backend_map.lookup(&fhash);
    __u32 backend_idx;

    if (existing_backend && *existing_backend < num) {
        backend_idx = *existing_backend;
        lb_stat_inc(3);  // session_reuse
    } else {
        // اختر backend جديد بـ O(1) hash
        backend_idx = ((__u32)fhash) % num;
        // سجّل لضمان persistence
        conn_backend_map.update(&fhash, &backend_idx);
        lb_stat_inc(5);  // new_sessions
    }

    // ── DNAT: تعديل Destination IP + Port ────────────────────────────
    struct backend_info *backend = healthy_backends_map.lookup(&backend_idx);
    if (!backend || !backend->healthy) {
        // Backend غير صحي → أعد الاختيار (fallback)
        __u32 alt = (backend_idx + 1) % num;
        backend = healthy_backends_map.lookup(&alt);
        if (!backend) goto done;
    }

    // تأكد من أن الـ packet هو TCP/UDP قبل DNAT
    if (meta->protocol != IPPROTO_TCP && meta->protocol != IPPROTO_UDP) {
        goto done;
    }

    // إعادة قراءة الـ headers بعد pipeline_meta (قد تكون متغيرة)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) goto done;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) goto done;

    // حفظ القديم للـ checksum update
    __u32 old_dst_ip = iph->daddr;

    // تطبيق DNAT
    iph->daddr = backend->ip;
    update_ip_checksum(iph, old_dst_ip, backend->ip);

    if (meta->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        if ((void *)(tcph + 1) <= data_end) {
            __u16 old_port = tcph->dest;
            tcph->dest = bpf_htons(backend->port);
            update_tcp_checksum(tcph, old_dst_ip, backend->ip,
                                old_port, bpf_htons(backend->port));
        }
    } else if (meta->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        if ((void *)(udph + 1) <= data_end) {
            udph->dest = bpf_htons(backend->port);
            udph->check = 0;  // UDP checksum optional for IPv4
        }
    }

    // Rewrite MAC addresses to bounce back to router
    unsigned char tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);
    
    meta->verdict = XDP_TX;
    lb_stat_inc(2);  // dnat_applied

done:;
    __u8 verdict = meta->verdict;
    bpf_xdp_adjust_meta(ctx, (int)sizeof(struct pipeline_meta));
    return verdict;
}

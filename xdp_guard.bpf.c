#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_DEVICES 1024
#define REASON_PPS_EXCEEDED  1
#define REASON_BPS_EXCEEDED  2
#define REASON_PORT_MISMATCH 3

struct device_profile {
    __u8  dev_type;
    __u16 allowed_port;
    __u8  allowed_proto;
    __u32 max_pps;
    __u32 max_bps;
};

struct sliding_window {
    __u64 prev_bucket_ts;
    __u32 prev_pkt_cnt;
    __u64 prev_byte_cnt;
    
    __u64 curr_bucket_ts;
    __u32 curr_pkt_cnt;
    __u64 curr_byte_cnt;
};

struct drop_event {
    __u8  src_mac[ETH_ALEN];
    __u32 src_ip;
    __u16 src_port;
    __u8  reason_code;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);
    __type(key, __u8[ETH_ALEN]);
    __type(value, struct device_profile);
} device_profile_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_DEVICES);
    __type(key, __u32);
    __type(value, struct sliding_window);
} sliding_window_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);
    __type(key, __u8[ETH_ALEN]);
    __type(value, __u64);
} blacklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline void submit_drop_event(__u8 *mac, __u32 ip, __u16 port, __u8 reason) {
    struct drop_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    __builtin_memcpy(e->src_mac, mac, ETH_ALEN);
    e->src_ip = ip;
    e->src_port = port;
    e->reason_code = reason;
    e->timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);
}

SEC("xdp")
int xdp_guard_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u8 *src_mac = eth->h_source;

    __u64 *blocked_at = bpf_map_lookup_elem(&blacklist_map, src_mac);
    if (blocked_at) {
        return XDP_DROP;
    }

    struct device_profile *profile = bpf_map_lookup_elem(&device_profile_map, src_mac);
    if (!profile) {
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u8  proto  = iph->protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        src_port = tcph->source;
        dst_port = tcph->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        src_port = udph->source;
        dst_port = udph->dest;
    }

    __u32 pkt_len  = data_end - data;
    __u64 now_ns   = bpf_ktime_get_ns();
    __u64 now_sec  = now_ns / 1000000000ULL;
    __u32 map_idx  = 0;

    struct sliding_window *sw = bpf_map_lookup_elem(&sliding_window_map, &map_idx);
    if (!sw) return XDP_PASS;

    if (now_sec > sw->curr_bucket_ts) {
        sw->prev_bucket_ts = sw->curr_bucket_ts;
        sw->prev_pkt_cnt   = sw->curr_pkt_cnt;
        sw->prev_byte_cnt  = sw->curr_byte_cnt;

        sw->curr_bucket_ts = now_sec;
        sw->curr_pkt_cnt   = 1;
        sw->curr_byte_cnt  = pkt_len;
    } else {
        sw->curr_pkt_cnt++;
        sw->curr_byte_cnt += pkt_len;
    }

    __u32 est_pps = sw->curr_pkt_cnt;
    __u64 est_bps = sw->curr_byte_cnt * 8;

    if (profile->dev_type == 1) {
        if (proto != profile->allowed_proto || 
           (dst_port != profile->allowed_port && src_port != profile->allowed_port)) {
            submit_drop_event(src_mac, src_ip, bpf_ntohs(src_port), REASON_PORT_MISMATCH);
            return XDP_DROP;
        }

        if (est_bps > profile->max_bps) {
            submit_drop_event(src_mac, src_ip, bpf_ntohs(src_port), REASON_BPS_EXCEEDED);
            return XDP_DROP;
        }
    } else {
        if (est_pps > profile->max_pps) {
            submit_drop_event(src_mac, src_ip, bpf_ntohs(src_port), REASON_PPS_EXCEEDED);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define ETH_ALEN 6

struct device_profile {
    uint8_t  dev_type;
    uint16_t allowed_port;
    uint8_t  allowed_proto;
    uint32_t max_pps;
    uint32_t max_bps;
};

struct drop_event {
    uint8_t  src_mac[ETH_ALEN];
    uint32_t src_ip;
    uint16_t src_port;
    uint8_t  reason_code;
    uint64_t timestamp;
};

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct drop_event *e = data;
    int blacklist_map_fd = *(int *)ctx;

    printf("\n🚨 [XDP-Guard ALERT] 이상 트래픽 감지 및 차단 발생!\n");
    printf(" ├─ 차단 기기 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           e->src_mac[0], e->src_mac[1], e->src_mac[2],
           e->src_mac[3], e->src_mac[4], e->src_mac[5]);
    printf(" ├─ 출발지 IP/Port: %d.%d.%d.%d:%d\n",
           e->src_ip & 0xFF, (e->src_ip >> 8) & 0xFF,
           (e->src_ip >> 16) & 0xFF, (e->src_ip >> 24) & 0xFF, e->src_port);
    printf(" └─ 차단 사유 코드: %d (1:PPS, 2:BPS, 3:PORT)\n", e->reason_code);

    uint64_t now_ts = e->timestamp;
    int err = bpf_map_update_elem(blacklist_map_fd, e->src_mac, &now_ts, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update blacklist_map: %s\n", strerror(errno));
    } else {
        printf(" ➔ [Control Plane] blacklist_map 에 등록 완료\n");
    }

    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct ring_buffer *rb = NULL;
    int prog_fd, dev_prof_fd, blist_fd, rb_fd;
    int ifindex;
    const char *ifname = "lo";

    if (argc > 1) {
        ifname = argv[1];
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file("xdp_guard.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: bpf_object__open_file failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: bpf_object__load failed\n");
        return 1;
    }

    dev_prof_fd = bpf_object__find_map_fd_by_name(obj, "device_profile_map");
    blist_fd    = bpf_object__find_map_fd_by_name(obj, "blacklist_map");
    rb_fd       = bpf_object__find_map_fd_by_name(obj, "rb");

    uint8_t test_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    struct device_profile cam_prof = {
        .dev_type      = 1,
        .allowed_port  = 554,
        .allowed_proto = 17,
        .max_pps       = 1000,
        .max_bps       = 10000000
    };
    bpf_map_update_elem(dev_prof_fd, test_mac, &cam_prof, BPF_ANY);
    printf("✅ [Control Plane] IP 카메라 프로필 등록 완료\n");

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_guard_prog");
    prog_fd = bpf_program__fd(prog);

    DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
    int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, &opts);
    if (err) {
        fprintf(stderr, "ERROR: bpf_xdp_attach failed: %s\n", strerror(errno));
        return 1;
    }
    printf("🚀 [Data Plane] XDP-Guard 엔진이 '%s' 인터페이스에 로드되었습니다.\n", ifname);

    rb = ring_buffer__new(rb_fd, handle_event, &blist_fd, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("📡 [Control Plane] Event Polling 시작...\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    printf("\n🧹 Clean up 진행 중...\n");
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
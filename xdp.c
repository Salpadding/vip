//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "GPL";

#define MAX_MAP_ENTRIES 16
#define ETH_P_ARP 0x0806

#define MAC_LENGTH 6
#define IPV4_LENGTH 4

struct arp_header {
    __be16 hardware_type;
    __be16 protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    __be16 opcode;
    char sender_mac[MAC_LENGTH];
    __be32 sender_ip;
    char target_mac[MAC_LENGTH];
    __be32 target_ip;
} __attribute__((packed));


struct arp_sender {
    char sender_mac[MAC_LENGTH];
    __be32 sender_ip;
} __attribute__((packed));


const struct arp_sender *unused __attribute__((unused));

// ip -> 1/0
// 表示这个 ip 是否属于当前机器
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32); // source IPv4 address
	__type(value, __u32); // packet count
} vip_set SEC(".maps");


// ringbuffer 把客户端mac地址 传给 go 
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} messages SEC(".maps");


// 收到目标 ip = vip 的请求后 立刻通知 go 
SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;


	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		goto done;
	}



    // 查看是否是 arp 协议
	if (eth->h_proto != bpf_htons(ETH_P_ARP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		goto done;
	}

    // 查看 opcode 是否是 arp 请求
    struct arp_header* ah = (void*)(eth + 1);

    if((void*)(ah + 1) > data_end) goto done;

    if(ah->opcode != bpf_htons(1)) {
        goto done;
    }


    u32 key = ah->target_ip;
    // 查看这个vip是不是要路由的本地
	__u32 *ok = bpf_map_lookup_elem(&vip_set, &key);
    
    if(!ok || !(*ok)) {
        // 如果不路由到本地跳过
        goto done;
    }


    // 把请求方的 mac 地址传递给 go
    struct arp_sender* sender = bpf_ringbuf_reserve(&messages, sizeof(struct arp_sender), 0);
    // 忽略缓冲溢出
    if(!sender) {
        goto done;
    }

    memcpy(sender, &(ah->sender_mac), sizeof(*sender));
    bpf_ringbuf_submit(sender, 0);


done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}

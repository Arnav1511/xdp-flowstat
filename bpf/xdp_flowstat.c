// SPDX-License-Identifier: GPL-2.0
//
// Stage 3: count ingress packets by IP protocol.
//
// Parses the ethernet header, then (for IPv4 only) the IP header, and
// increments one of four slots in a per-CPU array. Everything is passed on
// to the stack -- every code path returns XDP_PASS.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ETH_P_IP is a #define in <linux/if_ether.h>, not an enum, so BTF does not
// carry it and it is absent from vmlinux.h. BTF describes types, not macros.
// IPPROTO_TCP/UDP/ICMP *are* an enum, so those do come from vmlinux.h.
#define ETH_P_IP 0x0800

#define SLOT_TCP   0
#define SLOT_UDP   1
#define SLOT_ICMP  2
#define SLOT_OTHER 3
#define SLOT_MAX   4

// BPF_MAP_TYPE_PERCPU_ARRAY gives every CPU its own copy of each slot.
// XDP runs in NAPI context with preemption disabled, so a CPU cannot race
// with itself -- the increment below needs no atomic. Userspace sums the
// per-CPU copies when it reads. That is the whole reason for per-CPU here:
// it trades a little read-side work for a contention-free write path.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SLOT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} proto_count SEC(".maps");

static __always_inline void count(__u32 slot)
{
	__u64 *val = bpf_map_lookup_elem(&proto_count, &slot);

	// NULL CHECK (required by the verifier).
	// bpf_map_lookup_elem returns PTR_TO_MAP_VALUE_OR_NULL. That type is
	// not dereferenceable. Comparing it against NULL is what narrows it to
	// PTR_TO_MAP_VALUE on the fall-through path. Same shape of proof as a
	// bounds check, different pointer type.
	if (!val)
		return;

	*val += 1;
}

SEC("xdp")
int xdp_flowstat(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;

	// BOUNDS CHECK 1 -- proves bytes [0, 14) are readable.
	// Without it, eth->h_proto (offset 12, size 2) is an access at off=12
	// against a packet pointer with range 0.
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	// h_proto is __be16; the constant must be byte-swapped, not the field.
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		count(SLOT_OTHER);
		return XDP_PASS;
	}

	struct iphdr *ip = (void *)(eth + 1);

	// BOUNDS CHECK 2 -- proves bytes [14, 34) are readable.
	// Check 1 says nothing about anything past byte 14. The verifier tracks
	// range per pointer, and this is a new pointer at a new offset.
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	// ip->protocol sits at a fixed offset 9 within the IPv4 header,
	// ahead of any options, so ihl does not need decoding to read it.
	switch (ip->protocol) {
	case IPPROTO_TCP:
		count(SLOT_TCP);
		break;
	case IPPROTO_UDP:
		count(SLOT_UDP);
		break;
	case IPPROTO_ICMP:
		count(SLOT_ICMP);
		break;
	default:
		count(SLOT_OTHER);
		break;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

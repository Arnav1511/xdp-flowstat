// SPDX-License-Identifier: GPL-2.0
//
// Stage 5: count ingress packets by address family and IP protocol.
//
// Handles VLAN-tagged frames (802.1Q and QinQ) and IPv6, including a bounded
// walk over IPv6 extension headers. Every path returns XDP_PASS.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Ethertypes and the IPv6 extension-header protocol numbers are #defines in
// the kernel headers, not enum members, so BTF does not carry them and they
// are absent from vmlinux.h. (IPPROTO_TCP/UDP/ICMP/ESP/AH *are* enum members,
// so those do come from vmlinux.h.) BTF describes types, never macros.
#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_HOPOPTS  0
#define IPPROTO_ROUTING  43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ICMPV6   58
#define IPPROTO_DSTOPTS  60
#define IPPROTO_MH       135

// Bounds on the two loops. Both exist for the verifier's benefit as much as
// for correctness: an unbounded walk over attacker-controlled headers is
// exactly what the verifier refuses to accept.
#define MAX_VLAN_DEPTH 2
#define MAX_EXT_HDRS   4

#define SLOT_V4_TCP   0
#define SLOT_V4_UDP   1
#define SLOT_V4_ICMP  2
#define SLOT_V4_OTHER 3
#define SLOT_V6_TCP   4
#define SLOT_V6_UDP   5
#define SLOT_V6_ICMP  6
#define SLOT_V6_OTHER 7
#define SLOT_NON_IP   8
#define SLOT_MAX      9

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SLOT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} proto_count SEC(".maps");

static __always_inline void count(__u32 slot)
{
	__u64 *val = bpf_map_lookup_elem(&proto_count, &slot);

	// NULL CHECK: bpf_map_lookup_elem returns PTR_TO_MAP_VALUE_OR_NULL,
	// which is not dereferenceable. This comparison narrows the type.
	if (!val)
		return;

	*val += 1;
}

static __always_inline __u32 v4_slot(__u8 proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return SLOT_V4_TCP;
	case IPPROTO_UDP:
		return SLOT_V4_UDP;
	case IPPROTO_ICMP:
		return SLOT_V4_ICMP;
	default:
		return SLOT_V4_OTHER;
	}
}

static __always_inline __u32 v6_slot(__u8 proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return SLOT_V6_TCP;
	case IPPROTO_UDP:
		return SLOT_V6_UDP;
	case IPPROTO_ICMPV6:
		return SLOT_V6_ICMP;
	default:
		return SLOT_V6_OTHER;
	}
}

SEC("xdp")
int xdp_flowstat(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;

	// BOUNDS CHECK 1 -- proves bytes [0, 14).
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__be16 proto = eth->h_proto;
	void *nh     = (void *)(eth + 1); // next header

	// A bounded loop, not #pragma unroll. Bounded loops have verified since
	// kernel 5.3; before that this had to be hand-unrolled. The bound is what
	// lets the verifier prove termination -- `while (is_vlan(proto))` would
	// be rejected outright.
	for (int i = 0; i < MAX_VLAN_DEPTH; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) &&
		    proto != bpf_htons(ETH_P_8021AD))
			break;

		struct vlan_hdr *vh = nh;

		// BOUNDS CHECK 2 -- each iteration re-proves 4 more bytes. The
		// range established on the previous pass says nothing here.
		if ((void *)(vh + 1) > data_end)
			return XDP_PASS;

		proto = vh->h_vlan_encapsulated_proto;
		nh    = (void *)(vh + 1);
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = nh;

		// BOUNDS CHECK 3 -- the fixed 20-byte IPv4 header. ip->protocol
		// sits at offset 9, ahead of any options, so ihl need not be
		// decoded to read it.
		if ((void *)(ip + 1) > data_end)
			return XDP_PASS;

		count(v4_slot(ip->protocol));
		return XDP_PASS;
	}

	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = nh;

		// BOUNDS CHECK 4 -- the fixed 40-byte IPv6 header.
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;

		__u8 nexthdr = ip6->nexthdr;
		void *cur    = (void *)(ip6 + 1);

		// IPv6 puts the transport protocol behind a chain of extension
		// headers. Walk a bounded number of them; anything deeper (or an
		// encrypted ESP payload) counts as v6/other rather than guessing.
		for (int i = 0; i < MAX_EXT_HDRS; i++) {
			if (nexthdr == IPPROTO_HOPOPTS ||
			    nexthdr == IPPROTO_ROUTING ||
			    nexthdr == IPPROTO_DSTOPTS ||
			    nexthdr == IPPROTO_MH) {
				struct ipv6_opt_hdr *opt = cur;

				// BOUNDS CHECK 5 -- 2 bytes for the option header.
				if ((void *)(opt + 1) > data_end)
					return XDP_PASS;

				nexthdr = opt->nexthdr;
				// hdrlen is in 8-octet units, excluding the first 8.
				// It comes from the packet, so this is a VARIABLE
				// advance: after it, cur is a packet pointer with a
				// variable offset and the verifier tracks only an
				// upper bound (255 + 1) * 8 = 2048.
				cur += ((__u32)opt->hdrlen + 1) * 8;
			} else if (nexthdr == IPPROTO_FRAGMENT) {
				struct frag_hdr *fh = cur;

				// BOUNDS CHECK 6 -- the fragment header is a fixed 8.
				if ((void *)(fh + 1) > data_end)
					return XDP_PASS;

				nexthdr = fh->nexthdr;
				cur += 8;
			} else {
				break;
			}
		}

		count(v6_slot(nexthdr));
		return XDP_PASS;
	}

	// ARP, LLDP, anything that is not IP.
	count(SLOT_NON_IP);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

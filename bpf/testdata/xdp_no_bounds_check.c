// DELIBERATELY BROKEN. Not part of the build.
// Reads the ethernet header without ever checking ctx->data_end.
// clang compiles this happily. The verifier will not load it.
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_no_bounds_check(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	// MISSING: if ((void *)(eth + 1) > (void *)(long)ctx->data_end) return XDP_PASS;
	if (eth->h_proto == 0)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

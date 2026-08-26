// DELIBERATELY BROKEN. Not part of the build.
// Body is correct; only the SEC() string is wrong. This is rejected at a
// DIFFERENT layer than the bounds-check failure -- by the loader, not the
// verifier, because the section name is what selects the program type.
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tc")
int xdp_wrong_section(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

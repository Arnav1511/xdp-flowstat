// SPDX-License-Identifier: GPL-2.0
//
// Stage 2: the smallest XDP program that does something observable.
// It inspects nothing and passes every packet up to the kernel stack.
//
// vmlinux.h is generated from /sys/kernel/btf/vmlinux (see `make vmlinux`).
// It replaces <linux/...> kernel headers entirely -- that is what makes this
// CO-RE: field offsets become relocations resolved at load time, not
// constants baked in at compile time.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// SEC() places this function in an ELF section literally named "xdp".
// That string is the contract with the loader: it is how cilium/ebpf knows
// to ask the kernel for BPF_PROG_TYPE_XDP. The CPU does not care about it.
SEC("xdp")
int xdp_pass_all(struct xdp_md *ctx)
{
	// ctx->data and ctx->data_end are the only things we are given.
	// We deliberately do not dereference them yet -- the moment we do,
	// the verifier requires a bounds check. That is Stage 3's lesson.
	return XDP_PASS;
}

// The kernel refuses to load a BPF program with no license section.
// "GPL" unlocks GPL-only helpers (bpf_probe_read_kernel, most tracing
// helpers). A non-GPL string loads, but restricts which helpers you may call.
char _license[] SEC("license") = "GPL";

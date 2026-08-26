# xdp-flowstat

An XDP program that counts packets by protocol at the NIC driver layer, exposes
the counters via an eBPF map, and serves them as Prometheus metrics.

**Status: Stage 2 — minimal XDP program attaching and detaching cleanly.**
No counting, no maps, no metrics yet.

## What works today

- `bpf/xdp_flowstat.c` — returns `XDP_PASS` for every packet. Two instructions.
- `cmd/flowstat` — a [cilium/ebpf](https://github.com/cilium/ebpf) loader that
  attaches the program, holds it, and detaches on SIGINT/SIGTERM.
- `scripts/` — an isolated veth test harness.

## Requirements

- Linux kernel with `CONFIG_DEBUG_INFO_BTF=y` (any modern distro kernel)
- clang 15+ and LLVM (`clang-19 llvm-19 libbpf-dev` on Ubuntu/Mint)
- Go 1.24+
- root for attaching (`kernel.unprivileged_bpf_disabled` is 2 on most distros)

`vmlinux.h` is committed so a fresh clone builds without needing BTF on the
build host. Regenerate for your own kernel with `make vmlinux`.

`cmd/flowstat/flowstat_bpfel.{go,o}` are also committed — bpf2go embeds the
object via `go:embed`, so `go build` works without clang installed.

## Build

```bash
make build              # go generate (clang) + go build
make generate-docker    # same, in a container, if you have no host clang
```

## Test harness

XDP is **ingress-only**, so the program attaches to the *host* end of the veth
pair. Traffic originating in the namespace arrives on `veth-fs0`'s ingress.

```
 ┌─ netns: flowstat ─┐              ┌─ host netns ──────────┐
 │  veth-fs1 ────────┼──────────────┼──── veth-fs0          │
 │  10.200.0.2/24    │              │     10.200.0.1/24     │
 └───────────────────┘              │        ▲              │
                                    │        └── XDP here   │
                                    └───────────────────────┘
```

```bash
make up                 # create netns + veth pair
make down               # tear it all down
```

## Run

```bash
sudo ./bin/flowstat -iface veth-fs0 -mode native
```

The loader **refuses to attach to the interface carrying the default route**
(read from `/proc/net/route`) unless you pass `-force`. Attaching a faulty XDP
program to the NIC carrying your SSH session will lock you out of the machine.

Verify from another terminal:

```bash
ip link show veth-fs0                 # look for "xdp" (driver) vs "xdpgeneric"
sudo bpftool prog show | grep xdp
sudo ip netns exec flowstat ping -c 5 10.200.0.1
```

Ctrl-C detaches. The BPF link is refcounted against the process, so even
SIGKILL detaches it — no orphaned programs.

### native vs generic

`-mode` is explicit on purpose. cilium/ebpf's default silently falls back from
driver to generic mode, and you would never know which you got.

- `native` (`XDPDriverMode`) — runs in the driver's NAPI poll loop, **before
  `alloc_skb()`**. This is where XDP's performance comes from.
- `generic` (`XDPGenericMode`) — runs after the `sk_buff` is allocated. Works
  on any interface, but loses the entire point. Testing only.

## Deliberately broken programs

`bpf/testdata/` holds two programs that fail to load, on purpose, at two
different layers:

| File | Rejected by | Why |
|---|---|---|
| `xdp_no_bounds_check.c` | **verifier** | dereferences `ctx->data` without comparing against `ctx->data_end` |
| `xdp_wrong_section.c` | **loader** | `SEC("tc")` makes the loader infer `SchedCLS`, not `XDP` |

Both compile cleanly — the verifier is a load-time gate, not a compile-time one.

```bash
clang -target bpf -O2 -g -Wall -Wno-missing-declarations \
      -c bpf/testdata/xdp_no_bounds_check.c -o bpf/testdata/xdp_no_bounds_check.o
sudo bpftool prog load bpf/testdata/xdp_no_bounds_check.o /sys/fs/bpf/broken
```

The verifier reports `R1=pkt(r=0)` then `invalid access to packet, off=12
size=2`. It tracks a *type* and a provable *range* per register. Fresh from
`ctx->data` the range is zero; the check `off + size <= r` gives `12 + 2 <= 0`,
which fails. Comparing against `data_end` is what widens the range — the bounds
check is a proof for the static analyser, not a runtime guard.

## Roadmap

- **Stage 2** ✅ attach/detach cleanly
- **Stage 3** per-protocol counters in a `BPF_MAP_TYPE_PERCPU_ARRAY`
- **Stage 4** Prometheus exporter

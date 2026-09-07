# xdp-flowstat

An XDP program that counts packets by protocol at the NIC driver layer, exposes
the counters via an eBPF map, and serves them as Prometheus metrics.

**Status: Stage 5 — VLAN and IPv6 parsing, counters by family and protocol.**

## What works today

- `bpf/xdp_flowstat.c` — parses the ethernet header, up to two VLAN tags,
  then IPv4 or IPv6 (walking a bounded chain of IPv6 extension headers), and
  counts into a 9-slot `BPF_MAP_TYPE_PERCPU_ARRAY`. Every path returns
  `XDP_PASS`.
- `cmd/flowstat` — a [cilium/ebpf](https://github.com/cilium/ebpf) loader that
  attaches the program, serves `/metrics`, and detaches on SIGINT/SIGTERM.
- `scripts/` — an isolated veth test harness, plus a verifier lab.

## Metrics

```
xdp_flowstat_packets_total{family="ipv4",protocol="tcp"}    2
xdp_flowstat_packets_total{family="ipv4",protocol="udp"}    0
xdp_flowstat_packets_total{family="ipv4",protocol="icmp"}  15
xdp_flowstat_packets_total{family="ipv4",protocol="other"}  0
xdp_flowstat_packets_total{family="ipv6",protocol="tcp"}    0
xdp_flowstat_packets_total{family="ipv6",protocol="udp"}    0
xdp_flowstat_packets_total{family="ipv6",protocol="icmp"}   0
xdp_flowstat_packets_total{family="ipv6",protocol="other"}  0
xdp_flowstat_packets_total{family="non_ip",protocol="other"} 9
```

Served on `-metrics-addr` (default `:2112`). The map is read inside
`Collect()`, i.e. on scrape, rather than copied into a gauge by a background
ticker: no scrape sees data staler than itself, and no work happens when
nobody is asking.

These are `CounterValue`, not gauges. They only increase, and Prometheus needs
to know that for `rate()` to handle a counter reset (process restart) correctly.

Cardinality is fixed at nine series. That is deliberate — a per-source-address
variant would need an LRU hash and a top-N, not a Prometheus label per address.

### Parsing limits

Deliberate bounds, not oversights. The verifier requires every loop to be
bounded, so "how deep do we walk" is a design decision that has to be made
explicitly.

| Limit | Effect |
|---|---|
| `MAX_VLAN_DEPTH = 2` | a frame with three or more tags counts as `non_ip` |
| `MAX_EXT_HDRS = 4` | a longer IPv6 header chain counts as `ipv6`/`other` |
| ESP / AH not decoded | encrypted payloads count as `ipv6`/`other`; the transport header is not visible |
| `SLOT_MAX` defined in both C and Go | can drift silently if a slot is added |

### Complexity cost

Adding VLAN and IPv6 parsing took the program from **57 to 196 instructions**.
The verifier explores every reachable path, so its `insn_processed` count grows
faster than the static size. `scripts/verifier-lab.sh` prints the figure for
the current program.

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
make test               # unit tests for the collector (no root, no kernel)
make generate-docker    # same as build, in a container, if you have no host clang
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
curl -s localhost:2112/metrics | grep xdp_flowstat
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

### Reproducing the rejections

`scripts/verifier-lab.sh` deletes each check in turn, compiles the result, and
tries to load it. Every variant compiles; every variant is rejected.

```bash
sudo ./scripts/verifier-lab.sh
```

## Roadmap

- **Stage 2** ✅ attach/detach cleanly
- **Stage 3** ✅ per-protocol counters in a `BPF_MAP_TYPE_PERCPU_ARRAY`
- **Stage 4** ✅ Prometheus exporter
- **Stage 5** ✅ IPv6 and VLAN parsing

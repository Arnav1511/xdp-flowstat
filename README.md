# xdp-flowstat

An XDP program that counts ingress packets by address family and IP protocol at
the NIC driver layer, exposes the counters through an eBPF map, and serves them
as Prometheus metrics.

It is small on purpose. The interesting part is not the counting — it is where
the counting happens, and what the kernel makes you prove before it will let you
do it there.

```
xdp_flowstat_packets_total{family="ipv4",protocol="icmp"}   15
xdp_flowstat_packets_total{family="ipv6",protocol="icmp"}    8
xdp_flowstat_packets_total{family="non_ip",protocol="other"} 9
```

- [Quick start](#quick-start)
- [How it works](#how-it-works) — XDP's position, CO-RE, the verifier, complexity
- [Design decisions](#design-decisions)
- [What it does not do](#what-it-does-not-do)
- [Reference](#reference)

---

## Quick start

```bash
make build              # clang -target bpf + bpf2go + go build
sudo make up            # create an isolated veth pair in its own netns
sudo ./bin/flowstat -iface veth-fs0 -mode native

# elsewhere
curl -s localhost:2112/metrics | grep xdp_flowstat
sudo ip netns exec flowstat ping -c 5 10.200.0.1
```

Ctrl-C detaches. `sudo make down` removes the harness.

The loader **refuses to attach to the interface carrying the default route**
(read from `/proc/net/route`) unless you pass `-force`. A faulty XDP program on
the NIC carrying your SSH session will lock you out of the machine, and a rule
enforced only by care is a rule that fails at 1am.

---

## How it works

### Where XDP sits

XDP runs inside the driver's NAPI poll loop, on the raw DMA'd buffer, **before
the kernel allocates an `sk_buff`**. Everything else about its performance
follows from that one fact.

```
NIC DMAs frame into the RX ring
   │
   ├─► XDP                    raw buffer. no sk_buff exists yet.
   │
   ├─► alloc_skb()            ~200B of metadata, cache misses
   ├─► GRO coalescing
   ├─► ingress qdisc  ─► tc BPF     sk_buff exists, GRO done
   ├─► netfilter PREROUTING (iptables / nftables)
   ├─► routing decision
   └─► netfilter INPUT ─► socket demux
```

Consequences:

- **`XDP_DROP` costs a pointer bump.** The page returns straight to the driver's
  recycle ring; you never paid for the `sk_buff`. This is where the "roughly 10×
  faster than `iptables -j DROP`" figure comes from.
- **`struct xdp_md` is almost empty** — `data`, `data_end`, `data_meta`,
  `ingress_ifindex`, `rx_queue_index`, `egress_ifindex`. No protocol fields, no
  metadata, because none has been computed yet. That austerity *is* the
  performance story, visible in the type.
- **`XDP_TX` and `XDP_REDIRECT`** can bounce or forward a packet without the
  stack ever seeing it. Load balancers and DDoS scrubbers live here.

### What XDP cannot do that tc BPF can

| | XDP | tc BPF |
|---|---|---|
| Direction | **ingress only** | ingress **and** egress |
| `sk_buff` metadata | none — no `mark`, `priority`, cgroup, socket | full access |
| GRO | runs **before** it, sees wire frames | runs after, sees coalesced segments |
| Interface support | needs driver support for native mode | anything: veth, tunnels, bonds, `lo` |
| Packet growth | `bpf_xdp_adjust_head/tail`, limited by headroom | grows freely, skb handles fragmentation |

Both limitations trace back to the same sentence: *before `sk_buff` allocation,
receive only*. "Which process generated this traffic" is structurally
unanswerable from XDP, because the socket association does not exist yet.

The usual caveat: `BPF_XDP_DEVMAP` and `BPF_XDP_CPUMAP` programs (5.8+) do run
on the egress side of an `XDP_REDIRECT`. Neither is a general TX hook — you
cannot attach one to an interface and observe locally-generated traffic.

### CO-RE, and why there are no kernel headers here

`bpf/xdp_flowstat.c` includes `vmlinux.h` and nothing from `<linux/...>`. That
file is generated from the running kernel's own BTF:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h  # make vmlinux
```

3.4 MB, ~167k lines, every type the kernel knows about — reconstructed from the
type information the kernel ships about itself (`CONFIG_DEBUG_INFO_BTF=y`).

Without CO-RE, reading a field 40 bytes into a struct compiles to
`load 4 bytes from (pointer + 40)`, with `40` baked into the instruction stream.
Ship that to a kernel built with one extra `#ifdef` earlier in the struct and
you silently read the neighbouring field. No error. Wrong data.

`vmlinux.h` opens with:

```c
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
```

which makes clang emit a **relocation record** instead of a constant: *"this
instruction reads the field named `protocol` in `struct iphdr` — patch in
whatever offset it has here."* At load time the loader reads the target kernel's
BTF, resolves the field by name, and rewrites the instruction before the
verifier sees it.

**CO-RE is dynamic linking for struct field offsets.** You ship unresolved
symbols; the loader resolves them against the kernel it finds.

What breaks it: a kernel without BTF (nothing to resolve against); a field
genuinely renamed or removed, unless guarded with `bpf_core_field_exists()`; and
the nasty one — a field whose *meaning* changed while its layout did not. CO-RE
fixes layout, not semantics, so that loads fine and reports garbage.

**Honest scope note.** This program does not actually need CO-RE. `struct
xdp_md` is stable UAPI and `ethhdr`/`iphdr`/`ipv6hdr` are wire formats; none of
them move. Compiling with and without `preserve_access_index` yields identical
offsets (`0xc`, `0xe`, `0x22`, `0x9`). CO-RE earns its keep when you read
*internal* kernel structs from tracing programs. Knowing where the boundary sits
matters more than invoking the acronym.

### What the verifier is actually doing

The verifier is an abstract interpreter that walks every reachable path through
the program's control flow graph before the kernel will run it. Per register it
tracks:

- a **type** — `SCALAR_VALUE`, `PTR_TO_CTX`, `PTR_TO_PACKET`,
  `PTR_TO_PACKET_END`, `PTR_TO_MAP_VALUE_OR_NULL`, `PTR_TO_STACK`, …
- for scalars, a **known-bits mask** plus signed and unsigned min/max bounds
- for packet pointers, a **range** (`r`) — how many bytes past this pointer are
  *provably* readable

Fresh out of `ctx->data`, a packet pointer is `pkt(r=0)`: you have proven
nothing. Reading `eth->h_proto` is `off=12 size=2`, and the test `off + size <= r`
gives `12 + 2 <= 0`. Rejected.

What widens the range is **comparing a derived pointer against `data_end`**. The
verifier splits its analysis at the branch and, on the fall-through path,
records that those bytes exist:

```
0: (61) r2 = *(u32 *)(r1 +4)      ; R2=pkt_end()
1: (61) r1 = *(u32 *)(r1 +0)      ; R1=pkt(r=0)
2: (bf) r5 = r1                   ; R5=pkt(r=0)
3: (07) r5 += 14                  ; R5=pkt(off=14,r=0)     ← range still zero
4: (2d) if r5 > r2 goto pc+178    ; R5=pkt(off=14,r=14)    ← range now 14
```

Nothing was loaded. No packet arrived. **The comparison itself is the proof.**
That is why eBPF packet-parsing code looks paranoid: the checks are not runtime
guards, they are the only way to convince a static analyser that a pointer is
safe before a single packet exists.

Two things that catch people out: the range attaches to a *specific register*,
so re-reading `ctx->data` resets it; and any helper that can move the packet
(`bpf_xdp_adjust_head`) invalidates every packet pointer you hold.

Map lookups fail differently. `bpf_map_lookup_elem` returns
`PTR_TO_MAP_VALUE_OR_NULL`, a type that is not dereferenceable at all. The NULL
check narrows the **type**, not a range — and at runtime a lookup on an array
map with an in-range key can never return NULL. You are not defending against a
failure; you are discharging a proof obligation.

### The proof chain, measured

`scripts/verifier-lab.sh` deletes each safety check in turn, compiles, and tries
to load. **Every variant compiles cleanly** — the verifier is a load-time gate,
not a compile-time one. Measured on 7.0.0-31-generic:

| Check deleted | `off` | `r` proven | processed | states |
|---|---|---|---|---|
| NULL (map lookup) | — | — | 17 | 2 |
| ethernet header | 12 | **0** | 5 | 0 |
| VLAN header | 16 | 14 | 27 | 3 |
| IPv4 header | 31 | 22 | 47 | 5 |
| IPv6 header | 28 | 22 | 105 | 11 |
| IPv6 option header | 63 | 62 | 129 | 13 |
| IPv6 fragment header | 70 | **0** ⚠ | 241 | 25 |
| *baseline, all present* | — | — | **1220** | **121** |

Every `off` reconciles against the parse position. `off=31` is 14 (ethernet) +
4 + 4 (two VLAN tags) + 9 (`ip->protocol`) — the verifier followed the VLAN loop
through both iterations and knows exactly where it ended up.

`r` climbs `0 → 14 → 22 → 62` as each surviving check adds to what is proven.
Each rejection is the *next* thing wanting more range than the *previous* check
established.

**The fragment-header row is the interesting one.** Every other rejection reads
`id=0`; that one reads `R1(id=8, off=70, r=0)` — a fresh pointer id, and a
proven range back to zero. The cause is one line in the extension-header walk:

```c
cur += ((__u32)opt->hdrlen + 1) * 8;   // hdrlen comes from the packet
```

After adding a **runtime value** to a packet pointer, the verifier can no longer
track a static offset. It assigns a new id and resets the range to zero, because
it genuinely does not know where `cur` landed — only an upper bound. So the next
check is not defensive repetition: after a variable advance you are proving
things from scratch, every iteration. If you ever see `id=N` with `r=0` deep in
a program, that is the tell.

### Complexity

Two limits, and they are the *same constant* used twice:

```c
if (attr->insn_cnt == 0 ||
    attr->insn_cnt > (bpf_capable() ? BPF_COMPLEXITY_LIMIT_INSNS : BPF_MAXINSNS))
        return -E2BIG;
```

- **Program size** — `BPF_COMPLEXITY_LIMIT_INSNS` (1,000,000) privileged,
  `BPF_MAXINSNS` (4,096) unprivileged. A static count of instructions.
- **Complexity budget** — the same 1,000,000, but counting `insn_processed`:
  how many instructions the verifier *walks* while exploring paths.

Because verification is path-sensitive, the second grows faster than the first.
Adding VLAN and IPv6 parsing here took the program from **57 to 196
instructions** (3.4×) but from a handful to **1,220 processed** — roughly 6× the
static size. A few-hundred-instruction program with heavy branching can exhaust
a million verifier steps while nowhere near the size limit, and fails with
`BPF program is too large. Processed N insn`.

What keeps it tractable is **state pruning**: the verifier caches states at
branch points and stops when it reaches one it has already proven equivalent or
more general. This program peaks at `max_states_per_insn 5` across 121 states.
Code that defeats pruning — unrolled loops with varying constants, many distinct
register states — is what actually burns the budget. The fixes are making code
uniform, `bpf_loop()`, or splitting into tail calls or global subprograms that
verify independently.

### Reading a load failure

| errno | Meaning | What to do |
|---|---|---|
| `EPERM` | missing `CAP_BPF` / `CAP_NET_ADMIN` | you are not root enough |
| `EACCES` | caps fine, **the verifier refused** | read the verifier log |
| `EINVAL` / `E2BIG` | malformed `bpf_attr`, oversized `insn_cnt` | usually never reached verification — look at your loader or ELF |

A verifier rejection surfacing as a *permissions* error sends people hunting for
capabilities they already have. Knowing which layer rejected you is the
diagnostic skill: the loader rejects before any syscall (wrong section name →
wrong program type inferred, fails instantly, no register dump), while the
verifier rejects inside `BPF_PROG_LOAD` with a wall of register states.

### Why cilium/ebpf and not libbpf

**Because libbpf means cgo, and cgo poisons the Go deployment story.** Cross
compilation breaks, static linking against musl becomes a fight, the container
image needs `libbpf.so` and a matching glibc, builds slow, and delve/pprof get
worse.

cilium/ebpf is pure Go — it implements the `bpf()` syscall and ELF loading
natively. `bin/flowstat` is a single static binary with the bytecode embedded
via `go:embed`; it needs no clang, no headers, no shared library at runtime. The
API is Go you already know: `signal.NotifyContext`, `errors.As`, `io.Closer`.

Reach for libbpf when your userspace is C anyway, when you need a kernel feature
the week it lands (libbpf is upstream and tracks the kernel; cilium/ebpf
reimplements and lags), or for the more exotic surfaces — USDT, `struct_ops`,
BPF iterators.

---

## Design decisions

**`-mode` is explicit, never defaulted.** cilium/ebpf's zero value means "try
driver, silently fall back to generic." Fine in production, wrong for
understanding what you built — you would never know which you got. Passing
`XDPDriverMode` means the kernel *errors* rather than falling back, so a
successful attach is evidence of native mode rather than a hope.
`generic` runs after `alloc_skb()`: same API, none of the benefit, testing only.

**`BPF_MAP_TYPE_PERCPU_ARRAY`, not `ARRAY` with atomics.** XDP runs in NAPI
context with preemption disabled, so a CPU cannot race with itself. Each CPU
increments its own copy with a plain `*val += 1` — no `__sync_fetch_and_add`, no
cache line bouncing between cores at line rate. The cost is paid once on the
read side, summing across CPUs.

**The map is read inside `Collect()`, on scrape.** A background ticker copying
into gauges would mean every scrape sees data up to one tick stale, and work
happening when nobody is asking.

**`CounterValue`, not `GaugeValue`.** These only increase. Prometheus needs the
type to handle a counter reset — the process restarting — correctly in `rate()`.

**A private registry, not `DefaultRegisterer`.** Nothing is exported unless this
binary asks for it, so a dependency cannot silently add series. Go runtime and
process collectors are registered explicitly.

**Cardinality is fixed at nine series.** Deliberate. The obvious next feature —
per-source-address counters — is where eBPF observability projects melt a
Prometheus server. That wants an LRU hash and a top-N, not a label per address.

**The collector reads through a `counterSource` interface, not `*ebpf.Map`.**
That is what makes the exposition unit-testable with no kernel, no root and no
attached program (`make test`).

---

## What it does not do

Deliberate bounds, not oversights. The verifier requires every loop to be
bounded, so "how deep do we walk" is a design decision that must be made
explicitly rather than discovered.

| Limit | Effect |
|---|---|
| `MAX_VLAN_DEPTH = 2` | a frame with three or more tags counts as `non_ip` |
| `MAX_EXT_HDRS = 4` | a longer IPv6 extension chain counts as `ipv6`/`other` |
| ESP / AH not decoded | encrypted payloads count as `ipv6`/`other` |
| IPv4 options ignored | `ip->protocol` sits at a fixed offset, so `ihl` is not decoded |
| `SLOT_MAX` defined in both C and Go | can drift silently if a slot is added |

`XDP_PASS` does not mean *delivered* — it means *handed to the stack*. Between
this hook and a socket sit `alloc_skb`, tc ingress, netfilter, routing and
socket demux, any of which can drop the packet. The gap between "counted here"
and "reached the application" is itself a useful diagnostic signal.

---

## Reference

### Requirements

- Linux kernel with `CONFIG_DEBUG_INFO_BTF=y` (any modern distro kernel)
- clang 15+ and LLVM (`clang-19 llvm-19 libbpf-dev` on Ubuntu/Mint)
- Go 1.24+
- root to attach (`kernel.unprivileged_bpf_disabled` is 2 on most distros)

`vmlinux.h` and `cmd/flowstat/flowstat_bpfel.{go,o}` are committed, so a fresh
clone builds without BTF or clang on the build host. Regenerate with
`make vmlinux` and `make generate`.

### Build

```bash
make build              # go generate (clang) + go build
make test               # collector unit tests — no root, no kernel
make generate-docker    # build in a container if the host has no clang
```

### Test harness

XDP is ingress-only, so the program attaches to the **host** end of the pair.
Traffic originating in the namespace arrives on `veth-fs0`'s ingress; attaching
to `veth-fs1` would show you the opposite direction.

```
 ┌─ netns: flowstat ─┐              ┌─ host netns ──────────┐
 │  veth-fs1 ────────┼──────────────┼──── veth-fs0          │
 │  10.200.0.2/24    │              │     10.200.0.1/24     │
 └───────────────────┘              │        ▲              │
                                    │        └── XDP here   │
                                    └───────────────────────┘
```

```bash
sudo make up      # create netns + veth pair
sudo make down    # tear down, detaching any XDP program first
```

### Flags

| Flag | Default | |
|---|---|---|
| `-iface` | *(required)* | interface to attach to |
| `-mode` | `native` | `native` or `generic` |
| `-metrics-addr` | `:2112` | listen address for `/metrics` |
| `-force` | `false` | allow attaching to the default-route interface |

### Verifying an attach

```bash
ip link show veth-fs0          # "xdp" = driver mode, "xdpgeneric" = fallback
sudo bpftool prog show | grep xdp_flowstat
```

`xlated NN B` is the BPF bytecode size; `jited NN B` is the same logic as native
machine code. The BPF link is refcounted against the loader process, so even
`SIGKILL` detaches it — the kernel does that, not the deferred `Close()`.

### The verifier lab

```bash
sudo ./scripts/verifier-lab.sh

# just the verdicts
sudo ./scripts/verifier-lab.sh 2>&1 | grep -E "══|invalid|offset is outside|processed"
```

Line numbers are derived from the source at runtime, so the lab does not rot
when the program changes.

`bpf/testdata/` additionally holds two programs that fail at **different
layers** — `xdp_no_bounds_check.c` (verifier: range) and `xdp_wrong_section.c`
(loader: `SEC("tc")` infers `SchedCLS`, so it never reaches the verifier).

---

## Roadmap

- **Stage 2** ✅ attach and detach cleanly
- **Stage 3** ✅ per-protocol counters in a `BPF_MAP_TYPE_PERCPU_ARRAY`
- **Stage 4** ✅ Prometheus exporter
- **Stage 5** ✅ VLAN and IPv6 parsing

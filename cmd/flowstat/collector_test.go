package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeSource stands in for the BPF map so the collector can be exercised
// without a kernel, root, or an attached program.
type fakeSource struct {
	vals [slotMax]uint64
	err  error
}

func (f fakeSource) counters() ([slotMax]uint64, error) { return f.vals, f.err }

const header = `# HELP xdp_flowstat_packets_total Ingress packets observed by the XDP program, by address family and IP protocol.
# TYPE xdp_flowstat_packets_total counter
`

// expose renders the expected exposition. Prometheus sorts by label values,
// so the order is (family, protocol) ascending: ipv4, ipv6, non_ip.
func expose(v4tcp, v4udp, v4icmp, v4other, v6tcp, v6udp, v6icmp, v6other, nonip string) string {
	return header +
		`xdp_flowstat_packets_total{family="ipv4",protocol="icmp"} ` + v4icmp + "\n" +
		`xdp_flowstat_packets_total{family="ipv4",protocol="other"} ` + v4other + "\n" +
		`xdp_flowstat_packets_total{family="ipv4",protocol="tcp"} ` + v4tcp + "\n" +
		`xdp_flowstat_packets_total{family="ipv4",protocol="udp"} ` + v4udp + "\n" +
		`xdp_flowstat_packets_total{family="ipv6",protocol="icmp"} ` + v6icmp + "\n" +
		`xdp_flowstat_packets_total{family="ipv6",protocol="other"} ` + v6other + "\n" +
		`xdp_flowstat_packets_total{family="ipv6",protocol="tcp"} ` + v6tcp + "\n" +
		`xdp_flowstat_packets_total{family="ipv6",protocol="udp"} ` + v6udp + "\n" +
		`xdp_flowstat_packets_total{family="non_ip",protocol="other"} ` + nonip + "\n"
}

func TestCollectorExposition(t *testing.T) {
	tests := []struct {
		name string
		src  fakeSource
		want string
	}{
		{
			name: "all zero",
			src:  fakeSource{},
			want: expose("0", "0", "0", "0", "0", "0", "0", "0", "0"),
		},
		{
			name: "ipv4 and non-ip only, as on a quiet veth",
			src: fakeSource{vals: [slotMax]uint64{
				slotV4ICMP: 5, slotNonIP: 2,
			}},
			want: expose("0", "0", "5", "0", "0", "0", "0", "0", "2"),
		},
		{
			name: "both families populated",
			src: fakeSource{vals: [slotMax]uint64{
				slotV4TCP: 2, slotV4UDP: 7, slotV4ICMP: 15, slotV4Other: 1,
				slotV6TCP: 3, slotV6UDP: 4, slotV6ICMP: 9, slotV6Other: 6,
				slotNonIP: 11,
			}},
			want: expose("2", "7", "15", "1", "3", "4", "9", "6", "11"),
		},
		{
			// Per-CPU sums can exceed 2^53, where float64 stops being exact.
			// Prometheus values are float64, so this is a real ceiling.
			name: "large values survive the float64 conversion",
			src:  fakeSource{vals: [slotMax]uint64{slotV6TCP: 1 << 52}},
			want: expose("0", "0", "0", "0", "4.503599627370496e+15", "0", "0", "0", "0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCollector(tt.src)
			if err := testutil.CollectAndCompare(c, strings.NewReader(tt.want)); err != nil {
				t.Errorf("unexpected exposition:\n%v", err)
			}
		})
	}
}

// A failed map read must surface as a scrape error, not as silent zeroes.
func TestCollectorReportsReadError(t *testing.T) {
	c := newCollector(fakeSource{err: errors.New("boom")})

	err := testutil.CollectAndCompare(c, strings.NewReader(header))
	if err == nil {
		t.Fatal("expected an error from the scrape, got nil")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error should mention the underlying cause, got: %v", err)
	}
}

// Guards against slotLabels drifting out of sync with the SLOT_* defines in
// bpf/xdp_flowstat.c if a slot is added.
func TestSlotLabelsComplete(t *testing.T) {
	seen := map[string]bool{}
	for i, l := range slotLabels {
		if l.family == "" || l.protocol == "" {
			t.Errorf("slot %d has an empty label: %+v", i, l)
		}
		key := l.family + "/" + l.protocol
		if seen[key] {
			t.Errorf("slot %d duplicates label pair %s", i, key)
		}
		seen[key] = true
	}
}

// TestSlotCountMatchesBPFMap closes the one place C and Go can silently
// disagree: SLOT_MAX in bpf/xdp_flowstat.c and slotMax here.
//
// loadFlowstat() parses the ELF that bpf2go embedded at build time. It makes no
// bpf() syscall, so this needs no kernel, no root and no attached program --
// but the map definition it reads is the real compiled one. Add a slot to the C
// without adding it here (or vice versa) and this fails.
func TestSlotCountMatchesBPFMap(t *testing.T) {
	spec, err := loadFlowstat()
	if err != nil {
		t.Fatalf("load embedded collection spec: %v", err)
	}

	m, ok := spec.Maps["proto_count"]
	if !ok {
		t.Fatal("compiled object has no map named proto_count")
	}

	if m.MaxEntries != slotMax {
		t.Errorf("SLOT_MAX in bpf/xdp_flowstat.c is %d, slotMax in Go is %d -- they must match",
			m.MaxEntries, slotMax)
	}
	if got := len(slotLabels); got != int(m.MaxEntries) {
		t.Errorf("slotLabels has %d entries, BPF map has %d", got, m.MaxEntries)
	}

	// The Go side reads each value as a uint64 out of a per-CPU slice.
	if m.ValueSize != 8 {
		t.Errorf("map value is %d bytes, Go reads uint64 (8)", m.ValueSize)
	}
	if m.KeySize != 4 {
		t.Errorf("map key is %d bytes, Go writes uint32 (4)", m.KeySize)
	}
}

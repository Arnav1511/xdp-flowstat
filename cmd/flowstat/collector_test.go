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

const header = `# HELP xdp_flowstat_packets_total Ingress packets observed by the XDP program, by IP protocol.
# TYPE xdp_flowstat_packets_total counter
`

func TestCollectorExposition(t *testing.T) {
	tests := []struct {
		name string
		src  fakeSource
		want string
	}{
		{
			name: "all zero",
			src:  fakeSource{},
			want: header + `xdp_flowstat_packets_total{protocol="icmp"} 0
xdp_flowstat_packets_total{protocol="other"} 0
xdp_flowstat_packets_total{protocol="tcp"} 0
xdp_flowstat_packets_total{protocol="udp"} 0
`,
		},
		{
			name: "mixed",
			src:  fakeSource{vals: [slotMax]uint64{slotTCP: 2, slotUDP: 7, slotICMP: 15, slotOther: 9}},
			want: header + `xdp_flowstat_packets_total{protocol="icmp"} 15
xdp_flowstat_packets_total{protocol="other"} 9
xdp_flowstat_packets_total{protocol="tcp"} 2
xdp_flowstat_packets_total{protocol="udp"} 7
`,
		},
		{
			// Per-CPU sums can exceed 2^53, where float64 stops being exact.
			// Prometheus values are float64, so this is a real ceiling.
			name: "large values survive the float64 conversion",
			src:  fakeSource{vals: [slotMax]uint64{slotTCP: 1 << 52}},
			want: header + `xdp_flowstat_packets_total{protocol="icmp"} 0
xdp_flowstat_packets_total{protocol="other"} 0
xdp_flowstat_packets_total{protocol="tcp"} 4.503599627370496e+15
xdp_flowstat_packets_total{protocol="udp"} 0
`,
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

// Guards against slotNames drifting out of sync with the SLOT_* defines in
// bpf/xdp_flowstat.c if a slot is added.
func TestSlotNamesComplete(t *testing.T) {
	for i, name := range slotNames {
		if name == "" {
			t.Errorf("slot %d has no label name", i)
		}
	}
}

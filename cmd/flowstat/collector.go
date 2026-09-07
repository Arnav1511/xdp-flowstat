package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

// slotLabels maps a slot index to its Prometheus label values. Index order
// must match the SLOT_* defines in bpf/xdp_flowstat.c.
//
// Cardinality is fixed at 9 series. That is deliberate: a per-source-address
// variant would need an LRU hash and a top-N, not a label per address.
var slotLabels = [slotMax]struct{ family, protocol string }{
	slotV4TCP:   {"ipv4", "tcp"},
	slotV4UDP:   {"ipv4", "udp"},
	slotV4ICMP:  {"ipv4", "icmp"},
	slotV4Other: {"ipv4", "other"},
	slotV6TCP:   {"ipv6", "tcp"},
	slotV6UDP:   {"ipv6", "udp"},
	slotV6ICMP:  {"ipv6", "icmp"},
	slotV6Other: {"ipv6", "other"},
	slotNonIP:   {"non_ip", "other"},
}

// counterSource is the collector's view of the BPF map. An interface rather
// than *ebpf.Map so the collector can be tested without a kernel.
type counterSource interface {
	counters() ([slotMax]uint64, error)
}

// mapSource reads the real per-CPU array.
type mapSource struct{ m *ebpf.Map }

func (s mapSource) counters() ([slotMax]uint64, error) { return readCounters(s.m) }

// collector implements prometheus.Collector.
//
// The map is read inside Collect, i.e. on scrape, rather than copied into a
// gauge by a background ticker. Two reasons: no scrape ever sees data staler
// than the scrape itself, and no work happens when nobody is asking.
type collector struct {
	src  counterSource
	desc *prometheus.Desc
}

func newCollector(src counterSource) *collector {
	return &collector{
		src: src,
		desc: prometheus.NewDesc(
			"xdp_flowstat_packets_total",
			"Ingress packets observed by the XDP program, by address family and IP protocol.",
			[]string{"family", "protocol"},
			nil,
		),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	totals, err := c.src.counters()
	if err != nil {
		// Surfaces as an error on the scrape rather than silently reporting
		// stale or zero values.
		ch <- prometheus.NewInvalidMetric(c.desc, fmt.Errorf("read bpf map: %w", err))
		return
	}

	for slot, l := range slotLabels {
		// CounterValue, not GaugeValue: these only ever increase, and
		// Prometheus needs to know that to handle resets in rate() correctly.
		ch <- prometheus.MustNewConstMetric(
			c.desc, prometheus.CounterValue, float64(totals[slot]), l.family, l.protocol,
		)
	}
}

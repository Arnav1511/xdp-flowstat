package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

// slotNames maps a slot index to its Prometheus label value. Index order must
// match the SLOT_* defines in bpf/xdp_flowstat.c.
var slotNames = [slotMax]string{
	slotTCP:   "tcp",
	slotUDP:   "udp",
	slotICMP:  "icmp",
	slotOther: "other",
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
			"Ingress packets observed by the XDP program, by IP protocol.",
			[]string{"protocol"},
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

	for slot, name := range slotNames {
		// CounterValue, not GaugeValue: these only ever increase, and
		// Prometheus needs to know that to handle resets in rate() correctly.
		ch <- prometheus.MustNewConstMetric(
			c.desc, prometheus.CounterValue, float64(totals[slot]), name,
		)
	}
}

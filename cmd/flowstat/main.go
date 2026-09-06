// Command flowstat loads an XDP program, attaches it to an interface, counts
// ingress packets by IP protocol, and detaches cleanly on SIGINT/SIGTERM.
//
// Stage 4: per-protocol counters in a per-CPU array, exported as Prometheus
// metrics on /metrics and also printed every 2s.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// bpf2go compiles bpf/xdp_flowstat.c with clang and generates Go bindings that
// embed the resulting ELF via go:embed. That is why the built binary needs
// neither clang nor the .o file at runtime -- the bytecode ships inside it.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations" flowstat ../../bpf/xdp_flowstat.c -- -I../../bpf

// defaultRouteIface returns the interface carrying the default route, or "".
// /proc/net/route stores destinations as big-endian hex; 00000000 is 0.0.0.0.
func defaultRouteIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Scan() // discard header row
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

func main() {
	iface := flag.String("iface", "", "interface to attach XDP to (required)")
	mode := flag.String("mode", "native", "XDP attach mode: native | generic")
	force := flag.Bool("force", false, "allow attaching to the default-route interface (DANGEROUS)")
	addr := flag.String("metrics-addr", ":2112", "listen address for the Prometheus /metrics endpoint")
	flag.Parse()

	if *iface == "" {
		log.Fatal("-iface is required (try: veth-fs0)")
	}

	// Guard rail: refuse the interface carrying the default route unless
	// explicitly overridden. A faulty XDP program there can drop the traffic
	// carrying your own SSH session.
	if def := defaultRouteIface(); def != "" && def == *iface && !*force {
		log.Fatalf("refusing to attach to %q: it carries the default route. "+
			"Attaching a broken XDP program here can lock you out of this machine. "+
			"Pass -force only if you are certain.", *iface)
	}

	nic, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatalf("interface %q: %v", *iface, err)
	}

	var flags link.XDPAttachFlags
	switch *mode {
	case "native":
		flags = link.XDPDriverMode // runs inside the driver, before sk_buff
	case "generic":
		flags = link.XDPGenericMode // runs after sk_buff alloc; testing only
	default:
		log.Fatalf("-mode must be native or generic, got %q", *mode)
	}

	// Pre-5.11 kernels charged BPF memory against RLIMIT_MEMLOCK. On modern
	// kernels this is a harmless no-op, but it keeps the loader portable.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock rlimit: %v", err)
	}

	// Load: parse the embedded ELF, create maps, apply CO-RE relocations
	// against this kernel's BTF, then bpf(BPF_PROG_LOAD) -> the verifier.
	var objs flowstatObjects
	if err := loadFlowstatObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// %+v prints the full verifier log, not just the last line.
			log.Fatalf("verifier rejected the program:\n%+v", ve)
		}
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFlowstat,
		Interface: nic.Index,
		Flags:     flags,
	})
	if err != nil {
		log.Fatalf("attach to %s in %s mode: %v", *iface, *mode, err)
	}
	defer l.Close() // detaches; also happens if the process dies

	log.Printf("attached xdp_flowstat to %s (ifindex %d) in %s mode", *iface, nic.Index, *mode)
	log.Printf("inspect with: sudo bpftool prog show   |   ip link show %s", *iface)
	log.Printf("Ctrl-C to detach")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := startMetricsServer(*addr, objs.ProtoCount)
	defer func() {
		// Give in-flight scrapes a moment to finish rather than cutting them off.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("metrics server shutdown: %v", err)
		}
	}()
	log.Printf("serving metrics on http://localhost%s/metrics", *addr)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("signal received, detaching from %s", *iface)
			return // runs the deferred l.Close() and objs.Close()

		case <-ticker.C:
			totals, err := readCounters(objs.ProtoCount)
			if err != nil {
				log.Printf("read counters: %v", err)
				continue
			}
			fmt.Printf("tcp=%-8d udp=%-8d icmp=%-8d other=%-8d\n",
				totals[slotTCP], totals[slotUDP], totals[slotICMP], totals[slotOther])
		}
	}
}

// Slot indices, matching the #defines in bpf/xdp_flowstat.c.
const (
	slotTCP = iota
	slotUDP
	slotICMP
	slotOther
	slotMax
)

// readCounters reads every slot of the per-CPU array and sums each one across
// all CPUs.
//
// For a BPF_MAP_TYPE_PERCPU_ARRAY the kernel returns one value per possible
// CPU, so the destination must be a slice: cilium/ebpf sizes it from
// ebpf.MustPossibleCPU(). Summing here is why the kernel side needs no atomic
// -- each CPU writes only its own copy.
func readCounters(m *ebpf.Map) ([slotMax]uint64, error) {
	var totals [slotMax]uint64

	for slot := uint32(0); slot < slotMax; slot++ {
		var perCPU []uint64
		if err := m.Lookup(&slot, &perCPU); err != nil {
			return totals, fmt.Errorf("lookup slot %d: %w", slot, err)
		}
		for _, v := range perCPU {
			totals[slot] += v
		}
	}

	return totals, nil
}

// startMetricsServer registers the collector on its own registry and serves
// /metrics in the background.
//
// A private registry rather than prometheus.DefaultRegisterer: nothing is
// exported unless this function asks for it, so a dependency cannot silently
// add metrics to this binary's output.
func startMetricsServer(addr string, m *ebpf.Map) *http.Server {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		newCollector(mapSource{m: m}),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
	}))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server: %v", err)
		}
	}()

	return srv
}

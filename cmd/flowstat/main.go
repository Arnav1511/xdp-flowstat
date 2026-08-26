// Command flowstat loads a minimal XDP program, attaches it to an interface,
// and detaches cleanly on SIGINT/SIGTERM.
//
// Stage 2: the program passes every packet. No maps, no counters, no metrics.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
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
		Program:   objs.XdpPassAll,
		Interface: nic.Index,
		Flags:     flags,
	})
	if err != nil {
		log.Fatalf("attach to %s in %s mode: %v", *iface, *mode, err)
	}
	defer l.Close() // detaches; also happens if the process dies

	log.Printf("attached xdp_pass_all to %s (ifindex %d) in %s mode", *iface, nic.Index, *mode)
	log.Printf("inspect with: sudo bpftool prog show   |   ip link show %s", *iface)
	log.Printf("Ctrl-C to detach")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Printf("signal received, detaching from %s", *iface)
}

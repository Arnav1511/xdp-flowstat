.PHONY: vmlinux generate build test clean up down lab lab-summary

BPFTOOL ?= bpftool

# bpf2go needs llvm-strip to remove DWARF from the compiled object. Distros
# often ship it only as llvm-strip-NN with no unsuffixed symlink, so find the
# highest version available rather than requiring update-alternatives.
BPF2GO_STRIP ?= $(shell command -v llvm-strip 2>/dev/null || ls -1 /usr/bin/llvm-strip-* 2>/dev/null | sort -V | tail -1)
export BPF2GO_STRIP

# Regenerate bpf/vmlinux.h from the running kernel's BTF.
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	@echo "vmlinux.h: $$(wc -l < bpf/vmlinux.h) lines"

# Compile the eBPF C with clang and generate the Go bindings.
generate:
	go generate ./...

build: generate
	go build -o bin/flowstat ./cmd/flowstat

test:
	go test ./...

lab:
	sudo ./scripts/verifier-lab.sh

lab-summary:
	sudo ./scripts/lab-summary.sh

up:
	sudo ./scripts/veth-up.sh

down:
	sudo ./scripts/veth-down.sh

clean:
	rm -rf bin cmd/flowstat/flowstat_bpfel.go cmd/flowstat/flowstat_bpfel.o

# Fallback: compile the eBPF object in a container when the host has no clang.
# Produces identical output to `make generate`.
IMG ?= xdp-flowstat-build
generate-docker:
	docker build -q -f Dockerfile.build -t $(IMG) .
	docker run --rm -u "$$(id -u):$$(id -g)" \
	  -v "$(CURDIR)":/src -v "$$(go env GOMODCACHE)":/go/pkg/mod \
	  -e GOCACHE=/tmp/gocache -e GOFLAGS=-mod=mod \
	  -w /src $(IMG) sh -c 'go generate ./... && go build -o bin/flowstat ./cmd/flowstat'

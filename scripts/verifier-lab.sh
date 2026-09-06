#!/usr/bin/env bash
# Delete each safety check from bpf/xdp_flowstat.c in turn, compile, and try to
# load. Every variant compiles; every variant is rejected by the verifier.
#
# Needs root only for the load step (kernel.unprivileged_bpf_disabled=2).
#   sudo ./scripts/verifier-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."

SRC=bpf/xdp_flowstat.c
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# name:lines-to-delete (sed ranges)
run() {
	local name="$1" del="$2"
	printf '\n══════ %s (deleting lines %s) ══════\n' "$name" "$del"
	sed "${del}d" "$SRC" > "$TMP/v.c"
	if ! clang -target bpf -O2 -g -Wall -Wno-missing-declarations \
	          -I bpf -c "$TMP/v.c" -o "$TMP/v.o" 2>"$TMP/cc.log"; then
		echo "UNEXPECTED: failed to COMPILE"; cat "$TMP/cc.log"; return
	fi
	echo "compiled OK -- so this is not a compile-time error"
	bpftool prog load "$TMP/v.o" /sys/fs/bpf/vlab 2>&1 | grep -vE "^libbpf: (map|prog) '" | head -20
	rm -f /sys/fs/bpf/vlab 2>/dev/null
}

run "BOUNDS CHECK 1 (ethernet header)" "61,62"
run "BOUNDS CHECK 2 (IPv4 header)"     "75,76"
run "NULL CHECK (map lookup)"          "44,45"

printf '\n══════ baseline: unmodified program ══════\n'
clang -target bpf -O2 -g -Wall -Wno-missing-declarations -I bpf -c "$SRC" -o "$TMP/ok.o"
bpftool prog load "$TMP/ok.o" /sys/fs/bpf/vlab 2>&1 | head -5 && echo "loaded OK"
rm -f /sys/fs/bpf/vlab 2>/dev/null

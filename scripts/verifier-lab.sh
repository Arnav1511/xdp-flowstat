#!/usr/bin/env bash
# Delete each safety check from bpf/xdp_flowstat.c in turn, compile, and try to
# load. Every variant compiles; every variant is rejected by the verifier.
#
# Line numbers are derived from the source at runtime rather than hardcoded,
# so this does not rot when the program changes.
#
# Needs root only for the load step (kernel.unprivileged_bpf_disabled=2).
#   sudo ./scripts/verifier-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.."

SRC=bpf/xdp_flowstat.c
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Find the line holding a check, and return "N,N+1" -- the check plus the
# return statement beneath it.
lines_for() {
	local n
	n=$(grep -n -- "$1" "$SRC" | head -1 | cut -d: -f1)
	if [ -z "$n" ]; then
		echo "PATTERN NOT FOUND: $1" >&2
		return 1
	fi
	echo "${n},$((n + 1))"
}

run() {
	local name="$1" pattern="$2" del
	del=$(lines_for "$pattern") || return
	printf '\n══════ %s (deleting lines %s) ══════\n' "$name" "$del"
	sed "${del}d" "$SRC" > "$TMP/v.c"
	if ! clang -target bpf -O2 -g -Wall -Wno-missing-declarations \
	          -I bpf -c "$TMP/v.c" -o "$TMP/v.o" 2>"$TMP/cc.log"; then
		echo "UNEXPECTED: failed to COMPILE"; cat "$TMP/cc.log"; return
	fi
	echo "compiled OK -- so this is not a compile-time error"
	bpftool prog load "$TMP/v.o" /sys/fs/bpf/vlab 2>&1 \
		| grep -vE "^libbpf: (map|prog) '" > "$TMP/log"

	# Show where the verifier started reasoning...
	head -20 "$TMP/log"
	# ...then show the verdict if it fell outside those first 20 lines.
	# Deeper checks push the rejection past any fixed head limit; shallow
	# ones do not, and reprinting it there would just duplicate.
	local errline
	errline=$(grep -nE "invalid access|invalid mem access" "$TMP/log" | head -1 | cut -d: -f1)
	if [ -n "$errline" ] && [ "$errline" -gt 20 ]; then
		echo "   [...]"
		grep -E "invalid access|invalid mem access|offset is outside|^processed" "$TMP/log" \
			| sed 's/^/   /'
	fi
	rm -f /sys/fs/bpf/vlab 2>/dev/null
}

run "NULL CHECK (map lookup)"        'if (!val)'
run "BOUNDS 1: ethernet header"      '(eth + 1) > data_end'
run "BOUNDS 2: VLAN header"          '(vh + 1) > data_end'
run "BOUNDS 3: IPv4 header"          '(ip + 1) > data_end'
run "BOUNDS 4: IPv6 header"          '(ip6 + 1) > data_end'
run "BOUNDS 5: IPv6 option header"   '(opt + 1) > data_end'
run "BOUNDS 6: IPv6 fragment header" '(fh + 1) > data_end'

printf '\n══════ baseline: unmodified program ══════\n'
clang -target bpf -O2 -g -Wall -Wno-missing-declarations -I bpf -c "$SRC" -o "$TMP/ok.o"
# -d prints the verifier log even on success, so the complexity cost is visible.
bpftool -d prog load "$TMP/ok.o" /sys/fs/bpf/vlab 2>&1 | grep -E "^processed" \
	|| echo "(loaded, but no 'processed' line -- try without -d)"
rm -f /sys/fs/bpf/vlab 2>/dev/null
echo "loaded OK"

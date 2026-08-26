#!/usr/bin/env bash
# Tear down the veth test harness. Safe to run repeatedly.
#
# Deleting one end of a veth pair deletes both ends automatically, and
# deleting a netns destroys any interface still inside it. So this is
# belt-and-braces on purpose.
set -uo pipefail

NS=flowstat
HOST_IF=veth-fs0

# Detach XDP first so we never leave an orphaned program pinned to a link
# that is about to disappear.
if ip link show "$HOST_IF" &>/dev/null; then
	ip link set dev "$HOST_IF" xdp off 2>/dev/null || true
	ip link set dev "$HOST_IF" xdpgeneric off 2>/dev/null || true
	ip link del "$HOST_IF" 2>/dev/null || true
	echo "removed link $HOST_IF"
fi

if ip netns list | grep -qw "$NS"; then
	ip netns del "$NS"
	echo "removed netns $NS"
fi

echo "OK: teardown complete"

#!/usr/bin/env bash
# Create an isolated veth pair for XDP testing.
#
#   [ netns: flowstat ]                    [ host netns ]
#     veth-fs1  10.200.0.2/24  <------->  veth-fs0  10.200.0.1/24
#                                            ^
#                                            +-- XDP attaches HERE
#
# Traffic originating in the namespace arrives on veth-fs0's INGRESS,
# which is the only direction XDP ever sees.
#
# Nothing here touches wlo1, docker0, br-*, or any container veth.
set -euo pipefail

NS=flowstat
HOST_IF=veth-fs0
PEER_IF=veth-fs1
HOST_IP=10.200.0.1/24
PEER_IP=10.200.0.2/24

# --- refuse to run if it would clobber something ---------------------------
for name in "$HOST_IF" "$PEER_IF"; do
	if ip link show "$name" &>/dev/null; then
		echo "ERROR: interface $name already exists. Run veth-down.sh first." >&2
		exit 1
	fi
done
if ip netns list | grep -qw "$NS"; then
	echo "ERROR: netns $NS already exists. Run veth-down.sh first." >&2
	exit 1
fi

# --- build the harness -----------------------------------------------------
ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$PEER_IF"
ip link set "$PEER_IF" netns "$NS"

ip addr add "$HOST_IP" dev "$HOST_IF"
ip link set "$HOST_IF" up

ip netns exec "$NS" ip addr add "$PEER_IP" dev "$PEER_IF"
ip netns exec "$NS" ip link set "$PEER_IF" up
ip netns exec "$NS" ip link set lo up

echo "OK: netns=$NS  host=$HOST_IF(${HOST_IP})  peer=$PEER_IF(${PEER_IP})"
echo
echo "Generate traffic with:"
echo "  sudo ip netns exec $NS ping -c 5 ${HOST_IP%%/*}"

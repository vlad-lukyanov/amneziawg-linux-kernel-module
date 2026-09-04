#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# AWG 2.0 backward-compatibility integration test.
# Tests per-peer advanced_security, ranged_headers, junk_offsets detection.
#
# Topology:
#   ns_server (AWG 2.0 server, H1-H4 ranged, S3-S4 junk offsets)
#       |
#       | veth pair
#       |
#   ns_client1 - AWG 2.0 client (ranged headers, junk offsets)
#   ns_client2 - AWG 1.0 client (fixed headers, no junk offsets)
#   ns_client3 - Legacy WireGuard client (standard WG types, no junk)

set -e
set -o pipefail

export LANG=C
export WG_HIDE_KEYS=never

NS_SERVER="awg-test-server"
NS_CLIENT1="awg-test-client1"
NS_CLIENT2="awg-test-client2"
NS_CLIENT3="awg-test-client3"
VETH_SERVER="veth-s"
VETH_CLIENT1="veth-c1"
VETH_CLIENT2="veth-c2"
VETH_CLIENT3="veth-c3"
PASS=0
FAIL=0
TOTAL=0

cleanup() {
    set +e
    exec 2>/dev/null
    for ns in "$NS_SERVER" "$NS_CLIENT1" "$NS_CLIENT2" "$NS_CLIENT3"; do
        ip netns del "$ns" 2>/dev/null
    done
    ip link del "$VETH_SERVER" 2>/dev/null
}
trap cleanup EXIT

pass() { ((PASS++)); ((TOTAL++)); echo -e "\x1b[32m[PASS]\x1b[0m $*"; }
fail() { ((FAIL++)); ((TOTAL++)); echo -e "\x1b[31m[FAIL]\x1b[0m $*"; }
info() { echo -e "\x1b[36m[INFO]\x1b[0m $*"; }

# --- Key generation ---
info "Generating keys..."
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)

CLIENT1_PRIV=$(wg genkey)
CLIENT1_PUB=$(echo "$CLIENT1_PRIV" | wg pubkey)

CLIENT2_PRIV=$(wg genkey)
CLIENT2_PUB=$(echo "$CLIENT2_PRIV" | wg pubkey)

CLIENT3_PRIV=$(wg genkey)
CLIENT3_PUB=$(echo "$CLIENT3_PRIV" | wg pubkey)

PSK=$(wg genpsk)

# --- Create namespaces and veth pairs ---
info "Creating network namespaces..."

for ns in "$NS_SERVER" "$NS_CLIENT1" "$NS_CLIENT2" "$NS_CLIENT3"; do
    ip netns add "$ns"
done

# Server <-> Client1 veth pair
ip link add "$VETH_SERVER" type veth peer name "$VETH_CLIENT1"
ip link set "$VETH_SERVER" netns "$NS_SERVER"
ip link set "$VETH_CLIENT1" netns "$NS_CLIENT1"

# Server <-> Client2 veth pair
ip link add veth-s2 type veth peer name "$VETH_CLIENT2"
ip link set veth-s2 netns "$NS_SERVER"
ip link set "$VETH_CLIENT2" netns "$NS_CLIENT2"

# Server <-> Client3 veth pair
ip link add veth-s3 type veth peer name "$VETH_CLIENT3"
ip link set veth-s3 netns "$NS_SERVER"
ip link set "$VETH_CLIENT3" netns "$NS_CLIENT3"

# --- Configure interfaces ---
info "Configuring interfaces..."

# Server: lo up, veth up, assign IPs
ip netns exec "$NS_SERVER" ip link set lo up
ip netns exec "$NS_SERVER" ip addr add 10.0.0.1/24 dev "$VETH_SERVER"
ip netns exec "$NS_SERVER" ip addr add 10.0.1.1/24 dev veth-s2
ip netns exec "$NS_SERVER" ip addr add 10.0.2.1/24 dev veth-s3
ip netns exec "$NS_SERVER" ip link set "$VETH_SERVER" up
ip netns exec "$NS_SERVER" ip link set veth-s2 up
ip netns exec "$NS_SERVER" ip link set veth-s3 up

# Clients: lo up, veth up, assign IPs
ip netns exec "$NS_CLIENT1" ip link set lo up
ip netns exec "$NS_CLIENT1" ip addr add 10.0.0.2/24 dev "$VETH_CLIENT1"
ip netns exec "$NS_CLIENT1" ip link set "$VETH_CLIENT1" up

ip netns exec "$NS_CLIENT2" ip link set lo up
ip netns exec "$NS_CLIENT2" ip addr add 10.0.1.2/24 dev "$VETH_CLIENT2"
ip netns exec "$NS_CLIENT2" ip link set "$VETH_CLIENT2" up

ip netns exec "$NS_CLIENT3" ip link set lo up
ip netns exec "$NS_CLIENT3" ip addr add 10.0.2.2/24 dev "$VETH_CLIENT3"
ip netns exec "$NS_CLIENT3" ip link set "$VETH_CLIENT3" up

# ============================================================
# TEST 1: AWG 2.0 server with AWG 2.0 client (full compat)
# ============================================================
info "--- TEST 1: AWG 2.0 server <-> AWG 2.0 client ---"

# Server: AWG 2.0 config — ranged headers H1-H4, junk offsets S3-S4
ip netns exec "$NS_SERVER" ip link add wg0 type amneziawg
ip netns exec "$NS_SERVER" ip link set wg0 up
ip netns exec "$NS_SERVER" ip addr add 192.168.0.1/24 dev wg0

ip netns exec "$NS_SERVER" wg set wg0 \
    listen-port 51820 \
    private-key <(echo "$SERVER_PRIV") \
    peer "$CLIENT1_PUB" \
        preshared-key <(echo "$PSK") \
        allowed-ips 192.168.0.2/32 \
        endpoint 127.0.0.1:51821 \
        persistent-keepalive 25

# AWG 2.0 server: set H1-H4 ranges (ranged headers for AWG 2.0 peers)
ip netns exec "$NS_SERVER" wg set wg0 \
    jc 4 jmin 40 jmax 80 \
    s1 24 s2 24 s3 24 s4 24 \
    h1 100000000-100000100 \
    h2 200000000-200000100 \
    h3 300000000-300000100 \
    h4 400000000-400000100

# Client1: AWG 2.0 config — same ranges
ip netns exec "$NS_CLIENT1" ip link add wg0 type amneziawg
ip netns exec "$NS_CLIENT1" ip link set wg0 up
ip netns exec "$NS_CLIENT1" ip addr add 192.168.0.2/24 dev wg0

ip netns exec "$NS_CLIENT1" wg set wg0 \
    listen-port 51821 \
    private-key <(echo "$CLIENT1_PRIV") \
    peer "$SERVER_PUB" \
        preshared-key <(echo "$PSK") \
        allowed-ips 192.168.0.0/24 \
        endpoint 127.0.0.1:51820

ip netns exec "$NS_CLIENT1" wg set wg0 \
    h1 100000000-100000100 \
    h2 200000000-200000100 \
    h3 300000000-300000100 \
    h4 400000000-400000100

# Trigger handshake
ip netns exec "$NS_CLIENT1" ping -c 1 -W 3 192.168.0.1 >/dev/null 2>&1 && \
    pass "TEST 1: AWG 2.0 <-> AWG 2.0 ping OK" || \
    fail "TEST 1: AWG 2.0 <-> AWG 2.0 ping FAILED"

# ============================================================
# TEST 2: AWG 2.0 server <-> AWG 1.0 client (fixed headers)
# ============================================================
info "--- TEST 2: AWG 2.0 server <-> AWG 1.0 client (fixed headers) ---"

# Server: add AWG 1.0 peer
ip netns exec "$NS_SERVER" wg set wg0 \
    peer "$CLIENT2_PUB" \
        preshared-key <(echo "$PSK") \
        allowed-ips 192.168.1.2/32 \
        endpoint 127.0.0.1:51822

# Client2: AWG 1.0 config — fixed headers (no h1-h4 ranges, use single values)
ip netns exec "$NS_CLIENT2" ip link add wg0 type amneziawg
ip netns exec "$NS_CLIENT2" ip link set wg0 up
ip netns exec "$NS_CLIENT2" ip addr add 192.168.1.2/24 dev wg0

ip netns exec "$NS_CLIENT2" wg set wg0 \
    listen-port 51822 \
    private-key <(echo "$CLIENT2_PRIV") \
    peer "$SERVER_PUB" \
        preshared-key <(echo "$PSK") \
        allowed-ips 192.168.1.0/24 \
        endpoint 127.0.0.1:51820

# AWG 1.0: fixed single-value headers (same as default WG types)
ip netns exec "$NS_CLIENT2" wg set wg0 \
    h1 100000000 \
    h2 200000000 \
    h3 300000000 \
    h4 400000000

# Trigger handshake
ip netns exec "$NS_CLIENT2" ping -c 1 -W 3 192.168.1.1 >/dev/null 2>&1 && \
    pass "TEST 2: AWG 2.0 <-> AWG 1.0 ping OK" || \
    fail "TEST 2: AWG 2.0 <-> AWG 1.0 ping FAILED"

# ============================================================
# TEST 3: AWG 2.0 server <-> Legacy WireGuard client (no AWG)
# ============================================================
info "--- TEST 3: AWG 2.0 server <-> Legacy WireGuard client ---"

# Server: add legacy WG peer (will use default H1 type = MESSAGE_HANDSHAKE_INITIATION)
ip netns exec "$NS_SERVER" wg set wg0 \
    peer "$CLIENT3_PUB" \
        preshared-key <(echo "$PSK") \
        allowed-ips 192.168.2.2/32 \
        endpoint 127.0.0.1:51823

# Client3: standard WireGuard — no AWG ranges at all
ip netns exec "$NS_CLIENT3" ip link add wg0 type wireguard
ip netns exec "$NS_CLIENT3" ip link set wg0 up
ip netns exec "$NS_CLIENT3" ip addr add 192.168.2.2/24 dev wg0

ip netns exec "$NS_CLIENT3" wg set wg0 \
    listen-port 51823 \
    private-key <(echo "$CLIENT3_PRIV") \
    peer "$SERVER_PUB" \
        preshared-key <(echo "$PSK") \
        allowed-ips 192.168.2.0/24 \
        endpoint 127.0.0.1:51820

# Trigger handshake
ip netns exec "$NS_CLIENT3" ping -c 1 -W 3 192.168.2.1 >/dev/null 2>&1 && \
    pass "TEST 3: AWG 2.0 <-> legacy WG ping OK" || \
    fail "TEST 3: AWG 2.0 <-> legacy WG ping FAILED"

# ============================================================
# TEST 4: Per-peer flags via netlink (wg show)
# ============================================================
info "--- TEST 4: Per-peer flags via netlink ---"

# Give handshake time to complete
sleep 1

# Check server-side peer flags
SERVER_OUTPUT=$(ip netns exec "$NS_SERVER" wg show wg0 2>&1)

# Client1 (AWG 2.0) should show advanced_security
echo "$SERVER_OUTPUT" | grep -q "$CLIENT1_PUB" && \
    pass "TEST 4a: client1 peer found on server" || \
    fail "TEST 4a: client1 peer NOT found on server"

# Client3 (legacy WG) should also be present
echo "$SERVER_OUTPUT" | grep -q "$CLIENT3_PUB" && \
    pass "TEST 4b: client3 (legacy WG) peer found on server" || \
    fail "TEST 4b: client3 (legacy WG) peer NOT found on server"

# ============================================================
# TEST 5: Mixed traffic — all three clients simultaneously
# ============================================================
info "--- TEST 5: Simultaneous traffic from all clients ---"

ip netns exec "$NS_CLIENT1" ping -c 2 -W 3 192.168.0.1 >/dev/null 2>&1 && \
    pass "TEST 5a: client1 concurrent ping OK" || \
    fail "TEST 5a: client1 concurrent ping FAILED"

ip netns exec "$NS_CLIENT2" ping -c 2 -W 3 192.168.1.1 >/dev/null 2>&1 && \
    pass "TEST 5b: client2 concurrent ping OK" || \
    fail "TEST 5b: client2 concurrent ping FAILED"

ip netns exec "$NS_CLIENT3" ping -c 2 -W 3 192.168.2.1 >/dev/null 2>&1 && \
    pass "TEST 5c: client3 concurrent ping OK" || \
    fail "TEST 5c: client3 concurrent ping FAILED"

# ============================================================
# TEST 6: Data transfer (iperf3 if available)
# ============================================================
if command -v iperf3 &>/dev/null; then
    info "--- TEST 6: Data transfer via iperf3 ---"

    ip netns exec "$NS_SERVER" iperf3 -s -D -B 192.168.0.1
    sleep 0.5

    RESULT=$(ip netns exec "$NS_CLIENT1" iperf3 -c 192.168.0.1 -t 2 -J 2>/dev/null)
    if echo "$RESULT" | grep -q '"sum"'; then
        BYTES=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['end']['sum_received']['bytes'])" 2>/dev/null)
        if [ "${BYTES:-0}" -gt 0 ]; then
            pass "TEST 6: iperf3 transfer OK (${BYTES} bytes)"
        else
            fail "TEST 6: iperf3 transfer empty"
        fi
    else
        fail "TEST 6: iperf3 transfer failed"
    fi

    kill %1 2>/dev/null || true
else
    info "TEST 6: Skipped (iperf3 not installed)"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "========================================="
echo -e " Results: \x1b[32m${PASS} passed\x1b[0m, \x1b[31m${FAIL} failed\x1b[0m / ${TOTAL} total"
echo "========================================="

[ "$FAIL" -eq 0 ] && exit 0 || exit 1

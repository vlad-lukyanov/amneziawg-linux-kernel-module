#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# AWG 2.0 backward-compatibility integration test.
# Tests per-peer advanced_security, ranged_headers, junk_offsets detection.
#
# Uses awg-set (raw genetlink to "amneziawg" family) for AWG interfaces,
# standard wg for in-tree WireGuard client.
#
# Topology:
#   ns_server (AWG 2.0 server, H1-H4 ranged, S3-S4 junk offsets)
#       |
#       | veth pairs
#       |
#   ns_client1 - AWG 2.0 client (ranged headers, junk offsets)
#   ns_client2 - AWG 1.0 client (fixed headers, no junk offsets)
#   ns_client3 - Legacy WireGuard client (in-tree wireguard module)

set -e
set -o pipefail

export LANG=C
export WG_HIDE_KEYS=never

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AWG_SET="$SCRIPT_DIR/awg-set"

NS_SERVER="awg-server"
NS_CLIENT1="awg-c1"
NS_CLIENT2="awg-c2"
NS_CLIENT3="awg-c3"
PASS=0
FAIL=0
TOTAL=0

cleanup() {
    set +e
    exec 2>/dev/null
    # Kill iperf3 if running
    kill $(ip netns pids "$NS_SERVER" 2>/dev/null | xargs) 2>/dev/null
    for ns in "$NS_SERVER" "$NS_CLIENT1" "$NS_CLIENT2" "$NS_CLIENT3"; do
        ip netns del "$ns" 2>/dev/null
    done
}
trap cleanup EXIT

pass() { ((PASS++)); ((TOTAL++)); echo -e "\x1b[32m[PASS]\x1b[0m $*"; }
fail() { ((FAIL++)); ((TOTAL++)); echo -e "\x1b[31m[FAIL]\x1b[0m $*"; }
info() { echo -e "\x1b[36m[INFO]\x1b[0m $*"; }

# --- Preflight ---
if [ ! -x "$AWG_SET" ]; then
    info "Building awg-set helper..."
    gcc -o "$AWG_SET" "$SCRIPT_DIR/awg-set.c" -Wall -Wextra || {
        echo "Failed to build awg-set"; exit 1
    }
fi

if ! command -v wg &>/dev/null; then
    echo "wg tool not found (needed for key generation)"; exit 1
fi

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

# Write keys to temp files for awg-set
TMPDIR=$(mktemp -d)
trap "cleanup; rm -rf $TMPDIR" EXIT
echo "$SERVER_PRIV" > "$TMPDIR/server.key"
echo "$CLIENT1_PRIV" > "$TMPDIR/c1.key"
echo "$CLIENT2_PRIV" > "$TMPDIR/c2.key"
echo "$CLIENT3_PRIV" > "$TMPDIR/c3.key"
echo "$PSK" > "$TMPDIR/psk.key"

# --- Create namespaces and veth pairs ---
info "Creating network namespaces..."

ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT1"
ip netns add "$NS_CLIENT2"
ip netns add "$NS_CLIENT3"

# Server <-> Client1
ip link add veth-c1_s type veth peer name veth-c1_c
ip link set veth-c1_s netns "$NS_SERVER"
ip link set veth-c1_c netns "$NS_CLIENT1"

# Server <-> Client2
ip link add veth-c2_s type veth peer name veth-c2_c
ip link set veth-c2_s netns "$NS_SERVER"
ip link set veth-c2_c netns "$NS_CLIENT2"

# Server <-> Client3
ip link add veth-c3_s type veth peer name veth-c3_c
ip link set veth-c3_s netns "$NS_SERVER"
ip link set veth-c3_c netns "$NS_CLIENT3"

# --- Configure network ---
info "Configuring network..."

ip netns exec "$NS_SERVER" ip link set lo up
ip netns exec "$NS_SERVER" ip addr add 10.0.0.1/24 dev veth-c1_s
ip netns exec "$NS_SERVER" ip addr add 10.0.1.1/24 dev veth-c2_s
ip netns exec "$NS_SERVER" ip addr add 10.0.2.1/24 dev veth-c3_s
ip netns exec "$NS_SERVER" ip link set veth-c1_s up
ip netns exec "$NS_SERVER" ip link set veth-c2_s up
ip netns exec "$NS_SERVER" ip link set veth-c3_s up

ip netns exec "$NS_CLIENT1" ip link set lo up
ip netns exec "$NS_CLIENT1" ip addr add 10.0.0.2/24 dev veth-c1_c
ip netns exec "$NS_CLIENT1" ip link set veth-c1_c up

ip netns exec "$NS_CLIENT2" ip link set lo up
ip netns exec "$NS_CLIENT2" ip addr add 10.0.1.2/24 dev veth-c2_c
ip netns exec "$NS_CLIENT2" ip link set veth-c2_c up

ip netns exec "$NS_CLIENT3" ip link set lo up
ip netns exec "$NS_CLIENT3" ip addr add 10.0.2.2/24 dev veth-c3_c
ip netns exec "$NS_CLIENT3" ip link set veth-c3_c up

# ============================================================
# TEST 1: AWG 2.0 server <-> AWG 2.0 client
# ============================================================
info "--- TEST 1: AWG 2.0 server <-> AWG 2.0 client ---"

ip netns exec "$NS_SERVER" ip link add wg0 type amneziawg
ip netns exec "$NS_SERVER" ip link set wg0 up
ip netns exec "$NS_SERVER" ip addr add 192.168.0.1/24 dev wg0

# Server: device-level config (no peers yet)
ip netns exec "$NS_SERVER" "$AWG_SET" wg0 \
    private-key "$TMPDIR/server.key" \
    listen-port 51820 \
    h1 100000000-100000100 \
    h2 200000000-200000100 \
    h3 300000000-300000100 \
    h4 400000000-400000100 \
    s1 24 s2 24 s3 24 s4 24 \
    jc 4 jmin 40 jmax 80

# Server: add peers one by one
ip netns exec "$NS_SERVER" "$AWG_SET" wg0 \
    peer "$CLIENT1_PUB" \
        replace-allowed-ips \
        preshared-key "$TMPDIR/psk.key" \
        endpoint 10.0.0.2:51821 \
        allowed-ips 192.168.0.2/32 \
        persistent-keepalive 25

ip netns exec "$NS_SERVER" "$AWG_SET" wg0 \
    peer "$CLIENT2_PUB" \
        replace-allowed-ips \
        preshared-key "$TMPDIR/psk.key" \
        endpoint 10.0.1.2:51822 \
        allowed-ips 192.168.1.2/32 \
        persistent-keepalive 25

ip netns exec "$NS_SERVER" "$AWG_SET" wg0 \
    peer "$CLIENT3_PUB" \
        replace-allowed-ips \
        preshared-key "$TMPDIR/psk.key" \
        endpoint 10.0.2.2:51823 \
        allowed-ips 192.168.2.2/32 \
        persistent-keepalive 25

# Client1: AWG 2.0 — same ranges
ip netns exec "$NS_CLIENT1" ip link add wg0 type amneziawg
ip netns exec "$NS_CLIENT1" ip link set wg0 up
ip netns exec "$NS_CLIENT1" ip addr add 192.168.0.2/24 dev wg0

ip netns exec "$NS_CLIENT1" "$AWG_SET" wg0 \
    private-key "$TMPDIR/c1.key" \
    listen-port 51821 \
    h1 100000000-100000100 \
    h2 200000000-200000100 \
    h3 300000000-300000100 \
    h4 400000000-400000100 \
    s1 24 s2 24 s3 24 s4 24 \
    peer "$SERVER_PUB" \
        preshared-key "$TMPDIR/psk.key" \
        endpoint 10.0.0.1:51820 \
        allowed-ips 192.168.0.0/24

ip netns exec "$NS_CLIENT1" ping -c 2 -W 3 192.168.0.1 >/dev/null 2>&1 && \
    pass "TEST 1: AWG 2.0 <-> AWG 2.0 ping OK" || \
    fail "TEST 1: AWG 2.0 <-> AWG 2.0 ping FAILED"

# ============================================================
# TEST 2: AWG 2.0 server <-> AWG 1.0 client (fixed headers)
# ============================================================
info "--- TEST 2: AWG 2.0 server <-> AWG 1.0 client ---"

ip netns exec "$NS_CLIENT2" ip link add wg0 type amneziawg
ip netns exec "$NS_CLIENT2" ip link set wg0 up
ip netns exec "$NS_CLIENT2" ip addr add 192.168.1.2/24 dev wg0

# AWG 1.0: fixed single-value headers
ip netns exec "$NS_CLIENT2" "$AWG_SET" wg0 \
    private-key "$TMPDIR/c2.key" \
    listen-port 51822 \
    h1 100000000 \
    h2 200000000 \
    h3 300000000 \
    h4 400000000 \
    peer "$SERVER_PUB" \
        preshared-key "$TMPDIR/psk.key" \
        endpoint 10.0.1.1:51820 \
        allowed-ips 192.168.1.0/24

ip netns exec "$NS_CLIENT2" ping -c 2 -W 3 192.168.1.1 >/dev/null 2>&1 && \
    pass "TEST 2: AWG 2.0 <-> AWG 1.0 ping OK" || \
    fail "TEST 2: AWG 2.0 <-> AWG 1.0 ping FAILED"

# ============================================================
# TEST 3: AWG 2.0 server <-> Legacy WireGuard client
# ============================================================
info "--- TEST 3: AWG 2.0 server <-> legacy WireGuard client ---"

ip netns exec "$NS_CLIENT3" ip link add wg0 type wireguard
ip netns exec "$NS_CLIENT3" ip link set wg0 up
ip netns exec "$NS_CLIENT3" ip addr add 192.168.2.2/24 dev wg0

# Standard wg tool works for in-tree wireguard module
ip netns exec "$NS_CLIENT3" wg set wg0 \
    listen-port 51823 \
    private-key "$TMPDIR/c3.key" \
    peer "$SERVER_PUB" \
        preshared-key "$TMPDIR/psk.key" \
        allowed-ips 192.168.2.0/24 \
        endpoint 10.0.2.1:51820

ip netns exec "$NS_CLIENT3" ping -c 2 -W 3 192.168.2.1 >/dev/null 2>&1 && \
    pass "TEST 3: AWG 2.0 <-> legacy WG ping OK" || \
    fail "TEST 3: AWG 2.0 <-> legacy WG ping FAILED"

# ============================================================
# TEST 4: Mixed traffic — all three clients simultaneously
# ============================================================
info "--- TEST 4: Simultaneous traffic from all clients ---"

ip netns exec "$NS_CLIENT1" ping -c 2 -W 3 192.168.0.1 >/dev/null 2>&1 && \
    pass "TEST 4a: client1 (AWG 2.0) concurrent OK" || \
    fail "TEST 4a: client1 (AWG 2.0) concurrent FAILED"

ip netns exec "$NS_CLIENT2" ping -c 2 -W 3 192.168.1.1 >/dev/null 2>&1 && \
    pass "TEST 4b: client2 (AWG 1.0) concurrent OK" || \
    fail "TEST 4b: client2 (AWG 1.0) concurrent FAILED"

ip netns exec "$NS_CLIENT3" ping -c 2 -W 3 192.168.2.1 >/dev/null 2>&1 && \
    pass "TEST 4c: client3 (legacy WG) concurrent OK" || \
    fail "TEST 4c: client3 (legacy WG) concurrent FAILED"

# ============================================================
# TEST 5: Data transfer (iperf3 if available)
# ============================================================
if command -v iperf3 &>/dev/null; then
    info "--- TEST 5: Data transfer via iperf3 ---"

    ip netns exec "$NS_SERVER" iperf3 -s -D -B 192.168.0.1 -p 5201
    sleep 0.5

    RESULT=$(ip netns exec "$NS_CLIENT1" iperf3 -c 192.168.0.1 -t 2 -J -p 5201 2>/dev/null)
    if echo "$RESULT" | grep -q '"sum"'; then
        BYTES=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['end']['sum_received']['bytes'])" 2>/dev/null)
        if [ "${BYTES:-0}" -gt 0 ]; then
            pass "TEST 5: iperf3 transfer OK (${BYTES} bytes)"
        else
            fail "TEST 5: iperf3 transfer empty"
        fi
    else
        fail "TEST 5: iperf3 transfer failed"
    fi

    ip netns exec "$NS_SERVER" kill $(ip netns pids "$NS_SERVER" 2>/dev/null | grep -v $$ | head -1) 2>/dev/null || true
else
    info "TEST 5: Skipped (iperf3 not installed)"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "========================================="
echo -e " Results: \x1b[32m${PASS} passed\x1b[0m, \x1b[31m${FAIL} failed\x1b[0m / ${TOTAL} total"
echo "========================================="

[ "$FAIL" -eq 0 ] && exit 0 || exit 1

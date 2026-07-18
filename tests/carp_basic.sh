#!/bin/bash
# CARP integration test using ip netns
# Tests: module load, failover, carpd add/status/del
set -e

PASS_COUNT=0
FAIL_COUNT=0

log()  { echo "[TEST] $*"; }
pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

cleanup() {
    ip netns exec carp_ns1 ip link set veth1a down 2>/dev/null || true
    ip netns exec carp_ns2 ip link set veth2a down 2>/dev/null || true
    ip netns del carp_ns1 2>/dev/null || true
    ip netns del carp_ns2 2>/dev/null || true
    ip link del veth1 2>/dev/null || true
    ip link del veth2 2>/dev/null || true
}
trap cleanup EXIT

# --- Test 1: Module load ---
log "Loading CARP module..."
modprobe carp carp_allow=1 2>/dev/null || insmod ../kmod/carp.ko carp_allow=1
if lsmod | grep -q carp; then
    pass "CARP module loaded"
else
    fail "CARP module not loaded"
    echo "=== Results: PASS=$PASS_COUNT FAIL=$FAIL_COUNT ==="
    exit 1
fi

# --- Test 2: /proc entries ---
if [ -d /proc/net/carp ]; then
    pass "/proc/net/carp exists"
else
    fail "/proc/net/carp missing"
fi

if [ -f /proc/net/carp/stats ]; then
    pass "/proc/net/carp/stats exists"
else
    fail "/proc/net/carp/stats missing"
fi

if [ -f /proc/net/carp/interfaces ]; then
    pass "/proc/net/carp/interfaces exists"
else
    fail "/proc/net/carp/interfaces missing"
fi

# --- Test 3: Set up two network namespaces ---
log "Setting up network namespaces..."
ip netns add carp_ns1 2>/dev/null || true
ip netns add carp_ns2 2>/dev/null || true

# Create veth pairs
ip link add veth1 type veth peer name veth1b 2>/dev/null || true
ip link set veth1b netns carp_ns1
ip link set veth1 netns carp_ns2

ip link add veth2 type veth peer name veth2b 2>/dev/null || true
ip link set veth2b netns carp_ns2
ip link set veth2 netns carp_ns1

# Configure addresses
ip netns exec carp_ns1 ip link set lo up
ip netns exec carp_ns1 ip link set veth1b up
ip netns exec carp_ns1 ip addr add 192.168.1.1/24 dev veth1b
ip netns exec carp_ns1 ip link set veth2b up
ip netns exec carp_ns1 ip addr add 192.168.1.3/24 dev veth2b

ip netns exec carp_ns2 ip link set lo up
ip netns exec carp_ns2 ip link set veth1 up
ip netns exec carp_ns2 ip addr add 192.168.1.2/24 dev veth1
ip netns exec carp_ns2 ip link set veth2 up
ip netns exec carp_ns2 ip addr add 192.168.1.4/24 dev veth2

# --- Test 4: Add CARP VHID ---
log "Adding CARP VHID..."
if [ -x ../tools/carpd ]; then
    CARPD="../tools/carpd"
else
    CARPD="carpd"
fi

$CARPD add veth1 1 --advbase 1 --advskew 0 --addr 192.168.1.100 2>/dev/null && \
    pass "carpd add succeeded" || fail "carpd add failed"

# --- Test 5: Check status ---
log "Checking status..."
STATUS=$($CARPD status veth1 1 2>/dev/null)
if echo "$STATUS" | grep -q "vhid 1"; then
    pass "carpd status shows vhid 1"
    echo "  $STATUS"
else
    fail "carpd status missing vhid 1"
fi

# --- Test 6: Check /proc/net/carp/interfaces ---
log "Checking /proc/net/carp/interfaces..."
IFACES=$(cat /proc/net/carp/interfaces 2>/dev/null)
if echo "$IFACES" | grep -q "vhid 1"; then
    pass "/proc/net/carp/interfaces shows vhid 1"
else
    fail "/proc/net/carp/interfaces missing vhid 1"
fi

# --- Test 7: Check statistics ---
log "Checking statistics..."
STATS=$(cat /proc/net/carp/stats 2>/dev/null)
if echo "$STATS" | grep -q "IPv4 input"; then
    pass "/proc/net/carp/stats shows counters"
else
    fail "/proc/net/carp/stats missing counters"
fi

# --- Test 8: Add second VHID ---
log "Adding second VHID..."
$CARPD add veth1 2 --advbase 1 --advskew 100 --addr 192.168.1.200 2>/dev/null && \
    pass "carpd add vhid 2 succeeded" || fail "carpd add vhid 2 failed"

STATUS2=$($CARPD status veth1 2 2>/dev/null)
if echo "$STATUS2" | grep -q "vhid 2"; then
    pass "carpd status shows vhid 2"
else
    fail "carpd status missing vhid 2"
fi

# --- Test 9: Delete VHID ---
log "Deleting VHID..."
$CARPD del veth1 2 2>/dev/null && \
    pass "carpd del vhid 2 succeeded" || fail "carpd del vhid 2 failed"

# --- Test 10: Verify delete ---
STATUS3=$($CARPD status veth1 2 2>/dev/null)
if ! echo "$STATUS3" | grep -q "vhid 2"; then
    pass "VHID 2 deleted successfully"
else
    fail "VHID 2 still present after delete"
fi

# --- Test 11: Cross-namespace connectivity ---
log "Testing cross-namespace connectivity..."
ip netns exec carp_ns1 ping -c 1 -W 1 192.168.1.2 >/dev/null 2>&1 && \
    pass "Cross-namespace ping works" || fail "Cross-namespace ping failed"

# --- Summary ---
echo ""
echo "=== Results ==="
echo "PASSED: $PASS_COUNT"
echo "FAILED: $FAIL_COUNT"
if [ $FAIL_COUNT -eq 0 ]; then
    echo "ALL TESTS PASSED"
else
    echo "SOME TESTS FAILED"
fi
exit $FAIL_COUNT

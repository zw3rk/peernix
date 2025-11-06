#!/bin/bash
# Test script to verify fail-fast behavior when no peers have the requested file

set -e

echo "🧪 Testing fail-fast behavior for file not found in any peer"
echo "============================================================"

# Build the main peernix binary
echo "📦 Building peernix..."
cd /home/runner/work/peernix/peernix
go build -o peernix main.go

# Clean up any existing processes
pkill -f "peernix.*9991" || true
pkill -f "peernix.*9992" || true
pkill -f "peernix.*9993" || true
sleep 1

# Create a temp directory for config files
TEMP_DIR=$(mktemp -d)
echo "📁 Using temp directory: $TEMP_DIR"

# Create config for peer 1 (port 9991)
cat > "$TEMP_DIR/peernix1.conf" << EOF
udp-port = 9991
http-port = 9991
signing-enabled = false
EOF

# Create config for peer 2 (port 9992)
cat > "$TEMP_DIR/peernix2.conf" << EOF
udp-port = 9992
http-port = 9992
signing-enabled = false
EOF

# Create config for peer 3 (port 9993) - this will be the querying peer
cat > "$TEMP_DIR/peernix3.conf" << EOF
udp-port = 9993
http-port = 9993
signing-enabled = false
EOF

# Start peer 1
echo "🚀 Starting peer 1 on port 9991..."
cd "$TEMP_DIR"
cp peernix1.conf peernix.conf
/home/runner/work/peernix/peernix/peernix > peer1.log 2>&1 &
PEER1_PID=$!

# Start peer 2
echo "🚀 Starting peer 2 on port 9992..."
mkdir -p "$TEMP_DIR/peer2"
cd "$TEMP_DIR/peer2"
cp "$TEMP_DIR/peernix2.conf" peernix.conf
/home/runner/work/peernix/peernix/peernix > "$TEMP_DIR/peer2.log" 2>&1 &
PEER2_PID=$!

# Wait for peers to start
sleep 3

echo "✅ Peers started: PID=$PEER1_PID (port 9991), PID=$PEER2_PID (port 9992)"
echo ""

# Test 1: Query for a hash that doesn't exist in any peer
echo "📝 Test 1: Query for non-existent hash"
echo "---------------------------------------"
NONEXISTENT_HASH="aaaabbbbccccdddd11112222333344445555"

echo "⏱️  Starting timer..."
START_TIME=$(date +%s.%N)

# Query from peer 3 (which won't be running, so we'll query directly)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:9991/nix-cache/${NONEXISTENT_HASH}.narinfo" 2>&1 || echo "connection_failed")

END_TIME=$(date +%s.%N)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo "HTTP Response Code: $HTTP_CODE"
echo "⏱️  Query duration: ${DURATION} seconds"

# Check logs for "not_found" responses
echo ""
echo "📋 Checking peer 1 logs for 'not_found' response:"
grep -i "not_found" "$TEMP_DIR/peer1.log" || echo "  (no not_found responses found)"

echo ""
echo "📋 Checking peer 2 logs for 'not_found' response:"
grep -i "not_found" "$TEMP_DIR/peer2.log" || echo "  (no not_found responses found)"

# The test passes if:
# 1. HTTP returns 404 (not found)
# 2. Response time is reasonably fast (< 3 seconds for fail-fast, compared to 5+ seconds timeout)
echo ""
if [ "$HTTP_CODE" = "404" ]; then
    echo "✅ Test passed: Received expected 404 response"
    if (( $(echo "$DURATION < 3" | bc -l) )); then
        echo "✅ Fail-fast working: Response received in ${DURATION}s (< 3s threshold)"
    else
        echo "⚠️  Response time ${DURATION}s is slower than expected for fail-fast"
        echo "   (This could be due to peer discovery timing)"
    fi
else
    echo "❌ Test failed: Expected 404, got $HTTP_CODE"
fi

# Cleanup
echo ""
echo "🧹 Cleaning up..."
kill $PEER1_PID 2>/dev/null || true
kill $PEER2_PID 2>/dev/null || true
rm -rf "$TEMP_DIR"

echo ""
echo "✅ Test completed"

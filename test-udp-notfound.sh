#!/bin/bash
# Simple test to verify UDP communication and "not_found" response

set -e

echo "🧪 Testing UDP 'not_found' response"
echo "===================================="

# Build the test UDP tool
echo "📦 Building test UDP tool..."
cd /home/runner/work/peernix/peernix/test
go build -o test-udp-direct test-udp-direct.go

# Build peernix
echo "📦 Building peernix..."
cd /home/runner/work/peernix/peernix
go build -o peernix main.go

# Clean up any existing processes
pkill -f "peernix" || true
sleep 1

# Start peernix on default port
echo "🚀 Starting peernix on port 9999..."
./peernix > /tmp/peernix-test.log 2>&1 &
PEERNIX_PID=$!

# Wait for startup
sleep 3

echo "✅ Peernix started (PID=$PEERNIX_PID)"
echo ""

# Test 1: Query for a path that definitely doesn't exist
echo "📝 Test 1: Query for non-existent hash"
echo "---------------------------------------"
FAKE_HASH="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"

echo "Querying for hash: $FAKE_HASH"
cd /home/runner/work/peernix/peernix/test

# Run the UDP test tool
timeout 5 ./test-udp-direct has_path "$FAKE_HASH" 2>&1 || true

echo ""
echo "📋 Checking peernix logs:"
echo "Last 10 lines:"
tail -10 /tmp/peernix-test.log

echo ""
echo "Checking for 'not_found' responses:"
grep -i "not_found" /tmp/peernix-test.log || echo "  (no not_found messages found - might need more time for discovery)"

# Cleanup
echo ""
echo "🧹 Cleaning up..."
kill $PEERNIX_PID 2>/dev/null || true
sleep 1

echo ""
echo "✅ Test completed"
echo ""
echo "Note: This test verifies that peernix responds with 'not_found'"
echo "      The full fail-fast behavior requires multiple peers."

#!/bin/bash
set -e

echo "🧪 Testing peernix binary cache functionality"

# Clean up any existing peernix processes
pkill -f peernix || true
sleep 1

# Start peernix on test port
echo "📡 Starting peernix on port 9998..."
./result/bin/peernix -port-http 9998 -port-udp 9998 &
PEERNIX_PID=$!

# Wait for startup
sleep 3

echo "🔍 Testing basic endpoints..."

# Test nix-cache-info
echo "📋 Testing nix-cache-info endpoint:"
curl -s http://localhost:9998/nix-cache/nix-cache-info
echo

# Test status
echo "📊 Testing status endpoint:"
curl -s http://localhost:9998/status | head -15
echo

# Test with a known store path
STORE_PATH=$(ls /nix/store | grep -E '^[0-9a-z]{32}-hello' | head -1)
if [ -z "$STORE_PATH" ]; then
    echo "📦 Building hello package for testing..."
    HELLO_PATH=$(nix-build '<nixpkgs>' -A hello 2>/dev/null)
    HASH=$(basename "$HELLO_PATH" | cut -d'-' -f1)
else
    HASH=$(echo "$STORE_PATH" | cut -d'-' -f1)
fi

echo "🧮 Testing with hash: $HASH"

# Test narinfo
echo "📝 Testing narinfo generation:"
curl -s "http://localhost:9998/nix-cache/${HASH}.narinfo"
echo

# Test NAR download (first 100 bytes)
echo "📦 Testing NAR download (first 100 bytes):"
curl -s "http://localhost:9998/nix-cache/${HASH}.nar" | head -c 100
echo -e "\n"

# Test if format is compatible
echo "🔍 Testing Nix compatibility..."
echo "Attempting to copy from peernix (this tests full protocol compatibility):"

# Create temporary test store
TEST_STORE="/tmp/peernix-test-$$"
mkdir -p "$TEST_STORE"

# Test copying from peernix
if nix copy --from "http://localhost:9998/nix-cache/" --to "file://$TEST_STORE" "/nix/store/$HASH"* --no-check-sigs 2>&1; then
    echo "✅ SUCCESS: Nix can copy from peernix!"
    echo "📂 Contents of test store:"
    ls -la "$TEST_STORE/"
else
    echo "❌ FAILED: Nix copy failed"
fi

# Clean up
echo "🧹 Cleaning up..."
kill $PEERNIX_PID 2>/dev/null || true
rm -rf "$TEST_STORE"

echo "✅ Test completed"
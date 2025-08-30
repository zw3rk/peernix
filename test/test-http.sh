#!/bin/bash

# Test script for peernix HTTP endpoints
# Copyright Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.

set -e

PORT=9999
HOST="localhost"

echo "🔍 Testing peernix HTTP endpoints..."
echo ""

# Function to test a narinfo endpoint
test_narinfo() {
    local hash="$1"
    echo "📦 Testing .narinfo for hash: $hash"
    echo "   URL: http://$HOST:$PORT/nix-cache/$hash.narinfo"
    
    response=$(curl -s -w "\n   Status: %{http_code}" "http://$HOST:$PORT/nix-cache/$hash.narinfo")
    echo "$response"
    echo ""
}

# Function to test a nar endpoint
test_nar() {
    local hash="$1"
    echo "📦 Testing .nar for hash: $hash"
    echo "   URL: http://$HOST:$PORT/nix-cache/$hash.nar"
    
    # Just get the status and size, don't download the full NAR
    curl -s -I "http://$HOST:$PORT/nix-cache/$hash.nar" | grep -E "^HTTP|^Content-"
    echo ""
}

# Check if server is running
if ! curl -s -f "http://$HOST:$PORT/" > /dev/null 2>&1; then
    echo "⚠️  Server doesn't appear to be running on http://$HOST:$PORT"
    echo "   Start it with: ./result/bin/peernix"
    exit 1
fi

echo "✅ Server is running on http://$HOST:$PORT"
echo ""

# If hash provided as argument, test it
if [ $# -gt 0 ]; then
    test_narinfo "$1"
    test_nar "$1"
else
    echo "Usage: $0 <store-hash>"
    echo ""
    echo "Example store hashes from your system:"
    ls /nix/store/ | grep -E '^[a-z0-9]{32}-' | head -5 | while read store_entry; do
        hash="${store_entry:0:32}"
        name="${store_entry:33}"
        echo "  $hash  ($name)"
    done
    echo ""
    echo "To test: $0 <hash-from-above>"
fi
# Fail-Fast Implementation for File Not Found

## Overview
This implementation adds a fail-fast mechanism to peernix that allows the server to quickly determine when no peers have a requested file, rather than waiting for a timeout.

## Changes Made

### 1. UDP Protocol Enhancement
**File**: `main.go` (lines 784-788)

The UDP server now responds with explicit "not_found" messages when it doesn't have a requested path:

```go
if hasPath(hash) {
    metrics.UDPQueriesFound.Add(1)
    log.Printf("[INFO] Responding YES to %s for hash: %s", addr, hash)
    conn.WriteToUDP([]byte("yes"), addr)
} else {
    // Respond with not_found to enable fail-fast behavior
    log.Printf("[DEBUG] Responding NOT_FOUND to %s for hash: %s", addr, hash)
    conn.WriteToUDP([]byte("not_found"), addr)
}
```

**Previous behavior**: No response sent when path doesn't exist
**New behavior**: Sends "not_found" response explicitly

### 2. Enhanced Result Tracking
**File**: `main.go` (lines 1293-1296)

Added a `notFound` boolean field to the result struct to distinguish between:
- Explicit "not_found" responses from peers
- Communication failures/timeouts
- Successful responses

```go
type result struct {
    addr     *net.UDPAddr
    err      error
    notFound bool // indicates peer responded with "not_found"
}
```

### 3. Response Handling
**File**: `main.go` (lines 1427-1441)

Added specific handling for "not_found" responses:

```go
} else if response == "not_found" {
    // Peer responded that it doesn't have the path
    peersMux.Lock()
    for i := range peers {
        if peers[i].Addr == p.Addr {
            peers[i].LastSeen = time.Now()
            peers[i].FailureCount = 0
            break
        }
    }
    peersMux.Unlock()

    log.Printf("[DEBUG] Peer %s confirmed not having hash %s", p.Addr, hash)
    results <- result{nil, fmt.Errorf("peer doesn't have path"), true}
    return
}
```

This treats "not_found" as a healthy response (updates LastSeen, resets FailureCount) but marks it as notFound=true.

### 4. Fail-Fast Logic
**File**: `main.go` (lines 1463-1482)

The main fail-fast implementation tracks responses and returns early when all peers have responded:

```go
// Wait for first success or all failures
notFoundCount := 0
failureCount := 0
for i := 0; i < len(currentPeers); i++ {
    select {
    case res := <-results:
        if res.err == nil {
            log.Printf("[INFO] Found %s at peer %s via parallel query", hash, res.addr.IP.String())
            return res.addr
        }
        // Track not_found responses separately from other failures
        if res.notFound {
            notFoundCount++
        } else {
            failureCount++
        }
        // Fail fast if all peers have responded (either not_found or error)
        if notFoundCount+failureCount == len(currentPeers) {
            log.Printf("[INFO] All %d peers responded: %d confirmed not found, %d failed/timeout - failing fast", 
                len(currentPeers), notFoundCount, failureCount)
            return nil
        }
    case <-ctx.Done():
        log.Printf("[DEBUG] Peer query timeout for hash %s after receiving %d responses (%d not_found, %d failed)", 
            hash, notFoundCount+failureCount, notFoundCount, failureCount)
        return nil
    }
}
```

**Previous behavior**: Waited for first success OR timeout (2 seconds)
**New behavior**: Returns immediately when all peers respond (either "not_found" or failure)

## Benefits

1. **Faster Cache Misses**: When a file doesn't exist on any peer, the client gets a 404 response as soon as all peers respond, rather than waiting for the full 2-second timeout.

2. **Better User Experience**: For cache misses with many peers, the response time can be reduced from 2 seconds to hundreds of milliseconds (depending on network latency).

3. **Better Observability**: The logs now distinguish between:
   - Peers that confirmed they don't have the file ("not_found")
   - Peers that failed to respond (timeout/error)

4. **Maintained Backward Compatibility**: 
   - Old peernix versions that don't send "not_found" still work (treated as timeout)
   - The protocol gracefully handles mixed versions

## Example Scenarios

### Scenario 1: File found on first peer
- Peer 1: responds "yes" immediately
- Result: Fast success (~10-50ms)
- Other peers: queries cancelled

### Scenario 2: File not on any peer (NEW - Fast)
- Peer 1: responds "not_found" after 50ms
- Peer 2: responds "not_found" after 80ms  
- Peer 3: responds "not_found" after 100ms
- Result: Fast failure after 100ms (when last peer responds)

### Scenario 3: File not on any peer (OLD - Slow)
- Peer 1: no response (timeout)
- Peer 2: no response (timeout)
- Peer 3: no response (timeout)
- Result: Slow failure after 2000ms (timeout)

## Testing

Tests have been added:
- `test/test-fail-fast.go` - Mock peer simulation
- `test-fail-fast.sh` - Integration test script
- `test-udp-notfound.sh` - Simple UDP response verification

To manually test:
1. Start multiple peernix instances on different ports
2. Query for a non-existent hash
3. Observe the logs show "not_found" responses and fast failure

## Backward Compatibility

The implementation maintains full backward compatibility:
- Old clients work with new servers
- New clients work with old servers (fallback to timeout behavior)
- Mixed version networks work correctly

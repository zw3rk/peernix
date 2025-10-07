# Fix for .nar Not Found Errors Hours After GC

## Problem

Peernix was experiencing failures where `.narinfo` requests would succeed, but subsequent `.nar` requests (hours later) would fail with "No cached peer for .nar hash" errors. This occurred even when GC had run hours before, not during the requests.

## Root Cause Analysis

The issue is **NOT** a Time-of-Check to Time-of-Use (TOCTOU) race condition with GC. Instead, it's a **peer caching design issue**:

### How the Peer Cache Works

1. When a `.narinfo` is requested and found in a **peer**, the peer's IP is cached in `narInfoPeerCache`
2. When a `.nar` is requested later, it checks `narInfoPeerCache` for the peer IP
3. This prevents querying all peers again and ensures consistency (same peer serves both .narinfo and .nar)

### The Bug

When a `.narinfo` is served from the **local store**:
- No peer IP is cached (because it was served locally, not from a peer)
- The path is served successfully

Hours later, after GC deletes the path:
1. Client requests `.nar` for the same hash
2. `hasPath()` returns `false` (path deleted by GC)
3. Code checks `narInfoPeerCache` → **no entry found**
4. Code refuses to query peers (to avoid hash mismatches)
5. Returns 404: "No cached peer for .nar hash"

### Timeline Example

```
T0: Client requests abc123.narinfo
    → Found in local store
    → Served from local store
    → narInfoPeerCache[abc123] = (empty, nothing cached)

T0 + 6 hours: Nix GC runs, deletes /nix/store/abc123-...

T0 + 8 hours: Client requests abc123.nar
    → hasPath() returns false (deleted by GC)
    → Check narInfoPeerCache[abc123] → NOT FOUND
    → Return 404 "No cached peer for .nar hash"
```

## Solution

Cache a "localhost" marker when serving `.narinfo` from local store:

1. **When serving .narinfo from local store**: Cache `"localhost"` in `narInfoPeerCache`
2. **When .nar request arrives**: 
   - If cached peer is `"localhost"` and path is gone → query peers as fallback
   - If a peer has it, update cache with actual peer IP
   - If no peer has it, return 404

This allows graceful fallback to peers when locally-served paths are deleted by GC.

## Changes Made

### 1. Cache "localhost" marker for local .narinfo

```go
if isNarInfo {
    // ... generate narinfo from local store ...
    
    // Cache "localhost" marker so .nar requests know this was served locally
    narInfoPeerCacheMux.Lock()
    narInfoPeerCache[hash] = "localhost"
    narInfoPeerCacheMux.Unlock()
}
```

### 2. Handle "localhost" fallback for .nar requests

```go
if isNar {
    peerIP, exists = narInfoPeerCache[hash]
    if exists {
        // If cached peer is "localhost" but we're here, path was deleted
        if peerIP == "localhost" {
            // Query peers as fallback
            peerAddr := findPeerForHash(hash)
            if peerAddr != nil {
                peerIP = peerAddr.IP.String()
                // Update cache with actual peer
                narInfoPeerCache[hash] = peerIP
            } else {
                return 404 // No peers have it either
            }
        }
    }
}
```

## Impact

### Before Fix
1. `.narinfo` served from local store → no peer cached
2. Hours later, GC deletes path
3. `.nar` request → 404 "No cached peer" (even if peers have it)

### After Fix
1. `.narinfo` served from local store → cache "localhost" marker
2. Hours later, GC deletes path
3. `.nar` request → detects "localhost" marker → queries peers
4. If peer has it → serves from peer (updates cache)
5. If no peer has it → 404 (correct behavior)

## Why This Explains the Symptoms

The user reported: "Errors are still happening hours after the last GC"

This makes perfect sense now:
- The `.narinfo` was served from local store at time T
- GC ran at time T + X hours (deleted the path)
- The `.nar` request came at time T + Y hours (where Y > X)
- The error occurred at T + Y, which is indeed "hours after the last GC"
- The failure was NOT caused by GC timing, but by the **lack of peer cache entry** for locally-served narinfos

## Testing

To verify the fix:

1. Request `.narinfo` for a hash in local store
2. Verify "localhost" is cached in `narInfoPeerCache`
3. Delete the path from local store (simulating GC)
4. Request `.nar` for the same hash
5. Verify it queries peers and serves from peer if available
6. Verify cache is updated with actual peer IP

## Related Code

- `handleNixCache()`: Main request handler
- `narInfoPeerCache`: Global map caching which peer served a narinfo
- `findPeerForHash()`: Queries all peers for a hash

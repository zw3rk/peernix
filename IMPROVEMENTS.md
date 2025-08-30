# Peernix Improvement Plan

## Executive Summary
After thorough review of the peernix codebase, I've identified several critical improvements needed for protocol compliance, performance, reliability, and security. This document outlines these improvements prioritized by importance.

## Critical Issues (Must Fix)

### 1. Missing `/nix-cache/nix-cache-info` Endpoint ✅ YES, REQUIRED
**Issue**: Nix clients expect this endpoint to identify the binary cache capabilities.
**Solution**: Add endpoint returning:
```
StoreDir: /nix/store
WantMassQuery: 0
Priority: 50
```

### 2. Incomplete NarInfo Format
**Issue**: Missing critical fields that Nix expects:
- `URL`: Where to fetch the NAR
- `Compression`: NAR compression type (none, xz, bzip2, gzip)
- `FileHash`: Hash of the compressed NAR
- `FileSize`: Size of compressed NAR
- `NarHash`: Hash of uncompressed NAR
- `Sig`: Signature (optional but recommended)

**Solution**: Generate complete narinfo using `nix-store --generate-binary-cache-key` or compute hashes.

### 3. Race Condition in Metrics
**Issue**: Line 169-171 - RequestTimes slice trimming happens inside RLock, but modifies the slice
**Solution**: Move trimming to write-locked section or use ring buffer

## Concurrency & Performance Issues

### 4. Single-Threaded UDP Server ✅ MAJOR ISSUE
**Current**: UDP server blocks on each message, can't handle concurrent queries
**Impact**: 
- Peer discovery blocks all UDP operations for 1 second
- Path queries block while checking disk
- Single peer can DOS the UDP server

**Solution**: Process UDP messages in goroutines:
```go
go func(msg string, addr *net.UDPAddr) {
    // Handle message
}(string(buf[:n]), addr)
```

### 5. Sequential Peer Querying
**Issue**: When querying peers for a path, we wait sequentially for responses
**Solution**: Query all known peers in parallel with goroutines and channels

### 6. No Connection Pooling
**Issue**: Creating new HTTP client for each peer request
**Solution**: Maintain per-peer HTTP client with connection pooling

## Discovery Mechanism Improvements

### 7. mDNS/Zeroconf Discovery ✅ RECOMMENDED
**Benefits**:
- More standard than UDP broadcast
- Works better across network segments
- Built-in service metadata
- Libraries available (github.com/grandcat/zeroconf)

**Implementation**:
```go
// Advertise service
server, _ := zeroconf.Register("peernix", "_nix-cache._tcp", "local.", 9999, []string{"version=1"}, nil)

// Discover peers
resolver, _ := zeroconf.NewResolver(nil)
entries := make(chan *zeroconf.ServiceEntry)
go resolver.Browse(ctx, "_nix-cache._tcp", "local.", entries)
```

### 8. Peer Persistence
**Issue**: Peers lost on restart
**Solution**: Save discovered peers to disk, verify on startup

## Network Efficiency

### 9. Compression Support ✅ HIGH VALUE
**Benefits**: 
- Reduce bandwidth by 50-90% for typical Nix packages
- Nix already supports xz, bzip2, gzip

**Implementation**:
```go
// Compress NAR on-the-fly
if acceptsCompression(r.Header.Get("Accept-Encoding")) {
    w.Header().Set("Content-Encoding", "gzip")
    gw := gzip.NewWriter(w)
    defer gw.Close()
    generateNar(hash, gw)
}
```

### 10. Parallel Store Operations
**Issue**: nix-store commands run sequentially
**Solution**: Cache results and run multiple operations in parallel

## Security Enhancements

### 11. Signing Support ✅ IMPORTANT
**Why**: Prevents tampering, required for trusted substituters
**Implementation**:
- Generate keypair: `nix-store --generate-binary-cache-key`
- Sign narinfos with Ed25519
- Add `Sig:` field to narinfo

### 12. Rate Limiting
**Issue**: No protection against abuse
**Solution**: Add per-IP rate limiting using golang.org/x/time/rate

### 13. Authentication/Authorization
**Consider**: Optional peer authentication using pre-shared keys or TLS client certs

## Reliability Improvements

### 14. Health Checks for Peers
**Issue**: No verification that peers are still alive
**Solution**: Periodic health checks, remove dead peers

### 15. Retry Logic
**Issue**: Single failure causes miss
**Solution**: Retry failed peer requests with exponential backoff

### 16. Request Deduplication
**Issue**: Multiple requests for same path query all peers
**Solution**: Coalesce concurrent requests for same hash

## Implementation Priority

### Phase 1: Critical Fixes (1-2 days)
1. Add `/nix-cache/nix-cache-info` endpoint
2. Fix metrics race condition
3. Make UDP server concurrent
4. Complete narinfo format

### Phase 2: Performance (2-3 days)
5. Parallel peer querying
6. Connection pooling
7. Compression support
8. Request coalescing

### Phase 3: Discovery & Reliability (3-4 days)
9. mDNS discovery
10. Peer persistence
11. Health checks
12. Retry logic

### Phase 4: Security (2-3 days)
13. Signing support
14. Rate limiting
15. Optional authentication

## Code Structure Improvements

### Suggested Refactoring
1. Split into packages:
   - `discovery/` - Peer discovery (UDP, mDNS)
   - `cache/` - Nix store operations
   - `p2p/` - Peer communication
   - `metrics/` - Metrics collection

2. Use interfaces for discovery:
```go
type Discovery interface {
    Advertise(ctx context.Context) error
    Discover(ctx context.Context) <-chan Peer
}
```

3. Use context for cancellation and timeouts

4. Add configuration file support (YAML/TOML)

## Immediate Quick Wins

1. **Add nix-cache-info endpoint** (5 minutes):
```go
http.HandleFunc("/nix-cache/nix-cache-info", handleNixCacheInfo)
```

2. **Fix UDP concurrency** (30 minutes):
   - Wrap message handling in goroutines

3. **Add compression** (1 hour):
   - Check Accept-Encoding header
   - Compress responses

4. **Parallel peer queries** (1 hour):
   - Use goroutines and channels

## Testing Recommendations

1. Load testing with concurrent requests
2. Network partition testing
3. Large file transfer testing
4. Compression ratio benchmarks
5. Peer discovery in different network configurations

## Monitoring Additions

Add metrics for:
- Compression ratio
- Peer response times
- Cache effectiveness
- Error rates by type
- Queue depths

## Conclusion

The current implementation is a solid foundation but needs improvements in:
1. **Protocol compliance** - Complete Nix binary cache protocol
2. **Concurrency** - Handle multiple requests efficiently  
3. **Discovery** - More robust peer discovery
4. **Performance** - Compression and parallelization
5. **Security** - Signing and rate limiting

The suggested improvements would make peernix production-ready for team/organization use.
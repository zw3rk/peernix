# Peernix Implementation Roadmap

## Quick Wins (Do Immediately)

### 1. Add nix-cache-info endpoint (5 minutes)
```go
func handleNixCacheInfo(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/x-nix-cache-info")
    fmt.Fprintf(w, "StoreDir: /nix/store\n")
    fmt.Fprintf(w, "WantMassQuery: 0\n")
    fmt.Fprintf(w, "Priority: 50\n")
}
// Add to main(): http.HandleFunc("/nix-cache/nix-cache-info", handleNixCacheInfo)
```

### 2. Fix metrics race (10 minutes)
- Move slice trimming outside RLock or use proper locking

### 3. UDP concurrency (30 minutes)
- Wrap message handlers in goroutines
- Prevents one slow operation from blocking all UDP

## High Impact Improvements

### 4. Compression (1-2 hours)
- Check Accept-Encoding header
- Compress with gzip for 50-90% bandwidth savings
- Update narinfo with Compression field

### 5. Parallel peer queries (1-2 hours)
- Query all peers simultaneously
- Return first successful response
- Massive speedup for cache misses

### 6. Complete narinfo format (2-3 hours)
- Add URL, FileHash, NarHash fields
- Compute hashes during generation
- Required for proper Nix compatibility

## Medium Priority

### 7. mDNS Discovery (4-6 hours)
- Better than UDP broadcast
- Works across network segments
- More standard approach

### 8. Connection pooling (2-3 hours)
- Reuse HTTP connections to peers
- Reduce latency and overhead

### 9. Peer health checks (2-3 hours)
- Periodic liveness checks
- Remove dead peers
- Maintain peer scores

## Advanced Features

### 10. Signing support (1 day)
- Generate Ed25519 keypair
- Sign narinfos
- Verify signatures

### 11. Configuration file (4-6 hours)
- YAML/TOML config
- Configurable ports, timeouts
- Discovery preferences

### 12. Request coalescing (4-6 hours)
- Deduplicate concurrent requests
- Single backend fetch for multiple clients
- Reduces load on peers

## Architectural Improvements

### 13. Package structure (1-2 days)
```
peernix/
├── cmd/peernix/main.go
├── pkg/
│   ├── discovery/
│   │   ├── udp.go
│   │   └── mdns.go
│   ├── cache/
│   │   ├── store.go
│   │   └── narinfo.go
│   ├── p2p/
│   │   └── client.go
│   └── metrics/
│       └── collector.go
```

### 14. Interface-based design
- Discovery interface
- Storage interface
- Makes testing easier

## Performance Targets

After improvements:
- Handle 1000+ concurrent requests
- Sub-100ms response for cached content
- 50-90% bandwidth reduction with compression
- Discover peers in <1 second
- Parallel query 10+ peers simultaneously

## Success Metrics

- [ ] Passes Nix binary cache protocol tests
- [ ] Handles 100 req/sec load test
- [ ] Compression reduces bandwidth >50%
- [ ] mDNS discovers peers automatically
- [ ] No race conditions or deadlocks
- [ ] Graceful degradation when peers fail

## Timeline Estimate

- **Week 1**: Quick wins + High impact (items 1-6)
- **Week 2**: Medium priority (items 7-9)  
- **Week 3**: Advanced features (items 10-12)
- **Week 4**: Architectural improvements + testing

Total: ~4 weeks for production-ready system
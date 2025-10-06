# Fix for .nar Not Found Errors After Nix GC

## Problem

This addresses the issue where peernix would return a `.narinfo` file successfully, but then fail to serve the corresponding `.nar` file with "not found" errors. This occurred even when GC was not actively running at the time of the request.

## Root Cause

The issue was a **Time-of-Check to Time-of-Use (TOCTOU) race condition**:

1. Client requests `.narinfo` for hash `abc123`
2. `hasPath("abc123")` checks if path exists → returns `true`
3. `generateNarInfo()` generates narinfo successfully
4. **Nix GC runs and deletes `/nix/store/abc123-...` from disk**
5. Client requests `.nar` file based on the `.narinfo`
6. `generateNar("abc123")` tries to access path → **fails with "not found"**

### Contributing Factors

- **Stale cache**: `findStorePath()` caches results for 5 minutes without invalidation
- **No verification**: Once a path is found, it's used without re-checking existence
- **GC can happen anytime**: Even if "GC was not running" during failures, the deletion happened between requests

## Solution

The fix adds three layers of protection:

### 1. Re-verification Before Use

Both `generateNarInfo()` and `generateNar()` now re-check path existence immediately before operations:

```go
// Re-verify path exists to catch TOCTOU race with GC
if _, err := os.Stat(fullPath); err != nil {
    // Path was deleted (likely by GC), invalidate cache
    storeCacheMux.Lock()
    delete(storeCache, "path:"+hash)
    storeCacheMux.Unlock()
    return fmt.Errorf("store path no longer exists (GC?): %s", hash)
}
```

### 2. Lock File Checking

Added detection of GC in progress:

```go
// Also check for lock file - path might be in process of being deleted
if _, err := os.Stat(fullPath + ".lock"); err == nil {
    return fmt.Errorf("store path is locked (GC in progress?): %s", hash)
}
```

### 3. Cache Invalidation on Failure

All `nix-store` operation failures now immediately invalidate the cache:

```go
if err != nil {
    // nix-store command failed, invalidate cache
    storeCacheMux.Lock()
    delete(storeCache, "path:"+hash)
    storeCacheMux.Unlock()
    return err
}
```

## Impact

### Before
- Client gets `.narinfo` → GC deletes path → `.nar` request fails with unclear error
- Cache remains stale for up to 5 minutes
- Subsequent requests continue failing

### After
- Client gets `.narinfo` → GC deletes path → `.nar` request fails with clear error
- Cache is immediately invalidated
- Subsequent requests correctly report "not found"
- If path is re-added, it will be found again

## Testing

To verify the fix:

1. Request `.narinfo` for a hash that exists
2. Run `nix-collect-garbage` to delete the path
3. Request `.nar` for the same hash
4. Verify clear error message: "store path no longer exists (GC?)"
5. Verify cache was invalidated (subsequent requests behave correctly)

## Notes

- This fix **does not prevent** the race condition (GC can still delete paths between requests)
- It **handles the race gracefully** by detecting it and providing clear errors
- Cache invalidation ensures stale data doesn't persist
- Lock file checking adds safety during active GC operations

## Related Files Modified

- `main.go`: Added re-verification and cache invalidation in `generateNarInfo()` and `generateNar()`
- `.gitignore`: Added `nix.peernix.conf` (generated runtime config)

## References

- [TOCTOU on Wikipedia](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)
- The "gap" mentioned in the issue is the time window between check and use
- This fix "plugs the gap" by minimizing the window and detecting when the race occurs

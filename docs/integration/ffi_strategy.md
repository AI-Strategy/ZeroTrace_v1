# ZeroTrace FFI Strategy

For ultra-low latency applications (Voice/Video), ZeroTrace can be compiled as a dynamic library (`.so`, `.dll`, `.dylib`) and loaded directly into the host process.

## Architecture

1.  **Rust Core**: Compile `zerotrace-core` with `crate-type = ["cdylib"]`.
2.  **C-ABI Exports**: Expose `no_mangle` functions for `scan_input`, `redact`, etc.
3.  **Host Bindings**: Use `ctypes` (Python), `Fiddle` (Ruby), or `N-API` (Node.js) to call these functions.

## Example Rust Export

```rust
#[no_mangle]
pub extern "C" fn zerotrace_scan(input: *const c_char) -> bool {
    // ... unsafe pointer handling ...
    // Call internal detect::scan_for_anomalies
    true
}
```

## Benefits

-   **Zero Network Overhead**: Function calls take nanoseconds.
-   **Shared Memory**: Pass pointers to large video buffers without copying.

# ZeroTrace FFI Strategy (Legacy Support)

**Governance Note**: The ZeroTrace Backend is **Strictly Rust**. 
This FFI strategy is documented ONLY for integrating ZeroTrace into *external* legacy systems (e.g., existing C++ or Node.js pipelines) where full Rust migration is impossible.

**Preferred Integration**: 
-   **Rust-to-Rust**: Add `zerotrace-core = "0.1"` to your `Cargo.toml`.

## Architecture (External Only)

1.  **Rust Core**: Compile `zerotrace-core` with `crate-type = ["cdylib"]`.
2.  **C-ABI Exports**: Expose `no_mangle` functions.
3.  **Host Bindings**: C/C++ or other ABI-compatible languages.

## Example Rust Export

```rust
#[no_mangle]
pub extern "C" fn zerotrace_scan(input: *const c_char) -> bool {
    // ... unsafe pointer handling ...
    // Call internal detect::scan_for_anomalies
    true
}
```

## Policy
Internal components (e.g., CLI, API) MUST use the Rust Crate directly. FFI is for **Edge Cases Only**.

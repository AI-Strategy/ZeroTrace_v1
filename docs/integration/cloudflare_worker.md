# ZeroTrace: Cloudflare Worker Migration Guide

To deploy `zerotrace-core` as a Cloudflare Worker, we must adapt the runtime from a standard binary (Tokio) to the WASM-based `worker` crate.

## 1. `worker-rs` Crate

Add to `Cargo.toml`:
```toml
[dependencies]
worker = "0.0.18"
```

## 2. Lib.rs Adaptation

Modify `src/lib.rs` to expose a `worker::event` entry point instead of a `main` function.

```rust
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // 1. Initialize Upstash Client
    let redis = UpstashClient::from_env_worker(&env)?;

    // 2. Intercept Loop (Same logic as Core, adapted for Worker types)
    // ...
    
    Response::ok("ZeroTrace Edge: Secure")
}
```

## 3. The "Edge-Vault Pattern"

1.  **Registry Checking**: Use `env.kv("REGISTRY_KV")` for ultra-fast lookups of commonly used safe domains.
2.  **State Management**: Use `UpstashClient` (via REST) for global session state or "Semantic Caching".
3.  **Secrets**: Manage API keys via `wrangler secret put`, accessible via `env.secret()`.

## 4. Deployment

```bash
wrangler publish
```

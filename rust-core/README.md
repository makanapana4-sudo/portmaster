# Portmaster Rust Core (Experimental)

This directory is an incremental Rust implementation area for selected Portmaster user-mode responsibilities.

The workspace now contains reusable, tested building blocks:
- connection identity types for TCP and UDP;
- validated core resource-limit configuration;
- a fixed-capacity TTL cache;
- a bounded multi-producer, single-consumer event queue;
- shared error types.

These components are not yet connected to the running Portmaster service. The existing Go implementation remains authoritative and must not be removed or bypassed until migrated features demonstrate behavior parity, security equivalence, and measured performance improvements.

## Existing repository architecture

- `windows_kext/driver`: Rust Windows kernel driver using the Windows Filtering Platform (WFP).
- `windows_kext/protocol`: Rust binary protocol associated with the driver.
- `windows_kext/kextinterface`: Go-side interface to the Windows driver.
- `desktop/tauri`: existing Tauri desktop application.
- Root Go packages: the current user-mode service, including networking, DNS, filtering, configuration, and supporting functionality.

Do not duplicate or replace the existing WFP driver or Tauri desktop application without first documenting a concrete gap and validating compatibility.

## Workspace layout

```text
rust-core/
  Cargo.toml
  README.md
  PERFORMANCE.md
  tools/
    measure-process.ps1
  crates/
    portmaster-core/
      Cargo.toml
      src/
        lib.rs
        cache.rs
        config.rs
        connection.rs
        error.rs
        event_queue.rs
```

## Design constraints

- Keep this core isolated from the live networking stack during early development.
- Validate configuration and resource limits before starting work.
- Keep unsafe Rust forbidden in this platform-independent crate.
- Bound queues and caches; define backpressure behavior instead of silently dropping events.
- Avoid unnecessary dependencies and background threads.
- Preserve the existing WFP driver protocol until compatibility is proven.
- Never silently disable filtering or fail open on security-critical errors.
- Do not weaken Windows Firewall, Microsoft Defender, or other host protections.
- Do not store credentials, tokens, or private user data in source control.

## Build and test

From the repository root:

```sh
cargo fmt --manifest-path rust-core/Cargo.toml --all -- --check
cargo clippy --manifest-path rust-core/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --manifest-path rust-core/Cargo.toml --workspace
```

GitHub Actions runs these checks on Linux and Windows when Rust core files change. The existing WFP kernel driver has its own separate build workflow and is not built by this core workflow.

## Performance

See [PERFORMANCE.md](PERFORMANCE.md) for a repeatable baseline/candidate measurement procedure and the Windows process sampler.

No product-level speed or memory improvement is claimed yet: these Rust components are not on Portmaster's production execution path. Startup time, idle CPU, memory, DNS latency, packet processing, and long-running stability must be measured after each real service feature is migrated.

## Migration order

1. Map existing Go configuration and connection-lifecycle behavior.
2. Add protocol-compatible event and command models using fixtures from `windows_kext/protocol`.
3. Integrate bounded event processing with explicit backpressure and recovery.
4. Migrate selected service features behind an opt-in development switch.
5. Compare baseline and candidate on identical workloads.
6. Expand migration only after functional, security, and performance checks pass.

**Status: experimental foundation.** Production behavior is unchanged.

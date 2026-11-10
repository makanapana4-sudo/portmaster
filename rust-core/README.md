# Portmaster Rust Core (Experimental)

This directory is an incremental Rust implementation area for selected Portmaster user-mode responsibilities.

The workspace now contains reusable building blocks:
- connection identity types for TCP and UDP;
- validated core resource-limit configuration;
- a DNS response cache with Portmaster-compatible TTL, negative-response, stale-answer and refresh-window policies, plus count and byte limits;
- a bounded single-flight DNS request coordinator with cancellation, timeout recovery and safe leader replacement;
- a DNS wire parser and query builder, including compressed-name validation, EDNS support, minimum TTL extraction, upstream response matching and safe TTL rewriting;
- synchronous DNS-over-UDP upstream exchanges with retries and automatic DNS-over-TCP fallback, including transaction/question validation;
- an integrated synchronous DNS resolver joining query validation, cache lookup/insertion, duplicate-request coalescing, upstream fetches and stale fallback;
- a fixed-size DNS worker pool with a bounded queue and explicit `QueueFull` backpressure.
- a fixed-capacity TTL cache;
- a bounded multi-producer, single-consumer event queue;
- safe framing, typed decoding of all seven driver event kinds, bounded incremental stream decoding, and a generic transport adapter for the existing Windows driver protocol;
- shared error types.

These components are not yet connected to the running Portmaster service. The existing Go implementation remains authoritative and must not be removed or bypassed until migrated features demonstrate behavior parity, security equivalence, and measured performance improvements.

## Existing repository architecture

- `windows_kext/driver`: Rust Windows kernel driver using the Windows Filtering Platform (WFP).
- `windows_kext/protocol`: existing Rust wire protocol shared with the driver.
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
        dns_cache.rs
        dns_coalescer.rs
        dns_wire.rs
        dns_query.rs
        dns_resolver.rs
        dns_service.rs
        dns_upstream.rs
        driver_info.rs
        driver_protocol.rs
        driver_stream.rs
        driver_transport.rs
        error.rs
        event_queue.rs
```

## Design constraints

- Keep this core isolated from the live networking stack during early development.
- Validate configuration and resource limits before starting work.
- Keep resolver selection, upstream transport, response filtering and persistence separate from the DNS cache until those pieces have their own parity tests.
- Keep unsafe Rust forbidden in this platform-independent crate.
- Bound queues and caches; define backpressure behavior instead of silently dropping events.
- Parse driver frames with size checks, decode all current event kinds, and borrow packet payloads and bandwidth records instead of copying them.
- Keep the platform-neutral transport generic over Read and Write until the Windows handle lifecycle and synchronization have been designed and tested.
- Keep incomplete stream frames in a bounded buffer and process multiple complete frames in one read.
- Encode driver commands into reusable buffers to avoid repeated allocations.
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

GitHub Actions runs these checks on Linux and Windows when Rust core or shared protocol files change. The workflow also runs the existing `windows_kext/protocol` crate tests so the reused message IDs and wire types stay covered. The existing WFP kernel driver has its own separate build workflow and is not built by this core workflow.

## Performance

See [PERFORMANCE.md](PERFORMANCE.md) for a repeatable baseline/candidate measurement procedure and the Windows process sampler.

No product-level speed or memory improvement is claimed yet: these Rust components are not on Portmaster's production execution path. Startup time, idle CPU, memory, DNS latency, packet processing, and long-running stability must be measured after each real service feature is migrated.

## Migration order

1. Map existing Go configuration and connection-lifecycle behavior.
2. Confirm command and typed info-message parity against the Go-side and driver protocol fixtures.
3. Connect the Rust event pipeline to the existing driver through a test-only adapter.
4. Integrate bounded event processing with explicit backpressure and recovery.
5. Migrate selected service features behind an opt-in development switch.
6. Compare baseline and candidate on identical workloads.
7. Expand migration only after functional, security, and performance checks pass.

**Status: experimental foundation.** Production behavior is unchanged.

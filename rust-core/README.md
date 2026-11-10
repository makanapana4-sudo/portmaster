# Portmaster Rust Core (Experimental)

This directory is the starting point for an incremental Rust implementation of Portmaster's user-mode core.

It is intentionally separate from the existing Go service. The Go implementation remains the working reference and must not be removed or bypassed until the Rust implementation has demonstrated feature parity, security equivalence, and measured performance improvements.

## Current repository architecture

The repository already contains important Rust and native components:

- `windows_kext/driver`: Rust Windows kernel driver using the Windows Filtering Platform (WFP).
- `windows_kext/protocol`: Rust protocol crate associated with the driver.
- `windows_kext/kextinterface`: existing Go-side interface to the Windows driver.
- `desktop/tauri`: Tauri-based desktop application.
- Root Go modules and packages: the existing Portmaster user-mode service and its networking, DNS, filtering, configuration, and supporting functionality.

Do not duplicate or replace the existing WFP driver or Tauri desktop application without first documenting a concrete gap and validating compatibility.

## Goals

1. Build a modular Rust user-mode core that can eventually take over selected responsibilities from the Go service.
2. Preserve the existing Windows WFP integration and its protocol until a fully tested replacement is available.
3. Reduce idle CPU and memory usage based on repeatable benchmarks, not assumptions about programming languages.
4. Keep security behavior at least as strict as the current implementation.
5. Migrate incrementally, with the Go implementation remaining available as a reference and fallback.

## Non-goals for the initial milestone

- Do not replace the production Go service.
- Do not change driver installation, signing, loading, or startup behavior.
- Do not install or load experimental kernel drivers.
- Do not claim feature parity or performance improvements without tests and measurements.
- Do not remove Electron/Tauri or alter the current desktop application in this milestone.

## Migration rules

- Inspect the existing implementation before designing each Rust module.
- Record the corresponding Go packages, public behavior, configuration keys, and tests.
- Define stable Rust interfaces and explicit error behavior.
- Keep unsafe Rust isolated, small, and documented.
- Bound queues and caches; avoid unbounded background work.
- Use asynchronous I/O only where it improves the workload.
- Never silently disable filtering or fail open on security-critical errors.
- Do not weaken Windows Firewall, Microsoft Defender, or other host protections.
- Do not store credentials, tokens, or private user data in source control.

## Initial workspace

The first implementation milestone should establish a Cargo workspace and a small, testable library for shared core types and configuration validation. It must not connect to the live network stack or alter firewall rules.

Suggested structure:

```text
rust-core/
  Cargo.toml
  README.md
  crates/
    portmaster-core/
      Cargo.toml
      src/
        lib.rs
        config.rs
        connection.rs
        error.rs
```

Keep dependencies minimal. Prefer the standard library until a real requirement justifies an external crate.

## Required validation

Before considering this code usable:

- Run `cargo fmt --check`.
- Run `cargo clippy --workspace --all-targets -- -D warnings`.
- Run `cargo test --workspace`.
- Add tests for invalid configuration, boundary values, and error handling.
- On Windows, validate compatibility with the existing driver protocol in a test environment.
- Benchmark the original and Rust components under identical workloads, including idle, browsing, DNS-heavy, and high-connection scenarios.

## Status

**Experimental scaffold only.** No existing Portmaster functionality has been migrated yet. The current Go service remains authoritative.

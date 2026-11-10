# Performance Measurement

## Current measured status

There are no valid Portmaster launch-time, CPU, RAM, or throughput results for the Rust core yet. The Rust workspace is not started by the Portmaster service, so the current fork must not be described as a faster Portmaster build.

The cache and queue are reusable Rust components, but they have not replaced a production code path. This commit alone should not materially change the running Portmaster application's resource use.

## Compare equivalent builds

Compare baseline and candidate on the same Windows machine with the same driver, rules, blocklists, resolver, network, power mode, and workload. Separate cold starts from warm starts. Use at least three runs and compare medians.

| Measurement | What to record |
| --- | --- |
| Service startup | Process start to the same service-ready signal |
| UI startup | Process start to the same connected, usable UI state |
| Idle CPU | Average CPU after startup settles |
| Workload CPU | Average and peak CPU during browsing, DNS-heavy, and many-connection tests |
| Memory | Average and peak private bytes and working set |
| Responsiveness | DNS latency, connection-decision latency, and UI response |
| Stability | Errors, dropped events, memory growth, and long-running behavior |

Do not combine service and UI memory unless both builds use the same process boundaries.

## Windows process sampler

Run the sampler as an ordinary user against a process ID:

```powershell
powershell -ExecutionPolicy Bypass -File .\rust-core\tools\measure-process.ps1 -ProcessId 1234 -DurationSeconds 120
```

It writes a CSV of samples and a JSON summary alongside it. Run it separately for the baseline and candidate with the same duration and workload. CPU is reported as a percentage of total logical processor capacity; memory is reported in MiB.

The sampler does not measure application readiness or cold-start duration. Measure readiness from the same observable service/UI signal in both builds.

## Interpreting results

A language rewrite is not evidence by itself of lower resource use. Improvements depend on which code paths move, data structures, allocations, I/O, concurrency, logging, and compatibility layers. The existing Go service remains authoritative until migrated behavior passes feature and security tests.

Do not publish percentage improvements until repeatable measurements are available. A lower idle memory footprint is a target, not a measured result.

## Small production-path optimization included

The Go Windows driver command writer now serializes verdict, IPv4 update, and IPv6 update messages into fixed-size byte arrays rather than passing structs through `encoding/binary.Write`. This removes reflection-based struct serialization from those calls and reuses fixed-size stack-shaped buffers in the source code. The writer also handles partial writes and reports a zero-byte write as `io.ErrShortWrite`.

The change is protocol-preserving and has byte-layout and short-write tests. It affects driver control messages, not every packet, DNS lookup, or application startup. No allocation benchmark or end-to-end CPU saving has been measured yet, so do not extrapolate it into an overall Portmaster percentage.

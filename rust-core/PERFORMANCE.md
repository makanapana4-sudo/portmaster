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

## Protocol parsing safeguards and microbenchmarks

The Go driver-info parser now rejects frames larger than 16 MiB before attempting to read their body. It validates bandwidth-record counts against the remaining bytes in the declared frame before allocating a slice, checks every fixed-size read against the current frame boundary, and drains unread frame bytes in chunks rather than allocating a buffer equal to the remaining frame length. Fixed connection, end-event, and bandwidth records are decoded from fixed-size stack buffers with direct little-endian field reads instead of reflection-based struct decoding. Successful frames no longer build formatted error values on the hot path.

The Rust core now decodes all seven driver info message types. Connection packet payloads, log messages, and bandwidth record storage are borrowed from the original frame. Bandwidth records are decoded on demand by index or iterator, avoiding a second allocation for a slice of decoded records.

The Go command writer includes microbenchmarks comparing the fixed-buffer serialization against the previous `encoding/binary.Write` approach:

```sh
go test ./windows_kext/kextinterface -run '^$' -bench=Command -benchmem
```

Run the benchmarks on the same machine and Go version, and compare repeated runs. These microbenchmarks isolate the serialization function; they do not measure full Portmaster CPU usage or startup time.


The parser benchmarks can be run together with the command benchmarks:

```sh
go test ./windows_kext/kextinterface -run '^
```

The new fixed-offset decoder is intentionally benchmarked separately for a small IPv4 connection event and a 128-record bandwidth event. Compare against the pre-change build on the same Go version; do not infer whole-service savings from these isolated benchmarks.

The Rust core now has a generic driver transport adapter that connects command writes to incremental event reads. Its read path uses a fixed 16 KiB buffer, retries interrupted reads, reports nonblocking WouldBlock separately from EOF, and delegates framing to the bounded stream decoder. Its command path uses the fixed 39-byte stack encoder and Write::write_all. This adapter is platform-neutral; it deliberately does not open the Windows device or install/load a driver.
 -bench='(Command|RecvInfo)' -benchmem -count=3
```

The new fixed-offset decoder is intentionally benchmarked separately for a small IPv4 connection event and a 128-record bandwidth event. Compare against the pre-change build on the same Go version; do not infer whole-service savings from these isolated benchmarks.

The Rust core now has a generic driver transport adapter that connects command writes to incremental event reads. Its read path uses a fixed 16 KiB buffer, retries interrupted reads, reports nonblocking WouldBlock separately from EOF, and delegates framing to the bounded stream decoder. Its command path uses the fixed 39-byte stack encoder and Write::write_all. This adapter is platform-neutral; it deliberately does not open the Windows device or install/load a driver.


The decoder benchmarks now include reference cases that reproduce the previous reflection-based Go implementation using binary.Read for connection records and one call per bandwidth record. Compare the matching fixed-decoder and BinaryReadBaseline cases. The benchmark sinks keep the decoded output reachable so the compiler cannot remove the work.

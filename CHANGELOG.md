# Changelog

## [v0.10.0] - 2026-08-08

### Added

- PyPI now publishes native `linux/amd64` and `linux/arm64` wheels containing the CO-RE sidecar and precompiled BPF object. Linux installs can use `--backend core` directly after `pip install blocksnoop`; a portable wheel remains available for CLI and compatibility use on other platforms.
- CI and release gates inspect the wheel tags and ELF architectures, install both native wheels on matching runners, and verify the exact artifacts again after PyPI publication.

### Changed

- The official multi-architecture Docker image is now Core-only and installs Blocksnoop from a native wheel. Its runtime no longer contains BCC, kernel headers, build tools, or `uv`.
- Published Docker images are exercised on native amd64 and arm64 runners, including real Core collection and private PID-namespace integration.

## [v0.9.2] - 2026-08-08

### Fixed

- `blocksnoop doctor` now reports inaccessible tracefs/debugfs and BPF-object paths as actionable diagnostics instead of raising permission errors. It still finds usable tracepoints from another readable mount.

## [v0.9.1] - 2026-08-08

### Fixed

- Release smoke checks now wait until the exact PyPI package is installable through the Simple Index, rather than relying only on the JSON API. The diagnostics check preserves its JSON report in a file and validates it with the installed package environment, while source-distribution inspection no longer uses a pipe that can fail spuriously.

## [v0.9.0] - 2026-08-08

### Added

- `blocksnoop doctor [PID]` reports backend readiness without attaching BPF or spawning the native collector. Text and JSON output cover BTF, tracepoints, effective capabilities, sidecar/object availability, BCC, and target PID-namespace identity.
- Both detector backends expose lost-event counters. Core validates per-source deltas from the sidecar and drains records already in flight during shutdown.

### Changed

- The Core sidecar protocol is now v2. Python resolves the target namespace device/inode and namespace-local PID/TID before spawn; eBPF filters with `bpf_get_ns_current_pid_tgid`, bringing Core parity to hostPID collectors monitoring processes in private container PID namespaces.
- Release publication is ordered and verified from the registries: exact PyPI hashes/install, Docker revision/digest, amd64+arm64 manifest, live Core workload, and a remote-image private-PID-namespace test.

### Known limitations

- Core remains explicit with `--backend core`; BCC is still the default compatibility backend.
- The portable PyPI wheel does not yet bundle a native sidecar. The official Docker image contains the amd64/arm64 collector and BPF object.

## [v0.8.0] - 2026-08-08

### Added

- Experimental `--backend core` support backed by a small libbpf sidecar and a precompiled, BTF-enabled eBPF object. The official Docker image builds the native collector for both amd64 and arm64.
- A versioned NDJSON protocol between Python and `blocksnoop-ebpf`, including explicit readiness, blocking events, lost-event notifications, and fatal startup errors.

### Changed

- Detector selection now goes through a shared backend protocol and factory. BCC remains the default and compatibility backend; selecting Core is explicit and never falls back silently.
- BCC compilation and attachment are deferred until detector startup, so the Core path neither imports nor requires BCC.

### Known limitations

- The first Core backend supports targets in the same PID namespace as blocksnoop. Cross-PID-namespace translation remains on the BCC backend until the next migration stage.
- PyPI continues to ship the portable Python and BPF sources, but not a platform-specific native sidecar yet. Use the official Docker image or build `native/blocksnoop-ebpf` on Linux to try `--backend core`.

## [v0.7.3] - 2026-08-08

### Fixed

- The PyPI wheel and source distribution now include the eBPF program used at runtime, so `pip install blocksnoop` can load `blocksnoop/bpf/blockdetect.c` outside a source checkout. CI builds and installs the wheel in a clean environment to prevent regressions.
- `--tid` now filters events in the eBPF program as well as Austin samples. Thread IDs are translated through `NSpid` for cross-PID-namespace attaches.
- Cross-namespace Austin wrappers are created atomically with private permissions and safely quote paths before invoking the shell.

## [v0.7.2] - 2026-06-10

### Fixed

- Detector traced only `epoll_wait` and silently emitted nothing on loops whose event loop enters a different epoll syscall — the "attaches fine, Austin samples, but no events come out" failure. `_detect_epoll_syscall` picked the first syscall whose *tracepoint existed* (always `epoll_wait` on modern kernels) rather than the one the *target* actually calls, so loops on glibc (which routes `epoll_wait()` through the `epoll_pwait` syscall) or uvloop/libuv (which calls `epoll_pwait`/`epoll_pwait2` directly) were never timed. The BPF program now generates a `sys_enter`/`sys_exit` probe pair for **every** epoll variant available on the kernel, sharing one `callback_start` map, so detection is independent of the libc/loop's syscall choice. Reproduced against a production uvloop worker (event loop on `epoll_pwait`, syscall 281).

### Fixed

- Cross-PID-namespace attach (e.g. `hostPID: true` Job targeting a container with its own PID namespace): the BPF tgid filter was comparing against the host PID while `bpf_get_ns_current_pid_tgid()` returned the namespace-local PID, so every event was filtered out. Austin also received the host PID instead of the container-local one and couldn't attach, with all samples rejected as "wrong tid". The nsenter wrapper now also enters the target's PID namespace (`nsenter -m -p`), and both PID and TID passed to Austin are translated to their namespace-local form (via `/proc/<pid>/status` NSpid).

## [v0.7.0] - 2026-05-12

### Changed

- Cross-namespace Austin attach no longer writes any files into the target container — uses shell fd redirection (`/proc/self/fd/N`) instead of copying the Austin binary and musl linker into the target's rootfs. Works against hardened targets with `readOnlyRootFilesystem: true`, regardless of the target's libc (alpine/musl, debian/glibc, distroless).

### Added

- README section documenting cross-container attach behavior and constraints
- `examples/reproduce-cross-ns.sh`: runnable Docker reproduction of the cross-mount-namespace attach scenario
- `.mise.toml`: uv integration for local development

## [v0.6.2] - 2026-03-03

### Fixed

- nsenter wrapper now also copies the musl dynamic linker into the target container, fixing Austin execution when the target image has no musl runtime (e.g. glibc-only Python images)

## [v0.6.1] - 2026-03-03

### Fixed

- nsenter wrapper now copies Austin binary into target container's filesystem, fixing `No such file or directory` when profiling across mount namespaces (e.g. `kubectl debug`)

## [v0.6.0] - 2026-03-03

### Added

- Auto-detect mount namespace mismatch and wrap Austin with `nsenter -m` so stack profiling works in cross-container scenarios (e.g. `kubectl debug`)

## [v0.5.3] - 2026-03-03

### Fixed

- Docker: Austin binary now works on Debian Bookworm (switched to musl build + installed musl runtime)
- Clean shutdown when Austin fails to start (`AustinError` no longer logs tracebacks)

## [v0.5.2] - 2026-03-03

### Added

- Austin lifecycle logging: metadata events on attach, termination summary, and 3-second health check warning when no samples are received

### Fixed

- Clean Ctrl+C shutdown: suppress expected `ValueError` from Austin's MOJO parser when pipe is interrupted

## [v0.5.1] - 2026-02-27

### Fixed

- PID namespace mismatch: use `bpf_get_ns_current_pid_tgid()` (kernel 5.7+) so container-local PIDs are resolved correctly without `hostPID: true`
- Stats display corruption when child stdout interleaves or line count changes between empty and data states (fixed line count + output to stderr)

## [v0.5.0] - 2026-02-27

### Added

- `--stats` mode: run only the eBPF detector to capture all epoll gaps and display live distribution statistics (count, min, avg, p50, p90, p95, p99, max, events/s)
- Stats mode supports `--json` for machine-readable output (one JSON line per second)
- Stats mode skips Austin profiler requirement, making it easier to get started

### Changed

- `--threshold` default is now `0` in stats mode (capture all gaps) and `100` in normal mode

## [v0.4.0] - 2026-02-27

### Added

- Source code lines displayed inline in stack traces (console and JSON output)

## [v0.3.0] - 2026-02-27

### Added

- Comprehensive verbose logging (`-v`) across the full pipeline: CLI startup banner, Austin sampling stats, correlation results, eBPF thread lifecycle
- Austin sample counters (accepted/filtered/overflow) logged periodically and at shutdown
- Diagnostic log when no Python stacks are found for a blocking event, with buffer fill level for quick troubleshooting

## [v0.2.0] - 2026-02-26

### Added

- Auto-detect and symlink kernel headers in Python, fixing `kubectl debug` usage where `docker-entrypoint.sh` was bypassed

### Changed

- README Kubernetes ephemeral container example now uses `--profile=sysadmin` for eBPF access

### Removed

- `docker-entrypoint.sh` — kernel header logic moved into `detector.py`

## [v0.1.1] - 2026-02-23

### Added

- Docker Hub publishing in release workflow (multi-arch: amd64, arm64) as `oloapm/blocksnoop`
- `.dockerignore` to reduce Docker build context size

### Changed

- Dockerfile optimized for production (no dev dependencies)
- README Kubernetes examples now reference `oloapm/blocksnoop` Docker Hub image

## [v0.1.0] - 2026-02-23

### Changed

- Renamed package from `loopspy` to `blocksnoop` (CLI command, pip install name, import paths, Docker service)
- Changed license from MIT to GPL-3.0-or-later

### Added

- CI workflow (lint, type check, unit tests on Python 3.12/3.13)
- Release workflow (build + publish to PyPI on tag push)

### Fixed

- Fixed type checker errors in `cli.py` (pid narrowing, bcc import suppression)

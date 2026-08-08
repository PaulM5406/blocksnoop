# Changelog

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

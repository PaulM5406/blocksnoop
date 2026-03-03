# Changelog

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

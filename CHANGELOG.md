# Changelog

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

# Changelog

## [Unreleased]

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

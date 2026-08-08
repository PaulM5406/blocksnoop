#!/usr/bin/env python3
"""Fail-closed attestation of the kernel visible to a Core test container.

This is deliberately a small standard-library probe.  It does not claim that
an arbitrary GitHub-hosted runner has a particular kernel: callers may supply
the expected architecture and major/minor release, and the command fails when
the running kernel differs or a Core prerequisite is not visible.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import struct
import sys
from pathlib import Path
from typing import Any


TRACEFS_ROOTS = (
    Path("/sys/kernel/tracing/events/syscalls"),
    Path("/sys/kernel/debug/tracing/events/syscalls"),
)
EPOLL_SYSCALLS = ("epoll_wait", "epoll_pwait", "epoll_pwait2")
BTF_MAGIC = 0xEB9F
BTF_HEADER_SIZE = 24


def _readable(path: Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.R_OK)
    except OSError:
        return False


def _btf_check() -> dict[str, Any]:
    path = Path("/sys/kernel/btf/vmlinux")
    result: dict[str, Any] = {"path": str(path), "readable": _readable(path)}
    if not result["readable"]:
        result["error"] = "kernel BTF is not readable"
        return result
    try:
        header = path.read_bytes()[:BTF_HEADER_SIZE]
    except OSError as exc:
        result["error"] = str(exc)
        return result
    if len(header) < BTF_HEADER_SIZE:
        result["error"] = "kernel BTF header is truncated"
        return result
    magic, version, flags, header_len = struct.unpack_from("<HBBI", header)
    result.update(
        {
            "magic": f"0x{magic:04x}",
            "version": version,
            "flags": flags,
            "header_len": header_len,
            "valid": magic == BTF_MAGIC
            and version == 1
            and header_len >= BTF_HEADER_SIZE,
        }
    )
    if not result["valid"]:
        result["error"] = "kernel BTF header has an unexpected magic, version, or size"
    return result


def _tracepoint_check() -> dict[str, Any]:
    roots: list[dict[str, Any]] = []
    complete_pairs: list[str] = []
    for root in TRACEFS_ROOTS:
        pairs = [
            syscall
            for syscall in EPOLL_SYSCALLS
            if _readable(root / f"sys_enter_{syscall}" / "format")
            and _readable(root / f"sys_exit_{syscall}" / "format")
        ]
        roots.append({"path": str(root), "pairs": pairs})
        complete_pairs.extend(pair for pair in pairs if pair not in complete_pairs)
    return {
        "roots": roots,
        "complete_pairs": complete_pairs,
        "valid": bool(complete_pairs),
    }


def _capabilities() -> str | None:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return None


def _kernel_config() -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for name in ("unprivileged_bpf_disabled", "unprivileged_userns_clone"):
        path = Path("/proc/sys/kernel") / name
        try:
            result[name] = path.read_text().strip()
        except OSError:
            result[name] = None
    return result


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-arch", metavar="ARCH")
    parser.add_argument(
        "--require-kernel-prefix",
        metavar="MAJOR.MINOR",
        help="fail unless uname -r starts with this exact major.minor prefix",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    release = platform.release()
    architecture = platform.machine()
    btf = _btf_check()
    tracepoints = _tracepoint_check()
    failures: list[str] = []
    if args.require_arch and architecture != args.require_arch:
        failures.append(
            f"architecture is {architecture!r}, expected {args.require_arch!r}"
        )
    if args.require_kernel_prefix and not release.startswith(
        f"{args.require_kernel_prefix}."
    ):
        failures.append(
            f"kernel release is {release!r}, expected {args.require_kernel_prefix!r}.x"
        )
    if not tracepoints["valid"]:
        failures.append("no readable complete epoll syscall tracepoint pair")

    report = {
        "schema": "blocksnoop.kernel-contract/v1",
        "kernel_release": release,
        "architecture": architecture,
        "effective_capabilities": _capabilities(),
        "kernel_settings": _kernel_config(),
        "btf": btf,
        "tracepoints": tracepoints,
        "status": "pass" if not failures else "fail",
        "failures": failures,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if failures:
        for failure in failures:
            print(f"kernel contract failed: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Unprivileged black-box checks for the native sidecar CLI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run(binary: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [binary, *args],
        check=False,
        capture_output=True,
        text=True,
    )


def main() -> int:
    binary = str(Path(sys.argv[1]).resolve())

    help_result = run(binary, "--help")
    assert help_result.returncode == 0, help_result.stderr
    assert "--protocol-version 2" in help_result.stdout
    assert "--threshold-ns" in help_result.stdout
    assert "--pidns-dev" in help_result.stdout

    missing_protocol = run(
        binary,
        "--pid",
        "1",
        "--tid",
        "1",
        "--pidns-dev",
        "1",
        "--pidns-ino",
        "1",
        "--threshold-ns",
        "0",
    )
    assert missing_protocol.returncode == 2
    assert missing_protocol.stdout == ""

    wrong_protocol = run(
        binary,
        "--protocol-version",
        "1",
        "--pid",
        "1",
        "--tid",
        "1",
        "--pidns-dev",
        "1",
        "--pidns-ino",
        "1",
        "--threshold-ns",
        "0",
    )
    assert wrong_protocol.returncode == 2
    assert wrong_protocol.stdout == ""

    invalid_pid = run(
        binary,
        "--protocol-version",
        "2",
        "--pid",
        "0",
        "--tid",
        "1",
        "--pidns-dev",
        "1",
        "--pidns-ino",
        "1",
        "--threshold-ns",
        "0",
    )
    assert invalid_pid.returncode == 2
    assert invalid_pid.stdout == ""

    negative_threshold = run(
        binary,
        "--protocol-version",
        "2",
        "--pid",
        "1",
        "--tid",
        "1",
        "--pidns-dev",
        "1",
        "--pidns-ino",
        "1",
        "--threshold-ns",
        "-1",
    )
    assert negative_threshold.returncode == 2
    assert negative_threshold.stdout == ""

    missing_namespace = run(
        binary,
        "--protocol-version",
        "2",
        "--pid",
        "1",
        "--tid",
        "1",
        "--threshold-ns",
        "0",
    )
    assert missing_namespace.returncode == 2
    assert missing_namespace.stdout == ""
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

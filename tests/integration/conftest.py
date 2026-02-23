"""Test infrastructure for Docker-based integration tests."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field

import pytest


@dataclass
class BlocksnoopResult:
    exit_code: int
    stdout: str
    stderr: str
    events: list[dict] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)


def run_blocksnoop_docker(
    fixture: str,
    timeout_s: int = 8,
    threshold_ms: int = 100,
    extra_args: list[str] | None = None,
) -> BlocksnoopResult:
    """Run blocksnoop in Docker against a test fixture, return parsed result."""
    cmd = [
        "docker",
        "compose",
        "run",
        "--rm",
        "blocksnoop",
        "timeout",
        "--signal=TERM",
        str(timeout_s),
        "blocksnoop",
        "--json",
        "-t",
        str(threshold_ms),
    ]
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(["--", "python", fixture])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 30)

    raw_lines = proc.stdout.strip().splitlines() if proc.stdout.strip() else []
    events: list[dict] = []
    for line in raw_lines:
        try:
            events.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue  # skip summary lines or partial output on SIGTERM

    return BlocksnoopResult(
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        events=events,
        raw_lines=raw_lines,
    )


@pytest.fixture(scope="session")
def docker_image():
    """Build the Docker image once per session. Skip if Docker unavailable."""
    if not shutil.which("docker"):
        pytest.skip("Docker not available")

    # Check Docker daemon is running
    check = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        timeout=10,
    )
    if check.returncode != 0:
        pytest.skip("Docker daemon not running")

    # Build the image
    result = subprocess.run(
        ["docker", "compose", "build"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        pytest.skip(f"Docker build failed: {result.stderr[:500]}")

    return True

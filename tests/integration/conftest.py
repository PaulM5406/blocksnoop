"""Test infrastructure for Docker-based integration tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

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
    remote_image = os.environ.get("BLOCKSNOOP_TEST_IMAGE")
    if remote_image:
        cmd = [
            "docker",
            "run",
            "--rm",
            "--privileged",
            "--pid=host",
            "-v",
            "/sys/kernel/debug:/sys/kernel/debug",
            remote_image,
            "timeout",
            "--signal=TERM",
            str(timeout_s),
            "blocksnoop",
            "--json",
            "-t",
            str(threshold_ms),
        ]
    else:
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
    # The Core-only image intentionally excludes the repository tests. Pass
    # fixture source as an argv value for both local and published images.
    cmd.extend(["--", "python", "-c", Path(fixture).read_text()])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 30)

    raw_lines = proc.stdout.strip().splitlines() if proc.stdout.strip() else []
    events: list[dict] = []
    for line in raw_lines:
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue  # skip summary lines or partial output on SIGTERM
        # v1 NDJSON has multiple record types.  Only blocking_event records
        # have the event fields asserted by integration tests; session start
        # and summary records are successful protocol output, not detections.
        if isinstance(record, dict) and record.get("type") == "blocking_event":
            events.append(record)

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
    remote_image = os.environ.get("BLOCKSNOOP_TEST_IMAGE")
    if not shutil.which("docker"):
        if remote_image:
            pytest.fail("Docker is required to smoke BLOCKSNOOP_TEST_IMAGE")
        pytest.skip("Docker not available")

    # Check Docker daemon is running
    try:
        check = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        if remote_image:
            pytest.fail("Docker daemon timed out while smoking BLOCKSNOOP_TEST_IMAGE")
        pytest.skip("Docker daemon did not respond within 10 seconds")
    if check.returncode != 0:
        if remote_image:
            pytest.fail("Docker daemon is required to smoke BLOCKSNOOP_TEST_IMAGE")
        pytest.skip("Docker daemon not running")

    if remote_image:
        result = subprocess.run(
            ["docker", "pull", remote_image],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            pytest.fail(f"Could not pull BLOCKSNOOP_TEST_IMAGE: {result.stderr[:500]}")
        return remote_image

    # Build the image — try `docker compose` (v2 plugin) first, fall back to
    # `docker-compose` (standalone binary) so this works on machines where
    # either is installed.
    for compose_cmd in (["docker", "compose"], ["docker-compose"]):
        if compose_cmd[0] == "docker-compose" and not shutil.which("docker-compose"):
            continue
        result = subprocess.run(
            [*compose_cmd, "build"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            return "blocksnoop-blocksnoop:latest"
        # If it's "unknown command" we fall through to the next compose impl;
        # any other error is a real build failure → skip with diagnostics.
        if "unknown" not in (result.stderr or "").lower():
            pytest.skip(f"Docker build failed: {result.stderr[:500]}")
    pytest.skip("No working `docker compose` or `docker-compose` found")


@pytest.fixture(scope="session")
def docker_client():
    """Return a docker.from_env() client, or skip if Docker is unreachable.

    Used by integration tests that need fine-grained container topology
    (e.g. `pid_mode="host"` or custom volume/network setup) which the
    existing subprocess-based `run_blocksnoop_docker` helper doesn't expose.
    """
    remote_image = os.environ.get("BLOCKSNOOP_TEST_IMAGE")
    try:
        import docker  # type: ignore[import-not-found]
    except ImportError:
        if remote_image:
            pytest.fail("Docker SDK is required to smoke BLOCKSNOOP_TEST_IMAGE")
        pytest.skip("docker SDK not installed (add to dev deps)")

    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # noqa: BLE001 — any failure means we skip
        if remote_image:
            pytest.fail(f"Docker SDK is required to smoke BLOCKSNOOP_TEST_IMAGE: {exc}")
        pytest.skip(f"Docker daemon not reachable via SDK: {exc}")
    return client

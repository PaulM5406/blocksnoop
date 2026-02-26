"""Integration tests for CLI behavior."""

import json
import subprocess

import pytest

pytestmark = pytest.mark.docker


def test_no_args_shows_error(docker_image):
    """Running blocksnoop with no arguments should fail with usage info."""
    proc = subprocess.run(
        ["docker", "compose", "run", "--rm", "blocksnoop", "blocksnoop"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0
    combined = (proc.stdout + proc.stderr).lower()
    assert "usage" in combined or "error" in combined


def test_human_readable_output(docker_image):
    """Without --json, console output goes to stderr and contains BLOCKED markers."""
    proc = subprocess.run(
        [
            "docker",
            "compose",
            "run",
            "--rm",
            "blocksnoop",
            "timeout",
            "--signal=TERM",
            "8",
            "blocksnoop",
            "-t",
            "100",
            "--",
            "python",
            "tests/fixtures/blocking_io.py",
        ],
        capture_output=True,
        text=True,
        timeout=40,
    )
    assert "BLOCKED" in proc.stderr, (
        f"Expected 'BLOCKED' in stderr output, got:\nstderr={proc.stderr[:500]}\nstdout={proc.stdout[:500]}"
    )


def test_log_file_output(docker_image):
    """--log-file writes Datadog-compatible JSON lines to the specified file."""
    proc = subprocess.run(
        [
            "docker",
            "compose",
            "run",
            "--rm",
            "blocksnoop",
            "sh",
            "-c",
            "timeout --signal=TERM 8 "
            "blocksnoop --log-file /tmp/blocksnoop_test.json --service test-svc --env ci "
            "-t 100 -- python tests/fixtures/blocking_io.py; "
            "cat /tmp/blocksnoop_test.json",
        ],
        capture_output=True,
        text=True,
        timeout=40,
    )
    # The cat output appears on stdout
    lines = [line for line in proc.stdout.strip().splitlines() if line.strip()]
    assert len(lines) >= 1, (
        f"Expected JSON lines in log file, got:\n{proc.stdout[:500]}"
    )

    for line in lines:
        record = json.loads(line)
        assert "timestamp" in record
        assert "level" in record
        assert record["source"] == "blocksnoop"
        assert record["dd"]["service"] == "test-svc"
        assert record["dd"]["env"] == "ci"

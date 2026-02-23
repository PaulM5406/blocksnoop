"""Integration tests for CPU-bound blocking detection."""

import pytest

from tests.integration.conftest import run_blocksnoop_docker

pytestmark = pytest.mark.docker

FIXTURE = "tests/fixtures/blocking_cpu.py"


@pytest.fixture(scope="module")
def cpu_result(docker_image):
    return run_blocksnoop_docker(FIXTURE, timeout_s=10, threshold_ms=100)


def test_detects_cpu_blocking(cpu_result):
    assert (
        len(cpu_result.events) >= 1
    ), f"Expected at least 1 event, got {len(cpu_result.events)}"


def test_duration_above_threshold(cpu_result):
    for event in cpu_result.events:
        assert (
            event["duration_ms"] >= 100
        ), f"Event duration {event['duration_ms']}ms below 100ms threshold"


def test_stack_contains_cpu_heavy(cpu_result):
    """At least one event's stack should reference cpu_heavy."""
    stacks_with_match = []
    for event in cpu_result.events:
        stacks = event.get("python_stacks")
        if not stacks:
            continue
        for stack in stacks:
            for frame in stack:
                if "cpu_heavy" in frame.get("function", "") or "cpu_heavy" in frame.get(
                    "file", ""
                ):
                    stacks_with_match.append(event)
                    break

    if not any(e.get("python_stacks") for e in cpu_result.events):
        pytest.skip("No stacks captured in this run")

    assert len(stacks_with_match) > 0, "No stack referenced cpu_heavy"

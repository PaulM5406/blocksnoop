"""Integration tests for blocking I/O detection."""

import pytest

from tests.integration.conftest import run_loopspy_docker

pytestmark = pytest.mark.docker

FIXTURE = "tests/fixtures/blocking_io.py"


@pytest.fixture(scope="module")
def io_result(docker_image):
    return run_loopspy_docker(FIXTURE, timeout_s=8, threshold_ms=100)


def test_detects_blocking_events(io_result):
    assert len(io_result.events) >= 2, (
        f"Expected at least 2 events, got {len(io_result.events)}"
    )


def test_duration_above_threshold(io_result):
    for event in io_result.events:
        assert event["duration_ms"] >= 100, (
            f"Event duration {event['duration_ms']}ms below 100ms threshold"
        )


def test_duration_in_expected_range(io_result):
    """blocking_io.py sleeps 300ms, so durations should be 200–600ms."""
    for event in io_result.events:
        assert 200 <= event["duration_ms"] <= 600, (
            f"Duration {event['duration_ms']}ms outside expected 200–600ms range"
        )


def test_json_schema(io_result):
    assert len(io_result.events) > 0
    for event in io_result.events:
        assert isinstance(event["event_number"], int)
        assert isinstance(event["timestamp_s"], (int, float))
        assert isinstance(event["duration_ms"], (int, float))
        assert isinstance(event["pid"], int)
        assert isinstance(event["tid"], int)
        assert "python_stack" in event


def test_stack_contains_blocking_function(io_result):
    """At least one event's stack should reference blocking_io."""
    stacks_with_match = []
    for event in io_result.events:
        stack = event.get("python_stack")
        if stack is None:
            continue
        for frame in stack:
            if "blocking_io" in frame.get("function", "") or "blocking_io" in frame.get("file", ""):
                stacks_with_match.append(event)
                break

    if not any(e.get("python_stack") for e in io_result.events):
        pytest.skip("No stacks captured in this run")

    assert len(stacks_with_match) > 0, "No stack referenced blocking_io"


def test_high_threshold_no_events(docker_image):
    """With threshold above the 300ms sleep, no events should be detected."""
    result = run_loopspy_docker(FIXTURE, timeout_s=8, threshold_ms=500)
    assert len(result.events) == 0, (
        f"Expected 0 events with 500ms threshold, got {len(result.events)}"
    )

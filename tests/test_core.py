"""Unit tests for loopspy.core data structures."""

import pytest

from loopspy.core import BlockingEvent, DetectorConfig, PythonStackTrace, StackFrame


def test_stack_frame_frozen():
    frame = StackFrame(function="my_func", file="app.py", line=10)
    assert frame.function == "my_func"
    assert frame.file == "app.py"
    assert frame.line == 10
    with pytest.raises(AttributeError):
        frame.function = "other"  # type: ignore[misc]


def test_python_stack_trace():
    frames = (
        StackFrame(function="inner", file="app.py", line=5),
        StackFrame(function="outer", file="app.py", line=20),
    )
    stack = PythonStackTrace(thread_id=1234, thread_name="MainThread", frames=frames)
    assert stack.thread_id == 1234
    assert stack.thread_name == "MainThread"
    assert len(stack.frames) == 2
    assert stack.frames[0].function == "inner"


def test_blocking_event_duration_ms():
    event = BlockingEvent(start_ns=0, end_ns=150_000_000, pid=1, tid=1)
    assert event.duration_ms == 150.0


def test_blocking_event_no_stack():
    event = BlockingEvent(start_ns=0, end_ns=1_000_000, pid=1, tid=1)
    assert event.python_stack is None


def test_detector_config_defaults():
    config = DetectorConfig(pid=1234)
    assert config.tid == 1234
    assert config.sample_interval_ms == config.threshold_ms / 3


def test_detector_config_custom_tid():
    config = DetectorConfig(pid=1234, tid=5678)
    assert config.tid == 5678

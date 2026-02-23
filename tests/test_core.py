"""Unit tests for blocksnoop.core data structures."""

import pytest

from blocksnoop.core import BlockingEvent, DetectorConfig, PythonStackTrace, StackFrame


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


def test_blocking_event_no_stacks():
    event = BlockingEvent(start_ns=0, end_ns=1_000_000, pid=1, tid=1)
    assert event.python_stacks == ()


def test_blocking_event_with_stacks():
    stack = PythonStackTrace(
        thread_id=1,
        thread_name="main",
        frames=(StackFrame(function="f", file="f.py", line=1),),
    )
    event = BlockingEvent(
        start_ns=0, end_ns=1_000_000, pid=1, tid=1, python_stacks=(stack,)
    )
    assert len(event.python_stacks) == 1
    assert event.python_stacks[0].frames[0].function == "f"


def test_detector_config_defaults():
    config = DetectorConfig(pid=1234)
    assert config.tid == 1234
    assert config.sample_interval_ms == config.threshold_ms / 3


def test_detector_config_custom_tid():
    config = DetectorConfig(pid=1234, tid=5678)
    assert config.tid == 5678


def test_detector_config_correlation_padding_default():
    config = DetectorConfig(pid=1234)
    assert config.correlation_padding_ms == 200.0


def test_detector_config_correlation_padding_custom():
    config = DetectorConfig(pid=1234, correlation_padding_ms=50.0)
    assert config.correlation_padding_ms == 50.0

"""Unit tests for loopspy.profiler (no root, eBPF, or py-spy required)."""

from unittest.mock import patch

import pytest

from loopspy.core import PythonStackTrace, StackFrame
from loopspy.profiler import StackRingBuffer, _parse_pyspy_output, check_pyspy_available

RAW_PYSPY_OUTPUT = """\
Thread 12345 (active): "MainThread"
    cpu_heavy (app.py:42)
    main (app.py:30)
"""


def _make_stack(thread_id: int = 1, name: str = "T") -> PythonStackTrace:
    return PythonStackTrace(
        thread_id=thread_id,
        thread_name=name,
        frames=(StackFrame(function="f", file="f.py", line=1),),
    )


# --- StackRingBuffer ---


def test_ring_buffer_push_and_find():
    buf = StackRingBuffer(size=8)
    s100 = _make_stack(1, "t100")
    s200 = _make_stack(2, "t200")
    s300 = _make_stack(3, "t300")
    buf.push(100, s100)
    buf.push(200, s200)
    buf.push(300, s300)
    result = buf.find_in_range(150, 250)
    assert result is s200


def test_ring_buffer_overflow():
    buf = StackRingBuffer(size=3)
    stacks = [_make_stack(i) for i in range(5)]
    for i, s in enumerate(stacks):
        buf.push(i * 100, s)
    # Oldest entries (0, 1) should be gone; newest (2, 3, 4) should be findable
    assert buf.find_in_range(0, 100) is None
    assert buf.find_in_range(200, 250) is stacks[2]
    assert buf.find_in_range(400, 450) is stacks[4]


def test_ring_buffer_find_no_match():
    buf = StackRingBuffer(size=8)
    buf.push(100, _make_stack())
    buf.push(200, _make_stack())
    result = buf.find_in_range(500, 600)
    assert result is None


def test_ring_buffer_empty():
    buf = StackRingBuffer(size=8)
    assert buf.find_in_range(0, 1000) is None


# --- _parse_pyspy_output ---


def test_parse_pyspy_output():
    result = _parse_pyspy_output(RAW_PYSPY_OUTPUT, tid=12345)
    assert result is not None
    assert result.thread_id == 12345
    assert result.thread_name == "MainThread"
    assert len(result.frames) == 2
    assert result.frames[0].function == "cpu_heavy"
    assert result.frames[0].file == "app.py"
    assert result.frames[0].line == 42
    assert result.frames[1].function == "main"
    assert result.frames[1].line == 30


def test_parse_pyspy_output_wrong_tid():
    result = _parse_pyspy_output(RAW_PYSPY_OUTPUT, tid=99999)
    assert result is None


# --- check_pyspy_available ---


def test_check_pyspy_available():
    with patch("shutil.which", return_value="/usr/bin/py-spy"):
        assert check_pyspy_available() is True

    with patch("shutil.which", return_value=None):
        assert check_pyspy_available() is False

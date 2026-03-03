"""Unit tests for blocksnoop.profiler (no root, eBPF, or external tools required)."""

import logging
from unittest.mock import patch

from austin.stats import AustinFrame, AustinMetrics, AustinSample

from blocksnoop.core import PythonStackTrace, StackFrame
from blocksnoop.profiler import (
    AustinSampler,
    StackRingBuffer,
    _LoopspyAustin,
    _in_same_mount_ns,
    check_austin_available,
)


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


def test_ring_buffer_find_all_in_range():
    buf = StackRingBuffer(size=8)
    s100 = _make_stack(1, "t100")
    s200 = _make_stack(2, "t200")
    s300 = _make_stack(3, "t300")
    s400 = _make_stack(4, "t400")
    buf.push(100, s100)
    buf.push(200, s200)
    buf.push(300, s300)
    buf.push(400, s400)
    # Range [150, 350] should return s200, s300
    result = buf.find_all_in_range(150, 350)
    assert result == [s200, s300]


def test_ring_buffer_find_all_in_range_empty():
    buf = StackRingBuffer(size=8)
    assert buf.find_all_in_range(0, 1000) == []


def test_ring_buffer_find_all_in_range_no_match():
    buf = StackRingBuffer(size=8)
    buf.push(100, _make_stack())
    assert buf.find_all_in_range(500, 600) == []


def test_ring_buffer_find_nearest():
    buf = StackRingBuffer(size=8)
    s100 = _make_stack(1, "early")
    s500 = _make_stack(2, "mid")
    s900 = _make_stack(3, "late")
    buf.push(100, s100)
    buf.push(500, s500)
    buf.push(900, s900)
    # Target 480 within [0, 1000] → closest to 500
    assert buf.find_nearest(target_ns=480, start_ns=0, end_ns=1000) is s500
    # Target 850 within [0, 1000] → closest to 900
    assert buf.find_nearest(target_ns=850, start_ns=0, end_ns=1000) is s900


# --- check_austin_available ---


def test_check_austin_available():
    with patch("shutil.which", return_value="/usr/local/bin/austin"):
        assert check_austin_available() is True

    with patch("shutil.which", return_value=None):
        assert check_austin_available() is False


# --- _LoopspyAustin.on_sample ---


def _make_austin_sample(tid_hex: str, frames: tuple[AustinFrame, ...] | None = None):
    return AustinSample(
        pid=100,
        iid=None,
        thread=tid_hex,
        metrics=AustinMetrics(time=100),
        frames=frames,
    )


def test_loopspy_austin_on_sample_pushes_matching_tid():
    buf = StackRingBuffer()
    austin = _LoopspyAustin.__new__(_LoopspyAustin)
    austin._ring_buffer = buf
    austin._tid = 0x64  # 100 decimal
    austin.sample_count = 0
    austin.filtered_count = 0

    sample = _make_austin_sample(
        "64",
        frames=(
            AustinFrame(filename="app.py", function="my_func", line=10),
            AustinFrame(filename="lib.py", function="other", line=20),
        ),
    )
    austin.on_sample(sample)

    entries = buf._ordered_entries()
    assert len(entries) == 1
    stack = entries[0][1]
    assert stack.thread_id == 100
    assert len(stack.frames) == 2
    assert stack.frames[0].function == "my_func"
    assert stack.frames[0].file == "app.py"
    assert stack.frames[0].line == 10
    assert stack.frames[1].function == "other"
    assert stack.frames[1].file == "lib.py"


def test_loopspy_austin_on_sample_skips_wrong_tid():
    buf = StackRingBuffer()
    austin = _LoopspyAustin.__new__(_LoopspyAustin)
    austin._ring_buffer = buf
    austin._tid = 100
    austin.sample_count = 0
    austin.filtered_count = 0

    sample = _make_austin_sample(
        "ff",
        frames=(AustinFrame(filename="a.py", function="f", line=1),),
    )
    austin.on_sample(sample)

    assert len(buf._ordered_entries()) == 0


def test_loopspy_austin_on_sample_skips_no_frames():
    buf = StackRingBuffer()
    austin = _LoopspyAustin.__new__(_LoopspyAustin)
    austin._ring_buffer = buf
    austin._tid = 100
    austin.sample_count = 0
    austin.filtered_count = 0

    sample = _make_austin_sample("64", frames=None)
    austin.on_sample(sample)

    assert len(buf._ordered_entries()) == 0


# --- AustinSampler lifecycle (mocked ThreadedAustin) ---


def test_austin_sampler_start_stop():
    """AustinSampler creates _LoopspyAustin, starts it, and stops cleanly."""
    with (
        patch.object(_LoopspyAustin, "start") as mock_start,
        patch.object(_LoopspyAustin, "terminate") as mock_terminate,
        patch.object(_LoopspyAustin, "join") as mock_join,
    ):
        sampler = AustinSampler(pid=100, sample_interval_ms=33, tid=100)
        sampler.start()

        mock_start.assert_called_once_with(
            [
                "-i",
                "33000",
                "-p",
                "100",
            ]
        )
        assert sampler._austin is not None

        # Simulate austin pushing samples via on_sample
        sampler._austin.on_sample(
            _make_austin_sample(
                "64",
                frames=(AustinFrame(filename="app.py", function="my_func", line=10),),
            )
        )
        sampler._austin.on_sample(
            _make_austin_sample(
                "64",
                frames=(AustinFrame(filename="lib.py", function="other", line=20),),
            )
        )

        sampler.stop()
        mock_terminate.assert_called_once()
        mock_join.assert_called_once_with(timeout=5)

    entries = sampler.ring_buffer._ordered_entries()
    assert len(entries) == 2
    assert entries[0][1].frames[0].function == "my_func"
    assert entries[1][1].frames[0].function == "other"


# --- AustinSampler.stop error handling ---


def test_sampler_stop_handles_oserror():
    """terminate() raising OSError should not prevent stop() from completing."""
    with (
        patch.object(_LoopspyAustin, "start"),
        patch.object(_LoopspyAustin, "terminate", side_effect=OSError("already dead")),
        patch.object(_LoopspyAustin, "join"),
    ):
        sampler = AustinSampler(pid=100, sample_interval_ms=33, tid=100)
        sampler.start()
        sampler.stop()  # should not raise
    assert sampler._austin is None


def test_sampler_stop_logs_unexpected_error(caplog):
    """terminate() raising RuntimeError should log a warning."""
    with (
        patch.object(_LoopspyAustin, "start"),
        patch.object(
            _LoopspyAustin, "terminate", side_effect=RuntimeError("unexpected")
        ),
        patch.object(_LoopspyAustin, "join"),
        caplog.at_level(logging.WARNING, logger="blocksnoop.profiler"),
    ):
        sampler = AustinSampler(pid=100, sample_interval_ms=33, tid=100)
        sampler.start()
        sampler.stop()
    assert "Unexpected error terminating Austin" in caplog.text


# --- StackRingBuffer overflow tracking ---


def test_ring_buffer_overflow_count():
    """Overflow count tracks entries lost when buffer is full."""
    buf = StackRingBuffer(size=3)
    for i in range(5):
        buf.push(i * 100, _make_stack(i))
    assert buf.overflow_count == 2


def test_ring_buffer_no_overflow():
    """No overflow when buffer has spare capacity."""
    buf = StackRingBuffer(size=8)
    for i in range(3):
        buf.push(i * 100, _make_stack(i))
    assert buf.overflow_count == 0


def test_ring_buffer_overflow_logs_warning(caplog):
    """First overflow emits a warning log."""
    buf = StackRingBuffer(size=2)
    with caplog.at_level(logging.WARNING, logger="blocksnoop.profiler"):
        buf.push(100, _make_stack())
        buf.push(200, _make_stack())
        assert len(caplog.records) == 0
        buf.push(300, _make_stack())  # first overflow
    assert "overflow" in caplog.text.lower()
    # Second overflow should not emit another warning
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="blocksnoop.profiler"):
        buf.push(400, _make_stack())
    assert len(caplog.records) == 0


# ---------------------------------------------------------------------------
# Mount namespace detection
# ---------------------------------------------------------------------------


def test_in_same_mount_ns_same():
    """Returns True when both stat results match."""
    mock_stat = type("stat_result", (), {"st_dev": 3, "st_ino": 100})()
    with patch("blocksnoop.profiler.os.stat", return_value=mock_stat):
        assert _in_same_mount_ns(1234) is True


def test_in_same_mount_ns_different():
    """Returns False when stat results differ."""
    self_stat = type("stat_result", (), {"st_dev": 3, "st_ino": 100})()
    target_stat = type("stat_result", (), {"st_dev": 3, "st_ino": 200})()

    def mock_stat(path: str) -> object:
        return self_stat if "self" in path else target_stat

    with patch("blocksnoop.profiler.os.stat", side_effect=mock_stat):
        assert _in_same_mount_ns(1234) is False


def test_in_same_mount_ns_oserror():
    """Returns True (assume same) when /proc namespace files are unavailable."""
    with patch("blocksnoop.profiler.os.stat", side_effect=OSError):
        assert _in_same_mount_ns(1234) is True

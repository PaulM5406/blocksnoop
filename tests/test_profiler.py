"""Unit tests for blocksnoop.profiler (no root, eBPF, or external tools required)."""

import logging
import os
import shlex
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from austin.stats import AustinFrame, AustinMetrics, AustinSample

from blocksnoop.core import PythonStackTrace, StackFrame
from blocksnoop.profiler import (
    AustinSampler,
    StackRingBuffer,
    _LoopspyAustin,
    _create_nsenter_wrapper,
    _in_same_mount_ns,
    _resolve_ns_pid,
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


# ---------------------------------------------------------------------------
# nsenter wrapper generation
# ---------------------------------------------------------------------------


def test_create_nsenter_wrapper_writes_only_to_blocksnoop_tmp():
    """Wrapper must not write into the target's filesystem (/proc/<pid>/root/...)."""
    pid = 99001
    with (
        patch("blocksnoop.profiler.shutil.which", return_value="/fake/austin"),
        patch("blocksnoop.profiler._find_musl_linker", return_value="/fake/ld-musl.so"),
    ):
        wrapper = _create_nsenter_wrapper(pid)

    try:
        path = Path(wrapper)
        assert path.parent == Path(tempfile.gettempdir())
        assert path.name.startswith(".austin-nsenter-")
        assert path.name != f".austin-nsenter-{pid}"
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    finally:
        os.unlink(wrapper)


def test_create_nsenter_wrapper_includes_fd_redirects():
    """Wrapper script contains fd redirects, nsenter, and exec via /proc/self/fd."""
    pid = 99002
    with (
        patch("blocksnoop.profiler.shutil.which", return_value="/usr/local/bin/austin"),
        patch(
            "blocksnoop.profiler._find_musl_linker",
            return_value="/lib/ld-musl-x86_64.so.1",
        ),
    ):
        wrapper = _create_nsenter_wrapper(pid)
    try:
        with open(wrapper) as f:
            script = f.read()
        assert script.startswith("#!/bin/sh\n")
        assert "exec 3</usr/local/bin/austin" in script
        assert "exec 4</lib/ld-musl-x86_64.so.1" in script
        # Both mount AND PID namespaces must be entered: `-m` for the target's
        # filesystem view, `-p` so /proc (bound to the target's PID ns) can
        # resolve /proc/self/fd/N for the caller. Without `-p`, the caller's
        # host PID isn't visible in the target's /proc and the execve fails.
        assert f"exec nsenter -m -p -t {pid} --" in script
        assert "/proc/self/fd/4 /proc/self/fd/3" in script
        # fd 3 must be opened before nsenter line
        assert script.index("exec 3<") < script.index("nsenter")
    finally:
        os.unlink(wrapper)


def test_create_nsenter_wrapper_without_musl_linker():
    """When austin is static (no linker), the script drops fd 4."""
    pid = 99003
    with (
        patch("blocksnoop.profiler.shutil.which", return_value="/usr/local/bin/austin"),
        patch("blocksnoop.profiler._find_musl_linker", return_value=None),
    ):
        wrapper = _create_nsenter_wrapper(pid)
    try:
        with open(wrapper) as f:
            script = f.read()
        assert "exec 3</usr/local/bin/austin" in script
        assert "exec 4<" not in script
        assert "/proc/self/fd/4" not in script
        assert f"exec nsenter -m -p -t {pid} -- /proc/self/fd/3" in script
    finally:
        os.unlink(wrapper)


def test_create_nsenter_wrapper_quotes_shell_paths():
    """Paths are shell-quoted before the wrapper interpolates them."""
    austin_path = "/opt/austin; touch /tmp/pwned"
    linker_path = "/opt/ld musl.so"
    with (
        patch("blocksnoop.profiler.shutil.which", return_value=austin_path),
        patch("blocksnoop.profiler._find_musl_linker", return_value=linker_path),
    ):
        wrapper = _create_nsenter_wrapper(99006)
    try:
        script = Path(wrapper).read_text()
        assert f"exec 3<{shlex.quote(austin_path)}" in script
        assert f"exec 4<{shlex.quote(linker_path)}" in script
    finally:
        os.unlink(wrapper)


def test_create_nsenter_wrapper_raises_when_austin_missing():
    """RuntimeError when austin is not on PATH."""
    with patch("blocksnoop.profiler.shutil.which", return_value=None):
        try:
            _create_nsenter_wrapper(99004)
        except RuntimeError as e:
            assert "Austin" in str(e)
        else:
            raise AssertionError("expected RuntimeError")


def test_austin_sampler_stop_cleans_up_wrapper_only():
    """Cross-ns sampler unlinks only the wrapper, never /proc/<pid>/root paths."""
    pid = 99005
    unlinked: list[str] = []

    def tracking_unlink(path):
        unlinked.append(str(path))

    with (
        patch("blocksnoop.profiler._in_same_mount_ns", return_value=False),
        patch(
            "blocksnoop.profiler._create_nsenter_wrapper",
            return_value=f"/tmp/.austin-nsenter-{pid}",
        ),
        patch.object(_LoopspyAustin, "start"),
        patch.object(_LoopspyAustin, "terminate"),
        patch.object(_LoopspyAustin, "join"),
        patch("blocksnoop.profiler.os.unlink", side_effect=tracking_unlink),
    ):
        sampler = AustinSampler(pid=pid, sample_interval_ms=33, tid=pid)
        sampler.start()
        sampler.stop()

    assert unlinked == [f"/tmp/.austin-nsenter-{pid}"]


def test_austin_sampler_start_cleans_up_wrapper_when_austin_fails():
    """A failed Austin start must not leave a privileged wrapper in /tmp."""
    pid = 99006
    wrapper = "/tmp/.austin-nsenter-random"
    unlinked: list[str] = []

    with (
        patch("blocksnoop.profiler._in_same_mount_ns", return_value=False),
        patch("blocksnoop.profiler._create_nsenter_wrapper", return_value=wrapper),
        patch("blocksnoop.profiler._resolve_ns_pid", return_value=pid),
        patch.object(_LoopspyAustin, "start", side_effect=RuntimeError("boom")),
        patch("blocksnoop.profiler.os.unlink", side_effect=unlinked.append),
    ):
        sampler = AustinSampler(pid=pid, sample_interval_ms=33, tid=pid)
        with pytest.raises(RuntimeError, match="boom"):
            sampler.start()

    assert sampler._austin is None
    assert sampler._nsenter_wrapper is None
    assert unlinked == [wrapper]


# ---------------------------------------------------------------------------
# PID namespace translation
# ---------------------------------------------------------------------------


def test_resolve_ns_pid_picks_innermost(tmp_path):
    """When NSpid lists multiple values, return the deepest (rightmost) one."""
    status = "Name:\tpython\nNSpid:\t833976\t1\n"
    mock_open = patch("builtins.open", new=lambda *a, **k: _StringIO(status))
    with mock_open:
        assert _resolve_ns_pid(833976) == 1


def test_resolve_ns_pid_single_value_returns_pid_unchanged(tmp_path):
    """Without nested PID ns, NSpid has a single entry == the host PID."""
    status = "Name:\tpython\nNSpid:\t4242\n"
    with patch("builtins.open", new=lambda *a, **k: _StringIO(status)):
        assert _resolve_ns_pid(4242) == 4242


def test_resolve_ns_pid_missing_nspid_line_returns_pid(tmp_path):
    """If /proc/<pid>/status has no NSpid line (very old kernel), fall back to pid."""
    status = "Name:\tpython\nUmask:\t0022\n"
    with patch("builtins.open", new=lambda *a, **k: _StringIO(status)):
        assert _resolve_ns_pid(7777) == 7777


def test_resolve_ns_pid_oserror_returns_pid():
    """If /proc/<pid>/status is unreadable, fall back to pid."""
    with patch("builtins.open", side_effect=OSError):
        assert _resolve_ns_pid(1234) == 1234


def test_austin_sampler_uses_ns_pid_when_cross_ns():
    """Cross-ns: Austin must be invoked with the container-local PID, not the host PID.

    Reason: the nsenter wrapper enters the target's PID namespace via `-p`, so
    Austin sees PIDs as the container does. Passing the host PID would make
    Austin look for a process that doesn't exist in that namespace.
    """
    host_pid = 833976
    ns_pid = 1
    start_args: list[list[str]] = []

    def capture_start(self, args):  # noqa: ARG001
        start_args.append(list(args))

    with (
        patch("blocksnoop.profiler._in_same_mount_ns", return_value=False),
        patch(
            "blocksnoop.profiler._create_nsenter_wrapper",
            return_value=f"/tmp/.austin-nsenter-{host_pid}",
        ),
        patch("blocksnoop.profiler._resolve_ns_pid", return_value=ns_pid),
        patch.object(_LoopspyAustin, "start", new=capture_start),
    ):
        sampler = AustinSampler(pid=host_pid, sample_interval_ms=10, tid=host_pid)
        sampler.start()

    assert len(start_args) == 1
    args = start_args[0]
    assert "-p" in args
    assert args[args.index("-p") + 1] == str(ns_pid)
    assert str(host_pid) not in args


def test_austin_sampler_filters_on_ns_tid_when_cross_ns():
    """Cross-ns: _LoopspyAustin must filter on the container-local TID.

    Austin reports samples with thread IDs as the container's PID namespace
    sees them (e.g. the main thread's tid is 1, not the host TID). If
    _LoopspyAustin is instantiated with the host TID, every sample is
    rejected as "wrong tid" and zero samples are accepted — exactly the
    failure observed on the K8s cluster.
    """
    host_pid = 833976
    ns_pid = 1
    captured_tids: list[int] = []

    real_init = _LoopspyAustin.__init__

    def capture_init(self, ring_buffer, tid):
        captured_tids.append(tid)
        real_init(self, ring_buffer, tid)

    with (
        patch("blocksnoop.profiler._in_same_mount_ns", return_value=False),
        patch(
            "blocksnoop.profiler._create_nsenter_wrapper",
            return_value=f"/tmp/.austin-nsenter-{host_pid}",
        ),
        patch("blocksnoop.profiler._resolve_ns_pid", return_value=ns_pid),
        patch.object(_LoopspyAustin, "__init__", new=capture_init),
        patch.object(_LoopspyAustin, "start"),
    ):
        sampler = AustinSampler(pid=host_pid, sample_interval_ms=10, tid=host_pid)
        sampler.start()

    assert captured_tids == [ns_pid], (
        f"expected _LoopspyAustin to receive container-local tid {ns_pid}, "
        f"got {captured_tids}"
    )


def test_austin_sampler_uses_host_pid_when_same_ns():
    """Same mount ns: no namespace crossing, Austin gets the host PID directly."""
    pid = 4242
    start_args: list[list[str]] = []

    def capture_start(self, args):  # noqa: ARG001
        start_args.append(list(args))

    with (
        patch("blocksnoop.profiler._in_same_mount_ns", return_value=True),
        patch.object(_LoopspyAustin, "start", new=capture_start),
    ):
        sampler = AustinSampler(pid=pid, sample_interval_ms=10, tid=pid)
        sampler.start()

    assert len(start_args) == 1
    args = start_args[0]
    assert "-p" in args
    assert args[args.index("-p") + 1] == str(pid)


# Small in-test helper to avoid an extra import at module top.
class _StringIO:
    def __init__(self, data: str) -> None:
        self._data = data

    def __enter__(self) -> "_StringIO":
        return self

    def __exit__(self, *exc) -> None:
        pass

    def __iter__(self):
        return iter(self._data.splitlines(keepends=True))

"""Unit tests for the StatsCollector."""

from __future__ import annotations

import array
import io
import json
import threading

from blocksnoop.core import BlockingEvent
from blocksnoop.stats import StatsCollector, _percentile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(duration_ms: float) -> BlockingEvent:
    """Create a BlockingEvent with the given duration."""
    start_ns = 0
    end_ns = int(duration_ms * 1_000_000)
    return BlockingEvent(start_ns=start_ns, end_ns=end_ns, pid=1234, tid=1234)


# ---------------------------------------------------------------------------
# _percentile
# ---------------------------------------------------------------------------


def test_percentile_single_element():
    a = array.array("d", [42.0])
    assert _percentile(a, 0.50) == 42.0
    assert _percentile(a, 0.99) == 42.0


def test_percentile_multiple_elements():
    a = array.array("d", range(1, 101))  # 1..100
    assert _percentile(a, 0.50) == 50.0
    assert _percentile(a, 0.90) == 90.0
    assert _percentile(a, 0.99) == 99.0


def test_percentile_two_elements():
    a = array.array("d", [10.0, 20.0])
    assert _percentile(a, 0.0) == 10.0
    assert _percentile(a, 1.0) == 20.0


# ---------------------------------------------------------------------------
# on_event accumulates sorted durations
# ---------------------------------------------------------------------------


def test_on_event_accumulates_sorted():
    buf = io.StringIO()
    c = StatsCollector(pid=1, stream=buf)
    c.on_event(_make_event(5.0))
    c.on_event(_make_event(1.0))
    c.on_event(_make_event(3.0))
    # Access internals to check sorting
    assert list(c._durations) == [1.0, 3.0, 5.0]


# ---------------------------------------------------------------------------
# print_stats: console output
# ---------------------------------------------------------------------------


def test_print_stats_console_empty():
    buf = io.StringIO()
    c = StatsCollector(pid=42, stream=buf)
    c._start_time = 0.0  # force known time
    c._print_stats()
    output = buf.getvalue()
    assert "PID 42" in output
    assert "(no events yet)" in output


def test_print_stats_console_with_data():
    buf = io.StringIO()
    c = StatsCollector(pid=42, stream=buf)
    c._start_time = 0.0
    for ms in [1.0, 2.0, 3.0, 4.0, 5.0]:
        c.on_event(_make_event(ms))
    c._print_stats()
    output = buf.getvalue()
    assert "PID 42" in output
    assert "min" in output
    assert "avg" in output
    assert "p50" in output
    assert "p90" in output
    assert "p95" in output
    assert "p99" in output
    assert "max" in output


def test_print_stats_console_overwrites():
    """Second print should include ANSI cursor-up sequence."""
    buf = io.StringIO()
    c = StatsCollector(pid=1, stream=buf)
    c._start_time = 0.0
    c.on_event(_make_event(1.0))
    c._print_stats()
    first_output = buf.getvalue()
    assert "\033[" not in first_output  # no cursor-up on first print

    c._print_stats()
    second_output = buf.getvalue()[len(first_output) :]
    assert "\033[" in second_output  # cursor-up on second print


# ---------------------------------------------------------------------------
# print_stats: JSON output
# ---------------------------------------------------------------------------


def test_print_stats_json_empty():
    buf = io.StringIO()
    c = StatsCollector(pid=42, json_mode=True, stream=buf)
    c._start_time = 0.0
    c._print_stats()
    record = json.loads(buf.getvalue().strip())
    assert record["pid"] == 42
    assert record["count"] == 0
    assert "min_ms" not in record


def test_print_stats_json_with_data():
    buf = io.StringIO()
    c = StatsCollector(pid=42, json_mode=True, stream=buf)
    c._start_time = 0.0
    for ms in [1.0, 2.0, 3.0, 4.0, 5.0]:
        c.on_event(_make_event(ms))
    c._print_stats()
    record = json.loads(buf.getvalue().strip())
    assert record["count"] == 5
    assert record["min_ms"] == 1.0
    assert record["max_ms"] == 5.0
    assert "p50_ms" in record
    assert "p90_ms" in record
    assert "p95_ms" in record
    assert "p99_ms" in record


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_thread_safety():
    """Concurrent on_event calls from multiple threads should not corrupt data."""
    buf = io.StringIO()
    c = StatsCollector(pid=1, stream=buf)
    n_threads = 4
    events_per_thread = 1000

    def _feed(offset: int) -> None:
        for i in range(events_per_thread):
            c.on_event(_make_event(float(offset * events_per_thread + i)))

    threads = [threading.Thread(target=_feed, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(c._durations) == n_threads * events_per_thread
    # Verify sorted
    for i in range(1, len(c._durations)):
        assert c._durations[i] >= c._durations[i - 1]


# ---------------------------------------------------------------------------
# start / stop lifecycle
# ---------------------------------------------------------------------------


def test_start_stop_lifecycle():
    """start() and stop() should not raise."""
    buf = io.StringIO()
    c = StatsCollector(pid=1, stream=buf)
    c.start()
    c.on_event(_make_event(10.0))
    c.stop()
    # After stop, the final stats should have been printed
    output = buf.getvalue()
    assert "PID 1" in output


def test_stop_without_start():
    """stop() without start() should not raise."""
    buf = io.StringIO()
    c = StatsCollector(pid=1, stream=buf)
    c.stop()  # should not raise

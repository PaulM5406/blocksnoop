"""Unit tests for blocksnoop.reporter (no root, eBPF, or Austin required)."""

import json
from io import StringIO

from blocksnoop.core import BlockingEvent, PythonStackTrace, StackFrame
from blocksnoop.reporter import Reporter, _get_source_line
from blocksnoop.sinks import ConsoleSink, JsonStreamSink


def _make_event(
    duration_ns: int = 200_000_000, tid: int = 42, with_stack: bool = True
) -> BlockingEvent:
    stacks: tuple[PythonStackTrace, ...] = ()
    if with_stack:
        stacks = (
            PythonStackTrace(
                thread_id=tid,
                thread_name="MainThread",
                frames=(
                    StackFrame(function="cpu_heavy", file="app.py", line=42),
                    StackFrame(function="main", file="app.py", line=30),
                ),
            ),
        )
    return BlockingEvent(
        start_ns=0, end_ns=duration_ns, pid=100, tid=tid, python_stacks=stacks
    )


# --- Console (non-JSON) mode ---


def test_console_output():
    buf = StringIO()
    reporter = Reporter(sinks=[ConsoleSink(stream=buf, color=False)])
    reporter.report(_make_event(duration_ns=200_000_000, tid=42, with_stack=True))
    output = buf.getvalue()
    assert "BLOCKED" in output
    assert "200.0ms" in output
    assert "tid=42" in output
    assert "cpu_heavy" in output
    assert "app.py:42" in output


def test_console_no_stack():
    buf = StringIO()
    reporter = Reporter(sinks=[ConsoleSink(stream=buf, color=False)])
    reporter.report(_make_event(with_stack=False))
    output = buf.getvalue()
    assert "(no Python stack captured)" in output


# --- JSON mode ---


def test_json_mode_output():
    buf = StringIO()
    reporter = Reporter(sinks=[JsonStreamSink(stream=buf)])
    reporter.report(_make_event(duration_ns=150_000_000, tid=7, with_stack=True))
    output = buf.getvalue().strip()
    record = json.loads(output)
    assert record["event_number"] == 1
    assert record["duration_ms"] == 150.0
    assert record["pid"] == 100
    assert record["tid"] == 7
    assert isinstance(record["python_stacks"], list)
    assert len(record["python_stacks"]) == 1
    assert len(record["python_stacks"][0]) == 2
    assert record["python_stacks"][0][0]["function"] == "cpu_heavy"
    assert "level" in record


# --- Summary ---


def test_summary():
    buf = StringIO()
    reporter = Reporter(sinks=[ConsoleSink(stream=buf, color=False)])
    reporter.report(_make_event())
    reporter.report(_make_event())
    reporter.summary(45.2, loss_counts={"kernel": 2, "perf_buffer": 3})
    output = buf.getvalue()
    assert "Duration: 45.2s" in output
    assert "Blocking events detected: 2" in output
    assert "Lost detector events: 5" in output


# --- Event count ---


def test_event_count():
    buf = StringIO()
    reporter = Reporter(sinks=[ConsoleSink(stream=buf, color=False)])
    reporter.report(_make_event())
    reporter.report(_make_event())
    reporter.report(_make_event())
    assert reporter.event_count == 3


# --- Multi-sink fanout ---


def test_multi_sink():
    console_buf = StringIO()
    json_buf = StringIO()
    reporter = Reporter(
        sinks=[
            ConsoleSink(stream=console_buf, color=False),
            JsonStreamSink(stream=json_buf),
        ]
    )
    reporter.report(_make_event())
    assert "BLOCKED" in console_buf.getvalue()
    record = json.loads(json_buf.getvalue().strip())
    assert record["event_number"] == 1


# --- Close ---


def test_close():
    buf = StringIO()
    reporter = Reporter(sinks=[ConsoleSink(stream=buf, color=False)])
    reporter.close()  # should not raise


# --- _get_source_line ---


def test_get_source_line_real_file():
    """Reading a line from a real file returns stripped source."""
    # __file__ is this test file; line 1 is the module docstring.
    result = _get_source_line(__file__, 1)
    assert result is not None
    assert "Unit tests" in result


def test_get_source_line_nonexistent_file():
    assert _get_source_line("/no/such/file.py", 1) is None


def test_get_source_line_out_of_range():
    assert _get_source_line(__file__, 999_999) is None


# --- source field in report() ---


def test_report_includes_source_field():
    """report() adds a 'source' key to each frame dict."""
    buf = StringIO()
    reporter = Reporter(sinks=[JsonStreamSink(stream=buf)])
    reporter.report(_make_event())
    record = json.loads(buf.getvalue().strip())
    for frame in record["python_stacks"][0]:
        assert "source" in frame


def test_json_session_lifecycle_is_typed_and_complete():
    """A clean JSON session has one start, events, and one final summary."""
    buf = StringIO()
    reporter = Reporter(
        sinks=[JsonStreamSink(stream=buf)],
        backend="core",
        threshold_ms=100.0,
        target_pid=100,
        target_tid=42,
    )
    reporter.start()
    reporter.report(_make_event(duration_ns=600_000_000))
    reporter.summary(2.5, loss_counts={"perf_buffer": 1})

    records = [json.loads(line) for line in buf.getvalue().splitlines()]
    assert [record["type"] for record in records] == [
        "session_start",
        "blocking_event",
        "session_summary",
    ]
    assert {record["schema"] for record in records} == {"blocksnoop.events/v1"}
    assert {record["schema_version"] for record in records} == {1}
    assert len({record["session_id"] for record in records}) == 1

    event = records[1]
    for key in (
        "event_number",
        "timestamp_s",
        "duration_ms",
        "pid",
        "tid",
        "python_stacks",
        "level",
    ):
        assert key in event

    summary = records[2]
    assert summary["termination_reason"] == "clean"
    assert summary["status"] == "completed"
    assert summary["event_count"] == 1
    assert summary["error_event_count"] == 1
    assert summary["total_blocked_ms"] == 600.0
    assert summary["max_blocked_ms"] == 600.0
    assert summary["lost_event_count"] == 1
    assert summary["top_signatures"] == [
        {
            "fingerprint": summary["top_signatures"][0]["fingerprint"],
            "location": "app.py:42 in cpu_heavy",
            "count": 1,
            "total_blocked_ms": 600.0,
            "max_blocked_ms": 600.0,
        }
    ]


def test_summary_only_keeps_machine_lifecycle_but_suppresses_events():
    buf = StringIO()
    reporter = Reporter(sinks=[JsonStreamSink(stream=buf)], summary_only=True)
    reporter.start()
    reporter.report(_make_event())
    reporter.summary(1.0)

    records = [json.loads(line) for line in buf.getvalue().splitlines()]
    assert [record["type"] for record in records] == [
        "session_start",
        "session_summary",
    ]
    assert records[-1]["event_count"] == 1


def test_policy_failure_uses_events_errors_and_losses():
    reporter = Reporter(error_threshold_ms=500.0)
    reporter.report(_make_event(duration_ns=200_000_000))
    reporter.summary(1.0, loss_counts={"perf_buffer": 1})
    assert reporter.policy_failed("event", fail_on_loss=False)
    assert not reporter.policy_failed("error", fail_on_loss=False)
    assert reporter.policy_failed("none", fail_on_loss=True)


def test_console_summary_aggregates_repeated_call_sites():
    buf = StringIO()
    reporter = Reporter(sinks=[ConsoleSink(stream=buf, color=False)])
    reporter.report(_make_event(duration_ns=200_000_000))
    reporter.report(_make_event(duration_ns=300_000_000))
    reporter.summary(1.0)

    output = buf.getvalue()
    assert "Total blocked time: 500.0ms" in output
    assert "Longest blocking event: 300.0ms" in output
    assert "Top blocking call sites" in output
    assert "app.py:42 in cpu_heavy — 2 events, 500.0ms total, 300.0ms max" in output

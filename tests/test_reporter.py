"""Unit tests for loopspy.reporter (no root, eBPF, or py-spy required)."""

import json
from io import StringIO

from loopspy.core import BlockingEvent, PythonStackTrace, StackFrame
from loopspy.reporter import Reporter
from loopspy.sinks import ConsoleSink, JsonStreamSink


def _make_event(
    duration_ns: int = 200_000_000, tid: int = 42, with_stack: bool = True
) -> BlockingEvent:
    stack = None
    if with_stack:
        stack = PythonStackTrace(
            thread_id=tid,
            thread_name="MainThread",
            frames=(
                StackFrame(function="cpu_heavy", file="app.py", line=42),
                StackFrame(function="main", file="app.py", line=30),
            ),
        )
    return BlockingEvent(
        start_ns=0, end_ns=duration_ns, pid=100, tid=tid, python_stack=stack
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
    assert isinstance(record["python_stack"], list)
    assert len(record["python_stack"]) == 2
    assert record["python_stack"][0]["function"] == "cpu_heavy"
    assert "level" in record


# --- Summary ---


def test_summary():
    buf = StringIO()
    reporter = Reporter(sinks=[ConsoleSink(stream=buf, color=False)])
    reporter.report(_make_event())
    reporter.report(_make_event())
    reporter.summary(45.2)
    output = buf.getvalue()
    assert "Duration: 45.2s" in output
    assert "Blocking events detected: 2" in output


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

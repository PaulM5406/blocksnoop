"""Unit tests for loopspy.sinks."""

import json
import tempfile
from io import StringIO

from loopspy.sinks import ConsoleSink, JsonFileSink, JsonStreamSink, _level_for_duration


def _make_record(
    duration_ms: float = 200.0, tid: int = 42, with_stack: bool = True
) -> dict:
    stack = None
    if with_stack:
        stack = [
            {"function": "cpu_heavy", "file": "app.py", "line": 42},
            {"function": "main", "file": "app.py", "line": 30},
        ]
    return {
        "event_number": 1,
        "timestamp_s": 7.23,
        "duration_ms": duration_ms,
        "pid": 100,
        "tid": tid,
        "python_stack": stack,
    }


def _make_summary() -> dict:
    return {"duration_s": 45.2, "event_count": 3}


# --- Severity classification ---


def test_level_warning():
    assert _level_for_duration(200.0) == "warning"
    assert _level_for_duration(499.9) == "warning"


def test_level_error():
    assert _level_for_duration(500.0) == "error"
    assert _level_for_duration(1000.0) == "error"


# --- ConsoleSink ---


def test_console_emit_with_stack():
    buf = StringIO()
    sink = ConsoleSink(stream=buf, color=False)
    sink.emit(_make_record())
    output = buf.getvalue()
    assert "BLOCKED" in output
    assert "200.0ms" in output
    assert "tid=42" in output
    assert "cpu_heavy" in output
    assert "app.py:42" in output


def test_console_emit_no_stack():
    buf = StringIO()
    sink = ConsoleSink(stream=buf, color=False)
    sink.emit(_make_record(with_stack=False))
    output = buf.getvalue()
    assert "(no Python stack captured)" in output


def test_console_emit_blank_line_between_stacks():
    buf = StringIO()
    sink = ConsoleSink(stream=buf, color=False)
    sink.emit(_make_record(with_stack=True))
    output = buf.getvalue()
    # Events with stacks end with a blank line
    assert output.endswith("\n\n")


def test_console_summary():
    buf = StringIO()
    sink = ConsoleSink(stream=buf, color=False)
    sink.emit_summary(_make_summary())
    output = buf.getvalue()
    assert "loopspy session" in output
    assert "45.2s" in output
    assert "3" in output


def test_console_color_warning():
    buf = StringIO()
    sink = ConsoleSink(stream=buf, color=True)
    sink.emit(_make_record(duration_ms=200.0))
    output = buf.getvalue()
    assert "\033[33m" in output  # yellow for warning


def test_console_color_error():
    buf = StringIO()
    sink = ConsoleSink(stream=buf, color=True)
    sink.emit(_make_record(duration_ms=600.0))
    output = buf.getvalue()
    assert "\033[31m" in output  # red for error


def test_console_color_dim_stack():
    buf = StringIO()
    sink = ConsoleSink(stream=buf, color=True)
    sink.emit(_make_record(with_stack=True))
    output = buf.getvalue()
    assert "\033[2m" in output  # dim for stack frames


# --- JsonStreamSink ---


def test_json_stream_emit():
    buf = StringIO()
    sink = JsonStreamSink(stream=buf)
    sink.emit(_make_record(duration_ms=250.0, tid=7))
    record = json.loads(buf.getvalue().strip())
    assert record["event_number"] == 1
    assert record["duration_ms"] == 250.0
    assert record["tid"] == 7
    assert record["pid"] == 100
    assert record["python_stack"] is not None


def test_json_stream_level_present():
    buf = StringIO()
    sink = JsonStreamSink(stream=buf)
    sink.emit(_make_record(duration_ms=200.0))
    record = json.loads(buf.getvalue().strip())
    assert record["level"] == "warning"


def test_json_stream_level_error():
    buf = StringIO()
    sink = JsonStreamSink(stream=buf)
    sink.emit(_make_record(duration_ms=600.0))
    record = json.loads(buf.getvalue().strip())
    assert record["level"] == "error"


def test_json_stream_backward_compatible_schema():
    """Verify all fields from the original --json schema are present."""
    buf = StringIO()
    sink = JsonStreamSink(stream=buf)
    sink.emit(_make_record())
    record = json.loads(buf.getvalue().strip())
    for key in (
        "event_number",
        "timestamp_s",
        "duration_ms",
        "pid",
        "tid",
        "python_stack",
    ):
        assert key in record


def test_json_stream_no_summary():
    """JSON stream mode doesn't emit summary (matches current behavior)."""
    buf = StringIO()
    sink = JsonStreamSink(stream=buf)
    sink.emit_summary(_make_summary())
    assert buf.getvalue() == ""


# --- JsonFileSink ---


def test_json_file_writes_valid_json():
    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as f:
        path = f.name
    sink = JsonFileSink(path=path, service="my-api", env="production")
    sink.emit(_make_record(duration_ms=300.0, tid=99))
    sink.close()
    with open(path) as f:
        line = f.readline().strip()
    record = json.loads(line)
    assert record["duration_ms"] == 300.0
    assert record["tid"] == 99


def test_json_file_datadog_fields():
    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as f:
        path = f.name
    sink = JsonFileSink(path=path, service="my-api", env="staging")
    sink.emit(_make_record())
    sink.close()
    with open(path) as f:
        record = json.loads(f.readline().strip())
    assert record["service"] == "my-api"
    assert record["source"] == "loopspy"
    assert record["dd"] == {"service": "my-api", "env": "staging"}
    assert "T" in record["timestamp"]  # ISO format
    assert record["level"] == "warning"
    assert "Blocking call detected" in record["message"]


def test_json_file_summary():
    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as f:
        path = f.name
    sink = JsonFileSink(path=path, service="demo", env="test")
    sink.emit_summary(_make_summary())
    sink.close()
    with open(path) as f:
        record = json.loads(f.readline().strip())
    assert record["level"] == "info"
    assert record["event_count"] == 3
    assert record["dd"] == {"service": "demo", "env": "test"}
    assert "session ended" in record["message"]


def test_json_file_multiple_events():
    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as f:
        path = f.name
    sink = JsonFileSink(path=path, service="svc", env="prod")
    sink.emit(_make_record(duration_ms=100.0))
    sink.emit(_make_record(duration_ms=600.0))
    sink.emit_summary(_make_summary())
    sink.close()
    with open(path) as f:
        lines = [json.loads(line) for line in f if line.strip()]
    assert len(lines) == 3
    assert lines[0]["level"] == "warning"
    assert lines[1]["level"] == "error"
    assert lines[2]["level"] == "info"

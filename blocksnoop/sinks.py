"""Output sinks for blocksnoop — console, JSON stream, and JSON file."""

from __future__ import annotations

import json
import logging
import sys
import typing
from datetime import datetime, timezone

# ANSI escape codes
_RESET = "\033[0m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_DIM = "\033[2m"

# Stdlib modules whose frames are noise in console stack traces.
# They are kept in JSON sinks for completeness.
_HIDDEN_PREFIXES = ("asyncio/", "selectors.py", "threading.py")


def _level_for_duration(duration_ms: float) -> str:
    """Classify severity based on blocking duration."""
    return "error" if duration_ms >= 500 else "warning"


class Sink(typing.Protocol):
    """Protocol for output sinks."""

    def emit(self, record: dict) -> None:
        ...

    def emit_summary(self, summary: dict) -> None:
        ...

    def close(self) -> None:
        ...


class ConsoleSink:
    """Human-readable output to a stream (default: stderr) with optional ANSI colors."""

    def __init__(
        self, stream: typing.TextIO | None = None, *, color: bool | None = None
    ) -> None:
        self._stream = stream or sys.stderr
        if color is None:
            self._color = hasattr(self._stream, "isatty") and self._stream.isatty()
        else:
            self._color = color

    def emit(self, record: dict) -> None:
        duration_ms = record["duration_ms"]
        level = _level_for_duration(duration_ms)

        header = (
            f"[{record['timestamp_s']:7.2f}s] #{record['event_number']:<3} BLOCKED  "
            f"{duration_ms:>8.1f}ms  tid={record['tid']}"
        )

        if self._color:
            color = _RED if level == "error" else _YELLOW
            header = f"{color}{header}{_RESET}"

        self._stream.write(header + "\n")

        stack = record.get("python_stack")
        if stack:
            # Filter out asyncio/stdlib internals for readability
            app_frames = [
                f
                for f in stack
                if not any(f["file"].startswith(p) for p in _HIDDEN_PREFIXES)
            ]
            frames_to_show = app_frames if app_frames else stack
            self._stream.write("  Python stack (most recent call last):\n")
            for frame in frames_to_show:
                line = f"    {frame['file']}:{frame['line']} in {frame['function']}"
                if self._color:
                    line = f"{_DIM}{line}{_RESET}"
                self._stream.write(line + "\n")
            if len(frames_to_show) < len(stack):
                hidden = len(stack) - len(frames_to_show)
                note = f"    ... {hidden} asyncio/stdlib frames hidden"
                if self._color:
                    note = f"{_DIM}{note}{_RESET}"
                self._stream.write(note + "\n")
            self._stream.write("\n")
        else:
            self._stream.write("  (no Python stack captured)\n")

    def emit_summary(self, summary: dict) -> None:
        self._stream.write("--- blocksnoop session ---\n")
        self._stream.write(f"Duration: {summary['duration_s']:.1f}s\n")
        self._stream.write(f"Blocking events detected: {summary['event_count']}\n")

    def close(self) -> None:
        pass


class JsonStreamSink:
    """JSON lines to a stream (default: stdout), backward compatible with --json."""

    def __init__(self, stream: typing.TextIO | None = None) -> None:
        self._stream = stream or sys.stdout

    def emit(self, record: dict) -> None:
        output = {**record, "level": _level_for_duration(record["duration_ms"])}
        self._stream.write(json.dumps(output) + "\n")
        self._stream.flush()

    def emit_summary(self, summary: dict) -> None:
        pass  # JSON stream mode doesn't emit summary (matches current behavior)

    def close(self) -> None:
        pass


class JsonFileSink:
    """Structured JSON lines to a file for log aggregators (Datadog/Fluentd/CloudWatch)."""

    def __init__(
        self, path: str, *, service: str = "blocksnoop", env: str = ""
    ) -> None:
        self._service = service
        self._env = env
        self._handler = logging.FileHandler(path)
        self._handler.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: dict) -> None:
        duration_ms = record["duration_ms"]
        level = _level_for_duration(duration_ms)

        output = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": level,
            "message": f"Blocking call detected: {duration_ms:.1f}ms on tid={record['tid']}",
            "service": self._service,
            "source": "blocksnoop",
            "duration_ms": duration_ms,
            "event_number": record["event_number"],
            "pid": record["pid"],
            "tid": record["tid"],
            "python_stack": record.get("python_stack"),
            "dd": {"service": self._service, "env": self._env},
        }

        log_record = logging.LogRecord(
            name="blocksnoop",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg=json.dumps(output),
            args=(),
            exc_info=None,
        )
        self._handler.emit(log_record)

    def emit_summary(self, summary: dict) -> None:
        output = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": "info",
            "message": (
                f"blocksnoop session ended: {summary['event_count']} blocking events "
                f"in {summary['duration_s']:.1f}s"
            ),
            "service": self._service,
            "source": "blocksnoop",
            "duration_s": summary["duration_s"],
            "event_count": summary["event_count"],
            "dd": {"service": self._service, "env": self._env},
        }

        log_record = logging.LogRecord(
            name="blocksnoop",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=json.dumps(output),
            args=(),
            exc_info=None,
        )
        self._handler.emit(log_record)

    def close(self) -> None:
        self._handler.close()

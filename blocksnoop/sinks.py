"""Output sinks for blocksnoop — console, JSON stream, and JSON file."""

from __future__ import annotations

import json
import logging
import sys
import typing
from datetime import datetime, timezone

from blocksnoop.core import STDLIB_FRAME_PREFIXES

# ANSI escape codes
_RESET = "\033[0m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_DIM = "\033[2m"


_DEFAULT_ERROR_THRESHOLD_MS = 500.0


def _level_for_duration(
    duration_ms: float, error_threshold_ms: float = _DEFAULT_ERROR_THRESHOLD_MS
) -> str:
    """Classify severity based on blocking duration."""
    return "error" if duration_ms >= error_threshold_ms else "warning"


class Sink(typing.Protocol):
    """Protocol for output sinks."""

    def emit_session_start(self, record: dict) -> None: ...

    def emit(self, record: dict) -> None: ...

    def emit_summary(self, summary: dict) -> None: ...

    def close(self) -> None: ...


class ConsoleSink:
    """Human-readable output to a stream (default: stderr) with optional ANSI colors."""

    def __init__(
        self,
        stream: typing.TextIO | None = None,
        *,
        color: bool | None = None,
        error_threshold_ms: float = _DEFAULT_ERROR_THRESHOLD_MS,
        summary_only: bool = False,
    ) -> None:
        self._stream = stream or sys.stderr
        if color is None:
            self._color = hasattr(self._stream, "isatty") and self._stream.isatty()
        else:
            self._color = color
        self._error_threshold_ms = error_threshold_ms
        self._summary_only = summary_only

    def emit_session_start(self, record: dict) -> None:
        """Session metadata is machine-readable; the console starts with events."""
        return

    def emit(self, record: dict) -> None:
        if self._summary_only:
            return
        duration_ms = record["duration_ms"]
        level = _level_for_duration(duration_ms, self._error_threshold_ms)

        header = (
            f"[{record['timestamp_s']:7.2f}s] #{record['event_number']:<3} BLOCKED  "
            f"{duration_ms:>8.1f}ms  tid={record['tid']}"
        )

        if self._color:
            color = _RED if level == "error" else _YELLOW
            header = f"{color}{header}{_RESET}"

        self._stream.write(header + "\n")

        stacks = record.get("python_stacks")
        if stacks:
            for i, stack in enumerate(stacks):
                # Filter out asyncio/stdlib internals for readability.
                # Use ``in`` so both relative ("asyncio/events.py") and absolute
                # ("/usr/lib/python3.13/asyncio/events.py") paths are matched.
                app_frames = [
                    f
                    for f in stack
                    if not any(p in f["file"] for p in STDLIB_FRAME_PREFIXES)
                ]
                frames_to_show = app_frames if app_frames else stack
                if i == 0:
                    self._stream.write("  Python stack (most recent call last):\n")
                else:
                    self._stream.write("  ---\n")
                for frame in frames_to_show:
                    line = f"    {frame['file']}:{frame['line']} in {frame['function']}"
                    if self._color:
                        line = f"{_DIM}{line}{_RESET}"
                    self._stream.write(line + "\n")
                    source = frame.get("source")
                    if source:
                        src_line = f"      {source}"
                        if self._color:
                            src_line = f"{_DIM}{src_line}{_RESET}"
                        self._stream.write(src_line + "\n")
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
        self._stream.write(
            f"Total blocked time: {summary.get('total_blocked_ms', 0.0):.1f}ms\n"
        )
        self._stream.write(
            f"Longest blocking event: {summary.get('max_blocked_ms', 0.0):.1f}ms\n"
        )
        self._stream.write(f"Lost detector events: {summary['lost_event_count']}\n")
        if summary["lost_events_by_source"]:
            losses = ", ".join(
                f"{source}={count}"
                for source, count in sorted(summary["lost_events_by_source"].items())
            )
            self._stream.write(f"Lost detector events by source: {losses}\n")
        top_signatures = summary.get("top_signatures", [])
        if top_signatures:
            self._stream.write("Top blocking call sites (by total blocked time):\n")
            for index, signature in enumerate(top_signatures, start=1):
                self._stream.write(
                    f"  {index}. {signature['location']} — "
                    f"{signature['count']} events, "
                    f"{signature['total_blocked_ms']:.1f}ms total, "
                    f"{signature['max_blocked_ms']:.1f}ms max\n"
                )

    def close(self) -> None:
        pass


class JsonStreamSink:
    """JSON lines to a stream (default: stdout), backward compatible with --json."""

    def __init__(
        self,
        stream: typing.TextIO | None = None,
        *,
        error_threshold_ms: float = _DEFAULT_ERROR_THRESHOLD_MS,
    ) -> None:
        self._stream = stream or sys.stdout
        self._error_threshold_ms = error_threshold_ms

    def emit_session_start(self, record: dict) -> None:
        self._write(record)

    def emit(self, record: dict) -> None:
        output = dict(record)
        if "duration_ms" in output:
            output["level"] = _level_for_duration(
                float(output["duration_ms"]), self._error_threshold_ms
            )
        self._write(output)

    def emit_summary(self, summary: dict) -> None:
        self._write(summary)

    def _write(self, record: dict) -> None:
        self._stream.write(json.dumps(record, sort_keys=True) + "\n")
        self._stream.flush()

    def close(self) -> None:
        pass


class JsonFileSink:
    """Structured JSON lines to a file for log aggregators (Datadog/Fluentd/CloudWatch)."""

    def __init__(
        self,
        path: str,
        *,
        service: str = "blocksnoop",
        env: str = "",
        error_threshold_ms: float = _DEFAULT_ERROR_THRESHOLD_MS,
    ) -> None:
        self._service = service
        self._env = env
        self._error_threshold_ms = error_threshold_ms
        self._handler = logging.FileHandler(path)
        self._handler.setFormatter(logging.Formatter("%(message)s"))

    def emit_session_start(self, record: dict) -> None:
        output = dict(record)
        output.setdefault("level", "info")
        output.setdefault("message", "blocksnoop session started")
        self._write(output)

    def emit(self, record: dict) -> None:
        output = dict(record)
        if "duration_ms" in output:
            duration_ms = float(output["duration_ms"])
            output["level"] = _level_for_duration(duration_ms, self._error_threshold_ms)
            output.setdefault(
                "message",
                f"Blocking call detected: {duration_ms:.1f}ms on tid={record['tid']}",
            )
        self._write(output)

    def emit_summary(self, summary: dict) -> None:
        output = dict(summary)
        output.setdefault("level", "info")
        output.setdefault(
            "message",
            f"blocksnoop session ended: {summary['event_count']} blocking events "
            f"in {summary['duration_s']:.1f}s",
        )
        self._write(output)

    def _write(self, record: dict) -> None:
        output = {
            **record,
            "timestamp": record.get(
                "observed_at",
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ),
            "service": self._service,
            "env": self._env,
            "source": "blocksnoop",
            "dd": {"service": self._service, "env": self._env},
        }
        log_record = logging.LogRecord(
            name="blocksnoop",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=json.dumps(output, sort_keys=True),
            args=(),
            exc_info=None,
        )
        self._handler.emit(log_record)

    def close(self) -> None:
        self._handler.close()

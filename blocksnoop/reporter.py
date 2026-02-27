"""Reporter module for blocksnoop — dispatches blocking events to output sinks."""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence

from blocksnoop.core import BlockingEvent
from blocksnoop.sinks import ConsoleSink, Sink

_logger = logging.getLogger("blocksnoop.reporter")


class Reporter:
    def __init__(self, sinks: Sequence[Sink] | None = None) -> None:
        self._sinks: Sequence[Sink] = sinks if sinks is not None else [ConsoleSink()]
        self._start_time = time.monotonic()
        self._event_count = 0

    def report(self, event: BlockingEvent) -> None:
        """Build a record dict and emit to all sinks."""
        self._event_count += 1
        if self._event_count == 1:
            _logger.debug(
                "First blocking event reported (duration=%.1fms)", event.duration_ms
            )
        elapsed_s = time.monotonic() - self._start_time

        python_stacks: list[list[dict]] | None = None
        if event.python_stacks:
            python_stacks = [
                [
                    {"function": f.function, "file": f.file, "line": f.line}
                    for f in stack.frames
                ]
                for stack in event.python_stacks
            ]

        record = {
            "event_number": self._event_count,
            "timestamp_s": round(elapsed_s, 6),
            "duration_ms": round(event.duration_ms, 3),
            "pid": event.pid,
            "tid": event.tid,
            "python_stacks": python_stacks,
        }

        for sink in self._sinks:
            sink.emit(record)

    @property
    def event_count(self) -> int:
        return self._event_count

    def summary(self, duration_s: float) -> None:
        """Build a summary dict and emit to all sinks."""
        summary = {
            "duration_s": duration_s,
            "event_count": self._event_count,
        }
        for sink in self._sinks:
            sink.emit_summary(summary)

    def close(self) -> None:
        """Close all sinks."""
        for sink in self._sinks:
            sink.close()

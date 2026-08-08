"""Build stable session records and dispatch them to output sinks."""

from __future__ import annotations

import hashlib
import linecache
import logging
import time
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from blocksnoop.core import STDLIB_FRAME_PREFIXES, BlockingEvent
from blocksnoop.sinks import ConsoleSink, Sink

_logger = logging.getLogger("blocksnoop.reporter")

EVENT_SCHEMA = "blocksnoop.events/v1"
EVENT_SCHEMA_VERSION = 1


def _get_source_line(file: str, line: int) -> str | None:
    """Return the stripped source code at *file*:*line*, or None."""
    text = linecache.getline(file, line).strip()
    return text if text else None


def _signature_for_stacks(
    stacks: list[list[dict[str, object]]] | None,
) -> dict[str, str]:
    """Return a stable, human-readable signature for a blocking call site."""
    if not stacks:
        identity = "no-python-stack"
        return {
            "fingerprint": hashlib.sha256(identity.encode()).hexdigest()[:12],
            "location": "(no Python stack captured)",
        }

    frames = stacks[0]
    application_frames = [
        frame
        for frame in frames
        if not any(prefix in str(frame["file"]) for prefix in STDLIB_FRAME_PREFIXES)
    ]
    selected = application_frames or frames
    parts = [
        f"{frame['file']}:{frame['line']}:{frame['function']}" for frame in selected
    ]
    identity = "|".join(parts)
    first = selected[0]
    return {
        "fingerprint": hashlib.sha256(identity.encode()).hexdigest()[:12],
        "location": f"{first['file']}:{first['line']} in {first['function']}",
    }


class Reporter:
    """Emit a typed session lifecycle plus blocking events and aggregates."""

    def __init__(
        self,
        sinks: Sequence[Sink] | None = None,
        *,
        backend: str | None = None,
        threshold_ms: float | None = None,
        target_pid: int | None = None,
        target_tid: int | None = None,
        error_threshold_ms: float = 500.0,
        summary_only: bool = False,
    ) -> None:
        self._sinks: Sequence[Sink] = sinks if sinks is not None else [ConsoleSink()]
        self._start_time = time.monotonic()
        self._event_count = 0
        self._error_event_count = 0
        self._total_blocked_ms = 0.0
        self._max_blocked_ms = 0.0
        self._lost_event_count = 0
        self._signatures: dict[str, dict[str, Any]] = {}
        self._session_id = str(uuid.uuid4())
        self._backend = backend
        self._threshold_ms = threshold_ms
        self._target_pid = target_pid
        self._target_tid = target_tid
        self._error_threshold_ms = error_threshold_ms
        self._summary_only = summary_only
        self._started = False

    def start(self) -> None:
        """Emit exactly one machine-readable session start record."""
        if self._started:
            return
        self._started = True
        record = self._base_record("session_start")
        record.update(
            {
                "backend": self._backend,
                "threshold_ms": self._threshold_ms,
                "target_pid": self._target_pid,
                "target_tid": self._target_tid,
            }
        )
        for sink in self._sinks:
            sink.emit_session_start(record)

    def report(self, event: BlockingEvent) -> None:
        """Build an event record, aggregate it, and emit it to all sinks."""
        self._event_count += 1
        if self._event_count == 1:
            _logger.debug(
                "First blocking event reported (duration=%.1fms)", event.duration_ms
            )
        elapsed_s = time.monotonic() - self._start_time

        python_stacks: list[list[dict[str, object]]] | None = None
        if event.python_stacks:
            python_stacks = [
                [
                    {
                        "function": frame.function,
                        "file": frame.file,
                        "line": frame.line,
                        "source": _get_source_line(frame.file, frame.line),
                    }
                    for frame in stack.frames
                ]
                for stack in event.python_stacks
            ]

        record = {
            **self._base_record("blocking_event"),
            "event_number": self._event_count,
            "timestamp_s": round(elapsed_s, 6),
            "duration_ms": round(event.duration_ms, 3),
            "pid": event.pid,
            "tid": event.tid,
            "python_stacks": python_stacks,
        }
        duration_ms = float(record["duration_ms"])
        self._total_blocked_ms += duration_ms
        self._max_blocked_ms = max(self._max_blocked_ms, duration_ms)
        if duration_ms >= self._error_threshold_ms:
            self._error_event_count += 1
        signature = _signature_for_stacks(python_stacks)
        aggregate = self._signatures.setdefault(
            signature["fingerprint"],
            {
                **signature,
                "count": 0,
                "total_blocked_ms": 0.0,
                "max_blocked_ms": 0.0,
            },
        )
        aggregate["count"] += 1
        aggregate["total_blocked_ms"] += duration_ms
        aggregate["max_blocked_ms"] = max(aggregate["max_blocked_ms"], duration_ms)

        if not self._summary_only:
            for sink in self._sinks:
                sink.emit(record)

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def error_event_count(self) -> int:
        return self._error_event_count

    def policy_failed(self, fail_on: str, *, fail_on_loss: bool) -> bool:
        """Return whether the completed session violates the requested policy."""
        if fail_on == "event" and self._event_count:
            return True
        if fail_on == "error" and self._error_event_count:
            return True
        return fail_on_loss and bool(self._lost_event_count)

    def summary(
        self,
        duration_s: float,
        *,
        loss_counts: Mapping[str, int] | None = None,
        termination_reason: str = "clean",
    ) -> None:
        """Emit the single final session summary, including top call sites."""
        losses = dict(loss_counts or {})
        self._lost_event_count = sum(losses.values())
        summary = {
            **self._base_record("session_summary"),
            "termination_reason": termination_reason,
            "status": _status_for_termination(termination_reason),
            "duration_s": duration_s,
            "event_count": self._event_count,
            "error_event_count": self._error_event_count,
            "total_blocked_ms": round(self._total_blocked_ms, 3),
            "max_blocked_ms": round(self._max_blocked_ms, 3),
            "lost_event_count": self._lost_event_count,
            "lost_events_by_source": losses,
            "top_signatures": self._top_signatures(),
        }
        for sink in self._sinks:
            sink.emit_summary(summary)

    def close(self) -> None:
        """Close all sinks."""
        for sink in self._sinks:
            sink.close()

    def _base_record(self, record_type: str) -> dict[str, object]:
        return {
            "schema": EVENT_SCHEMA,
            "schema_version": EVENT_SCHEMA_VERSION,
            "type": record_type,
            "session_id": self._session_id,
            "observed_at": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
        }

    def _top_signatures(self) -> list[dict[str, object]]:
        ranked = sorted(
            self._signatures.values(),
            key=lambda value: (value["total_blocked_ms"], value["max_blocked_ms"]),
            reverse=True,
        )[:5]
        return [
            {
                "fingerprint": value["fingerprint"],
                "location": value["location"],
                "count": value["count"],
                "total_blocked_ms": round(value["total_blocked_ms"], 3),
                "max_blocked_ms": round(value["max_blocked_ms"], 3),
            }
            for value in ranked
        ]


def _status_for_termination(termination_reason: str) -> str:
    """Translate a lifecycle reason into a stable session status."""
    return {
        "clean": "completed",
        "child_exit": "child_failed",
        "signal": "interrupted",
        "runtime_error": "failed",
    }.get(termination_reason, "unknown")

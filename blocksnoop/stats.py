"""Live statistics collector for eBPF-only epoll gap analysis."""

from __future__ import annotations

import array
import bisect
import json
import sys
import threading
import time
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from blocksnoop.core import BlockingEvent

_WARN_THRESHOLD = 10_000_000  # 10M events (~80 MB)


class StatsCollector:
    """Collects epoll gap durations and prints live statistics.

    Durations are stored in a sorted ``array.array('d')`` for compact
    storage and O(1) percentile lookup.

    The console display is written to *stream* as a single atomic write
    per tick, so interleaved output from other threads (warnings, log
    messages) does not corrupt the display.
    """

    def __init__(
        self,
        pid: int,
        *,
        json_mode: bool = False,
        stream: IO[str] = sys.stderr,
    ) -> None:
        self._pid = pid
        self._json_mode = json_mode
        self._stream = stream
        self._durations: array.array[float] = array.array("d")
        self._lock = threading.Lock()
        self._start_time: float = 0.0
        self._timer: threading.Timer | None = None
        self._lines_printed: int = 0
        self._warned = False

    # -- public API ----------------------------------------------------------

    def on_event(self, event: BlockingEvent) -> None:
        """Callback wired to EbpfDetector; accumulates durations."""
        with self._lock:
            bisect.insort(self._durations, event.duration_ms)
            if not self._warned and len(self._durations) >= _WARN_THRESHOLD:
                self._warned = True

    def start(self) -> None:
        """Begin periodic display updates."""
        self._start_time = time.monotonic()
        self._schedule()

    def stop(self) -> None:
        """Cancel the display timer and print final stats."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        self._print_stats()

    # -- internals -----------------------------------------------------------

    def _schedule(self) -> None:
        self._timer = threading.Timer(1.0, self._tick)
        self._timer.daemon = True
        self._timer.start()

    def _tick(self) -> None:
        self._print_stats()
        self._schedule()

    def _print_stats(self) -> None:
        with self._lock:
            count = len(self._durations)
            warned = self._warned
            elapsed = time.monotonic() - self._start_time
            if self._json_mode:
                self._print_json(count, elapsed)
            else:
                self._print_console(count, elapsed, warned)

    def _print_console(self, count: int, elapsed: float, warned: bool) -> None:
        # Build the entire frame as a single string so we do one write(),
        # minimising the window for interleaved output from other threads.
        parts: list[str] = []

        # Erase the previous frame: move up, clear each line, move back up
        if self._lines_printed > 0:
            parts.append(f"\033[{self._lines_printed}A")
            parts.append("\033[2K\n" * self._lines_printed)
            parts.append(f"\033[{self._lines_printed}A")

        rate = count / elapsed if elapsed > 0 else 0.0
        lines: list[str] = []
        lines.append(
            f"blocksnoop stats \u2014 PID {self._pid} \u2014 "
            f"{elapsed:.1f}s \u2014 {count} events ({rate:.0f}/s)"
        )
        lines.append("")

        stat_labels = ("min", "avg", "p50", "p90", "p95", "p99", "max")
        if count > 0:
            d = self._durations
            avg = sum(d) / count
            values: tuple[float, ...] = (
                d[0],
                avg,
                _percentile(d, 0.50),
                _percentile(d, 0.90),
                _percentile(d, 0.95),
                _percentile(d, 0.99),
                d[-1],
            )
            for label, val in zip(stat_labels, values):
                lines.append(f"  {label:<5}  {val:10.1f}ms")
        else:
            for label in stat_labels:
                lines.append(f"  {label:<5}  {'---':>10}ms")

        if warned:
            lines.append("")
            lines.append(
                f"  warning: {_WARN_THRESHOLD:,} events collected "
                f"(~{count * 8 // 1_000_000} MB)"
            )

        parts.append("\n".join(lines) + "\n")
        self._stream.write("".join(parts))
        self._stream.flush()
        self._lines_printed = len(lines)

    def _print_json(self, count: int, elapsed: float) -> None:
        rate = count / elapsed if elapsed > 0 else 0.0
        d = self._durations
        record: dict[str, object] = {
            "pid": self._pid,
            "elapsed_s": round(elapsed, 1),
            "count": count,
            "rate": round(rate, 1),
        }
        if count > 0:
            avg = sum(d) / count
            record.update(
                {
                    "min_ms": round(d[0], 3),
                    "avg_ms": round(avg, 3),
                    "p50_ms": round(_percentile(d, 0.50), 3),
                    "p90_ms": round(_percentile(d, 0.90), 3),
                    "p95_ms": round(_percentile(d, 0.95), 3),
                    "p99_ms": round(_percentile(d, 0.99), 3),
                    "max_ms": round(d[-1], 3),
                }
            )
        self._stream.write(json.dumps(record) + "\n")
        self._stream.flush()


def _percentile(sorted_arr: array.array[float], p: float) -> float:
    """Return the *p*-th percentile from a sorted array (nearest-rank)."""
    n = len(sorted_arr)
    idx = int(p * (n - 1))
    return sorted_arr[idx]

"""Profiler module for blocksnoop — py-spy based stack sampling."""

from __future__ import annotations

import bisect
import re
import shutil
import subprocess
import threading
import time
from typing import Optional

from blocksnoop.core import PythonStackTrace, StackFrame


def check_pyspy_available() -> bool:
    """Return True if py-spy binary is found in PATH."""
    return shutil.which("py-spy") is not None


def _parse_pyspy_output(raw: str, tid: int) -> Optional[PythonStackTrace]:
    """Parse py-spy raw format output for a specific thread id.

    Expected format::

        Thread 12345 (idle): "MainThread"
          compute_heavy (app.py:42)
          handle_request (app.py:30)

        Thread 12346 (active): "WorkerThread"
          do_work (worker.py:10)

    Returns the PythonStackTrace for the thread matching tid, or None if not found.
    """
    thread_header = re.compile(
        r'^Thread\s+(\d+)\s+\([^)]*\):\s+"([^"]*)"', re.MULTILINE
    )
    frame_line = re.compile(r"^\s+(\S+)\s+\(([^:]+):(\d+)\)\s*$")

    # Split into per-thread blocks by finding header positions
    headers = list(thread_header.finditer(raw))
    if not headers:
        return None

    target_block: Optional[tuple[int, str, str]] = None  # (thread_id, name, block_text)
    for idx, match in enumerate(headers):
        thread_id = int(match.group(1))
        thread_name = match.group(2)
        block_start = match.end()
        block_end = headers[idx + 1].start() if idx + 1 < len(headers) else len(raw)
        if thread_id == tid:
            target_block = (thread_id, thread_name, raw[block_start:block_end])
            break

    if target_block is None:
        return None

    thread_id, thread_name, block_text = target_block
    frames: list[StackFrame] = []
    for line in block_text.splitlines():
        m = frame_line.match(line)
        if m:
            frames.append(
                StackFrame(function=m.group(1), file=m.group(2), line=int(m.group(3)))
            )

    return PythonStackTrace(
        thread_id=thread_id,
        thread_name=thread_name,
        frames=tuple(frames),
    )


class StackRingBuffer:
    """Fixed-size ring buffer storing (timestamp_ns, PythonStackTrace) tuples.

    Entries are stored in chronological insertion order. Thread-safe.
    """

    def __init__(self, size: int = 256) -> None:
        self._size = size
        self._buffer: list[Optional[tuple[int, PythonStackTrace]]] = [None] * size
        self._head = 0  # index of next write position
        self._count = 0  # number of valid entries
        self._lock = threading.Lock()

    def push(self, timestamp_ns: int, stack: PythonStackTrace) -> None:
        """Add an entry, overwriting the oldest entry when the buffer is full."""
        with self._lock:
            self._buffer[self._head] = (timestamp_ns, stack)
            self._head = (self._head + 1) % self._size
            if self._count < self._size:
                self._count += 1

    def _ordered_entries(self) -> list[tuple[int, PythonStackTrace]]:
        """Return entries in chronological order (oldest first). Must hold lock."""
        if self._count == 0:
            return []
        if self._count < self._size:
            # Buffer not yet full: entries occupy [0, _count), head == _count
            return [self._buffer[i] for i in range(self._count)]  # type: ignore[misc]
        # Buffer full: oldest entry is at _head
        ordered = []
        for i in range(self._size):
            entry = self._buffer[(self._head + i) % self._size]
            if entry is not None:
                ordered.append(entry)
        return ordered

    def find_in_range(self, start_ns: int, end_ns: int) -> Optional[PythonStackTrace]:
        """Binary search for the snapshot closest to start_ns within [start_ns, end_ns].

        Returns None if no entry falls within the window.
        """
        with self._lock:
            entries = self._ordered_entries()

        if not entries:
            return None

        timestamps = [e[0] for e in entries]

        # Find insertion point for start_ns
        pos = bisect.bisect_left(timestamps, start_ns)

        best: Optional[tuple[int, PythonStackTrace]] = None
        best_diff = end_ns - start_ns + 1  # larger than any valid diff

        # Check the entry at pos and pos-1 as candidates
        for idx in (pos - 1, pos):
            if 0 <= idx < len(entries):
                ts, stack = entries[idx]
                if start_ns <= ts <= end_ns:
                    diff = abs(ts - start_ns)
                    if diff < best_diff:
                        best_diff = diff
                        best = (ts, stack)

        return best[1] if best is not None else None


class StackSampler:
    """Background daemon thread that periodically samples a process via py-spy."""

    def __init__(
        self, pid: int, sample_interval_ms: float, tid: Optional[int] = None
    ) -> None:
        self._pid = pid
        self._tid = tid if tid is not None else pid
        self._interval_s = sample_interval_ms / 1000.0
        self.ring_buffer = StackRingBuffer()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background sampling thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="blocksnoop-sampler"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the sampling thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._sample()
            self._stop_event.wait(timeout=self._interval_s)

    def _sample(self) -> None:
        try:
            result = subprocess.run(
                ["py-spy", "dump", "--pid", str(self._pid)],
                capture_output=True,
                text=True,
                timeout=max(self._interval_s * 2, 5.0),
            )
            raw = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return

        stack = _parse_pyspy_output(raw, self._tid)
        if stack is not None:
            self.ring_buffer.push(time.monotonic_ns(), stack)

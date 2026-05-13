"""Profiler module for blocksnoop — stack sampling via Austin."""

from __future__ import annotations

import bisect
import glob
import logging
import os
import shutil
import stat
import threading
import time
from pathlib import Path

from austin.errors import AustinError
from austin.stats import AustinMetadata, AustinSample
from austin.threads import ThreadedAustin

from blocksnoop.core import PythonStackTrace, StackFrame

_logger = logging.getLogger("blocksnoop.profiler")


def check_austin_available() -> bool:
    """Return True if austin binary is found in PATH."""
    return shutil.which("austin") is not None


def _in_same_mount_ns(pid: int) -> bool:
    """Check if the current process shares a mount namespace with *pid*."""
    try:
        self_mnt = os.stat("/proc/self/ns/mnt")
        target_mnt = os.stat(f"/proc/{pid}/ns/mnt")
        return (self_mnt.st_dev, self_mnt.st_ino) == (
            target_mnt.st_dev,
            target_mnt.st_ino,
        )
    except OSError:
        return True  # assume same namespace if we can't check


def _find_musl_linker() -> str | None:
    """Find the musl dynamic linker on this system."""
    matches = glob.glob("/lib/ld-musl-*.so.1")
    return matches[0] if matches else None


def _resolve_ns_pid(pid: int) -> int:
    """Return *pid* translated into the deepest PID namespace it belongs to.

    `/proc/<pid>/status` exposes an ``NSpid`` line listing the PID at each
    nested namespace level, from outermost to innermost. When blocksnoop runs
    in a different PID namespace from the target (e.g. ``hostPID: true`` Job
    targeting a container with its own PID namespace), we must pass the
    innermost PID to Austin — that's the PID Austin will see once we
    ``nsenter -p`` into the target's PID namespace. If no nesting exists,
    returns *pid* unchanged.
    """
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("NSpid:"):
                    parts = line.split()
                    # parts = ["NSpid:", outermost, ..., innermost]
                    if len(parts) >= 2:
                        return int(parts[-1])
                    break
    except OSError:
        pass
    return pid


def _create_nsenter_wrapper(pid: int) -> str:
    """Create a script that runs austin inside the target's mount + pid namespaces.

    Uses shell fd redirection to open the austin binary (and the musl dynamic
    linker, if austin needs one) in *blocksnoop's* mount namespace, then
    ``nsenter -m -p``s into the target and execs via ``/proc/self/fd/N``.

    Both namespaces must be entered:

    - ``-m`` so Austin sees the target's filesystem (its Python binary +
      shared libraries).
    - ``-p`` so the ``/proc`` mounted inside the target's mount namespace
      (which is bound to the target's PID namespace) recognises the caller
      and resolves ``/proc/self/fd/N``. Without ``-p``, ``/proc/self`` has
      no entry for the caller (its host PID isn't visible in the container's
      PID namespace) and ``execve("/proc/self/fd/N")`` fails with ENOENT.

    fds opened by shell redirection survive ``execve`` (no CLOEXEC), so
    Austin loads from blocksnoop's rootfs while running with the target's
    filesystem and process views. Nothing is written to the target.
    """
    austin_path = shutil.which("austin")
    if austin_path is None:
        raise RuntimeError("Austin binary not found")

    musl_linker = _find_musl_linker()
    lines = ["#!/bin/sh", f"exec 3<{austin_path}"]
    if musl_linker is not None:
        lines.append(f"exec 4<{musl_linker}")
        # Invoke austin via the musl linker so we don't depend on the target
        # having a compatible libc/linker installed.
        austin_invocation = "/proc/self/fd/4 /proc/self/fd/3"
    else:
        austin_invocation = "/proc/self/fd/3"
    lines.append(f'exec nsenter -m -p -t {pid} -- {austin_invocation} "$@"')

    wrapper = f"/tmp/.austin-nsenter-{pid}"
    with open(wrapper, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(wrapper, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    return wrapper


class StackRingBuffer:
    """Fixed-size ring buffer storing (timestamp_ns, PythonStackTrace) tuples.

    Entries are stored in chronological insertion order. Thread-safe.
    """

    def __init__(self, size: int = 256) -> None:
        self._size = size
        self._buffer: list[tuple[int, PythonStackTrace] | None] = [None] * size
        self._head = 0  # index of next write position
        self._count = 0  # number of valid entries
        self._overflow_count = 0
        self._lock = threading.Lock()

    @property
    def overflow_count(self) -> int:
        """Number of entries lost to overflow."""
        return self._overflow_count

    def push(self, timestamp_ns: int, stack: PythonStackTrace) -> None:
        """Add an entry, overwriting the oldest entry when the buffer is full."""
        with self._lock:
            self._buffer[self._head] = (timestamp_ns, stack)
            self._head = (self._head + 1) % self._size
            if self._count < self._size:
                self._count += 1
            else:
                self._overflow_count += 1
                if self._overflow_count == 1:
                    _logger.warning(
                        "Stack ring buffer overflow (size=%d) — oldest samples "
                        "are being dropped. Consider increasing buffer size.",
                        self._size,
                    )

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

    def find_all_in_range(self, start_ns: int, end_ns: int) -> list[PythonStackTrace]:
        """Return all samples within [start_ns, end_ns], oldest first."""
        with self._lock:
            entries = self._ordered_entries()

        if not entries:
            return []

        timestamps = [e[0] for e in entries]
        lo = bisect.bisect_left(timestamps, start_ns)
        hi = bisect.bisect_right(timestamps, end_ns)
        return [entries[i][1] for i in range(lo, hi)]

    def find_in_range(self, start_ns: int, end_ns: int) -> PythonStackTrace | None:
        """Binary search for the snapshot closest to start_ns within [start_ns, end_ns].

        Returns None if no entry falls within the window.
        """
        return self.find_nearest(target_ns=start_ns, start_ns=start_ns, end_ns=end_ns)

    def find_nearest(
        self,
        target_ns: int,
        start_ns: int,
        end_ns: int,
    ) -> PythonStackTrace | None:
        """Return the sample closest to *target_ns* within [start_ns, end_ns].

        Uses binary search on the chronologically-ordered entries.
        Returns ``None`` if no entry falls within the window.
        """
        with self._lock:
            entries = self._ordered_entries()

        if not entries:
            return None

        timestamps = [e[0] for e in entries]

        # Find insertion point for target_ns
        pos = bisect.bisect_left(timestamps, target_ns)

        best: tuple[int, PythonStackTrace] | None = None
        best_diff = end_ns - start_ns + 1  # larger than any valid diff

        # Check the entry at pos and pos-1 as candidates
        for idx in (pos - 1, pos):
            if 0 <= idx < len(entries):
                ts, stack = entries[idx]
                if start_ns <= ts <= end_ns:
                    diff = abs(ts - target_ns)
                    if diff < best_diff:
                        best_diff = diff
                        best = (ts, stack)

        return best[1] if best is not None else None


class _LoopspyAustin(ThreadedAustin):
    """ThreadedAustin subclass that pushes samples to a ring buffer."""

    def __init__(self, ring_buffer: StackRingBuffer, tid: int) -> None:
        super().__init__()
        self._ring_buffer = ring_buffer
        self._tid = tid
        self.sample_count = 0
        self.filtered_count = 0

    def on_metadata(self, metadata: AustinMetadata) -> None:
        _logger.debug("Austin metadata: %s=%s", metadata.name, metadata.value)

    def on_terminate(self) -> None:
        _logger.debug(
            "Austin terminated (samples: %d accepted, %d filtered)",
            self.sample_count,
            self.filtered_count,
        )
        if self.sample_count == 0:
            _logger.warning(
                "Austin produced no samples — stack traces will be unavailable. "
                "Ensure the target is a Python process and ptrace is allowed."
            )

    def on_sample(self, sample: AustinSample) -> None:
        if sample.frames is None:
            return
        try:
            if int(sample.thread, 16) != self._tid:
                self.filtered_count += 1
                return
        except (ValueError, TypeError):
            self.filtered_count += 1
            return
        frames = tuple(
            StackFrame(function=f.function, file=f.filename, line=f.line)
            for f in sample.frames
        )
        self._ring_buffer.push(
            time.monotonic_ns(),
            PythonStackTrace(thread_id=self._tid, thread_name="", frames=frames),
        )
        self.sample_count += 1
        if self.sample_count == 1:
            _logger.debug(
                "Austin: first sample received (tid=%d, %d frames)",
                self._tid,
                len(frames),
            )
        elif self.sample_count % 100 == 0:
            _logger.debug(
                "Austin samples: %d accepted, %d filtered (wrong tid), buffer=%d/%d",
                self.sample_count,
                self.filtered_count,
                self._ring_buffer._count,
                self._ring_buffer._size,
            )


class AustinSampler:
    """Background sampler using Austin via austin-python's ThreadedAustin."""

    def __init__(
        self, pid: int, sample_interval_ms: float, tid: int | None = None
    ) -> None:
        self._pid = pid
        self._tid = tid if tid is not None else pid
        self._interval_us = int(sample_interval_ms * 1000)
        self.ring_buffer = StackRingBuffer()
        self._austin: _LoopspyAustin | None = None
        self._health_timer: threading.Timer | None = None
        self._nsenter_wrapper: str | None = None

    def start(self) -> None:
        """Spawn Austin and start sampling."""
        if self._austin is not None:
            return
        _logger.debug(
            "Starting Austin: pid=%d, tid=%d, interval=%dμs",
            self._pid,
            self._tid,
            self._interval_us,
        )
        austin_pid = self._pid
        austin_tid = self._tid
        nsenter_wrapper: str | None = None
        if not _in_same_mount_ns(self._pid):
            nsenter_wrapper = _create_nsenter_wrapper(self._pid)
            self._nsenter_wrapper = nsenter_wrapper
            # The wrapper enters the target's PID namespace via `nsenter -p`,
            # so Austin sees PIDs/TIDs as the *container* does — small numbers
            # like 1, not host PIDs. We must translate BOTH:
            #   - the pid arg passed to Austin (`-p`), or it can't attach
            #   - the tid used by _LoopspyAustin to filter samples, or every
            #     sample arrives with the container-local thread id and gets
            #     rejected as "wrong tid", producing zero accepted samples.
            austin_pid = _resolve_ns_pid(self._pid)
            austin_tid = _resolve_ns_pid(self._tid)
            _logger.debug(
                "Using nsenter to access target mount+pid namespaces "
                "(host_pid=%d host_tid=%d, ns_pid=%d ns_tid=%d)",
                self._pid,
                self._tid,
                austin_pid,
                austin_tid,
            )
        self._austin = _LoopspyAustin(self.ring_buffer, austin_tid)
        if nsenter_wrapper is not None:
            # Override austin-python's binary_path (a cached_property) so it
            # uses our nsenter wrapper instead of the bare austin binary.
            self._austin.__dict__["binary_path"] = Path(nsenter_wrapper)
        self._austin.start(
            [
                "-i",
                str(self._interval_us),
                "-p",
                str(austin_pid),
            ]
        )
        self._health_timer = threading.Timer(3.0, self._check_health)
        self._health_timer.daemon = True
        self._health_timer.start()

    def _check_health(self) -> None:
        if self._austin is not None and self._austin.sample_count == 0:
            _logger.warning(
                "Austin has not produced any samples after 3s. "
                "Check that the target process (pid=%d) is a Python process "
                "and that ptrace is allowed.",
                self._pid,
            )

    def stop(self) -> None:
        """Terminate Austin and wait for the thread."""
        if self._health_timer is not None:
            self._health_timer.cancel()
            self._health_timer = None
        if self._austin is None:
            return
        _logger.debug(
            "Stopping Austin (total samples: %d accepted, %d filtered, %d overflows)",
            self._austin.sample_count,
            self._austin.filtered_count,
            self.ring_buffer.overflow_count,
        )
        try:
            self._austin.terminate()
        except (OSError, AustinError):
            _logger.debug("Austin process already terminated")
        except Exception:
            _logger.warning("Unexpected error terminating Austin", exc_info=True)
        try:
            self._austin.join(timeout=5)
        except (OSError, ValueError, AustinError):
            # OSError: thread already joined; ValueError: MOJO parser interrupted
            # during shutdown; AustinError: Austin failed to start or already exited.
            _logger.debug("Austin thread stopped during shutdown")
        except Exception:
            _logger.warning("Unexpected error joining Austin thread", exc_info=True)
        self._austin = None
        if self._nsenter_wrapper is not None:
            try:
                os.unlink(self._nsenter_wrapper)
            except OSError:
                pass
            self._nsenter_wrapper = None

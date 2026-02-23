"""eBPF-based blocking event detector for blocksnoop."""

from __future__ import annotations

import ctypes
import logging
import os
import threading
from collections.abc import Callable

from blocksnoop.core import BlockingEvent, DetectorConfig

_logger = logging.getLogger("blocksnoop.detector")


# Preferred order: epoll_wait is simplest (no sigset_t), then epoll_pwait, then epoll_pwait2.
_EPOLL_CANDIDATES = ("epoll_wait", "epoll_pwait", "epoll_pwait2")
_TRACEFS_EVENTS = "/sys/kernel/debug/tracing/events/syscalls"


def _detect_epoll_syscall() -> str:
    """Return the best available epoll syscall tracepoint name."""
    for name in _EPOLL_CANDIDATES:
        if os.path.isdir(os.path.join(_TRACEFS_EVENTS, f"sys_enter_{name}")):
            return name
    raise RuntimeError(
        f"No epoll tracepoint found in {_TRACEFS_EVENTS}. "
        "Ensure tracefs is mounted and the kernel supports syscall tracepoints."
    )


class _BpfEvent(ctypes.Structure):
    _fields_ = [
        ("start_ns", ctypes.c_uint64),
        ("end_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
    ]


class EbpfDetector:
    def __init__(
        self,
        config: DetectorConfig,
        callback: Callable[[BlockingEvent], None],
    ) -> None:
        self._config = config
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        bpf_source_path = os.path.join(
            os.path.dirname(__file__), "bpf", "blockdetect.c"
        )
        with open(bpf_source_path, "r") as f:
            source = f.read()

        threshold_ns = int(config.threshold_ms * 1_000_000)
        epoll_syscall = _detect_epoll_syscall()
        _logger.debug("Using epoll syscall: %s", epoll_syscall)
        source = source.replace("__TARGET_TGID__", str(config.pid))
        source = source.replace("__THRESHOLD_NS__", str(threshold_ns))
        source = source.replace("__EPOLL_SYSCALL__", epoll_syscall)
        if epoll_syscall != "epoll_wait":
            source = source.replace("#ifdef __NEEDS_SIGSET_T__", "#if 1")

        from bcc import BPF  # type: ignore[import]

        self._bpf = BPF(text=source)
        self._bpf["events"].open_perf_buffer(self._handle_event)
        _logger.debug("BPF program loaded, perf buffer open")

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            self._bpf.perf_buffer_poll(timeout=100)

    def _handle_event(self, cpu: int, data: ctypes.c_void_p, size: int) -> None:
        event = ctypes.cast(data, ctypes.POINTER(_BpfEvent)).contents
        blocking_event = BlockingEvent(
            start_ns=event.start_ns,
            end_ns=event.end_ns,
            pid=event.pid,
            tid=event.tid,
            python_stacks=(),
        )
        _logger.debug(
            "Blocking event: tid=%d duration=%.1fms",
            event.tid,
            blocking_event.duration_ms,
        )
        self._callback(blocking_event)

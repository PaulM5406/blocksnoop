"""eBPF-based blocking event detector for blocksnoop."""

from __future__ import annotations

import ctypes
import glob
import logging
import os
import platform
import threading
from pathlib import Path

from collections.abc import Callable

from blocksnoop.core import BlockingEvent, DetectorConfig

_logger = logging.getLogger("blocksnoop.detector")


# Preferred order: epoll_wait is simplest (no sigset_t), then epoll_pwait, then epoll_pwait2.
_EPOLL_CANDIDATES = ("epoll_wait", "epoll_pwait", "epoll_pwait2")
_TRACEFS_EVENTS = "/sys/kernel/debug/tracing/events/syscalls"

_ARCH_SUFFIXES = ("arm64", "amd64", "cloud-amd64")
_MACHINE_TO_KARCH = {"aarch64": "arm64", "x86_64": "x86"}


def _ensure_kernel_headers() -> None:
    """Symlink installed kernel headers so BCC finds them for the running kernel.

    In containers the installed headers package often differs from the host
    kernel.  BCC only needs stable UAPI headers for blocksnoop's tracepoint
    program, so mismatched versions work fine.
    """
    kernel = os.uname().release
    build_dir = Path(f"/lib/modules/{kernel}/build")

    if build_dir.is_dir():
        return

    # Find arch-specific headers
    arch_headers: Path | None = None
    for suffix in _ARCH_SUFFIXES:
        matches = sorted(glob.glob(f"/usr/src/linux-headers-*-{suffix}"))
        if matches:
            arch_headers = Path(matches[0])
            break

    # Find common headers
    common_matches = sorted(glob.glob("/usr/src/linux-headers-*-common"))
    common_headers = Path(common_matches[0]) if common_matches else None

    if not arch_headers and not common_headers:
        _logger.warning(
            "No kernel headers found in /usr/src — BCC compilation will likely fail"
        )
        return

    headers = arch_headers or common_headers
    assert headers is not None

    build_dir.parent.mkdir(parents=True, exist_ok=True)
    build_dir.symlink_to(headers)
    _logger.debug("Symlinked %s → %s", build_dir, headers)

    # Merge common includes into arch-specific tree
    if common_headers and arch_headers:
        _merge_common_headers(arch_headers, common_headers)


def _merge_common_headers(arch_headers: Path, common_headers: Path) -> None:
    """Symlink common header dirs and arch-specific asm into the arch tree."""
    include = common_headers / "include"
    if include.is_dir():
        for sub in include.iterdir():
            target = arch_headers / "include" / sub.name
            if not target.exists():
                target.symlink_to(sub)
                _logger.debug("Symlinked common include %s", sub.name)

    machine = platform.machine()
    karch = _MACHINE_TO_KARCH.get(machine, machine)

    asm_src = common_headers / "arch" / karch / "include" / "asm"
    asm_dst = arch_headers / "include" / "asm"
    if asm_src.is_dir() and not asm_dst.exists():
        asm_dst.symlink_to(asm_src)

    uapi_asm_src = common_headers / "arch" / karch / "include" / "uapi" / "asm"
    uapi_asm_dst = arch_headers / "include" / "uapi" / "asm"
    if uapi_asm_src.is_dir() and not uapi_asm_dst.exists():
        uapi_asm_dst.parent.mkdir(parents=True, exist_ok=True)
        uapi_asm_dst.symlink_to(uapi_asm_src)


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

        _ensure_kernel_headers()

        from bcc import BPF  # type: ignore[import]

        self._bpf = BPF(text=source)
        self._bpf["events"].open_perf_buffer(self._handle_event)
        _logger.debug("BPF program loaded, perf buffer open")

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        _logger.debug("eBPF polling thread started (pid=%d)", self._config.pid)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None
        _logger.debug("eBPF polling thread stopped")

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

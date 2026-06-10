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


def _detect_epoll_syscalls() -> list[str]:
    """Return every epoll syscall tracepoint available on this kernel.

    We trace *all* available variants instead of guessing one. Which epoll
    syscall a process's event loop actually enters depends on its libc and
    loop implementation: glibc routes ``epoll_wait()`` through the
    ``epoll_pwait`` syscall, and uvloop/libuv call ``epoll_pwait`` (or, on
    recent kernels, ``epoll_pwait2``) directly. A detector hard-wired to
    ``epoll_wait`` attaches fine but never fires on those loops — the exact
    "everything attaches but nothing comes out" failure. Tracing the whole
    family makes detection independent of that choice; the candidates that
    don't exist on this kernel are simply skipped so BCC never references a
    missing tracepoint.
    """
    available = [
        name
        for name in _EPOLL_CANDIDATES
        if os.path.isdir(os.path.join(_TRACEFS_EVENTS, f"sys_enter_{name}"))
    ]
    if not available:
        raise RuntimeError(
            f"No epoll tracepoint found in {_TRACEFS_EVENTS}. "
            "Ensure tracefs is mounted and the kernel supports syscall tracepoints."
        )
    return available


# A sys_exit/sys_enter probe pair, instantiated once per available epoll
# variant and substituted into blockdetect.c's __EPOLL_PROBES__ marker. The
# tgid/tid resolution and threshold placeholders are filled by
# _build_bpf_source after all pairs are joined.
_EPOLL_PROBE_TEMPLATE = r"""
// __EPOLL_SYSCALL__ returns → callbacks about to run
TRACEPOINT_PROBE(syscalls, sys_exit___EPOLL_SYSCALL__) {
#ifdef __USE_NS_PID__
    struct bpf_pidns_info nsdata = {};
    if (bpf_get_ns_current_pid_tgid(__PIDNS_DEV__, __PIDNS_INO__, &nsdata, sizeof(nsdata)) != 0)
        return 0;
    u32 tgid = nsdata.tgid;
    u32 tid = nsdata.pid;
#else
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
#endif

    if (tgid != __TARGET_TGID__)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    callback_start.update(&tid, &ts);
    return 0;
}

// entering __EPOLL_SYSCALL__ → callbacks done
TRACEPOINT_PROBE(syscalls, sys_enter___EPOLL_SYSCALL__) {
#ifdef __USE_NS_PID__
    struct bpf_pidns_info nsdata = {};
    if (bpf_get_ns_current_pid_tgid(__PIDNS_DEV__, __PIDNS_INO__, &nsdata, sizeof(nsdata)) != 0)
        return 0;
    u32 tgid = nsdata.tgid;
    u32 tid = nsdata.pid;
#else
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
#endif

    if (tgid != __TARGET_TGID__)
        return 0;

    u64 *tsp = callback_start.lookup(&tid);
    if (!tsp)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 delta = now - *tsp;

    if (delta > __THRESHOLD_NS__) {
        struct event_t evt = {};
        evt.start_ns = *tsp;
        evt.end_ns = now;
        evt.pid = tgid;
        evt.tid = tid;
        events.perf_submit(args, &evt, sizeof(evt));
    }

    callback_start.delete(&tid);
    return 0;
}
"""


def _build_bpf_source(
    raw_source: str,
    *,
    threshold_ms: float,
    target_tgid: int,
    epoll_syscalls: list[str],
    pidns_info: tuple[int, int] | None,
) -> str:
    """Assemble the final BCC program from blockdetect.c.

    Generates one probe pair per epoll variant, then fills the threshold,
    target tgid and (optional) PID-namespace placeholders. When *pidns_info*
    is given, ``__USE_NS_PID__`` is defined so the probes use
    ``bpf_get_ns_current_pid_tgid`` and compare against the target's
    namespace-local tgid.
    """
    threshold_ns = int(threshold_ms * 1_000_000)
    probes = "\n".join(
        _EPOLL_PROBE_TEMPLATE.replace("__EPOLL_SYSCALL__", name)
        for name in epoll_syscalls
    )
    source = raw_source.replace("__EPOLL_PROBES__", probes)
    source = source.replace("__THRESHOLD_NS__", str(threshold_ns))
    source = source.replace("__TARGET_TGID__", str(target_tgid))
    if pidns_info is not None:
        dev, ino = pidns_info
        source = "#define __USE_NS_PID__\n" + source
        source = source.replace("__PIDNS_DEV__", str(dev))
        source = source.replace("__PIDNS_INO__", str(ino))
    return source


def _resolve_target_ns_tgid(host_pid: int) -> int:
    """Return the target's TGID *as seen from its own PID namespace*.

    Reads ``NSpid`` from ``/proc/<host_pid>/status``. That line lists the
    PID at each nested PID namespace level (outermost → innermost). The
    innermost value is what the kernel's ``bpf_get_ns_current_pid_tgid``
    helper returns for tasks running in the target's PID namespace, so
    that's what the BPF filter must compare against.

    Falls back to ``host_pid`` when the file can't be read or no ``NSpid``
    line exists — i.e. the same-namespace case where host TGID == target
    TGID, which is also the safe default for old kernels without ``NSpid``.
    """
    try:
        with open(f"/proc/{host_pid}/status") as f:
            for line in f:
                if line.startswith("NSpid:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[-1])
                    break
    except OSError:
        pass
    return host_pid


def _get_pidns_info(target_pid: int | None = None) -> tuple[int, int] | None:
    """Return (st_dev, st_ino) of the *target's* PID namespace.

    The eBPF filter compares each event's PID-namespace dev/ino against
    this pair, so we must use the namespace the target lives in — not
    blocksnoop's own. When blocksnoop and the target share a PID namespace
    (e.g. ``docker run --pid=container:<target>``) the two are identical,
    which is why this distinction didn't matter before.

    When blocksnoop runs in a different PID namespace from the target
    (e.g. K8s Job with ``hostPID: true`` against a container in its own
    PID ns), this function reads ``/proc/<target_pid>/ns/pid`` so the
    eBPF filter matches the target's events and not the (empty) set of
    events in blocksnoop's own PID namespace.

    Falls back to ``/proc/self/ns/pid`` when no target is provided or the
    target's namespace file is unreachable.
    """
    candidates: list[str] = []
    if target_pid is not None:
        candidates.append(f"/proc/{target_pid}/ns/pid")
    candidates.append("/proc/self/ns/pid")
    for path in candidates:
        try:
            st = os.stat(path)
            return (st.st_dev, st.st_ino)
        except OSError:
            continue
    return None


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
            raw_source = f.read()

        epoll_syscalls = _detect_epoll_syscalls()
        _logger.debug("Tracing epoll syscalls: %s", ", ".join(epoll_syscalls))

        # `__TARGET_TGID__` is compared against the tgid the BPF program
        # observes. When `__USE_NS_PID__` is enabled the program uses
        # `bpf_get_ns_current_pid_tgid()` which returns the *namespace-local*
        # tgid (e.g. 1 for the main process in a container). We therefore
        # need to substitute the in-target NSpid here, not the host PID, or
        # every event gets filtered out. _resolve_target_ns_tgid() returns
        # the host PID when blocksnoop and target share a PID namespace.
        target_tgid = _resolve_target_ns_tgid(config.pid)

        pidns_info = _get_pidns_info(target_pid=config.pid)
        if pidns_info is not None:
            _logger.debug(
                "Using PID-namespace-aware filtering (dev=%d, ino=%d)", *pidns_info
            )
        else:
            _logger.warning(
                "PID namespace translation unavailable"
                " \u2014 ensure hostPID or matching namespace"
            )

        source = _build_bpf_source(
            raw_source,
            threshold_ms=config.threshold_ms,
            target_tgid=target_tgid,
            epoll_syscalls=epoll_syscalls,
            pidns_info=pidns_info,
        )

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

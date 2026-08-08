"""Core eBPF sidecar detector backend using a versioned NDJSON protocol."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
from collections.abc import Callable
from typing import Any

from blocksnoop.core import BlockingEvent, DetectorConfig, LostEvent

_logger = logging.getLogger("blocksnoop.core_backend")

PROTOCOL_VERSION = 2
DEFAULT_SIDECAR = "blocksnoop-ebpf"
_STDERR_TAIL_LIMIT = 4096
_UINT64_MAX = (1 << 64) - 1
_LOSS_SOURCES = frozenset(("perf_buffer",))


def find_sidecar(executable: str = DEFAULT_SIDECAR) -> str | None:
    """Resolve a sidecar executable, allowing an explicit test/deploy override."""
    return shutil.which(os.environ.get("BLOCKSNOOP_EBPF", executable))


class CoreDetectorError(RuntimeError):
    """The Core eBPF sidecar could not be started or did not handshake."""


class CoreDetector:
    """Read blocking events from the ``blocksnoop-ebpf`` Core sidecar.

    The sidecar writes one JSON object per stdout line. Every message carries
    ``version: 2`` and one of four types: ``ready``, ``event``, ``lost`` or
    ``fatal``. ``start`` waits for ``ready`` so a forced Core backend fails
    early and explicitly instead of falling back to BCC.
    """

    def __init__(
        self,
        config: DetectorConfig,
        callback: Callable[[BlockingEvent], None],
        *,
        loss_callback: Callable[[LostEvent], None] | None = None,
        executable: str = DEFAULT_SIDECAR,
        ready_timeout_s: float = 5.0,
    ) -> None:
        self._config = config
        self._callback = callback
        self._loss_callback = loss_callback
        self._executable = executable
        self._ready_timeout_s = ready_timeout_s
        self._process: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None
        self._stderr_tail = ""
        self._ready = threading.Event()
        self._stop_requested = threading.Event()
        self._startup_error: str | None = None
        self._runtime_error: str | None = None
        self._lock = threading.Lock()
        self._loss_lock = threading.Lock()
        self._loss_counts: dict[str, int] = {}
        self._expected_pid = config.pid
        self._expected_tid = config.tid
        self._pidns_dev: int | None = None
        self._pidns_ino: int | None = None

    def start(self) -> None:
        """Launch the sidecar and wait for its protocol ``ready`` message."""
        with self._lock:
            if self._process is not None:
                return

            sidecar = find_sidecar(self._executable)
            if sidecar is None:
                raise CoreDetectorError(
                    f"{self._executable} sidecar was not found in PATH. "
                    "Install a blocksnoop release that includes the Core sidecar "
                    "or run with --backend bcc."
                )

            assert self._config.tid is not None
            self._ready.clear()
            self._stop_requested.clear()
            self._startup_error = None
            self._runtime_error = None
            self._stderr_tail = ""
            self._loss_counts = {}
            try:
                command = self._build_command(sidecar)
                self._process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    shell=False,
                )
                self._reader = threading.Thread(target=self._read_messages, daemon=True)
                self._stderr_reader = threading.Thread(
                    target=self._read_stderr, daemon=True
                )
                self._reader.start()
                self._stderr_reader.start()
            except OSError as exc:
                self._cleanup_locked()
                detail = exc.strerror or str(exc)
                raise CoreDetectorError(
                    f"Could not start {sidecar}: {detail}. "
                    "Check that the sidecar is executable and matches this platform."
                ) from exc
            except Exception:
                self._cleanup_locked()
                raise

        if not self._ready.wait(timeout=self._ready_timeout_s):
            self.stop()
            raise CoreDetectorError(
                f"{self._executable} did not send a ready handshake within "
                f"{self._ready_timeout_s:g}s. Check sidecar logs and protocol version."
            )
        if self._startup_error is not None:
            error = self._startup_error
            self.stop()
            stderr = self._stderr_tail.strip()
            stderr_detail = f" Sidecar stderr: {stderr}" if stderr else ""
            raise CoreDetectorError(
                f"{self._executable} handshake failed: {error}. "
                "Check that its protocol version matches blocksnoop."
                f"{stderr_detail}"
            )

    def check_health(self) -> None:
        """Raise an actionable error when the sidecar failed after ``ready``."""
        if self._runtime_error is not None:
            raise CoreDetectorError(
                f"{self._executable} stopped collecting: {self._runtime_error}. "
                f"Sidecar stderr: {self._stderr_tail.strip() or '(empty)'}"
            )
        process = self._process
        if (
            process is not None
            and process.poll() is not None
            and not self._stop_requested.is_set()
        ):
            raise CoreDetectorError(
                f"{self._executable} exited unexpectedly. "
                f"Sidecar stderr: {self._stderr_tail.strip() or '(empty)'}"
            )

    def stop(self) -> None:
        """Stop the sidecar. Safe to call before start or more than once."""
        with self._lock:
            # Keep readers alive until EOF so any loss records already in the
            # pipe reach the CLI summary, while suppressing the expected
            # post-stop EOF error.
            self._stop_requested.set()
            self._cleanup_locked()

    @property
    def loss_counts(self) -> dict[str, int]:
        """Thread-safe snapshot of sidecar loss counters by source."""
        with self._loss_lock:
            return dict(self._loss_counts)

    def _build_command(self, sidecar: str) -> list[str]:
        """Build a v2 sidecar command in the target's PID namespace.

        The native collector resolves the explicit PID namespace with
        ``bpf_get_ns_current_pid_tgid``. Resolve and validate the target
        identity before spawning so Core cannot attach but observe a different
        process. The collector itself stays in blocksnoop's namespace: unlike
        Austin, it needs no ``nsenter`` wrapper.
        """
        target_ns = self._pid_namespace(self._config.pid)
        if target_ns is None:
            raise CoreDetectorError(
                "Could not resolve the target PID namespace from /proc. "
                "Ensure the target is still running and /proc/<pid>/ns/pid is readable."
            )
        self._pidns_dev, self._pidns_ino = target_ns
        self._expected_pid = self._resolve_namespace_pid(self._config.pid)
        assert self._config.tid is not None
        self._validate_target_tid(self._config.tid, target_ns)
        self._expected_tid = self._resolve_namespace_pid(self._config.tid)
        arguments = [
            sidecar,
            "--protocol-version",
            str(PROTOCOL_VERSION),
            "--pid",
            str(self._expected_pid),
            "--tid",
            str(self._expected_tid),
            "--pidns-dev",
            str(self._pidns_dev),
            "--pidns-ino",
            str(self._pidns_ino),
            "--threshold-ns",
            str(int(self._config.threshold_ms * 1_000_000)),
        ]
        return arguments

    @staticmethod
    def _pid_namespace(pid: int | None) -> tuple[int, int] | None:
        path = "/proc/self/ns/pid" if pid is None else f"/proc/{pid}/ns/pid"
        try:
            stat = os.stat(path)
        except OSError:
            return None
        return stat.st_dev, stat.st_ino

    @staticmethod
    def _resolve_namespace_pid(host_pid: int) -> int:
        try:
            with open(f"/proc/{host_pid}/status") as status:
                for line in status:
                    if line.startswith("NSpid:"):
                        values = line.split()[1:]
                        if values:
                            return int(values[-1])
        except (OSError, ValueError):
            pass
        raise CoreDetectorError(
            f"Could not resolve NSpid for target task {host_pid}. "
            "Ensure the target is still running and /proc is readable."
        )

    def _validate_target_tid(self, tid: int, target_namespace: tuple[int, int]) -> None:
        """Ensure an explicit TID belongs to the selected host PID and pidns."""
        try:
            with open(f"/proc/{tid}/status") as status:
                fields = {
                    line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                    for line in status
                    if ":" in line
                }
            task_ns = self._pid_namespace(tid)
        except OSError as exc:
            raise CoreDetectorError(
                f"Could not inspect target TID {tid}; ensure it is still running."
            ) from exc
        if fields.get("Tgid") != str(self._config.pid) or task_ns != target_namespace:
            raise CoreDetectorError(
                f"TID {tid} does not belong to PID {self._config.pid} in its PID namespace."
            )

    def _cleanup_locked(self) -> None:
        process = self._process
        reader = self._reader
        stderr_reader = self._stderr_reader
        self._process = None
        self._reader = None
        self._stderr_reader = None
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=2)
        if (
            stderr_reader is not None
            and stderr_reader is not threading.current_thread()
        ):
            stderr_reader.join(timeout=2)

    def _read_messages(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            self._set_error("sidecar stdout is unavailable")
            return

        try:
            for line in process.stdout:
                self._handle_line(line)
        finally:
            if (
                not self._stop_requested.is_set()
                and self._startup_error is None
                and self._runtime_error is None
            ):
                if not self._ready.is_set():
                    self._set_error("sidecar exited before sending ready")
                else:
                    self._set_error("sidecar exited unexpectedly after ready")

    def _read_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        while chunk := process.stderr.read(1024):
            self._stderr_tail = (self._stderr_tail + chunk)[-_STDERR_TAIL_LIMIT:]

    def _handle_line(self, line: str) -> None:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            self._set_error("received invalid NDJSON")
            return
        if not isinstance(message, dict):
            self._set_error("received a non-object NDJSON message")
            return
        if message.get("version") != PROTOCOL_VERSION:
            self._set_error(f"unsupported protocol version {message.get('version')!r}")
            return

        message_type = message.get("type")
        if message_type == "ready":
            self._handle_ready(message)
        elif message_type == "event":
            self._handle_event(message)
        elif message_type == "lost":
            self._handle_lost(message)
        elif message_type == "fatal":
            self._set_error(str(message.get("message", "unknown sidecar error")))
        else:
            self._set_error(f"received unknown message type {message_type!r}")

    def _handle_ready(self, message: dict[str, Any]) -> None:
        try:
            pid = self._require_event_int(message, "pid")
            tid = self._require_event_int(message, "tid")
            threshold_ns = self._require_event_int(message, "threshold_ns")
            pidns = self._require_pidns(message)
        except (KeyError, ValueError):
            self._set_error(
                "ready message has invalid pid, tid, PID namespace or threshold_ns"
            )
            return
        tracepoints = message.get("tracepoints")
        expected_threshold_ns = int(self._config.threshold_ms * 1_000_000)
        if (
            pid != self._expected_pid
            or tid != self._expected_tid
            or threshold_ns != expected_threshold_ns
            or pidns != (self._pidns_dev, self._pidns_ino)
            or not isinstance(tracepoints, list)
            or not tracepoints
            or not all(isinstance(tracepoint, str) for tracepoint in tracepoints)
        ):
            self._set_error(
                "ready message does not match requested target or tracepoints"
            )
            return
        self._ready.set()

    def _handle_event(self, message: dict[str, Any]) -> None:
        try:
            start_ns = self._require_event_int(message, "start_ns")
            end_ns = self._require_event_int(message, "end_ns")
            pid = self._require_event_int(message, "pid")
            tid = self._require_event_int(message, "tid")
            pidns = self._require_pidns(message)
        except (KeyError, ValueError):
            _logger.warning("Ignoring malformed Core sidecar event: %r", message)
            return
        if (
            start_ns < 0
            or end_ns < start_ns
            or pid != self._expected_pid
            or tid != self._expected_tid
            or pidns != (self._pidns_dev, self._pidns_ino)
        ):
            _logger.warning("Ignoring invalid Core sidecar event: %r", message)
            return
        event = BlockingEvent(start_ns=start_ns, end_ns=end_ns, pid=pid, tid=tid)
        try:
            self._callback(event)
        except Exception:
            _logger.exception(
                "Core detector callback failed; continuing to read events"
            )

    def _handle_lost(self, message: dict[str, Any]) -> None:
        try:
            count = self._require_event_int(message, "count")
            pidns = self._require_pidns(message)
        except (KeyError, ValueError):
            self._set_error("received malformed lost record")
            return
        source = message.get("source")
        if (
            count < 0
            or count > _UINT64_MAX
            or source not in _LOSS_SOURCES
            or pidns != (self._pidns_dev, self._pidns_ino)
        ):
            self._set_error("received invalid lost record")
            return
        event = LostEvent(count=count, source=source)
        with self._loss_lock:
            self._loss_counts[source] = self._loss_counts.get(source, 0) + count
        if self._loss_callback is not None:
            try:
                self._loss_callback(event)
            except Exception:
                _logger.exception("Core detector loss callback failed")

    def _require_pidns(self, message: dict[str, Any]) -> tuple[int, int]:
        return (
            self._require_event_int(message, "pidns_dev"),
            self._require_event_int(message, "pidns_ino"),
        )

    @staticmethod
    def _require_event_int(message: dict[str, Any], field: str) -> int:
        value = message[field]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{field} is not an integer")
        return value

    def _set_error(self, error: str) -> None:
        if self._ready.is_set():
            if self._runtime_error is None:
                self._runtime_error = error
            _logger.error(
                "Core sidecar error after ready: %s. Restart blocksnoop; "
                "stderr tail: %s",
                error,
                self._stderr_tail.strip() or "(empty)",
            )
            return
        self._startup_error = error
        self._ready.set()

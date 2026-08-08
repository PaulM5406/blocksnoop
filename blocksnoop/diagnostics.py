"""Read-only runtime diagnostics for blocksnoop backends."""

from __future__ import annotations

import errno
import importlib.util
import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from blocksnoop.backends import Backend
from blocksnoop.core_backend import find_sidecar

DiagnosticStatus = Literal["pass", "warn", "fail"]
_EPOLL_SYSCALLS = ("epoll_wait", "epoll_pwait", "epoll_pwait2")
_TRACEFS_ROOTS = (
    Path("/sys/kernel/tracing/events/syscalls"),
    Path("/sys/kernel/debug/tracing/events/syscalls"),
)
_EXPECTED_FILESYSTEM_ERRORS = {
    errno.EACCES,
    errno.EPERM,
    errno.ENOENT,
    errno.ENOTDIR,
    errno.ESTALE,
}


@dataclass(frozen=True)
class DiagnosticCheck:
    name: str
    status: DiagnosticStatus
    detail: str
    remediation: str | None = None


@dataclass(frozen=True)
class TargetNamespace:
    target_pid: int
    target_tid: int
    local_pid: int
    local_tid: int
    pidns_dev: int
    pidns_ino: int
    same_as_collector: bool


@dataclass(frozen=True)
class DoctorReport:
    requested_backend: Backend
    effective_backend: Backend | None
    checks: tuple[DiagnosticCheck, ...]
    namespace: TargetNamespace | None = None
    stats_mode: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "blocksnoop.doctor/v1",
            "schema_version": 1,
            "status": "ready" if self.healthy else "not_ready",
            "mode": "stats" if self.stats_mode else "capture",
            "requested_backend": self.requested_backend,
            "effective_backend": self.effective_backend,
            "checks": [asdict(check) for check in self.checks],
            "namespace": asdict(self.namespace) if self.namespace else None,
        }

    @property
    def healthy(self) -> bool:
        return self.effective_backend is not None


def collect_diagnostics(
    backend: Backend,
    *,
    target_pid: int | None = None,
    target_tid: int | None = None,
    stats_mode: bool = False,
) -> DoctorReport:
    """Inspect selected-backend prerequisites without attaching BPF.

    ``stats_mode`` mirrors ``blocksnoop --stats``: it intentionally omits
    Austin because that mode collects only eBPF timing events.  The default
    capture mode requires Austin, so ``doctor`` is a useful pre-flight check
    for the actual command rather than merely for its eBPF half.
    """
    checks: list[DiagnosticCheck] = [
        _check_platform(),
        _check_root(),
    ]
    if backend == "core":
        checks.extend(
            (
                _check_path(
                    "btf",
                    Path("/sys/kernel/btf/vmlinux"),
                    "kernel BTF is readable (informational for this tracepoint-only program)",
                    "Kernel BTF is optional here; attach is authoritative for Core support.",
                    False,
                ),
                _check_tracepoints(),
                _check_privileges(),
                _check_pid_namespace_helper(),
            )
        )
        sidecar = find_sidecar()
        checks.extend(
            (
                _check_sidecar(sidecar, backend),
                _check_bpf_object(sidecar, backend),
            )
        )
    else:
        checks.extend((_check_tracepoints(), _check_privileges(), _check_bcc()))
    if not stats_mode:
        checks.append(_check_austin())

    namespace, namespace_check = _check_namespace(target_pid, target_tid)
    checks.append(namespace_check)
    required = {
        "bcc": {"platform", "root", "tracepoints", "privileges", "bcc"},
        "core": {
            "platform",
            "root",
            "tracepoints",
            "privileges",
            "pid_namespace_helper",
            "sidecar",
            "bpf_object",
        },
    }[backend]
    if not stats_mode:
        required = {*required, "austin"}
    if target_pid is not None:
        required = {*required, "namespace"}
    effective: Backend | None = backend
    if any(check.name in required and check.status != "pass" for check in checks):
        effective = None
    return DoctorReport(backend, effective, tuple(checks), namespace, stats_mode)


def _check_platform() -> DiagnosticCheck:
    if sys.platform == "linux":
        return DiagnosticCheck("platform", "pass", "Linux runtime detected")
    return DiagnosticCheck(
        "platform",
        "fail",
        f"unsupported platform: {sys.platform}",
        "Run blocksnoop on a Linux host or use a Linux debug container.",
    )


def _check_root() -> DiagnosticCheck:
    """Match the current runtime's deliberately strict root policy.

    Core can technically attach with carefully selected Linux capabilities,
    but Austin and cross-namespace collection need additional capabilities.
    Until that complete least-privilege profile is supported end-to-end, the
    CLI's root requirement is the honest, testable contract.
    """
    if os.geteuid() == 0:
        return DiagnosticCheck("root", "pass", "running as root")
    return DiagnosticCheck(
        "root",
        "fail",
        "blocksnoop currently requires an effective UID of 0",
        "Run with sudo, or use a privileged debug container.",
    )


def _check_austin() -> DiagnosticCheck:
    if shutil.which("austin") is not None:
        return DiagnosticCheck("austin", "pass", "Austin sampler is available")
    return DiagnosticCheck(
        "austin",
        "fail",
        "Austin sampler was not found in PATH",
        "Install Austin or use `blocksnoop doctor --stats` for eBPF-only mode.",
    )


def render_diagnostics(report: DoctorReport, *, verbose: bool = False) -> str:
    effective = report.effective_backend or "unavailable"
    lines = [
        "blocksnoop doctor",
        f"status: {'ready' if report.healthy else 'not_ready'}",
        f"mode: {'stats' if report.stats_mode else 'capture'}",
        f"backend: requested={report.requested_backend} effective={effective}",
    ]
    for check in report.checks:
        if verbose or check.status != "pass":
            lines.append(f"{check.status.upper():5s} {check.name}: {check.detail}")
            if check.remediation and check.status != "pass":
                lines.append(f"      fix: {check.remediation}")
    return "\n".join(lines)


def _check_path(
    name: str, path: Path, success: str, remediation: str, required: bool
) -> DiagnosticCheck:
    if _is_readable_file(path):
        return DiagnosticCheck(name, "pass", success)
    return DiagnosticCheck(
        name, "fail" if required else "warn", f"not readable: {path}", remediation
    )


def _is_readable_file(path: Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.R_OK)
    except OSError as error:
        if error.errno in _EXPECTED_FILESYSTEM_ERRORS:
            return False
        raise


def _check_tracepoints() -> DiagnosticCheck:
    for root in _TRACEFS_ROOTS:
        pairs: list[str] = []
        for syscall in _EPOLL_SYSCALLS:
            entered = root / f"sys_enter_{syscall}" / "format"
            exited = root / f"sys_exit_{syscall}" / "format"
            if _is_readable_file(entered) and _is_readable_file(exited):
                pairs.append(syscall)
        if pairs:
            return DiagnosticCheck(
                "tracepoints", "pass", f"epoll pairs available: {', '.join(pairs)}"
            )
    return DiagnosticCheck(
        "tracepoints",
        "fail",
        "no readable complete epoll tracepoint pair",
        "Mount tracefs and grant read access to epoll syscall tracepoints.",
    )


def _check_privileges() -> DiagnosticCheck:
    try:
        with open("/proc/self/status") as status:
            values = {
                line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in status
                if ":" in line
            }
        capabilities = int(values["CapEff"], 16)
    except (OSError, KeyError, ValueError):
        return DiagnosticCheck(
            "privileges",
            "warn",
            "effective BPF capabilities could not be proven",
            "Run as root in a privileged debug container and verify CAP_SYS_ADMIN, "
            "or both CAP_BPF and CAP_PERFMON, before attaching.",
        )
    has_sys_admin = bool(capabilities & (1 << 21))
    has_bpf_pair = bool(capabilities & (1 << 38)) and bool(capabilities & (1 << 39))
    if has_sys_admin or has_bpf_pair:
        return DiagnosticCheck(
            "privileges", "pass", "effective BPF capabilities are present"
        )
    return DiagnosticCheck(
        "privileges",
        "fail",
        "CAP_SYS_ADMIN or CAP_BPF+CAP_PERFMON is missing",
        "Run blocksnoop as root in a privileged debug container. Capability-only "
        "operation is not yet a supported end-to-end profile.",
    )


def _check_pid_namespace_helper() -> DiagnosticCheck:
    """Assess the kernel-version baseline; attach remains authoritative."""
    release = os.uname().release
    match = re.match(r"(\d+)\.(\d+)", release)
    if match is None:
        return DiagnosticCheck(
            "pid_namespace_helper",
            "warn",
            f"could not determine helper support from kernel release {release!r}",
            "Use kernel 5.7+ or a kernel with the helper backported.",
        )
    version = int(match.group(1)), int(match.group(2))
    if version >= (5, 7):
        return DiagnosticCheck(
            "pid_namespace_helper",
            "pass",
            f"kernel {release} meets the 5.7 helper baseline; attach is authoritative",
        )
    return DiagnosticCheck(
        "pid_namespace_helper",
        "fail",
        f"kernel {release} is older than the 5.7 helper baseline",
        "Use kernel 5.7+ or a kernel with the helper backported.",
    )


def _check_sidecar(sidecar: str | None, backend: Backend) -> DiagnosticCheck:
    if sidecar:
        return DiagnosticCheck("sidecar", "pass", f"resolved: {sidecar}")
    return DiagnosticCheck(
        "sidecar",
        "fail" if backend == "core" else "warn",  # Core is the only caller.
        "blocksnoop-ebpf sidecar was not found",
        "Install a native Linux blocksnoop wheel, use the official Docker image, "
        "or set BLOCKSNOOP_EBPF to a compatible sidecar.",
    )


def _check_bpf_object(sidecar: str | None, backend: Backend) -> DiagnosticCheck:
    configured = os.environ.get("BLOCKSNOOP_BPF_OBJECT")
    candidates = [Path(configured)] if configured else _bpf_object_candidates(sidecar)
    for candidate in candidates:
        if _is_readable_file(candidate):
            return DiagnosticCheck("bpf_object", "pass", f"resolved: {candidate}")
    detail = (
        "no object path could be proven"
        if not candidates
        else "not readable: " + ", ".join(f"{candidate}" for candidate in candidates)
    )
    return DiagnosticCheck(
        "bpf_object",
        "fail" if backend == "core" else "warn",
        detail,
        "Build core_blockdetect.bpf.o or set BLOCKSNOOP_BPF_OBJECT.",
    )


def _bpf_object_candidates(sidecar: str | None) -> list[Path]:
    if sidecar is None:
        return []
    binary = Path(sidecar)
    return [
        binary.parent.parent / "blocksnoop" / "bpf" / "core_blockdetect.bpf.o",
        binary.parent.parent / "bpf" / "core_blockdetect.bpf.o",
        binary.parent / "core_blockdetect.bpf.o",
    ]


def _check_bcc() -> DiagnosticCheck:
    if importlib.util.find_spec("bcc") is not None:
        return DiagnosticCheck("bcc", "pass", "legacy Python bcc module is importable")
    return DiagnosticCheck(
        "bcc",
        "fail",
        "legacy Python bcc module is not importable",
        "Install BCC for the explicit `--backend bcc` compatibility path, "
        "or use the default Core backend.",
    )


def _check_namespace(
    target_pid: int | None, target_tid: int | None
) -> tuple[TargetNamespace | None, DiagnosticCheck]:
    if target_pid is None:
        return None, DiagnosticCheck(
            "namespace",
            "warn",
            "no target PID supplied; namespace identity will be verified at attach",
            "Run `blocksnoop doctor PID` for target-specific checks.",
        )
    tid = target_pid if target_tid is None else target_tid
    try:
        target = os.stat(f"/proc/{target_pid}/ns/pid")
        task = os.stat(f"/proc/{tid}/ns/pid")
        with open(f"/proc/{target_pid}/status") as status:
            target_values = {
                line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in status
                if ":" in line
            }
        with open(f"/proc/{tid}/status") as status:
            task_values = {
                line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in status
                if ":" in line
            }
        if task_values.get("Tgid") != str(target_pid) or (
            target.st_dev,
            target.st_ino,
        ) != (task.st_dev, task.st_ino):
            raise ValueError("TID does not belong to target PID namespace")
        local_pid = int(target_values["NSpid"].split()[-1])
        local_tid = int(task_values["NSpid"].split()[-1])
        own = os.stat("/proc/self/ns/pid")
    except (OSError, KeyError, ValueError):
        return None, DiagnosticCheck(
            "namespace",
            "fail",
            "target namespace could not be proven",
            "Ensure /proc/PID and /proc/TID are readable while the target runs.",
        )
    namespace = TargetNamespace(
        target_pid,
        tid,
        local_pid,
        local_tid,
        target.st_dev,
        target.st_ino,
        (target.st_dev, target.st_ino) == (own.st_dev, own.st_ino),
    )
    return namespace, DiagnosticCheck(
        "namespace", "pass", "target PID/TID and PID namespace are consistent"
    )

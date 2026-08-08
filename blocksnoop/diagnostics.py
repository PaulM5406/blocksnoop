"""Read-only runtime diagnostics for blocksnoop backends."""

from __future__ import annotations

import importlib.util
import os
import re
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

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "requested_backend": self.requested_backend,
            "effective_backend": self.effective_backend,
            "checks": [asdict(check) for check in self.checks],
            "namespace": asdict(self.namespace) if self.namespace else None,
        }

    @property
    def healthy(self) -> bool:
        return self.effective_backend is not None


def collect_diagnostics(
    backend: Backend, *, target_pid: int | None = None, target_tid: int | None = None
) -> DoctorReport:
    """Inspect prerequisites without spawning a sidecar or attaching BPF."""
    checks: list[DiagnosticCheck] = [
        _check_path(
            "btf",
            Path("/sys/kernel/btf/vmlinux"),
            "kernel BTF is readable",
            "Use a BTF-enabled kernel or select --backend bcc.",
            backend == "core",
        ),
        _check_tracepoints(),
        _check_privileges(),
        _check_pid_namespace_helper(),
    ]
    sidecar = find_sidecar()
    checks.extend(
        (
            _check_sidecar(sidecar, backend),
            _check_bpf_object(sidecar, backend),
            _check_bcc(backend),
        )
    )
    namespace, namespace_check = _check_namespace(target_pid, target_tid)
    checks.append(namespace_check)
    required = {
        "bcc": {"tracepoints", "privileges", "bcc"},
        "core": {
            "btf",
            "tracepoints",
            "privileges",
            "pid_namespace_helper",
            "sidecar",
            "bpf_object",
        },
    }[backend]
    if target_pid is not None:
        required = {*required, "namespace"}
    effective: Backend | None = backend
    if any(check.name in required and check.status != "pass" for check in checks):
        effective = None
    return DoctorReport(backend, effective, tuple(checks), namespace)


def render_diagnostics(report: DoctorReport, *, verbose: bool = False) -> str:
    effective = report.effective_backend or "unavailable"
    lines = [
        "blocksnoop doctor",
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
    if path.is_file() and os.access(path, os.R_OK):
        return DiagnosticCheck(name, "pass", success)
    return DiagnosticCheck(
        name, "fail" if required else "warn", f"not readable: {path}", remediation
    )


def _check_tracepoints() -> DiagnosticCheck:
    pairs = [
        syscall
        for root in _TRACEFS_ROOTS
        for syscall in _EPOLL_SYSCALLS
        if (root / f"sys_enter_{syscall}" / "format").is_file()
        and (root / f"sys_exit_{syscall}" / "format").is_file()
    ]
    if pairs:
        return DiagnosticCheck(
            "tracepoints", "pass", f"epoll pairs available: {', '.join(pairs)}"
        )
    return DiagnosticCheck(
        "tracepoints",
        "fail",
        "no readable complete epoll tracepoint pair",
        "Mount tracefs and enable epoll syscall tracepoints.",
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
            "Verify CAP_SYS_ADMIN, or both CAP_BPF and CAP_PERFMON, before attaching.",
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
        "Run the container with --privileged or grant the required BPF capabilities.",
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
        "fail" if backend == "core" else "warn",
        "blocksnoop-ebpf was not found in PATH",
        "Install it or set BLOCKSNOOP_EBPF.",
    )


def _check_bpf_object(sidecar: str | None, backend: Backend) -> DiagnosticCheck:
    configured = os.environ.get("BLOCKSNOOP_BPF_OBJECT")
    candidates = [Path(configured)] if configured else _bpf_object_candidates(sidecar)
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.R_OK):
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


def _check_bcc(backend: Backend) -> DiagnosticCheck:
    if importlib.util.find_spec("bcc") is not None:
        return DiagnosticCheck("bcc", "pass", "Python bcc module is importable")
    return DiagnosticCheck(
        "bcc",
        "fail" if backend == "bcc" else "warn",
        "Python bcc module is not importable",
        "Install BCC or select --backend core.",
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

"""Contract tests for the machine-readable Core doctor pre-flight."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

from blocksnoop.diagnostics import (
    DiagnosticCheck,
    _check_root,
    collect_diagnostics,
)


def _pass(name: str) -> DiagnosticCheck:
    return DiagnosticCheck(name, "pass", "ok")


@contextmanager
def _core_patches(
    *, austin: DiagnosticCheck | None = None
) -> Iterator[tuple[object, ...]]:
    """Return patches for a deterministic healthy Core host."""
    patches = (
        patch("blocksnoop.diagnostics._check_platform", return_value=_pass("platform")),
        patch("blocksnoop.diagnostics._check_root", return_value=_pass("root")),
        patch(
            "blocksnoop.diagnostics._check_path",
            return_value=DiagnosticCheck("btf", "warn", "optional"),
        ),
        patch(
            "blocksnoop.diagnostics._check_tracepoints",
            return_value=_pass("tracepoints"),
        ),
        patch(
            "blocksnoop.diagnostics._check_privileges",
            return_value=_pass("privileges"),
        ),
        patch(
            "blocksnoop.diagnostics._check_pid_namespace_helper",
            return_value=_pass("pid_namespace_helper"),
        ),
        patch("blocksnoop.diagnostics.find_sidecar", return_value="/sidecar"),
        patch("blocksnoop.diagnostics._check_sidecar", return_value=_pass("sidecar")),
        patch(
            "blocksnoop.diagnostics._check_bpf_object",
            return_value=_pass("bpf_object"),
        ),
        patch(
            "blocksnoop.diagnostics._check_austin",
            return_value=austin or _pass("austin"),
        ),
        patch(
            "blocksnoop.diagnostics._check_namespace",
            return_value=(None, DiagnosticCheck("namespace", "warn", "no target")),
        ),
    )
    with ExitStack() as stack:
        yield tuple(stack.enter_context(item) for item in patches)


def test_core_doctor_accepts_missing_kernel_btf_when_attach_prerequisites_pass() -> (
    None
):
    with _core_patches():
        report = collect_diagnostics("core")

    assert report.healthy
    assert report.effective_backend == "core"
    assert {check.name for check in report.checks} == {
        "platform",
        "root",
        "btf",
        "tracepoints",
        "privileges",
        "pid_namespace_helper",
        "sidecar",
        "bpf_object",
        "austin",
        "namespace",
    }
    assert (
        next(check for check in report.checks if check.name == "btf").status == "warn"
    )
    assert "bcc" not in {check.name for check in report.checks}


def test_core_capture_doctor_requires_austin() -> None:
    with _core_patches(austin=DiagnosticCheck("austin", "fail", "missing")):
        report = collect_diagnostics("core")

    assert not report.healthy
    assert report.effective_backend is None


def test_core_stats_doctor_does_not_require_or_probe_austin() -> None:
    with _core_patches() as patches:
        report = collect_diagnostics("core", stats_mode=True)

    assert report.healthy
    assert report.stats_mode
    assert "austin" not in {check.name for check in report.checks}
    assert not patches[9].called


def test_doctor_json_contract_is_versioned_and_has_a_verdict() -> None:
    with _core_patches():
        report = collect_diagnostics("core", stats_mode=True)

    payload = report.as_dict()
    assert payload["schema"] == "blocksnoop.doctor/v1"
    assert payload["schema_version"] == 1
    assert payload["status"] == "ready"
    assert payload["mode"] == "stats"


def test_root_check_matches_the_runtime_root_only_policy() -> None:
    with patch("blocksnoop.diagnostics.os.geteuid", return_value=1000):
        check = _check_root()

    assert check.status == "fail"
    assert check.remediation is not None


def test_bcc_doctor_only_checks_the_explicit_legacy_backend() -> None:
    with (
        patch("blocksnoop.diagnostics._check_platform", return_value=_pass("platform")),
        patch("blocksnoop.diagnostics._check_root", return_value=_pass("root")),
        patch(
            "blocksnoop.diagnostics._check_tracepoints",
            return_value=_pass("tracepoints"),
        ),
        patch(
            "blocksnoop.diagnostics._check_privileges",
            return_value=_pass("privileges"),
        ),
        patch("blocksnoop.diagnostics._check_bcc", return_value=_pass("bcc")),
        patch("blocksnoop.diagnostics._check_austin", return_value=_pass("austin")),
        patch(
            "blocksnoop.diagnostics._check_namespace",
            return_value=(None, DiagnosticCheck("namespace", "warn", "no target")),
        ),
    ):
        report = collect_diagnostics("bcc")

    assert report.healthy
    assert {check.name for check in report.checks} == {
        "platform",
        "root",
        "tracepoints",
        "privileges",
        "bcc",
        "austin",
        "namespace",
    }

"""Unit tests for CLI argument parsing, validation, and sink assembly."""

import errno
import io
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from blocksnoop.cli import (
    _build_sinks,
    _parse_args,
    _resolve_target,
    _run_normal,
    _run_loop,
    _validate_environment,
    main,
)
from blocksnoop.core_backend import CoreDetectorError
from blocksnoop.detector import BccDetectorError
from blocksnoop.diagnostics import (
    DiagnosticCheck,
    DoctorReport,
    _check_namespace,
    _check_pid_namespace_helper,
    _check_privileges,
    _check_tracepoints,
    collect_diagnostics,
)
from blocksnoop.sinks import ConsoleSink, JsonFileSink, JsonStreamSink


# ---------------------------------------------------------------------------
# Fixture: pretend we are root so CLI doesn't bail out early
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fake_root():
    """Pretend we are root so CLI doesn't bail out early."""
    with patch("os.geteuid", return_value=0):
        yield


# ---------------------------------------------------------------------------
# _parse_args
# ---------------------------------------------------------------------------


def test_parse_args_defaults():
    args, _ = _parse_args(["1234"])
    assert args.target == "1234"
    assert args.threshold is None
    assert args.stats is False
    assert args.backend == "bcc"
    assert args.tid is None
    assert args.json_mode is False
    assert args.log_file is None
    assert args.service == "blocksnoop"
    assert args.env == ""
    assert args.no_color is False
    assert args.verbose is False
    assert args.error_threshold == 500.0
    assert args.correlation_padding == 200.0


def test_parse_args_all_flags():
    args, _ = _parse_args(
        [
            "-t",
            "50",
            "--tid",
            "999",
            "--backend",
            "core",
            "--json",
            "--log-file",
            "/tmp/out.json",
            "--service",
            "my-api",
            "--env",
            "production",
            "--no-color",
            "-v",
            "--error-threshold",
            "300",
            "--correlation-padding",
            "150",
            "5678",
        ]
    )
    assert args.threshold == 50
    assert args.tid == 999
    assert args.backend == "core"
    assert args.json_mode is True
    assert args.log_file == "/tmp/out.json"
    assert args.service == "my-api"
    assert args.env == "production"
    assert args.no_color is True
    assert args.verbose is True
    assert args.error_threshold == 300.0
    assert args.correlation_padding == 150.0
    assert args.target == "5678"


def test_parse_args_stats_flag():
    args, _ = _parse_args(["--stats", "1234"])
    assert args.stats is True
    assert args.threshold is None  # resolved later in main()


def test_parse_args_threshold_and_padding_parsing():
    args, _ = _parse_args(["-t", "25.5", "--correlation-padding", "99.9", "1"])
    assert args.threshold == 25.5
    assert args.correlation_padding == 99.9


def test_parse_args_error_threshold_parsing():
    args, _ = _parse_args(["--error-threshold", "123.4", "1"])
    assert args.error_threshold == 123.4


def test_parse_doctor_accepts_backend_after_subcommand():
    args, _ = _parse_args(["doctor", "--backend", "core", "1234"])
    assert args.doctor is True
    assert args.backend == "core"
    assert args.target == "1234"


# ---------------------------------------------------------------------------
# _resolve_target
# ---------------------------------------------------------------------------


def test_resolve_target_pid_mode():
    args, _ = _parse_args(["1234"])
    pid, command = _resolve_target(args)
    assert pid == 1234
    assert command == []


def test_resolve_target_command_mode():
    args, _ = _parse_args(["--", "python", "app.py"])
    pid, command = _resolve_target(args)
    assert pid is None
    assert command == ["python", "app.py"]


def test_resolve_target_non_numeric_becomes_command():
    args, _ = _parse_args(["python", "app.py"])
    pid, command = _resolve_target(args)
    assert pid is None
    assert command == ["python", "app.py"]


def test_run_loop_rolls_back_partial_start() -> None:
    start = Mock(side_effect=RuntimeError("attach failed"))
    stop = Mock()
    check_health = Mock()
    on_exit = Mock()

    with pytest.raises(RuntimeError, match="attach failed"):
        _run_loop(start, stop, check_health, on_exit, child_process=None)

    stop.assert_called_once_with()
    check_health.assert_not_called()
    on_exit.assert_called_once_with()


def test_run_loop_reaps_child_when_start_fails() -> None:
    child = Mock()
    child.poll.return_value = None
    start = Mock(side_effect=RuntimeError("attach failed"))

    with pytest.raises(RuntimeError, match="attach failed"):
        _run_loop(start, Mock(), Mock(), Mock(), child)

    child.terminate.assert_called_once_with()
    child.wait.assert_called_once_with(timeout=5)


def test_run_loop_checks_health_and_reaps_running_child() -> None:
    child = Mock()
    child.poll.return_value = None
    health_error = RuntimeError("sidecar stopped")
    check_health = Mock(side_effect=health_error)

    with pytest.raises(RuntimeError, match="sidecar stopped"):
        _run_loop(Mock(), Mock(), check_health, Mock(), child)

    check_health.assert_called_once_with()
    child.terminate.assert_called_once_with()
    child.wait.assert_called_once_with(timeout=5)


def test_run_loop_checks_health_in_pid_mode() -> None:
    health_error = RuntimeError("detector stopped")
    check_health = Mock(side_effect=health_error)

    with pytest.raises(RuntimeError, match="detector stopped"):
        _run_loop(Mock(), Mock(), check_health, Mock(), None)

    check_health.assert_called_once_with()


# ---------------------------------------------------------------------------
# _validate_environment
# ---------------------------------------------------------------------------


def test_validate_non_root_error():
    with patch("os.geteuid", return_value=1000), pytest.raises(SystemExit, match="1"):
        _validate_environment()


def test_validate_missing_austin_error(capsys):
    with (
        patch("blocksnoop.cli.check_austin_available", return_value=False),
        pytest.raises(SystemExit, match="1"),
    ):
        _validate_environment()
    assert "austin not found" in capsys.readouterr().err


def test_validate_stats_mode_skips_austin():
    """In stats mode, missing Austin should not cause an error."""
    import types

    fake_bcc = types.ModuleType("bcc")
    with (
        patch("blocksnoop.cli.check_austin_available", return_value=False),
        patch.dict("sys.modules", {"bcc": fake_bcc}),
    ):
        # Should NOT raise — stats mode skips the Austin check
        _validate_environment(stats_mode=True)


def test_validate_core_backend_does_not_require_bcc(capsys):
    with (
        patch("blocksnoop.cli.check_austin_available", return_value=True),
        patch("blocksnoop.cli.validate_backend_available") as validate_backend,
    ):
        _validate_environment(backend="core")
    validate_backend.assert_called_once_with("core")
    assert capsys.readouterr().err == ""


def test_validate_missing_bcc_error(capsys):
    with (
        patch("blocksnoop.cli.check_austin_available", return_value=True),
        patch.dict("sys.modules", {"bcc": None}),
        pytest.raises(SystemExit, match="1"),
    ):
        _validate_environment()
    captured = capsys.readouterr()
    assert "bcc" in captured.err
    assert "https://github.com/iovisor/bcc/blob/master/INSTALL.md" in captured.err


def test_doctor_json_is_read_only_and_reports_backend(capsys):
    report = DoctorReport(
        requested_backend="core",
        effective_backend="core",
        checks=(DiagnosticCheck("btf", "pass", "readable"),),
    )
    with (
        patch("blocksnoop.cli.collect_diagnostics", return_value=report) as doctor,
        patch("blocksnoop.cli.validate_backend_available") as validate,
        patch("sys.argv", ["blocksnoop", "doctor", "--backend", "core", "--json"]),
    ):
        main()
    assert '"requested_backend": "core"' in capsys.readouterr().out
    doctor.assert_called_once_with("core", target_pid=None, target_tid=None)
    validate.assert_not_called()


def test_doctor_namespace_reports_distinct_local_pid_and_tid() -> None:
    statuses = {
        "/proc/100/status": "Tgid:\t100\nNSpid:\t100\t7\n",
        "/proc/101/status": "Tgid:\t100\nNSpid:\t101\t8\n",
    }

    def fake_open(path: str, *args: object, **kwargs: object) -> io.StringIO:
        return io.StringIO(statuses[path])

    with (
        patch("builtins.open", side_effect=fake_open),
        patch(
            "blocksnoop.diagnostics.os.stat",
            side_effect=[
                SimpleNamespace(st_dev=1, st_ino=2),
                SimpleNamespace(st_dev=1, st_ino=2),
                SimpleNamespace(st_dev=3, st_ino=4),
            ],
        ),
    ):
        namespace, check = _check_namespace(100, 101)

    assert check.status == "pass"
    assert namespace is not None
    assert (namespace.local_pid, namespace.local_tid) == (7, 8)


def test_doctor_privileges_rejects_root_without_bpf_capabilities() -> None:
    with patch(
        "builtins.open", return_value=io.StringIO("CapEff:\t0000000000000000\n")
    ):
        check = _check_privileges()
    assert check.status == "fail"


def test_doctor_tracepoints_reports_permission_error() -> None:
    with patch(
        "pathlib.Path.is_file", side_effect=PermissionError(errno.EACCES, "denied")
    ):
        check = _check_tracepoints()

    assert check.status == "fail"
    assert "no readable" in check.detail
    assert check.remediation is not None
    assert "grant read access" in check.remediation


def test_doctor_tracepoints_uses_readable_root_after_permission_error() -> None:
    inaccessible = Path("/tracefs-inaccessible/events/syscalls")
    readable = Path("/tracefs-readable/events/syscalls")
    expected = {
        readable / "sys_enter_epoll_wait" / "format",
        readable / "sys_exit_epoll_wait" / "format",
    }

    def is_file(path: Path) -> bool:
        if str(path).startswith(str(inaccessible)):
            raise PermissionError(errno.EACCES, "denied")
        return path in expected

    with (
        patch("blocksnoop.diagnostics._TRACEFS_ROOTS", (inaccessible, readable)),
        patch("pathlib.Path.is_file", autospec=True, side_effect=is_file),
        patch("blocksnoop.diagnostics.os.access", return_value=True),
    ):
        check = _check_tracepoints()

    assert check.status == "pass"
    assert check.detail == "epoll pairs available: epoll_wait"


def test_doctor_tracepoints_uses_first_root_with_pairs() -> None:
    first = Path("/tracefs-first/events/syscalls")
    second = Path("/tracefs-second/events/syscalls")
    expected = {
        first / "sys_enter_epoll_wait" / "format",
        first / "sys_exit_epoll_wait" / "format",
        second / "sys_enter_epoll_pwait" / "format",
        second / "sys_exit_epoll_pwait" / "format",
    }

    with (
        patch("blocksnoop.diagnostics._TRACEFS_ROOTS", (first, second)),
        patch(
            "pathlib.Path.is_file",
            autospec=True,
            side_effect=lambda path: path in expected,
        ),
        patch("blocksnoop.diagnostics.os.access", return_value=True),
    ):
        check = _check_tracepoints()

    assert check.detail == "epoll pairs available: epoll_wait"


def test_doctor_tracepoints_reraises_unexpected_io_error() -> None:
    with (
        patch("pathlib.Path.is_file", side_effect=OSError(errno.EIO, "I/O error")),
        pytest.raises(OSError, match="I/O error"),
    ):
        _check_tracepoints()


@pytest.mark.parametrize(
    ("release", "status"),
    [("5.6.19", "fail"), ("5.7.0", "pass"), ("vendor-kernel", "warn")],
)
def test_doctor_pid_namespace_helper_kernel_baseline(release: str, status: str) -> None:
    with patch(
        "blocksnoop.diagnostics.os.uname", return_value=SimpleNamespace(release=release)
    ):
        check = _check_pid_namespace_helper()
    assert check.status == status


def test_core_doctor_rejects_unproven_required_helper() -> None:
    passing = DiagnosticCheck("other", "pass", "ok")
    with (
        patch("blocksnoop.diagnostics._check_path", return_value=passing),
        patch("blocksnoop.diagnostics._check_tracepoints", return_value=passing),
        patch("blocksnoop.diagnostics._check_privileges", return_value=passing),
        patch("blocksnoop.diagnostics._check_sidecar", return_value=passing),
        patch("blocksnoop.diagnostics._check_bpf_object", return_value=passing),
        patch("blocksnoop.diagnostics._check_bcc", return_value=passing),
        patch(
            "blocksnoop.diagnostics._check_pid_namespace_helper",
            return_value=DiagnosticCheck("pid_namespace_helper", "warn", "unknown"),
        ),
        patch(
            "blocksnoop.diagnostics._check_namespace",
            return_value=(None, passing),
        ),
    ):
        report = collect_diagnostics("core")
    assert report.effective_backend is None


def test_doctor_json_parses_options_after_target(capsys) -> None:
    report = DoctorReport("core", "core", ())
    with (
        patch("blocksnoop.cli.collect_diagnostics", return_value=report) as doctor,
        patch(
            "sys.argv", ["blocksnoop", "doctor", "1234", "--backend", "core", "--json"]
        ),
    ):
        main()
    assert '"effective_backend": "core"' in capsys.readouterr().out
    doctor.assert_called_once_with("core", target_pid=1234, target_tid=None)


def test_normal_summary_receives_detector_losses_without_stderr_warning() -> None:
    args = SimpleNamespace(
        backend="core",
        threshold=100.0,
        tid=None,
        correlation_padding=200.0,
        error_threshold=500.0,
        json_mode=False,
        log_file=None,
        service="blocksnoop",
        env="",
        no_color=True,
        verbose=False,
    )
    detector = Mock()
    detector.loss_counts = {"kernel": 4}

    def run_loop(*args: object, **kwargs: object) -> None:
        args[3]()  # on_exit, after the detector would have been stopped

    with (
        patch("blocksnoop.cli.Reporter") as reporter_class,
        patch("blocksnoop.cli.AustinSampler"),
        patch("blocksnoop.cli.Correlator"),
        patch("blocksnoop.cli.create_detector", return_value=detector),
        patch("blocksnoop.cli._run_loop", side_effect=run_loop),
        patch("blocksnoop.cli._report_detector_losses") as legacy_warning,
    ):
        _run_normal(args, 1234, None)

    reporter_class.return_value.summary.assert_called_once()
    assert reporter_class.return_value.summary.call_args.kwargs["loss_counts"] == {
        "kernel": 4
    }
    legacy_warning.assert_not_called()


# ---------------------------------------------------------------------------
# _build_sinks
# ---------------------------------------------------------------------------


def test_build_sinks_console_mode():
    args, _ = _parse_args(["1234"])
    sinks = _build_sinks(args)
    assert len(sinks) == 1
    assert isinstance(sinks[0], ConsoleSink)


def test_build_sinks_json_mode():
    args, _ = _parse_args(["--json", "1234"])
    sinks = _build_sinks(args)
    assert len(sinks) == 1
    assert isinstance(sinks[0], JsonStreamSink)


def test_build_sinks_log_file_mode(tmp_path):
    log_file = str(tmp_path / "events.json")
    args, _ = _parse_args(["--log-file", log_file, "1234"])
    sinks = _build_sinks(args)
    assert len(sinks) == 2
    assert isinstance(sinks[0], ConsoleSink)
    assert isinstance(sinks[1], JsonFileSink)


def test_build_sinks_combined_modes(tmp_path):
    log_file = str(tmp_path / "events.json")
    args, _ = _parse_args(["--json", "--log-file", log_file, "1234"])
    sinks = _build_sinks(args)
    assert len(sinks) == 2
    assert isinstance(sinks[0], JsonStreamSink)
    assert isinstance(sinks[1], JsonFileSink)


# ---------------------------------------------------------------------------
# --verbose
# ---------------------------------------------------------------------------


def test_verbose_sets_debug_level():
    """--verbose should configure logging at DEBUG level."""
    with (
        patch("blocksnoop.cli.check_austin_available", return_value=True),
        patch("blocksnoop.cli._validate_environment"),
        patch("blocksnoop.cli.create_detector"),
        patch("blocksnoop.cli.AustinSampler"),
        patch("subprocess.Popen") as mock_popen,
        patch("sys.argv", ["blocksnoop", "-v", "--", "python", "app.py"]),
        patch("blocksnoop.cli.logging.basicConfig") as mock_basic_config,
    ):
        mock_popen.return_value.pid = 1234
        mock_popen.return_value.poll.return_value = 0
        try:
            main()
        except SystemExit:
            pass
    mock_basic_config.assert_called_once()
    assert mock_basic_config.call_args.kwargs["level"] == logging.DEBUG


def test_core_runtime_error_is_user_facing_without_traceback(capsys) -> None:
    with (
        patch("blocksnoop.cli._validate_environment"),
        patch(
            "blocksnoop.cli._run_normal",
            side_effect=CoreDetectorError("sidecar crashed"),
        ),
        patch("sys.argv", ["blocksnoop", "--backend", "core", "1234"]),
        pytest.raises(SystemExit, match="1"),
    ):
        main()

    stderr = capsys.readouterr().err
    assert "Core backend unavailable: sidecar crashed" in stderr
    assert "Traceback" not in stderr


def test_bcc_runtime_error_is_user_facing_without_traceback(capsys) -> None:
    with (
        patch("blocksnoop.cli._validate_environment"),
        patch(
            "blocksnoop.cli._run_normal",
            side_effect=BccDetectorError("perf buffer stopped"),
        ),
        patch("sys.argv", ["blocksnoop", "1234"]),
        pytest.raises(SystemExit, match="1"),
    ):
        main()

    stderr = capsys.readouterr().err
    assert "BCC backend unavailable: perf buffer stopped" in stderr
    assert "Traceback" not in stderr


# ---------------------------------------------------------------------------
# Legacy test (kept for backward compatibility)
# ---------------------------------------------------------------------------


def test_missing_austin_produces_clear_error(capsys):
    """Missing Austin should crash with a clear error."""
    with (
        patch("blocksnoop.cli.check_austin_available", return_value=False),
        patch("sys.argv", ["blocksnoop", "1234"]),
        pytest.raises(SystemExit, match="1"),
    ):
        main()
    captured = capsys.readouterr()
    assert "austin not found" in captured.err


def test_missing_bcc_produces_clear_error(capsys):
    """Missing bcc should crash with an error containing the install URL."""
    with (
        patch("blocksnoop.cli.check_austin_available", return_value=True),
        patch.dict("sys.modules", {"bcc": None}),
        patch("sys.argv", ["blocksnoop", "1234"]),
        pytest.raises(SystemExit, match="1"),
    ):
        main()
    captured = capsys.readouterr()
    assert "bcc" in captured.err
    assert "https://github.com/iovisor/bcc/blob/master/INSTALL.md" in captured.err

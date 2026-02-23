"""Unit tests for CLI argument parsing, validation, and sink assembly."""

import logging
from unittest.mock import patch

import pytest

from blocksnoop.cli import (
    _build_sinks,
    _parse_args,
    _resolve_target,
    _validate_environment,
    main,
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
    assert args.threshold == 100
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
    assert args.json_mode is True
    assert args.log_file == "/tmp/out.json"
    assert args.service == "my-api"
    assert args.env == "production"
    assert args.no_color is True
    assert args.verbose is True
    assert args.error_threshold == 300.0
    assert args.correlation_padding == 150.0
    assert args.target == "5678"


def test_parse_args_threshold_and_padding_parsing():
    args, _ = _parse_args(["-t", "25.5", "--correlation-padding", "99.9", "1"])
    assert args.threshold == 25.5
    assert args.correlation_padding == 99.9


def test_parse_args_error_threshold_parsing():
    args, _ = _parse_args(["--error-threshold", "123.4", "1"])
    assert args.error_threshold == 123.4


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
        patch("blocksnoop.cli.EbpfDetector"),
        patch("blocksnoop.cli.AustinSampler"),
        patch("subprocess.Popen") as mock_popen,
        patch("sys.argv", ["blocksnoop", "-v", "--", "python", "app.py"]),
        patch("blocksnoop.cli.logging.basicConfig") as mock_basic_config,
    ):
        mock_popen.return_value.pid = 1234
        mock_popen.return_value.wait.side_effect = KeyboardInterrupt
        try:
            main()
        except SystemExit:
            pass
    mock_basic_config.assert_called_once()
    assert mock_basic_config.call_args.kwargs["level"] == logging.DEBUG


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

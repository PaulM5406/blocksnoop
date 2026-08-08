"""Unit tests for selectable detector backends (no BPF or sidecar required)."""

from __future__ import annotations

import io
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

from blocksnoop.backends import create_detector, validate_backend_available
from blocksnoop.core import BlockingEvent, DetectorConfig
from blocksnoop.core_backend import CoreDetector, CoreDetectorError, find_sidecar
from blocksnoop.detector import BccDetector, EbpfDetector


class _FakeProcess:
    def __init__(self, stdout: str, stderr: str = "") -> None:
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def _config() -> DetectorConfig:
    return DetectorConfig(pid=1234, tid=1235, threshold_ms=12.5)


_READY = (
    '{"version": 1, "type": "ready", "pid": 1234, "tid": 1235, '
    '"threshold_ns": 12500000, "tracepoints": ["epoll_wait"]}'
)


def test_bcc_detector_is_the_clear_name_and_legacy_alias() -> None:
    assert EbpfDetector is BccDetector


def test_bcc_detector_constructor_does_not_import_or_attach_bcc() -> None:
    detector = BccDetector(config=_config(), callback=Mock())
    assert detector._bpf is None
    assert detector._thread is None


def test_bcc_detector_imports_and_attaches_only_on_start() -> None:
    bpf = MagicMock()
    bpf.__getitem__.return_value = Mock()
    bpf_class = Mock(return_value=bpf)
    detector = BccDetector(config=_config(), callback=Mock())

    with (
        patch(
            "blocksnoop.detector._detect_epoll_syscalls", return_value=["epoll_wait"]
        ),
        patch("blocksnoop.detector._get_pidns_info", return_value=None),
        patch("blocksnoop.detector._ensure_kernel_headers"),
        patch.object(BccDetector, "_poll_loop"),
        patch.dict(sys.modules, {"bcc": SimpleNamespace(BPF=bpf_class)}),
    ):
        assert bpf_class.call_count == 0
        detector.start()
        assert bpf_class.call_count == 1
        detector.stop()


def test_factory_selects_requested_backend_without_fallback() -> None:
    callback = Mock()
    config = _config()
    with (
        patch("blocksnoop.detector.BccDetector", autospec=True) as bcc,
        patch("blocksnoop.core_backend.CoreDetector", autospec=True) as core,
    ):
        assert (
            create_detector("bcc", config=config, callback=callback) is bcc.return_value
        )
        assert (
            create_detector("core", config=config, callback=callback)
            is core.return_value
        )


def test_validate_core_backend_never_imports_bcc() -> None:
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch.dict(sys.modules, {"bcc": None}),
    ):
        validate_backend_available("core")


def test_core_sidecar_environment_override_is_resolved() -> None:
    with (
        patch.dict("os.environ", {"BLOCKSNOOP_EBPF": "/opt/blocksnoop-ebpf"}),
        patch(
            "blocksnoop.core_backend.shutil.which", return_value="/opt/blocksnoop-ebpf"
        ) as which,
    ):
        assert find_sidecar() == "/opt/blocksnoop-ebpf"
    which.assert_called_once_with("/opt/blocksnoop-ebpf")


def test_core_detector_reports_missing_sidecar_without_spawning() -> None:
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value=None),
        patch("blocksnoop.core_backend.subprocess.Popen") as popen,
        pytest.raises(CoreDetectorError, match="not found in PATH"),
    ):
        CoreDetector(_config(), Mock()).start()
    popen.assert_not_called()


def test_core_detector_decodes_ready_event_and_lost_messages() -> None:
    callback = Mock()
    process = _FakeProcess(
        "\n".join(
            [
                _READY,
                '{"version": 1, "type": "event", "start_ns": 10, "end_ns": 20, "pid": 1234, "tid": 1235}',
                '{"version": 1, "type": "lost", "count": 2}',
            ]
        )
        + "\n"
    )
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch(
            "blocksnoop.core_backend.subprocess.Popen", return_value=process
        ) as popen,
    ):
        detector = CoreDetector(_config(), callback)
        detector.start()
        detector.stop()

    callback.assert_called_once_with(
        BlockingEvent(start_ns=10, end_ns=20, pid=1234, tid=1235)
    )
    assert popen.call_args.args[0] == [
        "/bin/sidecar",
        "--protocol-version",
        "1",
        "--pid",
        "1234",
        "--tid",
        "1235",
        "--threshold-ns",
        "12500000",
    ]
    assert popen.call_args.kwargs["shell"] is False
    assert process.wait_calls == 1


def test_core_detector_fatal_handshake_reaps_process_and_keeps_stderr_tail() -> None:
    process = _FakeProcess(
        '{"version": 1, "type": "fatal", "message": "BTF unavailable"}\n',
        "kernel details\n",
    )
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch("blocksnoop.core_backend.subprocess.Popen", return_value=process),
        pytest.raises(CoreDetectorError, match="BTF unavailable.*kernel details"),
    ):
        CoreDetector(_config(), Mock()).start()
    assert process.wait_calls == 1


def test_core_detector_rejects_incoherent_ready_handshake() -> None:
    process = _FakeProcess(
        '{"version": 1, "type": "ready", "pid": 99, "tid": 1235, '
        '"threshold_ns": 12500000, "tracepoints": ["epoll_wait"]}\n'
    )
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch("blocksnoop.core_backend.subprocess.Popen", return_value=process),
        pytest.raises(CoreDetectorError, match="ready message does not match"),
    ):
        CoreDetector(_config(), Mock()).start()
    assert process.wait_calls == 1


def test_core_detector_rejects_corrupt_sidecar_handshake() -> None:
    process = _FakeProcess("this is not NDJSON\n")
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch("blocksnoop.core_backend.subprocess.Popen", return_value=process),
        pytest.raises(CoreDetectorError, match="invalid NDJSON"),
    ):
        CoreDetector(_config(), Mock()).start()


def test_core_detector_rejects_invalid_or_mismatched_events() -> None:
    callback = Mock()
    process = _FakeProcess(
        "\n".join(
            [
                _READY,
                '{"version": 1, "type": "event", "start_ns": true, "end_ns": 2, "pid": 1234, "tid": 1235}',
                '{"version": 1, "type": "event", "start_ns": 3, "end_ns": 2, "pid": 1234, "tid": 1235}',
                '{"version": 1, "type": "event", "start_ns": 1, "end_ns": 2, "pid": 99, "tid": 1235}',
            ]
        )
        + "\n"
    )
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch("blocksnoop.core_backend.subprocess.Popen", return_value=process),
    ):
        detector = CoreDetector(_config(), callback)
        detector.start()
        detector.stop()
    callback.assert_not_called()


def test_core_detector_logs_callback_exception_and_continues(caplog) -> None:
    callback = Mock(side_effect=[RuntimeError("sink down"), None])
    event = '"start_ns": 1, "end_ns": 2, "pid": 1234, "tid": 1235'
    process = _FakeProcess(
        "\n".join(
            [
                _READY,
                f'{{"version": 1, "type": "event", {event}}}',
                f'{{"version": 1, "type": "event", {event}}}',
            ]
        )
        + "\n"
    )
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch("blocksnoop.core_backend.subprocess.Popen", return_value=process),
        caplog.at_level("ERROR", logger="blocksnoop.core_backend"),
    ):
        detector = CoreDetector(_config(), callback)
        detector.start()
        assert detector._reader is not None
        detector._reader.join(timeout=1)
        detector.stop()
    assert callback.call_count == 2
    assert "callback failed" in caplog.text


def test_core_detector_start_and_stop_are_idempotent() -> None:
    process = _FakeProcess(_READY + "\n")
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch(
            "blocksnoop.core_backend.subprocess.Popen", return_value=process
        ) as popen,
    ):
        detector = CoreDetector(_config(), Mock())
        detector.start()
        detector.start()
        detector.stop()
        detector.stop()
    popen.assert_called_once()
    assert process.wait_calls == 1


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        ('{"version": 1, "type": "fatal", "message": "poll failed"}\n', "poll failed"),
        ("", "exited unexpectedly after ready"),
    ],
)
def test_core_detector_reports_runtime_fatal_or_eof(suffix: str, expected: str) -> None:
    process = _FakeProcess(_READY + "\n" + suffix)
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch("blocksnoop.core_backend.subprocess.Popen", return_value=process),
    ):
        detector = CoreDetector(_config(), Mock())
        detector.start()
        assert detector._reader is not None
        detector._reader.join(timeout=1)
        with pytest.raises(CoreDetectorError, match=expected):
            detector.check_health()
        detector.stop()


def test_core_detector_wraps_sidecar_exec_error() -> None:
    with (
        patch("blocksnoop.core_backend.find_sidecar", return_value="/bin/sidecar"),
        patch(
            "blocksnoop.core_backend.subprocess.Popen",
            side_effect=OSError(8, "Exec format error"),
        ),
        pytest.raises(CoreDetectorError, match="Could not start.*executable"),
    ):
        CoreDetector(_config(), Mock()).start()

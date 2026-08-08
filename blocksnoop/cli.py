"""CLI entry point for blocksnoop."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import subprocess
import sys
import time
import typing

from blocksnoop.backends import Backend, create_detector, validate_backend_available
from blocksnoop.core import DetectorConfig
from blocksnoop.core_backend import CoreDetectorError
from blocksnoop.correlator import Correlator
from blocksnoop.profiler import (
    AustinSampler,
    check_austin_available,
)
from blocksnoop.reporter import Reporter
from blocksnoop.sinks import ConsoleSink, JsonFileSink, JsonStreamSink, Sink
from blocksnoop.stats import StatsCollector

_logger = logging.getLogger("blocksnoop.cli")


def _parse_args(
    argv: list[str] | None = None,
) -> tuple[argparse.Namespace, argparse.ArgumentParser]:
    """Parse CLI arguments and return (namespace, parser)."""
    parser = argparse.ArgumentParser(
        description="Detect blocking calls in asyncio event loops"
    )
    parser.add_argument(
        "target", nargs="?", default=None, help="PID of the target process"
    )
    parser.add_argument(
        "command", nargs=argparse.REMAINDER, help="Command to launch (after --)"
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=float,
        default=None,
        help="Blocking threshold in ms (default: 100, or 0 with --stats)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="eBPF-only mode: capture all epoll gaps and show distribution statistics",
    )
    parser.add_argument(
        "--tid",
        type=int,
        default=None,
        help="Thread ID to monitor (default: main thread)",
    )
    parser.add_argument(
        "--backend",
        choices=("bcc", "core"),
        default="bcc",
        help="eBPF backend to use (default: bcc)",
    )
    parser.add_argument(
        "--json", dest="json_mode", action="store_true", help="JSON lines output"
    )
    parser.add_argument(
        "--log-file",
        default=None,
        metavar="PATH",
        help="Write JSON lines to FILE for log aggregators",
    )
    parser.add_argument(
        "--service",
        default="blocksnoop",
        help="Service name for structured logs (default: blocksnoop)",
    )
    parser.add_argument(
        "--env",
        default="",
        help="Environment tag for structured logs (e.g. production)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors in terminal output"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging to stderr"
    )
    parser.add_argument(
        "--error-threshold",
        type=float,
        default=500.0,
        metavar="MS",
        help="Duration in ms above which events are classified as errors (default: 500)",
    )
    parser.add_argument(
        "--correlation-padding",
        type=float,
        default=200.0,
        metavar="MS",
        help="Correlation time window padding in ms (default: 200)",
    )

    return parser.parse_args(argv), parser


def _resolve_target(args: argparse.Namespace) -> tuple[int | None, list[str]]:
    """Return (target_pid, command) from parsed args."""
    # Strip leading "--" from command list (used as separator: blocksnoop -- python app.py)
    command: list[str] = list(args.command)
    if command and command[0] == "--":
        command = command[1:]

    # Resolve target: if it's not a valid PID, treat it as part of the command
    # (handles: blocksnoop -- python app.py, where argparse assigns "python" to target)
    target_pid: int | None = None
    if args.target is not None:
        try:
            target_pid = int(args.target)
        except ValueError:
            command = [args.target] + command

    return target_pid, command


def _validate_environment(
    *, stats_mode: bool = False, backend: Backend = "bcc"
) -> None:
    """Check runtime prerequisites; exits on failure."""
    if os.geteuid() != 0:
        print("error: blocksnoop must be run as root (sudo)", file=sys.stderr)
        sys.exit(1)

    if not stats_mode and not check_austin_available():
        print(
            "error: austin not found in PATH.\n"
            "  Install: https://github.com/P403n1x87/austin",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        validate_backend_available(backend)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


def _build_sinks(args: argparse.Namespace) -> list[Sink]:
    """Assemble output sinks from parsed args."""
    sinks: list[Sink] = []
    if args.json_mode:
        sinks.append(
            JsonStreamSink(sys.stdout, error_threshold_ms=args.error_threshold)
        )
    else:
        sinks.append(
            ConsoleSink(
                sys.stderr,
                color=not args.no_color,
                error_threshold_ms=args.error_threshold,
            )
        )
    if args.log_file:
        sinks.append(
            JsonFileSink(
                path=args.log_file,
                service=args.service,
                env=args.env,
                error_threshold_ms=args.error_threshold,
            )
        )
    return sinks


def _run_loop(
    start: typing.Callable[[], None],
    stop: typing.Callable[[], None],
    check_health: typing.Callable[[], None],
    on_exit: typing.Callable[[], None],
    child_process: subprocess.Popen | None,
) -> None:
    """Signal/wait loop shared by normal and stats paths."""
    cleaned_up = False

    def _cleanup() -> None:
        nonlocal cleaned_up
        if cleaned_up:
            return
        cleaned_up = True
        try:
            stop()
        finally:
            try:
                on_exit()
            finally:
                _stop_child(child_process)

    try:
        start()
    except Exception:
        _cleanup()
        raise

    def _shutdown(signum: int, frame: object) -> None:
        _cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        if child_process is not None:
            while child_process.poll() is None:
                check_health()
                time.sleep(0.1)
            child_process.wait()
        else:
            while True:
                check_health()
                time.sleep(1)
    except KeyboardInterrupt:
        _cleanup()
    except Exception:
        _cleanup()
        raise
    else:
        _cleanup()


def _stop_child(child_process: subprocess.Popen | None) -> None:
    """Terminate and reap a launched target without masking pipeline cleanup."""
    if child_process is None:
        return
    try:
        if child_process.poll() is None:
            child_process.terminate()
        child_process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            child_process.kill()
            child_process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


def main() -> None:
    args, parser = _parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        stream=sys.stderr,
        format="%(name)s %(levelname)s: %(message)s",
    )

    # Resolve threshold default: 0 for --stats, 100 otherwise
    if args.threshold is None:
        args.threshold = 0.0 if args.stats else 100.0

    target_pid, command = _resolve_target(args)

    _validate_environment(stats_mode=args.stats, backend=args.backend)
    _logger.debug(
        "Detector backend requested=%s effective=%s", args.backend, args.backend
    )

    # Validation: must have either a PID or a command
    if target_pid is None and not command:
        parser.print_usage(sys.stderr)
        print(
            "error: provide a target PID or a command to launch (after --)",
            file=sys.stderr,
        )
        sys.exit(1)

    child_process: subprocess.Popen | None = None

    # Launch mode: spawn subprocess and use its PID
    if command:
        child_process = subprocess.Popen(command)
        pid = child_process.pid
        _logger.debug("Launched child process: pid=%d, cmd=%s", pid, command)
    else:
        assert target_pid is not None  # guaranteed by validation above
        pid = target_pid

    try:
        if args.stats:
            _run_stats(args, pid, child_process)
        else:
            _run_normal(args, pid, child_process)
    except CoreDetectorError as exc:
        print(f"error: Core backend unavailable: {exc}", file=sys.stderr)
        sys.exit(1)


def _run_stats(
    args: argparse.Namespace,
    pid: int,
    child_process: subprocess.Popen | None,
) -> None:
    """Stats-only path: eBPF detector + StatsCollector, no Austin."""
    config = DetectorConfig(
        pid=pid,
        threshold_ms=args.threshold,
        tid=args.tid,
    )
    collector = StatsCollector(pid=pid, json_mode=args.json_mode)
    detector = create_detector(args.backend, config=config, callback=collector.on_event)

    _logger.debug(
        "Stats mode: pid=%d, tid=%d, threshold=%.0fms",
        config.pid,
        config.tid,
        config.threshold_ms,
    )

    def _start() -> None:
        collector.start()
        detector.start()

    def _stop() -> None:
        detector.stop()
        collector.stop()

    _run_loop(
        _start,
        _stop,
        detector.check_health,
        on_exit=lambda: None,
        child_process=child_process,
    )


def _run_normal(
    args: argparse.Namespace,
    pid: int,
    child_process: subprocess.Popen | None,
) -> None:
    """Normal path: eBPF + Austin + correlator + reporter."""
    sinks = _build_sinks(args)
    config = DetectorConfig(
        pid=pid,
        threshold_ms=args.threshold,
        tid=args.tid,
        correlation_padding_ms=args.correlation_padding,
    )
    reporter = Reporter(sinks=sinks)
    sampler = AustinSampler(
        pid=pid, sample_interval_ms=config.sample_interval_ms, tid=config.tid
    )
    correlator = Correlator(
        ring_buffer=sampler.ring_buffer,
        reporter_callback=reporter.report,
        correlation_padding_ns=int(config.correlation_padding_ms * 1_000_000),
    )
    detector = create_detector(
        args.backend, config=config, callback=correlator.on_event
    )

    _logger.debug(
        "Pipeline ready: pid=%d, tid=%d, threshold=%.0fms, "
        "sample_interval=%.0fms, correlation_padding=%.0fms",
        config.pid,
        config.tid,
        config.threshold_ms,
        config.sample_interval_ms,
        config.correlation_padding_ms,
    )

    start_time = time.monotonic()

    def _start() -> None:
        sampler.start()
        detector.start()

    def _stop() -> None:
        detector.stop()
        sampler.stop()

    def _on_exit() -> None:
        reporter.summary(time.monotonic() - start_time)
        reporter.close()

    _run_loop(_start, _stop, detector.check_health, _on_exit, child_process)


if __name__ == "__main__":
    main()

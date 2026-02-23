"""CLI entry point for blocksnoop."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

from blocksnoop.core import DetectorConfig
from blocksnoop.correlator import Correlator
from blocksnoop.detector import EbpfDetector
from blocksnoop.profiler import StackSampler, check_pyspy_available
from blocksnoop.reporter import Reporter
from blocksnoop.sinks import ConsoleSink, JsonFileSink, JsonStreamSink, Sink


def main() -> None:
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
        default=100,
        help="Blocking threshold in ms (default: 100)",
    )
    parser.add_argument(
        "--tid",
        type=int,
        default=None,
        help="Thread ID to monitor (default: main thread)",
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

    args = parser.parse_args()

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

    # Validation: must be root
    if os.geteuid() != 0:
        print("error: blocksnoop must be run as root (sudo)", file=sys.stderr)
        sys.exit(1)

    # Validation: py-spy must be available
    if not check_pyspy_available():
        print(
            "error: py-spy not found in PATH. Install with: pip install py-spy",
            file=sys.stderr,
        )
        sys.exit(1)

    # Validation: bcc must be importable
    try:
        import bcc  # noqa: F401  # type: ignore[unresolved-import]
    except ImportError:
        print("error: bcc (BPF Compiler Collection) is not installed", file=sys.stderr)
        sys.exit(1)

    # Validation: must have either a PID or a command
    if target_pid is None and not command:
        parser.print_usage(sys.stderr)
        print(
            "error: provide a target PID or a command to launch (after --)",
            file=sys.stderr,
        )
        sys.exit(1)

    # Assemble sinks
    sinks: list[Sink] = []
    if args.json_mode:
        sinks.append(JsonStreamSink(sys.stdout))
    else:
        sinks.append(ConsoleSink(sys.stderr, color=not args.no_color))
    if args.log_file:
        sinks.append(
            JsonFileSink(path=args.log_file, service=args.service, env=args.env)
        )

    child_process: subprocess.Popen | None = None

    # Launch mode: spawn subprocess and use its PID
    if command:
        child_process = subprocess.Popen(command)
        pid = child_process.pid
    else:
        assert target_pid is not None
        pid = target_pid

    # Wire the pipeline
    config = DetectorConfig(pid=pid, threshold_ms=args.threshold, tid=args.tid)
    reporter = Reporter(sinks=sinks)
    sampler = StackSampler(
        pid=pid, sample_interval_ms=config.sample_interval_ms, tid=config.tid
    )
    correlator = Correlator(
        ring_buffer=sampler.ring_buffer, reporter_callback=reporter.report
    )
    detector = EbpfDetector(config=config, callback=correlator.on_event)

    start_time = time.monotonic()
    sampler.start()
    detector.start()

    def _shutdown(signum: int, frame: object) -> None:
        detector.stop()
        sampler.stop()
        reporter.summary(time.monotonic() - start_time)
        reporter.close()
        if child_process is not None:
            child_process.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # In launch mode, also forward signals to the child and wait for it
    if child_process is not None:
        try:
            child_process.wait()
        except KeyboardInterrupt:
            pass
        detector.stop()
        sampler.stop()
        reporter.summary(time.monotonic() - start_time)
        reporter.close()
        child_process.terminate()
    else:
        # Attach mode: sleep until interrupted
        while True:
            time.sleep(1)


if __name__ == "__main__":
    main()

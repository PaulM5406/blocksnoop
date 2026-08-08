"""Core data structures for blocksnoop."""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Mapping
from typing import Protocol

# Stdlib module prefixes whose frames are noise in stack traces.
# Used by the correlator (to find the deepest app frame) and console sink
# (to hide asyncio/stdlib internals).
STDLIB_FRAME_PREFIXES: tuple[str, ...] = ("asyncio/", "selectors.py", "threading.py")


@dataclass(frozen=True)
class StackFrame:
    function: str
    file: str
    line: int


@dataclass(frozen=True)
class PythonStackTrace:
    thread_id: int
    thread_name: str
    frames: tuple[StackFrame, ...]


@dataclass(frozen=True)
class BlockingEvent:
    start_ns: int
    end_ns: int
    pid: int
    tid: int
    python_stacks: tuple[PythonStackTrace, ...] = ()

    @property
    def duration_ms(self) -> float:
        return (self.end_ns - self.start_ns) / 1_000_000


@dataclass(frozen=True)
class LostEvent:
    """A batch of kernel events the detector could not deliver."""

    count: int
    source: str


@dataclass
class DetectorConfig:
    pid: int
    threshold_ms: float = 100.0
    tid: int | None = None
    correlation_padding_ms: float = 200.0
    sample_interval_ms: float = field(init=False)

    def __post_init__(self) -> None:
        if self.tid is None:
            self.tid = self.pid
        self.sample_interval_ms = self.threshold_ms / 3


class Detector(Protocol):
    """Common lifecycle for blocking-event detector backends."""

    def start(self) -> None:
        """Start delivering blocking events to the configured callback."""

    def stop(self) -> None:
        """Stop the backend and release its resources."""

    def check_health(self) -> None:
        """Raise when the running backend can no longer deliver events."""

    @property
    def loss_counts(self) -> Mapping[str, int]:
        """Number of dropped events, grouped by the backend-reported source."""

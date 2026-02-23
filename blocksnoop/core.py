"""Core data structures for blocksnoop."""

from __future__ import annotations

from dataclasses import dataclass, field

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

"""Core data structures for loopspy."""

from __future__ import annotations

from dataclasses import dataclass, field


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
    python_stack: PythonStackTrace | None = None

    @property
    def duration_ms(self) -> float:
        return (self.end_ns - self.start_ns) / 1_000_000


@dataclass
class DetectorConfig:
    pid: int
    threshold_ms: float = 100.0
    tid: int | None = None
    sample_interval_ms: float = field(init=False)

    def __post_init__(self) -> None:
        if self.tid is None:
            self.tid = self.pid
        self.sample_interval_ms = self.threshold_ms / 3

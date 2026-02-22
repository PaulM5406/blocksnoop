"""Correlator module for loopspy — enriches blocking events with Python stacks."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from loopspy.core import BlockingEvent
from loopspy.profiler import StackRingBuffer


class Correlator:
    def __init__(self, ring_buffer: StackRingBuffer, reporter_callback: Callable[[BlockingEvent], None]) -> None:
        self._ring_buffer = ring_buffer
        self._callback = reporter_callback

    def on_event(self, event: BlockingEvent) -> None:
        """Enrich a BlockingEvent with Python stack from the ring buffer."""
        stack = self._ring_buffer.find_in_range(event.start_ns, event.end_ns)
        if stack is not None:
            event = replace(event, python_stack=stack)
        self._callback(event)

"""Correlator module for blocksnoop — enriches blocking events with Python stacks."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import replace

from blocksnoop.core import STDLIB_FRAME_PREFIXES, BlockingEvent, PythonStackTrace
from blocksnoop.profiler import StackRingBuffer

_logger = logging.getLogger("blocksnoop.correlator")


def _leaf_key(stack: PythonStackTrace) -> tuple[str, str]:
    """Return (function, file) of the deepest app-level frame for dedup.

    Austin stores frames root-to-leaf (frames[0]=<module>, frames[-1]=leaf).
    Walk from leaf toward root, skipping stdlib frames.
    Dedup by (function, file) — not line — so samples hitting different lines
    within the same function (e.g. a loop) collapse to one call site.
    """
    for f in reversed(stack.frames):
        if not any(p in f.file for p in STDLIB_FRAME_PREFIXES):
            return (f.function, f.file)
    f = stack.frames[-1]
    return (f.function, f.file)


def _is_informative(stack: PythonStackTrace) -> bool:
    """Return True if the stack has app frames beyond just ``<module>``."""
    app_frames = [
        f for f in stack.frames if not any(p in f.file for p in STDLIB_FRAME_PREFIXES)
    ]
    return len(app_frames) > 1 or (
        len(app_frames) == 1 and app_frames[0].function != "<module>"
    )


class Correlator:
    def __init__(
        self,
        ring_buffer: StackRingBuffer,
        reporter_callback: Callable[[BlockingEvent], None],
        correlation_padding_ns: int = 200_000_000,
    ) -> None:
        self._ring_buffer = ring_buffer
        self._callback = reporter_callback
        self._correlation_padding_ns = correlation_padding_ns

    def on_event(self, event: BlockingEvent) -> None:
        """Enrich a BlockingEvent with Python stacks from the ring buffer.

        BPF timestamps come from ``bpf_ktime_get_ns`` while the ring buffer
        uses ``time.monotonic_ns``.  Rather than computing an exact clock
        offset (which is skewed by perf-buffer delivery latency), we anchor
        the search on the current Python time: the blocking call just ended,
        so samples from during the call are roughly in
        ``[now - duration, now]``.  We collect all samples and deduplicate
        by their deepest (leaf) frame to show every unique blocking call site.
        """
        now = time.monotonic_ns()
        duration = event.end_ns - event.start_ns
        # BPF timestamps (bpf_ktime_get_ns) and Python timestamps
        # (time.monotonic_ns) use different clock sources.  Rather than computing
        # an exact offset — which is skewed by perf-buffer delivery latency — we
        # widen the search window by a configurable padding (default 200 ms).
        # Increase this value if stacks are frequently missing; decrease it to
        # reduce false-positive correlations.
        padding = max(duration, self._correlation_padding_ns)
        search_start = now - duration - padding
        search_end = now
        all_stacks = self._ring_buffer.find_all_in_range(search_start, search_end)
        _logger.debug(
            "Search window: %d ns, padding: %d ns, found %d stacks",
            duration,
            padding,
            len(all_stacks),
        )
        if all_stacks:
            seen: dict[tuple[str, str], PythonStackTrace] = {}
            for stack in all_stacks:
                if not stack.frames:
                    continue
                key = _leaf_key(stack)
                if key not in seen:
                    seen[key] = stack
            if seen:
                # Prefer stacks with real app frames over <module>-only stacks.
                informative = {k: v for k, v in seen.items() if _is_informative(v)}
                stacks = (
                    tuple(informative.values()) if informative else tuple(seen.values())
                )
                event = replace(event, python_stacks=stacks)
        self._callback(event)

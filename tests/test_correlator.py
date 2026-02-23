"""Unit tests for blocksnoop.correlator."""

from unittest.mock import patch

from blocksnoop.core import BlockingEvent, PythonStackTrace, StackFrame
from blocksnoop.correlator import Correlator, _is_informative, _leaf_key
from blocksnoop.profiler import StackRingBuffer


def _make_stack(fn: str = "blocking_io", file: str = "app.py") -> PythonStackTrace:
    return PythonStackTrace(
        thread_id=1,
        thread_name="main",
        frames=(StackFrame(function=fn, file=file, line=10),),
    )


def _make_deep_stack(leaf_fn: str, leaf_file: str = "app.py") -> PythonStackTrace:
    """Stack with <module> at root, asyncio in middle, app func at leaf."""
    return PythonStackTrace(
        thread_id=1,
        thread_name="main",
        frames=(
            StackFrame(function="<module>", file="app.py", line=222),
            StackFrame(function="_run_once", file="asyncio/base_events.py", line=2050),
            StackFrame(function="handle_login", file="app.py", line=50),
            StackFrame(function=leaf_fn, file=leaf_file, line=10),
        ),
    )


def _make_idle_stack() -> PythonStackTrace:
    """Event loop idle stack: <module> + asyncio — no real app frames."""
    return PythonStackTrace(
        thread_id=1,
        thread_name="main",
        frames=(
            StackFrame(function="<module>", file="app.py", line=222),
            StackFrame(function="_run_once", file="asyncio/base_events.py", line=2050),
            StackFrame(function="run_forever", file="asyncio/base_events.py", line=683),
            StackFrame(function="select", file="selectors.py", line=452),
        ),
    )


def test_leaf_key_uses_deepest_app_frame():
    """_leaf_key skips stdlib frames and returns the deepest app frame."""
    stack = _make_deep_stack("_slow_db_query")
    key = _leaf_key(stack)
    assert key == ("_slow_db_query", "app.py")


def test_leaf_key_idle_stack_falls_back_to_module():
    """For an idle stack, the deepest app frame is <module>."""
    key = _leaf_key(_make_idle_stack())
    assert key[0] == "<module>"


def test_leaf_key_all_stdlib_falls_back_to_leaf():
    """If all frames are stdlib, use the actual leaf frame."""
    stack = PythonStackTrace(
        thread_id=1,
        thread_name="main",
        frames=(
            StackFrame(function="select", file="selectors.py", line=452),
            StackFrame(function="_run_once", file="asyncio/base_events.py", line=2050),
        ),
    )
    key = _leaf_key(stack)
    assert key == ("_run_once", "asyncio/base_events.py")


def test_is_informative_with_app_frames():
    assert _is_informative(_make_deep_stack("_slow_db_query")) is True


def test_is_informative_idle_stack():
    assert _is_informative(_make_idle_stack()) is False


def test_is_informative_single_app_frame():
    """A single non-<module> app frame is informative."""
    stack = _make_stack("blocking_io")
    assert _is_informative(stack) is True


def test_correlator_enriches_event():
    """Correlator attaches Python stacks from the blocking window."""
    ring = StackRingBuffer()
    results: list[BlockingEvent] = []
    correlator = Correlator(ring, results.append)

    ring.push(850, _make_stack())

    event = BlockingEvent(start_ns=100, end_ns=300, pid=1, tid=1)
    with patch("blocksnoop.correlator.time") as mock_time:
        mock_time.monotonic_ns.return_value = 1000
        correlator.on_event(event)

    assert len(results) == 1
    assert len(results[0].python_stacks) == 1
    assert results[0].python_stacks[0].frames[0].function == "blocking_io"


def test_correlator_collects_multiple_distinct_stacks():
    """Correlator collects all unique stacks from the blocking window."""
    ring = StackRingBuffer()
    results: list[BlockingEvent] = []
    correlator = Correlator(ring, results.append)

    # now=1000, BPF duration=400 → window covers these timestamps
    ring.push(300, _make_deep_stack("_slow_db_query"))
    ring.push(500, _make_deep_stack("_slow_hash_password"))
    ring.push(700, _make_deep_stack("_slow_write_log"))

    event = BlockingEvent(start_ns=100, end_ns=500, pid=1, tid=1)
    with patch("blocksnoop.correlator.time") as mock_time:
        mock_time.monotonic_ns.return_value = 1000
        correlator.on_event(event)

    assert len(results) == 1
    fns = {s.frames[-1].function for s in results[0].python_stacks}
    assert fns == {"_slow_db_query", "_slow_hash_password", "_slow_write_log"}


def test_correlator_deduplicates_by_leaf_frame():
    """Duplicate leaf frames are collapsed to one representative stack."""
    ring = StackRingBuffer()
    results: list[BlockingEvent] = []
    correlator = Correlator(ring, results.append)

    ring.push(300, _make_deep_stack("_slow_db_query"))
    ring.push(500, _make_deep_stack("_slow_db_query"))

    event = BlockingEvent(start_ns=100, end_ns=500, pid=1, tid=1)
    with patch("blocksnoop.correlator.time") as mock_time:
        mock_time.monotonic_ns.return_value = 1000
        correlator.on_event(event)

    assert len(results) == 1
    assert len(results[0].python_stacks) == 1
    assert results[0].python_stacks[0].frames[-1].function == "_slow_db_query"


def test_correlator_deduplicates_same_function_different_lines():
    """Samples hitting different lines in the same function collapse to one."""
    ring = StackRingBuffer()
    results: list[BlockingEvent] = []
    correlator = Correlator(ring, results.append)

    # Two samples inside _slow_hash_password at different lines (loop body)
    stack_line_92 = PythonStackTrace(
        thread_id=1,
        thread_name="main",
        frames=(
            StackFrame(function="<module>", file="app.py", line=222),
            StackFrame(function="handle_login", file="app.py", line=147),
            StackFrame(function="_slow_hash_password", file="app.py", line=92),
        ),
    )
    stack_line_93 = PythonStackTrace(
        thread_id=1,
        thread_name="main",
        frames=(
            StackFrame(function="<module>", file="app.py", line=222),
            StackFrame(function="handle_login", file="app.py", line=147),
            StackFrame(function="_slow_hash_password", file="app.py", line=93),
        ),
    )
    ring.push(300, stack_line_92)
    ring.push(500, stack_line_93)

    event = BlockingEvent(start_ns=100, end_ns=500, pid=1, tid=1)
    with patch("blocksnoop.correlator.time") as mock_time:
        mock_time.monotonic_ns.return_value = 1000
        correlator.on_event(event)

    assert len(results) == 1
    assert len(results[0].python_stacks) == 1
    assert results[0].python_stacks[0].frames[-1].function == "_slow_hash_password"


def test_correlator_filters_idle_stacks_when_informative_available():
    """Idle stacks (only <module> + asyncio) are dropped when better stacks exist."""
    ring = StackRingBuffer()
    results: list[BlockingEvent] = []
    correlator = Correlator(ring, results.append)

    ring.push(200, _make_idle_stack())  # idle event loop sample
    ring.push(300, _make_idle_stack())  # another idle sample
    ring.push(500, _make_deep_stack("_slow_db_query"))  # actual blocking sample

    event = BlockingEvent(start_ns=100, end_ns=500, pid=1, tid=1)
    with patch("blocksnoop.correlator.time") as mock_time:
        mock_time.monotonic_ns.return_value = 1000
        correlator.on_event(event)

    assert len(results) == 1
    # Only the informative stack should remain
    assert len(results[0].python_stacks) == 1
    assert results[0].python_stacks[0].frames[-1].function == "_slow_db_query"


def test_correlator_keeps_idle_stacks_when_no_better_option():
    """If all stacks are idle, keep them rather than showing nothing."""
    ring = StackRingBuffer()
    results: list[BlockingEvent] = []
    correlator = Correlator(ring, results.append)

    ring.push(500, _make_idle_stack())

    event = BlockingEvent(start_ns=100, end_ns=500, pid=1, tid=1)
    with patch("blocksnoop.correlator.time") as mock_time:
        mock_time.monotonic_ns.return_value = 1000
        correlator.on_event(event)

    assert len(results) == 1
    assert len(results[0].python_stacks) == 1


def test_correlator_no_match():
    """Correlator passes event through with no stacks when ring buffer is empty."""
    ring = StackRingBuffer()
    results: list[BlockingEvent] = []
    correlator = Correlator(ring, results.append)

    event = BlockingEvent(start_ns=100, end_ns=200, pid=1, tid=1)
    with patch("blocksnoop.correlator.time") as mock_time:
        mock_time.monotonic_ns.return_value = 300
        correlator.on_event(event)

    assert len(results) == 1
    assert results[0].python_stacks == ()


def test_correlator_small_padding_misses_distant_stacks():
    """A very small padding narrows the search window, missing distant stacks."""
    ring = StackRingBuffer()
    results: list[BlockingEvent] = []
    # Use a tiny padding (1 ns) — the stack at ts=100 should be outside the window
    correlator = Correlator(ring, results.append, correlation_padding_ns=1)

    # Stack at ts=100, but now=1_000_000_000 (1 second later)
    ring.push(100, _make_stack())

    event = BlockingEvent(start_ns=500, end_ns=600, pid=1, tid=1)
    with patch("blocksnoop.correlator.time") as mock_time:
        mock_time.monotonic_ns.return_value = 1_000_000_000
        correlator.on_event(event)

    assert len(results) == 1
    assert results[0].python_stacks == ()


def test_correlator_large_padding_finds_distant_stacks():
    """A large padding widens the search window, finding distant stacks."""
    ring = StackRingBuffer()
    results: list[BlockingEvent] = []
    # 2-second padding
    correlator = Correlator(ring, results.append, correlation_padding_ns=2_000_000_000)

    ring.push(100, _make_stack())

    event = BlockingEvent(start_ns=500, end_ns=600, pid=1, tid=1)
    with patch("blocksnoop.correlator.time") as mock_time:
        mock_time.monotonic_ns.return_value = 1_000_000_000
        correlator.on_event(event)

    assert len(results) == 1
    assert len(results[0].python_stacks) == 1

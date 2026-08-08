"""Detector backend selection, kept separate from the CLI pipeline."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from blocksnoop.core import BlockingEvent, Detector, DetectorConfig, LostEvent

Backend = Literal["bcc", "core"]


def validate_backend_available(backend: Backend) -> None:
    """Raise an actionable error when the selected backend is unavailable."""
    if backend == "bcc":
        try:
            import bcc  # noqa: F401  # type: ignore[unresolved-import]
        except ImportError as exc:
            raise RuntimeError(
                "bcc (BPF Compiler Collection) is not installed. "
                "Install it from https://github.com/iovisor/bcc/blob/master/INSTALL.md "
                "or run with --backend core."
            ) from exc
        return

    from blocksnoop.core_backend import find_sidecar

    if find_sidecar() is None:
        raise RuntimeError(
            "blocksnoop-ebpf sidecar was not found in PATH. "
            "Install a blocksnoop release that includes the Core sidecar "
            "or run with --backend bcc."
        )


def create_detector(
    backend: Backend,
    *,
    config: DetectorConfig,
    callback: Callable[[BlockingEvent], None],
    loss_callback: Callable[[LostEvent], None] | None = None,
) -> Detector:
    """Create exactly the requested detector backend; never silently fall back."""
    if backend == "bcc":
        from blocksnoop.detector import BccDetector

        return BccDetector(
            config=config, callback=callback, loss_callback=loss_callback
        )
    if backend == "core":
        from blocksnoop.core_backend import CoreDetector

        return CoreDetector(
            config=config, callback=callback, loss_callback=loss_callback
        )
    raise ValueError(f"Unsupported detector backend: {backend}")

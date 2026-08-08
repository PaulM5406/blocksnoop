"""Detector backend selection, kept separate from the CLI pipeline."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from blocksnoop.core import BlockingEvent, Detector, DetectorConfig, LostEvent

Backend = Literal["bcc", "core"]


class BackendUnavailableError(RuntimeError):
    """An explicitly selected eBPF backend cannot be used in this runtime."""


def validate_backend_available(backend: Backend) -> None:
    """Validate exactly the requested backend; selection never falls back.

    Core is the normal backend.  BCC remains an explicit compatibility path
    for legacy hosts, and its dependency is deliberately not installed by
    blocksnoop itself.
    """
    if backend == "bcc":
        try:
            import bcc  # noqa: F401  # type: ignore[unresolved-import]
        except ImportError as exc:
            raise BackendUnavailableError(
                "BCC is the explicit legacy backend, but its Python module is not "
                "installed. Install it from "
                "https://github.com/iovisor/bcc/blob/master/INSTALL.md, or omit "
                "`--backend bcc` to use the default Core backend."
            ) from exc
        return

    from blocksnoop.core_backend import find_sidecar

    if find_sidecar() is None:
        raise BackendUnavailableError(
            "Core sidecar `blocksnoop-ebpf` was not found. Install a native Linux "
            "blocksnoop wheel or use the official Docker image; alternatively set "
            "BLOCKSNOOP_EBPF to a compatible sidecar. The portable wheel does not "
            "include native Core assets."
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

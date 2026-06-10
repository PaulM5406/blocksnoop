"""Tests for kernel header detection in detector module."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from blocksnoop.detector import (
    _build_bpf_source,
    _detect_epoll_syscalls,
    _ensure_kernel_headers,
)

# Mirrors blockdetect.c — the marker _build_bpf_source replaces with probes.
_RAW_SOURCE = (
    "BPF_HASH(callback_start, u32, u64);\nBPF_PERF_OUTPUT(events);\n__EPOLL_PROBES__\n"
)


def _setup_headers(
    tmp_path: Path, *, arch_suffix: str = "amd64", with_common: bool = False
) -> Path:
    """Create a fake /usr/src layout with arch-specific (and optionally common) headers."""
    usr_src = tmp_path / "usr" / "src"
    arch = usr_src / f"linux-headers-6.1.0-1-{arch_suffix}"
    arch.mkdir(parents=True)
    (arch / "include").mkdir()
    (arch / "include" / "generated").mkdir()
    (arch / "include" / "generated" / "autoconf.h").touch()

    if with_common:
        common = usr_src / "linux-headers-6.1.0-1-common"
        common.mkdir(parents=True)
        include = common / "include"
        include.mkdir()
        (include / "linux").mkdir()
        (include / "linux" / "types.h").touch()
        # arch-specific asm headers
        asm = common / "arch" / "x86" / "include" / "asm"
        asm.mkdir(parents=True)
        (asm / "ptrace.h").touch()
        uapi_asm = common / "arch" / "x86" / "include" / "uapi" / "asm"
        uapi_asm.mkdir(parents=True)
        (uapi_asm / "types.h").touch()

    return tmp_path


def test_build_dir_exists_is_noop(tmp_path: Path) -> None:
    """When /lib/modules/{kernel}/build already exists, do nothing."""
    modules = tmp_path / "lib" / "modules" / "6.12.69" / "build"
    modules.mkdir(parents=True)

    with (
        patch("blocksnoop.detector.os.uname") as mock_uname,
        patch("blocksnoop.detector.glob.glob", return_value=[]),
        patch("blocksnoop.detector.Path", wraps=Path) as mock_path_cls,
    ):
        mock_uname.return_value = type("uname", (), {"release": "6.12.69"})()
        # Make Path() for the build_dir check point to our tmp_path
        original_path = Path

        def patched_path(p: str, *args: object) -> Path:
            if p.startswith("/lib/modules"):
                return original_path(str(tmp_path) + p)
            return original_path(p, *args)

        mock_path_cls.side_effect = patched_path
        # Should not raise or create anything
        _ensure_kernel_headers()


def test_symlinks_arch_headers_when_build_missing(tmp_path: Path) -> None:
    """When build dir is missing, symlink to available arch headers."""
    root = _setup_headers(tmp_path, arch_suffix="amd64")
    modules_dir = root / "lib" / "modules" / "6.12.69"
    build_dir = modules_dir / "build"
    usr_src = root / "usr" / "src"
    arch_headers = usr_src / "linux-headers-6.1.0-1-amd64"

    with (
        patch("blocksnoop.detector.os.uname") as mock_uname,
        patch(
            "blocksnoop.detector.glob.glob",
            side_effect=lambda pattern: (
                [str(arch_headers)]
                if "amd64" in pattern
                else sorted(str(p) for p in usr_src.glob(pattern.split("/")[-1]))
                if "*" in pattern
                else []
            ),
        ),
        patch("blocksnoop.detector.Path") as mock_path_cls,
    ):
        mock_uname.return_value = type("uname", (), {"release": "6.12.69"})()

        # Wire Path() calls to use tmp_path-based paths
        real_build = build_dir
        real_parent = modules_dir

        mock_build = type(
            "MockPath",
            (),
            {
                "is_dir": lambda self: real_build.is_dir(),
                "parent": type(
                    "MockParent",
                    (),
                    {
                        "mkdir": lambda self, **kw: real_parent.mkdir(**kw),
                    },
                )(),
                "symlink_to": lambda self, target: real_build.symlink_to(target),
            },
        )()

        mock_path_cls.side_effect = lambda p: (
            mock_build if "lib/modules" in str(p) else Path(p)
        )

        _ensure_kernel_headers()

    assert real_build.is_symlink()
    assert real_build.resolve() == arch_headers.resolve()


def test_merges_common_headers(tmp_path: Path) -> None:
    """When common headers exist, merge includes and asm symlinks into arch tree."""
    root = _setup_headers(tmp_path, arch_suffix="amd64", with_common=True)
    usr_src = root / "usr" / "src"
    arch_headers = usr_src / "linux-headers-6.1.0-1-amd64"
    common_headers = usr_src / "linux-headers-6.1.0-1-common"

    from blocksnoop.detector import _merge_common_headers

    with patch("blocksnoop.detector.platform.machine", return_value="x86_64"):
        _merge_common_headers(arch_headers, common_headers)

    # Common include/linux should be symlinked into arch tree
    assert (arch_headers / "include" / "linux").is_symlink()
    # asm symlink
    assert (arch_headers / "include" / "asm").is_symlink()
    # uapi/asm symlink
    assert (arch_headers / "include" / "uapi" / "asm").is_symlink()


def test_no_headers_found_warns(tmp_path: Path, caplog: object) -> None:
    """When no headers are found, log a warning but don't raise."""
    import logging

    with (
        patch("blocksnoop.detector.os.uname") as mock_uname,
        patch("blocksnoop.detector.glob.glob", return_value=[]),
        patch("blocksnoop.detector.Path") as mock_path_cls,
        caplog.at_level(logging.WARNING),  # type: ignore[union-attr]
    ):
        mock_uname.return_value = type("uname", (), {"release": "6.12.69"})()
        mock_path_cls.return_value = type(
            "MockPath",
            (),
            {"is_dir": lambda self: False},
        )()

        _ensure_kernel_headers()

    assert "No kernel headers found" in caplog.text  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# _get_pidns_info
# ---------------------------------------------------------------------------


def test_get_pidns_info_returns_dev_ino() -> None:
    """_get_pidns_info returns (st_dev, st_ino), defaulting to /proc/self/ns/pid."""
    from blocksnoop.detector import _get_pidns_info

    mock_result = type("stat_result", (), {"st_dev": 3, "st_ino": 4026531836})()
    with patch("blocksnoop.detector.os.stat", return_value=mock_result):
        result = _get_pidns_info()
    assert result == (3, 4026531836)


def test_get_pidns_info_returns_none_on_failure() -> None:
    """_get_pidns_info returns None when /proc/self/ns/pid is unavailable."""
    from blocksnoop.detector import _get_pidns_info

    with patch("blocksnoop.detector.os.stat", side_effect=OSError("No such file")):
        result = _get_pidns_info()
    assert result is None


def test_get_pidns_info_prefers_target_pid_namespace() -> None:
    """When a target PID is given, read /proc/<target>/ns/pid so the eBPF filter
    matches the target's PID namespace (not blocksnoop's).

    Regression: without this, cross-PID-ns runs (e.g. K8s hostPID Job against a
    container in its own PID namespace) filter out every event because the
    eBPF program compares each event's namespace ino against blocksnoop's own
    PID-ns ino, which the target's events never carry.
    """
    from blocksnoop.detector import _get_pidns_info

    target_stat = type("stat_result", (), {"st_dev": 4, "st_ino": 4026532001})()
    self_stat = type("stat_result", (), {"st_dev": 3, "st_ino": 4026531836})()

    def fake_stat(path: str) -> object:
        return target_stat if "/proc/833976/" in path else self_stat

    with patch("blocksnoop.detector.os.stat", side_effect=fake_stat):
        result = _get_pidns_info(target_pid=833976)
    assert result == (4, 4026532001)


def test_get_pidns_info_falls_back_to_self_when_target_unreachable() -> None:
    """If /proc/<target>/ns/pid can't be stat'd, fall back to /proc/self/ns/pid."""
    from blocksnoop.detector import _get_pidns_info

    self_stat = type("stat_result", (), {"st_dev": 3, "st_ino": 4026531836})()

    def fake_stat(path: str) -> object:
        if path == "/proc/self/ns/pid":
            return self_stat
        raise OSError("not visible")

    with patch("blocksnoop.detector.os.stat", side_effect=fake_stat):
        result = _get_pidns_info(target_pid=833976)
    assert result == (3, 4026531836)


# ---------------------------------------------------------------------------
# _resolve_target_ns_tgid
# ---------------------------------------------------------------------------


class _StringIO:
    """Local helper avoiding an extra module import at top."""

    def __init__(self, data: str) -> None:
        self._data = data

    def __enter__(self) -> "_StringIO":
        return self

    def __exit__(self, *exc) -> None:
        pass

    def __iter__(self):
        return iter(self._data.splitlines(keepends=True))


def test_resolve_target_ns_tgid_picks_innermost() -> None:
    """NSpid lists outer→inner. Return the innermost value — what the BPF
    helper `bpf_get_ns_current_pid_tgid` reports for the target's tasks.
    """
    from blocksnoop.detector import _resolve_target_ns_tgid

    status = "Name:\tpython\nNSpid:\t833976\t1\n"
    with patch("builtins.open", new=lambda *a, **k: _StringIO(status)):
        assert _resolve_target_ns_tgid(833976) == 1


def test_resolve_target_ns_tgid_single_value() -> None:
    """Same-namespace target: NSpid has a single column == host PID."""
    from blocksnoop.detector import _resolve_target_ns_tgid

    status = "Name:\tpython\nNSpid:\t4242\n"
    with patch("builtins.open", new=lambda *a, **k: _StringIO(status)):
        assert _resolve_target_ns_tgid(4242) == 4242


def test_resolve_target_ns_tgid_oserror_falls_back_to_host_pid() -> None:
    """Unreadable status → fall back to host PID (safe default)."""
    from blocksnoop.detector import _resolve_target_ns_tgid

    with patch("builtins.open", side_effect=OSError):
        assert _resolve_target_ns_tgid(9999) == 9999


# ---------------------------------------------------------------------------
# _detect_epoll_syscalls
# ---------------------------------------------------------------------------


def _fake_tracefs(*available: str):
    """Return an os.path.isdir replacement reporting only *available* variants."""
    present = {
        os.path.join("/sys/kernel/debug/tracing/events/syscalls", f"sys_enter_{n}")
        for n in available
    }
    return lambda path: path in present


def test_detect_epoll_syscalls_returns_all_available() -> None:
    """Every available variant is traced, in preferred order — not just the first.

    Regression: the loop on a uvloop/glibc target enters epoll_pwait, so a
    detector that returned only epoll_wait attached but never fired.
    """
    with patch(
        "blocksnoop.detector.os.path.isdir",
        side_effect=_fake_tracefs("epoll_wait", "epoll_pwait", "epoll_pwait2"),
    ):
        assert _detect_epoll_syscalls() == ["epoll_wait", "epoll_pwait", "epoll_pwait2"]


def test_detect_epoll_syscalls_skips_missing_variants() -> None:
    """Variants without a kernel tracepoint are skipped so BCC never references
    a missing one."""
    with patch(
        "blocksnoop.detector.os.path.isdir",
        side_effect=_fake_tracefs("epoll_wait", "epoll_pwait"),
    ):
        assert _detect_epoll_syscalls() == ["epoll_wait", "epoll_pwait"]


def test_detect_epoll_syscalls_raises_when_none() -> None:
    """No epoll tracepoint at all is a hard error (tracefs not mounted)."""
    import pytest

    with patch("blocksnoop.detector.os.path.isdir", side_effect=_fake_tracefs()):
        with pytest.raises(RuntimeError, match="No epoll tracepoint"):
            _detect_epoll_syscalls()


# ---------------------------------------------------------------------------
# _build_bpf_source
# ---------------------------------------------------------------------------


def test_build_bpf_source_emits_a_probe_pair_per_variant() -> None:
    """Each traced variant gets its own sys_enter/sys_exit probe pair."""
    source = _build_bpf_source(
        _RAW_SOURCE,
        threshold_ms=100,
        target_tgid=1,
        epoll_syscalls=["epoll_wait", "epoll_pwait", "epoll_pwait2"],
        pidns_info=None,
    )
    for name in ("epoll_wait", "epoll_pwait", "epoll_pwait2"):
        assert f"sys_exit_{name}" in source
        assert f"sys_enter_{name}" in source
    # No unresolved placeholders survive into the compiled program.
    assert "__EPOLL_PROBES__" not in source
    assert "__EPOLL_SYSCALL__" not in source
    assert "__THRESHOLD_NS__" not in source
    assert "__TARGET_TGID__" not in source


def test_build_bpf_source_substitutes_threshold_and_tgid() -> None:
    """threshold_ms is converted to ns and the target tgid is inlined."""
    source = _build_bpf_source(
        _RAW_SOURCE,
        threshold_ms=250,
        target_tgid=4242,
        epoll_syscalls=["epoll_wait"],
        pidns_info=None,
    )
    assert "250000000" in source  # 250ms → ns
    assert "4242" in source


def test_build_bpf_source_without_pidns_uses_host_pid_path() -> None:
    """No pidns_info → __USE_NS_PID__ stays undefined (same-namespace path)."""
    source = _build_bpf_source(
        _RAW_SOURCE,
        threshold_ms=100,
        target_tgid=1,
        epoll_syscalls=["epoll_wait"],
        pidns_info=None,
    )
    assert "#define __USE_NS_PID__" not in source
    assert "bpf_get_current_pid_tgid()" in source


def test_build_bpf_source_with_pidns_enables_ns_filtering() -> None:
    """pidns_info → __USE_NS_PID__ defined and dev/ino inlined for the helper."""
    source = _build_bpf_source(
        _RAW_SOURCE,
        threshold_ms=100,
        target_tgid=1,
        epoll_syscalls=["epoll_pwait"],
        pidns_info=(7, 4026532001),
    )
    assert source.startswith("#define __USE_NS_PID__\n")
    assert "bpf_get_ns_current_pid_tgid(7, 4026532001" in source
    assert "__PIDNS_DEV__" not in source
    assert "__PIDNS_INO__" not in source

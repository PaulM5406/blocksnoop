"""Unit tests for native-wheel sidecar resolution."""

from pathlib import Path
from unittest.mock import patch

from blocksnoop.core_backend import (
    DEFAULT_SIDECAR,
    _packaged_sidecar,
    find_sidecar,
)


def test_packaged_sidecar_resolves_linux_asset(tmp_path: Path) -> None:
    package_dir = tmp_path / "blocksnoop"
    sidecar = package_dir / "_native" / DEFAULT_SIDECAR
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text("sidecar")
    sidecar.chmod(0o755)

    with (
        patch("blocksnoop.core_backend.__file__", str(package_dir / "core_backend.py")),
        patch("blocksnoop.core_backend.sys.platform", "linux"),
    ):
        assert _packaged_sidecar() == str(sidecar)


def test_packaged_sidecar_is_not_selected_outside_linux(tmp_path: Path) -> None:
    package_dir = tmp_path / "blocksnoop"
    sidecar = package_dir / "_native" / DEFAULT_SIDECAR
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text("sidecar")
    sidecar.chmod(0o755)

    with (
        patch("blocksnoop.core_backend.__file__", str(package_dir / "core_backend.py")),
        patch("blocksnoop.core_backend.sys.platform", "darwin"),
    ):
        assert _packaged_sidecar() is None


def test_find_sidecar_prefers_environment_override(monkeypatch) -> None:
    monkeypatch.setenv("BLOCKSNOOP_EBPF", "/opt/blocksnoop-ebpf")
    with (
        patch("blocksnoop.core_backend._packaged_sidecar") as packaged,
        patch(
            "blocksnoop.core_backend.shutil.which", return_value="/opt/blocksnoop-ebpf"
        ) as which,
    ):
        assert find_sidecar() == "/opt/blocksnoop-ebpf"

    packaged.assert_not_called()
    which.assert_called_once_with("/opt/blocksnoop-ebpf")


def test_find_sidecar_prefers_packaged_linux_asset(monkeypatch) -> None:
    monkeypatch.delenv("BLOCKSNOOP_EBPF", raising=False)
    with (
        patch(
            "blocksnoop.core_backend._packaged_sidecar",
            return_value="/site/blocksnoop/_native/blocksnoop-ebpf",
        ),
        patch("blocksnoop.core_backend.shutil.which") as which,
    ):
        assert find_sidecar() == "/site/blocksnoop/_native/blocksnoop-ebpf"

    which.assert_not_called()


def test_find_sidecar_falls_back_to_path(monkeypatch) -> None:
    monkeypatch.delenv("BLOCKSNOOP_EBPF", raising=False)
    with (
        patch("blocksnoop.core_backend._packaged_sidecar", return_value=None),
        patch(
            "blocksnoop.core_backend.shutil.which",
            return_value="/usr/bin/blocksnoop-ebpf",
        ) as which,
    ):
        assert find_sidecar() == "/usr/bin/blocksnoop-ebpf"

    which.assert_called_once_with(DEFAULT_SIDECAR)

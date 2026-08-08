"""Setuptools hooks for optional native Linux wheel assets."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from wheel.bdist_wheel import bdist_wheel


def _native_wheel_enabled() -> bool:
    return os.environ.get("BLOCKSNOOP_NATIVE_WHEEL") == "1"


def _remove_native_assets(build_lib: str) -> None:
    """Keep a portable build clean when reusing a previous native build tree."""
    root = Path(build_lib) / "blocksnoop"
    for relative_path in (
        "_native/blocksnoop-ebpf",
        "bpf/core_blockdetect.bpf.o",
    ):
        (root / relative_path).unlink(missing_ok=True)


class BuildPyWithNativeAssets(build_py):
    """Copy prebuilt Linux assets into build_lib only for native wheels."""

    def run(self) -> None:
        super().run()
        if not _native_wheel_enabled():
            _remove_native_assets(self.build_lib)
            return
        if sys.platform != "linux":
            raise RuntimeError("BLOCKSNOOP_NATIVE_WHEEL is supported only on Linux")

        asset_dir_value = os.environ.get("BLOCKSNOOP_NATIVE_ASSET_DIR")
        if not asset_dir_value:
            raise RuntimeError(
                "BLOCKSNOOP_NATIVE_ASSET_DIR is required for a native wheel"
            )
        asset_dir = Path(asset_dir_value)
        assets = {
            asset_dir / "blocksnoop-ebpf": "blocksnoop/_native/blocksnoop-ebpf",
            asset_dir
            / "core_blockdetect.bpf.o": "blocksnoop/bpf/core_blockdetect.bpf.o",
        }
        missing = [str(source) for source in assets if not source.is_file()]
        if missing:
            raise RuntimeError(
                "native wheel assets are missing; run make -C native OUT_DIR=... first: "
                + ", ".join(missing)
            )

        for source, relative_destination in assets.items():
            destination = Path(self.build_lib, relative_destination)
            self.mkpath(str(destination.parent))
            self.copy_file(str(source), str(destination))
            if source.name == "blocksnoop-ebpf":
                destination.chmod(
                    destination.stat().st_mode
                    | stat.S_IXUSR
                    | stat.S_IXGRP
                    | stat.S_IXOTH
                )


class NativeAssetWheel(bdist_wheel):
    """Tag an asset-only Linux wheel as platform-specific, not pure Python."""

    def finalize_options(self) -> None:
        super().finalize_options()
        if _native_wheel_enabled():
            self.root_is_pure = False

    def get_tag(self) -> tuple[str, str, str]:
        if _native_wheel_enabled():
            _, _, platform_tag = super().get_tag()
            return "py3", "none", platform_tag
        return super().get_tag()


setup(
    cmdclass={
        "bdist_wheel": NativeAssetWheel,
        "build_py": BuildPyWithNativeAssets,
    }
)

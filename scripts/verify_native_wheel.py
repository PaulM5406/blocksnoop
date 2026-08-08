#!/usr/bin/env python3
"""Fail closed when a Linux wheel is missing or mis-tags Core assets."""

from __future__ import annotations

import argparse
import os
import struct
import sys
import zipfile
from importlib.resources import files
from pathlib import Path


_SIDECAR = "blocksnoop/_native/blocksnoop-ebpf"
_BPF_OBJECT = "blocksnoop/bpf/core_blockdetect.bpf.o"
_ARCH_MACHINE = {"x86_64": 62, "aarch64": 183}
_BPF_MACHINE = 247


def _elf_machine(data: bytes, label: str) -> int:
    if data[:4] != b"\x7fELF" or len(data) < 20:
        raise AssertionError(f"{label} is not a complete ELF file")
    if data[5] != 1:
        raise AssertionError(f"{label} is not little-endian")
    return struct.unpack_from("<H", data, 18)[0]


def _verify_elf(path: Path, expected_machine: int, label: str) -> None:
    machine = _elf_machine(path.read_bytes()[:64], label)
    if machine != expected_machine:
        raise AssertionError(
            f"{label} has ELF machine {machine}, expected {expected_machine}"
        )


def _verify_wheel(wheel: Path, architecture: str) -> None:
    expected_tag = f"py3-none-manylinux_2_28_{architecture}"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        missing = {_SIDECAR, _BPF_OBJECT} - names
        if missing:
            raise AssertionError(f"{wheel.name} is missing assets: {sorted(missing)}")

        wheel_metadata = next(
            name for name in names if name.endswith(".dist-info/WHEEL")
        )
        tags = {
            line.removeprefix("Tag: ")
            for line in archive.read(wheel_metadata).decode().splitlines()
            if line.startswith("Tag: ")
        }
        if expected_tag not in tags:
            raise AssertionError(
                f"{wheel.name} must contain Tag: {expected_tag}; found {sorted(tags)}"
            )
        if any(tag.endswith("-any") for tag in tags):
            raise AssertionError(
                f"{wheel.name} must not advertise a universal wheel tag"
            )

        sidecar_info = archive.getinfo(_SIDECAR)
        if not sidecar_info.external_attr >> 16 & 0o111:
            raise AssertionError(f"{wheel.name} sidecar is not executable")
        sidecar = archive.read(_SIDECAR)
        bpf_object = archive.read(_BPF_OBJECT)

    machine = _elf_machine(sidecar[:64], _SIDECAR)
    if machine != _ARCH_MACHINE[architecture]:
        raise AssertionError(
            f"{wheel.name} sidecar has ELF machine {machine}, "
            f"expected {_ARCH_MACHINE[architecture]}"
        )
    if _elf_machine(bpf_object[:64], _BPF_OBJECT) != _BPF_MACHINE:
        raise AssertionError(f"{wheel.name} BPF object is not EM_BPF")


def _verify_installed(architecture: str) -> None:
    root = Path(str(files("blocksnoop")))
    sidecar = root / "_native" / "blocksnoop-ebpf"
    bpf_object = root / "bpf" / "core_blockdetect.bpf.o"
    if not sidecar.is_file() or not os.access(sidecar, os.X_OK):
        raise AssertionError(
            f"installed sidecar is absent or non-executable: {sidecar}"
        )
    if not bpf_object.is_file():
        raise AssertionError(f"installed BPF object is absent: {bpf_object}")
    _verify_elf(sidecar, _ARCH_MACHINE[architecture], "installed sidecar")
    _verify_elf(bpf_object, _BPF_MACHINE, "installed BPF object")

    from blocksnoop.core_backend import find_sidecar

    if find_sidecar() != str(sidecar):
        raise AssertionError(
            "Core sidecar discovery did not select the packaged native asset"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=sorted(_ARCH_MACHINE), required=True)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args()
    if bool(args.wheel) == args.installed:
        parser.error("provide exactly one of --wheel or --installed")
    if args.wheel:
        _verify_wheel(args.wheel, args.arch)
    else:
        _verify_installed(args.arch)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"native wheel gate failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

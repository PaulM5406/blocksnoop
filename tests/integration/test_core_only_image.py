"""Contract checks for the published Core-only runtime image."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.docker


def test_core_only_image_embeds_native_assets_without_bcc(
    docker_image, docker_client
) -> None:
    """The Core image must run packaged assets, never its build dependencies."""
    command = [
        "sh",
        "-ec",
        """
        ! command -v bcc
        ! dpkg-query -W -f='${db:Status-Status}' bpfcc-tools 2>/dev/null | grep -qx installed
        ! find /usr/src -maxdepth 1 -type d -name 'linux-headers*' | grep -q .
        python - <<'PY'
        import importlib.util
        import json
        import os
        import subprocess
        from importlib.resources import files

        assert importlib.util.find_spec("bcc") is None
        root = files("blocksnoop")
        sidecar = root.joinpath("_native/blocksnoop-ebpf")
        bpf_object = root.joinpath("bpf/core_blockdetect.bpf.o")
        assert os.access(sidecar, os.X_OK), sidecar
        assert bpf_object.is_file(), bpf_object

        doctor = subprocess.run(
            ["blocksnoop", "doctor", "--backend", "core", "--json"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert doctor.returncode in (0, 1), doctor.stderr
        report = json.loads(doctor.stdout)
        checks = {check["name"]: check for check in report["checks"]}
        assert checks["sidecar"]["status"] == "pass"
        assert checks["bpf_object"]["status"] == "pass"
        assert checks["bcc"]["status"] == "warn"
        PY
        """,
    ]
    docker_client.containers.run(docker_image, command=command, remove=True)

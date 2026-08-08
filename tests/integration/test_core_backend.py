"""Docker-image contract for the experimental libbpf backend."""

import pytest

from tests.integration.conftest import run_blocksnoop_docker

pytestmark = pytest.mark.docker


@pytest.mark.parametrize(
    "fixture",
    ["tests/fixtures/blocking_cpu.py", "tests/fixtures/blocking_io.py"],
)
def test_core_backend_detects_blocking_workloads(docker_image, fixture):
    result = run_blocksnoop_docker(
        fixture,
        timeout_s=10,
        threshold_ms=100,
        extra_args=["--backend", "core"],
    )

    assert result.events, (
        f"Core backend emitted no events for {fixture}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert all(event["duration_ms"] >= 100 for event in result.events)

"""Docker contract for the first-class default eBPF backend."""

import pytest

from tests.integration.conftest import run_blocksnoop_docker

pytestmark = pytest.mark.docker


@pytest.mark.parametrize(
    "fixture",
    ["tests/fixtures/blocking_cpu.py", "tests/fixtures/blocking_io.py"],
)
def test_default_backend_detects_blocking_workloads(docker_image, fixture):
    result = run_blocksnoop_docker(
        fixture,
        timeout_s=10,
        threshold_ms=100,
    )

    assert result.events, (
        f"The default backend emitted no blocking events for {fixture}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert all(event["duration_ms"] >= 100 for event in result.events)

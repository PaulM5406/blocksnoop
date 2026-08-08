"""End-to-end regression test for cross-PID-namespace attach.

When blocksnoop and the target live in different PID namespaces (the K8s
``hostPID: true`` Job topology), the fd-passing nsenter wrapper must:

  - Enter BOTH mount and PID namespaces (``nsenter -m -p``). With just ``-m``,
    ``/proc/self/fd/N`` ENOENTs because the procfs in the target's mount ns
    is bound to the target's PID namespace and the caller's host PID isn't
    visible there.
  - Translate the host PID to the target's container-local PID (``NSpid``
    from ``/proc/<pid>/status``) before passing it to Austin via ``-p``.
    The host PID doesn't exist inside the target's PID namespace.

Both bugs slipped past ``examples/reproduce-cross-ns.sh`` because that repro
uses ``--pid=container:<target>``, which collapses the two PID namespaces
(no ``-p`` needed, host PID == container PID). This test uses
``pid_mode="host"`` for blocksnoop to actually exercise the cross-PID-ns
path that production K8s Jobs encounter.
"""

from __future__ import annotations

import json
import os
import time

import pytest

pytestmark = pytest.mark.docker

TARGET_IMAGE = "python:3.11-slim"
# An asyncio loop with a synchronous blocking call inside (300ms > 100ms
# threshold). The loop sits in an epoll syscall between awaits, which is what
# blocksnoop's eBPF program watches (the whole epoll family — epoll_wait /
# epoll_pwait / epoll_pwait2 — so the variant the libc/loop picks doesn't
# matter); a bare `time.sleep` loop without asyncio wouldn't trigger any
# eBPF events.
TARGET_SCRIPT = (
    "import asyncio, time\n"
    "async def main():\n"
    "    while True:\n"
    "        time.sleep(0.3)\n"
    "        await asyncio.sleep(0.05)\n"
    "asyncio.run(main())\n"
)

THRESHOLD_MS = 100
BLOCKSNOOP_TIMEOUT_S = 10
SETTLE_DELAY_S = 2


def test_default_backend_attaches_across_pid_namespaces(docker_image, docker_client):
    """blocksnoop in host PID ns + target in private PID ns → Austin samples.

    Regression test for two bugs that broke this exact topology:
      1. nsenter without ``-p`` → /proc/self/fd unresolvable inside target.
      2. host PID passed to Austin → "Cannot attach to the given process".
    """
    image = docker_client.images.get(docker_image)
    if not os.environ.get("BLOCKSNOOP_TEST_IMAGE"):
        assert docker_image in image.tags, (
            "docker-compose must tag the locally built image consistently, even "
            "when the checkout is a worktree"
        )

    target = docker_client.containers.run(
        TARGET_IMAGE,
        command=["python", "-c", TARGET_SCRIPT],
        detach=True,
        remove=True,
        read_only=True,
        tmpfs={"/tmp": ""},
    )
    try:
        # Let CPython finish import + reach the sleep loop.
        time.sleep(SETTLE_DELAY_S)

        host_pid = docker_client.api.inspect_container(target.id)["State"]["Pid"]
        assert host_pid > 0, "target container has no host PID"
        assert host_pid != 1, "target unexpectedly shares the collector PID namespace"

        exit_code, status = target.exec_run(["cat", "/proc/1/status"])
        assert exit_code == 0, status.decode()
        nspid_line = next(
            line for line in status.decode().splitlines() if line.startswith("NSpid:")
        )
        target_ns_pid = int(nspid_line.split()[-1])

        # blocksnoop in HOST PID namespace — same topology as a K8s Job with
        # hostPID: true targeting a worker pod that has its own PID ns. Run
        # detached so we can collect logs even when `timeout` exits with 124
        # (the expected outcome — Austin runs until the test window closes).
        snoop = docker_client.containers.run(
            docker_image,
            command=[
                "timeout",
                str(BLOCKSNOOP_TIMEOUT_S),
                "blocksnoop",
                "-t",
                str(THRESHOLD_MS),
                "--json",
                str(host_pid),
            ],
            pid_mode="host",
            privileged=True,
            volumes={"/sys/kernel/debug": {"bind": "/sys/kernel/debug", "mode": "rw"}},
            detach=True,
        )
        try:
            snoop.wait(timeout=BLOCKSNOOP_TIMEOUT_S + 10)
            output = snoop.logs(stdout=True, stderr=True)
        finally:
            try:
                snoop.remove(force=True)
            except Exception:  # noqa: BLE001
                pass
    finally:
        # Best-effort cleanup — `remove=True` handles the normal path; this
        # catches the case where blocksnoop's run raised before reaching
        # the natural end.
        try:
            target.stop(timeout=1)
        except Exception:  # noqa: BLE001
            pass

    text = output.decode() if isinstance(output, bytes) else output

    # Both bugs surface as one of these markers — assert them explicitly so
    # a regression produces a readable failure rather than just "no events".
    assert "Cannot determine the version" not in text, (
        "Austin couldn't read Python ELF — fd-passing wrapper broke "
        "(likely missing `-p` on nsenter):\n" + text
    )
    assert "Austin has not produced any samples" not in text, (
        "Austin attached but produced no samples — likely missing NSpid "
        "translation (Austin got the host PID, not the container PID):\n" + text
    )
    assert "Cannot attach to the given process" not in text, (
        "Austin couldn't attach — host PID likely passed instead of "
        "container-local NSpid:\n" + text
    )
    assert "Core backend unavailable" not in text, text
    assert "Core sidecar error" not in text, text
    assert '"type":"fatal"' not in text, text

    # Parse JSON events; at least one with a python_stacks payload proves
    # Austin both attached AND read Python frames across the namespace gap.
    events: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(ev, dict)
            and ev.get("type") == "blocking_event"
            and "python_stacks" in ev
        ):
            events.append(ev)

    assert events, f"no Austin samples with python_stacks emitted; raw output:\n{text}"
    assert all(event["duration_ms"] >= THRESHOLD_MS for event in events)

    # The v1 default backend is Core.  Namespace-local ids prove that its
    # bpf_get_ns_current_pid_tgid filter saw the target namespace, rather than
    # accepting the host PID or silently switching to BCC.
    assert all(event["pid"] == target_ns_pid for event in events), text
    assert all(event["tid"] == target_ns_pid for event in events), text
    assert all(event["pid"] != host_pid for event in events), text

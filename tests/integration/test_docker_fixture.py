"""Unit-level contracts for Docker fixture failure handling."""

from __future__ import annotations

import subprocess

import pytest

from tests.integration import conftest as integration_conftest


def _docker_info_timeout(*_args: object, **_kwargs: object) -> None:
    raise subprocess.TimeoutExpired(["docker", "info"], timeout=10)


def test_docker_image_timeout_skips_without_remote_image(monkeypatch) -> None:
    monkeypatch.delenv("BLOCKSNOOP_TEST_IMAGE", raising=False)
    monkeypatch.setattr(integration_conftest.shutil, "which", lambda _name: "docker")
    monkeypatch.setattr(integration_conftest.subprocess, "run", _docker_info_timeout)

    with pytest.raises(pytest.skip.Exception, match="did not respond"):
        integration_conftest.docker_image.__wrapped__()


def test_docker_image_timeout_fails_for_remote_image(monkeypatch) -> None:
    monkeypatch.setenv(
        "BLOCKSNOOP_TEST_IMAGE", "registry.example/blocksnoop@sha256:test"
    )
    monkeypatch.setattr(integration_conftest.shutil, "which", lambda _name: "docker")
    monkeypatch.setattr(integration_conftest.subprocess, "run", _docker_info_timeout)

    with pytest.raises(pytest.fail.Exception, match="timed out"):
        integration_conftest.docker_image.__wrapped__()

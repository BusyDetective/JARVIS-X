"""Shared pytest fixtures.

TEST-DOUBLE vs REAL ISOLATION
  * `trust_test_backend` (opt-in) lets the UNSAFE host-side test double in
    tests/improvement_helpers.py count as a trusted backend, so validation LOGIC (counts,
    baselines, state machine...) can be exercised with real pytest runs. It proves nothing
    about isolation.
  * `container_backend` is a REAL container backend and is only available when a working
    docker/podman runtime and the validation image exist; otherwise tests using it are
    SKIPPED (never silently passed). Those tests are the real isolation integration tests.
"""
from __future__ import annotations

import asyncio
import os

import pytest

import app.sandbox.models as sandbox_models


@pytest.fixture
def trust_test_backend(monkeypatch):
    monkeypatch.setattr(sandbox_models, "TRUSTED_BACKENDS", sandbox_models.TRUSTED_BACKENDS | {"test-double"})


_REAL: dict = {}


def _probe_real_backend():
    from app.sandbox.container import ContainerBackend
    from app.sandbox.errors import IsolationUnavailableError
    from app.sandbox.policy import SandboxPolicy

    if "result" in _REAL:
        return _REAL["result"]
    image = os.environ.get("JARVIS_TEST_CONTAINER_IMAGE", "jarvisx-validation:1")
    try:
        backend = ContainerBackend(SandboxPolicy(timeout_seconds=120, memory_limit_mb=1024), cli=os.environ.get("JARVIS_TEST_CONTAINER_CLI", "auto"),
                                   image=image, oci_runtime=os.environ.get("JARVIS_TEST_OCI_RUNTIME") or None)
        asyncio.run(backend.preflight())
        _REAL["result"] = (backend, None)
    except IsolationUnavailableError as exc:
        _REAL["result"] = (None, f"no usable container isolation here: {exc.reason.value} ({exc})")
    return _REAL["result"]


@pytest.fixture
def container_backend():
    backend, reason = _probe_real_backend()
    if backend is None:
        pytest.skip(reason)
    return backend

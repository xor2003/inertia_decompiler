"""Deferred static intake must retain freshness and closed admission guards."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import angr_platforms.X86_16.ir.entry_domain_call_preservation as consumer
import test_x86_16_mz_static_invocation as fixtures

import inertia_decompiler.mz_static_intake as intake


def _refusal():
    return intake.MzStaticIntakeInstall8616(
        status=intake.MzStaticIntakeStatus8616.SOURCE_REFUSED,
        inventory=None, entry_linear=0, boot_sha256="", refusal_addr=None,
    )


def test_retained_source_change_retries_refusal(monkeypatch):
    request = intake.MzStaticIntakeRequest8616(source=b"first")
    project = SimpleNamespace()
    calls = []
    monkeypatch.setattr(intake, "_request_freshness_key_8616", lambda _project: (0, 0, "same-image"))

    def install(_project, source, *, declared_boot=None, declared_boot_recompute=None, declared_services=()):
        assert declared_boot is None
        assert declared_boot_recompute is None
        assert declared_services == ()
        calls.append(source)
        return _refusal()

    monkeypatch.setattr(intake, "install_mz_static_invocation_source_8616", install)
    request.install(project)
    request.source = b"changed"
    request.install(project)
    assert calls == [b"first", b"changed"]


def test_reentrant_source_query_does_not_restart_intake(monkeypatch):
    request = intake.MzStaticIntakeRequest8616(source=b"retained")
    project = SimpleNamespace(_inertia_mz_static_invocation_request_8616=request)
    calls = []
    monkeypatch.setattr(intake, "_request_freshness_key_8616", lambda _project: None)

    def install(_project, _source, *, declared_boot=None, declared_boot_recompute=None, declared_services=()):
        assert declared_boot is None
        assert declared_boot_recompute is None
        assert declared_services == ()
        calls.append(1)
        assert len(calls) == 1, "recursive query restarted the same in-progress intake"
        assert consumer._real16_invocation_source_8616(project) is None
        return _refusal()

    monkeypatch.setattr(intake, "install_mz_static_invocation_source_8616", install)
    assert consumer._real16_invocation_source_8616(project) is None
    assert calls == [1]


def test_incomplete_inventory_ledger_never_installs(monkeypatch, tmp_path: Path):
    base = fixtures.BASE
    root = base + 0x60
    image = fixtures._build_image(((root, b"\xc3"),))
    source = fixtures._build_mz(image, entry_ip=root - base)
    project = fixtures._make_project(source, tmp_path, root)
    build = intake.build_invocation_inventory_8616

    def corrupt(*args, **kwargs):
        inventory = build(*args, **kwargs)
        assert inventory.ready
        return replace(inventory, stats=replace(inventory.stats, failure_count=1))

    monkeypatch.setattr(intake, "build_invocation_inventory_8616", corrupt)
    assert fixtures._source(project) is None


def test_unexpected_exception_does_not_leave_request_in_progress(monkeypatch):
    request = intake.MzStaticIntakeRequest8616(source=b"retained")
    project = SimpleNamespace()
    calls = []
    monkeypatch.setattr(intake, "_request_freshness_key_8616", lambda _project: None)

    def install(_project, _source, *, declared_boot=None, declared_boot_recompute=None, declared_services=()):
        assert declared_boot is None
        assert declared_boot_recompute is None
        assert declared_services == ()
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("unexpected inventory defect")
        return _refusal()

    import pytest
    monkeypatch.setattr(intake, "install_mz_static_invocation_source_8616", install)
    with pytest.raises(ValueError, match="unexpected inventory defect"):
        request.install(project)
    assert request.install(project).status is intake.MzStaticIntakeStatus8616.SOURCE_REFUSED
    assert calls == [1, 1]


def test_malformed_owned_request_fails_loudly():
    """The dynamic project slot does not excuse an invalid owned request."""
    import pytest
    for request in (object(), SimpleNamespace(install=None)):
        project = SimpleNamespace(_inertia_mz_static_invocation_request_8616=request)
        with pytest.raises((AttributeError, TypeError)):
            consumer._real16_invocation_source_8616(project)

"""One function worker shares bounded raw imports, never authenticated proofs."""
from types import SimpleNamespace

import pytest

from inertia.cli import cli_decompilation as cli
from inertia.ir import native_import_surface_cache as cache
from inertia.ir import vex_import
from tests.ir.test_near_call_preservation import _surface

pytestmark = pytest.mark.decompiler


@pytest.fixture
def native_request(monkeypatch):
    surface = _surface()
    lift = vex_import._lift_x86_16_function_surface_8616
    calls = []

    def tracked(*args, **kwargs):
        calls.append(args[1].addr)
        return lift(*args, **kwargs)

    monkeypatch.setattr(vex_import, "_lift_x86_16_function_surface_8616", tracked)

    def consume():
        with cache.native_import_request_8616():
            return vex_import.raw_x86_16_import_bundle_for_artifact_8616(
                surface.project, surface.boundary, surface.artifact,
            )

    def invoke():
        return cli._decompile_function(
            surface.project, None, SimpleNamespace(addr=surface.artifact.function_addr), 30, "dos",
        )

    return surface, calls, consume, invoke


def test_function_request_shares_real_imports_and_releases_between_functions(native_request, monkeypatch):
    """Successive nested consumers share raw work only within this function."""
    surface, calls, consume, invoke = native_request

    def run(self):
        assert consume().artifact is surface.artifact
        assert consume().artifact is surface.artifact
        return "ok", "result"

    monkeypatch.setattr(cli._DecompileRun8616, "run_8616", run)
    assert invoke() == ("ok", "result")
    assert len(calls) == 1
    assert cache._ACTIVE.get() is None
    assert invoke() == ("ok", "result")
    assert len(calls) == 2
    assert cache._ACTIVE.get() is None


def test_function_request_rechecks_native_mutation(native_request, monkeypatch):
    """Raw reuse cannot conceal changed instruction bytes between consumers."""
    surface, calls, consume, invoke = native_request

    def run(self):
        assert consume() is not None
        surface.project.loader.memory.store(surface.call.addr, b"\x90")
        assert consume() is None
        return "refused", "changed bytes"

    monkeypatch.setattr(cli._DecompileRun8616, "run_8616", run)
    assert invoke()[0] == "refused"
    assert len(calls) >= 1
    assert cache._ACTIVE.get() is None


@pytest.mark.parametrize("error", [RuntimeError, cli._AnalysisTimeout])
def test_function_request_releases_after_error_or_timeout(native_request, monkeypatch, error):
    """Exceptional function termination cannot leak records to the next run."""
    surface, calls, consume, invoke = native_request

    def run(self):
        assert consume().artifact is surface.artifact
        assert consume().artifact is surface.artifact
        raise error("interrupted")

    monkeypatch.setattr(cli._DecompileRun8616, "run_8616", run)
    with pytest.raises(error):
        invoke()
    assert len(calls) == 1
    assert cache._ACTIVE.get() is None
    assert consume() is not None
    assert len(calls) == 2

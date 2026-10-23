"""Keep both mutation boundaries while reusing one operation's frozen graph."""

import pytest

from inertia.ir import ir_boundary_cfg as owner
from inertia.ir import native_import_surface_cache as cache
from inertia.ir import source_graph_binding as graph
from inertia.ir import vex_import
from tests.ir.test_native_fact_rebind import _jump_world

pytestmark = pytest.mark.decompiler


def test_scoped_native_rebind_encodes_before_and_after_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Warm native facts require two caller traversals, including the final seal."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        artifact = vex_import.raw_x86_16_function_bundle_8616(project, boundary).artifact
        assert owner._scoped_native_failure_8616(project, boundary, artifact) is None
        encoded = []
        original = graph._record_key_8616

        def record_key(record: dict, field_orders: dict | None = None) -> tuple:
            encoded.append(record)
            return original(record, field_orders)

        monkeypatch.setattr(graph, "_record_key_8616", record_key)
        graph.capture_immutable_source_graph_facts_8616(
            artifact.function_addr, artifact.blocks, artifact.refusals,
        )
        one_walk = list(encoded)
        assert one_walk
        encoded.clear()
        assert owner._scoped_native_failure_8616(project, boundary, artifact) is None
        assert encoded == one_walk + one_walk


@pytest.mark.parametrize("mutation", ("caller", "native", "boundary"))
def test_scoped_native_rebind_rejects_callback_mutation(
    mutation: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retained pre-callback facts never excuse a changed source or current IR."""
    project, boundary = _jump_world()
    original = vex_import._detached_terminal_evidence_8616
    calls = []
    with cache.native_import_request_8616():
        artifact = vex_import.raw_x86_16_function_bundle_8616(project, boundary).artifact
        assert owner._scoped_native_failure_8616(project, boundary, artifact) is None

        def mutate(surface: object) -> object:
            evidence = original(surface)
            calls.append(1)
            if mutation == "caller":
                object.__setattr__(artifact.blocks[0].instrs[0], "op", "INVALID")
            elif mutation == "native":
                project.loader.memory.store(boundary.addr, b"\x90")
            else:
                boundary.info["changed_by_callback"] = True
            return evidence

        monkeypatch.setattr(vex_import, "_detached_terminal_evidence_8616", mutate)
        assert owner._scoped_native_failure_8616(project, boundary, artifact) is not None
        assert calls

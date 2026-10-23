"""Verify IR attachment uses the function retained by native code generation."""

from types import SimpleNamespace

import pytest

from inertia.alias.indexed_address_projection import apply_x86_16_indexed_address_aliases_8616
from inertia.cli.cli_function_discovery import _pick_function
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from inertia.ir.indexed_address_pipeline import apply_x86_16_indexed_address_evidence_8616
from inertia.ir.vex_import import apply_x86_16_vex_ir_artifact
from inertia.lowering.indexed_address_collector_parity import collect_indexed_address_collector_parity_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.call_stack_effect_pipeline import apply_x86_16_call_stack_effects_8616
from tests.cli.test_x86_16_cod_samples import _project_from_bytes

pytestmark = pytest.mark.decompiler


def _recovered_function():
    apply_x86_16_bootstrap()
    project = _project_from_bytes(b"\xb8\x02\x00\xc3")
    cfg, function = _pick_function(
        project, 0x1000, regions=[(0x1000, 0x1004)],
        force_smart_scan=False, seed_calling_conventions_enabled=False,
    )
    assert cfg.kb is not project.kb
    assert function.addr not in project.kb.functions
    return project, cfg, function


def test_ir_attachment_uses_retained_function_without_default_kb_mutation():
    project, cfg, function = _recovered_function()
    original_kb = project.kb
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr), _func=function)

    assert apply_x86_16_vex_ir_artifact(project, codegen) is False

    assert codegen._inertia_vex_ir_source_function_8616 is function
    assert codegen._inertia_vex_ir_function_ssa.function_addr == function.addr
    assert codegen._inertia_vex_ir_function_ssa.blocks
    assert cfg.functions[function.addr] is function
    assert project.kb is original_kb
    assert function.addr not in original_kb.functions


def test_terminal_return_type_uses_retained_function_without_default_kb_mutation():
    """AX evidence must come from the same native function used by codegen."""
    from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort

    from inertia.lowering.terminal_register_return_types import materialize_terminal_register_return_type_8616

    project, cfg, function = _recovered_function()
    prototype = SimTypeFunction([], SimTypeChar()).with_arch(project.arch)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=function.addr, functy=prototype, statements=None),
        _func=function,
    )

    result = materialize_terminal_register_return_type_8616(project, codegen)

    assert result.changed
    assert result.stats.materialized_count == 1
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeShort)
    assert codegen.cfunc.functy.returnty.size == 16
    assert cfg.functions[function.addr] is function
    assert function.addr not in project.kb.functions


def test_ir_attachment_refuses_foreign_function_owner():
    _project, _cfg, function = _recovered_function()
    other_project = _project_from_bytes(b"\xb8\x03\x00\xc3")
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr), _func=function)

    with pytest.raises(PipelineHardError, match="different project"):
        apply_x86_16_vex_ir_artifact(other_project, codegen)


def test_ir_attachment_refuses_retained_function_address_mismatch():
    project, _cfg, function = _recovered_function()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr + 1), _func=function)

    with pytest.raises(PipelineHardError, match="address"):
        apply_x86_16_vex_ir_artifact(project, codegen)


def test_semantic_projection_uses_same_retained_function_as_ir():
    project, _cfg, function = _recovered_function()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr), _func=function)
    apply_x86_16_vex_ir_artifact(project, codegen)

    assert apply_x86_16_call_stack_effects_8616(project, codegen) is False

    assert codegen._inertia_vex_ir_function_ssa_stage_8616 is FunctionSSAArtifactStage8616.SEMANTIC
    assert codegen._inertia_call_semantic_projection_8616.complete
    assert "x86_16_call_stack_effects" in function.info
    assert function.addr not in project.kb.functions


def test_parity_census_consumes_same_retained_function_as_ir():
    project, _cfg, function = _recovered_function()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr), _func=function)
    apply_x86_16_vex_ir_artifact(project, codegen)
    apply_x86_16_indexed_address_evidence_8616(project, codegen)
    apply_x86_16_indexed_address_aliases_8616(project, codegen)

    census = collect_indexed_address_collector_parity_8616(project, codegen)

    assert census is not None
    assert census.closed and census.exact
    assert codegen._inertia_indexed_address_collector_parity_8616 is census
    assert function.addr not in project.kb.functions


def test_native_import_retains_analysis_owner_before_decode(monkeypatch: pytest.MonkeyPatch) -> None:
    """GC during decoding must not revoke the supplied function's actual KB."""
    import gc
    import weakref

    import angr
    from angr.codenode import BlockNode

    from inertia.ir.vex_import import build_x86_16_ir_function_artifact

    apply_x86_16_bootstrap()
    project = _project_from_bytes(bytes.fromhex("c3"))
    knowledge = angr.KnowledgeBase(project)
    function = knowledge.functions.function(addr=0x1000, create=True)
    function._register_node(True, BlockNode(0x1000, 1))
    assert function.project is project
    manager_ref = weakref.ref(knowledge.functions)
    holders = [knowledge]
    del knowledge
    original_block = project.factory.block
    decode_checks: list[bool] = []

    def release_analysis_during_decode(*args: object, **kwargs: object) -> object:
        """Release the temporary owner exactly at the external decode boundary."""
        holders.clear()
        gc.collect()
        decode_checks.append(manager_ref() is not None)
        return original_block(*args, **kwargs)

    monkeypatch.setattr(project.factory, "block", release_analysis_during_decode)
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert decode_checks and all(decode_checks)
    assert manager_ref() is not None
    assert artifact.blocks and artifact.source_revision is not None
    assert project.kb.functions.function(addr=0x1000, create=False) is None

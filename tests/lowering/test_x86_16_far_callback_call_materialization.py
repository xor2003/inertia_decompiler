"""Binary-backed far callback call materialization and refusal controls."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CConstant,
    CFunctionCall,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable
from inertia.semantics.callsite_summary import summarize_x86_16_callsite
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.lowering.callsite_prototype_seeding import (
    materialize_physical_callsite_prototype_8616,
)
from inertia.lowering.far_callback_call_materialization import (
    FarCallbackCallMaterializationDecision8616,
    materialize_binary_far_callback_calls_8616,
)
from inertia.lowering.far_pointer_type import far_pointer_type_8616
import inertia.structuring.call_argument_path_conditions as path_conditions

from inertia.frontend.x86_16.mz_image import UnpackedMZImage
from inertia.cli.project_loading import _build_project

_CALLER_CODE = bytes.fromhex(
    "55 8b ec 83 ec 04 83 f8 00 74 0c "
    "c7 46 fc 00 00 c7 46 fe 00 10 eb 0c "
    "c7 46 fc 1a 00 c7 46 fe 00 10 eb 00 "
    "ff 76 08 ff 76 fe ff 76 fc "
    "9a 34 00 00 10 83 c4 06 8b e5 5d cb"
)


def _surface(
    tmp_path: Path,
    *,
    bad_target: bool = False,
    guessed_prototype: bool = True,
    seeded_prototype: bool = False,
) -> tuple[object, SimpleNamespace, CFunctionCall, object]:
    """Build one sidecar-free DOS image and a three-scalar caller C AST."""
    image = bytearray(0x120)
    image[0:5] = bytes.fromhex("55 8b ec 5d cb")
    image[0x1A:0x1F] = bytes.fromhex("55 8b ec 5d c3" if bad_target else "55 8b ec 5d cb")
    image[0x34:0x43] = bytes.fromhex("55 8b ec ff 76 0a ff 5e 06 83 c4 02 5d cb 90")
    image[0x6B:0x6B + len(_CALLER_CODE)] = _CALLER_CODE
    path = tmp_path / "CALLBACK.EXE"
    path.write_bytes(UnpackedMZImage(
        image=bytes(image), relocations=(), entry_cs=0, entry_ip=0x6B,
        stack_ss=0, stack_sp=0xFFFE,
    ).to_mz_bytes())
    project = _build_project(path, force_blob=False, base_addr=0x1000, entry_point=0)
    edges = (
        (0x1006B, 0x10076), (0x1006B, 0x10082),
        (0x10076, 0x1008E), (0x10082, 0x1008E),
    )
    function = SimpleNamespace(
        addr=0x1006B,
        block_addrs_set={addr for edge in edges for addr in edge},
        graph=SimpleNamespace(edges=edges), info={},
    )
    source = build_x86_16_ir_function_artifact(project, function)
    assert not source.refusals
    ssa = build_x86_16_function_ssa(source)
    summary = summarize_x86_16_callsite(
        SimpleNamespace(project=project, addr=0x1006B, blocks=()), 0x10097,
    )
    assert summary is not None
    assert summary.arg_widths == (2, 2, 2)
    callee = SimpleNamespace(
        addr=0x10034, name="sub_10034", is_prototype_guessed=guessed_prototype,
        calling_convention=None, info={},
        prototype=None if seeded_prototype else SimTypeFunction(
            [SimTypeShort(False), SimTypeShort(False), SimTypeShort(False)],
            SimTypeShort(False), variadic=False,
        ).with_arch(project.arch),
    )
    if seeded_prototype:
        materialize_physical_callsite_prototype_8616(project, callee, summary)
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
        _inertia_raw_vex_ir_function_ssa_8616=ssa,
        _inertia_callsite_summary_inventory_8616={summary.callsite_addr: summary},
        _inertia_callsite_prototype_decls=(),
        _inertia_typed_conditions=(ConditionIR(
            op="eq", lhs=object(), rhs=object(), src_insn=0x10074,
            block_addr=0x1006B, taken_target=0x10076, fallthrough_target=0x10082,
        ),),
    )
    scalar = CVariable("arg_8", variable_type=SimTypeShort(False), codegen=codegen)
    call = CFunctionCall(
        "sub_10034", callee,
        [CVariable("local_4", variable_type=SimTypeShort(False), codegen=codegen),
         CVariable("local_2", variable_type=SimTypeShort(False), codegen=codegen),
         scalar],
        tags={"ins_addr": 0x10097}, codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1006B,
        statements=CStatements([CReturn(call, codegen=codegen)], codegen=codegen),
    )
    codegen._inertia_callsite_summaries = {id(call): summary}
    return project, codegen, call, scalar


def _typed_condition_boundaries(monkeypatch: pytest.MonkeyPatch, codegen: object) -> None:
    """Supply the exact two-predecessor CFG and a typed predicate consumer."""
    monkeypatch.setattr(path_conditions, "condition_chain_successors_8616", lambda _p, _c: {
        0x1006B: (0x10076, 0x10082),
        0x10076: (0x1008E,),
        0x10082: (0x1008E,),
        0x1008E: (),
    })
    monkeypatch.setattr(
        path_conditions, "materialize_condition_ir_expression_8616",
        lambda _p, _c, _condition: CVariable(
            SimMemoryVariable(0xDEAD, 2, name="selector", region=codegen.cfunc.addr),
            variable_type=SimTypeShort(False), codegen=codegen,
        ),
    )


def test_far_callback_call_is_atomically_grouped_and_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two proven far code values become one typed conditional C argument."""
    project, codegen, call, scalar = _surface(tmp_path)
    _typed_condition_boundaries(monkeypatch, codegen)

    result = materialize_binary_far_callback_calls_8616(project, codegen)

    assert result.closed and result.changed
    assert result.decisions == (FarCallbackCallMaterializationDecision8616.MATERIALIZED,)
    assert len(call.args) == 2 and call.args[1] is scalar
    callback = call.args[0]
    assert isinstance(callback, CITE)
    assert isinstance(callback.iftrue, CVariable)
    assert isinstance(callback.iffalse, CVariable)
    assert {callback.iftrue.variable.name, callback.iffalse.variable.name} == {
        "sub_10000", "sub_1001a",
    }
    assert callback.type.size == 32
    assert len(call.callee_func.prototype.args) == 2
    assert call.callee_func.prototype.args[0].size == 32
    assert codegen._inertia_callsite_summaries[id(call)].logical_arg_widths == (4, 2)
    assert codegen._inertia_callsite_summary_inventory_8616[0x10097].logical_arg_widths == (4, 2)
    assert any("sub_10000" in decl for decl in codegen._inertia_callsite_prototype_decls)
    assert "unsigned short sub_1001a(unsigned short);" in codegen._inertia_callsite_prototype_decls
    assert codegen.cfunc._inertia_callsite_prototype_decls == codegen._inertia_callsite_prototype_decls
    assert (result.raw_fact_count, result.normalized_fact_count,
            result.classified_fact_count, result.materialized_count,
            result.failure_count) == (1, 1, 1, 1, 0)


def test_far_callback_call_refuses_bad_target_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A near-return code entry cannot silently publish a far C callback."""
    project, codegen, call, _scalar = _surface(tmp_path, bad_target=True)
    _typed_condition_boundaries(monkeypatch, codegen)
    original_args = tuple(call.args)
    original_proto = call.callee_func.prototype

    result = materialize_binary_far_callback_calls_8616(project, codegen)

    assert result.closed and not result.changed
    assert result.decisions == (FarCallbackCallMaterializationDecision8616.TARGET_NOT_PROVEN,)
    assert tuple(call.args) == original_args
    assert call.callee_func.prototype is original_proto
    assert codegen._inertia_callsite_summaries[id(call)].logical_arg_widths == ()
    assert result.failure_count == 1


def test_far_callback_call_replaces_only_owned_physical_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-guessed three-word seed is replaceable only with typed provenance."""
    project, codegen, call, _scalar = _surface(tmp_path, seeded_prototype=True)
    _typed_condition_boundaries(monkeypatch, codegen)
    assert not call.callee_func.is_prototype_guessed

    result = materialize_binary_far_callback_calls_8616(project, codegen)

    assert result.closed and result.changed
    assert len(call.args) == 2
    assert tuple(argument.size for argument in call.callee_func.prototype.args) == (32, 16)


def test_far_callback_call_refines_physical_projection_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later argument replay cannot reinstate the packed scalar callback."""
    project, codegen, call, scalar = _surface(tmp_path, seeded_prototype=True)
    _typed_condition_boundaries(monkeypatch, codegen)
    summary = codegen._inertia_callsite_summaries[id(call)]
    physical = replace(summary, logical_arg_widths=summary.arg_widths)
    codegen._inertia_callsite_summaries[id(call)] = physical
    codegen._inertia_callsite_summary_inventory_8616[summary.callsite_addr] = physical

    first = materialize_binary_far_callback_calls_8616(project, codegen)
    call.args = [CConstant(0x10000000, SimTypeLong(False), codegen=codegen), scalar]
    replay = materialize_binary_far_callback_calls_8616(project, codegen)
    stable = materialize_binary_far_callback_calls_8616(project, codegen)

    assert first.changed and first.closed
    assert replay.changed and replay.closed
    assert isinstance(call.args[0], CITE)
    assert stable.closed and not stable.changed
    assert stable.decisions == (FarCallbackCallMaterializationDecision8616.ALREADY_MATERIALIZED,)


def test_far_callback_call_refuses_unowned_prototype_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exact binary proof must not overwrite a conflicting non-guessed type."""
    project, codegen, call, _scalar = _surface(tmp_path, guessed_prototype=False)
    _typed_condition_boundaries(monkeypatch, codegen)
    original_args = tuple(call.args)
    original_proto = call.callee_func.prototype

    result = materialize_binary_far_callback_calls_8616(project, codegen)

    assert result.closed and not result.changed
    assert result.decisions == (FarCallbackCallMaterializationDecision8616.PROTOTYPE_CONFLICT,)
    assert tuple(call.args) == original_args
    assert call.callee_func.prototype is original_proto
    assert result.failure_count == 1


def test_far_callback_call_refuses_wrong_pointee_abi_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A prior far-pointer width alone cannot authorize the wrong callback ABI."""
    project, codegen, call, _scalar = _surface(tmp_path, guessed_prototype=False)
    _typed_condition_boundaries(monkeypatch, codegen)
    wrong_pointee = SimTypeFunction(
        [SimTypeLong(False)], SimTypeShort(False), variadic=False,
    ).with_arch(project.arch)
    wrong_pointer = far_pointer_type_8616(wrong_pointee, project.arch)
    call.callee_func.prototype = SimTypeFunction(
        [wrong_pointer, SimTypeShort(False)], SimTypeShort(False), variadic=False,
    ).with_arch(project.arch)
    original_args = tuple(call.args)
    original_proto = call.callee_func.prototype

    result = materialize_binary_far_callback_calls_8616(project, codegen)

    assert result.closed and not result.changed
    assert result.decisions == (FarCallbackCallMaterializationDecision8616.PROTOTYPE_CONFLICT,)
    assert tuple(call.args) == original_args
    assert call.callee_func.prototype is original_proto

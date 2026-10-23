"""Scoped call-stack input authority through materialization and validation.

Declared-world controls: AX=0 nets 0, AX=4 nets -4. Every control binds the
real carrier/context/domains from the native fixture — never a fabricated
scope or a guessed scalar.

Wrapper-protocol scope: these are native-proof positives driving a
handwritten-C wrapper protocol fixture. The AX4 callee loops on a selector
path in the native CFG while the generated C runs sequentially, so these
tests control the emitted wrapper protocol — ordered temporaries, SP word
writes, binding markers — not native execution equivalence or
whole-function acceptance.
"""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import replace
from itertools import count
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import angr
import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.knowledge_plugins.functions.function import Function
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeShort

from inertia.alias.scoped_call_stack_context import (
    ScopedCallEntryBinding8616,
    ScopedCallStackContext8616,
    prove_scoped_call_stack_context_8616,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.ir.function_artifact import IRFunctionArtifact
from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.ir.scoped_call_stack_coordinates import IRScopedCallStackCoordinates8616
from inertia.lowering.call_stack_input_contracts import (
    CALL_STACK_INPUT_BINDING_TAG_8616,
)
from inertia.lowering.call_stack_input_replay import (
    run_call_stack_input_aware_lowering_8616,
)
from inertia.lowering.call_stack_inputs import lower_call_stack_inputs_8616
from inertia.lowering.entry_stack_pointer_capture import (
    EntryStackPointerCaptureFailure8616,
    ScopedCallPositionAuthority8616,
    observe_entry_stack_pointer_capture_8616,
    prepare_entry_stack_pointer_capture_8616,
)
from inertia.pipeline.call_stack_input_outcome import (
    CallStackInputFailure8616,
    CallStackInputStatus8616,
)
from inertia.pipeline.errors import PipelineHardError
from inertia.pipeline.structured_ast_output import (
    observe_structured_ast_output_8616,
)
from inertia.semantics.call_return_segment import ReturnSegmentFrame8616
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.scoped_call_stack_coordinates import (
    prove_scoped_call_stack_coordinates_8616,
)
from inertia.validation.validation_call_stack_inputs import (
    CallStackInputValidation8616,
    ScopedCallStackInputValidation8616,
    validate_call_stack_inputs_8616,
    validate_scoped_call_stack_inputs_8616,
)
from tests.pipeline.test_structured_ast_output import _actual_ast
from tests.support.scoped_stack_fixture import (
    CALL2_RET_1,
    CALL2_RET_2,
    CALL2_SITE_1,
    CALL2_SITE_2,
    CALLEE,
    CALLEE_LOOP,
    CALLER,
    CALLSITE,
    RETURN_ADDR,
    build_scoped_stack_parts_8616,
    scoped_callee_domain_for_callsite_8616,
)

pytestmark = pytest.mark.decompiler

_RETURN_ADDRS = {CALLSITE: RETURN_ADDR, CALL2_SITE_1: CALL2_RET_1,
                 CALL2_SITE_2: CALL2_RET_2}

# ``_world``/``_lowered_world`` hand the full declared environment to each
# control: fixture parts, caller artifact, the angr-facing codegen namespace,
# the bound C calls, the authenticated context and the per-callsite domains.
type _ScopedWorld = tuple[
    dict[str, object], IRFunctionArtifact, SimpleNamespace, list[Any],
    ScopedCallStackContext8616, dict[int, tuple[object, object, object]],
]


def _carrier_for(
    parts: dict[str, object], artifact: IRFunctionArtifact,
    callsite: int, caller_scope: object, callee_scope: object,
    coverage: object,
) -> IRScopedCallStackCoordinates8616:
    """Build the scoped carrier bound to one exact callsite row."""
    call_instr = call_block = None
    for block in artifact.blocks:
        for instr in block.instrs:
            if instr.op == "CALL" and instr.addr == callsite:
                call_instr, call_block = instr, block
    assert call_instr is not None
    summary = CallsiteSummary8616(
        callsite_addr=callsite, target_addr=CALLEE,
        return_addr=_RETURN_ADDRS[callsite],
        kind="near", arg_count=0, arg_widths=(), stack_cleanup=None,
        return_register=None, return_used=None,
    )
    carrier = prove_scoped_call_stack_coordinates_8616(
        cast(angr.Project, parts["project"]), summary,
        instruction=call_instr, block=call_block,
        return_frame=ReturnSegmentFrame8616(callsite_addr=callsite),
        caller_scope=cast(Real16InvocationDomain8616, caller_scope),
        callee_scope=cast(Real16InvocationDomain8616, callee_scope),
        coverage=cast(IRBoundaryCoverageResult8616, coverage),
    )
    assert carrier.failure is None
    return carrier


def _domains(
    parts: dict[str, object], two_calls: bool,
) -> dict[int, tuple[object, object, object]]:
    """Pair each callsite with its own authenticated caller/callee domains."""
    if not two_calls:
        return {CALLSITE: (parts["caller_domain"], parts["callee_domain"],
                           parts["coverage"])}
    second = scoped_callee_domain_for_callsite_8616(parts, CALL2_SITE_2)
    return {
        CALL2_SITE_1: (parts["caller_domain"], parts["callee_domain"],
                       parts["coverage"]),
        CALL2_SITE_2: second,
    }


def _world(ax_seed: int, *, two_calls: bool = False) -> _ScopedWorld:
    """Declared world with context, codegen and bound C calls."""
    parts = build_scoped_stack_parts_8616(ax_seed, CALLEE_LOOP, two_calls=two_calls)
    artifact = parts["caller_artifact"]
    assert isinstance(artifact, IRFunctionArtifact)
    domains = _domains(parts, two_calls)
    bindings = tuple(
        ScopedCallEntryBinding8616(
            _carrier_for(parts, artifact, site, *triple),
            cast(Real16InvocationDomain8616, triple[0]),
            cast(Real16InvocationDomain8616, triple[1]),
        )
        for site, triple in domains.items()
    )
    context = prove_scoped_call_stack_context_8616(bindings)
    assert context is not None
    project = cast(angr.Project, parts["project"])
    counter = count()
    codegen = SimpleNamespace(
        project=project, next_node_idx=lambda: next(counter),
        next_ident=lambda name: name, display_vvar_ids=False,
        cstyle_null_cmp=False, stmt_comments={}, expr_comments={},
        display_block_addrs=False, use_compound_assignments=False,
        prettify_thiscall=False, show_casts=True, const_formats={},
        max_str_len=2048, kb=project.kb, _func=None,
        default_simtype_from_bits=lambda bits, signed=False: None,
    )
    root = c.CStatements([], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=CALLER, statements=root, variables_in_use={},
        variable_manager=project.kb.variables[CALLER], refresh=lambda: None)
    codegen._variables_in_use = codegen.cfunc.variables_in_use
    codegen._inertia_vex_ir_artifact = artifact
    calls: list[Any] = []
    for site in domains:
        target = Function(project.kb.functions, CALLEE, name="callee")
        target.prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(
            project.arch)
        calls.append(c.CFunctionCall(
            "callee", target, [], tags={"ins_addr": site}, codegen=codegen))
    if len(calls) == 1:
        root.statements = [c.CReturn(c.CBinaryOp(
            "Add", calls[0], c.CConstant(1, SimTypeInt(False), codegen=codegen),
            codegen=codegen), codegen=codegen)]
    else:
        root.statements = [
            c.CExpressionStatement(calls[0], codegen=codegen),
            c.CReturn(c.CBinaryOp(
                "Add", calls[1],
                c.CConstant(1, SimTypeInt(False), codegen=codegen),
                codegen=codegen), codegen=codegen)]
    return parts, artifact, codegen, calls, context, domains


def _wrappers(codegen: SimpleNamespace) -> list[Any]:
    """Collect every materialized binding wrapper in the actual tree."""
    from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
    return [
        node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements)
        if isinstance(node, c.CMultiStatementExpression)
        and CALL_STACK_INPUT_BINDING_TAG_8616 in node.tags
    ]


def _compile_and_run(codegen: SimpleNamespace, path: Path, entry: int) -> tuple[int, ...]:
    """Compile the generated caller against an SP-observing callee."""
    declarations = '\n'.join(
        f'{value.type.c_repr()} {value.c_repr()};'
        for value in codegen.cfunc.variables_in_use.values())
    text = f'''#include <stdint.h>
#include <stdio.h>
uint32_t inertia_esp={entry};
unsigned calls=0;
unsigned short callee(void) {{ ++calls; return inertia_esp & 0xffff; }}
unsigned short caller(void) {{ {declarations}
{codegen.cfunc.statements.c_repr()}
}}
int main(void) {{ unsigned value=caller();
printf("%u %u %u %u\\n",value,calls,inertia_esp & 0xffff,inertia_esp >> 16); }}
'''
    path.write_text(text)
    compiler = shutil.which('gcc')
    assert compiler is not None
    compiled = subprocess.run(
        [compiler, '-std=c11', str(path), '-o', str(path.with_suffix(''))],
        capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr + text
    executed = subprocess.run(
        [str(path.with_suffix(''))], capture_output=True, text=True, check=True)
    return tuple(map(int, executed.stdout.split()))


def test_scoped_ax0_materializes_validates_and_executes(tmp_path: Path) -> None:
    """AX=0: net-zero caller delta lowers, validates and executes faithfully."""
    parts, _art, codegen, _calls, context, _d = _world(0)
    entry = 0x12348000
    result = lower_call_stack_inputs_8616(
        codegen, scoped_context=context,
        scoped_caller_scope=cast(Real16InvocationDomain8616,
                                 parts["caller_domain"]))
    assert result is not None and result.status is CallStackInputStatus8616.MATERIALIZED
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=cast(Real16InvocationDomain8616,
                                 parts["caller_domain"]))
    assert verdict.complete and not verdict.issue_tokens()
    assert _compile_and_run(codegen, tmp_path / 'ax0.c', entry) == (
        (entry - 1) & 0xffff, 1, entry & 0xffff, entry >> 16)


def test_scoped_ax4_net_minus_four(tmp_path: Path) -> None:
    """AX=4: the conditional -4 delta reaches the generated word writes."""
    parts, _art, codegen, _calls, context, _d = _world(4)
    entry = 0x8000
    result = lower_call_stack_inputs_8616(
        codegen, scoped_context=context,
        scoped_caller_scope=cast(Real16InvocationDomain8616,
                                 parts["caller_domain"]))
    assert result is not None and result.status is CallStackInputStatus8616.MATERIALIZED
    assert _compile_and_run(codegen, tmp_path / 'ax4.c', entry) == (
        (entry - 1) & 0xffff, 1, (entry - 4) & 0xffff, entry >> 16)


def test_missing_context_refuses_atomically() -> None:
    """Scoped evidence stays unavailable without its offered context."""
    parts, _art, codegen, calls, context, _d = _world(0)
    original = codegen.cfunc.statements
    kwarg_sets: tuple[dict[str, Any], ...] = (
        {}, {"scoped_context": context},
        {"scoped_caller_scope": parts["caller_domain"]})
    for kwargs in kwarg_sets:
        result = lower_call_stack_inputs_8616(codegen, **kwargs)
        assert result is not None
        assert result.failure is CallStackInputFailure8616.POSITION_UNPROVEN
        assert codegen.cfunc.statements is original and calls[0].args == []
        assert not codegen.cfunc.variables_in_use


def test_foreign_context_and_scope_refuse() -> None:
    """Another world's context or caller domain supplies no authority."""
    parts, _art, codegen, calls, context, _d = _world(0)
    parts_b, _art_b, _cg_b, _calls_b, context_b, _d_b = _world(0)
    original = codegen.cfunc.statements
    kwarg_sets: tuple[dict[str, Any], ...] = (
        {"scoped_context": context_b,
         "scoped_caller_scope": parts["caller_domain"]},
        {"scoped_context": context,
         "scoped_caller_scope": parts_b["caller_domain"]},
    )
    for kwargs in kwarg_sets:
        result = lower_call_stack_inputs_8616(codegen, **kwargs)
        assert result is not None and result.failure is not None
        assert codegen.cfunc.statements is original and calls[0].args == []


def test_byte_drift_revokes_materialized_authority() -> None:
    """Source mutation revokes validation and any further lowering."""
    parts, _art, codegen, _calls, context, _d = _world(0)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    lower_call_stack_inputs_8616(
        codegen, scoped_context=context, scoped_caller_scope=caller_scope)
    project = cast(angr.Project, parts["project"])
    project.loader.memory.store(0x1076, b"\x2b\xd9")
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert not verdict.complete and verdict.issue_tokens()
    result = lower_call_stack_inputs_8616(
        codegen, scoped_context=context, scoped_caller_scope=caller_scope)
    assert result is not None and result.failure is not None


def test_universal_validation_rejects_scoped_tree() -> None:
    """A scoped-only proof is never an unconditional validation success."""
    parts, _art, codegen, _calls, context, _d = _world(0)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    lower_call_stack_inputs_8616(
        codegen, scoped_context=context, scoped_caller_scope=caller_scope)
    universal = validate_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements)
    assert universal.issues and universal.materialized_count == 0
    scoped = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert scoped.complete
    assert isinstance(scoped, ScopedCallStackInputValidation8616)
    assert not isinstance(scoped, CallStackInputValidation8616)


def test_forged_authority_refuses() -> None:
    """A marker carrying another world's retained result cannot verify."""
    parts, _art, codegen, _calls, context, _d = _world(0)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    lower_call_stack_inputs_8616(
        codegen, scoped_context=context, scoped_caller_scope=caller_scope)
    parts_b, _art_b, _cg_b, _calls_b, _ctx_b, _d_b = _world(0)
    wrapper = _wrappers(codegen)[0]
    marker = wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616]
    from inertia.alias.scoped_call_stack_positions import (
        prove_scoped_call_stack_position_8616,
    )
    block_addr, index = next(
        (block.addr, i) for block in _art_b.blocks
        for i, ins in enumerate(block.instrs) if ins.op == "CALL")
    forged = prove_scoped_call_stack_position_8616(
        _art_b, block_addr, index,
        cast(Real16InvocationDomain8616, parts_b["caller_domain"]),
        cast(Real16InvocationDomain8616, parts_b["callee_domain"]),
        context=_ctx_b)
    assert forged.failure is None
    wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616] = replace(
        marker, authority=ScopedCallPositionAuthority8616(forged))
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert not verdict.complete


def test_two_calls_each_materialize_under_own_binding(tmp_path: Path) -> None:
    """Two callsites use their individually authenticated domains."""
    parts, _art, codegen, _calls, context, _d = _world(4, two_calls=True)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    result = lower_call_stack_inputs_8616(
        codegen, scoped_context=context, scoped_caller_scope=caller_scope)
    assert result is not None and result.status is CallStackInputStatus8616.MATERIALIZED
    assert len(_wrappers(codegen)) == 2
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert verdict.complete
    entry = 0x12340000
    value, call_count, low, high = _compile_and_run(
        codegen, tmp_path / 'two.c', entry)
    assert (value, call_count, low, high) == (
        (entry - 1) & 0xffff, 2, (entry - 4) & 0xffff, entry >> 16)


def test_scoped_replay_and_context_free_replay() -> None:
    """Scoped contexts reopen under authority; without it replay refuses."""
    parts, _art, codegen, _calls, context, _d = _world(0)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    lower_call_stack_inputs_8616(
        codegen, scoped_context=context, scoped_caller_scope=caller_scope)
    consumed = []

    def consume() -> bool:
        consumed.append(True)
        return False

    assert not run_call_stack_input_aware_lowering_8616(
        codegen, consume, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert consumed == [True]
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert verdict.complete
    try:
        run_call_stack_input_aware_lowering_8616(
            codegen, consume)
        raised = False
    except PipelineHardError:
        raised = True
    assert raised and consumed == [True]


def _lowered_world(ax_seed: int = 0, *, two_calls: bool = False) -> _ScopedWorld:
    """A ``_world`` plus applied scoped lowering and complete validation.

    Native-proof positives driving a wrapper-protocol control — the AX4
    callee loops in the native CFG while the generated C runs sequentially —
    so they control the emitted protocol contract, not native execution
    equivalence.
    """
    parts, artifact, codegen, calls, context, domains = _world(
        ax_seed, two_calls=two_calls)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    result = lower_call_stack_inputs_8616(
        codegen, scoped_context=context, scoped_caller_scope=caller_scope)
    assert result is not None
    assert result.status is CallStackInputStatus8616.MATERIALIZED
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert verdict.complete
    return parts, artifact, codegen, calls, context, domains


def _find_projection(node: object, key: str) -> Iterator[object]:
    """Yield every value stored under an exact key in decoded JSON."""
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key:
                yield value
            yield from _find_projection(value, key)
    elif isinstance(node, list):
        for item in node:
            yield from _find_projection(item, key)


def test_position_projection_cannot_diverge_from_retained_proof() -> None:
    """The scalar projection mirrors the retained proof and can never be set."""
    parts, artifact, codegen, _calls, context, _d = _lowered_world(4)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    root = codegen.cfunc.statements
    variables = dict(codegen.cfunc.variables_in_use)
    authority = _wrappers(codegen)[0].tags[
        CALL_STACK_INPUT_BINDING_TAG_8616].authority
    assert type(authority) is ScopedCallPositionAuthority8616
    assert authority.position is authority.result.proof
    assert authority.position is not None
    forged_result = replace(
        authority.result,
        proof=replace(
            authority.position,
            caller_after_offset=authority.position.caller_after_offset + 2))
    # The control deliberately writes through the read-only property
    # boundary; the dynamic Any surface keeps the attempted assignment so
    # the contract's AttributeError refusal stays the checked behavior.
    with pytest.raises(AttributeError):
        cast(Any, authority).position = forged_result.proof
    with pytest.raises(AttributeError):
        cast(Any, authority).result = forged_result
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, root, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert verdict.complete
    forged = ScopedCallPositionAuthority8616(forged_result)
    outcome = prepare_entry_stack_pointer_capture_8616(
        codegen, artifact, (forged,), scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert outcome is not None
    assert outcome.failure is EntryStackPointerCaptureFailure8616.SOURCE_CHANGED
    assert codegen.cfunc.statements is root
    assert dict(codegen.cfunc.variables_in_use) == variables


def test_validator_requires_offered_binding_set() -> None:
    """Every retained scoped use must bind under the OFFERED context."""
    parts, _art, codegen, calls, context, _d = _lowered_world(
        0, two_calls=True)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    root = codegen.cfunc.statements
    variables = dict(codegen.cfunc.variables_in_use)
    original_args = [tuple(call.args or []) for call in calls]
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, root, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert verdict.complete

    parts_b, _art_b, _cg_b, _calls_b, foreign_context, _d_b = _world(0)
    swapped = replace(context, bindings=(
        replace(context.bindings[0],
                callee_scope=cast(Real16InvocationDomain8616,
                                  parts_b["callee_domain"])),
        *context.bindings[1:]))
    for bad_context in (
            ScopedCallStackContext8616(),
            ScopedCallStackContext8616(context.bindings[:1]),
            foreign_context,
            swapped):
        verdict = validate_scoped_call_stack_inputs_8616(
            codegen, root, scoped_context=bad_context,
            scoped_caller_scope=caller_scope)
        assert not verdict.complete and verdict.issue_tokens()
        assert codegen.cfunc.statements is root
        assert [tuple(call.args or []) for call in calls] == original_args
        assert dict(codegen.cfunc.variables_in_use) == variables
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, root, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert verdict.complete


def test_capture_and_replay_require_offered_context() -> None:
    """Observation and replay authenticate the offered context itself."""
    parts, artifact, codegen, _calls, context, _d = _lowered_world(0)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    original = codegen.cfunc.statements
    assert observe_entry_stack_pointer_capture_8616(
        codegen, artifact, scoped_context=context,
        scoped_caller_scope=caller_scope) is not None
    for bad_context in (ScopedCallStackContext8616(), None):
        assert observe_entry_stack_pointer_capture_8616(
            codegen, artifact, scoped_context=bad_context,
            scoped_caller_scope=caller_scope) is None
    consumed = []

    def consume() -> bool:
        consumed.append(True)
        return False

    with pytest.raises(PipelineHardError):
        run_call_stack_input_aware_lowering_8616(
            codegen, consume, scoped_context=ScopedCallStackContext8616(),
            scoped_caller_scope=caller_scope)
    assert consumed == [] and codegen.cfunc.statements is original
    assert not run_call_stack_input_aware_lowering_8616(
        codegen, consume, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert consumed == [True]
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert verdict.complete


def test_authority_identity_includes_source_and_context() -> None:
    """Equality/hash include artifact and context identity, not just offsets."""
    parts, artifact, codegen, _calls, context, _d = _lowered_world(0)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    original_root = codegen.cfunc.statements
    variables = dict(codegen.cfunc.variables_in_use)
    original = _wrappers(codegen)[0].tags[
        CALL_STACK_INPUT_BINDING_TAG_8616].authority
    _parts_b, artifact_b, _cg_b, _calls_b, context_b, _d_b = _world(0)
    same = ScopedCallPositionAuthority8616(original.result)
    assert same == original and hash(same) == hash(original)
    variants = (
        ScopedCallPositionAuthority8616(
            replace(original.result, artifact=artifact_b)),
        ScopedCallPositionAuthority8616(
            replace(original.result, context=context_b)),
    )
    for variant in variants:
        assert variant.position == original.position
        assert variant.result.caller_scope is original.result.caller_scope
        assert variant != original
    assert len({original, same, *variants}) == 3
    for forged in variants:
        outcome = prepare_entry_stack_pointer_capture_8616(
            codegen, artifact, (forged,), scoped_context=context,
            scoped_caller_scope=caller_scope)
        assert outcome is not None
        assert outcome.failure is EntryStackPointerCaptureFailure8616.SOURCE_CHANGED
        assert codegen.cfunc.statements is original_root
        assert dict(codegen.cfunc.variables_in_use) == variables


def test_ast_copy_preserves_scoped_authority(tmp_path: Path) -> None:
    """Ordinary AST copies retain the live authority handle, not a projection."""
    parts, _art, codegen, calls, context, _d = _lowered_world(0)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    original_root = codegen.cfunc.statements
    original_marker = _wrappers(codegen)[0].tags[
        CALL_STACK_INPUT_BINDING_TAG_8616]
    memo = {id(codegen): codegen}
    memo.update({id(call.callee_func): call.callee_func for call in calls})
    copied_root = copy.deepcopy(original_root, memo)
    assert copied_root is not original_root
    codegen.cfunc.statements = copied_root
    copied_marker = _wrappers(codegen)[0].tags[
        CALL_STACK_INPUT_BINDING_TAG_8616]
    assert copied_marker.authority is original_marker.authority
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert verdict.complete
    universal = validate_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements)
    assert universal.issues
    entry = 0x12348000
    assert _compile_and_run(codegen, tmp_path / 'copy.c', entry) == (
        (entry - 1) & 0xffff, 1, entry & 0xffff, entry >> 16)
    project = cast(angr.Project, parts["project"])
    project.loader.memory.store(0x1076, b"\x2b\xd9")
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert not verdict.complete


def test_scoped_snapshot_is_diagnostic_not_restored_authority() -> None:
    """Snapshots publish a scoped diagnostic that cannot re-enter as authority."""
    parts, _art, codegen, _calls, context, _d = _lowered_world(0)
    caller_scope = cast(Real16InvocationDomain8616, parts["caller_domain"])
    wrapper = _wrappers(codegen)[0]
    marker = wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616]
    generator, constant = _actual_ast()
    constant.tags["binding"] = marker
    observed = observe_structured_ast_output_8616(generator)
    assert observed.complete and observed.snapshot is not None
    payload = json.loads(observed.snapshot.payload_json)
    bindings = list(_find_projection(payload, "call_stack_input_binding"))
    assert bindings
    diagnostics = [
        value for binding in bindings
        for value in _find_projection(binding, "scoped_call_position")]
    assert diagnostics
    assert isinstance(diagnostics[0], dict)
    scopes = {
        item[0]: item[1] for item in diagnostics[0].get("mapping", [])
        if isinstance(item, list) and len(item) == 2
    }
    assert scopes.get("position") is not None
    assert scopes.get("caller_scope") is not None
    assert scopes.get("callee_scope") is not None
    wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616] = bindings[0]
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert not verdict.complete
    wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616] = marker
    verdict = validate_scoped_call_stack_inputs_8616(
        codegen, codegen.cfunc.statements, scoped_context=context,
        scoped_caller_scope=caller_scope)
    assert verdict.complete

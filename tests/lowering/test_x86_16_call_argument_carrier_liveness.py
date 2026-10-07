"""Regress exact call-argument virtual-carrier liveness during PUSH cleanup."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CDirtyExpression,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
)
from angr.sim_type import SimTypeShort
import inertia.postprocess.decompiler_postprocess_calls as postprocess_calls
import inertia.postprocess.decompiler_postprocess_stage as postprocess_stage
import inertia.structuring.decompiler_structuring_stage as structuring_stage
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.postprocess.decompiler_postprocess_calls import (
    _bind_call_argument_rematerialization_classifier_8616,
    _materialize_callsite_stack_arguments_8616,
)
from inertia.lowering.call_argument_carrier_liveness import (
    CallArgumentCarrierLivenessVerdict8616,
    CallArgumentMaterializationVerdict8616,
    call_argument_requires_typed_rematerialization_8616,
    classify_call_argument_carrier_liveness_8616,
    classify_call_argument_materialization_8616,
)
from inertia.lowering.real_mode_linear import (
    prune_consumed_call_push_stack_assignments_8616,
)
from inertia.pipeline.errors import PipelineHardError
from capstone.x86_const import X86_INS_PUSH


class _Codegen:
    """Minimal third-party structured-codegen surface for C AST fixtures."""

    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(
            arch=Arch86_16(),
            _inertia_c_target="portable-flat",
        )
        self.cstyle_null_cmp = False
        root = CStatements([], addr=0x4010, codegen=self)
        self.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    def next_idx(self, _name: str) -> int:
        """Return a stable synthetic C AST index."""
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _dirty(codegen: _Codegen, varid: int) -> CDirtyExpression:
    """Build one virtual carrier with a stable structured identity."""
    return CDirtyExpression(SimpleNamespace(varid=varid), codegen=codegen)


def _push_function(push_addr: int) -> SimpleNamespace:
    """Build exact decoded PUSH provenance for one lowering fixture."""
    return SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=push_addr, id=X86_INS_PUSH),),
                ),
            ),
        ),
    )


def test_carrier_liveness_matches_cloned_virtual_identity() -> None:
    codegen = _Codegen()

    evidence = classify_call_argument_carrier_liveness_8616(
        _dirty(codegen, 324),
        (_dirty(codegen, 324),),
    )

    assert evidence.verdict is CallArgumentCarrierLivenessVerdict8616.LIVE_ARGUMENT_DEFINITION
    assert evidence.closes_evidence is True


def test_carrier_liveness_refuses_lvalue_without_structured_identity() -> None:
    codegen = _Codegen()

    evidence = classify_call_argument_carrier_liveness_8616(
        CConstant(0, SimTypeShort(False), codegen=codegen),
        (_dirty(codegen, 324),),
    )

    assert evidence.verdict is CallArgumentCarrierLivenessVerdict8616.UNKNOWN_REFUSE
    assert evidence.failure_count == 1


def test_argument_materialization_rejects_nested_virtual_carrier() -> None:
    codegen = _Codegen()

    evidence = classify_call_argument_materialization_8616(
        _dirty(codegen, 324),
    )

    assert (
        evidence.verdict
        is CallArgumentMaterializationVerdict8616.UNRESOLVED_VIRTUAL_CARRIER
    )
    assert evidence.closes_evidence is True


def test_argument_materialization_accepts_self_contained_constant() -> None:
    codegen = _Codegen()

    evidence = classify_call_argument_materialization_8616(
        CConstant(21, SimTypeShort(False), codegen=codegen),
    )

    assert evidence.verdict is CallArgumentMaterializationVerdict8616.SELF_CONTAINED
    assert evidence.closes_evidence is True


def test_typed_immediate_source_replaces_existing_virtual_argument() -> None:
    codegen = _Codegen()
    callsite_addr = 0x4018
    call = CFunctionCall(
        "sub_5000",
        SimpleNamespace(name="sub_5000"),
        [_dirty(codegen, 324)],
        codegen=codegen,
        tags={"ins_addr": callsite_addr},
    )
    codegen.cfunc.statements.statements.append(
        CExpressionStatement(call, codegen=codegen)
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x5000,
            return_addr=callsite_addr + 3,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=False,
            push_arg_sources=(("imm", 21),),
            push_arg_instruction_addrs=(0x4016,),
        )
    }
    _bind_call_argument_rematerialization_classifier_8616(
        codegen,
        call_argument_requires_typed_rematerialization_8616,
    )

    changed = _materialize_callsite_stack_arguments_8616(codegen.project, codegen)

    assert changed is True
    assert len(call.args) == 1
    assert isinstance(call.args[0], CConstant)
    assert call.args[0].value == 21


def test_typed_partial_sources_replace_only_proven_virtual_arguments() -> None:
    codegen = _Codegen()
    callsite_addr = 0x4018
    unknown_arg = _dirty(codegen, 324)
    proven_arg = _dirty(codegen, 325)
    call = CFunctionCall(
        "sub_5000",
        SimpleNamespace(name="sub_5000"),
        [unknown_arg, proven_arg],
        codegen=codegen,
        tags={"ins_addr": callsite_addr},
    )
    codegen.cfunc.statements.statements.append(
        CExpressionStatement(call, codegen=codegen)
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x5000,
            return_addr=callsite_addr + 3,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=False,
            push_arg_sources=(("imm", 21), None),
            push_arg_instruction_addrs=(0x4014, 0x4016),
        )
    }
    _bind_call_argument_rematerialization_classifier_8616(
        codegen,
        call_argument_requires_typed_rematerialization_8616,
    )

    changed = _materialize_callsite_stack_arguments_8616(codegen.project, codegen)

    assert changed is True
    assert isinstance(call.args[0], CDirtyExpression)
    assert call.args[0].dirty.varid == unknown_arg.dirty.varid == 324
    assert isinstance(call.args[1], CConstant)
    assert call.args[1].value == 21


def test_postprocess_baseline_replays_structuring_owned_call_arguments(monkeypatch) -> None:
    """Core regeneration must not leave stale call arguments in the baseline."""
    codegen = _Codegen()
    calls: list[str] = []
    codegen._inertia_callsite_stack_arguments_structuring_pass_ran_8616 = True
    codegen._inertia_callsite_argument_replay_consumer_8616 = (
        lambda _project, _codegen: calls.append("replay") or True
    )
    monkeypatch.setattr(
        postprocess_stage._calls,
        "_attach_callsite_summaries_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        postprocess_stage._calls,
        "_normalize_call_target_names_8616",
        lambda *_args: False,
    )

    changed = postprocess_stage._prime_callsite_summaries_before_validation_baseline_8616(
        codegen.project,
        codegen,
    )

    assert changed is True
    assert calls == ["replay"]
    assert codegen._inertia_pre_validation_callsite_summaries_primed is True


def test_postprocess_baseline_fails_if_structuring_replay_is_unbound(monkeypatch) -> None:
    """Wrong-layer fallback must fail instead of repairing arguments in Rewrite."""
    codegen = _Codegen()
    codegen._inertia_callsite_stack_arguments_structuring_pass_ran_8616 = True
    monkeypatch.setattr(
        postprocess_stage._calls,
        "_attach_callsite_summaries_8616",
        lambda *_args: False,
    )

    with pytest.raises(PipelineHardError, match="Structuring-owned callsite argument replay"):
        postprocess_stage._prime_callsite_summaries_before_validation_baseline_8616(
            codegen.project,
            codegen,
        )


def test_structuring_call_replay_can_preserve_stack_setup(monkeypatch) -> None:
    """Render rollback replay must not prune the stack effects it restored."""
    codegen = _Codegen()
    observed: list[tuple[bool, bool]] = []

    def replay(_project: object, replay_codegen: object) -> bool:
        observed.append(
            (
                replay_codegen._inertia_callsite_disable_consumed_arg_store_prune_8616,
                replay_codegen._inertia_callsite_disable_stack_probe_setup_prune_8616,
            )
        )
        return True

    monkeypatch.setattr(
        postprocess_calls,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        replay,
    )
    monkeypatch.setattr(
        structuring_stage,
        "finalize_shared_call_occurrences_8616",
        lambda project, replay_codegen: observed.append((project is codegen.project, replay_codegen is codegen))
        or False,
    )

    changed = structuring_stage._replay_structuring_callsite_arguments_after_regeneration_8616(
        codegen.project,
        codegen,
        preserve_setup=True,
    )

    assert changed is True
    assert observed == [(True, True), (True, True)]
    assert codegen._inertia_callsite_disable_consumed_arg_store_prune_8616 is False
    assert codegen._inertia_callsite_disable_stack_probe_setup_prune_8616 is False


def test_consumed_push_keeps_definition_read_by_materialized_call() -> None:
    codegen = _Codegen()
    push_addr = 0x4016
    definition = CAssignment(
        _dirty(codegen, 324),
        CConstant(21, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": push_addr},
    )
    codegen.cfunc.statements.statements.append(definition)

    changed = prune_consumed_call_push_stack_assignments_8616(
        codegen.project,
        codegen,
        frozenset({push_addr}),
        materialized_args_by_push_instruction_addr={
            push_addr: (_dirty(codegen, 324),),
        },
        function=_push_function(push_addr),
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [definition]
    result = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert result.preserved_live_definition_count == 1
    assert result.liveness_refusal_count == 0

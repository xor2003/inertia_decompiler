from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import FrameAccessArtifact, StackFrameSlot
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.ir.core import AddressStatus, MemSpace, SegmentOrigin
import inertia.lowering.stack_lowering as stack_lowering_module
from inertia.lowering.real_mode_linear import _known_bp_stack_offsets_8616, _ss_probe_enabled_8616
from inertia.lowering.ss_bp_substitution import substitute_ss_bp_dereferences_with_variables
from inertia.lowering.stack_lowering import run_stack_lowering_pass_8616
from inertia.lowering.stack_lowering_from_facts import (
    _unbound_typed_frame_slots_8616,
    build_stack_variable_bindings_from_alias_facts_8616,
    lower_stack_accesses_from_alias_facts_8616,
)
from inertia.lowering.stack_lowering_impl import (
    _prefer_bound_stack_cvar_8616,
    _sole_bound_stack_cvar_8616,
    _typed_alias_fact_bp_offsets_8616,
)
from inertia.lowering.stack_lowering_result import (
    StackLoweringResult,
    StackLoweringStatus,
    StackSlotFailure,
    materialization_diagnostics_8616,
)
from inertia.lowering.stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from inertia.lowering.stack_variable_binding import (
    StackBaseBpBiasEvidence8616,
    StackVariableBinding,
    stable_ss_offset_to_ir_address_8616,
    stable_stack_binding_tags_8616,
)
from inertia.pipeline.errors import PipelineHardError
from capstone.x86_const import X86_OP_MEM, X86_REG_BP

from inertia.alias.alias_model_impl import AliasStorageFacts, _StackSlotIdentity, _StorageDomainSignature
from inertia.cli.cli_c_ast_rewrites import _canonicalize_stack_cvar_expr


def test_stack_lowering_result_uses_typed_status_values() -> None:
    result = StackLoweringResult(
        status=StackLoweringStatus.PARTIAL,
        failures=[StackSlotFailure(offset=-2, size=2, reason="not materialized")],
    )

    assert result.status is StackLoweringStatus.PARTIAL
    assert result.is_ok is False
    assert result.is_failed is False
    assert result.failure_count == 1
    assert result.to_dict()["status"] == "partial"
    assert "Stack lowering: partial" in materialization_diagnostics_8616(result)


def test_stack_variable_binding_preserves_stable_ss_address_contract() -> None:
    binding = StackVariableBinding(-4, 2, var_name="local_4")
    address = stable_ss_offset_to_ir_address_8616(binding.bp_offset, binding.size)

    assert binding.to_dict() == {
        "bp_offset": -4,
        "size": 2,
        "var_name": "local_4",
        "is_stable": True,
    }
    assert address.space is MemSpace.SS
    assert address.offset == -4
    assert address.size == 2
    assert address.status is AddressStatus.STABLE
    assert address.segment_origin is SegmentOrigin.PROVEN


def test_typed_frame_slot_reconciliation_uses_byte_range_coverage() -> None:
    bindings = (
        StackVariableBinding(-2, 2, var_name="local_2"),
        StackVariableBinding(6, 2, var_name="arg_6"),
    )
    slots = (
        StackFrameSlot(base="bp", offset=-2, role="local", size=2),
        StackFrameSlot(base="bp", offset=7, role="arg", size=1),
    )

    assert _unbound_typed_frame_slots_8616(bindings, slots) == ()


def test_stack_binding_builder_refuses_non_bp_alias_facts() -> None:
    non_bp_fact = AliasStorageFacts(
        domain=_StorageDomainSignature("stack", 2),
        identity=("stack", _StackSlotIdentity("si", -2, 2)),
    )

    assert build_stack_variable_bindings_from_alias_facts_8616([non_bp_fact]) == []


def test_stack_lowering_fails_when_typed_bp_slot_has_no_alias_binding() -> None:
    class FakeCodegen:
        def __init__(self) -> None:
            self._inertia_vex_ir_frame = FrameAccessArtifact(
                slots=(StackFrameSlot(base="bp", offset=-8, role="local", size=2),)
            )

    codegen = FakeCodegen()

    with pytest.raises(PipelineHardError, match="typed BP frame slots"):
        lower_stack_accesses_from_alias_facts_8616(codegen, [])

    assert codegen._inertia_stack_lowering_debug == {
        "stable_stack_fact_count": 0,
        "stable_bp_fact_count": 0,
        "stack_binding_count": 0,
        "stack_slot_candidates": 0,
        "stack_slot_bindings": 0,
        "stack_slot_materialized": 0,
        "stack_slot_failed": 0,
        "typed_frame_raw_fact_count": 1,
        "typed_frame_normalized_fact_count": 1,
        "typed_frame_classified_fact_count": 1,
        "typed_frame_bound_count": 0,
        "typed_frame_failure_count": 1,
    }


def test_bound_stack_cvar_resolution_uses_binding_bp_offset() -> None:
    class FakeCodegen:
        def __init__(self) -> None:
            self.project = SimpleNamespace(arch=Arch86_16())
            self._inertia_stack_variable_bindings = (StackVariableBinding(-6, 2),)
            self._idx = 0

        def next_idx(self, _name: str) -> int:
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = FakeCodegen()
    variable = SimStackVariable(-6, 2, base="bp", name="local_6")
    cvar = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    seen_offsets: list[int] = []

    def resolve_stack_cvar_at_offset(_codegen: object, offset: int) -> structured_c.CVariable:
        seen_offsets.append(offset)
        return cvar

    assert _sole_bound_stack_cvar_8616(codegen, resolve_stack_cvar_at_offset) is cvar
    assert seen_offsets == [-6]


def test_named_stack_fallback_preserves_exact_slot_identity() -> None:
    """A sole named local must not replace a different exact BP slot."""

    class FakeCodegen:
        def __init__(self) -> None:
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cfunc = SimpleNamespace(variables_in_use={}, arg_list=())
            self._idx = 0

        def next_idx(self, _name: str) -> int:
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = FakeCodegen()
    source_var = SimStackVariable(-4, 2, base="bp", name="local_4")
    source = structured_c.CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)
    named_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    named = structured_c.CVariable(named_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[named_var] = named

    resolved = _prefer_bound_stack_cvar_8616(codegen, source, lambda _codegen, _offset: source)

    assert resolved is source


def test_exact_stack_condition_binding_refuses_inferred_bp_rebase() -> None:
    """Typed SS:BP evidence must outrank a structured stack-base bias."""

    root = object()

    class FakeCodegen:
        def __init__(self) -> None:
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cfunc = SimpleNamespace(addr=0x108D0, statements=root, variables_in_use={}, arg_list=())
            self._idx = 0

        def next_idx(self, _name: str) -> int:
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = FakeCodegen()
    target_var = SimStackVariable(-2, 2, base="bp", name="local_2")
    target = structured_c.CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    source_var = SimStackVariable(-4, 2, base="bp", name="local_4")
    source_binding = StackVariableBinding(-4, 2, var_name="local_4")
    source = structured_c.CVariable(
        source_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags=stable_stack_binding_tags_8616(source_binding),
    )
    codegen.cfunc.variables_in_use[target_var] = target
    codegen._inertia_semantic_alias_facts = [
        AliasStorageFacts(
            domain=_StorageDomainSignature("stack", 2),
            identity=("stack", _StackSlotIdentity("bp", -2, 2)),
        )
    ]
    codegen._inertia_stack_base_bp_bias_evidence_8616 = StackBaseBpBiasEvidence8616(
        statement_root=root,
        stack_base_displacements=(-4,),
        known_bp_offsets=frozenset({-2}),
        inferred_bias=2,
    )

    assert _canonicalize_stack_cvar_expr(source, codegen) is source


def test_known_bp_stack_offsets_uses_typed_stack_bindings() -> None:
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, variables_in_use={}, arg_list=()),
        _inertia_semantic_alias_facts=[],
        _inertia_stack_variable_bindings=(object(), StackVariableBinding(-8, 2)),
    )

    assert _known_bp_stack_offsets_8616(codegen) == {-8}


def test_known_bp_stack_offsets_uses_typed_alias_facts() -> None:
    stack_fact = AliasStorageFacts(
        domain=_StorageDomainSignature("stack", 2),
        identity=("stack", _StackSlotIdentity("bp", -10, 2)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, variables_in_use={}, arg_list=()),
        _inertia_semantic_alias_facts=[object(), stack_fact],
        _inertia_stack_variable_bindings=(),
    )

    assert _known_bp_stack_offsets_8616(codegen) == {-10}


def test_known_bp_stack_offsets_caches_function_block_disassembly() -> None:
    class CountingBlock:
        def __init__(self) -> None:
            self.capstone_reads = 0

        @property
        def capstone(self) -> SimpleNamespace:
            self.capstone_reads += 1
            operand = SimpleNamespace(type=X86_OP_MEM, mem=SimpleNamespace(base=X86_REG_BP, disp=4))
            return SimpleNamespace(insns=(SimpleNamespace(operands=(operand,)),))

    block = CountingBlock()
    function = SimpleNamespace(blocks=(block,))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, variables_in_use={}, arg_list=()),
        _inertia_current_function_8616=function,
        _inertia_semantic_alias_facts=[],
        _inertia_stack_variable_bindings=(),
    )

    assert _known_bp_stack_offsets_8616(codegen) == {4}
    assert _known_bp_stack_offsets_8616(codegen) == {4}
    assert block.capstone_reads == 1

    codegen.cfunc = SimpleNamespace(addr=0x2000, variables_in_use={}, arg_list=())
    assert _known_bp_stack_offsets_8616(codegen) == {4}
    assert block.capstone_reads == 2


def test_stack_lowering_impl_uses_typed_alias_fact_fields() -> None:
    stack_fact = AliasStorageFacts(
        domain=_StorageDomainSignature("stack", 2),
        identity=("stack", _StackSlotIdentity("bp", 0xFFF4, 2)),
    )

    assert _typed_alias_fact_bp_offsets_8616([object(), stack_fact]) == {-12}


def test_ss_probe_enabled_uses_typed_stack_probe_facts() -> None:
    codegen = SimpleNamespace(
        _inertia_typed_stack_probe_return_facts={
            1: object(),
            2: TypedStackProbeReturnFact8616(call_node_id=2, segment_space="ss", width=2, carrier_keys=()),
        }
    )

    assert _ss_probe_enabled_8616(codegen) is True


def test_stack_lowering_coordinator_runs_typed_lowering_before_rewrite_cleanup() -> None:
    calls: list[str] = []

    def lower_stable_ss_stack_accesses() -> bool:
        calls.append("typed-ss")
        return True

    def rewrite_ss_stack_byte_offsets() -> bool:
        calls.append("rewrite")
        return False

    def canonicalize_stack_cvars() -> bool:
        calls.append("canonicalize")
        return False

    changed = run_stack_lowering_pass_8616(
        lower_stable_ss_stack_accesses=lower_stable_ss_stack_accesses,
        rewrite_ss_stack_byte_offsets=rewrite_ss_stack_byte_offsets,
        canonicalize_stack_cvars=canonicalize_stack_cvars,
        max_rounds=1,
    )

    assert changed is True
    assert calls == ["typed-ss", "rewrite", "canonicalize"]


def test_stack_lowering_preserves_segment_provenance_before_global_projection(monkeypatch) -> None:
    calls: list[str] = []
    codegen = SimpleNamespace(cfunc=SimpleNamespace())
    project = SimpleNamespace(_inertia_c_target="portable-flat")

    monkeypatch.setattr(
        stack_lowering_module,
        "lower_stable_ss_linear_stack_dereferences_8616",
        lambda *_args, **_kwargs: calls.append("stable-ss") or False,
    )
    monkeypatch.setattr(
        stack_lowering_module,
        "apply_runtime_segment_lowering_8616",
        lambda *_args, **_kwargs: calls.append("runtime-segment") or False,
    )
    monkeypatch.setattr(
        stack_lowering_module,
        "lower_stable_ds_es_linear_global_dereferences_8616",
        lambda *_args, **_kwargs: calls.append("global-dereference") or False,
    )
    monkeypatch.setattr(
        stack_lowering_module,
        "lower_stable_ds_es_linear_global_addresses_8616",
        lambda *_args, **_kwargs: calls.append("global-address") or False,
    )

    changed = run_stack_lowering_pass_8616(
        rewrite_ss_stack_byte_offsets=lambda: calls.append("rewrite") or False,
        canonicalize_stack_cvars=lambda: calls.append("canonicalize") or False,
        codegen=codegen,
        project=project,
        max_rounds=1,
    )

    assert changed is False
    assert calls == [
        "stable-ss",
        "runtime-segment",
        "global-dereference",
        "global-address",
        "rewrite",
        "canonicalize",
    ]


def test_stack_probe_return_facts_use_typed_callsite_summary_fields() -> None:
    summary = CallsiteSummary8616(
        callsite_addr=0x1234,
        target_addr=0x2000,
        return_addr=0x1237,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register="ax",
        return_used=True,
        stack_probe_helper=True,
        helper_return_state="stack_address",
        helper_return_space="ss",
        helper_return_width=2,
        helper_return_address_kind="stack",
    )
    codegen = SimpleNamespace(_inertia_callsite_summaries={1: object(), 2: summary})

    facts = build_typed_stack_probe_return_facts_8616(codegen)

    assert facts == {
        2: TypedStackProbeReturnFact8616(call_node_id=2, segment_space="ss", width=2, carrier_keys=())
    }
    assert codegen._inertia_typed_stack_probe_return_facts == facts


def test_ss_bp_substitution_uses_typed_stack_binding_fields() -> None:
    c_text = "x = *((ss << 4) + BP) - 0x4; y = ((ss << 4) + BP) - 4;"
    bindings = (StackVariableBinding(-4, 2, var_name="local_4"),)

    result = substitute_ss_bp_dereferences_with_variables(c_text, bindings)

    assert "x = local_4;" in result
    assert "y = &local_4;" in result

"""Regression tests for binary-proven aggregate stack-object recovery."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import (
    SimTypeChar,
    SimTypeFixedSizeArray,
    SimTypeLong,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering import stack_aggregate_objects as aggregate_objects
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
    _direct_stack_move_destination_expr_8616,
    _direct_stack_move_source_expr_8616,
)
from angr_platforms.X86_16.lowering.stack_aggregate_objects import (
    StackAggregateEvidenceKind8616,
    StackAggregateObjectFact8616,
    StackAggregateRecovery8616,
    StackAggregateRecoveryStatus8616,
    decay_stack_aggregate_call_arguments_8616,
    materialize_stack_aggregate_objects_8616,
    prune_nonmemory_stack_aggregate_carriers_8616,
    reapply_stack_aggregate_object_facts_8616,
    recover_stack_aggregate_object_facts_from_instructions_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
)
from capstone.x86_const import (
    X86_INS_CALL,
    X86_INS_LEA,
    X86_INS_MOV,
    X86_INS_PUSH,
    X86_INS_SHL,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
)
from x86_16_frame_coordinate_fixtures import proven_frame_coordinate

_AX = 1
_BP = 2
_SI = 3


@dataclass(frozen=True)
class _MemoryOperand:
    base: int
    index: int
    disp: int


@dataclass(frozen=True)
class _Operand:
    type: int
    size: int = 0
    reg: int = 0
    imm: int = 0
    mem: _MemoryOperand | None = None


@dataclass(frozen=True)
class _Instruction:
    id: int
    operands: tuple[_Operand, ...]
    mnemonic: str = ""
    address: int = 0
    size: int = 1

    def reg_name(self, reg_id: int) -> str:
        return {_AX: "ax", _BP: "bp", _SI: "si"}.get(reg_id, "")


class _AggregateCodegen:
    """Minimal structured-codegen boundary used by materialization tests."""

    def __init__(self) -> None:
        self.project = SimpleNamespace(
            arch=Arch86_16(),
            kb=SimpleNamespace(
                functions=SimpleNamespace(function=lambda **_kwargs: None),
            ),
        )
        self.cstyle_null_cmp = False
        self.cfunc = SimpleNamespace(
            addr=0x1000,
            variables_in_use={},
            unified_local_vars={},
        )
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        """Return a deterministic structured-C node index."""
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _VariableManager:
    """Minimal variable type store matching angr's refresh contract."""

    def __init__(self) -> None:
        self.variable_types: dict[object, object] = {}

    def set_variable_type(
        self,
        variable: object,
        variable_type: object,
        *,
        override_bot: bool = True,
        all_unified: bool = False,
    ) -> None:
        """Persist one type assignment for a current variable identity."""
        del override_bot, all_unified
        self.variable_types[variable] = variable_type

    def get_variable_type(self, variable: object) -> object | None:
        """Return a previously persisted variable type."""
        return self.variable_types.get(variable)


def _reg(reg_id: int) -> _Operand:
    return _Operand(X86_OP_REG, size=2, reg=reg_id)


def _imm(value: int) -> _Operand:
    return _Operand(X86_OP_IMM, size=2, imm=value)


def _mem(displacement: int, width: int, *, index: int = 0) -> _Operand:
    return _Operand(X86_OP_MEM, size=width, mem=_MemoryOperand(_BP, index, displacement))


def _drawframe_shape(*, allocation: int = 82) -> tuple[_Instruction, ...]:
    return (
        _Instruction(X86_INS_MOV, (_reg(_AX), _imm(allocation)), "mov"),
        _Instruction(X86_INS_CALL, (_imm(0x7000),), "call"),
        _Instruction(X86_INS_LEA, (_reg(_AX), _mem(-82, 2)), "lea"),
        _Instruction(X86_INS_MOV, (_mem(-83, 1, index=_SI), _imm(0)), "mov"),
        _Instruction(X86_INS_MOV, (_mem(-82, 1, index=_SI), _imm(0)), "mov"),
        _Instruction(X86_INS_MOV, (_mem(-2, 2), _imm(0)), "mov"),
    )


def _addressed_full_frame_shape() -> tuple[_Instruction, ...]:
    return (
        _Instruction(X86_INS_MOV, (_reg(_AX), _imm(80)), "mov"),
        _Instruction(X86_INS_CALL, (_imm(0x7000),), "call"),
        _Instruction(X86_INS_LEA, (_reg(_AX), _mem(-80, 2)), "lea"),
        _Instruction(X86_INS_LEA, (_reg(_AX), _mem(-80, 2)), "lea"),
    )


def _addressed_partition_shape() -> tuple[_Instruction, ...]:
    return (
        _Instruction(X86_INS_MOV, (_reg(_AX), _imm(18)), "mov"),
        _Instruction(X86_INS_CALL, (_imm(0x7000),), "call"),
        _Instruction(X86_INS_LEA, (_reg(_AX), _mem(-18, 2)), "lea"),
        _Instruction(X86_INS_MOV, (_mem(-2, 2), _imm(0)), "mov"),
        _Instruction(X86_INS_LEA, (_reg(_AX), _mem(-18, 2)), "lea"),
        _Instruction(X86_INS_MOV, (_reg(_AX), _mem(-2, 2)), "mov"),
        _Instruction(X86_INS_LEA, (_reg(_AX), _mem(-18, 2)), "lea"),
    )


def _top_addressed_partition_shape() -> tuple[_Instruction, ...]:
    return (
        _Instruction(X86_INS_MOV, (_reg(_AX), _imm(46)), "mov"),
        _Instruction(X86_INS_CALL, (_imm(0x7000),), "call"),
        _Instruction(X86_INS_MOV, (_mem(-46, 2), _reg(_AX)), "mov"),
        _Instruction(X86_INS_LEA, (_reg(_AX), _mem(-44, 2)), "lea"),
        _Instruction(X86_INS_LEA, (_reg(_AX), _mem(-44, 2)), "lea"),
        _Instruction(X86_INS_MOV, (_mem(-44, 1, index=_SI), _imm(0)), "mov"),
        _Instruction(X86_INS_LEA, (_reg(_AX), _mem(-44, 2)), "lea"),
    )


def _interior_word_array_shape(*, scaled: bool = True) -> tuple[_Instruction, ...]:
    scale = (_Instruction(X86_INS_SHL, (_reg(_SI), _imm(1)), "shl"),) if scaled else ()
    return (
        _Instruction(X86_INS_MOV, (_reg(_AX), _imm(118)), "mov"),
        _Instruction(X86_INS_CALL, (_imm(0x7000),), "call"),
        _Instruction(X86_INS_MOV, (_mem(-118, 2), _imm(0)), "mov"),
        _Instruction(X86_INS_MOV, (_mem(-4, 2), _imm(0)), "mov"),
        _Instruction(X86_INS_MOV, (_reg(_SI), _mem(-2, 2)), "mov"),
        *scale,
        _Instruction(X86_INS_MOV, (_mem(-90, 2, index=_SI), _reg(_AX)), "mov"),
        _Instruction(X86_INS_MOV, (_reg(_SI), _mem(-118, 2)), "mov"),
        *scale,
        _Instruction(X86_INS_MOV, (_reg(_AX), _mem(-90, 2, index=_SI)), "mov"),
        _Instruction(X86_INS_MOV, (_reg(_SI), _mem(-4, 2)), "mov"),
        *scale,
        _Instruction(X86_INS_MOV, (_reg(_AX), _mem(-90, 2, index=_SI)), "mov"),
    )


def _stack_cvar(
    codegen: _AggregateCodegen,
    offset: int,
    size: int,
    name: str,
    variable_type: object,
) -> tuple[SimStackVariable, structured_c.CVariable]:
    variable = SimStackVariable(offset, size, base="bp", name=name, region=0x1000)
    cvar = structured_c.CVariable(variable, variable_type=variable_type, codegen=codegen)
    codegen.cfunc.variables_in_use[variable] = cvar
    return variable, cvar


def test_recovers_bottom_frame_byte_aggregate_from_closed_binary_evidence() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        _drawframe_shape(),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.MATERIALIZABLE
    assert recovery.raw_fact_count == 5
    assert recovery.normalized_fact_count == 5
    assert recovery.classified_fact_count == 1
    assert recovery.failure_count == 0
    assert recovery.facts == (
        StackAggregateObjectFact8616(
            base_offset=-82,
            byte_size=80,
            element_width=1,
            frame_allocation_size=82,
            address_taken_count=1,
            indexed_access_count=2,
            indexed_offsets=(-83, -82),
            scalar_boundary_offset=-2,
            scalar_boundary_width=2,
        ),
    )


def test_recovers_full_frame_byte_aggregate_from_allocation_and_address_takes() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        _addressed_full_frame_shape(),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.MATERIALIZABLE
    assert recovery.raw_fact_count == 3
    assert recovery.classified_fact_count == 1
    assert recovery.failure_count == 0
    assert recovery.facts == (
        StackAggregateObjectFact8616(
            base_offset=-80,
            byte_size=80,
            element_width=1,
            frame_allocation_size=80,
            address_taken_count=2,
            indexed_access_count=0,
            indexed_offsets=(),
            scalar_boundary_offset=None,
            scalar_boundary_width=None,
            evidence_kind=StackAggregateEvidenceKind8616.FULL_FRAME_ADDRESS,
        ),
    )


def test_refuses_full_frame_aggregate_when_another_local_is_accessed() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        (
            *_addressed_full_frame_shape(),
            _Instruction(X86_INS_MOV, (_mem(-2, 2), _imm(0)), "mov"),
        ),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.NO_EVIDENCE
    assert recovery.classified_fact_count == 0
    assert recovery.materialized_count == 0


def test_recovers_addressed_bottom_frame_partition_with_repeated_top_scalar() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        _addressed_partition_shape(),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.MATERIALIZABLE
    assert recovery.raw_fact_count == 6
    assert recovery.classified_fact_count == 1
    assert recovery.failure_count == 0
    assert recovery.facts == (
        StackAggregateObjectFact8616(
            base_offset=-18,
            byte_size=16,
            element_width=1,
            frame_allocation_size=18,
            address_taken_count=3,
            indexed_access_count=0,
            indexed_offsets=(),
            scalar_boundary_offset=-2,
            scalar_boundary_width=2,
            evidence_kind=StackAggregateEvidenceKind8616.ADDRESSED_PARTITION,
        ),
    )


def test_refuses_addressed_partition_with_conflicting_fixed_frame_access() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        (
            *_addressed_partition_shape(),
            _Instruction(X86_INS_MOV, (_mem(-4, 2), _imm(0)), "mov"),
        ),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.REFUSED
    assert recovery.classified_fact_count == 0
    assert recovery.failure_count == 1
    assert recovery.refusals == ("addressed_partition_boundary_ambiguous",)


def test_recovers_addressed_top_frame_partition_with_bottom_scalar() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        _top_addressed_partition_shape(),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.MATERIALIZABLE
    assert recovery.raw_fact_count == 6
    assert recovery.classified_fact_count == 1
    assert recovery.failure_count == 0
    assert recovery.facts == (
        StackAggregateObjectFact8616(
            base_offset=-44,
            byte_size=44,
            element_width=1,
            frame_allocation_size=46,
            address_taken_count=3,
            indexed_access_count=1,
            indexed_offsets=(-44,),
            scalar_boundary_offset=-46,
            scalar_boundary_width=2,
            evidence_kind=StackAggregateEvidenceKind8616.ADDRESSED_PARTITION,
        ),
    )


def test_refuses_addressed_top_partition_with_conflicting_fixed_access() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        (
            *_top_addressed_partition_shape(),
            _Instruction(X86_INS_MOV, (_mem(-20, 2), _imm(0)), "mov"),
        ),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.REFUSED
    assert recovery.classified_fact_count == 0
    assert recovery.failure_count == 1
    assert recovery.refusals == ("top_addressed_partition_fixed_access_conflict",)


def test_refuses_addressed_top_partition_with_conflicting_indexed_access() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        (
            *_top_addressed_partition_shape(),
            _Instruction(X86_INS_MOV, (_mem(-43, 1, index=_SI), _imm(0)), "mov"),
        ),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.REFUSED
    assert recovery.classified_fact_count == 0
    assert recovery.failure_count == 1
    assert recovery.refusals == ("top_addressed_partition_indexed_access_conflict",)


def test_refuses_ambiguous_stack_probe_allocations() -> None:
    instructions = (*_drawframe_shape(), _Instruction(X86_INS_MOV, (_reg(_AX), _imm(84)), "mov"), _Instruction(X86_INS_CALL, (_imm(28672),), "call"))

    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        instructions,
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.REFUSED
    assert recovery.classified_fact_count == 0
    assert recovery.failure_count == 1
    assert recovery.refusals == ("ambiguous_frame_allocation",)


def test_refuses_shape_without_binary_proven_stack_allocation() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        _drawframe_shape()[2:],
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.NO_EVIDENCE
    assert recovery.classified_fact_count == 0
    assert recovery.materialized_count == 0


def test_recovers_interior_word_array_from_scaled_index_and_scalar_boundary() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        _interior_word_array_shape(),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.MATERIALIZABLE
    assert recovery.classified_fact_count == 1
    assert recovery.failure_count == 0
    assert recovery.facts == (
        StackAggregateObjectFact8616(
            base_offset=-90,
            byte_size=86,
            element_width=2,
            frame_allocation_size=118,
            address_taken_count=0,
            indexed_access_count=3,
            indexed_offsets=(-90,),
            scalar_boundary_offset=-4,
            scalar_boundary_width=2,
        ),
    )


def test_refuses_interior_word_array_without_element_scale_proof() -> None:
    recovery = recover_stack_aggregate_object_facts_from_instructions_8616(
        _interior_word_array_shape(scaled=False),
        stack_probe_targets=frozenset({0x7000}),
    )

    assert recovery.status is StackAggregateRecoveryStatus8616.NO_EVIDENCE
    assert recovery.classified_fact_count == 0
    assert recovery.materialized_count == 0


def test_materialization_promotes_interior_word_array(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(codegen, -90, 2, "aTemp", SimTypeShort(False))
    _boundary_var, boundary_cvar = _stack_cvar(codegen, -4, 2, "iRowMax", SimTypeShort(False))
    fact = StackAggregateObjectFact8616(-90, 86, 2, 118, 0, 3, (-90,), -4, 2)
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=8,
        normalized_fact_count=8,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert isinstance(base_cvar.variable_type, SimTypeFixedSizeArray)
    assert base_cvar.variable_type.length == 43
    assert base_cvar.variable_type.elem_type == SimTypeShort(False).with_arch(codegen.project.arch)
    assert boundary_cvar.variable_type == SimTypeShort(False)


def test_materialization_creates_missing_binary_proven_aggregate_base(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    fact = StackAggregateObjectFact8616(-90, 86, 2, 118, 0, 3, (-90,), -4, 2)
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=8,
        normalized_fact_count=8,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    tracked = codegen._inertia_stack_aggregate_cvars_8616[-90]
    assert isinstance(tracked.variable, SimStackVariable)
    assert tracked.variable.offset == -90
    assert tracked.variable.size == 86
    assert tracked.variable.name == "local_5a"
    assert isinstance(tracked.variable_type, SimTypeFixedSizeArray)
    assert tracked.variable_type.length == 43
    assert codegen._inertia_stack_aggregate_recovery_8616.materialized_count == 1
    assert codegen._inertia_stack_aggregate_recovery_8616.failure_count == 0

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is False
    assert codegen._inertia_stack_aggregate_cvars_8616[-90] is tracked


def test_materialization_promotes_exact_base_without_merging_overlaps(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    base_var, base_cvar = _stack_cvar(codegen, -82, 1, "achTmp", SimTypeChar(False))
    overlap_var, overlap_cvar = _stack_cvar(codegen, -85, 4, "local_55", SimTypeLong(False))
    scalar_var, scalar_cvar = _stack_cvar(codegen, -2, 2, "iRow", SimTypeShort(False))
    fact = StackAggregateObjectFact8616(-82, 80, 1, 82, 1, 2, (-83, -82), -2, 2)
    unified = SimStackVariable(-82, 1, base="bp", name="achTmp", region=0x1000)
    base_cvar.unified_variable = unified
    codegen.cfunc.unified_local_vars[unified] = {(base_cvar, SimTypeShort(False))}
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=5,
        normalized_fact_count=5,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert base_var.size == 1
    assert base_cvar.variable_type.length == 80
    assert overlap_var.size == 4
    assert overlap_cvar.variable_type == SimTypeLong(False)
    assert scalar_var.size == 2
    assert scalar_cvar.variable_type == SimTypeShort(False)
    assert codegen._inertia_stack_aggregate_cvars_8616 == {-82: base_cvar}
    assert codegen._inertia_stack_aggregate_recovery_8616.materialized_count == 1
    assert codegen._inertia_stack_aggregate_recovery_8616.failure_count == 0
    assert next(iter(codegen.cfunc.unified_local_vars[unified]))[1].length == 80

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is False
    assert codegen._inertia_stack_aggregate_recovery_8616.materialized_count == 1
    assert codegen._inertia_stack_aggregate_recovery_8616.failure_count == 0

    base_var.size = 2
    base_cvar.variable_type = SimTypeShort(False)
    codegen.cfunc.unified_local_vars[unified] = {(base_cvar, SimTypeShort(False))}
    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert base_var.size == 2
    assert base_cvar.variable_type.length == 80
    assert next(iter(codegen.cfunc.unified_local_vars[unified]))[1].length == 80


def test_materialization_rebinds_stale_tracked_cvar_after_codegen_regeneration(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    stale_var, stale_cvar = _stack_cvar(codegen, -82, 1, "local_52", SimTypeChar(False))
    fact = StackAggregateObjectFact8616(-82, 80, 1, 82, 1, 2, (-83, -82), -2, 2)
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=5,
        normalized_fact_count=5,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert codegen._inertia_stack_aggregate_cvars_8616 == {-82: stale_cvar}

    current_var = SimStackVariable(-82, 2, base="bp", name="achTmp", region=0x1000)
    current_cvar = structured_c.CVariable(
        current_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {current_var: current_cvar}
    codegen.cfunc.unified_local_vars = {current_var: {(current_cvar, SimTypeShort(False))}}

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert stale_var.size == 1
    assert current_var.size == 2
    assert current_cvar.variable_type.length == 80
    assert next(iter(codegen.cfunc.unified_local_vars[current_var]))[1].length == 80
    assert codegen._inertia_stack_aggregate_cvars_8616 == {-82: current_cvar}


def test_materialization_restores_proven_scalar_boundary_width_after_regeneration(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(codegen, -82, 1, "achTmp", SimTypeChar(False))
    boundary_var, boundary_cvar = _stack_cvar(codegen, -2, 4, "iRow", SimTypeLong(False))
    codegen.cfunc.unified_local_vars = {
        boundary_var: {(boundary_cvar, SimTypeLong(False))},
    }
    fact = StackAggregateObjectFact8616(-82, 80, 1, 82, 1, 2, (-83, -82), -2, 2)
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=5,
        normalized_fact_count=5,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert base_cvar.variable_type.length == 80
    assert boundary_var.size == 4
    assert boundary_cvar.variable_type == SimTypeShort(False).with_arch(codegen.project.arch)
    assert next(iter(codegen.cfunc.unified_local_vars[boundary_var]))[1] == SimTypeShort(
        False
    ).with_arch(codegen.project.arch)


def test_materialization_supports_addressed_top_partition(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(codegen, -44, 1, "achT", SimTypeChar(False))
    boundary_var, boundary_cvar = _stack_cvar(
        codegen,
        -46,
        4,
        "cSpace",
        SimTypeLong(False),
    )
    codegen.cfunc.unified_local_vars = {
        boundary_var: {(boundary_cvar, SimTypeLong(False))},
    }
    call = structured_c.CFunctionCall(
        "memset",
        None,
        (structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([call], codegen=codegen)
    fact = StackAggregateObjectFact8616(
        -44,
        44,
        1,
        46,
        3,
        1,
        (-44,),
        -46,
        2,
        StackAggregateEvidenceKind8616.ADDRESSED_PARTITION,
    )
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=6,
        normalized_fact_count=6,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert base_cvar.variable_type.length == 44
    assert boundary_cvar.variable_type == SimTypeShort(False).with_arch(codegen.project.arch)
    assert next(iter(codegen.cfunc.unified_local_vars[boundary_var]))[1] == SimTypeShort(
        False
    ).with_arch(codegen.project.arch)
    assert call.args == [base_cvar]


def test_materialization_promotes_projected_entry_sp_aggregate_base(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    codegen._inertia_vex_ir_frame = proven_frame_coordinate(-2)
    base_var, base_cvar = _stack_cvar(
        codegen,
        -92,
        2,
        "local_5a",
        SimTypeShort(False),
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=base_var,
        cvar=base_cvar,
        bp_offset=-90,
        entry_sp_offset=-92,
        size=2,
        display_name="local_5a",
    )
    fact = StackAggregateObjectFact8616(-90, 86, 2, 118, 0, 3, (-90,), -4, 2)
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=5,
        normalized_fact_count=5,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert isinstance(base_cvar.variable_type, SimTypeFixedSizeArray)
    assert base_cvar.variable_type.length == 43
    assert base_var.size == 2
    assert len(codegen.cfunc.variables_in_use) == 1
    assert machine_bp_offset_for_stack_variable_8616(codegen, base_var) == -90
    regenerated = SimStackVariable(-92, 86, base="bp", name="local_5a")
    assert machine_bp_offset_for_stack_variable_8616(codegen, regenerated) == -90


def test_materialization_creates_missing_base_at_projected_entry_sp(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    codegen._inertia_vex_ir_frame = proven_frame_coordinate(-2)
    boundary_var, boundary_cvar = _stack_cvar(
        codegen,
        -4,
        2,
        "local_2",
        SimTypeShort(False),
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=boundary_var,
        cvar=boundary_cvar,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
        display_name="local_2",
    )
    fact = StackAggregateObjectFact8616(-82, 80, 1, 82, 1, 2, (-83, -82), -2, 2)
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=5,
        normalized_fact_count=5,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    aggregate_vars = tuple(
        variable
        for variable in codegen.cfunc.variables_in_use
        if isinstance(variable, SimStackVariable) and variable.size == 80
    )
    assert len(aggregate_vars) == 1
    assert aggregate_vars[0].offset == -84
    assert machine_bp_offset_for_stack_variable_8616(codegen, aggregate_vars[0]) == -82


def test_materialization_decays_addressed_stack_array_call_argument(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(codegen, -82, 80, "achTmp", SimTypeChar(False))
    stale_operand = structured_c.CVariable(
        SimStackVariable(-82, 2, base="bp", name="local_52"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        "memset",
        None,
        (structured_c.CUnaryOp("Reference", stale_operand, codegen=codegen),),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([call], codegen=codegen)
    fact = StackAggregateObjectFact8616(-82, 80, 1, 82, 1, 2, (-83, -82), -2, 2)
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=5,
        normalized_fact_count=5,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert call.args == [base_cvar]
    assert codegen._inertia_stack_aggregate_call_decay_8616.materialized_count == 1
    assert codegen._inertia_stack_aggregate_call_decay_8616.failure_count == 0


def test_materialization_decays_nested_addressed_stack_array_call_argument(monkeypatch) -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(codegen, -44, 1, "achT", SimTypeChar(False))
    stale_operand = structured_c.CVariable(
        SimStackVariable(-44, 2, base="bp", name="local_2c"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    pointer = structured_c.CBinaryOp(
        "Add",
        structured_c.CUnaryOp("Reference", stale_operand, codegen=codegen),
        structured_c.CConstant(3, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        "memset",
        None,
        (pointer,),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([call], codegen=codegen)
    fact = StackAggregateObjectFact8616(
        -44,
        44,
        1,
        46,
        3,
        1,
        (-44,),
        -46,
        2,
        StackAggregateEvidenceKind8616.ADDRESSED_PARTITION,
    )
    recovery = StackAggregateRecovery8616(
        StackAggregateRecoveryStatus8616.MATERIALIZABLE,
        raw_fact_count=6,
        normalized_fact_count=6,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        facts=(fact,),
    )
    monkeypatch.setattr(
        aggregate_objects,
        "collect_stack_aggregate_object_facts_8616",
        lambda *_args, **_kwargs: recovery,
    )

    assert materialize_stack_aggregate_objects_8616(codegen, object(), object()) is True
    assert pointer.lhs is base_cvar
    assert call.args == [pointer]
    assert codegen._inertia_stack_aggregate_call_decay_8616.materialized_count == 1
    assert codegen._inertia_stack_aggregate_call_decay_8616.failure_count == 0


def test_final_decay_replays_after_call_argument_regeneration_and_is_idempotent() -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(
        codegen,
        -82,
        80,
        "achTmp",
        SimTypeFixedSizeArray(SimTypeChar(False), 80).with_arch(codegen.project.arch),
    )
    stale_operand = structured_c.CVariable(
        SimStackVariable(-82, 2, base="bp", name="local_52"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        "memset",
        None,
        (structured_c.CUnaryOp("Reference", stale_operand, codegen=codegen),),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([call], codegen=codegen)
    fact = StackAggregateObjectFact8616(-82, 80, 1, 82, 1, 2, (-83, -82), -2, 2)
    codegen._inertia_stack_aggregate_object_facts_8616 = (fact,)
    codegen._inertia_stack_aggregate_cvars_8616 = {-82: base_cvar}

    assert decay_stack_aggregate_call_arguments_8616(codegen) is True
    assert call.args == [base_cvar]
    assert codegen._inertia_stack_aggregate_call_decay_8616.materialized_count == 1
    assert decay_stack_aggregate_call_arguments_8616(codegen) is False
    assert call.args == [base_cvar]
    assert codegen._inertia_stack_aggregate_call_decay_8616.failure_count == 0


def test_frame_object_type_replays_after_cfunction_regeneration() -> None:
    codegen = _AggregateCodegen()
    current_var, current_cvar = _stack_cvar(
        codegen,
        -44,
        2,
        "local_2c",
        SimTypeShort(False),
    )
    variable_manager = _VariableManager()
    variable_manager.set_variable_type(current_var, SimTypeShort(False))
    codegen.cfunc.variable_manager = variable_manager
    stale_codegen = _AggregateCodegen()
    _stale_var, stale_cvar = _stack_cvar(
        stale_codegen,
        -44,
        44,
        "local_2c",
        SimTypeFixedSizeArray(SimTypeChar(False), 44),
    )
    fact = StackAggregateObjectFact8616(
        -44,
        44,
        1,
        46,
        2,
        1,
        (-44,),
        -46,
        2,
        StackAggregateEvidenceKind8616.ADDRESSED_PARTITION,
    )
    codegen._inertia_stack_aggregate_object_facts_8616 = (fact,)
    codegen._inertia_stack_aggregate_cvars_8616 = {-44: stale_cvar}
    codegen.cfunc.unified_local_vars = {
        current_var: {(current_cvar, SimTypeShort(False))}
    }

    changed = reapply_stack_aggregate_object_facts_8616(codegen)

    assert changed is True
    assert isinstance(current_cvar.variable_type, SimTypeFixedSizeArray)
    assert current_cvar.variable_type.length == 44
    persisted_type = variable_manager.get_variable_type(current_var)
    assert isinstance(persisted_type, SimTypeFixedSizeArray)
    assert persisted_type.length == 44
    refreshed_type = next(iter(codegen.cfunc.unified_local_vars[current_var]))[1]
    assert isinstance(refreshed_type, SimTypeFixedSizeArray)
    assert refreshed_type.length == 44
    stats = codegen._inertia_stack_aggregate_object_replay_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert reapply_stack_aggregate_object_facts_8616(codegen) is False


def test_indexed_destination_consumes_exact_aggregate_displacement_evidence() -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(
        codegen,
        -82,
        1,
        "achTmp",
        SimTypeFixedSizeArray(SimTypeChar(False), 80).with_arch(codegen.project.arch),
    )
    _indexed_var, indexed_cvar = _stack_cvar(codegen, -83, 1, "local_53", SimTypeChar(False))
    aggregate = StackAggregateObjectFact8616(-82, 80, 1, 82, 1, 2, (-83, -82), -2, 2)
    codegen._inertia_stack_aggregate_object_facts_8616 = (aggregate,)
    codegen._inertia_stack_aggregate_cvars_8616 = {-82: base_cvar}
    fact = DirectStackMoveFact8616(
        dst_offset=-83,
        width=1,
        source_kind=DirectStackMoveSourceKind8616.IMMEDIATE,
        ins_addr=0x1234,
        source_value=0,
        dst_index_immediate=3,
    )

    destination = _direct_stack_move_destination_expr_8616(codegen, fact, indexed_cvar)

    assert isinstance(destination, structured_c.CIndexedVariable)
    assert destination.variable is base_cvar
    assert isinstance(destination.index, structured_c.CBinaryOp)
    assert destination.index.op == "Sub"
    assert destination.index.lhs.value == 3
    assert destination.index.rhs.value == 1


def test_word_aggregate_destination_requires_matching_index_byte_scale() -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(
        codegen,
        -90,
        86,
        "aTemp",
        SimTypeFixedSizeArray(SimTypeShort(False), 43).with_arch(codegen.project.arch),
    )
    _indexed_var, indexed_cvar = _stack_cvar(codegen, -90, 2, "local_5a", SimTypeShort(False))
    _index_var, index_cvar = _stack_cvar(codegen, -2, 2, "iRow", SimTypeShort(False))
    aggregate = StackAggregateObjectFact8616(-90, 86, 2, 118, 0, 3, (-90,), -4, 2)
    codegen._inertia_stack_aggregate_object_facts_8616 = (aggregate,)
    codegen._inertia_stack_aggregate_cvars_8616 = {-90: base_cvar}
    fact = DirectStackMoveFact8616(
        dst_offset=-90,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.IMMEDIATE,
        ins_addr=0x1234,
        source_value=0,
        dst_index_stack_offset=-2,
        dst_index_byte_scale=2,
    )

    destination = _direct_stack_move_destination_expr_8616(codegen, fact, indexed_cvar)

    assert isinstance(destination, structured_c.CIndexedVariable)
    assert destination.variable is base_cvar
    assert destination.index is index_cvar
    refused = _direct_stack_move_destination_expr_8616(
        codegen,
        DirectStackMoveFact8616(
            dst_offset=-90,
            width=2,
            source_kind=DirectStackMoveSourceKind8616.IMMEDIATE,
            ins_addr=0x1234,
            source_value=0,
            dst_index_stack_offset=-2,
            dst_index_byte_scale=1,
        ),
        indexed_cvar,
    )
    assert refused is None


def test_word_aggregate_source_consumes_matching_index_byte_scale() -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(
        codegen,
        -90,
        86,
        "aTemp",
        SimTypeFixedSizeArray(SimTypeShort(False), 43).with_arch(codegen.project.arch),
    )
    _index_var, index_cvar = _stack_cvar(codegen, -118, 2, "iRand", SimTypeShort(False))
    aggregate = StackAggregateObjectFact8616(-90, 86, 2, 118, 0, 3, (-90,), -4, 2)
    codegen._inertia_stack_aggregate_object_facts_8616 = (aggregate,)
    codegen._inertia_stack_aggregate_cvars_8616 = {-90: base_cvar}
    fact = DirectStackMoveFact8616(
        dst_offset=-114,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
        ins_addr=0x1234,
        source_aggregate_base_offset=-90,
        source_index_offset=-118,
        source_index_byte_scale=2,
        source_access_width=2,
    )

    source = _direct_stack_move_source_expr_8616(codegen, fact)

    assert isinstance(source, structured_c.CIndexedVariable)
    assert source.variable is base_cvar
    assert source.index is index_cvar


def test_prunes_pure_scalar_aggregate_carrier_tagged_to_push_effect() -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(codegen, -82, 1, "achTmp", SimTypeChar(False))
    _source_var, source_cvar = _stack_cvar(codegen, -4, 2, "carrier", SimTypeShort(False))
    shift = structured_c.CBinaryOp(
        "Shr",
        source_cvar,
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(base_cvar, shift, codegen=codegen, tags={"ins_addr": 0x101})
    codegen.cfunc.statements = SimpleNamespace(statements=[assignment])
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        StackAggregateObjectFact8616(-82, 80, 1, 82, 1, 2, (-83, -82), -2, 2),
    )

    changed = prune_nonmemory_stack_aggregate_carriers_8616(
        codegen,
        (_Instruction(X86_INS_PUSH, (), "push", address=0x100, size=2),),
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    assert codegen._inertia_stack_aggregate_carrier_prune_8616.raw_fact_count == 1
    assert codegen._inertia_stack_aggregate_carrier_prune_8616.classified_fact_count == 1
    assert codegen._inertia_stack_aggregate_carrier_prune_8616.materialized_count == 1
    assert codegen._inertia_stack_aggregate_carrier_prune_8616.failure_count == 0


def test_keeps_scalar_aggregate_assignment_without_push_or_call_proof() -> None:
    codegen = _AggregateCodegen()
    _base_var, base_cvar = _stack_cvar(codegen, -82, 1, "achTmp", SimTypeChar(False))
    assignment = structured_c.CAssignment(
        base_cvar,
        structured_c.CConstant(7, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    codegen.cfunc.statements = SimpleNamespace(statements=[assignment])
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        StackAggregateObjectFact8616(-82, 80, 1, 82, 1, 2, (-83, -82), -2, 2),
    )

    changed = prune_nonmemory_stack_aggregate_carriers_8616(
        codegen,
        (_Instruction(X86_INS_MOV, (), "mov", address=0x100, size=1),),
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [assignment]
    assert codegen._inertia_stack_aggregate_carrier_prune_8616.raw_fact_count == 1
    assert codegen._inertia_stack_aggregate_carrier_prune_8616.classified_fact_count == 0

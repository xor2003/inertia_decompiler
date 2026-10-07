from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa
import inertia.lowering.stack_memory_ssa as stack_memory_lowering
from inertia.lowering.stack_lowering_result import (
    StackLoweringResult,
    StackLoweringStatus,
    StackSlotFailure,
)
from inertia.lowering.stack_memory_ssa import (
    StackMemoryObjectKind8616,
    StackMemorySSALoweringRefusalKind8616,
    lower_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)
from inertia.pipeline.errors import PipelineHardError

from inertia.alias.stack_memory_ssa import build_x86_16_stack_memory_ssa_alias_artifact
from inertia.widening.stack_memory_objects import (
    build_x86_16_stack_memory_object_widening_artifact,
)


def _bp_slot(offset: int, size: int = 2) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )


def _stack_alias_artifact(offset: int = -2):
    slot = _bp_slot(offset)
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=0x1000,
            blocks=(
                IRBlock(
                    addr=0x1000,
                    instrs=(
                        IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=1, size=2)), size=2),
                        IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (slot,), size=2),
                    ),
                ),
            ),
        )
    )
    return build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)


def _stack_alias_artifact_for_instructions(instructions):
    return build_x86_16_stack_memory_ssa_alias_artifact(
        build_x86_16_function_ssa(
            IRFunctionArtifact(
                function_addr=0x1000,
                blocks=(IRBlock(addr=0x1000, instrs=instructions),),
            )
        )
    )


class _FakeCodegen:
    def __init__(self, source) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(
            addr=source.function_addr,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
            sort_local_vars=lambda: None,
        )
        self._inertia_stack_memory_ssa_alias_artifact = source
        if source.accesses:
            self._inertia_stack_memory_object_widening_artifact = (
                build_x86_16_stack_memory_object_widening_artifact(source)
            )
        self._inertia_vex_ir_frame = FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                status=FrameCoordinateStatus8616.PROVEN,
                bp_entry_sp_delta=-2,
                detail="test fixture",
                stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
            )
        )
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_stack_memory_ssa_lowering_materializes_real_stack_cvariable() -> None:
    codegen = _FakeCodegen(_stack_alias_artifact())
    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)
    assert artifact is not None and artifact.complete is True
    assert artifact.stats.raw_fact_count == artifact.stats.materialized_count == 1
    assert artifact.stats.failure_count == 0
    assert artifact.candidates[0].role is StackMemoryObjectKind8616.LOCAL
    assert artifact.candidates[0].versions == (1,)
    stack_variables = [variable for variable in codegen.cfunc.variables_in_use if isinstance(variable, SimStackVariable)]
    assert len(stack_variables) == 1
    assert stack_variables[0].base == "bp"
    assert stack_variables[0].offset == -4
    assert machine_bp_offset_for_stack_variable_8616(codegen, stack_variables[0]) == -2
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(
        stack_variables[0]
    )
    assert projection is not None and projection.entry_sp_offset == -4
    assert isinstance(codegen.cfunc.variables_in_use[stack_variables[0]].variable_type, SimTypeShort)
    assert artifact.candidates[0].entry_sp_offset == -4
    assert artifact.result is not None and artifact.result.materialized[0][0] == -2
    assert len(codegen._inertia_semantic_alias_facts) == 1


def test_stack_memory_ssa_local_replay_preserves_distinct_argument_coordinates() -> None:
    codegen = _FakeCodegen(_stack_alias_artifact())
    left = SimStackVariable(2, 2, base="bp", name="arg_4", region=0x1000)
    right = SimStackVariable(4, 2, base="bp", name="arg_6", region=0x1000)
    left_cvar = CVariable(left, variable_type=SimTypeShort(False), codegen=codegen)
    right_cvar = CVariable(right, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.arg_list = (left_cvar, right_cvar)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=left,
        cvar=left_cvar,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=right,
        cvar=right_cvar,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete is True
    assert machine_bp_offset_for_stack_variable_8616(codegen, left) == 4
    assert machine_bp_offset_for_stack_variable_8616(codegen, right) == 6
    registry = stack_variable_coordinate_registry_8616(codegen)
    assert registry.for_bp_range(4, 2) is not None
    assert registry.for_bp_range(6, 2) is not None


def test_stack_memory_ssa_lowering_refuses_unproven_frame_coordinate() -> None:
    codegen = _FakeCodegen(_stack_alias_artifact())
    codegen._inertia_vex_ir_frame = FrameAccessArtifact()

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete is True
    assert artifact.candidates == ()
    assert artifact.refusals[0].kind is StackMemorySSALoweringRefusalKind8616.FRAME_COORDINATE_UNPROVEN
    assert codegen.cfunc.variables_in_use == {}


def test_stack_memory_ssa_lowering_reuses_proven_entry_sp_projection() -> None:
    codegen = _FakeCodegen(_stack_alias_artifact())
    projected = SimStackVariable(-4, 1, base="bp", name="projected", region=0x1000)
    projected_cvar = CVariable(projected, codegen=codegen)
    codegen.cfunc.variables_in_use[projected] = projected_cvar
    codegen.cfunc.unified_local_vars[projected] = set()

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete is True
    assert artifact.projection_retirement.complete is True
    assert artifact.projection_retirement.retired == ()
    assert projected in codegen.cfunc.variables_in_use
    assert projected.size == 2
    assert projected in codegen.cfunc.unified_local_vars


def test_stack_memory_ssa_lowering_defers_positive_argument_ranges() -> None:
    codegen = _FakeCodegen(_stack_alias_artifact(offset=4))

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete is True
    assert artifact.candidates == ()
    assert artifact.refusals[0].kind is StackMemorySSALoweringRefusalKind8616.ARGUMENT_STORAGE_TRIAL_REQUIRED
    assert codegen.cfunc.variables_in_use == {}


def test_stack_memory_ssa_lowering_refuses_frame_control_storage() -> None:
    codegen = _FakeCodegen(_stack_alias_artifact(offset=0))

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete is True
    assert artifact.candidates == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    assert artifact.refusals[0].kind is StackMemorySSALoweringRefusalKind8616.FRAME_CONTROL_SLOT
    assert codegen.cfunc.variables_in_use == {}


@pytest.mark.parametrize(
    ("source", "overlap_count"),
    [
        (
            _stack_alias_artifact_for_instructions(
                (
                    IRInstr("STORE", None, (_bp_slot(-2), IRValue(MemSpace.CONST, const=1, size=2)), size=2),
                    IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),)),
                    IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (_bp_slot(-2),), size=2),
                )
            ),
            0,
        ),
        (
            _stack_alias_artifact_for_instructions(
                (
                    IRInstr(
                        "LOAD",
                        IRValue(MemSpace.REG, name="ax", size=2),
                        (
                            IRAddress(
                                MemSpace.SS,
                                base=("sp",),
                                offset=2,
                                size=2,
                                status=AddressStatus.PROVISIONAL,
                                segment_origin=SegmentOrigin.DEFAULTED,
                            ),
                        ),
                        size=2,
                    ),
                )
            ),
            0,
        ),
    ],
)
def test_stack_memory_ssa_lowering_preserves_upstream_refusals(source, overlap_count: int) -> None:
    codegen = _FakeCodegen(source)

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete is True
    assert len(source.overlaps) == overlap_count
    assert artifact.candidates == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == len(source.refusals)
    assert {refusal.kind for refusal in artifact.refusals} == {
        StackMemorySSALoweringRefusalKind8616.SOURCE_ALIAS_REFUSAL
    }
    assert codegen.cfunc.variables_in_use == {}


def test_stack_memory_ssa_lowering_refuses_partial_composed_byte_views() -> None:
    source = _stack_alias_artifact_for_instructions(
        (
            IRInstr(
                "STORE",
                None,
                (_bp_slot(-4), IRValue(MemSpace.CONST, const=1, size=2)),
                size=2,
            ),
            IRInstr(
                "LOAD",
                IRValue(MemSpace.REG, name="ax", size=2),
                (_bp_slot(-3),),
                size=2,
            ),
        )
    )
    codegen = _FakeCodegen(source)

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete is True
    assert source.refusals == ()
    assert len(source.accesses) == 2
    assert len(source.overlaps) == 1
    assert artifact.candidates == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    assert {refusal.kind for refusal in artifact.refusals} == {
        StackMemorySSALoweringRefusalKind8616.SOURCE_WIDENING_REFUSAL
    }
    assert {(address.offset, address.size) for address in artifact.refusals[0].related_addresses} >= {
        (-4, 2),
        (-3, 2),
    }
    assert codegen.cfunc.variables_in_use == {}


def test_stack_memory_ssa_lowering_materializes_nested_byte_view_owner() -> None:
    word = _bp_slot(-4)
    high_byte = _bp_slot(-3, size=1)
    source = _stack_alias_artifact_for_instructions(
        (
            IRInstr(
                "STORE",
                None,
                (word, IRValue(MemSpace.CONST, const=1, size=2)),
                size=2,
            ),
            IRInstr(
                "LOAD",
                IRValue(MemSpace.REG, name="al", size=1),
                (high_byte,),
                size=1,
            ),
        )
    )
    codegen = _FakeCodegen(source)

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete is True
    assert artifact.refusals == ()
    assert len(artifact.candidates) == 1
    candidate = artifact.candidates[0]
    assert (candidate.address.offset, candidate.address.size) == (-4, 2)
    assert candidate.versions == (1, 2)
    stack_variables = [
        variable for variable in codegen.cfunc.variables_in_use if isinstance(variable, SimStackVariable)
    ]
    assert [(variable.offset, variable.size) for variable in stack_variables] == [(-6, 2)]
    assert isinstance(codegen.cfunc.variables_in_use[stack_variables[0]].variable_type, SimTypeShort)


def test_stack_memory_ssa_lowering_hard_fails_composed_access_without_widening() -> None:
    word = _bp_slot(-4)
    high_byte = _bp_slot(-3, size=1)
    source = _stack_alias_artifact_for_instructions(
        (
            IRInstr(
                "STORE",
                None,
                (word, IRValue(MemSpace.CONST, const=1, size=2)),
                size=2,
            ),
            IRInstr("LOAD", IRValue(MemSpace.REG, name="al", size=1), (high_byte,), size=1),
        )
    )
    codegen = _FakeCodegen(source)
    del codegen._inertia_stack_memory_object_widening_artifact

    with pytest.raises(PipelineHardError, match="before Widening"):
        lower_x86_16_stack_memory_ssa_alias_artifact(codegen)


def test_stack_memory_ssa_lowering_hard_fails_missing_materialization(monkeypatch) -> None:
    codegen = _FakeCodegen(_stack_alias_artifact())
    monkeypatch.setattr(
        stack_memory_lowering,
        "lower_stack_accesses_from_alias_facts_8616",
        lambda *_args, **_kwargs: StackLoweringResult(
            status=StackLoweringStatus.PARTIAL,
            failures=[StackSlotFailure(-2, 2, "not materialized")],
        ),
    )

    with pytest.raises(PipelineHardError, match="not fully materialized"):
        lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    artifact = codegen._inertia_stack_memory_ssa_lowering_artifact
    assert artifact.complete is False
    assert artifact.stats.classified_fact_count == 1
    assert artifact.stats.materialized_count == 0
    assert artifact.stats.failure_count == 1

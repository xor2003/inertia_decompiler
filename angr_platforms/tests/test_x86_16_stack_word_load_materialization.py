from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.rustylib.ailment import Tags
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from angr_platforms.X86_16.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.lowering.stack_word_load_materialization import (
    StackWordLoadRefusalKind8616,
    materialize_stack_word_load_recompositions_8616,
)


class _Codegen:
    def __init__(self, source: object) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self._inertia_stack_memory_ssa_alias_artifact = source
        self.cstyle_null_cmp = False
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _stack_address(offset: int) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )


def _alias_artifact(*accesses: tuple[int, int]):
    return build_x86_16_stack_memory_ssa_alias_artifact(
        build_x86_16_function_ssa(
            IRFunctionArtifact(
                function_addr=0x1000,
                blocks=(
                    IRBlock(
                        addr=0x1000,
                        instrs=tuple(
                            IRInstr(
                                "LOAD",
                                IRValue(MemSpace.REG, name="ax", size=2),
                                (_stack_address(offset),),
                                size=2,
                                addr=instruction_addr,
                            )
                            for instruction_addr, offset in accesses
                        ),
                    ),
                ),
            )
        )
    )


def _projection(
    codegen: _Codegen,
    *,
    bp_offset: int = -2,
    high_operand: object | None = None,
    tags: object | None = None,
) -> tuple[structured_c.CVariable, structured_c.CBinaryOp]:
    variable = SimStackVariable(-4, 2, base="bp", name="local_2")
    cvar = structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=bp_offset,
        entry_sp_offset=-4,
        size=2,
    )
    operand = (
        high_operand
        if high_operand is not None
        else structured_c.CConstant(0x1234, SimTypeShort(False), codegen=codegen)
    )
    high = structured_c.CUnaryOp(
        "Dereference",
        operand,
        codegen=codegen,
        tags=tags or {},
    )
    shifted = structured_c.CBinaryOp(
        "Shl",
        high,
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    return cvar, structured_c.CBinaryOp("Or", cvar, shifted, codegen=codegen)


def test_stack_word_load_materializes_exact_alias_projection() -> None:
    source = _alias_artifact((0x1010, -2))
    codegen = _Codegen(source)
    cvar, root = _projection(codegen, tags=Tags({"ins_addr": 0x1010}))

    result = materialize_stack_word_load_recompositions_8616(codegen, root)

    assert result.root is cvar
    assert result.changed is True
    assert result.artifact.complete is True
    assert result.artifact.stats.raw_fact_count == 1
    assert result.artifact.stats.materialized_count == 1
    assert result.artifact.refusals == ()


@pytest.mark.parametrize("captured_half", [None, "low", "high", "both"])
def test_stack_word_load_uses_tagged_canonical_argument_projection(captured_half) -> None:
    codegen = _Codegen(_alias_artifact((0x1010, 4)))
    owner_variable = SimStackVariable(2, 2, base="bp", name="lhs")
    owner = structured_c.CVariable(owner_variable, codegen=codegen)
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=owner_variable, cvar=owner,
        bp_offset=4, entry_sp_offset=2, size=2,
    )
    low = structured_c.CUnaryOp(
        "Dereference", structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen), codegen=codegen
    )
    high = structured_c.CUnaryOp(
        "Dereference", structured_c.CConstant(0x101, SimTypeShort(False), codegen=codegen), codegen=codegen
    )
    if captured_half in {"low", "both"}:
        low = structured_c.CVariable(SimRegisterVariable(0, 1), codegen=codegen)
    if captured_half in {"high", "both"}:
        high = structured_c.CVariable(SimRegisterVariable(1, 1), codegen=codegen)
    root = structured_c.CBinaryOp(
        "Or", low,
        structured_c.CBinaryOp(
            "Mul", high,
            structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen, tags=Tags({"ins_addr": 0x1010}),
    )

    result = materialize_stack_word_load_recompositions_8616(codegen, root)

    assert result.root is (owner if captured_half is None else root)
    assert result.changed is (captured_half is None)
    assert result.artifact.complete
    if captured_half is not None:
        assert result.artifact.refusals[0].kind is StackWordLoadRefusalKind8616.CAPTURED_VALUE


def test_stack_word_load_materializes_registered_byte_pair_projection() -> None:
    codegen = _Codegen(_alias_artifact())
    owner, _unused = _projection(codegen)
    high_variable = SimStackVariable(-3, 1, base="bp", name="local_3")
    high = structured_c.CVariable(
        high_variable,
        variable_type=SimTypeChar(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    root = structured_c.CBinaryOp(
        "Or",
        owner,
        structured_c.CBinaryOp(
            "Mul",
            high,
            structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    result = materialize_stack_word_load_recompositions_8616(codegen, root)

    assert result.root is owner
    assert result.changed is True
    assert result.artifact.complete is True
    assert result.artifact.stats.raw_fact_count == 1
    assert result.artifact.stats.materialized_count == 1
    assert result.artifact.refusals == ()


def test_stack_word_load_materializes_argument_through_proven_frame_coordinate() -> None:
    codegen = _Codegen(_alias_artifact((0x1010, 4)))
    variable = SimStackVariable(2, 1, base="bp", name="arg_4")
    cvar = structured_c.CVariable(
        variable,
        variable_type=SimTypeChar(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={variable: cvar},
        unified_local_vars={},
        arg_list=(cvar,),
        sort_local_vars=lambda: None,
    )
    codegen._inertia_vex_ir_frame = FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=-2,
            detail="test fixture",
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        )
    )
    high = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CConstant(0x1234, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1010},
    )
    root = structured_c.CBinaryOp(
        "Or",
        cvar,
        structured_c.CBinaryOp(
            "Shl",
            high,
            structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    result = materialize_stack_word_load_recompositions_8616(codegen, root)

    assert result.root is cvar
    assert result.changed is True
    assert result.artifact.complete is True
    assert variable.size == 2
    assert isinstance(cvar.variable_type, SimTypeChar)


def test_stack_word_load_retains_same_owner_without_logical_identity() -> None:
    codegen = _Codegen(_alias_artifact())
    owner, _unused = _projection(codegen)
    root = structured_c.CBinaryOp(
        "Or",
        owner,
        structured_c.CBinaryOp(
            "Mul",
            owner,
            structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    result = materialize_stack_word_load_recompositions_8616(codegen, root)

    assert result.root is root
    assert result.changed is False
    assert result.artifact.refusals[0].kind is (
        StackWordLoadRefusalKind8616.NO_INSTRUCTION_PROVENANCE
    )


@pytest.mark.parametrize(
    ("accesses", "tags", "bp_offset", "expected"),
    [
        (
            ((0x1010, -2),),
            {},
            -2,
            StackWordLoadRefusalKind8616.NO_INSTRUCTION_PROVENANCE,
        ),
        (
            ((0x1010, -2), (0x1020, -4)),
            {"inertia_source_instruction_addrs": (0x1010, 0x1020)},
            -2,
            StackWordLoadRefusalKind8616.ALIAS_LOAD_AMBIGUOUS,
        ),
        (
            ((0x1010, -2),),
            {"ins_addr": 0x1020},
            -2,
            StackWordLoadRefusalKind8616.ALIAS_LOAD_MISSING,
        ),
        (
            ((0x1010, -2),),
            {"ins_addr": 0x1010},
            -4,
            StackWordLoadRefusalKind8616.STACK_PROJECTION_MISMATCH,
        ),
    ],
)
def test_stack_word_load_retains_unproven_projection(
    accesses: tuple[tuple[int, int], ...],
    tags: dict[str, object],
    bp_offset: int,
    expected: StackWordLoadRefusalKind8616,
) -> None:
    codegen = _Codegen(_alias_artifact(*accesses))
    _cvar, root = _projection(codegen, bp_offset=bp_offset, tags=tags)

    result = materialize_stack_word_load_recompositions_8616(codegen, root)

    assert result.root is root
    assert result.changed is False
    assert result.artifact.complete is True
    assert result.artifact.stats.failure_count == 1
    assert result.artifact.refusals[0].kind is expected


def test_stack_word_load_retains_side_effectful_high_operand() -> None:
    codegen = _Codegen(_alias_artifact((0x1010, -2)))
    call = structured_c.CFunctionCall(
        "side_effect",
        SimpleNamespace(name="side_effect", prototype=None),
        [],
        codegen=codegen,
    )
    _cvar, root = _projection(
        codegen,
        high_operand=call,
        tags={"ins_addr": 0x1010},
    )

    result = materialize_stack_word_load_recompositions_8616(codegen, root)

    assert result.root is root
    assert result.changed is False
    assert result.artifact.refusals[0].kind is (
        StackWordLoadRefusalKind8616.SIDE_EFFECTFUL_HIGH
    )

"""Typed split-return condition selection and refusal boundaries."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.ir import IRAddress, IRInstr, IRValue, MemSpace
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.function_ssa_registry import (
    function_ssa_artifact_at_address_8616,
)
from inertia.ir.instruction_origin import IRInstructionOrigin8616
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY, Lifter86_16  # noqa: F401
from inertia.lowering.condition_transfer import (
    collect_typed_condition_artifacts_8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrialSignedness8616,
)
from inertia.lowering.interprocedural_storage_return_defs import (
    resolve_call_output_definitions_8616,
)
from inertia.lowering.interprocedural_storage_return_split import (
    classify_split_return_storage_8616,
)
from inertia.lowering.interprocedural_storage_return_split_conditions import (
    select_split_return_condition_8616,
)
from inertia.lowering.interprocedural_storage_return_type_contracts import (
    ReturnStorageTypeFailure8616,
    ReturnStorageTypeResult8616,
    SplitReturnRelation8616,
)
from tests.lowering.x86_16_native_call_fixtures import retain_native_call_index_8616


def _storage(register: str) -> StorageIdentity8616:
    """Build one exact full-word return register identity."""
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=2,
        register=register,
    )


def _conditions() -> tuple[ConditionIR, ConditionIR, ConditionIR]:
    """Build one canonical signed DX:AX <= SS:BP wide comparison."""
    high_register = IRValue(
        space=MemSpace.REG,
        name="dx",
        offset=4,
        size=2,
    )
    low_register = IRValue(
        space=MemSpace.REG,
        name="ax",
        offset=0,
        size=2,
    )
    high_stack = IRValue(
        space=MemSpace.SS,
        name="bp",
        offset=-2,
        size=2,
        expr=("cmp-stack", "bp"),
    )
    low_stack = replace(high_stack, offset=-4)
    return (
        ConditionIR(
            op="sle",
            lhs=high_register,
            rhs=high_stack,
            width_bits=16,
            src_insn=0x1006,
            block_addr=0x1003,
            producer_insn=0x1003,
            taken_target=0x100A,
            fallthrough_target=0x1008,
        ),
        ConditionIR(
            op="sge",
            lhs=high_register,
            rhs=high_stack,
            width_bits=16,
            src_insn=0x100A,
            block_addr=0x100A,
            producer_insn=0x1003,
            taken_target=0x100E,
            fallthrough_target=0x100C,
        ),
        ConditionIR(
            op="ule",
            lhs=low_register,
            rhs=low_stack,
            width_bits=16,
            src_insn=0x1011,
            block_addr=0x100E,
            producer_insn=0x100E,
            taken_target=0x1014,
            fallthrough_target=0x1013,
        ),
    )


def _artifact(*, active_false_trampoline: bool = False) -> SSAFunctionArtifact:
    """Build the exact SSA CFG for the canonical wide condition chain."""
    active = (
        IRInstr(
            op="MOV",
            dst=IRValue(space=MemSpace.REG, name="bx", size=2, version=1),
            args=(IRValue(space=MemSpace.CONST, const=1, size=2),),
            size=2,
            addr=0x1008,
        ),
    )
    block_addrs = (0x1003, 0x1008, 0x100A, 0x100C, 0x100E, 0x1013, 0x1014)
    return SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=tuple(
            SSABlock(
                addr=addr,
                instrs=(active if addr == 0x1008 and active_false_trampoline else ()),
                bindings=(),
            )
            for addr in block_addrs
        ),
        predecessor_map={
            0x1003: (),
            0x1008: (0x1003,),
            0x100A: (0x1003,),
            0x100C: (0x100A,),
            0x100E: (0x100A,),
            0x1013: (0x1008, 0x100E),
            0x1014: (0x100C, 0x100E),
        },
    )


def test_exact_split_condition_chain_retains_both_transparent_paths() -> None:
    candidate, failure = select_split_return_condition_8616(
        _artifact(),
        0x1003,
        _conditions(),
        _storage("dx"),
        _storage("ax"),
    )

    assert failure is None
    assert candidate is not None
    assert candidate.signedness is StorageTrialSignedness8616.SIGNED
    assert candidate.transparent_block_addrs == (0x1008, 0x100C)


def test_split_condition_refuses_semantically_active_trampoline() -> None:
    candidate, failure = select_split_return_condition_8616(
        _artifact(active_false_trampoline=True),
        0x1003,
        _conditions(),
        _storage("dx"),
        _storage("ax"),
    )

    assert candidate is None
    assert failure is ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE


@pytest.mark.parametrize("target", [0x1013, 0x1014, None, True])
def test_split_condition_transfer_requires_exact_cfg_target(target) -> None:
    """A retained JMP is transparent only with its exact constant successor."""
    artifact = _artifact()
    jump = IRInstr(
        op="JMP", dst=None,
        args=(IRValue(MemSpace.CONST, const=target, size=4),), addr=0x1008,
    )
    artifact = replace(artifact, blocks=tuple(
        replace(block, instrs=(jump,)) if block.addr == 0x1008 else block
        for block in artifact.blocks
    ))
    candidate, failure = select_split_return_condition_8616(
        artifact, 0x1003, _conditions(), _storage("dx"), _storage("ax"),
    )
    if target == 0x1013:
        assert failure is None
        assert candidate is not None
        assert candidate.transparent_block_addrs == (0x1008, 0x100C)
    else:
        assert candidate is None
        assert failure is ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE


@pytest.mark.parametrize("mutation", [
    "none", "version", "block", "unknown", "expression", "origin", "duplicate_origin", "origin_block",
])
def test_split_piece_witness_preserves_value_and_site_identity(mutation) -> None:
    """Repeated reads are one witness only for the same known direct SSA value."""
    from inertia.lowering.interprocedural_storage_contracts import (
        StorageTrialStats8616,
        StorageTrialValueClass8616,
    )
    from inertia.lowering.interprocedural_storage_return_split import (
        _piece_use_8616,
    )
    from inertia.lowering.interprocedural_storage_return_trial_materialization import (
        _witness_use_8616,
    )
    from inertia.lowering.interprocedural_storage_return_type_contracts import (
        ReturnStorageTypeResult8616,
        ReturnStorageTypeVerdict8616,
    )

    value = IRValue(MemSpace.REG, name="ax", size=2, version=0)
    other = value
    if mutation == "version":
        other = replace(value, version=1)
    elif mutation == "unknown":
        value = other = replace(value, version=None)
    elif mutation == "expression":
        value = other = replace(value, expr=("Iop_Sub16",))
    reads = tuple(
        IRInstr("MOV", None, (argument,), addr=0x100E,
                origin=IRInstructionOrigin8616(0x100E, index + 1))
        for index, argument in enumerate((value, other))
    )
    if mutation == "origin":
        reads = (reads[0], replace(reads[1], origin=None))
    elif mutation == "duplicate_origin":
        reads = (reads[0], replace(reads[1], origin=reads[0].origin))
    elif mutation == "origin_block":
        reads = (reads[0], replace(reads[1], origin=IRInstructionOrigin8616(0x2000, 2)))
    blocks = (SSABlock(0x100E, reads, ()),)
    if mutation == "block":
        blocks = (SSABlock(0x100E, reads[:1], ()), SSABlock(0x2000, reads[1:], ()))
    artifact = SSAFunctionArtifact(0x1000, blocks)
    condition = _conditions()[2]
    use, conflict = _piece_use_8616(artifact, _storage("ax"), condition, 0x1000)
    scalar_uses, scalar_conflict = _witness_use_8616(
        artifact,
        CallerReturnUseFact8616(
            caller_addr=0x1000, callsite_addr=0x1000,
            verdict=CallerReturnUseVerdict8616.USED,
            kind=CallsiteReturnUseKind8616.CONDITION, witness_instruction_addr=0x100E,
        ),
        ReturnStorageTypeResult8616(
            ReturnStorageTypeVerdict8616.PROVEN, StorageTrialSignedness8616.UNSIGNED,
            StorageTrialValueClass8616.VALUE, condition, None, StorageTrialStats8616(1, 1, 1, 1),
        ),
        (_storage("ax"),),
    )
    if mutation == "none":
        assert use is not None
        assert use.instr_index == 0
        assert not conflict
        assert scalar_uses == (use,)
        assert not scalar_conflict
    else:
        assert use is None
        assert scalar_uses is None


@pytest.mark.parametrize("index", range(3))
@pytest.mark.parametrize("field", ["block_addr", "taken_target", "fallthrough_target"])
def test_split_condition_refuses_each_missing_graph_coordinate(index, field) -> None:
    conditions = list(_conditions())
    conditions[index] = replace(conditions[index], **{field: None})
    candidate, failure = select_split_return_condition_8616(
        _artifact(), 0x1003, conditions, _storage("dx"), _storage("ax"),
    )
    assert candidate is None
    assert failure is ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE


def test_split_condition_refuses_nonadjacent_comparison_pieces() -> None:
    first, equal, low = _conditions()
    assert isinstance(low.rhs, IRValue)
    nonadjacent = replace(low, rhs=replace(low.rhs, offset=-6))

    candidate, failure = select_split_return_condition_8616(
        _artifact(),
        0x1003,
        (first, equal, nonadjacent),
        _storage("dx"),
        _storage("ax"),
    )

    assert candidate is None
    assert failure is ReturnStorageTypeFailure8616.SPLIT_OPERAND_CONFLICT


def _lifted_classification(
    code: bytes,
    block_addrs: set[int],
    registers: tuple[str, str] = ("ax", "dx"),
) -> ReturnStorageTypeResult8616:
    """Classify one real-lifter split CALL return with exact function bounds."""
    caller_addr = 0x1000
    callee_addr = 0x1020
    padding = bytes(callee_addr - caller_addr - len(code))
    lifted = angr.Project(
        io.BytesIO(code + padding + bytes.fromhex("b80100ba0200c3")),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": caller_addr,
            "entry_point": caller_addr,
        },
        auto_load_libs=False,
    )
    caller = SimpleNamespace(
        addr=caller_addr, block_addrs_set=block_addrs, info={},
        blocks=tuple(lifted.factory.block(address, opt_level=0) for address in sorted(block_addrs)),
    )
    callee = SimpleNamespace(addr=callee_addr, block_addrs_set={callee_addr}, info={})
    functions = SimpleNamespace(
        function=lambda addr, create=False: (
            caller if addr == caller_addr else callee if addr == callee_addr else None
        )
    )
    project = lifted
    project.kb.functions = functions
    callsite_index = retain_native_call_index_8616(project, caller_addr, caller_addr + len(code))
    original_cache = Instruction_ANY._inertia_module_condition_cache
    Instruction_ANY._inertia_module_condition_cache = {}
    try:
        artifact = function_ssa_artifact_at_address_8616(project, caller_addr).artifact
        conditions, _edges = collect_typed_condition_artifacts_8616(
            project,
            caller_addr,
        )
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
    assert artifact is not None
    fact = CallerReturnUseFact8616(
        caller_addr=caller_addr,
        callsite_addr=caller_addr,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=CallsiteReturnUseKind8616.CONDITION,
        witness_instruction_addr=0x1003,
    )
    output_storages = tuple(_storage(register) for register in registers)
    definitions = resolve_call_output_definitions_8616(
        artifact,
        fact,
        callee_addr,
        (callee_addr,),
        output_storages,
        project=project, callsite_index=callsite_index,
    )
    assert definitions.complete
    return classify_split_return_storage_8616(
        artifact,
        fact,
        definitions,
        output_storages,
        conditions,
    )


@pytest.mark.parametrize(
    ("machine_hex", "relation", "signedness"),
    [
        (
            "e81d003b56fe7c087f053b46fc7201c3c3",
            SplitReturnRelation8616.SLT,
            StorageTrialSignedness8616.SIGNED,
        ),
        (
            "e81d003b56fe720877053b46fc7201c3c3",
            SplitReturnRelation8616.ULT,
            StorageTrialSignedness8616.UNSIGNED,
        ),
    ],
)
@pytest.mark.parametrize("registers", [("ax", "dx"), ("dx", "ax")])
def test_real_lifter_strict_split_relations_materialize_exact_piece_uses(
    machine_hex: str,
    relation: SplitReturnRelation8616,
    signedness: StorageTrialSignedness8616,
    registers: tuple[str, str],
) -> None:
    result = _lifted_classification(
        bytes.fromhex(machine_hex),
        {0x1000, 0x1003, 0x1008, 0x100A, 0x100F, 0x1010},
        registers,
    )

    assert result.complete
    assert result.signedness is signedness
    assert result.split_condition_use is not None
    assert result.split_condition_use.relation is relation
    assert tuple(piece.storage.register for piece in result.split_condition_use.pieces) == registers
    expected = {"ax": 0x100A, "dx": 0x1003}
    assert tuple(piece.use.instr_addr for piece in result.split_condition_use.pieces) == tuple(expected[reg] for reg in registers)


@pytest.mark.parametrize(
    ("machine_hex", "relation"),
    [
        ("e81d003b56fe75053b46fc7401c3c3", SplitReturnRelation8616.EQ),
        ("e81d003b56fe75063b46fc7501c3c3", SplitReturnRelation8616.NE),
    ],
)
def test_real_lifter_equality_split_relations_retain_sign_insensitive_type(
    machine_hex: str,
    relation: SplitReturnRelation8616,
) -> None:
    result = _lifted_classification(
        bytes.fromhex(machine_hex),
        {0x1000, 0x1003, 0x1008, 0x100D, 0x100E},
    )

    assert result.complete
    assert result.signedness is StorageTrialSignedness8616.SIGN_INSENSITIVE
    assert result.split_condition_use is not None
    assert result.split_condition_use.relation is relation
    assert len(result.split_condition_use.conditions) == 2
    assert tuple(piece.use.instr_addr for piece in result.split_condition_use.pieces) == (
        0x1008,
        0x1003,
    )


def test_equality_split_refuses_branches_that_disagree_on_the_true_sink() -> None:
    result = _lifted_classification(
        bytes.fromhex("e81d003b56fe75053b46fc7501c3c3"),
        {0x1000, 0x1003, 0x1008, 0x100D, 0x100E},
    )

    assert not result.complete
    assert result.failure is ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE


@pytest.mark.parametrize("mutation", ("none", "register", "load", "store", "call", "unknown", "other_instruction", "missing_tmp_identity"))
def test_split_trampoline_requires_closed_temporary_effects(mutation: str) -> None:
    """Coordinate temporaries are transparent; observable or unknown effects refuse."""
    temporary = IRValue(MemSpace.TMP, name="t_coordinate", size=2, version=1, source_tmp=0)
    constant = IRValue(MemSpace.CONST, const=1, size=2)
    prefix = IRInstr("MOV", temporary, (constant,), size=2, addr=0x1008)
    if mutation == "register":
        prefix = replace(prefix, dst=IRValue(MemSpace.REG, name="bx", size=2, version=1))
    elif mutation == "load":
        prefix = replace(prefix, op="LOAD", args=(IRAddress(MemSpace.DS, offset=0x1234, size=2),))
    elif mutation == "store":
        prefix = replace(prefix, op="STORE", dst=None,
                         args=(IRAddress(MemSpace.DS, offset=0x1234, size=2), constant))
    elif mutation == "call":
        prefix = replace(prefix, op="CALL", dst=None)
    elif mutation == "unknown":
        prefix = replace(prefix, op="unmodeled_effect")
    elif mutation == "other_instruction":
        prefix = replace(prefix, addr=0x1007)
    elif mutation == "missing_tmp_identity":
        prefix = replace(prefix, dst=replace(temporary, source_tmp=None))
    jump = IRInstr("JMP", None, (IRValue(MemSpace.CONST, const=0x1013, size=4),), addr=0x1008)
    artifact = _artifact()
    artifact = replace(artifact, blocks=tuple(
        replace(block, instrs=(prefix, jump)) if block.addr == 0x1008 else block
        for block in artifact.blocks
    ))
    candidate, failure = select_split_return_condition_8616(
        artifact, 0x1003, _conditions(), _storage("dx"), _storage("ax"),
    )
    if mutation == "none":
        assert candidate is not None
        assert failure is None
    else:
        assert candidate is None
        assert failure is ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE

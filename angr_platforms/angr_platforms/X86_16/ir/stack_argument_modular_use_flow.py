"""Layer: IR.

Responsibility: close one local SSA dependency census for bit-pattern-only
stack-argument uses; unknown or sign-dependent operations remain refusals.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .core import (
    AddressStatus,
    IRAddress,
    IRAtom,
    IRBinaryValue,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .scalar_definitions import (
    ScalarDefinitionIndex8616,
    build_scalar_definition_index_8616,
    reaching_scalar_definitions_8616,
)
from .scalar_value_projection import scalar_active_unary_projection_8616
from .ssa import SSABlock
from .ssa_function import SSAFunctionArtifact
from .stack_argument_modular_use_contracts import (
    ModularArgumentUseFailure8616,
    ModularReturnRegister8616,
)

_SIGN_INSENSITIVE_OPERATIONS_8616 = frozenset({
    "MOV", "Iop_Add16", "Iop_Add32", "Iop_And8", "Iop_And16", "Iop_And32",
    "Iop_CmpEQ16", "Iop_Or16", "Iop_Shl16", "Iop_Shr8", "Iop_Shr16",
    "Iop_Shr32", "Iop_Xor8", "Iop_Xor16",
})
_SIGN_DEPENDENT_OPERATIONS_8616 = frozenset({
    "Iop_Sar16", "Iop_DivS16", "Iop_ModS16", "Iop_CmpLTS16",
    "Iop_CmpLES16", "Iop_16Sto32",
})


def _captured_operand_bits_8616(
    value: IRValue, definitions: ScalarDefinitionIndex8616,
    *, block_addr: int, before_index: int,
) -> int | None:
    """Recover bit width from one exact pending-MOV or word-equality producer."""
    reaching = reaching_scalar_definitions_8616(
        definitions, value, block_addr=block_addr, before_index=before_index,
    )
    if len(reaching) != 1:
        return None
    instruction = reaching[0].instruction
    byte_result = (instruction.size == value.size == 1
                   and instruction.dst is not None and instruction.dst.size == 1)
    word_operands = (len(instruction.args) == 2
                     and all(isinstance(arg, IRValue) and arg.size == 2 for arg in instruction.args))
    if (instruction.op == "Iop_CmpEQ16" and byte_result and word_operands
            and value.expr == (instruction.op,)):
        return 1
    if (instruction.op != "MOV" or len(instruction.args) != 1
            or instruction.size != value.size or instruction.dst is None
            or instruction.dst.size != value.size):
        return None
    source = instruction.args[0]
    if not isinstance(source, IRValue):
        return None
    projection = scalar_active_unary_projection_8616(source)
    if projection is None or source.size != value.size or source.expr != value.expr:
        return None
    return int(projection.target_bits)


def _bitwise_not_use_8616(value: IRValue, operand_bits: int | None) -> bool:
    """Authenticate bitwise complement for dependence only, never equality."""
    unary = value.active_unary
    if unary is None or value.source_tmp is not None:
        return False
    if value.expr is not None and value.expr != (unary.op,):
        return False
    bits = unary.result_bits
    if bits not in {1, 8, 16, 32, 64} or unary.op != f"Iop_Not{bits}":
        return False
    source = unary.operand
    if source.active_unary is not None:
        source_bits = source.active_unary.result_bits
    else:
        source_bits = source.size * 8 if operand_bits is None else operand_bits
    return bool(source_bits == bits and source.size == value.size == (bits + 7) // 8)


def _scalar_use_tainted_8616(
    value: IRValue,
    definitions: ScalarDefinitionIndex8616,
    tainted_sites: set[tuple[int, int]],
    *,
    block_addr: int,
    before_index: int,
) -> tuple[bool, bool]:
    """Resolve a typed SSA use to one local definition or an incoming value."""
    unary = value.active_unary
    if unary is not None:
        operand_bits = _captured_operand_bits_8616(
            unary.operand, definitions, block_addr=block_addr,
            before_index=before_index,
        )
        projection = scalar_active_unary_projection_8616(value, proven_operand_bits=operand_bits)
        # This census proves bit-pattern use only. Signed extension requires
        # a separate sign-dependent-use proof and cannot disappear here.
        if ((projection is None and not _bitwise_not_use_8616(value, operand_bits))
                or (projection is not None and projection.signed)):
            return False, False
        return _scalar_use_tainted_8616(
            unary.operand, definitions, tainted_sites,
            block_addr=block_addr, before_index=before_index,
        )
    if value.space is MemSpace.CONST:
        return False, True
    if value.space is MemSpace.UNKNOWN:
        return False, False
    reaching = reaching_scalar_definitions_8616(
        definitions, value, block_addr=block_addr, before_index=before_index,
    )
    if len(reaching) > 1 or (value.space is MemSpace.TMP and not reaching):
        return False, False
    tainted = bool(reaching and (reaching[0].block_addr, reaching[0].instr_index) in tainted_sites)
    if value.index is None:
        return tainted, True
    indexed, complete = _atom_use_tainted_8616(
        value.index, definitions, tainted_sites,
        block_addr=block_addr, before_index=before_index,
    )
    return tainted or indexed, complete


def _atom_use_tainted_8616(
    atom: IRAtom,
    definitions: ScalarDefinitionIndex8616,
    tainted_sites: set[tuple[int, int]],
    *,
    block_addr: int,
    before_index: int,
) -> tuple[bool, bool]:
    """Inspect structured value and address components, refusing gaps."""
    if isinstance(atom, IRValue):
        return _scalar_use_tainted_8616(
            atom, definitions, tainted_sites,
            block_addr=block_addr, before_index=before_index,
        )
    if isinstance(atom, IRBinaryValue):
        # Nested operations have no instruction site for the operation gate.
        return False, False
    if not isinstance(atom, IRAddress) or (atom.base and not atom.base_values):
        return False, False
    if atom.status is not AddressStatus.STABLE or atom.segment_origin is not SegmentOrigin.PROVEN:
        return False, False
    results = tuple(
        _atom_use_tainted_8616(
            child, definitions, tainted_sites,
            block_addr=block_addr, before_index=before_index,
        )
        for child in atom.base_values
    )
    return any(item[0] for item in results), all(item[1] for item in results)


def _tainted_instruction_failure_8616(
    instruction: IRInstr,
    return_register: ModularReturnRegister8616,
) -> ModularArgumentUseFailure8616 | None:
    """Require a bit-pattern operation with no extra live register output."""
    if instruction.op in _SIGN_DEPENDENT_OPERATIONS_8616:
        return ModularArgumentUseFailure8616.SIGN_DEPENDENT_OPERATION
    if instruction.op not in _SIGN_INSENSITIVE_OPERATIONS_8616 or instruction.dst is None:
        return ModularArgumentUseFailure8616.UNSUPPORTED_USE
    if instruction.dst.space is MemSpace.REG and instruction.dst.name not in {return_register.value, "flags"}:
        return ModularArgumentUseFailure8616.UNSUPPORTED_USE
    return None


def classify_tainted_block_8616(
    artifact: SSAFunctionArtifact,
    block: SSABlock,
    source_indices: frozenset[int],
    *,
    return_register: ModularReturnRegister8616 = ModularReturnRegister8616.AX,
) -> ModularArgumentUseFailure8616 | None:
    """Trace every local SSA use of the input bytes to the final return word."""
    definitions = build_scalar_definition_index_8616(artifact)
    tainted_sites: set[tuple[int, int]] = set()
    return_sites: list[int] = []
    for instr_index in range(min(source_indices), len(block.instrs)):
        instruction = block.instrs[instr_index]
        if instr_index in source_indices:
            tainted_sites.add((block.addr, instr_index))
            continue
        uses = tuple(
            _atom_use_tainted_8616(
                argument, definitions, tainted_sites,
                block_addr=block.addr, before_index=instr_index,
            )
            for argument in instruction.args
        )
        if not all(complete for _, complete in uses):
            return ModularArgumentUseFailure8616.SSA_DEFINITION_UNKNOWN
        if not any(tainted for tainted, _ in uses):
            continue
        failure = _tainted_instruction_failure_8616(instruction, return_register)
        if failure is not None:
            return failure
        tainted_sites.add((block.addr, instr_index))
        if instruction.dst is not None and instruction.dst.space is MemSpace.REG and instruction.dst.name == return_register.value:
            return_sites.append(instr_index)
    return_writes = tuple(
        index for index, instruction in enumerate(block.instrs)
        if instruction.dst is not None
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name == return_register.value
    )
    if not return_sites or not return_writes or return_writes[-1] != return_sites[-1]:
        return ModularArgumentUseFailure8616.RETURN_FLOW_UNKNOWN
    return None


__all__ = ["classify_tainted_block_8616"]

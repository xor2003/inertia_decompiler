"""Layer: IR.

Responsibility: prove a stable stack word has only sign-insensitive scalar uses
on one closed, straight-line function path ending in a proven AX or DX return word.
This is a bit-pattern proof, not a claim about the original C signedness or
permission to rewrite a pointer-return expression.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from .core import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .logical_memory_contracts import IRLogicalMemoryAccess8616
from .ssa import SSABlock
from .ssa_function import SSAFunctionArtifact
from .stack_argument_modular_use_contracts import (
    ModularArgumentUseFailure8616,
    ModularArgumentUseResult8616,
    ModularArgumentUseStats8616,
    ModularArgumentUseVerdict8616,
    ModularReturnRegister8616,
)
from .stack_argument_modular_use_flow import classify_tainted_block_8616


def _refuse_8616(
    failure: ModularArgumentUseFailure8616,
    *,
    normalized: bool = False,
    classified: bool = False,
) -> ModularArgumentUseResult8616:
    """Retain one failed obligation in the five-stage evidence count."""
    return ModularArgumentUseResult8616(
        verdict=ModularArgumentUseVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
        stats=ModularArgumentUseStats8616(1, int(normalized), int(classified), 0, 1),
    )


def _linear_block_order_8616(
    boundary: ExactFunctionRangeBoundary8616,
    artifact: SSAFunctionArtifact,
) -> tuple[int, ...] | None:
    """Accept only one exact path covering every imported block and edge."""
    block_addrs = frozenset(block.addr for block in artifact.blocks)
    if block_addrs != boundary.block_addrs_set or boundary.addr not in block_addrs:
        return None
    successors: dict[int, list[int]] = {addr: [] for addr in block_addrs}
    predecessors: dict[int, list[int]] = {addr: [] for addr in block_addrs}
    for source, target in boundary.successor_edges:
        if source not in block_addrs or target not in block_addrs:
            return None
        successors[source].append(target)
        predecessors[target].append(source)
    if len(boundary.successor_edges) != len(block_addrs) - 1:
        return None
    if any(tuple(sorted(preds)) != artifact.predecessor_map.get(addr) for addr, preds in predecessors.items()):
        return None
    order: list[int] = []
    current = boundary.addr
    while current not in order:
        order.append(current)
        next_addrs = successors[current]
        if not next_addrs:
            break
        if len(next_addrs) != 1:
            return None
        current = next_addrs[0]
    if len(order) != len(block_addrs) or successors[order[-1]]:
        return None
    return tuple(order)


def _input_access_8616(
    artifact: SSAFunctionArtifact,
    storage: IRAddress,
) -> IRLogicalMemoryAccess8616 | None:
    """Find one complete logical word read and reject overlapping views."""
    logical = artifact.logical_memory
    if (
        logical is None
        or not logical.closed
        or bool(logical.refusals)
        or logical.function_addr != artifact.function_addr
        or not _supported_input_storage_8616(storage)
    ):
        return None
    overlapping = tuple(
        access for access in logical.accesses
        if access.address.space is MemSpace.SS
        and access.address.base == storage.base
        and access.address.offset < storage.offset + storage.size
        and storage.offset < access.address.offset + access.address.size
    )
    if len(overlapping) != 1:
        return None
    access = overlapping[0]
    if access.key.function_addr != artifact.function_addr or not access.complete:
        return None
    if not _complete_word_access_8616(access, storage):
        return None
    return access


def _supported_input_storage_8616(storage: IRAddress) -> bool:
    """Require one stable, proven 16-bit SS:BP input identity."""
    return (
        storage.space is MemSpace.SS
        and storage.base == ("bp",)
        and storage.size == 2
        and storage.status is AddressStatus.STABLE
        and storage.segment_origin is SegmentOrigin.PROVEN
    )


def _complete_word_access_8616(access: IRLogicalMemoryAccess8616, storage: IRAddress) -> bool:
    """Require one exact two-byte logical read without a guessed view."""
    address = access.address
    if (
        access.kind != "read"
        or address.offset != storage.offset
        or address.size != storage.size
        or address.status is not AddressStatus.STABLE
        or address.segment_origin is not SegmentOrigin.PROVEN
    ):
        return False
    return tuple(sorted(item.source_byte_offset for item in access.execution_slices)) == (0, 1)


def _prior_calls_preserve_input_8616(
    artifact: SSAFunctionArtifact,
    order: tuple[int, ...],
    access: IRLogicalMemoryAccess8616,
    storage: IRAddress,
) -> bool:
    """Require every preceding call to preserve BP and the input word."""
    order_index = {addr: index for index, addr in enumerate(order)}
    read_site = (order_index[access.key.block_addr], min(
        item.instr_index for item in access.execution_slices
    ))
    call_effects = {
        (item.block_addr, item.instr_index): item.effect
        for item in artifact.memory_call_effects
    }
    for block in artifact.blocks:
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.op != "CALL":
                continue
            site = (order_index[block.addr], instr_index)
            if site >= read_site:
                return False
            effect = call_effects.get((block.addr, instr_index))
            if effect is None or not effect.bp_preserved or not effect.preserves(storage):
                return False
    return True


def _source_indices_8616(
    block: SSABlock,
    access: IRLogicalMemoryAccess8616,
) -> frozenset[int] | None:
    """Bind both logical bytes to exact typed LOAD instruction sites."""
    indices = frozenset(item.instr_index for item in access.execution_slices)
    if len(indices) != 2:
        return None
    for item in access.execution_slices:
        if item.block_addr != block.addr or item.instr_index >= len(block.instrs):
            return None
        instruction = block.instrs[item.instr_index]
        if instruction.op != "LOAD" or instruction.addr != access.key.insn_addr or instruction.dst is None:
            return None
        if instruction.dst.size != 1 or len(instruction.args) != 1 or not isinstance(instruction.args[0], IRAddress):
            return None
        address = instruction.args[0]
        if (
            address.space is not item.address.space
            or address.base != item.address.base
            or address.offset != item.address.offset
            or address.size != item.address.size
        ):
            return None
    return indices


def _later_block_preserves_return_8616(
    block: SSABlock, return_register: ModularReturnRegister8616,
) -> bool:
    """Refuse effects that might consume or replace the tainted return word."""
    for instruction in block.instrs:
        if instruction.op in {"CALL", "STORE"}:
            return False
        destination = instruction.dst
        if destination is not None and destination.space is MemSpace.REG and destination.name in {return_register.value, "flags"}:
            return False
        if any(
            isinstance(argument, IRValue)
            and argument.space is MemSpace.REG
            and argument.name in {return_register.value, "flags"}
            for argument in instruction.args
        ):
            return False
    return True


def _terminal_return_addr_8616(
    artifact: SSAFunctionArtifact,
    order: tuple[int, ...],
    read_block_addr: int,
    return_register: ModularReturnRegister8616,
) -> int | None:
    """Require one unchanged return word through the terminal RET."""
    block_by_addr = {block.addr: block for block in artifact.blocks}
    for later_addr in order[order.index(read_block_addr) + 1:]:
        if not _later_block_preserves_return_8616(block_by_addr[later_addr], return_register):
            return None
    terminal = block_by_addr[order[-1]].instrs
    if not terminal or terminal[-1].op != "RET":
        return None
    return_addr = terminal[-1].addr
    return return_addr if isinstance(return_addr, int) else None


def prove_stack_argument_modular_return_use_8616(
    boundary: ExactFunctionRangeBoundary8616,
    artifact: SSAFunctionArtifact,
    storage: IRAddress,
    *,
    return_register: ModularReturnRegister8616 = ModularReturnRegister8616.AX,
) -> ModularArgumentUseResult8616:
    """Prove bit-pattern-only use of one BP word through a return word.

    This deliberately does not infer source signedness or change generated C.
    A caller must join this fact with pointer shape and return-expression proof
    before materializing a pointer-return contract.
    """
    if boundary.addr != artifact.function_addr:
        return _refuse_8616(ModularArgumentUseFailure8616.FUNCTION_IDENTITY_CONFLICT)
    order = _linear_block_order_8616(boundary, artifact)
    if order is None or any(block.refusals for block in artifact.blocks):
        return _refuse_8616(ModularArgumentUseFailure8616.CFG_NOT_CLOSED)
    access = _input_access_8616(artifact, storage)
    if access is None:
        return _refuse_8616(ModularArgumentUseFailure8616.INPUT_ACCESS_UNKNOWN)
    block = next((item for item in artifact.blocks if item.addr == access.key.block_addr), None)
    if block is None:
        return _refuse_8616(ModularArgumentUseFailure8616.INPUT_ACCESS_UNKNOWN)
    source_indices = _source_indices_8616(block, access)
    if source_indices is None:
        return _refuse_8616(ModularArgumentUseFailure8616.INPUT_ACCESS_UNKNOWN)
    if not _prior_calls_preserve_input_8616(artifact, order, access, storage):
        return _refuse_8616(ModularArgumentUseFailure8616.CALL_EFFECT_UNKNOWN, normalized=True)
    use_failure = classify_tainted_block_8616(
        artifact, block, source_indices, return_register=return_register,
    )
    if use_failure is not None:
        return _refuse_8616(
            use_failure,
            normalized=True,
            classified=use_failure is ModularArgumentUseFailure8616.RETURN_FLOW_UNKNOWN,
        )
    return_addr = _terminal_return_addr_8616(artifact, order, block.addr, return_register)
    if return_addr is None:
        return _refuse_8616(ModularArgumentUseFailure8616.RETURN_FLOW_UNKNOWN, normalized=True, classified=True)
    return ModularArgumentUseResult8616(
        verdict=ModularArgumentUseVerdict8616.PROVEN,
        failure=None,
        stats=ModularArgumentUseStats8616(1, 1, 1, 1, 0),
        input_access_key=access.key,
        return_instruction_addr=return_addr,
    )


__all__ = [
    "ModularArgumentUseFailure8616",
    "ModularArgumentUseResult8616",
    "ModularArgumentUseStats8616",
    "ModularArgumentUseVerdict8616",
    "prove_stack_argument_modular_return_use_8616",
]

"""Prove a paired far-call result's immediate segmented caller use.

Layer: Types/Lowering.
Responsibility: join an exact callee CALL target and DX:AX CALL_OUTPUT definitions with a closed,
single-edge SSA transfer into ES:BX and one logical dereference. This proves
caller use only; it does not infer a pointee family or publish a C return type.
Consumes alias, widening, and typed facts through IR, CFG, and logical-memory
evidence.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.alias.domains import AX, BX, DX, register_domain_for_name
from inertia.ir.core import IRAddress, IRAtom, IRValue, MemSpace
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRMemoryAccessKind8616,
    logical_memory_execution_address_matches_8616,
)
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact

from .far_return_pointer_use_contracts import (
    FarReturnPointerUseEvidence8616,
    FarReturnPointerUseFailure8616,
    FarReturnPointerUseResult8616,
    FarReturnPointerUseStats8616,
    FarReturnPointerUseVerdict8616,
)
from .interprocedural_storage_contracts import (
    StorageDefinitionKind8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
)
from .interprocedural_storage_return_defs import (
    CallOutputDefinitionResult8616,
    call_candidates_at_address_8616,
)
from .interprocedural_storage_return_type_contracts import ReturnPointerAliasStep8616

__all__ = [
    "FarReturnPointerUseEvidence8616",
    "FarReturnPointerUseFailure8616",
    "FarReturnPointerUseResult8616",
    "FarReturnPointerUseStats8616",
    "FarReturnPointerUseVerdict8616",
    "prove_far_return_pointer_use_8616",
]


def _refuse_8616(
    failure: FarReturnPointerUseFailure8616,
    *,
    normalized: bool = False,
) -> FarReturnPointerUseResult8616:
    """Retain one failed obligation without classifying or materializing it."""
    return FarReturnPointerUseResult8616(
        FarReturnPointerUseVerdict8616.UNKNOWN_REFUSE,
        failure,
        None,
        FarReturnPointerUseStats8616(1, int(normalized), 0, 0, 1),
    )


def _is_output_8616(
    definition: StorageReachingDefinition8616,
    register: str,
    callsite_addr: int,
) -> bool:
    """Check one exact full-word register output from this machine call."""
    storage = definition.source_storage
    return bool(
        definition.is_complete
        and definition.definition_kind is StorageDefinitionKind8616.CALL_OUTPUT
        and definition.instr_addr == callsite_addr
        and storage is not None
        and storage.is_exact
        and storage.kind is StorageIdentityKind8616.REGISTER
        and storage.register == register
        and storage.width == 2
        and definition.value.space is MemSpace.REG
        and definition.value.name == register
        and definition.value.size == 2
        and definition.value.version is None
    )


def _single_successor_8616(
    artifact: SSAFunctionArtifact,
    call_block_addr: int,
) -> SSABlock | None:
    """Require one complete, exclusive straight-line post-call CFG edge."""
    blocks = {block.addr: block for block in artifact.blocks}
    if set(artifact.predecessor_map) != set(blocks):
        return None
    if any(
        predecessor not in blocks
        for predecessors in artifact.predecessor_map.values()
        for predecessor in predecessors
    ):
        return None
    successors = tuple(
        addr for addr, predecessors in artifact.predecessor_map.items()
        if call_block_addr in predecessors
    )
    if len(successors) != 1:
        return None
    successor = successors[0]
    if artifact.predecessor_map[successor] != (call_block_addr,):
        return None
    return blocks[successor]


def _copy_step_8616(
    block_addr: int,
    index: int,
    instruction_addr: int,
    source: IRValue,
    target: IRValue,
    source_name: str,
    target_name: str,
) -> ReturnPointerAliasStep8616 | None:
    """Accept only an exact entry-register to full-word register MOV."""
    invalid_source = (
        source.space is not MemSpace.REG
        or source.name != source_name
        or source.size != 2
        or source.version != 0
        or source.expr is not None
    )
    invalid_target = (
        target.space is not MemSpace.REG
        or target.name != target_name
        or target.size != 2
        or not isinstance(target.version, int)
    )
    if invalid_source or invalid_target:
        return None
    step = ReturnPointerAliasStep8616(block_addr, index, instruction_addr, source, target)
    return step if step.complete else None


def _logical_access_8616(
    artifact: SSAFunctionArtifact,
    block_addr: int,
    instruction_addr: int,
    execution_address: IRAddress,
) -> IRLogicalMemoryAccess8616 | None:
    """Bind one byte-sliced ES:BX operation to its exact logical access."""
    logical = artifact.logical_memory
    if logical is None or not logical.closed or logical.function_addr != artifact.function_addr:
        return None
    if any(refusal.insn_addr == instruction_addr for refusal in logical.refusals):
        return None
    matches = tuple(
        access for access in logical.accesses
        if access.key.block_addr == block_addr
        and access.key.insn_addr == instruction_addr
        and access.kind in {IRMemoryAccessKind8616.READ, IRMemoryAccessKind8616.WRITE}
        and access.address.space is MemSpace.ES
        and access.address.base == ("bx",)
        and any(
            logical_memory_execution_address_matches_8616(
                execution_address,
                access.address,
                slice_.source_byte_offset,
                access.address_bits,
            )
            for slice_ in access.execution_slices
        )
    )
    if len(matches) != 1 or not matches[0].complete:
        return None
    return matches[0]


@dataclass(slots=True)
class _FarUseScan8616:
    """Track two independent entry-register carriers in one exact successor."""

    artifact: SSAFunctionArtifact
    successor: SSABlock
    callee_addr: int
    callsite_addr: int
    segment_copy: ReturnPointerAliasStep8616 | None = None
    offset_copy: ReturnPointerAliasStep8616 | None = None
    segment_input_live: bool = True
    offset_input_live: bool = True

    def _access_result(
        self,
        instruction_addr: int,
        address: IRAddress,
    ) -> FarReturnPointerUseResult8616:
        """Bind a paired live carrier to one complete logical operation."""
        if self.segment_copy is None:
            return _refuse_8616(FarReturnPointerUseFailure8616.SEGMENT_COPY_MISSING, normalized=True)
        if self.offset_copy is None:
            return _refuse_8616(FarReturnPointerUseFailure8616.OFFSET_COPY_MISSING, normalized=True)
        access = _logical_access_8616(
            self.artifact, self.successor.addr, instruction_addr, address,
        )
        if access is None:
            return _refuse_8616(FarReturnPointerUseFailure8616.LOGICAL_ACCESS_UNPROVEN, normalized=True)
        evidence = FarReturnPointerUseEvidence8616(
            self.artifact.function_addr,
            self.callee_addr,
            self.callsite_addr,
            self.segment_copy,
            self.offset_copy,
            instruction_addr,
            access.key,
            access.address,
            access.address.size,
        )
        if not evidence.complete:
            return _refuse_8616(FarReturnPointerUseFailure8616.LOGICAL_ACCESS_UNPROVEN, normalized=True)
        return FarReturnPointerUseResult8616(
            FarReturnPointerUseVerdict8616.PROVEN,
            None,
            evidence,
            FarReturnPointerUseStats8616(1, 1, 1, 1, 0),
        )

    def _apply_register_write(
        self,
        index: int,
        instruction_addr: int,
        op: str,
        destination: IRValue | None,
        arguments: tuple[IRAtom, ...],
    ) -> FarReturnPointerUseResult8616 | None:
        """Reject clobbers and record only exact full-word copies."""
        if destination is None or destination.space is not MemSpace.REG:
            return None
        domain = register_domain_for_name(destination.name)
        if domain == AX:
            self.offset_input_live = False
            return None
        if domain == DX:
            self.segment_input_live = False
            return None
        if destination.name == "es":
            if self.segment_copy is not None:
                return _refuse_8616(FarReturnPointerUseFailure8616.CARRIER_CLOBBERED, normalized=True)
            source = arguments[0] if op == "MOV" and len(arguments) == 1 else None
            if self.segment_input_live and isinstance(source, IRValue):
                self.segment_copy = _copy_step_8616(
                    self.successor.addr, index, instruction_addr, source, destination, "dx", "es",
                )
            return None
        if domain == BX:
            if self.offset_copy is not None:
                return _refuse_8616(FarReturnPointerUseFailure8616.CARRIER_CLOBBERED, normalized=True)
            source = arguments[0] if op == "MOV" and len(arguments) == 1 else None
            if self.offset_input_live and isinstance(source, IRValue):
                self.offset_copy = _copy_step_8616(
                    self.successor.addr, index, instruction_addr, source, destination, "ax", "bx",
                )
        return None

    def run(self) -> FarReturnPointerUseResult8616:
        """Scan one straight-line block, refusing every unproven pair."""
        for index, instruction in enumerate(self.successor.instrs):
            if instruction.addr is None:
                return _refuse_8616(FarReturnPointerUseFailure8616.CALLSITE_UNPROVEN, normalized=True)
            if instruction.op == "CALL":
                return _refuse_8616(FarReturnPointerUseFailure8616.CARRIER_CLOBBERED, normalized=True)
            if instruction.op in {"LOAD", "STORE"}:
                for argument in instruction.args:
                    if isinstance(argument, IRAddress) and argument.space is MemSpace.ES and argument.base == ("bx",):
                        return self._access_result(instruction.addr, argument)
            refused = self._apply_register_write(
                index, instruction.addr, instruction.op, instruction.dst, instruction.args,
            )
            if refused is not None:
                return refused
        return _refuse_8616(FarReturnPointerUseFailure8616.DEREFERENCE_NOT_FOUND, normalized=True)


def prove_far_return_pointer_use_8616(
    artifact: SSAFunctionArtifact,
    callsite_addr: int,
    definitions: CallOutputDefinitionResult8616,
) -> FarReturnPointerUseResult8616:
    """Prove an immediate DX:AX -> ES:BX logical dereference, or refuse."""
    if not definitions.complete or len(definitions.definitions) != 2:
        return _refuse_8616(FarReturnPointerUseFailure8616.OUTPUT_SHAPE_MISMATCH)
    provenance = definitions.provenance
    if provenance is None or (
        provenance.definition_addr != callsite_addr
        or provenance.token != callsite_addr
        or provenance.function_addr < 0
    ):
        return _refuse_8616(FarReturnPointerUseFailure8616.CALL_TARGET_MISMATCH)
    by_register = {
        definition.source_storage.register: definition
        for definition in definitions.definitions
        if definition.source_storage is not None
        and definition.source_storage.kind is StorageIdentityKind8616.REGISTER
    }
    if set(by_register) != {"ax", "dx"} or not all(
        _is_output_8616(by_register[name], name, callsite_addr)
        for name in ("ax", "dx")
    ):
        return _refuse_8616(FarReturnPointerUseFailure8616.OUTPUT_SHAPE_MISMATCH)
    callsites = call_candidates_at_address_8616(artifact, callsite_addr)
    if len(callsites) != 1:
        return _refuse_8616(FarReturnPointerUseFailure8616.CALLSITE_UNPROVEN, normalized=True)
    call_block_addr, call_index, call = callsites[0]
    target = call.args[0] if call.args else None
    if (
        not isinstance(target, IRValue)
        or target.space is not MemSpace.CONST
        or not isinstance(target.const, int)
        or target.const != provenance.function_addr
    ):
        return _refuse_8616(FarReturnPointerUseFailure8616.CALL_TARGET_MISMATCH, normalized=True)
    call_block = next((block for block in artifact.blocks if block.addr == call_block_addr), None)
    if (
        call_block is None
        or
        call_index != len(call_block.instrs) - 1
        or any(definition.block_addr != call_block_addr or definition.instr_index != call_index for definition in definitions.definitions)
    ):
        return _refuse_8616(FarReturnPointerUseFailure8616.CALLSITE_UNPROVEN, normalized=True)
    successor = _single_successor_8616(artifact, call_block_addr)
    if successor is None:
        return _refuse_8616(FarReturnPointerUseFailure8616.CFG_INCOMPLETE, normalized=True)
    return _FarUseScan8616(artifact, successor, provenance.function_addr, callsite_addr).run()

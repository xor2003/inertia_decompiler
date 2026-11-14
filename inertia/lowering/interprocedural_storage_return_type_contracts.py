# cython: language_level=3, infer_types=True
"""Typed contracts for interprocedural return storage classification.

Layer: Types/Lowering.
Responsibility: retain complete scalar-condition or pointer-use evidence and
stable typed refusal reasons for one return-storage classification trial.
Consumes alias, widening, and typed facts.
This module owns contracts only; it does not inspect IR, run analysis, mutate
codegen, or recover semantics from source, assembly, COD, or rendered C text.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import AddressStatus, IRAddress, IRValue, MemSpace, SegmentOrigin
from inertia.ir.logical_memory_register_transfer_contracts import LogicalMemoryRegisterTransferKind8616
from inertia.ir.ssa_function import SSAIncomingValue
from inertia.semantics.caller_return_use_contracts import CallerReturnUseFact8616
from inertia.widening.stack_word_register_transfers import StackWordRegisterTransfer8616

from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
)
import dataclasses
import operator
import builtins

__all__ = [
    "ReturnPointerAliasStep8616",
    "ReturnPointerCfgEdge8616",
    "ReturnPointerFlowScan8616",
    "ReturnPointerPhiEvidence8616",
    "ReturnPointerUseEvidence8616",
    "ReturnSplitConditionUseEvidence8616",
    "ReturnSplitPieceUse8616",
    "ReturnStorageTypeFailure8616",
    "ReturnStorageTypeResult8616",
    "ReturnStorageTypeVerdict8616",
    "SplitReturnRelation8616",
]


class ReturnStorageTypeVerdict8616(StrEnum):
    """Outcome of classifying one logical return at one callsite."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class ReturnStorageTypeFailure8616(StrEnum):
    """Stable reasons why a return storage type cannot be published."""

    RETURN_USE_UNKNOWN = "return_use_unknown"
    RETURN_NOT_OBSERVED = "return_not_observed"
    RETURN_USE_NOT_CONDITION = "return_use_not_condition"
    RETURN_USE_NOT_VALUE = "return_use_not_value"
    OUTPUT_STORAGE_UNKNOWN = "output_storage_unknown"
    OUTPUT_STORAGE_CONFLICT = "output_storage_conflict"
    SPLIT_OUTPUT_UNSUPPORTED = "split_output_unsupported"
    OUTPUT_CARRIER_UNSUPPORTED = "output_carrier_unsupported"
    CONDITION_NOT_FOUND = "condition_not_found"
    CONDITION_CONFLICT = "condition_conflict"
    SIGNEDNESS_UNKNOWN = "signedness_unknown"
    VALUE_CLASS_UNKNOWN = "value_class_unknown"
    CALLER_IDENTITY_CONFLICT = "caller_identity_conflict"
    CALL_OUTPUT_DEFINITION_UNKNOWN = "call_output_definition_unknown"
    CALL_OUTPUT_DEFINITION_CONFLICT = "call_output_definition_conflict"
    POINTER_WITNESS_NOT_FOUND = "pointer_witness_not_found"
    POINTER_WITNESS_CONFLICT = "pointer_witness_conflict"
    POINTER_DEREFERENCE_NOT_FOUND = "pointer_dereference_not_found"
    POINTER_ADDRESS_UNKNOWN = "pointer_address_unknown"
    POINTER_ADDRESS_AMBIGUOUS = "pointer_address_ambiguous"
    POINTER_ALIAS_CLOBBERED = "pointer_alias_clobbered"
    POINTER_CFG_INCOMPLETE = "pointer_cfg_incomplete"
    POINTER_CFG_CYCLE = "pointer_cfg_cycle"
    POINTER_CFG_JOIN_CONFLICT = "pointer_cfg_join_conflict"
    POINTER_PHI_CONFLICT = "pointer_phi_conflict"
    POINTER_STACK_EVIDENCE_INCOMPLETE = "pointer_stack_evidence_incomplete"
    SPLIT_OUTPUT_DEFINITION_CONFLICT = "split_output_definition_conflict"
    SPLIT_CONDITION_NOT_FOUND = "split_condition_not_found"
    SPLIT_CONDITION_CONFLICT = "split_condition_conflict"
    SPLIT_CFG_INCOMPLETE = "split_cfg_incomplete"
    SPLIT_OPERAND_CONFLICT = "split_operand_conflict"
    SPLIT_WITNESS_NOT_FOUND = "split_witness_not_found"
    SPLIT_WITNESS_CONFLICT = "split_witness_conflict"


class SplitReturnRelation8616(StrEnum):
    """Wide relation proven by one exact split-return decision graph."""

    EQ = "eq"
    NE = "ne"
    SLT = "slt"
    SLE = "sle"
    SGT = "sgt"
    SGE = "sge"
    ULT = "ult"
    ULE = "ule"
    UGT = "ugt"
    UGE = "uge"


@dataclasses.dataclass(frozen=True, )
class ReturnPointerAliasStep8616:
    """One exact SSA-preserving copy in a returned pointer's lineage."""

    block_addr: cython.longlong
    instr_index: cython.longlong
    instr_addr: cython.longlong
    source: IRValue
    target: IRValue

    @property
    def complete(self) -> cython.bint:
        """Return whether this step retains exact versioned equal-width values."""
        return (
            self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
            and isinstance(self.source.version, int)
            and isinstance(self.target.version, int)
            and self.source.size > 0
            and operator.eq(self.source.size, self.target.size)
        )


@dataclasses.dataclass(frozen=True, )
class ReturnPointerCfgEdge8616:
    """One exact in-function CFG edge traversed by a pointer carrier."""

    source_block_addr: cython.longlong
    target_block_addr: cython.longlong
    carrier_register: object
    value: IRValue

    @property
    def complete(self) -> cython.bint:
        """Return whether this edge retains one exact full-word register value."""
        return (
            self.source_block_addr >= 0
            and self.target_block_addr >= 0
            and operator.ne(self.source_block_addr, self.target_block_addr)
            and self.value.space is MemSpace.REG
            and operator.eq(self.value.name, self.carrier_register)
            and self.value.size == 2
            and isinstance(self.value.version, int)
        )


@dataclasses.dataclass(frozen=True, )
class ReturnPointerPhiEvidence8616:
    """Exact all-predecessor SSA phi proof for one pointer carrier."""

    block_addr: cython.longlong
    carrier_register: object
    target: IRValue
    incoming: object

    @property
    def complete(self) -> cython.bint:
        """Return whether this phi retains sorted full-word register inputs."""
        source_blocks = tuple(item.source_block_addr for item in iter(self.incoming))
        return (
            self.block_addr >= 0
            and self.target.space is MemSpace.REG
            and operator.eq(self.target.name, self.carrier_register)
            and self.target.size == 2
            and isinstance(self.target.version, int)
            and operator.eq(self.target.expr, ("phi", hex(self.block_addr)))
            and len(source_blocks) >= 2
            and operator.eq(source_blocks, tuple(sorted(tuple(set(source_blocks)))))
            and all(
                item.value.space is MemSpace.REG
                and operator.eq(item.value.name, self.carrier_register)
                and item.value.size == 2
                and isinstance(item.value.version, int)
                for item in iter(self.incoming)
            )
        )


@dataclasses.dataclass(frozen=True, )
class ReturnPointerUseEvidence8616:
    """Exact alias lineage from one call output to a segmented dereference."""

    caller_addr: cython.longlong
    callsite_addr: cython.longlong
    witness_instruction_addr: cython.longlong
    dereference_instruction_addr: cython.longlong
    carrier_register: object
    address: IRAddress
    aliases: object
    cfg_edges: tuple[ReturnPointerCfgEdge8616, ...] = ()
    phis: tuple[ReturnPointerPhiEvidence8616, ...] = ()
    stack_transfers: tuple[StackWordRegisterTransfer8616, ...] = ()

    @property
    def complete(self) -> cython.bint:
        """Return whether the output reaches one stable single-base address."""
        stack_reload_proven = any(
            transfer.source.kind is LogicalMemoryRegisterTransferKind8616.RELOAD
            and operator.eq(transfer.source.register.name, self.carrier_register)
            and any(
                prior.source.kind is LogicalMemoryRegisterTransferKind8616.SPILL
                and operator.eq(prior.storage_version, transfer.storage_version)
                for prior in iter(self.stack_transfers[:index])
            )
            for index, transfer in builtins.iter(enumerate(self.stack_transfers))
        )
        register_alias_proven = any(
            operator.eq(step.target.name, self.carrier_register) for step in iter(self.aliases)
        )
        return (
            self.caller_addr >= 0
            and self.callsite_addr >= 0
            and self.witness_instruction_addr >= 0
            and self.dereference_instruction_addr >= 0
            and self.address.status is AddressStatus.STABLE
            and self.address.segment_origin is SegmentOrigin.PROVEN
            and self.address.space in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
            and operator.eq(self.address.base, (self.carrier_register,))
            and self.address.size > 0
            and bool(self.aliases or self.stack_transfers)
            and all(step.complete for step in iter(self.aliases))
            and (register_alias_proven or stack_reload_proven)
            and all(edge.complete for edge in iter(self.cfg_edges))
            and all(phi.complete for phi in iter(self.phis))
            and all(transfer.complete for transfer in iter(self.stack_transfers))
        )


@dataclasses.dataclass(frozen=True, )
class ReturnPointerFlowScan8616:
    """Closed pointer-flow evidence or one typed refusal reason."""

    evidence: ReturnPointerUseEvidence8616 | None = None
    failure: ReturnStorageTypeFailure8616 | None = None

    @property
    def complete(self) -> cython.bint:
        """Return whether exactly one complete scan outcome is retained."""
        return (self.evidence is None) != (self.failure is None) and (self.evidence is None or self.evidence.complete)


@dataclasses.dataclass(frozen=True, )
class ReturnSplitPieceUse8616:
    """One exact physical piece consumed by a split-return condition chain."""

    storage: StorageIdentity8616
    condition: ConditionIR
    use: StorageUseEvidence8616

    @property
    def complete(self) -> cython.bint:
        """Return whether this piece retains exact storage and use identity."""
        return bool(
            self.storage.is_exact
            and self.use.is_complete
            and operator.eq(self.condition.producer_insn, self.use.instr_addr)
        )


@dataclasses.dataclass(frozen=True, )
class ReturnSplitConditionUseEvidence8616:
    """Closed decision-graph proof over one split return value."""

    caller_addr: cython.longlong
    callsite_addr: cython.longlong
    relation: SplitReturnRelation8616
    conditions: object
    pieces: object
    true_sink_addr: cython.longlong
    false_sink_addr: cython.longlong
    transparent_block_addrs: tuple[cython.longlong, ...] = ()

    @property
    def complete(self) -> cython.bint:
        """Return whether the chain and both physical uses are exact."""
        storage_keys = tuple(piece.storage.key for piece in iter(self.pieces))
        return (
            self.caller_addr >= 0
            and self.callsite_addr >= 0
            and self.true_sink_addr >= 0
            and self.false_sink_addr >= 0
            and operator.ne(self.true_sink_addr, self.false_sink_addr)
            and len(self.conditions) in {2, 3}
            and operator.eq(len(set(self.conditions)), len(self.conditions))
            and len(set(storage_keys)) == 2
            and all(piece.complete for piece in iter(self.pieces))
            and all(operator.eq(piece.use.callsite_addr, self.callsite_addr) for piece in iter(self.pieces))
            and all(piece.condition in self.conditions for piece in iter(self.pieces))
            and operator.eq(len(set(self.transparent_block_addrs)), len(self.transparent_block_addrs))
        )


@dataclasses.dataclass(frozen=True, )
class ReturnStorageTypeResult8616:
    """Complete return type proof or one typed refusal with retained evidence."""

    verdict: ReturnStorageTypeVerdict8616
    signedness: StorageTrialSignedness8616 | None
    value_class: StorageTrialValueClass8616 | None
    condition: ConditionIR | None
    failure: ReturnStorageTypeFailure8616 | None
    stats: StorageTrialStats8616
    pointer_use: ReturnPointerUseEvidence8616 | None = None
    split_condition_use: ReturnSplitConditionUseEvidence8616 | None = None
    byte_extension_fact: CallerReturnUseFact8616 | None = None

    @property
    def complete(self) -> cython.bint:
        """Return whether exactly one complete witness produced a type proof."""
        evidence_count = (
            int(self.condition is not None)
            + int(self.pointer_use is not None)
            + int(self.split_condition_use is not None)
            + int(self.byte_extension_fact is not None)
        )
        return (
            self.verdict is ReturnStorageTypeVerdict8616.PROVEN
            and self.signedness is not None
            and self.value_class is not None
            and evidence_count == 1
            and (self.pointer_use is None or self.pointer_use.complete)
            and (
                self.split_condition_use is None
                or self.split_condition_use.complete
            )
            and (
                self.byte_extension_fact is None
                or (
                    self.byte_extension_fact.classified
                    and self.byte_extension_fact.byte_extension is not None
                )
            )
            and self.failure is None
            and self.stats.complete
        )

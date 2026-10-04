"""Typed interprocedural parameter and return storage contracts.

Layer: Types/Lowering.
Responsibility: retain exact storage, SSA definition/use, type-class, and caller
census evidence needed to resolve function interfaces.
Consumes alias, widening, and typed facts. This module does not mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from ..ir import AddressStatus, IRAddress, IRValue, MemSpace
from .interprocedural_storage_logical_input_contracts import (
    LogicalInputRootBinding8616,
    LogicalPushValue8616,
)
from .interprocedural_storage_return_discard import DiscardedReturnTrial8616
from .interprocedural_storage_return_passthrough_contracts import ReturnPassThroughTrial8616

if TYPE_CHECKING:
    from .input_offset_value import InputOffsetValue8616
    from .interprocedural_memory_output_object_contracts import MemoryOutputObjectContract8616
    from .interprocedural_storage_live_out_contracts import MemoryLiveOutUseFact8616
    from .interprocedural_storage_return_type_contracts import ReturnPointerUseEvidence8616
    from .pointer_parameter_caller_target_contracts import PointerParameterCallerTarget8616
    from .pointer_parameter_memory_output_contracts import PointerParameterMemoryOutputObject8616

__all__ = [
    "CallsiteStorageBinding8616",
    "CallsiteStorageTrials8616",
    "FunctionStorageContract8616",
    "FunctionStorageResolution8616",
    "FunctionStorageTrials8616",
    "ProgramStorageResolution8616",
    "StorageDefinitionKind8616",
    "StorageIdentity8616",
    "StorageIdentityKind8616",
    "StorageReachingDefinition8616",
    "StorageSlotContract8616",
    "StorageTrial8616",
    "StorageTrialFailureKind8616",
    "StorageTrialRole8616",
    "StorageTrialSignedness8616",
    "StorageTrialStats8616",
    "StorageTrialValueClass8616",
    "StorageTrialVerdict8616",
    "StorageUseEvidence8616",
    "ValueProvenance8616",
]


class StorageIdentityKind8616(StrEnum):
    """Architectural storage categories accepted by interface trials."""

    STACK = "stack"
    MEMORY = "memory"
    REGISTER = "register"


class StorageDefinitionKind8616(StrEnum):
    """Producer categories retained without fabricating SSA versions."""

    VALUE = "value"
    CALL_OUTPUT = "call_output"


class StorageTrialRole8616(StrEnum):
    """Direction of one candidate relative to the callee boundary."""

    INPUT = "input"
    LIVE_OUT = "live_out"
    RETURN = "return"


class StorageTrialSignedness8616(StrEnum):
    """Sign interpretation proven for one candidate value."""

    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    SIGN_INSENSITIVE = "sign_insensitive"
    SIGNED = "signed"
    UNSIGNED = "unsigned"

class StorageTrialValueClass8616(StrEnum):
    """Value-versus-pointer interpretation proven before C lowering."""

    UNKNOWN = "unknown"
    VALUE = "value"
    POINTER = "pointer"


class StorageTrialVerdict8616(StrEnum):
    """Typed outcome of resolving one function's complete trial set."""

    ACCEPTED = "accepted"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class StorageTrialFailureKind8616(StrEnum):
    """Stable reasons why trials cannot become a function contract."""

    INCOMPLETE_CALLER_CENSUS = "incomplete_caller_census"
    CALLSITE_SET_CONFLICT = "callsite_set_conflict"
    INCOMPLETE_TRIAL = "incomplete_trial"
    ARGUMENT_ORDER_CONFLICT = "argument_order_conflict"
    STORAGE_CONFLICT = "storage_conflict"
    SIGNEDNESS_CONFLICT = "signedness_conflict"
    VALUE_CLASS_CONFLICT = "value_class_conflict"
    POINTEE_WIDTH_CONFLICT = "pointee_width_conflict"
    STACK_DELTA_CONFLICT = "stack_delta_conflict"
    SPLIT_PROVENANCE_CONFLICT = "split_provenance_conflict"
    PASSTHROUGH_OUTPUT_UNRESOLVED = "passthrough_output_unresolved"


@dataclass(frozen=True, slots=True)
class StorageIdentity8616:
    """One exact stack, segmented-memory, or register identity."""

    kind: StorageIdentityKind8616
    width: int
    address: IRAddress | None = None
    register: str | None = None

    @property
    def is_exact(self) -> bool:
        """Return whether this identity names one stable architectural range."""
        if self.width <= 0:
            return False
        address = self.address
        if self.kind in {StorageIdentityKind8616.STACK, StorageIdentityKind8616.MEMORY}:
            if (
                address is None
                or self.register is not None
                or address.size != self.width
                or address.status is not AddressStatus.STABLE
            ):
                return False
            if self.kind is StorageIdentityKind8616.STACK:
                return address.space is MemSpace.SS and address.base in {("bp",), ("sp",)}
            return address.space in {MemSpace.DS, MemSpace.ES} and not address.base
        return self.address is None and isinstance(self.register, str) and bool(self.register)

    @property
    def key(self) -> tuple[object, ...]:
        """Return deterministic exact-storage identity for joins."""
        if self.address is not None:
            return (self.kind, self.width, self.address.space, self.address.base,
                    self.address.offset, self.address.size, self.address.version)
        return (self.kind, self.width, self.register)


@dataclass(frozen=True, slots=True)
class StorageReachingDefinition8616:
    """Exact ordinary value or machine-call output reaching one use."""

    value: IRValue
    block_addr: int
    instr_index: int
    instr_addr: int
    source_storage: StorageIdentity8616 | None = None
    definition_kind: StorageDefinitionKind8616 = StorageDefinitionKind8616.VALUE
    logical_push: LogicalPushValue8616 | None = None

    @property
    def is_complete(self) -> bool:
        """Return whether this is an exact versioned or constant definition."""
        source_complete = self.source_storage is None or self.source_storage.is_exact
        if self.definition_kind is StorageDefinitionKind8616.CALL_OUTPUT:
            source = self.source_storage
            address = source.address if source is not None else None
            has_value_identity = (
                self.value.version is None
                and self.value.const is None
                and source is not None
                and (
                    (source.kind is StorageIdentityKind8616.REGISTER
                     and self.value.space is MemSpace.REG and self.value.name == source.register)
                    or (address is not None and self.value.space is address.space
                        and self.value.offset == address.offset
                        and self.value.name == (address.base[0] if len(address.base) == 1 else None))
                )
            )
        else:
            has_value_identity = isinstance(self.value.version, int) or isinstance(self.value.const, int)
        width_matches = self.value.size <= 0 or self.source_storage is None or self.value.size == self.source_storage.width
        return (
            self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
            and source_complete
            and has_value_identity
            and width_matches
            and (self.logical_push is None or self.logical_push.definition_slice(self) is not None)
        )


@dataclass(frozen=True, slots=True)
class StorageUseEvidence8616:
    """Exact instruction use reached by one retained definition."""

    block_addr: int
    instr_index: int
    instr_addr: int
    callsite_addr: int

    @property
    def is_complete(self) -> bool:
        """Return whether the use and machine callsite are identified."""
        return self.block_addr >= 0 and self.instr_index >= 0 and self.instr_addr >= 0 and self.callsite_addr >= 0


@dataclass(frozen=True, slots=True)
class ValueProvenance8616:
    """Shared producer identity required when joining split return pieces."""

    function_addr: int
    definition_addr: int
    token: int


@dataclass(frozen=True, slots=True)
class StorageTrial8616:
    """One interface use retaining typed storage and its exact evidence.

    Input offset evidence retains numeric proof/refusal independently of type
    classification; it never promotes DEFAULTED addresses or authorizes pointers.
    """

    callee_addr: int
    caller_addr: int
    callsite_addr: int
    role: StorageTrialRole8616
    logical_index: int
    piece_index: int
    piece_count: int
    storage: StorageIdentity8616
    reaching_definition: StorageReachingDefinition8616
    use: StorageUseEvidence8616
    signedness: StorageTrialSignedness8616
    value_class: StorageTrialValueClass8616
    provenance: ValueProvenance8616 | None = None
    pointee_width_bytes: int | None = None
    pointer_use: ReturnPointerUseEvidence8616 | None = None
    logical_root: LogicalInputRootBinding8616 | None = None
    input_offset_value: InputOffsetValue8616 | None = field(default=None, repr=False, compare=False)

    @property
    def input_offset_value_is_bound(self) -> bool:
        """Require numeric proof of this exact input, never segment/type authority."""
        proof = self.input_offset_value
        return bool(
            self.logical_root_is_bound and proof is not None and proof.complete
            and proof.binding is self.logical_root
            and proof.definition is self.reaching_definition
            and proof.use == self.use
        )

    @property
    def logical_root_is_bound(self) -> bool:
        """Require retained input Value proof to match this exact scope and piece.

        Absence is not a whole-value proof. In particular, DEFAULTED callee
        storage remains DEFAULTED; binding the caller Value does not widen it.
        """
        binding = self.logical_root
        if binding is None or not binding.complete:
            return False
        scope_matches = (
            self.role is StorageTrialRole8616.INPUT
            and binding.callee_addr == self.callee_addr
            and binding.caller_addr == self.caller_addr
            and binding.callsite_addr == self.callsite_addr
            and binding.logical_index == self.logical_index
        )
        piece_matches = (
            binding.piece_index == self.piece_index and binding.piece_count == self.piece_count
            and binding.byte_width == self.storage.width
            and self.storage.kind is StorageIdentityKind8616.STACK
            and binding.callee_piece_address == self.storage.address
        )
        return bool(
            scope_matches and piece_matches and binding.call_use == self.use
            and binding.matches_definition(self.reaching_definition)
        )

    @property
    def pointer_use_is_bound(self) -> bool:
        """Bind a retained near-return proof to this exact caller, call and use.

        A dereference width alone does not prove an address space. Legacy trials
        may omit this evidence, but consumers needing a segmented pointer must
        require this property rather than infer a space from the C pointer type.
        """
        evidence = self.pointer_use
        if evidence is None or not evidence.complete:
            return False
        pointer_return = (
            self.role is StorageTrialRole8616.RETURN
            and self.value_class is StorageTrialValueClass8616.POINTER
            and self.piece_count == 1
        )
        exact_use = (
            evidence.caller_addr == self.caller_addr
            and evidence.callsite_addr == self.callsite_addr
            and evidence.witness_instruction_addr == self.use.instr_addr
        )
        return pointer_return and exact_use

    @property
    def is_complete(self) -> bool:
        """Return whether every fact required for safe materialization exists."""
        return_output_complete = (
            self.provenance is not None
            and self.reaching_definition.definition_kind is StorageDefinitionKind8616.CALL_OUTPUT
            and self.reaching_definition.instr_addr == self.callsite_addr
        )
        return (
            self.callee_addr >= 0
            and self.caller_addr >= 0
            and self.callsite_addr == self.use.callsite_addr
            and self.logical_index >= 0
            and 0 <= self.piece_index < self.piece_count
            and self.storage.is_exact
            and self.reaching_definition.is_complete
            and self.use.is_complete
            and self.signedness is not StorageTrialSignedness8616.UNKNOWN
            and self.value_class is not StorageTrialValueClass8616.UNKNOWN
            and (self.pointee_width_bytes is None or self.pointee_width_bytes > 0)
            and (
                self.pointee_width_bytes is None
                or self.value_class is StorageTrialValueClass8616.POINTER
            )
            and (self.role is StorageTrialRole8616.INPUT or return_output_complete)
            and (self.pointer_use is None or self.pointer_use_is_bound)
            and (self.logical_root is None or self.logical_root_is_bound)
        )


@dataclass(frozen=True, slots=True)
class CallsiteStorageTrials8616:
    """Typed interface trials, memory effects, and stack state for one call."""

    caller_addr: int
    callee_addr: int
    callsite_addr: int
    arguments: tuple[StorageTrial8616, ...] = ()
    returns: tuple[StorageTrial8616, ...] = ()
    live_outs: tuple[StorageTrial8616, ...] = ()
    memory_effects: tuple[MemoryLiveOutUseFact8616, ...] = ()
    pointer_effects: tuple[PointerParameterCallerTarget8616, ...] = ()
    return_passthroughs: tuple[ReturnPassThroughTrial8616, ...] = ()
    stack_delta: int | None = None
    discarded_return: DiscardedReturnTrial8616 | None = None


@dataclass(frozen=True, slots=True)
class FunctionStorageTrials8616:
    """Complete caller census and candidate trials for one internal function."""

    function_addr: int
    caller_census_complete: bool
    expected_callsite_addrs: tuple[int, ...]
    callsites: tuple[CallsiteStorageTrials8616, ...]


@dataclass(frozen=True, slots=True)
class StorageSlotContract8616:
    """Accepted logical slot with any exact pointer-dereference width."""

    role: StorageTrialRole8616
    logical_index: int
    pieces: tuple[StorageIdentity8616, ...]
    signedness: StorageTrialSignedness8616
    value_class: StorageTrialValueClass8616
    pointee_width_bytes: int | None = None

    @property
    def width(self) -> int:
        """Return total logical width across exact physical pieces."""
        return sum(piece.width for piece in self.pieces)


@dataclass(frozen=True, slots=True)
class CallsiteStorageBinding8616:
    """Accepted callsite proofs retained with the function contract."""

    caller_addr: int
    callsite_addr: int
    arguments: tuple[StorageTrial8616, ...]
    returns: tuple[StorageTrial8616, ...]
    stack_delta: int
    live_outs: tuple[StorageTrial8616, ...] = ()
    memory_effects: tuple[MemoryLiveOutUseFact8616, ...] = ()
    pointer_effects: tuple[PointerParameterCallerTarget8616, ...] = ()
    return_passthroughs: tuple[ReturnPassThroughTrial8616, ...] = ()
    discarded_return: DiscardedReturnTrial8616 | None = None


@dataclass(frozen=True, slots=True)
class FunctionStorageContract8616:
    """One accepted interface applied to a callee and every known callsite."""

    function_addr: int
    inputs: tuple[StorageSlotContract8616, ...]
    outputs: tuple[StorageSlotContract8616, ...]
    stack_delta: int
    callsites: tuple[CallsiteStorageBinding8616, ...]
    memory_outputs: tuple[MemoryOutputObjectContract8616, ...] = ()
    pointer_memory_outputs: tuple[PointerParameterMemoryOutputObject8616, ...] = ()


@dataclass(frozen=True, slots=True)
class StorageTrialStats8616:
    """Mandatory closed evidence counters for storage-trial resolution."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every classified fact was materialized exactly once."""
        return (
            self.raw_fact_count == self.normalized_fact_count == self.classified_fact_count == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class FunctionStorageResolution8616:
    """Accepted contract or typed refusal for one internal function."""

    function_addr: int
    verdict: StorageTrialVerdict8616
    contract: FunctionStorageContract8616 | None
    failures: tuple[StorageTrialFailureKind8616, ...]
    stats: StorageTrialStats8616


@dataclass(frozen=True, slots=True)
class ProgramStorageResolution8616:
    """Deterministic SCC resolution and atomic publication payload."""

    function_trials: tuple[FunctionStorageTrials8616, ...]
    resolutions: tuple[FunctionStorageResolution8616, ...]
    sccs: tuple[tuple[int, ...], ...]
    iterations_by_scc: tuple[int, ...]
    stats: StorageTrialStats8616

    def contract_for(self, function_addr: int) -> FunctionStorageContract8616 | None:
        """Return the accepted contract for one exact function address."""
        for item in self.resolutions:
            if item.function_addr == function_addr and item.verdict is StorageTrialVerdict8616.ACCEPTED:
                return item.contract
        return None

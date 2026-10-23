"""Normalize dead block-local TMP definitions from complete typed evidence.

Layer: IR.
Responsibility: collect exact value dependencies and remove only uniquely
bound, dead, pure-total scalar definitions while preserving all other effects.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from . import scalar_instruction_effects as scalar_owner_8616
from .condition_ir import ConditionIR, ConditionRegisterBindingIR, ConditionRegisterUpdateIR, ConditionSource
from .core import (
    IRActiveUnary8616,
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCallOutputProvenance8616,
    IRCallOutputShape8616,
    IRCondition,
    IRInstr,
    IRValue,
    MemSpace,
)
from .instruction_origin import IRInstructionOrigin8616
from .scalar_instruction_effects import (
    ScalarInstructionEffectKind8616,
    _classify_boolean_binary_8616,
    _classify_comparison_8616,
    _classify_select_8616,
    _classify_widening_product_8616,
    scalar_boolean_result_bits_8616,
    scalar_instruction_effect_8616,
    scalar_select_result_bits_8616,
)
from .scalar_value_projection import scalar_active_unary_projection_8616, scalar_binary_operation_8616


class DeadTemporaryNormalizationStatus8616(StrEnum):
    """Completeness of dependency evidence, never a semantic validation verdict."""

    COMPLETE = "complete"
    UNKNOWN_REFUSE = "unknown_refuse"


class DeadTemporaryDecisionKind8616(StrEnum):
    """Evidence-backed fate of one original instruction row."""

    KEEP_LIVE = "keep_live"
    UNKNOWN_REFUSE = "unknown_refuse"
    REMOVE_DEAD_TOTAL = "remove_dead_total"


@dataclass(frozen=True, slots=True)
class DeadTemporaryDependencyRead8616:
    """Exact TMP pins collected without parsing compatibility strings."""

    tmp_ids: frozenset[int]
    status: DeadTemporaryNormalizationStatus8616


@dataclass(frozen=True, slots=True)
class DeadTemporaryDecision8616:
    """Instruction position and typed retention/removal decision."""

    instruction_index: int
    kind: DeadTemporaryDecisionKind8616


@dataclass(frozen=True, slots=True)
class DeadTemporaryNormalizationStats8616:
    """Closed removal ledger; classified removals must materialize exactly."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class DeadTemporaryNormalizationResult8616:
    """Normalized block with original identities and durable evidence."""

    block: IRBlock
    status: DeadTemporaryNormalizationStatus8616
    decisions: tuple[DeadTemporaryDecision8616, ...]
    evidence: DeadTemporaryNormalizationStats8616


def _exact_tmp_id(value: object) -> bool:
    """Require a nonnegative integer TMP identity, rejecting Boolean aliases."""
    return type(value) is int and value >= 0


def _value_metadata_valid(value: IRValue) -> bool:
    """Reject foreign metadata hidden inside an owned scalar value contract."""
    if value.name is not None and type(value.name) is not str:
        return False
    for coordinate in (value.version, value.memory_access_size, value.memory_access_insn):
        if coordinate is not None and type(coordinate) is not int:
            return False
    output = value.call_output
    if output is None:
        return True
    return (type(output) is IRCallOutputProvenance8616 and type(output.shape) is IRCallOutputShape8616
            and type(output.callsite_addr) is int and type(output.target_addr) is int)


def _unary_operand_dependencies_valid(unary: IRActiveUnary8616) -> bool:
    """Require one explicit typed operand and complete result-width metadata."""
    return (type(unary.operand) is IRValue and type(unary.operand.size) is int
            and unary.operand.size > 0 and type(unary.result_bits) is int
            and unary.result_bits > 0 and type(unary.op) is str and bool(unary.op))


def _unary_view_dependencies_valid(value: IRValue) -> bool:
    """Validate unary graph structure, independently of operation totality."""
    unary = value.active_unary
    if type(unary) is not IRActiveUnary8616 or not _unary_operand_dependencies_valid(unary):
        return False
    if value.source_tmp is not None or value.size != (unary.result_bits + 7) // 8:
        return False
    return value.expr is None or value.expr == (unary.op,)


def _value_children(value: IRValue) -> tuple[object, ...] | None:
    """Validate typed scalar fields and expose every computation/provenance pin."""
    if not _value_metadata_valid(value):
        return None
    scalar_fields = (value.size, value.offset, value.index_shift)
    if not all(type(field) is int for field in scalar_fields) or type(value.space) is not MemSpace:
        return None
    if value.source_tmp is not None and not _exact_tmp_id(value.source_tmp):
        return None
    if value.const is not None and type(value.const) is not int:
        return None
    if value.expr is not None and (type(value.expr) is not tuple or not all(type(label) is str for label in value.expr)):
        return None
    if value.index is not None and type(value.index) not in (IRValue, IRBinaryValue):
        return None
    if value.active_unary is not None and not _unary_view_dependencies_valid(value):
        return None
    if value.space is MemSpace.TMP and value.source_tmp is None and value.active_unary is None:
        return None
    return value.index, value.active_unary


def _dependency_children(payload: object) -> tuple[object, ...] | None:
    """Expose only exact owned dependency fields; unsupported payloads refuse."""
    if payload is None or type(payload) in (str, int, bool, bytes):
        return ()
    if type(payload) is tuple:
        return payload
    if type(payload) is IRValue:
        return _value_children(payload)
    if type(payload) is IRBinaryValue:
        binary = payload
        valid = (type(binary.lhs) in (IRValue, IRBinaryValue) and type(binary.rhs) in (IRValue, IRBinaryValue)
                 and type(binary.op) is str and type(binary.size) is int)
        return (binary.lhs, binary.rhs) if valid else None
    if type(payload) is IRActiveUnary8616:
        unary = payload
        if not _unary_operand_dependencies_valid(unary):
            return None
        return (unary.operand,)
    if type(payload) is IRAddress:
        address = payload
        if type(address.base_values) is not tuple or not all(type(value) is IRValue for value in address.base_values):
            return None
        return (address.base_values,)
    if type(payload) is IRCondition:
        condition = payload
        valid = type(condition.args) is tuple and all(type(arg) in (IRValue, IRBinaryValue, IRAddress, IRCondition) for arg in condition.args)
        return (condition.args,) if valid else None
    return _condition_dependency_children(payload)


def _condition_dependency_children(payload: object) -> tuple[object, ...] | None:
    """Project condition metadata through its exact owned value fields."""
    if type(payload) is ConditionRegisterBindingIR:
        return payload.value, payload.update
    if type(payload) is ConditionRegisterUpdateIR:
        return (payload.rhs,)
    if type(payload) is ConditionIR:
        return payload.lhs, payload.rhs, payload.producer_semantics, payload.register_bindings
    if type(payload) is ConditionSource:
        source = payload
        return (source.lhs, source.rhs, source.normalized_lhs, source.normalized_rhs,
                source.semantics, source.register_bindings)
    return None


def read_dead_temporary_dependencies_8616(payload: object) -> DeadTemporaryDependencyRead8616:
    """Walk typed roots iteratively, refusing cycles and opaque dependency fields."""
    stack: list[tuple[object, bool]] = [(payload, False)]
    active: set[int] = set()
    visited: set[int] = set()
    tmp_ids: set[int] = set()
    while stack:
        current, leaving = stack.pop()
        identity = id(current)
        if leaving:
            active.remove(identity)
            visited.add(identity)
            continue
        if identity in active:
            return DeadTemporaryDependencyRead8616(frozenset(tmp_ids), DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE)
        if identity in visited:
            continue
        children = _dependency_children(current)
        if children is None:
            return DeadTemporaryDependencyRead8616(frozenset(tmp_ids), DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE)
        if type(current) is IRValue:
            value = current
            if value.source_tmp is not None:
                tmp_ids.add(value.source_tmp)
        active.add(identity)
        stack.append((current, True))
        stack.extend((child, False) for child in reversed(children))
    return DeadTemporaryDependencyRead8616(frozenset(tmp_ids), DeadTemporaryNormalizationStatus8616.COMPLETE)


def _total_scalar_sources(args: tuple[object, ...], boolean_bits: dict[int, int]) -> bool:
    """Authenticate pure total scalar reads, including explicit unary conversions."""
    pending = list(args)
    while pending:
        value = pending.pop()
        if type(value) is not IRValue:
            return False
        if value.size <= 0:
            return False
        if value.space not in (MemSpace.REG, MemSpace.TMP, MemSpace.CONST):
            return False
        if value.space is MemSpace.CONST and value.const is None:
            return False
        if value.index is not None or value.offset or value.index_shift:
            return False
        if value.active_unary is not None:
            operand = value.active_unary.operand
            proven_bits = boolean_bits.get(operand.source_tmp) if operand.source_tmp is not None else None
            if scalar_active_unary_projection_8616(value, proven_operand_bits=proven_bits) is None:
                return False
            pending.append(value.active_unary.operand)
        elif value.expr and value.source_tmp is None:
            return False
    return True


def _pure_total_definition(instruction: IRInstr, boolean_bits: dict[int, int] | None = None) -> bool:
    """Combine closed destination effects with operation-specific totality."""
    destination = instruction.dst
    if type(destination) is not IRValue or destination.space is not MemSpace.TMP:
        return False
    if instruction.call_stack_effect is not None or not _total_scalar_sources(instruction.args, boolean_bits or {}):
        return False
    effect = scalar_instruction_effect_8616(instruction)
    if effect.kind is not ScalarInstructionEffectKind8616.CLOSED_DESTINATION:
        return False
    if instruction.op == "MOV":
        return True
    if scalar_binary_operation_8616(instruction.op) is not None:
        return True
    for classifier in (_classify_comparison_8616, _classify_boolean_binary_8616,
                       _classify_widening_product_8616, _classify_select_8616):
        classified = classifier(instruction)
        if classified is not None and classified.kind is ScalarInstructionEffectKind8616.CLOSED_DESTINATION:
            return True
    return False


def _boolean_definition_bits(instruction: IRInstr, boolean_bits: dict[int, int]) -> int | None:
    """Preserve predicate width from a closed producer or authenticated conversion."""
    result_bits = scalar_boolean_result_bits_8616(instruction)
    if result_bits is not None:
        return result_bits
    if instruction.op != "MOV" or len(instruction.args) != 1:
        return None
    source = instruction.args[0]
    if type(source) is not IRValue or source.active_unary is None:
        return None
    operand = source.active_unary.operand
    proven_bits = boolean_bits.get(operand.source_tmp) if operand.source_tmp is not None else None
    projection = scalar_active_unary_projection_8616(source, proven_operand_bits=proven_bits)
    return 1 if projection is not None and projection.target_bits == 1 else None


def refuse_dead_temporary_normalization_8616(block: IRBlock) -> DeadTemporaryNormalizationResult8616:
    """Keep every row unchanged when any required evidence remains unbounded."""
    decisions = tuple(DeadTemporaryDecision8616(index, DeadTemporaryDecisionKind8616.UNKNOWN_REFUSE)
                      for index in range(len(block.instrs)))
    return DeadTemporaryNormalizationResult8616(
        block, DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE, decisions,
        DeadTemporaryNormalizationStats8616(len(block.instrs), len(block.instrs), 0, 0, 1),
    )


def _origin_coordinates_valid(origin: IRInstructionOrigin8616, block_addr: int) -> bool:
    """Require exact source coordinates and marker types before deleting rows."""
    return (
        _exact_tmp_id(origin.block_addr) and origin.block_addr == block_addr
        and _exact_tmp_id(origin.statement_index)
        and type(origin.is_block_next) is bool
        and type(origin.is_instruction_mark) is bool
    )


def _instruction_roots(instruction: IRInstr, block_addr: int) -> tuple[object, ...] | None:
    """Retain arguments, input destinations and exact source-coordinate pins."""
    if type(instruction.args) is not tuple or type(instruction.op) is not str or type(instruction.size) is not int:
        return None
    if instruction.dst is not None and type(instruction.dst) is not IRValue:
        return None
    roots: tuple[object, ...] = instruction.args
    if instruction.dst is not None and (instruction.dst.space is not MemSpace.TMP or instruction.op == "CALL"):
        roots += (instruction.dst,)
    origin = instruction.origin
    if origin is not None:
        if type(origin) is not IRInstructionOrigin8616 or not _origin_coordinates_valid(origin, block_addr):
            return None
        for pin in (origin.address_tmp, origin.block_next_tmp):
            if pin is not None:
                if not _exact_tmp_id(pin):
                    return None
                roots += (IRValue(MemSpace.TMP, source_tmp=pin),)
    return roots


def _collect_block_facts(
    block: IRBlock,
) -> tuple[dict[int, int], list[frozenset[int]], list[bool]] | None:
    """Require unique definitions and complete reads in exact original order."""
    definitions: dict[int, int] = {}
    dependencies: list[frozenset[int]] = []
    pure: list[bool] = []
    boolean_bits: dict[int, int] = {}
    for index, instruction in enumerate(block.instrs):
        roots = _instruction_roots(instruction, block.addr)
        if roots is None:
            return None
        reads = read_dead_temporary_dependencies_8616(roots)
        if reads.status is DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE or not reads.tmp_ids <= definitions.keys():
            return None
        dependencies.append(reads.tmp_ids)
        is_pure = _pure_total_definition(instruction, boolean_bits)
        destination = instruction.dst
        if destination is not None:
            if read_dead_temporary_dependencies_8616(destination).status is DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE:
                return None
            if destination.space is MemSpace.TMP and instruction.op != "CALL":
                pin = destination.source_tmp
                if pin is None or pin in definitions:
                    return None
                definitions[pin] = index
                result_bits = _boolean_definition_bits(instruction, boolean_bits) if is_pure else None
                if result_bits is not None:
                    boolean_bits[pin] = result_bits
        pure.append(is_pure)
    return definitions, dependencies, pure


def normalize_dead_temporaries_8616(
    block: IRBlock,
    external_payloads: tuple[object, ...] = (),
    external_live_tmp_ids: frozenset[int] = frozenset(),
) -> DeadTemporaryNormalizationResult8616:
    """Remove exact dead pure-total TMP chains; incomplete evidence keeps the block."""
    if type(external_payloads) is not tuple or type(external_live_tmp_ids) is not frozenset:
        return refuse_dead_temporary_normalization_8616(block)
    if not all(_exact_tmp_id(pin) for pin in external_live_tmp_ids):
        return refuse_dead_temporary_normalization_8616(block)
    external = read_dead_temporary_dependencies_8616(external_payloads)
    if external.status is DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE:
        return refuse_dead_temporary_normalization_8616(block)
    facts = _collect_block_facts(block)
    if facts is None:
        return refuse_dead_temporary_normalization_8616(block)
    definitions, dependencies, pure = facts
    live = set(external.tmp_ids | external_live_tmp_ids)
    if not live <= definitions.keys():
        return refuse_dead_temporary_normalization_8616(block)
    keep: set[int] = set()
    for index in range(len(block.instrs) - 1, -1, -1):
        destination = block.instrs[index].dst
        if not pure[index] or (destination is not None and destination.source_tmp in live):
            keep.add(index)
            live.update(dependencies[index])
    decisions = tuple(DeadTemporaryDecision8616(index, DeadTemporaryDecisionKind8616.KEEP_LIVE
                                              if index in keep else DeadTemporaryDecisionKind8616.REMOVE_DEAD_TOTAL)
                      for index in range(len(block.instrs)))
    instrs = tuple(instruction for index, instruction in enumerate(block.instrs) if index in keep)
    removed = len(block.instrs) - len(instrs)
    return DeadTemporaryNormalizationResult8616(
        replace(block, instrs=instrs) if removed else block, DeadTemporaryNormalizationStatus8616.COMPLETE,
        decisions, DeadTemporaryNormalizationStats8616(len(block.instrs), len(instrs), removed, removed, 0),
    )


def dead_temporary_normalization_producers_8616() -> tuple[object, ...]:
    """Bind every owning operation/dependency authority consumed by this pass."""
    return (normalize_dead_temporaries_8616, read_dead_temporary_dependencies_8616,
            refuse_dead_temporary_normalization_8616, _exact_tmp_id, _value_metadata_valid, _unary_operand_dependencies_valid, _unary_view_dependencies_valid, _value_children,
            _dependency_children, _condition_dependency_children, _total_scalar_sources,
            _pure_total_definition, _boolean_definition_bits, _instruction_roots, _origin_coordinates_valid, _collect_block_facts,
            scalar_instruction_effect_8616, scalar_binary_operation_8616, scalar_active_unary_projection_8616,
            _classify_comparison_8616, _classify_boolean_binary_8616, _classify_widening_product_8616,
            _classify_select_8616, scalar_select_result_bits_8616,
            scalar_owner_8616._SELECT_BITS_8616,
            scalar_boolean_result_bits_8616, scalar_owner_8616.scalar_dispatch_producers_8616,
            *scalar_owner_8616.scalar_dispatch_producers_8616())

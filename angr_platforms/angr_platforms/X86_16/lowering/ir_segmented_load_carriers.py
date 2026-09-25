"""Replay exact segmented IR loads into retained structured register carriers.

Layer: Types/Lowering
Responsibility: consume proven function IR LOAD and same-instruction register
write facts only for unresolved carriers; preserve earlier typed object lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not guess across missing temporary and instruction provenance.
"""

from __future__ import annotations

import copy
import functools
import logging
import os
from dataclasses import dataclass
from typing import Protocol, cast

from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable
from archinfo import Arch

from ..c_ast_utils import (
    _iter_c_nodes_deep_8616,
    _replace_c_children_8616,
    _structured_codegen_node_8616,
    _structured_slot_names_8616,
)
from ..ir.core import AddressStatus, IRAddress, IRBinaryValue, IRValue, MemSpace, SegmentOrigin
from ..ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from ..ir.logical_memory_register_transfer import trace_logical_word_register_transfer_8616
from ..ir.logical_memory_register_transfer_contracts import (
    LogicalMemoryRegisterTransfer8616,
    LogicalMemoryRegisterTransferKind8616,
)
from ..ir.segment_state import SegmentStateArtifact
from ..ir.ssa_cfg import build_ssa_cfg_snapshot_8616, compute_ssa_dominators_8616
from .gp_register_state import (
    gp_live_in_names_from_ssa_8616,
    runtime_gp_live_in_name_8616,
    runtime_gp_state_expr_8616,
)
from .segment_access_policy import instruction_addrs_from_node_8616
from .segment_register_state import runtime_segment_state_cvar_8616
from .segmented_load_origins import materialize_segmented_load_origins_8616

__all__ = ["IRSegmentedLoadCarrierStats8616", "materialize_ir_segmented_load_carriers_8616"]


class _Project8616(Protocol):
    """Angr project architecture consumed by register and SimType construction."""

    arch: Arch


class _CFunction8616(Protocol):
    """Structured function fields mutated by carrier replay."""

    addr: int
    statements: object


class _Codegen8616(Protocol):
    """Dynamic codegen boundary consumed by carrier replay."""

    project: _Project8616 | None
    cfunc: _CFunction8616 | None
    _inertia_segment_state_artifact: SegmentStateArtifact
    _inertia_ir_segmented_load_carrier_stats_8616: IRSegmentedLoadCarrierStats8616


@dataclass(frozen=True, slots=True)
class IRSegmentedLoadCarrierStats8616:
    """Closed evidence loop for direct segmented-load carrier replay."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class _SegmentedLoadFact8616:
    """One exact IR load fact keyed by temporary and instruction identity."""

    temporary_id: int
    instruction_addr: int
    address: IRAddress
    segment_constant: int | None


@dataclass(frozen=True, slots=True)
class _RegisterWriteFact8616:
    """One exact IR register write containing a proven segmented LOAD leaf."""

    register_name: str
    instruction_addr: int
    value: IRValue | IRBinaryValue
    loads_by_temporary: dict[int, _SegmentedLoadFact8616]


@dataclass(frozen=True, slots=True)
class _LogicalRegisterWriteFact8616:
    """One proven logical word reload into an exact physical register."""

    register_name: str
    block_addr: int
    instruction_addr: int
    address: IRAddress


@dataclass(frozen=True, slots=True)
class _RegisterSSAIdentity8616:
    """Exact structured-codegen identity shared with def-use validation."""

    reg: int
    size: int
    region: int
    ident: int | str


@dataclass(frozen=True, slots=True)
class _LogicalAssignmentMaterialization8616:
    """Inserted reload keys and SSA identities now owned by those assignments."""

    keys: frozenset[tuple[str, str, int]]
    identities: frozenset[_RegisterSSAIdentity8616]


def _store_stats_8616(
    codegen: _Codegen8616,
    stats: IRSegmentedLoadCarrierStats8616,
) -> None:
    """Publish closed counters and optionally expose worker-process diagnostics."""
    codegen._inertia_ir_segmented_load_carrier_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS"):
        logging.getLogger(__name__).warning(
            "IR segmented-load carriers function=%#x raw=%d normalized=%d classified=%d materialized=%d failures=%d",
            codegen.cfunc.addr if codegen.cfunc is not None else -1,
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        )


def _debug_assignment_identity_8616(node: structured_c.CAssignment) -> None:
    """Report bounded third-party AST identity only when explicitly requested."""
    if not os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS"):
        return
    lhs = node.lhs
    variable = lhs.variable if isinstance(lhs, structured_c.CVariable) else None
    if not isinstance(variable, SimRegisterVariable):
        return
    logging.getLogger(__name__).warning(
        "IR segmented-load carrier AST lhs=%s variable=%s name=%r reg=%r size=%r insn_addrs=%r tags=%r",
        type(lhs).__name__,
        type(variable).__name__,
        variable.name,
        variable.reg,
        variable.size,
        instruction_addrs_from_node_8616(node),
        node.tags,
    )


def _temporary_id_8616(node: object) -> int | None:
    """Return an explicit temporary ID without parsing rendered names."""
    if isinstance(node, structured_c.CDirtyExpression):
        dirty = node.dirty
        temporary_id = dirty.tmp_idx
        if dirty.category is VirtualVariableCategory.TMP and isinstance(temporary_id, int):
            return temporary_id
        return None
    if isinstance(node, structured_c.CVariable) and isinstance(node.variable, SimTemporaryVariable):
        temporary_id = node.variable.tmp_id
        return temporary_id if isinstance(temporary_id, int) else None
    return None


def _owned_load_fact_8616(
    temporary_node: object,
    provenance_node: object,
    facts: dict[tuple[int, int], _SegmentedLoadFact8616],
) -> _SegmentedLoadFact8616 | None:
    """Select one load only when temporary and instruction identities agree."""
    temporary_id = _temporary_id_8616(temporary_node)
    if temporary_id is None:
        return None
    matches = tuple(
        facts[(temporary_id, instruction_addr)]
        for instruction_addr in instruction_addrs_from_node_8616(provenance_node)
        if (temporary_id, instruction_addr) in facts
    )
    return matches[0] if len(matches) == 1 else None


def _iter_dereference_operands_8616(node: object) -> tuple[object, ...]:
    """Return dereference nodes reachable through bounded value operators."""
    if isinstance(node, structured_c.CUnaryOp):
        return (node,) if node.op == "Dereference" else ()
    if isinstance(node, structured_c.CBinaryOp):
        return (
            *_iter_dereference_operands_8616(node.lhs),
            *_iter_dereference_operands_8616(node.rhs),
        )
    if isinstance(node, structured_c.CTypeCast):
        return _iter_dereference_operands_8616(node.expr)
    return ()


def _additive_terms_8616(node: object, sign: int = 1) -> tuple[tuple[int, object], ...]:
    """Flatten only additive structured-C address terms without rewriting them."""
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _additive_terms_8616(node.lhs, sign) + _additive_terms_8616(node.rhs, sign)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
        return _additive_terms_8616(node.lhs, sign) + _additive_terms_8616(node.rhs, -sign)
    return ((sign, node),)


def _register_shapes_in_expr_8616(node: object) -> frozenset[tuple[int, int]]:
    """Collect physical register shapes from one bounded address expression."""
    shapes: set[tuple[int, int]] = set()
    for _sign, term in _additive_terms_8616(node):
        if not isinstance(term, structured_c.CVariable):
            continue
        for variable in (term.unified_variable, term.variable):
            if (
                isinstance(variable, SimRegisterVariable)
                and isinstance(variable.reg, int)
                and isinstance(variable.size, int)
            ):
                shapes.add((variable.reg, variable.size))
    return frozenset(shapes)


def _constant_integer_expr_8616(node: object) -> int | None:
    """Evaluate a bounded, side-effect-free integer expression or refuse it."""
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, structured_c.CTypeCast):
        return _constant_integer_expr_8616(node.expr)
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    lhs = _constant_integer_expr_8616(node.lhs)
    rhs = _constant_integer_expr_8616(node.rhs)
    if lhs is None or rhs is None:
        return None
    if node.op == "Add":
        return lhs + rhs
    if node.op == "Sub":
        return lhs - rhs
    if node.op == "Mul":
        return lhs * rhs
    if node.op == "Shl" and 0 <= rhs < 64:
        return lhs << rhs
    return None


def _matches_constant_segment_linear_load_8616(
    codegen: _Codegen8616,
    expression: object,
    fact: _SegmentedLoadFact8616,
) -> bool:
    """Prove that an integer dereference is one lane of an exact IR load.

    The segment constant, logical address, width, and source instruction all
    come from owned IR. Structured C contributes only the still-visible linear
    base and physical-register address terms. An arbitrary integer dereference
    therefore remains untouched.
    """
    return _constant_segment_offset_expr_8616(codegen, expression, fact) is not None


def _matching_linear_base_indexes_8616(
    terms: tuple[tuple[int, object], ...],
    constant_values: tuple[int | None, ...],
    linear_base: int,
    allowed_lanes: frozenset[int],
) -> tuple[int, ...]:
    """Indexes whose constant term can serve as the segment linear base."""
    matching: list[int] = []
    for index, ((sign, _term), value) in enumerate(zip(terms, constant_values, strict=True)):
        if (
            value is None
            or sign != 1
            or not linear_base <= value <= linear_base + 0xFFFF
        ):
            continue
        residual = value - linear_base + sum(
            other_sign * other_value
            for other_index, ((other_sign, _other_term), other_value) in enumerate(
                zip(terms, constant_values, strict=True)
            )
            if other_index != index and other_value is not None
        )
        if residual in allowed_lanes:
            matching.append(index)
    return tuple(matching)


def _residual_offset_expr_8616(
    codegen: _Codegen8616,
    terms: tuple[tuple[int, object], ...],
    base_index: int,
    base_value: int,
    linear_base: int,
) -> object | None:
    """Rebuild the additive offset after removing the linear base term."""
    offset_terms: list[tuple[int, object]] = []
    for index, (sign, term) in enumerate(terms):
        if index == base_index:
            residual = base_value - linear_base
            if residual:
                offset_terms.append(
                    (
                        1,
                        structured_c.CConstant(
                            residual,
                            SimTypeShort(False),
                            codegen=codegen,
                        ),
                    )
                )
            continue
        offset_terms.append((sign, term))
    result: object | None = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen) if not offset_terms else None
    for sign, term in offset_terms:
        if result is None:
            result = (
                term
                if sign == 1
                else structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    term,
                    codegen=codegen,
                )
            )
        else:
            result = structured_c.CBinaryOp(
                "Add" if sign == 1 else "Sub",
                result,
                term,
                codegen=codegen,
            )
    return result


def _constant_segment_offset_expr_8616(
    codegen: _Codegen8616,
    dereference: object,
    fact: _SegmentedLoadFact8616,
) -> object | None:
    """Recover one SSA-preserving offset from an IR-proven linear dereference."""
    project = codegen.project
    segment = fact.segment_constant
    if (
        project is None
        or segment is None
        or not isinstance(dereference, structured_c.CUnaryOp)
        or dereference.op != "Dereference"
    ):
        return None
    required_shapes = {
        project.arch.registers[value.name][:2]
        for value in fact.address.base_values
        if value.space is MemSpace.REG
        and isinstance(value.name, str)
        and value.name in project.arch.registers
    }
    if len(required_shapes) != len(fact.address.base_values):
        return None
    linear_base = (segment & 0xFFFF) << 4
    first_lane = fact.address.offset & 0xFFFF
    allowed_lanes = frozenset(
        (first_lane + lane) & 0xFFFF
        for lane in range(max(int(fact.address.size), 1))
    )
    operand = dereference.operand
    if not required_shapes.issubset(_register_shapes_in_expr_8616(operand)):
        return None
    terms = _additive_terms_8616(operand)
    constant_values = tuple(_constant_integer_expr_8616(term) for _sign, term in terms)
    matching_bases = _matching_linear_base_indexes_8616(
        terms, constant_values, linear_base, allowed_lanes
    )
    if len(matching_bases) != 1:
        return None
    base_index = matching_bases[0]
    base_value = constant_values[base_index]
    if base_value is None:
        return None
    return _residual_offset_expr_8616(codegen, terms, base_index, base_value, linear_base)


def _constant_segment_helper_for_dereference_8616(
    codegen: _Codegen8616,
    dereference: object,
    facts: tuple[_SegmentedLoadFact8616, ...],
) -> tuple[structured_c.CFunctionCall, _SegmentedLoadFact8616] | None:
    """Materialize one uniquely matched dereference while retaining its SSA offset."""
    matches = tuple(
        (fact, offset)
        for fact in facts
        if (offset := _constant_segment_offset_expr_8616(codegen, dereference, fact)) is not None
    )
    if len(matches) != 1:
        return None
    fact, offset = matches[0]
    helper = {1: "SEG_U8", 2: "SEG_U16", 4: "SEG_U32"}.get(fact.address.size)
    if helper is None or fact.segment_constant is None:
        return None
    return (
        structured_c.CFunctionCall(
            helper,
            None,
            [
                structured_c.CConstant(
                    fact.segment_constant,
                    SimTypeShort(False),
                    codegen=codegen,
                ),
                offset,
            ],
            codegen=codegen,
            tags={
                "inertia_x86_16_runtime_segment_helper": helper,
                "inertia_source_instruction_addrs": (fact.instruction_addr,),
            },
        ),
        fact,
    )


def _constant_segment_facts_for_assignment_8616(
    codegen: _Codegen8616,
    assignment: structured_c.CAssignment,
    facts: dict[tuple[int, int], _SegmentedLoadFact8616],
) -> tuple[_SegmentedLoadFact8616, ...]:
    """Return unique instruction-owned facts matched by a linear C dereference."""
    matched: dict[tuple[int, MemSpace, tuple[str, ...], int, int], _SegmentedLoadFact8616] = {}
    instruction_addrs = instruction_addrs_from_node_8616(assignment)
    if os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS"):
        candidates = tuple(
            fact
            for fact in facts.values()
            if fact.instruction_addr in instruction_addrs and fact.segment_constant is not None
        )
        if candidates:
            logging.getLogger(__name__).warning(
                "IR segmented-load linear candidate insns=%r rhs=%s derefs=%d facts=%r",
                tuple(sorted(instruction_addrs)),
                type(assignment.rhs).__name__,
                len(_iter_dereference_operands_8616(assignment.rhs)),
                tuple(
                    (fact.instruction_addr, fact.address.base, fact.address.offset, fact.address.size)
                    for fact in candidates
                ),
            )
    for fact in facts.values():
        if fact.instruction_addr not in instruction_addrs:
            continue
        if not any(
            _matches_constant_segment_linear_load_8616(codegen, dereference, fact)
            for dereference in (
                assignment.rhs,
                *_iter_dereference_operands_8616(assignment.rhs),
            )
        ):
            continue
        key = (
            fact.instruction_addr,
            fact.address.space,
            fact.address.base,
            fact.address.offset,
            fact.address.size,
        )
        matched[key] = fact
    return tuple(matched.values())


def _register_expr_8616(
    codegen: _Codegen8616, register_name: str
) -> structured_c.CVariable | None:
    """Build one architecture-backed physical-register expression."""
    project = codegen.project
    if project is None:
        return None
    shape = project.arch.registers.get(register_name)
    if shape is None or len(shape) < 2:
        return None
    offset, size = shape[:2]
    return structured_c.CVariable(
        SimRegisterVariable(offset, size, name=register_name),
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )


def _offset_base_terms_8616(
    codegen: _Codegen8616,
    cfunc: _CFunction8616 | None,
    live_ins: frozenset[str],
    address: IRAddress,
) -> tuple[list[str], list[object]] | None:
    """Project each address base register to its runtime/GP expression."""
    register_names: list[str] = []
    terms: list[object] = []
    for value in address.base_values:
        if value.space is not MemSpace.REG or not isinstance(value.name, str):
            return None
        runtime_name = runtime_gp_live_in_name_8616(value.name)
        register = (
            runtime_gp_state_expr_8616(
                value.name,
                codegen=codegen,
                function_addr=cfunc.addr,
            )
            if cfunc is not None and runtime_name in live_ins
            else _register_expr_8616(codegen, value.name)
        )
        if os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS"):
            logging.getLogger(__name__).warning(
                "IR segmented-load offset base=%s canonical=%r live_ins=%r runtime=%s",
                value.name,
                runtime_name,
                tuple(sorted(live_ins)),
                cfunc is not None and runtime_name in live_ins,
            )
        if register is None:
            return None
        register_names.append(value.name)
        terms.append(register)
    return register_names, terms


def _offset_expr_8616(codegen: _Codegen8616, address: IRAddress) -> object | None:
    """Project one exact register-plus-displacement segmented offset."""
    project = codegen.project
    cfunc = codegen.cfunc
    live_ins: frozenset[str] = frozenset()
    if project is not None and cfunc is not None:
        resolution = registered_function_ssa_artifact_8616(project, cfunc.addr)
        if resolution.verdict is FunctionSSAArtifactVerdict8616.PROVEN and resolution.artifact is not None:
            live_ins = gp_live_in_names_from_ssa_8616(resolution.artifact)
    resolved = _offset_base_terms_8616(codegen, cfunc, live_ins, address)
    if resolved is None:
        return None
    register_names, terms = resolved
    if tuple(register_names) != address.base:
        return None
    expression: object | None = None
    for term in terms:
        expression = term if expression is None else structured_c.CBinaryOp("Add", expression, term, codegen=codegen)
    if address.offset:
        displacement = structured_c.CConstant(abs(address.offset), SimTypeShort(False), codegen=codegen)
        if expression is None:
            expression = structured_c.CConstant(address.offset & 0xFFFF, SimTypeShort(False), codegen=codegen)
        else:
            expression = structured_c.CBinaryOp(
                "Add" if address.offset > 0 else "Sub", expression, displacement, codegen=codegen
            )
    return expression or structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)


def _track_mov_constants_8616(
    instruction: object,
    register_constants: dict[str, int],
    segment_constants: dict[MemSpace, int],
) -> None:
    """Track constant propagation through ``MOV`` into GP/segment registers."""
    destination = instruction.dst
    if not (
        instruction.op == "MOV"
        and isinstance(destination, IRValue)
        and destination.space is MemSpace.REG
        and isinstance(destination.name, str)
        and len(instruction.args) == 1
        and isinstance(instruction.args[0], IRValue)
    ):
        return
    source = instruction.args[0]
    constant = (
        source.const
        if source.space is MemSpace.CONST and isinstance(source.const, int)
        else register_constants.get(source.name)
        if source.space is MemSpace.REG and isinstance(source.name, str)
        else None
    )
    if constant is None:
        register_constants.pop(destination.name, None)
    else:
        register_constants[destination.name] = constant & 0xFFFF
    if destination.name in {"ds", "es", "ss"}:
        segment_space = MemSpace(destination.name)
        if constant is None:
            segment_constants.pop(segment_space, None)
        else:
            segment_constants[segment_space] = constant & 0xFFFF


def _stable_load_address_8616(instruction: object) -> IRAddress | None:
    """Return the instruction's stable segmented load address, if proven."""
    destination = instruction.dst
    if not (
        instruction.op == "LOAD"
        and isinstance(instruction.addr, int)
        and isinstance(destination, IRValue)
        and destination.space is MemSpace.TMP
        and isinstance(destination.source_tmp, int)
        and len(instruction.args) == 1
        and isinstance(instruction.args[0], IRAddress)
    ):
        return None
    address = instruction.args[0]
    if (
        address.space not in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
        or address.status is not AddressStatus.STABLE
        or address.segment_origin is not SegmentOrigin.PROVEN
        or address.size not in {1, 2, 4}
    ):
        return None
    return address


def _debug_load_fact_8616(fact: _SegmentedLoadFact8616) -> None:
    """Emit one segmented-load fact debug line."""
    if not os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS"):
        return
    logging.getLogger(__name__).warning(
        "IR segmented-load fact tmp=%d insn=%#x space=%s base=%r offset=%#x width=%d segment=%r",
        fact.temporary_id,
        fact.instruction_addr,
        fact.address.space.value,
        fact.address.base,
        fact.address.offset,
        fact.address.size,
        fact.segment_constant,
    )


def _load_facts_8616(codegen: _Codegen8616) -> dict[tuple[int, int], _SegmentedLoadFact8616]:
    """Collect exact stable loads with explicit VEX temporary provenance."""
    project = codegen.project
    cfunc = codegen.cfunc
    if project is None or cfunc is None:
        return {}
    resolution = registered_function_ir_artifact_8616(project, cfunc.addr)
    if resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN or resolution.artifact is None:
        return {}
    try:
        segment_state = codegen._inertia_segment_state_artifact
    except AttributeError:
        segment_state = None
    candidates: dict[tuple[int, int], _SegmentedLoadFact8616 | None] = {}
    for block in resolution.artifact.blocks:
        register_constants: dict[str, int] = {}
        segment_constants: dict[MemSpace, int] = {}
        for instruction in block.instrs:
            _track_mov_constants_8616(instruction, register_constants, segment_constants)
            address = _stable_load_address_8616(instruction)
            if address is None:
                continue
            destination = instruction.dst
            segment_constant = segment_constants.get(address.space)
            if segment_constant is None and isinstance(segment_state, SegmentStateArtifact):
                state = segment_state.state_before_instruction(
                    instruction.addr,
                    address.space.value,
                )
                segment_constant = state.constant_value() if state is not None else None
            fact = _SegmentedLoadFact8616(
                destination.source_tmp,
                instruction.addr,
                address,
                segment_constant,
            )
            _debug_load_fact_8616(fact)
            key = (fact.temporary_id, fact.instruction_addr)
            candidates[key] = fact if key not in candidates else None
    return {key: fact for key, fact in candidates.items() if fact is not None}


def _ir_load_dependencies_8616(
    value: object, loads_by_temporary: dict[int, _SegmentedLoadFact8616]
) -> tuple[_SegmentedLoadFact8616, ...] | None:
    """Return all exact segmented-load leaves of one bounded IR value."""
    if isinstance(value, IRValue):
        if value.space is MemSpace.TMP:
            if not isinstance(value.source_tmp, int):
                return None
            fact = loads_by_temporary.get(value.source_tmp)
            return (fact,) if fact is not None else None
        return () if value.space in {MemSpace.REG, MemSpace.CONST} else None
    if isinstance(value, IRBinaryValue):
        lhs = _ir_load_dependencies_8616(value.lhs, loads_by_temporary)
        rhs = _ir_load_dependencies_8616(value.rhs, loads_by_temporary)
        return None if lhs is None or rhs is None else (*lhs, *rhs)
    return None


def _register_write_facts_8616(
    codegen: _Codegen8616,
    load_facts: dict[tuple[int, int], _SegmentedLoadFact8616],
) -> dict[tuple[str, int], _RegisterWriteFact8616]:
    """Collect unambiguous same-instruction register writes using LOAD leaves."""
    project = codegen.project
    cfunc = codegen.cfunc
    if project is None or cfunc is None:
        return {}
    resolution = registered_function_ir_artifact_8616(project, cfunc.addr)
    if resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN or resolution.artifact is None:
        return {}
    loads_by_addr: dict[int, dict[int, _SegmentedLoadFact8616]] = {}
    for fact in load_facts.values():
        loads_by_addr.setdefault(fact.instruction_addr, {})[fact.temporary_id] = fact
    candidates: dict[tuple[str, int], _RegisterWriteFact8616 | None] = {}
    for block in resolution.artifact.blocks:
        for instruction in block.instrs:
            destination = instruction.dst
            if not (
                instruction.op == "MOV"
                and isinstance(instruction.addr, int)
                and isinstance(destination, IRValue)
                and destination.space is MemSpace.REG
                and isinstance(destination.name, str)
                and len(instruction.args) == 1
                and isinstance(instruction.args[0], (IRValue, IRBinaryValue))
            ):
                continue
            loads = loads_by_addr.get(instruction.addr, {})
            dependencies = _ir_load_dependencies_8616(instruction.args[0], loads)
            if not dependencies:
                continue
            write_fact = _RegisterWriteFact8616(
                destination.name.lower(), instruction.addr, instruction.args[0], loads
            )
            key = (write_fact.register_name, write_fact.instruction_addr)
            candidates[key] = write_fact if key not in candidates else None
    return {key: fact for key, fact in candidates.items() if fact is not None}


def _logical_register_write_facts_8616(
    codegen: _Codegen8616,
) -> dict[tuple[str, int], _LogicalRegisterWriteFact8616]:
    """Collect exact logical word reloads from the authoritative SSA contract."""
    project = codegen.project
    cfunc = codegen.cfunc
    if project is None or cfunc is None:
        return {}
    resolution = registered_function_ssa_artifact_8616(project, cfunc.addr)
    artifact = resolution.artifact
    if (
        resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
        or artifact is None
        or artifact.logical_memory is None
        or not artifact.logical_memory.closed
    ):
        return {}
    candidates: dict[tuple[str, int], _LogicalRegisterWriteFact8616 | None] = {}
    instruction_blocks = {
        instruction.addr: block.addr
        for block in artifact.blocks
        for instruction in block.instrs
        if isinstance(instruction.addr, int)
    }
    for access in artifact.logical_memory.accesses:
        transfer = trace_logical_word_register_transfer_8616(artifact, access)
        if not (
            isinstance(transfer, LogicalMemoryRegisterTransfer8616)
            and transfer.kind is LogicalMemoryRegisterTransferKind8616.RELOAD
            and transfer.complete
            and isinstance(transfer.register.name, str)
        ):
            continue
        fact = _LogicalRegisterWriteFact8616(
            transfer.register.name.lower(),
            instruction_blocks.get(access.key.insn_addr, -1),
            access.key.insn_addr,
            access.address,
        )
        if fact.block_addr < 0:
            continue
        key = (fact.register_name, fact.instruction_addr)
        candidates[key] = fact if key not in candidates else None
    return {key: fact for key, fact in candidates.items() if fact is not None}


def _register_ssa_identity_8616(node: object) -> _RegisterSSAIdentity8616 | None:
    """Return the same exact structured register identity used by validation."""
    if not isinstance(node, structured_c.CVariable):
        return None
    for variable in (node.unified_variable, node.variable):
        if (
            isinstance(variable, SimRegisterVariable)
            and isinstance(variable.reg, int)
            and isinstance(variable.size, int)
            and isinstance(variable.region, int)
            and isinstance(variable.ident, (int, str))
        ):
            return _RegisterSSAIdentity8616(variable.reg, variable.size, variable.region, variable.ident)
    return None


def _same_block_reload_for_read_8616(
    codegen: _Codegen8616,
    identity: _RegisterSSAIdentity8616,
    use_addr: int,
    logical_facts: dict[tuple[str, int], _LogicalRegisterWriteFact8616],
) -> _LogicalRegisterWriteFact8616 | None:
    """Prove a stable same-block reload; refuse absent ordering provenance."""
    project = codegen.project
    cfunc = codegen.cfunc
    if project is None or cfunc is None:
        return None
    register_names = _identity_register_names_8616(project, identity)
    if len(register_names) != 1:
        return None
    resolution = registered_function_ssa_artifact_8616(project, cfunc.addr)
    if resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN or resolution.artifact is None:
        return None
    block = _use_block_for_addr_8616(resolution.artifact, use_addr)
    if block is None:
        return None
    candidates = tuple(
        fact
        for fact in logical_facts.values()
        if fact.register_name in register_names
        and fact.block_addr == block.addr
        and fact.instruction_addr <= use_addr
    )
    if not candidates:
        return None
    candidate = max(candidates, key=lambda fact: fact.instruction_addr)
    base_registers = {
        value.name.lower()
        for value in candidate.address.base_values
        if value.space is MemSpace.REG and isinstance(value.name, str)
    }
    clobber_names = base_registers | register_names
    if not _same_block_window_clear_8616(block, candidate, use_addr, clobber_names):
        return None
    return candidate


def _same_block_window_clear_8616(
    block: object,
    candidate: _LogicalRegisterWriteFact8616,
    use_addr: int,
    clobber_names: frozenset[str],
) -> bool:
    """True when no CALL/STORE/register write crosses the candidate→use window."""
    for instruction in block.instrs:
        if instruction.addr is None:
            return False
        if not (candidate.instruction_addr < instruction.addr < use_addr):
            continue
        destination = instruction.dst
        if instruction.op in {"CALL", "STORE"}:
            return False
        if (
            isinstance(destination, IRValue)
            and destination.space is MemSpace.REG
            and isinstance(destination.name, str)
            and destination.name.lower() in clobber_names
        ):
            return False
    return True


def _collect_inherited_addresses_8616(
    value: object,
    inherited: frozenset[int] | None,
    active: frozenset[int],
    inherited_addresses: dict[int, frozenset[int] | None],
) -> None:
    """Propagate one nearest exact instruction identity through AST children."""
    if isinstance(value, dict):
        for child in value.values():
            _collect_inherited_addresses_8616(child, inherited, active, inherited_addresses)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _collect_inherited_addresses_8616(child, inherited, active, inherited_addresses)
        return
    if not _structured_codegen_node_8616(value) or id(value) in active:
        return
    marker = id(value)
    direct = instruction_addrs_from_node_8616(value)
    current = direct if len(direct) == 1 else inherited
    if current is None and isinstance(
        value,
        (
            structured_c.CDoWhileLoop,
            structured_c.CForLoop,
            structured_c.CWhileLoop,
        ),
    ):
        body_addresses = {
            address
            for child in _iter_c_nodes_deep_8616(value.body)
            for address in instruction_addrs_from_node_8616(child)
        }
        if body_addresses:
            current = frozenset({min(body_addresses)})
    previous = inherited_addresses.get(marker, current)
    inherited_addresses[marker] = current if previous == current else None
    child_active = active | {marker}
    for attr in _structured_slot_names_8616(value):
        try:
            # Dynamic third-party angr C-AST boundary: slot names vary by release.
            child = getattr(value, attr)
        except Exception:
            continue
        _collect_inherited_addresses_8616(child, current, child_active, inherited_addresses)


def _inherited_instruction_addresses_8616(
    root: object,
) -> dict[int, frozenset[int] | None]:
    """Map each AST occurrence to its nearest unambiguous instruction provenance."""
    inherited_addresses: dict[int, frozenset[int] | None] = {}
    _collect_inherited_addresses_8616(root, None, frozenset(), inherited_addresses)
    return inherited_addresses


def _identity_register_names_8616(
    project: _Project8616,
    identity: _RegisterSSAIdentity8616,
) -> frozenset[str]:
    """Register names matching the SSA identity's reg+size shape."""
    return frozenset(
        name.lower()
        for name, shape in project.arch.registers.items()
        if len(shape) >= 2 and shape[:2] == (identity.reg, identity.size)
    )


def _use_block_for_addr_8616(artifact: object, use_addr: int) -> object | None:
    """Return the unique SSA block containing ``use_addr``."""
    blocks = tuple(
        block
        for block in artifact.blocks
        if any(instruction.addr == use_addr for instruction in block.instrs)
    )
    return blocks[0] if len(blocks) == 1 else None


def _debug_nearest_fact_8616(
    identity: _RegisterSSAIdentity8616,
    use_addr: int,
    use_block: object,
    logical_facts: dict[tuple[str, int], _LogicalRegisterWriteFact8616],
    names: frozenset[str],
) -> None:
    """Emit the nearest-fact debug line for tracked identities."""
    if not (
        os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS")
        and identity.ident in {"ir_3", "ir_4", "ir_5", "ir_6", "ir_9"}
    ):
        return
    logging.getLogger(__name__).warning(
        "IR segmented-load placement identity=%r use=%#x block=%#x facts=%r",
        identity,
        use_addr,
        use_block.addr,
        tuple(
            (fact.register_name, fact.block_addr, fact.instruction_addr)
            for fact in logical_facts.values()
            if fact.register_name in names
        ),
    )


def _nearest_dominating_fact_8616(
    logical_facts: dict[tuple[str, int], _LogicalRegisterWriteFact8616],
    names: frozenset[str],
    dominators: object,
    use_block_addr: int,
    use_addr: int,
) -> _LogicalRegisterWriteFact8616 | None:
    """Select the deepest dominating reload candidate before the use."""
    candidates = tuple(
        fact
        for fact in logical_facts.values()
        if fact.register_name in names
        and dominators.dominates(fact.block_addr, use_block_addr) is True
        and (fact.block_addr != use_block_addr or fact.instruction_addr < use_addr)
    )
    if not candidates:
        return None
    depths = {
        fact.block_addr: len(dominators.dominators(fact.block_addr) or ())
        for fact in candidates
    }
    nearest_depth = max(depths.values())
    nearest = tuple(fact for fact in candidates if depths[fact.block_addr] == nearest_depth)
    return max(nearest, key=lambda fact: fact.instruction_addr)


def _ssa_reachable_set_8616(edges: object, seed: int, stop: int) -> set[int]:
    """Blocks reachable from ``seed`` along ``edges``, stopping at ``stop``."""
    reached = {seed}
    pending = [seed]
    while pending:
        block_addr = pending.pop()
        if block_addr == stop:
            continue
        for successor in edges(block_addr) or ():
            if successor not in reached:
                reached.add(successor)
                pending.append(successor)
    return reached


def _path_window_instructions_clear_8616(
    block: object,
    block_addr: int,
    candidate: _LogicalRegisterWriteFact8616,
    use_block_addr: int,
    use_addr: int,
    clobber_names: frozenset[str],
) -> bool:
    """True when no CALL/STORE/clobber write crosses the candidate→use window."""
    for instruction in block.instrs:
        if instruction.addr is None and block_addr in (candidate.block_addr, use_block_addr):
            return False
        if instruction.addr is not None:
            if block_addr == candidate.block_addr and instruction.addr <= candidate.instruction_addr:
                continue
            if block_addr == use_block_addr and instruction.addr >= use_addr:
                continue
        destination = instruction.dst
        if instruction.op in {"CALL", "STORE"}:
            return False
        if (
            isinstance(destination, IRValue)
            and destination.space is MemSpace.REG
            and isinstance(destination.name, str)
            and destination.name.lower() in clobber_names
        ):
            return False
    return True


def _nearest_linear_logical_fact_8616(
    codegen: _Codegen8616,
    identity: _RegisterSSAIdentity8616,
    use_addr: int,
    logical_facts: dict[tuple[str, int], _LogicalRegisterWriteFact8616],
) -> _LogicalRegisterWriteFact8616 | None:
    """Select a dominating reload on proven mutation-free paths; refuse unknown boundaries."""
    project = codegen.project
    cfunc = codegen.cfunc
    if project is None or cfunc is None:
        return None
    names = _identity_register_names_8616(project, identity)
    if len(names) != 1:
        return None
    resolution = registered_function_ssa_artifact_8616(project, cfunc.addr)
    if resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN or resolution.artifact is None:
        return None
    use_block = _use_block_for_addr_8616(resolution.artifact, use_addr)
    if use_block is None:
        return None
    _debug_nearest_fact_8616(identity, use_addr, use_block, logical_facts, names)
    snapshot = build_ssa_cfg_snapshot_8616(resolution.artifact)
    dominators = compute_ssa_dominators_8616(snapshot)
    if not snapshot.complete or not dominators.complete:
        return None
    use_block_addr = use_block.addr
    candidate = _nearest_dominating_fact_8616(
        logical_facts, names, dominators, use_block_addr, use_addr
    )
    if candidate is None:
        return None
    base_registers = {
        value.name.lower()
        for value in candidate.address.base_values
        if value.space is MemSpace.REG and isinstance(value.name, str)
    }
    blocks_by_addr = {block.addr: block for block in resolution.artifact.blocks}
    forward = _ssa_reachable_set_8616(snapshot.successors, candidate.block_addr, use_block_addr)
    reverse = _ssa_reachable_set_8616(snapshot.predecessors, use_block_addr, candidate.block_addr)
    path_blocks = forward & reverse
    if candidate.block_addr not in path_blocks or use_block_addr not in path_blocks:
        return None
    clobber_names = base_registers | names
    for block_addr in sorted(path_blocks):
        block = blocks_by_addr.get(block_addr)
        if block is None or not _path_window_instructions_clear_8616(
            block, block_addr, candidate, use_block_addr, use_addr, clobber_names
        ):
            return None
    return candidate


def _collect_owner_paths_8616(
    value: object,
    owners: tuple[int, ...],
    in_condition: bool,
    active: frozenset[int],
    use_ids: frozenset[int],
    ordinary_owner_paths: list[tuple[int, ...]],
    condition_owner_paths: list[tuple[int, ...]],
) -> None:
    """Record ancestry across the dynamic third-party angr C-AST boundary."""
    if isinstance(value, dict):
        for child in value.values():
            _collect_owner_paths_8616(
                child, owners, in_condition, active, use_ids, ordinary_owner_paths, condition_owner_paths
            )
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _collect_owner_paths_8616(
                child, owners, in_condition, active, use_ids, ordinary_owner_paths, condition_owner_paths
            )
        return
    if not _structured_codegen_node_8616(value) or id(value) in active:
        return
    marker = id(value)
    current_owners = (*owners, marker) if isinstance(value, structured_c.CStatements) else owners
    if marker in use_ids:
        (condition_owner_paths if in_condition else ordinary_owner_paths).append(current_owners)
    child_active = active | {marker}
    for attr in _structured_slot_names_8616(value):
        try:
            child = getattr(value, attr)
        except Exception:
            continue
        is_loop_condition = isinstance(
            value,
            (
                structured_c.CDoWhileLoop,
                structured_c.CForLoop,
                structured_c.CWhileLoop,
            ),
        ) and attr == "condition"
        _collect_owner_paths_8616(
            child,
            current_owners,
            in_condition or is_loop_condition,
            child_active,
            use_ids,
            ordinary_owner_paths,
            condition_owner_paths,
        )


def _insertion_candidates_8616(
    root: object,
    owner_ids: set[int],
    owner_depths: dict[int, int],
    load_addr: int,
    first_use_addr: int,
) -> list[tuple[int, int, list[object], int, bool]]:
    """Collect (nearest following address, owner depth, statements, index, is_loop)."""
    candidates: list[tuple[int, int, list[object], int, bool]] = []
    for container in _iter_c_nodes_deep_8616(root):
        if not isinstance(container, structured_c.CStatements):
            continue
        if id(container) not in owner_ids:
            continue
        statements = container.statements
        if not isinstance(statements, list):
            continue
        for index, statement in enumerate(tuple(statements)):
            following = tuple(
                address
                for address in instruction_addrs_from_node_8616(statement)
                if load_addr < address <= first_use_addr
            )
            if following:
                candidates.append(
                    (
                        min(following),
                        owner_depths[id(container)],
                        statements,
                        index,
                        isinstance(
                            statement,
                            (
                                structured_c.CDoWhileLoop,
                                structured_c.CForLoop,
                                structured_c.CWhileLoop,
                            ),
                        ),
                    )
                )
    return candidates


def _select_unique_insertion_8616(
    candidates: list[tuple[int, int, list[object], int, bool]],
    load_addr: int,
    first_use_addr: int,
) -> tuple[list[object], int] | None:
    """Resolve tie-breaking to a unique (statements, index) insertion site."""
    nearest_addr = min(candidate[0] for candidate in candidates)
    nearest = tuple(candidate for candidate in candidates if candidate[0] == nearest_addr)
    deepest_owner = max(candidate[1] for candidate in nearest)
    nearest = tuple(candidate for candidate in nearest if candidate[1] == deepest_owner)
    loop_boundaries = tuple(candidate for candidate in nearest if candidate[4])
    if loop_boundaries:
        nearest = loop_boundaries
    locations = {
        (id(statements), index)
        for _addr, _depth, statements, index, _is_loop in nearest
    }
    if len(locations) != 1:
        container_ids = {
            id(statements)
            for _addr, _depth, statements, _index, _is_loop in nearest
        }
        if len(container_ids) == 1:
            nearest = (min(nearest, key=lambda candidate: candidate[3]),)
            locations = {(id(nearest[0][2]), nearest[0][3])}
    if len(locations) != 1:
        if os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS"):
            logging.getLogger(__name__).warning(
                "IR segmented-load insertion refused load=%#x use=%#x candidates=%r",
                load_addr,
                first_use_addr,
                tuple(
                    (addr, depth, index, is_loop)
                    for addr, depth, _statements, index, is_loop in nearest
                ),
            )
        return None
    _addr, _depth, statements, index, _is_loop = nearest[0]
    return statements, index


def _insert_before_unique_following_statement_8616(
    root: object,
    load_addr: int,
    first_use_addr: int,
    assignment: structured_c.CAssignment,
    use_occurrences: tuple[structured_c.CVariable, ...],
) -> bool:
    """Insert in the structured statement ancestry that owns the exact SSA use."""
    use_ids = {id(node) for node in use_occurrences}
    ordinary_owner_paths: list[tuple[int, ...]] = []
    condition_owner_paths: list[tuple[int, ...]] = []
    _collect_owner_paths_8616(
        root, (), False, frozenset(), frozenset(use_ids), ordinary_owner_paths, condition_owner_paths
    )
    selected_paths = condition_owner_paths or ordinary_owner_paths
    owner_ids = (
        set.intersection(*(set(path) for path in selected_paths))
        if selected_paths
        else set()
    )
    owner_depths = {
        owner: max(path.index(owner) for path in selected_paths if owner in path)
        for owner in owner_ids
    }
    candidates = _insertion_candidates_8616(root, owner_ids, owner_depths, load_addr, first_use_addr)
    if not candidates:
        return False
    site = _select_unique_insertion_8616(candidates, load_addr, first_use_addr)
    if site is None:
        return False
    statements, index = site
    statements.insert(index, assignment)
    return True


def _collect_register_def_reads_8616(
    statements: object,
) -> tuple[
    dict[_RegisterSSAIdentity8616, set[int]],
    dict[_RegisterSSAIdentity8616, list[structured_c.CVariable]],
]:
    """Collect SSA definition addresses and read occurrences per identity."""
    definitions: dict[_RegisterSSAIdentity8616, set[int]] = {}
    lhs_ids: set[int] = set()
    for node in _iter_c_nodes_deep_8616(statements):
        if not isinstance(node, structured_c.CAssignment):
            continue
        lhs_ids.add(id(node.lhs))
        identity = _register_ssa_identity_8616(node.lhs)
        definition_addresses = instruction_addrs_from_node_8616(node)
        if identity is not None and len(definition_addresses) == 1:
            definitions.setdefault(identity, set()).add(next(iter(definition_addresses)))
    reads: dict[_RegisterSSAIdentity8616, list[structured_c.CVariable]] = {}
    for node in _iter_c_nodes_deep_8616(statements):
        if id(node) in lhs_ids or not isinstance(node, structured_c.CVariable):
            continue
        identity = _register_ssa_identity_8616(node)
        if identity is not None:
            reads.setdefault(identity, []).append(node)
    return definitions, reads


def _debug_logical_insertion_8616(
    identity: _RegisterSSAIdentity8616,
    use_addrs: set[int],
    definitions: dict[_RegisterSSAIdentity8616, set[int]],
    fact: _LogicalRegisterWriteFact8616,
    inserted: bool,
) -> None:
    """Emit the insertion debug line for tracked identities."""
    if not (
        os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS")
        and identity.ident in {"ir_3", "ir_4", "ir_5", "ir_6", "ir_9"}
    ):
        return
    logging.getLogger(__name__).warning(
        "IR segmented-load insertion identity=%r uses=%r definitions=%r fact=(%#x,%#x) inserted=%s",
        identity,
        tuple(sorted(use_addrs)),
        tuple(sorted(definitions.get(identity, ()))),
        fact.block_addr,
        fact.instruction_addr,
        inserted,
    )


def _materialize_identity_assignment_8616(
    codegen: _Codegen8616,
    identity: _RegisterSSAIdentity8616,
    occurrences: list[structured_c.CVariable],
    provenance: dict[int, frozenset[int] | None],
    definitions: dict[_RegisterSSAIdentity8616, set[int]],
    logical_facts: dict[tuple[str, int], _LogicalRegisterWriteFact8616],
) -> tuple[str, str, int] | None:
    """Insert one missing SSA assignment at its uniquely proven boundary."""
    cfunc = codegen.cfunc
    use_addrs = {
        next(iter(addresses))
        for node in occurrences
        if (addresses := provenance.get(id(node))) is not None and len(addresses) == 1
    }
    if not use_addrs or cfunc is None:
        return None
    first_use = min(use_addrs)
    if any(address < first_use for address in definitions.get(identity, ())):
        return None
    fact = _nearest_linear_logical_fact_8616(
        codegen,
        identity,
        first_use,
        logical_facts,
    )
    if fact is None:
        return None
    source = _helper_for_address_8616(codegen, fact.address, fact.instruction_addr)
    if source is None:
        return None
    lhs = copy.copy(occurrences[0])
    assignment = structured_c.CAssignment(
        lhs,
        source,
        codegen=codegen,
        tags={
            "ins_addr": fact.instruction_addr,
            "inertia_source_instruction_addrs": (fact.instruction_addr,),
        },
    )
    inserted = _insert_before_unique_following_statement_8616(
        cfunc.statements,
        fact.instruction_addr,
        first_use,
        assignment,
        tuple(
            node
            for node in occurrences
            if provenance.get(id(node)) == frozenset({first_use})
        ),
    )
    _debug_logical_insertion_8616(identity, use_addrs, definitions, fact, inserted)
    if not inserted:
        return None
    return ("reg", fact.register_name, fact.instruction_addr)


def _materialize_missing_logical_assignments_8616(
    codegen: _Codegen8616,
    logical_facts: dict[tuple[str, int], _LogicalRegisterWriteFact8616],
) -> _LogicalAssignmentMaterialization8616:
    """Restore exact missing SSA assignments at proven structured boundaries."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return _LogicalAssignmentMaterialization8616(frozenset(), frozenset())
    provenance = _inherited_instruction_addresses_8616(cfunc.statements)
    definitions, reads = _collect_register_def_reads_8616(cfunc.statements)
    materialized: set[tuple[str, str, int]] = set()
    materialized_identities: set[_RegisterSSAIdentity8616] = set()
    for identity, occurrences in reads.items():
        key = _materialize_identity_assignment_8616(
            codegen,
            identity,
            occurrences,
            provenance,
            definitions,
            logical_facts,
        )
        if key is not None:
            materialized.add(key)
            materialized_identities.add(identity)
    return _LogicalAssignmentMaterialization8616(
        frozenset(materialized),
        frozenset(materialized_identities),
    )


def _read_side_logical_replacements_8616(
    codegen: _Codegen8616,
    logical_facts: dict[tuple[str, int], _LogicalRegisterWriteFact8616],
    assignment_owned_identities: frozenset[_RegisterSSAIdentity8616],
) -> dict[int, _LogicalRegisterWriteFact8616]:
    """Classify exact SSA reads that may safely replay a stable logical reload."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return {}
    definitions = tuple(
        node.lhs
        for node in _iter_c_nodes_deep_8616(cfunc.statements)
        if isinstance(node, structured_c.CAssignment)
    )
    lhs_nodes = {id(node) for node in definitions}
    # Existing SSA definitions own their saved values, just like inserted ones.
    # Replaying their reads can discard lowered address terms and reread memory.
    assignment_owned_identities = assignment_owned_identities.union(
        identity for node in definitions if (identity := _register_ssa_identity_8616(node)) is not None
    )
    inherited_addresses = _inherited_instruction_addresses_8616(cfunc.statements)
    replacements: dict[int, _LogicalRegisterWriteFact8616] = {}
    for node in _iter_c_nodes_deep_8616(cfunc.statements):
        fact = _read_replacement_for_node_8616(
            codegen,
            node,
            lhs_nodes,
            assignment_owned_identities,
            inherited_addresses,
            logical_facts,
        )
        if fact is not None:
            replacements[id(node)] = fact
    return replacements


def _read_replacement_for_node_8616(
    codegen: _Codegen8616,
    node: object,
    lhs_nodes: set[int],
    assignment_owned_identities: frozenset[_RegisterSSAIdentity8616],
    inherited_addresses: dict[int, frozenset[int] | None],
    logical_facts: dict[tuple[str, int], _LogicalRegisterWriteFact8616],
) -> _LogicalRegisterWriteFact8616 | None:
    """Classify one read-side variable against same-block reload facts."""
    if id(node) in lhs_nodes or not isinstance(node, structured_c.CVariable):
        return None
    identity = _register_ssa_identity_8616(node)
    if identity is None:
        if os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS"):
            logging.getLogger(__name__).warning(
                "IR segmented-load read refused identity variable=%r unified=%r",
                node.variable,
                node.unified_variable,
            )
        return None
    if identity in assignment_owned_identities:
        return None
    direct_addresses = instruction_addrs_from_node_8616(node)
    addresses = direct_addresses or inherited_addresses.get(id(node)) or frozenset()
    if len(addresses) != 1:
        if os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS"):
            logging.getLogger(__name__).warning(
                "IR segmented-load read refused provenance identity=%r direct=%r inherited=%r",
                identity,
                direct_addresses,
                inherited_addresses.get(id(node)),
            )
        return None
    fact = _same_block_reload_for_read_8616(
        codegen,
        identity,
        next(iter(addresses)),
        logical_facts,
    )
    if fact is None and os.environ.get("INERTIA_DEBUG_IR_SEGMENTED_LOAD_CARRIERS"):
        logging.getLogger(__name__).warning(
            "IR segmented-load read refused flow identity=%r use=%#x",
            identity,
            next(iter(addresses)),
        )
    return fact


def _register_name_from_node_8616(codegen: _Codegen8616, node: object) -> str | None:
    """Return one exact physical register name from a structured destination."""
    if isinstance(node, structured_c.CVariable) and isinstance(node.variable, SimRegisterVariable):
        shape = (node.variable.reg, node.variable.size)
    elif isinstance(node, structured_c.CDirtyExpression):
        dirty = node.dirty
        if dirty.category is not VirtualVariableCategory.REGISTER:
            return None
        shape = (dirty.oident, dirty.size)
    else:
        return None
    project = codegen.project
    if project is None:
        return None
    names = {
        name.lower()
        for name, register_shape in project.arch.registers.items()
        if len(register_shape) >= 2 and register_shape[:2] == shape
    }
    return next(iter(names)) if len(names) == 1 else None


def _ir_value_expr_8616(
    codegen: _Codegen8616,
    value: IRValue | IRBinaryValue,
    loads_by_temporary: dict[int, _SegmentedLoadFact8616],
) -> object | None:
    """Project one bounded IR value using only exact owned leaves."""
    if isinstance(value, IRValue):
        if value.space is MemSpace.REG and isinstance(value.name, str):
            return _register_expr_8616(codegen, value.name)
        if value.space is MemSpace.CONST and isinstance(value.const, int):
            return cast(
                object,
                structured_c.CConstant(value.const, SimTypeShort(False), codegen=codegen),
            )
        if value.space is MemSpace.TMP and isinstance(value.source_tmp, int):
            fact = loads_by_temporary.get(value.source_tmp)
            return _helper_for_fact_8616(codegen, fact) if fact is not None else None
        return None
    lhs = _ir_value_expr_8616(codegen, value.lhs, loads_by_temporary)
    rhs = _ir_value_expr_8616(codegen, value.rhs, loads_by_temporary)
    if lhs is None or rhs is None:
        return None
    operation = value.op.rstrip("0123456789")
    c_operation = {name: name for name in ("Add", "And", "Mul", "Or", "Sar", "Shl", "Shr", "Sub", "Xor")}.get(operation)
    return structured_c.CBinaryOp(c_operation, lhs, rhs, codegen=codegen) if c_operation is not None else None


def _helper_for_fact_8616(
    codegen: _Codegen8616, fact: _SegmentedLoadFact8616
) -> structured_c.CFunctionCall | None:
    """Build one segmented helper from a directly owned load fact."""
    return _helper_for_address_8616(
        codegen,
        fact.address,
        fact.instruction_addr,
        segment_constant=fact.segment_constant,
    )


def _helper_for_address_8616(
    codegen: _Codegen8616,
    address: IRAddress,
    instruction_addr: int,
    *,
    segment_constant: int | None = None,
) -> structured_c.CFunctionCall | None:
    """Build one segmented helper from an exact logical address."""
    cfunc = codegen.cfunc
    segment_type = SimTypeShort(False).with_arch(codegen.project.arch) if codegen.project is not None else None
    segment = (
        structured_c.CConstant(segment_constant, SimTypeShort(False), codegen=codegen)
        if segment_constant is not None
        else runtime_segment_state_cvar_8616(
            address.space.value,
            codegen=codegen,
            variable_type=segment_type,
            function_addr=cfunc.addr,
        )
        if cfunc is not None
        else None
    )
    offset = _offset_expr_8616(codegen, address)
    if segment is None or offset is None:
        return None
    helper = {1: "SEG_U8", 2: "SEG_U16", 4: "SEG_U32"}[address.size]
    return structured_c.CFunctionCall(
        helper,
        None,
        [segment, offset],
        codegen=codegen,
        tags={
            "inertia_x86_16_runtime_segment_helper": helper,
            "inertia_source_instruction_addrs": (instruction_addr,),
        },
    )


def _replace_constant_dereference_8616(
    value: object,
    *,
    boundary: _Codegen8616,
    constant_facts: tuple[_SegmentedLoadFact8616, ...],
    replaced_facts: list[_SegmentedLoadFact8616],
) -> object:
    """Replace one exact constant-segment dereference leaf."""
    replacement = _constant_segment_helper_for_dereference_8616(
        boundary,
        value,
        constant_facts,
    )
    if replacement is None:
        return value
    helper, replaced_fact = replacement
    replaced_facts.append(replaced_fact)
    return helper


_CarrierKey8616 = tuple[str, int, int] | tuple[str, str, int]


@dataclass(slots=True)
class _CarrierTransform8616:
    """Mutable state shared by segmented-load carrier transform dispatch."""

    boundary: _Codegen8616
    facts: dict[tuple[int, int], _SegmentedLoadFact8616]
    register_facts: dict[tuple[str, int], _RegisterWriteFact8616]
    logical_register_facts: dict[tuple[str, int], _LogicalRegisterWriteFact8616]
    read_replacements: dict[int, _LogicalRegisterWriteFact8616]
    classified: set[_CarrierKey8616]
    materialized: set[_CarrierKey8616]

    def transform(self, node: object) -> object:
        """Replace only nodes with exact temporary/instruction or register/instruction ownership."""
        replaced = self._read_replacement(node)
        if replaced is not None:
            return replaced
        if isinstance(node, structured_c.CAssignment):
            return self._assignment(node)
        return self._dirty(node)

    def _read_replacement(self, node: object) -> object | None:
        """Replay a classified read-side reload, or continue dispatch."""
        read_fact = self.read_replacements.get(id(node))
        if read_fact is None:
            return None
        read_key = ("reg", read_fact.register_name, read_fact.instruction_addr)
        self.classified.add(read_key)
        replacement = _helper_for_address_8616(
            self.boundary,
            read_fact.address,
            read_fact.instruction_addr,
        )
        if replacement is None:
            return None
        self.materialized.add(read_key)
        return replacement

    def _assignment(self, node: structured_c.CAssignment) -> object:
        """Replay segmented helpers into one proven assignment carrier."""
        _debug_assignment_identity_8616(node)
        fact = _owned_load_fact_8616(node.lhs, node, self.facts)
        if fact is not None:
            key = ("tmp", fact.temporary_id, fact.instruction_addr)
            self.classified.add(key)
            replacement = _helper_for_fact_8616(self.boundary, fact)
            if replacement is not None:
                node.rhs = replacement
                self.materialized.add(key)
            return node
        register_name = _register_name_from_node_8616(self.boundary, node.lhs)
        if self._constant_segment_rhs(node):
            return node
        if register_name is None:
            return node
        if not (
            isinstance(node.rhs, (structured_c.CConstant, structured_c.CDirtyExpression))
            or (
                isinstance(node.rhs, structured_c.CVariable)
                and isinstance(node.rhs.variable, SimTemporaryVariable)
            )
        ):
            return node
        if self._logical_assignment(node, register_name):
            return node
        return self._register_assignment(node, register_name)

    def _constant_segment_rhs(self, node: structured_c.CAssignment) -> bool:
        """Replace exact constant-segment dereference leaves inside the rhs."""
        constant_fact_tuple = tuple(
            _constant_segment_facts_for_assignment_8616(
                self.boundary,
                node,
                self.facts,
            )
        )
        replaced_facts: list[_SegmentedLoadFact8616] = []
        new_rhs = _replace_constant_dereference_8616(
            node.rhs,
            boundary=self.boundary,
            constant_facts=constant_fact_tuple,
            replaced_facts=replaced_facts,
        )
        if new_rhs is node.rhs:
            _replace_c_children_8616(
                node.rhs,
                functools.partial(
                    _replace_constant_dereference_8616,
                    boundary=self.boundary,
                    constant_facts=constant_fact_tuple,
                    replaced_facts=replaced_facts,
                ),
            )
        else:
            node.rhs = new_rhs
        for replaced_fact in replaced_facts:
            direct_key = (
                "tmp",
                replaced_fact.temporary_id,
                replaced_fact.instruction_addr,
            )
            self.classified.add(direct_key)
            self.materialized.add(direct_key)
        return bool(replaced_facts)

    def _logical_assignment(self, node: structured_c.CAssignment, register_name: str) -> bool:
        """Replay a proven logical reload into an unmodified scalar rhs."""
        logical_matches = tuple(
            self.logical_register_facts[(register_name, instruction_addr)]
            for instruction_addr in instruction_addrs_from_node_8616(node)
            if (register_name, instruction_addr) in self.logical_register_facts
        )
        if not logical_matches:
            return False
        logical_fact = max(
            logical_matches,
            key=lambda candidate: candidate.instruction_addr,
        )
        logical_key = (
            "reg",
            logical_fact.register_name,
            logical_fact.instruction_addr,
        )
        self.classified.add(logical_key)
        replacement = _helper_for_address_8616(
            self.boundary,
            logical_fact.address,
            logical_fact.instruction_addr,
        )
        if replacement is not None:
            node.rhs = replacement
            self.materialized.add(logical_key)
        return True

    def _register_assignment(self, node: structured_c.CAssignment, register_name: str) -> object:
        """Replay a same-instruction register write value into the rhs."""
        matches = tuple(
            self.register_facts[(register_name, instruction_addr)]
            for instruction_addr in instruction_addrs_from_node_8616(node)
            if (register_name, instruction_addr) in self.register_facts
        )
        if not matches:
            return node
        register_fact = max(matches, key=lambda candidate: candidate.instruction_addr)
        register_key = ("reg", register_fact.register_name, register_fact.instruction_addr)
        self.classified.add(register_key)
        replacement = _ir_value_expr_8616(
            self.boundary, register_fact.value, register_fact.loads_by_temporary
        )
        if replacement is not None:
            node.rhs = replacement
            self.materialized.add(register_key)
        return node

    def _dirty(self, node: object) -> object:
        """Replay a temporary dirty expression owned by one exact load."""
        if not isinstance(node, structured_c.CDirtyExpression):
            return node
        fact = _owned_load_fact_8616(node, node, self.facts)
        if fact is None:
            return node
        key = ("tmp", fact.temporary_id, fact.instruction_addr)
        self.classified.add(key)
        replacement = _helper_for_fact_8616(self.boundary, fact)
        if replacement is None:
            return node
        self.materialized.add(key)
        return replacement


def materialize_ir_segmented_load_carriers_8616(codegen: object) -> bool:
    """Materialize exact segmented LOADs in retained temporary/register carriers."""
    boundary = cast(_Codegen8616, codegen)
    facts = _load_facts_8616(boundary)
    register_facts = _register_write_facts_8616(boundary, facts)
    logical_register_facts = _logical_register_write_facts_8616(boundary)
    cfunc = boundary.cfunc
    if cfunc is None or not (facts or logical_register_facts):
        _store_stats_8616(
            boundary,
            IRSegmentedLoadCarrierStats8616(len(facts), len(facts), 0, 0, 0),
        )
        return False
    inserted_assignments = _materialize_missing_logical_assignments_8616(
        boundary,
        logical_register_facts,
    )
    classified: set[_CarrierKey8616] = set(inserted_assignments.keys)
    materialized: set[_CarrierKey8616] = set(inserted_assignments.keys)
    origin_keys = materialize_segmented_load_origins_8616(codegen, frozenset(facts))
    materialized.update(("tmp", temporary_id, instruction_addr) for temporary_id, instruction_addr in origin_keys)
    classified.update(materialized)
    transform_ctx = _CarrierTransform8616(
        boundary=boundary,
        facts=facts,
        register_facts=register_facts,
        logical_register_facts=logical_register_facts,
        read_replacements=_read_side_logical_replacements_8616(
            boundary,
            logical_register_facts,
            inserted_assignments.identities,
        ),
        classified=classified,
        materialized=materialized,
    )
    transform_ctx.transform(cfunc.statements)
    _replace_c_children_8616(cfunc.statements, transform_ctx.transform)
    _store_stats_8616(
        boundary,
        IRSegmentedLoadCarrierStats8616(
            raw_fact_count=len(facts) + len(register_facts) + len(logical_register_facts),
            normalized_fact_count=len(facts) + len(register_facts) + len(logical_register_facts),
            classified_fact_count=len(classified),
            materialized_count=len(materialized),
            failure_count=len(classified - materialized),
        ),
    )
    return bool(materialized)

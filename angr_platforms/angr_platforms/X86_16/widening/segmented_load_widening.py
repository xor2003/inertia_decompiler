"""Prove and materialize adjacent segmented scalar loads as wider values.

Layer: Widening.
Responsibility: join exact adjacent segmented-load identities after Alias and
materialize lowering-owned byte pairs before Rewrite consumes the wider value.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

import builtins
import logging
import os
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CStatements,
    CTypeCast,
    CVariable,
)
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable
from capstone.x86_const import X86_INS_MOV, X86_OP_MEM, X86_OP_REG

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616, _same_c_expression_8616
from ..frontend_function_instructions import collect_function_instruction_inventory_8616
from ..ir.core import SEGMENTED_LOAD_ADDRESS_TAG_8616, IRAddress, IRValue, MemSpace
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from .segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_identity_8616,
    segmented_load_tags_8616,
)

__all__ = [
    "SegmentedLoadWideningReport8616",
    "apply_segmented_load_widening_8616",
    "join_adjacent_segmented_load_identities_8616",
]

log: logging.Logger = logging.getLogger(__name__)


class _CFunctionBoundary8616(Protocol):
    """Owned fields consumed from the dynamic angr C-function boundary."""

    addr: int


class _CodegenBoundary8616(Protocol):
    """Owned view of widening metadata attached to the dynamic angr codegen."""

    cfunc: _CFunctionBoundary8616
    project: object
    _inertia_segmented_load_widening_report_8616: SegmentedLoadWideningReport8616


@dataclass(frozen=True, slots=True)
class SegmentedLoadWideningReport8616:
    """Closed evidence loop for adjacent segmented-load widening."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _dynamic_cfunc_attr_8616(cfunc: object, name: str) -> object | None:
    """Read version-dependent attributes at the dynamic angr C-function boundary."""
    return builtins.getattr(cfunc, name, None)


def _dynamic_cfunc_setattr_8616(cfunc: object, name: str, value: object) -> None:
    """Write version-dependent attributes at the dynamic angr C-function boundary."""
    builtins.setattr(cfunc, name, value)


def join_adjacent_segmented_load_identities_8616(
    low: SegmentedLoadIdentity8616 | None,
    high: SegmentedLoadIdentity8616 | None,
) -> SegmentedLoadIdentity8616 | None:
    """Return the exact two-byte identity for two proven adjacent byte loads."""
    if low is None or high is None:
        return None
    if low.width != 1 or high.width != 1:
        return None
    if low.space is not high.space or low.region != high.region:
        return None
    if low.offset == 0xFFFF or high.offset != low.offset + 1:
        return None
    return SegmentedLoadIdentity8616(
        space=low.space,
        offset=low.offset,
        width=2,
        region=low.region,
    )


def _strip_casts_8616(node: object) -> object:
    """Return an expression without syntax-only casts."""
    while isinstance(node, CTypeCast):
        node = node.expr
    return node


def _pure_constant_value_8616(node: object) -> int | None:
    """Evaluate integer-only offset and shift expressions."""
    node = _strip_casts_8616(node)
    if isinstance(node, CConstant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if not isinstance(node, CBinaryOp):
        return None
    lhs = _pure_constant_value_8616(node.lhs)
    rhs = _pure_constant_value_8616(node.rhs)
    if lhs is None or rhs is None:
        return None
    if node.op == "Add":
        return lhs + rhs
    if node.op == "Sub":
        return lhs - rhs
    if node.op == "Mul":
        return lhs * rhs
    if node.op == "Shl" and 0 <= rhs <= 63:
        return lhs << rhs
    return None


def _flatten_offset_terms_8616(
    node: object,
    sign: int = 1,
) -> tuple[int, tuple[tuple[int, object], ...]]:
    """Split an offset into a constant and signed symbolic terms."""
    node = _strip_casts_8616(node)
    constant = _pure_constant_value_8616(node)
    if constant is not None:
        return sign * constant, ()
    if isinstance(node, CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs_constant, lhs_terms = _flatten_offset_terms_8616(node.lhs, sign)
        rhs_sign = sign if node.op == "Add" else -sign
        rhs_constant, rhs_terms = _flatten_offset_terms_8616(node.rhs, rhs_sign)
        return lhs_constant + rhs_constant, lhs_terms + rhs_terms
    return 0, ((sign, node),)


def _same_signed_terms_8616(
    lhs: tuple[tuple[int, object], ...],
    rhs: tuple[tuple[int, object], ...],
) -> bool:
    """Return whether two symbolic offset term multisets are equal."""
    unmatched = list(rhs)
    for lhs_sign, lhs_node in lhs:
        match_index = next(
            (
                index
                for index, (rhs_sign, rhs_node) in enumerate(unmatched)
                if lhs_sign == rhs_sign and _same_c_expression_8616(lhs_node, rhs_node)
            ),
            None,
        )
        if match_index is None:
            return False
        del unmatched[match_index]
    return not unmatched


def _adjacent_offsets_8616(low: object, high: object) -> bool:
    """Prove that two structured offsets differ by exactly one byte."""
    low_constant, low_terms = _flatten_offset_terms_8616(low)
    high_constant, high_terms = _flatten_offset_terms_8616(high)
    return high_constant == low_constant + 1 and _same_signed_terms_8616(low_terms, high_terms)


def _segmented_byte_load_8616(node: object) -> tuple[CFunctionCall, object, object] | None:
    """Return a lowering-owned segmented byte load and its arguments."""
    node = _strip_casts_8616(node)
    if not isinstance(node, CFunctionCall) or not isinstance(node.tags, dict):
        return None
    if node.tags.get("inertia_x86_16_runtime_segment_helper") != "SEG_U8":
        return None
    address = node.tags.get(SEGMENTED_LOAD_ADDRESS_TAG_8616)
    # A register-relative offset can cross FFFFh; SEG_U16 is a contiguous lvalue.
    if isinstance(address, IRAddress) and (address.base or address.base_values):
        return None
    if not isinstance(node.args, (list, tuple)) or len(node.args) != 2:
        return None
    return node, node.args[0], node.args[1]


def _overwide_segmented_byte_lane_8616(
    node: object,
) -> tuple[CFunctionCall, object, object] | None:
    """Return a word helper used as one lane of an angr byte decomposition."""
    node = _strip_casts_8616(node)
    if not isinstance(node, CFunctionCall) or not isinstance(node.tags, dict):
        return None
    if node.tags.get("inertia_x86_16_runtime_segment_helper") != "SEG_U16":
        return None
    if not isinstance(node.args, (list, tuple)) or len(node.args) != 2:
        return None
    return node, node.args[0], node.args[1]


def _shifted_high_byte_8616(node: object) -> tuple[CFunctionCall, object, object] | None:
    """Return a segmented byte load widened into the high byte position."""
    node = _strip_casts_8616(node)
    if not isinstance(node, CBinaryOp):
        return None
    expected = 8 if node.op == "Shl" else 0x100 if node.op == "Mul" else None
    if expected is None:
        return None
    for possible_load, possible_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _pure_constant_value_8616(possible_scale) == expected:
            return _segmented_byte_load_8616(possible_load)
    return None


def _shifted_overwide_segmented_byte_lane_8616(
    node: object,
) -> tuple[CFunctionCall, object, object] | None:
    """Return an over-wide segmented lane shifted into byte position one."""
    node = _strip_casts_8616(node)
    if not isinstance(node, CBinaryOp):
        return None
    expected = 8 if node.op == "Shl" else 0x100 if node.op == "Mul" else None
    if expected is None:
        return None
    for possible_load, possible_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _pure_constant_value_8616(possible_scale) == expected:
            return _overwide_segmented_byte_lane_8616(possible_load)
    return None


def _instruction_addrs_8616(node: object) -> frozenset[int]:
    """Return exact instruction addresses attached at the structured-C boundary."""
    tags = node.tags if isinstance(node, (CAssignment, CFunctionCall)) else None
    if not isinstance(tags, dict):
        return frozenset()
    values: set[int] = set()
    direct = tags.get("ins_addr")
    if isinstance(direct, int):
        values.add(direct)
    source_addrs = tags.get("inertia_source_instruction_addrs")
    if isinstance(source_addrs, (list, tuple, set, frozenset)):
        values.update(value for value in source_addrs if isinstance(value, int))
    return frozenset(values)


def _ssa_segmented_word_mov_addrs_8616(codegen: _CodegenBoundary8616) -> frozenset[int]:
    """Return SSA-proven ``MOV reg16, segmented-address`` instruction sites."""
    cfunc_addr = codegen.cfunc.addr
    if not isinstance(cfunc_addr, int):
        return frozenset()
    resolution = registered_function_ssa_artifact_8616(codegen.project, cfunc_addr)
    if resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN or resolution.artifact is None:
        return frozenset()
    proven: set[int] = set()
    for block in resolution.artifact.blocks:
        for instruction in block.instrs:
            destination = instruction.dst
            if not _is_segmented_word_mov_8616(instruction, destination):
                continue
            if isinstance(instruction.addr, int):
                proven.add(instruction.addr)
    return frozenset(proven)


def _is_segmented_word_mov_8616(instruction: object, destination: object) -> bool:
    """Return whether an instruction is a proven segmented word MOV."""
    if instruction.op.upper() != "MOV" or instruction.size != 2:
        return False
    if not isinstance(destination, IRValue):
        return False
    if destination.space is not MemSpace.REG or destination.size != 2:
        return False
    if len(instruction.args) != 1 or not isinstance(instruction.args[0], IRAddress):
        return False
    return instruction.args[0].space in {MemSpace.DS, MemSpace.ES, MemSpace.SS}


_GP_WORD_REGISTER_NAMES_8616 = frozenset({"ax", "bp", "bx", "cx", "di", "dx", "si", "sp"})


def _decoded_segmented_word_mov_addr_8616(wrapper: object) -> int | None:
    """Return one ``MOV reg16, mem16`` site across the dynamic third-party Capstone boundary."""
    raw = builtins.getattr(wrapper, "insn", wrapper)
    if builtins.getattr(raw, "id", None) != X86_INS_MOV:
        return None
    raw_operands = builtins.getattr(raw, "operands", ())
    if not isinstance(raw_operands, (list, tuple)) or len(raw_operands) != 2:
        return None
    destination, source = raw_operands
    if (
        builtins.getattr(destination, "type", None) != X86_OP_REG
        or builtins.getattr(source, "type", None) != X86_OP_MEM
        or builtins.getattr(destination, "size", None) != 2
        or builtins.getattr(source, "size", None) != 2
    ):
        return None
    register_id = builtins.getattr(destination, "reg", None)
    reg_name = builtins.getattr(raw, "reg_name", None)
    if not isinstance(register_id, int) or not callable(reg_name):
        return None
    try:
        destination_name = str(reg_name(register_id)).lower()
    except (TypeError, ValueError):
        return None
    if destination_name not in _GP_WORD_REGISTER_NAMES_8616:
        return None
    address = builtins.getattr(raw, "address", builtins.getattr(wrapper, "address", None))
    return address if isinstance(address, int) else None


def _decoded_segmented_word_mov_addrs_8616(codegen: _CodegenBoundary8616) -> frozenset[int]:
    """Return complete frontend-decoded ``MOV reg16, mem16`` evidence sites."""
    function_entry = codegen.cfunc.addr
    inventory = collect_function_instruction_inventory_8616(
        codegen.project,
        function_entry=function_entry if isinstance(function_entry, int) else None,
    )
    if not inventory.complete:
        return frozenset()
    return frozenset(
        address
        for instruction in inventory.instructions
        if (address := _decoded_segmented_word_mov_addr_8616(instruction)) is not None
    )


def _temporary_byte_load_assignment_8616(
    statement: object,
) -> tuple[CAssignment, CFunctionCall, object, object] | None:
    """Return one byte-load assignment to a non-observable VEX temporary."""
    if not isinstance(statement, CAssignment) or not isinstance(statement.lhs, CVariable):
        return None
    if (
        not isinstance(statement.lhs.variable, SimTemporaryVariable)
        or statement.lhs.variable.size not in {1, 2}
    ):
        return None
    load = _segmented_byte_load_8616(statement.rhs)
    if load is None:
        return None
    call, segment, offset = load
    return statement, call, segment, offset


def _word_register_assignment_8616(statement: object) -> CAssignment | None:
    """Return one exact 16-bit architectural-register assignment."""
    if not isinstance(statement, CAssignment):
        return None
    lhs = statement.lhs
    if isinstance(lhs, CVariable):
        variable = lhs.variable
        return statement if isinstance(variable, SimRegisterVariable) and variable.size == 2 else None
    if isinstance(lhs, CDirtyExpression):
        dirty = lhs.dirty
        if dirty.category is VirtualVariableCategory.REGISTER and dirty.bits == 16:
            return statement
    return None


def _pure_register_assignment_8616(statement: object) -> bool:
    """Return whether a delayed recomposition may move before this register effect."""
    if not isinstance(statement, CAssignment):
        return False
    lhs = statement.lhs
    if isinstance(lhs, CVariable):
        return isinstance(lhs.variable, SimRegisterVariable)
    if isinstance(lhs, CDirtyExpression):
        return lhs.dirty.category is VirtualVariableCategory.REGISTER
    return False


@dataclass
class _ByteLoadWidenStats8616:
    """Evidence counters for statement-level byte-pair widening."""

    changed: bool = False
    raw: int = 0
    normalized: int = 0
    classified: int = 0
    materialized: int = 0


def _authorized_word_destination_8616(
    statements: list[object],
    index: int,
    first_assignment: object,
    first_call: object,
    second_assignment: object,
    second_call: object,
    proven_mov_addrs: frozenset[int],
) -> tuple[int | None, CAssignment | None, frozenset[int]]:
    """Return the authorized destination assignment index/statement/addrs."""
    load_addrs = (
        _instruction_addrs_8616(first_assignment)
        | _instruction_addrs_8616(first_call)
    ) & (
        _instruction_addrs_8616(second_assignment)
        | _instruction_addrs_8616(second_call)
    )
    for candidate_index in range(index + 2, min(index + 7, len(statements))):
        candidate = _word_register_assignment_8616(statements[candidate_index])
        if candidate is not None:
            candidate_authorized = (
                load_addrs & _instruction_addrs_8616(candidate) & proven_mov_addrs
            )
            if len(candidate_authorized) == 1:
                return candidate_index, candidate, candidate_authorized
        if not _pure_register_assignment_8616(statements[candidate_index]):
            break
    return None, None, frozenset()


def _try_merge_byte_pair_8616(
    statements: list[object],
    index: int,
    rebuilt: list[object],
    *,
    proven_mov_addrs: frozenset[int],
    codegen: _CodegenBoundary8616,
    stats: _ByteLoadWidenStats8616,
) -> int | None:
    """Merge one authorized split-byte pair into a word load, or refuse."""
    first = _temporary_byte_load_assignment_8616(statements[index])
    second = _temporary_byte_load_assignment_8616(statements[index + 1])
    if first is None or second is None:
        return None
    stats.raw += 1
    first_assignment, first_call, first_segment, first_offset = first
    second_assignment, second_call, second_segment, second_offset = second
    if not _same_c_expression_8616(first_segment, second_segment):
        return None
    if _adjacent_offsets_8616(first_offset, second_offset):
        low_call, low_segment, low_offset = first_call, first_segment, first_offset
        high_call = second_call
    elif _adjacent_offsets_8616(second_offset, first_offset):
        low_call, low_segment, low_offset = second_call, second_segment, second_offset
        high_call = first_call
    else:
        return None
    stats.normalized += 1
    destination_index, destination, authorized = _authorized_word_destination_8616(
        statements, index,
        first_assignment, first_call, second_assignment, second_call,
        proven_mov_addrs,
    )
    if destination is None or destination_index is None:
        return None
    stats.classified += 1
    identity = join_adjacent_segmented_load_identities_8616(
        segmented_load_identity_8616(low_call),
        segmented_load_identity_8616(high_call),
    )
    tags: dict[str, object] = {
        "inertia_x86_16_runtime_segment_helper": "SEG_U16",
        "inertia_source_instruction_addrs": tuple(sorted(authorized)),
    }
    if identity is not None:
        tags = segmented_load_tags_8616(identity, existing=tags)
    destination.rhs = CFunctionCall(
        "SEG_U16",
        None,
        [low_segment, low_offset],
        codegen=codegen,
        tags=tags,
    )
    rebuilt.append(destination)
    rebuilt.extend(statements[index + 2 : destination_index])
    stats.materialized += 1
    stats.changed = True
    return destination_index + 1


def _widen_statement_byte_loads_8616(
    root: object,
    *,
    codegen: _CodegenBoundary8616,
    proven_mov_addrs: frozenset[int],
) -> tuple[bool, int, int, int, int]:
    """Collapse typed-evidence-authorized split bytes into one word-register load."""
    stats = _ByteLoadWidenStats8616()
    statement_groups = (
        node
        for node in (root, *_iter_c_nodes_deep_8616(root))
        if isinstance(node, CStatements)
    )
    seen_groups: set[int] = set()
    for group in statement_groups:
        if id(group) in seen_groups:
            continue
        seen_groups.add(id(group))
        statements = list(group.statements)
        rebuilt: list[object] = []
        index = 0
        while index < len(statements):
            if index + 2 >= len(statements):
                rebuilt.extend(statements[index:])
                break
            merged_index = _try_merge_byte_pair_8616(
                statements, index, rebuilt,
                proven_mov_addrs=proven_mov_addrs, codegen=codegen, stats=stats,
            )
            if merged_index is None:
                rebuilt.append(statements[index])
                index += 1
                continue
            index = merged_index
        if stats.changed and rebuilt != statements:
            group.statements = rebuilt
    return stats.changed, stats.raw, stats.normalized, stats.classified, stats.materialized


@dataclass
class _SegmentedLoadWidener8616:
    """Apply typed-evidence widening to one structured C tree."""

    codegen: _CodegenBoundary8616
    proven_mov_addrs: frozenset[int]
    stats: _ByteLoadWidenStats8616 = field(default_factory=_ByteLoadWidenStats8616)

    def _typed_pair(self, node: CBinaryOp) -> object | None:
        """Return a typed-identity SEG_U16 call for one pair, or None."""
        for possible_low, possible_high in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low = _segmented_byte_load_8616(possible_low)
            high = _shifted_high_byte_8616(possible_high)
            if low is None or high is None:
                continue
            self.stats.raw += 1
            low_call, low_segment, low_offset = low
            high_call, high_segment, high_offset = high
            if not _same_c_expression_8616(low_segment, high_segment):
                continue
            self.stats.normalized += 1
            if not _adjacent_offsets_8616(low_offset, high_offset):
                continue
            self.stats.classified += 1
            identity = join_adjacent_segmented_load_identities_8616(
                segmented_load_identity_8616(low_call),
                segmented_load_identity_8616(high_call),
            )
            tags: dict[str, object] = {"inertia_x86_16_runtime_segment_helper": "SEG_U16"}
            if identity is not None:
                tags = segmented_load_tags_8616(identity, existing=tags)
            self.stats.materialized += 1
            return CFunctionCall(
                "SEG_U16",
                None,
                [low_segment, low_offset],
                codegen=self.codegen,
                tags=tags,
            )
        return None

    def _authorized_pair(self, node: CBinaryOp) -> object | None:
        """Return an instruction-authorized SEG_U16 call for one pair, or None."""
        for possible_low, possible_high in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low = _overwide_segmented_byte_lane_8616(possible_low)
            high = _shifted_overwide_segmented_byte_lane_8616(possible_high)
            if low is None or high is None:
                continue
            self.stats.raw += 1
            low_call, low_segment, low_offset = low
            high_call, high_segment, high_offset = high
            if not _same_c_expression_8616(low_segment, high_segment):
                continue
            self.stats.normalized += 1
            if not _adjacent_offsets_8616(low_offset, high_offset):
                continue
            authorized = (
                _instruction_addrs_8616(low_call)
                & _instruction_addrs_8616(high_call)
                & self.proven_mov_addrs
            )
            if len(authorized) != 1:
                continue
            self.stats.classified += 1
            self.stats.materialized += 1
            return CFunctionCall(
                "SEG_U16",
                None,
                [low_segment, low_offset],
                codegen=self.codegen,
                tags={
                    "inertia_x86_16_runtime_segment_helper": "SEG_U16",
                    "inertia_source_instruction_addrs": tuple(sorted(authorized)),
                },
            )
        return None

    def transform(self, node: object) -> object:
        """Materialize one adjacent byte pair when all widening facts agree."""
        if not isinstance(node, CBinaryOp) or node.op not in {"Or", "Add"}:
            return node
        typed = self._typed_pair(node)
        if typed is not None:
            return typed
        authorized = self._authorized_pair(node)
        if authorized is not None:
            return authorized
        return node


def _cfunc_rewrite_roots_8616(cfunc: object) -> list[tuple[list[str], object]]:
    """Return the distinct (attributes, root) rewrite anchors on one cfunc."""
    roots: list[tuple[list[str], object]] = []
    seen_roots: dict[int, list[str]] = {}
    for attribute in ("body", "statements", "stmt"):
        root = _dynamic_cfunc_attr_8616(cfunc, attribute)
        if root is None:
            continue
        if id(root) in seen_roots:
            seen_roots[id(root)].append(attribute)
            continue
        attributes = [attribute]
        seen_roots[id(root)] = attributes
        roots.append((attributes, root))
    return roots


def apply_segmented_load_widening_8616(codegen: object) -> bool:
    """Widen proven adjacent segmented byte loads in one structured C tree."""
    typed_codegen = cast(_CodegenBoundary8616, codegen)
    cfunc = typed_codegen.cfunc
    proven_mov_addrs = _ssa_segmented_word_mov_addrs_8616(
        typed_codegen
    ) | _decoded_segmented_word_mov_addrs_8616(typed_codegen)

    widener = _SegmentedLoadWidener8616(codegen=typed_codegen, proven_mov_addrs=proven_mov_addrs)

    changed = False
    for attributes, root in _cfunc_rewrite_roots_8616(cfunc):
        replacement = widener.transform(root)
        if replacement is not root:
            if isinstance(root, CStatements) and not isinstance(replacement, CStatements):
                replacement = CStatements([replacement], codegen=codegen)
            for attribute in attributes:
                _dynamic_cfunc_setattr_8616(cfunc, attribute, replacement)
            root = replacement
            changed = True
        for _ in range(3):
            if not _replace_c_children_8616(root, widener.transform):
                break
            changed = True

    statement_changed, statement_raw, statement_normalized, statement_classified, statement_materialized = (
        _widen_statement_byte_loads_8616(
            _dynamic_cfunc_attr_8616(cfunc, "statements"),
            codegen=typed_codegen,
            proven_mov_addrs=proven_mov_addrs,
        )
    )
    changed = statement_changed or changed
    raw = widener.stats.raw + statement_raw
    normalized = widener.stats.normalized + statement_normalized
    classified = widener.stats.classified + statement_classified
    materialized = widener.stats.materialized + statement_materialized

    typed_codegen._inertia_segmented_load_widening_report_8616 = SegmentedLoadWideningReport8616(
        raw_fact_count=raw,
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=raw - materialized,
    )
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_LOAD_WIDENING"):
        log.warning(
            "[segmented-load-widening] function=%#x proven_movs=%s raw=%d normalized=%d "
            "classified=%d materialized=%d",
            typed_codegen.cfunc.addr,
            tuple(sorted(proven_mov_addrs)),
            raw,
            normalized,
            classified,
            materialized,
        )
    return changed

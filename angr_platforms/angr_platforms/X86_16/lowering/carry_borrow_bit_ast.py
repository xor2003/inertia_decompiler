"""Bounded C-AST placement for proven numeric carry/borrow values.

Layer: Types/Lowering.
Responsibility: locate an exact instruction-tagged carry use, resolve its C-SSA
slice across structured scopes, and retire only proven-dead pure assignments.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CIfElse,
    CStatements,
    CTypeCast,
    CVariable,
)

from ..c_ast_utils import (
    _clone_c_ast_tree_8616,
    _iter_c_node_occurrences_8616,
    _iter_c_nodes_deep_8616,
    _same_c_expression_8616,
)
from ..semantics.carry_borrow_contracts import CarryBorrowKind8616
from ..structuring_cfg_ownership import CFGInstructionSite8616, CFGOwnershipArtifact
from .carry_borrow_bit_contracts import CarryBorrowBitLoweringFact8616, CarryBorrowBitLoweringFailure8616
from .carry_borrow_bit_scope import (
    CarryBitOccurrence8616,
    InlinedCarryBitOccurrence8616,
    assignment_map_8616,
    node_instruction_site_8616,
    node_matches_instruction_site_8616,
    read_counts_8616,
    select_cfg_reaching_definitions_8616,
    statement_containers_8616,
    variable_key_8616,
)


@dataclass(frozen=True)
class CarryBitCarrierClosure8616:
    """Exact low-instruction definitions reaching one carry mask."""

    assignments: tuple[CAssignment, ...]
    nodes: tuple[object, ...]
    definition_nodes: tuple[tuple[object, ...], ...]


def _constant_int_8616(node: object) -> int | None:
    """Return an integer constant through syntax-only casts."""
    while isinstance(node, CTypeCast):
        node = node.expr
    return int(node.value) if isinstance(node, CConstant) and isinstance(node.value, int) else None


def _direct_masked_variable_8616(node: object) -> CVariable | None:
    """Return the variable in an exact ``value & 1`` expression."""
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp) or node.op != "And":
        return None
    for value, mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_int_8616(mask) != 1:
            continue
        while isinstance(value, CTypeCast):
            value = value.expr
        if isinstance(value, CBinaryOp) and value.op in {"Shr", "Sar"} and _constant_int_8616(value.rhs) == 0:
            value = value.lhs
            while isinstance(value, CTypeCast):
                value = value.expr
        if isinstance(value, CVariable):
            return value
    return None


def _masked_carry_variable_8616(node: object) -> tuple[CVariable, int] | None:
    """Return the carry variable and canonical mask depth for one C node."""
    direct = _direct_masked_variable_8616(node)
    if direct is not None:
        return direct, 1
    if not isinstance(node, CBinaryOp) or node.op != "And":
        return None
    for value, mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_int_8616(mask) == 1 and (nested := _direct_masked_variable_8616(value)) is not None:
            return nested, 2
    return None


def carry_bit_occurrences_8616(
    root: object,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> tuple[CarryBitOccurrence8616, ...]:
    """Collect maximal carry masks owned by the proven high instruction."""
    high_site = CFGInstructionSite8616(fact.high_block_addr, fact.high_ins_addr)
    candidates_by_node: dict[int, CarryBitOccurrence8616] = {}
    for container in statement_containers_8616(root):
        for statement_index, statement in enumerate(container.statements):
            for node in _iter_c_node_occurrences_8616(statement):
                if (
                    not isinstance(node, CBinaryOp)
                    or not isinstance(node_instruction_site_8616(node, ownership), CFGInstructionSite8616)
                    or not node_matches_instruction_site_8616(node, high_site, ownership)
                ):
                    continue
                masked = _masked_carry_variable_8616(node)
                if masked is not None:
                    variable, depth = masked
                    candidates_by_node[id(node)] = CarryBitOccurrence8616(
                        root, container, statement_index, node, variable, depth
                    )
    candidates = tuple(candidates_by_node.values())
    if not candidates:
        return ()
    maximal_depth = max(item.mask_depth for item in candidates)
    return tuple(item for item in candidates if item.mask_depth == maximal_depth)


def _inlined_addition_carry_8616(
    node: object,
    low_site: CFGInstructionSite8616,
    ownership: CFGOwnershipArtifact,
) -> CBinaryOp | None:
    """Return one exact low-site unsigned addition carry projection."""
    while isinstance(node, CTypeCast):
        node = node.expr
    if (
        not isinstance(node, CBinaryOp)
        or node.op != "Shr"
        or _constant_int_8616(node.rhs) != 16
        or not node_matches_instruction_site_8616(node, low_site, ownership)
    ):
        return None
    addition = node.lhs
    while isinstance(addition, CTypeCast):
        addition = addition.expr
    if (
        not isinstance(addition, CBinaryOp)
        or addition.op != "Add"
        or not node_matches_instruction_site_8616(addition, low_site, ownership)
    ):
        return None
    return node


def inlined_carry_bit_occurrences_8616(
    root: object,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> tuple[InlinedCarryBitOccurrence8616, ...]:
    """Collect low carry projections inlined into exact high-site expressions."""
    if fact.kind is not CarryBorrowKind8616.ADD_WITH_CARRY:
        return ()
    low_site = CFGInstructionSite8616(fact.low_block_addr, fact.low_ins_addr)
    high_site = CFGInstructionSite8616(fact.high_block_addr, fact.high_ins_addr)
    candidates_by_node: dict[int, InlinedCarryBitOccurrence8616] = {}
    for container in statement_containers_8616(root):
        for statement_index, statement in enumerate(container.statements):
            for high_node in _iter_c_node_occurrences_8616(statement):
                if (
                    not isinstance(high_node, CBinaryOp)
                    or high_node.op not in {"Shr", "Sar"}
                    or _constant_int_8616(high_node.rhs) != 16
                    or not isinstance(
                        node_instruction_site_8616(high_node, ownership), CFGInstructionSite8616
                    )
                    or not node_matches_instruction_site_8616(high_node, high_site, ownership)
                ):
                    continue
                low_projections: dict[int, CBinaryOp] = {}
                for node in _iter_c_nodes_deep_8616(high_node.lhs):
                    projection = _inlined_addition_carry_8616(node, low_site, ownership)
                    if projection is not None:
                        low_projections[id(projection)] = projection
                if len(low_projections) == 1:
                    candidates_by_node.setdefault(
                        id(high_node),
                        InlinedCarryBitOccurrence8616(
                            root,
                            container,
                            statement_index,
                            high_node,
                            high_node,
                        )
                    )
    return tuple(candidates_by_node.values())


def carry_bit_carrier_closure_8616(
    occurrence: CarryBitOccurrence8616,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CarryBitCarrierClosure8616 | CarryBorrowBitLoweringFailure8616:
    """Resolve the exact low-instruction assignment slice reaching carry."""
    seed = variable_key_8616(occurrence.flag_variable)
    if seed is None:
        return CarryBorrowBitLoweringFailure8616.CARRY_VARIABLE_IDENTITY_MISSING
    assignments = assignment_map_8616(occurrence)
    definitions = assignments.get(seed, ())
    if not definitions:
        return CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_MISSING
    selection = select_cfg_reaching_definitions_8616(occurrence, definitions, fact, ownership)
    if isinstance(selection, CarryBorrowBitLoweringFailure8616):
        return selection
    nodes: list[object] = []
    definition_nodes: list[tuple[object, ...]] = []
    for assignment in selection.definitions:
        rhs_nodes = tuple(_iter_c_nodes_deep_8616(assignment.rhs))
        nodes.extend(rhs_nodes)
        definition_nodes.append(rhs_nodes)
    return CarryBitCarrierClosure8616(selection.definitions, tuple(nodes), tuple(definition_nodes))


def _side_effect_free_8616(node: object) -> bool:
    """Return whether deleting one carrier RHS cannot delete an effect."""
    return not any(isinstance(item, (CFunctionCall, CDirtyExpression)) for item in _iter_c_nodes_deep_8616(node))


def _owned_projection_pure_8616(node: object) -> bool:
    """Return whether one owned expression can be discarded after equivalent-arm proof."""
    for item in _iter_c_nodes_deep_8616(node):
        if isinstance(item, CDirtyExpression):
            return False
        if isinstance(item, CFunctionCall) and not item.tags.get("inertia_x86_16_runtime_segment_helper"):
            return False
    return True


def _equivalent_low_arm_assignment_8616(
    statement: object,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CAssignment | None:
    """Return one low result assignment duplicated across two pure conditional arms."""
    if not isinstance(statement, CIfElse) or not isinstance(statement.else_node, CStatements):
        return None
    pairs = statement.condition_and_nodes
    if not isinstance(pairs, (list, tuple)) or len(pairs) != 1:
        return None
    condition, body = pairs[0]
    if (
        not isinstance(body, CStatements)
        or len(body.statements) != 1
        or len(statement.else_node.statements) != 1
        or not _owned_projection_pure_8616(condition)
    ):
        return None
    first = body.statements[0]
    second = statement.else_node.statements[0]
    low_site = CFGInstructionSite8616(fact.low_block_addr, fact.low_ins_addr)
    operation = "Sub" if fact.kind is CarryBorrowKind8616.SUB_WITH_BORROW else "Add"
    arms = _same_variable_assignments_8616(first, second)
    if arms is None:
        return None
    first, second = arms
    if not (
        isinstance(first.rhs, CBinaryOp)
        and first.rhs.op == operation
        and node_matches_instruction_site_8616(first.rhs, low_site, ownership)
        and _same_c_expression_8616(first.rhs, second.rhs)
    ):
        return None
    return first


def _same_variable_assignments_8616(
    first: object,
    second: object,
) -> tuple[CAssignment, CAssignment] | None:
    """Return both assignments when they bind the same C-SSA variable."""
    if not (
        isinstance(first, CAssignment)
        and isinstance(second, CAssignment)
        and isinstance(first.lhs, CVariable)
        and isinstance(second.lhs, CVariable)
        and variable_key_8616(first.lhs) == variable_key_8616(second.lhs)
    ):
        return None
    return first, second


def _collapse_equivalent_low_arms_8616(
    root: object,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> bool:
    """Collapse pure identical structured copies of the exact low result."""
    changed = False
    for container in statement_containers_8616(root):
        for statement_index, statement in enumerate(tuple(container.statements)):
            assignment = _equivalent_low_arm_assignment_8616(statement, fact, ownership)
            if assignment is None:
                continue
            container.statements[statement_index] = _clone_c_ast_tree_8616(assignment)
            changed = True
    return changed


def _static_definition_8616(
    root: object,
    variable: CVariable,
) -> CAssignment | None:
    """Return one equivalent static-value definition for a C-SSA variable."""
    key = variable_key_8616(variable)
    if key is None:
        return None
    definitions = tuple(
        node
        for node in _iter_c_node_occurrences_8616(root)
        if isinstance(node, CAssignment)
        and isinstance(node.lhs, CVariable)
        and variable_key_8616(node.lhs) == key
        and isinstance(node.rhs, CVariable)
        and node.rhs.vvar_id is None
    )
    if not definitions or any(
        not _same_c_expression_8616(definition.rhs, definitions[0].rhs) for definition in definitions[1:]
    ):
        return None
    return definitions[0]


def _project_low_static_operands_8616(
    root: object,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> bool:
    """Project exact low arithmetic through unique static C-SSA definitions."""
    low_site = CFGInstructionSite8616(fact.low_block_addr, fact.low_ins_addr)
    operation = "Sub" if fact.kind is CarryBorrowKind8616.SUB_WITH_BORROW else "Add"
    projected_definitions: dict[int, CAssignment] = {}
    changed = False
    for node in _iter_c_node_occurrences_8616(root):
        if (
            not isinstance(node, CAssignment)
            or not isinstance(node.rhs, CBinaryOp)
            or node.rhs.op != operation
            or not node_matches_instruction_site_8616(node.rhs, low_site, ownership)
        ):
            continue
        for attribute in ("lhs", "rhs"):
            operand = node.rhs.lhs if attribute == "lhs" else node.rhs.rhs
            if not isinstance(operand, CVariable):
                continue
            definition = _static_definition_8616(root, operand)
            if definition is None:
                continue
            replacement = _clone_c_ast_tree_8616(definition.rhs)
            if attribute == "lhs":
                node.rhs.lhs = replacement
            else:
                node.rhs.rhs = replacement
            projected_definitions[id(definition)] = definition
            changed = True
    if not changed:
        return False
    reads = read_counts_8616(root)
    for container in statement_containers_8616(root):
        container.statements = [
            statement
            for statement in container.statements
            if not (
                id(statement) in projected_definitions
                and isinstance(statement, CAssignment)
                and isinstance(statement.lhs, CVariable)
                and (key := variable_key_8616(statement.lhs)) is not None
                and reads[key] == 0
            )
        ]
    return True


def finalize_low_arithmetic_copies_8616(
    root: object,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> bool:
    """Canonicalize exact low arithmetic after its carry use is materialized."""
    collapsed = _collapse_equivalent_low_arms_8616(root, fact, ownership)
    projected = _project_low_static_operands_8616(root, fact, ownership)
    return collapsed or projected


def prune_dead_carry_bit_carriers_8616(
    occurrence: CarryBitOccurrence8616,
    closure: CarryBitCarrierClosure8616,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> None:
    """Retire only dead, pure assignments in the proven low carrier slice."""
    owned = {id(assignment) for assignment in closure.assignments}
    low_site = CFGInstructionSite8616(fact.low_block_addr, fact.low_ins_addr)
    while True:
        reads = read_counts_8616(occurrence.root)
        changed = False
        for container in statement_containers_8616(occurrence.root):
            kept: list[object] = []
            for statement in container.statements:
                removable = False
                if (
                    id(statement) in owned
                    and isinstance(statement, CAssignment)
                    and isinstance(statement.lhs, CVariable)
                    and node_matches_instruction_site_8616(statement, low_site, ownership)
                ):
                    key = variable_key_8616(statement.lhs)
                    removable = key is not None and reads[key] == 0 and _side_effect_free_8616(statement.rhs)
                if removable:
                    changed = True
                else:
                    kept.append(statement)
            container.statements = kept
        if not changed:
            return

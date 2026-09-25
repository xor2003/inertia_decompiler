"""Copy propagation over proven alias storage domains.

Layer: Widening.
Responsibility: owns copy propagation within proven alias storage domains.
Consumes alias-proven storage identity to replace repeated local values only
within the proven storage domain.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.sim_variable import SimTemporaryVariable

from ..alias.alias_model_impl import AliasStorageFacts
from ..c_ast_utils import (
    _clone_c_ast_tree_8616,
    _iter_c_nodes_deep_8616,
    _replace_c_children_8616,
    _unwrap_statements_8616,
)
from ..callsite_summary import callsite_summary_inventory_8616
from ..pipeline.contracts import SemanticLaneState
from ..semantics.alias_query import (
    describe_alias_storage,
)
from ..semantics.expression_analysis import (
    VirtualValueIdentity8616,
    describe_virtual_value_identity_8616,
)

__all__ = ["_widening_copy_propagation_8616"]

log: logging.Logger = logging.getLogger(__name__)


class _DiagnosticCRepr8616(Protocol):
    """Minimal angr structured-C rendering boundary used by diagnostics."""

    def c_repr(self) -> object:
        """Return the third-party structured-C representation."""
        ...


def _debug_copy_replacement_8616(
    *,
    storage_key: str,
    original: object,
    replacement: object,
) -> None:
    """Log one alias-keyed replacement when copy-propagation diagnostics are enabled."""
    if os.environ.get("INERTIA_DEBUG_WIDENING_COPYPROP") != "1":
        return

    def _render(node: object) -> str:
        """Render one dynamic angr C expression for diagnostics."""
        try:
            return str(cast(_DiagnosticCRepr8616, node).c_repr())
        except (AttributeError, TypeError):
            return repr(node)

    log.warning(
        "[widening-copyprop] key=%s original=%s replacement=%s original_facts=%r replacement_facts=%r",
        storage_key,
        _render(original),
        _render(replacement),
        describe_alias_storage(original),
        describe_alias_storage(replacement),
    )


class _WideningCopypropCodegen8616(Protocol):
    """Codegen counters written at the dynamic third-party angr boundary."""

    cfunc: object | None
    widening_copyprop_nested_replacements_8616: int
    widening_copyprop_address_context_refused_8616: int
    widening_copyprop_memory_kills_8616: int
    widening_copyprop_nontrivial_stack_definitions_refused_8616: int
    widening_copyprop_nontrivial_assignment_uses_refused_8616: int
    widening_copyprop_recursive_definitions_refused_8616: int
    widening_copyprop_typed_cast_definitions_refused_8616: int
    widening_copyprop_unknown_identity_refused_8616: int
    widening_copyprop_width_mismatch_refused_8616: int
    _inertia_widening_call_push_definition_guard_8616: SemanticLaneState
    _inertia_widening_nontrivial_definition_guard_8616: SemanticLaneState
    _inertia_widening_copy_width_guard_8616: SemanticLaneState


@dataclass(frozen=True)
class _ReusableDefinition8616:
    """One alias-proven source and the structured contexts that may consume it."""

    expression: object
    condition_only: bool


class _ConditionNode8616(Protocol):
    """Third-party structured node exposing a mutable condition field."""

    condition: object


class _CondNode8616(Protocol):
    """Third-party structured node exposing a mutable cond field."""

    cond: object


class _ConditionPairsNode8616(Protocol):
    """Third-party structured node exposing mutable condition/body pairs."""

    condition_and_nodes: object


class _MultiStatementExpressionNode8616(Protocol):
    """Third-party structured expression exposing a mutable result expression."""

    expr: object


@dataclass
class _CopypropRun8616:
    """Mutable propagation state for one widening copy-propagation pass.

    ``block_defs``/``virtual_defs`` are rebound per walked statement block;
    nested bodies receive the same dict objects through ``inherited_defs`` so
    linear-flow mutations stay shared, and each walk restores its parent's
    maps on exit.
    """

    typed_codegen: _WideningCopypropCodegen8616
    enable_nested: bool
    call_push_instruction_addrs: frozenset[int]
    call_push_definition_guard: SemanticLaneState
    nontrivial_definition_guard: SemanticLaneState
    copy_width_guard: SemanticLaneState
    changed: bool = False
    guarded_call_push_assignment_ids: set[int] = field(default_factory=set)
    block_defs: dict[str, _ReusableDefinition8616] = field(default_factory=dict)
    virtual_defs: dict[VirtualValueIdentity8616, object] = field(default_factory=dict)

    @staticmethod
    def _lhs_writes_memory(lhs: object) -> bool:
        """Classify lvalues through the dynamic third-party angr C AST boundary."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if lhs is None:
            return False
        if isinstance(lhs, structured_c.CVariable) or describe_virtual_value_identity_8616(lhs) is not None:
            return False
        if isinstance(lhs, structured_c.CUnaryOp) and lhs.op == "Dereference":
            return True
        if isinstance(lhs, (structured_c.CIndexedVariable, structured_c.CStructField)):
            return True
        # Unknown lvalue shape: conservatively treat it as an observable memory write.
        return True

    def _block_def_key(self, storage_facts: AliasStorageFacts) -> str | None:
        """Create a key from alias facts crossing a dynamic compatibility boundary."""
        domain = storage_facts.domain
        identity = storage_facts.identity
        if domain is None or identity is None:
            if domain is not None:
                self.typed_codegen.widening_copyprop_unknown_identity_refused_8616 = (
                    int(self.typed_codegen.widening_copyprop_unknown_identity_refused_8616 or 0) + 1
                )
            return None
        return f"{domain}:{identity}"

    def _replacement_for_variable(self, node: object, *, condition_use: bool = False) -> object | None:
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if not isinstance(node, structured_c.CVariable):
            return None
        virtual_identity = describe_virtual_value_identity_8616(node)
        if virtual_identity is not None:
            virtual_replacement = self.virtual_defs.get(virtual_identity)
            if virtual_replacement is not None:
                return virtual_replacement
        storage_key = self._block_def_key(describe_alias_storage(node))
        definition = self.block_defs.get(storage_key) if storage_key is not None else None
        if definition is None:
            return None
        if definition.condition_only and not condition_use:
            self.typed_codegen.widening_copyprop_nontrivial_assignment_uses_refused_8616 = (
                int(self.typed_codegen.widening_copyprop_nontrivial_assignment_uses_refused_8616 or 0) + 1
            )
            return None
        replacement = definition.expression
        if storage_key is not None:
            _debug_copy_replacement_8616(
                storage_key=storage_key,
                original=node,
                replacement=replacement,
            )
        return replacement

    @staticmethod
    def _expression_bit_width(expr: object) -> int | None:
        """Return an explicit bit width from a virtual or alias-backed value."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(expr, structured_c.CDirtyExpression):
            bits = expr.dirty.bits
            return bits if isinstance(bits, int) and bits > 0 else None
        if isinstance(expr, structured_c.CVariable):
            size = expr.variable.size
            if isinstance(expr.variable, SimTemporaryVariable):
                return size if isinstance(size, int) and size > 0 else None
            return size * 8 if isinstance(size, int) and size > 0 else None
        return None

    def _recordable_copy_source(self, lhs: object, rhs: object) -> _ReusableDefinition8616 | None:
        """Return a reusable RHS only when no explicit conversion is crossed.

        Widening does not own enough destination-conversion evidence to prove
        that an explicit C cast is representation preserving. In particular,
        propagating ``short_value = (char)word_value`` into a later use loses
        the signed-byte destination identity. Keep every explicit cast as a
        definition/use barrier until Types supplies such a proof. Also retain
        nontrivial expressions behind proven stack variables: substituting
        them duplicates work while the named storage remains live. Transient
        register carriers still require propagation into structured uses.
        """
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(rhs, structured_c.CTypeCast):
            self.typed_codegen.widening_copyprop_typed_cast_definitions_refused_8616 = (
                int(self.typed_codegen.widening_copyprop_typed_cast_definitions_refused_8616 or 0) + 1
            )
            return None
        if isinstance(lhs, structured_c.CVariable) and isinstance(rhs, structured_c.CVariable):
            lhs_bits = self._expression_bit_width(lhs)
            rhs_bits = self._expression_bit_width(rhs)
            self.copy_width_guard.raw += 1
            self.copy_width_guard.normalized += 1
            self.copy_width_guard.classified += 1
            self.copy_width_guard.materialized += 1
            if lhs_bits is None or rhs_bits is None or lhs_bits != rhs_bits:
                self.typed_codegen.widening_copyprop_width_mismatch_refused_8616 += 1
                return None
        lhs_identity = describe_alias_storage(lhs).identity
        if (
            isinstance(lhs_identity, tuple)
            and len(lhs_identity) == 2
            and lhs_identity[0] == "stack"
            and not isinstance(rhs, (structured_c.CVariable, structured_c.CConstant))
        ):
            self.typed_codegen.widening_copyprop_nontrivial_stack_definitions_refused_8616 = (
                int(self.typed_codegen.widening_copyprop_nontrivial_stack_definitions_refused_8616 or 0)
                + 1
            )
            return None
        nontrivial = not isinstance(rhs, (structured_c.CVariable, structured_c.CConstant))
        if nontrivial:
            self.nontrivial_definition_guard.raw += 1
            self.nontrivial_definition_guard.normalized += 1
            self.nontrivial_definition_guard.classified += 1
            self.nontrivial_definition_guard.materialized += 1
        return _ReusableDefinition8616(_clone_c_ast_tree_8616(rhs), condition_only=nontrivial)

    def _expression_reads_storage_key(self, expr: object, storage_key: str) -> bool:
        """Return whether an expression reads the alias domain being defined."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        for nested in (expr, *_iter_c_nodes_deep_8616(expr)):
            if not isinstance(nested, structured_c.CVariable):
                continue
            nested_key = self._block_def_key(describe_alias_storage(nested))
            if nested_key == storage_key:
                return True
        return False

    def _should_process_child_8616(self, parent: object, attr: str) -> bool:
        """Filter children through the dynamic third-party angr C AST boundary."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(parent, structured_c.CUnaryOp) and parent.op in {"Dereference", "Reference"}:  # noqa: SIM102
            if attr == "operand":
                self.typed_codegen.widening_copyprop_address_context_refused_8616 = (
                    int(self.typed_codegen.widening_copyprop_address_context_refused_8616 or 0) + 1
                )
                return False
        return True

    def _transform_nested_8616(self, node: object, *, condition_use: bool) -> object:
        """Transform nested nodes through the dynamic third-party angr C AST boundary."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(node, structured_c.CMultiStatementExpression):
            return self._propagate_expr(node, condition_use=condition_use)
        nested_replacement = self._replacement_for_variable(node, condition_use=condition_use)
        if nested_replacement is None or _is_same_expr(nested_replacement, node):
            return node
        self.changed = True
        self.typed_codegen.widening_copyprop_nested_replacements_8616 = (
            int(self.typed_codegen.widening_copyprop_nested_replacements_8616 or 0) + 1
        )
        return _clone_c_ast_tree_8616(nested_replacement)

    def _propagate_expr(self, expr: object, *, condition_use: bool = False) -> object:
        """Propagate expressions through the dynamic third-party angr C AST boundary."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if self.enable_nested and isinstance(expr, structured_c.CMultiStatementExpression):
            typed_expression = cast(_MultiStatementExpressionNode8616, expr)
            self.walk_statements(
                expr.stmts,
                inherited_defs=self.block_defs,
                inherited_virtual_defs=self.virtual_defs,
            )
            propagated_value = self._propagate_expr(expr.expr, condition_use=condition_use)
            if propagated_value is not expr.expr:
                typed_expression.expr = propagated_value
            return expr
        replacement = self._replacement_for_variable(expr, condition_use=condition_use)
        if replacement is not None and not _is_same_expr(replacement, expr):
            self.changed = True
            if self.enable_nested:
                self.typed_codegen.widening_copyprop_nested_replacements_8616 = (
                    int(self.typed_codegen.widening_copyprop_nested_replacements_8616 or 0) + 1
                )
            return _clone_c_ast_tree_8616(replacement)
        if not self.enable_nested:
            return expr

        if _replace_c_children_8616(
            expr,
            lambda node: self._transform_nested_8616(node, condition_use=condition_use),
            should_process_child=self._should_process_child_8616,
        ):
            self.changed = True
        return expr

    def _record_virtual_copy_definition(self, lhs: object, rhs: object) -> None:
        """Record a pure whole-value virtual copy from explicit typed evidence."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        identity = describe_virtual_value_identity_8616(lhs)
        if identity is None:
            return
        source = rhs
        rhs_identity = describe_virtual_value_identity_8616(rhs)
        if rhs_identity is not None:
            source = self.virtual_defs.get(rhs_identity)
        if not isinstance(source, structured_c.CVariable):
            self.virtual_defs.pop(identity, None)
            return
        source_facts = describe_alias_storage(source)
        if source_facts.identity is None or source_facts.needs_synthesis():
            self.virtual_defs.pop(identity, None)
            return
        lhs_bits = self._expression_bit_width(lhs)
        source_bits = self._expression_bit_width(source)
        if lhs_bits is None or lhs_bits != source_bits:
            self.virtual_defs.pop(identity, None)
            return
        self.virtual_defs[identity] = _clone_c_ast_tree_8616(source)

    def _propagate_virtual_comparison_operands(self, condition: object) -> None:
        """Replace direct comparison carriers from proven whole-value copies."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if not self.enable_nested:
            return
        comparison = condition
        if isinstance(comparison, structured_c.CUnaryOp) and comparison.op == "Not":
            comparison = comparison.operand
        if not isinstance(comparison, structured_c.CBinaryOp) or not comparison.op.startswith("Cmp"):
            return
        for is_lhs, operand in ((True, comparison.lhs), (False, comparison.rhs)):
            identity = describe_virtual_value_identity_8616(operand)
            replacement = self.virtual_defs.get(identity) if identity is not None else None
            if replacement is None or self._expression_bit_width(operand) != self._expression_bit_width(
                replacement
            ):
                continue
            if is_lhs:
                comparison.lhs = _clone_c_ast_tree_8616(replacement)
            else:
                comparison.rhs = _clone_c_ast_tree_8616(replacement)
            self.typed_codegen.widening_copyprop_nested_replacements_8616 = (
                int(self.typed_codegen.widening_copyprop_nested_replacements_8616 or 0) + 1
            )
            self.changed = True

    def _propagate_condition_pair_8616(self, pair: object) -> tuple[object, bool]:
        """Propagate one ``(condition, node)`` pair; clear defs on side effects."""
        if not isinstance(pair, tuple) or len(pair) < 2:
            return pair, False
        pair_condition = pair[0]
        propagated_pair_condition = self._propagate_expr(pair_condition, condition_use=True)
        self._propagate_virtual_comparison_operands(propagated_pair_condition)
        pair_changed = propagated_pair_condition is not pair_condition
        if pair_changed:
            pair = (propagated_pair_condition, *pair[1:])
        if _is_side_effecting(propagated_pair_condition):
            self.block_defs.clear()
            self.virtual_defs.clear()
        return pair, pair_changed

    def _propagate_direct_condition(self, stmt: object) -> None:
        """Consume current block definitions in a structured condition.

        A condition is evaluated at its statement's position in the block,
        so preceding alias-proven definitions are available on every path
        reaching it. Nested statement bodies still receive fresh maps and
        therefore cannot inherit unproven loop-carried state.
        """
        condition_node = cast(_ConditionNode8616, stmt) if hasattr(stmt, "condition") else None
        cond_node = cast(_CondNode8616, stmt) if hasattr(stmt, "cond") else None
        condition = condition_node.condition if condition_node is not None else None
        if condition is None and cond_node is not None:
            condition = cond_node.cond
        if condition is None:
            pairs_node = cast(_ConditionPairsNode8616, stmt) if hasattr(stmt, "condition_and_nodes") else None
            pairs = pairs_node.condition_and_nodes if pairs_node is not None else None
            if not isinstance(pairs, (list, tuple)):
                return
            rewritten_pairs: list[object] = []
            pairs_changed = False
            for pair in pairs:
                rewritten_pair, pair_changed = self._propagate_condition_pair_8616(pair)
                pairs_changed = pairs_changed or pair_changed
                rewritten_pairs.append(rewritten_pair)
            if pairs_changed and pairs_node is not None:
                pairs_node.condition_and_nodes = type(pairs)(rewritten_pairs)
            return
        propagated = self._propagate_expr(condition, condition_use=True)
        self._propagate_virtual_comparison_operands(propagated)
        if propagated is not condition:
            if condition_node is not None:
                condition_node.condition = propagated
            elif cond_node is not None:
                cond_node.cond = propagated
        if _is_side_effecting(propagated):
            self.block_defs.clear()
            self.virtual_defs.clear()

    def _walk_assignment(self, stmt: object) -> None:
        """Propagate through one ``CAssignment`` and update definition maps."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        rhs = stmt.rhs
        lhs = stmt.lhs

        # Attempt copy propagation on the RHS before applying memory-write
        # kills. The store itself is the effect; its value expression can
        # still consume earlier proven copies.
        propagated_rhs = self._propagate_expr(rhs)
        if propagated_rhs is not rhs:
            stmt.rhs = propagated_rhs
            rhs = propagated_rhs

        # A memory write can invalidate any previous expression whose
        # source may have read memory. Alias precision is not available
        # here, so unknown means kill rather than propagate stale data.
        if self._lhs_writes_memory(lhs):
            if self.block_defs:
                self.typed_codegen.widening_copyprop_memory_kills_8616 = (
                    int(self.typed_codegen.widening_copyprop_memory_kills_8616 or 0) + 1
                )
            self.block_defs.clear()
            self.virtual_defs.clear()
            if _is_side_effecting(rhs):
                self.block_defs.clear()
            return

        # Record this definition's source for future propagation.
        # Alias-proven plain variables are reusable definitions;
        # memory stores are effects, not reusable definitions.
        lhs_key = (
            self._block_def_key(describe_alias_storage(lhs))
            if isinstance(lhs, structured_c.CVariable)
            else None
        )
        tags = stmt.tags
        ins_addr = tags.get("ins_addr") if isinstance(tags, dict) else None
        guarded_call_push_definition = (
            lhs_key is not None
            and isinstance(ins_addr, int)
            and ins_addr in self.call_push_instruction_addrs
        )
        if lhs_key is not None and not _is_side_effecting(rhs):
            self._record_block_definition(stmt, lhs, rhs, lhs_key, guarded_call_push_definition)

        if not guarded_call_push_definition:
            self._record_virtual_copy_definition(lhs, rhs)

        # Side-effecting calls kill all domain state
        if _is_side_effecting(rhs):
            self.block_defs.clear()
            self.virtual_defs.clear()

    def _record_block_definition(
        self,
        stmt: object,
        lhs: object,
        rhs: object,
        lhs_key: str,
        guarded_call_push_definition: bool,
    ) -> None:
        """Record, refuse, or drop one alias-proven block definition."""
        if guarded_call_push_definition:
            self.block_defs.pop(lhs_key, None)
            assignment_id = id(stmt)
            if assignment_id not in self.guarded_call_push_assignment_ids:
                self.guarded_call_push_assignment_ids.add(assignment_id)
                self.call_push_definition_guard.classified += 1
                self.call_push_definition_guard.materialized += 1
            return
        if self._expression_reads_storage_key(rhs, lhs_key):
            self.block_defs.pop(lhs_key, None)
            self.typed_codegen.widening_copyprop_recursive_definitions_refused_8616 = (
                int(self.typed_codegen.widening_copyprop_recursive_definitions_refused_8616 or 0)
                + 1
            )
            return
        recordable_source = self._recordable_copy_source(lhs, rhs)
        if recordable_source is None:
            self.block_defs.pop(lhs_key, None)
        else:
            self.block_defs[lhs_key] = recordable_source

    def walk_statements(
        self,
        statements_obj: object,
        inherited_defs: dict[str, _ReusableDefinition8616] | None = None,
        inherited_virtual_defs: dict[VirtualValueIdentity8616, object] | None = None,
    ) -> None:
        """Walk statements through the dynamic third-party angr C AST boundary."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        stmts = _unwrap_statements_8616(statements_obj)
        # Map storage domain key -> source_expr for last plain-variable definition.
        parent_defs = self.block_defs
        parent_virtual_defs = self.virtual_defs
        self.block_defs = inherited_defs if inherited_defs is not None else {}
        self.virtual_defs = inherited_virtual_defs if inherited_virtual_defs is not None else {}
        try:
            for stmt in stmts:
                self._walk_statement_8616(stmt, structured_c)
        finally:
            self.block_defs = parent_defs
            self.virtual_defs = parent_virtual_defs

    def _walk_statement_8616(self, stmt: object, structured_c: object) -> None:
        """Dispatch one structured statement to its propagation arm."""
        if isinstance(stmt, structured_c.CStatements):
            self.walk_statements(
                stmt,
                inherited_defs=self.block_defs,
                inherited_virtual_defs=self.virtual_defs,
            )
            return
        if isinstance(stmt, structured_c.CAssignment):
            self._walk_assignment(stmt)
            return
        if isinstance(stmt, structured_c.CReturn) and stmt.retval is not None:
            propagated_return = self._propagate_expr(stmt.retval)
            if propagated_return is not stmt.retval:
                stmt.retval = propagated_return
            if _is_side_effecting(propagated_return):
                self.block_defs.clear()
                self.virtual_defs.clear()
            return
        if isinstance(stmt, (structured_c.CForLoop, structured_c.CWhileLoop, structured_c.CDoWhileLoop)):
            # A loop header executes after loop-carried writes. Pre-loop copies
            # are not invariants without a separate alias/liveness proof.
            self.block_defs.clear()
            self.virtual_defs.clear()
        self._propagate_direct_condition(stmt)
        self._walk_node(stmt)
        if isinstance(stmt, (structured_c.CIfElse, structured_c.CSwitchCase)) and _is_side_effecting(stmt):
            # A branch-local write may reach the continuation. Without a
            # path-sensitive join, every inherited definition is stale.
            self.block_defs.clear()
            self.virtual_defs.clear()

    def _walk_node(self, node: object) -> None:
        """Walk nested nodes through the dynamic third-party angr C AST boundary."""
        if node is None:
            return
        if hasattr(node, "statements"):
            self.walk_statements(node)
        for attr in (
            "condition",
            "cond",
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "retval",
            "expr",
            "switch",
            "initializer",
            "iterator",
        ):
            child = getattr(node, attr, None)
            if child is not None:
                self._walk_node(child)
        if hasattr(node, "condition_and_nodes"):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                self._walk_node(cond)
                self._walk_node(body)
        if hasattr(node, "cases"):
            for case_body in _iter_switch_case_bodies_8616(getattr(node, "cases", None)):
                self._walk_node(case_body)
        if hasattr(node, "default"):
            self._walk_node(getattr(node, "default", None))


_WIDENING_COPYPROP_COUNTERS_8616: tuple[str, ...] = (
    "widening_copyprop_nested_replacements_8616",
    "widening_copyprop_address_context_refused_8616",
    "widening_copyprop_memory_kills_8616",
    "widening_copyprop_nontrivial_stack_definitions_refused_8616",
    "widening_copyprop_nontrivial_assignment_uses_refused_8616",
    "widening_copyprop_recursive_definitions_refused_8616",
    "widening_copyprop_typed_cast_definitions_refused_8616",
    "widening_copyprop_unknown_identity_refused_8616",
    "widening_copyprop_width_mismatch_refused_8616",
)


def _iter_switch_case_bodies_8616(cases: object) -> tuple[object, ...]:
    """Yield switch-case bodies through the dynamic third-party angr boundary."""
    if cases is None:
        return ()
    if isinstance(cases, dict):
        return tuple(cases.values())
    bodies: list[object] = []
    if isinstance(cases, (list, tuple)):
        for case in cases:
            if isinstance(case, (list, tuple)) and len(case) >= 2:
                bodies.append(case[1])
            else:
                bodies.append(case)
    return tuple(bodies)


def _widening_copy_propagation_8616(codegen: object, *, enable_nested: bool = False) -> bool:
    """Propagate copies using alias storage domains.

    For each block, maintain a map from storage domain to the last
    definition. When a RHS is a CVariable with the same storage domain
    as a prior definition, replace it with the original source.

    Returns True if any copy was propagated.
    The codegen and C AST nodes cross a dynamic third-party angr boundary; owned
    Inertia counters are written through a typed protocol cast.
    """
    typed_codegen = cast(_WideningCopypropCodegen8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        return False
    if cfunc is None:
        return False
    callsite_inventory = callsite_summary_inventory_8616(typed_codegen)
    raw_call_push_instruction_addrs = tuple(
        instruction_addr
        for summary in callsite_inventory.values()
        for instruction_addr in summary.push_arg_instruction_addrs
    )
    call_push_instruction_addrs = frozenset(
        instruction_addr
        for instruction_addr in raw_call_push_instruction_addrs
        if isinstance(instruction_addr, int)
    )
    call_push_definition_guard = SemanticLaneState(
        name="widening_call_push_definition_guard",
        raw=len(raw_call_push_instruction_addrs),
        normalized=len(call_push_instruction_addrs),
        failures=len(raw_call_push_instruction_addrs) - len(call_push_instruction_addrs),
    )
    typed_codegen._inertia_widening_call_push_definition_guard_8616 = (
        call_push_definition_guard
    )
    nontrivial_definition_guard = SemanticLaneState(
        name="widening_nontrivial_definition_guard"
    )
    typed_codegen._inertia_widening_nontrivial_definition_guard_8616 = (
        nontrivial_definition_guard
    )
    copy_width_guard = SemanticLaneState(name="widening_copy_width_guard")
    typed_codegen._inertia_widening_copy_width_guard_8616 = copy_width_guard
    for counter_name in _WIDENING_COPYPROP_COUNTERS_8616:
        # Dynamic-name init at the angr codegen boundary (no owned container).
        if not hasattr(typed_codegen, counter_name):
            setattr(typed_codegen, counter_name, 0)

    run = _CopypropRun8616(
        typed_codegen=typed_codegen,
        enable_nested=enable_nested,
        call_push_instruction_addrs=call_push_instruction_addrs,
        call_push_definition_guard=call_push_definition_guard,
        nontrivial_definition_guard=nontrivial_definition_guard,
        copy_width_guard=copy_width_guard,
    )
    roots = (getattr(cfunc, "statements", None), getattr(cfunc, "body", None))
    walked_root_ids: set[int] = set()
    for root in roots:
        if root is None or id(root) in walked_root_ids:
            continue
        walked_root_ids.add(id(root))
        run.walk_statements(root)
    if not walked_root_ids:
        run.walk_statements(cfunc)
    call_push_definition_guard.assert_closed_loop(layer="widening")
    nontrivial_definition_guard.assert_closed_loop(layer="widening")
    copy_width_guard.assert_closed_loop(layer="widening")
    return run.changed


def _is_side_effecting(expr: object) -> bool:
    """Check if expression has side effects that prevent copy propagation."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    for node in _iter_c_nodes_deep_8616(expr):
        if isinstance(node, structured_c.CAssignment):
            return True
        if isinstance(node, structured_c.CFunctionCall):
            return True
    return False


def _is_same_expr(a: object, b: object) -> bool:
    """Check if two expressions are structurally identical across the dynamic third-party angr boundary."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if type(a) is not type(b):
        return False
    if isinstance(a, structured_c.CVariable):
        return getattr(a, "variable", None) is getattr(b, "variable", None) and getattr(a, "offset", None) == getattr(
            b, "offset", None
        )
    if isinstance(a, structured_c.CConstant):
        return getattr(a, "value", None) == getattr(b, "value", None)
    if isinstance(a, structured_c.CBinaryOp):
        rhs_binary = b
        return (
            a.op == getattr(rhs_binary, "op", None)
            and _is_same_expr(a.lhs, getattr(rhs_binary, "lhs", None))
            and _is_same_expr(a.rhs, getattr(rhs_binary, "rhs", None))
        )
    if isinstance(a, structured_c.CUnaryOp):
        rhs_unary = b
        return a.op == getattr(rhs_unary, "op", None) and _is_same_expr(
            a.operand, getattr(rhs_unary, "operand", None)
        )
    return a is b

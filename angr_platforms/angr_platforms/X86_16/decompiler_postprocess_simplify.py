"""Structured-C cleanup pass; keep semantic proof outside this module.

Layer: Rewrite/Postprocess cleanup.
Responsibility: cleanup-only simplification of already-proven structured C AST expressions.

This module may simplify C AST expressions after earlier stages have already
proved the underlying facts. Legitimate work here includes projection cleanup,
constant folding, redundant boolean wrapper removal, and inlining/deleting
single-use virtual temporaries when that is side-effect free and evidence-backed.

Current migration debt:
- word/byte projection materialization depends on alias/widening facts here;
- stack/global identity checks still reach into alias and lowering helpers;
- virtual temporary elimination still reasons about dirty/register carriers.

Those proofs belong earlier: alias/widening should decide storage identity and
adjacent-slice joins; lowering should materialize stack/global objects; IR or
semantics should expose clean values before C rendering. This file should become
a consumer that only removes redundant C syntax around already-materialized
values.

Do not add new alias, width, stack, register, or memory recovery here. If a
simplification needs proof, add the proof to the earliest owning layer and make
this pass consume a structured fact. Unknown or unproven cases must keep the
original C AST.

Adjacent byte variables must remain a byte expression unless an earlier owner
has materialized and bound a wider object. Creating a new word variable here
can lose its stores and inherit a byte type despite word-sized storage.

Dynamic attributes in this codegen boundary are limited to third-party angr C
AST/codegen compatibility objects.
"""

from __future__ import annotations

import contextlib
import logging
import operator
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from .decompiler_postprocess_flags import _bool_cite_values_8616
from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)
from .lowering.stack_lowering_from_facts import (
    _canonical_stack_offset_8616,
)
from .semantics.alias_query import _storage_domain_for_expr
from .widening_alias import join_adjacent_register_slices
from .widening_model import prove_adjacent_storage_slices

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SingleUseTemporaryEliminationStats8616:
    """Closed-loop evidence counters for cleanup-only temporary elimination."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


class _SingleUseTemporaryCodegen8616(Protocol):
    """Owned temporary-elimination metadata on the dynamic angr codegen boundary."""

    cfunc: object
    _inertia_single_use_temporary_elimination_stats_8616: SingleUseTemporaryEliminationStats8616


PROJECTION_CLEANUP_RULES: tuple[tuple[str, str], ...] = (
    (
        "concat_fold",
        "Fold concatenations of constant halves into one constant and preserve the narrower shift width otherwise.",
    ),
    (
        "or_zero_elimination",
        "Eliminate redundant zero terms in Or expressions after the low-level expression facts are stable.",
    ),
    (
        "and_zero_collapse",
        "Collapse And expressions with a zero operand into typed zero constants.",
    ),
    (
        "double_not_collapse",
        "Remove redundant boolean negation pairs after boolean cite recovery.",
    ),
    (
        "zero_compare_projection",
        "Convert zero comparisons into the underlying projection or flag source when the evidence is explicit.",
    ),
    (
        "word_or_update_materialization",
        "Materialize proven in-place word OR updates on stable locals instead of leaking byte-carrier projections.",
    ),
    (
        "sub_self_zero",
        "Collapse self-subtractions into typed zero constants once the low-level operands are proven identical.",
    ),
)


__all__ = [
    "_eliminate_single_use_temporaries_8616",
    "_maybe_eliminate_single_use_temporaries_8616",
    "_simplify_boolean_cites_8616",
    "_simplify_structured_expressions_8616",
    "describe_x86_16_projection_cleanup_rules",
]


def describe_x86_16_projection_cleanup_rules() -> tuple[tuple[str, str], ...]:
    """Describe cleanup-only projection simplification rules for architecture checks."""
    return PROJECTION_CLEANUP_RULES


_TRANSFORM_FALLTHROUGH_8616: Any = object()


def _iter_seq_children_8616(node: object, attr: str) -> Iterator[tuple[str, object]]:
    """Yield structured children held by one sequence attribute."""
    seq = getattr(node, attr, None)
    if not seq:
        return
    for item in seq:
        if _structured_codegen_node_8616(item):
            yield attr, item
        elif isinstance(item, tuple):
            for subitem in item:
                if _structured_codegen_node_8616(subitem):
                    yield attr, subitem


def _iter_structured_children_8616(node: object) -> Iterator[tuple[str, object]]:
    """Yield ``(attr, child)`` pairs for structured codegen children of a node."""
    for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
        child = getattr(node, attr, None)
        if _structured_codegen_node_8616(child):
            yield attr, child
    for attr in ("statements", "operands", "args"):
        yield from _iter_seq_children_8616(node, attr)
    pairs = getattr(node, "condition_and_nodes", None)
    if pairs:
        for cond, body in pairs:
            for subitem in (cond, body):
                if _structured_codegen_node_8616(subitem):
                    yield "condition_and_nodes", subitem


def _dirty_attr_8616(obj: object, attr: str) -> object | None:
    """Read one dirty-expression attribute defensively."""
    try:
        return getattr(obj, attr, None)
    except (AttributeError, TypeError, ValueError):
        return None


def _dirty_reg_key_8616(dirty: object) -> tuple[str, object] | None:
    """Build the register-location key for a dirty expression."""
    reg_offset = None
    for attr in ("reg_offset", "reg", "variable_offset"):
        value = _dirty_attr_8616(dirty, attr)
        if isinstance(value, int):
            reg_offset = value
            break
    bits = _dirty_attr_8616(dirty, "bits")
    if not isinstance(bits, int):
        size = _dirty_attr_8616(dirty, "size")
        if isinstance(size, int):
            bits = size * 8
    if isinstance(reg_offset, int):
        return ("dirty-reg", (reg_offset, bits if isinstance(bits, int) else None))
    return None


def _virtual_expr_keys_8616(node: object) -> tuple[tuple[str, object], ...]:
    keys: list[tuple[str, object]] = []
    if isinstance(node, CDirtyExpression) and (dirty := node.dirty) is not None:
        if isinstance(dirty, str) and dirty:
            keys.append(("dirty-name", dirty))
        varid = _dirty_attr_8616(dirty, "varid")
        if isinstance(varid, int):
            keys.append(("dirty-varid", varid))
        tmp_idx = _dirty_attr_8616(dirty, "tmp_idx")
        if isinstance(tmp_idx, int):
            keys.append(("dirty-tmp", tmp_idx))
        name = _dirty_attr_8616(dirty, "name")
        if isinstance(name, str) and name:
            keys.append(("dirty-name", name))
        reg_key = _dirty_reg_key_8616(dirty)
        if reg_key is not None:
            keys.append(reg_key)
    if isinstance(node, CVariable):
        variable = node.variable
        name = node.name or variable.name
        if isinstance(name, str) and name.startswith(("tmp_", "vvar_", "ir_")):
            keys.append(("virtual-name", name))
    return tuple(dict.fromkeys(keys))


def _virtual_expr_key_8616(node: object) -> tuple[str, object] | None:
    keys = _virtual_expr_keys_8616(node)
    if keys:
        return keys[0]
    return None


def _virtual_inline_identity_keys_8616(keys: tuple[tuple[str, object], ...]) -> tuple[tuple[str, object], ...]:
    """Return keys that identify one virtual value, not the register it occupies.

    A CDirtyExpression often carries both SSA-like identity (varid/tmp/name) and
    storage location (dirty-reg). tmp ids and register locations are reused
    across lowered blocks, so they are fallback identities only when no stable
    varid/name key is present.
    """
    stable_keys = tuple(key for key in keys if key[0] in {"dirty-name", "dirty-varid", "virtual-name"})
    if stable_keys:
        return stable_keys
    tmp_keys = tuple(key for key in keys if key[0] == "dirty-tmp")
    return tmp_keys or keys


def _virtual_definition_has_disposable_storage_8616(node: object) -> bool:
    """Require explicit virtual or register storage before deleting a definition."""
    keys = _virtual_expr_keys_8616(node)
    if isinstance(node, CDirtyExpression):
        return any(key_kind == "dirty-reg" for key_kind, _value in keys)
    return isinstance(node, CVariable) and any(
        key_kind == "virtual-name" for key_kind, _value in keys
    )


def _debug_c_repr_8616(node: object) -> str:
    try:
        return "".join(str(text) for text, _obj in cast(Any, node).c_repr_chunks(asexpr=True))
    except Exception:
        return repr(node)


def _pure_virtual_inline_rhs_8616(expr: object) -> bool:
    if isinstance(expr, (CConstant, CVariable, CDirtyExpression)):
        return True
    if isinstance(expr, CTypeCast):
        return _pure_virtual_inline_rhs_8616(expr.expr)
    if isinstance(expr, CUnaryOp):
        if expr.op == "Dereference":
            return False
        if expr.op == "Reference":
            operand = expr.operand
            if isinstance(operand, CIndexedVariable):
                return _pure_virtual_inline_rhs_8616(operand.variable) and _pure_virtual_inline_rhs_8616(operand.index)
            return isinstance(operand, CVariable)
        return _pure_virtual_inline_rhs_8616(expr.operand)
    if isinstance(expr, CBinaryOp):
        return _pure_virtual_inline_rhs_8616(expr.lhs) and _pure_virtual_inline_rhs_8616(expr.rhs)
    if isinstance(expr, CITE):
        return (
            _pure_virtual_inline_rhs_8616(expr.cond)
            and _pure_virtual_inline_rhs_8616(expr.iftrue)
            and _pure_virtual_inline_rhs_8616(expr.iffalse)
        )
    return False


def _expr_contains_virtual_key_8616(node: object, target_key: tuple[str, object]) -> bool:
    if node is None:
        return False
    if _virtual_expr_key_8616(node) == target_key:
        return True
    for _attr, child in _iter_structured_children_8616(node):
        if _expr_contains_virtual_key_8616(child, target_key):
            return True
    return False


@dataclass
class _VirtualInlineRun8616:
    """Inline pure SSA-like virtual definitions by structural AST evidence.

    Layer: rewrite/cleanup. Consumes CDirtyExpression/CVariable virtual
    definitions that are unique in the function; refuses memory/call/address
    side effects and never inspects rendered C text.
    """

    codegen: object
    cfunc: object = None
    root: object = None
    definitions: dict[tuple[str, object], object | None] = field(default_factory=dict)
    replacements: dict[tuple[str, object], object] = field(default_factory=dict)
    changed: bool = False
    protected_refused_count: int = 0
    candidate_count: int = 0
    refused_count: int = 0
    _pruned: int = 0

    def run(self) -> object:
        """Inline pure SSA-like virtual definitions by structural AST evidence.

        This consumes CDirtyExpression/CVariable virtual definitions that are unique
        in the function. It does not inspect rendered C text and refuses any RHS
        with memory/call/address side effects.
        """
        self.cfunc = getattr(self.codegen, "cfunc", None)
        self.root = getattr(self.cfunc, "statements", None)
        if self.root is None:
            return False
        self.definitions = {}
        self.candidate_count = 0
        self.refused_count = 0
        self._collect_virtual_definitions_8616()
        self.replacements = {key: rhs for key, rhs in self.definitions.items() if rhs is not None}
        if not self.replacements:
            self._publish_refusal_stats_8616()
            return False
        self.changed = False
        self.protected_refused_count = 0
        self._transform(self.root)
        if self.protected_refused_count:
            cast(Any, self.codegen)._inertia_virtual_inline_protected_address_refused = (
                int(getattr(self.codegen, "_inertia_virtual_inline_protected_address_refused", 0) or 0) + self.protected_refused_count
            )
        pruned_defs = self._prune_consumed_virtual_definitions_8616(self.root)
        if pruned_defs:
            self.changed = True
            cast(Any, self.codegen)._inertia_virtual_inline_pruned_defs = (
                int(getattr(self.codegen, "_inertia_virtual_inline_pruned_defs", 0) or 0) + pruned_defs
            )
        if self.changed:
            cast(Any, self.codegen)._inertia_virtual_inline_candidates = (
                int(getattr(self.codegen, "_inertia_virtual_inline_candidates", 0) or 0) + self.candidate_count
            )
            cast(Any, self.codegen)._inertia_virtual_inline_materialized = int(
                getattr(self.codegen, "_inertia_virtual_inline_materialized", 0) or 0
            ) + len(self.replacements)
            cast(Any, self.codegen)._inertia_virtual_inline_refused = (
                int(getattr(self.codegen, "_inertia_virtual_inline_refused", 0) or 0) + self.refused_count
            )
        return self.changed

    def _collect_virtual_definitions_8616(self) -> None:
        """Collect unique pure virtual definitions keyed by identity."""
        for node in self._walk(self.root):
            if not isinstance(node, CAssignment):
                continue
            raw_keys = _virtual_expr_keys_8616(node.lhs)
            keys = _virtual_inline_identity_keys_8616(raw_keys)
            if not keys:
                continue
            self.candidate_count += 1
            rhs = node.rhs
            if os.environ.get("INERTIA_DEBUG_VIRTUAL_INLINE"):
                _log.warning(
                    "[virtual-inline] def keys=%r raw_keys=%r lhs=%s rhs=%s",
                    keys,
                    raw_keys,
                    _debug_c_repr_8616(node.lhs),
                    _debug_c_repr_8616(rhs),
                )
            if not _pure_virtual_inline_rhs_8616(rhs) or any(_expr_contains_virtual_key_8616(rhs, key) for key in keys):
                for key in keys:
                    self.definitions[key] = None
                self.refused_count += 1
                continue
            if any(key in self.definitions for key in keys):
                for key in keys:
                    self.definitions[key] = None
                self.refused_count += 1
                continue
            for key in keys:
                self.definitions[key] = rhs

    def _publish_refusal_stats_8616(self) -> None:
        """Publish candidate/refusal counters when nothing was inlined."""
        if not self.candidate_count:
            return
        cast(Any, self.codegen)._inertia_virtual_inline_candidates = (
            int(getattr(self.codegen, "_inertia_virtual_inline_candidates", 0) or 0) + self.candidate_count
        )
        cast(Any, self.codegen)._inertia_virtual_inline_refused = (
            int(getattr(self.codegen, "_inertia_virtual_inline_refused", 0) or 0) + self.refused_count
        )

    def _walk(self, node: object) -> Iterator[object]:
        if node is None:
            return
        yield node
        for _attr, child in _iter_structured_children_8616(node):
            yield from self._walk(child)

    def _transform_replacement(
        self,
        node: object,
        *,
        protected_address_context: bool,
        resolving_keys: set[tuple[str, object]],
    ) -> object:
        """Resolve a virtual-key replacement for the node or fall through."""
        raw_keys = _virtual_expr_keys_8616(node)
        keys = _virtual_inline_identity_keys_8616(raw_keys)
        key = next((candidate_key for candidate_key in keys if candidate_key in self.replacements), None)
        replacement = self.replacements.get(key) if key is not None else None
        if replacement is not None:
            if key is None:
                return node
            if key in resolving_keys:
                if os.environ.get("INERTIA_DEBUG_VIRTUAL_INLINE"):
                    _log.warning("[virtual-inline] cycle-refuse key=%r expr=%s", key, _debug_c_repr_8616(node))
                return node
            if protected_address_context:
                self.protected_refused_count += 1
                if os.environ.get("INERTIA_DEBUG_VIRTUAL_INLINE"):
                    _log.warning(
                        "[virtual-inline] protected-address-refuse key=%r expr=%s replacement=%s",
                        key,
                        _debug_c_repr_8616(node),
                        _debug_c_repr_8616(replacement),
                    )
                return node
            if os.environ.get("INERTIA_DEBUG_VIRTUAL_INLINE"):
                _log.warning(
                    "[virtual-inline] replace key=%r expr=%s replacement=%s",
                    key,
                    _debug_c_repr_8616(node),
                    _debug_c_repr_8616(replacement),
                )
            self.changed = True
            resolving_keys.add(key)
            try:
                return self._transform(
                    replacement,
                    protected_address_context=protected_address_context,
                    resolving_keys=resolving_keys,
                )
            finally:
                resolving_keys.discard(key)
        if os.environ.get("INERTIA_DEBUG_VIRTUAL_INLINE") and raw_keys:
            _log.warning(
                "[virtual-inline] no replacement keys=%r raw_keys=%r expr=%s",
                keys,
                raw_keys,
                _debug_c_repr_8616(node),
            )
        return _TRANSFORM_FALLTHROUGH_8616

    def _transform(self,
        node: object,
        *,
        assignment_lhs: bool = False,
        protected_address_context: bool = False,
        resolving_keys: set[tuple[str, object]] | None = None,
    ) -> object:
        if node is None:
            return node
        if resolving_keys is None:
            resolving_keys = set()
        if not assignment_lhs:
            replaced = self._transform_replacement(
                node,
                protected_address_context=protected_address_context,
                resolving_keys=resolving_keys,
            )
            if replaced is not _TRANSFORM_FALLTHROUGH_8616:
                return replaced
        self._transform_scalar_children(node, protected_address_context=protected_address_context)
        for attr in ("statements", "operands", "args"):
            self._transform_seq_children(
                node, attr, protected_address_context=protected_address_context
            )
        self._transform_pair_children(node, protected_address_context=protected_address_context)
        return node

    def _transform_scalar_children(self, node: object, *, protected_address_context: bool) -> None:
        """Recurse into single-valued structured child attributes."""
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if not _structured_codegen_node_8616(child):
                continue
            child_protected_address_context = protected_address_context or (
                attr == "operand" and isinstance(node, CUnaryOp) and node.op in {"Dereference", "Reference"}
            )
            new_child = self._transform(
                child,
                assignment_lhs=attr == "lhs" and isinstance(node, CAssignment),
                protected_address_context=child_protected_address_context,
            )
            if new_child is not child:
                setattr(cast(Any, node), attr, new_child)

    def _transform_seq_children(self, node: object, attr: str, *, protected_address_context: bool) -> None:
        """Recurse into sequence attributes and rebuild changed lists."""
        seq = getattr(node, attr, None)
        if not seq:
            return
        new_seq = []
        seq_changed = False
        for item in seq:
            if _structured_codegen_node_8616(item):
                new_item = self._transform(item, protected_address_context=protected_address_context)
                new_seq.append(new_item)
                seq_changed |= new_item is not item
            else:
                new_seq.append(item)
        if seq_changed:
            setattr(cast(Any, node), attr, new_seq)

    def _transform_pair_children(self, node: object, *, protected_address_context: bool) -> None:
        """Recurse into condition_and_nodes pairs and rebuild changed lists."""
        pairs = getattr(node, "condition_and_nodes", None)
        if not pairs:
            return
        new_pairs = []
        pair_changed = False
        for cond, body in pairs:
            new_cond = (
                self._transform(cond, protected_address_context=protected_address_context)
                if _structured_codegen_node_8616(cond)
                else cond
            )
            new_body = (
                self._transform(body, protected_address_context=protected_address_context)
                if _structured_codegen_node_8616(body)
                else body
            )
            pair_changed |= new_cond is not cond or new_body is not body
            new_pairs.append((new_cond, new_body))
        if pair_changed:
            cast(Any, node).condition_and_nodes = new_pairs

    def _collect_virtual_key_use_counts_8616(self,
        node: object,
        tracked_keys: set[tuple[str, object]],
        *,
        assignment_lhs: bool = False,
        seen: set[int] | None = None,
    ) -> dict[tuple[str, object], int]:
        counts: dict[tuple[str, object], int] = {}
        if node is None or not tracked_keys:
            return counts
        if not _structured_codegen_node_8616(node):
            return counts
        if seen is None:
            seen = set()
        node_id = id(node)
        if node_id in seen:
            return counts
        seen.add(node_id)

        if not assignment_lhs:
            for key in _virtual_expr_keys_8616(node):
                if key in tracked_keys:
                    counts[key] = counts.get(key, 0) + 1

        for attr, child in _iter_structured_children_8616(node):
            child_counts = self._collect_virtual_key_use_counts_8616(
                child,
                tracked_keys,
                assignment_lhs=attr == "lhs" and isinstance(node, CAssignment),
                seen=seen,
            )
            for key, count in child_counts.items():
                counts[key] = counts.get(key, 0) + count

        return counts

    def _visit_prune_container_8616(
        self,
        container: object,
        use_counts: dict[tuple[str, object], int],
        visited: set[int],
    ) -> None:
        """Remove consumed virtual definitions inside one container."""
        if not _structured_codegen_node_8616(container):
            return
        container_id = id(container)
        if container_id in visited:
            return
        visited.add(container_id)
        statements = getattr(container, "statements", None)
        if isinstance(statements, list):
            kept = self._filter_consumed_definitions_8616(statements, use_counts)
            if len(kept) != len(statements):
                cast(Any, container).statements = kept
            for statement in kept:
                self._visit_prune_container_8616(statement, use_counts, visited)
        self._visit_prune_children_8616(container, use_counts, visited)

    def _visit_prune_children_8616(
        self,
        container: object,
        use_counts: dict[tuple[str, object], int],
        visited: set[int],
    ) -> None:
        """Recurse into a container's nested bodies."""
        for attr in ("body", "else_node"):
            child = getattr(container, attr, None)
            if _structured_codegen_node_8616(child):
                self._visit_prune_container_8616(child, use_counts, visited)
        pairs = getattr(container, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    self._visit_prune_container_8616(body, use_counts, visited)

    def _filter_consumed_definitions_8616(
        self,
        statements: list[object],
        use_counts: dict[tuple[str, object], int],
    ) -> list[object]:
        """Keep statements whose virtual definitions are still live."""
        kept = []
        for statement in statements:
            keys = (
                _virtual_inline_identity_keys_8616(_virtual_expr_keys_8616(statement.lhs))
                if isinstance(statement, CAssignment)
                else ()
            )
            if (
                keys
                and any(key in self.replacements for key in keys)
                and _virtual_definition_has_disposable_storage_8616(statement.lhs)
                and _pure_virtual_inline_rhs_8616(statement.rhs)
                and all(use_counts.get(key, 0) == 0 for key in keys)
            ):
                self._pruned += 1
                continue
            kept.append(statement)
        return kept

    def _prune_consumed_virtual_definitions_8616(self, node: object) -> int:
        self._pruned = 0
        replacement_keys = set(self.replacements)
        use_counts = self._collect_virtual_key_use_counts_8616(self.root, replacement_keys)
        self._visit_prune_container_8616(node, use_counts, set())
        return self._pruned


def _inline_single_assignment_virtual_expressions_8616(codegen: object) -> bool:
    """Inline unique pure virtual definitions in-place across the structured AST."""
    return bool(_VirtualInlineRun8616(codegen=codegen).run())
def _simplify_boolean_cites_8616(codegen: object) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node: object) -> object:
        if not isinstance(node, CITE):
            return node
        values = _bool_cite_values_8616(node)
        if values == (1, 0):
            return node.cond
        if values == (0, 1):
            return CUnaryOp("Not", node.cond, codegen=codegen, tags=node.tags)
        return node

    root = cast(Any, codegen).cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        if isinstance(root, CStatements) and not isinstance(new_root, CStatements):
            new_root = CStatements(
                statements=[new_root] if not isinstance(new_root, list) else new_root, codegen=codegen
            )
        cast(Any, codegen).cfunc.statements = new_root
        root = new_root
        changed = True

    if _replace_c_children_8616(root, transform):
        changed = True
    return changed


def _arithmetic_candidate_pairs_8616(expr: object) -> list[tuple[object, object]]:
    """Operand orders to try for an Add/Sub update: both orders for Add, one for Sub."""
    if not isinstance(expr, CBinaryOp):
        return []
    if expr.op == "Add":
        return [(expr.lhs, expr.rhs), (expr.rhs, expr.lhs)]
    if expr.op == "Sub":
        return [(expr.lhs, expr.rhs)]
    return []


_STACK_FLAGS_REGISTER_NAMES_8616: frozenset[str] = frozenset({"sp", "bp", "esp", "ebp", "eflags", "flags"})


_PURE_BINARY_FOLDS_8616: dict[str, Callable[[int, int], int]] = {
    "Add": operator.add,
    "Sub": operator.sub,
    "Mul": operator.mul,
    "Div": operator.floordiv,
    "Mod": operator.mod,
    "And": operator.and_,
    "Or": operator.or_,
    "Xor": operator.xor,
    "Shl": operator.lshift,
    "Shr": operator.rshift,
    "Sar": operator.rshift,
}


@dataclass
class _SimplifyExpressionRun8616:
    """Run context for structured-expression simplification over the codegen cfunc."""

    codegen: object

    def run(self) -> bool:
        if getattr(self.codegen, "cfunc", None) is None:
            return False
        roots = self._collect_cfunc_roots_8616()
        changed, active_roots = self._apply_root_transforms_8616(roots)
        for root in active_roots:
            changed = self._refresh_root_children_8616(root) or changed
        for root in active_roots:
            if self._materialize_word_or_update_statements_8616(root):
                changed = True
        for _ in range(4):
            if not _inline_single_assignment_virtual_expressions_8616(self.codegen):
                break
            changed = True
        for root in active_roots:
            if self._materialize_word_or_update_statements_8616(root):
                changed = True
        return changed

    def _collect_cfunc_roots_8616(self) -> list[tuple[list[str], object]]:
        """Collect unique top-level cfunc roots with the attribute paths that name them."""
        roots: list[tuple[list[str], object]] = []
        seen_roots: dict[int, list[str]] = {}
        for attr in ("body", "statements", "stmt"):
            root = getattr(cast(Any, self.codegen).cfunc, attr, None)
            if root is None:
                continue
            root_id = id(root)
            if root_id in seen_roots:
                seen_roots[root_id].append(attr)
                continue
            attrs = [attr]
            seen_roots[root_id] = attrs
            roots.append((attrs, root))
        return roots

    def _apply_root_transforms_8616(
        self, roots: list[tuple[list[str], object]]
    ) -> tuple[bool, list[object]]:
        """Transform each root, write replacements back through every alias attribute."""
        changed = False
        active_roots: list[object] = []
        for attrs, root in roots:
            new_root = self.transform(root)
            if new_root is not root:
                if isinstance(root, CStatements) and not isinstance(new_root, CStatements):
                    new_root = CStatements(
                        statements=[new_root] if not isinstance(new_root, list) else new_root, codegen=self.codegen
                    )
                for attr in attrs:
                    setattr(cast(Any, self.codegen).cfunc, attr, new_root)
                root = new_root
                changed = True
            active_roots.append(root)
        return changed, active_roots

    def _refresh_root_children_8616(self, root: object) -> bool:
        """Re-transform children until stable, then restore shift conditions and word ops."""
        changed = False
        for _ in range(3):
            if not _replace_c_children_8616(root, self.transform):
                break
            changed = True
        if self._restore_not_shift_conditions_in_node_8616(root):
            self._bump_stat_8616("_inertia_not_shift_condition_restored_count_8616")
            changed = True
        return changed

    def _bump_stat_8616(self, attr: str) -> None:
        """Increment a numeric debug/stat counter on the dynamic codegen boundary."""
        setattr(cast(Any, self.codegen), attr, int(getattr(self.codegen, attr, 0) or 0) + 1)

    def _invert_cmp_op_8616(self, op: str) -> str | None:
        return {
            "CmpGT": "CmpLE",
            "CmpGE": "CmpLT",
            "CmpLT": "CmpGE",
            "CmpLE": "CmpGT",
            "CmpEQ": "CmpNE",
            "CmpNE": "CmpEQ",
        }.get(op)

    def _is_c_constant_int_8616(self, expr: object, value: int) -> bool:
        return isinstance(expr, CConstant) and isinstance(expr.value, int) and expr.value == value

    def _c_constant_int_value_8616(self, expr: object) -> int | None:
        if isinstance(expr, CConstant) and isinstance(expr.value, int):
            return int(expr.value)
        return None

    def _unwrap_c_casts_8616(self, expr: object) -> object:
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        return expr

    def _constant_result_type_8616(self, node: CBinaryOp | CUnaryOp, value: int) -> object:
        if value < 0 or value > 0xFFFF:
            return SimTypeLong(value < 0)
        return node.type or SimTypeShort(False)

    def _fold_pure_constant_binary_8616(self, op: str, lhs: int, rhs: int) -> int | None:
        if op in {"Div", "Mod"} and rhs == 0:
            return None
        if op in {"Shl", "Shr", "Sar"} and (rhs < 0 or rhs > 63):
            return None
        fold = _PURE_BINARY_FOLDS_8616.get(op)
        return None if fold is None else fold(lhs, rhs)

    def _pure_constant_expr_value_8616(self, expr: object) -> int | None:
        expr = self._unwrap_c_casts_8616(expr)
        if isinstance(expr, CConstant) and isinstance(expr.value, int):
            return int(expr.value)
        if isinstance(expr, CUnaryOp):
            operand = self._pure_constant_expr_value_8616(expr.operand)
            if operand is None:
                return None
            if expr.op == "Neg":
                return -operand
            if expr.op == "Not":
                return int(not operand)
            if expr.op == "BitNot":
                return ~operand
            return None
        if isinstance(expr, CBinaryOp):
            lhs = self._pure_constant_expr_value_8616(expr.lhs)
            rhs = self._pure_constant_expr_value_8616(expr.rhs)
            if lhs is None or rhs is None:
                return None
            return self._fold_pure_constant_binary_8616(str(expr.op), lhs, rhs)
        return None

    def _flatten_offset_terms_8616(self, expr: object, sign: int = 1) -> tuple[int, tuple[tuple[int, object], ...]]:
        expr = self._unwrap_c_casts_8616(expr)
        const_value = self._pure_constant_expr_value_8616(expr)
        if const_value is not None:
            return sign * const_value, ()
        if isinstance(expr, CBinaryOp) and expr.op == "Add":
            lhs_const, lhs_terms = self._flatten_offset_terms_8616(expr.lhs, sign)
            rhs_const, rhs_terms = self._flatten_offset_terms_8616(expr.rhs, sign)
            return lhs_const + rhs_const, lhs_terms + rhs_terms
        if isinstance(expr, CBinaryOp) and expr.op == "Sub":
            lhs_const, lhs_terms = self._flatten_offset_terms_8616(expr.lhs, sign)
            rhs_const, rhs_terms = self._flatten_offset_terms_8616(expr.rhs, -sign)
            return lhs_const + rhs_const, lhs_terms + rhs_terms
        return 0, ((sign, expr),)

    def _same_signed_term_multiset_8616(self,
        lhs_terms: tuple[tuple[int, object], ...],
        rhs_terms: tuple[tuple[int, object], ...],
    ) -> bool:
        unmatched = list(rhs_terms)
        for lhs_sign, lhs_expr in lhs_terms:
            found_index = None
            for idx, (rhs_sign, rhs_expr) in enumerate(unmatched):
                if lhs_sign == rhs_sign and _same_c_expression_8616(lhs_expr, rhs_expr):
                    found_index = idx
                    break
            if found_index is None:
                return False
            del unmatched[found_index]
        return not unmatched

    def _global_byte_reference_addr_8616(self, expr: object) -> int | None:
        expr = self._unwrap_c_casts_8616(expr)
        if not isinstance(expr, CUnaryOp) or expr.op != "Reference":
            return None
        target = self._unwrap_c_casts_8616(expr.operand)
        if not isinstance(target, CVariable):
            return None
        variable = target.variable
        if not isinstance(variable, SimMemoryVariable):
            return None
        if variable.size != 1:
            return None
        addr = variable.addr
        return addr if isinstance(addr, int) else None

    def _global_byte_address_terms_8616(self, expr: object) -> tuple[int, tuple[tuple[int, object], ...], bool]:
        const_value, terms = self._flatten_offset_terms_8616(expr)
        normalized_terms: list[tuple[int, object]] = []
        saw_global_byte_ref = False
        for sign, term in terms:
            ref_addr = self._global_byte_reference_addr_8616(term)
            if ref_addr is not None:
                const_value += sign * ref_addr
                saw_global_byte_ref = True
                continue
            normalized_terms.append((sign, term))
        return const_value, tuple(normalized_terms), saw_global_byte_ref

    def _byte_deref_address_info_8616(self, expr: object) -> tuple[object, int, tuple[tuple[int, object], ...]] | None:
        expr = self._unwrap_c_casts_8616(expr)
        if not isinstance(expr, CUnaryOp) or expr.op != "Dereference":
            return None
        addr_expr = expr.operand
        const_value, terms, saw_global_byte_ref = self._global_byte_address_terms_8616(addr_expr)
        if not saw_global_byte_ref:
            return None
        return addr_expr, const_value, terms

    def _shifted_byte_deref_high_info_8616(self,
        expr: object,
    ) -> tuple[object, int, tuple[tuple[int, object], ...]] | None:
        expr = self._unwrap_c_casts_8616(expr)
        if not isinstance(expr, CBinaryOp):
            return None
        if expr.op == "Shl":
            for maybe_deref, maybe_shift in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                if self._pure_constant_expr_value_8616(maybe_shift) == 8:
                    return self._byte_deref_address_info_8616(maybe_deref)
        if expr.op == "Mul":
            for maybe_deref, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                if self._pure_constant_expr_value_8616(maybe_scale) == 0x100:
                    return self._byte_deref_address_info_8616(maybe_deref)
        return None

    def _make_word_deref_from_addr_expr_8616(self, addr_expr: object) -> CFunctionCall:
        return CFunctionCall(
            "MEM_U16",
            None,
            [addr_expr],
            codegen=self.codegen,
            tags={"inertia_x86_16_runtime_pointer_helper": "MEM_U16"},
        )

    def _fold_global_byte_deref_pair_8616(self, expr: object) -> object | None:
        if not isinstance(expr, CBinaryOp) or expr.op not in {"Or", "Add"}:
            return None
        for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            low_info = self._byte_deref_address_info_8616(maybe_low)
            high_info = self._shifted_byte_deref_high_info_8616(maybe_high)
            if low_info is None or high_info is None:
                continue
            low_addr_expr, low_const, low_terms = low_info
            _high_addr_expr, high_const, high_terms = high_info
            if high_const != low_const + 1:
                continue
            if not self._same_signed_term_multiset_8616(low_terms, high_terms):
                continue
            return cast(object | None, self._make_word_deref_from_addr_expr_8616(low_addr_expr))
        return None

    def _is_power_of_two_minus_one_8616(self, value: int) -> bool:
        """Check if value is of form 2^n - 1 (all bits set up to position n-1)."""
        if value <= 0:
            return False
        return (value & (value + 1)) == 0

    def _bit_position_of_power_of_two_8616(self, value: int) -> int | None:
        """Return n if value == 2^n, else None."""
        if value <= 0 or (value & (value - 1)) != 0:
            return None
        return (value - 1).bit_length()

    def _leading_set_bits_8616(self, value: int) -> int:
        """Return position of highest set bit (1-indexed, so 0xFF -> 8)."""
        if value == 0:
            return 0
        return value.bit_length()

    def _extract_same_zero_compare_expr_8616(self, expr: object) -> object | None:
        if not isinstance(expr, CBinaryOp) or expr.op != "CmpEQ":
            return None
        if self._is_c_constant_int_8616(expr.rhs, 0):
            return cast(object | None, expr.lhs)
        if self._is_c_constant_int_8616(expr.lhs, 0):
            return cast(object | None, expr.rhs)
        return None

    def _extract_scaled_zero_flag_source_8616(self, expr: CBinaryOp) -> object | None:
        """Recover a zero-compare source hidden behind a ``x & mask == 0 << 6`` scaling."""
        for maybe_logic, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            if not self._is_c_constant_int_8616(maybe_scale, 64):
                continue
            source_expr = self._extract_same_zero_compare_expr_8616(maybe_logic)
            if source_expr is not None:
                return source_expr
            if not isinstance(maybe_logic, CBinaryOp) or maybe_logic.op != "LogicalAnd":
                continue
            lhs_expr = self._extract_same_zero_compare_expr_8616(maybe_logic.lhs)
            rhs_expr = self._extract_same_zero_compare_expr_8616(maybe_logic.rhs)
            if lhs_expr is not None and rhs_expr is not None and _same_c_expression_8616(lhs_expr, rhs_expr):
                return lhs_expr
        return None

    def _extract_zero_flag_source_from_children_8616(self, children: tuple[object, ...]) -> object | None:
        """Recurse into structured child expressions for a zero-flag source."""
        for child in children:
            if _structured_codegen_node_8616(child):
                extracted = self._extract_zero_flag_source_expr_8616(child)
                if extracted is not None:
                    return extracted
        return None

    def _extract_zero_flag_source_expr_8616(self, expr: object) -> object | None:
        if isinstance(expr, CBinaryOp):
            if expr.op == "Mul":
                source_expr = self._extract_scaled_zero_flag_source_8616(expr)
                if source_expr is not None:
                    return source_expr

            return self._extract_zero_flag_source_from_children_8616((expr.lhs, expr.rhs))

        if isinstance(expr, (CUnaryOp, CTypeCast)):
            child = expr.operand if isinstance(expr, CUnaryOp) else expr.expr
            return self._extract_zero_flag_source_from_children_8616((child,))

        return None

    def _stack_or_flags_offsets_8616(self) -> frozenset[int]:
        """Collect arch register offsets that identify stack or flags storage."""
        arch = getattr(getattr(self.codegen, "project", None), "arch", None)
        registers = getattr(arch, "registers", {}) if arch is not None else {}
        offsets: set[int] = set()
        for register_name in _STACK_FLAGS_REGISTER_NAMES_8616:
            register_info = registers.get(register_name)
            if isinstance(register_info, tuple) and register_info and isinstance(register_info[0], int):
                offsets.add(register_info[0])
        return frozenset(offsets)

    def _expr_contains_stack_or_flags_register_8616(self, expr: object) -> bool:
        return self._stack_or_flags_register_in_node_8616(expr, self._stack_or_flags_offsets_8616())

    def _stack_or_flags_register_in_node_8616(self, node: object, offsets: frozenset[int]) -> bool:
        node = self._unwrap_c_casts_8616(node)
        if isinstance(node, CVariable):
            variable = node.variable
            if not isinstance(variable, SimRegisterVariable):
                return False
            name = variable.name
            if isinstance(name, str) and name.lower() in _STACK_FLAGS_REGISTER_NAMES_8616:
                return True
            for attr in ("reg", "reg_offset", "offset"):
                offset = getattr(variable, attr, None)
                if isinstance(offset, int) and offset in offsets:
                    return True
            return False
        if isinstance(node, CDirtyExpression):
            return False
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child) and self._stack_or_flags_register_in_node_8616(child, offsets):
                return True
        return self._seq_contains_stack_or_flags_8616(node, offsets)

    def _seq_structured_children_8616(self, node: object) -> Iterator[object]:
        """Yield structured children from sequence-valued attributes (operands/args/tuples)."""
        for attr in ("operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    yield item
                if isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            yield subitem

    def _seq_contains_stack_or_flags_8616(self, node: object, offsets: frozenset[int]) -> bool:
        """Scan sequence-valued attributes (operands, args, and tuple items) for stack/flags."""
        return any(
            self._stack_or_flags_register_in_node_8616(child, offsets)
            for child in self._seq_structured_children_8616(node)
        )

    def _shifted_high_byte_source_8616(self, expr: object) -> object | None:
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        if not isinstance(expr, CBinaryOp):
            return None
        if expr.op == "Shl" and self._is_c_constant_int_8616(expr.rhs, 8):
            return cast(object | None, expr.lhs)
        if expr.op == "Mul" and self._is_c_constant_int_8616(expr.rhs, 0x100):
            return cast(object | None, expr.lhs)
        if expr.op == "Mul" and self._is_c_constant_int_8616(expr.lhs, 0x100):
            return cast(object | None, expr.rhs)
        return None

    def _or_terms_8616(self, expr: object) -> list[object]:
        if isinstance(expr, CBinaryOp) and expr.op == "Or":
            return [*self._or_terms_8616(expr.lhs), *self._or_terms_8616(expr.rhs)]
        return [expr]

    def _match_word_or_carrier_expr_8616(self, expr: object, target: object) -> int | None:
        terms = self._or_terms_8616(expr)
        constant_terms: list[int] = []
        saw_target = False
        saw_shifted_target = False
        for term in terms:
            const_value = self._c_constant_int_value_8616(term)
            if const_value is not None:
                constant_terms.append(const_value)
                continue
            if _same_c_expression_8616(term, target):
                saw_target = True
                continue
            shifted = self._shifted_high_byte_source_8616(term)
            if shifted is not None and _same_c_expression_8616(shifted, target):
                saw_shifted_target = True
                continue
            return None
        if not saw_target or not saw_shifted_target or len(constant_terms) != 1:
            return None
        value = constant_terms[0]
        if value < 0 or value > 0xFF:
            return None
        return value

    def _match_word_or_carrier_expr_pair_8616(self, expr: object, low_target: object, high_target: object) -> int | None:
        terms = self._or_terms_8616(expr)
        constant_terms: list[int] = []
        saw_low = False
        saw_shifted_high = False
        for term in terms:
            const_value = self._c_constant_int_value_8616(term)
            if const_value is not None:
                constant_terms.append(const_value)
                continue
            if _same_c_expression_8616(term, low_target):
                saw_low = True
                continue
            shifted = self._shifted_high_byte_source_8616(term)
            if shifted is not None and _same_c_expression_8616(shifted, high_target):
                saw_shifted_high = True
                continue
            return None
        if not saw_low or not saw_shifted_high or len(constant_terms) != 1:
            return None
        value = constant_terms[0]
        if value < 0 or value > 0xFF:
            return None
        return value

    def _match_word_or_carrier_shift_8616(self, expr: object, target: object) -> int | None:
        if not isinstance(expr, CBinaryOp) or expr.op != "Shr":
            return None
        if not self._is_c_constant_int_8616(expr.rhs, 8):
            return None
        return self._match_word_or_carrier_expr_8616(expr.lhs, target)

    def _match_word_or_carrier_pair_shift_8616(self, expr: object, low_target: object, high_target: object) -> int | None:
        if not isinstance(expr, CBinaryOp) or expr.op != "Shr":
            return None
        if not self._is_c_constant_int_8616(expr.rhs, 8):
            return None
        return self._match_word_or_carrier_expr_pair_8616(expr.lhs, low_target, high_target)

    def _stack_word_contains_high_byte_8616(self, word_expr: object, high_expr: object) -> bool:
        word_domain = _storage_domain_for_expr(word_expr)
        high_domain = _storage_domain_for_expr(high_expr)
        if word_domain.space != "stack" or high_domain.space != "stack":
            return False
        word_slot = word_domain.stack_slot
        high_slot = high_domain.stack_slot
        if word_slot is None or high_slot is None:
            return False
        if word_slot.base != high_slot.base:
            return False
        if word_slot.region != high_slot.region:
            return False
        word_offset = _canonical_stack_offset_8616(word_slot.offset)
        high_offset = _canonical_stack_offset_8616(high_slot.offset)
        if not isinstance(word_offset, int) or not isinstance(high_offset, int):
            return False
        return int(word_domain.width or 0) == 2 and high_offset == word_offset + 1

    def _materialize_joined_word_expr_8616(self, low_expr: object, high_expr: object) -> object | None:
        """Consume register-view joins; never invent stack or memory C objects."""
        if not (
            isinstance(low_expr, CVariable) and isinstance(high_expr, CVariable)
            and isinstance(low_expr.variable, SimRegisterVariable)
            and isinstance(high_expr.variable, SimRegisterVariable)
        ):
            return None
        alias_state = getattr(self.codegen, "_inertia_alias_state", None)
        if alias_state is None:
            alias_state = getattr(getattr(self.codegen, "cfunc", None), "_inertia_alias_state", None)
        proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
        return cast(object | None, join_adjacent_register_slices(
            low_expr, high_expr, self.codegen, alias_state=alias_state, proof=proof,
        ))

    def _simplify_zero_flag_comparison_8616(self, expr: object) -> object:
        if not isinstance(expr, CBinaryOp) or expr.op not in {"CmpEQ", "CmpNE"}:
            return expr

        if self._is_c_constant_int_8616(expr.rhs, 0):
            source = expr.lhs
        elif self._is_c_constant_int_8616(expr.lhs, 0):
            source = expr.rhs
        else:
            return expr

        source_expr = self._extract_zero_flag_source_expr_8616(source)
        if source_expr is None:
            return expr
        source_expr = self._restore_not_shift_zero_flag_source_8616(source_expr)
        if self._expr_contains_stack_or_flags_register_8616(source_expr):
            return expr
        if expr.op == "CmpEQ":
            return source_expr
        return CUnaryOp("Not", cast(Any, source_expr), codegen=self.codegen)

    def _restore_not_shift_zero_flag_source_8616(self, source_expr: object) -> object | None:
        source_expr = self._unwrap_c_casts_8616(source_expr)
        if not isinstance(source_expr, CBinaryOp) or source_expr.op not in {"Shr", "Sar"}:
            return source_expr
        lhs = self._unwrap_c_casts_8616(source_expr.lhs)
        if not isinstance(lhs, CUnaryOp) or lhs.op != "Not":
            return cast(object | None, source_expr)
        shift = source_expr.rhs
        restored_shift = CBinaryOp(
            source_expr.op,
            cast(Any, lhs.operand),
            shift,
            codegen=self.codegen,
            tags=source_expr.tags,
        )
        return cast(object | None, CBinaryOp(
            "CmpEQ",
            restored_shift,
            CConstant(0, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
            tags=lhs.tags or source_expr.tags,
        ))

    def _restore_not_shift_in_binary_8616(self, expr: CBinaryOp) -> tuple[object, bool]:
        lhs, lhs_changed = self._restore_not_shift_condition_expr_8616(expr.lhs)
        rhs, rhs_changed = self._restore_not_shift_condition_expr_8616(expr.rhs)
        if lhs_changed:
            expr.lhs = lhs
        if rhs_changed:
            expr.rhs = rhs
        if expr.op in {"Shr", "Sar"}:
            lhs_node = self._unwrap_c_casts_8616(expr.lhs)
            shift = self._c_constant_int_value_8616(self._unwrap_c_casts_8616(expr.rhs))
            if isinstance(lhs_node, CUnaryOp) and lhs_node.op == "Not" and isinstance(shift, int) and shift > 0:
                restored = self._restore_not_shift_zero_flag_source_8616(expr)
                if restored is not expr:
                    return restored, True
        return expr, lhs_changed or rhs_changed

    def _restore_not_shift_condition_expr_8616(self, expr: object) -> tuple[object, bool]:
        expr = self._unwrap_c_casts_8616(expr)
        if isinstance(expr, CBinaryOp):
            return self._restore_not_shift_in_binary_8616(expr)
        if isinstance(expr, CUnaryOp):
            operand, operand_changed = self._restore_not_shift_condition_expr_8616(expr.operand)
            if operand_changed:
                cast(Any, expr).operand = operand
            return expr, operand_changed
        if isinstance(expr, CTypeCast):
            inner, inner_changed = self._restore_not_shift_condition_expr_8616(expr.expr)
            if inner_changed:
                cast(Any, expr).expr = inner
            return expr, inner_changed
        return expr, False

    def _restore_not_shift_in_pairs_8616(self, node: object, changed_local: bool) -> bool:
        """Rewrite ``condition_and_nodes`` pair conditions in place when any changed."""
        pairs = getattr(node, "condition_and_nodes", None)
        if not pairs:
            return changed_local
        new_pairs = []
        pair_changed = False
        for condition, body in pairs:
            new_condition = condition
            if _structured_codegen_node_8616(condition):
                new_condition, condition_changed = self._restore_not_shift_condition_expr_8616(condition)
                pair_changed = pair_changed or condition_changed
            if _structured_codegen_node_8616(body):
                changed_local = self._restore_not_shift_conditions_in_node_8616(body) or changed_local
            new_pairs.append((new_condition, body))
        if pair_changed:
            cast(Any, node).condition_and_nodes = new_pairs
            return True
        return changed_local

    def _restore_not_shift_in_children_8616(self, node: object, changed_local: bool) -> bool:
        """Recurse into body/else branches and statement lists."""
        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                changed_local = self._restore_not_shift_conditions_in_node_8616(child) or changed_local
        statements = getattr(node, "statements", None)
        if statements:
            for statement in tuple(statements):
                if _structured_codegen_node_8616(statement):
                    changed_local = self._restore_not_shift_conditions_in_node_8616(statement) or changed_local
        return changed_local

    def _restore_not_shift_conditions_in_node_8616(self, node: object) -> bool:
        if not _structured_codegen_node_8616(node):
            return False
        changed_local = False
        for attr in ("condition", "cond"):
            condition = getattr(node, attr, None)
            if not _structured_codegen_node_8616(condition):
                continue
            new_condition, condition_changed = self._restore_not_shift_condition_expr_8616(condition)
            if condition_changed:
                setattr(cast(Any, node), attr, new_condition)
                changed_local = True
        changed_local = self._restore_not_shift_in_pairs_8616(node, changed_local)
        return self._restore_not_shift_in_children_8616(node, changed_local)

    def _fold_stat_counted_8616(self, node: object) -> object | None:
        """Folds that bump a codegen counter: global byte pairs and pure constants."""
        if isinstance(node, CBinaryOp) and node.op in {"Or", "Add"}:
            folded_global_word = self._fold_global_byte_deref_pair_8616(node)
            if folded_global_word is not None:
                self._bump_stat_8616("_inertia_global_byte_pair_folded_count_8616")
                return folded_global_word
        if isinstance(node, (CBinaryOp, CUnaryOp)):
            folded_constant = self._pure_constant_expr_value_8616(node)
            if folded_constant is not None:
                self._bump_stat_8616("_inertia_pure_constant_folded_count_8616")
                return CConstant(
                    folded_constant,
                    cast(Any, self._constant_result_type_8616(node, folded_constant)),
                    codegen=self.codegen,
                    tags=node.tags,
                )
        return None

    def transform(self, node: object) -> object:
        counted = self._fold_stat_counted_8616(node)
        if counted is not None:
            return counted

        if isinstance(node, CBinaryOp):
            folded_binary = self._fold_binary_transform_8616(node)
            if folded_binary is not None:
                return folded_binary

        if isinstance(node, CUnaryOp) and node.op == "Not":
            folded_not = self._fold_not_transform_8616(node)
            if folded_not is not None:
                return folded_not

        if isinstance(node, CITE) and _same_c_expression_8616(node.iftrue, node.iffalse):
            self._bump_stat_8616("_inertia_same_arm_cite_simplified_count_8616")
            return node.iftrue

        simplified = self._simplify_zero_flag_comparison_8616(node)
        if simplified is not node:
            return simplified

        if isinstance(node, CBinaryOp):
            folded_tail = self._fold_tail_binary_8616(node)
            if folded_tail is not None:
                return folded_tail
        return node

    def _fold_tail_binary_8616(self, node: CBinaryOp) -> object | None:
        """Last-chance binary folds: same-operand dedup, zero-compare, and self-cancel."""
        if node.op in {"LogicalAnd", "LogicalOr", "And", "Or"} and _same_c_expression_8616(node.lhs, node.rhs):
            return node.lhs
        if node.op in {"CmpEQ", "CmpNE"}:
            folded_cmp = self._fold_cmp_against_zero_8616(node)
            if folded_cmp is not None:
                return folded_cmp
        if node.op in {"Sub", "Xor"} and _same_c_expression_8616(node.lhs, node.rhs):
            type_ = node.type or node.lhs.type
            if type_ is not None:
                return CConstant(0, type_, codegen=self.codegen)
        return None

    def _fold_binary_transform_8616(self, node: CBinaryOp) -> object | None:
        """Dispatch the pure binary-operator folds; None means no fold applied."""
        if node.op == "Concat":
            return self._fold_concat_8616(node)
        if node.op in {"Shl", "Shr", "Sar"} and self._is_c_constant_int_8616(node.rhs, 0):
            return node.lhs
        if node.op in {"Mul", "And"}:
            return self._fold_zero_operand_binary_8616(node)
        if node.op == "Or":
            return self._fold_or_word_or_zero_8616(node)
        return None

    def _fold_concat_8616(self, node: CBinaryOp) -> object:
        lhs_val = _c_constant_value_8616(node.lhs)
        rhs_val = _c_constant_value_8616(node.rhs)
        rhs_bits = getattr(node.rhs.type, "size", None)
        lhs_bits = getattr(node.lhs.type, "size", None)
        if rhs_bits is None:
            rhs_bits = lhs_bits if lhs_bits is not None else 16

        if lhs_val is not None and rhs_val is not None:
            return CConstant((lhs_val << rhs_bits) | rhs_val, cast(Any, node.type), codegen=self.codegen)

        shift = CConstant(rhs_bits, cast(Any, node.rhs.type or node.lhs.type), codegen=self.codegen)
        return CBinaryOp(
            "Or",
            CBinaryOp("Shl", node.lhs, shift, codegen=self.codegen, tags=node.tags),
            node.rhs,
            codegen=self.codegen,
            tags=node.tags,
        )

    def _fold_zero_operand_binary_8616(self, node: CBinaryOp) -> object | None:
        if self._is_c_constant_int_8616(node.lhs, 0) or self._is_c_constant_int_8616(node.rhs, 0):
            type_ = node.type or node.lhs.type or node.rhs.type
            if type_ is not None:
                return CConstant(0, type_, codegen=self.codegen)
        return None

    def _fold_or_word_or_zero_8616(self, node: CBinaryOp) -> object | None:
        shifted_rhs = self._shifted_high_byte_source_8616(node.rhs)
        if shifted_rhs is not None:
            folded = self._materialize_joined_word_expr_8616(node.lhs, shifted_rhs)
            if folded is not None:
                return folded
        shifted_lhs = self._shifted_high_byte_source_8616(node.lhs)
        if shifted_lhs is not None:
            folded = self._materialize_joined_word_expr_8616(node.rhs, shifted_lhs)
            if folded is not None:
                return folded
        if self._is_c_constant_int_8616(node.lhs, 0):
            return node.rhs
        if self._is_c_constant_int_8616(node.rhs, 0):
            return node.lhs
        return None

    def _fold_not_transform_8616(self, node: CUnaryOp) -> object | None:
        operand = node.operand
        if isinstance(operand, CUnaryOp) and operand.op == "Not":
            return operand.operand
        if isinstance(operand, CBinaryOp):
            inverted = self._invert_cmp_op_8616(operand.op)
            if inverted is not None:
                # Some angr C types have no architecture attached after
                # snapshot/restore.  Constructing a replacement binary
                # node makes angr compute a common type and raises from
                # ``SimType.size``.  Keep the original typed condition;
                # this is a cleanup-only inversion, not semantic proof.
                try:
                    for operand_type in (operand.lhs.type, operand.rhs.type):
                        if operand_type is not None:
                            operand_type.size  # noqa: B018
                except ValueError:
                    return node
                return CBinaryOp(
                    inverted,
                    operand.lhs,
                    operand.rhs,
                    codegen=self.codegen,
                    tags=node.tags or operand.tags,
                )
        return None

    def _fold_cmp_against_zero_8616(self, node: CBinaryOp) -> object | None:
        """Reduce ``(x - C) cmp0`` to ``x cmp C`` on either operand side."""
        for probe, other in ((node.rhs, node.lhs), (node.lhs, node.rhs)):
            if not (isinstance(probe, CConstant) and probe.value == 0):
                continue
            if isinstance(other, CBinaryOp) and other.op == "Sub" and isinstance(other.rhs, CConstant):
                return CBinaryOp(node.op, other.lhs, other.rhs, codegen=self.codegen, tags=node.tags)
        return None

    def _materialize_word_or_update_statements_8616(self, root_node: object) -> bool:
        self.changed_local = False

        self._visit_word_or_node_8616(root_node)

        return self.changed_local



    def _unwrap_expr_8616(self, expr: object) -> object:
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        return expr

    def _virtual_assignment_key_8616(self, stmt: object) -> tuple[str, object] | None:
        if not isinstance(stmt, CAssignment):
            return None
        return _virtual_expr_key_8616(stmt.lhs)

    def _virtual_assignment_keys_8616(self, stmt: object) -> tuple[tuple[str, object], ...]:
        if not isinstance(stmt, CAssignment):
            return ()
        return _virtual_expr_keys_8616(stmt.lhs)

    def _copy_alias_map_8616(self, statements: list[object]) -> dict[tuple[str, object], object]:
        aliases: dict[tuple[str, object], object] = {}
        for candidate in statements:
            if not isinstance(candidate, CAssignment):
                continue
            keys = self._virtual_assignment_keys_8616(candidate)
            if not keys:
                continue
            rhs = candidate.rhs
            if not _pure_virtual_inline_rhs_8616(rhs):
                for key in keys:
                    aliases.pop(key, None)
                continue
            for key in keys:
                aliases[key] = rhs
        return aliases

    def _debug_aliases_8616(self, aliases: dict[tuple[str, object], object]) -> list[str]:
        if not os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
            return []
        return [f"{key}={_debug_c_repr_8616(value)}" for key, value in sorted(aliases.items(), key=str)]

    def _resolve_copy_alias_expr_8616(self,
        expr: object, aliases: dict[tuple[str, object], object], used: set[tuple[str, object]]
    ) -> object:
        expr = self._unwrap_expr_8616(expr)
        keys = _virtual_expr_keys_8616(expr)
        if not keys:
            return expr
        key = next((candidate_key for candidate_key in keys if candidate_key in aliases), None)
        if key is None:
            return expr
        replacement = aliases.get(key)
        if replacement is None:
            return expr
        used.add(key)
        replacement_key = _virtual_expr_key_8616(replacement)
        if replacement_key == key:
            return expr
        return self._resolve_copy_alias_expr_8616(replacement, aliases, used)

    def _match_joined_stack_word_base_8616(self,
        expr: object,
        word_target: object,
        high_target: object,
        aliases: dict[tuple[str, object], object],
        used: set[tuple[str, object]],
    ) -> object | None:
        expr = self._unwrap_expr_8616(expr)
        if not isinstance(expr, CBinaryOp) or expr.op != "Or":
            return None
        for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            low_expr = self._resolve_copy_alias_expr_8616(maybe_low, aliases, used)
            shifted = self._shifted_high_byte_source_8616(maybe_high)
            if shifted is None:
                continue
            high_expr = self._resolve_copy_alias_expr_8616(shifted, aliases, used)
            if _same_c_expression_8616(low_expr, word_target) and _same_c_expression_8616(high_expr, high_target):
                return word_target
        return None

    def _same_after_copy_alias_8616(self,
        left: object,
        right: object,
        aliases: dict[tuple[str, object], object],
        used: set[tuple[str, object]],
    ) -> bool:
        left_resolved = self._resolve_copy_alias_expr_8616(left, aliases, used)
        right_resolved = self._resolve_copy_alias_expr_8616(right, aliases, used)
        return bool(_same_c_expression_8616(left_resolved, right_resolved))

    def _contains_unresolved_virtual_expr_8616(self, expr: object) -> bool:
        if expr is None:
            return False
        if _virtual_expr_key_8616(expr) is not None:
            return True
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval"):
            child = getattr(expr, attr, None)
            if _structured_codegen_node_8616(child) and self._contains_unresolved_virtual_expr_8616(child):
                return True
        return any(
            self._contains_unresolved_virtual_expr_8616(child)
            for child in self._seq_structured_children_8616(expr)
        )

    def _log_arithmetic_pair_refuse_8616(
        self,
        reason: str,
        low_rhs: object,
        high_rhs: object,
        word_target: object,
        high_target: object,
        aliases: dict[tuple[str, object], object],
    ) -> None:
        if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
            _log.warning(
                "[word-or-update] arithmetic-pair refused reason=%s low_op=%r high_op=%r high_lhs_op=%r word_domain=%r high_domain=%r aliases=%r",
                reason,
                getattr(low_rhs, "op", None),
                getattr(high_rhs, "op", None),
                getattr(getattr(high_rhs, "lhs", None), "op", None),
                _storage_domain_for_expr(word_target),
                _storage_domain_for_expr(high_target),
                self._debug_aliases_8616(aliases),
            )

    def _gate_arithmetic_update_pair_8616(
        self,
        low_rhs: object,
        high_rhs: object,
        word_target: object,
        high_target: object,
        aliases: dict[tuple[str, object], object],
    ) -> tuple[CBinaryOp, CBinaryOp] | None:
        """Unwrap and gate the ``word op delta`` low/high pair before matching."""
        low_rhs = self._unwrap_expr_8616(low_rhs)
        high_rhs = self._unwrap_expr_8616(high_rhs)
        if not isinstance(high_rhs, CBinaryOp) or high_rhs.op != "Shr":
            self._log_arithmetic_pair_refuse_8616("high-not-shr", low_rhs, high_rhs, word_target, high_target, aliases)
            return None
        if not self._is_c_constant_int_8616(self._unwrap_expr_8616(high_rhs.rhs), 8):
            self._log_arithmetic_pair_refuse_8616("shift-not-8", low_rhs, high_rhs, word_target, high_target, aliases)
            return None
        update_expr = low_rhs
        high_update_expr = self._unwrap_expr_8616(high_rhs.lhs)
        if not isinstance(update_expr, CBinaryOp) or update_expr.op not in {"Add", "Sub"}:
            self._log_arithmetic_pair_refuse_8616(
                "update-not-add-sub", low_rhs, high_rhs, word_target, high_target, aliases
            )
            return None
        if (
            not isinstance(high_update_expr, CBinaryOp)
            or high_update_expr.op not in {"Add", "Sub"}
            or high_update_expr.op != update_expr.op
        ):
            self._log_arithmetic_pair_refuse_8616(
                "high-update-not-same-op", low_rhs, high_rhs, word_target, high_target, aliases
            )
            return None
        return update_expr, high_update_expr

    def _match_arithmetic_delta_8616(
        self,
        maybe_base: object,
        maybe_delta: object,
        high_update_expr: CBinaryOp,
        low_rhs: object,
        high_rhs: object,
        word_target: object,
        high_target: object,
        aliases: dict[tuple[str, object], object],
    ) -> tuple[object, set[tuple[str, object]]] | None:
        """Match one low-side ``base op delta`` candidate against the high update."""
        low_used: set[tuple[str, object]] = set()
        if (
            self._match_joined_stack_word_base_8616(maybe_base, word_target, high_target, aliases, low_used)
            is None
        ):
            return None
        delta = self._resolve_copy_alias_expr_8616(maybe_delta, aliases, low_used)
        matched_used: set[tuple[str, object]] | None = None
        for high_base, high_delta in _arithmetic_candidate_pairs_8616(high_update_expr):
            high_used = set(low_used)
            if (
                self._match_joined_stack_word_base_8616(high_base, word_target, high_target, aliases, high_used)
                is None
            ):
                continue
            resolved_high_delta = self._resolve_copy_alias_expr_8616(high_delta, aliases, high_used)
            if not _same_c_expression_8616(delta, resolved_high_delta):
                continue
            matched_used = high_used
            break
        if matched_used is None:
            return None
        if _expr_contains_virtual_key_8616(delta, _virtual_expr_key_8616(word_target) or ("", "")):
            self._log_arithmetic_pair_refuse_8616(
                "delta-contains-target", low_rhs, high_rhs, word_target, high_target, aliases
            )
            return None
        if self._contains_unresolved_virtual_expr_8616(delta):
            self._log_arithmetic_pair_refuse_8616(
                "delta-unresolved-virtual", low_rhs, high_rhs, word_target, high_target, aliases
            )
            return None
        return delta, matched_used

    def _match_stack_word_arithmetic_update_8616(self,
        low_rhs: object,
        high_rhs: object,
        word_target: object,
        high_target: object,
        aliases: dict[tuple[str, object], object],
    ) -> tuple[str, object, set[tuple[str, object]]] | None:
        low_rhs = self._unwrap_expr_8616(low_rhs)
        high_rhs = self._unwrap_expr_8616(high_rhs)
        gated = self._gate_arithmetic_update_pair_8616(low_rhs, high_rhs, word_target, high_target, aliases)
        if gated is None:
            return None
        update_expr, high_update_expr = gated

        for maybe_base, maybe_delta in _arithmetic_candidate_pairs_8616(update_expr):
            matched = self._match_arithmetic_delta_8616(
                maybe_base,
                maybe_delta,
                high_update_expr,
                low_rhs,
                high_rhs,
                word_target,
                high_target,
                aliases,
            )
            if matched is None:
                continue
            delta, matched_used = matched
            if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                _log.warning(
                    "[word-or-update] arithmetic-pair matched op=%s word=%r high=%r delta=%r used=%r",
                    update_expr.op,
                    word_target,
                    high_target,
                    delta,
                    sorted(str(key) for key in matched_used),
                )
            return update_expr.op, delta, matched_used
        self._log_arithmetic_pair_refuse_8616(
            "base-not-joined-word", low_rhs, high_rhs, word_target, high_target, aliases
        )
        return None

    def _log_duplicate_shift_refuse_8616(
        self,
        reason: str,
        rhs: object,
        word_target: object,
        aliases: dict[tuple[str, object], object],
    ) -> None:
        if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
            _log.warning(
                "[word-or-update] duplicate-shift refused reason=%s target_domain=%r rhs_op=%r rhs_lhs_op=%r rhs=%r target=%r aliases=%r",
                reason,
                _storage_domain_for_expr(word_target),
                getattr(rhs, "op", None),
                getattr(getattr(rhs, "lhs", None), "op", None),
                rhs,
                word_target,
                self._debug_aliases_8616(aliases),
            )

    def _gate_duplicate_shift_update_8616(
        self,
        rhs: object,
        word_target: object,
        aliases: dict[tuple[str, object], object],
    ) -> CBinaryOp | None:
        """Gate ``(x|x<<8) op delta >> 8`` shape down to its Add/Sub update expr."""
        target_domain = _storage_domain_for_expr(word_target)
        if target_domain.space != "stack" or target_domain.width != 2:
            self._log_duplicate_shift_refuse_8616("target-not-stack-word", rhs, word_target, aliases)
            return None
        if not isinstance(rhs, CBinaryOp) or rhs.op != "Shr":
            self._log_duplicate_shift_refuse_8616("rhs-not-shr", rhs, word_target, aliases)
            return None
        if not self._is_c_constant_int_8616(self._unwrap_expr_8616(rhs.rhs), 8):
            self._log_duplicate_shift_refuse_8616("shift-not-8", rhs, word_target, aliases)
            return None
        update_expr = self._unwrap_expr_8616(rhs.lhs)
        if not isinstance(update_expr, CBinaryOp) or update_expr.op not in {"Add", "Sub"}:
            self._log_duplicate_shift_refuse_8616("update-not-add-sub", rhs, word_target, aliases)
            return None
        return update_expr

    def _match_duplicate_or_base_8616(
        self,
        base: object,
        word_target: object,
        aliases: dict[tuple[str, object], object],
        candidate_used: set[tuple[str, object]],
    ) -> bool:
        """Check that ``base`` is an Or of the target word with its shifted self."""
        base = self._unwrap_expr_8616(base)
        if not isinstance(base, CBinaryOp) or base.op != "Or":
            return False
        for maybe_low, maybe_high in ((base.lhs, base.rhs), (base.rhs, base.lhs)):
            low_expr = self._resolve_copy_alias_expr_8616(maybe_low, aliases, candidate_used)
            shifted = self._shifted_high_byte_source_8616(maybe_high)
            if shifted is None:
                continue
            high_expr = self._resolve_copy_alias_expr_8616(shifted, aliases, candidate_used)
            if _same_c_expression_8616(low_expr, word_target) and _same_c_expression_8616(high_expr, word_target):
                return True
        return False

    def _match_duplicate_word_arithmetic_shift_8616(self,
        rhs: object,
        word_target: object,
        aliases: dict[tuple[str, object], object],
    ) -> tuple[str, object, set[tuple[str, object]]] | None:
        rhs = self._unwrap_expr_8616(rhs)
        update_expr = self._gate_duplicate_shift_update_8616(rhs, word_target, aliases)
        if update_expr is None:
            return None
        for maybe_base, maybe_delta in _arithmetic_candidate_pairs_8616(update_expr):
            candidate_used: set[tuple[str, object]] = set()
            if not self._match_duplicate_or_base_8616(maybe_base, word_target, aliases, candidate_used):
                continue
            delta = self._resolve_copy_alias_expr_8616(maybe_delta, aliases, candidate_used)
            if self._contains_unresolved_virtual_expr_8616(delta):
                self._log_duplicate_shift_refuse_8616("delta-unresolved-virtual", rhs, word_target, aliases)
                continue
            if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                _log.warning(
                    "[word-or-update] duplicate-shift matched op=%s target=%r delta=%r used=%r",
                    update_expr.op,
                    word_target,
                    delta,
                    sorted(str(key) for key in candidate_used),
                )
            return update_expr.op, delta, candidate_used
        self._log_duplicate_shift_refuse_8616("base-not-duplicate-word", rhs, word_target, aliases)
        return None

    def _delete_tail_virtual_aliases_8616(self, statements: list[object], used_keys: set[tuple[str, object]]) -> None:
        if not used_keys:
            return
        kept: list[object] = []
        for statement in statements:
            keys = self._virtual_assignment_keys_8616(statement)
            if keys and any(key in used_keys for key in keys):
                continue
            kept.append(statement)
        statements[:] = kept

    def _visit_word_or_node_8616(self, node: object) -> None:
        if isinstance(node, list):
            replacement = self._rewrite_statement_list_8616(node)
            if replacement is not node:
                node[:] = replacement
            return
        if isinstance(node, CStatements):
            new_statements = self._rewrite_statement_list_8616(list(node.statements))
            if new_statements != node.statements:
                cast(Any, node).statements = new_statements
            return
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    self._visit_word_or_node_8616(body)
        for attr in ("body", "else_node", "condition", "init", "iteration"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                self._visit_word_or_node_8616(child)

    def _log_word_or_seq_8616(self, i: int, stmt: object, next_stmt: object) -> None:
        if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):  # noqa: SIM102
            if isinstance(stmt, CAssignment) or isinstance(next_stmt, CAssignment):
                same_lhs = (
                    isinstance(stmt, CAssignment)
                    and isinstance(next_stmt, CAssignment)
                    and _same_c_expression_8616(stmt.lhs, next_stmt.lhs)
                )
                _log.warning(
                    "[word-or-update] seq i=%d stmt=%s next=%s same_lhs=%s lhs=%s rhs=%s next_lhs=%s next_rhs=%s",
                    i,
                    type(stmt).__name__,
                    type(next_stmt).__name__ if next_stmt is not None else None,
                    same_lhs,
                    type(stmt.lhs).__name__ if isinstance(stmt, CAssignment) else None,
                    type(stmt.rhs).__name__ if isinstance(stmt, CAssignment) else None,
                    type(next_stmt.lhs).__name__ if isinstance(next_stmt, CAssignment) else None,
                    type(next_stmt.rhs).__name__ if isinstance(next_stmt, CAssignment) else None,
                )

    def _probe_word_or_pair_8616(
        self, stmt: object, next_stmt: object
    ) -> tuple[object | None, int | None, int | None]:
        """Classify an adjacent assignment pair for word-or joining."""
        replacement_lhs: object | None = None
        immediate: int | None = None
        shifted_immediate: int | None = None
        if isinstance(stmt, CAssignment) and isinstance(next_stmt, CAssignment):
            if (
                isinstance(stmt.lhs, CVariable)
                and isinstance(next_stmt.lhs, CVariable)
                and _same_c_expression_8616(stmt.lhs, next_stmt.lhs)
            ):
                replacement_lhs = stmt.lhs
                immediate = self._match_word_or_carrier_expr_8616(stmt.rhs, stmt.lhs)
                shifted_immediate = self._match_word_or_carrier_shift_8616(next_stmt.rhs, stmt.lhs)
            elif isinstance(stmt.lhs, CVariable) and isinstance(next_stmt.lhs, CVariable):
                joined_lhs = self._materialize_joined_word_expr_8616(stmt.lhs, next_stmt.lhs)
                if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                    _log.warning(
                        "[word-or-update] join lhs=%r next_lhs=%r joined=%s low_domain=%r high_domain=%r",
                        stmt.lhs,
                        next_stmt.lhs,
                        type(joined_lhs).__name__ if joined_lhs is not None else None,
                        _storage_domain_for_expr(stmt.lhs),
                        _storage_domain_for_expr(next_stmt.lhs),
                    )
                if isinstance(joined_lhs, CVariable) or self._stack_word_contains_high_byte_8616(
                    stmt.lhs, next_stmt.lhs
                ):
                    replacement_lhs = joined_lhs if isinstance(joined_lhs, CVariable) else stmt.lhs
                    immediate = self._match_word_or_carrier_expr_pair_8616(stmt.rhs, stmt.lhs, next_stmt.lhs)
                    shifted_immediate = self._match_word_or_carrier_pair_shift_8616(
                        next_stmt.rhs, stmt.lhs, next_stmt.lhs
                    )
                with contextlib.suppress(Exception):
                    self._bump_stat_8616("_inertia_word_or_update_candidates")
        return replacement_lhs, immediate, shifted_immediate

    def _try_duplicate_shift_8616(
        self,
        stmt: object,
        copy_aliases: dict[tuple[str, object], object],
        new_statements: list[object],
    ) -> int | None:
        """Fold ``x = (x|x<<8) op delta >> 8`` into a single arithmetic update."""
        if not (isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable)):
            return None
        with contextlib.suppress(Exception):
            self._bump_stat_8616("_inertia_word_arithmetic_shift_candidates")
        duplicate_shift = self._match_duplicate_word_arithmetic_shift_8616(stmt.rhs, stmt.lhs, copy_aliases)
        if duplicate_shift is None:
            return None
        op, delta, used_keys = duplicate_shift
        self._delete_tail_virtual_aliases_8616(new_statements, used_keys)
        replacement_rhs = CBinaryOp(op, stmt.lhs, delta, codegen=self.codegen)
        new_statements.append(CAssignment(stmt.lhs, replacement_rhs, codegen=self.codegen))
        with contextlib.suppress(Exception):
            self._bump_stat_8616("_inertia_word_arithmetic_shift_materialized_count")
        return 1

    def _try_arithmetic_pair_update_8616(
        self,
        stmt: object,
        next_stmt: object,
        replacement_lhs: object | None,
        copy_aliases: dict[tuple[str, object], object],
        new_statements: list[object],
    ) -> int | None:
        """Fold a low/high arithmetic update pair into one word-width update."""
        if not (
            replacement_lhs is not None
            and isinstance(stmt, CAssignment)
            and isinstance(next_stmt, CAssignment)
            and isinstance(next_stmt.lhs, CVariable)
            and self._stack_word_contains_high_byte_8616(replacement_lhs, next_stmt.lhs)
        ):
            return None
        with contextlib.suppress(Exception):
            self._bump_stat_8616("_inertia_word_arithmetic_update_candidates")
        arithmetic_update = self._match_stack_word_arithmetic_update_8616(
            stmt.rhs,
            next_stmt.rhs,
            replacement_lhs,
            next_stmt.lhs,
            copy_aliases,
        )
        if arithmetic_update is None:
            return None
        op, delta, used_keys = arithmetic_update
        self._delete_tail_virtual_aliases_8616(new_statements, used_keys)
        replacement_rhs = CBinaryOp(op, replacement_lhs, delta, codegen=self.codegen)
        new_statements.append(CAssignment(replacement_lhs, replacement_rhs, codegen=self.codegen))
        with contextlib.suppress(Exception):
            self._bump_stat_8616("_inertia_word_arithmetic_update_materialized_count")
        return 2

    def _try_word_or_update_8616(
        self,
        stmt: object,
        replacement_lhs: object | None,
        immediate: int | None,
        shifted_immediate: int | None,
        new_statements: list[object],
    ) -> int | None:
        """Fold ``low = v; high = v>>8`` or-style carriers into ``word |= imm``."""
        if not (
            replacement_lhs is not None
            and isinstance(stmt, CAssignment)
            and immediate is not None
            and shifted_immediate == immediate
        ):
            return None
        replacement_rhs = CBinaryOp(
            "Or",
            replacement_lhs,
            CConstant(immediate, cast(Any, stmt.rhs.type), codegen=self.codegen),
            codegen=self.codegen,
        )
        new_statements.append(CAssignment(replacement_lhs, replacement_rhs, codegen=self.codegen))
        with contextlib.suppress(Exception):
            self._bump_stat_8616("_inertia_word_or_update_materialized_count")
        return 2

    def _log_word_or_refused_8616(
        self, stmt: CAssignment, next_stmt: CAssignment, immediate: int | None, shifted_immediate: int | None
    ) -> None:
        if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
            term_debug = []
            for term in self._or_terms_8616(stmt.rhs):
                term_debug.append(
                    (
                        type(term).__name__,
                        self._c_constant_int_value_8616(term),
                        _same_c_expression_8616(term, stmt.lhs),
                        _same_c_expression_8616(term, next_stmt.lhs),
                        type(self._shifted_high_byte_source_8616(term)).__name__
                        if self._shifted_high_byte_source_8616(term) is not None
                        else None,
                    )
                )
            _log.warning(
                "[word-or-update] refused lhs=%r rhs=%r next_lhs=%r next_rhs=%r immediate=%r shifted=%r terms=%r",
                stmt.lhs,
                stmt.rhs,
                next_stmt.lhs,
                next_stmt.rhs,
                immediate,
                shifted_immediate,
                term_debug,
            )
        with contextlib.suppress(Exception):
            self._bump_stat_8616("_inertia_word_or_update_refused")

    def _rewrite_statement_list_8616(self, statements: list[object]) -> list[object]:
        new_statements: list[object] = []
        i = 0
        while i < len(statements):
            stmt = statements[i]
            next_stmt = statements[i + 1] if i + 1 < len(statements) else None
            copy_aliases = self._copy_alias_map_8616(new_statements)
            self._log_word_or_seq_8616(i, stmt, next_stmt)
            replacement_lhs, immediate, shifted_immediate = self._probe_word_or_pair_8616(stmt, next_stmt)
            consumed = self._try_duplicate_shift_8616(stmt, copy_aliases, new_statements)
            if consumed is None:
                consumed = self._try_arithmetic_pair_update_8616(
                    stmt, next_stmt, replacement_lhs, copy_aliases, new_statements
                )
            if consumed is None:
                consumed = self._try_word_or_update_8616(
                    stmt, replacement_lhs, immediate, shifted_immediate, new_statements
                )
            if consumed is not None:
                self.changed_local = True
                i += consumed
                continue
            if replacement_lhs is not None and isinstance(stmt, CAssignment) and isinstance(next_stmt, CAssignment):
                self._log_word_or_refused_8616(stmt, next_stmt, immediate, shifted_immediate)
            self._visit_word_or_node_8616(stmt)
            new_statements.append(stmt)
            i += 1
        return new_statements

def _simplify_structured_expressions_8616(codegen: object) -> bool:
    return _SimplifyExpressionRun8616(codegen=codegen).run()
def _is_virtual_register_temporary_8616(lhs: object) -> bool:
    """Accept only register-backed carriers, never stack or memory storage."""
    return isinstance(lhs, CVariable) and isinstance(lhs.variable, SimRegisterVariable)


def _crosses_nested_execution_scope_8616(stmt: object) -> bool:
    """Refuse moving a definition into control flow with different frequency."""
    return isinstance(stmt, (CDoWhileLoop, CForLoop, CIfElse, CSwitchCase, CWhileLoop))


def _safe_inline_expr_8616(expr: object) -> bool:
    """Return whether an expression is free of direct memory reads and calls."""
    if isinstance(expr, (CConstant, CVariable)):
        return True
    if isinstance(expr, CTypeCast):
        return _safe_inline_expr_8616(expr.expr)
    if isinstance(expr, CUnaryOp):
        if expr.op == "Dereference":
            return False
        return _safe_inline_expr_8616(expr.operand)
    if isinstance(expr, CBinaryOp):
        return _safe_inline_expr_8616(expr.lhs) and _safe_inline_expr_8616(expr.rhs)
    if isinstance(expr, CITE):
        return (
            _safe_inline_expr_8616(expr.cond)
            and _safe_inline_expr_8616(expr.iftrue)
            and _safe_inline_expr_8616(expr.iffalse)
        )
    return False


def _count_var_uses_seq_8616(seq: object, target: object) -> int:
    """Sum temporary uses inside one sequence attribute."""
    total = 0
    for item in seq:
        if _structured_codegen_node_8616(item):
            total += _count_var_uses_8616(item, target)
        elif isinstance(item, tuple):
            for subitem in item:
                if _structured_codegen_node_8616(subitem):
                    total += _count_var_uses_8616(subitem, target)
    return total


def _count_var_uses_pairs_8616(pairs: object, target: object) -> int:
    """Sum temporary uses inside condition/body pairs."""
    total = 0
    for cond, body in pairs:
        if _structured_codegen_node_8616(cond):
            total += _count_var_uses_8616(cond, target)
        if _structured_codegen_node_8616(body):
            total += _count_var_uses_8616(body, target)
    return total


def _count_var_uses_8616(node: object, target: object, *, assignment_lhs: bool = False) -> int:
    """Count structural uses of one temporary across the dynamic angr AST."""
    if node is None:
        return 0
    if isinstance(node, CVariable):
        return 0 if assignment_lhs else int(_same_c_expression_8616(node, target))

    total = 0
    for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
        child = getattr(node, attr, None)
        if _structured_codegen_node_8616(child):
            total += _count_var_uses_8616(
                child,
                target,
                assignment_lhs=assignment_lhs and attr == "lhs" and isinstance(node, CAssignment),
            )
    for attr in ("statements", "operands", "args"):
        seq = getattr(node, attr, None)
        if seq:
            total += _count_var_uses_seq_8616(seq, target)
    pairs = getattr(node, "condition_and_nodes", None)
    if pairs:
        total += _count_var_uses_pairs_8616(pairs, target)
    return total


def _replace_var_use_in_seq_8616(seq: object, target: object, replacement: object) -> tuple[list[object], bool]:
    """Rewrite uses inside one sequence attribute, returning the rebuilt list."""
    new_seq: list[object] = []
    seq_changed = False
    for item in seq:
        if _structured_codegen_node_8616(item):
            new_item, item_changed = _replace_var_use_8616(item, target, replacement)
            new_seq.append(new_item)
            seq_changed |= item_changed
        else:
            new_seq.append(item)
    return new_seq, seq_changed


def _replace_var_use_in_pairs_8616(
    pairs: object, target: object, replacement: object
) -> tuple[list[tuple[object, object]], bool]:
    """Rewrite uses inside condition/body pairs, returning the rebuilt pairs."""
    new_pairs: list[tuple[object, object]] = []
    pair_changed = False
    for cond, body in pairs:
        new_cond, cond_changed = (
            _replace_var_use_8616(cond, target, replacement)
            if _structured_codegen_node_8616(cond)
            else (cond, False)
        )
        new_body, body_changed = (
            _replace_var_use_8616(body, target, replacement)
            if _structured_codegen_node_8616(body)
            else (body, False)
        )
        new_pairs.append((new_cond, new_body))
        pair_changed |= cond_changed or body_changed
    return new_pairs, pair_changed


def _replace_var_use_in_attrs_8616(
    node: object, target: object, replacement: object, assignment_lhs: bool
) -> bool:
    """Rewrite uses in scalar child attributes, tracking the assignment-lhs guard."""
    changed = False
    for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
        child = getattr(node, attr, None)
        if not _structured_codegen_node_8616(child):
            continue
        new_child, child_changed = _replace_var_use_8616(
            child,
            target,
            replacement,
            assignment_lhs=assignment_lhs and attr == "lhs" and isinstance(node, CAssignment),
        )
        if child_changed:
            setattr(cast(Any, node), attr, new_child)
            changed = True
    return changed


def _replace_var_use_8616(
    node: object,
    target: object,
    replacement: object,
    *,
    assignment_lhs: bool = False,
) -> tuple[object, bool]:
    """Replace one temporary use across the dynamic angr AST."""
    if isinstance(node, CVariable):
        if not assignment_lhs and _same_c_expression_8616(node, target):
            return replacement, True
        return node, False

    changed_local = False
    changed_local = _replace_var_use_in_attrs_8616(node, target, replacement, assignment_lhs) or changed_local
    for attr in ("statements", "operands", "args"):
        seq = getattr(node, attr, None)
        if not seq:
            continue
        new_seq, seq_changed = _replace_var_use_in_seq_8616(seq, target, replacement)
        if seq_changed:
            setattr(cast(Any, node), attr, new_seq)
            changed_local = True
    pairs = getattr(node, "condition_and_nodes", None)
    if pairs:
        new_pairs, pair_changed = _replace_var_use_in_pairs_8616(pairs, target, replacement)
        if pair_changed:
            cast(Any, node).condition_and_nodes = new_pairs
            changed_local = True
    return node, changed_local


@dataclass(slots=True)
class _SingleUseTemporaryRun8616:
    """Mutable accumulator driving the single-use-temporary elimination pass."""

    codegen: object
    changed: bool = False
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def run(self) -> bool:
        """Visit the cfunc statement list and publish the closed-loop stats."""
        typed_codegen = cast(_SingleUseTemporaryCodegen8616, self.codegen)
        if getattr(self.codegen, "cfunc", None) is None:
            return False

        root = cast(Any, typed_codegen.cfunc).statements
        self._visit(root)
        typed_codegen._inertia_single_use_temporary_elimination_stats_8616 = (
            SingleUseTemporaryEliminationStats8616(
                raw_fact_count=self.raw_fact_count,
                normalized_fact_count=self.normalized_fact_count,
                classified_fact_count=self.classified_fact_count,
                materialized_count=self.materialized_count,
                failure_count=self.failure_count,
            )
        )
        return self.changed

    def _try_eliminate_carrier_8616(
        self, stmt: CAssignment, next_stmt: object, later_statements: list[object]
    ) -> bool:
        """Attempt to inline ``stmt.rhs`` into its single use in ``next_stmt``."""
        self.raw_fact_count += 1
        if not _is_virtual_register_temporary_8616(stmt.lhs):
            self.failure_count += 1
            return False
        self.normalized_fact_count += 1
        if _crosses_nested_execution_scope_8616(next_stmt):
            self.failure_count += 1
            return False
        immediate_uses = _count_var_uses_8616(next_stmt, stmt.lhs)
        later_uses = sum(_count_var_uses_8616(rest, stmt.lhs) for rest in later_statements)
        if not (immediate_uses == 1 and later_uses == 0):
            self.failure_count += 1
            return False
        self.classified_fact_count += 1
        _, replaced = _replace_var_use_8616(next_stmt, stmt.lhs, stmt.rhs)
        if not replaced:
            self.failure_count += 1
            return False
        self.changed = True
        self.materialized_count += 1
        return True

    def _visit(self, node: object) -> None:
        """Visit one statement block and eliminate locally proven carriers."""
        if not isinstance(node, CStatements):
            return

        new_statements = []
        statements = list(node.statements)
        idx = 0
        while idx < len(statements):
            stmt = statements[idx]
            next_stmt = statements[idx + 1] if idx + 1 < len(statements) else None
            removed = False

            if (
                isinstance(stmt, CAssignment)
                and isinstance(stmt.lhs, CVariable)
                and _safe_inline_expr_8616(stmt.rhs)
                and next_stmt is not None
            ):
                removed = self._try_eliminate_carrier_8616(stmt, next_stmt, statements[idx + 2 :])

            if not removed:
                new_statements.append(stmt)
                self._visit(stmt)
            idx += 1

        if len(new_statements) != len(node.statements):
            cast(Any, node).statements = new_statements


def _eliminate_single_use_temporaries_8616(codegen: object) -> bool:
    """Inline one-use register carriers without crossing storage or control scope."""
    return _SingleUseTemporaryRun8616(codegen=codegen).run()


def _maybe_eliminate_single_use_temporaries_8616(project: object, codegen: object) -> bool:
    if not getattr(project, "_inertia_postprocess_single_use_temporaries_enabled", False):
        return False
    return _eliminate_single_use_temporaries_8616(codegen)

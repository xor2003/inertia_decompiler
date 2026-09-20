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
import os
from collections.abc import Iterator
from dataclasses import dataclass
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


def _virtual_expr_keys_8616(node: object) -> tuple[tuple[str, object], ...]:
    def _dirty_attr_8616(obj: object, attr: str) -> object | None:
        try:
            return getattr(obj, attr, None)
        except (AttributeError, TypeError, ValueError):
            return None

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
            keys.append(("dirty-reg", (reg_offset, bits if isinstance(bits, int) else None)))
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
    for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
        child = getattr(node, attr, None)
        if _structured_codegen_node_8616(child) and _expr_contains_virtual_key_8616(child, target_key):
            return True
    for attr in ("statements", "operands", "args"):
        seq = getattr(node, attr, None)
        if not seq:
            continue
        for item in seq:
            if _structured_codegen_node_8616(item) and _expr_contains_virtual_key_8616(item, target_key):
                return True
            if isinstance(item, tuple):
                for subitem in item:
                    if _structured_codegen_node_8616(subitem) and _expr_contains_virtual_key_8616(subitem, target_key):
                        return True
    pairs = getattr(node, "condition_and_nodes", None)
    if pairs:
        for cond, body in pairs:
            if _structured_codegen_node_8616(cond) and _expr_contains_virtual_key_8616(cond, target_key):
                return True
            if _structured_codegen_node_8616(body) and _expr_contains_virtual_key_8616(body, target_key):
                return True
    return False


def _inline_single_assignment_virtual_expressions_8616(codegen: object) -> bool:
    """Inline pure SSA-like virtual definitions by structural AST evidence.

    This consumes CDirtyExpression/CVariable virtual definitions that are unique
    in the function. It does not inspect rendered C text and refuses any RHS
    with memory/call/address side effects.
    """
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    if root is None:
        return False

    def _walk(node: object) -> Iterator[object]:
        if node is None:
            return
        yield node
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                yield from _walk(child)
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    yield from _walk(item)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            yield from _walk(subitem)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    yield from _walk(cond)
                if _structured_codegen_node_8616(body):
                    yield from _walk(body)

    definitions: dict[tuple[str, object], object | None] = {}
    candidate_count = 0
    refused_count = 0
    for node in _walk(root):
        if not isinstance(node, CAssignment):
            continue
        raw_keys = _virtual_expr_keys_8616(node.lhs)
        keys = _virtual_inline_identity_keys_8616(raw_keys)
        if not keys:
            continue
        candidate_count += 1
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
                definitions[key] = None
            refused_count += 1
            continue
        if any(key in definitions for key in keys):
            for key in keys:
                definitions[key] = None
            refused_count += 1
            continue
        for key in keys:
            definitions[key] = rhs

    replacements = {key: rhs for key, rhs in definitions.items() if rhs is not None}
    if not replacements:
        if candidate_count:
            cast(Any, codegen)._inertia_virtual_inline_candidates = (
                int(getattr(codegen, "_inertia_virtual_inline_candidates", 0) or 0) + candidate_count
            )
            cast(Any, codegen)._inertia_virtual_inline_refused = (
                int(getattr(codegen, "_inertia_virtual_inline_refused", 0) or 0) + refused_count
            )
        return False

    changed = False

    protected_refused_count = 0

    def _transform(
        node: object,
        *,
        assignment_lhs: bool = False,
        protected_address_context: bool = False,
        resolving_keys: set[tuple[str, object]] | None = None,
    ) -> object:
        nonlocal changed, protected_refused_count
        if node is None:
            return node
        if resolving_keys is None:
            resolving_keys = set()
        if not assignment_lhs:
            raw_keys = _virtual_expr_keys_8616(node)
            keys = _virtual_inline_identity_keys_8616(raw_keys)
            key = next((candidate_key for candidate_key in keys if candidate_key in replacements), None)
            replacement = replacements.get(key) if key is not None else None
            if replacement is not None:
                if key is None:
                    return node
                if key in resolving_keys:
                    if os.environ.get("INERTIA_DEBUG_VIRTUAL_INLINE"):
                        _log.warning("[virtual-inline] cycle-refuse key=%r expr=%s", key, _debug_c_repr_8616(node))
                    return node
                if protected_address_context:
                    protected_refused_count += 1
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
                changed = True
                resolving_keys.add(key)
                try:
                    return _transform(
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
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if not _structured_codegen_node_8616(child):
                continue
            child_protected_address_context = protected_address_context or (
                attr == "operand" and isinstance(node, CUnaryOp) and node.op in {"Dereference", "Reference"}
            )
            new_child = _transform(
                child,
                assignment_lhs=attr == "lhs" and isinstance(node, CAssignment),
                protected_address_context=child_protected_address_context,
            )
            if new_child is not child:
                setattr(cast(Any, node), attr, new_child)
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            new_seq = []
            seq_changed = False
            for item in seq:
                if _structured_codegen_node_8616(item):
                    new_item = _transform(item, protected_address_context=protected_address_context)
                    new_seq.append(new_item)
                    seq_changed |= new_item is not item
                else:
                    new_seq.append(item)
            if seq_changed:
                setattr(cast(Any, node), attr, new_seq)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            new_pairs = []
            pair_changed = False
            for cond, body in pairs:
                new_cond = (
                    _transform(cond, protected_address_context=protected_address_context)
                    if _structured_codegen_node_8616(cond)
                    else cond
                )
                new_body = (
                    _transform(body, protected_address_context=protected_address_context)
                    if _structured_codegen_node_8616(body)
                    else body
                )
                pair_changed |= new_cond is not cond or new_body is not body
                new_pairs.append((new_cond, new_body))
            if pair_changed:
                cast(Any, node).condition_and_nodes = new_pairs
        return node

    _transform(root)
    if protected_refused_count:
        cast(Any, codegen)._inertia_virtual_inline_protected_address_refused = (
            int(getattr(codegen, "_inertia_virtual_inline_protected_address_refused", 0) or 0) + protected_refused_count
        )

    def _collect_virtual_key_use_counts_8616(
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

        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if not _structured_codegen_node_8616(child):
                continue
            child_counts = _collect_virtual_key_use_counts_8616(
                child,
                tracked_keys,
                assignment_lhs=attr == "lhs" and isinstance(node, CAssignment),
                seen=seen,
            )
            for key, count in child_counts.items():
                counts[key] = counts.get(key, 0) + count

        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                nested_items = item if isinstance(item, tuple) else (item,)
                for subitem in nested_items:
                    if not _structured_codegen_node_8616(subitem):
                        continue
                    child_counts = _collect_virtual_key_use_counts_8616(
                        subitem,
                        tracked_keys,
                        seen=seen,
                    )
                    for key, count in child_counts.items():
                        counts[key] = counts.get(key, 0) + count

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                for subitem in (cond, body):
                    if not _structured_codegen_node_8616(subitem):
                        continue
                    child_counts = _collect_virtual_key_use_counts_8616(subitem, tracked_keys, seen=seen)
                    for key, count in child_counts.items():
                        counts[key] = counts.get(key, 0) + count

        return counts

    def _prune_consumed_virtual_definitions_8616(node: object) -> int:
        pruned = 0
        replacement_keys = set(replacements)
        use_counts = _collect_virtual_key_use_counts_8616(root, replacement_keys)
        visited: set[int] = set()

        def _visit(container: object) -> None:
            nonlocal pruned
            if not _structured_codegen_node_8616(container):
                return
            container_id = id(container)
            if container_id in visited:
                return
            visited.add(container_id)
            statements = getattr(container, "statements", None)
            if isinstance(statements, list):
                kept = []
                for statement in statements:
                    keys = (
                        _virtual_inline_identity_keys_8616(
                            _virtual_expr_keys_8616(statement.lhs)
                        )
                        if isinstance(statement, CAssignment)
                        else ()
                    )
                    if (
                        keys
                        and any(key in replacements for key in keys)
                        and _virtual_definition_has_disposable_storage_8616(
                            statement.lhs
                        )
                        and _pure_virtual_inline_rhs_8616(statement.rhs)
                        and all(use_counts.get(key, 0) == 0 for key in keys)
                    ):
                        pruned += 1
                        continue
                    kept.append(statement)
                if len(kept) != len(statements):
                    cast(Any, container).statements = kept
                for statement in kept:
                    _visit(statement)

            for attr in ("body", "else_node"):
                child = getattr(container, attr, None)
                if _structured_codegen_node_8616(child):
                    _visit(child)
            pairs = getattr(container, "condition_and_nodes", None)
            if pairs:
                for _cond, body in pairs:
                    if _structured_codegen_node_8616(body):
                        _visit(body)

        _visit(node)
        return pruned

    pruned_defs = _prune_consumed_virtual_definitions_8616(root)
    if pruned_defs:
        changed = True
        cast(Any, codegen)._inertia_virtual_inline_pruned_defs = (
            int(getattr(codegen, "_inertia_virtual_inline_pruned_defs", 0) or 0) + pruned_defs
        )
    if changed:
        cast(Any, codegen)._inertia_virtual_inline_candidates = (
            int(getattr(codegen, "_inertia_virtual_inline_candidates", 0) or 0) + candidate_count
        )
        cast(Any, codegen)._inertia_virtual_inline_materialized = int(
            getattr(codegen, "_inertia_virtual_inline_materialized", 0) or 0
        ) + len(replacements)
        cast(Any, codegen)._inertia_virtual_inline_refused = (
            int(getattr(codegen, "_inertia_virtual_inline_refused", 0) or 0) + refused_count
        )
    return changed


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


def _simplify_structured_expressions_8616(codegen: object) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def _invert_cmp_op_8616(op: str) -> str | None:
        return {
            "CmpGT": "CmpLE",
            "CmpGE": "CmpLT",
            "CmpLT": "CmpGE",
            "CmpLE": "CmpGT",
            "CmpEQ": "CmpNE",
            "CmpNE": "CmpEQ",
        }.get(op)

    def _is_c_constant_int_8616(expr: object, value: int) -> bool:
        return isinstance(expr, CConstant) and isinstance(expr.value, int) and expr.value == value

    def _c_constant_int_value_8616(expr: object) -> int | None:
        if isinstance(expr, CConstant) and isinstance(expr.value, int):
            return int(expr.value)
        return None

    def _unwrap_c_casts_8616(expr: object) -> object:
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        return expr

    def _constant_result_type_8616(node: CBinaryOp | CUnaryOp, value: int) -> object:
        if value < 0 or value > 0xFFFF:
            return SimTypeLong(value < 0)
        return node.type or SimTypeShort(False)

    def _fold_pure_constant_binary_8616(op: str, lhs: int, rhs: int) -> int | None:
        if op == "Add":
            return lhs + rhs
        if op == "Sub":
            return lhs - rhs
        if op == "Mul":
            return lhs * rhs
        if op == "Div":
            return None if rhs == 0 else lhs // rhs
        if op == "Mod":
            return None if rhs == 0 else lhs % rhs
        if op == "And":
            return lhs & rhs
        if op == "Or":
            return lhs | rhs
        if op == "Xor":
            return lhs ^ rhs
        if op == "Shl":
            return None if rhs < 0 or rhs > 63 else lhs << rhs
        if op in {"Shr", "Sar"}:
            return None if rhs < 0 or rhs > 63 else lhs >> rhs
        return None

    def _pure_constant_expr_value_8616(expr: object) -> int | None:
        expr = _unwrap_c_casts_8616(expr)
        if isinstance(expr, CConstant) and isinstance(expr.value, int):
            return int(expr.value)
        if isinstance(expr, CUnaryOp):
            operand = _pure_constant_expr_value_8616(expr.operand)
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
            lhs = _pure_constant_expr_value_8616(expr.lhs)
            rhs = _pure_constant_expr_value_8616(expr.rhs)
            if lhs is None or rhs is None:
                return None
            return _fold_pure_constant_binary_8616(str(expr.op), lhs, rhs)
        return None

    def _flatten_offset_terms_8616(expr: object, sign: int = 1) -> tuple[int, tuple[tuple[int, object], ...]]:
        expr = _unwrap_c_casts_8616(expr)
        const_value = _pure_constant_expr_value_8616(expr)
        if const_value is not None:
            return sign * const_value, ()
        if isinstance(expr, CBinaryOp) and expr.op == "Add":
            lhs_const, lhs_terms = _flatten_offset_terms_8616(expr.lhs, sign)
            rhs_const, rhs_terms = _flatten_offset_terms_8616(expr.rhs, sign)
            return lhs_const + rhs_const, lhs_terms + rhs_terms
        if isinstance(expr, CBinaryOp) and expr.op == "Sub":
            lhs_const, lhs_terms = _flatten_offset_terms_8616(expr.lhs, sign)
            rhs_const, rhs_terms = _flatten_offset_terms_8616(expr.rhs, -sign)
            return lhs_const + rhs_const, lhs_terms + rhs_terms
        return 0, ((sign, expr),)

    def _same_signed_term_multiset_8616(
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

    def _global_byte_reference_addr_8616(expr: object) -> int | None:
        expr = _unwrap_c_casts_8616(expr)
        if not isinstance(expr, CUnaryOp) or expr.op != "Reference":
            return None
        target = _unwrap_c_casts_8616(expr.operand)
        if not isinstance(target, CVariable):
            return None
        variable = target.variable
        if not isinstance(variable, SimMemoryVariable):
            return None
        if variable.size != 1:
            return None
        addr = variable.addr
        return addr if isinstance(addr, int) else None

    def _global_byte_address_terms_8616(expr: object) -> tuple[int, tuple[tuple[int, object], ...], bool]:
        const_value, terms = _flatten_offset_terms_8616(expr)
        normalized_terms: list[tuple[int, object]] = []
        saw_global_byte_ref = False
        for sign, term in terms:
            ref_addr = _global_byte_reference_addr_8616(term)
            if ref_addr is not None:
                const_value += sign * ref_addr
                saw_global_byte_ref = True
                continue
            normalized_terms.append((sign, term))
        return const_value, tuple(normalized_terms), saw_global_byte_ref

    def _byte_deref_address_info_8616(expr: object) -> tuple[object, int, tuple[tuple[int, object], ...]] | None:
        expr = _unwrap_c_casts_8616(expr)
        if not isinstance(expr, CUnaryOp) or expr.op != "Dereference":
            return None
        addr_expr = expr.operand
        const_value, terms, saw_global_byte_ref = _global_byte_address_terms_8616(addr_expr)
        if not saw_global_byte_ref:
            return None
        return addr_expr, const_value, terms

    def _shifted_byte_deref_high_info_8616(
        expr: object,
    ) -> tuple[object, int, tuple[tuple[int, object], ...]] | None:
        expr = _unwrap_c_casts_8616(expr)
        if not isinstance(expr, CBinaryOp):
            return None
        if expr.op == "Shl":
            for maybe_deref, maybe_shift in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                if _pure_constant_expr_value_8616(maybe_shift) == 8:
                    return _byte_deref_address_info_8616(maybe_deref)
        if expr.op == "Mul":
            for maybe_deref, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                if _pure_constant_expr_value_8616(maybe_scale) == 0x100:
                    return _byte_deref_address_info_8616(maybe_deref)
        return None

    def _make_word_deref_from_addr_expr_8616(addr_expr: object) -> CFunctionCall:
        return CFunctionCall(
            "MEM_U16",
            None,
            [addr_expr],
            codegen=codegen,
            tags={"inertia_x86_16_runtime_pointer_helper": "MEM_U16"},
        )

    def _fold_global_byte_deref_pair_8616(expr: object) -> object | None:
        if not isinstance(expr, CBinaryOp) or expr.op not in {"Or", "Add"}:
            return None
        for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            low_info = _byte_deref_address_info_8616(maybe_low)
            high_info = _shifted_byte_deref_high_info_8616(maybe_high)
            if low_info is None or high_info is None:
                continue
            low_addr_expr, low_const, low_terms = low_info
            _high_addr_expr, high_const, high_terms = high_info
            if high_const != low_const + 1:
                continue
            if not _same_signed_term_multiset_8616(low_terms, high_terms):
                continue
            return cast(object | None, _make_word_deref_from_addr_expr_8616(low_addr_expr))
        return None

    def _is_power_of_two_minus_one_8616(value: int) -> bool:
        """Check if value is of form 2^n - 1 (all bits set up to position n-1)."""
        if value <= 0:
            return False
        return (value & (value + 1)) == 0

    def _bit_position_of_power_of_two_8616(value: int) -> int | None:
        """Return n if value == 2^n, else None."""
        if value <= 0 or (value & (value - 1)) != 0:
            return None
        return (value - 1).bit_length()

    def _leading_set_bits_8616(value: int) -> int:
        """Return position of highest set bit (1-indexed, so 0xFF -> 8)."""
        if value == 0:
            return 0
        return value.bit_length()

    def _extract_same_zero_compare_expr_8616(expr: object) -> object | None:
        if not isinstance(expr, CBinaryOp) or expr.op != "CmpEQ":
            return None
        if _is_c_constant_int_8616(expr.rhs, 0):
            return cast(object | None, expr.lhs)
        if _is_c_constant_int_8616(expr.lhs, 0):
            return cast(object | None, expr.rhs)
        return None

    def _extract_zero_flag_source_expr_8616(expr: object) -> object | None:
        if isinstance(expr, CBinaryOp):
            if expr.op == "Mul":
                for maybe_logic, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                    if not _is_c_constant_int_8616(maybe_scale, 64):
                        continue
                    source_expr = _extract_same_zero_compare_expr_8616(maybe_logic)
                    if source_expr is not None:
                        return source_expr
                    if not isinstance(maybe_logic, CBinaryOp) or maybe_logic.op != "LogicalAnd":
                        continue
                    lhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.lhs)
                    rhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.rhs)
                    if lhs_expr is not None and rhs_expr is not None and _same_c_expression_8616(lhs_expr, rhs_expr):
                        return lhs_expr

            for child in (expr.lhs, expr.rhs):
                if _structured_codegen_node_8616(child):
                    extracted = _extract_zero_flag_source_expr_8616(child)
                    if extracted is not None:
                        return extracted

        elif isinstance(expr, CUnaryOp):
            child = expr.operand
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        elif isinstance(expr, CTypeCast):
            child = expr.expr
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        return None

    def _expr_contains_stack_or_flags_register_8616(expr: object) -> bool:
        stack_or_flags_offsets: set[int] = set()
        arch = getattr(getattr(codegen, "project", None), "arch", None)
        registers = getattr(arch, "registers", {}) if arch is not None else {}
        for register_name in ("sp", "bp", "esp", "ebp", "eflags", "flags"):
            register_info = registers.get(register_name)
            if isinstance(register_info, tuple) and register_info and isinstance(register_info[0], int):
                stack_or_flags_offsets.add(register_info[0])

        def _contains(node: object) -> bool:
            node = _unwrap_c_casts_8616(node)
            if isinstance(node, CVariable):
                variable = node.variable
                if not isinstance(variable, SimRegisterVariable):
                    return False
                name = variable.name
                if isinstance(name, str) and name.lower() in {"sp", "bp", "esp", "ebp", "eflags", "flags"}:
                    return True
                for attr in ("reg", "reg_offset", "offset"):
                    offset = getattr(variable, attr, None)
                    if isinstance(offset, int) and offset in stack_or_flags_offsets:
                        return True
                return False
            if isinstance(node, CDirtyExpression):
                return False
            for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval"):
                child = getattr(node, attr, None)
                if _structured_codegen_node_8616(child) and _contains(child):
                    return True
            for attr in ("operands", "args"):
                seq = getattr(node, attr, None)
                if not seq:
                    continue
                for item in seq:
                    if _structured_codegen_node_8616(item) and _contains(item):
                        return True
                    if isinstance(item, tuple):
                        for subitem in item:
                            if _structured_codegen_node_8616(subitem) and _contains(subitem):
                                return True
            return False

        return _contains(expr)

    def _shifted_high_byte_source_8616(expr: object) -> object | None:
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        if not isinstance(expr, CBinaryOp):
            return None
        if expr.op == "Shl" and _is_c_constant_int_8616(expr.rhs, 8):
            return cast(object | None, expr.lhs)
        if expr.op == "Mul" and _is_c_constant_int_8616(expr.rhs, 0x100):
            return cast(object | None, expr.lhs)
        if expr.op == "Mul" and _is_c_constant_int_8616(expr.lhs, 0x100):
            return cast(object | None, expr.rhs)
        return None

    def _or_terms_8616(expr: object) -> list[object]:
        if isinstance(expr, CBinaryOp) and expr.op == "Or":
            return [*_or_terms_8616(expr.lhs), *_or_terms_8616(expr.rhs)]
        return [expr]

    def _match_word_or_carrier_expr_8616(expr: object, target: object) -> int | None:
        terms = _or_terms_8616(expr)
        constant_terms: list[int] = []
        saw_target = False
        saw_shifted_target = False
        for term in terms:
            const_value = _c_constant_int_value_8616(term)
            if const_value is not None:
                constant_terms.append(const_value)
                continue
            if _same_c_expression_8616(term, target):
                saw_target = True
                continue
            shifted = _shifted_high_byte_source_8616(term)
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

    def _match_word_or_carrier_expr_pair_8616(expr: object, low_target: object, high_target: object) -> int | None:
        terms = _or_terms_8616(expr)
        constant_terms: list[int] = []
        saw_low = False
        saw_shifted_high = False
        for term in terms:
            const_value = _c_constant_int_value_8616(term)
            if const_value is not None:
                constant_terms.append(const_value)
                continue
            if _same_c_expression_8616(term, low_target):
                saw_low = True
                continue
            shifted = _shifted_high_byte_source_8616(term)
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

    def _match_word_or_carrier_shift_8616(expr: object, target: object) -> int | None:
        if not isinstance(expr, CBinaryOp) or expr.op != "Shr":
            return None
        if not _is_c_constant_int_8616(expr.rhs, 8):
            return None
        return _match_word_or_carrier_expr_8616(expr.lhs, target)

    def _match_word_or_carrier_pair_shift_8616(expr: object, low_target: object, high_target: object) -> int | None:
        if not isinstance(expr, CBinaryOp) or expr.op != "Shr":
            return None
        if not _is_c_constant_int_8616(expr.rhs, 8):
            return None
        return _match_word_or_carrier_expr_pair_8616(expr.lhs, low_target, high_target)

    def _stack_word_contains_high_byte_8616(word_expr: object, high_expr: object) -> bool:
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

    def _materialize_joined_word_expr_8616(low_expr: object, high_expr: object) -> object | None:
        """Consume register-view joins; never invent stack or memory C objects."""
        if not (
            isinstance(low_expr, CVariable) and isinstance(high_expr, CVariable)
            and isinstance(low_expr.variable, SimRegisterVariable)
            and isinstance(high_expr.variable, SimRegisterVariable)
        ):
            return None
        alias_state = getattr(codegen, "_inertia_alias_state", None)
        if alias_state is None:
            alias_state = getattr(getattr(codegen, "cfunc", None), "_inertia_alias_state", None)
        proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
        return cast(object | None, join_adjacent_register_slices(
            low_expr, high_expr, codegen, alias_state=alias_state, proof=proof,
        ))

    def _simplify_zero_flag_comparison_8616(expr: object) -> object:
        if not isinstance(expr, CBinaryOp) or expr.op not in {"CmpEQ", "CmpNE"}:
            return expr

        if _is_c_constant_int_8616(expr.rhs, 0):
            source = expr.lhs
        elif _is_c_constant_int_8616(expr.lhs, 0):
            source = expr.rhs
        else:
            return expr

        source_expr = _extract_zero_flag_source_expr_8616(source)
        if source_expr is None:
            return expr
        source_expr = _restore_not_shift_zero_flag_source_8616(source_expr)
        if _expr_contains_stack_or_flags_register_8616(source_expr):
            return expr
        if expr.op == "CmpEQ":
            return source_expr
        return CUnaryOp("Not", cast(Any, source_expr), codegen=codegen)

    def _restore_not_shift_zero_flag_source_8616(source_expr: object) -> object | None:
        source_expr = _unwrap_c_casts_8616(source_expr)
        if not isinstance(source_expr, CBinaryOp) or source_expr.op not in {"Shr", "Sar"}:
            return source_expr
        lhs = _unwrap_c_casts_8616(source_expr.lhs)
        if not isinstance(lhs, CUnaryOp) or lhs.op != "Not":
            return cast(object | None, source_expr)
        shift = source_expr.rhs
        restored_shift = CBinaryOp(
            source_expr.op,
            cast(Any, lhs.operand),
            shift,
            codegen=codegen,
            tags=source_expr.tags,
        )
        return cast(object | None, CBinaryOp(
            "CmpEQ",
            restored_shift,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags=lhs.tags or source_expr.tags,
        ))

    def _restore_not_shift_condition_expr_8616(expr: object) -> tuple[object, bool]:
        expr = _unwrap_c_casts_8616(expr)
        if isinstance(expr, CBinaryOp):
            lhs, lhs_changed = _restore_not_shift_condition_expr_8616(expr.lhs)
            rhs, rhs_changed = _restore_not_shift_condition_expr_8616(expr.rhs)
            if lhs_changed:
                expr.lhs = lhs
            if rhs_changed:
                expr.rhs = rhs
            if expr.op in {"Shr", "Sar"}:
                lhs_node = _unwrap_c_casts_8616(expr.lhs)
                shift = _c_constant_int_value_8616(_unwrap_c_casts_8616(expr.rhs))
                if isinstance(lhs_node, CUnaryOp) and lhs_node.op == "Not" and isinstance(shift, int) and shift > 0:
                    restored = _restore_not_shift_zero_flag_source_8616(expr)
                    if restored is not expr:
                        return restored, True
            return expr, lhs_changed or rhs_changed
        if isinstance(expr, CUnaryOp):
            operand, operand_changed = _restore_not_shift_condition_expr_8616(expr.operand)
            if operand_changed:
                cast(Any, expr).operand = operand
            return expr, operand_changed
        if isinstance(expr, CTypeCast):
            inner, inner_changed = _restore_not_shift_condition_expr_8616(expr.expr)
            if inner_changed:
                cast(Any, expr).expr = inner
            return expr, inner_changed
        return expr, False

    def _restore_not_shift_conditions_in_node_8616(node: object) -> bool:
        if not _structured_codegen_node_8616(node):
            return False
        changed_local = False
        for attr in ("condition", "cond"):
            condition = getattr(node, attr, None)
            if not _structured_codegen_node_8616(condition):
                continue
            new_condition, condition_changed = _restore_not_shift_condition_expr_8616(condition)
            if condition_changed:
                setattr(cast(Any, node), attr, new_condition)
                changed_local = True
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            new_pairs = []
            pair_changed = False
            for condition, body in pairs:
                new_condition = condition
                if _structured_codegen_node_8616(condition):
                    new_condition, condition_changed = _restore_not_shift_condition_expr_8616(condition)
                    pair_changed = pair_changed or condition_changed
                if _structured_codegen_node_8616(body):
                    changed_local = _restore_not_shift_conditions_in_node_8616(body) or changed_local
                new_pairs.append((new_condition, body))
            if pair_changed:
                cast(Any, node).condition_and_nodes = new_pairs
                changed_local = True
        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                changed_local = _restore_not_shift_conditions_in_node_8616(child) or changed_local
        statements = getattr(node, "statements", None)
        if statements:
            for statement in tuple(statements):
                if _structured_codegen_node_8616(statement):
                    changed_local = _restore_not_shift_conditions_in_node_8616(statement) or changed_local
        return changed_local

    def transform(node: object) -> object:
        if isinstance(node, CBinaryOp) and node.op in {"Or", "Add"}:
            folded_global_word = _fold_global_byte_deref_pair_8616(node)
            if folded_global_word is not None:
                cast(Any, codegen)._inertia_global_byte_pair_folded_count_8616 = (
                    int(getattr(codegen, "_inertia_global_byte_pair_folded_count_8616", 0) or 0) + 1
                )
                return folded_global_word

        if isinstance(node, (CBinaryOp, CUnaryOp)):
            folded_constant = _pure_constant_expr_value_8616(node)
            if folded_constant is not None:
                cast(Any, codegen)._inertia_pure_constant_folded_count_8616 = (
                    int(getattr(codegen, "_inertia_pure_constant_folded_count_8616", 0) or 0) + 1
                )
                return CConstant(
                    folded_constant,
                    cast(Any, _constant_result_type_8616(node, folded_constant)),
                    codegen=codegen,
                    tags=node.tags,
                )

        if isinstance(node, CBinaryOp) and node.op == "Concat":
            lhs_val = _c_constant_value_8616(node.lhs)
            rhs_val = _c_constant_value_8616(node.rhs)
            rhs_bits = getattr(node.rhs.type, "size", None)
            lhs_bits = getattr(node.lhs.type, "size", None)
            if rhs_bits is None:
                rhs_bits = lhs_bits if lhs_bits is not None else 16

            if lhs_val is not None and rhs_val is not None:
                return CConstant((lhs_val << rhs_bits) | rhs_val, cast(Any, node.type), codegen=codegen)

            shift = CConstant(
                rhs_bits, cast(Any, node.rhs.type or node.lhs.type), codegen=codegen
            )
            return CBinaryOp(
                "Or",
                CBinaryOp("Shl", node.lhs, shift, codegen=codegen, tags=node.tags),
                node.rhs,
                codegen=codegen,
                tags=node.tags,
            )

        if (
            isinstance(node, CBinaryOp)
            and node.op in {"Shl", "Shr", "Sar"}
            and _is_c_constant_int_8616(node.rhs, 0)
        ):
            return node.lhs

        if isinstance(node, CBinaryOp) and node.op == "Mul":  # noqa: SIM102
            if _is_c_constant_int_8616(node.lhs, 0) or _is_c_constant_int_8616(node.rhs, 0):
                type_ = (
                    node.type or node.lhs.type or node.rhs.type
                )
                if type_ is not None:
                    return CConstant(0, type_, codegen=codegen)

        if isinstance(node, CBinaryOp) and node.op == "Or":
            folded = None
            shifted_rhs = _shifted_high_byte_source_8616(node.rhs)
            if shifted_rhs is not None:
                folded = _materialize_joined_word_expr_8616(node.lhs, shifted_rhs)
            if folded is None:
                shifted_lhs = _shifted_high_byte_source_8616(node.lhs)
                if shifted_lhs is not None:
                    folded = _materialize_joined_word_expr_8616(node.rhs, shifted_lhs)
            if folded is not None:
                return folded
            if _is_c_constant_int_8616(node.lhs, 0):
                return node.rhs
            if _is_c_constant_int_8616(node.rhs, 0):
                return node.lhs

        if isinstance(node, CBinaryOp) and node.op == "And":  # noqa: SIM102
            if _is_c_constant_int_8616(node.lhs, 0) or _is_c_constant_int_8616(node.rhs, 0):
                type_ = (
                    node.type or node.lhs.type or node.rhs.type
                )
                if type_ is not None:
                    return CConstant(0, type_, codegen=codegen)

        if isinstance(node, CUnaryOp) and node.op == "Not":
            operand = node.operand
            if isinstance(operand, CUnaryOp) and operand.op == "Not":
                return operand.operand
            if isinstance(operand, CBinaryOp):
                inverted = _invert_cmp_op_8616(operand.op)
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
                        codegen=codegen,
                        tags=node.tags or operand.tags,
                    )

        if isinstance(node, CITE) and _same_c_expression_8616(node.iftrue, node.iffalse):
            cast(Any, codegen)._inertia_same_arm_cite_simplified_count_8616 = (
                int(getattr(codegen, "_inertia_same_arm_cite_simplified_count_8616", 0) or 0) + 1
            )
            return node.iftrue

        simplified = _simplify_zero_flag_comparison_8616(node)
        if simplified is not node:
            return simplified

        if (
            isinstance(node, CBinaryOp)
            and node.op in {"LogicalAnd", "LogicalOr", "And", "Or"}
            and _same_c_expression_8616(node.lhs, node.rhs)
        ):
            return node.lhs
        if isinstance(node, CBinaryOp) and node.op in {"CmpEQ", "CmpNE"}:
            if isinstance(node.rhs, CConstant) and node.rhs.value == 0:  # noqa: SIM102
                if isinstance(node.lhs, CBinaryOp) and node.lhs.op == "Sub" and isinstance(node.lhs.rhs, CConstant):
                    return CBinaryOp(
                        node.op,
                        node.lhs.lhs,
                        node.lhs.rhs,
                        codegen=codegen,
                        tags=node.tags,
                    )
            if isinstance(node.lhs, CConstant) and node.lhs.value == 0:  # noqa: SIM102
                if isinstance(node.rhs, CBinaryOp) and node.rhs.op == "Sub" and isinstance(node.rhs.rhs, CConstant):
                    return CBinaryOp(
                        node.op,
                        node.rhs.lhs,
                        node.rhs.rhs,
                        codegen=codegen,
                        tags=node.tags,
                    )
        if (
            isinstance(node, CBinaryOp)
            and node.op in {"Sub", "Xor"}
            and _same_c_expression_8616(node.lhs, node.rhs)
        ):
            type_ = node.type or node.lhs.type
            if type_ is not None:
                return CConstant(0, type_, codegen=codegen)
        return node

    def _materialize_word_or_update_statements_8616(root_node: object) -> bool:
        changed_local = False

        def _unwrap_expr_8616(expr: object) -> object:
            while isinstance(expr, CTypeCast):
                expr = expr.expr
            return expr

        def _virtual_assignment_key_8616(stmt: object) -> tuple[str, object] | None:
            if not isinstance(stmt, CAssignment):
                return None
            return _virtual_expr_key_8616(stmt.lhs)

        def _virtual_assignment_keys_8616(stmt: object) -> tuple[tuple[str, object], ...]:
            if not isinstance(stmt, CAssignment):
                return ()
            return _virtual_expr_keys_8616(stmt.lhs)

        def _copy_alias_map_8616(statements: list[object]) -> dict[tuple[str, object], object]:
            aliases: dict[tuple[str, object], object] = {}
            for candidate in statements:
                if not isinstance(candidate, CAssignment):
                    continue
                keys = _virtual_assignment_keys_8616(candidate)
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

        def _debug_aliases_8616(aliases: dict[tuple[str, object], object]) -> list[str]:
            if not os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                return []
            return [f"{key}={_debug_c_repr_8616(value)}" for key, value in sorted(aliases.items(), key=str)]

        def _resolve_copy_alias_expr_8616(
            expr: object, aliases: dict[tuple[str, object], object], used: set[tuple[str, object]]
        ) -> object:
            expr = _unwrap_expr_8616(expr)
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
            return _resolve_copy_alias_expr_8616(replacement, aliases, used)

        def _match_joined_stack_word_base_8616(
            expr: object,
            word_target: object,
            high_target: object,
            aliases: dict[tuple[str, object], object],
            used: set[tuple[str, object]],
        ) -> object | None:
            expr = _unwrap_expr_8616(expr)
            if not isinstance(expr, CBinaryOp) or expr.op != "Or":
                return None
            for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                low_expr = _resolve_copy_alias_expr_8616(maybe_low, aliases, used)
                shifted = _shifted_high_byte_source_8616(maybe_high)
                if shifted is None:
                    continue
                high_expr = _resolve_copy_alias_expr_8616(shifted, aliases, used)
                if _same_c_expression_8616(low_expr, word_target) and _same_c_expression_8616(high_expr, high_target):
                    return word_target
            return None

        def _same_after_copy_alias_8616(
            left: object,
            right: object,
            aliases: dict[tuple[str, object], object],
            used: set[tuple[str, object]],
        ) -> bool:
            left_resolved = _resolve_copy_alias_expr_8616(left, aliases, used)
            right_resolved = _resolve_copy_alias_expr_8616(right, aliases, used)
            return bool(_same_c_expression_8616(left_resolved, right_resolved))

        def _contains_unresolved_virtual_expr_8616(expr: object) -> bool:
            if expr is None:
                return False
            if _virtual_expr_key_8616(expr) is not None:
                return True
            for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval"):
                child = getattr(expr, attr, None)
                if _structured_codegen_node_8616(child) and _contains_unresolved_virtual_expr_8616(child):
                    return True
            for attr in ("operands", "args"):
                seq = getattr(expr, attr, None)
                if not seq:
                    continue
                for item in seq:
                    if _structured_codegen_node_8616(item) and _contains_unresolved_virtual_expr_8616(item):
                        return True
                    if isinstance(item, tuple):
                        for subitem in item:
                            if _structured_codegen_node_8616(subitem) and _contains_unresolved_virtual_expr_8616(
                                subitem
                            ):
                                return True
            return False

        def _match_stack_word_arithmetic_update_8616(
            low_rhs: object,
            high_rhs: object,
            word_target: object,
            high_target: object,
            aliases: dict[tuple[str, object], object],
        ) -> tuple[str, object, set[tuple[str, object]]] | None:
            def _refuse(reason: str) -> None:
                if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                    _log.warning(
                        "[word-or-update] arithmetic-pair refused reason=%s low_op=%r high_op=%r high_lhs_op=%r word_domain=%r high_domain=%r aliases=%r",
                        reason,
                        getattr(low_rhs, "op", None),
                        getattr(high_rhs, "op", None),
                        getattr(getattr(high_rhs, "lhs", None), "op", None),
                        _storage_domain_for_expr(word_target),
                        _storage_domain_for_expr(high_target),
                        _debug_aliases_8616(aliases),
                    )

            used: set[tuple[str, object]] = set()
            low_rhs = _unwrap_expr_8616(low_rhs)
            high_rhs = _unwrap_expr_8616(high_rhs)
            if not isinstance(high_rhs, CBinaryOp) or high_rhs.op != "Shr":
                _refuse("high-not-shr")
                return None
            if not _is_c_constant_int_8616(_unwrap_expr_8616(high_rhs.rhs), 8):
                _refuse("shift-not-8")
                return None
            update_expr = low_rhs
            high_update_expr = _unwrap_expr_8616(high_rhs.lhs)
            if not isinstance(update_expr, CBinaryOp) or update_expr.op not in {"Add", "Sub"}:
                _refuse("update-not-add-sub")
                return None
            if (
                not isinstance(high_update_expr, CBinaryOp)
                or high_update_expr.op not in {"Add", "Sub"}
                or high_update_expr.op != update_expr.op
            ):
                _refuse("high-update-not-same-op")
                return None

            def _arithmetic_candidates_8616(expr: object) -> list[tuple[object, object]]:
                if not isinstance(expr, CBinaryOp):
                    return []
                if expr.op == "Add":
                    return [(expr.lhs, expr.rhs), (expr.rhs, expr.lhs)]
                if expr.op == "Sub":
                    return [(expr.lhs, expr.rhs)]
                return []

            for maybe_base, maybe_delta in _arithmetic_candidates_8616(update_expr):
                low_used = set(used)
                if (
                    _match_joined_stack_word_base_8616(
                        maybe_base,
                        word_target,
                        high_target,
                        aliases,
                        low_used,
                    )
                    is None
                ):
                    continue
                delta = _resolve_copy_alias_expr_8616(maybe_delta, aliases, low_used)
                matched_high = False
                matched_used: set[tuple[str, object]] = set(low_used)
                for high_base, high_delta in _arithmetic_candidates_8616(high_update_expr):
                    high_used = set(low_used)
                    if (
                        _match_joined_stack_word_base_8616(
                            high_base,
                            word_target,
                            high_target,
                            aliases,
                            high_used,
                        )
                        is None
                    ):
                        continue
                    resolved_high_delta = _resolve_copy_alias_expr_8616(high_delta, aliases, high_used)
                    if not _same_c_expression_8616(delta, resolved_high_delta):
                        continue
                    matched_high = True
                    matched_used = high_used
                    break
                if not matched_high:
                    continue
                if _expr_contains_virtual_key_8616(delta, _virtual_expr_key_8616(word_target) or ("", "")):
                    _refuse("delta-contains-target")
                    continue
                if _contains_unresolved_virtual_expr_8616(delta):
                    _refuse("delta-unresolved-virtual")
                    continue
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
            _refuse("base-not-joined-word")
            return None

        def _match_duplicate_word_arithmetic_shift_8616(
            rhs: object,
            word_target: object,
            aliases: dict[tuple[str, object], object],
        ) -> tuple[str, object, set[tuple[str, object]]] | None:
            def _refuse(reason: str) -> None:
                if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                    _log.warning(
                        "[word-or-update] duplicate-shift refused reason=%s target_domain=%r rhs_op=%r rhs_lhs_op=%r rhs=%r target=%r aliases=%r",
                        reason,
                        _storage_domain_for_expr(word_target),
                        getattr(rhs, "op", None),
                        getattr(getattr(rhs, "lhs", None), "op", None),
                        rhs,
                        word_target,
                        _debug_aliases_8616(aliases),
                    )

            target_domain = _storage_domain_for_expr(word_target)
            if target_domain.space != "stack" or target_domain.width != 2:
                _refuse("target-not-stack-word")
                return None
            used: set[tuple[str, object]] = set()
            rhs = _unwrap_expr_8616(rhs)
            if not isinstance(rhs, CBinaryOp) or rhs.op != "Shr":
                _refuse("rhs-not-shr")
                return None
            if not _is_c_constant_int_8616(_unwrap_expr_8616(rhs.rhs), 8):
                _refuse("shift-not-8")
                return None
            update_expr = _unwrap_expr_8616(rhs.lhs)
            if not isinstance(update_expr, CBinaryOp) or update_expr.op not in {"Add", "Sub"}:
                _refuse("update-not-add-sub")
                return None
            candidates: list[tuple[object, object]] = []
            if update_expr.op == "Add":
                candidates.extend(((update_expr.lhs, update_expr.rhs), (update_expr.rhs, update_expr.lhs)))
            else:
                candidates.append((update_expr.lhs, update_expr.rhs))
            for maybe_base, maybe_delta in candidates:
                candidate_used = set(used)
                base = _unwrap_expr_8616(maybe_base)
                if not isinstance(base, CBinaryOp) or base.op != "Or":
                    continue
                matched_base = False
                for maybe_low, maybe_high in ((base.lhs, base.rhs), (base.rhs, base.lhs)):
                    low_expr = _resolve_copy_alias_expr_8616(maybe_low, aliases, candidate_used)
                    shifted = _shifted_high_byte_source_8616(maybe_high)
                    if shifted is None:
                        continue
                    high_expr = _resolve_copy_alias_expr_8616(shifted, aliases, candidate_used)
                    if _same_c_expression_8616(low_expr, word_target) and _same_c_expression_8616(
                        high_expr, word_target
                    ):
                        matched_base = True
                        break
                if not matched_base:
                    continue
                delta = _resolve_copy_alias_expr_8616(maybe_delta, aliases, candidate_used)
                if _contains_unresolved_virtual_expr_8616(delta):
                    _refuse("delta-unresolved-virtual")
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
            _refuse("base-not-duplicate-word")
            return None

        def _delete_tail_virtual_aliases_8616(statements: list[object], used_keys: set[tuple[str, object]]) -> None:
            if not used_keys:
                return
            kept: list[object] = []
            for statement in statements:
                keys = _virtual_assignment_keys_8616(statement)
                if keys and any(key in used_keys for key in keys):
                    continue
                kept.append(statement)
            statements[:] = kept

        def visit(node: object) -> None:
            nonlocal changed_local
            if isinstance(node, list):
                replacement = _rewrite_statement_list_8616(node)
                if replacement is not node:
                    node[:] = replacement
                return
            if isinstance(node, CStatements):
                new_statements = _rewrite_statement_list_8616(list(node.statements))
                if new_statements != node.statements:
                    cast(Any, node).statements = new_statements
                return
            pairs = getattr(node, "condition_and_nodes", None)
            if pairs:
                for _cond, body in pairs:
                    if _structured_codegen_node_8616(body):
                        visit(body)
            for attr in ("body", "else_node", "condition", "init", "iteration"):
                child = getattr(node, attr, None)
                if _structured_codegen_node_8616(child):
                    visit(child)

        def _rewrite_statement_list_8616(statements: list[object]) -> list[object]:
            nonlocal changed_local
            new_statements: list[object] = []
            i = 0
            while i < len(statements):
                stmt = statements[i]
                next_stmt = statements[i + 1] if i + 1 < len(statements) else None
                copy_aliases = _copy_alias_map_8616(new_statements)
                immediate = None
                shifted_immediate = None
                replacement_lhs = None
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
                if isinstance(stmt, CAssignment) and isinstance(next_stmt, CAssignment):
                    if (
                        isinstance(stmt.lhs, CVariable)
                        and isinstance(next_stmt.lhs, CVariable)
                        and _same_c_expression_8616(stmt.lhs, next_stmt.lhs)
                    ):
                        replacement_lhs = stmt.lhs
                        immediate = _match_word_or_carrier_expr_8616(stmt.rhs, stmt.lhs)
                        shifted_immediate = _match_word_or_carrier_shift_8616(next_stmt.rhs, stmt.lhs)
                    elif isinstance(stmt.lhs, CVariable) and isinstance(next_stmt.lhs, CVariable):
                        joined_lhs = _materialize_joined_word_expr_8616(stmt.lhs, next_stmt.lhs)
                        if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                            _log.warning(
                                "[word-or-update] join lhs=%r next_lhs=%r joined=%s low_domain=%r high_domain=%r",
                                stmt.lhs,
                                next_stmt.lhs,
                                type(joined_lhs).__name__ if joined_lhs is not None else None,
                                _storage_domain_for_expr(stmt.lhs),
                                _storage_domain_for_expr(next_stmt.lhs),
                            )
                        if isinstance(joined_lhs, CVariable):
                            replacement_lhs = joined_lhs
                            immediate = _match_word_or_carrier_expr_pair_8616(stmt.rhs, stmt.lhs, next_stmt.lhs)
                            shifted_immediate = _match_word_or_carrier_pair_shift_8616(
                                next_stmt.rhs, stmt.lhs, next_stmt.lhs
                            )
                        elif _stack_word_contains_high_byte_8616(stmt.lhs, next_stmt.lhs):
                            replacement_lhs = stmt.lhs
                            immediate = _match_word_or_carrier_expr_pair_8616(stmt.rhs, stmt.lhs, next_stmt.lhs)
                            shifted_immediate = _match_word_or_carrier_pair_shift_8616(
                                next_stmt.rhs, stmt.lhs, next_stmt.lhs
                            )
                        with contextlib.suppress(Exception):
                            cast(Any, codegen)._inertia_word_or_update_candidates = (
                                int(getattr(codegen, "_inertia_word_or_update_candidates", 0) or 0) + 1
                            )
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    with contextlib.suppress(Exception):
                        cast(Any, codegen)._inertia_word_arithmetic_shift_candidates = (
                            int(getattr(codegen, "_inertia_word_arithmetic_shift_candidates", 0) or 0) + 1
                        )
                    duplicate_shift = _match_duplicate_word_arithmetic_shift_8616(
                        stmt.rhs,
                        stmt.lhs,
                        copy_aliases,
                    )
                    if duplicate_shift is not None:
                        op, delta, used_keys = duplicate_shift
                        _delete_tail_virtual_aliases_8616(new_statements, used_keys)
                        replacement_rhs = CBinaryOp(
                            op,
                            stmt.lhs,
                            delta,
                            codegen=codegen,
                        )
                        new_statements.append(CAssignment(stmt.lhs, replacement_rhs, codegen=codegen))
                        with contextlib.suppress(Exception):
                            cast(Any, codegen)._inertia_word_arithmetic_shift_materialized_count = (
                                int(getattr(codegen, "_inertia_word_arithmetic_shift_materialized_count", 0) or 0) + 1
                            )
                        changed_local = True
                        i += 1
                        continue
                if (
                    replacement_lhs is not None
                    and isinstance(stmt, CAssignment)
                    and isinstance(next_stmt, CAssignment)
                    and isinstance(next_stmt.lhs, CVariable)
                    and _stack_word_contains_high_byte_8616(replacement_lhs, next_stmt.lhs)
                ):
                    with contextlib.suppress(Exception):
                        cast(Any, codegen)._inertia_word_arithmetic_update_candidates = (
                            int(getattr(codegen, "_inertia_word_arithmetic_update_candidates", 0) or 0) + 1
                        )
                    current_assignment = cast(CAssignment, stmt)
                    next_assignment = cast(CAssignment, next_stmt)
                    arithmetic_update = _match_stack_word_arithmetic_update_8616(
                        current_assignment.rhs,
                        next_assignment.rhs,
                        replacement_lhs,
                        next_assignment.lhs,
                        copy_aliases,
                    )
                    if arithmetic_update is not None:
                        op, delta, used_keys = arithmetic_update
                        _delete_tail_virtual_aliases_8616(new_statements, used_keys)
                        replacement_rhs = CBinaryOp(
                            op,
                            replacement_lhs,
                            delta,
                            codegen=codegen,
                        )
                        new_statements.append(CAssignment(replacement_lhs, replacement_rhs, codegen=codegen))
                        with contextlib.suppress(Exception):
                            cast(Any, codegen)._inertia_word_arithmetic_update_materialized_count = (
                                int(getattr(codegen, "_inertia_word_arithmetic_update_materialized_count", 0) or 0) + 1
                            )
                        changed_local = True
                        i += 2
                        continue
                if (
                    replacement_lhs is not None
                    and isinstance(stmt, CAssignment)
                    and immediate is not None
                    and shifted_immediate == immediate
                ):
                    replacement_rhs = CBinaryOp(
                        "Or",
                        replacement_lhs,
                        CConstant(immediate, cast(Any, stmt.rhs.type), codegen=codegen),
                        codegen=codegen,
                    )
                    new_statements.append(CAssignment(replacement_lhs, replacement_rhs, codegen=codegen))
                    with contextlib.suppress(Exception):
                        cast(Any, codegen)._inertia_word_or_update_materialized_count = (
                            int(getattr(codegen, "_inertia_word_or_update_materialized_count", 0) or 0) + 1
                        )
                    changed_local = True
                    i += 2
                    continue
                if replacement_lhs is not None and isinstance(stmt, CAssignment) and isinstance(next_stmt, CAssignment):
                    if os.environ.get("INERTIA_DEBUG_WORD_OR_UPDATE"):
                        term_debug = []
                        for term in _or_terms_8616(stmt.rhs):
                            term_debug.append(
                                (
                                    type(term).__name__,
                                    _c_constant_int_value_8616(term),
                                    _same_c_expression_8616(term, stmt.lhs),
                                    _same_c_expression_8616(term, next_stmt.lhs),
                                    type(_shifted_high_byte_source_8616(term)).__name__
                                    if _shifted_high_byte_source_8616(term) is not None
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
                        cast(Any, codegen)._inertia_word_or_update_refused = (
                            int(getattr(codegen, "_inertia_word_or_update_refused", 0) or 0) + 1
                        )
                visit(stmt)
                new_statements.append(stmt)
                i += 1
            return new_statements

        visit(root_node)
        return changed_local

    roots: list[tuple[list[str], object]] = []
    seen_roots: dict[int, list[str]] = {}
    for attr in ("body", "statements", "stmt"):
        root = getattr(cast(Any, codegen).cfunc, attr, None)
        if root is None:
            continue
        root_id = id(root)
        if root_id in seen_roots:
            seen_roots[root_id].append(attr)
            continue
        attrs = [attr]
        seen_roots[root_id] = attrs
        roots.append((attrs, root))

    changed = False
    active_roots: list[object] = []
    for attrs, root in roots:
        new_root = transform(root)
        if new_root is not root:
            if isinstance(root, CStatements) and not isinstance(new_root, CStatements):
                new_root = CStatements(
                    statements=[new_root] if not isinstance(new_root, list) else new_root, codegen=codegen
                )
            for attr in attrs:
                setattr(cast(Any, codegen).cfunc, attr, new_root)
            root = new_root
            changed = True
        active_roots.append(root)

    for root in active_roots:
        for _ in range(3):
            if not _replace_c_children_8616(root, transform):
                break
            changed = True
        if _restore_not_shift_conditions_in_node_8616(root):
            cast(Any, codegen)._inertia_not_shift_condition_restored_count_8616 = (
                int(getattr(codegen, "_inertia_not_shift_condition_restored_count_8616", 0) or 0) + 1
            )
            changed = True
    for root in active_roots:
        if _materialize_word_or_update_statements_8616(root):
            changed = True
    for _ in range(4):
        if not _inline_single_assignment_virtual_expressions_8616(codegen):
            break
        changed = True
    for root in active_roots:
        if _materialize_word_or_update_statements_8616(root):
            changed = True
    return changed


def _eliminate_single_use_temporaries_8616(codegen: object) -> bool:
    """Inline one-use register carriers without crossing storage or control scope."""
    typed_codegen = cast(_SingleUseTemporaryCodegen8616, codegen)
    if getattr(codegen, "cfunc", None) is None:
        return False

    raw_fact_count = 0
    normalized_fact_count = 0
    classified_fact_count = 0
    materialized_count = 0
    failure_count = 0

    def _is_virtual_register_temporary(lhs: object) -> bool:
        """Accept only register-backed carriers, never stack or memory storage."""
        return isinstance(lhs, CVariable) and isinstance(lhs.variable, SimRegisterVariable)

    def _crosses_nested_execution_scope(stmt: object) -> bool:
        """Refuse moving a definition into control flow with different frequency."""
        return isinstance(stmt, (CDoWhileLoop, CForLoop, CIfElse, CSwitchCase, CWhileLoop))

    def _safe_inline_expr(expr: object) -> bool:
        """Return whether an expression is free of direct memory reads and calls."""
        if isinstance(expr, (CConstant, CVariable)):
            return True
        if isinstance(expr, CTypeCast):
            return _safe_inline_expr(expr.expr)
        if isinstance(expr, CUnaryOp):
            if expr.op == "Dereference":
                return False
            return _safe_inline_expr(expr.operand)
        if isinstance(expr, CBinaryOp):
            return _safe_inline_expr(expr.lhs) and _safe_inline_expr(expr.rhs)
        if isinstance(expr, CITE):
            return _safe_inline_expr(expr.cond) and _safe_inline_expr(expr.iftrue) and _safe_inline_expr(expr.iffalse)
        return False

    def _count_var_uses(node: object, target: object, *, assignment_lhs: bool = False) -> int:
        """Count structural uses of one temporary across the dynamic angr AST."""
        if node is None:
            return 0
        if isinstance(node, CVariable):
            return 0 if assignment_lhs else int(_same_c_expression_8616(node, target))

        total = 0
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                total += _count_var_uses(
                    child,
                    target,
                    assignment_lhs=assignment_lhs and attr == "lhs" and isinstance(node, CAssignment),
                )
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    total += _count_var_uses(item, target)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            total += _count_var_uses(subitem, target)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    total += _count_var_uses(cond, target)
                if _structured_codegen_node_8616(body):
                    total += _count_var_uses(body, target)
        return total

    def _replace_var_use(
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
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if not _structured_codegen_node_8616(child):
                continue
            new_child, child_changed = _replace_var_use(
                child,
                target,
                replacement,
                assignment_lhs=assignment_lhs and attr == "lhs" and isinstance(node, CAssignment),
            )
            if child_changed:
                setattr(cast(Any, node), attr, new_child)
                changed_local = True
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            new_seq = []
            seq_changed = False
            for item in seq:
                if _structured_codegen_node_8616(item):
                    new_item, item_changed = _replace_var_use(item, target, replacement)
                    new_seq.append(new_item)
                    seq_changed |= item_changed
                else:
                    new_seq.append(item)
            if seq_changed:
                setattr(cast(Any, node), attr, new_seq)
                changed_local = True
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            new_pairs = []
            pair_changed = False
            for cond, body in pairs:
                new_cond, cond_changed = (
                    _replace_var_use(cond, target, replacement)
                    if _structured_codegen_node_8616(cond)
                    else (cond, False)
                )
                new_body, body_changed = (
                    _replace_var_use(body, target, replacement)
                    if _structured_codegen_node_8616(body)
                    else (body, False)
                )
                new_pairs.append((new_cond, new_body))
                pair_changed |= cond_changed or body_changed
            if pair_changed:
                cast(Any, node).condition_and_nodes = new_pairs
                changed_local = True
        return node, changed_local

    changed = False

    def visit(node: object) -> None:
        """Visit one statement block and eliminate locally proven carriers."""
        nonlocal changed
        nonlocal classified_fact_count, failure_count, materialized_count
        nonlocal normalized_fact_count, raw_fact_count
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
                and _safe_inline_expr(stmt.rhs)
                and next_stmt is not None
            ):
                raw_fact_count += 1
                if not _is_virtual_register_temporary(stmt.lhs):
                    failure_count += 1
                else:
                    normalized_fact_count += 1
                    if _crosses_nested_execution_scope(next_stmt):
                        failure_count += 1
                    else:
                        immediate_uses = _count_var_uses(next_stmt, stmt.lhs)
                        later_uses = sum(_count_var_uses(rest, stmt.lhs) for rest in statements[idx + 2 :])
                        if immediate_uses == 1 and later_uses == 0:
                            classified_fact_count += 1
                            _, replaced = _replace_var_use(next_stmt, stmt.lhs, stmt.rhs)
                            if replaced:
                                changed = True
                                materialized_count += 1
                                removed = True
                            else:
                                failure_count += 1
                        else:
                            failure_count += 1

            if not removed:
                new_statements.append(stmt)
                visit(stmt)
            idx += 1

        if len(new_statements) != len(node.statements):
            cast(Any, node).statements = new_statements

    root = cast(Any, typed_codegen.cfunc).statements
    visit(root)
    typed_codegen._inertia_single_use_temporary_elimination_stats_8616 = (
        SingleUseTemporaryEliminationStats8616(
            raw_fact_count=raw_fact_count,
            normalized_fact_count=normalized_fact_count,
            classified_fact_count=classified_fact_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
        )
    )
    return changed


def _maybe_eliminate_single_use_temporaries_8616(project: object, codegen: object) -> bool:
    if not getattr(project, "_inertia_postprocess_single_use_temporaries_enabled", False):
        return False
    return _eliminate_single_use_temporaries_8616(codegen)

"""Syntax-only helpers for angr structured C AST nodes.

Layer: Helper boundary.
Responsibility: provide syntax-only traversal and comparison for C AST nodes.

These helpers are shared by lowering, structuring, validation, and late
postprocess code.  They must remain syntax utilities: traversal, child
replacement, statement unwrapping, and structural expression equality.
This is a dynamic third-party angr boundary: callers may pass different
structured-codegen node classes and versions, so guarded getattr/setattr is
permitted here for C AST shape inspection and child replacement only.

Do not add stack/global/segment recovery, rendered-text parsing, semantic
classification, or validation exceptions here.  Semantic proof belongs in IR,
alias, widening, lowering, structuring, or validation-owned modules.
"""
from __future__ import annotations

import copy
import typing
from collections.abc import Callable, Iterator, Sequence
from contextlib import suppress
from enum import StrEnum
from functools import lru_cache
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CConstruct,
    CDirtyExpression,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

__all__ = [
    "_c_ast_cycle_path_8616",
    "_clone_c_ast_tree_8616",
    "_iter_c_node_occurrences_8616",
    "_iter_c_nodes_deep_8616",
    "_iter_c_statement_nodes_8616",
    "_replace_c_children_8616",
    "_safe_assign_cfunc_statements_8616",
    "_same_c_expression_8616",
    "_structured_codegen_node_8616",
    "_structured_slot_names_8616",
    "_unwrap_statements_8616",
]

_STRUCTURED_NON_CHILD_ATTRS_8616 = frozenset({"codegen", "idx", "tags"})
_STRUCTURED_CHILD_ATTRS_BY_CLASS_8616 = {
    "CAILBlock": ("block",),
    "CAssignment": ("lhs", "rhs"),
    "CBinaryOp": ("lhs", "rhs"),
    "CDoWhileLoop": ("condition", "body"),
    "CExpressionStatement": ("expr",),
    "CForLoop": ("initializer", "condition", "iterator", "body"),
    "CFunction": ("arg_list", "statements"),
    "CFunctionCall": ("callee_target", "callee_func", "args"),
    "CITE": ("cond", "iftrue", "iffalse"),
    "CIfBreak": ("condition",),
    "CIfElse": ("condition_and_nodes", "else_node"),
    "CIncompleteSwitchCase": ("head", "cases"),
    "CIndexedVariable": ("variable", "index"),
    "CMultiStatementExpression": ("stmts", "expr"),
    "CReturn": ("retval",),
    "CStatements": ("statements",),
    "CSwitchCase": ("switch", "cases", "default"),
    "CTypeCast": ("expr",),
    "CUnaryOp": ("operand",),
    "CVEXCCallExpression": ("callee", "operands"),
    "CVariableField": ("variable", "field"),
    "CWhileLoop": ("condition", "body"),
}


class _CFuncStatements8616(Protocol):
    """Statement root view needed at the dynamic third-party angr boundary."""

    statements: object


class _CodegenCFunc8616(Protocol):
    """Codegen view needed at the dynamic third-party angr boundary."""

    cfunc: _CFuncStatements8616


class _ConditionalPairs8616(Protocol):
    """Conditional children exposed by the dynamic codegen boundary."""

    condition_and_nodes: Sequence[tuple[object, object]] | None


class _SwitchCases8616(Protocol):
    """Case entries preserved and replaced at the dynamic codegen boundary."""

    cases: Sequence[object] | None


def _unwrap_statements_8616(node: object) -> tuple[object, ...]:
    """Safely extract statement children across the dynamic third-party angr boundary."""
    if node is None:
        return ()
    if isinstance(node, CStatements):
        return tuple(node.statements or ())
    if isinstance(node, (list, tuple)):
        return tuple(node)
    raw = getattr(node, "statements", ())
    if isinstance(raw, CStatements):
        return tuple(raw.statements)
    if isinstance(raw, (list, tuple)):
        return tuple(raw)
    return ()


def _structured_codegen_node_8616(value: object) -> bool:
    """Return whether a value participates in the structured C AST boundary."""
    return isinstance(value, CConstruct) or type(value).__module__.startswith(
        "angr.analyses.decompiler.structured_codegen"
    )


def _labeled_c_children_8616(value: object, label: str) -> Iterator[tuple[str, object]]:
    """Yield labeled structured nodes from one dynamic child container."""
    if _structured_codegen_node_8616(value):
        yield label, value
        return
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _labeled_c_children_8616(child, f"{label}[{key!r}]")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from _labeled_c_children_8616(child, f"{label}[{index}]")


def _c_ast_cycle_path_8616(node: object, *, max_nodes: int = 16_384) -> tuple[str, ...]:
    """Return one owned-child path that proves a structured C AST cycle."""
    active_indexes: dict[int, int] = {}
    completed: set[int] = set()
    path: list[str] = []
    visited = 0

    def _walk(current: object, edge: str) -> tuple[str, ...]:
        """Depth-first search using active-path identity, not shared-node identity."""
        nonlocal visited
        if not _structured_codegen_node_8616(current):
            return ()
        marker = id(current)
        op = getattr(current, "op", None)
        detail = f"[op={op}]" if isinstance(op, str) and op else ""
        entry = f"{edge}:{type(current).__name__}{detail}"
        if marker in active_indexes:
            return (*path, f"{entry}(cycle-to={active_indexes[marker]})")
        if marker in completed or visited >= max_nodes:
            return ()
        active_indexes[marker] = len(path)
        path.append(entry)
        visited += 1
        for attr in _structured_slot_names_8616(current):
            with suppress(Exception):
                value = getattr(current, attr)
                for child_edge, child in _labeled_c_children_8616(value, attr):
                    cycle = _walk(child, child_edge)
                    if cycle:
                        return cycle
        path.pop()
        active_indexes.pop(marker, None)
        completed.add(marker)
        return ()

    return _walk(node, "root")


def _clone_c_ast_tree_8616(node: object, memo: dict[int, object] | None = None) -> object:
    """Clone structured C nodes while preserving non-AST boundary objects."""
    if not _structured_codegen_node_8616(node):
        return node
    if memo is None:
        memo = {}
    marker = id(node)
    if marker in memo:
        return memo[marker]

    cloned = copy.copy(node)
    memo[marker] = cloned

    def _clone_value(value: object) -> object:
        """Clone nested structured nodes and child containers only."""
        if _structured_codegen_node_8616(value):
            return _clone_c_ast_tree_8616(value, memo)
        if isinstance(value, list):
            return [_clone_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(_clone_value(item) for item in value)
        if isinstance(value, dict):
            return {key: _clone_value(item) for key, item in value.items()}
        return value

    for attr in _structured_slot_names_8616(node):
        with suppress(Exception):
            setattr(cloned, attr, _clone_value(getattr(node, attr)))
    return cloned


def _safe_assign_cfunc_statements_8616(codegen: object, new_root: object, old_root: object) -> object:
    """Assign cfunc statements across the dynamic third-party angr boundary."""
    if isinstance(old_root, CStatements) and not isinstance(new_root, CStatements):
        if isinstance(new_root, list):
            new_root = CStatements(statements=new_root, codegen=codegen)
        else:
            new_root = CStatements(statements=[new_root], codegen=codegen)
    cast(_CodegenCFunc8616, codegen).cfunc.statements = new_root
    return new_root


@lru_cache(maxsize=256)
def _structured_slot_names_for_type_8616(value_type: type) -> tuple[str, ...]:
    """Collect slots across the dynamic third-party angr C AST boundary."""
    attrs: list[str] = []
    if value_type is object:
        return ()

    for cls in value_type.mro():
        slots = getattr(cls, "__slots__", ())
        if not slots:
            continue
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if isinstance(slot, str) and not slot.startswith("_") and slot not in _STRUCTURED_NON_CHILD_ATTRS_8616:
                attrs.append(slot)  # noqa: PERF401

    seen = set()
    ordered: list[str] = []
    for attr in attrs:
        if attr in seen:
            continue
        seen.add(attr)
        ordered.append(attr)
    return tuple(ordered)


def _structured_slot_names_8616(value: object) -> tuple[str, ...]:
    """List child slots across the dynamic third-party angr C AST boundary."""
    child_attrs = _STRUCTURED_CHILD_ATTRS_BY_CLASS_8616.get(type(value).__name__)
    if child_attrs is not None:
        return child_attrs

    base_attrs = _structured_slot_names_for_type_8616(cast(typing.Hashable, type(value)))
    if not hasattr(value, "__dict__"):
        return base_attrs

    attrs: list[str] = list(base_attrs)
    try:
        dynamic_keys = tuple(value.__dict__.keys())
    except Exception:
        dynamic_keys = ()
    if not dynamic_keys:
        return base_attrs
    attrs.extend(
        attr
        for attr in dynamic_keys
        if isinstance(attr, str) and not attr.startswith("_") and attr not in _STRUCTURED_NON_CHILD_ATTRS_8616
    )
    if not attrs:
        return ()

    seen = set()
    ordered: list[str] = []
    for attr in attrs:
        if attr in seen:
            continue
        seen.add(attr)
        ordered.append(attr)
    return tuple(ordered)


def _iter_c_node_children_8616(value: object, seen_values: set[int] | None = None) -> Iterator[object]:
    """Yield structured nodes directly contained by a dynamic boundary value."""
    if seen_values is None:
        seen_values = set()

    stack = [value]
    while stack:
        current = stack.pop()
        try:
            current_id = id(current)
        except Exception:
            continue
        if current_id in seen_values:
            continue
        seen_values.add(current_id)

        if _structured_codegen_node_8616(current):
            yield current
            continue

        if isinstance(current, (str, bytes)):
            continue

        if isinstance(current, dict):
            with suppress(Exception):
                stack.extend(tuple(current.values()))
            continue

        if isinstance(current, (list, tuple, set)):
            with suppress(Exception):
                stack.extend(tuple(current))
            continue


def _iter_c_statement_nodes_8616(root: object) -> Iterator[object]:
    """Iterate control-flow containers without descending into expressions."""
    stack = [root]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if not _structured_codegen_node_8616(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        for attr in ("statements", "body", "else_node", "condition_and_nodes", "cases", "default"):
            with suppress(Exception):
                value = getattr(current, attr)
                if isinstance(value, (list, tuple)):
                    for item in reversed(tuple(value)):
                        if isinstance(item, tuple):
                            stack.extend(reversed(item))
                        else:
                            stack.append(item)
                else:
                    stack.append(value)


class CTraversalFailure8616(StrEnum):
    """Classify structural failures without parsing diagnostic text."""

    CHILD_READ = "child_read"
    CHILD_WRITE = "child_write"
    CONTAINER_CYCLE = "container_cycle"


class CTraversalContractError8616(RuntimeError):
    """Report the exact AST field where structural traversal became unsafe."""

    def __init__(self, node_type: str, child_path: str, reason: CTraversalFailure8616) -> None:
        """Retain structured context and provide an actionable error message."""
        self.node_type = node_type
        self.child_path = child_path
        self.reason = reason
        super().__init__(f"C AST traversal failed at {node_type}.{child_path}: {reason.value}")


def _replace_c_child_value_8616(
    value: object, parent: object, path: str, active: frozenset[int],
    pending: list[object], transform: Callable[[object], object],
) -> tuple[object, bool]:
    """Project one child edge without losing nested container structure."""
    if _structured_codegen_node_8616(value):
        replacement = transform(value)
        pending.append(replacement)
        return replacement, replacement is not value
    if not isinstance(value, (list, tuple, dict)):
        return value, False
    identity = id(value)
    if identity in active:
        raise CTraversalContractError8616(
            type(parent).__name__, path, CTraversalFailure8616.CONTAINER_CYCLE,
        )
    child_active = active | {identity}
    items = value.items() if isinstance(value, dict) else enumerate(value)
    replacements: list[tuple[object, object]] = []
    container_changed = False
    for index, (key, item) in enumerate(items):
        replacement, item_changed = _replace_c_child_value_8616(
            item, parent, f"{path}[{index}]", child_active, pending, transform,
        )
        replacements.append((key, replacement))
        container_changed |= item_changed
    if not container_changed:
        return value, False
    if isinstance(value, dict):
        result = value.copy()
        result.update(replacements)
        return result, True
    values = [replacement for _, replacement in replacements]
    return (tuple(values) if isinstance(value, tuple) else values), True


def _replace_c_children_8616(
    node: object,
    transform: Callable[[object], object],
    seen: set[int] | None = None,
    *,
    should_process_child: Callable[[object, str], object] | None = None,
) -> bool:
    """Replace every declared child using the same schema as read traversal.

    Preserve container kinds and mapping keys. Report malformed child access
    and cyclic containers at the responsible node/field, not as absent children.
    """
    visited = set() if seen is None else seen
    pending = [node]
    changed = False

    def process_field(current: object, attr: str) -> bool:
        """Apply the child policy and contextualize dynamic field-access errors."""
        if should_process_child is not None and not should_process_child(current, attr):
            return False
        try:
            value = getattr(current, attr, None)
        except Exception as exc:
            raise CTraversalContractError8616(
                type(current).__name__, attr, CTraversalFailure8616.CHILD_READ,
            ) from exc
        replacement, field_changed = _replace_c_child_value_8616(
            value, current, attr, frozenset(), pending, transform,
        )
        if field_changed:
            try:
                setattr(current, attr, replacement)
            except Exception as exc:
                raise CTraversalContractError8616(
                    type(current).__name__, attr, CTraversalFailure8616.CHILD_WRITE,
                ) from exc
        return field_changed

    while pending:
        current = pending.pop()
        if not _structured_codegen_node_8616(current) or id(current) in visited:
            continue
        visited.add(id(current))
        for attr in _structured_slot_names_8616(current):
            if process_field(current, attr):
                changed = True
    return changed


def _iter_c_nodes_deep_8616(node: object, seen: set[int] | None = None) -> Iterator[object]:
    """Iterate C AST nodes across the dynamic third-party angr boundary."""
    if seen is None:
        seen = set()
    if not _structured_codegen_node_8616(node):
        return

    node_stack = [node]
    while node_stack:
        current = node_stack.pop()
        node_id = id(current)
        if node_id in seen:
            continue
        seen.add(node_id)
        yield current

        seen_values: set[int] = set()
        for attr in _structured_slot_names_8616(current):
            try:
                value = getattr(current, attr)
            except Exception:
                continue
            if _structured_codegen_node_8616(value):
                node_stack.append(value)
            elif isinstance(value, (dict, list, tuple, set)):
                node_stack.extend(_iter_c_node_children_8616(value, seen_values))


def _iter_c_node_occurrences_8616(
    value: object,
    active_node_ids: frozenset[int] = frozenset(),
) -> Iterator[object]:
    """Yield each AST edge occurrence while refusing active-path cycles."""
    if isinstance(value, dict):
        for child in value.values():
            yield from _iter_c_node_occurrences_8616(child, active_node_ids)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            yield from _iter_c_node_occurrences_8616(child, active_node_ids)
        return
    if not _structured_codegen_node_8616(value):
        return
    node_id = id(value)
    if node_id in active_node_ids:
        return
    yield value
    child_active_ids = active_node_ids | {node_id}
    for attr in _structured_slot_names_8616(value):
        with suppress(Exception):
            # Dynamic boundary: angr C node child slots vary by class and version.
            yield from _iter_c_node_occurrences_8616(
                getattr(value, attr),
                child_active_ids,
            )


def _dirty_register_identity_8616(dirty: object) -> tuple[str, object] | None:
    """Read register identity from version-dependent third-party dirty nodes."""
    for attr in ("reg_offset", "reg", "variable_offset"):
        value = None
        with suppress(AttributeError, TypeError, ValueError):
            value = getattr(dirty, attr, None)
        if isinstance(value, int):
            bits = None
            with suppress(AttributeError, TypeError, ValueError):
                bits = getattr(dirty, "bits", None)
            size = None
            with suppress(AttributeError, TypeError, ValueError):
                size = getattr(dirty, "size", None)
            size_bits = bits if isinstance(bits, int) else size * 8 if isinstance(size, int) else None
            return ("dirty-reg", (value, size_bits))
    return None


def _dirty_identity_8616(node: CDirtyExpression) -> tuple[str, object] | None:
    """Preserve native dirty identity precedence without guessing unknown nodes."""
    dirty = node.dirty
    register = _dirty_register_identity_8616(dirty)
    if register is not None:
        return register
    if isinstance(dirty, str) and dirty:
        return ("dirty-name", dirty)
    varid = getattr(dirty, "varid", None)
    if isinstance(varid, int):
        return ("dirty-varid", varid)
    tmp_idx = getattr(dirty, "tmp_idx", None)
    if isinstance(tmp_idx, int):
        return ("dirty-tmp", tmp_idx)
    name = getattr(dirty, "name", None)
    if isinstance(name, str) and name:
        return ("dirty-name", name)
    return None


def _same_c_variable_8616(lhs: CVariable, rhs: CVariable) -> bool:
    """Compare existing storage coordinates at the native C-variable boundary."""
    lvar = lhs.variable
    rvar = rhs.variable
    if type(lvar) is not type(rvar):
        return False
    if isinstance(lvar, SimRegisterVariable):
        return bool(lvar.reg == cast(SimRegisterVariable, rvar).reg)
    # Stack variables subclass memory variables but also require frame identity.
    if isinstance(lvar, SimStackVariable):
        rhs_stack = cast(SimStackVariable, rvar)
        return bool(
            lvar.offset == rhs_stack.offset and lvar.size == rhs_stack.size
            and lvar.base == rhs_stack.base and lvar.region == rhs_stack.region
        )
    if isinstance(lvar, SimMemoryVariable):
        rhs_memory = cast(SimMemoryVariable, rvar)
        return bool(lvar.addr == rhs_memory.addr and lvar.size == rhs_memory.size)
    return lhs is rhs


def _same_c_leaf_8616(lhs: object, rhs: object) -> bool:
    """Compare same-class leaves, retaining identity fallback for unknown nodes."""
    if isinstance(lhs, CConstant):
        return bool(lhs.value == cast(CConstant, rhs).value)
    if isinstance(lhs, CDirtyExpression):
        rhs_dirty = cast(CDirtyExpression, rhs)
        lhs_key = _dirty_identity_8616(lhs)
        rhs_key = _dirty_identity_8616(rhs_dirty)
        if lhs_key is not None or rhs_key is not None:
            return lhs_key == rhs_key
        return lhs.dirty is rhs_dirty.dirty
    if isinstance(lhs, CVariable):
        return _same_c_variable_8616(lhs, cast(CVariable, rhs))
    return lhs is rhs


def _same_c_expression_8616(lhs: object, rhs: object) -> bool:
    """Compare C expressions across the dynamic third-party angr boundary."""
    if type(lhs) is not type(rhs):
        return False
    if isinstance(lhs, CTypeCast):
        rhs_cast = cast(CTypeCast, rhs)
        return _same_c_expression_8616(lhs.expr, rhs_cast.expr)
    if isinstance(lhs, CUnaryOp):
        rhs_unary = cast(CUnaryOp, rhs)
        return lhs.op == rhs_unary.op and _same_c_expression_8616(lhs.operand, rhs_unary.operand)
    if isinstance(lhs, CBinaryOp):
        rhs_binary = cast(CBinaryOp, rhs)
        return (
            lhs.op == rhs_binary.op
            and _same_c_expression_8616(lhs.lhs, rhs_binary.lhs)
            and _same_c_expression_8616(lhs.rhs, rhs_binary.rhs)
        )
    if isinstance(lhs, CITE):
        rhs_ite = cast(CITE, rhs)
        return (
            _same_c_expression_8616(lhs.cond, rhs_ite.cond)
            and _same_c_expression_8616(lhs.iftrue, rhs_ite.iftrue)
            and _same_c_expression_8616(lhs.iffalse, rhs_ite.iffalse)
        )
    if isinstance(lhs, CFunctionCall):
        rhs_call = cast(CFunctionCall, rhs)
        if not _same_call_target_8616(lhs, rhs_call):
            return False
        lhs_args = tuple(lhs.args or ())
        rhs_args = tuple(rhs_call.args or ())
        return len(lhs_args) == len(rhs_args) and all(
            _same_c_expression_8616(lhs_arg, rhs_arg) for lhs_arg, rhs_arg in zip(lhs_args, rhs_args, strict=True)
        )
    if isinstance(lhs, CIndexedVariable):
        rhs_indexed = cast(CIndexedVariable, rhs)
        return _same_c_expression_8616(lhs.variable, rhs_indexed.variable) and _same_c_expression_8616(
            lhs.index, rhs_indexed.index
        )
    return _same_c_leaf_8616(lhs, rhs)


def _same_call_target_8616(lhs: CFunctionCall, rhs: CFunctionCall) -> bool:
    """Compare call targets across the dynamic third-party angr boundary."""
    lhs_func = lhs.callee_func
    rhs_func = rhs.callee_func
    if lhs_func is not None or rhs_func is not None:
        if lhs_func is None or rhs_func is None:
            return False
        lhs_addr = getattr(lhs_func, "addr", None)
        rhs_addr = getattr(rhs_func, "addr", None)
        if isinstance(lhs_addr, int) or isinstance(rhs_addr, int):
            return lhs_addr == rhs_addr
        return getattr(lhs_func, "name", None) == getattr(rhs_func, "name", None)
    lhs_target = lhs.callee_target
    rhs_target = rhs.callee_target
    if lhs_target is None or rhs_target is None:
        return lhs_target is rhs_target
    return _same_c_expression_8616(lhs_target, rhs_target)

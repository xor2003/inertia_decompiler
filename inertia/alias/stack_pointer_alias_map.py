"""Authoritative structured-C stack-pointer alias result and cache contract.

Layer: Alias.
Responsibility: own the single computation that proves which structured-C
variables carry stack locations, publish it under one canonical exact-identity
key scheme (``id(variable)``), and share it through the codegen cache slot
consumed by both lowering canonicalization and tail-validation fingerprinting.

Proof model: a variable's stack alias is published only when all of the
following hold: it has exactly one syntactic assignment (unique definition),
that definition is unconditional (not inside a branch, loop body, switch case
or unknown container), its rhs resolves to a stack location through
pointer-address evidence only (``&slot`` references and proven carriers; a
plain ``p = q`` copies a pointer VALUE and cannot invent ``&q``), no read of
the variable precedes its definition, and no unsupported write or escaped
address can mutate it (non-assignment writes, ``&var`` reaching a call, or
writes under unknown nodes refuse). Iteration order alone never establishes
use ordering; overwritten, mutually exclusive, conditional, and
use-before-definition carriers all refuse. Variable names never prove
storage identity.

Consumers must distinguish ``complete`` from budget-exhausted results: an
exhausted result means the evidence walk did not finish, so the map is not
authoritative and consumers must preserve code rather than use partial
aliases. A legacy bare ``(root, dict)`` tuple carries no verdict and is never
consumed.

Cache invalidation: the recorded ``root`` is the ``cfunc.statements`` object
compared by identity. Replacing the root invalidates an entry, but in-place
AST mutation does not, so the explicit postprocess invalidation hooks that
clear the shared slot remain required.
"""

from __future__ import annotations

import enum
import types
import typing
from collections.abc import Iterator
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CDoWhileLoop,
    CExpression,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypePointer
from angr.sim_variable import SimStackVariable

_STACK_POINTER_ALIAS_CACHE_ATTR_8616 = "_inertia_stack_pointer_aliases_for_cvars"
_STACK_POINTER_ALIAS_NODE_BUDGET_8616 = 4096

_MUTATION_OPS_8616 = frozenset(
    {"PreIncrement", "PostIncrement", "PreDecrement", "PostDecrement"}
)
_EXPR_CHILD_ATTRS_8616 = (
    "expr",
    "lhs",
    "rhs",
    "operand",
    "operands",
    "args",
    "index",
    "condition",
    "retval",
    "ret_values",
    "elements",
    "true_expr",
    "false_expr",
    "value",
)
_CONTAINER_TYPES_8616 = (
    CStatements,
    CIfElse,
    CWhileLoop,
    CDoWhileLoop,
    CForLoop,
    CExpressionStatement,
)


class StackPointerAliasStatus8616(enum.Enum):
    """Completeness verdict of the shared stack alias evidence walk."""

    COMPLETE = "complete"
    NODE_BUDGET_EXHAUSTED = "node_budget_exhausted"


@dataclass(frozen=True)
class StackPointerAliasResult8616:
    """One authoritative stack-alias result with verdict and closed counters.

    ``aliases`` maps ``id(variable)`` to a terminal ``(base_expr, offset)``
    pair: each base is an intrinsic stack-slot expression, never re-resolved
    through this map, so transitive reads cannot smuggle a later definition
    into an earlier copy. Publication is globally safe: every collected read
    of a published variable is ordered after its definition, so consumers need
    no per-use position checks. ``definition_index`` records each proven
    variable's assignment position as evidence. ``refused`` holds the ``id``
    of carrier candidates that were not proven.

    Evidence counters: ``raw_fact_count`` counts assignment statements seen;
    ``normalized_fact_count`` counts carrier-eligible assignments whose rhs
    is pointer-shaped (unrelated scalar assignments never normalize as alias
    facts); ``classified_fact_count`` counts distinct candidate variables;
    ``materialized_count`` counts typed decisions consumers preserve (proven
    aliases plus retained refusals); ``failure_count`` counts refused
    candidates. ``classified == materialized`` is required.
    The payload is immutable: ``aliases``/``definition_index`` are
    mapping-proxied at construction.
    """

    root: object
    status: StackPointerAliasStatus8616
    aliases: typing.Mapping[int, tuple[object, int]]
    definition_index: typing.Mapping[int, int]
    refused: frozenset[int]
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    decision_count: int = 0
    visited_nodes: int = 0

    def __post_init__(self) -> None:
        """Freeze the proof payload and enforce census invariants.

        A COMPLETE result must satisfy the closed evidence funnel:
        ``classified == materialized`` (every classified candidate produced a
        typed decision), ``failure == len(refused)``, and proven/refused sets
        disjoint. A contradictory COMPLETE payload is rejected, not trusted.
        """
        object.__setattr__(self, "aliases", types.MappingProxyType(dict(self.aliases)))
        object.__setattr__(self, "definition_index", types.MappingProxyType(dict(self.definition_index)))
        object.__setattr__(self, "refused", frozenset(self.refused))
        if set(self.aliases) & self.refused:
            raise ValueError("alias result has overlapping proven and refused variables")
        if self.status is StackPointerAliasStatus8616.COMPLETE:
            if self.materialized_count != len(self.aliases):
                raise ValueError("complete alias result with unmaterialized aliases")
            if self.classified_fact_count != self.materialized_count:
                raise ValueError("complete alias result with non-positive classification")
            if self.failure_count != len(self.refused):
                raise ValueError("complete alias result with inconsistent failure census")
            if self.decision_count != self.classified_fact_count + self.failure_count:
                raise ValueError("complete alias result with inconsistent decision census")
            if not (
                self.raw_fact_count
                >= self.normalized_fact_count
                >= self.decision_count
                >= self.classified_fact_count
                >= 0
            ):
                raise ValueError("complete alias result with inverted evidence funnel")

    @property
    def complete(self) -> bool:
        """Return whether the evidence walk finished inside its budget."""
        return self.status is StackPointerAliasStatus8616.COMPLETE


def _codegen_attr_8616(owner: object, name: str, default: object = None) -> object:
    """Dynamic third-party angr boundary: read optional codegen attributes."""
    return getattr(owner, name, default)


def read_stack_pointer_alias_map_8616(
    codegen: object,
) -> StackPointerAliasResult8616 | None:
    """Return the cached result when it matches the live statements root.

    Foreign values, legacy bare tuples, malformed entries, and stale roots are
    never returned: their provenance and verdict are unverifiable, so callers
    must recompute or refuse rather than silently consume them. In-place AST
    mutation does not replace the root, so the postprocess invalidation hooks
    that clear the shared slot remain the authoritative stale-cache defense.
    """
    entry = _codegen_attr_8616(codegen, _STACK_POINTER_ALIAS_CACHE_ATTR_8616)
    if not isinstance(entry, StackPointerAliasResult8616):
        return None
    cfunc = _codegen_attr_8616(codegen, "cfunc")
    root = _codegen_attr_8616(cfunc, "statements")
    if root is None or entry.root is not root:
        return None
    return entry


def write_stack_pointer_alias_map_8616(codegen: object, entry: StackPointerAliasResult8616) -> None:
    """Store ``entry`` in the shared codegen alias-map cache slot."""
    # dynamic-boundary: the cache slot lives on angr codegen objects shared by
    # lowering and validation consumers.
    typing.cast(typing.Any, codegen)._inertia_stack_pointer_aliases_for_cvars = entry


def _iter_statements_in_order_8616(root: object) -> Iterator[tuple[object, bool]]:
    """Yield ``(node, conditional)`` in program order (depth-first pre-order).

    Children of any container other than a plain ``CStatements``/list sequence
    are conditional: branches, loop bodies, switch cases, and unknown control
    or statement nodes cannot prove an unconditional global alias.
    """
    stack: list[tuple[object, bool]] = [(root, False)]
    seen: set[int] = set()
    while stack:
        node, conditional = stack.pop()
        if node is None:
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)
        yield node, conditional
        _push_children_in_program_order_8616(node, stack, conditional)


def _push_children_in_program_order_8616(
    node: object, stack: list[tuple[object, bool]], conditional: bool
) -> None:
    """Queue a node's children so they pop in program order."""
    if isinstance(node, CStatements):
        stack.extend((child, conditional) for child in reversed(tuple(node.statements or ())))
    elif isinstance(node, CExpressionStatement):
        _push_loop_children_8616((node.expr,), stack, conditional)
    elif isinstance(node, CIfElse):
        _push_if_else_children_8616(node, stack)
    elif isinstance(node, CForLoop):
        _push_loop_children_8616((node.body, node.iterator, node.initializer), stack, True)
    elif isinstance(node, (CWhileLoop, CDoWhileLoop)):
        _push_loop_children_8616((node.body,), stack, True)
    elif isinstance(node, (list, tuple)):
        stack.extend((child, True) for child in reversed(tuple(node)))


def _push_loop_children_8616(
    children: tuple[object, ...], stack: list[tuple[object, bool]], conditional: bool
) -> None:
    """Queue children so they pop in program order."""
    for child in children:
        if child is not None:
            stack.append((child, conditional))


def _push_if_else_children_8616(node: CIfElse, stack: list[tuple[object, bool]]) -> None:
    """Queue branch bodies of an if-else node in program order; each is conditional."""
    if node.else_node is not None:
        stack.append((node.else_node, True))
    for pair in reversed(tuple(node.condition_and_nodes or ())):
        if isinstance(pair, tuple) and len(pair) >= 2:
            stack.append((pair[1], True))


def _stack_var_pointer_capable_8616(var: object, cvar: object) -> bool:
    """Return whether a stack variable may carry a pointer-shaped value."""
    if not isinstance(var, SimStackVariable) or var.base != "bp":
        return False
    if isinstance(var.size, int) and var.size >= 2:
        return True
    return isinstance(_codegen_attr_8616(cvar, "variable_type"), SimTypePointer)


def _resolve_reference_alias_8616(node: CUnaryOp) -> tuple[object, int] | None:
    """Resolve ``&operand`` to a stack-slot alias.

    Address-of names the operand's own storage: only a bp slot has provable
    stack storage. A value alias must never be projected through ``&``.
    """
    operand = _canonical_unwrap_8616(node.operand)
    if not isinstance(operand, CVariable):
        return None
    variable = operand.variable
    if isinstance(variable, SimStackVariable) and variable.base == "bp":
        return operand, 0
    return None


def _rhs_is_pointer_shaped_8616(rhs: object) -> bool:
    """Return whether an unwrapped rhs can carry a stack-pointer alias.

    A residual ``CTypeCast`` counts so a narrowing cast is refused rather
    than silently dropped from the candidate census.
    """
    return isinstance(rhs, (CVariable, CBinaryOp, CTypeCast)) or (
        isinstance(rhs, CUnaryOp) and rhs.op == "Reference"
    )


def _canonical_unwrap_8616(node: object) -> object:
    """Unwrap only representation-preserving casts; never erase narrowing.

    ``(byte)&local`` truncates the pointer and cannot prove a stack address,
    so only casts whose destination type is at least as wide as the source
    are removed. Unknown sizes are not unwrapped.
    """
    while isinstance(node, CTypeCast):
        dst = _codegen_attr_8616(node, "dst_type")
        src = _codegen_attr_8616(node, "src_type")
        dst_size = _codegen_attr_8616(dst, "size")
        src_size = _codegen_attr_8616(src, "size")
        if not (isinstance(dst_size, int) and isinstance(src_size, int) and dst_size >= src_size):
            return node
        node = _codegen_attr_8616(node, "expr")
    return node


def _resolve_rhs_alias_8616(
    expr: object,
    proven: dict[int, tuple[object, int]],
) -> tuple[object, int] | None:
    """Resolve one rhs expression against earlier proven definitions.

    A rhs variable resolves only through a definition already proven (an
    ordered carrier copy). ``&slot`` references seed intrinsically; an
    Add/Sub adjusts a proven or referenced base by a constant. Any other
    shape cannot prove a stack address.
    """
    node = _canonical_unwrap_8616(expr)
    if isinstance(node, CVariable):
        # A plain copy carries the rhs VALUE: only a proven carrier qualifies.
        # A stack slot's stored value is never the address of that slot, so an
        # unproven or never-assigned variable cannot seed ``p = &q``.
        variable = node.variable
        if variable is None:
            return None
        return proven.get(id(variable))
    if isinstance(node, CUnaryOp) and node.op == "Reference":
        return _resolve_reference_alias_8616(node)
    if isinstance(node, CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs = _resolve_rhs_alias_8616(node.lhs, proven)
        rhs = _resolve_rhs_alias_8616(node.rhs, proven)
        lhs_value = _codegen_attr_8616(_canonical_unwrap_8616(node.lhs), "value")
        rhs_value = _codegen_attr_8616(_canonical_unwrap_8616(node.rhs), "value")
        if lhs is not None and isinstance(rhs_value, int):
            base, offset = lhs
            return base, offset + (rhs_value if node.op == "Add" else -rhs_value)
        if rhs is not None and isinstance(lhs_value, int) and node.op == "Add":
            base, offset = rhs
            return base, offset + lhs_value
    return None


def _carrier_lhs_variable_8616(stmt: object) -> object | None:
    """Return the carrier-eligible lhs variable of one assignment, if any."""
    lhs = _canonical_unwrap_8616(_codegen_attr_8616(stmt, "lhs"))
    if not isinstance(lhs, CVariable):
        return None
    variable = lhs.variable
    if variable is None or (isinstance(variable, SimStackVariable) and variable.base != "bp"):
        return None
    return typing.cast(object, variable)


def _lhs_carrier_gate_ok_8616(variable: object, lhs: object, rhs: object) -> bool:
    """Return whether a non-pointer-capable stack lhs may still carry a pointer."""
    if not isinstance(variable, SimStackVariable) or _stack_var_pointer_capable_8616(variable, lhs):
        return True
    return (isinstance(rhs, CUnaryOp) and rhs.op == "Reference") or isinstance(rhs, CBinaryOp)


def _expr_children_8616(node: object) -> Iterator[object]:
    """Yield expression-level children of a structured-C node."""
    for attr in _EXPR_CHILD_ATTRS_8616:
        child = _codegen_attr_8616(node, attr)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            yield from (item for item in child if item is not None)
        else:
            yield child


def _mark_lhs_vars_mutated_8616(
    lhs: object, mutated: set[int], budget: list[int]
) -> bool:
    """Mark every variable under a write-position expression as mutated."""
    stack: list[object] = [lhs]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        budget[0] -= 1
        if budget[0] < 0:
            return False
        if isinstance(node, CVariable):
            if node.variable is not None:
                mutated.add(id(node.variable))
            continue
        stack.extend(_expr_children_8616(node))
    return True


def _unary_op_evidence_8616(
    item: CUnaryOp, in_call: bool, escaped: set[int], mutated: set[int]
) -> None:
    """Record escape/mutation evidence from one unary-op node."""
    operand = item.operand
    if not isinstance(operand, CVariable) or operand.variable is None:
        return
    key = id(operand.variable)
    if item.op == "Reference" and in_call:
        escaped.add(key)
    if item.op in _MUTATION_OPS_8616:
        mutated.add(key)


def _scan_expr_evidence_8616(
    node: object,
    index: int,
    *,
    prune_containers: bool,
    reads: dict[int, int],
    escaped: set[int],
    mutated: set[int],
    call_reads: dict[int, list[int]],
    budget: list[int],
) -> bool:
    """Collect reads, escapes, and mutations under one expression subtree.

    ``reads`` records each variable's earliest read index. ``escaped``
    records variables whose ``&var`` reaches a call argument, and ``mutated``
    records variables written outside a plain top-level ``CAssignment``
    (increments, nested assignments). ``prune_containers`` stops descent into
    statement containers that the ordered walk yields separately.
    """
    stack: list[tuple[object, bool]] = [(node, False)]
    seen: set[int] = set()
    while stack:
        item, in_call = stack.pop()
        if item is None or id(item) in seen:
            continue
        seen.add(id(item))
        budget[0] -= 1
        if budget[0] < 0:
            return False
        if prune_containers and isinstance(item, _CONTAINER_TYPES_8616):
            continue
        if isinstance(item, CAssignment):
            if not _mark_lhs_vars_mutated_8616(
                _codegen_attr_8616(item, "lhs"), mutated, budget
            ):
                return False
            rhs = _codegen_attr_8616(item, "rhs")
            if rhs is not None:
                stack.append((rhs, in_call))
            continue
        if _scan_leaf_evidence_8616(item, index, in_call, reads, escaped, mutated, call_reads):
            continue
        child_in_call = in_call or isinstance(item, CFunctionCall)
        stack.extend((child, child_in_call) for child in _expr_children_8616(item))
    return True


def _scan_leaf_evidence_8616(
    item: object,
    index: int,
    in_call: bool,
    reads: dict[int, int],
    escaped: set[int],
    mutated: set[int],
    call_reads: dict[int, list[int]],
) -> bool:
    """Handle leaf-level evidence for one scanned node; True if it is a leaf."""
    if isinstance(item, CVariable):
        variable = item.variable
        if variable is not None:
            key = id(variable)
            reads[key] = min(reads.get(key, index), index)
            if in_call:
                call_reads.setdefault(key, []).append(index)
        return True
    if isinstance(item, CUnaryOp):
        _unary_op_evidence_8616(item, in_call, escaped, mutated)
    return False


def _lhs_base_variable_8616(lhs: object) -> object | None:
    """Return the base variable of a write-position expression, if any."""
    node = _canonical_unwrap_8616(lhs)
    if isinstance(node, CVariable):
        return typing.cast(object, node.variable)
    child = _codegen_attr_8616(node, "variable")
    if child is not None:
        return _lhs_base_variable_8616(child)
    return None


def _scan_assignment_evidence_8616(
    node: object,
    index: int,
    out: tuple[dict[int, int], set[int], set[int], dict[int, list[int]], list[int]],
) -> bool:
    """Scan an assignment's lhs index/pointee expressions and rhs."""
    reads, escaped, mutated, call_reads, budget = out
    lhs = _codegen_attr_8616(node, "lhs")
    if lhs is not None and not isinstance(_canonical_unwrap_8616(lhs), CVariable):
        # `x[i] = v`/`*p = v`: index and pointee expressions are reads,
        # and the write mutates the lvalue's own base variable.
        if not _scan_expr_evidence_8616(
            lhs, index,
            prune_containers=True, reads=reads, escaped=escaped, mutated=mutated,
            call_reads=call_reads, budget=budget,
        ):
            return False
        base_var = _lhs_base_variable_8616(lhs)
        if base_var is not None:
            mutated.add(id(base_var))
    rhs = _codegen_attr_8616(node, "rhs")
    if rhs is None:
        return True
    return _scan_expr_evidence_8616(
        rhs, index,
        prune_containers=True, reads=reads, escaped=escaped, mutated=mutated,
        call_reads=call_reads, budget=budget,
    )


def _scan_statement_evidence_8616(
    node: object,
    index: int,
    out: tuple[dict[int, int], set[int], set[int], dict[int, list[int]], list[int]],
) -> bool:
    """Scan one statement node's non-child evidence (conditions and exprs)."""
    reads, escaped, mutated, call_reads, budget = out

    def scan(sub: object) -> bool:
        if sub is None:
            return True
        return _scan_expr_evidence_8616(
            sub, index,
            prune_containers=True, reads=reads, escaped=escaped, mutated=mutated,
            call_reads=call_reads, budget=budget,
        )

    if isinstance(node, CAssignment):
        return _scan_assignment_evidence_8616(node, index, out)
    if isinstance(node, CIfElse):
        for pair in node.condition_and_nodes or ():
            if isinstance(pair, tuple) and pair and not scan(pair[0]):
                return False
        return True
    if isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop)):
        return scan(_codegen_attr_8616(node, "condition"))
    if isinstance(node, _CONTAINER_TYPES_8616):
        return True
    # Unknown statement nodes may hide writes the ordered walk cannot
    # attribute; scan their whole subtree and treat nested assignment
    # targets as mutated so their carriers refuse.
    return _scan_expr_evidence_8616(
        node, index,
        prune_containers=False, reads=reads, escaped=escaped, mutated=mutated,
        call_reads=call_reads, budget=budget,
    )


def _is_control_unsafe_node_8616(node: object) -> bool:
    """Return whether a top-level node can alter execution order.

    Labels, jumps, switch constructs, and unknown statement types can make a
    later definition unreachable or reachable without dominating uses, so
    definitions after them cannot publish unconditional aliases.
    """
    return not isinstance(node, (*_CONTAINER_TYPES_8616, CAssignment, CExpression))


def _write_range_8616(lhs: object) -> tuple[int, int, int] | None:
    """Return ``(start, end, var_id)`` of a write to a bp stack slot, if any."""
    base_var = _lhs_base_variable_8616(lhs)
    if not isinstance(base_var, SimStackVariable) or base_var.base != "bp":
        return None
    if isinstance(base_var.offset, int) and isinstance(base_var.size, int):
        return base_var.offset, base_var.offset + base_var.size, id(base_var)
    return None


def _collect_evidence_8616(
    root: object, max_nodes: int
) -> tuple[
    list[tuple[int, object, bool]],
    dict[int, int],
    set[int],
    set[int],
    dict[int, list[int]],
    list[tuple[int, int, int]],
    int,
    bool,
]:
    """Collect ordered assignments plus read/escape/mutation/write evidence."""
    assignments: list[tuple[int, object, bool]] = []
    reads: dict[int, int] = {}
    escaped: set[int] = set()
    mutated: set[int] = set()
    call_reads: dict[int, list[int]] = {}
    write_ranges: list[tuple[int, int, int]] = []
    control_unsafe = False
    budget = [max_nodes]
    for index, (node, conditional) in enumerate(_iter_statements_in_order_8616(root)):
        budget[0] -= 1
        if budget[0] < 0:
            visited = max_nodes - budget[0]
            return assignments, reads, escaped, mutated, call_reads, write_ranges, visited, True
        if isinstance(node, CAssignment):
            assignments.append((index, node, conditional or control_unsafe))
            write_range = _write_range_8616(_codegen_attr_8616(node, "lhs"))
            if write_range is not None:
                write_ranges.append(write_range)
        if not _scan_statement_evidence_8616(
            node, index, (reads, escaped, mutated, call_reads, budget)
        ):
            visited = max_nodes - budget[0]
            return assignments, reads, escaped, mutated, call_reads, write_ranges, visited, True
        if _is_control_unsafe_node_8616(node):
            control_unsafe = True
    visited_nodes = max_nodes - budget[0]
    return assignments, reads, escaped, mutated, call_reads, write_ranges, visited_nodes, False


def _pointer_target_of_rhs_8616(
    rhs: object, latest_targets: dict[int, int | None]
) -> int | None:
    """Return the variable id whose slot address an rhs may carry, if any.

    ``&v`` yields ``id(v)``; a copy or ``+/-`` constant offset of a carrier
    propagates that carrier's current target. Other shapes carry no known
    stack address.
    """
    node = _canonical_unwrap_8616(rhs)
    if isinstance(node, CUnaryOp) and node.op == "Reference":
        operand = _canonical_unwrap_8616(node.operand)
        if isinstance(operand, CVariable) and operand.variable is not None:
            return id(operand.variable)
        return None
    if isinstance(node, CVariable):
        if node.variable is None:
            return None
        return latest_targets.get(id(node.variable))
    if isinstance(node, CBinaryOp) and node.op in {"Add", "Sub"}:
        for side in (node.lhs, node.rhs):
            target = _pointer_target_of_rhs_8616(side, latest_targets)
            if target is not None:
                return target
    return None


def _resolve_escaped_vars_8616(
    assignments: list[tuple[int, object, bool]],
    call_reads: dict[int, list[int]],
    escaped: set[int],
) -> None:
    """Extend ``escaped`` with carriers whose addresses reach call args.

    ``t = &v; unknown(t)`` hands ``&v`` to the call: v's slot may be written.
    The target of the *latest* pointer-shaped definition before each call
    read escapes; copies propagate targets transitively. One ordered pass,
    monotonic and bounded.
    """
    latest_targets: dict[int, int | None] = {}
    defs: dict[int, list[tuple[int, int | None]]] = {}
    for index, stmt, _conditional in assignments:
        variable = _carrier_lhs_variable_8616(stmt)
        if variable is None:
            continue
        key = id(variable)
        target = _pointer_target_of_rhs_8616(
            _codegen_attr_8616(stmt, "rhs"), latest_targets
        )
        latest_targets[key] = target
        defs.setdefault(key, []).append((index, target))
    for carrier_id, read_indices in call_reads.items():
        for read_index in read_indices:
            earlier = [
                (def_index, target)
                for def_index, target in defs.get(carrier_id, ())
                if def_index < read_index
            ]
            if not earlier:
                continue
            _latest_index, target = max(earlier, key=lambda pair: pair[0])
            if target is not None:
                escaped.add(target)


def _carrier_slot_overlapped_8616(
    variable: object, key: int, write_ranges: list[tuple[int, int, int]]
) -> bool:
    """Return whether another bp slot write overlaps this carrier's storage.

    Distinct ``SimStackVariable`` objects are different views: a byte or word
    view overlapping the carrier's range can mutate its stored value even
    when the object identity differs, so object id alone is not proof.
    """
    if not isinstance(variable, SimStackVariable):
        return False
    if not (isinstance(variable.offset, int) and isinstance(variable.size, int)):
        return True
    start = variable.offset
    end = variable.offset + variable.size
    for write_start, write_end, write_id in write_ranges:
        if write_id != key and write_start < end and start < write_end:
            return True
    return False


def _candidate_is_unproven_8616(
    key: int,
    index: int,
    conditional: bool,
    variable: object,
    def_counts: dict[int, int],
    reads: dict[int, int],
    escaped: set[int],
    mutated: set[int],
    write_ranges: list[tuple[int, int, int]],
) -> bool:
    """Return whether a classified candidate lacks a publishable proof."""
    if def_counts.get(key, 0) != 1 or conditional:
        return True
    if key in escaped or key in mutated:
        return True
    return reads.get(key, index) < index or _carrier_slot_overlapped_8616(
        variable, key, write_ranges
    )


def _propagate_ordered_defs_8616(
    assignments: list[tuple[int, object, bool]],
    def_counts: dict[int, int],
    reads: dict[int, int],
    escaped: set[int],
    mutated: set[int],
    write_ranges: list[tuple[int, int, int]],
) -> tuple[dict[int, tuple[object, int]], dict[int, int], set[int], int]:
    """Propagate aliases through ordered unique unconditional definitions."""
    proven: dict[int, tuple[object, int]] = {}
    definition_index: dict[int, int] = {}
    refused: set[int] = set()
    normalized_count = 0
    for index, stmt, conditional in assignments:
        lhs = _canonical_unwrap_8616(_codegen_attr_8616(stmt, "lhs"))
        if not isinstance(lhs, CVariable):
            continue
        variable = lhs.variable
        if variable is None or (isinstance(variable, SimStackVariable) and variable.base != "bp"):
            continue
        key = id(variable)
        rhs = _canonical_unwrap_8616(_codegen_attr_8616(stmt, "rhs"))
        if not _rhs_is_pointer_shaped_8616(rhs) or not _lhs_carrier_gate_ok_8616(variable, lhs, rhs):
            continue
        normalized_count += 1
        if _candidate_is_unproven_8616(
            key, index, conditional, variable, def_counts, reads, escaped, mutated,
            write_ranges,
        ):
            refused.add(key)
            continue
        resolved = _resolve_rhs_alias_8616(rhs, proven)
        if resolved is None:
            refused.add(key)
            continue
        proven[key] = resolved
        definition_index[key] = index
    return proven, definition_index, refused, normalized_count


def compute_stack_pointer_aliases_8616(
    codegen: object,
    root: object,
    *,
    max_nodes: int = _STACK_POINTER_ALIAS_NODE_BUDGET_8616,
) -> StackPointerAliasResult8616:
    """Compute the authoritative ordered-unique-definition stack alias map.

    Assignments are collected in program order and processed once; a carrier
    is published only when its single definition is unconditional, its rhs
    resolves through pointer-address evidence, no read precedes that
    definition, and no unsupported write or escaped address can mutate it.
    All other carrier candidates refuse explicitly.
    """
    evidence = _collect_evidence_8616(root, max_nodes)
    (
        assignments,
        reads,
        escaped,
        mutated,
        call_reads,
        write_ranges,
        visited_nodes,
        exhausted,
    ) = evidence

    raw_fact_count = len(assignments)
    def_counts: dict[int, int] = {}
    for _index, stmt, _conditional in assignments:
        variable = _carrier_lhs_variable_8616(stmt)
        if variable is None:
            continue
        key = id(variable)
        def_counts[key] = def_counts.get(key, 0) + 1

    _resolve_escaped_vars_8616(assignments, call_reads, escaped)
    proven, definition_index, refused, normalized_fact_count = (
        _propagate_ordered_defs_8616(
            assignments, def_counts, reads, escaped, mutated, write_ranges
        )
    )

    result = StackPointerAliasResult8616(
        root=root,
        status=(
            StackPointerAliasStatus8616.NODE_BUDGET_EXHAUSTED
            if exhausted
            else StackPointerAliasStatus8616.COMPLETE
        ),
        aliases=proven,
        definition_index=definition_index,
        refused=frozenset(refused),
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=len(proven),
        materialized_count=len(proven),
        failure_count=len(refused),
        decision_count=len(proven) + len(refused),
        visited_nodes=visited_nodes,
    )
    return result


__all__ = [
    "StackPointerAliasResult8616",
    "StackPointerAliasStatus8616",
    "compute_stack_pointer_aliases_8616",
    "read_stack_pointer_alias_map_8616",
    "write_stack_pointer_alias_map_8616",
]

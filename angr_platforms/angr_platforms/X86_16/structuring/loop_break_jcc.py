"""Structuring-owned materialization for unconsumed loop-break JCCs.

Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

Responsibility: consume binary JCC/CFG evidence and repair loop bodies by
materializing missing ``if (...) break;`` guards, or by inverting an existing
continuation guard when the decoded edge polarity proves it.  This module
operates on C AST objects and typed callback contracts only; rendered C text and
source declarations are not evidence.

angr's Rust-backed Tags supports key lookup but is not a Python Mapping.
Both supported tag representations must retain instruction membership evidence.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CBreak,
    CConstant,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatement,
    CStatements,
    CUnaryOp,
    CWhileLoop,
)
from angr.rustylib.ailment import Tags

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.condition_ir import (
    ConditionIR,
    canonicalize_condition_storage_fingerprint_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)
from ..pipeline.errors import PipelineHardError
from .condition_materialization import materialize_condition_ir_expression_8616
from .condition_storage_identity import same_condition_storage_identity_8616
from .loop_break_topology import LoopBreakTopology8616, collect_loop_break_topology_8616


@dataclass(frozen=True, order=True, slots=True)
class LoopBranchGuardFact8616:
    """Binary-proven identity, targets, and semantics for one loop guard."""

    jcc_addr: int
    block_addr: int
    body_target: int
    fallthrough_target: int
    false_target: int
    decoded_condition_fingerprint: str
    guard_condition_fingerprint: str
    condition_ir: ConditionIR | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True, order=True, slots=True)
class LoopHeaderDuplicateGuardRemovalFact8616:
    """Exact condition evidence for one redundant loop-break guard removal."""

    jcc_addr: int
    block_addr: int
    removed_guard_fingerprint: str
    retained_loop_fingerprint: str


@dataclass(frozen=True, slots=True)
class _LoopHeaderDuplicateGuardRemovalResult8616:
    """Internal AST mutation result paired with its typed validation fact."""

    removed_condition: object
    fact: LoopHeaderDuplicateGuardRemovalFact8616


@dataclass(slots=True)
class UnconsumedLoopBreakJccStats8616:
    """Evidence counters for unconsumed loop-break JCC materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refused_existing_condition: int = 0
    refused_no_fallthrough_jump: int = 0
    refused_decode: int = 0
    refused_no_loop_anchor: int = 0
    refused_duplicate_guard: int = 0
    removed_loop_header_duplicate_guard: int = 0
    split_loop_header_condition_chain: int = 0
    ast_query_count: int = 0
    ast_query_build_count: int = 0
    ast_query_hit_count: int = 0
    ast_query_invalidation_count: int = 0


@dataclass(frozen=True, slots=True)
class _LoopBreakInitialSurface8616:
    """Read-only AST projections captured before loop-break mutation starts."""

    condition_keys: frozenset[tuple[int, int]]
    loop_header_jcc_addrs: frozenset[int]
    typed_loop_condition_jcc_addrs: frozenset[int]
    break_nodes_by_key: tuple[tuple[tuple[int, int], tuple[object, ...]], ...]


@dataclass(frozen=True, slots=True)
class _LoopBreakAstSubtreeSurface8616:
    """Syntax-only membership projections for one unchanged AST subtree."""

    root: object
    nodes: tuple[object, ...]
    node_ids: frozenset[int]
    instruction_addresses: frozenset[int]


@dataclass(slots=True)
class _LoopBreakAstQuerySession8616:
    """Reuse syntax-only subtree queries until structuring mutates the AST."""

    _surfaces: dict[int, _LoopBreakAstSubtreeSurface8616] = field(default_factory=dict)
    query_count: int = 0
    build_count: int = 0
    hit_count: int = 0
    invalidation_count: int = 0

    def _surface(self, root: object) -> _LoopBreakAstSubtreeSurface8616:
        """Return one current subtree surface with closed query accounting."""
        self.query_count += 1
        marker = id(root)
        cached = self._surfaces.get(marker)
        if cached is not None and cached.root is root:
            self.hit_count += 1
            return cached
        nodes = tuple(_iter_c_nodes_deep_8616(root))
        surface = _LoopBreakAstSubtreeSurface8616(
            root=root,
            nodes=nodes,
            node_ids=frozenset(id(node) for node in nodes),
            instruction_addresses=frozenset(
                int(address)
                for node in nodes
                if isinstance((tags := _dynamic_attr_8616(node, "tags", None)), (Mapping, Tags))
                and isinstance((address := tags.get("ins_addr")), int)
            ),
        )
        self._surfaces[marker] = surface
        self.build_count += 1
        return surface

    def contains_instruction(self, root: object, target_addr: int) -> bool:
        """Return whether one unchanged subtree carries an exact instruction tag."""
        return int(target_addr) in self._surface(root).instruction_addresses

    def contains_node(self, root: object, target: object) -> bool:
        """Return whether one unchanged subtree contains a node by identity."""
        return id(target) in self._surface(root).node_ids

    def nodes(self, root: object) -> tuple[object, ...]:
        """Return current subtree nodes in deterministic traversal order."""
        return self._surface(root).nodes

    def record_mutation(self) -> None:
        """Invalidate every cached subtree after a reported AST mutation."""
        self._surfaces.clear()
        self.invalidation_count += 1

    def record_stats(self, stats: UnconsumedLoopBreakJccStats8616) -> None:
        """Publish closed acceleration accounting on the owning pass stats."""
        if self.query_count != self.build_count + self.hit_count:
            raise PipelineHardError("loop-break AST query accounting is not closed")
        stats.ast_query_count += self.query_count
        stats.ast_query_build_count += self.build_count
        stats.ast_query_hit_count += self.hit_count
        stats.ast_query_invalidation_count += self.invalidation_count


@dataclass(frozen=True, slots=True)
class UnconsumedLoopBreakJccCallbacks8616:
    """Dynamic adapters for CFG/JCC proof and C AST expression handling."""

    linear_jcc_block_starts: Callable[[object, object], tuple[tuple[int, object], ...]]
    branch_target_imm: Callable[[object], int | None]
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None]
    resolve_one_hop_jmp_target: Callable[[object, int | None], int | None]
    translate_cmp_jcc_guard: Callable[[object, object, int, int], object | None]
    decoded_condition_expr: Callable[[object, object, object, dict[str, int]], object | None]
    inverted_condition_expr: Callable[[object, object, object, dict[str, int]], object | None]
    expr_fingerprint: Callable[[object, object], str]
    same_c_expression: Callable[[object, object], bool]
    clone_c_value: Callable[[object], object]
    record_condition_evidence: Callable[[object, object, object | None, object], None]


class _LoopBreakJccCodegenLike8616(Protocol):
    """Structural view of dynamic angr/codegen state used by loop-break JCC repair."""

    cfunc: object
    _inertia_typed_conditions: object
    _inertia_loop_branch_guard_facts_8616: tuple[LoopBranchGuardFact8616, ...]
    _inertia_loop_header_duplicate_guard_removal_facts_8616: tuple[
        LoopHeaderDuplicateGuardRemovalFact8616,
        ...,
    ]
    _inertia_unconsumed_loop_break_jcc_stats_8616: UnconsumedLoopBreakJccStats8616


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Dynamic boundary: read optional angr/codegen C AST attributes."""
    return getattr(obj, name, default)


def _dynamic_sequence_8616(obj: object) -> tuple[object, ...]:
    """Return a tuple from a dynamic angr/codegen boundary sequence-like object."""
    if isinstance(obj, tuple):
        return obj
    if isinstance(obj, list):
        return tuple(obj)
    return ()


def _condition_body_pairs_8616(obj: object) -> tuple[tuple[object, object | None], ...]:
    """Return condition/body pairs from a dynamic CIfElse boundary value."""
    pairs: list[tuple[object, object | None]] = []
    for item in _dynamic_sequence_8616(obj):
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        condition, body = item
        pairs.append((condition, body))
    return tuple(pairs)


def _typed_condition_body_pair_8616(condition: object, body: CStatement) -> list[tuple[CExpression, CStatement | None]]:
    """Return a typed single-pair CIfElse condition/body list."""
    return [(cast(CExpression, condition), body)]


def _dynamic_int_8616(obj: object, default: int = -1) -> int:
    """Return an integer from a dynamic angr/codegen boundary value."""
    if isinstance(obj, int):
        return int(obj)
    if isinstance(obj, str):
        try:
            return int(obj, 0)
        except ValueError:
            return default
    return default


def _root_contains_ins_addr_8616(
    root: object,
    target_addr: int,
    query_session: _LoopBreakAstQuerySession8616 | None = None,
) -> bool:
    """Return whether a C AST subtree carries the instruction address tag."""
    if root is None:
        return False
    if query_session is not None:
        return query_session.contains_instruction(root, target_addr)
    for node in _iter_c_nodes_deep_8616(root):
        tags = _dynamic_attr_8616(node, "tags", None)
        if isinstance(tags, (Mapping, Tags)) and tags.get("ins_addr") == int(target_addr):
            return True
    return False


def _condition_tags_8616(condition: object) -> tuple[int, int] | None:
    """Extract the JCC proof tag pair from a C AST condition."""
    tags = _dynamic_attr_8616(condition, "tags", None)
    if not isinstance(tags, (Mapping, Tags)):
        return None
    ins_addr = tags.get("ins_addr")
    block_addr = tags.get("vex_block_addr")
    if isinstance(ins_addr, int) and isinstance(block_addr, int):
        return int(ins_addr), int(block_addr)
    return None


def _typed_conditions_by_key_8616(codegen: object) -> dict[tuple[int, int], tuple[ConditionIR, ...]]:
    """Index transferred ConditionIR facts by exact branch and block identity."""
    raw_conditions = _dynamic_attr_8616(codegen, "_inertia_typed_conditions", ())
    if not isinstance(raw_conditions, (list, tuple)):
        return {}
    candidates: dict[tuple[int, int], list[ConditionIR]] = {}
    for condition in raw_conditions:
        if not isinstance(condition, ConditionIR):
            continue
        if not isinstance(condition.src_insn, int) or not isinstance(condition.block_addr, int):
            continue
        key = (int(condition.src_insn), int(condition.block_addr))
        bucket = candidates.setdefault(key, [])
        if condition not in bucket:
            bucket.append(condition)
    return {key: tuple(values) for key, values in candidates.items()}


def _typed_conditions_for_branch_8616(
    conditions_by_key: dict[tuple[int, int], tuple[ConditionIR, ...]],
    *,
    jcc_addr: int,
    block_addr: int,
    body_target: int,
    fallthrough_target: int,
) -> tuple[ConditionIR, ...]:
    """Select exact typed branch evidence across equivalent block boundaries."""
    exact = conditions_by_key.get((jcc_addr, block_addr), ())
    if exact:
        return exact
    same_jcc = tuple(
        dict.fromkeys(
            condition
            for (candidate_jcc, _candidate_block), conditions in conditions_by_key.items()
            if candidate_jcc == jcc_addr
            for condition in conditions
        )
    )
    target_matches = tuple(
        condition
        for condition in same_jcc
        if _typed_condition_matches_jcc_targets_8616(
            condition,
            body_target=body_target,
            fallthrough_target=fallthrough_target,
        )
    )
    return target_matches if target_matches else same_jcc


def _typed_condition_matches_jcc_targets_8616(
    condition: ConditionIR,
    *,
    body_target: int,
    fallthrough_target: int,
) -> bool:
    """Require typed targets to match the direct binary branch edges exactly."""
    return (
        isinstance(condition.taken_target, int)
        and int(condition.taken_target) == int(body_target)
        and isinstance(condition.fallthrough_target, int)
        and int(condition.fallthrough_target) == int(fallthrough_target)
    )


def _instruction_fallthrough_target_8616(jcc: object) -> int | None:
    """Return the direct fallthrough address for one dynamic instruction."""
    address = _dynamic_int_8616(_dynamic_attr_8616(jcc, "address", -1))
    size = _dynamic_int_8616(_dynamic_attr_8616(jcc, "size", 0), default=0)
    if address < 0 or size <= 0:
        return None
    return address + size


def _invert_materialized_condition_8616(
    condition: CExpression,
    codegen: object,
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
    tags: dict[str, int],
) -> CExpression:
    """Invert a typed comparison while preserving exact JCC provenance."""
    inverted_ops = {
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
    }
    if isinstance(condition, CBinaryOp) and condition.op in inverted_ops:
        return CBinaryOp(
            inverted_ops[condition.op],
            cast(CExpression, callbacks.clone_c_value(condition.lhs)),
            cast(CExpression, callbacks.clone_c_value(condition.rhs)),
            codegen=codegen,
            tags=dict(tags),
        )
    return CUnaryOp(
        "Not",
        cast(CExpression, callbacks.clone_c_value(condition)),
        codegen=codegen,
        tags=dict(tags),
    )


def _break_guard_condition_8616(node: object) -> object | None:
    """Return the condition for C AST break-guard shapes."""
    if isinstance(node, CIfBreak):
        return _dynamic_attr_8616(node, "condition", None)
    if not isinstance(node, CIfElse):
        return None
    if _dynamic_attr_8616(node, "else_node", None) is not None:
        return None
    pairs = _condition_body_pairs_8616(_dynamic_attr_8616(node, "condition_and_nodes", ()))
    if len(pairs) != 1:
        return None
    condition, body = pairs[0]
    if isinstance(body, CBreak):
        return condition
    if not isinstance(body, CStatements):
        return None
    statements = _dynamic_sequence_8616(_dynamic_attr_8616(body, "statements", ()))
    return condition if len(statements) == 1 and isinstance(statements[0], CBreak) else None


def _set_break_guard_condition_8616(node: object, condition: object) -> bool:
    """Replace the condition for supported C AST break-guard shapes."""
    if isinstance(node, CIfBreak):
        node.condition = condition
        return True
    if not isinstance(node, CIfElse):
        return False
    if _dynamic_attr_8616(node, "else_node", None) is not None:
        return False
    pairs = _condition_body_pairs_8616(_dynamic_attr_8616(node, "condition_and_nodes", ()))
    if len(pairs) != 1:
        return False
    _old_condition, body = pairs[0]
    if isinstance(body, CBreak):
        node.condition_and_nodes = _typed_condition_body_pair_8616(condition, body)
        return True
    if not isinstance(body, CStatements):
        return False
    statements = _dynamic_sequence_8616(_dynamic_attr_8616(body, "statements", ()))
    if len(statements) != 1 or not isinstance(statements[0], CBreak):
        return False
    node.condition_and_nodes = _typed_condition_body_pair_8616(condition, body)
    return True


def _collect_loop_break_initial_surface_8616(
    root: object,
) -> _LoopBreakInitialSurface8616:
    """Collect all pre-mutation loop-break projections in one AST walk."""
    condition_keys: set[tuple[int, int]] = set()
    loop_header_jcc_addrs: set[int] = set()
    typed_loop_condition_jcc_addrs: set[int] = set()
    break_nodes_by_key: dict[tuple[int, int], list[object]] = {}
    for node in _iter_c_nodes_deep_8616(root):
        for condition, _body in _condition_body_pairs_8616(
            _dynamic_attr_8616(node, "condition_and_nodes", ())
        ):
            key = _condition_tags_8616(condition)
            if key is not None:
                condition_keys.add(key)
        condition = _dynamic_attr_8616(node, "condition", None)
        condition_key = _condition_tags_8616(condition)
        if condition_key is not None:
            condition_keys.add(condition_key)
        if (
            isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop))
            and isinstance(_dynamic_attr_8616(node, "body", None), CStatements)
            and condition_key is not None
        ):
            loop_header_jcc_addrs.add(condition_key[0])
            tags = _dynamic_attr_8616(condition, "tags", None)
            if (
                isinstance(tags, (Mapping, Tags))
                and tags.get("inertia_typed_loop_condition_bound_8616") is True
            ):
                typed_loop_condition_jcc_addrs.add(condition_key[0])
        break_condition = _break_guard_condition_8616(node)
        break_key = _condition_tags_8616(break_condition)
        if break_key is not None:
            break_nodes_by_key.setdefault(break_key, []).append(node)
    return _LoopBreakInitialSurface8616(
        condition_keys=frozenset(condition_keys),
        loop_header_jcc_addrs=frozenset(loop_header_jcc_addrs),
        typed_loop_condition_jcc_addrs=frozenset(typed_loop_condition_jcc_addrs),
        break_nodes_by_key=tuple(
            (key, tuple(nodes)) for key, nodes in sorted(break_nodes_by_key.items())
        ),
    )


def _semantic_break_guards_in_loop_8616(
    loop_body: CStatements,
    *,
    project: object,
    guard_condition: object,
    guard_condition_fingerprint: str,
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
) -> tuple[object, ...]:
    """Return untagged or tagged break guards with one exact condition."""
    expected = _normalized_condition_fingerprint_8616(
        guard_condition_fingerprint
    )
    guards: list[object] = []
    seen: set[int] = set()
    for node in (loop_body, *_iter_c_nodes_deep_8616(loop_body)):
        condition = _break_guard_condition_8616(node)
        marker = id(node)
        if condition is None or marker in seen:
            continue
        actual = _normalized_condition_fingerprint_8616(
            callbacks.expr_fingerprint(condition, project)
        )
        same_storage = same_condition_storage_identity_8616(
            condition,
            guard_condition,
            same_expression=callbacks.same_c_expression,
        )
        if actual != expected and not same_storage:
            continue
        seen.add(marker)
        guards.append(node)
    return tuple(guards)


def _root_contains_node_8616(
    root: object,
    target: object,
    query_session: _LoopBreakAstQuerySession8616 | None = None,
) -> bool:
    """Return whether a dynamic C AST subtree contains a node by identity."""
    if query_session is not None:
        return query_session.contains_node(root, target)
    if root is target:
        return True
    return any(node is target for node in _iter_c_nodes_deep_8616(root))


def _loop_nodes_with_body_8616(
    root: object,
    query_session: _LoopBreakAstQuerySession8616 | None = None,
) -> tuple[CForLoop | CWhileLoop | CDoWhileLoop, ...]:
    """Return loop nodes that have a statement-list body."""
    loops: list[CForLoop | CWhileLoop | CDoWhileLoop] = []
    seen: set[int] = set()
    nodes = (
        query_session.nodes(root)
        if query_session is not None
        else tuple(_iter_c_nodes_deep_8616(root))
    )
    for node in nodes:
        if not isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            continue
        marker = id(node)
        if marker in seen:
            continue
        seen.add(marker)
        if isinstance(_dynamic_attr_8616(node, "body", None), CStatements):
            loops.append(node)
    return tuple(loops)


def _normalized_condition_fingerprint_8616(value: str) -> str:
    """Return the lossless IR-normalized condition identity for exact joins."""
    return str(
        normalize_condition_fingerprint_algebraic_8616(
            normalize_condition_fingerprint_string_8616(
                canonicalize_condition_storage_fingerprint_8616(value)
            )
        )
    )


def _existing_nonbreak_branch_consumes_jcc_8616(
    root: object,
    *,
    project: object,
    body_target: int,
    false_target: int,
    decoded_condition_fingerprint: str,
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
    query_session: _LoopBreakAstQuerySession8616,
) -> bool:
    """Return whether an exact non-break branch already owns the decoded JCC.

    angr may drop JCC tags while retaining an ``if`` whose body is anchored at
    the taken target.  That branch consumes the JCC even when it sits inside an
    unconditional loop; treating it as a missing loop exit would synthesize a
    contradictory break before the already-recovered branch.
    """
    expected = _normalized_condition_fingerprint_8616(
        decoded_condition_fingerprint
    )
    matches = 0
    for node in query_session.nodes(root):
        if not isinstance(node, CIfElse):
            continue
        if _break_guard_condition_8616(node) is not None:
            continue
        for condition, body in _condition_body_pairs_8616(
            _dynamic_attr_8616(node, "condition_and_nodes", ())
        ):
            if body is None:
                continue
            actual = _normalized_condition_fingerprint_8616(
                callbacks.expr_fingerprint(condition, project)
            )
            if actual != expected:
                continue
            if not _root_contains_ins_addr_8616(body, body_target, query_session):
                continue
            if _root_contains_ins_addr_8616(body, false_target, query_session):
                continue
            matches += 1
    return matches == 1


def _loop_headers_consuming_jcc_8616(
    root: object,
    *,
    project: object,
    body_target: int,
    false_target: int,
    exit_target: int | None,
    decoded_condition_fingerprint: str,
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
    query_session: _LoopBreakAstQuerySession8616,
) -> tuple[CForLoop | CWhileLoop | CDoWhileLoop, ...]:
    """Return the unique enclosing loop header that represents the JCC."""
    expected = _normalized_condition_fingerprint_8616(
        decoded_condition_fingerprint
    )
    matches: list[CForLoop | CWhileLoop | CDoWhileLoop] = []
    for loop_node in _loop_nodes_with_body_8616(root, query_session):
        loop_body = _dynamic_attr_8616(loop_node, "body", None)
        if not isinstance(loop_body, CStatements):
            continue
        if not _root_contains_ins_addr_8616(loop_body, body_target, query_session):
            continue
        if _root_contains_ins_addr_8616(loop_body, false_target, query_session):
            continue
        if (
            isinstance(exit_target, int)
            and _root_contains_ins_addr_8616(loop_body, exit_target, query_session)
        ):
            continue
        actual = _normalized_condition_fingerprint_8616(
            callbacks.expr_fingerprint(loop_node.condition, project)
        )
        if actual == expected:
            matches.append(loop_node)
    return tuple(matches) if len(matches) == 1 else ()


def _first_statement_index_containing_ins_addr_8616(
    statements: Sequence[object],
    target_addr: int,
    query_session: _LoopBreakAstQuerySession8616 | None = None,
) -> int | None:
    """Return the first statement index anchored at an instruction address."""
    for idx, stmt in enumerate(statements):
        if _root_contains_ins_addr_8616(stmt, int(target_addr), query_session):
            return idx
    return None


def _remove_loop_header_duplicate_break_guard_8616(
    project: object,
    loop_node: CForLoop | CWhileLoop | CDoWhileLoop,
    loop_body: CStatements,
    break_nodes: tuple[object, ...],
    *,
    key: tuple[int, int],
    decoded_condition: object,
    guard_condition: object,
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
) -> _LoopHeaderDuplicateGuardRemovalResult8616 | None:
    """Remove one exact JCC break already represented by the loop header."""
    loop_condition = loop_node.condition
    loop_condition_key = _condition_tags_8616(loop_condition)
    if loop_condition_key is None or loop_condition_key[0] != key[0]:
        return None
    decoded_matches = (
        callbacks.expr_fingerprint(loop_condition, project)
        == callbacks.expr_fingerprint(decoded_condition, project)
        or callbacks.same_c_expression(loop_condition, decoded_condition)
    )
    if not decoded_matches:
        return None
    statements = list(_dynamic_sequence_8616(loop_body.statements))
    candidates: list[tuple[int, object]] = []
    for break_node in break_nodes:
        current_condition = _break_guard_condition_8616(break_node)
        if current_condition is None:
            continue
        guard_matches = (
            callbacks.expr_fingerprint(current_condition, project)
            == callbacks.expr_fingerprint(guard_condition, project)
            or callbacks.same_c_expression(current_condition, guard_condition)
        )
        if not guard_matches:
            continue
        direct_indexes = [
            index
            for index, statement in enumerate(statements)
            if statement is break_node
        ]
        if len(direct_indexes) == 1:
            candidates.append((direct_indexes[0], current_condition))
    if len(candidates) != 1:
        return None
    remove_index, removed_condition = candidates[0]
    fact = LoopHeaderDuplicateGuardRemovalFact8616(
        jcc_addr=key[0],
        block_addr=key[1],
        removed_guard_fingerprint=callbacks.expr_fingerprint(
            removed_condition,
            project,
        ),
        retained_loop_fingerprint=callbacks.expr_fingerprint(
            loop_condition,
            project,
        ),
    )
    del statements[remove_index]
    loop_body.statements = statements
    return _LoopHeaderDuplicateGuardRemovalResult8616(
        removed_condition=removed_condition,
        fact=fact,
    )


def _condition_jcc_addrs_8616(condition: object) -> frozenset[int]:
    """Return every exact JCC address attached to one condition tree."""
    addresses: set[int] = set()
    for node in (condition, *_iter_c_nodes_deep_8616(condition)):
        key = _condition_tags_8616(node)
        if key is not None:
            addresses.add(key[0])
    return frozenset(addresses)


def _logical_and_prefix_matches_8616(
    project: object,
    condition: object,
    decoded_condition: object,
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
) -> bool:
    """Return whether a collapsed loop chain starts with one decoded JCC."""
    if (
        isinstance(condition, CBinaryOp)
        and condition.op == "CmpNE"
        and isinstance(condition.rhs, CConstant)
        and condition.rhs.value == 0
    ):
        condition = condition.lhs
    if not isinstance(condition, CBinaryOp) or condition.op != "LogicalAnd":
        return False
    prefix = condition.lhs
    while isinstance(prefix, CBinaryOp) and prefix.op == "LogicalAnd":
        prefix = prefix.lhs
    expected = _normalized_condition_fingerprint_8616(
        callbacks.expr_fingerprint(decoded_condition, project)
    )
    actual = _normalized_condition_fingerprint_8616(
        callbacks.expr_fingerprint(prefix, project)
    )
    return bool(expected) and (
        actual == expected
        or callbacks.same_c_expression(prefix, decoded_condition)
    )


def _condition_matches_decoded_8616(
    project: object,
    condition: object,
    decoded_condition: object,
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
) -> bool:
    """Return whether a loop condition has one decoded semantic predicate."""
    expected = _normalized_condition_fingerprint_8616(
        callbacks.expr_fingerprint(decoded_condition, project)
    )
    actual = _normalized_condition_fingerprint_8616(
        callbacks.expr_fingerprint(condition, project)
    )
    if os.environ.get("INERTIA_DEBUG_JCC_REWRITE"):
        logging.getLogger(__name__).warning(
            "[unconsumed-loop-break-jcc] split semantic condition "
            "expected=%s actual=%s type=%s op=%r",
            expected,
            actual,
            type(condition).__name__,
            _dynamic_attr_8616(condition, "op", None),
        )
    return bool(expected) and (
        actual == expected
        or callbacks.same_c_expression(condition, decoded_condition)
    )


def _body_break_guard_for_fact_8616(
    loop_body: CStatements,
    fact: LoopBranchGuardFact8616,
    *,
    project: object,
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
) -> tuple[object, object] | None:
    """Return one exact body break and condition for a binary JCC fact."""
    expected = _normalized_condition_fingerprint_8616(
        fact.guard_condition_fingerprint
    )
    matches: list[tuple[object, object]] = []
    for node in (loop_body, *_iter_c_nodes_deep_8616(loop_body)):
        condition = _break_guard_condition_8616(node)
        if condition is None:
            continue
        key = _condition_tags_8616(condition)
        if key is None or key[0] != fact.jcc_addr:
            continue
        actual = _normalized_condition_fingerprint_8616(
            callbacks.expr_fingerprint(condition, project)
        )
        if actual == expected:
            matches.append((node, condition))
    return matches[0] if len(matches) == 1 else None


def _split_materialized_loop_header_condition_chains_8616(
    project: object,
    root: object,
    codegen: object,
    decoded_conditions_by_jcc: Mapping[int, CExpression],
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
    stats: UnconsumedLoopBreakJccStats8616,
    query_session: _LoopBreakAstQuerySession8616,
) -> bool:
    """Move a fully materialized CFG suffix out of a collapsed loop header.

    angr may collapse consecutive body JCCs and their side effects into a
    short-circuit loop condition. The loop-break materializer then restores
    the same effects and guards in the body from exact binary evidence. Once
    every suffix JCC is represented there, keep only the first loop JCC and
    remove its now-redundant body break. This restores the binary CFG shape
    without deleting or inventing an effect.
    """
    if not decoded_conditions_by_jcc:
        return False
    facts_by_jcc = {
        fact.jcc_addr: fact
        for fact in loop_branch_guard_facts_8616(codegen)
    }
    changed = False
    debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
    for loop_node in _loop_nodes_with_body_8616(root, query_session):
        changed = _split_loop_header_chain_8616(
            project,
            codegen,
            loop_node,
            decoded_conditions_by_jcc,
            facts_by_jcc,
            callbacks,
            stats,
            query_session,
            debug_jcc,
        ) or changed
    return changed


def _split_loop_header_chain_8616(
    project: object,
    codegen: object,
    loop_node: CForLoop | CWhileLoop | CDoWhileLoop,
    decoded_conditions_by_jcc: Mapping[int, CExpression],
    facts_by_jcc: dict[int, LoopBranchGuardFact8616],
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
    stats: UnconsumedLoopBreakJccStats8616,
    query_session: _LoopBreakAstQuerySession8616,
    debug_jcc: bool,
) -> bool:
    """Split one collapsed loop header when every suffix JCC is materialized."""
    loop_body = cast(CStatements, loop_node.body)
    statements = _dynamic_sequence_8616(loop_body.statements)
    if not statements:
        return False
    first_guard = _break_guard_condition_8616(statements[0])
    first_key = _condition_tags_8616(first_guard)
    if first_guard is None or first_key is None:
        return False
    first_fact = facts_by_jcc.get(first_key[0])
    decoded_condition = decoded_conditions_by_jcc.get(first_key[0])
    if first_fact is None or decoded_condition is None:
        return False
    condition_matches = _condition_matches_decoded_8616(
        project,
        loop_node.condition,
        decoded_condition,
        callbacks,
    ) or _logical_and_prefix_matches_8616(
        project,
        loop_node.condition,
        decoded_condition,
        callbacks,
    )
    header_jccs = _condition_jcc_addrs_8616(loop_node.condition)
    if debug_jcc:
        logging.getLogger(__name__).warning(
            "[unconsumed-loop-break-jcc] split candidate first=%#x "
            "condition_matches=%s header_jccs=%r branch_jccs=%r body_types=%r",
            first_fact.jcc_addr,
            condition_matches,
            tuple(sorted(header_jccs)),
            tuple(sorted(facts_by_jcc)),
            tuple(type(statement).__name__ for statement in statements[:5]),
        )
    if not condition_matches:
        return False
    if not _suffix_chain_proven_8616(
        project,
        loop_body,
        first_fact,
        header_jccs,
        facts_by_jcc,
        callbacks,
        query_session,
    ):
        return False
    retained_condition = callbacks.clone_c_value(decoded_condition)
    if not isinstance(retained_condition, CExpression):
        return False
    removed_fingerprint = callbacks.expr_fingerprint(first_guard, project)
    retained_fingerprint = callbacks.expr_fingerprint(
        retained_condition,
        project,
    )
    fact = LoopHeaderDuplicateGuardRemovalFact8616(
        jcc_addr=first_fact.jcc_addr,
        block_addr=first_fact.block_addr,
        removed_guard_fingerprint=removed_fingerprint,
        retained_loop_fingerprint=retained_fingerprint,
    )
    rebuilt = list(statements)
    del rebuilt[0]
    loop_body.statements = rebuilt
    loop_node.condition = retained_condition
    query_session.record_mutation()
    _record_loop_header_duplicate_guard_removal_fact_8616(codegen, fact)
    callbacks.record_condition_evidence(
        project,
        codegen,
        first_guard,
        retained_condition,
    )
    stats.materialized_count += 1
    stats.removed_loop_header_duplicate_guard += 1
    stats.split_loop_header_condition_chain += 1
    return True


def _suffix_chain_proven_8616(
    project: object,
    loop_body: CStatements,
    first_fact: LoopBranchGuardFact8616,
    header_jccs: frozenset[int],
    facts_by_jcc: dict[int, LoopBranchGuardFact8616],
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
    query_session: _LoopBreakAstQuerySession8616,
) -> bool:
    """Return whether every collapsed suffix JCC has a proven body guard."""
    suffix_jccs = (header_jccs & facts_by_jcc.keys()) - {
        first_fact.jcc_addr
    }
    body_effect_addrs = header_jccs - facts_by_jcc.keys() - {
        first_fact.jcc_addr
    }
    if not _root_contains_ins_addr_8616(
        loop_body,
        first_fact.body_target,
        query_session,
    ):
        return False
    if _root_contains_ins_addr_8616(
        loop_body,
        first_fact.false_target,
        query_session,
    ):
        return False
    if any(
        not _root_contains_ins_addr_8616(
            loop_body,
            effect_addr,
            query_session,
        )
        for effect_addr in body_effect_addrs
    ):
        return False
    suffix_guards = tuple(
        _body_break_guard_for_fact_8616(
            loop_body,
            facts_by_jcc[jcc_addr],
            project=project,
            callbacks=callbacks,
        )
        for jcc_addr in sorted(suffix_jccs)
        if jcc_addr in facts_by_jcc
    )
    return len(suffix_guards) == len(suffix_jccs) and all(
        guard is not None for guard in suffix_guards
    )


def _unconsumed_loop_break_jcc_stats_8616(codegen: object) -> UnconsumedLoopBreakJccStats8616:
    """Return or initialize codegen counters for this structuring repair."""
    stats = _dynamic_attr_8616(codegen, "_inertia_unconsumed_loop_break_jcc_stats_8616", None)
    if isinstance(stats, UnconsumedLoopBreakJccStats8616):
        return stats
    stats = UnconsumedLoopBreakJccStats8616()
    typed_codegen = cast(_LoopBreakJccCodegenLike8616, codegen)
    typed_codegen._inertia_unconsumed_loop_break_jcc_stats_8616 = stats
    return stats


def loop_branch_guard_facts_8616(
    codegen: object,
) -> tuple[LoopBranchGuardFact8616, ...]:
    """Return the owned typed loop-branch guard fact contract."""
    typed_codegen = cast(_LoopBreakJccCodegenLike8616, codegen)
    try:
        facts = typed_codegen._inertia_loop_branch_guard_facts_8616
    except AttributeError:
        return ()
    if not isinstance(facts, tuple):
        raise TypeError("loop-branch guard facts must be a tuple")
    if not all(isinstance(fact, LoopBranchGuardFact8616) for fact in facts):
        raise TypeError(
            "loop-branch guard facts must contain only LoopBranchGuardFact8616"
        )
    return facts


def loop_header_duplicate_guard_removal_facts_8616(
    codegen: object,
) -> tuple[LoopHeaderDuplicateGuardRemovalFact8616, ...]:
    """Return exact Structuring-owned redundant loop-guard removal facts."""
    typed_codegen = cast(_LoopBreakJccCodegenLike8616, codegen)
    try:
        facts = typed_codegen._inertia_loop_header_duplicate_guard_removal_facts_8616
    except AttributeError:
        return ()
    if not isinstance(facts, tuple):
        raise TypeError("loop-header duplicate guard removal facts must be a tuple")
    if not all(
        isinstance(fact, LoopHeaderDuplicateGuardRemovalFact8616)
        for fact in facts
    ):
        raise TypeError(
            "loop-header duplicate guard removal facts must contain only "
            "LoopHeaderDuplicateGuardRemovalFact8616"
        )
    return facts


def _record_loop_header_duplicate_guard_removal_fact_8616(
    codegen: object,
    fact: LoopHeaderDuplicateGuardRemovalFact8616,
) -> None:
    """Persist one exact redundant loop-guard removal for validation."""
    existing_facts = loop_header_duplicate_guard_removal_facts_8616(codegen)
    for existing in existing_facts:
        if existing.jcc_addr == fact.jcc_addr and existing != fact:
            raise PipelineHardError(
                "conflicting loop-header duplicate guard removal facts "
                f"jcc={fact.jcc_addr:#x} block={fact.block_addr:#x}"
            )
    typed_codegen = cast(_LoopBreakJccCodegenLike8616, codegen)
    typed_codegen._inertia_loop_header_duplicate_guard_removal_facts_8616 = (
        tuple(dict.fromkeys((*existing_facts, fact)))
    )


def _record_loop_branch_guard_fact_8616(
    codegen: object,
    fact: LoopBranchGuardFact8616,
) -> None:
    """Persist one exact Structuring-owned loop-branch guard fact."""
    existing_facts = loop_branch_guard_facts_8616(codegen)
    retained: list[LoopBranchGuardFact8616] = []
    for existing in existing_facts:
        same_branch = existing.jcc_addr == fact.jcc_addr
        if same_branch and existing != fact:
            raise PipelineHardError(
                "conflicting loop-branch guard facts "
                f"jcc={fact.jcc_addr:#x} block={fact.block_addr:#x} "
                f"existing={existing!r} new={fact!r}"
            )
        retained.append(existing)
    retained.append(fact)
    typed_codegen = cast(_LoopBreakJccCodegenLike8616, codegen)
    typed_codegen._inertia_loop_branch_guard_facts_8616 = tuple(
        dict.fromkeys(retained)
    )


@dataclass(slots=True)
class _LoopBreakJccScan8616:
    """Mutable per-function scan state for unconsumed loop-break JCCs."""

    project: object
    codegen: object
    callbacks: UnconsumedLoopBreakJccCallbacks8616
    stats: UnconsumedLoopBreakJccStats8616
    root: object
    query_session: _LoopBreakAstQuerySession8616
    topology: LoopBreakTopology8616 | None
    existing_condition_keys: frozenset[tuple[int, int]]
    existing_loop_header_jcc_addrs: frozenset[int]
    typed_loop_condition_jcc_addrs: frozenset[int]
    existing_break_nodes_by_key: dict[tuple[int, int], tuple[object, ...]]
    typed_conditions_by_key: dict[tuple[int, int], tuple[ConditionIR, ...]]
    decoded_conditions_by_jcc: dict[int, CExpression] = field(default_factory=dict)
    changed: bool = False
    log: logging.Logger = field(default_factory=lambda: logging.getLogger(__name__))
    debug_jcc: bool = field(default_factory=lambda: bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")))

    def scan_jcc(self, block_addr: int, jcc: object) -> None:
        """Materialize one JCC's loop-break guard when the proof closes."""
        jcc_addr = _dynamic_int_8616(_dynamic_attr_8616(jcc, "address", -1))
        mnemonic = str(_dynamic_attr_8616(jcc, "mnemonic", "")).lower()
        if jcc_addr < 0 or mnemonic in {"jmp", "ljmp"} or not mnemonic.startswith("j"):
            return
        self.stats.raw_fact_count += 1
        key = (jcc_addr, int(block_addr))
        existing_break_nodes = tuple(
            node
            for existing_key, nodes in self.existing_break_nodes_by_key.items()
            if existing_key[0] == jcc_addr
            for node in nodes
        )
        if jcc_addr in self.typed_loop_condition_jcc_addrs and not existing_break_nodes:
            self.stats.refused_existing_condition += 1
            return
        has_existing_condition_without_break = (
            any(existing_key[0] == jcc_addr for existing_key in self.existing_condition_keys)
            and not existing_break_nodes
        )
        targets = self._targets_8616(block_addr, jcc_addr, jcc, key)
        if targets is None:
            return
        body_target, fallthrough_target, false_target, exit_target = targets
        self.stats.normalized_fact_count += 1

        tags: dict[str, int] = {
            "ins_addr": jcc_addr,
            "vex_block_addr": int(block_addr),
            "inertia_jcc_materialized_8616": True,
        }
        decoded = self._decode_8616(
            key, jcc_addr, int(block_addr), mnemonic,
            int(body_target), int(fallthrough_target), int(false_target), exit_target, tags,
        )
        if decoded is None:
            return
        guard_cond, decoded_cond, typed_condition = decoded
        self._materialize_8616(
            key,
            jcc_addr,
            int(block_addr),
            int(body_target),
            int(fallthrough_target),
            int(false_target),
            exit_target,
            guard_cond,
            decoded_cond,
            typed_condition,
            existing_break_nodes,
            has_existing_condition_without_break,
        )

    def _materialize_8616(
        self,
        key: tuple[int, int],
        jcc_addr: int,
        block_addr: int,
        body_target: int,
        fallthrough_target: int,
        false_target: int,
        exit_target: int | None,
        guard_cond: CExpression,
        decoded_cond: CExpression,
        typed_condition: ConditionIR | None,
        existing_break_nodes: tuple[object, ...],
        has_existing_condition_without_break: bool,
    ) -> None:
        """Fingerprint, consume-check, and anchor one decoded JCC guard."""
        fingerprints = self._fingerprints_8616(guard_cond, decoded_cond)
        if fingerprints is None:
            return
        decoded_condition_fingerprint, guard_condition_fingerprint = fingerprints
        if _existing_nonbreak_branch_consumes_jcc_8616(
            self.root,
            project=self.project,
            body_target=body_target,
            false_target=false_target,
            decoded_condition_fingerprint=decoded_condition_fingerprint,
            callbacks=self.callbacks,
            query_session=self.query_session,
        ):
            self.stats.refused_existing_condition += 1
            return
        resolved = self._consuming_break_nodes_8616(
            body_target,
            false_target,
            exit_target,
            decoded_condition_fingerprint,
            guard_cond,
            guard_condition_fingerprint,
            existing_break_nodes,
        )
        if resolved is None:
            return
        existing_break_nodes, cleared_existing_flag = resolved
        if cleared_existing_flag:
            has_existing_condition_without_break = False
        if (
            has_existing_condition_without_break
            and jcc_addr not in self.existing_loop_header_jcc_addrs
        ):
            self.stats.refused_existing_condition += 1
            return
        if existing_break_nodes or has_existing_condition_without_break:
            self.stats.classified_fact_count += 1
        branch_fact = LoopBranchGuardFact8616(
            jcc_addr=jcc_addr,
            block_addr=block_addr,
            body_target=body_target,
            fallthrough_target=fallthrough_target,
            false_target=false_target,
            decoded_condition_fingerprint=decoded_condition_fingerprint,
            guard_condition_fingerprint=guard_condition_fingerprint,
            condition_ir=typed_condition,
        )
        if has_existing_condition_without_break:
            _record_loop_branch_guard_fact_8616(self.codegen, branch_fact)
            self.stats.refused_existing_condition += 1
            return

        materialized_for_key = self._anchor_8616(
            key,
            block_addr,
            body_target,
            fallthrough_target,
            false_target,
            exit_target,
            guard_cond,
            decoded_cond,
            decoded_condition_fingerprint,
            guard_condition_fingerprint,
            branch_fact,
            existing_break_nodes,
        )
        if not materialized_for_key:
            if self.debug_jcc:
                self.log.warning(
                    "[unconsumed-loop-break-jcc] refuse loop anchor key=%r body_target=%#x "
                    "false_target=%#x exit_target=%r",
                    key,
                    body_target,
                    false_target,
                    exit_target,
                )
            self.stats.refused_no_loop_anchor += 1

    def _targets_8616(
        self,
        block_addr: int,
        jcc_addr: int,
        jcc: object,
        key: tuple[int, int],
    ) -> tuple[int, int, int, int | None] | None:
        """Resolve body/fallthrough/false targets or count the refusal."""
        body_target = self.callbacks.branch_target_imm(jcc)
        fallthrough_target = _instruction_fallthrough_target_8616(jcc)
        false_target = self.callbacks.next_unconditional_target_after_jcc(
            self.project, int(block_addr), jcc_addr,
        )
        if body_target is None or fallthrough_target is None or false_target is None:
            if self.debug_jcc:
                self.log.warning(
                    "[unconsumed-loop-break-jcc] refuse targets key=%r body_target=%r "
                    "fallthrough_target=%r false_target=%r",
                    key,
                    body_target,
                    fallthrough_target,
                    false_target,
                )
            self.stats.refused_no_fallthrough_jump += 1
            return None
        exit_target = self.callbacks.resolve_one_hop_jmp_target(self.project, int(false_target))
        return body_target, fallthrough_target, false_target, exit_target

    def _decode_8616(
        self,
        key: tuple[int, int],
        jcc_addr: int,
        block_addr: int,
        mnemonic: str,
        body_target: int,
        fallthrough_target: int,
        false_target: int,
        exit_target: int | None,
        tags: dict[str, int],
    ) -> tuple[CExpression, CExpression, ConditionIR | None] | None:
        """Decode one JCC to guard/decoded conditions or count the refusal."""
        typed_candidates = _typed_conditions_for_branch_8616(
            self.typed_conditions_by_key,
            jcc_addr=jcc_addr,
            block_addr=block_addr,
            body_target=body_target,
            fallthrough_target=fallthrough_target,
        )
        if self.debug_jcc:
            self.log.warning(
                "[unconsumed-loop-break-jcc] candidate key=%r mnemonic=%s body_target=%#x "
                "fallthrough_target=%#x false_target=%#x exit_target=%r typed_candidates=%d",
                key,
                mnemonic,
                body_target,
                fallthrough_target,
                false_target,
                exit_target,
                len(typed_candidates),
            )
        if len(typed_candidates) > 1:
            self.stats.refused_decode += 1
            return None
        typed_condition: ConditionIR | None = None
        if typed_candidates:
            typed_condition = typed_candidates[0]
            if not _typed_condition_matches_jcc_targets_8616(
                typed_condition,
                body_target=body_target,
                fallthrough_target=fallthrough_target,
            ):
                if self.debug_jcc:
                    self.log.warning(
                        "[unconsumed-loop-break-jcc] refuse typed targets key=%r "
                        "typed_taken=%r typed_fallthrough=%r",
                        key,
                        typed_condition.taken_target,
                        typed_condition.fallthrough_target,
                    )
                self.stats.refused_decode += 1
                return None
            decoded_cond = materialize_condition_ir_expression_8616(
                self.project,
                self.codegen,
                typed_condition,
            )
            guard_cond = (
                _invert_materialized_condition_8616(
                    decoded_cond,
                    self.codegen,
                    self.callbacks,
                    tags,
                )
                if decoded_cond is not None
                else None
            )
            if decoded_cond is not None:
                decoded_cond.tags = dict(tags)
        else:
            decoded = self.callbacks.translate_cmp_jcc_guard(
                self.project, self.codegen, block_addr, jcc_addr,
            )
            if decoded is None:
                self.stats.refused_decode += 1
                return None
            guard_cond = self.callbacks.inverted_condition_expr(
                self.project, self.codegen, decoded, tags,
            )
            decoded_cond = self.callbacks.decoded_condition_expr(
                self.project, self.codegen, decoded, tags,
            )
        if not isinstance(guard_cond, CExpression) or not isinstance(
            decoded_cond,
            CExpression,
        ):
            if self.debug_jcc:
                self.log.warning(
                    "[unconsumed-loop-break-jcc] refuse decode key=%r guard=%r decoded=%r",
                    key,
                    guard_cond,
                    decoded_cond,
                )
            self.stats.refused_decode += 1
            return None
        self.decoded_conditions_by_jcc[jcc_addr] = decoded_cond
        return guard_cond, decoded_cond, typed_condition

    def _fingerprints_8616(
        self,
        guard_cond: CExpression,
        decoded_cond: CExpression,
    ) -> tuple[str, str] | None:
        """Return canonicalized condition fingerprints or count the refusal."""
        decoded_condition_fingerprint = (
            canonicalize_condition_storage_fingerprint_8616(
                self.callbacks.expr_fingerprint(
                    decoded_cond,
                    self.project,
                )
            )
        )
        guard_condition_fingerprint = (
            canonicalize_condition_storage_fingerprint_8616(
                self.callbacks.expr_fingerprint(
                    guard_cond,
                    self.project,
                )
            )
        )
        if (
            not decoded_condition_fingerprint
            or not guard_condition_fingerprint
        ):
            self.stats.refused_decode += 1
            return None
        return decoded_condition_fingerprint, guard_condition_fingerprint

    def _consuming_break_nodes_8616(
        self,
        body_target: int,
        false_target: int,
        exit_target: int | None,
        decoded_condition_fingerprint: str,
        guard_cond: CExpression,
        guard_condition_fingerprint: str,
        existing_break_nodes: tuple[object, ...],
    ) -> tuple[tuple[object, ...], bool] | None:
        """Resolve loop-header break nodes or count the existing-condition refusal."""
        consuming_loop_headers = (
            _loop_headers_consuming_jcc_8616(
                self.root,
                project=self.project,
                body_target=body_target,
                false_target=false_target,
                exit_target=exit_target,
                decoded_condition_fingerprint=decoded_condition_fingerprint,
                callbacks=self.callbacks,
                query_session=self.query_session,
            )
            if not existing_break_nodes
            else ()
        )
        if not consuming_loop_headers:
            return existing_break_nodes, False
        resolved_nodes = tuple(
            dict.fromkeys(
                guard
                for loop_node in consuming_loop_headers
                for guard in _semantic_break_guards_in_loop_8616(
                    cast(CStatements, loop_node.body),
                    project=self.project,
                    guard_condition=guard_cond,
                    guard_condition_fingerprint=guard_condition_fingerprint,
                    callbacks=self.callbacks,
                )
            )
        )
        if not resolved_nodes:
            self.stats.refused_existing_condition += 1
            return None
        return resolved_nodes, True

    def _anchor_8616(
        self,
        key: tuple[int, int],
        block_addr: int,
        body_target: int,
        fallthrough_target: int,
        false_target: int,
        exit_target: int | None,
        guard_cond: CExpression,
        decoded_cond: CExpression,
        decoded_condition_fingerprint: str,
        guard_condition_fingerprint: str,
        branch_fact: LoopBranchGuardFact8616,
        existing_break_nodes: tuple[object, ...],
    ) -> bool:
        """Materialize or refuse the guard inside one matching loop anchor."""
        for loop_node in reversed(_loop_nodes_with_body_8616(self.root, self.query_session)):
            loop_body = _dynamic_attr_8616(loop_node, "body", None)
            if not isinstance(loop_body, CStatements):
                continue
            if not _root_contains_ins_addr_8616(
                loop_body,
                body_target,
                self.query_session,
            ):
                continue
            if _root_contains_ins_addr_8616(
                loop_body,
                false_target,
                self.query_session,
            ):
                continue
            if isinstance(exit_target, int) and _root_contains_ins_addr_8616(
                loop_body,
                int(exit_target),
                self.query_session,
            ):
                continue
            if not existing_break_nodes:
                if self._anchor_without_breaks_8616(
                    loop_body,
                    block_addr,
                    body_target,
                    fallthrough_target,
                    false_target,
                    key,
                    guard_cond,
                    guard_condition_fingerprint,
                    decoded_cond,
                    branch_fact,
                ):
                    return True
                continue
            if self._resolve_existing_breaks_8616(
                loop_node,
                loop_body,
                key,
                existing_break_nodes,
                decoded_cond,
                guard_cond,
                decoded_condition_fingerprint,
                guard_condition_fingerprint,
                branch_fact,
                body_target,
                false_target,
            ):
                return True
        return False

    def _anchor_without_breaks_8616(
        self,
        loop_body: CStatements,
        block_addr: int,
        body_target: int,
        fallthrough_target: int,
        false_target: int,
        key: tuple[int, int],
        guard_cond: CExpression,
        guard_condition_fingerprint: str,
        decoded_cond: CExpression,
        branch_fact: LoopBranchGuardFact8616,
    ) -> bool:
        """Census duplicate guards, then attempt the topology-proven insert."""
        semantic_break_guards = _semantic_break_guards_in_loop_8616(
            loop_body,
            project=self.project,
            guard_condition=guard_cond,
            guard_condition_fingerprint=guard_condition_fingerprint,
            callbacks=self.callbacks,
        )
        if len(semantic_break_guards) == 1:
            _record_loop_branch_guard_fact_8616(self.codegen, branch_fact)
            self.stats.refused_duplicate_guard += 1
            return True
        if len(semantic_break_guards) > 1:
            self.stats.refused_duplicate_guard += 1
            return True
        return self._insert_guard_8616(
            loop_body,
            block_addr,
            body_target,
            fallthrough_target,
            false_target,
            key,
            guard_cond,
            decoded_cond,
            branch_fact,
        )

    def _resolve_existing_breaks_8616(
        self,
        loop_node: CForLoop | CWhileLoop | CDoWhileLoop,
        loop_body: CStatements,
        key: tuple[int, int],
        existing_break_nodes: tuple[object, ...],
        decoded_cond: CExpression,
        guard_cond: CExpression,
        decoded_condition_fingerprint: str,
        guard_condition_fingerprint: str,
        branch_fact: LoopBranchGuardFact8616,
        body_target: int,
        false_target: int,
    ) -> bool:
        """Remove a duplicate header guard or rebind one body break."""
        removal = _remove_loop_header_duplicate_break_guard_8616(
            self.project,
            loop_node,
            loop_body,
            existing_break_nodes,
            key=key,
            decoded_condition=decoded_cond,
            guard_condition=guard_cond,
            callbacks=self.callbacks,
        )
        if removal is not None:
            _record_loop_branch_guard_fact_8616(self.codegen, branch_fact)
            _record_loop_header_duplicate_guard_removal_fact_8616(
                self.codegen,
                removal.fact,
            )
            self.callbacks.record_condition_evidence(
                self.project,
                self.codegen,
                removal.removed_condition,
                loop_node.condition,
            )
            self.stats.materialized_count += 1
            self.stats.removed_loop_header_duplicate_guard += 1
            self.changed = True
            self.query_session.record_mutation()
            self.existing_break_nodes_by_key = {
                **self.existing_break_nodes_by_key,
                key: (),
            }
            return True
        if self.debug_jcc:
            self.log.warning(
                "[unconsumed-loop-break-jcc] existing break candidates key=%r count=%d body_target=%#x false_target=%#x",
                key,
                len(existing_break_nodes),
                body_target,
                false_target,
            )
        for break_node in existing_break_nodes:
            if not _root_contains_node_8616(
                loop_body,
                break_node,
                self.query_session,
            ):
                if self.debug_jcc:
                    self.log.warning("[unconsumed-loop-break-jcc] existing break not in loop body key=%r", key)
                continue
            current_condition = _break_guard_condition_8616(break_node)
            current_fp = self.callbacks.expr_fingerprint(current_condition, self.project)
            if (
                current_fp == guard_condition_fingerprint
                or self.callbacks.same_c_expression(
                    current_condition,
                    guard_cond,
                )
                or same_condition_storage_identity_8616(
                    current_condition,
                    guard_cond,
                    same_expression=self.callbacks.same_c_expression,
                )
            ):
                _record_loop_branch_guard_fact_8616(
                    self.codegen,
                    branch_fact,
                )
                self.stats.refused_duplicate_guard += 1
                return True
            if (
                current_fp != decoded_condition_fingerprint
                and not self.callbacks.same_c_expression(
                    current_condition,
                    decoded_cond,
                )
            ):
                continue
            previous_condition = current_condition
            replacement_condition = self.callbacks.clone_c_value(guard_cond)
            if not _set_break_guard_condition_8616(break_node, replacement_condition):
                continue
            _record_loop_branch_guard_fact_8616(
                self.codegen,
                branch_fact,
            )
            self.callbacks.record_condition_evidence(self.project, self.codegen, previous_condition, replacement_condition)
            self.stats.materialized_count += 1
            self.changed = True
            self.query_session.record_mutation()
            return True
        return False

    def _insert_guard_8616(
        self,
        loop_body: CStatements,
        block_addr: int,
        body_target: int,
        fallthrough_target: int,
        false_target: int,
        key: tuple[int, int],
        guard_cond: CExpression,
        decoded_cond: CExpression,
        branch_fact: LoopBranchGuardFact8616,
    ) -> bool:
        """Insert a new break guard after CFG-exit and placement proof."""
        if self.topology is None or not self.topology.proves_exit(
            block_addr, body_target, fallthrough_target, false_target,
        ):
            return False
        body_statements = _dynamic_sequence_8616(_dynamic_attr_8616(loop_body, "statements", ()))
        insert_idx = _first_statement_index_containing_ins_addr_8616(
            body_statements,
            body_target,
            self.query_session,
        )
        if insert_idx is None:
            return False
        # New guards are classified only after CFG exit and placement proof.
        self.stats.classified_fact_count += 1
        guard = CIfBreak(self.callbacks.clone_c_value(guard_cond), codegen=self.codegen, cstyle_ifs=True)
        rebuilt = list(body_statements)
        rebuilt.insert(insert_idx, guard)
        loop_body.statements = rebuilt
        _record_loop_branch_guard_fact_8616(self.codegen, branch_fact)
        self.callbacks.record_condition_evidence(self.project, self.codegen, decoded_cond, guard.condition)
        self.stats.materialized_count += 1
        self.changed = True
        self.query_session.record_mutation()
        self.existing_break_nodes_by_key = {**self.existing_break_nodes_by_key, key: (guard,)}
        return True


def materialize_unconsumed_loop_break_jcc_8616(
    project: object,
    codegen: object,
    callbacks: UnconsumedLoopBreakJccCallbacks8616,
) -> bool:
    """Materialize loop-break guards from unconsumed binary JCC evidence."""
    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
    root = _dynamic_attr_8616(cfunc, "statements", None) if cfunc is not None else None
    if root is None:
        return False
    stats = _unconsumed_loop_break_jcc_stats_8616(codegen)
    initial_surface = _collect_loop_break_initial_surface_8616(root)
    query_session = _LoopBreakAstQuerySession8616()
    scan = _LoopBreakJccScan8616(
        project=project,
        codegen=codegen,
        callbacks=callbacks,
        stats=stats,
        root=root,
        query_session=query_session,
        topology=collect_loop_break_topology_8616(project, codegen),
        existing_condition_keys=initial_surface.condition_keys,
        existing_loop_header_jcc_addrs=initial_surface.loop_header_jcc_addrs,
        typed_loop_condition_jcc_addrs=initial_surface.typed_loop_condition_jcc_addrs,
        existing_break_nodes_by_key=dict(initial_surface.break_nodes_by_key),
        typed_conditions_by_key=_typed_conditions_by_key_8616(codegen),
    )

    for block_addr, jcc in callbacks.linear_jcc_block_starts(project, codegen):
        scan.scan_jcc(block_addr, jcc)

    changed = (
        _split_materialized_loop_header_condition_chains_8616(
            project,
            root,
            codegen,
            scan.decoded_conditions_by_jcc,
            callbacks,
            stats,
            query_session,
        )
        or scan.changed
    )
    query_session.record_stats(stats)
    if stats.raw_fact_count and stats.materialized_count == 0:
        stats.failure_count += 1
    return changed

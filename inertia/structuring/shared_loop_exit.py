# cython: language_level=3, infer_types=True
"""Preserve dispatch exits represented by breaks and a shared epilogue.

Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
Responsibility: bind binary exit evidence to an immutable structured surface.
Validation may compare these read-only snapshots, but must not mint new proof.
No body replacement, rendered-text recovery or effect deletion belongs here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBreak,
    CExpression,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CWhileLoop,
)

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import MemSpace
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.validation.tail_validation_fingerprint import _expr_fingerprint
from inertia.validation.validation_condition_precision import condition_precision_token_8616

from .condition_exit_normalization import transparent_condition_exit_8616
from .existing_loop_exit_conditions import _exit_polarity_8616, _loop_owner_8616
from .loop_break_topology import LoopBreakTopology8616
from .multi_arm_condition_ownership import first_statement_block_8616
import dataclasses
import operator
import builtins

Fingerprint8616 = typing.TypeAliasType("Fingerprint8616", Callable[[object], str])
GuardPath8616 = typing.TypeAliasType("GuardPath8616", tuple[tuple[int, tuple[str, ...]], ...])


class _FingerprintProject8616(Protocol):
    """Dynamic project boundary for a synchronous, isolated fingerprint read."""

    _inertia_tail_validation_expr_fingerprint_cache_8616: object
    _inertia_tail_validation_expr_fingerprint_cache_nodes_8616: object


@cython.ccall
def shared_exit_fingerprint_8616(expression: object, project: object) -> object:
    """Read current AST state without consuming or replacing cached identities.

    Publication and replay are different snapshots: an in-place mutation must
    not reuse the predicate cached at publication. Restore the surrounding
    synchronous worker's cache after this isolated read.
    """
    surface = cast(_FingerprintProject8616, project)
    try:
        previous = surface._inertia_tail_validation_expr_fingerprint_cache_8616
        previous_nodes = surface._inertia_tail_validation_expr_fingerprint_cache_nodes_8616
    except AttributeError:
        previous, previous_nodes = {}, {}
    surface._inertia_tail_validation_expr_fingerprint_cache_8616 = {}
    surface._inertia_tail_validation_expr_fingerprint_cache_nodes_8616 = {}
    try:
        return _expr_fingerprint(expression, project)
    finally:
        surface._inertia_tail_validation_expr_fingerprint_cache_8616 = previous
        surface._inertia_tail_validation_expr_fingerprint_cache_nodes_8616 = previous_nodes


class DispatchExit8616(Protocol):
    """Already-proven dispatch-to-function-exit contract."""

    @property
    def case_value(self) -> cython.longlong:
        """Return the dispatch comparison value."""

    @property
    def case_target(self) -> cython.longlong:
        """Return the binary case entry."""

    @property
    def exit_target(self) -> cython.longlong:
        """Return the proven shared epilogue entry."""


class ExitStatementKind8616(Enum):
    """Permitted straight-line shared epilogue statements."""

    ASSIGNMENT = "assignment"
    RETURN = "return"


@dataclasses.dataclass(frozen=True, )
class ExitStatementSnapshot8616:
    """Immutable target/value identity for one preserved epilogue statement."""

    kind: ExitStatementKind8616
    target: object
    value: object


@dataclasses.dataclass(frozen=True, )
class SharedLoopExitBinding8616:
    """Exact dispatch, guard placement and epilogue identity proven together."""

    case_value: cython.longlong
    case_target: cython.longlong
    exit_target: cython.longlong
    header: cython.longlong
    condition_key: object
    condition_token: object
    loop_token: object
    path: GuardPath8616
    epilogue: object


@dataclasses.dataclass(frozen=True, )
class SharedLoopExitReport8616:
    """Closed accounting for typed input obligations and unique bindings."""

    raw_fact_count: cython.longlong
    bindings: object

    @property
    def normalized_fact_count(self) -> cython.longlong:
        """Return the typed obligation count."""
        return self.raw_fact_count

    @property
    def classified_fact_count(self) -> cython.longlong:
        """Return the uniquely proven binding count."""
        return len(self.bindings)

    @property
    def materialized_count(self) -> cython.longlong:
        """Return the published immutable binding count."""
        return len(self.bindings)

    @property
    def failure_count(self) -> cython.longlong:
        """Return obligations that could not obtain a unique binding."""
        return self.raw_fact_count - self.materialized_count


def _flatten(statements: Sequence[object]) -> Iterator[object]:
    """Flatten sequential wrappers without entering control-flow statements."""
    statement: object
    for statement in statements:
        if isinstance(statement, CStatements):
            yield from _flatten(statement.statements)
        else:
            yield statement


@cython.ccall
def _token(expression: object, fingerprint: Fingerprint8616) -> object:
    """Use the existing immutable precision identity normalization."""
    return condition_precision_token_8616(fingerprint(expression))


@cython.ccall
def _epilogue(
    statements: object, fingerprint: Fingerprint8616,
) -> object:
    """Require assignments followed by exactly one return, never another branch."""
    value: object
    statement: object
    if not statements or not isinstance(statements[-1], CReturn):
        return None
    snapshots: list[ExitStatementSnapshot8616] = []
    for statement in statements[:-1]:
        if not isinstance(statement, CAssignment):
            return None
        snapshots.append(ExitStatementSnapshot8616(
            ExitStatementKind8616.ASSIGNMENT, _token(statement.lhs, fingerprint), _token(statement.rhs, fingerprint),
        ))
    value = statements[-1].retval
    snapshots.append(ExitStatementSnapshot8616(
        ExitStatementKind8616.RETURN, None, None if value is None else _token(value, fingerprint),
    ))
    return tuple(snapshots)


def _guards(
    node: object, fingerprint: Fingerprint8616, path: GuardPath8616 = (),
) -> Iterator[tuple[CExpression, GuardPath8616]]:
    """Keep ancestor polarity and stop at nested loop/switch break scopes."""
    _: object
    body: object
    index: object
    statement: object
    if isinstance(node, CStatements):
        for statement in node.statements:
            yield from _guards(statement, fingerprint, path)
    elif isinstance(node, CIfBreak):
        yield node.condition, path
    elif isinstance(node, CIfElse):
        arms = node.condition_and_nodes
        if len(arms) == 1 and node.else_node is None:
            condition, body = arms[0]
            while isinstance(body, CStatements) and len(body.statements) == 1:
                body = body.statements[0]
            if type(body) is CBreak:
                yield condition, path
        tokens = tuple(_token(condition, fingerprint) for condition, _ in iter(arms))
        for index, (_, body) in enumerate(arms):
            yield from _guards(body, fingerprint, tuple(path) + ((index, tokens),))
        yield from _guards(node.else_node, fingerprint, tuple(path) + ((len(arms), tokens),))


def _surfaces(
    root: object, evidence: DispatchExit8616, fingerprint: Fingerprint8616,
) -> Iterator[tuple[CWhileLoop, SharedLoopExitBinding8616]]:
    """Snapshot current loop exits without interpreting or changing semantics."""
    header: object
    snapshot: object
    condition: object
    container: object
    index: object
    loop: object
    path: object
    seen: set[cython.longlong] = set()
    for container in (root, ) + tuple(_iter_c_nodes_deep_8616(root)):
        if not isinstance(container, CStatements) or id(container) in seen:
            continue
        seen.add(id(container))
        for index, loop in enumerate(container.statements):
            if not isinstance(loop, CWhileLoop):
                continue
            suffix = tuple(_flatten(container.statements[index + 1:]))
            if not suffix or operator.ne(first_statement_block_8616(suffix[0]), evidence.exit_target):
                continue
            snapshot = _epilogue(suffix, fingerprint)
            header = first_statement_block_8616(loop.body)
            if snapshot is None or header is None:
                continue
            for condition, path in _guards(loop.body, fingerprint):
                key = condition.tags.get("ins_addr"), condition.tags.get("vex_block_addr")
                if not all(isinstance(address, int) and not isinstance(address, bool) for address in iter(key)):
                    continue
                if condition.tags.get("inertia_structuring_condition_cfg_materialized_8616") is not True:
                    continue
                yield loop, SharedLoopExitBinding8616(
                    evidence.case_value, evidence.case_target, evidence.exit_target, header,
                    (int(key[0]), int(key[1])), _token(condition, fingerprint),
                    _token(loop.condition, fingerprint), path, snapshot,
                )


def _proven(
    loop: CWhileLoop, binding: SharedLoopExitBinding8616, facts: object,
    topology: LoopBreakTopology8616, artifact: SSAFunctionArtifact | None,
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
) -> cython.bint:
    """Join exact condition ownership and empty connectors to binary exit evidence."""
    exit_edge: object
    owner: object
    polarity: object
    owner = _loop_owner_8616(loop, topology)
    candidates = tuple(fact for fact in iter(facts) if operator.eq((fact.src_insn, fact.block_addr), binding.condition_key))
    if owner is None or operator.ne(owner.header, binding.header) or len(candidates) != 1:
        return False
    fact = candidates[0]
    polarity = _exit_polarity_8616(fact, owner, topology)
    if polarity is None or fact.op not in ("eq", "ne") or operator.ne(polarity, (fact.op == "eq")):
        return False
    if fact.rhs is None or fact.rhs.space is not MemSpace.CONST or operator.ne(fact.rhs.const, binding.case_value):
        return False
    exit_edge = fact.taken_target if polarity else fact.fallthrough_target
    if exit_edge is None:
        return False
    return operator.eq(transparent_condition_exit_8616(
        artifact, exit_edge, successors, stop_at=fact.block_addr,
        retained_targets=frozenset((binding.case_target,)),
    ), binding.case_target)


def prove_shared_loop_exits_8616(
    root: object, evidence: Sequence[DispatchExit8616], facts: object,
    topology: object, artifact: SSAFunctionArtifact | None,
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]], fingerprint: Fingerprint8616,
) -> SharedLoopExitReport8616:
    """Publish only uniquely proven current dispatch-to-shared-epilogue bindings."""
    obligation: object
    bindings: list[SharedLoopExitBinding8616] = []
    for obligation in evidence:
        matches = tuple(
            binding for loop, binding in builtins.iter(_surfaces(root, obligation, fingerprint))
            if topology is not None and _proven(loop, binding, facts, topology, artifact, successors)
        )
        if len(matches) == 1:
            bindings.append(matches[0])
    return SharedLoopExitReport8616(len(evidence), tuple(bindings))


def matching_shared_loop_exits_8616(
    root: object, evidence: DispatchExit8616, bindings: object,
    fingerprint: Fingerprint8616,
) -> tuple[SharedLoopExitBinding8616, ...]:
    """Compare immutable proof with the current surface; never establish new proof."""
    return tuple(binding for _, binding in builtins.iter(_surfaces(root, evidence, fingerprint)) if binding in bindings)

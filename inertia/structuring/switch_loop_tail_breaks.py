# cython: language_level=3, infer_types=True
"""Collapse proven switch exits that target a loop-tail label.

Layer: Structuring.
Responsibility: replace exact C-AST gotos from switch arms to the immediately
following loop-tail label with ``break`` and remove that now-unreferenced label.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

This pass owns only CFG-equivalent region collapse after condition
materialization. It does not infer branch meaning, recover conditions, inspect
assembly or rendered C, or repair calls/types. A candidate is refused unless
the integer target, unique label, complete reference census, and nearest
breakable scope all prove that ``break`` has the same destination as ``goto``.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBreak,
    CDoWhileLoop,
    CForLoop,
    CGoto,
    CIfElse,
    CIncompleteSwitchCase,
    CLabel,
    CStatement,
    CStatements,
    CSwitchCase,
    CWhileLoop,
)

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
import dataclasses
import operator
import builtins


class SwitchLoopTailBreakDecision8616(StrEnum):
    """Typed outcome for one adjacent switch-and-label candidate."""

    MATERIALIZED = "materialized"
    REFUSED_EXECUTABLE_SUFFIX = "refused_executable_suffix"
    REFUSED_UNPROVEN_LABEL_TARGET = "refused_unproven_label_target"
    REFUSED_AMBIGUOUS_LABEL = "refused_ambiguous_label"
    REFUSED_NO_TARGET_GOTO = "refused_no_target_goto"
    REFUSED_NESTED_BREAKABLE = "refused_nested_breakable"
    REFUSED_AMBIGUOUS_GOTO_TARGET = "refused_ambiguous_goto_target"
    REFUSED_EXTERNAL_TARGET_REFERENCE = "refused_external_target_reference"
    REFUSED_MISSING_CODEGEN = "refused_missing_codegen"


@dataclasses.dataclass(frozen=True, )
class SwitchLoopTailBreakStats8616:
    """Closed evidence accounting for switch-loop tail collapse."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True, )
class SwitchLoopTailBreakMaterialization8616:
    """One exact loop-tail target and its replaced switch-arm gotos."""

    target: cython.longlong
    replaced_goto_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class SwitchLoopTailBreakResult8616:
    """Mutation and typed-decision report for one Structuring pass."""

    replaced_goto_count: cython.longlong = 0
    removed_label_count: cython.longlong = 0
    materializations: tuple[SwitchLoopTailBreakMaterialization8616, ...] = ()
    decisions: tuple[SwitchLoopTailBreakDecision8616, ...] = ()
    stats: SwitchLoopTailBreakStats8616 = SwitchLoopTailBreakStats8616()

    @property
    def changed(self) -> cython.bint:
        """Return whether this pass changed the C AST."""
        return self.replaced_goto_count > 0 or self.removed_label_count > 0


@dataclasses.dataclass(frozen=True, )
class _SwitchLoopTailCandidate8616:
    """Exact adjacent switch/label topology inside one loop body."""

    loop_body: CStatements
    switch: CSwitchCase
    label: CLabel
    label_index: cython.longlong


class SwitchLoopTailBreakInvariantError8616(RuntimeError):
    """Raised when classified Structuring evidence cannot be materialized."""


def _statement_children_8616(node: CStatement) -> tuple[CStatement, ...]:
    """Return explicit statement children for the supported angr C AST."""
    if isinstance(node, CStatements):
        return tuple(cast(Iterable[CStatement], node.statements or ()))
    if isinstance(node, CIfElse):
        children = [
            body
            for _condition, body in builtins.iter(tuple(node.condition_and_nodes or ()))
            if isinstance(body, CStatement)
        ]
        if isinstance(node.else_node, CStatement):
            children.append(node.else_node)
        return tuple(children)
    if isinstance(node, CSwitchCase):
        children = [body for _case_value, body in builtins.iter(tuple(node.cases or ()))]
        if isinstance(node.default, CStatement):
            children.append(node.default)
        return tuple(children)
    if isinstance(node, CIncompleteSwitchCase):
        children = [node.head] if isinstance(node.head, CStatement) else []
        children.extend(body for _case_value, body in builtins.iter(tuple(node.cases or ())))
        return tuple(children)
    if isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop)) and isinstance(node.body, CStatement):
        return (node.body,)
    return ()


def _loop_tail_candidates_8616(loop: object) -> tuple[_SwitchLoopTailCandidate8616, ...]:
    """Collect adjacent switch/label facts from one concrete loop body."""
    if not isinstance(loop, (CWhileLoop, CDoWhileLoop, CForLoop)) or not isinstance(loop.body, CStatements):
        return ()
    statements = tuple(cast(Iterable[CStatement], loop.body.statements or ()))
    return tuple(
        _SwitchLoopTailCandidate8616(loop.body, statement, statements[index + 1], index + 1)
        for index, statement in builtins.iter(enumerate(statements[:-1]))
        if isinstance(statement, CSwitchCase) and isinstance(statements[index + 1], CLabel)
    )


@cython.ccall
def _label_target_8616(label: CLabel) -> int | None:
    """Return the binary instruction target carried by one C label."""
    target: object
    target = label.tags.get("ins_addr")
    return target if isinstance(target, int) else None


@cython.ccall
def _collect_case_target_gotos_8616(
    node: object,
    target: cython.longlong,
    *,
    inside_nested_breakable: cython.bint,
    safe: object,
    unsafe: object,
) -> None:
    """Partition matching case gotos by their nearest breakable owner."""
    child: object
    if node is None:
        return
    if isinstance(node, CGoto):
        if operator.eq(node.target, target):
            (unsafe if inside_nested_breakable else safe).append(node)
        return
    nested = inside_nested_breakable or isinstance(
        node,
        (CSwitchCase, CIncompleteSwitchCase, CWhileLoop, CDoWhileLoop, CForLoop),
    )
    for child in _statement_children_8616(node):
        _collect_case_target_gotos_8616(
            child,
            target,
            inside_nested_breakable=nested,
            safe=safe,
            unsafe=unsafe,
        )


@cython.ccall
def _switch_target_gotos_8616(
    switch: CSwitchCase,
    target: cython.longlong,
) -> tuple[tuple[CGoto, ...], tuple[CGoto, ...]]:
    """Return convertible and nested-breakable gotos for one switch."""
    _case_value: object
    body: object
    safe: list[CGoto] = []
    unsafe: list[CGoto] = []
    for _case_value, body in tuple(switch.cases or ()):
        _collect_case_target_gotos_8616(
            body,
            target,
            inside_nested_breakable=False,
            safe=safe,
            unsafe=unsafe,
        )
    if isinstance(switch.default, CStatement):
        _collect_case_target_gotos_8616(
            switch.default,
            target,
            inside_nested_breakable=False,
            safe=safe,
            unsafe=unsafe,
        )
    return tuple(safe), tuple(unsafe)


@cython.ccall
def _replace_gotos_8616(
    node: CStatement,
    replacements: object,
) -> tuple[CStatement, cython.longlong]:
    """Replace preclassified goto identities while preserving AST parents."""
    replacement: object
    body: object
    child: object
    condition: object
    statement: object
    replacement = replacements.get(id(node))
    if replacement is not None:
        return replacement, 1
    replaced = 0
    if isinstance(node, CStatements):
        statements: list[CStatement] = []
        for statement in cast(Iterable[CStatement], node.statements or ()):
            updated, count = _replace_gotos_8616(statement, replacements)
            statements.append(updated)
            replaced += count
        node.statements = statements
        return node, replaced
    if isinstance(node, CIfElse):
        arms = []
        for condition, body in tuple(node.condition_and_nodes or ()):
            if isinstance(body, CStatement):
                body, count = _replace_gotos_8616(body, replacements)
                replaced += count
            arms.append((condition, body))
        node.condition_and_nodes = arms
        if isinstance(node.else_node, CStatement):
            node.else_node, count = _replace_gotos_8616(node.else_node, replacements)
            replaced += count
        return node, replaced
    for child in _statement_children_8616(node):
        _updated, count = _replace_gotos_8616(child, replacements)
        replaced += count
    return node, replaced


@cython.dataclasses.dataclass()
class _TailBreakScan8616:
    """Mutable counters and decision log for one tail-break scan."""

    root: object
    raw_count: cython.longlong = 0
    normalized_count: cython.longlong = 0
    classified_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0
    replaced_count: cython.longlong = 0
    removed_count: cython.longlong = 0
    materializations: object = field(
        default_factory=list
    )
    decisions: object = field(default_factory=list)

    @cython.ccall
    def _refuse(self, decision: SwitchLoopTailBreakDecision8616) -> None:
        """Record one refused candidate with its typed decision."""
        self.decisions.append(decision)
        self.failure_count += 1

    def process(self, candidate: _SwitchLoopTailCandidate8616) -> None:
        """Validate and materialize one switch-loop tail candidate."""
        target: object
        self.raw_count += 1
        statements = tuple(cast(Iterable[CStatement], candidate.loop_body.statements or ()))
        if operator.ne(candidate.label_index, len(statements) - 1):
            self._refuse(SwitchLoopTailBreakDecision8616.REFUSED_EXECUTABLE_SUFFIX)
            return
        target = _label_target_8616(candidate.label)
        if target is None:
            self._refuse(SwitchLoopTailBreakDecision8616.REFUSED_UNPROVEN_LABEL_TARGET)
            return
        matching_labels = tuple(
            node
            for node in builtins.iter(_iter_c_nodes_deep_8616(self.root))
            if isinstance(node, CLabel) and operator.eq(_label_target_8616(node), target)
        )
        if len(matching_labels) != 1 or matching_labels[0] is not candidate.label:
            self._refuse(SwitchLoopTailBreakDecision8616.REFUSED_AMBIGUOUS_LABEL)
            return
        self.normalized_count += 1
        safe_gotos, unsafe_gotos = _switch_target_gotos_8616(candidate.switch, target)
        if unsafe_gotos:
            self._refuse(SwitchLoopTailBreakDecision8616.REFUSED_NESTED_BREAKABLE)
            return
        if not safe_gotos:
            self._refuse(SwitchLoopTailBreakDecision8616.REFUSED_NO_TARGET_GOTO)
            return
        all_target_gotos = tuple(
            node
            for node in builtins.iter(_iter_c_nodes_deep_8616(self.root))
            if isinstance(node, CGoto) and operator.eq(node.target, target)
        )
        if any(goto.target_idx is not None for goto in iter(all_target_gotos)):
            self._refuse(SwitchLoopTailBreakDecision8616.REFUSED_AMBIGUOUS_GOTO_TARGET)
            return
        safe_ids = {id(goto) for goto in iter(safe_gotos)}
        if operator.ne({id(goto) for goto in iter(all_target_gotos)}, safe_ids):
            self._refuse(SwitchLoopTailBreakDecision8616.REFUSED_EXTERNAL_TARGET_REFERENCE)
            return
        if any(goto.codegen is None for goto in iter(safe_gotos)):
            self._refuse(SwitchLoopTailBreakDecision8616.REFUSED_MISSING_CODEGEN)
            return
        self.classified_count += 1
        self._materialize(candidate, statements, target, safe_gotos)

    @cython.ccall
    def _materialize(
        self,
        candidate: _SwitchLoopTailCandidate8616,
        statements: object,
        target: cython.longlong,
        safe_gotos: object,
    ) -> None:
        """Replace proven gotos with breaks and drop the tail label."""
        _case_value: object
        body: object
        replacements = {
            id(goto): CBreak(codegen=goto.codegen, tags=dict(goto.tags))
            for goto in iter(safe_gotos)
        }
        replaced_here = 0
        for _case_value, body in tuple(candidate.switch.cases or ()):
            _updated, count = _replace_gotos_8616(body, replacements)
            replaced_here += count
        if isinstance(candidate.switch.default, CStatement):
            _updated, count = _replace_gotos_8616(candidate.switch.default, replacements)
            replaced_here += count
        if operator.ne(replaced_here, len(replacements)):
            raise SwitchLoopTailBreakInvariantError8616(
                "classified switch-loop tail gotos did not materialize completely"
            )
        candidate.loop_body.statements = list(statements[:-1])
        self.replaced_count += replaced_here
        self.removed_count += 1
        self.materialized_count += 1
        self.materializations.append(
            SwitchLoopTailBreakMaterialization8616(target, replaced_here)
        )
        self.decisions.append(SwitchLoopTailBreakDecision8616.MATERIALIZED)


def materialize_switch_loop_tail_breaks_8616(root: object) -> SwitchLoopTailBreakResult8616:
    """Collapse only complete, topology-proven switch exits at loop tails."""
    candidate: object
    loop: object
    scan = _TailBreakScan8616(root)
    loops = tuple(
        node
        for node in builtins.iter(_iter_c_nodes_deep_8616(root))
        if isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop))
    )
    for loop in loops:
        for candidate in _loop_tail_candidates_8616(loop):
            scan.process(candidate)

    if operator.ne(scan.classified_count, scan.materialized_count):
        raise SwitchLoopTailBreakInvariantError8616(
            "classified switch-loop tail evidence did not close"
        )
    return SwitchLoopTailBreakResult8616(
        replaced_goto_count=scan.replaced_count,
        removed_label_count=scan.removed_count,
        materializations=tuple(scan.materializations),
        decisions=tuple(scan.decisions),
        stats=SwitchLoopTailBreakStats8616(
            raw_fact_count=scan.raw_count,
            normalized_fact_count=scan.normalized_count,
            classified_fact_count=scan.classified_count,
            materialized_count=scan.materialized_count,
            failure_count=scan.failure_count,
        ),
    )

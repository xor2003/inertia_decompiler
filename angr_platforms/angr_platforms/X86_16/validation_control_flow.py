"""Validate structured control-flow reachability without repairing output.

Layer: Tail validation.
Responsibility: report effectful structured branch bodies that are unreachable
because an immediately preceding equivalent, repeatable guard exits the path.
Forbidden: semantic recovery, source/COD/assembly/rendered-C inspection, AST
mutation, or using validation findings to rewrite control flow.
"""

from __future__ import annotations

import itertools
import logging
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBreak,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CStatements,
    CWhileLoop,
)

from .c_ast_utils import _iter_c_nodes_deep_8616
from .ir.condition_ir import (
    ConditionIR,
    canonicalize_condition_storage_fingerprint_8616,
    invert_condition_fingerprint_string_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)
from .pipeline.structured_ast_query_index import StructuredAstQueryIndex8616
from .structuring.loop_break_jcc import LoopBranchGuardFact8616
from .validation.canonicalize import EquivalenceResult, equivalent_expr_8616
from .validation.control_flow_ast_index import ControlFlowAstIndex8616
from .validation_branch_conditions import BranchConditionIssue8616
from .validation_control_flow_obligations import ControlFlowObligationIssue8616

log: logging.Logger = logging.getLogger(__name__)

__all__ = [
    "ControlFlowIssue8616",
    "ControlFlowIssueKind8616",
    "ControlFlowValidationReport8616",
    "LoopBranchGuardIssue8616",
    "LoopBranchGuardIssueKind8616",
    "validate_structured_control_flow_8616",
]


class ControlFlowIssueKind8616(StrEnum):
    """Structured reachability failures detected by final validation."""

    UNREACHABLE_DUPLICATE_GUARD_BODY = "unreachable-duplicate-guard-body"
    UNPROVEN_ADJACENT_GUARD_RELATION = "unproven-adjacent-guard-relation"


class LoopBranchGuardIssueKind8616(StrEnum):
    """Final loop-branch guard contradictions detected from Structuring facts."""

    CONFLICTING_EVIDENCE = "conflicting-evidence"
    DUPLICATE_GUARD = "duplicate-guard"
    GUARD_OUTSIDE_LOOP = "guard-outside-loop"
    INVALID_EVIDENCE = "invalid-evidence"
    MISSING_GUARD = "missing-guard"
    WRONG_GUARD_SHAPE = "wrong-guard-shape"


@dataclass(frozen=True, order=True, slots=True)
class ControlFlowIssue8616:
    """One unreachable or unproven adjacent guarded body."""

    kind: ControlFlowIssueKind8616
    sequence_index: int
    statement_index: int

    def token(self) -> str:
        """Return a deterministic AST-location fingerprint."""
        return (
            f"{self.kind.value}:sequence={self.sequence_index}:"
            f"statement={self.statement_index}"
        )


@dataclass(frozen=True, order=True, slots=True)
class LoopBranchGuardIssue8616:
    """One final loop-branch guard contradiction for exact JCC evidence."""

    kind: LoopBranchGuardIssueKind8616
    jcc_addr: int
    block_addr: int
    body_target: int
    false_target: int
    match_count: int = 0

    def token(self) -> str:
        """Return a deterministic binary-evidence fingerprint."""
        return (
            f"loop-branch:{self.kind.value}:jcc={self.jcc_addr:#x}:"
            f"block={self.block_addr:#x}:body={self.body_target:#x}:"
            f"false={self.false_target:#x}:matches={self.match_count}"
        )


type ControlFlowValidationIssue8616 = (
    BranchConditionIssue8616
    | ControlFlowIssue8616
    | LoopBranchGuardIssue8616
    | ControlFlowObligationIssue8616
)


@dataclass(frozen=True, slots=True)
class ControlFlowValidationReport8616:
    """Closed evidence-loop counters and structured reachability failures."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    issues: tuple[ControlFlowValidationIssue8616, ...] = ()

    @property
    def failure_count(self) -> int:
        """Return the number of unreachable or unproven guard bodies."""
        return len(self.issues)

    @property
    def passed(self) -> bool:
        """Return whether every classified adjacent guard remains reachable."""
        return (
            self.failure_count == 0
            and self.classified_fact_count == self.materialized_count
        )

    def issue_tokens(self) -> tuple[str, ...]:
        """Return stable issue fingerprints for tail-validation summaries."""
        return tuple(issue.token() for issue in self.issues)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible closed-loop evidence report."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
            "issues": list(self.issue_tokens()),
        }


def _body_has_executable_statement_8616(body: object) -> bool:
    """Return whether a guarded body contains at least one C statement."""
    if body is None:
        return False
    if isinstance(body, CStatements):
        return any(
            _body_has_executable_statement_8616(statement)
            for statement in body.statements
        )
    return True


def _condition_is_repeatable_8616(condition: object) -> bool:
    """Refuse equivalence reasoning when evaluating a condition can mutate state."""
    return not any(
        isinstance(node, (CAssignment, CFunctionCall))
        for node in _iter_c_nodes_deep_8616(condition)
    )


class _TaggedAstNode8616(Protocol):
    """Third-party C AST surface carrying optional instruction tags."""

    tags: Mapping[str, object] | None


def _ast_tags_8616(node: object) -> Mapping[str, object]:
    """Read optional tags at the third-party angr C AST boundary."""
    typed_node = cast(_TaggedAstNode8616, node)
    try:
        tags = typed_node.tags
    except AttributeError:
        return {}
    return tags if isinstance(tags, Mapping) else {}


def _node_ins_addr_8616(node: object) -> int | None:
    """Return one C AST node's exact instruction anchor when available."""
    ins_addr = _ast_tags_8616(node).get("ins_addr")
    return ins_addr if isinstance(ins_addr, int) else None


def _break_guard_condition_8616(node: object) -> object | None:
    """Return the condition for supported final C break-guard shapes."""
    if isinstance(node, CIfBreak):
        return cast(object, node.condition)
    if not isinstance(node, CIfElse) or node.else_node is not None:
        return None
    pairs = tuple(node.condition_and_nodes)
    if len(pairs) != 1:
        return None
    condition, body = pairs[0]
    if isinstance(body, CBreak):
        return cast(object, condition)
    if not isinstance(body, CStatements):
        return None
    statements = tuple(body.statements)
    if len(statements) == 1 and isinstance(statements[0], CBreak):
        return cast(object, condition)
    return None


def _loop_guards_for_fact_8616(
    ast_index: ControlFlowAstIndex8616,
    fact: LoopBranchGuardFact8616,
) -> tuple[CForLoop | CWhileLoop | CDoWhileLoop, ...]:
    """Select tagged loop headers by exact target evidence when available."""
    tagged: tuple[CForLoop | CWhileLoop | CDoWhileLoop, ...] = (
        ast_index.loop_guards(fact.jcc_addr)
    )
    target_matched = tuple(
        loop
        for loop in tagged
        if ast_index.subtree_contains_instruction(loop.body, fact.body_target)
        and not ast_index.subtree_contains_instruction(
            loop.body,
            fact.false_target,
        )
    )
    if target_matched:
        return target_matched
    if len(tagged) == 1:
        return tagged
    return tuple(
        loop
        for loop in tagged
        if _loop_matches_branch_region_8616(ast_index, loop, fact)
    )


def _loop_branch_fact_is_valid_8616(fact: LoopBranchGuardFact8616) -> bool:
    """Return whether one Structuring fact has exact representable identities."""
    if not (
        fact.jcc_addr >= 0
        and fact.block_addr >= 0
        and fact.block_addr <= fact.jcc_addr
        and fact.body_target >= 0
        and fact.fallthrough_target > fact.jcc_addr
        and fact.false_target >= 0
        and fact.body_target != fact.false_target
        and bool(fact.decoded_condition_fingerprint)
        and bool(fact.guard_condition_fingerprint)
    ):
        return False
    decoded = _normalize_condition_fingerprint_8616(
        fact.decoded_condition_fingerprint
    )
    guard = _normalize_condition_fingerprint_8616(
        fact.guard_condition_fingerprint
    )
    inverted = invert_condition_fingerprint_string_8616(decoded)
    return (
        inverted is not None
        and _normalize_condition_fingerprint_8616(inverted) == guard
    )


def _normalize_condition_fingerprint_8616(value: str) -> str:
    """Return the IR-canonical condition fingerprint used for exact joins."""
    return str(
        normalize_condition_fingerprint_algebraic_8616(
            normalize_condition_fingerprint_string_8616(
                canonicalize_condition_storage_fingerprint_8616(value)
            )
        )
    )


def _condition_fingerprint_matches_8616(
    condition: object,
    expected_fingerprint: str,
    condition_fingerprint: Callable[[object], str],
    condition_fingerprint_normalizer: Callable[[str], str] | None,
) -> bool:
    """Match one AST condition, including C scalar truth-value shorthand."""
    actual = _normalize_condition_fingerprint_8616(
        condition_fingerprint(condition)
    )
    expected = _normalize_condition_fingerprint_8616(expected_fingerprint)
    if condition_fingerprint_normalizer is not None:
        actual = _normalize_condition_fingerprint_8616(
            condition_fingerprint_normalizer(actual)
        )
        expected = _normalize_condition_fingerprint_8616(
            condition_fingerprint_normalizer(expected)
        )
    if actual == expected:
        return True
    truth_value = _normalize_condition_fingerprint_8616(
        f"CmpNE({actual},const:0)"
    )
    if condition_fingerprint_normalizer is not None:
        truth_value = _normalize_condition_fingerprint_8616(
            condition_fingerprint_normalizer(truth_value)
        )
    return truth_value == expected


def _loop_matches_branch_region_8616(
    ast_index: ControlFlowAstIndex8616,
    loop: CForLoop | CWhileLoop | CDoWhileLoop,
    fact: LoopBranchGuardFact8616,
) -> bool:
    """Join one loop to the proven JCC region without guessing lost tags."""
    if ast_index.subtree_contains_instruction(loop.body, fact.false_target):
        return False
    if ast_index.subtree_contains_instruction(loop.body, fact.body_target):
        return True
    header_anchors = (
        _node_ins_addr_8616(loop),
        _node_ins_addr_8616(loop.condition),
    )
    return any(
        anchor is not None
        and fact.block_addr <= anchor <= fact.jcc_addr
        for anchor in header_anchors
    )


def _semantic_fingerprint_pair_8616(
    fact: LoopBranchGuardFact8616,
    condition_ir_fingerprint: Callable[[ConditionIR], str | None] | None,
) -> tuple[object, object] | None:
    """Prefer inverted typed-IR fingerprints when the fact carries condition IR."""
    decoded_fingerprint = fact.decoded_condition_fingerprint
    guard_fingerprint = fact.guard_condition_fingerprint
    if fact.condition_ir is not None and condition_ir_fingerprint is not None:
        materialized = condition_ir_fingerprint(fact.condition_ir)
        if materialized is None:
            return None
        inverted = invert_condition_fingerprint_string_8616(materialized)
        if inverted is None:
            return None
        decoded_fingerprint = materialized
        guard_fingerprint = inverted
    return decoded_fingerprint, guard_fingerprint


def _semantic_guard_matches_8616(
    candidate: object,
    expected: object,
    fact: LoopBranchGuardFact8616,
    condition_fingerprint: Callable[[object], str],
    condition_fingerprint_normalizer: Callable[[str], str] | None,
    condition_storage_matcher: Callable[[ConditionIR, object, bool], bool] | None,
    *,
    inverted: bool,
) -> bool:
    """Use typed storage views only when ordinary identity is insufficient."""
    if _condition_fingerprint_matches_8616(
        candidate, expected, condition_fingerprint, condition_fingerprint_normalizer,
    ):
        return True
    return bool(
        fact.condition_ir is not None
        and condition_storage_matcher is not None
        and condition_storage_matcher(fact.condition_ir, candidate, inverted)
    )


def _semantic_loop_branch_guards_8616(
    ast_index: ControlFlowAstIndex8616,
    fact: LoopBranchGuardFact8616,
    condition_fingerprint: Callable[[object], str],
    condition_ir_fingerprint: Callable[[ConditionIR], str | None] | None,
    condition_fingerprint_normalizer: Callable[[str], str] | None,
    condition_storage_matcher: Callable[[ConditionIR, object, bool], bool] | None = None,
) -> tuple[object, ...]:
    """Join an untagged folded guard by exact condition and CFG evidence."""
    pair = _semantic_fingerprint_pair_8616(fact, condition_ir_fingerprint)
    if pair is None:
        return ()
    decoded_fingerprint, guard_fingerprint = pair
    guards: list[object] = []
    seen: set[int] = set()

    def matches(candidate: object, expected: object, *, inverted: bool) -> bool:
        """Dispatch to fingerprint or typed-storage equivalence."""
        return _semantic_guard_matches_8616(
            candidate,
            expected,
            fact,
            condition_fingerprint,
            condition_fingerprint_normalizer,
            condition_storage_matcher,
            inverted=inverted,
        )

    for loop in ast_index.loops:
        if not _loop_matches_branch_region_8616(ast_index, loop, fact):
            continue
        if matches(loop.condition, decoded_fingerprint, inverted=False):
            guards.append(loop)
            seen.add(id(loop))
        for node in ast_index.subtree_nodes(loop.body):
            guard_condition = _break_guard_condition_8616(node)
            if (
                guard_condition is None
                or id(node) in seen
                or not matches(guard_condition, guard_fingerprint, inverted=True)
            ):
                continue
            guards.append(node)
            seen.add(id(node))
    return tuple(guards)


def _adjacent_guard_sequence_issues_8616(
    ast_index: ControlFlowAstIndex8616,
) -> tuple[int, int, int, int, list[ControlFlowValidationIssue8616]]:
    """Count and report adjacent ``if/break`` + ``if`` duplicate-guard pairs."""
    raw_fact_count = 0
    normalized_fact_count = 0
    classified_fact_count = 0
    materialized_count = 0
    issues: list[ControlFlowValidationIssue8616] = []
    sequences = (
        node
        for node in ast_index.nodes
        if isinstance(node, CStatements)
    )
    for sequence_index, sequence in enumerate(sequences):
        statements = tuple(sequence.statements)
        for statement_index, (first, second) in enumerate(
            itertools.pairwise(statements)
        ):
            if not isinstance(first, CIfBreak) or not isinstance(second, CIfElse):
                continue
            raw_fact_count += 1
            if not second.condition_and_nodes:
                continue
            second_condition, second_body = second.condition_and_nodes[0]
            if not _body_has_executable_statement_8616(second_body):
                continue
            if not (
                _condition_is_repeatable_8616(first.condition)
                and _condition_is_repeatable_8616(second_condition)
            ):
                continue
            normalized_fact_count += 1
            equivalence = equivalent_expr_8616(
                first.condition,
                second_condition,
            )
            classified_fact_count += 1
            if equivalence is EquivalenceResult.DIFFERENT:
                materialized_count += 1
                continue
            kind = (
                ControlFlowIssueKind8616.UNREACHABLE_DUPLICATE_GUARD_BODY
                if equivalence is EquivalenceResult.EQUIVALENT
                else ControlFlowIssueKind8616.UNPROVEN_ADJACENT_GUARD_RELATION
            )
            issues.append(
                ControlFlowIssue8616(
                    kind=kind,
                    sequence_index=sequence_index,
                    statement_index=statement_index,
                )
            )
    return (
        raw_fact_count,
        normalized_fact_count,
        classified_fact_count,
        materialized_count,
        issues,
    )


def _loop_branch_issue_8616(
    fact: LoopBranchGuardFact8616,
    kind: LoopBranchGuardIssueKind8616,
    *,
    match_count: int = 0,
) -> LoopBranchGuardIssue8616:
    """Build one deterministic final loop-branch issue."""
    return LoopBranchGuardIssue8616(
        kind=kind,
        jcc_addr=fact.jcc_addr,
        block_addr=fact.block_addr,
        body_target=fact.body_target,
        false_target=fact.false_target,
        match_count=match_count,
    )


def _untagged_loop_branch_verdict_8616(
    ast_index: ControlFlowAstIndex8616,
    fact: LoopBranchGuardFact8616,
    condition_fingerprint: Callable[[object], str] | None,
    condition_ir_fingerprint: Callable[[ConditionIR], str | None] | None,
    condition_fingerprint_normalizer: Callable[[str], str] | None,
    condition_storage_matcher: Callable[[ConditionIR, object, bool], bool] | None,
) -> tuple[int, LoopBranchGuardIssue8616 | None]:
    """Accept one untagged guard only on a unique exact-condition match."""
    semantic_guards = (
        _semantic_loop_branch_guards_8616(
            ast_index,
            fact,
            condition_fingerprint,
            condition_ir_fingerprint,
            condition_fingerprint_normalizer,
            condition_storage_matcher,
        )
        if condition_fingerprint is not None
        else ()
    )
    if len(semantic_guards) == 1:
        return 1, None
    if len(semantic_guards) > 1:
        return 0, _loop_branch_issue_8616(
            fact,
            LoopBranchGuardIssueKind8616.DUPLICATE_GUARD,
            match_count=len(semantic_guards),
        )
    return 0, _loop_branch_issue_8616(
        fact,
        LoopBranchGuardIssueKind8616.MISSING_GUARD,
    )


def _tagged_loop_branch_verdict_8616(
    ast_index: ControlFlowAstIndex8616,
    fact: LoopBranchGuardFact8616,
    tagged_conditions: tuple[object, ...],
    break_guards: tuple[object, ...],
    loop_guards: tuple[object, ...],
    loop_bodies: tuple[object, ...],
) -> tuple[int, LoopBranchGuardIssue8616 | None]:
    """Require exactly one tagged in-loop guard for a tagged loop-branch fact."""
    associated_guards = tuple(
        guard
        for guard in break_guards
        if any(
            ast_index.subtree_contains_node(body, guard)
            for body in loop_bodies
        )
    )
    materialized_guards = (*associated_guards, *loop_guards)
    if break_guards and not associated_guards and not loop_guards:
        return 0, _loop_branch_issue_8616(
            fact,
            LoopBranchGuardIssueKind8616.GUARD_OUTSIDE_LOOP,
            match_count=len(break_guards),
        )
    if not materialized_guards:
        return 0, _loop_branch_issue_8616(
            fact,
            LoopBranchGuardIssueKind8616.WRONG_GUARD_SHAPE,
            match_count=len(tagged_conditions),
        )
    if (
        len(break_guards) != len(associated_guards)
        or len(materialized_guards) != 1
    ):
        return 0, _loop_branch_issue_8616(
            fact,
            LoopBranchGuardIssueKind8616.DUPLICATE_GUARD,
            match_count=len(tagged_conditions),
        )
    return 1, None


def _conflicted_fact_keys_8616(
    facts_by_key: dict[int, list[LoopBranchGuardFact8616]],
) -> tuple[set[int], int, list[LoopBranchGuardIssue8616]]:
    """Mark jcc keys with conflicting facts and count them as classified."""
    conflicted_keys: set[int] = set()
    classified_count = 0
    issues: list[LoopBranchGuardIssue8616] = []
    for key, facts in sorted(facts_by_key.items()):
        if len(facts) <= 1:
            continue
        conflicted_keys.add(key)
        classified_count += len(facts)
        issues.append(
            _loop_branch_issue_8616(
                facts[0],
                LoopBranchGuardIssueKind8616.CONFLICTING_EVIDENCE,
                match_count=len(facts),
            )
        )
    return conflicted_keys, classified_count, issues


def _debug_log_control_flow_8616(
    ast_index: ControlFlowAstIndex8616,
    normalized_loop_branch_facts: tuple[LoopBranchGuardFact8616, ...],
    issues: list[ControlFlowValidationIssue8616],
    condition_fingerprint: Callable[[object], str] | None,
    condition_ir_fingerprint: Callable[[ConditionIR], str | None] | None,
    condition_fingerprint_normalizer: Callable[[str], str] | None,
    condition_storage_matcher: Callable[[ConditionIR, object, bool], bool] | None,
    raw_fact_count: int,
    normalized_fact_count: int,
    classified_fact_count: int,
    materialized_count: int,
) -> None:
    """Emit the optional loop-branch validation diagnostic trace."""
    if not os.environ.get("INERTIA_DEBUG_VALIDATION_CONTROL_FLOW"):
        return
    log.warning(
        "control-flow validation loop_branch_facts=%r matches=%r "
        "semantic_matches=%r loops=%r issues=%r counters=(raw=%d normalized=%d "
        "classified=%d materialized=%d)",
        normalized_loop_branch_facts,
        tuple(
            (
                fact,
                ast_index.tagged_conditions(fact.jcc_addr),
                ast_index.break_guards(fact.jcc_addr),
                ast_index.loop_guards(fact.jcc_addr),
            )
            for fact in normalized_loop_branch_facts
        ),
        tuple(
            (
                fact,
                _semantic_loop_branch_guards_8616(
                    ast_index,
                    fact,
                    condition_fingerprint,
                    condition_ir_fingerprint,
                    condition_fingerprint_normalizer,
                    condition_storage_matcher,
                )
                if condition_fingerprint is not None
                and _loop_branch_fact_is_valid_8616(fact)
                else (),
            )
            for fact in normalized_loop_branch_facts
        ),
        tuple(
            (
                type(loop).__name__,
                _ast_tags_8616(loop),
                _ast_tags_8616(loop.condition),
                condition_fingerprint(loop.condition)
                if condition_fingerprint is not None
                else None,
                tuple(
                    (
                        fact.jcc_addr,
                        ast_index.subtree_contains_instruction(
                            loop.body,
                            fact.body_target,
                        ),
                        ast_index.subtree_contains_instruction(
                            loop.body,
                            fact.false_target,
                        ),
                    )
                    for fact in normalized_loop_branch_facts
                ),
            )
            for loop in ast_index.loops
        ),
        tuple(issue.token() for issue in issues),
        raw_fact_count,
        normalized_fact_count,
        classified_fact_count,
        materialized_count,
    )


def validate_structured_control_flow_8616(
    root: object,
    *,
    query_index: StructuredAstQueryIndex8616 | None = None,
    loop_branch_facts: tuple[LoopBranchGuardFact8616, ...] = (),
    condition_fingerprint: Callable[[object], str] | None = None,
    condition_ir_fingerprint: Callable[[ConditionIR], str | None] | None = None,
    condition_fingerprint_normalizer: Callable[[str], str] | None = None,
    condition_storage_matcher: Callable[[ConditionIR, object, bool], bool] | None = None,
) -> ControlFlowValidationReport8616:
    """Validate final guarded reachability and proven loop-branch presence.

    For ``if (condition) break; if (condition) { body; }``, a repeatable
    condition must be false on every path reaching the second statement.
    Therefore a nonempty second true body is unreachable. Different guards are
    counted as successfully materialized; uncertain equivalence is refused.
    Structuring-owned loop-branch facts additionally require exactly one tagged
    loop-header condition or in-loop break guard. When angr folds away the JCC
    tag, an untagged guard is accepted only by a unique exact condition
    fingerprint plus taken/exit target membership. Validation does not repair it.
    A storage matcher may additionally prove equivalent typed memory views;
    it must retain access width, signedness and the requested branch polarity.
    """
    ast_index = ControlFlowAstIndex8616.build(root, root_index=query_index)
    (
        raw_fact_count,
        normalized_fact_count,
        classified_fact_count,
        materialized_count,
        issues,
    ) = _adjacent_guard_sequence_issues_8616(ast_index)

    normalized_loop_branch_facts = tuple(sorted(set(loop_branch_facts)))
    raw_fact_count += len(loop_branch_facts)
    normalized_fact_count += len(normalized_loop_branch_facts)
    facts_by_key: dict[int, list[LoopBranchGuardFact8616]] = {}
    for fact in normalized_loop_branch_facts:
        facts_by_key.setdefault(fact.jcc_addr, []).append(fact)
    conflicted_keys, conflicted_classified, conflicted_issues = (
        _conflicted_fact_keys_8616(facts_by_key)
    )
    classified_fact_count += conflicted_classified
    issues.extend(conflicted_issues)

    loop_bodies = tuple(loop.body for loop in ast_index.loops)
    for fact in normalized_loop_branch_facts:
        key = fact.jcc_addr
        if key in conflicted_keys:
            continue
        classified_fact_count += 1
        if not _loop_branch_fact_is_valid_8616(fact):
            issues.append(
                _loop_branch_issue_8616(
                    fact,
                    LoopBranchGuardIssueKind8616.INVALID_EVIDENCE,
                )
            )
            continue
        tagged_conditions = ast_index.tagged_conditions(key)
        break_guards = ast_index.break_guards(key)
        loop_guards = _loop_guards_for_fact_8616(ast_index, fact)
        if not tagged_conditions:
            materialized_delta, issue = _untagged_loop_branch_verdict_8616(
                ast_index,
                fact,
                condition_fingerprint,
                condition_ir_fingerprint,
                condition_fingerprint_normalizer,
                condition_storage_matcher,
            )
            materialized_count += materialized_delta
            if issue is not None:
                issues.append(issue)
            continue
        materialized_delta, issue = _tagged_loop_branch_verdict_8616(
            ast_index,
            fact,
            tagged_conditions,
            break_guards,
            loop_guards,
            loop_bodies,
        )
        materialized_count += materialized_delta
        if issue is not None:
            issues.append(issue)
    _debug_log_control_flow_8616(
        ast_index,
        normalized_loop_branch_facts,
        issues,
        condition_fingerprint,
        condition_ir_fingerprint,
        condition_fingerprint_normalizer,
        condition_storage_matcher,
        raw_fact_count,
        normalized_fact_count,
        classified_fact_count,
        materialized_count,
    )
    if not ast_index.stats().is_closed:
        raise RuntimeError("control-flow AST index query accounting is not closed")
    return ControlFlowValidationReport8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_fact_count,
        materialized_count=materialized_count,
        issues=tuple(issues),
    )

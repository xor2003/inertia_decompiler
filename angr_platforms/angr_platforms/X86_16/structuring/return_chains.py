"""CFG-proven return-chain materialization helpers.

Layer: Structuring.
Responsibility: own AST shaping for CFG-proven conditional return chains.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Dynamic boundary: this module receives angr/codegen C AST objects and callback
adapters from compatibility layers while the remaining CFG proof helpers migrate
out of legacy postprocess code.
"""

from __future__ import annotations

import contextlib
import logging
import os
import typing
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDoWhileLoop,
    CExpression,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CGoto,
    CIfElse,
    CReturn,
    CStatement,
    CStatements,
    CTypeCast,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable

from ..callsite_summary import CallerReturnUseVerdict8616
from ..frontend_function_instructions import FunctionInstructionInventory8616
from ..lowering.terminal_call_return_types import CalleeResultContract8616 as TerminalCallResultContract8616
from ..lowering.terminal_return_expressions import (
    return_expression_has_wide_word_composition_8616 as return_expression_has_wide_word_composition_8616,
)
from ..semantics.branch_target_return import (
    BranchTargetReturnEffectKind8616 as BranchTargetReturnEffectKind8616,
)
from ..semantics.branch_target_return import (
    TerminalAxReturnEffect8616 as TerminalAxReturnEffect8616,
)
from ..semantics.branch_target_return import (
    TerminalAxReturnEffectKind8616 as TerminalAxReturnEffectKind8616,
)
from ..semantics.branch_target_return import (
    TerminalAxReturnOperandKind8616 as TerminalAxReturnOperandKind8616,
)
from ..semantics.branch_target_return import (
    branch_target_return_effect_8616 as branch_target_return_effect_8616,
)
from ..semantics.branch_target_return import (
    terminal_ax_return_effect_8616 as terminal_ax_return_effect_8616,
)
from ..semantics.return_register_preservation import instruction_preserves_return_registers_8616
from ..semantics.terminal_call_paths import (
    TerminalCallPathCallbacks8616,
    TerminalCallPathStatus8616,
    prove_terminal_call_path_8616,
)
from .expression_substitution import unique_tagged_conditions_8616
from .multi_arm_return_chains import multi_arm_wide_return_obligation_count_8616
from .return_chain_condition_selection import select_cfg_return_condition_8616
from .return_path_preservation import return_path_preserves_return_registers_8616
from .selector_return_projection import (
    assess_selector_return_projection_8616,
    mask_accumulator_has_unconsumed_effects_8616,
    require_selector_return_projection_8616,
    selector_return_storage_write_obligations_8616,
)
from .surplus_guard_contracts import (
    SurplusGuardCleanupEvidence8616 as SurplusGuardCleanupEvidence8616,
)
from .surplus_guard_contracts import (
    SurplusGuardCleanupStats8616 as SurplusGuardCleanupStats8616,
)
from .terminal_register_values import (
    compose_ax_byte_lanes_8616 as compose_ax_byte_lanes_8616,
)
from .terminal_register_values import (
    terminal_ax_value_supports_widths_8616,
)


class _ReturnChainCFunction8616(Protocol):
    """Dynamic angr/codegen C function object carrying a mutable statement root."""

    addr: int
    statements: object


class _ReturnChainCodegen8616(Protocol):
    """Dynamic angr/codegen object plus Inertia return-chain metadata fields."""

    cfunc: _ReturnChainCFunction8616
    _inertia_cfg_selector_return_stats_8616: dict[str, int]
    _inertia_return_selector_materialized_8616: bool
    _inertia_return_chain_flattened_8616: bool
    _inertia_return_chain_suffix_materialized_8616: bool
    _inertia_return_chain_materialized_values_8616: tuple[int, ...]
    _inertia_return_chain_materialized_condition_fingerprints_8616: tuple[str, ...]
    _inertia_return_chain_final_value_8616: int
    _inertia_empty_return_branch_stats_8616: dict[str, int]
    _inertia_empty_return_branch_refused_unsafe_effects_8616: int
    _inertia_empty_return_branch_values_8616: tuple[int, ...]
    _inertia_return_expr_chain_materialized_8616: bool
    _inertia_return_expr_chain_materialized_return_fingerprints_8616: tuple[str, ...]
    _inertia_mask_accumulator_materialized_8616: bool
    _inertia_mask_accumulator_condition_fingerprints_8616: tuple[str, ...]
    _inertia_mask_accumulator_return_fingerprint_8616: str
    _inertia_mask_accumulator_update_immediates_8616: tuple[int, ...]
    _inertia_decrement_switch_return_materialized_8616: bool
    _inertia_sequential_decrement_switch_return_materialized_8616: bool
    _inertia_return_selector_raw_stack_slot_aliases_8616: dict[str, tuple[str, ...]]


def ensure_return_chain_codegen_state_8616(codegen: object) -> None:
    """Initialize structuring-owned return-chain state on a dynamic angr codegen object."""
    # Dynamic boundary: angr creates CStructuredCodeGenerator instances without
    # these Inertia extension fields. The fields become owned after initialization.
    typed_codegen = cast(_ReturnChainCodegen8616, codegen)
    if not hasattr(codegen, "_inertia_cfg_selector_return_stats_8616") or not isinstance(
        typed_codegen._inertia_cfg_selector_return_stats_8616, dict
    ):
        typed_codegen._inertia_cfg_selector_return_stats_8616 = {"candidates": 0, "materialized": 0, "refused": 0}
    if not hasattr(codegen, "_inertia_empty_return_branch_stats_8616") or not isinstance(
        typed_codegen._inertia_empty_return_branch_stats_8616, dict
    ):
        typed_codegen._inertia_empty_return_branch_stats_8616 = {"candidates": 0, "materialized": 0, "refused": 0}
    if not hasattr(codegen, "_inertia_return_selector_materialized_8616"):
        typed_codegen._inertia_return_selector_materialized_8616 = False
    if not hasattr(codegen, "_inertia_return_chain_flattened_8616"):
        typed_codegen._inertia_return_chain_flattened_8616 = False
    if not hasattr(codegen, "_inertia_return_chain_suffix_materialized_8616"):
        typed_codegen._inertia_return_chain_suffix_materialized_8616 = False
    if not hasattr(codegen, "_inertia_return_chain_materialized_values_8616"):
        typed_codegen._inertia_return_chain_materialized_values_8616 = ()
    if not hasattr(codegen, "_inertia_return_chain_materialized_condition_fingerprints_8616"):
        typed_codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = ()
    if not hasattr(codegen, "_inertia_return_chain_final_value_8616"):
        typed_codegen._inertia_return_chain_final_value_8616 = 0
    if not hasattr(codegen, "_inertia_empty_return_branch_refused_unsafe_effects_8616"):
        typed_codegen._inertia_empty_return_branch_refused_unsafe_effects_8616 = 0
    if not hasattr(codegen, "_inertia_empty_return_branch_values_8616"):
        typed_codegen._inertia_empty_return_branch_values_8616 = ()
    if not hasattr(codegen, "_inertia_return_expr_chain_materialized_8616"):
        typed_codegen._inertia_return_expr_chain_materialized_8616 = False
    if not hasattr(codegen, "_inertia_return_expr_chain_materialized_return_fingerprints_8616"):
        typed_codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = ()
    if not hasattr(codegen, "_inertia_mask_accumulator_materialized_8616"):
        typed_codegen._inertia_mask_accumulator_materialized_8616 = False
    if not hasattr(codegen, "_inertia_mask_accumulator_condition_fingerprints_8616"):
        typed_codegen._inertia_mask_accumulator_condition_fingerprints_8616 = ()
    if not hasattr(codegen, "_inertia_mask_accumulator_return_fingerprint_8616"):
        typed_codegen._inertia_mask_accumulator_return_fingerprint_8616 = ""
    if not hasattr(codegen, "_inertia_mask_accumulator_update_immediates_8616"):
        typed_codegen._inertia_mask_accumulator_update_immediates_8616 = ()
    if not hasattr(codegen, "_inertia_decrement_switch_return_materialized_8616"):
        typed_codegen._inertia_decrement_switch_return_materialized_8616 = False
    if not hasattr(codegen, "_inertia_sequential_decrement_switch_return_materialized_8616"):
        typed_codegen._inertia_sequential_decrement_switch_return_materialized_8616 = False
    if not hasattr(codegen, "_inertia_return_selector_raw_stack_slot_aliases_8616") or not isinstance(
        typed_codegen._inertia_return_selector_raw_stack_slot_aliases_8616, dict
    ):
        typed_codegen._inertia_return_selector_raw_stack_slot_aliases_8616 = {}


class SurplusIfGuardKind8616(Enum):
    """Structured classification for surplus empty-if guard candidates."""

    EMPTY_RETURN = "empty_return"
    EMPTY_NOOP = "empty_noop"
    IDENTICAL_ASSIGNMENT_ARMS = "identical_assignment_arms"


class IdenticalAssignmentArmCollapseStatus8616(Enum):
    """Terminal status for a surplus identical-arm structuring pass."""

    MATERIALIZED = "materialized"
    NO_BRANCH_PROOF = "no_branch_proof"
    WITHIN_BRANCH_BUDGET = "within_branch_budget"
    NO_ELIGIBLE_CANDIDATE = "no_eligible_candidate"


@dataclass(frozen=True, slots=True)
class IdenticalAssignmentArmCollapseStats8616:
    """Closed evidence loop for redundant conditional-arm collapse."""

    status: IdenticalAssignmentArmCollapseStatus8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    branch_count: int | None
    total_if_count: int
    branch_backed_refusal_count: int


class VoidTailCallSuffixDiamondStatus8616(Enum):
    """Structured result for CFG-proven void-tail-call suffix-diamond repair."""

    MATERIALIZED = "materialized"
    NO_SUFFIX = "no_suffix"
    EMPTY_SUFFIX = "empty_suffix"
    BRANCH_MATCH_MISSING_OR_AMBIGUOUS = "branch_match_missing_or_ambiguous"
    FALSE_ARM_MATCHES_TRUE = "false_arm_matches_true"
    SUFFIX_MISSING_TRUE = "suffix_missing_true"
    AMBIGUOUS_SUFFIX_CALL = "ambiguous_suffix_call"


class VoidTailCallGuardStatus8616(Enum):
    """Structured result for CFG-proven plain void-tail-call guard repair."""

    MATERIALIZED = "materialized"
    MISSING_FOLLOWING_TAIL = "missing_following_tail"


@dataclass(frozen=True, slots=True)
class VoidTailCallGuardProof8616:
    """Bind one CFG-proven true branch condition to its tail-call fingerprint."""

    condition: CExpression
    condition_keys: frozenset[object]
    true_fingerprint: str


class DuplicateEmptyReturnGuardPruneReason8616(Enum):
    """Structured reason for pruning a duplicate empty return guard."""

    ADJACENT_DUPLICATE_EMPTY_GUARD = "adjacent_duplicate_empty_guard"
    EMPTY_PREFIX_BEFORE_CHAIN = "empty_prefix_before_chain"
    DUPLICATE_PREFIX_BEFORE_CHAIN = "duplicate_prefix_before_chain"


class ConditionBranchTagEvidence8616(Enum):
    """Structured evidence that a condition tag maps to a real branch instruction."""

    NO_TAG = "no_tag"
    CONDITIONAL_BRANCH = "conditional_branch"
    NON_BRANCH = "non_branch"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ConditionIdentityCallbacks8616:
    """Dynamic adapters needed to fingerprint a structured branch condition."""

    condition_tags: Callable[[object], object]
    expr_fingerprint: Callable[[object, object], str]


@dataclass(frozen=True, slots=True)
class ConditionBranchTagCallbacks8616:
    """Dynamic adapters needed to classify condition tag branch evidence."""

    condition_tags: Callable[[object], object]
    load_block: Callable[[int], object | None]
    is_conditional_branch_insn: Callable[[object], bool]


@dataclass(frozen=True, slots=True)
class ExpressionFingerprintCallbacks8616:
    """Dynamic adapters needed to fingerprint C AST expressions and components."""

    expr_fingerprint: Callable[[object, object], str]
    iter_c_nodes_deep: Callable[[object], Iterable[object]]


@dataclass(frozen=True, slots=True)
class ReturnChainCountCallbacks8616:
    """Dynamic adapters needed to account for structured return-chain AST nodes."""

    iter_c_nodes_deep: Callable[[object], Iterable[object]]


@dataclass(frozen=True, slots=True)
class LastAxReturnValueCallbacks8616:
    """Dynamic adapters needed to scan codegen instructions for final AX return values."""

    function_insns: Callable[[object, object], Iterable[object]]
    signed_i16_immediate: Callable[[int], int]


def _capstone_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Dynamic third-party boundary: read optional Capstone instruction/operand attributes."""
    return getattr(obj, name, default)


def _capstone_int_attr_8616(obj: object, name: str, default: int = 0) -> int:
    """Dynamic third-party boundary: coerce optional Capstone numeric metadata."""
    value = _capstone_attr_8616(obj, name, default)
    return int(value) if isinstance(value, (int, str)) else int(default)


@dataclass(frozen=True, slots=True)
class VoidTailCallShapeCallbacks8616:
    """Dynamic adapters needed to classify void-tail-call guard statement shapes."""

    c_node_semantically_empty: Callable[[object], bool]


@dataclass(frozen=True, slots=True)
class VoidTailCallSuffixDiamondCallbacks8616:
    """Dynamic adapters needed to materialize a CFG-proven suffix diamond."""

    c_node_semantically_empty: Callable[[object], bool]
    calls_in_nodes: Callable[[Iterable[object]], tuple[CFunctionCall, ...]]
    node_component_fingerprints: Callable[[object], frozenset[str]]
    call_argument_component_fingerprints: Callable[[CFunctionCall], frozenset[str]]


@dataclass(frozen=True, slots=True)
class VoidTailCallSuffixDiamondResult8616:
    """Outcome of a suffix-diamond materialization attempt."""

    status: VoidTailCallSuffixDiamondStatus8616
    match_fingerprint: str | None = None
    suffix_types: tuple[str, ...] = ()
    match_count: int = 0
    suffix_from_else: bool = False


@dataclass(frozen=True, slots=True)
class VoidTailCallGuardResult8616:
    """Outcome of a plain void-tail-call guard materialization attempt."""

    status: VoidTailCallGuardStatus8616
    payload_type: str | None = None
    removed_following_tail: bool = False


@dataclass(frozen=True, slots=True)
class DuplicateEmptyReturnGuardPrunePlan8616:
    """Prune plan for a CFG-proven duplicate empty return guard."""

    index: int
    reason: DuplicateEmptyReturnGuardPruneReason8616
    value: int | None = None


@dataclass(frozen=True, slots=True)
class ReturnChainFlattenCallbacks8616:
    """Dynamic adapters needed to compare and rebuild angr C AST return chains."""

    set_cfunc_statements_root: Callable[[_ReturnChainCodegen8616, CStatements], None]
    final_return_value: Callable[[object, object], int | None]
    expr_fingerprint: Callable[[object, object], str]
    iter_c_nodes_deep: Callable[[object], Iterable[object]]
    single_if_return: Callable[[object], tuple[object, object] | None]
    const_return_value: Callable[[object], int | None]


def return_chain_counts_8616(root: object | None, callbacks: ReturnChainCountCallbacks8616) -> tuple[int, int]:
    """Count structured if/return nodes in a materialized return-chain C AST root."""
    if root is None:
        return 0, 0
    if_count = sum(1 for node in callbacks.iter_c_nodes_deep(root) if isinstance(node, CIfElse))
    return_count = sum(1 for node in callbacks.iter_c_nodes_deep(root) if isinstance(node, CReturn))
    return if_count, return_count


def return_chain_expected_counts_8616(codegen: _ReturnChainCodegen8616) -> tuple[int, int] | None:
    """Return minimum if/return counts implied by structuring materialization metadata."""
    if not (codegen._inertia_return_chain_flattened_8616 or codegen._inertia_return_chain_suffix_materialized_8616):
        return None
    values = codegen._inertia_return_chain_materialized_values_8616
    if not values:
        return None
    return len(values), len(values) + 1


def condition_identity_keys_8616(
    project: object,
    cond: object,
    callbacks: ConditionIdentityCallbacks8616,
) -> frozenset[object]:
    """Return stable identity keys for matching CFG branch proof to C AST condition."""
    keys: set[object] = set()
    try:
        tags = callbacks.condition_tags(cond)
    except Exception:
        tags = None
    if isinstance(tags, tuple) and len(tags) == 2 and all(isinstance(item, int) for item in tags):
        keys.add(("tags", tags))
    with contextlib.suppress(Exception):
        keys.add(("fp", callbacks.expr_fingerprint(cond, project)))
    return frozenset(keys)


def condition_branch_tag_evidence_8616(
    cond: object,
    callbacks: ConditionBranchTagCallbacks8616,
) -> ConditionBranchTagEvidence8616:
    """Classify condition tags through a dynamic boundary: third-party Capstone CFG blocks."""
    try:
        tags = callbacks.condition_tags(cond)
    except Exception:
        return ConditionBranchTagEvidence8616.UNKNOWN
    if not (isinstance(tags, tuple) and len(tags) == 2 and all(isinstance(item, int) for item in tags)):
        return ConditionBranchTagEvidence8616.NO_TAG
    try:
        block = callbacks.load_block(int(tags[0]))
    except Exception:
        return ConditionBranchTagEvidence8616.UNKNOWN
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()) if block is not None else ()
    if not insns:
        return ConditionBranchTagEvidence8616.UNKNOWN
    if callbacks.is_conditional_branch_insn(insns[0]):
        return ConditionBranchTagEvidence8616.CONDITIONAL_BRANCH
    return ConditionBranchTagEvidence8616.NON_BRANCH


def condition_has_jcc_evidence_8616(
    cond: object,
    callbacks: ConditionBranchTagCallbacks8616,
) -> bool:
    """Return whether condition tag evidence is branch-backed or conservatively unknown."""
    return condition_branch_tag_evidence_8616(cond, callbacks) in {
        ConditionBranchTagEvidence8616.CONDITIONAL_BRANCH,
        ConditionBranchTagEvidence8616.UNKNOWN,
    }


def call_argument_fingerprints_8616(
    project: object,
    call: CFunctionCall,
    callbacks: ExpressionFingerprintCallbacks8616,
) -> frozenset[str]:
    """Return fingerprints for direct call arguments from a dynamic boundary: angr codegen C AST calls."""
    fingerprints: set[str] = set()
    for arg in tuple(getattr(call, "args", ()) or ()):
        with contextlib.suppress(Exception):
            fingerprints.add(callbacks.expr_fingerprint(arg, project))
    return frozenset(fingerprints)


def call_argument_component_fingerprints_8616(
    project: object,
    call: CFunctionCall,
    callbacks: ExpressionFingerprintCallbacks8616,
) -> frozenset[str]:
    """Return fingerprints for call arguments from a dynamic boundary: angr codegen C AST components."""
    fingerprints: set[str] = set(call_argument_fingerprints_8616(project, call, callbacks))
    for arg in tuple(getattr(call, "args", ()) or ()):
        for node in (arg, *callbacks.iter_c_nodes_deep(arg)):
            with contextlib.suppress(Exception):
                fingerprints.add(callbacks.expr_fingerprint(node, project))
    return frozenset(fingerprints)


def node_component_fingerprints_8616(
    project: object,
    node: object,
    callbacks: ExpressionFingerprintCallbacks8616,
) -> frozenset[str]:
    """Return fingerprints for a C AST node and its nested components."""
    fingerprints: set[str] = set()
    for item in (node, *callbacks.iter_c_nodes_deep(node)):
        with contextlib.suppress(Exception):
            fingerprints.add(callbacks.expr_fingerprint(item, project))
    return frozenset(fingerprints)


def tail_call_from_statement_8616(
    stmt: object,
    callbacks: VoidTailCallShapeCallbacks8616,
) -> CFunctionCall | None:
    """Return the single tail call from a dynamic boundary: angr codegen C AST statements."""
    if isinstance(stmt, CStatements):
        nested = tuple(stmt.statements or ())
        semantic_children = tuple(child for child in nested if not callbacks.c_node_semantically_empty(child))
        if len(semantic_children) == 1:
            return tail_call_from_statement_8616(semantic_children[0], callbacks)
        return None
    if isinstance(stmt, CFunctionCall):
        return stmt
    if isinstance(stmt, CExpressionStatement):
        expr = stmt.expr
        if isinstance(expr, CFunctionCall):
            return expr
    if isinstance(stmt, CReturn):
        retval = stmt.retval
        if isinstance(retval, CFunctionCall):
            return retval
    return None


def flatten_straightline_c_statements_8616(
    stmt: object,
    callbacks: VoidTailCallShapeCallbacks8616,
) -> tuple[object, ...] | None:
    """Flatten straight-line statements from a dynamic boundary: angr codegen C AST."""
    if isinstance(stmt, CStatements):
        flattened: list[object] = []
        for child in tuple(stmt.statements or ()):
            if callbacks.c_node_semantically_empty(child):
                continue
            child_flattened = flatten_straightline_c_statements_8616(child, callbacks)
            if child_flattened is None:
                return None
            flattened.extend(child_flattened)
        return tuple(flattened)
    if isinstance(stmt, (CAssignment, CExpressionStatement, CFunctionCall, CReturn)):
        return (stmt,)
    return None


def tail_call_payload_from_statement_8616(
    stmt: object,
    codegen: object,
    callbacks: VoidTailCallShapeCallbacks8616,
) -> tuple[CFunctionCall, object] | None:
    """Extract tail-call payload from a dynamic boundary: angr codegen C AST statements."""
    direct_call = tail_call_from_statement_8616(stmt, callbacks)
    if direct_call is not None:
        if isinstance(stmt, CReturn):
            return direct_call, CExpressionStatement(direct_call, codegen=codegen)
        if isinstance(stmt, CStatements):
            flat = flatten_straightline_c_statements_8616(stmt, callbacks)
            if flat is not None and len(flat) == 1 and isinstance(flat[0], CReturn):
                return direct_call, CExpressionStatement(direct_call, codegen=codegen)
        return direct_call, stmt

    flat = flatten_straightline_c_statements_8616(stmt, callbacks)
    if flat is None:
        return None

    calls: list[CFunctionCall] = []
    payload: list[object] = []
    for item in flat:
        if isinstance(item, CAssignment):
            payload.append(item)
            continue
        if isinstance(item, CFunctionCall):
            calls.append(item)
            payload.append(item)
            continue
        if isinstance(item, CExpressionStatement):
            expr = item.expr
            if not isinstance(expr, CFunctionCall):
                return None
            calls.append(expr)
            payload.append(item)
            continue
        if isinstance(item, CReturn) and getattr(item, "retval", None) is None:
            payload.append(item)
            continue
        return None

    if len(calls) != 1:
        return None
    if not payload:
        return None
    return calls[0], CStatements(statements=list(payload), codegen=codegen)


def else_node_empty_8616(node: object | None) -> bool:
    """Return whether a dynamic boundary: angr codegen C AST else-node is empty."""
    if node is None:
        return True
    if isinstance(node, CStatements):
        return not list(node.statements or ())
    return False


def c_statement_shape_8616(stmt: object, *, max_depth: int = 3) -> object:
    """Return a bounded shape from a dynamic boundary: angr codegen C AST statements."""
    if max_depth <= 0 or stmt is None:
        return type(stmt).__name__
    if isinstance(stmt, CStatements):
        return (
            type(stmt).__name__,
            tuple(c_statement_shape_8616(child, max_depth=max_depth - 1) for child in tuple(stmt.statements or ())),
        )
    if isinstance(stmt, CReturn):
        return (type(stmt).__name__, type(stmt.retval).__name__)
    if isinstance(stmt, CIfElse):
        condition_nodes = tuple(
            cast(
                Iterable[tuple[object, object]],
                getattr(cast(object, stmt), "condition_and_nodes", ()) or (),
            )
        )
        return (
            type(stmt).__name__,
            tuple(c_statement_shape_8616(body, max_depth=max_depth - 1) for _cond, body in condition_nodes),
            c_statement_shape_8616(stmt.else_node, max_depth=max_depth - 1),
        )
    return type(stmt).__name__


@dataclass(frozen=True, slots=True)
class ReturnSelectorCallbacks8616:
    """Dynamic adapters for CFG-proven selector-return orchestration."""

    materialize_decrement_switch_return_chain: Callable[[object, _ReturnChainCodegen8616], bool]
    ordered_32bit_selector_return_expr_pairs: Callable[
        [object, _ReturnChainCodegen8616], list[tuple[CExpression, CExpression, CExpression]]
    ]
    ordered_conditional_return_expr_pairs: Callable[
        [object, _ReturnChainCodegen8616], list[tuple[CExpression, CExpression, CExpression]]
    ]
    selector_condition_call_addrs: Callable[[list[tuple[CExpression, CExpression, CExpression]]], frozenset[int]]
    selector_condition_call_addrs_from_cfg: Callable[[object, _ReturnChainCodegen8616], frozenset[int]]
    selector_function_has_unsafe_effects: Callable[[object, _ReturnChainCodegen8616, frozenset[int]], bool]
    clone_c_value_for_codegen_tree: Callable[[CExpression], CExpression]
    set_cfunc_statements_root: Callable[[_ReturnChainCodegen8616, CStatements], None]
    expr_fingerprint: Callable[[object, object], str]


@dataclass(frozen=True, slots=True)
class ReturnSelectorCallsiteProofCallbacks8616:
    """Dynamic adapters for selector-return condition-call CFG proof."""

    linear_jcc_block_starts: Callable[[object, object], Iterable[tuple[int, object]]]
    branch_target_imm: Callable[[object], int | None]
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None]
    branch_target_return_expr: Callable[[object, object, int], CExpression | None]
    translate_cmp_jcc_guard: Callable[[object, object, int, int], object | None]
    last_call_addr_before_jcc_in_function: Callable[[object, object, int], int | None]


@dataclass(frozen=True, slots=True)
class ReturnSelector32BitPairCallbacks8616:
    """Dynamic adapters for CFG-proven 32-bit selector-return pair ordering."""

    function_block_addrs: Callable[[object, _ReturnChainCodegen8616], Iterable[int]]
    load_block: Callable[[int], object | None]
    branch_target_imm: Callable[[object], int | None]
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None]
    translate_cmp_jcc_guard: Callable[[object, _ReturnChainCodegen8616, int, int], object | None]
    decoded_condition_expr: Callable[[object, _ReturnChainCodegen8616, object], CExpression | None]
    branch_target_return_expr: Callable[[object, _ReturnChainCodegen8616, int], CExpression | None]


@dataclass(frozen=True, slots=True)
class ReturnConditionalExprPairCallbacks8616:
    """Dynamic adapters for CFG-proven conditional return-expression pair ordering."""

    linear_jcc_block_starts: Callable[[object, _ReturnChainCodegen8616], Iterable[tuple[int, object]]]
    branch_target_imm: Callable[[object], int | None]
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None]
    branch_target_return_expr: Callable[[object, _ReturnChainCodegen8616, int], CExpression | None]
    translate_cmp_jcc_guard: Callable[[object, _ReturnChainCodegen8616, int, int], object | None]
    decoded_condition_expr: Callable[[object, _ReturnChainCodegen8616, object, dict[str, int]], CExpression | None]
    last_call_addr_before_jcc_in_function: Callable[[object, _ReturnChainCodegen8616, int], int | None]


@dataclass(frozen=True, slots=True)
class ReturnConditionalVoidTailCallCallbacks8616:
    """Dynamic adapters for CFG-proven conditional void-tail-call proof ordering."""

    linear_jcc_block_starts: Callable[[object, _ReturnChainCodegen8616], Iterable[tuple[int, object]]]
    branch_target_imm: Callable[[object], int | None]
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None]
    branch_target_return_expr: Callable[[object, _ReturnChainCodegen8616, int], CExpression | None]
    translate_cmp_jcc_guard: Callable[[object, _ReturnChainCodegen8616, int, int], object | None]
    decoded_condition_expr: Callable[[object, _ReturnChainCodegen8616, object], CExpression | None]


@dataclass(frozen=True, slots=True)
class Return32BitConditionalPairCallbacks8616:
    """Dynamic adapters for CFG-proven 32-bit conditional return-value ordering."""

    function_block_addrs: Callable[[object, _ReturnChainCodegen8616], Iterable[int]]
    load_block: Callable[[int], object | None]
    branch_target_imm: Callable[[object], int | None]
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None]
    branch_target_return_value: Callable[[object, int], int | None]
    translate_cmp_jcc_guard: Callable[[object, _ReturnChainCodegen8616, int, int], object | None]
    decoded_condition_expr: Callable[[object, _ReturnChainCodegen8616, object], CExpression | None]
    expr_fingerprint: Callable[[object, object], str]


@dataclass(frozen=True, slots=True)
class MaskAccumulatorPairCallbacks8616:
    """Dynamic adapters for CFG-proven mask-accumulator condition/value ordering."""

    linear_jcc_block_starts: Callable[[object, _ReturnChainCodegen8616], Iterable[tuple[int, object]]]
    selector_targets_from_32bit_jcc_chain: Callable[[int, object], tuple[int, int] | None]
    equality_return_target_from_32bit_jcc_chain: Callable[[int, object], int | None]
    inequality_target_from_32bit_jcc_chain: Callable[[int, object], int | None]
    branch_target_imm: Callable[[object], int | None]
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None]
    or_stack_update_imm: Callable[[object, int, int], int | None]
    translate_cmp_jcc_guard: Callable[[object, _ReturnChainCodegen8616, int, int], object | None]
    decoded_condition_expr: Callable[[object, _ReturnChainCodegen8616, object], CExpression | None]
    expr_fingerprint: Callable[[object, object], str]


@dataclass(frozen=True, slots=True)
class MaskAccumulatorMaterializationCallbacks8616:
    """Dynamic adapters for CFG-proven mask-accumulator AST materialization."""

    first_stack_zero_init: Callable[[object, _ReturnChainCodegen8616], int | None]
    ordered_mask_update_pairs: Callable[[object, _ReturnChainCodegen8616, int], list[tuple[CExpression, int]]]
    stack_slot_expr: Callable[[_ReturnChainCodegen8616, int, int], CExpression | None]
    expr_fingerprint: Callable[[object, object], str]


@dataclass(frozen=True, slots=True)
class SelectorStackExprCallbacks8616:
    """Dynamic adapters for selector stack-expression recovery from instruction evidence."""

    linear_function_insns: Callable[[object, _ReturnChainCodegen8616], Iterable[object]]
    stack_slot_expr: Callable[[_ReturnChainCodegen8616, int, int, object], CExpression | None]


@dataclass(frozen=True, slots=True)
class SequentialDecrementSwitchCallbacks8616:
    """Dynamic adapters for sequential decrement-switch return materialization."""

    set_cfunc_statements_root: Callable[[_ReturnChainCodegen8616, CStatements], None]
    selector_stack_expr: Callable[[object, _ReturnChainCodegen8616], CExpression | None]
    selector_function_has_unsafe_effects: Callable[[object, _ReturnChainCodegen8616], bool]
    selector_raw_stack_aliases: Callable[[object, CExpression], dict[str, tuple[str, ...]]]
    linear_function_insns: Callable[[object, _ReturnChainCodegen8616], Iterable[object]]
    next_linear_jmp_target: Callable[[tuple[object, ...], int], int | None]
    resolve_one_hop_jmp_target: Callable[[object, int | None], int | None]
    branch_target_imm: Callable[[object], int | None]
    branch_target_return_expr: Callable[[object, _ReturnChainCodegen8616, int], CExpression | None]
    clone_c_value: Callable[[CExpression], CExpression]
    expr_fingerprint: Callable[[object, object], str]


@dataclass(frozen=True, slots=True)
class ComplexDecrementSwitchCallbacks8616:
    """Dynamic adapters for complex decrement-switch return materialization."""

    set_cfunc_statements_root: Callable[[_ReturnChainCodegen8616, CStatements], None]
    selector_stack_expr: Callable[[object, _ReturnChainCodegen8616], CExpression | None]
    selector_function_has_unsafe_effects: Callable[[object, _ReturnChainCodegen8616], bool]
    selector_raw_stack_aliases: Callable[[object, CExpression], dict[str, tuple[str, ...]]]
    linear_function_insns: Callable[[object, _ReturnChainCodegen8616], Iterable[object]]
    next_linear_jmp_target: Callable[[tuple[object, ...], int], int | None]
    resolve_one_hop_jmp_target: Callable[[object, int | None], int | None]
    branch_target_imm: Callable[[object], int | None]
    branch_target_return_expr: Callable[[object, _ReturnChainCodegen8616, int], CExpression | None]
    clone_c_value: Callable[[CExpression], CExpression]
    expr_fingerprint: Callable[[object, object], str]


@dataclass(frozen=True, slots=True)
class SelectorUnsafeEffectsCallbacks8616:
    """Dynamic adapters for selector-return unsafe instruction-effect scans."""

    function_inventory: Callable[
        [object, _ReturnChainCodegen8616],
        FunctionInstructionInventory8616,
    ]
    direct_call_target: Callable[[object], int | None]
    callee_name_for_target: Callable[[object, int], tuple[str | None, object | None]]
    target_is_stack_probe_helper: Callable[[object, int | None, str | None], bool]


@dataclass(frozen=True, slots=True)
class ReturnChainProofCallbacks8616:
    """Dynamic adapters needed to read CFG/JCC return-chain proof from angr state."""

    linear_jcc_block_starts: Callable[[object, object], Iterable[tuple[int, object]]]
    branch_target_imm: Callable[[object], int | None]
    branch_target_return_value: Callable[[object, int], int | None]
    decoded_condition_expr: Callable[[object, object, object, dict[str, int] | None], CExpression | None]
    translate_cmp_jcc_guard: Callable[[object, object, int, int], object | None]
    last_call_addr_before_jcc: Callable[[object, object, int], int | None]
    condition_tags: Callable[[object], object]
    iter_c_nodes_deep: Callable[[object], Iterable[object]]


@dataclass(frozen=True, slots=True)
class ReturnChainEmptyIfCallbacks8616:
    """Dynamic adapters for CFG-proven empty-if return-chain orchestration."""

    ordered_return_values: Callable[[object, object], list[int]]
    selector_function_has_unsafe_effects: Callable[[object, object, frozenset[int]], bool]
    condition_call_addrs: Callable[[Iterable[CExpression]], frozenset[int]]
    condition_branch_return_value: Callable[[object, object], int | None]
    condition_branch_is_non_branch: Callable[[object, object], bool]
    condition_tags: Callable[[object], object]
    ordered_return_expr_pairs: Callable[[object, object], list[tuple[CExpression, CExpression, CExpression]]]
    ordered_return_pairs: Callable[[object, object], list[tuple[CExpression, int]]]
    ordered_32bit_return_pairs: Callable[[object, object], list[tuple[CExpression, int]]]
    flatten_conditional_return_chain: Callable[[object, _ReturnChainCodegen8616, list[tuple[CExpression, int]]], bool]
    materialize_conditional_return_suffix: Callable[
        [object, _ReturnChainCodegen8616, list[tuple[CExpression, int]]], bool
    ]
    prune_duplicate_empty_return_guard: Callable[[object, _ReturnChainCodegen8616], bool]
    expr_fingerprint: Callable[[object, object], str]
    iter_c_nodes_deep: Callable[[object], Iterable[object]]


@dataclass(frozen=True, slots=True)
class BranchTargetReturnBlockResult8616:
    """Block value plus any jump tail still requiring preservation proof.

    When ``next_target`` is present, ``expr`` is provisional, not a proven return.
    """

    expr: object | None = None
    next_target: int | None = None


@dataclass(frozen=True, slots=True)
class BranchTargetReturnScanCallbacks8616:
    """Dynamic adapters for branch-target return block scanning and materialization."""

    branch_target_imm: Callable[[object], int | None]
    combine_return_expr: Callable[[object | None, object | None], object | None]
    materialize_reg_imm: Callable[[int], object | None]
    materialize_stack_load: Callable[[int, int], object | None]
    materialize_direct_global_load: Callable[[int, int], object | None]
    materialize_ax_alu_imm: Callable[[object, str, int], object | None]
    materialize_ax_incdec: Callable[[object, str], object | None]


@dataclass(frozen=True, slots=True)
class TerminalAxInstructionAction8616:
    """Result of consuming one instruction during terminal-AX return scanning."""

    classified: bool = False
    abort: bool = False


@dataclass(frozen=True, slots=True)
class TerminalAxScanCallbacks8616:
    """Dynamic adapters for terminal-AX scan control and instruction materialization."""

    combined_return_expr: Callable[[], object | None]
    process_instruction: Callable[[object, TerminalAxReturnEffect8616], TerminalAxInstructionAction8616]


@dataclass(frozen=True, slots=True)
class TerminalAxScanResult8616:
    """Result of structuring-owned terminal-AX linear scan control."""

    expr: object | None = None
    raw_insns: int = 0
    classified: int = 0
    terminal_value_block_count: int = 0


class TerminalCallResultReturnStatus8616(Enum):
    """Terminal status for call-result return materialization."""

    MATERIALIZED = "materialized"
    ALREADY_MATERIALIZED = "already_materialized"
    NO_CALL_RETURN_CANDIDATE = "no_call_return_candidate"
    NON_ADJACENT_CALL_RETURN = "non_adjacent_call_return"
    AMBIGUOUS_AST_CANDIDATE = "ambiguous_ast_candidate"
    CALL_TAG_MISSING = "call_tag_missing"
    CALLEE_RETURNS_VOID = "callee_returns_void"
    CALLEE_RESULT_CONTRACT_UNKNOWN = "callee_result_contract_unknown"
    CALLER_USE_PROVEN_UNUSED = "caller_use_proven_unused"
    CALLER_USE_NOT_PROVEN = "caller_use_not_proven"
    CALL_BLOCK_MISSING_OR_AMBIGUOUS = "call_block_missing_or_ambiguous"
    CALL_INSTRUCTION_MISSING_OR_AMBIGUOUS = "call_instruction_missing_or_ambiguous"
    CFG_PATH_AMBIGUOUS = "cfg_path_ambiguous"
    UNSAFE_POST_CALL_EFFECT = "unsafe_post_call_effect"
    RETURN_NOT_REACHED = "return_not_reached"


def _unknown_terminal_call_result_contract_8616(
    _call: CFunctionCall,
) -> TerminalCallResultContract8616:
    """Keep legacy callback fixtures conservative when no type adapter exists."""
    return TerminalCallResultContract8616.UNKNOWN


@dataclass(frozen=True, slots=True)
class TerminalCallResultReturnCallbacks8616:
    """Dynamic adapters for proving a terminal call-result return path."""

    iter_c_nodes_deep: Callable[[object], Iterable[object]]
    function_block_ranges: Callable[[], Iterable[tuple[int, int]]]
    load_block: Callable[[int, int], object | None]
    successor_addrs: Callable[[int], Iterable[int]]
    branch_target_imm: Callable[[object], int | None]
    call_result_contract: Callable[
        [CFunctionCall], TerminalCallResultContract8616
    ] = _unknown_terminal_call_result_contract_8616


@dataclass(frozen=True, slots=True)
class TerminalCallResultReturnStats8616:
    """Closed evidence loop for terminal call-result return materialization."""

    status: TerminalCallResultReturnStatus8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    call_ins_addr: int | None = None
    path_block_addrs: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class _TerminalCallReturnCandidate8616:
    """One exact structured terminal-call return candidate."""

    call_container: CStatements
    return_container: CStatements
    call: CFunctionCall
    call_statement_index: int | None
    return_index: int
    already_materialized: bool
    return_use_proven_locally: bool
    return_statement: CReturn | None


@dataclass(frozen=True, slots=True)
class _TerminalAssignedCall8616:
    """One call assigned to an exact structured-C result carrier."""

    container: CStatements
    index: int
    call: CFunctionCall
    carrier: object


@dataclass(frozen=True, slots=True)
class _TerminalCarrierReturn8616:
    """One structured return of an exact result-carrier object."""

    container: CStatements
    index: int
    statement: CReturn


def _terminal_call_return_containers_8616(
    root: object,
    callbacks: TerminalCallResultReturnCallbacks8616,
) -> tuple[CStatements, ...]:
    """Return unique C statement containers from a dynamic angr AST boundary."""
    containers: list[CStatements] = []
    seen: set[int] = set()
    for node in (root, *callbacks.iter_c_nodes_deep(root)):
        if not isinstance(node, CStatements) or id(node) in seen:
            continue
        seen.add(id(node))
        containers.append(node)
    return tuple(containers)


def _terminal_call_return_leaf_8616(
    statement: object,
) -> tuple[str, CFunctionCall | None, CReturn | None] | None:
    """Unwrap one transparent statement wrapper to a terminal call/return leaf."""
    current = _terminal_call_return_statement_8616(statement)
    if current is None:
        return None
    if isinstance(current, CExpressionStatement) and isinstance(current.expr, CFunctionCall):
        return "call", current.expr, None
    if isinstance(current, CReturn):
        if isinstance(current.retval, CFunctionCall):
            return "returned_call", current.retval, None
        if current.retval is None:
            return "empty_return", None, current
    return None


def _terminal_call_return_statement_8616(statement: object) -> object | None:
    """Unwrap one transparent statement container without inferring meaning."""
    current = statement
    visited: set[int] = set()
    while isinstance(current, CStatements):
        if id(current) in visited:
            return None
        visited.add(id(current))
        children = tuple(current.statements or ())
        if len(children) != 1:
            return None
        current = children[0]
    return current


def _terminal_call_return_candidates_8616(
    root: object,
    callbacks: TerminalCallResultReturnCallbacks8616,
) -> tuple[tuple[_TerminalCallReturnCandidate8616, ...], bool]:
    """Collect exact adjacent candidates and report a unique non-adjacent shape."""
    candidates: list[_TerminalCallReturnCandidate8616] = []
    candidate_keys: set[tuple[int, int, bool]] = set()
    assigned_calls: list[_TerminalAssignedCall8616] = []
    carrier_returns: list[_TerminalCarrierReturn8616] = []
    non_adjacent = False
    containers = _terminal_call_return_containers_8616(root, callbacks)
    for container in containers:
        statements = tuple(container.statements or ())
        leaves = tuple(_terminal_call_return_leaf_8616(statement) for statement in statements)
        for index, statement in enumerate(statements):
            leaf_statement = _terminal_call_return_statement_8616(statement)
            if isinstance(leaf_statement, CAssignment) and isinstance(
                leaf_statement.rhs, CFunctionCall
            ):
                assigned_calls.append(
                    _TerminalAssignedCall8616(
                        container=container,
                        index=index,
                        call=leaf_statement.rhs,
                        carrier=leaf_statement.lhs,
                    )
                )
            elif (
                isinstance(leaf_statement, CReturn)
                and leaf_statement.retval is not None
                and not isinstance(leaf_statement.retval, CFunctionCall)
            ):
                carrier_returns.append(
                    _TerminalCarrierReturn8616(
                        container=container,
                        index=index,
                        statement=leaf_statement,
                    )
                )
        call_indexes = tuple(index for index, leaf in enumerate(leaves) if leaf is not None and leaf[0] == "call")
        empty_return_indexes = tuple(
            index for index, leaf in enumerate(leaves) if leaf is not None and leaf[0] == "empty_return"
        )
        for return_index, leaf in enumerate(leaves):
            if leaf is None or leaf[0] != "returned_call":
                continue
            call = leaf[1]
            if call is None:
                continue
            key = (id(call), id(call), True)
            if key in candidate_keys:
                continue
            candidate_keys.add(key)
            candidates.append(
                _TerminalCallReturnCandidate8616(
                    call_container=container,
                    return_container=container,
                    call=call,
                    call_statement_index=None,
                    return_index=return_index,
                    already_materialized=True,
                    return_use_proven_locally=True,
                    return_statement=None,
                )
            )
        for return_index in empty_return_indexes:
            call_index = return_index - 1
            if call_index < 0:
                continue
            call_leaf = leaves[call_index]
            return_leaf = leaves[return_index]
            if call_leaf is None or call_leaf[0] != "call" or return_leaf is None:
                continue
            call = call_leaf[1]
            empty_return = return_leaf[2]
            if call is None or empty_return is None:
                continue
            key = (id(call), id(empty_return), False)
            if key in candidate_keys:
                continue
            candidate_keys.add(key)
            candidates.append(
                _TerminalCallReturnCandidate8616(
                    call_container=container,
                    return_container=container,
                    call=call,
                    call_statement_index=call_index,
                    return_index=return_index,
                    already_materialized=False,
                    return_use_proven_locally=False,
                    return_statement=empty_return,
                )
            )
        if (
            not candidates
            and len(call_indexes) == 1
            and len(empty_return_indexes) == 1
            and call_indexes[0] < empty_return_indexes[0]
        ):
            non_adjacent = True
    for assigned_call in assigned_calls:
        for carrier_return in carrier_returns:
            if carrier_return.statement.retval is not assigned_call.carrier:
                continue
            same_container = assigned_call.container is carrier_return.container
            if same_container and carrier_return.index != assigned_call.index + 1:
                continue
            key = (id(assigned_call.call), id(carrier_return.statement), False)
            if key in candidate_keys:
                continue
            candidate_keys.add(key)
            candidates.append(
                _TerminalCallReturnCandidate8616(
                    call_container=assigned_call.container,
                    return_container=carrier_return.container,
                    call=assigned_call.call,
                    call_statement_index=assigned_call.index,
                    return_index=carrier_return.index,
                    already_materialized=False,
                    return_use_proven_locally=True,
                    return_statement=carrier_return.statement,
                )
            )
    return tuple(candidates), non_adjacent


def _dynamic_object_tuple_8616(value: object) -> tuple[object, ...]:
    """Narrow one third-party iterable boundary to an owned object tuple."""
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return tuple(value)
    return ()


def _terminal_call_path_stack_adjust_8616(insn: object) -> bool:
    """Return whether an instruction is an exact caller stack cleanup."""
    operands = _dynamic_object_tuple_8616(_capstone_attr_8616(insn, "operands", ()))
    return (
        str(_capstone_attr_8616(insn, "mnemonic", "")).lower() == "add"
        and len(operands) == 2
        and _capstone_int_attr_8616(operands[0], "type", -1) == 1
        and _return_chain_reg_name_8616(insn, operands[0]) == "sp"
        and _capstone_int_attr_8616(operands[1], "type", -1) == 2
    )


def _terminal_call_path_frame_teardown_8616(insn: object) -> bool:
    """Return whether an instruction preserves an AX-family call result."""
    mnemonic = str(_capstone_attr_8616(insn, "mnemonic", "")).lower()
    operands = _dynamic_object_tuple_8616(_capstone_attr_8616(insn, "operands", ()))
    if mnemonic in {"leave", "nop"}:
        return True
    if mnemonic == "pop" and len(operands) == 1 and _capstone_int_attr_8616(operands[0], "type", -1) == 1:
        return _return_chain_reg_name_8616(insn, operands[0]) not in {
            "ax",
            "al",
            "ah",
            "dx",
            "dl",
            "dh",
        }
    return (
        mnemonic == "mov"
        and len(operands) == 2
        and all(_capstone_int_attr_8616(operand, "type", -1) == 1 for operand in operands)
        and _return_chain_reg_name_8616(insn, operands[0]) == "sp"
        and _return_chain_reg_name_8616(insn, operands[1]) == "bp"
    )


def prove_terminal_call_result_path_8616(
    call_ins_addr: int,
    callbacks: TerminalCallResultReturnCallbacks8616,
) -> tuple[TerminalCallResultReturnStatus8616, tuple[int, ...]]:
    """Prove one AX-preserving CFG path from an exact call instruction to return."""
    result = prove_terminal_call_path_8616(
        call_ins_addr,
        TerminalCallPathCallbacks8616(
            function_block_ranges=callbacks.function_block_ranges,
            load_block=callbacks.load_block,
            successor_addrs=callbacks.successor_addrs,
            branch_target_imm=callbacks.branch_target_imm,
        ),
    )
    status = {
        TerminalCallPathStatus8616.PROVEN: TerminalCallResultReturnStatus8616.MATERIALIZED,
        TerminalCallPathStatus8616.CALL_BLOCK_MISSING_OR_AMBIGUOUS: (
            TerminalCallResultReturnStatus8616.CALL_BLOCK_MISSING_OR_AMBIGUOUS
        ),
        TerminalCallPathStatus8616.CALL_INSTRUCTION_MISSING_OR_AMBIGUOUS: (
            TerminalCallResultReturnStatus8616.CALL_INSTRUCTION_MISSING_OR_AMBIGUOUS
        ),
        TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS: TerminalCallResultReturnStatus8616.CFG_PATH_AMBIGUOUS,
        TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT: TerminalCallResultReturnStatus8616.UNSAFE_POST_CALL_EFFECT,
        TerminalCallPathStatus8616.RETURN_NOT_REACHED: TerminalCallResultReturnStatus8616.RETURN_NOT_REACHED,
    }[result.status]
    return status, result.path_block_addrs


def materialize_terminal_call_result_return_8616(
    root: object,
    codegen: object,
    *,
    caller_use: CallerReturnUseVerdict8616,
    callbacks: TerminalCallResultReturnCallbacks8616,
) -> TerminalCallResultReturnStats8616:
    """Replace one CFG-proven terminal call plus empty return with a returned call."""
    candidates, non_adjacent = _terminal_call_return_candidates_8616(root, callbacks)
    raw_count = len(candidates) or int(non_adjacent)
    if not candidates:
        return TerminalCallResultReturnStats8616(
            status=(
                TerminalCallResultReturnStatus8616.NON_ADJACENT_CALL_RETURN
                if non_adjacent
                else TerminalCallResultReturnStatus8616.NO_CALL_RETURN_CANDIDATE
            ),
            raw_fact_count=raw_count,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=int(non_adjacent),
        )
    if len(candidates) != 1:
        return TerminalCallResultReturnStats8616(
            status=TerminalCallResultReturnStatus8616.AMBIGUOUS_AST_CANDIDATE,
            raw_fact_count=len(candidates),
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=len(candidates),
        )

    candidate = candidates[0]
    call_tags = candidate.call.tags
    call_ins_addr = call_tags.get("ins_addr") if isinstance(call_tags, dict) else None
    if not isinstance(call_ins_addr, int):
        return TerminalCallResultReturnStats8616(
            status=TerminalCallResultReturnStatus8616.CALL_TAG_MISSING,
            raw_fact_count=1,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        )
    call_result_contract = callbacks.call_result_contract(candidate.call)
    if call_result_contract is TerminalCallResultContract8616.VOID:
        return TerminalCallResultReturnStats8616(
            status=TerminalCallResultReturnStatus8616.CALLEE_RETURNS_VOID,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
            call_ins_addr=call_ins_addr,
        )
    if caller_use is CallerReturnUseVerdict8616.UNUSED:
        return TerminalCallResultReturnStats8616(
            status=TerminalCallResultReturnStatus8616.CALLER_USE_PROVEN_UNUSED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=0,
            call_ins_addr=call_ins_addr,
        )
    if call_result_contract is not TerminalCallResultContract8616.VALUE:
        return TerminalCallResultReturnStats8616(
            status=TerminalCallResultReturnStatus8616.CALLEE_RESULT_CONTRACT_UNKNOWN,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
            call_ins_addr=call_ins_addr,
        )
    if (
        caller_use is not CallerReturnUseVerdict8616.USED
        and not candidate.return_use_proven_locally
    ):
        return TerminalCallResultReturnStats8616(
            status=TerminalCallResultReturnStatus8616.CALLER_USE_NOT_PROVEN,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
            call_ins_addr=call_ins_addr,
        )

    path_status, path = prove_terminal_call_result_path_8616(call_ins_addr, callbacks)
    if path_status is not TerminalCallResultReturnStatus8616.MATERIALIZED:
        return TerminalCallResultReturnStats8616(
            status=path_status,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
            call_ins_addr=call_ins_addr,
            path_block_addrs=path,
        )
    if candidate.already_materialized:
        return TerminalCallResultReturnStats8616(
            status=TerminalCallResultReturnStatus8616.ALREADY_MATERIALIZED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
            call_ins_addr=call_ins_addr,
            path_block_addrs=path,
        )

    replacement = CReturn(
        candidate.call,
        tags=(
            candidate.return_statement.tags
            if candidate.return_statement is not None
            else None
        ),
        codegen=codegen,
    )
    assert candidate.call_statement_index is not None
    if candidate.call_container is candidate.return_container:
        statements: list[CStatement] = list(
            cast(Iterable[CStatement], candidate.call_container.statements or ())
        )
        statements[candidate.call_statement_index : candidate.return_index + 1] = [
            replacement
        ]
        candidate.call_container.statements = statements
    else:
        call_statements: list[CStatement] = list(
            cast(Iterable[CStatement], candidate.call_container.statements or ())
        )
        del call_statements[candidate.call_statement_index]
        candidate.call_container.statements = call_statements
        return_statements: list[CStatement] = list(
            cast(Iterable[CStatement], candidate.return_container.statements or ())
        )
        return_statements[candidate.return_index] = replacement
        candidate.return_container.statements = return_statements
    return TerminalCallResultReturnStats8616(
        status=TerminalCallResultReturnStatus8616.MATERIALIZED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        call_ins_addr=call_ins_addr,
        path_block_addrs=path,
    )


def scan_branch_target_return_block_8616(
    block: object,
    callbacks: BranchTargetReturnScanCallbacks8616,
) -> BranchTargetReturnBlockResult8616:
    """Consume every effect or prove return-register preservation before reuse."""
    ax_value: object | None = None
    dx_value: object | None = None

    def _combined_return_expr() -> object | None:
        return callbacks.combine_return_expr(ax_value, dx_value)

    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    for insn in insns:
        effect = branch_target_return_effect_8616(insn, callbacks.branch_target_imm)
        if effect.kind in {
            BranchTargetReturnEffectKind8616.MOV_REG_IMM,
            BranchTargetReturnEffectKind8616.MOV_REG_STACK,
            BranchTargetReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL,
        }:
            value: object | None = None
            if effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_IMM:
                value = callbacks.materialize_reg_imm(effect.imm or 0)
            elif effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_STACK:
                value = callbacks.materialize_stack_load(int(effect.mem_disp or 0), int(effect.mem_size or 2))
            elif effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL:
                value = callbacks.materialize_direct_global_load(int(effect.mem_disp or 0), int(effect.mem_size or 2))
            if value is not None:
                if effect.dst_reg == "ax":
                    ax_value = value
                elif effect.dst_reg == "dx":
                    dx_value = value
                continue
        if effect.kind is BranchTargetReturnEffectKind8616.AX_ALU_IMM and ax_value is not None and effect.op:
            next_ax = callbacks.materialize_ax_alu_imm(ax_value, effect.op, effect.imm or 0)
            if next_ax is not None:
                ax_value = next_ax
                continue
        if effect.kind is BranchTargetReturnEffectKind8616.AX_INCDEC and ax_value is not None and effect.op:
            next_ax = callbacks.materialize_ax_incdec(ax_value, effect.op)
            if next_ax is not None:
                ax_value = next_ax
                continue
        if effect.kind is BranchTargetReturnEffectKind8616.JUMP:
            if effect.jump_target is None:
                return BranchTargetReturnBlockResult8616()
            return BranchTargetReturnBlockResult8616(
                expr=_combined_return_expr(), next_target=effect.jump_target,
            )
        if effect.kind is BranchTargetReturnEffectKind8616.RETURN:
            return BranchTargetReturnBlockResult8616(expr=_combined_return_expr())
        if effect.kind is BranchTargetReturnEffectKind8616.CONTROL_BOUNDARY:
            return BranchTargetReturnBlockResult8616()
        # Unmodeled arithmetic and failed materialization cannot preserve the
        # previous AX/DX value merely because the scanner did not consume them.
        if not instruction_preserves_return_registers_8616(insn):
            return BranchTargetReturnBlockResult8616()
    return BranchTargetReturnBlockResult8616()


def _return_chain_reg_name_8616(insn: object, operand: object) -> str:
    """Return a lower-case capstone register name for structuring pattern checks."""
    # Dynamic third-party capstone boundary: register ids are decoded by capstone wrappers.
    reg = getattr(operand, "reg", None)
    # Dynamic third-party capstone boundary: register-name rendering is supplied by capstone.
    reg_name = getattr(insn, "reg_name", None)
    if not isinstance(reg, int) or not callable(reg_name):
        return ""
    return str(reg_name(reg)).lower()


def return_epilogue_block_8616(block: object) -> bool:
    """Return whether a dynamic boundary: third-party Capstone block is only an epilogue."""
    saw_ret = False
    for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic in {"ret", "retf", "iret"}:
            saw_ret = True
            break
        if mnemonic in {"pop", "leave", "nop"}:
            continue
        if (
            mnemonic == "mov"
            and len(operands) == 2
            and int(getattr(operands[0], "type", -1)) == 1
            and int(getattr(operands[1], "type", -1)) == 1
            and _return_chain_reg_name_8616(insn, operands[0]) == "sp"
            and _return_chain_reg_name_8616(insn, operands[1]) == "bp"
        ):
            continue
        return False
    return saw_ret


def terminal_value_block_addrs_8616(
    block_addrs: Iterable[int],
    load_block: Callable[[int], object | None],
    branch_target_imm: Callable[[object], int | None],
) -> tuple[int, ...]:
    """Return value-producing blocks from a dynamic boundary: third-party Capstone CFG blocks."""
    value_block_addrs: list[int] = []
    for block_addr in block_addrs:
        try:
            candidate_block = load_block(int(block_addr))
        except Exception:
            continue
        if candidate_block is None:
            continue
        candidate_insns = tuple(getattr(getattr(candidate_block, "capstone", None), "insns", ()) or ())
        if not candidate_insns:
            continue
        last_insn = candidate_insns[-1]
        last_mnemonic = str(getattr(last_insn, "mnemonic", "")).lower()
        if last_mnemonic not in {"jmp", "ljmp"}:
            continue
        target = branch_target_imm(last_insn)
        if target is None:
            continue
        try:
            epilogue_block = load_block(int(target))
        except Exception:
            continue
        if epilogue_block is None or not return_epilogue_block_8616(epilogue_block):
            continue
        value_block_addrs.append(int(block_addr))
    return tuple(sorted(value_block_addrs))


def linear_terminal_ax_return_scan_8616(
    block_addrs: Iterable[int],
    load_block: Callable[[int], object | None],
    branch_target_imm: Callable[[object], int | None],
    callbacks: TerminalAxScanCallbacks8616,
) -> TerminalAxScanResult8616:
    """Scan terminal blocks through a dynamic boundary: third-party Capstone instructions."""
    ordered_block_addrs = tuple(sorted(int(addr) for addr in block_addrs))
    if not ordered_block_addrs:
        return TerminalAxScanResult8616()
    terminal_blocks = terminal_value_block_addrs_8616(ordered_block_addrs, load_block, branch_target_imm)
    terminal_block_count = len(terminal_blocks) or int(len(ordered_block_addrs) == 1)
    if len(terminal_blocks) > 1:
        return TerminalAxScanResult8616(
            terminal_value_block_count=terminal_block_count,
        )
    if terminal_blocks:
        ordered_block_addrs = terminal_blocks
    raw_insns = 0
    classified = 0
    ret_count = 0
    conditional_branches = 0
    for block_addr in ordered_block_addrs:
        try:
            block = load_block(int(block_addr))
        except Exception:
            return TerminalAxScanResult8616(raw_insns=raw_insns, classified=classified)
        if block is None:
            return TerminalAxScanResult8616(raw_insns=raw_insns, classified=classified)
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            raw_insns += 1
            mnemonic = str(getattr(insn, "mnemonic", "")).lower()
            if mnemonic.startswith("j") and mnemonic not in {"jmp", "ljmp"}:
                conditional_branches += 1
                continue
            if mnemonic in {"jmp", "ljmp"}:
                target = branch_target_imm(insn)
                if (
                    target is None
                    or conditional_branches
                    or int(block_addr)
                    not in terminal_value_block_addrs_8616((int(block_addr),), load_block, branch_target_imm)
                ):
                    return TerminalAxScanResult8616(
                        raw_insns=raw_insns,
                        classified=classified,
                        terminal_value_block_count=terminal_block_count,
                    )
                expr = callbacks.combined_return_expr()
                if expr is None:
                    return TerminalAxScanResult8616(
                        raw_insns=raw_insns,
                        classified=classified,
                        terminal_value_block_count=terminal_block_count,
                    )
                return TerminalAxScanResult8616(
                    expr=expr,
                    raw_insns=raw_insns,
                    classified=classified,
                    terminal_value_block_count=terminal_block_count,
                )
            if mnemonic in {"ret", "retf", "iret"}:
                ret_count += 1
                if ret_count > 1 or conditional_branches:
                    return TerminalAxScanResult8616(
                        raw_insns=raw_insns,
                        classified=classified,
                        terminal_value_block_count=terminal_block_count,
                    )
                return TerminalAxScanResult8616(
                    expr=callbacks.combined_return_expr(),
                    raw_insns=raw_insns,
                    classified=classified,
                    terminal_value_block_count=terminal_block_count,
                )
            action = callbacks.process_instruction(insn, terminal_ax_return_effect_8616(insn))
            if action.abort:
                return TerminalAxScanResult8616(
                    raw_insns=raw_insns,
                    classified=classified,
                    terminal_value_block_count=terminal_block_count,
                )
            if action.classified:
                classified += 1
    return TerminalAxScanResult8616(
        raw_insns=raw_insns,
        classified=classified,
        terminal_value_block_count=terminal_block_count,
    )


def last_ax_return_value_8616(
    project: object,
    codegen: object,
    callbacks: LastAxReturnValueCallbacks8616,
) -> int | None:
    """Return the last immediate AX value proven by codegen instructions."""
    value: int | None = None
    for insn in callbacks.function_insns(project, codegen):
        mnemonic = str(_capstone_attr_8616(insn, "mnemonic", "")).lower()
        operands = tuple(cast(Iterable[object], _capstone_attr_8616(insn, "operands", ()) or ()))
        if len(operands) != 2 or mnemonic != "mov":
            continue
        destination, source = operands
        if _capstone_int_attr_8616(destination, "type", -1) != 1 or _capstone_int_attr_8616(source, "type", -1) != 2:
            continue
        reg_name = _capstone_attr_8616(insn, "reg_name", None)
        if not callable(reg_name):
            continue
        try:
            destination_name = str(reg_name(_capstone_attr_8616(destination, "reg", None))).lower()
        except Exception:
            continue
        if destination_name != "ax":
            continue
        value = callbacks.signed_i16_immediate(_capstone_int_attr_8616(source, "imm", 0))
    return value


def _debug_cvar_slot_8616(expr: object) -> str:
    """Render C variable slot details from a dynamic boundary: angr codegen debug C AST."""
    if not isinstance(expr, CVariable):
        return type(expr).__name__
    variable = expr.variable
    return (
        f"CVariable(name={expr.name!r}, "
        f"var_name={getattr(variable, 'name', None)!r}, "
        f"offset={getattr(variable, 'offset', None)!r}, "
        f"size={getattr(variable, 'size', None)!r}, "
        f"id={id(expr):#x}, var_id={id(variable):#x})"
    )


def selector_condition_call_addrs_8616(
    pairs: Iterable[tuple[CExpression, ...]],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> frozenset[int]:
    """Return condition call addresses from dynamic angr codegen proof nodes."""
    addrs: set[int] = set()
    for pair in pairs:
        cond = pair[0]
        cond_tags = getattr(cond, "tags", None)
        if isinstance(cond_tags, dict):
            condition_call_addr = cond_tags.get("condition_call_ins_addr")
            if isinstance(condition_call_addr, int):
                addrs.add(condition_call_addr)
        for node in (cond, *iter_c_nodes_deep(cond)):
            if not isinstance(node, CFunctionCall):
                continue
            tags = node.tags
            if not isinstance(tags, dict):
                continue
            ins_addr = tags.get("ins_addr")
            if isinstance(ins_addr, int):
                addrs.add(ins_addr)
            condition_call_addr = tags.get("condition_call_ins_addr")
            if isinstance(condition_call_addr, int):
                addrs.add(condition_call_addr)
    return frozenset(addrs)


def selector_condition_call_addrs_from_cfg_8616(
    project: object,
    codegen: object,
    callbacks: ReturnSelectorCallsiteProofCallbacks8616,
) -> frozenset[int]:
    """Return pre-JCC callsites from a dynamic boundary: third-party Capstone CFG."""
    addrs: set[int] = set()
    for block_addr, insn in callbacks.linear_jcc_block_starts(project, codegen):
        insn_addr = int(getattr(insn, "address", 0) or 0)
        true_target = callbacks.branch_target_imm(insn)
        false_target = callbacks.next_unconditional_target_after_jcc(project, int(block_addr), insn_addr)
        if true_target is None or false_target is None:
            continue
        true_expr = callbacks.branch_target_return_expr(project, codegen, true_target)
        false_expr = callbacks.branch_target_return_expr(project, codegen, false_target)
        if true_expr is None or false_expr is None:
            continue
        decoded = callbacks.translate_cmp_jcc_guard(project, codegen, int(block_addr), insn_addr)
        if decoded is None:
            continue
        condition_call_addr = callbacks.last_call_addr_before_jcc_in_function(project, codegen, insn_addr)
        if condition_call_addr is not None:
            addrs.add(condition_call_addr)
    return frozenset(addrs)


def last_call_addr_before_jcc_in_function_8616(insns: Iterable[object], jcc_addr: int) -> int | None:
    """Return last callsite before a JCC from a dynamic boundary: third-party Capstone instructions."""
    last_call_addr: int | None = None
    for insn in insns:
        insn_addr = int(getattr(insn, "address", -1))
        if insn_addr >= int(jcc_addr):
            break
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic.startswith("j"):
            last_call_addr = None
            continue
        if mnemonic in {"call", "lcall"}:
            last_call_addr = insn_addr
    return last_call_addr


def linear_jcc_block_starts_8616(insns: Iterable[object]) -> tuple[tuple[int, object], ...]:
    """Return linear JCC block starts from a dynamic boundary: third-party Capstone instructions."""
    pairs: list[tuple[int, object]] = []
    terminators = {"jmp", "ljmp", "ret", "retf", "iret"}
    indexed_insns = tuple(insns)
    for index, insn in enumerate(indexed_insns):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if not mnemonic.startswith("j") or mnemonic in {"jmp", "ljmp"}:
            continue
        block_start = int(getattr(insn, "address", 0) or 0)
        for prev_index in range(index - 1, -1, -1):
            prev = indexed_insns[prev_index]
            prev_mnemonic = str(getattr(prev, "mnemonic", "")).lower()
            if prev_mnemonic in terminators or prev_mnemonic.startswith("j") or prev_mnemonic in {"call", "lcall"}:
                break
            block_start = int(getattr(prev, "address", block_start) or block_start)
        pairs.append((block_start, insn))
    return tuple(pairs)


def is_conditional_branch_insn_8616(insn: object) -> bool:
    """Return whether a dynamic boundary: third-party Capstone instruction is conditional."""
    mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
    if mnemonic in {"jmp", "ljmp"}:
        return False
    if mnemonic.startswith("j"):
        return True
    return mnemonic in {"loop", "loope", "loopne", "loopnz", "loopz"}


def conditional_branch_count_8616(insns: Iterable[object]) -> int | None:
    """Count conditional branch instructions when a linear instruction stream is available."""
    indexed_insns = tuple(insns)
    if not indexed_insns:
        return None
    return sum(1 for insn in indexed_insns if is_conditional_branch_insn_8616(insn))


def next_unconditional_target_after_jcc_8616(
    block: object,
    jcc_addr: int,
    load_block: Callable[[int], object | None],
    branch_target_imm: Callable[[object], int | None],
) -> int | None:
    """Return following jump target from a dynamic boundary: third-party Capstone CFG blocks."""
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    for idx, insn in enumerate(insns):
        if int(getattr(insn, "address", -1)) != int(jcc_addr):
            continue
        if idx + 1 >= len(insns):
            next_addr = int(jcc_addr) + int(getattr(insn, "size", 0) or 0)
            if next_addr <= int(jcc_addr):
                return None
            next_block = load_block(next_addr)
            if next_block is None:
                return None
            next_insns = tuple(getattr(getattr(next_block, "capstone", None), "insns", ()) or ())
            if not next_insns:
                return None
            next_insn = next_insns[0]
            if str(getattr(next_insn, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
                return None
            return branch_target_imm(next_insn)
        next_insn = insns[idx + 1]
        if str(getattr(next_insn, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
            return None
        return branch_target_imm(next_insn)
    return None


def first_conditional_jcc_8616(block: object) -> object | None:
    """Return first conditional JCC from a dynamic boundary: third-party Capstone CFG block."""
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    for insn in insns:
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic.startswith("j") and mnemonic not in {"jmp", "ljmp"}:
            return cast(object, insn)
    return None


def selector_targets_from_32bit_jcc_chain_8616(
    block_addr: int,
    jcc_insn: object,
    load_block: Callable[[int], object | None],
    branch_target_imm: Callable[[object], int | None],
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None],
) -> tuple[int, int] | None:
    """Return true/false targets proven by a three-JCC 32-bit selector chain."""
    true_mid = branch_target_imm(jcc_insn)
    start_block = load_block(int(block_addr))
    if start_block is None:
        return None
    # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
    first_jcc_addr = int(getattr(jcc_insn, "address", -1))
    false_target = next_unconditional_target_after_jcc(start_block, int(block_addr), first_jcc_addr)
    if true_mid is None or false_target is None:
        return None
    mid_block = load_block(int(true_mid))
    if mid_block is None:
        return None
    jcc2 = first_conditional_jcc_8616(mid_block)
    if jcc2 is None:
        return None
    low_addr = branch_target_imm(jcc2)
    # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
    mid_jcc_addr = int(getattr(jcc2, "address", -1))
    mid_false = next_unconditional_target_after_jcc(mid_block, int(true_mid), mid_jcc_addr)
    if low_addr is None or mid_false is None:
        return None
    low_block = load_block(int(low_addr))
    if low_block is None:
        return None
    jcc3 = first_conditional_jcc_8616(low_block)
    if jcc3 is None:
        return None
    low_true = branch_target_imm(jcc3)
    # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
    low_jcc_addr = int(getattr(jcc3, "address", -1))
    low_false = next_unconditional_target_after_jcc(low_block, int(low_addr), low_jcc_addr)
    if low_true is None or low_false is None:
        return None
    if int(mid_false) == int(low_true) and int(false_target) == int(low_false):
        return int(low_true), int(false_target)
    if int(mid_false) == int(low_false) and int(false_target) == int(low_true):
        return int(low_false), int(false_target)
    return None


def equality_return_target_from_32bit_jcc_chain_8616(
    block_addr: int,
    jcc_insn: object,
    load_block: Callable[[int], object | None],
    branch_target_imm: Callable[[object], int | None],
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None],
) -> int | None:
    """Return equality target from a dynamic boundary: third-party Capstone JCC chain."""
    if str(getattr(jcc_insn, "mnemonic", "")).lower() not in {"je", "jz"}:
        return None
    mid_addr = branch_target_imm(jcc_insn)
    start_block = load_block(int(block_addr))
    if start_block is None:
        return None
    # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
    first_jcc_addr = int(getattr(jcc_insn, "address", -1))
    false_target = next_unconditional_target_after_jcc(start_block, int(block_addr), first_jcc_addr)
    if mid_addr is None or false_target is None:
        return None
    mid_block = load_block(int(mid_addr))
    if mid_block is None:
        return None
    jcc2 = first_conditional_jcc_8616(mid_block)
    if jcc2 is None or str(getattr(jcc2, "mnemonic", "")).lower() not in {"je", "jz"}:
        return None
    true_target = branch_target_imm(jcc2)
    # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
    second_jcc_addr = int(getattr(jcc2, "address", -1))
    second_false = next_unconditional_target_after_jcc(mid_block, int(mid_addr), second_jcc_addr)
    if true_target is None or second_false is None:
        return None
    if int(false_target) != int(second_false):
        return None
    return int(true_target)


def inequality_target_from_32bit_jcc_chain_8616(
    block_addr: int,
    jcc_insn: object,
    load_block: Callable[[int], object | None],
    branch_target_imm: Callable[[object], int | None],
    next_unconditional_target_after_jcc: Callable[[object, int, int], int | None],
) -> int | None:
    """Return inequality target from a dynamic boundary: third-party Capstone JCC chain."""
    if str(getattr(jcc_insn, "mnemonic", "")).lower() not in {"je", "jz"}:
        return None
    mid_addr = branch_target_imm(jcc_insn)
    start_block = load_block(int(block_addr))
    if start_block is None:
        return None
    # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
    first_jcc_addr = int(getattr(jcc_insn, "address", -1))
    false_target = next_unconditional_target_after_jcc(start_block, int(block_addr), first_jcc_addr)
    if mid_addr is None or false_target is None:
        return None
    mid_block = load_block(int(mid_addr))
    if mid_block is None:
        return None
    jcc2 = first_conditional_jcc_8616(mid_block)
    if jcc2 is None or str(getattr(jcc2, "mnemonic", "")).lower() not in {"jne", "jnz"}:
        return None
    true_target = branch_target_imm(jcc2)
    if true_target is None:
        return None
    if int(false_target) != int(true_target):
        return None
    return int(true_target)


def resolve_one_hop_jmp_target_8616(
    target: int | None,
    load_block: Callable[[int], object | None],
    branch_target_imm: Callable[[object], int | None],
) -> int | None:
    """Resolve one-hop target through a dynamic boundary: third-party Capstone jump stub."""
    if target is None:
        return None
    target_addr = int(target)
    try:
        block = load_block(target_addr)
    except Exception:
        return target_addr
    if block is None:
        return target_addr
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    if not insns:
        return target_addr
    first = insns[0]
    if str(getattr(first, "mnemonic", "")).lower() in {"jmp", "ljmp"}:
        resolved = branch_target_imm(first)
        if resolved is not None:
            return int(resolved)
    return target_addr


def branch_target_return_value_8616(
    target_addr: int,
    load_block: Callable[[int], object | None],
    signed_i16_immediate: Callable[[int], int],
) -> int | None:
    """Return CFG target AX value from a dynamic boundary: third-party Capstone block."""
    try:
        block = load_block(int(target_addr))
    except Exception:
        return None
    if block is None:
        return None
    for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if (
            mnemonic == "mov"
            and len(operands) == 2
            and int(getattr(operands[0], "type", -1)) == 1
            and str(insn.reg_name(operands[0].reg)).lower() == "ax"
            and int(getattr(operands[1], "type", -1)) == 2
        ):
            return signed_i16_immediate(int(getattr(operands[1], "imm", 0) or 0))
        if mnemonic in {"ret", "retf", "iret"} or mnemonic.startswith("j"):
            return None
    return None


def combine_dx_ax_return_expr_8616(
    ax_value: object | None,
    dx_value: object | None,
    codegen: object,
    stack_offset: Callable[[object], int | None],
    wide_stack_expr: Callable[[int, int], object | None],
) -> object | None:
    """Compose a proven DX:AX return without discarding either word."""
    if ax_value is None:
        return None
    if dx_value is None:
        return ax_value
    ax_offset = stack_offset(ax_value)
    dx_offset = stack_offset(dx_value)
    if isinstance(ax_offset, int) and isinstance(dx_offset, int) and dx_offset == ax_offset + 2:
        wide = wide_stack_expr(ax_offset, 4)
        if wide is not None:
            return wide
    if isinstance(ax_value, CConstant) and isinstance(dx_value, CConstant):
        low = int(ax_value.value or 0) & 0xFFFF
        high = int(dx_value.value or 0) & 0xFFFF
        value = (high << 16) | low
        if value & 0x80000000:
            value -= 0x100000000
        return cast(object, CConstant(value, SimTypeLong(True), codegen=codegen))
    long_type = SimTypeLong(False)
    low = CTypeCast(None, long_type, ax_value, codegen=codegen)
    high = CTypeCast(None, long_type, dx_value, codegen=codegen)
    shifted_high = CBinaryOp(
        "Shl",
        high,
        CConstant(16, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    return cast(object, CBinaryOp("Or", shifted_high, low, codegen=codegen))


def terminal_ax_fallback_supports_widths_8616(return_widths: Iterable[int | None]) -> bool:
    """Preserve the compatibility name for the Structuring value-width contract."""
    return bool(terminal_ax_value_supports_widths_8616(return_widths))


def branch_target_return_expr_8616(
    target_addr: int,
    load_block: Callable[[int], object | None],
    scan_block: Callable[[object], BranchTargetReturnBlockResult8616],
    *,
    max_depth: int = 4,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> object | None:
    """Follow CFG target jumps while a callback recovers per-block return expressions."""
    if _depth > max_depth:
        return None
    if _seen is None:
        _seen = set()
    target = int(target_addr)
    if target in _seen:
        return None
    _seen.add(target)
    try:
        block = load_block(target)
    except Exception:
        return None
    if block is None:
        return None
    result = scan_block(block)
    if result.expr is not None:
        if result.next_target is not None and not return_path_preserves_return_registers_8616(
            result.next_target, load_block, max_depth=max_depth - _depth - 1,
        ):
            return None
        return result.expr
    if result.next_target is None:
        return None
    return branch_target_return_expr_8616(
        int(result.next_target),
        load_block,
        scan_block,
        max_depth=max_depth,
        _depth=_depth + 1,
        _seen=_seen,
    )


def ordered_32bit_selector_return_expr_pairs_from_cfg_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: ReturnSelector32BitPairCallbacks8616,
) -> list[tuple[CExpression, CExpression, CExpression]]:
    """Return selector pairs from a dynamic boundary: third-party Capstone 32-bit chains."""
    pairs: list[tuple[CExpression, CExpression, CExpression]] = []
    for block_addr in sorted(int(addr) for addr in callbacks.function_block_addrs(project, codegen)):
        block = callbacks.load_block(int(block_addr))
        if block is None:
            continue
        # Dynamic third-party capstone boundary: block instruction streams are optional.
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        for insn in insns:
            mnemonic = str(getattr(insn, "mnemonic", "")).lower()
            if not mnemonic.startswith("j") or mnemonic in {"jmp", "ljmp"}:
                continue
            targets = selector_targets_from_32bit_jcc_chain_8616(
                int(block_addr),
                insn,
                callbacks.load_block,
                callbacks.branch_target_imm,
                callbacks.next_unconditional_target_after_jcc,
            )
            if targets is None:
                continue
            # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
            insn_addr = int(getattr(insn, "address", -1))
            decoded = callbacks.translate_cmp_jcc_guard(project, codegen, int(block_addr), insn_addr)
            if decoded is None:
                continue
            cond = callbacks.decoded_condition_expr(project, codegen, decoded)
            if cond is None:
                continue
            true_expr = callbacks.branch_target_return_expr(project, codegen, targets[0])
            false_expr = callbacks.branch_target_return_expr(project, codegen, targets[1])
            if true_expr is None or false_expr is None:
                continue
            pairs.append((cond, true_expr, false_expr))
    return pairs


def ordered_conditional_return_expr_pairs_from_cfg_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: ReturnConditionalExprPairCallbacks8616,
) -> list[tuple[CExpression, CExpression, CExpression]]:
    """Return CFG-proven conditional return expression pairs for ordinary JCCs."""
    pairs: list[tuple[CExpression, CExpression, CExpression]] = []
    for block_addr, insn in callbacks.linear_jcc_block_starts(project, codegen):
        true_target = callbacks.branch_target_imm(insn)
        # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
        insn_addr = int(getattr(insn, "address", -1))
        false_target = callbacks.next_unconditional_target_after_jcc(project, int(block_addr), insn_addr)
        if true_target is None or false_target is None:
            continue
        true_expr = callbacks.branch_target_return_expr(project, codegen, int(true_target))
        false_expr = callbacks.branch_target_return_expr(project, codegen, int(false_target))
        if true_expr is None or false_expr is None:
            continue
        decoded = callbacks.translate_cmp_jcc_guard(project, codegen, int(block_addr), insn_addr)
        if decoded is None:
            continue
        tags = {"ins_addr": insn_addr, "vex_block_addr": int(block_addr)}
        cond = callbacks.decoded_condition_expr(project, codegen, decoded, tags)
        if cond is None:
            continue
        condition_call_addr = callbacks.last_call_addr_before_jcc_in_function(project, codegen, insn_addr)
        if condition_call_addr is not None:
            # Dynamic angr/codegen C AST boundary: tags are optional metadata on expressions.
            current_tags = dict(getattr(cond, "tags", {}) or {})
            cond.tags = {**current_tags, "condition_call_ins_addr": int(condition_call_addr)}
        pairs.append((cond, true_expr, false_expr))
    return pairs


def ordered_conditional_void_tail_call_proofs_from_cfg_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: ReturnConditionalVoidTailCallCallbacks8616,
) -> list[tuple[CExpression, CExpression]]:
    """Return CFG-proven conditional void-tail-call guard proofs."""
    proofs: list[tuple[CExpression, CExpression]] = []
    for block_addr, insn in callbacks.linear_jcc_block_starts(project, codegen):
        true_target = callbacks.branch_target_imm(insn)
        # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
        insn_addr = int(getattr(insn, "address", -1))
        false_target = callbacks.next_unconditional_target_after_jcc(project, int(block_addr), insn_addr)
        if true_target is None or false_target is None:
            continue
        true_expr = callbacks.branch_target_return_expr(project, codegen, int(true_target))
        false_expr = callbacks.branch_target_return_expr(project, codegen, int(false_target))
        if true_expr is None or false_expr is not None:
            continue
        decoded = callbacks.translate_cmp_jcc_guard(project, codegen, int(block_addr), insn_addr)
        if decoded is None:
            continue
        cond = callbacks.decoded_condition_expr(project, codegen, decoded)
        if cond is None:
            continue
        proofs.append((cond, true_expr))
    return proofs


def ordered_32bit_conditional_return_pairs_from_cfg_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: Return32BitConditionalPairCallbacks8616,
) -> list[tuple[CExpression, int]]:
    """Return condition/value pairs from a dynamic boundary: third-party Capstone chains."""
    pairs: list[tuple[CExpression, int]] = []
    seen_conditions: set[str] = set()
    for block_addr in sorted(int(addr) for addr in callbacks.function_block_addrs(project, codegen)):
        block = callbacks.load_block(int(block_addr))
        if block is None:
            continue
        # Dynamic third-party capstone boundary: block instruction streams are optional.
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        for insn in insns:
            mnemonic = str(getattr(insn, "mnemonic", "")).lower()
            if not mnemonic.startswith("j") or mnemonic in {"jmp", "ljmp"}:
                continue
            target: int | None = None
            target_pair = selector_targets_from_32bit_jcc_chain_8616(
                int(block_addr),
                insn,
                callbacks.load_block,
                callbacks.branch_target_imm,
                callbacks.next_unconditional_target_after_jcc,
            )
            if target_pair is not None:
                target = target_pair[0]
            else:
                equality_target = equality_return_target_from_32bit_jcc_chain_8616(
                    int(block_addr),
                    insn,
                    callbacks.load_block,
                    callbacks.branch_target_imm,
                    callbacks.next_unconditional_target_after_jcc,
                )
                if isinstance(equality_target, int):
                    target = equality_target
            if target is None:
                target = inequality_target_from_32bit_jcc_chain_8616(
                    int(block_addr),
                    insn,
                    callbacks.load_block,
                    callbacks.branch_target_imm,
                    callbacks.next_unconditional_target_after_jcc,
                )
            if target is None:
                continue
            value = callbacks.branch_target_return_value(project, int(target))
            if value is None:
                continue
            # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
            insn_addr = int(getattr(insn, "address", -1))
            decoded = callbacks.translate_cmp_jcc_guard(project, codegen, int(block_addr), insn_addr)
            if decoded is None:
                continue
            cond = callbacks.decoded_condition_expr(project, codegen, decoded)
            if cond is None:
                continue
            fingerprint = callbacks.expr_fingerprint(cond, project)
            if fingerprint in seen_conditions:
                continue
            seen_conditions.add(fingerprint)
            pairs.append((cond, int(value)))
    return pairs


def ordered_32bit_mask_update_pairs_from_cfg_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    slot_offset: int,
    callbacks: MaskAccumulatorPairCallbacks8616,
) -> list[tuple[CExpression, int]]:
    """Return mask accumulator pairs from a dynamic boundary: third-party Capstone CFG."""
    pairs: list[tuple[CExpression, int]] = []
    seen_conditions: set[str] = set()
    for block_addr, insn in callbacks.linear_jcc_block_starts(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if not mnemonic.startswith("j") or mnemonic in {"jmp", "ljmp"}:
            continue
        target_pair = callbacks.selector_targets_from_32bit_jcc_chain(int(block_addr), insn)
        target = (
            target_pair[0]
            if target_pair is not None
            else callbacks.equality_return_target_from_32bit_jcc_chain(int(block_addr), insn)
        )
        if target is None:
            target = callbacks.inequality_target_from_32bit_jcc_chain(int(block_addr), insn)
        if target is None:
            branch_target = callbacks.branch_target_imm(insn)
            if (
                branch_target is not None
                and callbacks.or_stack_update_imm(project, int(branch_target), int(slot_offset)) is not None
            ):
                target = int(branch_target)
        # Dynamic third-party capstone boundary: instruction addresses are optional metadata.
        insn_addr = int(getattr(insn, "address", -1))
        if target is None:
            false_target = callbacks.next_unconditional_target_after_jcc(project, int(block_addr), insn_addr)
            if (
                false_target is not None
                and callbacks.or_stack_update_imm(project, int(false_target), int(slot_offset)) is not None
            ):
                target = int(false_target)
        if target is None:
            continue
        imm = callbacks.or_stack_update_imm(project, int(target), int(slot_offset))
        if imm is None:
            continue
        decoded = callbacks.translate_cmp_jcc_guard(project, codegen, int(block_addr), insn_addr)
        if decoded is None:
            continue
        cond = callbacks.decoded_condition_expr(project, codegen, decoded)
        if cond is None:
            continue
        fingerprint = callbacks.expr_fingerprint(cond, project)
        if fingerprint in seen_conditions:
            continue
        seen_conditions.add(fingerprint)
        pairs.append((cond, int(imm)))
    return pairs


def materialize_cfg_mask_accumulator_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: MaskAccumulatorMaterializationCallbacks8616,
) -> bool:
    """Materialize mask accumulator chain into a dynamic boundary: angr codegen C AST."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    slot_offset = callbacks.first_stack_zero_init(project, codegen)
    if slot_offset is None:
        return False
    pairs = list(callbacks.ordered_mask_update_pairs(project, codegen, int(slot_offset)))
    imms = tuple(int(imm) for _cond, imm in pairs)
    if imms == (1, 2, 4, 8, 16):
        eq_cond = next(
            (
                cond
                for cond, imm in pairs
                if int(imm) == 16 and isinstance(cond, CBinaryOp) and getattr(cond, "op", None) == "CmpEQ"
            ),
            None,
        )
        if eq_cond is not None:
            pairs.append((CBinaryOp("CmpNE", eq_cond.lhs, eq_cond.rhs, codegen=codegen), 32))
    if len(pairs) < 2:
        return False
    mask_expr = callbacks.stack_slot_expr(codegen, int(slot_offset), 2)
    if mask_expr is None:
        return False
    if mask_accumulator_has_unconsumed_effects_8616(cfunc.statements, mask_expr):
        return False
    statements: list[CStatement] = [
        CAssignment(mask_expr, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    ]
    for cond, imm in pairs:
        rhs = CBinaryOp("Or", mask_expr, CConstant(int(imm), SimTypeShort(False), codegen=codegen), codegen=codegen)
        body = CStatements(statements=[CAssignment(mask_expr, rhs, codegen=codegen)], codegen=codegen)
        statements.append(CIfElse([(cond, body)], else_node=None, cstyle_ifs=True, codegen=codegen))
    statements.append(CReturn(mask_expr, codegen=codegen))
    cfunc.statements = CStatements(statements=statements, codegen=codegen)
    codegen._inertia_mask_accumulator_materialized_8616 = True
    codegen._inertia_mask_accumulator_condition_fingerprints_8616 = tuple(
        callbacks.expr_fingerprint(cond, project) for cond, _imm in pairs
    )
    codegen._inertia_mask_accumulator_return_fingerprint_8616 = callbacks.expr_fingerprint(mask_expr, project)
    codegen._inertia_mask_accumulator_update_immediates_8616 = tuple(int(imm) for _cond, imm in pairs)
    return True


def selector_stack_expr_from_ax_load_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: SelectorStackExprCallbacks8616,
) -> CExpression | None:
    """Recover selector stack expression from a dynamic boundary: third-party Capstone instructions."""
    for insn in callbacks.linear_function_insns(project, codegen):
        # Dynamic third-party capstone boundary: instructions expose mnemonic/operands/reg_name.
        operands = tuple(getattr(insn, "operands", ()) or ())
        reg_name = getattr(insn, "reg_name", None)
        if not callable(reg_name):
            continue
        if (
            str(getattr(insn, "mnemonic", "")).lower() == "mov"
            and len(operands) == 2
            and int(getattr(operands[0], "type", -1)) == 1
            and _return_chain_reg_name_8616(insn, operands[0]) == "ax"
            and int(getattr(operands[1], "type", -1)) == 3
        ):
            mem = getattr(operands[1], "mem", None)
            mem_base = getattr(mem, "base", None)
            if mem is not None and isinstance(mem_base, int) and mem_base and str(reg_name(mem_base)).lower() == "bp":
                return callbacks.stack_slot_expr(
                    codegen,
                    int(mem.disp),
                    int(getattr(operands[1], "size", 0) or 2),
                    project,
                )
    return None


def materialize_sequential_decrement_switch_return_chain_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: SequentialDecrementSwitchCallbacks8616,
) -> bool:
    """Materialize decrement/JNE chains from a dynamic boundary: third-party Capstone instructions."""
    selector = callbacks.selector_stack_expr(project, codegen)
    if selector is None:
        return False
    if callbacks.selector_function_has_unsafe_effects(project, codegen):
        return False
    insns = tuple(callbacks.linear_function_insns(project, codegen))
    chain: list[object] = []
    for insn in insns:
        # Dynamic third-party capstone boundary: instructions expose mnemonic/operands/reg_name/address.
        reg_name = getattr(insn, "reg_name", None)
        if not callable(reg_name):
            continue
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        raw_operands = getattr(insn, "operands", ())
        operands: tuple[object, ...] = tuple(raw_operands) if isinstance(raw_operands, (list, tuple)) else ()
        if mnemonic == "or" and len(operands) == 2:
            all_ax_registers = True
            for op in operands:
                if int(getattr(op, "type", -1)) != 1 or _return_chain_reg_name_8616(insn, op) != "ax":
                    all_ax_registers = False
                    break
            if all_ax_registers:
                chain.append(insn)
                continue
        if mnemonic == "dec" and len(operands) == 1:  # noqa: SIM102
            if int(getattr(operands[0], "type", -1)) == 1 and _return_chain_reg_name_8616(insn, operands[0]) == "ax":
                chain.append(insn)
    if len(chain) < 2:
        return False
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}

    def _following_jcc_after(insn: object, expected: set[str]) -> object | None:
        """Return following JCC from a dynamic boundary: third-party Capstone instructions."""
        start = index_by_addr.get(int(getattr(insn, "address", -1)))
        if start is None or start + 1 >= len(insns):
            return None
        jcc = insns[start + 1]
        mnemonic = str(getattr(jcc, "mnemonic", "")).lower()
        return jcc if mnemonic in expected else None

    jccs = [_following_jcc_after(insn, {"jne", "jnz"}) for insn in chain]
    if any(jcc is None for jcc in jccs):
        return False
    case_targets: list[int] = []
    for jcc in jccs:
        if jcc is None:
            return False
        jcc_idx = index_by_addr.get(int(getattr(jcc, "address", -1)))
        if jcc_idx is None:
            return False
        target = callbacks.resolve_one_hop_jmp_target(project, callbacks.next_linear_jmp_target(insns, jcc_idx))
        if target is None:
            return False
        case_targets.append(int(target))
    last_jcc = jccs[-1]
    if last_jcc is None:
        return False
    default_target = callbacks.resolve_one_hop_jmp_target(project, callbacks.branch_target_imm(last_jcc))
    if default_target is None:
        return False
    case_exprs = [callbacks.branch_target_return_expr(project, codegen, target) for target in case_targets]
    default_expr = callbacks.branch_target_return_expr(project, codegen, int(default_target))
    if default_expr is None or any(expr is None for expr in case_exprs):
        return False

    statements: list[CStatement] = []
    condition_fingerprints: list[str] = []
    for case_value, expr in enumerate(case_exprs):
        if expr is None:
            return False
        cond = CBinaryOp(
            "CmpEQ",
            callbacks.clone_c_value(selector),
            CConstant(int(case_value), SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        condition_fingerprints.append(callbacks.expr_fingerprint(cond, project))
        statements.append(
            CIfElse(
                [
                    (
                        cond,
                        CStatements(
                            statements=[CReturn(callbacks.clone_c_value(expr), codegen=codegen)],
                            codegen=codegen,
                        ),
                    )
                ],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            )
        )
    statements.append(CReturn(callbacks.clone_c_value(default_expr), codegen=codegen))
    callbacks.set_cfunc_statements_root(codegen, CStatements(statements=statements, codegen=codegen))
    codegen._inertia_decrement_switch_return_materialized_8616 = True
    codegen._inertia_sequential_decrement_switch_return_materialized_8616 = True
    codegen._inertia_return_expr_chain_materialized_8616 = True
    codegen._inertia_return_selector_materialized_8616 = True
    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(condition_fingerprints)
    codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = tuple(
        callbacks.expr_fingerprint(expr, project) for expr in (*case_exprs, default_expr)
    )
    codegen._inertia_return_selector_raw_stack_slot_aliases_8616 = callbacks.selector_raw_stack_aliases(
        project, selector
    )
    return True


def materialize_complex_decrement_switch_return_chain_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: ComplexDecrementSwitchCallbacks8616,
) -> bool:
    """Materialize four-guard switch chains from a dynamic boundary: third-party Capstone instructions."""
    selector = callbacks.selector_stack_expr(project, codegen)
    if selector is None:
        return False
    if callbacks.selector_function_has_unsafe_effects(project, codegen):
        return False
    insns = tuple(callbacks.linear_function_insns(project, codegen))
    chain: list[object] = []
    for insn in insns:
        # Dynamic third-party capstone boundary: instructions expose mnemonic/operands/reg_name/address.
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        raw_operands = getattr(insn, "operands", ())
        operands: tuple[object, ...] = tuple(raw_operands) if isinstance(raw_operands, (list, tuple)) else ()
        if mnemonic == "or" and len(operands) == 2:
            all_ax_registers = True
            for op in operands:
                if int(getattr(op, "type", -1)) != 1 or _return_chain_reg_name_8616(insn, op) != "ax":
                    all_ax_registers = False
                    break
            if all_ax_registers:
                chain.append(insn)
                continue
        if mnemonic == "dec" and len(operands) == 1:  # noqa: SIM102
            if int(getattr(operands[0], "type", -1)) == 1 and _return_chain_reg_name_8616(insn, operands[0]) == "ax":
                chain.append(insn)
    if len(chain) < 4:
        return False
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}

    def _following_jcc_after(insn: object, expected: set[str]) -> object | None:
        """Return following JCC from a dynamic boundary: third-party Capstone instructions."""
        start = index_by_addr.get(int(getattr(insn, "address", -1)))
        if start is None or start + 1 >= len(insns):
            return None
        jcc = insns[start + 1]
        mnemonic = str(getattr(jcc, "mnemonic", "")).lower()
        return jcc if mnemonic in expected else None

    jcc0 = _following_jcc_after(chain[0], {"jne", "jnz"})
    jcc1 = _following_jcc_after(chain[1], {"jge", "jnl"})
    jcc2 = _following_jcc_after(chain[2], {"jg", "jnle"})
    jcc3 = _following_jcc_after(chain[3], {"jne", "jnz"})
    if any(jcc is None for jcc in (jcc0, jcc1, jcc2, jcc3)):
        return False

    def _fallthrough_target(jcc: object | None) -> int | None:
        """Return fallthrough target from a dynamic boundary: third-party Capstone instructions."""
        if jcc is None:
            return None
        jcc_idx = index_by_addr.get(int(getattr(jcc, "address", -1)))
        if jcc_idx is None:
            return None
        return callbacks.resolve_one_hop_jmp_target(project, callbacks.next_linear_jmp_target(insns, jcc_idx))

    target_case0 = _fallthrough_target(jcc0)
    target_default_1 = _fallthrough_target(jcc1)
    target_case12 = _fallthrough_target(jcc2)
    target_case3 = _fallthrough_target(jcc3)
    if jcc3 is None:
        return False
    target_default_2 = callbacks.resolve_one_hop_jmp_target(project, callbacks.branch_target_imm(jcc3))
    if None in {target_case0, target_default_1, target_case12, target_case3, target_default_2}:
        return False
    if (
        target_case0 is None
        or target_default_1 is None
        or target_case12 is None
        or target_case3 is None
        or target_default_2 is None
    ):
        return False
    target_case0_int = int(target_case0)
    target_default_int = int(target_default_1)
    target_case12_int = int(target_case12)
    target_case3_int = int(target_case3)
    target_default_2_int = int(target_default_2)
    if target_default_int != target_default_2_int:
        return False
    expr_case0 = callbacks.branch_target_return_expr(project, codegen, target_case0_int)
    expr_default = callbacks.branch_target_return_expr(project, codegen, target_default_int)
    expr_case12 = callbacks.branch_target_return_expr(project, codegen, target_case12_int)
    expr_case3 = callbacks.branch_target_return_expr(project, codegen, target_case3_int)
    if any(expr is None for expr in (expr_case0, expr_default, expr_case12, expr_case3)):
        return False
    if expr_case0 is None or expr_default is None or expr_case12 is None or expr_case3 is None:
        return False

    def _cmp(op: str, value: int) -> CBinaryOp:
        return CBinaryOp(
            op,
            callbacks.clone_c_value(selector),
            CConstant(int(value), SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    ordered: tuple[tuple[CExpression, CExpression], ...] = (
        (_cmp("CmpEQ", 0), expr_case0),
        (_cmp("CmpLT", 1), expr_default),
        (_cmp("CmpLE", 2), expr_case12),
        (_cmp("CmpEQ", 3), expr_case3),
    )
    statements: list[CStatement] = [
        CIfElse(
            [
                (
                    callbacks.clone_c_value(cond),
                    CStatements(
                        statements=[CReturn(callbacks.clone_c_value(expr), codegen=codegen)],
                        codegen=codegen,
                    ),
                )
            ],
            else_node=None,
            cstyle_ifs=True,
            codegen=codegen,
        )
        for cond, expr in ordered
    ]
    statements.append(CReturn(callbacks.clone_c_value(expr_default), codegen=codegen))
    callbacks.set_cfunc_statements_root(codegen, CStatements(statements=statements, codegen=codegen))
    codegen._inertia_decrement_switch_return_materialized_8616 = True
    codegen._inertia_return_expr_chain_materialized_8616 = True
    codegen._inertia_return_selector_materialized_8616 = True
    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(
        callbacks.expr_fingerprint(cond, project) for cond, _expr in ordered
    )
    codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = (
        *tuple(callbacks.expr_fingerprint(expr, project) for _cond, expr in ordered),
        callbacks.expr_fingerprint(expr_default, project),
    )
    codegen._inertia_return_selector_raw_stack_slot_aliases_8616 = callbacks.selector_raw_stack_aliases(
        project, selector
    )
    return True


def selector_function_has_unsafe_effects_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: SelectorUnsafeEffectsCallbacks8616,
    *,
    allowed_call_addrs: frozenset[int] = frozenset(),
) -> bool:
    """Return side-effect risk from a dynamic boundary: third-party Capstone instructions."""
    # Some instruction-only callers run before angr publishes a C function.
    try:
        root = codegen.cfunc.statements
    except AttributeError:
        root = None
    if selector_return_storage_write_obligations_8616(root):
        return True
    inventory = callbacks.function_inventory(project, codegen)
    if not inventory.complete:
        return True
    previous_insn: object | None = None
    seen_branch = False
    for insn in inventory.instructions:
        # Dynamic third-party capstone boundary: instructions expose mnemonic/operands/address/size.
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        capstone_insn = _capstone_attr_8616(insn, "insn", insn)
        operands = _dynamic_object_tuple_8616(
            _capstone_attr_8616(capstone_insn, "operands", ())
        )
        if mnemonic in {"call", "lcall"}:
            target = callbacks.direct_call_target(insn)
            if target is None:
                return True
            name, _callee = callbacks.callee_name_for_target(project, int(target))
            if not callbacks.target_is_stack_probe_helper(project, int(target), name):
                previous_capstone_insn = (
                    _capstone_attr_8616(previous_insn, "insn", previous_insn)
                    if previous_insn is not None
                    else None
                )
                prev_operands = _dynamic_object_tuple_8616(
                    _capstone_attr_8616(previous_capstone_insn, "operands", ())
                )
                next_addr = int(getattr(insn, "address", 0) or 0) + int(getattr(insn, "size", 0) or 0)
                stack_probe_rel0 = (
                    not seen_branch
                    and int(target) == next_addr
                    and str(getattr(previous_insn, "mnemonic", "")).lower() == "mov"
                    and len(prev_operands) == 2
                    and int(getattr(prev_operands[0], "type", -1)) == 1
                    and _return_chain_reg_name_8616(previous_insn, prev_operands[0]) == "ax"
                    and int(getattr(prev_operands[1], "type", -1)) == 2
                )
                if stack_probe_rel0:
                    previous_insn = insn
                    continue
                if int(getattr(insn, "address", -1)) in allowed_call_addrs:
                    previous_insn = insn
                    continue
                return True
            previous_insn = insn
            continue
        if mnemonic.startswith("j"):
            seen_branch = True
            previous_insn = insn
            continue
        if mnemonic in {"push", "pop", "ret", "retf", "iret", "leave"}:
            previous_insn = insn
            continue
        memory_write_mnemonics = {
            "mov",
            "add",
            "sub",
            "adc",
            "sbb",
            "and",
            "or",
            "xor",
            "inc",
            "dec",
            "neg",
            "not",
            "xchg",
        }
        if mnemonic in memory_write_mnemonics and operands and int(getattr(operands[0], "type", -1)) == 3:
            return True
        if mnemonic.startswith(("stos", "movs")):
            return True
        previous_insn = insn
    return False


def materialize_cfg_selector_return_branches_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: ReturnSelectorCallbacks8616,
) -> bool:
    """Materialize selector returns into a dynamic boundary: angr codegen C AST."""
    ensure_return_chain_codegen_state_8616(codegen)
    projection_before = assess_selector_return_projection_8616(codegen, project, callbacks.expr_fingerprint)
    if projection_before.active and projection_before.accepted:
        return False
    repairing_stale_projection = projection_before.active

    def _refuse(reason: str) -> bool:
        """Refuse initial discovery, but hard-fail a classified stale projection."""
        if repairing_stale_projection:
            require_selector_return_projection_8616(
                codegen,
                project,
                callbacks.expr_fingerprint,
                context=f"selector-return-replay:{reason}",
            )
        return False

    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    stats = codegen._inertia_cfg_selector_return_stats_8616
    if not isinstance(stats, dict):
        stats = {"candidates": 0, "materialized": 0, "refused": 0}
        codegen._inertia_cfg_selector_return_stats_8616 = stats
    multi_arm_obligations = multi_arm_wide_return_obligation_count_8616(
        codegen.cfunc.statements
    )
    if multi_arm_obligations:
        stats["candidates"] += multi_arm_obligations
        stats["refused"] += multi_arm_obligations
        if debug:
            log.warning(
                "[cfg-selector-return] refused existing multi-arm obligations=%d stats=%r",
                multi_arm_obligations,
                stats,
            )
        return _refuse("multi-arm-obligation")
    write_obligations = selector_return_storage_write_obligations_8616(codegen.cfunc.statements)
    if write_obligations:
        stats["refused"] += len(write_obligations)
        log.debug("[cfg-selector-return] function=%#x refused unconsumed storage writes=%d",
                  codegen.cfunc.addr, len(write_obligations))
        return _refuse("unconsumed-storage-writes")
    if callbacks.materialize_decrement_switch_return_chain(project, codegen):
        stats["materialized"] += 1
        require_selector_return_projection_8616(
            codegen,
            project,
            callbacks.expr_fingerprint,
            context="selector-return-replay:decrement-switch",
        )
        return True
    pairs = callbacks.ordered_32bit_selector_return_expr_pairs(project, codegen)
    pair_source = "32bit"
    if not pairs:
        pairs = callbacks.ordered_conditional_return_expr_pairs(project, codegen)
        pair_source = "jcc"
    stats["candidates"] += len(pairs)
    if debug:
        log.warning("[cfg-selector-return] candidates=%d source=%s stats=%r", len(pairs), pair_source, stats)
    if not pairs:
        return _refuse("missing-pairs")
    if len(pairs) > 1:
        fingerprints = [callbacks.expr_fingerprint(cond, project) for cond, _true_expr, _false_expr in pairs]
        if len(set(fingerprints)) != len(fingerprints):
            stats["refused"] += len(pairs)
            return _refuse("duplicate-conditions")
    allowed_call_addrs = callbacks.selector_condition_call_addrs(
        pairs
    ) | callbacks.selector_condition_call_addrs_from_cfg(project, codegen)
    if callbacks.selector_function_has_unsafe_effects(project, codegen, allowed_call_addrs):
        stats["refused"] += 1
        if debug:
            log.warning(
                "[cfg-selector-return] refused unsafe-effects stats=%r allowed_call_addrs=%r pair_slots=%r",
                stats,
                tuple(sorted(allowed_call_addrs)),
                tuple(
                    (_debug_cvar_slot_8616(cond.lhs), _debug_cvar_slot_8616(cond.rhs))
                    for cond, _true_expr, _false_expr in pairs
                    if isinstance(cond, CBinaryOp)
                ),
            )
        return _refuse("unsafe-effects")
    statements: list[object] = []
    return_fingerprints: list[str] = []
    for cond, true_expr, false_expr in pairs:
        if debug:
            log.warning(
                "[cfg-selector-return] materialize pair cond_fp=%r lhs=%s rhs=%s true=%s false=%s",
                callbacks.expr_fingerprint(cond, project),
                _debug_cvar_slot_8616(getattr(cond, "lhs", None)),
                _debug_cvar_slot_8616(getattr(cond, "rhs", None)),
                _debug_cvar_slot_8616(true_expr),
                _debug_cvar_slot_8616(false_expr),
            )
        true_body = CStatements(
            statements=[CReturn(callbacks.clone_c_value_for_codegen_tree(true_expr), codegen=codegen)],
            codegen=codegen,
        )
        statements.append(
            CIfElse(
                [(callbacks.clone_c_value_for_codegen_tree(cond), true_body)],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            )
        )
        return_fingerprints.append(callbacks.expr_fingerprint(true_expr, project))
    final_expr = pairs[-1][2]
    statements.append(CReturn(callbacks.clone_c_value_for_codegen_tree(final_expr), codegen=codegen))
    return_fingerprints.append(callbacks.expr_fingerprint(final_expr, project))
    callbacks.set_cfunc_statements_root(codegen, CStatements(statements=statements, codegen=codegen))
    stats["materialized"] += len(pairs)
    codegen._inertia_return_expr_chain_materialized_8616 = True
    codegen._inertia_return_selector_materialized_8616 = True
    condition_fingerprints = tuple(callbacks.expr_fingerprint(cond, project) for cond, _true_expr, _false_expr in pairs)
    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = condition_fingerprints
    codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = tuple(return_fingerprints)
    require_selector_return_projection_8616(
        codegen,
        project,
        callbacks.expr_fingerprint,
        context="selector-return-replay:cfg-pairs",
    )
    if debug:
        debug_cfunc = codegen.cfunc
        debug_root = getattr(debug_cfunc, "statements", None)
        first_stmt = next(iter(getattr(debug_root, "statements", ()) or ()), None)
        first_cond = None
        if isinstance(first_stmt, CIfElse):
            cond_nodes = first_stmt.condition_and_nodes or ()
            if cond_nodes:
                first_cond = cond_nodes[0][0]
        log.warning(
            "[cfg-selector-return] materialized root cond_fp=%r lhs=%s rhs=%s returns=%r",
            callbacks.expr_fingerprint(first_cond, project) if first_cond is not None else None,
            _debug_cvar_slot_8616(getattr(first_cond, "lhs", None)),
            _debug_cvar_slot_8616(getattr(first_cond, "rhs", None)),
            codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616,
        )
    return True


def condition_branch_return_value_8616(
    project: object,
    cond: object,
    callbacks: ReturnChainProofCallbacks8616,
) -> int | None:
    """Return branch return constant from a dynamic boundary: third-party Capstone block."""
    key = callbacks.condition_tags(cond)
    if not isinstance(key, tuple) or len(key) != 2:
        return None
    jcc_addr, block_addr = key
    if not isinstance(jcc_addr, int) or not isinstance(block_addr, int):
        return None
    try:
        block = project.factory.block(int(block_addr), opt_level=0)  # type: ignore[attr-defined]
    except Exception:
        return None
    for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        if int(getattr(insn, "address", -1)) != int(jcc_addr):
            continue
        target = callbacks.branch_target_imm(insn)
        if target is None:
            return None
        return callbacks.branch_target_return_value(project, target)
    return None


def ordered_conditional_return_values_8616(
    project: object,
    codegen: object,
    callbacks: ReturnChainProofCallbacks8616,
) -> list[int]:
    """Return CFG-proven JCC branch return constants in instruction order."""
    values: list[int] = []
    for _block_addr, insn in callbacks.linear_jcc_block_starts(project, codegen):
        target = callbacks.branch_target_imm(insn)
        if target is None:
            continue
        value = callbacks.branch_target_return_value(project, target)
        if value is not None:
            values.append(value)
    return values


def ordered_conditional_return_pairs_from_cfg_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: ReturnChainProofCallbacks8616,
) -> list[tuple[CExpression, int]]:
    """Return condition/return pairs from a dynamic boundary: third-party Capstone JCC order."""
    pairs: list[tuple[CExpression, int]] = []
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    jcc_count = 0
    return_target_count = 0
    decoded_count = 0
    selection_verdicts: list[str] = []
    structured_conditions = unique_tagged_conditions_8616(
        codegen.cfunc.statements,
        callbacks.iter_c_nodes_deep,
        callbacks.condition_tags,
    )
    for block_addr, insn in callbacks.linear_jcc_block_starts(project, codegen):
        jcc_count += 1
        target = callbacks.branch_target_imm(insn)
        if target is None:
            continue
        value = callbacks.branch_target_return_value(project, target)
        if value is None:
            continue
        return_target_count += 1
        insn_addr = int(getattr(insn, "address", 0) or 0)
        decoded = callbacks.translate_cmp_jcc_guard(project, codegen, int(block_addr), insn_addr)
        if decoded is None:
            continue
        decoded_count += 1
        tags = {"ins_addr": insn_addr, "vex_block_addr": int(block_addr)}
        condition_call_addr = callbacks.last_call_addr_before_jcc(project, codegen, insn_addr)
        decoded_expr = callbacks.decoded_condition_expr(project, codegen, decoded, tags)
        expr = structured_conditions.get((insn_addr, int(block_addr)))
        if expr is not None and condition_call_addr is not None:
            call_addrs = selector_condition_call_addrs_8616(((expr,),), callbacks.iter_c_nodes_deep)
            if condition_call_addr not in call_addrs:
                expr = None
        if expr is None:
            expr = decoded_expr
        elif decoded_expr is not None:
            branch_key = (insn_addr, int(block_addr))
            selection = select_cfg_return_condition_8616(
                codegen,
                expr,
                decoded_expr,
                same_branch_proven=(
                    callbacks.condition_tags(expr) == branch_key
                    and callbacks.condition_tags(decoded_expr) == branch_key
                ),
            )
            selection_verdicts.append(selection.verdict.value)
            expr = selection.condition
        if expr is None:
            continue
        if condition_call_addr is not None:
            expr.tags = {**dict(expr.tags or {}), "condition_call_ins_addr": int(condition_call_addr)}
        pairs.append((expr, int(value)))
    if debug:
        log.warning(
            "[cfg-return-chain] addr=%r jcc=%d return_targets=%d decoded=%d pairs=%d selections=%r",
            getattr(codegen.cfunc, "addr", None),
            jcc_count,
            return_target_count,
            decoded_count,
            len(pairs),
            tuple(selection_verdicts),
        )
    return pairs


def single_if_return_8616(stmt: object) -> tuple[object, object] | None:
    """Return condition and retval from a dynamic boundary: angr codegen C AST if-return."""
    if not isinstance(stmt, CIfElse):
        return None
    cond_nodes = stmt.condition_and_nodes or ()
    if len(cond_nodes) != 1:
        return None
    cond_body = next(iter(cond_nodes))
    if len(cond_body) != 2:
        return None
    cond, body = cond_body
    if isinstance(body, CStatements):
        body_statements = list(body.statements or ())
    elif isinstance(body, CReturn):
        body_statements = [body]
    else:
        return None
    if len(body_statements) != 1 or not isinstance(body_statements[0], CReturn):
        return None
    return cond, getattr(body_statements[0], "retval", None)


def const_return_value_8616(expr: object) -> int | None:
    """Return integer value from a dynamic boundary: angr codegen C constant."""
    if not isinstance(expr, CConstant):
        return None
    try:
        return int(expr.value)
    except Exception:
        return None


def is_empty_return_statement_8616(stmt: object) -> bool:
    """Return whether a dynamic boundary: angr codegen C AST statement is empty return."""
    if isinstance(stmt, CReturn):
        return stmt.retval is None
    if isinstance(stmt, CStatements):
        nested = list(stmt.statements or ())
        return len(nested) == 1 and is_empty_return_statement_8616(nested[0])
    return False


def duplicate_empty_return_guard_prune_plan_8616(
    project: object,
    statements: Sequence[object],
    values: Sequence[int],
    callbacks: ReturnChainFlattenCallbacks8616,
) -> DuplicateEmptyReturnGuardPrunePlan8616 | None:
    """Plan removal of a CFG-proven duplicate empty return guard before a return chain."""
    indexed_statements = tuple(statements)
    expected_values = tuple(int(value) for value in values)
    if not expected_values or len(indexed_statements) <= len(expected_values):
        return None

    for index in range(len(indexed_statements) - 1):
        previous = callbacks.single_if_return(indexed_statements[index])
        following = callbacks.single_if_return(indexed_statements[index + 1])
        if previous is None or following is None:
            continue
        previous_cond, previous_retval = previous
        following_cond, following_retval = following
        following_value = callbacks.const_return_value(following_retval)
        if previous_retval is not None or following_value not in expected_values:
            continue
        try:
            previous_fp = callbacks.expr_fingerprint(previous_cond, project)
            following_fp = callbacks.expr_fingerprint(following_cond, project)
        except Exception:
            continue
        if previous_fp != following_fp:
            continue
        return DuplicateEmptyReturnGuardPrunePlan8616(
            index=index,
            reason=DuplicateEmptyReturnGuardPruneReason8616.ADJACENT_DUPLICATE_EMPTY_GUARD,
            value=following_value,
        )

    chain_index: int | None = None
    for index in range(len(indexed_statements) - len(expected_values) + 1):
        matched = True
        for offset, expected_value in enumerate(expected_values):
            item = callbacks.single_if_return(indexed_statements[index + offset])
            if item is None or callbacks.const_return_value(item[1]) != expected_value:
                matched = False
                break
        if matched:
            chain_index = index
            break
    if chain_index is None or chain_index <= 0:
        return None

    previous_stmt = indexed_statements[chain_index - 1]
    if is_empty_return_statement_8616(previous_stmt):
        return DuplicateEmptyReturnGuardPrunePlan8616(
            index=chain_index - 1,
            reason=DuplicateEmptyReturnGuardPruneReason8616.EMPTY_PREFIX_BEFORE_CHAIN,
        )

    previous = callbacks.single_if_return(previous_stmt)
    first = callbacks.single_if_return(indexed_statements[chain_index])
    if previous is None or first is None:
        return None
    previous_cond, previous_retval = previous
    first_cond, _first_retval = first
    if previous_retval is not None:
        return None
    try:
        if callbacks.expr_fingerprint(previous_cond, project) != callbacks.expr_fingerprint(first_cond, project):
            return None
    except Exception:
        return None
    return DuplicateEmptyReturnGuardPrunePlan8616(
        index=chain_index - 1,
        reason=DuplicateEmptyReturnGuardPruneReason8616.DUPLICATE_PREFIX_BEFORE_CHAIN,
    )


def record_flattened_return_chain_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    cond_return_pairs: list[tuple[CExpression, int]],
    final_value: int,
    callbacks: ReturnChainFlattenCallbacks8616,
) -> None:
    """Record the CFG return-chain evidence consumed by the flattened C AST."""
    codegen._inertia_return_chain_flattened_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = tuple(int(value) for _cond, value in cond_return_pairs)
    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(
        callbacks.expr_fingerprint(cond, project) for cond, _value in cond_return_pairs
    )
    codegen._inertia_return_chain_final_value_8616 = int(final_value)


def root_matches_flattened_return_chain_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    cond_return_pairs: list[tuple[CExpression, int]],
    final_value: int,
    callbacks: ReturnChainFlattenCallbacks8616,
) -> bool:
    """Return true when a dynamic boundary: angr codegen C AST already matches CFG evidence."""
    cfunc = codegen.cfunc
    root = getattr(cfunc, "statements", None)
    statements = list(getattr(root, "statements", ()) or ())
    if len(statements) != len(cond_return_pairs) + 1:
        return False
    for stmt, (cond, value) in zip(statements[:-1], cond_return_pairs, strict=False):
        existing = callbacks.single_if_return(stmt)
        if existing is None:
            return False
        existing_cond, existing_retval = existing
        if callbacks.const_return_value(existing_retval) != int(value):
            return False
        try:
            if callbacks.expr_fingerprint(existing_cond, project) != callbacks.expr_fingerprint(cond, project):
                return False
        except Exception:
            return False
    return callbacks.const_return_value(getattr(statements[-1], "retval", None)) == int(final_value)


def flatten_conditional_return_chain_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    cond_return_pairs: list[tuple[CExpression, int]],
    callbacks: ReturnChainFlattenCallbacks8616,
) -> bool:
    """Flatten CFG-proven conditional returns, reporting changes only for real AST deltas."""
    if len(cond_return_pairs) < 2:
        return False
    final_value = callbacks.final_return_value(project, codegen)
    if final_value is None:
        return False
    if root_matches_flattened_return_chain_8616(project, codegen, cond_return_pairs, final_value, callbacks):
        record_flattened_return_chain_8616(project, codegen, cond_return_pairs, final_value, callbacks)
        return False
    statements: list[object] = []
    for cond, value in cond_return_pairs:
        if cond is None:
            return False
        body = CStatements(
            statements=[CReturn(CConstant(int(value), SimTypeShort(False), codegen=codegen), codegen=codegen)],
            codegen=codegen,
        )
        statements.append(CIfElse([(cast(CExpression, cond), body)], else_node=None, cstyle_ifs=True, codegen=codegen))
    statements.append(CReturn(CConstant(int(final_value), SimTypeShort(False), codegen=codegen), codegen=codegen))
    callbacks.set_cfunc_statements_root(codegen, CStatements(statements=statements, codegen=codegen))
    materialized_ifs = sum(
        1 for node in callbacks.iter_c_nodes_deep(codegen.cfunc.statements) if isinstance(node, CIfElse)
    )
    materialized_returns = sum(
        1 for node in callbacks.iter_c_nodes_deep(codegen.cfunc.statements) if isinstance(node, CReturn)
    )
    if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
        logging.getLogger(__name__).warning(
            "[empty-return-branch] flattened ifs=%d returns=%d expected_ifs=%d expected_returns=%d final=%r",
            materialized_ifs,
            materialized_returns,
            len(cond_return_pairs),
            len(cond_return_pairs) + 1,
            final_value,
        )
    if materialized_ifs != len(cond_return_pairs) or materialized_returns != len(cond_return_pairs) + 1:
        return False
    record_flattened_return_chain_8616(project, codegen, cond_return_pairs, final_value, callbacks)
    return True


def node_contains_call_8616(node: object, callbacks: ReturnChainFlattenCallbacks8616) -> bool:
    """Return whether a dynamic boundary: angr codegen C AST node contains a call."""
    return any(isinstance(child, CFunctionCall) for child in callbacks.iter_c_nodes_deep(node))


def calls_in_nodes_8616(
    nodes: Iterable[object], callbacks: ReturnChainFlattenCallbacks8616
) -> tuple[CFunctionCall, ...]:
    """Collect calls from a dynamic boundary: angr codegen C AST nodes."""
    calls: list[CFunctionCall] = []
    seen: set[int] = set()
    for node in nodes:
        if isinstance(node, CFunctionCall):
            seen.add(id(node))
            calls.append(node)
        for child in callbacks.iter_c_nodes_deep(node):
            if id(child) in seen:
                continue
            if isinstance(child, CFunctionCall):
                seen.add(id(child))
                calls.append(child)
    return tuple(calls)


def materialize_void_tail_call_suffix_diamond_8616(
    *,
    stmt: CIfElse,
    statements: list[object],
    index: int,
    cond: object,
    false_body: object,
    cond_keys: frozenset[object],
    proofs: Iterable[tuple[frozenset[object], str]],
    codegen: object,
    callbacks: VoidTailCallSuffixDiamondCallbacks8616,
) -> VoidTailCallSuffixDiamondResult8616:
    """Materialize tail-call suffix from a dynamic boundary: angr codegen C AST statements."""
    suffix_from_else = False
    else_node = getattr(stmt, "else_node", None)
    if index + 1 >= len(statements):
        if else_node is not None and not callbacks.c_node_semantically_empty(else_node):
            suffix = [else_node]
            suffix_from_else = True
        else:
            return VoidTailCallSuffixDiamondResult8616(
                status=VoidTailCallSuffixDiamondStatus8616.NO_SUFFIX,
                suffix_from_else=suffix_from_else,
            )
    else:
        suffix = list(statements[index + 1 :])
    if not suffix:
        return VoidTailCallSuffixDiamondResult8616(
            status=VoidTailCallSuffixDiamondStatus8616.EMPTY_SUFFIX,
            suffix_from_else=suffix_from_else,
        )
    if suffix_from_else and len(suffix) == 1 and isinstance(suffix[0], CStatements):
        true_body = suffix[0]
    else:
        true_body = CStatements(statements=suffix, codegen=codegen)
    true_body_statements = list(getattr(true_body, "statements", ()) or ())
    if not true_body_statements:
        return VoidTailCallSuffixDiamondResult8616(
            status=VoidTailCallSuffixDiamondStatus8616.EMPTY_SUFFIX,
            suffix_from_else=suffix_from_else,
        )

    suffix_calls = callbacks.calls_in_nodes(suffix)
    exact_matches = [true_fp for proof_keys, true_fp in proofs if cond_keys & proof_keys]
    if len(set(exact_matches)) != 1:
        return VoidTailCallSuffixDiamondResult8616(
            status=VoidTailCallSuffixDiamondStatus8616.BRANCH_MATCH_MISSING_OR_AMBIGUOUS,
            match_count=len(set(exact_matches)),
            suffix_from_else=suffix_from_else,
        )
    proven_true_fp = exact_matches[0]
    false_fps = callbacks.node_component_fingerprints(false_body)
    suffix_fps: set[str] = set()
    for suffix_stmt in suffix:
        suffix_fps.update(callbacks.node_component_fingerprints(suffix_stmt))
    if proven_true_fp in false_fps:
        return VoidTailCallSuffixDiamondResult8616(
            status=VoidTailCallSuffixDiamondStatus8616.FALSE_ARM_MATCHES_TRUE,
            match_fingerprint=proven_true_fp,
            suffix_from_else=suffix_from_else,
        )
    if proven_true_fp not in suffix_fps:
        return VoidTailCallSuffixDiamondResult8616(
            status=VoidTailCallSuffixDiamondStatus8616.SUFFIX_MISSING_TRUE,
            match_fingerprint=proven_true_fp,
            suffix_types=tuple(type(item).__name__ for item in suffix),
            suffix_from_else=suffix_from_else,
        )
    matching_suffix_calls = [
        call for call in suffix_calls if proven_true_fp in callbacks.call_argument_component_fingerprints(call)
    ]
    if len(matching_suffix_calls) > 1:
        return VoidTailCallSuffixDiamondResult8616(
            status=VoidTailCallSuffixDiamondStatus8616.AMBIGUOUS_SUFFIX_CALL,
            match_fingerprint=proven_true_fp,
            match_count=len(matching_suffix_calls),
            suffix_from_else=suffix_from_else,
        )

    _set_if_true_body_compat_8616(stmt, cond, true_body)
    stmt.else_node = false_body
    if not suffix_from_else:
        del statements[index + 1 :]
    return VoidTailCallSuffixDiamondResult8616(
        status=VoidTailCallSuffixDiamondStatus8616.MATERIALIZED,
        match_fingerprint=proven_true_fp,
        suffix_from_else=suffix_from_else,
    )


def materialize_void_tail_call_guard_8616(
    *,
    stmt: CIfElse,
    statements: list[object],
    index: int,
    proof: VoidTailCallGuardProof8616,
    tail_from_else: bool,
    tail_payload: tuple[CFunctionCall, object],
    codegen: object,
) -> VoidTailCallGuardResult8616:
    """Materialize a tail call under the CFG-proven true branch condition."""
    _call, payload_stmt = tail_payload
    if not tail_from_else and index + 1 >= len(statements):
        return VoidTailCallGuardResult8616(
            status=VoidTailCallGuardStatus8616.MISSING_FOLLOWING_TAIL,
            payload_type=type(payload_stmt).__name__,
        )
    new_body = (
        payload_stmt
        if isinstance(payload_stmt, CStatements)
        else CStatements(statements=[payload_stmt], codegen=codegen)
    )
    _set_if_true_body_compat_8616(stmt, proof.condition, new_body)
    stmt.else_node = None
    removed_following_tail = False
    if not tail_from_else:
        del statements[index + 1]
        removed_following_tail = True
    return VoidTailCallGuardResult8616(
        status=VoidTailCallGuardStatus8616.MATERIALIZED,
        payload_type=type(payload_stmt).__name__,
        removed_following_tail=removed_following_tail,
    )


def c_node_semantically_empty_8616(node: object, callbacks: ReturnChainFlattenCallbacks8616) -> bool:
    """Return whether a dynamic boundary: angr codegen C AST subtree has semantics."""
    if node is None:
        return True
    if isinstance(node, CStatements):
        return all(c_node_semantically_empty_8616(stmt, callbacks) for stmt in (node.statements or ()))
    if isinstance(node, CIfElse):
        if node_contains_call_8616(getattr(node, "condition", None), callbacks):
            return False
        cond_nodes = node.condition_and_nodes or ()
        if any(node_contains_call_8616(cond, callbacks) for cond, _body in cond_nodes):
            return False
        bodies_empty = all(c_node_semantically_empty_8616(body, callbacks) for _cond, body in cond_nodes)
        return bodies_empty and c_node_semantically_empty_8616(node.else_node, callbacks)
    return False


def surplus_empty_guard_condition_8616(
    stmt: object,
    callbacks: ReturnChainFlattenCallbacks8616,
) -> tuple[object, SurplusIfGuardKind8616] | None:
    """Return surplus empty-if guard from a dynamic boundary: angr codegen C AST."""
    if not isinstance(stmt, CIfElse):
        return None
    if not c_node_semantically_empty_8616(stmt.else_node, callbacks):
        return None
    cond_nodes = stmt.condition_and_nodes or ()
    if len(cond_nodes) != 1:
        return None
    cond_body = next(iter(cond_nodes))
    if len(cond_body) != 2:
        return None
    cond, body = cond_body
    if node_contains_call_8616(cond, callbacks):
        return None
    if not is_empty_return_statement_8616(body):
        if c_node_semantically_empty_8616(body, callbacks):
            return cond, SurplusIfGuardKind8616.EMPTY_NOOP
        return None
    return cond, SurplusIfGuardKind8616.EMPTY_RETURN


def identical_assignment_arm_condition_8616(
    stmt: object,
    project: object,
    callbacks: ExpressionFingerprintCallbacks8616,
) -> tuple[object, tuple[object, ...]] | None:
    """Return a condition and one preserved arm when both arms assign identically."""
    if not isinstance(stmt, CIfElse):
        return None
    cond_nodes = stmt.condition_and_nodes or ()
    if len(cond_nodes) != 1:
        return None
    cond_body = next(iter(cond_nodes))
    if len(cond_body) != 2:
        return None
    cond, body = cond_body
    if any(
        isinstance(node, CFunctionCall)
        for node in (cond, *callbacks.iter_c_nodes_deep(cond))
    ):
        return None
    if not isinstance(body, CStatements) or not isinstance(stmt.else_node, CStatements):
        return None
    body_statements = tuple(body.statements or ())
    else_statements = tuple(stmt.else_node.statements or ())
    if not body_statements or len(body_statements) != len(else_statements):
        return None
    if not all(
        isinstance(body_assignment, CAssignment)
        and isinstance(else_assignment, CAssignment)
        for body_assignment, else_assignment in zip(
            body_statements,
            else_statements,
            strict=True,
        )
    ):
        return None
    body_assignments = body_statements
    else_assignments = else_statements
    try:
        body_fingerprint = tuple(
            (
                callbacks.expr_fingerprint(body_assignment.lhs, project),
                callbacks.expr_fingerprint(body_assignment.rhs, project),
            )
            for body_assignment in body_assignments
        )
        else_fingerprint = tuple(
            (
                callbacks.expr_fingerprint(else_assignment.lhs, project),
                callbacks.expr_fingerprint(else_assignment.rhs, project),
            )
            for else_assignment in else_assignments
        )
    except Exception:
        return None
    if body_fingerprint != else_fingerprint:
        return None
    return cond, body_assignments


def collapse_surplus_identical_assignment_arms_8616(
    root: object,
    project: object,
    *,
    branch_count: int | None,
    expression_callbacks: ExpressionFingerprintCallbacks8616,
    branch_callbacks: ConditionBranchTagCallbacks8616,
) -> IdenticalAssignmentArmCollapseStats8616:
    """Collapse non-branch-backed identical diamonds within the machine branch budget."""
    total_if_count = sum(
        1
        for node in (root, *expression_callbacks.iter_c_nodes_deep(root))
        if isinstance(node, CIfElse)
    )
    if branch_count is None:
        return IdenticalAssignmentArmCollapseStats8616(
            IdenticalAssignmentArmCollapseStatus8616.NO_BRANCH_PROOF,
            total_if_count,
            total_if_count,
            0,
            0,
            0,
            None,
            total_if_count,
            0,
        )
    surplus = total_if_count - branch_count
    if surplus <= 0:
        return IdenticalAssignmentArmCollapseStats8616(
            IdenticalAssignmentArmCollapseStatus8616.WITHIN_BRANCH_BUDGET,
            total_if_count,
            total_if_count,
            0,
            0,
            0,
            branch_count,
            total_if_count,
            0,
        )

    candidates: list[tuple[CStatements, int, tuple[object, ...]]] = []
    branch_backed_refusals = 0
    seen_blocks: set[int] = set()
    blocks = (
        node
        for node in (root, *expression_callbacks.iter_c_nodes_deep(root))
        if isinstance(node, CStatements)
    )
    for block in blocks:
        if id(block) in seen_blocks:
            continue
        seen_blocks.add(id(block))
        for index, statement in enumerate(tuple(block.statements or ())):
            candidate = identical_assignment_arm_condition_8616(
                statement,
                project,
                expression_callbacks,
            )
            if candidate is None:
                continue
            condition, replacement = candidate
            if condition_has_jcc_evidence_8616(condition, branch_callbacks):
                branch_backed_refusals += 1
                continue
            candidates.append((block, index, replacement))

    if not candidates:
        return IdenticalAssignmentArmCollapseStats8616(
            IdenticalAssignmentArmCollapseStatus8616.NO_ELIGIBLE_CANDIDATE,
            total_if_count,
            total_if_count,
            0,
            0,
            0,
            branch_count,
            total_if_count,
            branch_backed_refusals,
        )

    selected = candidates[: min(surplus, len(candidates))]
    replacements_by_block: dict[int, tuple[CStatements, dict[int, tuple[object, ...]]]] = {}
    for block, index, replacement in selected:
        block_entry = replacements_by_block.setdefault(id(block), (block, {}))
        block_entry[1][index] = replacement
    materialized = 0
    for block, replacements in replacements_by_block.values():
        rebuilt: list[object] = []
        for index, statement in enumerate(tuple(block.statements or ())):
            replacement_for_index = replacements.get(index)
            if replacement_for_index is None:
                rebuilt.append(statement)
                continue
            rebuilt.extend(replacement_for_index)
            materialized += 1
        block.statements = rebuilt

    return IdenticalAssignmentArmCollapseStats8616(
        IdenticalAssignmentArmCollapseStatus8616.MATERIALIZED,
        total_if_count,
        total_if_count,
        len(candidates),
        materialized,
        int(bool(candidates) and materialized == 0),
        branch_count,
        total_if_count,
        branch_backed_refusals,
    )


def is_register_call_assignment_8616(stmt: object, callbacks: ReturnChainFlattenCallbacks8616) -> bool:
    """Return whether a dynamic boundary: angr codegen C AST assigns call to register."""
    if not isinstance(stmt, CAssignment):
        return False
    lhs = stmt.lhs
    if not isinstance(lhs, CVariable) or not isinstance(getattr(lhs, "variable", None), SimRegisterVariable):
        return False
    return node_contains_call_8616(stmt.rhs, callbacks)


def materialize_cfg_conditional_return_suffix_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    cond_return_pairs: list[tuple[CExpression, int]],
    callbacks: ReturnChainFlattenCallbacks8616,
) -> bool:
    """Rebuild return suffix from a dynamic boundary: angr codegen C AST statements."""
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    if len(cond_return_pairs) < 2:
        if debug:
            log.warning("[cfg-return-chain] suffix refused pair_count=%d", len(cond_return_pairs))
        return False
    final_value = callbacks.final_return_value(project, codegen)
    if final_value is None:
        if debug:
            log.warning("[cfg-return-chain] suffix refused missing final return")
        return False
    statements_node = getattr(codegen.cfunc, "statements", None)
    statements: list[object] = list(getattr(statements_node, "statements", ()) or ())
    if not statements:
        if debug:
            log.warning("[cfg-return-chain] suffix refused missing statements")
        return False
    cut_index = next(
        (index for index, stmt in enumerate(statements) if isinstance(stmt, (CIfElse, CReturn, CGoto))),
        None,
    )
    if cut_index is None:
        if debug:
            log.warning("[cfg-return-chain] suffix appending after setup statements=%d", len(statements))
        cut_index = len(statements)
    prefix: list[object] = list(statements[:cut_index])
    if (
        prefix
        and is_register_call_assignment_8616(prefix[-1], callbacks)
        and node_contains_call_8616(cond_return_pairs[0][0], callbacks)
    ):
        prefix.pop()
    if not prefix:
        if debug:
            log.warning("[cfg-return-chain] suffix refused empty semantic prefix cut=%d", cut_index)
        return False
    rebuilt: list[object] = list(prefix)
    for cond, value in cond_return_pairs:
        body = CStatements(
            statements=[CReturn(CConstant(int(value), SimTypeShort(False), codegen=codegen), codegen=codegen)],
            codegen=codegen,
        )
        rebuilt.append(CIfElse([(cast(CExpression, cond), body)], else_node=None, cstyle_ifs=True, codegen=codegen))
    rebuilt.append(CReturn(CConstant(int(final_value), SimTypeShort(False), codegen=codegen), codegen=codegen))
    callbacks.set_cfunc_statements_root(codegen, CStatements(statements=rebuilt, codegen=codegen))
    codegen._inertia_return_chain_suffix_materialized_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = tuple(int(value) for _cond, value in cond_return_pairs)
    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(
        callbacks.expr_fingerprint(cond, project) for cond, _value in cond_return_pairs
    )
    codegen._inertia_return_chain_final_value_8616 = int(final_value)
    return True


def _empty_if_body_is_empty_8616(body: object) -> bool:
    """Return whether a dynamic boundary: angr codegen C AST branch body is empty."""
    if isinstance(body, CStatements):
        return not tuple(body.statements or ())
    return body is None


def _empty_if_body_is_cfg_return_setup_only_8616(
    body: object,
    callbacks: ReturnChainEmptyIfCallbacks8616,
) -> bool:
    """Return whether a dynamic boundary: angr codegen C AST body is CFG setup only."""
    if _empty_if_body_is_empty_8616(body):
        return True
    if not isinstance(body, CStatements):
        return False
    statements = tuple(cast(Iterable[object], body.statements or ()))
    if not statements:
        return True
    for stmt in statements:
        if not isinstance(stmt, CAssignment):
            return False
        nodes = (stmt, *callbacks.iter_c_nodes_deep(stmt))
        if any(isinstance(node, CFunctionCall) for node in nodes):
            return False
        if any(
            isinstance(node, (CIfElse, CReturn, CGoto, CBreak, CWhileLoop, CDoWhileLoop, CForLoop)) for node in nodes
        ):
            return False
    return True


def _set_if_true_body_compat_8616(node: CIfElse, cond: object, body: CStatements) -> None:
    """Update true-branch aliases on a dynamic boundary: angr codegen CIfElse compatibility objects."""
    condition_and_nodes: list[tuple[CExpression, CStatement | None]] = [
        (cast(CExpression, cond), cast(CStatement, body))
    ]
    node.condition_and_nodes = condition_and_nodes
    # Dynamic angr/codegen compatibility aliases used by older structured-codegen trees.
    if hasattr(node, "iftrue"):
        typing.cast(typing.Any, node).iftrue = body
    if hasattr(node, "true_node"):
        typing.cast(typing.Any, node).true_node = body


def materialize_empty_if_return_branches_8616(
    project: object,
    codegen: _ReturnChainCodegen8616,
    callbacks: ReturnChainEmptyIfCallbacks8616,
) -> bool:
    """Materialize return chains from a dynamic boundary: angr codegen empty-if C AST."""
    cfunc = codegen.cfunc
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    changed = False
    stats = codegen._inertia_empty_return_branch_stats_8616
    if not isinstance(stats, dict):
        stats = {"candidates": 0, "materialized": 0, "refused": 0}
        codegen._inertia_empty_return_branch_stats_8616 = stats
    multi_arm_obligations = multi_arm_wide_return_obligation_count_8616(
        cfunc.statements
    )
    if multi_arm_obligations:
        stats["candidates"] += multi_arm_obligations
        stats["refused"] += multi_arm_obligations
        if debug:
            log.warning(
                "[empty-return-branch] refused existing multi-arm obligations=%d stats=%r",
                multi_arm_obligations,
                stats,
            )
        return False
    ordered_return_values = callbacks.ordered_return_values(project, codegen)
    ordered_cfg_return_pairs = callbacks.ordered_return_pairs(project, codegen)
    ordered_32bit_cfg_return_pairs = callbacks.ordered_32bit_return_pairs(project, codegen)
    allowed_call_addrs = callbacks.condition_call_addrs(
        cond for cond, _value in (*ordered_cfg_return_pairs, *ordered_32bit_cfg_return_pairs)
    )
    unsafe_effects = callbacks.selector_function_has_unsafe_effects(project, codegen, allowed_call_addrs)
    if unsafe_effects:
        codegen._inertia_empty_return_branch_refused_unsafe_effects_8616 = (
            int(codegen._inertia_empty_return_branch_refused_unsafe_effects_8616) + 1
        )
    ordered_index = 0
    cond_return_pairs: list[tuple[CExpression, int]] = []
    empty_if_nodes: list[CIfElse] = []

    def _return_stmt(value: int) -> CReturn:
        """Build a typed short return statement for the dynamic codegen tree."""
        return CReturn(CConstant(int(value), SimTypeShort(False), codegen=codegen), codegen=codegen)

    if debug:
        try:
            nodes = tuple(callbacks.iter_c_nodes_deep(getattr(cfunc, "statements", None)))
            if_nodes = tuple(node for node in nodes if isinstance(node, CIfElse))
            log.warning(
                "[empty-return-branch] scan nodes=%d ifs=%d root_type=%s",
                len(nodes),
                len(if_nodes),
                type(getattr(cfunc, "statements", None)).__name__,
            )
        except Exception:
            pass
    for node in callbacks.iter_c_nodes_deep(getattr(cfunc, "statements", None)):
        if not isinstance(node, CIfElse):
            continue
        cond_pairs = node.condition_and_nodes
        if not isinstance(cond_pairs, (list, tuple)) or not cond_pairs:
            if debug:
                log.warning(
                    "[empty-return-branch] refused no-cond-pairs type=%s cond_pairs_type=%s",
                    type(node).__name__,
                    type(cond_pairs).__name__,
                )
            continue
        cond, body = cond_pairs[0]
        else_body = node.else_node
        cfg_return_setup_candidate = _empty_if_body_is_cfg_return_setup_only_8616(
            body, callbacks
        ) and _empty_if_body_is_cfg_return_setup_only_8616(else_body, callbacks)
        if not _empty_if_body_is_empty_8616(body):
            if debug:
                body_statements = getattr(body, "statements", None)
                if isinstance(body_statements, CStatements):
                    body_count = len(tuple(body_statements.statements or ()))
                elif isinstance(body_statements, (list, tuple)):
                    body_count = len(body_statements)
                else:
                    body_count = -1
                child_types: tuple[str, ...] = ()
                if isinstance(body_statements, CStatements):
                    child_items = tuple(body_statements.statements or ())
                    child_types = tuple(type(child).__name__ for child in child_items)
                elif isinstance(body_statements, (list, tuple)):
                    child_items = tuple(body_statements)
                    child_types = tuple(type(child).__name__ for child in child_items)
                else:
                    child_items = ()
                assignment_fps = []
                for child in child_items:
                    if isinstance(child, CAssignment):
                        assignment_fps.append(  # noqa: PERF401
                            (
                                callbacks.expr_fingerprint(child.lhs, project),
                                callbacks.expr_fingerprint(child.rhs, project),
                            )
                        )
                log.warning(
                    "[empty-return-branch] refused nonempty body_type=%s body_count=%d "
                    "child_types=%r assignment_fps=%r cond_key=%r",
                    type(body).__name__,
                    body_count,
                    child_types,
                    tuple(assignment_fps),
                    callbacks.condition_tags(cond),
                )
            if not cfg_return_setup_candidate:
                continue
        empty_if_nodes.append(node)
        stats["candidates"] += 1
        if not _empty_if_body_is_empty_8616(body):
            continue
        if unsafe_effects:
            stats["refused"] += 1
            if debug:
                log.warning(
                    "[empty-return-branch] refused unsafe function effects cond_key=%r",
                    callbacks.condition_tags(cond),
                )
            continue
        value = callbacks.condition_branch_return_value(project, cond)
        if value is None and callbacks.condition_branch_is_non_branch(project, cond):
            stats["refused"] += 1
            if debug:
                log.warning(
                    "[empty-return-branch] refused non-jcc condition tag cond_key=%r",
                    callbacks.condition_tags(cond),
                )
            continue
        if value is None and ordered_index < len(ordered_return_values):
            value = ordered_return_values[ordered_index]
            ordered_index += 1
        if debug:
            log.warning(
                "[empty-return-branch] candidate cond_key=%r value=%r body_type=%s",
                callbacks.condition_tags(cond),
                value,
                type(body).__name__,
            )
        if value is None:
            stats["refused"] += 1
            continue
        cond_return_pairs.append((cast(CExpression, cond), value))
        new_body = CStatements(statements=[_return_stmt(value)], codegen=codegen)
        new_pairs = list(cond_pairs)
        new_pairs[0] = (cond, new_body)
        _set_if_true_body_compat_8616(node, cond, new_body)
        stats["materialized"] += 1
        changed = True
    if not cond_return_pairs and empty_if_nodes:
        total_if_nodes = sum(
            1
            for current in callbacks.iter_c_nodes_deep(getattr(cfunc, "statements", None))
            if isinstance(current, CIfElse)
        )
        if len(empty_if_nodes) != 1 or total_if_nodes != 1:
            stats["refused"] += len(empty_if_nodes)
            if debug:
                log.warning(
                    "[empty-return-branch] cfg expr rebuild refused: candidates=%d total_ifs=%d",
                    len(empty_if_nodes),
                    total_if_nodes,
                )
        elif callbacks.selector_function_has_unsafe_effects(project, codegen, allowed_call_addrs):
            stats["refused"] += len(empty_if_nodes)
            if debug:
                log.warning("[empty-return-branch] cfg expr rebuild refused: unsafe function effects")
        else:
            cfg_expr_pairs = callbacks.ordered_return_expr_pairs(project, codegen)
            if len(cfg_expr_pairs) >= len(empty_if_nodes):
                rebuilt_statements: list[CIfElse] = []
                for node, (cond, true_expr, false_expr) in zip(empty_if_nodes, cfg_expr_pairs, strict=False):
                    true_body = CStatements(statements=[CReturn(true_expr, codegen=codegen)], codegen=codegen)
                    false_body = CStatements(statements=[CReturn(false_expr, codegen=codegen)], codegen=codegen)
                    _set_if_true_body_compat_8616(node, cond, true_body)
                    node.else_node = false_body
                    rebuilt_statements.append(node)
                if rebuilt_statements:
                    cfunc.statements = CStatements(statements=rebuilt_statements, codegen=codegen)
                    codegen._inertia_return_expr_chain_materialized_8616 = True
                    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(
                        callbacks.expr_fingerprint(cond, project)
                        for cond, _true_expr, _false_expr in cfg_expr_pairs[: len(empty_if_nodes)]
                    )
                    codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = tuple(
                        callbacks.expr_fingerprint(expr, project)
                        for _cond, true_expr, false_expr in cfg_expr_pairs[: len(empty_if_nodes)]
                        for expr in (true_expr, false_expr)
                    )
                    stats["materialized"] += len(rebuilt_statements)
                    changed = True
            else:
                stats["refused"] += len(empty_if_nodes)
                if debug:
                    log.warning(
                        "[empty-return-branch] cfg expr rebuild refused: pairs=%d candidates=%d",
                        len(cfg_expr_pairs),
                        len(empty_if_nodes),
                    )
    if len(cond_return_pairs) >= 2:
        cfg_return_pairs = ordered_cfg_return_pairs
        flatten_pairs = cond_return_pairs
        if len(cfg_return_pairs) >= len(cond_return_pairs):
            flatten_pairs = cfg_return_pairs[: len(cond_return_pairs)]
            if debug:
                log.warning("[empty-return-branch] using cfg decoded return-chain pairs count=%d", len(flatten_pairs))
        changed = callbacks.flatten_conditional_return_chain(project, codegen, flatten_pairs) or changed
        cond_return_pairs = flatten_pairs
    if not cond_return_pairs:
        cfg_return_pairs = ordered_32bit_cfg_return_pairs
        if len(cfg_return_pairs) >= 2:
            if unsafe_effects:
                stats["refused"] += len(cfg_return_pairs)
                if debug:
                    log.warning(
                        "[cfg-return-chain] 32-bit flatten refused unsafe effects pairs=%d", len(cfg_return_pairs)
                    )
            else:
                changed = callbacks.flatten_conditional_return_chain(project, codegen, cfg_return_pairs) or changed
                cond_return_pairs = cfg_return_pairs
    if not cond_return_pairs:
        cfg_return_pairs = ordered_cfg_return_pairs
        if len(cfg_return_pairs) >= 2:
            if callbacks.selector_function_has_unsafe_effects(project, codegen, allowed_call_addrs):
                stats["refused"] += len(cfg_return_pairs)
                if debug:
                    log.warning(
                        "[cfg-return-chain] full flatten refused unsafe effects pairs=%d", len(cfg_return_pairs)
                    )
            else:
                changed = callbacks.flatten_conditional_return_chain(project, codegen, cfg_return_pairs) or changed
                cond_return_pairs = cfg_return_pairs
    if not cond_return_pairs and not codegen._inertia_return_chain_suffix_materialized_8616:
        cfg_return_pairs = ordered_cfg_return_pairs
        if unsafe_effects and cfg_return_pairs:
            stats["refused"] += len(cfg_return_pairs)
            if debug:
                log.warning(
                    "[cfg-return-chain] suffix materialization refused unsafe effects pairs=%d",
                    len(cfg_return_pairs),
                )
        elif callbacks.materialize_conditional_return_suffix(project, codegen, cfg_return_pairs):
            stats["materialized"] += len(cfg_return_pairs)
            changed = True
            cond_return_pairs = cfg_return_pairs
    changed = callbacks.prune_duplicate_empty_return_guard(project, codegen) or changed
    if cond_return_pairs:
        codegen._inertia_empty_return_branch_values_8616 = tuple(int(value) for _cond, value in cond_return_pairs)
    if debug:
        log.warning("[empty-return-branch] stats=%r changed=%s", stats, changed)
    return changed

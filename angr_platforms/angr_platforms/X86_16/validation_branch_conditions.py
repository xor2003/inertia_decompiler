"""Validate final structured branch predicates against exact ConditionIR facts.

Layer: Validation.
Responsibility: compare Structuring-tagged final C conditions with their unique
typed branch facts without recovering semantics or mutating the AST.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimStackVariable

from .c_ast_utils import _iter_c_nodes_deep_8616
from .caller_return_use_contracts import CallsiteReturnUseKind8616
from .callsite_summary import (
    CallsiteSummary8616,
    structured_callsite_addr_8616,
)
from .ir.condition_ir import (
    ConditionIR,
    canonicalize_condition_storage_fingerprint_8616,
    condition_sort_key_8616,
    invert_condition_fingerprint_string_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)
from .ir.core import IRValue, MemSpace
from .ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from .ir.logical_memory_register_transfer import trace_logical_word_register_transfers_8616
from .ir.logical_memory_register_transfer_contracts import (
    LogicalMemoryRegisterTransfer8616,
    LogicalMemoryRegisterTransferKind8616,
)
from .ir.ssa import SSABlock
from .ir.ssa_cfg import build_ssa_cfg_snapshot_8616, compute_ssa_dominators_8616
from .ir.ssa_cfg_contracts import SSACFGSnapshot8616, SSADominators8616
from .pipeline.structured_ast_query_index import StructuredAstQueryIndex8616
from .validation_condition_chains import validate_complete_condition_chain_8616
from .validation_condition_coverage import missing_required_condition_keys_8616
from .validation_condition_identity import (
    condition_precision_view_fingerprint_8616,
    condition_semantic_view_projection_fingerprint_8616,
)
from .validation_condition_precision import condition_precision_evidence_8616, condition_precision_token_8616
from .validation_terminal_wide_conditions import TerminalWideValidation8616, validate_terminal_wide_condition_8616

__all__ = [
    "BranchConditionIssue8616",
    "BranchConditionIssueKind8616",
    "BranchConditionValidationReport8616",
    "validate_materialized_branch_conditions_8616",
]

class BranchConditionIssueKind8616(StrEnum):
    """Contradictions between one materialized branch and typed evidence."""

    CONFLICTING_FACTS = "conflicting-facts"
    DUPLICATE_SURFACE = "duplicate-surface"
    INVALID_FINGERPRINT = "invalid-fingerprint"
    MISSING_FACT = "missing-fact"
    MISSING_SURFACE = "missing-surface"
    PREDICATE_MISMATCH = "predicate-mismatch"
    WIDE_PROOF_MISMATCH = "wide-proof-mismatch"


@dataclass(frozen=True, order=True, slots=True)
class BranchConditionIssue8616:
    """One exact JCC whose final predicate is not uniquely evidence-backed."""

    kind: BranchConditionIssueKind8616
    jcc_addr: int
    match_count: int = 0
    expected: str | None = None
    actual: str | None = None
    precision_candidates: tuple[str, ...] = ()
    block_addr: int | None = None

    def token(self) -> str:
        """Return a deterministic validation issue token."""
        token = (
            f"branch-condition:{self.kind.value}:jcc={self.jcc_addr:#x}:"
            f"matches={self.match_count}"
        )
        if self.expected is not None:
            token += f":expected={self.expected}"
        if self.block_addr is not None:
            token += f":block={self.block_addr:#x}"
        if self.actual is not None:
            token += f":actual={self.actual}"
        if self.precision_candidates:
            token += ":precision=" + "|".join(self.precision_candidates)
        return token


@dataclass(frozen=True, slots=True)
class BranchConditionValidationReport8616:
    """Closed evidence-loop counters for materialized branch predicates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    issues: tuple[BranchConditionIssue8616, ...] = ()

    @property
    def failure_count(self) -> int:
        """Return the number of predicate contradictions."""
        return len(self.issues)

    @property
    def passed(self) -> bool:
        """Return whether every classified predicate matches its typed fact."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count


class _TypedConditionCodegen8616(Protocol):
    """Dynamic codegen metadata consumed at the Validation boundary."""

    _inertia_typed_conditions: object
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    project: _ConditionProject8616
    cfunc: _ConditionCFunction8616


class _ConditionCFunction8616(Protocol):
    """Function identity needed to consume its proven SSA artifact."""

    addr: int


class _ConditionArch8616(Protocol):
    """Architecture register map used at the dynamic angr boundary."""

    registers: Mapping[str, tuple[int, int]]


class _ConditionProject8616(Protocol):
    """Project architecture surface used by Validation."""

    arch: _ConditionArch8616


class _TaggedConditionNode8616(Protocol):
    """Third-party C AST node carrying optional Structuring tags."""

    tags: Mapping[str, object] | None


@dataclass(frozen=True, slots=True)
class _LogicalReloadValidationContext8616:
    """Immutable function-wide proofs reused by register reload validation."""

    snapshot: SSACFGSnapshot8616 | None
    dominators: SSADominators8616 | None
    blocks_by_addr: Mapping[int, SSABlock]
    transfers_by_register: Mapping[
        tuple[str, int],
        tuple[LogicalMemoryRegisterTransfer8616, ...],
    ]

    @property
    def complete(self) -> bool:
        """Return whether CFG, dominance, blocks, and transfers are proven."""
        return bool(
            self.snapshot is not None
            and self.snapshot.complete
            and self.dominators is not None
            and self.dominators.complete
            and self.blocks_by_addr
        )


def _node_tags_8616(node: object) -> Mapping[str, object]:
    """Read tags at the dynamic angr C AST boundary."""
    try:
        tags = cast(_TaggedConditionNode8616, node).tags
    except AttributeError:
        return {}
    return tags if isinstance(tags, Mapping) else {}


def _materialized_conditions_8616(
    root: object,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> tuple[tuple[int, object], ...]:
    """Return unique final conditions explicitly owned by Structuring."""
    if query_index is not None:
        query_index.require_root(root)
    found: list[tuple[int, object]] = []
    seen: set[int] = set()
    nodes = query_index.nodes if query_index is not None else _iter_c_nodes_deep_8616(root)
    for node in nodes:
        candidates: tuple[object, ...] = ()
        if isinstance(node, CIfBreak):
            candidates = (node.condition,)
        elif isinstance(node, CIfElse):
            candidates = tuple(condition for condition, _body in node.condition_and_nodes)
        elif isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            candidates = (node.condition,)
        for condition in candidates:
            marker = id(condition)
            tags = _node_tags_8616(condition)
            jcc_addr = tags.get("ins_addr")
            structuring_owned = (
                tags.get("inertia_structuring_condition_cfg_materialized_8616") is True
                or tags.get("inertia_typed_loop_condition_bound_8616") is True
            )
            if (
                marker in seen
                or not structuring_owned
                or not isinstance(jcc_addr, int)
            ):
                continue
            seen.add(marker)
            found.append((jcc_addr, condition))
    return tuple(found)


def _typed_conditions_8616(codegen: object) -> tuple[ConditionIR, ...]:
    """Read transferred typed conditions from the dynamic codegen boundary."""
    try:
        value = cast(_TypedConditionCodegen8616, codegen)._inertia_typed_conditions
    except AttributeError:
        return ()
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(condition for condition in value if isinstance(condition, ConditionIR))


def _proven_call_return_condition_8616(
    codegen: object,
    fact: ConditionIR,
    candidate: object,
) -> bool:
    """Prove a bound call predicate equivalent to its AX-family comparison."""
    from .ir.condition_zero_input import project_register_zero_input_8616

    input_projection = project_register_zero_input_8616(fact)
    if (
        not isinstance(candidate, CBinaryOp)
        or candidate.op not in {"CmpEQ", "CmpNE"}
        or (fact.op not in {"eq", "ne"} and input_projection is None)
    ):
        return False
    operands = (candidate.lhs, candidate.rhs)
    calls = tuple(operand for operand in operands if isinstance(operand, CFunctionCall))
    constants = tuple(operand for operand in operands if isinstance(operand, CConstant))
    if len(calls) != 1 or len(constants) != 1 or not isinstance(constants[0].value, int):
        return False
    surface = cast(_TypedConditionCodegen8616, codegen)
    callsite_addr = structured_callsite_addr_8616(calls[0])
    try:
        summary = surface._inertia_callsite_summaries.get(id(calls[0]))
        if summary is None and isinstance(callsite_addr, int):
            summary = surface._inertia_callsite_summary_inventory_8616.get(callsite_addr)
        registers = surface.project.arch.registers
    except AttributeError:
        return False
    if not isinstance(summary, CallsiteSummary8616):
        return False
    if (
        summary.return_used is not True
        or summary.return_use_kind is not CallsiteReturnUseKind8616.CONDITION
        or summary.return_addr != fact.block_addr
        or callsite_addr != summary.callsite_addr
        or not isinstance(summary.return_register, str)
    ):
        return False
    register = registers.get(summary.return_register.lower())
    if register is None:
        return False
    values = (fact.lhs, fact.rhs)
    register_matches = any(
        isinstance(value, IRValue)
        and value.space is MemSpace.REG
        and (int(value.offset), int(value.size or register[1])) == (int(register[0]), int(register[1]))
        for value in values
    )
    constant_matches = (
        input_projection is not None
        and input_projection.constant == constants[0].value
    ) or any(
        isinstance(value, IRValue)
        and value.space is MemSpace.CONST
        and value.const == constants[0].value
        for value in values
    )
    return not (not register_matches or not constant_matches)


def _proven_stored_call_return_condition_8616(
    codegen: object,
    fact: ConditionIR,
    candidate: object,
) -> bool:
    """Accept a condition bound to the exact stack store of a call return."""
    if not isinstance(candidate, CBinaryOp) or candidate.op not in {"CmpEQ", "CmpNE"}:
        return False
    surface = cast(_TypedConditionCodegen8616, codegen)
    stack_nodes = tuple(
        node.variable
        for node in _iter_c_nodes_deep_8616(candidate)
        if isinstance(node, CVariable)
        and isinstance(node.variable, SimStackVariable)
        and node.variable.base == "bp"
    )
    if len(stack_nodes) != 1:
        return False
    variable = stack_nodes[0]
    offset = variable.offset
    size = variable.size
    if not isinstance(offset, int) or not isinstance(size, int):
        return False
    for summary in surface._inertia_callsite_summary_inventory_8616.values():
        if not isinstance(summary, CallsiteSummary8616) or summary.return_use_kind is not CallsiteReturnUseKind8616.VALUE:
            continue
        if summary.return_addr != fact.block_addr or summary.return_store_destination != ("bp", offset):
            continue
        if summary.return_store_width == size and summary.return_used is True:
            return True
    return False


def _normalized_fingerprint_8616(
    fingerprint: str,
    normalizer: Callable[[str], str] | None,
) -> str:
    """Canonicalize one semantic condition fingerprint."""
    normalized = str(
        normalize_condition_fingerprint_algebraic_8616(
            normalize_condition_fingerprint_string_8616(
                canonicalize_condition_storage_fingerprint_8616(fingerprint)
            )
        )
    )
    if normalizer is not None:
        normalized = str(
            normalize_condition_fingerprint_algebraic_8616(
                normalize_condition_fingerprint_string_8616(
                    canonicalize_condition_storage_fingerprint_8616(normalizer(normalized))
                )
            )
        )
    return normalized


def _logical_reload_address_fingerprint_8616(
    transfer: LogicalMemoryRegisterTransfer8616,
) -> str | None:
    """Serialize one proven segmented logical reload using validation grammar."""
    address = transfer.access.address
    if address.space not in {MemSpace.DS, MemSpace.ES, MemSpace.SS}:
        return None
    base_names = tuple(
        value.name.lower()
        for value in address.base_values
        if value.space is MemSpace.REG and isinstance(value.name, str)
    )
    if base_names != address.base:
        return None
    parts = [f"reg:{name}" for name in base_names]
    if address.offset or not parts:
        parts.append(f"const:{address.offset & 0xFFFF}")
    return (
        f"Dereference(Add(Mul(reg:{address.space.value},const:16),"
        f"{','.join(parts)}))"
    )


def _empty_logical_reload_validation_context_8616() -> _LogicalReloadValidationContext8616:
    """Return an explicit unproven logical-reload validation context."""
    return _LogicalReloadValidationContext8616(None, None, {}, {})


def _condition_register_operands_8616(fact: ConditionIR) -> tuple[IRValue, ...]:
    """Return named register operands that may have a proven memory origin."""
    return tuple(
        value
        for value in (fact.lhs, fact.rhs)
        if isinstance(value, IRValue)
        and value.space is MemSpace.REG
        and isinstance(value.name, str)
    )


def _build_logical_reload_validation_context_8616(
    codegen: object,
) -> _LogicalReloadValidationContext8616:
    """Build function-wide CFG and reload indexes once for validation."""
    surface = cast(_TypedConditionCodegen8616, codegen)
    try:
        resolution = registered_function_ssa_artifact_8616(
            surface.project,
            surface.cfunc.addr,
        )
    except AttributeError:
        return _empty_logical_reload_validation_context_8616()
    if resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN or resolution.artifact is None:
        return _empty_logical_reload_validation_context_8616()
    logical_memory = resolution.artifact.logical_memory
    if logical_memory is None or not logical_memory.closed:
        return _empty_logical_reload_validation_context_8616()
    snapshot = build_ssa_cfg_snapshot_8616(resolution.artifact)
    dominators = compute_ssa_dominators_8616(snapshot)
    if not snapshot.complete or not dominators.complete:
        return _empty_logical_reload_validation_context_8616()
    transfers_by_register: dict[
        tuple[str, int],
        list[LogicalMemoryRegisterTransfer8616],
    ] = {}
    for traced in trace_logical_word_register_transfers_8616(
        resolution.artifact,
        logical_memory.accesses,
    ):
        if not (
            isinstance(traced, LogicalMemoryRegisterTransfer8616)
            and traced.kind is LogicalMemoryRegisterTransferKind8616.RELOAD
            and traced.complete
            and isinstance(traced.register.name, str)
        ):
            continue
        key = (traced.register.name.lower(), traced.register.size)
        transfers_by_register.setdefault(key, []).append(traced)
    return _LogicalReloadValidationContext8616(
        snapshot,
        dominators,
        {block.addr: block for block in resolution.artifact.blocks},
        {
            key: tuple(transfers)
            for key, transfers in transfers_by_register.items()
        },
    )


def _proven_logical_reload_condition_fingerprints_8616(
    codegen: object,
    fact: ConditionIR,
    expected: str,
    normalizer: Callable[[str], str] | None,
    context: _LogicalReloadValidationContext8616 | None = None,
) -> frozenset[str]:
    """Project exact versioned register operands through proven logical reloads."""
    condition_block, condition_insn = fact.block_addr, fact.src_insn
    if condition_block is None or condition_insn is None:
        return frozenset()
    register_operands = _condition_register_operands_8616(fact)
    if not register_operands:
        return frozenset()
    active_context = context or _build_logical_reload_validation_context_8616(codegen)
    if not active_context.complete:
        return frozenset()
    snapshot = active_context.snapshot
    dominators = active_context.dominators
    if snapshot is None or dominators is None:
        return frozenset()
    replacements: dict[str, str] = {}
    for operand in register_operands:
        if operand.name is None:
            continue
        register_name = operand.name.lower()
        candidates = tuple(
            transfer
            for transfer in active_context.transfers_by_register.get(
                (register_name, operand.size),
                (),
            )
            if transfer.register.size == operand.size
            and dominators.dominates(transfer.register_site.block_addr, condition_block) is True
            and (
                transfer.register_site.block_addr != condition_block
                or transfer.register_site.instr_addr < condition_insn
            )
        )
        if not candidates:
            continue
        depths = {
            transfer.register_site.block_addr: len(
                dominators.dominators(transfer.register_site.block_addr) or ()
            )
            for transfer in candidates
        }
        nearest_depth = max(depths.values())
        nearest = tuple(
            transfer
            for transfer in candidates
            if depths[transfer.register_site.block_addr] == nearest_depth
        )
        candidate = max(nearest, key=lambda transfer: transfer.register_site.instr_addr)
        base_registers = {
            value.name.lower()
            for value in candidate.access.address.base_values
            if value.space is MemSpace.REG and isinstance(value.name, str)
        }
        forward = {candidate.register_site.block_addr}
        pending = [candidate.register_site.block_addr]
        while pending:
            block_addr = pending.pop()
            if block_addr == condition_block:
                continue
            for successor in snapshot.successors(block_addr) or ():
                if successor not in forward:
                    forward.add(successor)
                    pending.append(successor)
        reverse = {condition_block}
        pending = [condition_block]
        while pending:
            block_addr = pending.pop()
            if block_addr == candidate.register_site.block_addr:
                continue
            for predecessor in snapshot.predecessors(block_addr) or ():
                if predecessor not in reverse:
                    reverse.add(predecessor)
                    pending.append(predecessor)
        path_blocks = forward & reverse
        if candidate.register_site.block_addr not in path_blocks or condition_block not in path_blocks:
            continue
        stable = True
        for block_addr in path_blocks:
            block = active_context.blocks_by_addr.get(block_addr)
            if block is None:
                stable = False
                break
            for instr_index, instruction in enumerate(block.instrs):
                if (
                    block_addr == candidate.register_site.block_addr
                    and instr_index <= candidate.register_site.instr_index
                ):
                    continue
                if block_addr == condition_block:
                    if instruction.addr is None:
                        stable = False
                        break
                    if instruction.addr >= condition_insn:
                        continue
                destination = instruction.dst
                if instruction.op in {"CALL", "STORE"}:
                    stable = False
                    break
                if (
                    isinstance(destination, IRValue)
                    and destination.space is MemSpace.REG
                    and isinstance(destination.name, str)
                    and destination.name.lower() in {register_name, *base_registers}
                ):
                    stable = False
                    break
            if not stable:
                break
        address_fingerprint = _logical_reload_address_fingerprint_8616(candidate)
        if not stable or address_fingerprint is None:
            continue
        token = f"reg:{register_name}"
        previous = replacements.get(token)
        if previous is not None and previous != address_fingerprint:
            return frozenset()
        replacements[token] = address_fingerprint
    if not replacements:
        return frozenset()
    projected = expected
    for token, replacement in sorted(replacements.items()):
        projected = projected.replace(token, replacement)
    normalized = _normalized_fingerprint_8616(projected, normalizer)
    inverted_raw = invert_condition_fingerprint_string_8616(projected)
    inverted = (
        _normalized_fingerprint_8616(inverted_raw, normalizer)
        if inverted_raw is not None
        else None
    )
    return frozenset(value for value in (normalized, inverted) if value is not None)


def _post_body_do_while_fingerprint_8616(
    root: object,
    candidate: object,
    condition_fingerprint: Callable[[object], str],
) -> str | None:
    """Return the guard fingerprint after one proven terminal induction update.

    Dynamic boundary: loop bodies are third-party angr C-AST nodes whose
    statement container is not part of an owned Inertia contract.
    """
    loops = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CDoWhileLoop) and node.condition is candidate
    )
    if len(loops) != 1 or not isinstance(candidate, CBinaryOp):
        return None
    statements = tuple(getattr(loops[0].body, "statements", ()) or ())
    if not statements:
        return None
    iterator = statements[-1]
    if (
        not isinstance(iterator, CAssignment)
        or not isinstance(iterator.lhs, CVariable)
        or not isinstance(iterator.rhs, CBinaryOp)
        or iterator.rhs.op not in {"Add", "Sub"}
        or not isinstance(iterator.rhs.lhs, CVariable)
        or not isinstance(iterator.rhs.rhs, CConstant)
    ):
        return None
    target = condition_fingerprint(iterator.lhs)
    if condition_fingerprint(iterator.rhs.lhs) != target:
        return None
    replacement = condition_fingerprint(iterator.rhs)
    occurrence_count = 0

    def _fingerprint(node: object) -> str:
        nonlocal occurrence_count
        if isinstance(node, CVariable) and condition_fingerprint(node) == target:
            occurrence_count += 1
            return replacement
        if isinstance(node, CBinaryOp):
            return f"{node.op}({_fingerprint(node.lhs)},{_fingerprint(node.rhs)})"
        return condition_fingerprint(node)

    result = _fingerprint(candidate)
    return result if occurrence_count == 1 else None


def validate_materialized_branch_conditions_8616(
    codegen: object,
    root: object,
    *,
    query_index: StructuredAstQueryIndex8616 | None = None,
    condition_fingerprint: Callable[[object], str],
    condition_ir_fingerprint: Callable[[ConditionIR], str | None],
    condition_fingerprint_normalizer: Callable[[str], str] | None = None,
) -> BranchConditionValidationReport8616:
    """Validate each Structuring-tagged predicate against one exact typed fact."""
    surfaces = _materialized_conditions_8616(root, query_index)
    surfaces_by_jcc: dict[int, list[object]] = {}
    for jcc_addr, condition in surfaces:
        surfaces_by_jcc.setdefault(jcc_addr, []).append(condition)
    facts_by_jcc: dict[int, dict[tuple[object, ...], ConditionIR]] = {}
    typed_conditions = _typed_conditions_8616(codegen)
    for fact in typed_conditions:
        if isinstance(fact.src_insn, int):
            facts_by_jcc.setdefault(fact.src_insn, {})[
                condition_sort_key_8616(fact)
            ] = fact
    precision_after_by_jcc: dict[int, set[str]] = {}
    precision_views_by_jcc: dict[int, set[str]] = {}
    for evidence in condition_precision_evidence_8616(codegen):
        if isinstance(evidence.jcc_addr, int):
            precision_after_by_jcc.setdefault(evidence.jcc_addr, set()).add(evidence.after)
            if evidence.after_integer_view is not None:
                precision_views_by_jcc.setdefault(evidence.jcc_addr, set()).add(evidence.after_integer_view)

    logical_reload_context: _LogicalReloadValidationContext8616 | None = None
    classified_count = 0
    materialized_count = 0
    issues: list[BranchConditionIssue8616] = []
    for jcc_addr, candidates in sorted(surfaces_by_jcc.items()):
        classified_count += 1
        if len(candidates) != 1:
            issues.append(
                BranchConditionIssue8616(
                    BranchConditionIssueKind8616.DUPLICATE_SURFACE,
                    jcc_addr,
                    len(candidates),
                )
            )
            continue
        facts = tuple(facts_by_jcc.get(jcc_addr, {}).values())
        if not facts:
            issues.append(
                BranchConditionIssue8616(
                    BranchConditionIssueKind8616.MISSING_FACT,
                    jcc_addr,
                )
            )
            continue
        if len(facts) != 1:
            issues.append(
                BranchConditionIssue8616(
                    BranchConditionIssueKind8616.CONFLICTING_FACTS,
                    jcc_addr,
                    len(facts),
                )
            )
            continue
        wide_verdict = validate_terminal_wide_condition_8616(codegen, root, candidates[0], facts_by_jcc)
        if wide_verdict is TerminalWideValidation8616.PROVEN:
            materialized_count += 1
            continue
        if wide_verdict is not TerminalWideValidation8616.NOT_APPLICABLE:
            issues.append(BranchConditionIssue8616(
                BranchConditionIssueKind8616.WIDE_PROOF_MISMATCH, jcc_addr, actual=wide_verdict.value,
            ))
            continue
        # Exact typed call-return proof does not depend on rendering its former
        # register carrier, which may no longer exist in the final C surface.
        if _proven_call_return_condition_8616(codegen, facts[0], candidates[0]):
            materialized_count += 1
            continue
        expected_raw = condition_ir_fingerprint(facts[0])
        if expected_raw is None:
            issues.append(
                BranchConditionIssue8616(
                    BranchConditionIssueKind8616.INVALID_FINGERPRINT,
                    jcc_addr,
                )
            )
            continue
        actual_raw = condition_fingerprint(candidates[0])
        actual_precision = condition_precision_token_8616(actual_raw)
        actual = _normalized_fingerprint_8616(
            actual_raw,
            condition_fingerprint_normalizer,
        )
        semantic_view_raw = condition_semantic_view_projection_fingerprint_8616(
            facts[0],
            candidates[0],
            condition_fingerprint=condition_fingerprint,
        )
        semantic_view_actual = (
            _normalized_fingerprint_8616(
                semantic_view_raw,
                condition_fingerprint_normalizer,
            )
            if semantic_view_raw is not None
            else None
        )
        post_body_raw = _post_body_do_while_fingerprint_8616(
            root,
            candidates[0],
            condition_fingerprint,
        )
        post_body_actual = (
            _normalized_fingerprint_8616(
                post_body_raw,
                condition_fingerprint_normalizer,
            )
            if post_body_raw is not None
            else None
        )
        expected = _normalized_fingerprint_8616(
            expected_raw,
            condition_fingerprint_normalizer,
        )
        inverted_raw = invert_condition_fingerprint_string_8616(expected_raw)
        inverted = (
            _normalized_fingerprint_8616(
                inverted_raw,
                condition_fingerprint_normalizer,
            )
            if inverted_raw is not None
            else None
        )
        precision_after = precision_after_by_jcc.get(jcc_addr, set())
        precision_views = precision_views_by_jcc.get(jcc_addr, set())
        precision_view_matches = bool(precision_views) and precision_views == {
            condition_precision_token_8616(
                condition_precision_view_fingerprint_8616(candidates[0], condition_fingerprint)
            )
        }
        if logical_reload_context is None and _condition_register_operands_8616(facts[0]):
            logical_reload_context = _build_logical_reload_validation_context_8616(codegen)
        logical_reload_fingerprints = _proven_logical_reload_condition_fingerprints_8616(
            codegen,
            facts[0],
            expected,
            condition_fingerprint_normalizer,
            logical_reload_context,
        )
        chain_validation = validate_complete_condition_chain_8616(
            candidates[0],
            root_jcc_addr=jcc_addr,
            facts_by_jcc=facts_by_jcc,
            actual_fingerprint=actual_precision,
            precision_candidates=frozenset(precision_after),
        )
        fingerprint_matches = (
            actual in {expected, inverted}
            or semantic_view_actual in {expected, inverted}
            or post_body_actual in {expected, inverted}
            or actual in logical_reload_fingerprints
        )
        # Proven storage-view normalization must happen before compaction:
        # a digest cannot recover the original low/high-word expressions.
        precision_matches = (
            precision_view_matches
            or precision_after == {actual_precision}
            or precision_after == {condition_precision_token_8616(actual)}
        )
        if (
            fingerprint_matches
            or precision_matches
            or chain_validation.proven
            or _proven_stored_call_return_condition_8616(codegen, facts[0], candidates[0])
        ):
            materialized_count += 1
            continue
        issues.append(
            BranchConditionIssue8616(
                BranchConditionIssueKind8616.PREDICATE_MISMATCH,
                jcc_addr,
                expected=expected,
                actual=actual,
                precision_candidates=tuple(sorted(precision_after)),
            )
        )
    missing_keys = missing_required_condition_keys_8616(codegen, root, typed_conditions)
    issues.extend(
        BranchConditionIssue8616(
            BranchConditionIssueKind8616.MISSING_SURFACE, jcc_addr, block_addr=block_addr,
        )
        for jcc_addr, block_addr in missing_keys
    )
    return BranchConditionValidationReport8616(
        raw_fact_count=len(surfaces) + len(missing_keys),
        normalized_fact_count=len(surfaces_by_jcc) + len(missing_keys),
        classified_fact_count=classified_count + len(missing_keys),
        materialized_count=materialized_count,
        issues=tuple(issues),
    )

"""Materialize terminal software-interrupt results from typed evidence.

Layer: Structuring.
Responsibility: replace a stale pre-interrupt selector return with the exact
terminal interrupt call only when Semantics identifies the result register and
the binary CFG proves that register reaches the function return unchanged.
This module does not infer interrupt inputs, types, aliases, or rendered text.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeShort
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.errors import PipelineHardError
from ..semantics.software_interrupt_inputs import (
    SoftwareInterruptInputArtifact8616,
    SoftwareInterruptInputFact8616,
)
from ..structured_tags import copy_structured_tags_8616
from .return_chains import (
    TerminalCallResultReturnCallbacks8616,
    TerminalCallResultReturnStatus8616,
    prove_terminal_call_result_path_8616,
)

__all__ = [
    "SoftwareInterruptResultMaterializationStats8616",
    "SoftwareInterruptResultStatus8616",
    "materialize_software_interrupt_terminal_results_8616",
]


class SoftwareInterruptResultStatus8616(StrEnum):
    """Typed result of terminal interrupt-result materialization."""

    NO_INPUT_ARTIFACT = "no-input-artifact"
    NO_RESULT_FACT = "no-result-fact"
    NO_STALE_SELECTOR_RETURN = "no-stale-selector-return"
    AMBIGUOUS_CANDIDATE = "ambiguous-candidate"
    CFG_PROOF_REFUSED = "cfg-proof-refused"
    ALREADY_MATERIALIZED = "already-materialized"
    MATERIALIZED = "materialized"


@dataclass(frozen=True, slots=True)
class SoftwareInterruptResultMaterializationStats8616:
    """Closed evidence loop for terminal interrupt-result materialization."""

    status: SoftwareInterruptResultStatus8616
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    callsite_addr: int | None = None
    path_block_addrs: tuple[int, ...] = ()
    path_status: TerminalCallResultReturnStatus8616 | None = None


@dataclass(frozen=True, slots=True)
class _StaleSelectorCandidate8616:
    """One call assignment and stale selector return on the terminal path."""

    call_container: structured_c.CStatements
    return_container: structured_c.CStatements
    assignment_index: int
    return_index: int
    call: structured_c.CFunctionCall
    return_statement: structured_c.CReturn


@dataclass(frozen=True, slots=True)
class _SunkReturnedCallCandidate8616:
    """One interrupt call sunk into a return past a tagged condition."""

    ordered_container: structured_c.CStatements
    return_container: structured_c.CStatements
    insertion_index: int
    return_index: int
    call: structured_c.CFunctionCall
    return_statement: structured_c.CReturn


class _CodegenInterruptResultSurface8616(Protocol):
    """Owned interrupt artifacts attached to the dynamic codegen boundary."""

    cfunc: _CFunctionAddressSurface8616 | None
    project: _ProjectRegisterSurface8616
    _inertia_software_interrupt_input_artifact_8616: SoftwareInterruptInputArtifact8616
    _inertia_software_interrupt_result_stats_8616: SoftwareInterruptResultMaterializationStats8616


class _TaggedStatementSurface8616(Protocol):
    """Third-party structured statement tag field consumed by Structuring."""

    tags: object


class _ArchRegisterSurface8616(Protocol):
    """Third-party architecture register table consumed by Structuring."""

    registers: dict[str, tuple[int, int]]


class _ProjectRegisterSurface8616(Protocol):
    """Third-party project architecture field consumed by Structuring."""

    arch: _ArchRegisterSurface8616


class _CFunctionAddressSurface8616(Protocol):
    """Third-party structured function address consumed by Structuring."""

    addr: int | None


def _leaf_statement_8616(statement: object) -> object | None:
    """Unwrap only transparent one-statement C containers."""
    current = statement
    visited: set[int] = set()
    while isinstance(current, structured_c.CStatements):
        if id(current) in visited:
            return None
        visited.add(id(current))
        children = tuple(current.statements or ())
        if len(children) != 1:
            return None
        current = children[0]
    return current


def _callsite_addr_8616(call: structured_c.CFunctionCall) -> int | None:
    """Read one exact callsite tag from angr's structured-C boundary."""
    tags = copy_structured_tags_8616(call.tags)
    if tags is None:
        return None
    addr = tags.get("ins_addr")
    return addr if isinstance(addr, int) else None


def _statement_containers_8616(root: object) -> tuple[structured_c.CStatements, ...]:
    """Collect unique mutable statement containers deterministically."""
    containers: list[structured_c.CStatements] = []
    seen: set[int] = set()
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, structured_c.CStatements) or id(node) in seen:
            continue
        seen.add(id(node))
        containers.append(node)
    return tuple(containers)


def _returned_call_matches_8616(root: object, fact: SoftwareInterruptInputFact8616) -> bool:
    """Return whether final C already returns the exact interrupt call."""
    return any(
        isinstance(node, structured_c.CReturn)
        and isinstance(node.retval, structured_c.CFunctionCall)
        and _callsite_addr_8616(node.retval) == fact.callsite_addr
        for node in _iter_c_nodes_deep_8616(root)
    )


def _statement_addr_8616(statement: object) -> int | None:
    """Read one exact instruction address from a structured statement."""
    try:
        raw_tags = cast(_TaggedStatementSurface8616, statement).tags
    except AttributeError:
        return None
    tags = copy_structured_tags_8616(raw_tags)
    if tags is None:
        return None
    addr = tags.get("ins_addr")
    return addr if isinstance(addr, int) else None


def _sunk_returned_call_candidates_8616(
    root: object,
    fact: SoftwareInterruptInputFact8616,
) -> tuple[_SunkReturnedCallCandidate8616, ...]:
    """Find exact calls whose structured return moved past a later condition."""
    containers = _statement_containers_8616(root)
    returned_calls = _returned_call_owners_8616(containers, fact.callsite_addr)
    if len(returned_calls) != 1:
        return ()
    return_container, return_index, return_statement, call = returned_calls[0]
    return_addr = _statement_addr_8616(return_statement)
    if return_addr is None or return_addr <= fact.callsite_addr:
        return ()

    candidates: list[_SunkReturnedCallCandidate8616] = []
    for container in containers:
        candidate = _sunk_candidate_in_container_8616(
            container,
            return_container=return_container,
            return_index=return_index,
            return_statement=return_statement,
            return_addr=return_addr,
            call=call,
            callsite_addr=fact.callsite_addr,
        )
        if candidate is not None:
            candidates.append(candidate)
    return tuple(candidates)


def _returned_call_owners_8616(
    containers: tuple[structured_c.CStatements, ...],
    callsite_addr: int,
) -> list[
    tuple[structured_c.CStatements, int, structured_c.CReturn, structured_c.CFunctionCall]
]:
    """Find return statements whose retval embeds the exact callsite call."""
    returned_calls: list[
        tuple[structured_c.CStatements, int, structured_c.CReturn, structured_c.CFunctionCall]
    ] = []
    for container in containers:
        statements = tuple(cast(Iterable[structured_c.CStatement], container.statements or ()))
        for index, statement in enumerate(statements):
            if not isinstance(statement, structured_c.CReturn) or statement.retval is None:
                continue
            matching_calls = tuple(
                node
                for node in (
                    statement.retval,
                    *_iter_c_nodes_deep_8616(statement.retval),
                )
                if isinstance(node, structured_c.CFunctionCall)
                and _callsite_addr_8616(node) == callsite_addr
            )
            if len(matching_calls) == 1:
                returned_calls.append((container, index, statement, matching_calls[0]))
    return returned_calls


def _sunk_candidate_in_container_8616(
    container: structured_c.CStatements,
    *,
    return_container: structured_c.CStatements,
    return_index: int,
    return_statement: structured_c.CReturn,
    return_addr: int,
    call: structured_c.CFunctionCall,
    callsite_addr: int,
) -> _SunkReturnedCallCandidate8616 | None:
    """Return the sunk-call candidate proven for one container."""
    statements = tuple(cast(Iterable[structured_c.CStatement], container.statements or ()))
    return_owner_indexes = tuple(
        index
        for index, statement in enumerate(statements)
        if statement is return_statement
        or any(node is return_statement for node in _iter_c_nodes_deep_8616(statement))
    )
    if len(return_owner_indexes) != 1:
        return None
    return_owner_index = return_owner_indexes[0]
    condition_indexes: list[int] = []
    for index, statement in enumerate(statements[:return_owner_index]):
        leaf = _leaf_statement_8616(statement)
        if not isinstance(leaf, structured_c.CIfElse):
            continue
        condition_addr = _statement_addr_8616(leaf)
        if condition_addr is not None and callsite_addr < condition_addr <= return_addr:
            condition_indexes.append(index)
    if not condition_indexes:
        return None
    return _SunkReturnedCallCandidate8616(
        ordered_container=container,
        return_container=return_container,
        insertion_index=min(condition_indexes),
        return_index=return_index,
        call=call,
        return_statement=return_statement,
    )


def _interrupt_result_variable_8616(
    codegen: object,
    fact: SoftwareInterruptInputFact8616,
) -> structured_c.CVariable | None:
    """Build the exact ABI result-register carrier for one interrupt fact."""
    register_name = fact.result_register
    if register_name is None:
        return None
    surface = cast(_CodegenInterruptResultSurface8616, codegen)
    try:
        register_offset, register_size = surface.project.arch.registers[register_name]
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    variable_types = {
        1: SimTypeChar(False),
        2: SimTypeShort(False),
        4: SimTypeInt(False),
    }
    variable_type = variable_types.get(register_size)
    if variable_type is None:
        return None
    cfunc = surface.cfunc
    function_addr = cfunc.addr if cfunc is not None else None
    variable = SimRegisterVariable(
        register_offset,
        register_size,
        name=register_name,
        region=function_addr if isinstance(function_addr, int) else None,
        ident=f"{register_name}_{fact.callsite_addr:x}",
    )
    return structured_c.CVariable(variable, variable_type=variable_type, codegen=codegen)


def _materialize_sunk_returned_call_8616(
    candidate: _SunkReturnedCallCandidate8616,
    result: structured_c.CVariable,
    codegen: object,
) -> None:
    """Restore binary call order and return its explicit result carrier."""
    assignment = structured_c.CAssignment(
        result,
        candidate.call,
        tags=candidate.call.tags,
        codegen=codegen,
    )
    ordered_statements = list(
        cast(Iterable[structured_c.CStatement], candidate.ordered_container.statements or ())
    )
    ordered_statements.insert(candidate.insertion_index, assignment)
    candidate.ordered_container.statements = ordered_statements

    return_statements = list(
        cast(Iterable[structured_c.CStatement], candidate.return_container.statements or ())
    )
    return_statements[candidate.return_index] = structured_c.CReturn(
        result,
        tags=candidate.return_statement.tags,
        codegen=codegen,
    )
    candidate.return_container.statements = return_statements


def _stale_selector_candidates_8616(
    root: object,
    fact: SoftwareInterruptInputFact8616,
) -> tuple[_StaleSelectorCandidate8616, ...]:
    """Collect exact call assignments and stale selector return candidates."""
    candidates: list[_StaleSelectorCandidate8616] = []
    candidate_keys: set[tuple[int, int]] = set()
    assigned_calls: list[
        tuple[structured_c.CStatements, int, structured_c.CFunctionCall]
    ] = []
    selector_returns: list[
        tuple[structured_c.CStatements, int, structured_c.CReturn]
    ] = []
    for container in _statement_containers_8616(root):
        statements = tuple(cast(Iterable[structured_c.CStatement], container.statements or ()))
        leaves = tuple(_leaf_statement_8616(statement) for statement in statements)
        for index, leaf in enumerate(leaves):
            if (
                isinstance(leaf, structured_c.CAssignment)
                and isinstance(leaf.rhs, structured_c.CFunctionCall)
                and _callsite_addr_8616(leaf.rhs) == fact.callsite_addr
            ):
                assigned_calls.append((container, index, leaf.rhs))
            elif (
                isinstance(leaf, structured_c.CReturn)
                and isinstance(leaf.retval, structured_c.CConstant)
                and leaf.retval.value == fact.selector_value
            ):
                selector_returns.append((container, index, leaf))
    for call_container, assignment_index, call in assigned_calls:
        for return_container, return_index, return_statement in selector_returns:
            if call_container is return_container and return_index != assignment_index + 1:
                continue
            key = (id(call), id(return_statement))
            if key in candidate_keys:
                continue
            candidate_keys.add(key)
            candidates.append(
                _StaleSelectorCandidate8616(
                    call_container=call_container,
                    return_container=return_container,
                    assignment_index=assignment_index,
                    return_index=return_index,
                    call=call,
                    return_statement=return_statement,
                )
            )
    return tuple(candidates)


def _materialize_fact_8616(
    root: object,
    codegen: object,
    fact: SoftwareInterruptInputFact8616,
    callbacks: TerminalCallResultReturnCallbacks8616,
) -> SoftwareInterruptResultMaterializationStats8616:
    """Materialize one exact terminal interrupt-result fact."""
    sunk_candidates = _sunk_returned_call_candidates_8616(root, fact)
    if sunk_candidates:
        if len(sunk_candidates) != 1:
            return SoftwareInterruptResultMaterializationStats8616(
                status=SoftwareInterruptResultStatus8616.AMBIGUOUS_CANDIDATE,
                raw_fact_count=1,
                normalized_fact_count=len(sunk_candidates),
                classified_fact_count=len(sunk_candidates),
                failure_count=len(sunk_candidates),
                callsite_addr=fact.callsite_addr,
            )
        path_status, path = prove_terminal_call_result_path_8616(
            fact.callsite_addr,
            callbacks,
        )
        result = _interrupt_result_variable_8616(codegen, fact)
        if (
            path_status is not TerminalCallResultReturnStatus8616.MATERIALIZED
            or result is None
        ):
            return SoftwareInterruptResultMaterializationStats8616(
                status=SoftwareInterruptResultStatus8616.CFG_PROOF_REFUSED,
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                failure_count=1,
                callsite_addr=fact.callsite_addr,
                path_block_addrs=path,
                path_status=path_status,
            )
        _materialize_sunk_returned_call_8616(sunk_candidates[0], result, codegen)
        return SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.MATERIALIZED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            callsite_addr=fact.callsite_addr,
            path_block_addrs=path,
            path_status=path_status,
        )
    if _returned_call_matches_8616(root, fact):
        return SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.ALREADY_MATERIALIZED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            callsite_addr=fact.callsite_addr,
        )
    candidates = _stale_selector_candidates_8616(root, fact)
    if not candidates:
        return SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.NO_STALE_SELECTOR_RETURN,
            raw_fact_count=1,
        )
    if len(candidates) != 1:
        return SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.AMBIGUOUS_CANDIDATE,
            raw_fact_count=1,
            normalized_fact_count=len(candidates),
            classified_fact_count=len(candidates),
            failure_count=len(candidates),
            callsite_addr=fact.callsite_addr,
        )
    candidate = candidates[0]
    path_status, path = prove_terminal_call_result_path_8616(
        fact.callsite_addr,
        callbacks,
    )
    if path_status is not TerminalCallResultReturnStatus8616.MATERIALIZED:
        return SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.CFG_PROOF_REFUSED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            failure_count=1,
            callsite_addr=fact.callsite_addr,
            path_block_addrs=path,
            path_status=path_status,
        )
    replacement = structured_c.CReturn(
        candidate.call,
        tags=candidate.return_statement.tags,
        codegen=codegen,
    )
    if candidate.call_container is candidate.return_container:
        statements = list(
            cast(
                Iterable[structured_c.CStatement],
                candidate.call_container.statements or (),
            )
        )
        statements[candidate.assignment_index : candidate.return_index + 1] = [replacement]
        candidate.call_container.statements = statements
    else:
        call_statements = list(
            cast(
                Iterable[structured_c.CStatement],
                candidate.call_container.statements or (),
            )
        )
        del call_statements[candidate.assignment_index]
        candidate.call_container.statements = call_statements
        return_statements = list(
            cast(
                Iterable[structured_c.CStatement],
                candidate.return_container.statements or (),
            )
        )
        return_statements[candidate.return_index] = replacement
        candidate.return_container.statements = return_statements
    return SoftwareInterruptResultMaterializationStats8616(
        status=SoftwareInterruptResultStatus8616.MATERIALIZED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        callsite_addr=fact.callsite_addr,
        path_block_addrs=path,
        path_status=path_status,
    )


def materialize_software_interrupt_terminal_results_8616(
    root: object,
    codegen: object,
    callbacks: TerminalCallResultReturnCallbacks8616,
) -> bool:
    """Return terminal interrupt results only from typed ABI and CFG proof."""
    surface = cast(_CodegenInterruptResultSurface8616, codegen)
    try:
        artifact = surface._inertia_software_interrupt_input_artifact_8616
    except AttributeError:
        stats = SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.NO_INPUT_ARTIFACT,
        )
        surface._inertia_software_interrupt_result_stats_8616 = stats
        return False
    facts = tuple(fact for fact in artifact.facts if fact.result_register is not None)
    if not facts:
        stats = SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.NO_RESULT_FACT,
        )
        surface._inertia_software_interrupt_result_stats_8616 = stats
        return False
    if len(facts) != 1:
        stats = SoftwareInterruptResultMaterializationStats8616(
            status=SoftwareInterruptResultStatus8616.AMBIGUOUS_CANDIDATE,
            raw_fact_count=len(facts),
            failure_count=len(facts),
        )
    else:
        stats = _materialize_fact_8616(root, codegen, facts[0], callbacks)
    surface._inertia_software_interrupt_result_stats_8616 = stats
    if stats.classified_fact_count > stats.materialized_count or stats.failure_count:
        raise PipelineHardError(
            "classified software interrupt result was not materialized",
            layer="structuring",
        )
    return stats.status is SoftwareInterruptResultStatus8616.MATERIALIZED

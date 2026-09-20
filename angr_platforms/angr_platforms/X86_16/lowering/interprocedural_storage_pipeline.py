"""Collect and atomically publish production interprocedural storage trials.

Layer: Types/Lowering.
Responsibility: collect one current function's closed input and return trials,
merge them into the immutable program trial payload, resolve every retained SCC,
and publish the resulting accepted/refused contracts before owned consumers run.
This module does not infer missing evidence or mutate C declarations directly.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from ..caller_return_use_contracts import CallerReturnUseEvidence8616
from ..callsite_summary import caller_return_use_evidence_by_addr_8616
from ..pipeline.errors import PipelineHardError
from .interprocedural_storage_collection_contracts import (
    FunctionInputStorageTrialCollection8616,
)
from .interprocedural_storage_contracts import (
    ProgramStorageResolution8616,
)
from .interprocedural_storage_return_collection_contracts import (
    FunctionReturnStorageTrialCollection8616,
)
from .interprocedural_storage_return_trial_collection import (
    collect_function_return_storage_trials_8616,
)
from .interprocedural_storage_transaction import (
    accepted_function_storage_contract_8616,
    function_storage_resolution_8616,
    replace_function_storage_trials_8616,
)
from .interprocedural_storage_trial_collection import (
    collect_function_input_storage_trials_8616,
)
from .pointer_parameter_caller_targets import publish_pointer_parameter_caller_targets_8616
from .pointer_parameter_outputs import publish_pointer_parameter_outputs_8616

__all__ = [
    "FunctionStoragePublicationResult8616",
    "FunctionStoragePublicationVerdict8616",
    "collect_and_publish_function_storage_contract_8616",
    "publish_and_reconcile_callsite_interfaces_8616",
]


class FunctionStoragePublicationVerdict8616(StrEnum):
    """Typed production outcome for one function publication attempt."""

    FUNCTION_UNAVAILABLE = "function_unavailable"
    INPUT_REFUSED = "input_refused"
    RETURN_EVIDENCE_UNAVAILABLE = "return_evidence_unavailable"
    RETURN_EVIDENCE_CONFLICT = "return_evidence_conflict"
    RETURN_REFUSED = "return_refused"
    PUBLISHED_ACCEPTED = "published_accepted"
    PUBLISHED_REFUSED = "published_refused"
    UNCHANGED_ACCEPTED = "unchanged_accepted"
    UNCHANGED_REFUSED = "unchanged_refused"


@dataclass(frozen=True, slots=True)
class FunctionStoragePublicationResult8616:
    """Closed collection and atomic publication evidence for one function."""

    function_addr: int | None
    verdict: FunctionStoragePublicationVerdict8616
    input_collection: FunctionInputStorageTrialCollection8616 | None = None
    return_collection: FunctionReturnStorageTrialCollection8616 | None = None
    resolution: ProgramStorageResolution8616 | None = None
    changed: bool = False

    @property
    def published(self) -> bool:
        """Return whether this attempt reached the atomic transaction boundary."""
        return self.verdict in {
            FunctionStoragePublicationVerdict8616.PUBLISHED_ACCEPTED,
            FunctionStoragePublicationVerdict8616.PUBLISHED_REFUSED,
            FunctionStoragePublicationVerdict8616.UNCHANGED_ACCEPTED,
            FunctionStoragePublicationVerdict8616.UNCHANGED_REFUSED,
        }


class _CFunctionSurface8616(Protocol):
    """Owned current-function identity exposed by structured codegen."""

    addr: int


class _CodegenSurface8616(Protocol):
    """Owned codegen fields used by the Types/Lowering lifecycle."""

    cfunc: _CFunctionSurface8616
    _inertia_interprocedural_storage_publication_8616: FunctionStoragePublicationResult8616


class _FunctionManager8616(Protocol):
    """Third-party angr function lookup used at the pipeline boundary."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function without creating a guessed one."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party knowledge-base function surface."""

    functions: _FunctionManager8616


class _ProjectSurface8616(Protocol):
    """angr project plus explicit caller-evidence address aliases."""

    kb: _KnowledgeBase8616
    _inertia_caller_evidence_target_8616: int
    _inertia_caller_target_aliases_8616: tuple[int, ...]


def _record_result_8616(
    project: object,
    codegen: object,
    result: FunctionStoragePublicationResult8616,
) -> FunctionStoragePublicationResult8616:
    """Record current evidence, refusing stale accepted contracts before reuse."""
    if not result.published and result.function_addr is not None:
        previous = accepted_function_storage_contract_8616(project, result.function_addr)
        if previous is not None:
            raise PipelineHardError(
                "previously accepted storage contract cannot survive refused refresh: "
                f"function={result.function_addr:#x} verdict={result.verdict.value}",
                layer="types/lowering",
                function_addr=result.function_addr,
                details=result,
            )
    try:  # noqa: SIM105
        cast(
            _CodegenSurface8616,
            codegen,
        )._inertia_interprocedural_storage_publication_8616 = result
    except AttributeError:
        # Test/plugin boundaries may expose an immutable placeholder, not codegen.
        pass
    return result


def _function_context_8616(
    project: object,
    codegen: object,
) -> tuple[int, object] | None:
    """Return the exact current function and address without creating one."""
    try:
        function_addr = cast(_CodegenSurface8616, codegen).cfunc.addr
        function = cast(_ProjectSurface8616, project).kb.functions.function(
            addr=function_addr,
            create=False,
        )
    except (AttributeError, KeyError, TypeError):
        return None
    if not isinstance(function_addr, int) or function is None:
        return None
    return function_addr, function


def _accepted_target_addrs_8616(
    project: object,
    function_addr: int,
) -> tuple[int, ...]:
    """Return only explicit project target aliases for the current function."""
    surface = cast(_ProjectSurface8616, project)
    try:
        evidence_target = surface._inertia_caller_evidence_target_8616
    except AttributeError:
        evidence_target = None
    try:
        aliases = surface._inertia_caller_target_aliases_8616
    except AttributeError:
        aliases = ()
    if not isinstance(aliases, tuple):
        raise TypeError("caller target aliases must be a tuple")
    return tuple(
        dict.fromkeys(
            address
            for address in (function_addr, evidence_target, *aliases)
            if isinstance(address, int) and not isinstance(address, bool)
        )
    )


def _return_evidence_8616(
    project: object,
    function_addr: int,
    accepted_target_addrs: tuple[int, ...],
) -> tuple[
    CallerReturnUseEvidence8616 | None,
    FunctionStoragePublicationVerdict8616 | None,
]:
    """Select one exact or explicitly aliased caller-return census."""
    evidence_by_addr = caller_return_use_evidence_by_addr_8616(project)
    exact = evidence_by_addr.get(function_addr)
    if exact is not None:
        return exact, None
    candidates = tuple(
        evidence_by_addr[address]
        for address in accepted_target_addrs
        if address in evidence_by_addr
    )
    if not candidates:
        return None, FunctionStoragePublicationVerdict8616.RETURN_EVIDENCE_UNAVAILABLE
    reference = candidates[0]
    if any(candidate != reference for candidate in candidates[1:]):
        return None, FunctionStoragePublicationVerdict8616.RETURN_EVIDENCE_CONFLICT
    return reference, None


def collect_and_publish_function_storage_contract_8616(
    project: object,
    codegen: object,
) -> FunctionStoragePublicationResult8616:
    """Collect one complete function contract and republish the program payload."""
    context = _function_context_8616(project, codegen)
    if context is None:
        return _record_result_8616(
            project,
            codegen,
            FunctionStoragePublicationResult8616(
                None,
                FunctionStoragePublicationVerdict8616.FUNCTION_UNAVAILABLE,
            ),
        )
    function_addr, function = context
    pointer_outputs = publish_pointer_parameter_outputs_8616(
        project, function_addr, function=function
    )
    pointer_targets = publish_pointer_parameter_caller_targets_8616(
        project, function_addr, function=function, outputs=pointer_outputs
    )
    inputs = collect_function_input_storage_trials_8616(project, codegen, function_addr)
    if not inputs.complete:
        return _record_result_8616(
            project,
            codegen,
            FunctionStoragePublicationResult8616(
                function_addr,
                FunctionStoragePublicationVerdict8616.INPUT_REFUSED,
                input_collection=inputs,
            ),
        )
    accepted_targets = _accepted_target_addrs_8616(project, function_addr)
    evidence, evidence_failure = _return_evidence_8616(
        project,
        function_addr,
        accepted_targets,
    )
    if evidence is None:
        return _record_result_8616(
            project,
            codegen,
            FunctionStoragePublicationResult8616(
                function_addr,
                evidence_failure
                or FunctionStoragePublicationVerdict8616.RETURN_EVIDENCE_UNAVAILABLE,
                input_collection=inputs,
            ),
        )
    returns = collect_function_return_storage_trials_8616(
        project,
        function,
        inputs,
        evidence,
        accepted_target_addrs=accepted_targets,
        pointer_targets=pointer_targets,
    )
    if not returns.complete:
        return _record_result_8616(
            project,
            codegen,
            FunctionStoragePublicationResult8616(
                function_addr,
                FunctionStoragePublicationVerdict8616.RETURN_REFUSED,
                input_collection=inputs,
                return_collection=returns,
            ),
        )
    resolution, changed = replace_function_storage_trials_8616(project, returns.trials)
    function_resolution = function_storage_resolution_8616(project, function_addr)
    accepted = function_resolution is not None and function_resolution.contract is not None
    verdict = (
        FunctionStoragePublicationVerdict8616.PUBLISHED_ACCEPTED
        if changed and accepted
        else (
            FunctionStoragePublicationVerdict8616.PUBLISHED_REFUSED
            if changed
            else (
                FunctionStoragePublicationVerdict8616.UNCHANGED_ACCEPTED
                if accepted
                else FunctionStoragePublicationVerdict8616.UNCHANGED_REFUSED
            )
        )
    )
    return _record_result_8616(
        project,
        codegen,
        FunctionStoragePublicationResult8616(
            function_addr,
            verdict,
            input_collection=inputs,
            return_collection=returns,
            resolution=resolution,
            changed=changed,
        ),
    )


def publish_and_reconcile_callsite_interfaces_8616(
    project: object,
    codegen: object,
) -> bool:
    """Publish storage contracts before all declaration/prototype consumers."""
    from .callsite_prototype_declarations import (
        materialize_callsite_prototype_declarations_8616,
    )
    from .helper_call_interfaces import materialize_known_helper_call_interfaces_8616
    from .interprocedural_storage_prototype_application import (
        apply_accepted_function_storage_prototype_8616,
    )
    from .stack_prototype_materialization import (
        reconcile_exact_stack_argument_prototype_8616,
    )
    from .unobserved_call_results import lower_unobserved_call_result_assignments_8616

    collect_and_publish_function_storage_contract_8616(project, codegen)
    application = apply_accepted_function_storage_prototype_8616(project, codegen)
    prototype_changed = (
        False
        if application.blocks_legacy_reconciliation
        else reconcile_exact_stack_argument_prototype_8616(project, codegen)
    )
    helper_changed = materialize_known_helper_call_interfaces_8616(project, codegen)
    materialize_callsite_prototype_declarations_8616(project, codegen)
    result_changed = lower_unobserved_call_result_assignments_8616(codegen)
    return (
        application.changed
        or prototype_changed
        or helper_changed
        or result_changed
    )

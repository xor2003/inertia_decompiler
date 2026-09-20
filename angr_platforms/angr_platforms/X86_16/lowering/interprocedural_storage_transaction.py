"""Atomic publication boundary for interprocedural storage contracts.

Layer: Types/Lowering.
Responsibility: publish one resolved artifact and expose proof-bearing callee and
callsite views to downstream Types/Lowering consumers.
Consumes alias, widening, and typed facts. It mutates only the owned project
contract surface in one assignment.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: partial map updates, C-AST repair, or fallback signature inference.
"""

from __future__ import annotations

from typing import Protocol, cast

from ..pipeline.errors import PipelineHardError
from .interprocedural_memory_output_validation import (
    validate_memory_output_transaction_8616,
)
from .interprocedural_storage_contracts import (
    CallsiteStorageBinding8616,
    FunctionStorageContract8616,
    FunctionStorageResolution8616,
    FunctionStorageTrials8616,
    ProgramStorageResolution8616,
    StorageIdentityKind8616,
    StorageTrialVerdict8616,
)
from .interprocedural_storage_return_discard import discarded_return_publication_failure_8616
from .interprocedural_storage_solver import resolve_program_storage_trials_8616

__all__ = [
    "accepted_callsite_storage_binding_8616",
    "accepted_function_storage_contract_8616",
    "accepted_stack_input_layout_8616",
    "apply_program_storage_resolution_8616",
    "function_storage_resolution_8616",
    "program_storage_resolution_8616",
    "replace_function_storage_trials_8616",
]


class _ProjectStorageContractSurface8616(Protocol):
    """Owned contract artifact attached at the dynamic angr project boundary."""

    _inertia_interprocedural_storage_resolution_8616: ProgramStorageResolution8616


def _validate_discard_publication_8616(
    contract: FunctionStorageContract8616, resolution: ProgramStorageResolution8616,
) -> None:
    """Reject proof loss before any function or callsite contract is replaced."""
    trials = next(item for item in resolution.function_trials if item.function_addr == contract.function_addr)
    recursive_callers = next((frozenset(scc) for scc in resolution.sccs if contract.function_addr in scc), frozenset())
    failure = discarded_return_publication_failure_8616(contract, trials, recursive_callers)
    if failure is not None:
        raise PipelineHardError(
            f"discarded-return contract proof is incoherent: {failure.value}",
            layer="types/lowering", function_addr=contract.function_addr, details=failure,
        )


def apply_program_storage_resolution_8616(
    project: object,
    resolution: ProgramStorageResolution8616,
) -> bool:
    """Atomically publish callee contracts with all retained callsite bindings."""
    trial_addresses = tuple(item.function_addr for item in resolution.function_trials)
    resolution_addresses = tuple(item.function_addr for item in resolution.resolutions)
    if (
        len(set(trial_addresses)) != len(trial_addresses)
        or trial_addresses != tuple(sorted(trial_addresses))
        or resolution_addresses != trial_addresses
    ):
        raise PipelineHardError(
            "program storage resolution does not retain one ordered trial per result",
            layer="types/lowering",
        )
    if (
        resolution.stats.classified_fact_count > 0
        and resolution.stats.materialized_count == 0
    ):
        raise PipelineHardError(
            "classified storage trials produced no contract",
            layer="types/lowering",
        )
    for function_resolution in resolution.resolutions:
        contract = function_resolution.contract
        accepted = function_resolution.verdict is StorageTrialVerdict8616.ACCEPTED
        if accepted != (contract is not None):
            raise PipelineHardError(
                "storage verdict and function contract disagree",
                layer="types/lowering",
                details={"function_addr": function_resolution.function_addr},
            )
        if contract is None:
            continue
        if contract.function_addr != function_resolution.function_addr:
            raise PipelineHardError(
                "storage result and function contract identities disagree",
                layer="types/lowering",
                details={"function_addr": function_resolution.function_addr},
            )
        _validate_discard_publication_8616(contract, resolution)
        memory_validation = validate_memory_output_transaction_8616(contract)
        if not memory_validation.complete:
            failure = memory_validation.failure
            raise PipelineHardError(
                "memory-output contract transaction is incoherent: "
                f"{None if failure is None else failure.value}",
                layer="types/lowering",
                details={
                    "function_addr": function_resolution.function_addr,
                    "failure": None if failure is None else failure.value,
                },
            )
    surface = cast(_ProjectStorageContractSurface8616, project)
    try:
        previous = surface._inertia_interprocedural_storage_resolution_8616
    except AttributeError:
        previous = None
    if previous == resolution:
        return False
    surface._inertia_interprocedural_storage_resolution_8616 = resolution
    return True


def program_storage_resolution_8616(
    project: object,
) -> ProgramStorageResolution8616 | None:
    """Read the one atomic program storage payload from its project owner."""
    try:
        resolution = cast(
            _ProjectStorageContractSurface8616,
            project,
        )._inertia_interprocedural_storage_resolution_8616
    except AttributeError:
        return None
    if not isinstance(resolution, ProgramStorageResolution8616):
        raise TypeError("project interprocedural storage resolution has an invalid type")
    return resolution


def replace_function_storage_trials_8616(
    project: object,
    trials: FunctionStorageTrials8616,
) -> tuple[ProgramStorageResolution8616, bool]:
    """Replace one trial and atomically republish all retained SCC resolutions."""
    previous = program_storage_resolution_8616(project)
    trials_by_addr = {
        item.function_addr: item
        for item in (() if previous is None else previous.function_trials)
    }
    trials_by_addr[trials.function_addr] = trials
    resolution = resolve_program_storage_trials_8616(
        trials_by_addr[address] for address in sorted(trials_by_addr)
    )
    changed = apply_program_storage_resolution_8616(project, resolution)
    return resolution, changed


def function_storage_resolution_8616(
    project: object,
    function_addr: int,
) -> FunctionStorageResolution8616 | None:
    """Return one accepted or refused function result from the atomic payload."""
    resolution = program_storage_resolution_8616(project)
    if resolution is None:
        return None
    return next(
        (item for item in resolution.resolutions if item.function_addr == function_addr),
        None,
    )


def accepted_function_storage_contract_8616(
    project: object,
    function_addr: int,
) -> FunctionStorageContract8616 | None:
    """Read one accepted contract from the atomic project artifact."""
    function_resolution = function_storage_resolution_8616(project, function_addr)
    return None if function_resolution is None else function_resolution.contract


def accepted_callsite_storage_binding_8616(
    project: object,
    function_addr: int,
    callsite_addr: int,
) -> CallsiteStorageBinding8616 | None:
    """Return a proof-bearing binding from one accepted function contract."""
    contract = accepted_function_storage_contract_8616(project, function_addr)
    if contract is None:
        return None
    return next((item for item in contract.callsites if item.callsite_addr == callsite_addr), None)


def accepted_stack_input_layout_8616(
    project: object,
    function_addr: int,
) -> tuple[tuple[int, int], ...] | None:
    """Project one accepted contract to exact source-order ``BP+offset`` widths."""
    contract = accepted_function_storage_contract_8616(project, function_addr)
    if contract is None:
        return None
    layout: list[tuple[int, int]] = []
    for slot in contract.inputs:
        if len(slot.pieces) != 1:
            return None
        piece = slot.pieces[0]
        address = piece.address
        if (
            piece.kind is not StorageIdentityKind8616.STACK
            or address is None
            or address.base != ("bp",)
        ):
            return None
        layout.append((address.offset, slot.width))
    return tuple(layout)

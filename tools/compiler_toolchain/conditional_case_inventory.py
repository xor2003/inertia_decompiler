"""Layer: Tooling/gates.
Responsibility: decode an exact retained final-attempt inventory through existing worker IPC.

No new proof format, C recovery, companion emission, or acceptance is introduced.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from inertia.cli.cli_function_discovery import _make_placeholder_function
from inertia.cli.work_items import FunctionWorkItem, WorkItemStatus
from tools.compiler_toolchain.compiler_profile import FrozenCompilerContext
from tools.compiler_toolchain.conditional_case_composition import FinalFunctionAttempt, FrozenCaseCompositionInput
from tools.compiler_toolchain.conditional_function_receipt import ConditionalTransportOrigin

if TYPE_CHECKING:
    import angr


class _LoadedObject(Protocol):
    """Original source and load coordinates at the existing angr boundary."""
    binary: str
    mapped_base: int


class _Loader(Protocol):
    """Native loader metadata needed to bind the independent case request."""
    main_object: _LoadedObject


class _Project(Protocol):
    """Actual native project used by the canonical IPC decoder."""
    loader: _Loader


class FinalAttemptInventoryStatus(StrEnum):
    """A decoded inventory is evidence transport, not composition readiness."""
    DECODED = 'decoded'
    RECORD_CENSUS_REFUSED = 'record_census_refused'
    CONTEXT_REFUSED = 'context_refused'
    PROCESS_REFUSED = 'process_refused'
    RECORD_REFUSED = 'record_refused'


@dataclass(frozen=True, slots=True)
class FinalAttemptInventory:
    """All decoded attempts or one explicit refusal, preserving actual process exit."""
    status: FinalAttemptInventoryStatus
    process_returncode: int
    attempts: tuple[FinalFunctionAttempt, ...] = ()
    detail: str = ''


def _project_matches(project: object, contract: FrozenCaseCompositionInput) -> bool:
    """Check independent source/load pins before any accepted interface is attached."""
    image = cast(_Project, project).loader.main_object
    try:
        digest = hashlib.sha256(Path(image.binary).read_bytes()).hexdigest()
    except OSError:
        return False
    return digest == contract.image_sha256 and image.mapped_base == contract.mapped_base


def load_final_function_attempts(
    contract: FrozenCaseCompositionInput, *, project: object, records_dir: Path,
    artifact_dir: Path, compiler_context: FrozenCompilerContext, process_returncode: int,
    origin: ConditionalTransportOrigin = ConditionalTransportOrigin.FULL_SWEEP,
) -> FinalAttemptInventory:
    """Decode exactly the independently selected final worker records.

    Canonical address placeholders bind each real FunctionWorkItem to the actual
    project; the existing decoder authenticates accepted scalar generation,
    payload, source and loaded native bytes. Conditional companions remain
    untouched and are authenticated by the subsequent composition consumer.
    """
    from inertia.cli.cli_core import _read_serial_clean_worker_result_8616

    if compiler_context != contract.compiler_context or not _project_matches(project, contract):
        return FinalAttemptInventory(FinalAttemptInventoryStatus.CONTEXT_REFUSED, process_returncode)
    allowed = (0, 5) if origin is ConditionalTransportOrigin.FULL_SWEEP else (0,)
    if origin not in (ConditionalTransportOrigin.FULL_SWEEP, ConditionalTransportOrigin.SERIAL_WORKER) or process_returncode not in allowed:
        return FinalAttemptInventory(FinalAttemptInventoryStatus.PROCESS_REFUSED, process_returncode)
    names = tuple(f'{target.address:08x}.result.json' for target in contract.selected)
    current = {path.name for path in records_dir.glob('*.result.json')}
    if not names or len(set(names)) != len(names) or current != set(names):
        return FinalAttemptInventory(FinalAttemptInventoryStatus.RECORD_CENSUS_REFUSED, process_returncode)
    attempts: list[FinalFunctionAttempt] = []
    for index, target in enumerate(contract.selected):
        function = _make_placeholder_function(cast('angr.Project', project), target.address, target.emitted_name)
        item = FunctionWorkItem(index, None, function, recovery_addr=target.address)
        try:
            result = _read_serial_clean_worker_result_8616(
                records_dir / names[index], item=item, debug_output='',
            )
        except ValueError as error:
            return FinalAttemptInventory(FinalAttemptInventoryStatus.RECORD_REFUSED, process_returncode,
                                         detail=str(error))
        attempts.append(FinalFunctionAttempt(target, result, compiler_context, artifact_dir,
                                              process_returncode, origin=origin))
    has_conditional = any(attempt.result.status == WorkItemStatus.CONDITIONAL.value for attempt in attempts)
    if origin is ConditionalTransportOrigin.FULL_SWEEP and has_conditional != (process_returncode == 5):
        return FinalAttemptInventory(FinalAttemptInventoryStatus.PROCESS_REFUSED, process_returncode)
    return FinalAttemptInventory(FinalAttemptInventoryStatus.DECODED, process_returncode, tuple(attempts))

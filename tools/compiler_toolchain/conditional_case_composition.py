"""Layer: Tooling/gates.
Responsibility: bind final generated-function evidence for conditional case composition.

This synchronous consumer accepts owned final work results, not JSON proof claims.
Readiness does not grant semantic acceptance, discharge premises, or compile C.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from inertia.cli.accepted_payload_integrity import verify_function_work_result_payload_integrity_8616
from inertia.cli.work_items import FunctionWorkResult, WorkItemStatus
from inertia.frontend.x86_16.declared_entry_document import parse_declared_function_entry_spec_8616
from inertia.validation.tail_validation import x86_16_tail_validation_snapshot_passed
from tools.compiler_toolchain.compiler_profile import FrozenCompilerContext
from tools.compiler_toolchain.conditional_function_receipt import (
    ConditionalTransportOrigin,
    bind_conditional_function_artifact,
)
from tools.compiler_toolchain.msc6_function_targets import BinaryFunctionTarget


class CaseCompositionStatus(StrEnum):
    """Readiness and specific refusal categories; none denotes acceptance."""
    CONDITIONAL_READY = 'conditional_ready'
    INVENTORY_REFUSED = 'inventory_refused'
    INPUT_CHANGED = 'input_changed'
    FUNCTION_REFUSED = 'function_refused'
    PREMISE_REFUSED = 'premise_refused'


@dataclass(frozen=True, slots=True)
class FrozenCaseCompositionInput:
    """Independent selection and input pins frozen before child execution.

    Declaration entries contain canonical JSON of each requested declaration
    spec, not a self-reported domain or a hash copied from the child's receipt.
    Observation bytes are the original expected-run contract, frozen separately.
    """
    selected: tuple[BinaryFunctionTarget, ...]
    entry: BinaryFunctionTarget
    image_sha256: str
    declarations: tuple[tuple[int, str], ...]
    observations: bytes
    compiler_context: FrozenCompilerContext
    mapped_base: int


@dataclass(frozen=True, slots=True)
class FinalFunctionAttempt:
    """Final owned attempt retained by the sweep after all retries finish.

    The orchestrator supplies these records synchronously, including request
    context and the actual fresh artifact directory; serialized user receipts
    cannot construct authority through this owner.
    """
    target: BinaryFunctionTarget
    result: FunctionWorkResult
    compiler_context: FrozenCompilerContext
    artifact_dir: Path | None = None
    child_returncode: int = 0
    stale_directory: bool = False
    origin: ConditionalTransportOrigin = ConditionalTransportOrigin.DIRECT_CLI


@dataclass(frozen=True, slots=True)
class ConditionalCaseComposition:
    """Immutable generated fragments plus premises, still awaiting case checks."""
    status: CaseCompositionStatus
    payloads: tuple[tuple[BinaryFunctionTarget, str], ...] = ()
    premises: tuple[tuple[int, str], ...] = ()
    contract: FrozenCaseCompositionInput | None = None


def _declarations_coherent(contract: FrozenCaseCompositionInput) -> bool:
    """Require one source/load/environment while permitting distinct entry domains."""
    coordinates: set[tuple[str, int, str]] = set()
    selected = {target.address for target in contract.selected}
    for address, document in contract.declarations:
        try:
            spec = parse_declared_function_entry_spec_8616(json.loads(document))
        except ValueError:
            return False
        if (address not in selected or spec.source_sha256 != contract.image_sha256
                or spec.range_start != address
                or (spec.entry_segment << 4) + spec.entry_offset != address):
            return False
        coordinates.add((spec.relocated_sha256, spec.load_segment, spec.environment_sha256))
    return len(coordinates) == 1


def _conditional_premise(
    attempt: FinalFunctionAttempt, image: Path, contract: FrozenCaseCompositionInput,
) -> str | None:
    """Reuse the receipt binder, then match the independently requested premise."""
    if attempt.artifact_dir is None:
        return None
    bound = bind_conditional_function_artifact(
        attempt.artifact_dir, target=attempt.target, binary_path=image,
        child_returncode=attempt.child_returncode, stale_directory=attempt.stale_directory,
        expected_binary_sha256=contract.image_sha256,
        origin=attempt.origin,
        decoded_result=attempt.result if attempt.origin in (
            ConditionalTransportOrigin.SERIAL_WORKER, ConditionalTransportOrigin.FULL_SWEEP,
        ) else None,
    )
    if not bound.bound or bound.tail_validation_json is None:
        return None
    snapshot = json.loads(bound.tail_validation_json)
    if snapshot != attempt.result.tail_validation:
        return None
    if bound.payload_sha256 != hashlib.sha256(attempt.result.payload.encode()).hexdigest():
        return None
    premise = snapshot['structuring']['entry_premise']
    spec = premise['payload']['declaration']['spec']
    expected = dict(contract.declarations).get(attempt.target.address)
    if expected is None or json.loads(expected) != spec:
        return None
    return json.dumps(premise, sort_keys=True, separators=(',', ':'))


def _inventory_complete(
    contract: FrozenCaseCompositionInput, attempts: tuple[FinalFunctionAttempt, ...],
) -> bool:
    """Require exact independent selection, one final attempt each, and an entry."""
    selected = contract.selected
    addresses = tuple(target.address for target in selected)
    actual = tuple(attempt.target for attempt in attempts)
    selection_valid = bool(selected) and len(set(addresses)) == len(addresses) and contract.entry in selected
    attempts_valid = len(actual) == len(selected) and len(set(actual)) == len(actual) and set(actual) == set(selected)
    declarations_valid = len(dict(contract.declarations)) == len(contract.declarations)
    return selection_valid and attempts_valid and declarations_valid


def _inputs_current(
    contract: FrozenCaseCompositionInput, attempts: tuple[FinalFunctionAttempt, ...],
    image: Path, observations: bytes, context: FrozenCompilerContext,
) -> bool:
    """Compare immutable request pins with current run inputs."""
    return (observations == contract.observations and context == contract.compiler_context
            and hashlib.sha256(image.read_bytes()).hexdigest() == contract.image_sha256
            and all(attempt.compiler_context == context for attempt in attempts))


def _ordered_attempts(
    selected: tuple[BinaryFunctionTarget, ...], attempts: tuple[FinalFunctionAttempt, ...],
) -> tuple[FinalFunctionAttempt, ...]:
    """Return the verified final inventory in independently selected order."""
    by_target = {attempt.target: attempt for attempt in attempts}
    return tuple(by_target[target] for target in selected)


def _unconditional_source_bound(
    attempt: FinalFunctionAttempt, contract: FrozenCaseCompositionInput,
) -> bool:
    """Require the existing accepted scalar receipt's image, ABI and payload pins."""
    receipt = attempt.result.scalar_interface
    if receipt is None:
        return False
    source_matches = (receipt.source_sha256 == contract.image_sha256
                      and receipt.mapped_base == contract.mapped_base)
    payload_matches = (receipt.target == attempt.target.address
                       and receipt.payload_sha256 == attempt.result.validated_payload_hash)
    return bool(source_matches and payload_matches and receipt.arch_name == '86_16' and receipt.arch_bits == 32)


def _unconditional_delivery_complete(attempt: FinalFunctionAttempt) -> bool:
    """Keep aggregate sweep exit separate from the already checked OK function status."""
    if attempt.origin is ConditionalTransportOrigin.FULL_SWEEP:
        return attempt.child_returncode in (0, 5)
    return attempt.child_returncode == 0


def prepare_conditional_case_composition(
    contract: FrozenCaseCompositionInput, attempts: tuple[FinalFunctionAttempt, ...], *,
    image: Path, observations: bytes, compiler_context: FrozenCompilerContext,
) -> ConditionalCaseComposition:
    """Bind one complete final inventory without promoting conditional evidence.

    Returned payloads are immutable copies. Consumers must still reconcile typed
    interfaces, compile the complete source and compare pinned original/rebuilt
    runs; none of those obligations is inferred from readiness.
    """
    selected = contract.selected
    if not _inventory_complete(contract, attempts):
        return ConditionalCaseComposition(CaseCompositionStatus.INVENTORY_REFUSED)
    if not _inputs_current(contract, attempts, image, observations, compiler_context):
        return ConditionalCaseComposition(CaseCompositionStatus.INPUT_CHANGED)
    if not _declarations_coherent(contract):
        return ConditionalCaseComposition(CaseCompositionStatus.PREMISE_REFUSED)
    payloads: list[tuple[BinaryFunctionTarget, str]] = []
    premises: list[tuple[int, str]] = []
    for attempt in _ordered_attempts(selected, attempts):
        target = attempt.target
        result = attempt.result
        # Third-party function metadata is carried by the owned work result.
        if (result.function is None or result.function.addr != target.address
                or not verify_function_work_result_payload_integrity_8616(result).passed):
            return ConditionalCaseComposition(CaseCompositionStatus.FUNCTION_REFUSED)
        if result.status == WorkItemStatus.CONDITIONAL.value:
            premise = _conditional_premise(attempt, image, contract)
            if premise is None:
                return ConditionalCaseComposition(CaseCompositionStatus.PREMISE_REFUSED)
            premises.append((target.address, premise))
        elif (result.status != WorkItemStatus.OK.value or not _unconditional_delivery_complete(attempt)
                or not x86_16_tail_validation_snapshot_passed(result.tail_validation)
                or not _unconditional_source_bound(attempt, contract)):
            return ConditionalCaseComposition(CaseCompositionStatus.FUNCTION_REFUSED)
        payloads.append((target, result.payload))
    return _finish_composition(contract, image, tuple(payloads), tuple(premises))


def _finish_composition(
    contract: FrozenCaseCompositionInput, image: Path,
    payloads: tuple[tuple[BinaryFunctionTarget, str], ...], premises: tuple[tuple[int, str], ...],
) -> ConditionalCaseComposition:
    """Seal current source bytes after receipt reads, retaining conditional evidence."""
    if not premises:
        return ConditionalCaseComposition(CaseCompositionStatus.PREMISE_REFUSED)
    if hashlib.sha256(image.read_bytes()).hexdigest() != contract.image_sha256:
        return ConditionalCaseComposition(CaseCompositionStatus.INPUT_CHANGED)
    return ConditionalCaseComposition(
        CaseCompositionStatus.CONDITIONAL_READY, payloads, premises, contract,
    )

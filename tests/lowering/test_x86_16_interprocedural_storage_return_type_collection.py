"""Function-wide caller-observed return-type collection tests."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from inertia.semantics.caller_return_use_contracts import (
    AxValueView8616,
    ByteReturnExtensionKind8616,
    CallerReturnUseEvidence8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.semantics.callsite_summary import record_caller_return_use_evidence_8616
from inertia.ir import IRValue, MemSpace
from inertia.ir.condition_ir import ConditionIR
import inertia.lowering.interprocedural_storage_return_type_collection as collection
from inertia.lowering.interprocedural_storage_caller_context import (
    CallerSSAContext8616,
    CallerSSAContextVerdict8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrialSignedness8616,
)
from inertia.lowering.interprocedural_storage_return_type_collection import (
    FunctionReturnStorageTypeFailure8616,
    FunctionReturnStorageTypeVerdict8616,
    collect_function_return_storage_type_8616,
)


def _fact(
    callsite_addr: int,
    *,
    extension: ByteReturnExtensionKind8616 | None = None,
    condition: bool = False,
) -> CallerReturnUseFact8616:
    """Build one complete AL return-use witness."""
    return CallerReturnUseFact8616(
        caller_addr=0x2000,
        callsite_addr=callsite_addr,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=(CallsiteReturnUseKind8616.CONDITION if condition else CallsiteReturnUseKind8616.VALUE),
        witness_instruction_addr=callsite_addr + 6,
        byte_extension=extension,
        byte_extension_instruction_addr=(callsite_addr + 4 if extension is not None else None),
        observed_value_view=(AxValueView8616.AX if extension is not None else AxValueView8616.AL),
    )


def _record(project: object, facts: tuple[CallerReturnUseFact8616, ...]) -> None:
    """Attach one complete direct-caller census to a project fixture."""
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        CallerReturnUseEvidence8616(
            target_addr=0x1000,
            verdict=CallerReturnUseVerdict8616.USED,
            raw_fact_count=len(facts),
            normalized_fact_count=len(facts),
            classified_fact_count=len(facts),
            materialized_count=len(facts),
            failure_count=0,
            used_callsite_count=len(facts),
            unused_callsite_count=0,
            callsite_addrs=tuple(fact.callsite_addr for fact in facts),
            facts=facts,
        ),
    )


def _al_storage() -> tuple[StorageIdentity8616, ...]:
    """Return the exact Alias identity for a byte return in AL."""
    return (
        StorageIdentity8616(
            kind=StorageIdentityKind8616.REGISTER,
            width=1,
            register="al",
        ),
    )


def _install_context(monkeypatch) -> None:
    """Supply one exact caller boundary to the collection fixture."""
    monkeypatch.setattr(
        collection,
        "caller_ssa_context_for_return_use_8616",
        lambda _project, _callee, fact: CallerSSAContext8616(
            CallerSSAContextVerdict8616.PROVEN,
            fact.caller_addr,
            fact.callsite_addr,
            evidence_project=SimpleNamespace(),
            caller_function=SimpleNamespace(),
        ),
    )


def test_unsigned_extension_and_equality_join_as_unsigned(monkeypatch) -> None:
    """A sign-insensitive caller cannot erase an informative unsigned proof."""
    project = SimpleNamespace()
    unsigned = _fact(0x2010, extension=ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX)
    equality = _fact(0x2030, condition=True)
    _record(project, (unsigned, equality))
    _install_context(monkeypatch)
    condition = ConditionIR(
        "ne",
        IRValue(MemSpace.REG, name="al", offset=0, size=1),
        IRValue(MemSpace.CONST, const=13, size=1),
        width_bits=8,
        producer_insn=equality.witness_instruction_addr,
    )
    monkeypatch.setattr(
        collection,
        "collect_typed_condition_artifacts_8616",
        lambda *_args, **_kwargs: ([condition], []),
    )

    result = collect_function_return_storage_type_8616(project, 0x1000, _al_storage())

    assert result.complete
    assert result.verdict is FunctionReturnStorageTypeVerdict8616.PROVEN
    assert result.signedness is StorageTrialSignedness8616.UNSIGNED
    assert result.stats.raw_fact_count == 2
    assert result.stats.materialized_count == 2


def test_conflicting_extensions_refuse_function_type(monkeypatch) -> None:
    """Signed and unsigned extension witnesses are a hard type conflict."""
    project = SimpleNamespace()
    _record(
        project,
        (
            _fact(0x2010, extension=ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX),
            _fact(0x2030, extension=ByteReturnExtensionKind8616.SIGN_EXTEND_AL_TO_AX),
        ),
    )
    _install_context(monkeypatch)

    result = collect_function_return_storage_type_8616(project, 0x1000, _al_storage())

    assert result.verdict is FunctionReturnStorageTypeVerdict8616.CONFLICT
    assert result.failure is FunctionReturnStorageTypeFailure8616.SIGNEDNESS_CONFLICT
    assert not result.complete


def test_incomplete_caller_census_refuses_before_classification() -> None:
    """A missing retained callsite cannot publish a return type."""
    project = SimpleNamespace()
    fact = _fact(0x2010, extension=ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX)
    _record(project, (fact,))
    evidence = project._inertia_caller_return_use_evidence_by_addr_8616[0x1000]
    project._inertia_caller_return_use_evidence_by_addr_8616[0x1000] = replace(
        evidence,
        raw_fact_count=2,
    )

    result = collect_function_return_storage_type_8616(project, 0x1000, _al_storage())

    assert result.failure is FunctionReturnStorageTypeFailure8616.CENSUS_INCOMPLETE
    assert result.stats.failure_count == 1


def test_only_sign_insensitive_callers_refuse_signedness(monkeypatch) -> None:
    """Equality alone cannot choose signed or unsigned C char."""
    project = SimpleNamespace()
    equality = _fact(0x2030, condition=True)
    _record(project, (equality,))
    _install_context(monkeypatch)
    condition = ConditionIR(
        "eq",
        IRValue(MemSpace.REG, name="al", offset=0, size=1),
        IRValue(MemSpace.CONST, const=13, size=1),
        width_bits=8,
        producer_insn=equality.witness_instruction_addr,
    )
    monkeypatch.setattr(
        collection,
        "collect_typed_condition_artifacts_8616",
        lambda *_args, **_kwargs: ([condition], []),
    )

    result = collect_function_return_storage_type_8616(project, 0x1000, _al_storage())

    assert result.verdict is FunctionReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FunctionReturnStorageTypeFailure8616.SIGNEDNESS_UNINFORMATIVE


def test_missing_exact_caller_context_refuses(monkeypatch) -> None:
    """A caller address without its census-owned boundary is not type proof."""
    project = SimpleNamespace()
    fact = _fact(0x2010, extension=ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX)
    _record(project, (fact,))
    monkeypatch.setattr(
        collection,
        "caller_ssa_context_for_return_use_8616",
        lambda _project, _callee, item: CallerSSAContext8616(
            CallerSSAContextVerdict8616.UNAVAILABLE,
            item.caller_addr,
            item.callsite_addr,
        ),
    )

    result = collect_function_return_storage_type_8616(project, 0x1000, _al_storage())

    assert result.failure is FunctionReturnStorageTypeFailure8616.CALLER_CONTEXT_UNAVAILABLE

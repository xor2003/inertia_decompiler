"""Owner tests for the typed public proof-domain contract.

Layer: tests.
Responsibility: prove the ``proof_public_domain`` owner publishes all
six M1 identifications as typed fields, binds evidence honestly (no invented
ABI labels, no whole-machine-state overclaim, closed outcome inventory,
``not_established`` for unverified scope), rejects malformed declared
outputs instead of guessing, and keeps the real16 published register
projection in parity with ``INTERNAL_STATE_REGS``. Public boundary assertions live in ``test_dosunit_public_domain_integration.py``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import pytest

from tools.dosunit.proof_contracts import Architecture
from tools.dosunit.proof_public_domain import (
    AddressModel,
    CallingConvention,
    FlagModel,
    InitialDataRelation,
    InstructionMemory,
    MachineProofDomain,
    MemoryRelation,
    ObservableScope,
    OutcomeAdmission,
    OutcomeContract,
    OutcomeKind,
    OutputDeclarationSource,
    ReturnKind,
    common_image_bits,
    declared_output_regs,
    flat32_declared_outputs,
    flat32_public_domain,
    real16_public_domain,
)
from tools.dosunit.straightline_ssa import INTERNAL_STATE_REGS

BACKEND = OutputDeclarationSource.BACKEND_DECLARED
CALLER = OutputDeclarationSource.CALLER_DECLARED


def _flat32(
    *, image_bits: int | None = None, premise: Mapping[str, Any] | None = None
) -> MachineProofDomain:
    return flat32_public_domain(
        outputs=("eax", "esp"), register_source=CALLER, image_bits=image_bits, premise=premise
    )


def _outcome(document: dict, kind: str) -> dict:
    return next(item for item in document["outcomes"] if item["kind"] == kind)


def test_real16_domain_identifies_every_m1_field() -> None:
    """Publish all six M1 fields as typed values for the real16 lane."""
    document = real16_public_domain(registers=INTERNAL_STATE_REGS, image_bits=16).to_document()
    assert document["schema"] == "dosunit.proof_domain.v1"
    assert document["architecture"] == Architecture.REAL16.value
    assert document["widths"] == {
        "operand_bits": 16,
        "storage_bits": 32,
        "address_model": AddressModel.SEGMENTED_REAL_MODE.value,
        "operand_override_bits": [32],
    }
    assert document["calling_convention"] == CallingConvention.NONE_MACHINE_STATE_PROJECTION.value
    assert document["return_kind"] == ReturnKind.MACHINE_STATE_PROJECTION.value
    assert document["observable"]["scope"] == ObservableScope.WHOLE_MODELED_STATE.value
    assert document["observable"]["memory"] == MemoryRelation.WHOLE_SEGMENTED_BYTE_ARRAY.value
    assert document["observable"]["flag_model"] == FlagModel.LAZY_FLAG_SUMMARIES.value
    assert document["observable"]["register_source"] == OutputDeclarationSource.LOWERING_CONTRACT.value
    assert "control_ip" in document["observable"]["registers"]
    assert document["environment"]["instruction_memory"] == InstructionMemory.IMMUTABLE.value
    assert document["environment"]["initial_data"] == InitialDataRelation.SHARED_UNCONSTRAINED.value


def test_real16_register_inventory_parity() -> None:
    """The published projection must be exactly the compared tuple — no drift."""
    document = real16_public_domain(registers=INTERNAL_STATE_REGS).to_document()
    assert document["observable"]["registers"] == list(INTERNAL_STATE_REGS)
    assert len(INTERNAL_STATE_REGS) == len(set(INTERNAL_STATE_REGS))


def test_flat32_domain_identifies_every_m1_field() -> None:
    """Publish all six M1 fields as typed values for the flat32 lane."""
    document = _flat32(image_bits=32).to_document()
    assert document["architecture"] == Architecture.FLAT32.value
    assert document["widths"] == {
        "operand_bits": 32,
        "storage_bits": 32,
        "address_model": AddressModel.FLAT.value,
        "operand_override_bits": [],
    }
    assert document["observable"]["registers"] == ["eax", "esp"]
    assert document["observable"]["register_source"] == CALLER.value
    assert document["observable"]["scope"] == ObservableScope.DECLARED_OUTPUTS.value
    assert document["observable"]["memory"] == MemoryRelation.WHOLE_FLAT_BYTE_ARRAY.value
    assert document["observable"]["flag_model"] == FlagModel.LAZY_FLAG_SUMMARIES.value


def test_flat32_projection_does_not_claim_whole_machine_state() -> None:
    """flat32 omits caller-clobbered ecx and cc_* storage from the exit set."""
    domain = _flat32()
    assert domain.observable.scope is ObservableScope.DECLARED_OUTPUTS
    assert domain.calling_convention is CallingConvention.NONE_MACHINE_STATE_PROJECTION


@pytest.mark.parametrize("build", [lambda: real16_public_domain(registers=INTERNAL_STATE_REGS), _flat32])
def test_outcome_inventory_is_closed_and_honest(build: Callable[[], MachineProofDomain]) -> None:
    """Cover every outcome kind; keep not-established scope out of refused."""
    document = build().to_document()
    assert sorted(item["kind"] for item in document["outcomes"]) == sorted(
        kind.value for kind in OutcomeKind
    )
    assert _outcome(document, "normal_return")["admission"] == OutcomeAdmission.COMPARED.value
    # Unaudited whole-function nonreturning admission is explicit scope, not a
    # claimed refusal gate.
    nonreturning = _outcome(document, "nonreturning")
    assert nonreturning["admission"] == OutcomeAdmission.NOT_ESTABLISHED.value
    assert nonreturning["basis"], "not_established outcomes must name verified and open scope"
    for kind in ("fault", "external_effect"):
        outcome = _outcome(document, kind)
        assert outcome["admission"] == OutcomeAdmission.REFUSED.value
        assert outcome["basis"], "refused outcomes must name the enforcing mechanism"


@pytest.mark.parametrize("build", [lambda: real16_public_domain(registers=INTERNAL_STATE_REGS), _flat32])
def test_document_invents_no_language_abi(build: Callable[[], MachineProofDomain]) -> None:
    """The declared contract must not fabricate a source-level convention."""
    document = build().to_document()
    serialized = str(document).lower()
    for invented in ("cdecl", "stdcall", "pascal", "fastcall", "msc", "borland", "watcom"):
        assert invented not in serialized


def test_domain_documents_are_deterministic() -> None:
    """Same inputs serialize to the same document for both lanes."""
    assert real16_public_domain(registers=INTERNAL_STATE_REGS).to_document() == real16_public_domain(
        registers=INTERNAL_STATE_REGS
    ).to_document()
    assert _flat32().to_document() == _flat32().to_document()


def test_distinct_declared_outputs_change_the_sealed_document() -> None:
    """A narrower observable domain cannot share the sealed contract document."""
    wide = _flat32().to_document()
    narrow = flat32_public_domain(outputs=("eax",), register_source=CALLER).to_document()
    assert wide != narrow
    assert wide["observable"]["registers"] != narrow["observable"]["registers"]


def test_premise_is_serialized_into_the_domain() -> None:
    """Caller-declared premises change the sealed document."""
    premise = {"kind": "caller_supplied_entry_esp_domain", "interval": {"min": "0x1", "max": "0x2"}}
    with_premise = _flat32(premise=premise).to_document()
    without = _flat32().to_document()
    assert with_premise["environment"]["premise"] == [premise]
    assert without["environment"]["premise"] == []
    assert with_premise != without


def test_contradictory_image_width_refuses() -> None:
    """Width evidence contradicting the lane rejects the domain."""
    with pytest.raises(ValueError):
        real16_public_domain(registers=INTERNAL_STATE_REGS, image_bits=64)
    with pytest.raises(ValueError):
        _flat32(image_bits=16)
    with pytest.raises(ValueError):
        common_image_bits({"oracle": {"width": 16}, "candidate": {"width": 32}})


def test_real16_loaded_address_carrier_does_not_change_operand_mode() -> None:
    """Loaded real16 addresses use 32-bit transport without changing decoding."""
    domain = real16_public_domain(registers=INTERNAL_STATE_REGS, image_bits=32)
    assert domain.widths.operand_bits == 16
    assert domain.widths.storage_bits == 32
    assert domain.widths.address_model is AddressModel.SEGMENTED_REAL_MODE


def test_common_image_bits() -> None:
    """Report the shared image width or None when unreported."""
    assert common_image_bits({"oracle": {"width": 16}, "candidate": {"width": 16}}) == 16
    assert common_image_bits({"oracle": {}, "candidate": {"width": 32}}) == 32
    assert common_image_bits({}) is None
    assert common_image_bits({"oracle": {"width": "16"}}) is None


def test_outcome_contract_requires_basis() -> None:
    """An outcome admission without an enforcement basis rejects."""
    with pytest.raises(ValueError):
        OutcomeContract(OutcomeKind.FAULT, OutcomeAdmission.REFUSED, "")


def test_domain_requires_closed_outcome_inventory() -> None:
    """A missing outcome kind rejects the domain contract."""
    domain = real16_public_domain(registers=INTERNAL_STATE_REGS)
    incomplete = tuple(item for item in domain.outcomes if item.kind is not OutcomeKind.FAULT)
    with pytest.raises(ValueError):
        MachineProofDomain(
            architecture=domain.architecture,
            widths=domain.widths,
            calling_convention=domain.calling_convention,
            return_kind=domain.return_kind,
            outcomes=incomplete,
            observable=domain.observable,
            environment=domain.environment,
        )


@pytest.mark.parametrize(
    "value",
    [
        (),
        ("",),
        (" eax",),
        ("eax ",),
        ("eax", "eax"),
        (1,),
        (None,),
        "eax,esp",
        {"eax": True},
    ],
)
def test_declared_output_regs_rejects_malformed(value: object) -> None:
    """Arbitrary backend values are never coerced into register names."""
    with pytest.raises(ValueError):
        declared_output_regs(value, source="test")
    with pytest.raises(ValueError):
        flat32_public_domain(outputs=value, register_source=CALLER)


def test_declared_output_regs_accepts_clean_sequence() -> None:
    """A valid declaration returns the exact register tuple."""
    assert declared_output_regs(["eax", "esp"], source="test") == ("eax", "esp")


def test_flat32_declared_outputs_backend_wins() -> None:
    """A backend-declared projection beats the caller's CLI list."""
    names, source = flat32_declared_outputs({"outputs": ["eax", "ebx"]}, "eax,esp")
    assert names == ("eax", "ebx")
    assert source is BACKEND


def test_flat32_declared_outputs_accepts_either_raw_key() -> None:
    """The leaf-mode ``output_regs`` key resolves like ``outputs``."""
    names, source = flat32_declared_outputs({"output_regs": ["eip"]}, "eax")
    assert names == ("eip",)
    assert source is BACKEND


def test_flat32_declared_outputs_accepts_agreeing_keys() -> None:
    """Both raw keys are consistent when they declare the same set."""
    names, source = flat32_declared_outputs({"outputs": ["eax"], "output_regs": ["eax"]}, "esp")
    assert names == ("eax",)
    assert source is BACKEND


def test_flat32_declared_outputs_rejects_contradictory_keys() -> None:
    """Disagreeing backend keys are contradictory evidence, not a choice."""
    with pytest.raises(ValueError):
        flat32_declared_outputs({"outputs": ["eax"], "output_regs": ["eax", "ecx"]}, "esp")


@pytest.mark.parametrize(
    "contract",
    [
        {"outputs": []},
        {"outputs": ()},
        {"outputs": None},
        {"outputs": "eax,esp"},
        {"outputs": ["eax", " eax"]},
        {"outputs": [1]},
        {"output_regs": {}},
        {"output_regs": ["ecx"], "outputs": ["ecx", "edx"]},
        "not-a-mapping",
        42,
    ],
)
def test_flat32_declared_outputs_rejects_malformed_backend(contract: object) -> None:
    """A supplied backend field never falls back to the caller's list."""
    with pytest.raises(ValueError):
        flat32_declared_outputs(contract, "eax,esp")


def test_flat32_declared_outputs_cli_fallback_is_caller_sourced() -> None:
    """Omitted backend fields report the CLI declaration as their source."""
    names, source = flat32_declared_outputs({}, "eax,esp")
    assert names == ("eax", "esp")
    assert source is CALLER
    names, source = flat32_declared_outputs(None, "eax,esp")
    assert names == ("eax", "esp")
    assert source is CALLER


def test_flat32_declared_outputs_rejects_malformed_caller_declaration() -> None:
    """An empty or malformed CLI declaration refuses as well."""
    with pytest.raises(ValueError):
        flat32_declared_outputs({}, "")
    with pytest.raises(ValueError):
        flat32_declared_outputs({}, None)
    with pytest.raises(ValueError):
        flat32_declared_outputs({}, "eax,,esp")
    with pytest.raises(ValueError):
        flat32_declared_outputs({}, "eax, esp")


def test_flat32_domain_requires_its_declaration_source() -> None:
    """The flat32 projection cannot claim the real16 lowering contract."""
    with pytest.raises(ValueError):
        flat32_public_domain(outputs=("eax",), register_source=OutputDeclarationSource.LOWERING_CONTRACT)


def test_real16_domain_rejects_malformed_register_projection() -> None:
    """The compared register tuple is validated like any declaration."""
    with pytest.raises(ValueError):
        real16_public_domain(registers=())
    with pytest.raises(ValueError):
        real16_public_domain(registers=("ax", 7))

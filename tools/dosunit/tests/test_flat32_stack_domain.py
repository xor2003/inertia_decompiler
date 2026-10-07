"""Regression evidence for the caller-declared flat32 entry-ESP proof domain.

Real i386 bytes are lifted through pyvex/angr and compared with real Z3.
The declared premise is an unsigned interval on the TOP-LEVEL caller entry
``esp`` only: proofs that rely on it must publish ``conditional`` with the
exact interval serialized, proofs without it keep their honest verdicts, and
a nested callee never receives the root interval as its own frame interval.
The contextual retry substitutes nested state into root coordinates first.
"""

import sys
from pathlib import Path
from typing import Any

import angr
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "artifacts" / "msc8-z3cmp32"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from flat32_adapter import GPRS, installed

from tools.dosunit.compare.flat32_call_composition import (
    compare_functions_with_calls,
    summarize_with_calls,
)
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain

BASE = 0x100000
OTHER_BASE = 0x200000
OUTPUTS = GPRS

STACK_LO = 0x0007F000
STACK_HI = 0x00080000
DOMAIN = Flat32ProofDomain(STACK_LO, STACK_HI)
DOMAIN_CONSTRAINTS = [
    {"name": "esp", "kind": "unsigned_range", "min": STACK_LO, "max": STACK_HI}
]

# caller: mov eax,[esp+4]; call 0x0d; add eax,2; ret   (13 bytes, call ends 0x09)
CALLER = "8b442404 e804000000 83c002 c3"
# baseline callee: add eax,5; ret    (4 bytes, no stores)
CODE = f"{CALLER} 83c005 c3"
LEAF_FUNCTIONS = {BASE: 0x0D, BASE + 0x0D: 4}

# callee storing one concrete global dword below the declared stack window:
#   mov dword [0x5000], 0x2a; ret    (11 bytes)
# The return slot spans [STACK_LO-4, STACK_HI-4]; 0x5000 is disjoint, so the
# return proof is provable only under the declared premise.
STORE_VALUE = "2a000000"
STORE_CALLEE = f"c70500500000{STORE_VALUE} c3"
STORE_CODE = f"{CALLER} {STORE_CALLEE}"
STORE_FUNCTIONS = {BASE: 0x0D, BASE + 0x0D: 11}


def _project(code: str, base: int = BASE) -> angr.Project:
    """Load real i386 bytes as a flat shellcode project."""
    return angr.load_shellcode(bytes.fromhex(code.replace(" ", "")), arch="x86", load_address=base)


def _compare(
    oracle_code: str,
    candidate_code: str,
    *,
    oracle_functions: dict[int, int],
    candidate_functions: dict[int, int],
    oracle_base: int = BASE,
    candidate_base: int = BASE,
    entry_domain: Flat32ProofDomain | None = None,
    candidate_normalization: dict[int, int] | None = None,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    """Compare two composed call regions under the installed flat32 seams."""
    with installed(region=True):
        return compare_functions_with_calls(
            _project(oracle_code, oracle_base),
            _project(candidate_code, candidate_base),
            oracle_entry=oracle_base,
            candidate_entry=candidate_base,
            oracle_functions=oracle_functions,
            candidate_functions=candidate_functions,
            outputs=OUTPUTS,
            timeout_ms=timeout_ms,
            entry_domain=entry_domain,
            candidate_normalization=candidate_normalization,
        )


def _same_store_compare(
    *, entry_domain: Flat32ProofDomain | None = None
) -> dict[str, Any]:
    """Compare the global-store fixture against itself."""
    return _compare(
        STORE_CODE,
        STORE_CODE,
        oracle_functions=STORE_FUNCTIONS,
        candidate_functions=STORE_FUNCTIONS,
        entry_domain=entry_domain,
    )


def test_no_store_call_stays_unconditional_without_premise() -> None:
    """A callee with no stores proves with no premise and no assumption."""
    result = _compare(
        CODE, CODE, oracle_functions=LEAF_FUNCTIONS, candidate_functions=LEAF_FUNCTIONS
    )
    assert result["status"] == "passed"
    assert "assumptions" not in result
    assert "entry_domain_assumptions" not in result


def test_concrete_global_store_refuses_without_premise() -> None:
    """Without a declared domain the aliasing return-slot proof still refuses."""
    result = _same_store_compare()
    assert result["status"] == "refused"
    assert result["reason"].startswith("call_return_target")
    failure = result["return_proof_failure"]
    assert failure["side"] == "oracle"
    assert "input_constraints" not in failure["solver_result"]


def test_concrete_global_store_is_conditional_under_declared_domain() -> None:
    """A disjoint global store proves only under the caller-declared premise."""
    result = _same_store_compare(entry_domain=DOMAIN)
    assert result["status"] == "conditional"
    assert result["reason"] == "unproved_entry_esp_domain"
    assert result["return_targets_proved"] == 2
    assert result["oracle_inlined_calls"] == 1
    assert result["candidate_inlined_calls"] == 1
    assumptions = result["assumptions"]
    assert assumptions["kind"] == "caller_supplied_entry_esp_domain"
    assert assumptions["proved"] is False
    assert assumptions["provenance"] == "caller_supplied_domain"
    assert assumptions["input"] == "esp"
    assert assumptions["interval"] == {"min": hex(STACK_LO), "max": hex(STACK_HI)}
    assert result["entry_domain_assumptions"] == assumptions
    assert result["input_constraints"] == DOMAIN_CONSTRAINTS
    for side in ("oracle", "candidate"):
        assert result["call_sites"][side][0]["proved_under_entry_domain"] is True


def test_declared_premise_labels_even_unused_proofs_conditional() -> None:
    """A no-store call proved under a declared premise is still conditional."""
    result = _compare(
        CODE,
        CODE,
        oracle_functions=LEAF_FUNCTIONS,
        candidate_functions=LEAF_FUNCTIONS,
        entry_domain=DOMAIN,
    )
    assert result["status"] == "conditional"
    assert result["reason"] == "unproved_entry_esp_domain"


def test_overlapping_window_and_slot_overwrite_stay_refused() -> None:
    """A premise covering the store, or a store into the slot, never proves."""
    overlapping = _same_store_compare(entry_domain=Flat32ProofDomain(0x4000, 0x9000))
    assert overlapping["status"] == "refused"
    assert overlapping["reason"].startswith("call_return_target")

    # mov dword [esp], 0x2a; ret — the callee corrupts its own return slot.
    slot_corrupt = "c70424 2a000000 c3"
    code = f"{CALLER} {slot_corrupt}"
    functions = {BASE: 0x0D, BASE + 0x0D: 8}
    result = _compare(
        code,
        code,
        oracle_functions=functions,
        candidate_functions=functions,
        entry_domain=DOMAIN,
    )
    assert result["status"] == "refused"
    assert result["reason"] == "call_return_target_mismatch"
    failure = result["return_proof_failure"]
    assert failure["solver_result"]["input_constraints"] == DOMAIN_CONSTRAINTS


def test_unconstrained_pointer_store_still_refuses_under_domain() -> None:
    """A store through a free loaded pointer can alias the slot: refused."""
    callee = "c700 2a000000 c3"  # mov dword [eax], 0x2a; ret   (7 bytes)
    code = f"{CALLER} {callee}"
    functions = {BASE: 0x0D, BASE + 0x0D: 7}
    result = _compare(
        code,
        code,
        oracle_functions=functions,
        candidate_functions=functions,
        entry_domain=DOMAIN,
    )
    assert result["status"] == "refused"
    assert result["reason"].startswith("call_return_target")


def test_changed_observable_still_fails_under_domain() -> None:
    """A different stored global value remains a real mismatch, not a pass."""
    changed = f"{CALLER} c70500500000 2b000000 c3"
    result = _compare(
        STORE_CODE,
        changed,
        oracle_functions=STORE_FUNCTIONS,
        candidate_functions=STORE_FUNCTIONS,
        entry_domain=DOMAIN,
    )
    assert result["status"] == "failed"


def test_invalid_or_empty_domain_cannot_produce_vacuous_proof() -> None:
    """Non-integer, Boolean, out-of-word and empty intervals are rejected."""
    for bounds in (
        (5, 4),  # empty interval
        (-1, 5),  # below uint32
        (0, 0x100000000),  # above uint32
        (True, 5),  # bool masquerading as integer
        (0, False),  # bool masquerading as integer
        ("0x10", 0x20),  # string bound
        (0.0, 4.0),  # float bound
    ):
        with pytest.raises(ValueError):
            Flat32ProofDomain(bounds[0], bounds[1])  # type: ignore[arg-type]
    # A non-domain object is a refused input, never a vacuous pass.
    result = _same_store_compare(entry_domain=0x1234)  # type: ignore[arg-type]
    assert result["status"] == "refused"
    assert result["reason"] == "invalid_entry_domain"


def test_normalization_and_domain_assumptions_coexist() -> None:
    """Both caller-supplied premises stay serialized on one conditional."""
    moved_functions = {OTHER_BASE: 0x0D, OTHER_BASE + 0x0D: 11}
    result = _compare(
        STORE_CODE,
        STORE_CODE,
        oracle_functions=STORE_FUNCTIONS,
        candidate_functions=moved_functions,
        candidate_base=OTHER_BASE,
        entry_domain=DOMAIN,
        candidate_normalization={OTHER_BASE + 0x09: BASE + 0x09},
    )
    assert result["status"] == "conditional"
    assert result["reason"] == "unproved_constant_normalization+unproved_entry_esp_domain"
    assert result["normalization_assumptions"]["kind"] == "caller_supplied_constant_relocation"
    assert result["entry_domain_assumptions"]["kind"] == "caller_supplied_entry_esp_domain"
    assumptions = result["assumptions"]
    assert assumptions["unproved_constant_normalization"]["proved"] is False
    assert assumptions["unproved_entry_esp_domain"]["interval"] == {
        "min": hex(STACK_LO),
        "max": hex(STACK_HI),
    }


def test_nested_callee_store_rejects_repeated_interval_transport() -> None:
    """The root interval must never be re-asserted on a nested callee frame.

    root calls F, F calls G, and G stores to ``STACK_LO - 8``.  If the same
    interval were wrongly applied to the nested caller's entry ``esp`` input
    the proof would pass (slot range ``[LO-4, HI-4]`` excludes the store), but
    soundly ``esp_F = esp_root - 4`` gives slots in ``[LO-8, HI-8]`` where
    ``esp_root = LO`` aliases the store — the honest verdict stays refused.
    """
    # root: call +6; ret            (6 bytes; callsite 0x00, fallthrough 0x05)
    # F:    call +0xC; ret          (6 bytes; callsite 0x06, fallthrough 0x0B)
    # G:    mov dword [0x7EFF8],0x2a; ret   (11 bytes)
    nested = "e801000000 c3 e801000000 c3 c705f8ef0700 2a000000 c3"
    functions = {BASE: 6, BASE + 6: 6, BASE + 0x0C: 11}
    for domain in (None, DOMAIN):
        result = _compare(
            nested,
            nested,
            oracle_functions=functions,
            candidate_functions=functions,
            entry_domain=domain,
        )
        assert result["status"] == "refused"
        assert result["reason"].startswith("call_return_target")
        failure = result["return_proof_failure"]
        assert failure["callsite"] == hex(BASE + 6)
        # The retry substitutes every frame into ROOT coordinates. The actual
        # root premise still admits the alias; it must not be shifted onto F.
        if domain is None:
            assert "input_constraints" not in failure["solver_result"]
        else:
            assert failure["solver_result"]["input_constraints"] == DOMAIN_CONSTRAINTS


def test_summarize_retains_declared_constraints_and_assumptions() -> None:
    """A summary produced under a premise is always labelled as assumed."""
    with installed(region=True):
        summary = summarize_with_calls(
            _project(STORE_CODE),
            entry=BASE,
            functions=STORE_FUNCTIONS,
            outputs=OUTPUTS,
            entry_domain=DOMAIN,
        )
    assert summary["inlined_calls"] == 1
    assert summary["input_constraints"] == DOMAIN_CONSTRAINTS
    assumptions = summary["entry_domain_assumptions"]
    assert assumptions["kind"] == "caller_supplied_entry_esp_domain"
    assert assumptions["proved"] is False
    assert assumptions["interval"] == {"min": hex(STACK_LO), "max": hex(STACK_HI)}
    assert summary["call_sites"][0]["proved_under_entry_domain"] is True

    with installed(region=True):
        plain = summarize_with_calls(
            _project(CODE),
            entry=BASE,
            functions=LEAF_FUNCTIONS,
            outputs=OUTPUTS,
        )
    assert "input_constraints" not in plain
    assert "entry_domain_assumptions" not in plain

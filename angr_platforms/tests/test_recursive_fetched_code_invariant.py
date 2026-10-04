"""Actual fetched-code initialization and preservation must both be complete."""
from __future__ import annotations

from dataclasses import replace

import pytest
from recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import bind_real16_mz
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import prove_real16_code_prefixes
from tools.dosunit.recursive_proofs.real16_fetched_code_invariant import (
    FetchedCodeReason,
    check_fetched_code_invariant,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import prove_image_bound_real16_domain


@pytest.fixture(scope="module")
def code_inputs(tmp_path_factory: pytest.TempPathFactory):
    inputs = make_inputs(tmp_path_factory.mktemp("fetched-code"))
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    prefixes = prove_real16_code_prefixes(receipt, *inputs)
    assert prefixes.status is ProofStatus.PROVED, prefixes
    return inputs, prefixes


def test_absolute_code_bytes_and_all_prefixes_close_local_invariant(code_inputs) -> None:
    """The theorem is local modeled code stability and grants no binary verdict."""
    inputs, prefixes = code_inputs
    result = check_fetched_code_invariant(prefixes, *inputs)
    assert result.complete and result.status is ProofStatus.PROVED, result
    assert result.reason is FetchedCodeReason.PRESERVED
    assert len(result.domains) == 2
    assert all(domain.spans for domain in result.domains)
    assert result.counters.failure_count == 0 and not result.binary_equivalence_proved
    assert len(result.facts) == len(result.required)


@pytest.mark.parametrize("corruption", ["blocks", "ranges", "proposal", "model", "counters", "producer", "domain"])
def test_stale_or_narrower_prefix_receipt_cannot_close_code_memory(code_inputs, corruption) -> None:
    """Actual proofs cannot transfer to missing spans or different content/models."""
    inputs, prefixes = code_inputs
    if corruption == "blocks":
        prefixes = replace(prefixes, blocks=prefixes.blocks[:-1])
    elif corruption == "ranges":
        block = prefixes.blocks[0]
        prefixes = replace(prefixes, blocks=(replace(block, protected_ranges=block.protected_ranges[:-1]),
                                             *prefixes.blocks[1:]))
    elif corruption == "proposal":
        prefixes = replace(prefixes, proposal_hash="0" * 64)
    elif corruption == "model":
        prefixes = replace(prefixes, model_hash="0" * 64)
    elif corruption == "producer":
        prefixes = replace(prefixes, receipt=None)
    elif corruption == "domain":
        assert prefixes.receipt is not None and prefixes.receipt.domain is not None
        domain = prefixes.receipt.domain
        changed = replace(domain, domain=replace(domain.domain, alignment=4))
        prefixes = replace(prefixes, receipt=replace(prefixes.receipt, domain=changed))
    else:
        prefixes = replace(prefixes, counters=replace(prefixes.counters, failure_count=1))
    result = check_fetched_code_invariant(prefixes, *inputs)
    assert result.status is ProofStatus.UNKNOWN and not result.complete, result
    assert result.reason in {FetchedCodeReason.SOURCE, FetchedCodeReason.MODEL}
    assert result.counters.failure_count > 0
    assert len(result.required) == 11 + sum(len(rows) for rows in inputs.requests)


def test_expired_original_budget_keeps_full_fetched_denominator(code_inputs) -> None:
    inputs, prefixes = code_inputs
    result = check_fetched_code_invariant(prefixes, *inputs, timeout_ms=0)
    assert result.reason is FetchedCodeReason.DEADLINE and result.status is ProofStatus.UNKNOWN
    assert result.counters.failure_count == len(result.required)


def test_changed_loader_header_cannot_borrow_identical_loaded_code(code_inputs) -> None:
    """Same fetched bytes cannot transfer a scalar-domain-conditioned theorem."""
    inputs, prefixes = code_inputs
    original, candidate = inputs.loads
    changed_file = bytearray(original.file_bytes)
    old_sp = int.from_bytes(changed_file[0x10:0x12], "little")
    changed_file[0x10:0x12] = (old_sp ^ 2).to_bytes(2, "little")
    changed = bind_real16_mz(bytes(changed_file), load_segment=original.image.load_segment)
    assert changed.binding.snapshot == original.binding.snapshot
    assert changed.binding.file_sha256 != original.binding.file_sha256
    assert changed.binding.entry_registers != original.binding.entry_registers
    result = check_fetched_code_invariant(prefixes, inputs.system, (changed, candidate),
        inputs.initialized, inputs.bootstrap, inputs.requests)
    assert result.status is ProofStatus.UNKNOWN and result.reason is FetchedCodeReason.SOURCE, result
    assert not result.complete and result.counters.failure_count > 0


def test_malformed_prefix_side_refuses_before_manifest_indexing(code_inputs) -> None:
    """Invalid source-side metadata is a counted refusal, not an indexing crash."""
    inputs, prefixes = code_inputs
    first = replace(prefixes.blocks[0], side=2)
    malformed = replace(prefixes, blocks=(first, *prefixes.blocks[1:]))
    result = check_fetched_code_invariant(malformed, *inputs)
    assert result.reason is FetchedCodeReason.SOURCE and result.status is ProofStatus.UNKNOWN, result
    assert not result.complete and result.counters.failure_count == len(result.required)


def test_missing_absolute_seed_is_a_countermodel(code_inputs, monkeypatch: pytest.MonkeyPatch) -> None:
    """Dropping initialization cannot be hidden by valid code-preservation proofs."""
    inputs, prefixes = code_inputs
    from tools.dosunit.recursive_proofs import real16_fetched_code_invariant as owner

    def unseeded(snapshot, background, limits):
        return background
    monkeypatch.setattr(owner, "seed_loaded_array", unseeded)
    result = check_fetched_code_invariant(prefixes, *inputs)
    assert result.status is ProofStatus.COUNTEREXAMPLE and result.reason is FetchedCodeReason.COUNTERMODEL, result
    assert not result.complete and result.counters.failure_count

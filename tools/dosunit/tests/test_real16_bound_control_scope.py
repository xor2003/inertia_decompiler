"""Source-bound control proofs require the current complete invocation."""
from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

from tools.dosunit.tests.recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits
from tools.dosunit.recursive_proofs.real16_bound_control_scope import (
    BoundControlReason,
    prove_bound_real16_control_scope,
)
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import prove_real16_code_prefixes
from tools.dosunit.recursive_proofs.real16_image_bound_domain import prove_image_bound_real16_domain


def test_bound_control_requires_complete_current_manifest(tmp_path: Path) -> None:
    """A source theorem cannot transfer to changed registers, manifests or models."""
    inputs = make_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    source = prove_real16_code_prefixes(receipt, *inputs)
    assert source.status is ProofStatus.PROVED, source
    limits = LoadedRelationLimits(deadline=time.monotonic() + 60)
    positive = prove_bound_real16_control_scope(source, *inputs, limits=limits)
    assert positive.complete, positive
    assert len(positive.blocks) == sum(len(rows) for rows in inputs.requests)
    assert not positive.binary_equivalence_proved
    for corrupted in (replace(source, blocks=source.blocks[:-1]),
                      replace(source, model_hash="0" * 64),
                      replace(source, receipt=None)):
        refused = prove_bound_real16_control_scope(corrupted, *inputs, limits=limits)
        assert refused.status is ProofStatus.UNKNOWN and not refused.complete
        assert not refused.blocks and refused.counters.failure_count > 0
    missing = (inputs.requests[0][:-1], inputs.requests[1])
    refused = prove_bound_real16_control_scope(source, *inputs[:-1], missing, limits=limits)
    assert refused.status is ProofStatus.UNKNOWN and not refused.blocks
    expired = prove_bound_real16_control_scope(source, *inputs,
        limits=LoadedRelationLimits(deadline=time.monotonic() - 1))
    assert expired.reason is BoundControlReason.DEADLINE and not expired.complete
    assert not expired.blocks and expired.counters.materialized_count == 0

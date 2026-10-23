"""Detached replay snapshots must not alias mutable theorem payloads."""

import pytest

from inertia.ir import near_call_preservation as owner
from tests.ir.test_near_call_preservation import _consume, _prove_step, _surface

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("payload", ["stats", "shape"])
def test_in_place_theorem_payload_drift_refuses(monkeypatch, payload):
    """Mutation of a retained payload object cannot rewrite its snapshot."""
    surface = _surface()
    step = _prove_step(surface)
    theorem = step.theorem
    original = owner._callee_chain_failure_8616
    fired = False

    def mutate_after_callee(*args, **kwargs):
        nonlocal fired
        result = original(*args, **kwargs)
        if not fired:
            fired = True
            if payload == "stats":
                object.__setattr__(theorem.stats, "raw_fact_count", 2)
            else:
                object.__setattr__(theorem.shape, "control_bits", 16)
        return result

    monkeypatch.setattr(owner, "_callee_chain_failure_8616", mutate_after_callee)
    assert not _consume(surface, step)
    assert fired

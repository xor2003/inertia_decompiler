"""Public report schema must retain the component's restricted domain."""

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/dosunit/schemas/dosunit.binary16_compare.v1.schema.json"
SCHEMA = json.loads(SOURCE.read_text())


def report():
    """Small public document; no symbolic proof claim follows from validation."""
    return {"schema": "dosunit.binary16_compare.v1", "status": "unknown", "requested_functions": ["member"], "inputs": {"oracle": {}, "candidate": {}}, "provenance": {"oracle": {}, "candidate": {}}, "input_domain": {}, "backend": {}, "proof": {"schema": "test", "contract": {}, "status": "unknown", "verdicts": []}}


@pytest.mark.parametrize("component", [None, {"schema": "dosunit.binary16_compare.recursive_joint.v1", "attempted": False, "status": "unknown", "reason": "run_not_fresh_or_aborted"}])
def test_absent_or_unattempted_is_valid(component):
    value = report()
    value["recursive_joint"] = component
    jsonschema.validate(value, SCHEMA)


@pytest.mark.parametrize("component", [
    {"schema": "dosunit.binary16_compare.recursive_joint.v1", "attempted": False, "status": "conditional", "reason": "fake"},
    {"schema": "dosunit.binary16_compare.recursive_joint.v1", "attempted": True, "status": "conditional", "reason": "fake", "domain_scope": None},
])
def test_unbound_conditional_is_rejected(component):
    value = deepcopy(report())
    value["recursive_joint"] = component
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(value, SCHEMA)


def conditional_component():
    """Use the real serializer rather than inventing a parallel schema shape."""
    from tools.dosunit.proof_contracts import ProofStatus
    from tools.dosunit.real16_recursive_compare import RecursiveCompareOutcome, RecursiveDomainScope
    from tools.dosunit.recursive_proofs.real16_entry_domain import Real16ScalarDomain
    from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason

    scope = RecursiveDomainScope("a" * 64, "b" * 64, (0x10000, 0x10000), 0x10200,
                                 Real16ScalarDomain(0x7000, 0x1000), ("snap-a", "snap-b"),
                                 "domain-model", "scalar-model", "proposal")
    return RecursiveCompareOutcome(attempted=True, status=ProofStatus.CONDITIONAL,
        reason=JointReason.CONDITIONAL_MODEL, member_ids=("member",), domain_scope=scope,
        assumptions=("initialized_entry_only",), root="member", proposal_hash="proposal",
        model_hash="model").to_document()


def test_real_serialized_domain_is_valid():
    value = report()
    value["recursive_joint"] = conditional_component()
    jsonschema.validate(value, SCHEMA)


@pytest.mark.parametrize("field", ["original_sha256", "snapshot_hashes", "domain_model_hash", "scalar_model_hash", "proposal_hash", "arbitrary_entry_states_proved"])
def test_conditional_domain_cannot_lose_identity(field):
    value = report()
    value["recursive_joint"] = conditional_component()
    del value["recursive_joint"]["domain_scope"][field]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(value, SCHEMA)

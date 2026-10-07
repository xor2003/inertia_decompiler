"""Parent controls for complete PE32 recursive selection accounting."""
import json
from pathlib import Path
from types import ModuleType

import pytest
from jsonschema import Draft202012Validator, ValidationError

import tools.dosunit.compare.pe32_recursive_compare as pe32_recursive_compare


@pytest.fixture(scope="module")
def adapter() -> ModuleType:
    """Use the ordinary production adapter import for report regressions."""
    return pe32_recursive_compare


@pytest.mark.parametrize("timeout_ms", [0, 180000], ids=["deadline", "load"])
def test_paired_selection_survives_early_refusal(adapter: ModuleType, timeout_ms: int) -> None:
    """A refused component still accounts for each valid selected declaration."""
    request = adapter.Pe32RecursiveRequest(
        adapter.Flat32AccessDomain(0x402000, 0x403000, 0x402800, 0x402F00, 64),
        timeout_ms=timeout_ms,
    )
    outcome = adapter.prove_pe32_recursive_compare(
        oracle_exe=Path("/nonexistent-oracle.exe"),
        candidate_exe=Path("/nonexistent-candidate.exe"),
        oracle_functions={"f": (0x401000, 16)},
        candidate_functions={"f": (0x401000, 16)},
        request=request,
        unresolved_names=("missing",),
    )
    assert outcome.status is adapter.ProofStatus.UNKNOWN
    document = outcome.to_document()
    names = [row["name"] for row in document["selected"] + document["attempts"]]
    assert sorted(names) == ["f", "missing"]


@pytest.mark.parametrize("entry,size", [(-1, 16), (0x401000, 0), (0xFFFFFFFF, 2)])
def test_invalid_range_is_a_counted_refusal(adapter: ModuleType, entry: int, size: int) -> None:
    """Invalid coordinates cannot become selected rows or escape as exceptions."""
    request = adapter.Pe32RecursiveRequest(
        adapter.Flat32AccessDomain(0x402000, 0x403000, 0x402800, 0x402F00, 64),
    )
    outcome = adapter.prove_pe32_recursive_compare(
        oracle_exe=Path("/nonexistent-oracle.exe"),
        candidate_exe=Path("/nonexistent-candidate.exe"),
        oracle_functions={"f": (entry, size)},
        candidate_functions={"f": (entry, size)}, request=request,
    )
    assert outcome.status is adapter.ProofStatus.UNKNOWN
    assert [(row.name, row.reason) for row in outcome.attempts] == [
        ("f", adapter.Pe32RecursiveReason.DECLARATION),
    ]


def test_premise_cannot_be_reported_as_unconditional(adapter: ModuleType) -> None:
    """The owned report contract rejects an unconditional status with assumptions."""
    with pytest.raises(ValueError, match="cannot be unconditional"):
        adapter.Pe32RecursiveOutcome(
            attempted=True, status=adapter.ProofStatus.PROVED,
            reason=adapter.JointReason.DISCHARGED, assumptions=("declared_access_domain",),
        )


def test_recursive_schema_rejects_promotion_and_missing_accounting(adapter: ModuleType) -> None:
    """Unknown documents validate; missing selections and unsupported proof claims do not."""
    schema = json.loads((Path(__file__).resolve().parents[3] / "tools/dosunit/schemas/dosunit.pe32_compare.recursive_joint.v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    document = adapter.Pe32RecursiveOutcome(
        attempted=True, status=adapter.ProofStatus.UNKNOWN,
        reason=adapter.Pe32RecursiveReason.DEADLINE,
    ).to_document()
    validator.validate(document)
    for status in ("proved", "conditional"):
        with pytest.raises(ValidationError):
            validator.validate({**document, "status": status})
    del document["selected"]
    with pytest.raises(ValidationError):
        validator.validate(document)

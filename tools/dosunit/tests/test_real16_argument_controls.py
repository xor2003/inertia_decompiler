"""Layer: comparator regression controls.
Responsibility: expose actual-MZ stack value and pointer argument proof coverage.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function
from tools.dosunit.tests.test_real16_call_composition import _lower

from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.compare.real16_call_composition import compare_real16_with_calls

# Caller CALL sites/continuations are identical across each pair; differing
# callee encodings cannot change the saved return bytes by shifting the caller.
CASES = (
    ("stack_value", "52e82c0059c3", "5589e58b4604905dc3",
     "5589e58b8604005dc3", "5589e58b8606005dc3"),
    ("near_pointer", "52e82c0059c3", "5589e58b5e048b075dc3",
     "5589e58b5e048b47005dc3", "5589e58b5e048b47025dc3"),
    ("far_pointer", "0652e82b005959c3", "5589e5c45e04268b075dc3",
     "5589e5c49e0400268b075dc3", "5589e5c49e0400268b47025dc3"),
)


@pytest.mark.parametrize("name,caller_hex,oracle_hex,equivalent_hex,mutation_hex", CASES)
@pytest.mark.parametrize("mutation", [False, True], ids=["positive", "mutation"])
def test_stack_argument_consumption(
    tmp_path: Path, name: str, caller_hex: str, oracle_hex: str,
    equivalent_hex: str, mutation_hex: str, mutation: bool,
) -> None:
    """Compose full-state MZ bodies; positive must prove and corruption must not."""
    caller = bytes.fromhex(caller_hex)
    candidate_hex = mutation_hex if mutation else equivalent_hex
    documents = []
    for tag, code_hex in (("oracle", oracle_hex), ("candidate", candidate_hex)):
        callee = bytes.fromhex(code_hex)
        image = bytearray(0x300)
        image[0x200:0x200 + len(caller)] = caller
        image[0x230:0x230 + len(callee)] = callee
        catalog = [_edge_function("demo.exe:caller", "caller", offset=0x200, size=len(caller)),
                   _edge_function("demo.exe:callee", "callee", offset=0x230, size=len(callee))]
        documents.append(_lower(tmp_path, bytes(image), catalog, tag))
    result = compare_real16_with_calls(*documents, "demo.exe:caller", timeout_ms=20000)
    receipt = {"name": name, "mutation": mutation, "caller_hex": caller_hex,
               "oracle_callee_hex": oracle_hex, "candidate_callee_hex": candidate_hex,
               "solver_timeout_ms": 20000,
               "binary_sha256": {tag: hashlib.sha256((tmp_path / f"{tag}.exe").read_bytes()).hexdigest()
                                 for tag in ("oracle", "candidate")},
               "result": result}
    (tmp_path / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    verdict = proof_status_from_legacy(result["status"])
    assert result["calls"]["return_targets_proved"] == 2, result
    assert result["calls"]["cs_preserved_proved"] == 2, result
    assert result["skipped_layout_outputs"] == [], result
    if mutation:
        assert verdict is ProofStatus.COUNTEREXAMPLE, result
    else:
        assert verdict is ProofStatus.PROVED, result
        assert len(result["dependencies"]) == 2, result

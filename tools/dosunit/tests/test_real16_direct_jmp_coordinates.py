"""Full-width word JMP effects must agree with independent native execution."""
import pytest
import tools.dosunit.tests.test_real16_native_control_scope as native

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_call_contracts import prove_terms_equal


@pytest.mark.parametrize("vector", native.VECTORS, ids=lambda vector: vector.name)
@pytest.mark.parametrize("kind", (native.NearKind.JMP_REL8, native.NearKind.JMP_REL16))
def test_direct_jmp_preserves_selector_coordinate(vector: native.Vector, kind: native.NearKind) -> None:
    """Prove equality at low/high and wrapping coordinates; refusal cannot pass."""
    receipt = native._receipt(vector, kind)
    actual = native._native(receipt, kind)
    assert (actual.cs, actual.ip) == (vector.cs, vector.target_ip)
    state = native._lifted(receipt)
    expected = {"op": "const", "width": 32, "value": hex((actual.cs << 4) + actual.ip)}
    assert prove_terms_equal(state["control_ip"], expected, 3000) is ProofStatus.PROVED

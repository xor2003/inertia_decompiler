"""Prove the SetGear oracle rejects compile-valid semantic corruption."""

import pytest
from x86_16_setgear_behavior import assert_setgear_behavior

_REFERENCE = """
void _SetGear(unsigned short G) {
    if (ejected) return;
    if (G == 1) {
        if (!(Status & 1) || (short)Knots > 350) return;
        Status &= 254;
        Message(28678, 2);
    } else if (G == 0) {
        if ((Status & 1) || Alt == MinAlt || (Damaged & 4)) return;
        Status |= 1;
        Message(28686, 2);
    }
}
"""


def test_setgear_oracle_accepts_reference_decisions(tmp_path):
    assert_setgear_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("(short)Knots", "Knots"),
        ("if (ejected) return;", ""),
        ("Status &= 254;", "Status = 0;"),
        ("Message(28678, 2);", "Message(28678, 1);"),
        ("Status &= 254;\n        Message(28678, 2);", "Message(28678, 2);\n        Status &= 254;"),
    ],
    ids=["unsigned-speed", "lost-ejection-guard", "lost-other-flags", "wrong-message-kind", "call-before-store"],
)
def test_setgear_oracle_rejects_corrupted_decisions(tmp_path, original, replacement):
    assert original in _REFERENCE
    with pytest.raises(AssertionError, match="SetGear behavior failed"):
        assert_setgear_behavior(_REFERENCE.replace(original, replacement), tmp_path)

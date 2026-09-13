"""Verify the ReInitBars behavioral oracle accepts state and rejects corruption."""

from pathlib import Path

import pytest
from x86_16_reinitbars_execution import assert_reinitbars_loop_behavior

_BODY = """
void ReInitBars(void) {
    unsigned short saved_si = inertia_esi & 0xffff;
    unsigned short saved_di = inertia_edi & 0xffff;
    clStart = clock();
    for (unsigned short row = 0; row < cRow; ++row) {
        abarWork[row] = abarPerm[row];
        DrawBar(row);
    }
    inertia_esi = (inertia_esi & 0xffff0000) | saved_si;
    inertia_edi = (inertia_edi & 0xffff0000) | saved_di;
}
"""


def test_reinitbars_oracle_accepts_preserved_register_state(tmp_path: Path) -> None:
    """Legal architectural save/restore must compile and execute in the oracle."""
    assert_reinitbars_loop_behavior(_BODY, tmp_path)


@pytest.mark.parametrize(
    ("original", "corrupted"),
    [
        ("clStart = clock();", "(void)clock; clStart = 123;"),
        ("abarWork[row] = abarPerm[row];", "abarWork[row] = abarPerm[0];"),
        (
            "abarWork[row] = abarPerm[row];\n        DrawBar(row);",
            "DrawBar(row);\n        abarWork[row] = abarPerm[row];",
        ),
        ("| saved_si;", "| (saved_si ^ 1);"),
        ("(inertia_edi & 0xffff0000) | saved_di", "saved_di"),
    ],
    ids=["lost-clock", "wrong-copy", "draw-before-copy", "low-si", "high-edi"],
)
def test_reinitbars_oracle_rejects_executable_corruption(
    tmp_path: Path, original: str, corrupted: str,
) -> None:
    """Compile-valid corruptions must fail behavior, not merely compilation."""
    assert original in _BODY
    with pytest.raises(AssertionError, match="failed execution"):
        assert_reinitbars_loop_behavior(_BODY.replace(original, corrupted), tmp_path)

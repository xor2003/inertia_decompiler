"""Exercise every TID layout case and prove independent corruption detection."""

import pytest
from x86_16_tidshowrange_behavior import assert_tidshowrange_behavior

_REFERENCE = """
void _TIDShowRange(void) {
    static short RANGES[] = {200, 100, 50, 25, 10};
    char s[10];
    short l, mseg;
    RectFill(Rp2, 146, 21, 29, 9, 0);
    l = pstrlen(Rp2, itoa(RANGES[Tscale], s, 10));
    RpPrint(Rp2, 160-(l/2), 23, s);
    RectCopy(Rp2, 146, 21, 29, 9, Rp1, 146, 21);
    if ((mseg = MapInEMSSprite(2, 0))) {
        ScaleRotate(mseg, 2+23, 160+15, 46, 31, Rp2, 164+23, 164+15, 256, 0, 0, 0);
        switch (Tscale) {
        case 4: ScaleRotate(mseg, 54+9, 138+7, 18, 13, Rp2, 174+9, 177+7, 256, 0, 0, 0); break;
        case 3: ScaleRotate(mseg, 15+8, 136+9, 16, 18, Rp2, 177+8, 173+9, 256, 0, 0, 0); break;
        case 2: ScaleRotate(mseg, 2+5, 136+9, 9, 17, Rp2, 182+5, 173+9, 256, 0, 0, 0); break;
        case 1: ScaleRotate(mseg, 34+8, 136+9, 16, 18, Rp2, 178+8, 173+9, 256, 0, 0, 0); break;
        case 0: ScaleRotate(mseg, 77+10, 138+7, 20, 13, Rp2, 177+10, 176+7, 256, 0, 0, 0); break;
        }
        RectCopy(Rp2, 164, 164, 46, 31, Rp1, 164, 164);
    }
}
"""


def test_tidshowrange_oracle_accepts_source_behavior(tmp_path):
    assert_tidshowrange_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("switch (Tscale)", "switch (0)"),
        ("34+8", "34+9"),
        ("160-(l/2)", "160-((unsigned short)l/2)"),
        ("if ((mseg = MapInEMSSprite(2, 0)))", "if ((mseg = MapInEMSSprite(2, 0)) > 0)"),
        ("MapInEMSSprite(2, 0)", "MapInEMSSprite(2, 1)"),
        ("pstrlen(Rp2,", "pstrlen(Rp1,"),
        ("RectCopy(Rp2, 164, 164, 46, 31, Rp1, 164, 164);", ""),
        ("pstrlen(Rp2, itoa(RANGES[Tscale], s, 10))",
         "(itoa(RANGES[Tscale], s, 10), pstrlen(Rp2, s+1))"),
        ("RectCopy(Rp2, 164, 164, 46, 31, Rp1, 164, 164);",
         "RectCopy(Rp2, 164, 164, 46, 31, Rp1, 164, 164); RectCopy(Rp2, 164, 164, 46, 31, Rp1, 164, 164);"),
    ],
    ids=["constant-switch", "wrong-case-argument", "unsigned-width", "lost-high-segment",
         "wrong-mapping", "wrong-text-surface", "lost-final-copy", "lost-return-pointer", "duplicated-copy"],
)
def test_tidshowrange_oracle_rejects_compile_valid_corruption(tmp_path, original, replacement):
    assert original in _REFERENCE
    with pytest.raises(AssertionError, match="TIDShowRange behavior failed"):
        assert_tidshowrange_behavior(_REFERENCE.replace(original, replacement), tmp_path)

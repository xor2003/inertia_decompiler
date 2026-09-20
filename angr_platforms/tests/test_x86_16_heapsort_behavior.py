"""Mutation-check the source-oriented HeapSort call oracle."""

from pathlib import Path

import pytest
from x86_16_heapsort_behavior import assert_heapsort_behavior

_SOURCE = """
typedef struct g_08F0_entry { char field_0, field_1; } g_08F0_entry;
extern unsigned short g_0BA2;
extern g_08F0_entry g_0B4C[];
void sub_109e8(unsigned short);
void sub_107b8(g_08F0_entry *, g_08F0_entry *);
void sub_10768(unsigned short, unsigned short);
void sub_10a88(unsigned short);
void sub_10970(void) {
    unsigned short i;
    for (i = 1; g_0BA2 > (short)i; i += 1) { sub_109e8(i); }
    for (i = g_0BA2 - 1; (short)i > 0; i -= 1) {
        sub_107b8(&g_0B4C[0], &g_0B4C[(unsigned short)i]);
        sub_10768(0, i);
        sub_10a88(i - 1);
    }
}
"""


@pytest.mark.parametrize("outside_header", [False, True])
def test_heapsort_oracle_accepts_equivalent_loop_headers(tmp_path: Path, outside_header: bool) -> None:
    source = _SOURCE
    if outside_header:
        source = source.replace("for (i = g_0BA2 - 1;", "i = g_0BA2 - 1; for (;")
    assert_heapsort_behavior(source, tmp_path)


@pytest.mark.parametrize("old,new", [
    ("i = 1;", "i = 2;"),
    ("g_0BA2 > (short)i", "(g_0BA2 & 255) > (short)i"),
    ("i = g_0BA2 - 1;", "i = g_0BA2 - 2;"),
    ("sub_109e8(i);", "sub_109e8(i); sub_109e8(0);"),
    ("sub_10768(0, i);", ""),
    ("sub_10768(0, i);", "sub_10768(i, 0);"),
    ("&g_0B4C[(unsigned short)i]", "&g_0B4C[0]"),
    ("sub_10a88(i - 1);", "sub_10a88(i);"),
    ("sub_10768(0, i);\n        sub_10a88(i - 1);", "sub_10a88(i - 1);\n        sub_10768(0, i);"),
    ("unsigned short i;", "unsigned short i; g_0B4C[0].field_0 = 1;"),
], ids=["up-bound", "byte-truncation", "down-bound", "extra-call", "lost-call", "scalar-order",
        "wrong-pointer", "down-argument", "call-order", "unexpected-write"])
def test_heapsort_oracle_rejects_changed_behavior(tmp_path: Path, old: str, new: str) -> None:
    assert old in _SOURCE
    with pytest.raises(AssertionError, match="violated the ordered call/pointer oracle"):
        assert_heapsort_behavior(_SOURCE.replace(old, new), tmp_path)


@pytest.mark.parametrize("register", ["inertia_esi", "inertia_edi"])
@pytest.mark.parametrize("lane_mask", ["0x1UL", "0x10000UL"])
def test_heapsort_oracle_rejects_register_corruption(tmp_path: Path, register: str, lane_mask: str) -> None:
    """Both halves of each callee-preserved register remain observable."""
    corrupted = _SOURCE.replace("unsigned short i;", f"unsigned short i; {register} ^= {lane_mask};")
    with pytest.raises(AssertionError, match="violated the ordered call/pointer oracle"):
        assert_heapsort_behavior(corrupted, tmp_path)

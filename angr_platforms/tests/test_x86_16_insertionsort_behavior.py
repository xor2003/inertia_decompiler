"""Check that the InsertionSort oracle rejects compilable semantic defects."""

from pathlib import Path

import pytest
from x86_16_insertionsort_behavior import assert_insertionsort_behavior

_CORRECT = r'''
void sub_10808(void) {
    for (unsigned short row = 0; row < g_0BA2; ++row) {
        g_08F0_entry item = g_0B4C[row];
        unsigned short j = row;
        while (j) {
            ++g_0BAA;
            if ((signed char)g_0B4C[j - 1].field_0 <= (signed char)item.field_0) break;
            ++g_0BA4;
            g_0B4C[j] = g_0B4C[j - 1];
            sub_106c8(j);
            sub_10498(j);
            --j;
        }
        g_0B4C[j] = item;
        sub_106c8(j);
        sub_10498(j);
    }
}
'''


def test_insertion_oracle_accepts_complete_behavior(tmp_path: Path) -> None:
    assert_insertionsort_behavior(_CORRECT, tmp_path)


@pytest.mark.parametrize("old,new", [
    ("signed char", "unsigned char"),
    ("<=", "<"),
    ("g_0B4C[j] = g_0B4C[j - 1];", "g_0B4C[j].field_0 = g_0B4C[j - 1].field_0;"),
    ("sub_10498(j);", ""),
    ("sub_106c8(j);", "sub_106c8(row);"),
    ("++g_0BAA;", ""),
    ("g_0B4C[j] = item;", "g_0B4C[j] = item; inertia_edi = 0;"),
])
def test_insertion_oracle_rejects_semantic_corruption(tmp_path: Path, old: str, new: str) -> None:
    with pytest.raises(AssertionError, match="violated the insertion oracle"):
        assert_insertionsort_behavior(_CORRECT.replace(old, new), tmp_path)

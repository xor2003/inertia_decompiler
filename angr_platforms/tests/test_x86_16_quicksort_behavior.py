"""Prove QuickSort's compiled partition oracle accepts source logic and rejects mutations."""

from pathlib import Path

import pytest
from x86_16_quicksort_behavior import assert_quicksort_behavior

_SOURCE = r'''
typedef struct g_08F0_entry { char field_0, field_1; } g_08F0_entry;
extern g_08F0_entry abarWork[];
extern unsigned short iCompares;
int Swaps(g_08F0_entry *, g_08F0_entry *);
int SwapBars(unsigned short, unsigned short);
void QuickSort(short low, short high)
{
    short up, down, pivot;
    if (low >= high) return;
    if (high - low == 1) {
        ++iCompares;
        if ((signed char)abarWork[low].field_0 > (signed char)abarWork[high].field_0) {
            Swaps(&abarWork[low], &abarWork[high]);
            SwapBars(low, high);
        }
        return;
    }
    pivot = (signed char)abarWork[high].field_0;
    do {
        up = low;
        down = high;
        ++iCompares;
        while (up < down && (signed char)abarWork[up].field_0 <= pivot) ++up;
        ++iCompares;
        while (down > up && (signed char)abarWork[down].field_0 >= pivot) --down;
        if (up < down) {
            Swaps(&abarWork[up], &abarWork[down]);
            SwapBars(up, down);
        }
    } while (up < down);
    Swaps(&abarWork[up], &abarWork[high]);
    SwapBars(up, high);
    if (up - low < high - up) {
        QuickSort(low, up - 1);
        QuickSort(up + 1, high);
    } else {
        QuickSort(up + 1, high);
        QuickSort(low, up - 1);
    }
}
'''


def test_quicksort_oracle_accepts_source_partition_algorithm(tmp_path: Path) -> None:
    assert_quicksort_behavior(_SOURCE, tmp_path, named=True)


@pytest.mark.parametrize("old,new", [
    ("up < down && (signed char)abarWork[up].field_0 <= pivot", "up >= down"),
    ("pivot = (signed char)abarWork[high].field_0;", "pivot = 0;"),
    ("short up, down, pivot;", "short up, down; unsigned short pivot;"),
    ("SwapBars(up, down);", "SwapBars(down, up);"),
    ("Swaps(&abarWork[up], &abarWork[high]);", "Swaps(&abarWork[low], &abarWork[high]);"),
], ids=["lost-scan-comparison", "wrong-pivot", "unsigned-pivot", "wrong-draw-arguments", "wrong-pivot-swap"])
def test_quicksort_oracle_rejects_semantic_corruption(tmp_path: Path, old: str, new: str) -> None:
    assert old in _SOURCE
    with pytest.raises(AssertionError, match=r"violated the partition/call contract: exit=1; case=\d+ line=\d+ invariant="):
        assert_quicksort_behavior(_SOURCE.replace(old, new), tmp_path, named=True)

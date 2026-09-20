"""Ensure the SwapBars execution oracle rejects call and register corruption."""

from pathlib import Path

import pytest
from angr_platforms.X86_16.lowering.gp_word_runtime import GPRegisterRuntimeABI8616
from x86_16_swapbars_behavior import assert_swapbars_behavior

_SOURCE = r'''
void sub_10768(unsigned short first, unsigned short second)
{
    unsigned short saved_si = inertia_esi, saved_di = inertia_edi;
    sub_106c8(first);
    sub_106c8(second);
    sub_10498(first);
    inertia_esi = (inertia_esi & 0xffff0000UL) | saved_si;
    inertia_edi = (inertia_edi & 0xffff0000UL) | saved_di;
}
'''


@pytest.mark.parametrize("abi", list(GPRegisterRuntimeABI8616))
def test_swapbars_oracle_accepts_word_storage(tmp_path: Path, abi: GPRegisterRuntimeABI8616) -> None:
    assert_swapbars_behavior(_SOURCE, tmp_path, gp_runtime_abi=abi)


def test_swapbars_oracle_accepts_shared_runtime_views(tmp_path: Path) -> None:
    source = _SOURCE.replace(
        "inertia_esi = (inertia_esi & 0xffff0000UL) | saved_si;", "inertia_si = saved_si;",
    ).replace(
        "inertia_edi = (inertia_edi & 0xffff0000UL) | saved_di;", "inertia_di = saved_di;",
    )
    assert_swapbars_behavior(source, tmp_path, gp_runtime_abi=GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS)


@pytest.mark.parametrize("old,new", [
    ("sub_106c8(second);", "sub_106c8(first);"),
    ("sub_10498(first);", "sub_10498(second);"),
    ("sub_106c8(second);", ""),
    ("sub_10498(first);", "sub_10498(first); sub_10498(first);"),
    ("| saved_si;", "| saved_di;"),
    ("| saved_di;", "| 0;"),
    ("(inertia_esi & 0xffff0000UL)", "0x12340000UL"),
], ids=["first-for-second", "second-for-first", "lost-call", "extra-call",
        "wrong-si", "lost-di", "stale-upper-half"])
def test_swapbars_oracle_rejects_corruption(tmp_path: Path, old: str, new: str) -> None:
    assert old in _SOURCE
    with pytest.raises(AssertionError, match="violated the SwapBars oracle"):
        assert_swapbars_behavior(_SOURCE.replace(old, new), tmp_path)

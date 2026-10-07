from __future__ import annotations

from inertia.alias.domains import (
    AX,
    BX,
    CX,
    DX,
    FULL16,
    HIGH8,
    LOW8,
    DomainKey,
    View,
    join_register_views,
    register_domain_for_name,
    register_offset_for_name,
    register_pair_name,
    register_view_for_name,
    register_views_can_join,
)


def test_x86_16_alias_domains_map_byte_registers_to_word_domains() -> None:
    assert register_domain_for_name("al") == AX
    assert register_domain_for_name("ah") == AX
    assert register_domain_for_name("bl") == BX
    assert register_domain_for_name("ch") == CX
    assert register_domain_for_name("dh") == DX


def test_x86_16_alias_domains_map_register_views_and_pairs() -> None:
    assert register_view_for_name("ax") == FULL16
    assert register_view_for_name("al") == LOW8
    assert register_view_for_name("ah") == HIGH8
    assert register_pair_name("al") == "ax"
    assert register_pair_name("ah") == "ax"
    assert register_pair_name("ax") == "ax"


def test_x86_16_alias_domains_refuse_unknown_names() -> None:
    assert register_domain_for_name("r0") is None
    assert register_domain_for_name(None) is None
    assert register_view_for_name("r0") is None
    assert register_view_for_name(None) is None
    assert register_pair_name("r0") is None
    assert register_pair_name(None) is None
    assert register_offset_for_name("r0") is None
    assert register_offset_for_name(None) is None


def test_x86_16_alias_domains_join_adjacent_views() -> None:
    assert LOW8.bit_end == 8
    assert register_views_can_join(LOW8, HIGH8) is True
    assert join_register_views(LOW8, HIGH8) == FULL16
    assert join_register_views(HIGH8, LOW8) == FULL16
    assert register_views_can_join(LOW8, FULL16) is False
    assert join_register_views(LOW8, FULL16) is None


def test_x86_16_alias_domains_use_value_objects_for_identity() -> None:
    assert DomainKey("reg", "AX") == AX
    assert View(bit_offset=0, bit_width=8) == LOW8
    assert register_offset_for_name("ax") == 0
    assert register_offset_for_name("cx") == 2
    assert register_offset_for_name("dx") == 4
    assert register_offset_for_name("bx") == 6

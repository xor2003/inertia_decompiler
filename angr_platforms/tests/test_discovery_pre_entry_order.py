"""Startup's direct callee does not bound the beginning of application code."""

from types import SimpleNamespace

import pytest

from inertia_decompiler import cli_function_discovery as discovery


@pytest.mark.parametrize("helper_offset", [0x10, 0x50])
def test_ranked_helpers_survive_on_both_sides_of_main(monkeypatch, helper_offset):
    base, main_offset, entry_offset = 0x10000, 0x30, 0x80
    data = bytearray(b"\x90" * 0x100)
    for offset in (helper_offset, main_offset, 0x90):
        data[offset:offset + 3] = b"\x55\x8b\xec"
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"), entry=base + entry_offset,
        loader=SimpleNamespace(main_object=SimpleNamespace(
            linked_base=base, max_addr=len(data) - 1,
            memory=SimpleNamespace(load=lambda offset, size: bytes(data[offset:offset + size])),
        )),
    )
    monkeypatch.setattr(discovery, "_entry_window_seed_targets", lambda *args, **kwargs: {base + main_offset})
    ranked = [base + main_offset, base + helper_offset, base + 0x60, base + 0x90]
    monkeypatch.setattr(discovery, "_rank_exe_function_seeds", lambda project: ranked)

    assert discovery._rank_pre_entry_source_function_seeds_8616(project) == [
        base + main_offset, base + helper_offset,
    ]


def test_unranked_framed_body_is_not_admitted(monkeypatch):
    data = b"\x55\x8b\xec" + b"\x90" * 13 + b"\x55\x8b\xec"
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"), entry=0x10020,
        loader=SimpleNamespace(main_object=SimpleNamespace(
            linked_base=0x10000, max_addr=len(data) - 1,
            memory=SimpleNamespace(load=lambda offset, size: data[offset:offset + size]),
        )),
    )
    monkeypatch.setattr(discovery, "_entry_window_seed_targets", lambda *args, **kwargs: {0x10010})
    # The authoritative ranker may exclude a signature-matched runtime body.
    monkeypatch.setattr(discovery, "_rank_exe_function_seeds", lambda project: [0x10010])
    assert discovery._rank_pre_entry_source_function_seeds_8616(project) == [0x10010]

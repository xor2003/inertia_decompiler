"""Path-specific allocator staging preserves every required byte and effect."""
from dataclasses import dataclass

import pytest

from inertia.frontend.real16_dosbox_resize import DosboxMcbEntry, DosboxResizePolicy
from inertia.ir.real16_dosbox_resize_effects import (
    DosboxResizeEffects8616,
    DosboxResizeEffectsRefusal8616,
    stage_dosbox_resize_effects_8616,
)
from inertia.ir.real16_path_memory8616 import PathMemory8616, snapshot_path_memory_8616

pytestmark = pytest.mark.ssa_z3


@dataclass(frozen=True)
class _Layout:
    chunks: tuple[tuple[int, bytes], ...]


@dataclass(frozen=True)
class _Environment:
    chunks: tuple[tuple[int, bytes], ...]

    def memory_layout(self):
        return _Layout(self.chunks)


def _fixture(segment=0x103):
    psp = segment + 1
    header = b"Z" + psp.to_bytes(2, "little") + (0x20).to_bytes(2, "little") + b"x" * 11
    policy = DosboxResizePolicy(psp, (DosboxMcbEntry(segment, header),))
    image = header + b"\xA5" * (0x300 - 16)
    return policy, _Environment(((segment << 4, image),))


def _stage(policy, environment, memory=None, *, paragraphs=8, code_spans=(), frame_spans=()):
    return stage_dosbox_resize_effects_8616(
        policy, environment=environment, memory=PathMemory8616() if memory is None else memory,
        segment=policy.final_entry.data_segment, paragraphs=paragraphs, ax=0x4A37,
        code_spans=code_spans, frame_spans=frame_spans,
    )


@pytest.mark.parametrize("paragraphs,write_count,carry", [(0, 6, False), (8, 6, False), (0x20, 0, False), (0x21, 2, True)])
def test_stage_retains_complete_canonical_effects_without_mutation(paragraphs, write_count, carry):
    policy, env = _fixture()
    memory = PathMemory8616()
    before = snapshot_path_memory_8616(memory)
    result = _stage(policy, env, memory, paragraphs=paragraphs)
    assert isinstance(result, DosboxResizeEffects8616)
    assert len(result.response.writes) == write_count
    assert result.response.carry is carry
    assert result.current_chain == (policy.final_entry.image,)
    assert result.new_header_before == (b"\xA5" * 16 if paragraphs < 0x20 else None)
    assert snapshot_path_memory_8616(memory) == before


@pytest.mark.parametrize("state", ["tainted", "unknown", "changed"])
def test_unproved_or_changed_chain_refuses_without_mutating_overlay(state):
    policy, env = _fixture()
    memory = PathMemory8616()
    if state == "tainted":
        memory.taint()
    elif state == "unknown":
        memory.apply_write(policy.final_entry.address + 15, 1, None)
    else:
        memory.apply_write(policy.final_entry.address + 15, 1, b"y")
    before = snapshot_path_memory_8616(memory)
    result = _stage(policy, env, memory)
    assert isinstance(result, DosboxResizeEffectsRefusal8616)
    assert snapshot_path_memory_8616(memory) == before


def test_known_overlay_restores_chain_and_supplies_split_reserved_bytes():
    policy, env = _fixture()
    initial = bytearray(env.chunks[0][1])
    initial[15] = ord("y")
    env = _Environment(((env.chunks[0][0], bytes(initial)),))
    memory = PathMemory8616()
    memory.apply_write(policy.final_entry.address + 15, 1, b"x")
    split = (policy.final_entry.data_segment + 8) << 4
    memory.apply_write(split + 15, 1, b"z")
    result = _stage(policy, env, memory)
    assert isinstance(result, DosboxResizeEffects8616)
    assert result.current_chain == (policy.final_entry.image,)
    assert result.new_header_before == b"\xA5" * 15 + b"z"


@pytest.mark.parametrize("missing", ["chain", "split", "split_unknown"])
def test_missing_or_unknown_required_bytes_refuse(missing):
    policy, env = _fixture()
    memory = PathMemory8616()
    if missing == "chain":
        env = _Environment(((policy.final_entry.address, policy.final_entry.image[:-1]),))
    elif missing == "split":
        env = _Environment(((policy.final_entry.address, policy.final_entry.image),))
    else:
        split = (policy.final_entry.data_segment + 8) << 4
        memory.apply_write(split + 15, 1, None)
    assert isinstance(_stage(policy, env, memory), DosboxResizeEffectsRefusal8616)


@pytest.mark.parametrize("paragraphs", [8, 0x21])
def test_code_and_frame_aliases_check_even_same_value_growth_writes(paragraphs):
    policy, env = _fixture()
    protected = ((policy.final_entry.address + 3, 2),)
    assert _stage(policy, env, paragraphs=paragraphs, code_spans=protected) is DosboxResizeEffectsRefusal8616.CODE_WRITE
    assert _stage(policy, env, paragraphs=paragraphs, frame_spans=protected) is DosboxResizeEffectsRefusal8616.FRAME_ALIAS


def test_new_split_header_code_alias_refuses():
    policy, env = _fixture()
    split = (policy.final_entry.data_segment + 8) << 4
    assert _stage(policy, env, code_spans=((split, 1),)) is DosboxResizeEffectsRefusal8616.CODE_WRITE


def test_full_ivt_is_protected_for_every_allocator_write():
    policy, env = _fixture(segment=0x10)
    assert _stage(policy, env, paragraphs=0x21) is DosboxResizeEffectsRefusal8616.IVT_ALIAS


def test_all_prefix_headers_participate_in_path_overlay_reads():
    policy, env = _fixture()
    prefix = DosboxMcbEntry(0x100, b"M\7\0\2\0" + b"p" * 11)
    policy = DosboxResizePolicy(policy.psp_segment, (prefix, policy.final_entry))
    env = _Environment(((prefix.address, prefix.image + b"\xA5" * 32 + env.chunks[0][1]),))
    memory = PathMemory8616()
    memory.apply_write(prefix.address + 15, 1, None)
    assert isinstance(_stage(policy, env, memory), DosboxResizeEffectsRefusal8616)


@pytest.mark.parametrize("spans", [((0x1000, 0),), ((True, 1),), ((0xFFFFF, 2),)])
def test_malformed_protection_spans_cannot_supply_evidence(spans):
    policy, env = _fixture()
    assert _stage(policy, env, code_spans=spans) is DosboxResizeEffectsRefusal8616.SPAN_UNPROVEN

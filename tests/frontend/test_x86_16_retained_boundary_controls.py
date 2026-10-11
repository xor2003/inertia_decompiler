"""Retained exact callsite census owns rediscovery of an already imported head."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

import inertia.ir.entry_domain_call_preservation as owner
import inertia.ir.function_ssa_registry as registry
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
    retain_decoded_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616


def _retained():
    project = SimpleNamespace()
    boundary = ExactFunctionRangeBoundary8616(project, 0x1020, 0x80, frozenset({0x1020}), frozenset({0x1020}), (), decode_lower_bound=0x1000)
    index = DecodedDirectCallsiteIndex8616({}, DecodedDirectCallsiteIndexStats8616(0,0,0,0,0))
    record = retain_decoded_callsite_index_8616(project, boundary, index)
    return project, boundary, index, record


def test_exact_boundary_reuses_retained_authority_before_reframing(monkeypatch):
    project, boundary, _index, _record = _retained()
    def forbidden(*args):
        raise AssertionError("retained source must not be reframed")
    monkeypatch.setattr(registry, "function_boundary_at_address_8616", forbidden)
    assert owner._exact_boundary_for_8616(project, boundary.addr) is boundary


def test_no_retained_boundary_uses_existing_resolver(monkeypatch):
    project = SimpleNamespace()
    boundary = ExactFunctionRangeBoundary8616(project, 0x1020, 2, frozenset({0x1020}), frozenset({0x1020}), ())
    monkeypatch.setattr(registry, "function_boundary_at_address_8616", lambda *args: boundary)
    assert owner._exact_boundary_for_8616(project, boundary.addr) is boundary


@pytest.mark.parametrize("foreign", ["project", "head"])
def test_foreign_retained_surface_refuses(foreign):
    project, boundary, _index, record = _retained()
    forged = replace(boundary, project=object()) if foreign == "project" else replace(boundary, addr=0x1030)
    project._inertia_decoded_callsite_indexes_8616[boundary.addr] = replace(record, boundary=forged)
    assert owner._exact_boundary_for_8616(project, boundary.addr) is None


def test_changed_census_still_fails_loudly():
    project, boundary, index, _record = _retained()
    with pytest.raises(ValueError, match="conflicting decoded callsite census"):
        retain_decoded_callsite_index_8616(project, replace(boundary, successor_edges=((0x1020,0x1022),)), index)


def _native_window_fixture():
    """Decode real CALL/RET bytes once under two valid admission windows."""
    from capstone import CS_ARCH_X86, CS_MODE_16, Cs

    from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
    encoding = bytes.fromhex("e80d00c3")
    instructions = tuple(Cs(CS_ARCH_X86, CS_MODE_16).disasm(encoding, 0x1020))
    project = SimpleNamespace(loader=SimpleNamespace(memory={0x1020: encoding}))
    block = SimpleNamespace(addr=0x1020, capstone=SimpleNamespace(insns=instructions))
    boundary = ExactFunctionRangeBoundary8616(project, 0x1020, 0x80, frozenset({0x1020}),
        frozenset(i.address for i in instructions), (), (block,), decode_lower_bound=0x1000)
    def resolver(instruction):
        return 0x1030 if instruction.address == 0x1020 else None
    index = build_boundary_direct_callsite_index_8616(boundary, direct_target_resolver=resolver)
    return project, boundary, index, resolver


def test_window_only_change_reuses_exact_native_facts():
    """Both retain and lookup keep the first window without decoding again."""
    from inertia.frontend.x86_16.frontend_direct_callsite_index import decoded_callsite_index_for_boundary_8616
    project, boundary, index, _resolver = _native_window_fixture()
    smaller = replace(boundary, size=4, decode_lower_bound=0x1020)
    record = retain_decoded_callsite_index_8616(project, smaller, index)
    assert record.boundary is boundary
    assert record.index is index
    def forbidden(_instruction):
        raise AssertionError("same native census must not be decoded again")
    assert decoded_callsite_index_for_boundary_8616(project, smaller, direct_target_resolver=forbidden) is record


def test_rebuilt_index_with_different_window_reuses_facts():
    """New Capstone identities and index window fields do not change facts."""
    from capstone import CS_ARCH_X86, CS_MODE_16, Cs

    from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
    project, boundary, index, resolver = _native_window_fixture()
    block = SimpleNamespace(addr=0x1020, capstone=SimpleNamespace(insns=tuple(Cs(CS_ARCH_X86,CS_MODE_16).disasm(bytes.fromhex('e80d00c3'),0x1020))))
    smaller = replace(boundary, size=4, decode_lower_bound=0x1020, blocks=(block,))
    build_boundary_direct_callsite_index_8616(smaller, direct_target_resolver=resolver)
    assert retain_decoded_callsite_index_8616(project, smaller, index).boundary is boundary


@pytest.mark.parametrize("damage", ["bytes", "blocks", "instructions", "edges", "window", "project", "target", "retained_bytes", "retained_target"])
def test_native_census_damage_cannot_hide_behind_window_change(damage):
    """Window relaxation does not admit changed native facts or mutable state."""
    from capstone import CS_ARCH_X86, CS_MODE_16, Cs
    project, boundary, index, _resolver = _native_window_fixture()
    changed = replace(boundary, size=4, decode_lower_bound=0x1020)
    incoming = index
    if damage in {"bytes", "retained_bytes"}:
        changed_instructions = tuple(Cs(CS_ARCH_X86,CS_MODE_16).disasm(bytes.fromhex('e80e00c3'),0x1020))
        if damage == "retained_bytes":
            boundary.blocks[0].capstone.insns = changed_instructions
        else:
            changed = replace(changed, blocks=(SimpleNamespace(addr=0x1020,capstone=SimpleNamespace(insns=changed_instructions)),))
    elif damage == "blocks":
        changed = replace(changed, block_addrs_set=frozenset({0x1021}))
    elif damage == "instructions":
        changed = replace(changed, reachable_instruction_addrs=frozenset({0x1020}))
    elif damage == "edges":
        changed = replace(changed, successor_edges=((0x1020,0x1023),))
    elif damage == "window":
        changed = replace(changed, size=3)
    elif damage == "project":
        changed = replace(changed, project=SimpleNamespace())
    else:
        calls = index._entries_by_normalized_target[0x1030]
        entries = {0x1030: (replace(calls[0], target_addr=0x1031),)}
        if damage == "retained_target":
            index._entries_by_normalized_target.update(entries)
        else:
            incoming = replace(index, _entries_by_normalized_target=entries)
    with pytest.raises(ValueError):
        retain_decoded_callsite_index_8616(project, changed, incoming)

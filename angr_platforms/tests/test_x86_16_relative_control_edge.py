"""Binary-derived relative-edge evidence and independent native projections."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest
from angr_platforms.X86_16.alias.condition_register_liveness import _condition_by_block_8616
from angr_platforms.X86_16.control_coordinates import ControlAddressDomain, ControlWidth
from angr_platforms.X86_16.ir.condition_ir import (
    ConditionIR,
    build_condition_from_cmp_8616,
    build_condition_from_test_8616,
    deduplicate_conditions_8616,
)
from angr_platforms.X86_16.relative_control_edge import (
    DecodedRelativeEdge,
    RelativeEdgeForm,
    RelativeEdgeRefusal,
    RelativeEdgeRefusalReason,
    decode_relative_edge,
)
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_EFLAGS, UC_X86_REG_EIP, UC_X86_REG_IP


def _concrete_only(*args):
    raise AssertionError("concrete projection unexpectedly requests symbolic constants")


@pytest.mark.parametrize("encoding,form,width,displacement", [
    ("eb80", RelativeEdgeForm.JMP_REL8, ControlWidth.WORD, -128),
    ("74ff", RelativeEdgeForm.JCC_REL8, ControlWidth.WORD, -1),
    ("e2fe", RelativeEdgeForm.LOOP_REL8, ControlWidth.WORD, -2),
    ("e300", RelativeEdgeForm.JCXZ_REL8, ControlWidth.WORD, 0),
    ("e80080", RelativeEdgeForm.CALL_REL16, ControlWidth.WORD, -32768),
    ("e9ff7f", RelativeEdgeForm.JMP_REL16, ControlWidth.WORD, 32767),
    ("0f84feff", RelativeEdgeForm.JCC_REL16, ControlWidth.WORD, -2),
    ("66e800000080", RelativeEdgeForm.CALL_REL32, ControlWidth.DWORD, -2147483648),
    ("66e978563412", RelativeEdgeForm.JMP_REL32, ControlWidth.DWORD, 0x12345678),
    ("660f84ffffffff", RelativeEdgeForm.JCC_REL32, ControlWidth.DWORD, -1),
])
def test_exact_bytes_derive_form_width_displacement_and_identity(encoding, form, width, displacement):
    raw = bytes.fromhex(encoding)
    edge = decode_relative_edge(0x12345, raw, source="binary:original")
    assert isinstance(edge, DecodedRelativeEdge)
    assert (edge.form, edge.width, edge.displacement) == (form, width, displacement)
    assert edge.head == 0x12345 and edge.encoding == raw and edge.source == "binary:original"
    assert edge.encoding_digest == sha256(raw).hexdigest()


@pytest.mark.parametrize("encoding,reason", [
    ("", RelativeEdgeRefusalReason.EMPTY_ENCODING),
    ("0f8400", RelativeEdgeRefusalReason.LENGTH_MISMATCH),
    ("0f84000090", RelativeEdgeRefusalReason.LENGTH_MISMATCH),
    ("e800", RelativeEdgeRefusalReason.LENGTH_MISMATCH),
    ("660f84000000", RelativeEdgeRefusalReason.LENGTH_MISMATCH),
    ("67e300", RelativeEdgeRefusalReason.UNSUPPORTED_PREFIX),
    ("667400", RelativeEdgeRefusalReason.UNSUPPORTED_PREFIX),
    ("66e80000000090", RelativeEdgeRefusalReason.LENGTH_MISMATCH),
    ("c3", RelativeEdgeRefusalReason.UNSUPPORTED_FORM),
    ("9a00000000", RelativeEdgeRefusalReason.UNSUPPORTED_FORM),
])
def test_unsupported_or_incomplete_bytes_retain_typed_refusal(encoding, reason):
    raw = bytes.fromhex(encoding)
    result = decode_relative_edge(0x23456, raw, source="binary:changed")
    assert isinstance(result, RelativeEdgeRefusal)
    assert result.reason is reason
    assert (result.head, result.encoding, result.source) == (0x23456, raw, "binary:changed")


@pytest.mark.parametrize("head", [True, 1.5, -1, 0x100000000])
def test_invalid_coordinate_cannot_be_coerced_into_source_evidence(head):
    with pytest.raises((TypeError, ValueError)):
        decode_relative_edge(head, bytes.fromhex("7400"))


@pytest.mark.parametrize("changes", [
    {"displacement": 2}, {"width": ControlWidth.DWORD}, {"form": RelativeEdgeForm.JMP_REL8},
])
def test_forged_decoded_fields_are_rejected(changes):
    edge = decode_relative_edge(0x12340, bytes.fromhex("7401"))
    assert isinstance(edge, DecodedRelativeEdge)
    with pytest.raises(ValueError):
        replace(edge, **changes)


@pytest.mark.parametrize("ip,encoding", [(0xFFF0, "741e"), (0x10, "74de"), (0x200, "0f840d00")])
@pytest.mark.parametrize("taken", [False, True])
def test_word_conditional_projections_match_unicorn(ip, encoding, taken):
    cs = 0x1234
    raw = bytes.fromhex(encoding)
    head = (cs << 4) + ip
    edge = decode_relative_edge(head, raw)
    assert isinstance(edge, DecodedRelativeEdge)
    projected = edge.project(cs, _concrete_only)
    guest = Uc(UC_ARCH_X86, UC_MODE_16)
    guest.mem_map(0, 0x100000)
    guest.mem_write(head, raw)
    guest.reg_write(UC_X86_REG_CS, cs)
    guest.reg_write(UC_X86_REG_IP, ip)
    guest.reg_write(UC_X86_REG_EFLAGS, 0x42 if taken else 0x2)
    visited = []
    guest.hook_add(UC_HOOK_CODE, lambda _guest, address, _size, _data: visited.append(address))
    guest.emu_start(head, 0, count=1)
    assert visited == [head]
    native_ip = guest.reg_read(UC_X86_REG_EIP)
    native_control = (guest.reg_read(UC_X86_REG_CS) << 4) + native_ip
    assert native_ip == (projected.taken_offset if taken else projected.fallthrough_offset)
    assert native_control == (projected.taken_control if taken else projected.fallthrough_control)
    assert (native_control ^ 1) != (projected.taken_control if taken else projected.fallthrough_control)


def test_offset_domain_keeps_dword_wrap_without_a_loader_page():
    edge = decode_relative_edge(0xFFFFFFF0, bytes.fromhex("66e920000000"))
    assert isinstance(edge, DecodedRelativeEdge)
    projected = edge.project(0x1234, _concrete_only, domain=ControlAddressDomain.ARCHITECTURAL_OFFSET)
    assert projected.taken_offset == projected.taken_control == 0x16
    assert projected.fallthrough_offset == projected.fallthrough_control == 0xFFFFFFF6


def test_conditions_keep_distinct_unresolved_binary_edges_during_deduplication():
    first = decode_relative_edge(0x1200, bytes.fromhex("7401"))
    second = decode_relative_edge(0x1200, bytes.fromhex("7402"))
    assert isinstance(first, DecodedRelativeEdge) and isinstance(second, DecodedRelativeEdge)
    a = ConditionIR(op="eq", lhs=1, rhs=2, src_insn=0x1200, relative_edge=first)
    b = replace(a, relative_edge=second)
    assert a.taken_target is None and a.fallthrough_target is None
    assert len(deduplicate_conditions_8616([a, b, a])) == 2


@pytest.mark.parametrize("builder", [build_condition_from_cmp_8616, build_condition_from_test_8616])
def test_condition_builders_retain_the_exact_edge_without_resolving_targets(builder):
    edge = decode_relative_edge(0x1200, bytes.fromhex("7401"))
    assert isinstance(edge, DecodedRelativeEdge)
    args = (1, 2, "jz") if builder is build_condition_from_cmp_8616 else (1, "jz")
    condition = builder(*args, src_insn=edge.head, relative_edge=edge)
    assert isinstance(condition, ConditionIR)
    assert condition.relative_edge is edge
    assert condition.taken_target is None and condition.fallthrough_target is None


def test_alias_liveness_refuses_distinct_unresolved_edges_for_one_block():
    first = decode_relative_edge(0x1200, bytes.fromhex("7401"))
    second = decode_relative_edge(0x1200, bytes.fromhex("7402"))
    assert isinstance(first, DecodedRelativeEdge) and isinstance(second, DecodedRelativeEdge)
    a = ConditionIR(op="eq", lhs=1, rhs=2, src_insn=0x1200, block_addr=0x1200, relative_edge=first)
    b = replace(a, relative_edge=second)
    nodes, failures = _condition_by_block_8616((a, b))
    assert nodes == {}
    assert failures == 1

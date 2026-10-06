"""Exact-byte modular CALL metadata agrees with native control and rejects corruption."""
from __future__ import annotations

from typing import Any, cast

import archinfo
import capstone
import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.relative_control_edge import (
    DecodedRelativeEdge,
    RelativeDestinationVerdict,
    decode_relative_edge,
    invariant_relative_destination,
)
from pyvex.types import Arch
from test_real16_native_control_scope import NearKind, SourceReceipt, _lifted, _native

from tools.dosunit import straightline_ssa as S
from tools.dosunit.binary_callee_control_target import native_constant_control, relative_call_target
from tools.dosunit.binary_callee_intake import _near_call_target
from tools.dosunit.model import normalize_hex
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_contracts import prove_terms_equal


def _lift(code: bytes, head: int) -> pyvex.IRSB:
    return pyvex.IRSB(code, head, cast(Arch, Arch86_16()), opt_level=0)


def _instructions(code: bytes, head: int) -> list[dict[str, Any]]:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    return [{"address": {"linear": hex(row.address)}, "size": row.size,
             "bytes": bytes(row.bytes).hex(), "mnemonic": row.mnemonic, "op_str": row.op_str}
            for row in decoder.disasm(code, head)]


@pytest.mark.parametrize("head,encoded,target,cs", [
    (0x1203, "e88a87", 0x9990, 0x100),
    (0x1260, "e80000", 0x1263, 0x100),
    (0x11260, "e80000", 0x11263, 0x1000),
    (0xFFFFD, "e8f0ff", 0xFFFF0, 0xFFFF),
])
def test_full_target_agrees_with_native_effect(head: int, encoded: str, target: int, cs: int) -> None:
    """Byte discovery equals both native execution and lifted full-width control."""
    code = bytes.fromhex(encoded)
    irsb = _lift(code, head)
    transfer = S._transfer_info(irsb, _instructions(code, head))
    assert transfer is not None
    assert transfer["target"] == {"raw": normalize_hex(target), "low16": normalize_hex(target & 0xFFFF, width=4)}
    assert transfer["target_evidence"] == {"raw_fact_count": 1, "normalized_fact_count": 1,
                                         "classified_fact_count": 1, "materialized_count": 1, "failure_count": 0}
    assert _near_call_target(head, code, 2) == target
    receipt = SourceReceipt(code, "", head, cs, head - (cs << 4))
    native = _native(receipt, NearKind.CALL_REL16)
    assert (native.cs << 4) + native.ip == target
    assert native.return_word == (head + 3 - (cs << 4)) & 0xFFFF
    state = _lifted(receipt)
    assert prove_terms_equal(state["control_ip"], {"op": "const", "width": 32, "value": hex(target)}, 3000) is ProofStatus.PROVED


@pytest.mark.parametrize("head,encoded", [(0xFFFD, "e80000"), (0x12350, "e8cdff")])
def test_selector_dependent_wrapping_remains_unresolved(head: int, encoded: str) -> None:
    """A selector-dependent destination cannot become a static target."""
    code = bytes.fromhex(encoded)
    edge = decode_relative_edge(head, code)
    assert isinstance(edge, DecodedRelativeEdge)
    destination = invariant_relative_destination(edge)
    assert destination.verdict is RelativeDestinationVerdict.SELECTOR_DEPENDENT
    assert destination.target is None
    transfer = S._transfer_info(_lift(code, head), _instructions(code, head))
    assert transfer is not None
    assert "target" not in transfer
    assert transfer["target_refusal"] == "native_refused"
    assert transfer["target_evidence"]["failure_count"] == 1
    assert _near_call_target(head, code, 2) is None


@pytest.mark.parametrize("mutation", ["displacement", "high_bits", "constant", "wrong_cs", "flat_signed_word"])
def test_native_dag_corruption_does_not_publish_target(mutation: str) -> None:
    """Changed native effects cannot borrow intact instruction metadata."""
    code = bytes.fromhex("e88a87")
    block = _lift(code, 0x1203)
    if mutation == "displacement":
        block = _lift(bytes.fromhex("e88987"), 0x1203)
    elif mutation == "high_bits":
        block.next = pyvex.expr.Binop("Iop_Add32", [block.next, pyvex.expr.Const(pyvex.const.U32(0x10000))])
    elif mutation == "flat_signed_word":
        block.next = pyvex.expr.Binop("Iop_Add32", [pyvex.expr.Const(pyvex.const.U32(0x1206)),
                                                   pyvex.expr.Const(pyvex.const.U32(0xFFFF878A))])
    elif mutation == "constant":
        block.next = pyvex.expr.Const(pyvex.const.U32(0x19990))
    else:
        for statement in block.statements:
            if isinstance(statement, pyvex.stmt.WrTmp) and isinstance(statement.data, pyvex.expr.Get) and statement.data.offset == 40:
                statement.data.offset = 42
    result = relative_call_target(block, head=0x1203, encoding=code)
    assert result.target is None and result.failure is not None
    transfer = S._transfer_info(block, _instructions(code, 0x1203))
    assert transfer is not None
    assert "target" not in transfer
    assert transfer["target_evidence"]["materialized_count"] == 0
    assert transfer["target_evidence"]["failure_count"] == 1


def test_disassembly_text_cannot_repair_or_corrupt_native_evidence() -> None:
    """Only bytes and native effects determine the destination."""
    code = bytes.fromhex("e88a87")
    instructions = _instructions(code, 0x1203)
    instructions[0]["op_str"] = "0x19990"
    transfer = S._transfer_info(_lift(code, 0x1203), instructions)
    assert transfer is not None
    assert transfer["target"]["raw"] == "0x9990"
    instructions[0]["bytes"] = "e88987"
    transfer = S._transfer_info(_lift(code, 0x1203), instructions)
    assert transfer is not None
    assert "target" not in transfer


def test_missing_bytes_do_not_fall_back_to_text() -> None:
    """A plausible display operand supplies no byte proof."""
    code = bytes.fromhex("e88a87")
    instructions = _instructions(code, 0x1203)
    del instructions[0]["bytes"]
    transfer = S._transfer_info(_lift(code, 0x1203), instructions)
    assert transfer is not None
    assert "target" not in transfer
    assert transfer["target_refusal"] == "source_incomplete"


def test_operand_override_preserves_dword_coordinate() -> None:
    """Operand override keeps a full dword target and rejects width conflict."""
    code = bytes.fromhex("66e800000000")
    assert _near_call_target(0x11260, code, 4) == 0x11266
    assert _near_call_target(0x11260, code, 2) is None
    transfer = S._transfer_info(_lift(code, 0x11260), _instructions(code, 0x11260))
    assert transfer is not None
    assert transfer["target"]["raw"] == "0x11266"


def test_unsupported_prefix_is_an_explicit_nonresult() -> None:
    """Unsupported prefix evidence never defaults to a plain word CALL."""
    code = bytes.fromhex("2ee80000")
    assert _near_call_target(0x1260, code, 2) is None
    transfer = S._transfer_info(_lift(code, 0x1260), _instructions(code, 0x1260))
    assert transfer is not None
    assert "target" not in transfer
    assert transfer["target_refusal"] == "form_unsupported"



def test_flat32_relative_call_keeps_native_full_width_target() -> None:
    """Shared transfer serialization keeps the existing flat32 constant lane."""
    code = bytes.fromhex("e82a000000")
    head = 0x401203
    block = pyvex.IRSB(code, head, archinfo.ArchX86(), opt_level=0)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    row = next(decoder.disasm(code, head))
    records = [{"address": {"linear": hex(head)}, "size": row.size,
                "bytes": code.hex(), "mnemonic": row.mnemonic, "op_str": row.op_str}]
    transfer = S._transfer_info(block, records)
    assert transfer is not None
    assert transfer["target"]["raw"] == "0x401232"
    assert "target_refusal" not in transfer


def test_real16_far_call_keeps_native_selector_target() -> None:
    """A far immediate CALL retains its independent selector-based native control."""
    code = bytes.fromhex("9a78563412")
    block = _lift(code, 0x1203)
    assert block.jumpkind == "Ijk_Call"
    transfer = S._transfer_info(block, _instructions(code, 0x1203))
    assert transfer is not None
    expected = S._const_expr_value(block.next)
    assert expected is not None
    assert transfer["target"]["raw"] == normalize_hex(expected)
    assert "target_refusal" not in transfer



def test_real16_far_call_rejects_changed_native_high_bits() -> None:
    """A far encoded pointer cannot license a different full native constant."""
    code = bytes.fromhex("9a78563412")
    block = _lift(code, 0x1203)
    original = S._const_expr_value(block.next)
    assert original is not None
    block.next = pyvex.expr.Const(pyvex.const.U32(original + 0x10000))
    transfer = S._transfer_info(block, _instructions(code, 0x1203))
    assert transfer is not None
    assert "target" not in transfer
    assert transfer["target_refusal"] == "native_refused"



def test_flat32_pc_alias_rejects_partial_write() -> None:
    """An intervening partial eip write cannot reuse the earlier full constant."""
    block = pyvex.IRSB(bytes.fromhex("e82a000000"), 0x401203, archinfo.ArchX86(), opt_level=0)
    index = next(index for index, statement in enumerate(block.statements)
                 if isinstance(statement, pyvex.stmt.WrTmp) and isinstance(statement.data, pyvex.expr.Get)
                 and statement.data.offset == block.arch.ip_offset)
    block.statements.insert(index, pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U16(0x1234)), block.arch.ip_offset + 2))
    assert native_constant_control(block) is None

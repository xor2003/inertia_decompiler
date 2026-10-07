"""Binary-derived near-return continuation and scoped-consumption controls.

Real decoded instruction facts establish continuation provenance. Raw conditional
IR retains JMP and pending refusal; only a bound invocation view exposes RET.
Publication, widths, mutation, and missing evidence keep explicit refusals.
"""

from __future__ import annotations

import io
from pathlib import Path

import angr
import capstone
import pytest
import inertia.frontend.x86_16.frontend_function_boundary as boundary_mod
import inertia.frontend.x86_16.frontend_instruction_reachability as reach_mod
import inertia.frontend.x86_16.frontend_near_return_continuation as nrc
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.ir.entry_domain_call_preservation as edcp
import inertia.ir.ir_boundary_cfg as ibc
import inertia.ir.near_return_continuation_view as nrcv
import inertia.ir.vex_import as vex_import
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)

_BASE = 0x1000
_ENTRY = 0x1100
_PROVEN = nrc.NearReturnContinuationVerdict8616.PROVEN
_REFUSED = nrc.NearReturnContinuationVerdict8616.REFUSED
_FAIL = nrc.NearReturnContinuationFailure8616
_KIND = nrc.NearReturnContinuationKind8616
_PENDING_KIND = "near_return_continuation_pending"

# The caller edge the test premise binds: one real Capstone-decoded
# near-CALL instruction inside a caller range below the staged fixture
# region, retained by its own closed callsite index. The row/index
# objects are data fixtures carrying genuine decoded instruction
# evidence, never mocks of the proof — the premise owner revalidates
# every field including the operand-width proof.
_CALLER_START = 0x0F00
_CALLSITE_ADDR = 0x0F03
_CALL_SIZE = 3
_WIDE_CALL_SIZE = 6


class _UndecodedCallsiteInstruction:
    """Address/size-only row instruction carrying no width evidence.

    Negative-control fixture only: the premise must refuse a row whose
    instruction exposes no decoded prefix or operand facts, never fall
    back to trusting the near/far flag.
    """

    __slots__ = ("address", "size")

    def __init__(self, address: int, size: int) -> None:
        self.address = address
        self.size = size


def _decode_callsite_8616(code: bytes, address: int) -> object:
    """Decode one real 16-bit Capstone instruction for a caller row."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instruction, = tuple(decoder.disasm(code, address))
    return instruction


def _decoded_call_row(code: bytes, callee_addr: int) -> DecodedDirectCallsite8616:
    """Retain one real decoded call instruction as a callsite row."""
    instruction = _decode_callsite_8616(code, _CALLSITE_ADDR)
    assert instruction.operands[0].imm == callee_addr
    return DecodedDirectCallsite8616(
        caller_start=_CALLER_START,
        instructions=(instruction,),
        instruction_index=0,
        callsite_addr=_CALLSITE_ADDR,
        target_addr=callee_addr,
    )


def _callsite_row(callee_addr: int) -> DecodedDirectCallsite8616:
    """Build the exact decoded near-CALL row targeting one callee head."""
    code = b"\xe8" + (
        (callee_addr - (_CALLSITE_ADDR + _CALL_SIZE)) & 0xFFFF
    ).to_bytes(2, "little")
    row = _decoded_call_row(code, callee_addr)
    assert row.instructions[0].size == _CALL_SIZE
    return row


def _wide_callsite_row(callee_addr: int) -> DecodedDirectCallsite8616:
    """Build the decoded ``66 E8`` near-CALL row targeting one callee."""
    code = b"\x66\xe8" + (
        (callee_addr - (_CALLSITE_ADDR + _WIDE_CALL_SIZE)) & 0xFFFFFFFF
    ).to_bytes(4, "little")
    row = _decoded_call_row(code, callee_addr)
    assert row.instructions[0].size == _WIDE_CALL_SIZE
    return row


def _noncall_row(target_addr: int) -> DecodedDirectCallsite8616:
    """Build a decoded near-JMP row: an imm operand that pushes nothing."""
    code = b"\xe9" + (
        (target_addr - (_CALLSITE_ADDR + _CALL_SIZE)) & 0xFFFF
    ).to_bytes(2, "little")
    return _decoded_call_row(code, target_addr)


def _callsite_index(
    row: DecodedDirectCallsite8616, callee_addr: int,
) -> DecodedDirectCallsiteIndex8616:
    """Retain one synthetic row under its normalized near-target key."""
    stats = DecodedDirectCallsiteIndexStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )
    return DecodedDirectCallsiteIndex8616({callee_addr & 0xFFFF: (row,)}, stats)


def _premise(callee_addr: int = _ENTRY) -> object:
    """Prove the source-bound frame premise for the synthetic edge."""
    row = _callsite_row(callee_addr)
    premise = nrc.prove_near_call_frame_premise_8616(
        row, _callsite_index(row, callee_addr), callee_addr
    )
    assert premise is not None
    return premise


_PREMISE = _premise()

# pop cx; mov bx,sp; sub bx,ax; mov sp,bx; jmp cx  — the blocker shape.
_POSITIVE = bytes.fromhex("59 8B DC 2B D8 8B E3 FF E1")
# pop ax; mov cx,ax; jmp cx — provenance survives a register copy.
_MOV_CHAIN = bytes.fromhex("58 8B C8 FF E1")
# pop ax; xchg ax,cx; jmp cx — provenance survives a register swap.
_XCHG_CHAIN = bytes.fromhex("58 91 FF E1")
# mov bp,sp; jmp word [bp+0] — continuation read straight off the frame.
_MEM_POSITIVE = bytes.fromhex("8B EC FF 66 00")
# Same terminal, one word too high.
_MEM_WRONG_SLOT = bytes.fromhex("8B EC FF 66 02")
# mov bp,sp; mov [bp+0],ax; jmp [bp+0] — slot rewritten before the jump.
_MEM_MUTATED = bytes.fromhex("8B EC 89 46 00 FF 66 00")
# Same frame write, then the register form.
_REG_MUTATED = bytes.fromhex("8B EC 89 46 00 59 FF E1")
# Continuation loaded, terminal uses the wrong register.
_WRONG_REG = bytes.fromhex("59 8B DC 2B D8 8B E3 FF E3")
# Continuation loaded, then overwritten.
_RELOAD = bytes.fromhex("59 B9 00 12 FF E1")
# pop cx; mov cs,ax; jmp cx — CS clobbered on the path.
_CS_CLOBBER = bytes.fromhex("59 8E C8 FF E1")
# pop cx; call $+3 (self-tail); jmp cx — intervening near call.
_CALL_TAIL = bytes.fromhex("59 E8 00 00 FF E1")
# test ax,ax; jz error; <positive body>; error: mov ax,0; jmp bx.
_ERROR_TAIL = bytes.fromhex(
    "85 C0 74 0C"          # 0x1100 test ax,ax; jz 0x1110
    "59 8B DC 2B D8 8B E3 FF E1"  # 0x1104 proven body
    "90 90 90"             # 0x110D pad to 0x1110
    "B8 00 00 FF E3"       # 0x1110 error tail: mov ax,0; jmp bx
)
# mov bp,sp; mov byte [bp+1],0xff; jmp word [bp] — overlaps the return
# word's high byte (parent counterexample 1).
_OVERLAP_HIGH = bytes.fromhex("8B EC C6 46 01 FF FF 66 00")
# mov bp,sp; mov word [bp-1],0; jmp word [bp] — overlaps the low byte
# from below (parent counterexample 2; bytes ffff,0).
_OVERLAP_LOW = bytes.fromhex("8B EC C7 46 FF FF 00 FF 66 00")
# mov bp,sp; mov word [bp+1],0; jmp word [bp] — word store covering the
# high byte and the byte above (bytes 1,2).
_OVERLAP_ABOVE = bytes.fromhex("8B EC C7 46 01 00 00 FF 66 00")
# mov bp,sp; add [bp+1],ax; jmp word [bp] — non-mov store, same overlap.
_OVERLAP_ALU = bytes.fromhex("8B EC 01 46 01 FF 66 00")
# mov bp,sp; mov dword [bp],eax; jmp word [bp] — operand-size-overridden
# store; bytes 0..3.
_OVERLAP_WIDE_STORE = bytes.fromhex("8B EC 66 89 46 00 FF 66 00")
# pop cx; jmp ecx — wide continuation target reads unconstrained upper
# bits of ECX (parent counterexample 3).
_WIDE_REG_TARGET = bytes.fromhex("59 66 FF E1")
# mov bp,sp; jmp dword [bp] — wide memory target.
_WIDE_MEM_TARGET = bytes.fromhex("8B EC 66 FF 66 00")
# mov bp,sp; add bp,1; jmp word [bp] — tracked BP delta is no longer the
# entry top slot (parent counterexample 4).
_BP_DELTA_MOVED = bytes.fromhex("8B EC 83 C5 01 FF 66 00")
# mov bp,sp; xor bp,bp; jmp word [bp] — unmodeled BP write invalidates
# the frame delta entirely.
_BP_DELTA_LOST = bytes.fromhex("8B EC 31 ED FF 66 00")
# mov sp,ax; pop cx; jmp cx — unmodeled SP write invalidates SP delta;
# the pop slot is uncomputable.
_SP_DELTA_LOST = bytes.fromhex("8B E0 59 FF E1")
# pop ecx; jmp cx — a 32-bit pop is admitted as a stack effect but never
# binds a 16-bit continuation carrier.
_WIDE_POP = bytes.fromhex("66 59 FF E1")
# mov bp,sp; mov word [bp+2],0; jmp word [bp] — adjacent store above the
# return word does not overlap.
_ADJACENT_ABOVE = bytes.fromhex("8B EC C7 46 02 00 00 FF 66 00")
# mov bp,sp; mov word [bp-2],0; jmp word [bp] — adjacent store below
# (bytes fffe,ffff) does not overlap.
_ADJACENT_BELOW = bytes.fromhex("8B EC C7 46 FE 00 00 FF 66 00")
# mov bp,sp; mov byte [bp-1],0; jmp word [bp] — byte at ffff, no overlap.
_ADJACENT_BYTE = bytes.fromhex("8B EC C6 46 FF 00 FF 66 00")
# mov bp,sp; sub bp,2; jmp word [bp+2] — tracked BP arithmetic still
# lands on the return word.
_BP_ARITH_ROUND_TRIP = bytes.fromhex("8B EC 83 ED 02 FF 66 02")
# mov bp,sp; xchg bp,sp; jmp word [bp] — deltas swap; BP keeps slot 0.
_XCHG_DELTA_SWAP = bytes.fromhex("8B EC 87 EC FF 66 00")
# mov bp,sp; sub sp,4; xchg bp,sp; jmp word [bp] — BP receives the moved
# SP delta, not the entry frame.
_XCHG_DELTA_BAD = bytes.fromhex("8B EC 83 EC 04 87 EC FF 66 00")
# pop bp; jmp bp — a slot-0 pop binds BP itself as the continuation.
_POP_BP = bytes.fromhex("5D FF E5")
# pop bp; jmp word [bp] — the same pop destroys BP's frame delta.
_POP_BP_FRAME_LOST = bytes.fromhex("5D FF 66 00")
# pushf; mov bp,sp; jmp word [bp+2] — 2-byte push admitted below slot 0.
_PUSHF_POSITIVE = bytes.fromhex("9C 8B EC FF 66 02")
# pushfd; mov bp,sp; jmp word [bp+4] — 4-byte push admitted.
_PUSHFD_POSITIVE = bytes.fromhex("66 9C 8B EC FF 66 04")
# pusha; mov bp,sp; jmp word [bp+16] — 16 bytes of frame stores admitted.
_PUSHA_POSITIVE = bytes.fromhex("60 8B EC FF 66 10")
# enter 4,0; jmp word [bp+2] — standard frame: return word above the
# pushed BP.
_ENTER_POSITIVE = bytes.fromhex("C8 04 00 00 FF 66 02")
# enter 0,2; jmp word [bp+2] — nonzero nesting copies enclosing frame
# words; the form is not admitted.
_ENTER_NESTED = bytes.fromhex("C8 00 00 02 FF 66 02")
# pop cx; <0x66-prefixed leave>; jmp cx — wide leave is not admitted.
_WIDE_LEAVE = bytes.fromhex("59 66 C9 FF E1")
# pop cx; popa; jmp cx — popa reloads every GPR, clearing provenance.
_POPA_CLEARS = bytes.fromhex("59 61 FF E1")
# mov bp,sp; mov al,[bp]; jmp ax — a byte load never binds a word.
_BYTE_LOAD = bytes.fromhex("8B EC 8A 46 00 FF E0")
# mov bp,sp; mov eax,[bp]; jmp ax — dword load's low word is the
# continuation; the 16-bit target is bound.
_WIDE_LOAD = bytes.fromhex("8B EC 66 8B 46 00 FF E0")
# pop cx; push ax; jmp cx — the loaded register value survives a later
# overwrite of its former slot.
_VALUE_SURVIVES_STORE = bytes.fromhex("59 50 FF E1")
# mov bp,sp; lea bp,[bp-2]; jmp word [bp+2] — lea computes a tracked delta.
_LEA_DELTA = bytes.fromhex("8B EC 8D 6E FE FF 66 02")


def _project(code: bytes, *, entry: int = _ENTRY) -> angr.Project:
    """Build one blob project carrying ``code`` at ``entry``."""
    end = entry + len(code)
    image = bytearray(end - _BASE)
    image[entry - _BASE : end - _BASE] = code
    return angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": _BASE, "entry_point": entry,
        },
        auto_load_libs=False,
        simos="DOS",
    )


def _end(code: bytes, entry: int = _ENTRY) -> int:
    """Return the byte-exclusive region end for one fixture."""
    return entry + len(code)


def _reachability(project: angr.Project, code: bytes) -> object:
    """Collect the staged census for one fixture."""
    return reach_mod.collect_instruction_reachability_8616(
        project,
        entry=_ENTRY,
        region_start=_ENTRY,
        region_end=_end(code),
    )


def _prove(
    project: angr.Project, code: bytes, premise: object = _PREMISE,
) -> object:
    """Run the owned proof over the staged decoded census."""
    reachability = _reachability(project, code)
    return nrc.prove_near_return_continuations_8616(
        reachability.blocks,
        reachability.successor_edges,
        entry=_ENTRY,
        premise=premise,
    )


def _boundary(
    project: angr.Project, code: bytes, premise: object = _PREMISE,
) -> object | None:
    """Close the staged boundary, tolerating the baseline signature gap."""
    try:
        return boundary_mod.exact_function_range_boundary_8616(
            project, _ENTRY, _end(code), premise=premise
        )
    except TypeError:
        return None


def _mapped_boundary(project: angr.Project, premise: object = _PREMISE) -> object | None:
    """Close the staged mapped-entry boundary under the callsite premise."""
    try:
        return boundary_mod.mapped_entry_function_boundary_8616(
            project, _ENTRY, premise=premise
        )
    except TypeError:
        return None


def _record(artifact: object, block_addr: int) -> object:
    """Return the single record for one candidate block."""
    records = [r for r in artifact.records if r.block_addr == block_addr]
    assert len(records) == 1
    return records[0]


def test_positive_register_form_proves() -> None:
    """pop/copy/adjust/jmp through the continuation register is closed."""
    project = _project(_POSITIVE)
    artifact = _prove(project, _POSITIVE)
    assert artifact.complete
    record = _record(artifact, _ENTRY)
    assert record.verdict is _PROVEN
    assert record.kind is _KIND.REGISTER
    assert record.register == "cx"
    assert artifact.proven_block_addrs == frozenset({_ENTRY})


def test_mov_and_xchg_chains_preserve_continuation() -> None:
    """Provenance survives mov and xchg through an intermediate register."""
    for code in (_MOV_CHAIN, _XCHG_CHAIN):
        project = _project(code)
        artifact = _prove(project, code)
        assert artifact.complete, code.hex()
        record = _record(artifact, _ENTRY)
        assert record.verdict is _PROVEN
        assert record.kind is _KIND.REGISTER


def test_memory_form_proves() -> None:
    """jmp [ss:bp+delta] over the unmutated top slot proves a return."""
    project = _project(_MEM_POSITIVE)
    artifact = _prove(project, _MEM_POSITIVE)
    assert artifact.complete
    record = _record(artifact, _ENTRY)
    assert record.verdict is _PROVEN
    assert record.kind is _KIND.STACK_SLOT


@pytest.mark.parametrize(
    ("code", "candidate_addr", "failure"),
    [
        (_MEM_WRONG_SLOT, _ENTRY, _FAIL.MEMORY_FORM_UNPROVED),
        (_MEM_MUTATED, _ENTRY, _FAIL.CONTINUATION_MUTATED),
        (_REG_MUTATED, _ENTRY, _FAIL.CONTINUATION_NOT_BOUND),
        (_WRONG_REG, _ENTRY, _FAIL.CONTINUATION_NOT_BOUND),
        (_RELOAD, _ENTRY, _FAIL.CONTINUATION_NOT_BOUND),
        (_CS_CLOBBER, _ENTRY, _FAIL.CS_CLOBBERED_ON_PATH),
        (_CALL_TAIL, 0x1104, _FAIL.CALL_ON_PATH),
    ],
)
def test_corruption_controls_refuse(
    code: bytes, candidate_addr: int, failure: object,
) -> None:
    """Every tampered path keeps its typed refusal, never a proof."""
    project = _project(code)
    artifact = _prove(project, code)
    assert not artifact.complete
    record = _record(artifact, candidate_addr)
    assert record.verdict is _REFUSED
    assert record.failure is failure


def test_missing_premise_refuses() -> None:
    """Without the caller-supplied premise nothing is proven."""
    project = _project(_POSITIVE)
    artifact = _prove(project, _POSITIVE, premise=None)
    assert not artifact.complete
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.PREMISE_ABSENT


def test_error_tail_stays_refused() -> None:
    """A proven normal path never discharges an unproven sibling tail."""
    project = _project(_ERROR_TAIL)
    artifact = _prove(project, _ERROR_TAIL)
    assert not artifact.complete
    normal = _record(artifact, 0x1104)
    tail = _record(artifact, 0x1110)
    assert normal.verdict is _PROVEN
    assert tail.verdict is _REFUSED
    assert tail.failure is _FAIL.CONTINUATION_NOT_BOUND
    boundary = _boundary(project, _ERROR_TAIL)
    assert boundary is None


def test_positive_boundary_closes_under_premise() -> None:
    """The premise closes the census; no premise keeps the refusal."""
    project = _project(_POSITIVE)
    boundary = _boundary(project, _POSITIVE)
    assert boundary is not None
    continuations = boundary.near_return_continuations
    assert continuations is not None and continuations.complete
    assert continuations.proven_block_addrs == frozenset({_ENTRY})
    assert _ENTRY in boundary.block_addrs_set
    # The identical range without the premise must stay refused.
    assert boundary_mod.exact_function_range_boundary_8616(
        project, _ENTRY, _end(_POSITIVE)
    ) is None


def test_mapped_entry_boundary_under_premise() -> None:
    """The callsite fallback closes the same boundary via image bounds."""
    project = _project(_POSITIVE)
    boundary = _mapped_boundary(project)
    assert boundary is not None
    assert boundary.addr == _ENTRY
    continuations = boundary.near_return_continuations
    assert continuations is not None and continuations.complete
    assert _mapped_boundary(project, premise=None) is None


def _install_test_source(
    project: angr.Project, index: DecodedDirectCallsiteIndex8616,
) -> None:
    """Install the typed invocation source carrying the synthetic index."""
    edcp.install_real16_invocation_source_8616(
        project,
        edcp.Real16InvocationSource8616(
            boot=object(),
            boot_recompute=None,
            callsite_index=index,
        ),
    )


def _pending_callee(project: angr.Project) -> object:
    """Resolve the premise-derived callee through the real resolver."""
    row = _callsite_row(_ENTRY)
    _install_test_source(project, _callsite_index(row, _ENTRY))
    try:
        resolved = edcp._callee_artifact_and_boundary_8616(project, _ENTRY)
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
    assert resolved is not None
    artifact, boundary = resolved
    return artifact, boundary


def test_bare_enum_premise_refuses() -> None:
    """An unbound enum is never accepted as frame-premise authority."""
    project = _project(_POSITIVE)
    artifact = _prove(
        project,
        _POSITIVE,
        premise=nrc.EntryTopSlotKind8616.NEAR_CALL_CONTINUATION,
    )
    assert not artifact.complete
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.PREMISE_ABSENT


def test_foreign_premise_refuses() -> None:
    """A premise bound to another callee head is foreign authority."""
    project = _project(_POSITIVE)
    artifact = _prove(project, _POSITIVE, premise=_premise(_ENTRY + 0x40))
    assert not artifact.complete
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.PREMISE_FOREIGN


def test_stale_premise_index_refuses() -> None:
    """A rebuilt index no longer authenticates the identical row."""
    row = _callsite_row(_ENTRY)
    foreign_index = _callsite_index(_callsite_row(_ENTRY), _ENTRY)
    premise = nrc.NearCallFramePremise8616(
        kind=nrc.EntryTopSlotKind8616.NEAR_CALL_CONTINUATION,
        callsite=row,
        callsite_index=foreign_index,
        callee_addr=_ENTRY,
        callsite_addr=_CALLSITE_ADDR,
        caller_start=_CALLER_START,
        return_addr=_CALLSITE_ADDR + _CALL_SIZE,
    )
    assert nrc.near_call_frame_premise_stale_8616(premise)
    project = _project(_POSITIVE)
    artifact = _prove(project, _POSITIVE, premise=premise)
    assert not artifact.complete
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.PREMISE_STALE


def test_wide_near_call_premise_refuses() -> None:
    """A decoded ``66 E8`` near CALL pushes a dword; no word premise."""
    row = _wide_callsite_row(_ENTRY)
    premise = nrc.prove_near_call_frame_premise_8616(
        row, _callsite_index(row, _ENTRY), _ENTRY
    )
    assert premise is None


def test_undecoded_width_row_refuses_premise() -> None:
    """An address/size-only row carries no width proof and refuses."""
    row = DecodedDirectCallsite8616(
        caller_start=_CALLER_START,
        instructions=(
            _UndecodedCallsiteInstruction(_CALLSITE_ADDR, _CALL_SIZE),
        ),
        instruction_index=0,
        callsite_addr=_CALLSITE_ADDR,
        target_addr=_ENTRY,
    )
    premise = nrc.prove_near_call_frame_premise_8616(
        row, _callsite_index(row, _ENTRY), _ENTRY
    )
    assert premise is None


def test_noncall_row_refuses_premise() -> None:
    """A decoded near-JMP row pushes no return word; never a premise."""
    row = _noncall_row(_ENTRY)
    premise = nrc.prove_near_call_frame_premise_8616(
        row, _callsite_index(row, _ENTRY), _ENTRY
    )
    assert premise is None


def test_changed_width_premise_revokes() -> None:
    """A retained row whose instruction decodes wide revokes authority."""
    row = _wide_callsite_row(_ENTRY)
    premise = nrc.NearCallFramePremise8616(
        kind=nrc.EntryTopSlotKind8616.NEAR_CALL_CONTINUATION,
        callsite=row,
        callsite_index=_callsite_index(row, _ENTRY),
        callee_addr=_ENTRY,
        callsite_addr=_CALLSITE_ADDR,
        caller_start=_CALLER_START,
        return_addr=_CALLSITE_ADDR + _WIDE_CALL_SIZE,
    )
    assert nrc.near_call_frame_premise_stale_8616(premise)
    project = _project(_POSITIVE)
    artifact = _prove(project, _POSITIVE, premise=premise)
    assert not artifact.complete
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.PREMISE_STALE


def test_undecoded_width_premise_revokes() -> None:
    """A premise whose row lost decoded width evidence is revoked."""
    row = DecodedDirectCallsite8616(
        caller_start=_CALLER_START,
        instructions=(
            _UndecodedCallsiteInstruction(_CALLSITE_ADDR, _CALL_SIZE),
        ),
        instruction_index=0,
        callsite_addr=_CALLSITE_ADDR,
        target_addr=_ENTRY,
    )
    premise = nrc.NearCallFramePremise8616(
        kind=nrc.EntryTopSlotKind8616.NEAR_CALL_CONTINUATION,
        callsite=row,
        callsite_index=_callsite_index(row, _ENTRY),
        callee_addr=_ENTRY,
        callsite_addr=_CALLSITE_ADDR,
        caller_start=_CALLER_START,
        return_addr=_CALLSITE_ADDR + _CALL_SIZE,
    )
    assert nrc.near_call_frame_premise_stale_8616(premise)


def test_ir_import_retains_jump_with_pending_marker() -> None:
    """The conditional artifact keeps raw JMP plus the pending refusal."""
    project = _project(_POSITIVE)
    boundary = _boundary(project, _POSITIVE)
    assert boundary is not None
    artifact = vex_import.build_x86_16_ir_function_artifact(project, boundary)
    block = next(b for b in artifact.blocks if b.addr == _ENTRY)
    terminal = block.instrs[-1]
    assert terminal.op == "JMP"
    kinds = [refusal.kind for refusal in block.refusals]
    assert kinds == [_PENDING_KIND]
    assert artifact.refusals


def test_pending_artifact_publication_refuses() -> None:
    """Universal publication can never accept conditional evidence."""
    project = _project(_POSITIVE)
    boundary = _boundary(project, _POSITIVE)
    assert boundary is not None
    artifact = vex_import.build_x86_16_ir_function_artifact(project, boundary)
    verdict = publish_function_ir_artifact_8616(project, artifact)
    assert verdict.verdict is not FunctionIRArtifactVerdict8616.PROVEN
    assert verdict.artifact is None
    resolution = registered_function_ir_artifact_8616(project, _ENTRY)
    assert resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN


def test_pending_artifact_universal_coverage_refuses() -> None:
    """Universal coverage can never certify conditional evidence."""
    project = _project(_POSITIVE)
    boundary = _boundary(project, _POSITIVE)
    assert boundary is not None
    artifact = vex_import.build_x86_16_ir_function_artifact(project, boundary)
    coverage = ibc.prove_ir_boundary_coverage_8616(project, boundary, artifact)
    assert coverage.failure is not None
    assert not coverage.complete
    assert not coverage.complete_for(None)


def test_callee_resolution_binds_pending_not_published() -> None:
    """Premise-derived callee artifacts bind in-flight, never registered."""
    project = _project(_POSITIVE)
    artifact, boundary = _pending_callee(project)
    block = next(b for b in artifact.blocks if b.addr == _ENTRY)
    assert block.instrs[-1].op == "JMP"
    assert any(
        refusal.kind == _PENDING_KIND for refusal in block.refusals
    )
    continuations = boundary.near_return_continuations
    assert continuations is not None
    assert type(continuations.premise) is nrc.NearCallFramePremise8616
    resolution = registered_function_ir_artifact_8616(project, _ENTRY)
    assert resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN


def test_callee_route_refuses_pending_universal() -> None:
    """An unregistered conditional callee never enters universal coverage."""
    project = _project(_POSITIVE)
    row = _callsite_row(_ENTRY)
    _install_test_source(project, _callsite_index(row, _ENTRY))
    try:
        closure, refusal = edcp._callee_closure_8616(
            project, _ENTRY, edcp._CalleeResolution8616(resolver=lambda i: None),
        )
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
    assert closure is None
    assert refusal is edcp.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE


def test_callee_resolution_refuses_corruption() -> None:
    """Corrupted variants keep CALLEE_UNRESOLVED through the same route."""
    for code in (_WRONG_REG, _CS_CLOBBER, _CALL_TAIL, _ERROR_TAIL):
        project = _project(code)
        row = _callsite_row(_ENTRY)
        _install_test_source(project, _callsite_index(row, _ENTRY))
        try:
            assert edcp._callee_artifact_and_boundary_8616(project, _ENTRY) is None
        finally:
            edcp.install_real16_invocation_source_8616(project, None)


def test_parent_counterexamples_refuse() -> None:
    """Every parent-decoded counterexample keeps a typed refusal."""
    cases = [
        (_OVERLAP_HIGH, _FAIL.CONTINUATION_MUTATED),
        (_OVERLAP_LOW, _FAIL.CONTINUATION_MUTATED),
        (_WIDE_REG_TARGET, _FAIL.WIDTH_UNADMITTED),
        (_BP_DELTA_MOVED, _FAIL.MEMORY_FORM_UNPROVED),
    ]
    for code, failure in cases:
        project = _project(code)
        artifact = _prove(project, code)
        assert not artifact.complete, code.hex()
        record = _record(artifact, _ENTRY)
        assert record.verdict is _REFUSED, code.hex()
        assert record.failure is failure, code.hex()


@pytest.mark.parametrize(
    "code",
    [
        _OVERLAP_HIGH,
        _OVERLAP_LOW,
        _OVERLAP_ABOVE,
        _OVERLAP_ALU,
        _OVERLAP_WIDE_STORE,
    ],
)
def test_return_word_overlap_mutates(code: bytes) -> None:
    """Any store whose byte range meets ``SS:[0:2]`` poisons the slot."""
    project = _project(code)
    artifact = _prove(project, code)
    assert not artifact.complete, code.hex()
    record = _record(artifact, _ENTRY)
    assert record.verdict is _REFUSED
    assert record.failure is _FAIL.CONTINUATION_MUTATED


@pytest.mark.parametrize(
    "code",
    [_ADJACENT_ABOVE, _ADJACENT_BELOW, _ADJACENT_BYTE],
)
def test_adjacent_non_overlapping_store_keeps_proof(code: bytes) -> None:
    """Stores outside ``SS:[0:2]`` — including wrapped offsets — prove."""
    project = _project(code)
    artifact = _prove(project, code)
    assert artifact.complete, code.hex()
    record = _record(artifact, _ENTRY)
    assert record.verdict is _PROVEN


@pytest.mark.parametrize(
    "code",
    [_WIDE_REG_TARGET, _WIDE_MEM_TARGET, _WIDE_LEAVE],
)
def test_unadmitted_widths_refuse(code: bytes) -> None:
    """Operand-size-overridden targets and stack forms stay refused."""
    project = _project(code)
    artifact = _prove(project, code)
    assert not artifact.complete, code.hex()
    record = _record(artifact, _ENTRY)
    assert record.verdict is _REFUSED
    assert record.failure is _FAIL.WIDTH_UNADMITTED


@pytest.mark.parametrize(
    "code",
    [_BP_DELTA_MOVED, _BP_DELTA_LOST, _SP_DELTA_LOST, _WIDE_POP, _XCHG_DELTA_BAD, _POP_BP_FRAME_LOST, _POPA_CLEARS, _BYTE_LOAD],
)
def test_untracked_pointer_and_binding_forms_refuse(code: bytes) -> None:
    """Moved/lost stack deltas and unbound operands never prove."""
    project = _project(code)
    artifact = _prove(project, code)
    assert not artifact.complete, code.hex()
    record = _record(artifact, _ENTRY)
    assert record.verdict is _REFUSED, code.hex()


def test_bp_delta_moved_reports_unproved_memory_form() -> None:
    """add bp,1 moves the tracked slot so the terminal is unproved."""
    project = _project(_BP_DELTA_MOVED)
    artifact = _prove(project, _BP_DELTA_MOVED)
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.MEMORY_FORM_UNPROVED


def test_xor_bp_and_mov_sp_lose_deltas() -> None:
    """Unmodeled BP/SP writes invalidate the tracked deltas."""
    for code in (_BP_DELTA_LOST, _XCHG_DELTA_BAD, _POP_BP_FRAME_LOST):
        project = _project(code)
        artifact = _prove(project, code)
        record = _record(artifact, _ENTRY)
        assert record.failure is _FAIL.MEMORY_FORM_UNPROVED, code.hex()
    project = _project(_SP_DELTA_LOST)
    record = _record(_prove(project, _SP_DELTA_LOST), _ENTRY)
    assert record.failure is _FAIL.CONTINUATION_NOT_BOUND


def test_nested_enter_is_an_unadmitted_effect() -> None:
    """enter with a nonzero nesting level refuses as an unknown effect."""
    project = _project(_ENTER_NESTED)
    artifact = _prove(project, _ENTER_NESTED)
    assert not artifact.complete
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.UNKNOWN_EFFECT_ON_PATH


def test_wide_pop_does_not_bind() -> None:
    """pop ecx advances SP four bytes and binds no 16-bit carrier."""
    project = _project(_WIDE_POP)
    artifact = _prove(project, _WIDE_POP)
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.CONTINUATION_NOT_BOUND


def test_byte_load_does_not_bind() -> None:
    """mov al,[bp] loads only the low byte; jmp ax refuses."""
    project = _project(_BYTE_LOAD)
    artifact = _prove(project, _BYTE_LOAD)
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.CONTINUATION_NOT_BOUND


def test_popa_clears_register_provenance() -> None:
    """popa reloads every GPR; the continuation binding is lost."""
    project = _project(_POPA_CLEARS)
    artifact = _prove(project, _POPA_CLEARS)
    record = _record(artifact, _ENTRY)
    assert record.failure is _FAIL.CONTINUATION_NOT_BOUND


@pytest.mark.parametrize(
    "code",
    [
        _BP_ARITH_ROUND_TRIP,
        _XCHG_DELTA_SWAP,
        _POP_BP,
        _PUSHF_POSITIVE,
        _PUSHFD_POSITIVE,
        _PUSHA_POSITIVE,
        _ENTER_POSITIVE,
        _WIDE_LOAD,
        _VALUE_SURVIVES_STORE,
        _LEA_DELTA,
    ],
)
def test_width_and_delta_positives_prove(code: bytes) -> None:
    """Admitted widths and tracked deltas still close the proof."""
    project = _project(code)
    artifact = _prove(project, code)
    assert artifact.complete, code.hex()
    record = _record(artifact, _ENTRY)
    assert record.verdict is _PROVEN, code.hex()


# ---------------------------------------------------------------------------
# Real-MZ scoped transport: caller-derived premise through closure
# ---------------------------------------------------------------------------

from dataclasses import replace
from functools import partial

from inertia.ir.ir_boundary_cfg import (
    prove_scoped_ir_boundary_coverage_8616,
)

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    build_boundary_direct_callsite_index_8616,
)
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from inertia.cli.project_loading import _build_project
from tools.dosunit.runtime.real16_program_boot import (
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.runtime.real16_replay_model import LinearRange

# The MZ world: CALLER is the MZ entry whose one decoded near-CALL row
# targets CALLEE; CALLEE is the unregistered premise-derived body ending
# in ``jmp cx``. Every object the scope authenticates — the registered
# caller artifact, the retained index row, the pending callee pair — is
# produced by the real pipeline, never fabricated by the test.
_MZ_SEGMENT = 0x1000
_MZ_BASE = _MZ_SEGMENT << 4
_MZ_CALLER = _MZ_BASE + 0x20
_MZ_CALLEE = _MZ_BASE + 0x60
_MZ_JMP_HEAD = _MZ_CALLEE + 7
_MZ_CALLER_CODE = (
    b"\xe8"
    + ((_MZ_CALLEE - (_MZ_CALLER + 3)) & 0xFFFF).to_bytes(2, "little")
    + b"\xc3"
)
_MZ_CALLEE_CODE = _POSITIVE
_MZ_RANGES = (
    LinearRange(_MZ_CALLER, len(_MZ_CALLER_CODE)),
    LinearRange(_MZ_CALLEE, len(_MZ_CALLEE_CODE)),
)


def _mz_image() -> bytes:
    """Lay out the caller and callee islands inside one module image."""
    image = b""
    cursor = _MZ_BASE
    for address, code in (
        (_MZ_CALLER, _MZ_CALLER_CODE),
        (_MZ_CALLEE, _MZ_CALLEE_CODE),
    ):
        assert address >= cursor
        image += bytes(address - cursor) + code
        cursor = address + len(code)
    return image


def _mz_exe(image: bytes, entry_ip: int) -> bytes:
    """Emit a deterministic MZ wrapper around the module image."""
    header_size = 2 * 16
    exe_size = header_size + len(image)
    nblocks = (exe_size + 511) // 512
    lastsize = exe_size % 512
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = nblocks.to_bytes(2, "little")
    header[0x08:0x0A] = (2).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x00).to_bytes(2, "little")
    header[0x0C:0x0E] = (0x40).to_bytes(2, "little")
    header[0x0E:0x10] = (0x10).to_bytes(2, "little")
    header[0x10:0x12] = (0x100).to_bytes(2, "little")
    header[0x14:0x16] = entry_ip.to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    return bytes(header) + image


def _mz_boot_recompute(boot: object) -> object:
    """Recompute an equal boot object from the retained source bytes."""
    return program_from_mz_bytes(
        boot.source, boot.environment, code_ranges=boot.image.code_ranges
    )


def _mz_world(tmp_path: Path) -> tuple[object, angr.Project]:
    """Build the authentic ProgramBoot and project for the MZ fixture."""
    image = _mz_image()
    mz = _mz_exe(image, _MZ_CALLER - _MZ_BASE)
    env = ProgramEnvironment(
        psp_segment=_MZ_SEGMENT - 0x10,
        allocation=bytes(0x400),
        registers=tuple(
            (name, 0)
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                "eflags",
            )
        ),
        fs=0,
        gs=0,
    )
    boot = program_from_mz_bytes(mz, env, code_ranges=_MZ_RANGES)
    fixture = tmp_path / "near_return.exe"
    fixture.write_bytes(mz)
    project = _build_project(
        fixture, force_blob=False, base_addr=_MZ_BASE, entry_point=_MZ_CALLER
    )
    return boot, project


def _mz_resolver(project: angr.Project) -> object:
    """Return the shared decoded direct-target resolver for one project."""
    return partial(resolve_direct_call_target_from_instruction_8616, project)


def _mz_caller_surface(
    project: angr.Project,
) -> tuple[object, object, object]:
    """Register the caller and retain its decoded callsite index."""
    caller_boundary = boundary_mod.mapped_entry_function_boundary_8616(
        project, _MZ_CALLER
    )
    assert caller_boundary is not None
    caller_artifact = vex_import.build_x86_16_ir_function_artifact(
        project, caller_boundary
    )
    verdict = publish_function_ir_artifact_8616(project, caller_artifact)
    assert verdict.verdict is FunctionIRArtifactVerdict8616.PROVEN
    index = build_boundary_direct_callsite_index_8616(
        caller_boundary, direct_target_resolver=_mz_resolver(project)
    )
    return caller_boundary, caller_artifact, index


def _mz_pending_callee(
    project: angr.Project, boot: object,
) -> tuple[object, object]:
    """Resolve the pending callee through the real source-bound route."""
    _caller_boundary, _caller_artifact, index = _mz_caller_surface(project)
    edcp.install_real16_invocation_source_8616(
        project,
        edcp.Real16InvocationSource8616(
            boot=boot,
            boot_recompute=_mz_boot_recompute,
            callsite_index=index,
        ),
    )
    resolved = edcp._callee_artifact_and_boundary_8616(project, _MZ_CALLEE)
    assert resolved is not None
    return resolved


def test_scoped_callee_closure_under_bound_frame(tmp_path: Path) -> None:
    """The caller-derived premise discharges RET only under its own entry."""
    boot, project = _mz_world(tmp_path)
    try:
        artifact, boundary = _mz_pending_callee(project, boot)
        scope = edcp.entry_domain_invocation_premise_8616(
            project, artifact, boundary, _MZ_JMP_HEAD
        )
        assert scope is not None and scope.complete
        view = nrcv.prove_scoped_near_return_continuation_view_8616(
            artifact, boundary, invocation_scope=scope
        )
        assert view.failure is None
        assert view.source_artifact is artifact
        assert view.boundary is boundary
        # Context-free consumption stays refused; the bound entry exposes
        # the effective RET while the raw surface keeps JMP + pending.
        assert not view.complete
        assert view.cfg_projection_for(None) is None
        projection = view.cfg_projection_for(scope)
        assert projection is not None
        block = next(b for b in projection.blocks if b.addr == _MZ_CALLEE)
        assert block.instrs[-1].op == "RET"
        raw_block = next(b for b in artifact.blocks if b.addr == _MZ_CALLEE)
        assert raw_block.instrs[-1].op == "JMP"
        assert any(r.kind == _PENDING_KIND for r in raw_block.refusals)
        # Scoped coverage completes only under the bound entry.
        coverage = prove_scoped_ir_boundary_coverage_8616(
            project, boundary, artifact, view
        )
        assert coverage.scoped_view is view
        assert coverage.complete_for(scope)
        assert not coverage.complete
        assert not coverage.complete_for(None)
        # End to end: the scoped route closes the effect closure and the
        # state retains the identical conditional view.
        resolution = edcp._CalleeResolution8616(resolver=_mz_resolver(project))
        closure, refusal = edcp._callee_closure_8616(
            project, _MZ_CALLEE, resolution, invocation_scope=scope
        )
        assert refusal is None and closure is not None
        assert closure.complete_for(scope)
        assert not closure.complete
        state = closure.state
        assert state.source_artifact is artifact
        assert state.scoped_view is coverage.scoped_view or (
            type(state.scoped_view) is type(view)
            and state.scoped_view.source_artifact is artifact
        )
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_scoped_view_refuses_missing_scope(tmp_path: Path) -> None:
    """A conditional view without a typed consuming entry is refused."""
    boot, project = _mz_world(tmp_path)
    try:
        artifact, boundary = _mz_pending_callee(project, boot)
        view = nrcv.prove_scoped_near_return_continuation_view_8616(
            artifact, boundary, invocation_scope=None
        )
        assert view.failure is (
            nrcv.ScopedNearReturnContinuationViewFailure8616.SCOPE_ABSENT
        )
        assert not view.complete
        assert view.cfg_projection_for(None) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_scoped_view_refuses_foreign_surface_scope(tmp_path: Path) -> None:
    """A scope bound to a different artifact object owns nothing here."""
    boot, project = _mz_world(tmp_path)
    try:
        artifact, boundary = _mz_pending_callee(project, boot)
        # A fresh guarded census import is an equal but distinct artifact:
        # the chain minted over it cannot consume the held surface.
        from inertia.ir.real16_invocation_domain import (
            real16_native_census_import_8616,
        )

        foreign_artifact = real16_native_census_import_8616(project, boundary)
        assert foreign_artifact is not None and foreign_artifact is not artifact
        foreign_scope = edcp.entry_domain_invocation_premise_8616(
            project, foreign_artifact, boundary, _MZ_JMP_HEAD
        )
        assert foreign_scope is not None and foreign_scope.complete
        view = nrcv.prove_scoped_near_return_continuation_view_8616(
            artifact, boundary, invocation_scope=foreign_scope
        )
        assert view.failure is (
            nrcv.ScopedNearReturnContinuationViewFailure8616.SCOPE_UNBOUND
        )
        assert view.cfg_projection_for(foreign_scope) is None
        # And a real view stays refused for the foreign entry.
        real_scope = edcp.entry_domain_invocation_premise_8616(
            project, artifact, boundary, _MZ_JMP_HEAD
        )
        assert real_scope is not None and real_scope.complete
        real_view = nrcv.prove_scoped_near_return_continuation_view_8616(
            artifact, boundary, invocation_scope=real_scope
        )
        assert real_view.failure is None
        assert real_view.cfg_projection_for(foreign_scope) is None
        coverage = prove_scoped_ir_boundary_coverage_8616(
            project, boundary, artifact, real_view
        )
        assert coverage.complete_for(real_scope)
        assert not coverage.complete_for(foreign_scope)
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


@pytest.mark.parametrize("field,value", [
    ("raw_fact_count", 0),
    ("normalized_fact_count", 0),
    ("classified_fact_count", 0),
    ("materialized_count", 0),
    ("failure_count", 1),
])
def test_incomplete_view_ledger_cannot_authorize_projection(
    tmp_path: Path, field: str, value: int,
) -> None:
    """A mutated evidence ledger never authorizes scoped consumption."""
    boot, project = _mz_world(tmp_path)
    try:
        artifact, boundary = _mz_pending_callee(project, boot)
        scope = edcp.entry_domain_invocation_premise_8616(
            project, artifact, boundary, _MZ_JMP_HEAD
        )
        assert scope is not None and scope.complete
        view = nrcv.prove_scoped_near_return_continuation_view_8616(
            artifact, boundary, invocation_scope=scope
        )
        assert view.failure is None and view.complete_for(scope)
        incomplete = replace(view, **{field: value})
        assert incomplete.cfg_projection_for(scope) is None
        assert not incomplete.complete_for(scope)
        coverage = prove_scoped_ir_boundary_coverage_8616(
            project, boundary, artifact, incomplete
        )
        assert not coverage.complete_for(scope)
    finally:
        edcp.install_real16_invocation_source_8616(project, None)

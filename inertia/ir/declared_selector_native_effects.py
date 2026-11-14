# cython: language_level=3, infer_types=True
"""Typed per-row native effect classification over source-bound raw IR.

Layer: IR.

Responsibility: replace the opcode-table "implicit segment effect" guess
with the canonical ``scalar_instruction_effect_8616`` decision, applied
in the canonical census order owned by ``real16_invocation_domain``.
Only ``ORDINARY`` rows are segment-preserving; every other class is a
typed obligation the caller must route to its owner (store judging,
call-edge binding, control-transfer proof) or record as a refusal. This
module never proves transfer semantics, never authorizes preservation
for CALL/MEMORY/CONTROL rows, and never consumes names, rendered text,
or raw opcodes. Rows must already be source-bound by the canonical
fresh-import binding (``_scoped_native_failure_8616``); synthetic rows
exercise this classifier but can never satisfy a native census.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from .core import IRBlock, IRInstr, IRValue, MemSpace
from .scalar_instruction_effects import (
    ScalarInstructionClobber8616,
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
)
from .segment_state_transfer import SEGMENT_REGISTER_SET
import dataclasses
import operator


class NativeRowClass8616(StrEnum):
    """Typed per-row native-effect lane; only ORDINARY preserves segments."""

    ORDINARY = "ordinary"
    MEMORY_STORE = "memory_store"
    CONTROL = "control"
    CALL_EDGE = "call_edge"
    SEGMENT_WRITE = "segment_write"
    UNCLASSIFIED = "unclassified"


@dataclasses.dataclass(frozen=True, )
class NativeRowJudgement8616:
    """One classified bound row and its exact typed lane."""

    addr: int | None
    op: object
    row_class: NativeRowClass8616
    segment: object
    detail: object


@dataclasses.dataclass(frozen=True, )
class NativeSelectorBlock8616:
    """Sparse selector transfer rows emitted by the full native census visit.

    Exact block and instruction objects retain ownership. This projection is
    neither a preservation proof nor permission to skip full recording of
    STORE, fetch, control and call effects.
    """

    block: IRBlock
    rows: object
    record_rows: tuple[IRInstr, ...] = ()


@dataclasses.dataclass(frozen=True, )
class NativeEffectSurvey8616:
    """Closed per-instruction survey with five-stage accounting."""

    judgements: object
    instruction_addrs: object
    expected_addrs: object
    census_covered: bool | None
    raw: cython.longlong
    classified: cython.longlong
    unclassified: cython.longlong
    segment_writes: cython.longlong
    selector_blocks: tuple[NativeSelectorBlock8616, ...] = ()
    segment_identity_transfer: cython.bint = False


@cython.ccall
def classify_native_row_8616(instruction: IRInstr) -> NativeRowJudgement8616:
    """Classify one bound IR row in the canonical census order.

    Segment-named destinations are caught before any op lane, matching
    ``_writes_segment_register_8616`` precedence, so a decorated or
    oddly-shaped write still exposes its segment target. CALL, control
    and memory rows are obligations routed to their owners; only a
    closed scalar destination or bound no-effect mark is ORDINARY.
    """
    addr = instruction.addr if type(instruction.addr) is int else None
    op = instruction.op if type(instruction.op) is str else "<foreign>"
    dst = instruction.dst
    if (
        isinstance(dst, IRValue)
        and dst.space is MemSpace.REG
        and dst.name in SEGMENT_REGISTER_SET
    ):
        return NativeRowJudgement8616(
            addr, op, NativeRowClass8616.SEGMENT_WRITE, dst.name, "segment_dst")
    if op == "CALL":
        return NativeRowJudgement8616(
            addr, op, NativeRowClass8616.CALL_EDGE, None, "call_lane")
    if op in ("CJMP", "JMP", "RET"):
        return NativeRowJudgement8616(
            addr, op, NativeRowClass8616.CONTROL, None, "control_lane")
    effect = scalar_instruction_effect_8616(instruction)
    if effect.kind is ScalarInstructionEffectKind8616.CLOSED_DESTINATION:
        return NativeRowJudgement8616(
            addr, op, NativeRowClass8616.ORDINARY, None, effect.detail)
    if effect.kind is ScalarInstructionEffectKind8616.NO_REGISTER_WRITE:
        if effect.clobber is ScalarInstructionClobber8616.MEMORY:
            return NativeRowJudgement8616(
                addr, op, NativeRowClass8616.MEMORY_STORE, None, effect.detail)
        if effect.clobber is ScalarInstructionClobber8616.NONE:
            return NativeRowJudgement8616(
                addr, op, NativeRowClass8616.ORDINARY, None, effect.detail)
    if effect.kind is ScalarInstructionEffectKind8616.INSTRUCTION_POINTER_WRITE:
        return NativeRowJudgement8616(
            addr, op, NativeRowClass8616.CONTROL, None, effect.detail)
    return NativeRowJudgement8616(
        addr, op, NativeRowClass8616.UNCLASSIFIED, None,
        effect.detail or op)


@cython.ccall
def _recording_row_required_8616(
    instruction: IRInstr, verdict: NativeRowJudgement8616, fetched: object,
) -> cython.bint:
    """Keep each native head and every potentially selector-visible effect."""
    address: object
    dst: object
    address = verdict.addr
    if address is None:
        return True
    first_fetch = address not in fetched
    fetched.add(address)
    dst = instruction.dst
    segment_named = dst is not None and dst.name in SEGMENT_REGISTER_SET
    return first_fetch or verdict.row_class is not NativeRowClass8616.ORDINARY or segment_named


def survey_native_effects_8616(
    blocks: Iterable[IRBlock],
    expected_addrs: Iterable[int] | None = None,
) -> NativeEffectSurvey8616:
    """Classify every row of source-bound blocks and check census coverage.

    ``expected_addrs`` is the authenticated decoded instruction census
    (e.g. the byte-bound ``machine`` keys or
    ``boundary.reachable_instruction_addrs``). Coverage is exact set
    equality: an unbound or non-integer row address never counts, and a
    decoded instruction with no classified row fails coverage loudly.
    """
    expected: object
    block: object
    instr: object
    judgements: list[NativeRowJudgement8616] = []
    addrs: set[cython.longlong] = set()
    selector_blocks: list[NativeSelectorBlock8616] = []
    identity_transfer = True
    relevant = frozenset({NativeRowClass8616.CALL_EDGE,
                          NativeRowClass8616.SEGMENT_WRITE,
                          NativeRowClass8616.UNCLASSIFIED})
    for block in blocks:
        selector_rows: list[IRInstr] = []
        record_rows: list[IRInstr] = []
        fetched: set[cython.longlong] = set()
        for instr in block.instrs:
            verdict = classify_native_row_8616(instr)
            identity_transfer = identity_transfer and (
                verdict.addr is not None and instr.op != "CALL_OUTPUT"
                and verdict.row_class not in relevant
                and (verdict.row_class is not NativeRowClass8616.CONTROL
                     or instr.op in ("CJMP", "JMP", "RET")))
            if verdict.addr is not None:
                addrs.add(verdict.addr)
            judgements.append(verdict)
            if verdict.row_class in relevant:
                selector_rows.append(instr)
            if _recording_row_required_8616(instr, verdict, fetched):
                record_rows.append(instr)
        selector_blocks.append(NativeSelectorBlock8616(
            block, tuple(selector_rows), tuple(record_rows)))
    expected = (
        None if expected_addrs is None
        else frozenset(a for a in iter(expected_addrs) if type(a) is int)
    )
    covered = None if expected is None else operator.eq(frozenset(addrs), expected)
    return NativeEffectSurvey8616(
        tuple(judgements), frozenset(addrs), expected, covered,
        len(judgements), len(judgements),
        sum(1 for v in iter(judgements) if v.row_class is NativeRowClass8616.UNCLASSIFIED),
        sum(1 for v in iter(judgements) if v.row_class is NativeRowClass8616.SEGMENT_WRITE),
        tuple(selector_blocks), identity_transfer,
    )

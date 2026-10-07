"""Prove a symbolic CS-relative near CALL target matches exact native bytes.

Layer: Semantics (staged candidate; promote to ``semantics/`` on acceptance).
Responsibility: bind the typed IR call-control operand of one block-terminal
CALL to the decoded E8 displacement and the authoritative callsite summary
target. The binding closes only when the retained operand DAG is exactly the
``control_coordinates.relative_continuation`` composition emitted by the
frontend lifter under the loader-linear control domain, the CALL carries
block-``next`` origin provenance, and the real mapped bytes at the callsite
decode to the summary target. Foreign provenance, tampered operands,
width-truncated control, a non-CS segment base, or differing bytes all
produce typed refusals; no constant is ever substituted into the IR operand.

The shared owner is ``DirectNearCallCoordinates8616``: one typed coordinate
triple (decoded callsite, native-evidence continuation, full-width target)
consumed by ``prove_direct_near_call_target_binding_at_coordinates_8616``.
``prove_direct_near_call_target_binding_8616`` remains the summary-facing
wrapper deriving coordinates from an actual ``CallsiteSummary8616``;
``prove_direct_near_call_target_binding_from_decoded_8616`` derives them
from a decoded direct-callsite index entry instead, so consumers never
fabricate an ABI summary to reach the same proof. An optional
``Real16InvocationDomain8616`` premise may discharge only the
selector-window obligation for one exact callsite under its proven CS
domain; the default all-fetch-windows bound is unchanged and always
authoritative when the premise is absent or insufficient.

Owns instruction effects, flags, branch meaning, and expression
interpretation. Do not perform alias-state ownership, widening,
lowering/materialization, structuring, rewrite, postprocess, or
CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

import angr
import pyvex

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.control_coordinates import ControlAddressDomain
from inertia.frontend.x86_16.frontend_direct_callsite_index import DecodedDirectCallsite8616
from inertia.frontend.x86_16.synthetic_call_stub_evidence import is_synthetic_call_stub_8616
from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace
from inertia.ir.instruction_origin import IRInstructionOrigin8616
from inertia.ir.real16_invocation_domain import (
    Real16CallInvocation8616,
    Real16InvocationDomain8616,
)
from inertia.semantics.callsite_summary import (
    CallsiteMachineFrameKind8616,
    CallsiteSummary8616,
    callsite_machine_frame_kind_8616,
)

from .direct_ret_call_effect import (
    direct_near_call_encoding_is_bound_8616,
    direct_near_call_target_is_bound_8616,
)

__all__ = [
    "DirectNearCallCoordinates8616",
    "DirectNearCallTargetBinding8616",
    "DirectNearCallTargetBindingFailure8616",
    "DirectNearCallTargetBindingStats8616",
    "DirectNearCallTargetBindingVerdict8616",
    "DirectNearCallTargetShape8616",
    "prove_declared_direct_near_call_target_binding_at_coordinates_8616",
    "prove_direct_near_call_target_binding_8616",
    "prove_direct_near_call_target_binding_at_coordinates_8616",
    "prove_direct_near_call_target_binding_from_decoded_8616",
]

_MAX_ALIAS_DEPTH_8616 = 16
_CS_SEGMENT_REGISTER_8616 = "cs"


class _TargetBindingKind8616(StrEnum):
    """Separate native target identity from synthetic behavior authority."""

    REAL_BODY = "real_body"
    DECLARED_STUB = "declared_stub"


class DirectNearCallTargetBindingVerdict8616(StrEnum):
    """Evidence result for one symbolic direct near CALL target."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class DirectNearCallTargetBindingFailure8616(StrEnum):
    """Typed reasons a symbolic call target cannot bind its summary target."""

    CALL_IDENTITY_MALFORMED = "call_identity_malformed"
    CALLSITE_MISMATCH = "callsite_mismatch"
    INSTRUCTION_NOT_IN_BLOCK = "instruction_not_in_block"
    FRAME_KIND_NOT_NEAR = "frame_kind_not_near"
    RETURN_ADDRESS_MISMATCH = "return_address_mismatch"
    TARGET_UNRESOLVED = "target_unresolved"
    TARGET_OPERAND_CONSTANT = "target_operand_constant"
    TARGET_OPERAND_MALFORMED = "target_operand_malformed"
    ORIGIN_MISSING = "origin_missing"
    ORIGIN_NOT_BLOCK_NEXT = "origin_not_block_next"
    ORIGIN_BLOCK_MISMATCH = "origin_block_mismatch"
    NEXT_TMP_MISMATCH = "next_tmp_mismatch"
    PRODUCER_LEDGER_AMBIGUOUS = "producer_ledger_ambiguous"
    SHAPE_MISMATCH = "shape_mismatch"
    SEGMENT_DOMAIN_MISMATCH = "segment_domain_mismatch"
    CONTROL_WIDTH_MISMATCH = "control_width_mismatch"
    NEXT_ADDRESS_MISMATCH = "next_address_mismatch"
    DISPLACEMENT_MISMATCH = "displacement_mismatch"
    TARGET_BYTES_MISMATCH = "target_bytes_mismatch"
    SELECTOR_WINDOW_UNPROVED = "selector_window_unproved"
    CONTROL_DOMAIN_UNPROVED = "control_domain_unproved"
    TERMINAL_POSITION_MISMATCH = "terminal_position_mismatch"
    NATIVE_TERMINAL_MISMATCH = "native_terminal_mismatch"
    DECODED_INSTRUCTION_MISSING = "decoded_instruction_missing"
    DECODED_ENCODING_MISMATCH = "decoded_encoding_mismatch"
    DECODED_TARGET_MISMATCH = "decoded_target_mismatch"


@dataclass(frozen=True, slots=True)
class DirectNearCallTargetShape8616:
    """Exact facts recovered from a matched relative-continuation operand DAG.

    ``next_linear_addr`` is the loader-linear continuation embedded as the
    ``Sub32`` constant; ``displacement`` is the masked 16-bit operand of the
    architectural ``Add16``; ``segment_register`` is the proven leaf used by
    both CS-composition sites; ``control_bits`` is the retained dword width.
    """

    segment_register: str
    next_linear_addr: int
    displacement: int
    control_bits: int

    def to_dict(self) -> dict[str, object]:
        """Serialize recovered shape facts for diagnostics and workers."""
        return {
            "segment_register": self.segment_register,
            "next_linear_addr": self.next_linear_addr,
            "displacement": self.displacement,
            "control_bits": self.control_bits,
        }


class _DecodedNativeCallsiteInstruction8616(Protocol):
    """Third-party decoded instruction surface consumed as native evidence."""

    address: int
    size: int
    bytes: bytes


@dataclass(frozen=True, slots=True)
class _DecodedInstructionEvidence8616:
    """Native facts extracted at the third-party instruction boundary."""

    address: int
    size: int
    encoding: bytes


@dataclass(frozen=True, slots=True)
class DirectNearCallCoordinates8616:
    """Exact callsite coordinates for one direct near CALL binding proof.

    ``callsite_addr`` is the linear address of the decoded call instruction,
    ``next_addr`` is the linear continuation the machine call returns to, and
    ``target_addr`` is the decoded full-width linear target. The contract
    carries no ABI claims; malformed coordinate facts raise at construction
    rather than being normalized into a guessed proof.
    """

    callsite_addr: int
    next_addr: int
    target_addr: int

    def __post_init__(self) -> None:
        """Reject malformed coordinates instead of repairing foreign facts."""
        values = (self.callsite_addr, self.next_addr, self.target_addr)
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("direct near-call coordinates require nonnegative integers")
        if self.next_addr <= self.callsite_addr:
            raise ValueError("direct near-call continuation must follow the callsite")

    def to_dict(self) -> dict[str, int]:
        """Serialize the coordinate triple for diagnostics and workers."""
        return {
            "callsite_addr": self.callsite_addr,
            "next_addr": self.next_addr,
            "target_addr": self.target_addr,
        }


@dataclass(frozen=True, slots=True)
class DirectNearCallTargetBindingStats8616:
    """Closed five-stage accounting for one evaluated CALL target."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether the candidate resolved to one proof or refusal."""
        counts = (self.raw_fact_count, self.normalized_fact_count, self.classified_fact_count,
                  self.materialized_count, self.failure_count)
        if not all(type(count) is int and count >= 0 for count in counts):
            return False
        return bool(
            self.raw_fact_count == self.normalized_fact_count == 1
            and self.normalized_fact_count
            == self.materialized_count + self.failure_count
        )

    def to_dict(self) -> dict[str, int]:
        """Serialize the evidence ledger for diagnostics."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class DirectNearCallTargetBinding8616:
    """Verdict and retained shape for one symbolic direct near CALL target.

    A PROVEN verdict asserts that the CALL's control operand is the frontend's
    own CS-relative continuation for the exact decoded E8 instruction at
    ``callsite_addr`` and denotes the authoritative summary ``target_addr``.
    """

    callsite_addr: int | None
    target_addr: int | None
    verdict: DirectNearCallTargetBindingVerdict8616
    failure: DirectNearCallTargetBindingFailure8616 | None
    stats: DirectNearCallTargetBindingStats8616
    shape: DirectNearCallTargetShape8616 | None = None
    invocation: Real16CallInvocation8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether the binding closed with one exact target proof."""
        return bool(
            self.verdict is DirectNearCallTargetBindingVerdict8616.PROVEN
            and self.failure is None
            and _retained_coordinate_facts_8616(self.callsite_addr, self.target_addr, self.shape)
            and _retained_selector_domain_8616(
                self.callsite_addr, self.target_addr, self.invocation
            )
            and self.stats
            == DirectNearCallTargetBindingStats8616(1, 1, 1, 1, 0)
            and self.stats.closed
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the binding result for diagnostics and workers."""
        return {
            "callsite_addr": self.callsite_addr,
            "target_addr": self.target_addr,
            "verdict": self.verdict.value,
            "failure": None if self.failure is None else self.failure.value,
            "stats": self.stats.to_dict(),
            "shape": None if self.shape is None else self.shape.to_dict(),
            "invocation": (
                None
                if self.invocation is None
                else self.invocation.premise.to_dict()
            ),
        }


def _refuse_8616(
    callsite_addr: int | None,
    target_addr: int | None,
    failure: DirectNearCallTargetBindingFailure8616,
    *,
    normalized: bool = False,
    classified: bool = False,
    shape: DirectNearCallTargetShape8616 | None = None,
) -> DirectNearCallTargetBinding8616:
    """Retain one refused binding obligation in the five-stage evidence count."""
    return DirectNearCallTargetBinding8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        verdict=DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
        stats=DirectNearCallTargetBindingStats8616(
            1, int(normalized), int(classified), 0, 1
        ),
        shape=shape,
    )


def _target_in_all_fetch_windows_8616(head: int, target: int) -> bool:
    """Require one target across every selector capable of fetching the head.

    This arithmetic is conditional on the native instruction-fetch coordinate
    premise. It does not manufacture a selector-domain receipt or establish
    that premise for an arbitrary SSA entry state.
    """
    minimum_selector = max(0, (head - 0xFFFF + 15) // 16)
    maximum_selector = min(0xFFFF, head // 16)
    return (minimum_selector <= maximum_selector
            and (maximum_selector << 4) <= target <= (minimum_selector << 4) + 0xFFFF)


def _retained_coordinate_facts_8616(
    callsite: int | None, target: int | None, shape: DirectNearCallTargetShape8616 | None,
) -> bool:
    """Recheck coordinate consistency when a retained result is consumed."""
    if type(callsite) is not int or type(target) is not int or shape is None:
        return False
    if callsite < 0 or target < 0:
        return False
    if not all(type(value) is int for value in (shape.control_bits, shape.next_linear_addr, shape.displacement)):
        return False
    if (shape.segment_register != _CS_SEGMENT_REGISTER_8616 or shape.control_bits != 32
            or shape.next_linear_addr != callsite + 3):
        return False
    return (0 <= shape.displacement <= 0xFFFF
            and target == shape.next_linear_addr + _signed16_8616(shape.displacement))


def _retained_selector_domain_8616(
    callsite: int | None,
    target: int | None,
    invocation: Real16CallInvocation8616 | None,
) -> bool:
    """Recheck the selector-window obligation when a result is consumed.

    The default all-fetch-windows bound is always authoritative. A bound
    ``Real16CallInvocation8616`` may additionally discharge the obligation
    for one exact callsite/target pair, and only after its premise and
    consumption binding replay completely.
    """
    if type(callsite) is not int or type(target) is not int:
        return False
    if _target_in_all_fetch_windows_8616(callsite, target):
        return True
    return bool(
        invocation is not None
        and invocation.callsite_addr == callsite
        and invocation.target_addr == target
        and invocation.complete
    )


def _native_terminal_failure_8616(
    project: object, block: IRBlock, origin: IRInstructionOrigin8616, callsite: int,
    next_addr: int,
) -> DirectNearCallTargetBindingFailure8616 | None:
    """Check native terminal identity in the active or architectural flag view.

    A raw caller can have been imported before function-CFG flag omission was
    enabled. That omission changes VEX statement/temporary numbers, not CALL
    identity. Retry at most once in the architectural view if an active context
    exists; both attempts retain exact origin coordinates and next-temporary
    checks. Never accept merely because the instruction addresses match.
    """
    if not isinstance(project, angr.Project) or not isinstance(project.arch, Arch86_16):
        return DirectNearCallTargetBindingFailure8616.CONTROL_DOMAIN_UNPROVED
    if project.arch.control_address_domain is not ControlAddressDomain.LOADER_LINEAR:
        return DirectNearCallTargetBindingFailure8616.CONTROL_DOMAIN_UNPROVED
    size = next_addr - block.addr
    if not 0 < size <= 4096:
        return DirectNearCallTargetBindingFailure8616.TERMINAL_POSITION_MISMATCH
    native = project.factory.block(block.addr, size=size, opt_level=0, collect_data_refs=True).vex
    failure = _native_terminal_identity_failure_8616(native, origin)
    if failure is None:
        return None
    from inertia.ir.status_flag_lift_context import architectural_status_flag_replay_8616

    with architectural_status_flag_replay_8616() as suspended:
        if not suspended:
            return failure
        native = project.factory.block(block.addr, size=size, opt_level=0, collect_data_refs=True).vex
    return _native_terminal_identity_failure_8616(native, origin)


def _native_terminal_identity_failure_8616(
    native: object, origin: IRInstructionOrigin8616,
) -> DirectNearCallTargetBindingFailure8616 | None:
    """Require the exact native terminal position and temporary in one view."""
    if not isinstance(native, pyvex.IRSB) or native.jumpkind != "Ijk_Call":
        return DirectNearCallTargetBindingFailure8616.NATIVE_TERMINAL_MISMATCH
    if type(origin.statement_index) is not int or origin.statement_index != len(native.statements):
        return DirectNearCallTargetBindingFailure8616.TERMINAL_POSITION_MISMATCH
    if not isinstance(native.next, pyvex.expr.RdTmp) or native.next.tmp != origin.block_next_tmp:
        return DirectNearCallTargetBindingFailure8616.NATIVE_TERMINAL_MISMATCH
    return None


def _tmp_producers_8616(
    block: IRBlock,
) -> dict[int, IRInstr] | None:
    """Index the block's typed temporary producers or refuse an ambiguous ledger.

    VEX temporaries are block-local; a duplicate destination identity would
    mean the IR no longer records one definition per temporary.
    """
    producers: dict[int, IRInstr] = {}
    for instruction in block.instrs:
        destination = instruction.dst
        if (
            destination is None
            or destination.space is not MemSpace.TMP
            or destination.source_tmp is None
        ):
            continue
        if destination.source_tmp in producers:
            return None
        producers[destination.source_tmp] = instruction
    return producers


def _tmp_producer_8616(
    producers: dict[int, IRInstr],
    value: IRValue,
) -> IRInstr | None:
    """Resolve one temporary-typed value to its unique producer instruction."""
    if value.source_tmp is None or value.active_unary is not None:
        return None
    return producers.get(value.source_tmp)


def _operand_8616(
    producers: dict[int, IRInstr],
    value: IRValue,
) -> IRInstr | IRValue | None:
    """Resolve one operand position to a producer instruction or a leaf value."""
    if value.active_unary is not None:
        return None
    if value.source_tmp is not None:
        return producers.get(value.source_tmp)
    if value.space in {MemSpace.REG, MemSpace.CONST}:
        return value
    return None


def _const_int_8616(value: IRValue, size: int) -> int | None:
    """Return the exact integer of one constant operand at a required width."""
    if (
        value.space is not MemSpace.CONST
        or type(value.const) is not int
        or value.size != size
    ):
        return None
    if (value.active_unary is not None or value.source_tmp is not None
            or value.expr or value.call_output is not None):
        return None
    if value.offset or value.index is not None or value.index_shift:
        return None
    return value.const


def _conversion_operand_8616(
    producers: dict[int, IRInstr],
    value: IRValue,
    conversion: str,
) -> IRInstr | IRValue | None:
    """Resolve a captured conversion result through its exact active computation."""
    widths = {"Iop_16Uto32": (2, 4), "Iop_32to16": (4, 2)}.get(conversion)
    if widths is None or value.expr != (conversion,) or value.active_unary is not None:
        return None
    producer = _tmp_producer_8616(producers, value)
    if producer is None or producer.op != "MOV" or len(producer.args) != 1:
        return None
    if value.size != widths[1] or producer.size != widths[1]:
        return None
    if (producer.dst is None or producer.dst.size != widths[1]
            or producer.dst.active_unary is not None):
        return None
    source = producer.args[0]
    if not isinstance(source, IRValue):
        return None
    inner = _active_conversion_source_8616(source, conversion)
    return None if inner is None else _operand_8616(producers, inner)


def _active_conversion_source_8616(value: IRValue, conversion: str) -> IRValue | None:
    """Validate one supported active conversion, including both exact widths."""
    widths = {"Iop_16Uto32": (2, 4), "Iop_32to16": (4, 2)}.get(conversion)
    active = value.active_unary
    if widths is None or active is None or value.source_tmp is not None:
        return None
    if (not _plain_register_coordinates_8616(value)
            or value.expr != (conversion,) or active.op != conversion):
        return None
    if (value.size != widths[1] or type(active.result_bits) is not int
            or active.result_bits != widths[1] * 8):
        return None
    if active.operand.size != widths[0] or active.operand.active_unary is not None:
        return None
    return active.operand


def _reg_leaf_name_8616(
    producers: dict[int, IRInstr],
    operand: IRInstr | IRValue,
    *,
    depth: int = 0,
) -> str | None:
    """Reduce temporary copies and conversions to one 16-bit register leaf."""
    if depth > _MAX_ALIAS_DEPTH_8616:
        return None
    if isinstance(operand, IRValue):
        return _reg_leaf_value_name_8616(producers, operand, depth=depth)
    return _reg_leaf_instr_name_8616(producers, operand, depth=depth)


def _plain_register_coordinates_8616(operand: IRValue) -> bool:
    """Reject arithmetic and access decorations before reducing a register leaf."""
    coordinates_plain = (
        type(operand.offset) is int and operand.offset == 0
        and type(operand.index_shift) is int and operand.index_shift == 0
    )
    annotations_empty = all(value is None for value in (
        operand.const, operand.version, operand.index, operand.memory_access_size,
        operand.memory_access_insn, operand.call_output,
    ))
    return coordinates_plain and annotations_empty


def _reg_leaf_value_name_8616(
    producers: dict[int, IRInstr],
    operand: IRValue,
    *,
    depth: int,
) -> str | None:
    """Reduce one register or conversion leaf value to its register name."""
    if (operand.space is not MemSpace.REG or not operand.name
            or not _plain_register_coordinates_8616(operand)
            or operand.expr not in (None, ("Iop_16Uto32",))):
        return None
    if operand.active_unary is not None:
        inner = _active_conversion_source_8616(operand, "Iop_16Uto32")
        return None if inner is None else _reg_leaf_name_8616(producers, inner, depth=depth + 1)
    if operand.source_tmp is not None:
        producer = _tmp_producer_8616(producers, operand)
        return None if producer is None else _reg_leaf_name_8616(producers, producer, depth=depth + 1)
    return operand.name if operand.expr is None and operand.size == 2 else None


def _reg_leaf_instr_name_8616(
    producers: dict[int, IRInstr],
    operand: IRInstr,
    *,
    depth: int,
) -> str | None:
    """Reduce one copy producer instruction to its 16-bit register leaf."""
    if operand.op != "MOV" or len(operand.args) != 1:
        return None
    arg = operand.args[0]
    if not isinstance(arg, IRValue):
        return None
    if (not _plain_register_coordinates_8616(arg)
            or arg.expr not in (None, ("Iop_16Uto32",))):
        return None
    if arg.active_unary is not None:
        inner = _active_conversion_source_8616(arg, "Iop_16Uto32")
        return None if inner is None else _reg_leaf_name_8616(producers, inner, depth=depth + 1)
    if arg.source_tmp is not None:
        node = producers.get(arg.source_tmp)
        if node is None:
            return None
        return _reg_leaf_name_8616(producers, node, depth=depth + 1)
    if (arg.space is MemSpace.REG and arg.name and arg.expr is None
            and arg.size == 2 and _plain_register_coordinates_8616(arg)):
        return arg.name
    return None


def _segment_base_name_8616(
    producers: dict[int, IRInstr],
    value: IRValue,
) -> str | None:
    """Match ``Shl32(16Uto32(seg), 4)`` and return the segment register name."""
    node = _tmp_producer_8616(producers, value)
    if node is None or node.op != "Iop_Shl32" or node.size != 4 or len(node.args) != 2:
        return None
    base_value, count_value = node.args
    if not isinstance(base_value, IRValue) or not isinstance(count_value, IRValue):
        return None
    if _const_int_8616(count_value, size=1) != 4:
        return None
    operand = _conversion_operand_8616(producers, base_value, "Iop_16Uto32")
    if operand is None:
        return None
    return _reg_leaf_name_8616(producers, operand)


def _match_relative_continuation_8616(
    producers: dict[int, IRInstr],
    target: IRValue,
) -> DirectNearCallTargetShape8616 | None:
    """Match the exact ``relative_continuation`` loader-linear composition.

    Required DAG, exactly as emitted by the corrected near-CALL lifter under
    ``ControlAddressDomain.LOADER_LINEAR``::

        Add32( Shl32(16Uto32(seg), 4),
               16Uto32( Add16( 32to16( Sub32( next_linear,
                                              Shl32(16Uto32(seg), 4) )),
                               disp16 ) ) )

    The outer sum must retain dword width; the only narrowing is the
    architectural 32to16 IP projection followed by the Add16 displacement.
    """
    if target.space is not MemSpace.TMP or target.size != 4:
        return None
    add = _tmp_producer_8616(producers, target)
    if add is None or add.op != "Iop_Add32" or add.size != 4 or len(add.args) != 2:
        return None
    left, right = add.args
    if not isinstance(left, IRValue) or not isinstance(right, IRValue):
        return None
    segment = _segment_base_name_8616(producers, left)
    widened = _conversion_operand_8616(producers, right, "Iop_16Uto32")
    if (
        not isinstance(widened, IRInstr)
        or widened.op != "Iop_Add16"
        or widened.size != 2
        or len(widened.args) != 2
    ):
        return None
    ip_base, displacement_value = widened.args
    if not isinstance(ip_base, IRValue) or not isinstance(displacement_value, IRValue):
        return None
    displacement = _const_int_8616(displacement_value, size=2)
    narrowed = _conversion_operand_8616(producers, ip_base, "Iop_32to16")
    if (
        not isinstance(narrowed, IRInstr)
        or narrowed.op != "Iop_Sub32"
        or narrowed.size != 4
        or len(narrowed.args) != 2
    ):
        return None
    next_value, second_base = narrowed.args
    if not isinstance(next_value, IRValue) or not isinstance(second_base, IRValue):
        return None
    next_linear = _const_int_8616(next_value, size=4)
    second_segment = _segment_base_name_8616(producers, second_base)
    if (
        segment is None
        or second_segment is None
        or segment != second_segment
        or next_linear is None
        or displacement is None
    ):
        return None
    return DirectNearCallTargetShape8616(
        segment_register=segment,
        next_linear_addr=next_linear,
        displacement=displacement,
        control_bits=target.size * 8,
    )


def _signed16_8616(value: int) -> int:
    """Interpret a 16-bit displacement with its explicit sign, never modulo."""
    return value - 0x10000 if value & 0x8000 else value


def _call_identity_8616(
    instruction: IRInstr,
    expected_callsite: int,
    refusal_target: int | None,
    block: IRBlock,
) -> int | DirectNearCallTargetBinding8616:
    """Verify CALL identity, callsite agreement, and block membership.

    Returns the proven loader-linear callsite address on success, or the
    typed refusal. ``CALL_IDENTITY_MALFORMED`` carries no callsite because a
    malformed instruction address is not trusted as a coordinate.
    """
    callsite_addr = instruction.addr
    if instruction.op != "CALL" or type(callsite_addr) is not int or callsite_addr < 0:
        return _refuse_8616(
            None, refusal_target,
            DirectNearCallTargetBindingFailure8616.CALL_IDENTITY_MALFORMED,
        )
    if expected_callsite != callsite_addr:
        return _refuse_8616(
            callsite_addr, refusal_target,
            DirectNearCallTargetBindingFailure8616.CALLSITE_MISMATCH,
        )
    if not any(item is instruction or item == instruction for item in block.instrs):
        return _refuse_8616(
            callsite_addr, refusal_target,
            DirectNearCallTargetBindingFailure8616.INSTRUCTION_NOT_IN_BLOCK,
        )
    return callsite_addr


def _summary_call_coordinates_8616(
    callsite_addr: int,
    summary: CallsiteSummary8616,
) -> DirectNearCallCoordinates8616 | DirectNearCallTargetBinding8616:
    """Derive binding coordinates from an authoritative callsite summary.

    The summary must be a NEAR frame whose return and target coordinates are
    exact; the continuation is the summary's own ``return_addr`` fact and is
    cross-checked against the word-E8 instruction length.
    """
    if callsite_machine_frame_kind_8616(summary) is not CallsiteMachineFrameKind8616.NEAR:
        return _refuse_8616(
            callsite_addr, summary.target_addr,
            DirectNearCallTargetBindingFailure8616.FRAME_KIND_NOT_NEAR,
            normalized=True,
        )
    next_addr = summary.return_addr
    if type(next_addr) is not int or next_addr != callsite_addr + 3:
        return _refuse_8616(
            callsite_addr, summary.target_addr,
            DirectNearCallTargetBindingFailure8616.RETURN_ADDRESS_MISMATCH,
            normalized=True,
        )
    target_addr = summary.target_addr
    if type(target_addr) is not int or target_addr < 0:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.TARGET_UNRESOLVED,
            normalized=True,
        )
    return DirectNearCallCoordinates8616(callsite_addr, next_addr, target_addr)


def _decoded_call_coordinates_8616(
    decoded: DecodedDirectCallsite8616,
) -> DirectNearCallCoordinates8616 | DirectNearCallTargetBinding8616:
    """Derive binding coordinates from a decoded direct-callsite index entry.

    The continuation and target come from the decoded instruction's own
    address, size, and encoding — the unprefixed word-E8 ``E8 rel16`` form —
    never from a summary or an assumed instruction length. Far entries,
    missing instruction surfaces, prefixed or non-E8 encodings, and decoded
    displacement/target disagreement each produce a typed refusal.
    """
    callsite_addr = decoded.callsite_addr
    target_addr = decoded.target_addr
    refusal_callsite = callsite_addr if type(callsite_addr) is int else None
    refusal_target = target_addr if type(target_addr) is int else None
    if decoded.is_far:
        return _refuse_8616(
            refusal_callsite, refusal_target,
            DirectNearCallTargetBindingFailure8616.FRAME_KIND_NOT_NEAR,
            normalized=True,
        )
    if type(callsite_addr) is not int or callsite_addr < 0:
        return _refuse_8616(
            None, refusal_target,
            DirectNearCallTargetBindingFailure8616.CALL_IDENTITY_MALFORMED,
        )
    if type(target_addr) is not int or target_addr < 0:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.TARGET_UNRESOLVED,
            normalized=True,
        )
    evidence = _decoded_entry_instruction_8616(decoded)
    if isinstance(evidence, DirectNearCallTargetBinding8616):
        return evidence
    if evidence.address != callsite_addr:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.CALLSITE_MISMATCH,
        )
    if evidence.size != 3 or len(evidence.encoding) != 3 or evidence.encoding[0] != 0xE8:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.DECODED_ENCODING_MISMATCH,
        )
    next_addr = evidence.address + evidence.size
    displacement = int.from_bytes(evidence.encoding[1:3], "little")
    if next_addr + _signed16_8616(displacement) != target_addr:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.DECODED_TARGET_MISMATCH,
            normalized=True,
            classified=True,
        )
    return DirectNearCallCoordinates8616(callsite_addr, next_addr, target_addr)


def _decoded_entry_instruction_8616(
    decoded: DecodedDirectCallsite8616,
) -> _DecodedInstructionEvidence8616 | DirectNearCallTargetBinding8616:
    """Extract the entry's native instruction facts with typed refusal."""
    callsite_addr = decoded.callsite_addr
    target_addr = decoded.target_addr
    refusal_callsite = callsite_addr if type(callsite_addr) is int else None
    refusal_target = target_addr if type(target_addr) is int else None
    try:
        instruction = (
            decoded.instructions[decoded.instruction_index]
            if type(decoded.instruction_index) is int
            and 0 <= decoded.instruction_index < len(decoded.instructions)
            else None
        )
    except (IndexError, TypeError):
        instruction = None
    if instruction is None:
        return _refuse_8616(
            refusal_callsite, refusal_target,
            DirectNearCallTargetBindingFailure8616.DECODED_INSTRUCTION_MISSING,
        )
    surface = cast(_DecodedNativeCallsiteInstruction8616, instruction)
    try:
        evidence = _DecodedInstructionEvidence8616(
            surface.address, surface.size, bytes(surface.bytes),
        )
    except (AttributeError, TypeError):
        return _refuse_8616(
            refusal_callsite, refusal_target,
            DirectNearCallTargetBindingFailure8616.DECODED_INSTRUCTION_MISSING,
        )
    if type(evidence.address) is not int or evidence.address < 0 or type(evidence.size) is not int:
        return _refuse_8616(
            refusal_callsite, refusal_target,
            DirectNearCallTargetBindingFailure8616.DECODED_INSTRUCTION_MISSING,
        )
    return evidence


def _control_operand_8616(
    callsite_addr: int,
    target_addr: int,
    instruction: IRInstr,
) -> IRValue | DirectNearCallTargetBinding8616:
    """Validate the typed control operand position for a symbolic binding.

    Returns the retained symbolic TMP of dword width carrying the
    ``Iop_Add32`` composition tag; constant or malformed operands refuse.
    """
    if len(instruction.args) != 1 or not isinstance(instruction.args[0], IRValue):
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.TARGET_OPERAND_MALFORMED,
            normalized=True,
        )
    target = instruction.args[0]
    if target.space is MemSpace.CONST:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.TARGET_OPERAND_CONSTANT,
            normalized=True,
        )
    if (
        target.space is not MemSpace.TMP
        or target.source_tmp is None
        or target.expr != ("Iop_Add32",)
        or target.size != 4
    ):
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.TARGET_OPERAND_MALFORMED,
            normalized=True,
        )
    return target


def _origin_provenance_8616(
    project: object,
    block: IRBlock,
    instruction: IRInstr,
    target: IRValue,
    coordinates: DirectNearCallCoordinates8616,
) -> IRInstructionOrigin8616 | DirectNearCallTargetBinding8616:
    """Prove retained block-``next`` origin provenance and native identity.

    The bounded native re-lift is a required premise of this binding: a
    foreign control domain, truncated fetch window, or mismatched terminal
    is refused rather than discharged as a selector-domain receipt.
    """
    callsite_addr = coordinates.callsite_addr
    target_addr = coordinates.target_addr
    origin = instruction.origin
    if origin is None or not isinstance(origin, IRInstructionOrigin8616):
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.ORIGIN_MISSING,
            normalized=True,
        )
    if origin.is_block_next is not True:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.ORIGIN_NOT_BLOCK_NEXT,
            normalized=True,
        )
    if type(origin.block_addr) is not int or origin.block_addr != block.addr:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.ORIGIN_BLOCK_MISMATCH,
            normalized=True,
        )
    if (
        type(origin.block_next_tmp) is not int
        or origin.block_next_tmp != target.source_tmp
    ):
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.NEXT_TMP_MISMATCH,
            normalized=True,
        )
    native_failure = _native_terminal_failure_8616(
        project, block, origin, callsite_addr, coordinates.next_addr,
    )
    if native_failure is not None:
        return _refuse_8616(callsite_addr, target_addr, native_failure, normalized=True)
    return origin


def _shape_coordinate_failure_8616(
    coordinates: DirectNearCallCoordinates8616,
    shape: DirectNearCallTargetShape8616,
) -> DirectNearCallTargetBinding8616 | None:
    """Compare the recovered operand shape against the bound coordinates.

    Every comparison is exact: the retained control width, the proven CS
    segment leaf, the embedded continuation constant, and the signed 16-bit
    displacement must each denote the authoritative callsite and target.
    """
    callsite_addr = coordinates.callsite_addr
    target_addr = coordinates.target_addr
    if shape.control_bits != 32:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.CONTROL_WIDTH_MISMATCH,
            normalized=True,
            classified=True,
        )
    if shape.segment_register != _CS_SEGMENT_REGISTER_8616:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.SEGMENT_DOMAIN_MISMATCH,
            normalized=True,
            classified=True,
            shape=shape,
        )
    if shape.next_linear_addr != coordinates.next_addr:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.NEXT_ADDRESS_MISMATCH,
            normalized=True,
            classified=True,
            shape=shape,
        )
    if target_addr != shape.next_linear_addr + _signed16_8616(shape.displacement):
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.DISPLACEMENT_MISMATCH,
            normalized=True,
            classified=True,
            shape=shape,
        )
    return None


def _bound_selector_invocation_8616(
    project: object,
    block: IRBlock,
    coordinates: DirectNearCallCoordinates8616,
    invocation: Real16InvocationDomain8616 | None,
) -> Real16CallInvocation8616 | None:
    """Consume an invocation premise only when all-selector bounds fail."""
    if _target_in_all_fetch_windows_8616(
        coordinates.callsite_addr, coordinates.target_addr,
    ):
        return None
    if not isinstance(invocation, Real16InvocationDomain8616):
        return None
    candidate = Real16CallInvocation8616(
        premise=invocation,
        callsite_addr=coordinates.callsite_addr,
        target_addr=coordinates.target_addr,
        project=project,
        block=block,
    )
    if candidate.complete:
        return candidate
    return None


def _target_bytes_bound_8616(
    project: object,
    coordinates: DirectNearCallCoordinates8616,
    kind: _TargetBindingKind8616,
) -> bool:
    """Apply the explicit target policy before shared current-byte binding."""
    if kind is _TargetBindingKind8616.DECLARED_STUB:
        return is_synthetic_call_stub_8616(project, coordinates.target_addr) and (
            direct_near_call_encoding_is_bound_8616(
                project, coordinates.callsite_addr, coordinates.next_addr,
                coordinates.target_addr, CallsiteMachineFrameKind8616.NEAR,
            )
        )
    return direct_near_call_target_is_bound_8616(
        project, coordinates.callsite_addr, coordinates.next_addr,
        coordinates.target_addr, CallsiteMachineFrameKind8616.NEAR,
    )


def _prove_binding_core_8616(
    project: object,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    *,
    invocation: Real16InvocationDomain8616 | None = None,
    target_kind: _TargetBindingKind8616 = _TargetBindingKind8616.REAL_BODY,
) -> DirectNearCallTargetBinding8616:
    """Bind the symbolic CALL operand to the proven coordinate triple.

    Shared by every coordinate source: the operand DAG, retained origin
    provenance, native re-lift, recovered shape constants, selector fetch
    window, and mapped byte checks are identical regardless of who derived
    the coordinates. ``invocation`` is an optional source-bound premise
    that may discharge only the selector-window obligation for the exact
    proven CS domain at this callsite; every other check is unchanged.
    """
    callsite_addr = coordinates.callsite_addr
    target_addr = coordinates.target_addr
    operand = _control_operand_8616(callsite_addr, target_addr, instruction)
    if isinstance(operand, DirectNearCallTargetBinding8616):
        return operand
    provenance = _origin_provenance_8616(
        project, block, instruction, operand, coordinates,
    )
    if isinstance(provenance, DirectNearCallTargetBinding8616):
        return provenance
    producers = _tmp_producers_8616(block)
    if producers is None:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.PRODUCER_LEDGER_AMBIGUOUS,
            normalized=True,
        )
    shape = _match_relative_continuation_8616(producers, operand)
    if shape is None:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.SHAPE_MISMATCH,
            normalized=True,
            classified=True,
        )
    shape_failure = _shape_coordinate_failure_8616(coordinates, shape)
    if shape_failure is not None:
        return shape_failure
    bound_invocation = _bound_selector_invocation_8616(
        project, block, coordinates, invocation,
    )
    if not _target_in_all_fetch_windows_8616(callsite_addr, target_addr) and bound_invocation is None:
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED,
            normalized=True, classified=True, shape=shape,
        )
    if not _target_bytes_bound_8616(project, coordinates, target_kind):
        return _refuse_8616(
            callsite_addr, target_addr,
            DirectNearCallTargetBindingFailure8616.TARGET_BYTES_MISMATCH,
            normalized=True,
            classified=True,
            shape=shape,
        )
    return DirectNearCallTargetBinding8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        verdict=DirectNearCallTargetBindingVerdict8616.PROVEN,
        failure=None,
        stats=DirectNearCallTargetBindingStats8616(1, 1, 1, 1, 0),
        shape=shape,
        invocation=bound_invocation,
    )


def prove_direct_near_call_target_binding_at_coordinates_8616(
    project: object,
    *,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    invocation: Real16InvocationDomain8616 | None = None,
) -> DirectNearCallTargetBinding8616:
    """Shared owner: bind the symbolic CALL operand to typed coordinates.

    ``coordinates`` is the only authority for callsite, continuation, and
    full-width target; the IR instruction identity is still verified against
    them before the operand DAG, provenance, and native-byte stages run.
    """
    identity = _call_identity_8616(
        instruction, coordinates.callsite_addr, coordinates.target_addr, block,
    )
    if isinstance(identity, DirectNearCallTargetBinding8616):
        return identity
    return _prove_binding_core_8616(
        project, block, instruction, coordinates, invocation=invocation
    )


def prove_declared_direct_near_call_target_binding_at_coordinates_8616(
    project: object,
    *,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    invocation: Real16InvocationDomain8616 | None = None,
) -> DirectNearCallTargetBinding8616:
    """Bind a native near CALL to a registered synthetic target only.

    Reuses every operand, provenance, native re-lift and selector gate.
    Closed frontend stub membership is required in addition to current E8
    bytes. This proves control identity, never callee behavior or segment
    preservation. Consumers must rerun this function on every use: the
    result complete property is not a mutable-source authentication cache.
    """
    if not any(item is instruction for item in block.instrs):
        return _refuse_8616(
            coordinates.callsite_addr, coordinates.target_addr,
            DirectNearCallTargetBindingFailure8616.INSTRUCTION_NOT_IN_BLOCK,
        )
    identity = _call_identity_8616(
        instruction, coordinates.callsite_addr, coordinates.target_addr, block,
    )
    if isinstance(identity, DirectNearCallTargetBinding8616):
        return identity
    return _prove_binding_core_8616(
        project, block, instruction, coordinates, invocation=invocation,
        target_kind=_TargetBindingKind8616.DECLARED_STUB,
    )


def prove_direct_near_call_target_binding_from_decoded_8616(
    project: object,
    *,
    block: IRBlock,
    instruction: IRInstr,
    decoded: DecodedDirectCallsite8616,
    invocation: Real16InvocationDomain8616 | None = None,
) -> DirectNearCallTargetBinding8616:
    """Bind the symbolic CALL operand to a decoded direct-callsite entry.

    Coordinates derive from the entry's own native instruction evidence —
    exact unprefixed word-E8 identity, decoded ``address + size``
    continuation, and full-width signed displacement — so no ABI summary is
    fabricated for a decoded index fact.
    """
    coordinates = _decoded_call_coordinates_8616(decoded)
    if isinstance(coordinates, DirectNearCallTargetBinding8616):
        return coordinates
    return prove_direct_near_call_target_binding_at_coordinates_8616(
        project, block=block, instruction=instruction, coordinates=coordinates,
        invocation=invocation,
    )


def prove_direct_near_call_target_binding_8616(
    project: object,
    *,
    block: IRBlock,
    instruction: IRInstr,
    summary: CallsiteSummary8616,
    invocation: Real16InvocationDomain8616 | None = None,
) -> DirectNearCallTargetBinding8616:
    """Prove the symbolic CALL control operand denotes ``summary.target_addr``.

    The proof joins three independent facts: the typed IR operand DAG is
    exactly the frontend's CS-relative continuation for the decoded E8 at the
    callsite (retained provenance, both CS composition sites, full dword
    control width), the embedded continuation constants agree with the
    summary coordinates exactly, and the real mapped bytes at the callsite
    decode to the same-image target. No operand constant is rewritten, no
    segment value is guessed, and no word truncation is accepted.
    """
    identity = _call_identity_8616(
        instruction, summary.callsite_addr, summary.target_addr, block,
    )
    if isinstance(identity, DirectNearCallTargetBinding8616):
        return identity
    coordinates = _summary_call_coordinates_8616(identity, summary)
    if isinstance(coordinates, DirectNearCallTargetBinding8616):
        return coordinates
    return _prove_binding_core_8616(
        project, block, instruction, coordinates, invocation=invocation
    )

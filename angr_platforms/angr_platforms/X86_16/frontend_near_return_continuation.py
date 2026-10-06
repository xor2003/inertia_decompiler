"""Prove near-CALL continuations for indirect decoded block terminals.

Layer: Frontend.
Responsibility: bind one indirect ``jmp r16``/``jmp m16`` block terminal to
the incoming near-CALL continuation held in the entry stack frame, using
only decoded binary facts: a bounded forward dataflow over the closed
block/edge census tracks the entry-frame top slot, the 16-bit GPR origin
set, SP/BP entry-relative deltas, continuation-slot mutation, and path
poisons (intervening calls, CS/SS clobbers, unclassified effects). The
proof is conditional on an independently supplied source-bound premise
(``NearCallFramePremise8616``): the exact decoded near-CALL row and its
retained callsite index that proved the invocation form, where the
row's detail-decoded instruction itself must prove the word-width
return push — a ``0x66`` operand-size-overridden ``66 E8`` near call
pushes a dword and is refused, never admitted as a near-CALL premise —
bound to this exact callee head.
Without that premise, or with a premise bound to a foreign head or no
longer authenticated by its index, every candidate refuses; the proof
never invents it and never accepts a bare kind marker. A proven terminal
contributes no in-region edge, exactly like a decoded ``ret``; every
other indirect terminal keeps its typed refusal.

Slot reasoning is byte-range and modular-16-bit aware: a store poisons
the return word whenever any of its bytes overlaps ``SS:[entry+0:2)``,
not only when it starts exactly at slot zero. Access widths are admitted
explicitly or refused — the jump operand, pop/push items, and the
``enter``/``leave`` frame forms must each carry agreed 16-bit width
evidence (operand size, ``0x66`` prefix, register-name width) or the path
keeps ``WIDTH_UNADMITTED``. Any write to ``SP`` or ``BP`` that the
transfer rules do not resolve — partial aliases included — widens that
pointer's tracked delta to unknown.

This module never matches assembly text, symbol names, addresses, COD
records, or helper allowlists, and it never converts an indirect jump
into a return without the full provenance chain.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast

from capstone import CS_ERR_DETAIL, CsError

from .frontend_capstone_block import DirectCapstoneBlock8616
from .frontend_instruction_kinds import is_x86_16_call_mnemonic_8616

if TYPE_CHECKING:
    from .frontend_direct_callsite_index import (
        DecodedDirectCallsite8616,
        DecodedDirectCallsiteIndex8616,
    )

__all__ = [
    "EntryTopSlotKind8616",
    "NearCallFramePremise8616",
    "NearReturnContinuationArtifact8616",
    "NearReturnContinuationFailure8616",
    "NearReturnContinuationKind8616",
    "NearReturnContinuationRecord8616",
    "NearReturnContinuationVerdict8616",
    "near_call_frame_premise_stale_8616",
    "prove_near_call_frame_premise_8616",
    "prove_near_return_continuations_8616",
]


class EntryTopSlotKind8616(StrEnum):
    """Independently proved content of ``SS:[SP]`` at function entry."""

    NEAR_CALL_CONTINUATION = "near_call_continuation"


class NearReturnContinuationVerdict8616(StrEnum):
    """Per-terminal proof verdict."""

    PROVEN = "proven"
    REFUSED = "refused"


class NearReturnContinuationKind8616(StrEnum):
    """How the continuation value reaches the terminal operand."""

    REGISTER = "register"
    STACK_SLOT = "stack_slot"


class NearReturnContinuationFailure8616(StrEnum):
    """Typed reasons an indirect terminal cannot bind the continuation."""

    PREMISE_ABSENT = "near_return_continuation_premise_absent"
    MEMORY_FORM_UNPROVED = "near_return_continuation_memory_form_unproved"
    CONTINUATION_NOT_BOUND = "near_return_continuation_not_bound"
    CONTINUATION_MUTATED = "near_return_continuation_mutated"
    WIDTH_UNADMITTED = "near_return_continuation_width_unadmitted"
    CS_CLOBBERED_ON_PATH = "near_return_continuation_cs_clobbered"
    SS_CLOBBERED_ON_PATH = "near_return_continuation_ss_clobbered"
    CALL_ON_PATH = "near_return_continuation_call_on_path"
    UNKNOWN_EFFECT_ON_PATH = "near_return_continuation_unknown_effect"
    PATH_INCOMPLETE = "near_return_continuation_path_incomplete"
    FIXPOINT_UNBOUNDED = "near_return_continuation_fixpoint_unbounded"
    PREMISE_FOREIGN = "near_return_continuation_premise_foreign"
    PREMISE_STALE = "near_return_continuation_premise_stale"


@dataclass(frozen=True, slots=True)
class NearCallFramePremise8616:
    """Source-bound entry-frame premise for one exact callee head.

    The premise that ``SS:[SP]`` at ``callee_addr`` entry holds the
    return word pushed by a near CALL is derivable only from the exact
    decoded near-CALL row and the retained project callsite index that
    proved the invocation form, with the row's decoded instruction
    proving the word-width push (a ``0x66``-overridden ``66 E8`` form
    pushes a dword and never derives this premise). ``callsite`` and
    ``callsite_index`` are the provenance a consuming scope must re-bind
    by identity;
    ``callee_addr``/``callsite_addr``/``caller_start``/``return_addr``
    are the coordinates the row itself decoded. ``kind`` names the
    entry-slot class only — the row and index are the evidence, never
    the enum alone.
    """

    kind: EntryTopSlotKind8616
    callsite: DecodedDirectCallsite8616 = field(compare=False, repr=False)
    callsite_index: DecodedDirectCallsiteIndex8616 = field(
        compare=False, repr=False
    )
    callee_addr: int = 0
    callsite_addr: int = 0
    caller_start: int = 0
    return_addr: int = 0

    def to_dict(self) -> dict[str, object]:
        """Serialize this premise's decoded coordinates for diagnostics."""
        return {
            "kind": self.kind.value,
            "callee_addr": self.callee_addr,
            "callsite_addr": self.callsite_addr,
            "caller_start": self.caller_start,
            "return_addr": self.return_addr,
        }


def _near_call_word_evidence_8616(instruction: object) -> bool:
    """Return whether decoded facts prove a word-width return push.

    The premise's claim — a near CALL pushed exactly one return word —
    is re-derived from the row's decoded instruction, never inferred
    from the near/far flag: in the 16-bit domain the ``0x66``
    operand-size prefix switches the pushed return address to a dword,
    and the lone immediate target operand's decoded access size must
    corroborate the two-byte form. Only a detail-decoded ``call`` with
    exactly one immediate operand sized two bytes and no ``0x66`` prefix
    is admitted; a wide ``66 E8`` row, a non-call or non-immediate
    operand shape, or an instruction exposing no decoded prefix/operand
    evidence at all is refused rather than guessed.
    """
    wrapper = cast(_InstructionBoundary8616, instruction)
    try:
        try:
            insn = cast(_DecodedCallsiteInstruction8616, wrapper.insn)
        except AttributeError:
            insn = cast(_DecodedCallsiteInstruction8616, instruction)
        mnemonic = str(insn.mnemonic).lower()
        prefix = tuple(insn.prefix)
        operands = tuple(insn.operands)
    except (AttributeError, TypeError):
        return False
    except CsError as error:
        # Detail-disabled Capstone objects signal missing evidence this way,
        # including during wrapper inspection. Other decoder errors stay loud.
        if error.errno != CS_ERR_DETAIL:
            raise
        return False
    return (
        is_x86_16_call_mnemonic_8616(mnemonic)
        and len(operands) == 1
        and operands[0].type == 2
        and _operand_width_8616(operands[0]) == 2
        and _OPERAND_SIZE_PREFIX_8616 not in prefix
    )


def near_call_frame_premise_stale_8616(premise: NearCallFramePremise8616) -> bool:
    """Return whether the retained index no longer authenticates this row.

    A premise is stale when its retained callsite index no longer carries
    the identical decoded row under the callee's normalized target — a
    rebuilt inventory, an equal-but-distinct row object, or a foreign
    index all revoke the premise's authority rather than merely aging it.
    The retained row's decoded instruction must also still prove the
    word-width return push: a changed-width or undecoded row revokes the
    premise exactly like a lost index entry.
    """
    if not any(
        row is premise.callsite
        for row in premise.callsite_index.for_target(premise.callee_addr)
    ):
        return True
    instructions = premise.callsite.instructions
    instruction_index = premise.callsite.instruction_index
    if (
        not isinstance(instructions, tuple)
        or type(instruction_index) is not int
        or not 0 <= instruction_index < len(instructions)
    ):
        return True
    return not _near_call_word_evidence_8616(instructions[instruction_index])


def prove_near_call_frame_premise_8616(
    callsite: object,
    index: object,
    callee_addr: int,
) -> NearCallFramePremise8616 | None:
    """Bind the entry-frame premise to one exact decoded near-CALL row.

    The premise exists only when the retained, closed index still
    authenticates this identical row under the callee's normalized
    target, the row is a near (never far) direct call whose decoded
    target is exactly ``callee_addr``, the row's detail-decoded
    instruction proves a word-width return push (``call`` with one
    immediate operand sized two bytes and no ``0x66`` prefix — a
    ``66 E8`` wide form pushes a dword and refuses), and the row's
    retained instruction extent yields the return-word coordinate.
    ``None`` — never a synthesized premise — for far calls, foreign
    targets, unindexed or rebuilt rows, open indexes, malformed
    coordinates, or any row whose decoded width evidence is absent,
    unknown, or non-word.
    """
    from .frontend_direct_callsite_index import (
        DecodedDirectCallsite8616,
        DecodedDirectCallsiteIndex8616,
    )

    if type(callsite) is not DecodedDirectCallsite8616 or callsite.is_far:
        return None
    if type(index) is not DecodedDirectCallsiteIndex8616 or not index.stats.closed:
        return None
    if (
        type(callee_addr) is not int
        or callee_addr < 0
        or callsite.target_addr != callee_addr
        or type(callsite.callsite_addr) is not int
        or type(callsite.caller_start) is not int
    ):
        return None
    instructions = callsite.instructions
    instruction_index = callsite.instruction_index
    if (
        not isinstance(instructions, tuple)
        or type(instruction_index) is not int
        or not 0 <= instruction_index < len(instructions)
    ):
        return None
    instruction = cast(
        _DecodedCallsiteInstruction8616, instructions[instruction_index]
    )
    if (
        instruction.address != callsite.callsite_addr
        or type(instruction.size) is not int
        or instruction.size <= 0
    ):
        return None
    if not _near_call_word_evidence_8616(instruction):
        return None
    if not any(
        row is callsite for row in index.for_target(callee_addr)
    ):
        return None
    return NearCallFramePremise8616(
        kind=EntryTopSlotKind8616.NEAR_CALL_CONTINUATION,
        callsite=callsite,
        callsite_index=index,
        callee_addr=callee_addr,
        callsite_addr=callsite.callsite_addr,
        caller_start=callsite.caller_start,
        return_addr=callsite.callsite_addr + instruction.size,
    )


# Deterministic refusal-precedence order when a merged path state carries
# several distinct poisons; reporting picks the first present member.
_FAILURE_PRIORITY_8616: tuple[NearReturnContinuationFailure8616, ...] = (
    NearReturnContinuationFailure8616.CALL_ON_PATH,
    NearReturnContinuationFailure8616.CS_CLOBBERED_ON_PATH,
    NearReturnContinuationFailure8616.SS_CLOBBERED_ON_PATH,
    NearReturnContinuationFailure8616.UNKNOWN_EFFECT_ON_PATH,
    NearReturnContinuationFailure8616.WIDTH_UNADMITTED,
    NearReturnContinuationFailure8616.CONTINUATION_MUTATED,
    NearReturnContinuationFailure8616.PATH_INCOMPLETE,
)

# Sixteen-bit GPR provenance order; ``sp`` is value-tracked separately as a
# stack delta and never a valid continuation carrier.
_GPR_ORDER_8616: tuple[str, ...] = ("ax", "bx", "cx", "dx", "si", "di", "bp")
_GPR_INDEX_8616: Mapping[str, int] = {name: index for index, name in enumerate(_GPR_ORDER_8616)}

_GPR_ALIASES_8616: Mapping[str, str] = {
    "eax": "ax", "ebx": "bx", "ecx": "cx", "edx": "dx",
    "esi": "si", "edi": "di", "ebp": "bp", "esp": "sp",
    "al": "ax", "ah": "ax", "bl": "bx", "bh": "bx",
    "cl": "cx", "ch": "cx", "dl": "dx", "dh": "dx",
    "sil": "si", "dil": "di", "bpl": "bp",
}
_SP_NAMES_8616: frozenset[str] = frozenset({"sp", "esp", "spl"})
_BP_NAMES_8616: frozenset[str] = frozenset({"bp"})
_SEGMENT_NAMES_8616: frozenset[str] = frozenset({"cs", "ss", "ds", "es", "fs", "gs"})
_FLAG_NAMES_8616: frozenset[str] = frozenset({"eflags", "flags", "rflags"})

# Raw register-name widths, used to corroborate operand-size evidence on
# terminal jump operands; normalized aliases are resolved separately.
_REG16_NAMES_8616: frozenset[str] = frozenset(
    {"ax", "bx", "cx", "dx", "si", "di", "bp", "sp"}
)
_REG32_NAMES_8616: frozenset[str] = frozenset(
    {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
)
_REG8_NAMES_8616: frozenset[str] = frozenset(
    {"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "bpl", "spl"}
)
# Raw destination spellings whose write assigns the pointer's whole 16-bit
# tracked value; any other alias (``spl``/``bpl``) is a partial write and
# widens the delta to unknown.
_SP_FULL_NAMES_8616: frozenset[str] = frozenset({"sp", "esp"})
_BP_FULL_NAMES_8616: frozenset[str] = frozenset({"bp", "ebp"})

# The return word occupies bytes ``SS:[entry SP + 0 .. +2)``; slot deltas
# are 16-bit modular because 16-bit effective addresses wrap there.
_SLOT_MOD_8616 = 0x10000
_OPERAND_SIZE_PREFIX_8616 = 0x66

# ``pusha``/``popa`` family totals in bytes; Capstone spells the 16-bit
# forms ``pushaw``/``popaw`` and the operand-size-overridden forms
# ``pushal``/``popal``.
_PUSHA_TOTAL_8616: Mapping[str, int] = {
    "pusha": 16, "pushaw": 16, "pushad": 32, "pushal": 32,
}
_POPA_TOTAL_8616: Mapping[str, int] = {
    "popa": 16, "popaw": 16, "popad": 32, "popal": 32,
}
_PUSHF_MNEMONICS_8616: frozenset[str] = frozenset({"pushf", "pushfd"})
_POPF_MNEMONICS_8616: frozenset[str] = frozenset({"popf", "popfd"})

# Entry-relative stack delta bound. A loop that pushes or pops without a
# matching net effect exceeds it and widens to unknown rather than
# iterating without end.
_DELTA_BOUND_8616 = 128

# Interrupt/system-call families behave like unknown calls for path
# provenance: the continuation register and frame cannot be trusted.
_INTERRUPT_MNEMONICS_8616: frozenset[str] = frozenset(
    {"int", "int1", "int3", "into", "sysenter", "syscall"}
)
# Far/return forms write CS or leave the near domain entirely.
_CS_TRANSFER_MNEMONICS_8616: frozenset[str] = frozenset(
    {"ljmp", "retf", "retfw", "iret", "iretd", "iretq"}
)
# Control mnemonics legal only at a block terminal; mid-block sightings are
# decode anomalies and refuse as unknown effects.
_BRANCH_TERMINAL_MNEMONICS_8616: frozenset[str] = frozenset(
    {"jmp", "loop", "loope", "loopne", "loopnz", "loopz", "jcxz", "jecxz"}
)
# Instructions whose memory operand is strictly a read.
_MEM_READ_MNEMONICS_8616: frozenset[str] = frozenset(
    {"cmp", "test", "bt", "lodsb", "lodsw", "scasb", "scasw",
     "cmpsb", "cmpsw", "outsb", "outsw", "xlat", "xlatb", "bound",
     "verr", "verw", "invlpg", "lar", "lsl", "lgdt", "lidt", "lldt"}
)
# String mnemonics that write destination memory at ES:[DI].
_STRING_WRITE_MNEMONICS_8616: frozenset[str] = frozenset(
    {"movsb", "movsw", "stosb", "stosw", "insb", "insw", "movs", "stos", "ins"}
)
# Explicit no-tracked-effect instructions.
_NEUTRAL_MNEMONICS_8616: frozenset[str] = frozenset(
    {"nop", "fnop", "pause", "wait", "fwait", "emms", "clc", "stc", "cld",
     "std", "cli", "sti", "cmc", "clts", "invd", "wbinvd", "cpuid", "rdtsc",
     "rdmsr", "salc", "sahf", "lahf", "cbw", "cwde", "cwd", "cdq"}
)
# Anomalous non-return terminals that cannot carry near-continuation proof.
_ANOMALOUS_TERMINALS_8616: frozenset[str] = frozenset(
    {"hlt", "ud0", "ud1", "ud2"}
)


class _MemoryOperandBoundary8616(Protocol):
    """Capstone memory fields consumed by the continuation proof."""

    base: int
    index: int
    segment: int
    disp: int


class _OperandBoundary8616(Protocol):
    """Capstone operand fields consumed by the continuation proof."""

    type: int
    reg: int
    imm: int
    size: int
    access: int
    mem: _MemoryOperandBoundary8616


class _DecodedInstructionBoundary8616(Protocol):
    """Decoded Capstone instruction fields used at the backend boundary."""

    address: int
    mnemonic: str
    operands: Sequence[_OperandBoundary8616]
    prefix: Sequence[int]

    def reg_name(self, register_id: int) -> str:
        """Return Capstone's canonical register name."""
        ...

    def regs_access(self) -> tuple[Sequence[int], Sequence[int]]:
        """Return registers read and written, including implicit effects."""
        ...


class _InstructionBoundary8616(Protocol):
    """angr wrapper fields for one decoded Capstone instruction."""

    insn: _DecodedInstructionBoundary8616


class _DecodedCallsiteInstruction8616(Protocol):
    """Decoded callsite row instruction fields the premise derives.

    Detail-decoded fields — mnemonic, operand list, and prefix bytes —
    are required: the word-width return push a near CALL premise claims
    is proved from them, never inferred from the near/far flag alone.
    """

    address: int
    size: int
    mnemonic: str
    prefix: Sequence[int]
    operands: Sequence[_OperandBoundary8616]


class _CapstoneBoundary8616(Protocol):
    """Decoded instruction sequence exposed by a decoded block."""

    insns: Sequence[object]


class _BlockBoundary8616(Protocol):
    """Decoded block surface consumed by the continuation proof."""

    addr: int
    capstone: _CapstoneBoundary8616


@dataclass(frozen=True, slots=True)
class _InsnFacts8616:
    """One decoded instruction reduced to the facts this proof consumes."""

    address: int
    mnemonic: str
    operands: tuple[_OperandBoundary8616, ...]
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    decode_failed: bool
    insn: _DecodedInstructionBoundary8616


@dataclass(frozen=True, slots=True)
class _PathState8616:
    """Bounded per-path provenance lattice over the decoded block CFG.

    ``origins[i]`` is True only when GPR ``_GPR_ORDER_8616[i]`` provably
    holds the entry-frame top slot word. ``sp_delta``/``bp_delta`` are the
    entry-relative 16-bit deltas, ``None`` once uncomputable.
    ``slot_mutated`` records a possible write to the entry top slot before
    it is consumed; ``poisons`` unions every path-level refusal reason.
    """

    origins: tuple[bool, ...]
    sp_delta: int | None
    bp_delta: int | None
    slot_mutated: bool
    poisons: frozenset[NearReturnContinuationFailure8616]


@dataclass(frozen=True, slots=True)
class NearReturnContinuationRecord8616:
    """Proof or typed refusal for one indirect block terminal."""

    block_addr: int
    terminal_addr: int
    verdict: NearReturnContinuationVerdict8616
    failure: NearReturnContinuationFailure8616 | None
    kind: NearReturnContinuationKind8616 | None = None
    register: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this record for diagnostics."""
        return {
            "block_addr": self.block_addr,
            "terminal_addr": self.terminal_addr,
            "verdict": self.verdict.value,
            "failure": None if self.failure is None else self.failure.value,
            "kind": None if self.kind is None else self.kind.value,
            "register": self.register,
        }


@dataclass(frozen=True, slots=True)
class NearReturnContinuationArtifact8616:
    """Closed census of continuation proofs for one region's candidates.

    ``premise`` retains the exact source-bound entry-frame premise the
    proof consumed — identity-bound provenance a consuming scoped view
    must re-authenticate, so it is excluded from equality and the repr.
    """

    records: tuple[NearReturnContinuationRecord8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    premise: NearCallFramePremise8616 | None = field(
        default=None, compare=False, repr=False
    )

    @property
    def complete(self) -> bool:
        """Return whether every observed candidate proved its continuation."""
        return (
            self.raw_fact_count > 0
            and self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
            and self.failure_count == 0
        )

    @property
    def proven_block_addrs(self) -> frozenset[int]:
        """Return block addresses whose indirect terminal is a proven return."""
        return frozenset(
            record.block_addr
            for record in self.records
            if record.verdict is NearReturnContinuationVerdict8616.PROVEN
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize this artifact for diagnostics."""
        return {
            "premise": (
                None if self.premise is None else self.premise.to_dict()
            ),
            "records": [record.to_dict() for record in self.records],
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


def _merge_states_8616(
    left: _PathState8616 | None,
    right: _PathState8616 | None,
) -> _PathState8616 | None:
    """Join two path states; continuation survives only on every path."""
    if left is None:
        return right
    if right is None:
        return left
    origins = tuple(
        left_value and right_value
        for left_value, right_value in zip(left.origins, right.origins, strict=True)
    )
    sp_delta = left.sp_delta if left.sp_delta == right.sp_delta else None
    bp_delta = left.bp_delta if left.bp_delta == right.bp_delta else None
    return _PathState8616(
        origins=origins,
        sp_delta=sp_delta,
        bp_delta=bp_delta,
        slot_mutated=left.slot_mutated or right.slot_mutated,
        poisons=left.poisons | right.poisons,
    )


def _normalize_gpr_8616(name: str) -> str:
    """Normalize 32-bit and byte register spellings to their 16-bit parent."""
    lowered = name.lower()
    return _GPR_ALIASES_8616.get(lowered, lowered)


def _poisoned_8616(
    state: _PathState8616, reason: NearReturnContinuationFailure8616,
) -> _PathState8616:
    """Record one path poison without discarding the rest of the state."""
    if reason in state.poisons:
        return state
    return _PathState8616(
        origins=state.origins,
        sp_delta=state.sp_delta,
        bp_delta=state.bp_delta,
        slot_mutated=state.slot_mutated,
        poisons=state.poisons | {reason},
    )


def _bounded_delta_8616(delta: int | None) -> int | None:
    """Widen an unbounded entry-relative delta to unknown."""
    if delta is None or abs(delta) > _DELTA_BOUND_8616:
        return None
    return delta


def _reg_name_8616(insn: _DecodedInstructionBoundary8616, register_id: int) -> str:
    """Return one normalized register name or an empty marker."""
    try:
        name = insn.reg_name(register_id)
    except (AttributeError, TypeError):
        return ""
    return name.lower() if isinstance(name, str) else ""


def _effective_segment_8616(
    insn: _DecodedInstructionBoundary8616, memory: _MemoryOperandBoundary8616,
) -> str:
    """Return the effective segment name for one memory operand."""
    if memory.segment:
        return _reg_name_8616(insn, memory.segment)
    base_name = _reg_name_8616(insn, memory.base)
    index_name = _reg_name_8616(insn, memory.index)
    if base_name == "bp" or index_name == "bp":
        return "ss"
    return "ds"


def _stack_slot_8616(
    state: _PathState8616,
    insn: _DecodedInstructionBoundary8616,
    memory: _MemoryOperandBoundary8616,
) -> int | None:
    """Return the entry-relative byte slot of a provably SS-relative operand.

    ``None`` means either the operand is not stack-relative or its slot
    cannot be computed from tracked deltas; callers treat both as a
    potential continuation-slot alias. Only the 16-bit ``sp``/``bp``
    spellings are frame-relative carriers: an address-size-overridden
    ``esp``/``ebp`` base is a 32-bit address this proof does not track.
    """
    if _effective_segment_8616(insn, memory) != "ss" or memory.index:
        return None
    base_name = _reg_name_8616(insn, memory.base)
    if base_name == "sp":
        delta = state.sp_delta
    elif base_name == "bp":
        delta = state.bp_delta
    else:
        return None
    if delta is None:
        return None
    return delta + int(memory.disp)


def _operand_width_8616(operand: _OperandBoundary8616) -> int | None:
    """Return the decoder-reported access width of one operand, if sane."""
    try:
        size = int(operand.size)
    except (AttributeError, TypeError, ValueError):
        return None
    return size if size > 0 else None


def _operand_size_override_8616(
    insn: _DecodedInstructionBoundary8616,
) -> bool | None:
    """Return whether the instruction carries a ``0x66`` prefix.

    ``None`` reports that the decoder exposed no prefix list at all; that
    absence is never read as "no prefix" because the prefix is exactly
    what decides operand width.
    """
    try:
        return _OPERAND_SIZE_PREFIX_8616 in tuple(insn.prefix)
    except (AttributeError, TypeError):
        return None


def _slot_is_return_word_8616(slot: int | None) -> bool:
    """Return whether ``slot`` names exactly the entry return word."""
    return slot is not None and slot % _SLOT_MOD_8616 == 0


def _store_overlaps_return_word_8616(slot: int | None, width: int | None) -> bool:
    """Return whether a ``width``-byte store at ``slot`` may touch the word.

    The return word is the byte range ``{0, 1}`` in entry-relative,
    16-bit-modular slot space. Any byte of the store landing there is a
    potential overwrite; an uncomputable slot, an unreported or
    nonpositive width, and a width reaching the modulus are all treated
    as overlapping because they cannot prove exclusion.
    """
    if slot is None or width is None or width <= 0 or width >= _SLOT_MOD_8616:
        return True
    start = slot % _SLOT_MOD_8616
    end = start + width
    return start < 2 or end > _SLOT_MOD_8616


def _stack_item_width_8616(facts: _InsnFacts8616) -> int | None:
    """Return the per-item byte width of a push/pop-style stack access.

    Two independent decode signals must agree before a width is admitted:
    the operand's reported access size and the ``0x66`` operand-size
    prefix. Contradictory or absent evidence yields ``None`` rather than
    guessing a 2-byte stack slot.
    """
    operand = facts.operands[0] if facts.operands else None
    size = _operand_width_8616(operand) if operand is not None else None
    override = _operand_size_override_8616(facts.insn)
    prefix_width = None if override is None else (4 if override else 2)
    if size in (2, 4):
        if prefix_width is not None and prefix_width != size:
            return None
        return size
    return prefix_width


def _memory_write_mutates_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> bool:
    """Return whether this instruction may overwrite the entry top slot.

    Only a provably SS-relative store whose byte range provably misses
    the two-byte return word — above it, below it, or modular-wrapped
    clear — is admitted as a non-mutation; every alien-segment,
    uncomputable, or overlapping store is a potential continuation-slot
    alias, never ignored.
    """
    if not facts.operands or facts.operands[0].type != 3:
        return False
    operand = facts.operands[0]
    slot = _stack_slot_8616(state, facts.insn, operand.mem)
    return _store_overlaps_return_word_8616(slot, _operand_width_8616(operand))


def _apply_origins_8616(
    state: _PathState8616, assigned: Mapping[str, bool], writes: Sequence[str],
) -> tuple[bool, ...]:
    """Fold one instruction's register writes into the origin vector.

    Assigned origins win over the write audit so implicit writes the
    decoder does not report (for example ``enter``/``leave`` on ``bp``)
    still degrade; every reported GPR write without an assigned
    provenance drops to non-continuation.
    """
    written = {_normalize_gpr_8616(name) for name in writes}
    return tuple(
        assigned[name]
        if name in assigned
        else False
        if name in written
        else state.origins[index]
        for index, name in enumerate(_GPR_ORDER_8616)
    )


def _audit_writes_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> _PathState8616:
    """Poison CS/SS clobbers and unclassified written registers."""
    result = state
    for name in facts.writes:
        normalized = _normalize_gpr_8616(name)
        if normalized == "cs":
            result = _poisoned_8616(
                result, NearReturnContinuationFailure8616.CS_CLOBBERED_ON_PATH
            )
        elif normalized == "ss":
            result = _poisoned_8616(
                result, NearReturnContinuationFailure8616.SS_CLOBBERED_ON_PATH
            )
        elif (
            normalized in _GPR_INDEX_8616
            or normalized in _SP_NAMES_8616
            or normalized in _SEGMENT_NAMES_8616
            or normalized in _FLAG_NAMES_8616
        ):
            continue
        else:
            result = _poisoned_8616(
                result, NearReturnContinuationFailure8616.UNKNOWN_EFFECT_ON_PATH
            )
    return result


def _delta_state_8616(
    state: _PathState8616,
    sp_delta: int | None,
    bp_delta: int | None,
    mutated: bool,
) -> _PathState8616:
    """Return a state copy with updated deltas and slot mutation."""
    return _PathState8616(
        state.origins, sp_delta, bp_delta, mutated, state.poisons,
    )


def _step_pop_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> tuple[_PathState8616, Mapping[str, bool]]:
    """Fold one ``pop``: slot-0 word loads bind continuation provenance.

    Only the 16-bit pop binds a carrier: a 32-bit pop advances ``SP`` by
    four but its loaded low word is not admitted as a bound target here.
    Popping ``bp`` also destroys the frame delta — the register no longer
    names the entry frame — and popping ``sp`` leaves an unknown pointer.
    """
    operand = facts.operands[0] if facts.operands else None
    width = _stack_item_width_8616(facts)
    if operand is None or width not in (2, 4):
        result = _poisoned_8616(
            state, NearReturnContinuationFailure8616.WIDTH_UNADMITTED
        )
        return _delta_state_8616(result, None, None, result.slot_mutated), {}
    delta = state.sp_delta
    bp_delta = state.bp_delta
    mutated = state.slot_mutated
    assigned: dict[str, bool] = {}
    pop_into_sp = False
    if operand.type == 1:
        name = _normalize_gpr_8616(_reg_name_8616(facts.insn, operand.reg))
        if name in _GPR_INDEX_8616:
            assigned[name] = bool(
                width == 2 and delta == 0 and not mutated
            )
        if name == "bp":
            bp_delta = None
        elif name == "sp":
            pop_into_sp = True
    elif operand.type == 3:
        slot = _stack_slot_8616(state, facts.insn, operand.mem)
        mutated = mutated or _store_overlaps_return_word_8616(slot, width)
    new_delta = (
        None
        if pop_into_sp or delta is None
        else _bounded_delta_8616(delta + width)
    )
    return _delta_state_8616(state, new_delta, bp_delta, mutated), assigned


def _step_push_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> _PathState8616:
    """Fold one ``push``-family stack write into the slot census.

    The written range is the ``width`` bytes just below the tracked
    pointer; ``pushf``/``pushfd`` take their width from the ``0x66``
    prefix because they carry no explicit operand.
    """
    width = _stack_item_width_8616(facts)
    if width is None:
        result = _poisoned_8616(
            state, NearReturnContinuationFailure8616.WIDTH_UNADMITTED
        )
        return _delta_state_8616(result, None, state.bp_delta, result.slot_mutated)
    delta = state.sp_delta
    slot = None if delta is None else delta - width
    return _delta_state_8616(
        state,
        _bounded_delta_8616(None if delta is None else delta - width),
        state.bp_delta,
        state.slot_mutated or _store_overlaps_return_word_8616(slot, width),
    )


def _step_popf_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> _PathState8616:
    """Fold one ``popf``/``popfd``: a flag pop that only advances SP."""
    width = _stack_item_width_8616(facts)
    if width is None:
        result = _poisoned_8616(
            state, NearReturnContinuationFailure8616.WIDTH_UNADMITTED
        )
        return _delta_state_8616(result, None, state.bp_delta, result.slot_mutated)
    delta = state.sp_delta
    return _delta_state_8616(
        state,
        _bounded_delta_8616(None if delta is None else delta + width),
        state.bp_delta,
        state.slot_mutated,
    )


def _step_pusha_8616(state: _PathState8616, total: int) -> _PathState8616:
    """Fold one ``pusha``/``pushal``: ``total`` bytes written below SP."""
    delta = state.sp_delta
    slot = None if delta is None else delta - total
    return _delta_state_8616(
        state,
        _bounded_delta_8616(None if delta is None else delta - total),
        state.bp_delta,
        state.slot_mutated or _store_overlaps_return_word_8616(slot, total),
    )


def _step_popa_8616(state: _PathState8616, total: int) -> _PathState8616:
    """Fold one ``popa``/``popal``: every GPR loses continuation provenance."""
    delta = state.sp_delta
    return _delta_state_8616(
        state,
        _bounded_delta_8616(None if delta is None else delta + total),
        None,
        state.slot_mutated,
    )


def _step_enter_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> tuple[_PathState8616, Mapping[str, bool]]:
    """Fold one ``enter N, 0``: the frame push plus the allocation size.

    Only the flat, unoverridden form is admitted. A nonzero nesting level
    copies enclosing frame words this model does not track, and a
    ``0x66`` operand-size prefix widens the pushed frame pointer — both
    refuse rather than pretend a delta.
    """
    operands = facts.operands
    if _operand_size_override_8616(facts.insn) is not False:
        result = _poisoned_8616(
            state, NearReturnContinuationFailure8616.WIDTH_UNADMITTED
        )
        return (
            _delta_state_8616(result, None, None, result.slot_mutated),
            {"bp": False},
        )
    alloc: int | None = None
    nesting: int | None = None
    if (
        len(operands) == 2
        and operands[0].type == 2
        and operands[1].type == 2
    ):
        try:
            alloc = int(operands[0].imm)
            nesting = int(operands[1].imm)
        except (TypeError, ValueError):
            alloc = None
    if alloc is None or nesting != 0:
        result = _poisoned_8616(
            state, NearReturnContinuationFailure8616.UNKNOWN_EFFECT_ON_PATH
        )
        return (
            _delta_state_8616(result, None, None, result.slot_mutated),
            {"bp": False},
        )
    delta = state.sp_delta
    slot = None if delta is None else delta - 2
    frame_delta = None if delta is None else delta - 2
    return _delta_state_8616(
        state,
        _bounded_delta_8616(
            None if frame_delta is None else frame_delta - alloc
        ),
        frame_delta,
        state.slot_mutated or _store_overlaps_return_word_8616(slot, 2),
    ), {"bp": False}


def _step_leave_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> tuple[_PathState8616, Mapping[str, bool]]:
    """Fold one ``leave``: SP adopts the frame delta, BP is reloaded.

    Only the unprefixed 16-bit form is admitted: a ``0x66`` operand-size
    prefix makes ``leave`` pop a 4-byte frame pointer this proof does not
    model, so it refuses instead of claiming a width.
    """
    if _operand_size_override_8616(facts.insn) is not False:
        result = _poisoned_8616(
            state, NearReturnContinuationFailure8616.WIDTH_UNADMITTED
        )
        return (
            _delta_state_8616(result, None, None, result.slot_mutated),
            {"bp": False},
        )
    return _delta_state_8616(
        state,
        _bounded_delta_8616(
            None if state.bp_delta is None else state.bp_delta + 2
        ),
        None,
        state.slot_mutated,
    ), {"bp": False}


def _step_stack_forms_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> tuple[_PathState8616, Mapping[str, bool], bool]:
    """Handle push/pop/enter/leave frame effects.

    Returns ``(state, assigned, handled)`` where ``assigned`` maps GPR
    names to continuation provenance and ``handled`` reports whether the
    mnemonic was fully consumed here. Unadmitted operand or stack widths
    are still consumed here — as ``WIDTH_UNADMITTED`` poisons — so they
    can never fall through to the generic rules and pretend a delta.
    """
    mnemonic = facts.mnemonic
    if mnemonic == "pop":
        new_state, assigned = _step_pop_8616(state, facts)
        return new_state, assigned, True
    if mnemonic == "push" or mnemonic in _PUSHF_MNEMONICS_8616:
        return _step_push_8616(state, facts), {}, True
    if mnemonic in _PUSHA_TOTAL_8616:
        return _step_pusha_8616(state, _PUSHA_TOTAL_8616[mnemonic]), {}, True
    if mnemonic in _POPA_TOTAL_8616:
        assigned = dict.fromkeys(_GPR_ORDER_8616, False)
        return _step_popa_8616(state, _POPA_TOTAL_8616[mnemonic]), assigned, True
    if mnemonic in _POPF_MNEMONICS_8616:
        return _step_popf_8616(state, facts), {}, True
    if mnemonic == "enter":
        new_state, assigned = _step_enter_8616(state, facts)
        return new_state, assigned, True
    if mnemonic == "leave":
        new_state, assigned = _step_leave_8616(state, facts)
        return new_state, assigned, True
    return state, {}, False


def _lea_target_delta_8616(
    state: _PathState8616,
    insn: _DecodedInstructionBoundary8616,
    memory: _MemoryOperandBoundary8616,
) -> int | None:
    """Return the entry-relative delta one ``lea`` computes, if provable.

    Only a single ``sp``/``bp`` base with no index keeps a delta; the
    computed value is the base delta plus the displacement, bounded.
    """
    if memory.index:
        return None
    base_name = _reg_name_8616(insn, memory.base)
    if base_name == "sp":
        delta = state.sp_delta
    elif base_name == "bp":
        delta = state.bp_delta
    else:
        return None
    if delta is None:
        return None
    return _bounded_delta_8616(delta + int(memory.disp))


def _step_lea_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> tuple[Mapping[str, bool], int | None, int | None, bool]:
    """Fold one ``lea``: computed addresses never carry continuation.

    ``lea`` into ``sp``/``bp`` is an effective-address computation, so the
    pointer's tracked delta is recomputed from the source operand rather
    than left stale; partial destination aliases widen to unknown.
    """
    assigned: dict[str, bool] = {}
    sp_delta = state.sp_delta
    bp_delta = state.bp_delta
    operands = facts.operands
    if len(operands) == 2 and operands[0].type == 1:
        raw = _reg_name_8616(facts.insn, operands[0].reg)
        name = _normalize_gpr_8616(raw)
        computed = (
            _lea_target_delta_8616(state, facts.insn, operands[1].mem)
            if operands[1].type == 3
            else None
        )
        if name == "sp":
            sp_delta = computed if raw in _SP_FULL_NAMES_8616 else None
        elif name == "bp":
            bp_delta = computed if raw in _BP_FULL_NAMES_8616 else None
            assigned["bp"] = False
        elif name in _GPR_INDEX_8616:
            assigned[name] = False
    return assigned, sp_delta, bp_delta, state.slot_mutated


def _step_mov_reg_dest_8616(
    state: _PathState8616,
    facts: _InsnFacts8616,
    destination: _OperandBoundary8616,
    source: _OperandBoundary8616,
) -> tuple[Mapping[str, bool], int | None, int | None, bool]:
    """Fold one ``mov r, src`` transfer into provenance state.

    Tracked deltas move only through whole-pointer transfers: ``mov sp,
    bp`` and ``mov bp, sp`` copy the source delta, a self-copy keeps it,
    and every other write — including partial aliases such as a byte
    spelling — widens the destination delta to unknown.
    """
    assigned: dict[str, bool] = {}
    sp_delta = state.sp_delta
    bp_delta = state.bp_delta
    raw_dest = _reg_name_8616(facts.insn, destination.reg)
    dest_name = _normalize_gpr_8616(raw_dest)
    if dest_name == "sp":
        source_name = (
            _normalize_gpr_8616(_reg_name_8616(facts.insn, source.reg))
            if source.type == 1
            else ""
        )
        if raw_dest not in _SP_FULL_NAMES_8616:
            sp_delta = None
        elif source_name == "bp":
            sp_delta = state.bp_delta
        elif source_name == "sp":
            sp_delta = state.sp_delta
        else:
            sp_delta = None
        return assigned, sp_delta, bp_delta, state.slot_mutated
    if dest_name not in _GPR_INDEX_8616:
        return assigned, sp_delta, bp_delta, state.slot_mutated
    if dest_name == "bp":
        source_name = (
            _normalize_gpr_8616(_reg_name_8616(facts.insn, source.reg))
            if source.type == 1
            else ""
        )
        if raw_dest not in _BP_FULL_NAMES_8616:
            bp_delta = None
        elif source_name == "sp":
            bp_delta = state.sp_delta
        elif source_name != "bp":
            bp_delta = None
    assigned[dest_name] = _mov_source_origin_8616(state, facts, source)
    return assigned, sp_delta, bp_delta, state.slot_mutated


def _step_mov_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> tuple[Mapping[str, bool], int | None, int | None, bool]:
    """Classify one ``mov``/``xchg``/``lea`` transfer.

    Returns ``(assigned, sp_delta, bp_delta, mutated)``; an unchanged
    delta is returned verbatim and ``None`` records an uncomputable one.
    """
    mnemonic = facts.mnemonic
    operands = facts.operands
    if mnemonic == "lea":
        return _step_lea_8616(state, facts)
    if mnemonic == "xchg" and len(operands) == 2:
        return _step_xchg_8616(state, facts)
    if mnemonic != "mov" or len(operands) != 2:
        return {}, state.sp_delta, state.bp_delta, state.slot_mutated
    destination, source = operands
    if destination.type == 3:
        mutated = _memory_write_mutates_8616(state, facts)
        return {}, state.sp_delta, state.bp_delta, state.slot_mutated or mutated
    if destination.type != 1:
        return {}, state.sp_delta, state.bp_delta, state.slot_mutated
    return _step_mov_reg_dest_8616(state, facts, destination, source)


def _mov_source_origin_8616(
    state: _PathState8616, facts: _InsnFacts8616, source: _OperandBoundary8616,
) -> bool:
    """Return continuation provenance for one ``mov`` source operand.

    A memory source binds only when its access provably reads the whole
    return word — a two- or four-byte load whose low word is exactly
    ``SS:[0:2)``. A byte load never binds a word of provenance.
    """
    if source.type == 1:
        source_name = _normalize_gpr_8616(_reg_name_8616(facts.insn, source.reg))
        if source_name in _GPR_INDEX_8616:
            return state.origins[_GPR_INDEX_8616[source_name]]
        return False
    if source.type == 3:
        slot = _stack_slot_8616(state, facts.insn, source.mem)
        width = _operand_width_8616(source)
        return bool(
            width in (2, 4)
            and _slot_is_return_word_8616(slot)
            and not state.slot_mutated
        )
    return False


def _xchg_delta_after_swap_8616(
    state: _PathState8616, receives: Mapping[str, str], target: str,
) -> int | None:
    """Return ``target``'s delta after a register swap, or the old delta.

    ``receives[name]`` is the normalized source register ``name``
    receives from; a pointer swapped with another tracked pointer
    exchanges deltas, a self-swap keeps it, and any other source widens
    the tracked delta to unknown.
    """
    source = receives.get(target)
    if source is None or source == target:
        return state.sp_delta if target == "sp" else state.bp_delta
    if source == "sp":
        return state.sp_delta
    if source == "bp":
        return state.bp_delta
    return None


def _step_xchg_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> tuple[Mapping[str, bool], int | None, int | None, bool]:
    """Fold one ``xchg`` swap into provenance state.

    Register-to-register swaps exchange continuation provenance only at
    word width or wider — a byte swap clears both carriers — and exchange
    the tracked ``sp``/``bp`` deltas when a pointer participates. A
    memory participant both reads and writes its slot, so overlap with
    the return word is a mutation and no provenance is bound.
    """
    assigned: dict[str, bool] = {}
    sp_delta = state.sp_delta
    bp_delta = state.bp_delta
    mutated = state.slot_mutated
    left, right = facts.operands
    if left.type == 1 and right.type == 1:
        left_name = _normalize_gpr_8616(_reg_name_8616(facts.insn, left.reg))
        right_name = _normalize_gpr_8616(_reg_name_8616(facts.insn, right.reg))
        width = _operand_width_8616(left)
        word_swap = width is not None and width >= 2
        left_origin = (
            state.origins[_GPR_INDEX_8616[left_name]]
            if word_swap and left_name in _GPR_INDEX_8616
            else False
        )
        right_origin = (
            state.origins[_GPR_INDEX_8616[right_name]]
            if word_swap and right_name in _GPR_INDEX_8616
            else False
        )
        if left_name in _GPR_INDEX_8616:
            assigned[left_name] = right_origin
        if right_name in _GPR_INDEX_8616:
            assigned[right_name] = left_origin
        receives = {left_name: right_name, right_name: left_name}
        sp_delta = _xchg_delta_after_swap_8616(state, receives, "sp")
        bp_delta = _xchg_delta_after_swap_8616(state, receives, "bp")
        return assigned, sp_delta, bp_delta, mutated
    memory_operand = left if left.type == 3 else right if right.type == 3 else None
    if memory_operand is not None:
        slot = _stack_slot_8616(state, facts.insn, memory_operand.mem)
        mutated = mutated or _store_overlaps_return_word_8616(
            slot, _operand_width_8616(memory_operand)
        )
    for operand in (left, right):
        if operand.type != 1:
            continue
        name = _normalize_gpr_8616(_reg_name_8616(facts.insn, operand.reg))
        if name in _GPR_INDEX_8616:
            assigned[name] = False
        if name == "sp":
            sp_delta = None
        elif name == "bp":
            bp_delta = None
    return assigned, sp_delta, bp_delta, mutated


def _tracked_pointer_delta_8616(
    state: _PathState8616, facts: _InsnFacts8616, target: str,
) -> int | None:
    """Return the post-instruction delta for one tracked stack pointer.

    Only constant arithmetic on the pointer — ``add``/``sub`` with an
    immediate and ``inc``/``dec`` — admits a tracked delta; every other
    write form (partial aliases included) widens to unknown so no stale
    frame delta can survive an unmodeled write.
    """
    mnemonic = facts.mnemonic
    operands = facts.operands
    delta = state.sp_delta if target == "sp" else state.bp_delta
    if delta is None:
        return None
    if (
        mnemonic in {"add", "sub"}
        and len(operands) == 2
        and operands[0].type == 1
        and _normalize_gpr_8616(_reg_name_8616(facts.insn, operands[0].reg))
        == target
        and operands[1].type == 2
    ):
        try:
            amount = int(operands[1].imm)
        except (TypeError, ValueError):
            return None
        return _bounded_delta_8616(
            delta + amount if mnemonic == "add" else delta - amount
        )
    if (
        mnemonic in {"inc", "dec"}
        and len(operands) == 1
        and operands[0].type == 1
        and _normalize_gpr_8616(_reg_name_8616(facts.insn, operands[0].reg))
        == target
    ):
        return _bounded_delta_8616(
            delta + 1 if mnemonic == "inc" else delta - 1
        )
    return None


def _pointer_written_8616(facts: _InsnFacts8616, names: frozenset[str]) -> bool:
    """Return whether the instruction writes any alias of ``names``."""
    return any(
        _normalize_gpr_8616(name) in names for name in facts.writes
    )


def _sp_written_8616(facts: _InsnFacts8616) -> bool:
    """Return whether the instruction writes any SP alias."""
    return _pointer_written_8616(facts, _SP_NAMES_8616)


def _bp_written_8616(facts: _InsnFacts8616) -> bool:
    """Return whether the instruction writes any BP alias."""
    return _pointer_written_8616(facts, _BP_NAMES_8616)


def _segment_clobber_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> _PathState8616:
    """Poison operand-level CS/SS clobbers the write audit may not report.

    Third-party ``regs_access`` is the primary write census, but an
    operand carrying an explicit write flag — or no access flag at all —
    for ``cs`` or ``ss`` is still a clobber claim; unknown access refuses
    rather than trusting a silent segment mutation.
    """
    result = state
    for operand in facts.operands:
        if operand.type != 1:
            continue
        name = _normalize_gpr_8616(_reg_name_8616(facts.insn, operand.reg))
        if name not in {"cs", "ss"}:
            continue
        try:
            access = int(operand.access)
        except (AttributeError, TypeError, ValueError):
            access = 0
        if access == 1:
            continue
        result = _poisoned_8616(
            result,
            NearReturnContinuationFailure8616.CS_CLOBBERED_ON_PATH
            if name == "cs"
            else NearReturnContinuationFailure8616.SS_CLOBBERED_ON_PATH,
        )
    return result


def _string_write_mnemonic_8616(mnemonic: str) -> bool:
    """Return whether a possibly REP-prefixed mnemonic writes string memory."""
    parts = mnemonic.split()
    base = parts[-1] if parts else mnemonic
    return base in _STRING_WRITE_MNEMONICS_8616


def _control_refusal_8616(
    facts: _InsnFacts8616, terminal: bool,
) -> NearReturnContinuationFailure8616 | None:
    """Classify control-transfer mnemonics into path poisons."""
    mnemonic = facts.mnemonic
    if is_x86_16_call_mnemonic_8616(mnemonic) or mnemonic in _INTERRUPT_MNEMONICS_8616:
        return NearReturnContinuationFailure8616.CALL_ON_PATH
    if mnemonic in _CS_TRANSFER_MNEMONICS_8616:
        return NearReturnContinuationFailure8616.CS_CLOBBERED_ON_PATH
    if mnemonic in _ANOMALOUS_TERMINALS_8616:
        return NearReturnContinuationFailure8616.UNKNOWN_EFFECT_ON_PATH
    if mnemonic in {"ret", "retn", "retw", "retq"}:
        return None if terminal else NearReturnContinuationFailure8616.UNKNOWN_EFFECT_ON_PATH
    if mnemonic in _BRANCH_TERMINAL_MNEMONICS_8616 or mnemonic.startswith("j"):
        return None if terminal else NearReturnContinuationFailure8616.UNKNOWN_EFFECT_ON_PATH
    return None


def _step_instruction_8616(
    state: _PathState8616, facts: _InsnFacts8616, *, terminal: bool,
) -> _PathState8616:
    """Advance one path state across one decoded instruction."""
    if facts.decode_failed:
        return _poisoned_8616(
            state, NearReturnContinuationFailure8616.UNKNOWN_EFFECT_ON_PATH
        )
    refusal = _control_refusal_8616(facts, terminal)
    if refusal is not None:
        return _poisoned_8616(state, refusal)
    if terminal and _is_branch_terminal_8616(facts):
        return state
    result = _audit_writes_8616(state, facts)
    result = _segment_clobber_8616(result, facts)
    stack_state, assigned, handled = _step_stack_forms_8616(result, facts)
    mutated = stack_state.slot_mutated
    sp_delta = stack_state.sp_delta
    bp_delta = stack_state.bp_delta
    if not handled:
        mov_assigned, sp_delta, bp_delta, mutated = _step_mov_8616(
            _PathState8616(
                result.origins, sp_delta, bp_delta, mutated, result.poisons
            ),
            facts,
        )
        assigned = {**assigned, **mov_assigned}
        transfer_resolved = (
            facts.mnemonic in {"mov", "xchg", "lea"}
            and len(facts.operands) == 2
        )
        if not transfer_resolved:
            # ``mov``/``xchg``/``lea`` already resolved their pointer
            # writes; every other SP/BP-writing form either proves a
            # constant delta or widens to unknown.
            if _sp_written_8616(facts):
                sp_delta = _tracked_pointer_delta_8616(result, facts, "sp")
            if _bp_written_8616(facts):
                bp_delta = _tracked_pointer_delta_8616(result, facts, "bp")
        if _string_write_mnemonic_8616(facts.mnemonic):
            mutated = True
        if _unknown_memory_write_8616(result, facts):
            mutated = True
    origins = _apply_origins_8616(result, assigned, facts.writes)
    return _PathState8616(
        origins=origins,
        sp_delta=sp_delta,
        bp_delta=bp_delta,
        slot_mutated=mutated,
        poisons=stack_state.poisons,
    )


def _is_branch_terminal_8616(facts: _InsnFacts8616) -> bool:
    """Return whether a terminal instruction is a pure edge producer.

    ``loop``/``jcxz`` variants are excluded: ``loop`` decrements ``cx``
    and must pass through the generic write rules so the terminal jump's
    provenance cannot survive a counter update.
    """
    mnemonic = facts.mnemonic
    if mnemonic in {"ret", "retn", "retw", "retq"}:
        return True
    return mnemonic.startswith("j") and mnemonic not in {"jcxz", "jecxz"}


def _unknown_memory_write_8616(
    state: _PathState8616, facts: _InsnFacts8616,
) -> bool:
    """Return whether any memory operand may be a store needing slot proof.

    Every memory operand is audited, not only operand 0: a reported
    read-only access is trusted, while a write flag or absent access
    evidence makes the operand a potential store — resolved by proving
    its byte range misses the return word, never by ignoring it.
    ``mov``/``xchg``/``lea`` memory operands are resolved by their own
    transfer rules upstream.
    """
    if (
        facts.mnemonic in _MEM_READ_MNEMONICS_8616
        or facts.mnemonic in {"mov", "xchg", "lea"}
    ):
        return False
    for operand in facts.operands:
        if operand.type != 3:
            continue
        try:
            access = int(operand.access)
        except (AttributeError, TypeError, ValueError):
            access = 0
        if access and not (access & 2):
            continue
        slot = _stack_slot_8616(state, facts.insn, operand.mem)
        if _store_overlaps_return_word_8616(slot, _operand_width_8616(operand)):
            return True
    return False


def _transfer_block_state_8616(
    entry_state: _PathState8616, instructions: Sequence[_InsnFacts8616],
) -> _PathState8616:
    """Fold one block's instruction facts into its exit state."""
    state = entry_state
    last_index = len(instructions) - 1
    for index, facts in enumerate(instructions):
        state = _step_instruction_8616(state, facts, terminal=index == last_index)
    return state


def _decode_instruction_8616(instruction: object) -> _InsnFacts8616 | None:
    """Reduce one angr-wrapped or bare Capstone instruction to facts."""
    wrapper = cast(_InstructionBoundary8616, instruction)
    try:
        insn = wrapper.insn
    except AttributeError:
        insn = cast(_DecodedInstructionBoundary8616, instruction)
    try:
        mnemonic = str(insn.mnemonic).lower()
        operands = tuple(insn.operands)
        address = int(insn.address)
    except (AttributeError, TypeError, ValueError):
        return None
    decode_failed = False
    try:
        reads_raw, writes_raw = insn.regs_access()
        reads = tuple(
            _normalize_gpr_8616(_reg_name_8616(insn, reg_id))
            for reg_id in reads_raw
        )
        writes = tuple(
            _normalize_gpr_8616(_reg_name_8616(insn, reg_id))
            for reg_id in writes_raw
        )
    except (AttributeError, TypeError, ValueError):
        decode_failed = True
        reads, writes = (), ()
    return _InsnFacts8616(
        address=address,
        mnemonic=mnemonic,
        operands=operands,
        reads=reads,
        writes=writes,
        decode_failed=decode_failed,
        insn=insn,
    )


def _block_facts_8616(block: object) -> tuple[_InsnFacts8616, ...]:
    """Return the decoded instruction facts for one census block."""
    boundary = cast(_BlockBoundary8616, block)
    if isinstance(block, DirectCapstoneBlock8616):
        instructions = tuple(block.instructions)
    else:
        try:
            instructions = tuple(boundary.capstone.insns)
        except (AttributeError, TypeError):
            return ()
    facts: list[_InsnFacts8616] = []
    for instruction in instructions:
        decoded = _decode_instruction_8616(instruction)
        if decoded is not None:
            facts.append(decoded)
    return tuple(facts)


def _indirect_terminal_operand_8616(
    facts: _InsnFacts8616,
) -> _OperandBoundary8616 | None:
    """Return the single operand of an indirect ``jmp`` terminal, if any."""
    if facts.mnemonic != "jmp" or len(facts.operands) != 1:
        return None
    operand = facts.operands[0]
    if operand.type in {1, 3}:
        return operand
    return None


def _propagate_states_8616(
    blocks_by_addr: Mapping[int, tuple[_InsnFacts8616, ...]],
    predecessors: Mapping[int, tuple[int, ...]],
    entry: int,
) -> dict[int, _PathState8616] | None:
    """Run the bounded join fixpoint and return per-block entry states."""
    entry_state = _PathState8616(
        origins=tuple(False for _ in _GPR_ORDER_8616),
        sp_delta=0,
        bp_delta=None,
        slot_mutated=False,
        poisons=frozenset(),
    )
    ins: dict[int, _PathState8616] = {}
    outs: dict[int, _PathState8616] = {}
    max_passes = 4 * (len(blocks_by_addr) + 2)
    for _ in range(max_passes):
        changed = False
        for addr in sorted(blocks_by_addr):
            merged: _PathState8616 | None = entry_state if addr == entry else None
            for pred in predecessors.get(addr, ()):
                merged = _merge_states_8616(merged, outs.get(pred))
            if merged is None:
                continue
            new_out = _transfer_block_state_8616(merged, blocks_by_addr[addr])
            if ins.get(addr) != merged or outs.get(addr) != new_out:
                ins[addr] = merged
                outs[addr] = new_out
                changed = True
        if not changed:
            return ins
    return None


def _reported_failure_8616(
    poisons: frozenset[NearReturnContinuationFailure8616],
) -> NearReturnContinuationFailure8616 | None:
    """Pick the deterministic representative of merged path poisons."""
    for reason in _FAILURE_PRIORITY_8616:
        if reason in poisons:
            return reason
    return None


def _terminal_operand_width_8616(
    facts: _InsnFacts8616, operand: _OperandBoundary8616,
) -> int | None:
    """Return the admitted access width for an indirect ``jmp`` operand.

    Every decode signal present must agree: Capstone's operand access
    size, the ``0x66`` operand-size prefix, and — for register operands —
    the architectural width of the named register. Contradictory or
    absent evidence yields ``None`` rather than guessing a 16-bit near
    target, because a wide jump observes upper bits this proof never
    constrains.
    """
    signals: set[int] = set()
    size = _operand_width_8616(operand)
    if size is not None:
        signals.add(size)
    override = _operand_size_override_8616(facts.insn)
    if override is not None:
        signals.add(4 if override else 2)
    if operand.type == 1:
        name = _reg_name_8616(facts.insn, operand.reg)
        if name in _REG16_NAMES_8616:
            signals.add(2)
        elif name in _REG32_NAMES_8616:
            signals.add(4)
        elif name in _REG8_NAMES_8616:
            signals.add(1)
    if len(signals) != 1:
        return None
    return next(iter(signals))


def _evaluate_candidate_8616(
    block_addr: int,
    instructions: tuple[_InsnFacts8616, ...],
    operand: _OperandBoundary8616,
    state: _PathState8616 | None,
) -> NearReturnContinuationRecord8616:
    """Decide one indirect terminal under its merged path state.

    The operand's access width must provably be the 16-bit near-transfer
    width before provenance is consulted: a wider ``jmp`` observes upper
    bits or far frames this model does not constrain.
    """
    terminal_addr = instructions[-1].address
    if state is None:
        return NearReturnContinuationRecord8616(
            block_addr,
            terminal_addr,
            NearReturnContinuationVerdict8616.REFUSED,
            NearReturnContinuationFailure8616.PATH_INCOMPLETE,
        )
    poison = _reported_failure_8616(state.poisons)
    if poison is not None:
        return NearReturnContinuationRecord8616(
            block_addr,
            terminal_addr,
            NearReturnContinuationVerdict8616.REFUSED,
            poison,
        )
    width = _terminal_operand_width_8616(instructions[-1], operand)
    if width != 2:
        return NearReturnContinuationRecord8616(
            block_addr,
            terminal_addr,
            NearReturnContinuationVerdict8616.REFUSED,
            NearReturnContinuationFailure8616.WIDTH_UNADMITTED,
        )
    if operand.type == 1:
        name = _normalize_gpr_8616(
            _reg_name_8616(instructions[-1].insn, operand.reg)
        )
        proven = (
            name in _GPR_INDEX_8616
            and state.origins[_GPR_INDEX_8616[name]]
        )
        return NearReturnContinuationRecord8616(
            block_addr,
            terminal_addr,
            NearReturnContinuationVerdict8616.PROVEN
            if proven
            else NearReturnContinuationVerdict8616.REFUSED,
            None
            if proven
            else NearReturnContinuationFailure8616.CONTINUATION_NOT_BOUND,
            NearReturnContinuationKind8616.REGISTER if proven else None,
            name if proven else None,
        )
    slot = _stack_slot_8616(state, instructions[-1].insn, operand.mem)
    proven = _slot_is_return_word_8616(slot) and not state.slot_mutated
    return NearReturnContinuationRecord8616(
        block_addr,
        terminal_addr,
        NearReturnContinuationVerdict8616.PROVEN
        if proven
        else NearReturnContinuationVerdict8616.REFUSED,
        None
        if proven
        else (
            NearReturnContinuationFailure8616.CONTINUATION_MUTATED
            if _slot_is_return_word_8616(slot) and state.slot_mutated
            else NearReturnContinuationFailure8616.MEMORY_FORM_UNPROVED
        ),
        NearReturnContinuationKind8616.STACK_SLOT if proven else None,
        None,
    )


def _premise_failure_8616(
    premise: NearCallFramePremise8616 | None,
    entry: int,
) -> NearReturnContinuationFailure8616 | None:
    """Classify the source-bound premise for one exact callee head."""
    if (
        premise is None
        or type(premise) is not NearCallFramePremise8616
        or premise.kind is not EntryTopSlotKind8616.NEAR_CALL_CONTINUATION
    ):
        return NearReturnContinuationFailure8616.PREMISE_ABSENT
    if premise.callee_addr != entry:
        return NearReturnContinuationFailure8616.PREMISE_FOREIGN
    if near_call_frame_premise_stale_8616(premise):
        return NearReturnContinuationFailure8616.PREMISE_STALE
    return None


def _candidate_records_8616(
    candidates: Mapping[int, tuple[_InsnFacts8616, ...]],
    facts_by_addr: Mapping[int, tuple[_InsnFacts8616, ...]],
    predecessors: Mapping[int, tuple[int, ...]],
    entry: int,
) -> list[NearReturnContinuationRecord8616]:
    """Evaluate every candidate block under the proven entry states."""
    entry_states = _propagate_states_8616(facts_by_addr, predecessors, entry)
    records: list[NearReturnContinuationRecord8616] = []
    for addr, facts in sorted(candidates.items()):
        if entry_states is None:
            records.append(
                NearReturnContinuationRecord8616(
                    addr,
                    facts[-1].address,
                    NearReturnContinuationVerdict8616.REFUSED,
                    NearReturnContinuationFailure8616.FIXPOINT_UNBOUNDED,
                )
            )
            continue
        state = entry_states.get(addr)
        pre_terminal = (
            None
            if state is None
            else _transfer_block_state_8616(state, facts[:-1])
        )
        operand = _indirect_terminal_operand_8616(facts[-1])
        assert operand is not None
        records.append(
            _evaluate_candidate_8616(addr, facts, operand, pre_terminal)
        )
    return records


def prove_near_return_continuations_8616(
    blocks: Sequence[object],
    successor_edges: Sequence[tuple[int, int]],
    *,
    entry: int,
    premise: NearCallFramePremise8616 | None,
) -> NearReturnContinuationArtifact8616:
    """Prove indirect terminals that continue to the near-CALL return word.

    Consumes the closed decoded block/edge census — never raw bytes,
    rendered assembly, names, or addresses — under the source-bound
    ``premise``. A premise bound to another head refuses with
    ``PREMISE_FOREIGN``; one whose retained index no longer authenticates
    the identical row refuses with ``PREMISE_STALE``; an absent or
    untyped premise refuses with ``PREMISE_ABSENT``. Only then does a
    candidate prove — when every binary-proven path from entry leaves the
    jump operand bound to the entry-frame top slot, with CS and SS
    preserved, no intervening call, no slot mutation, and no
    unclassified effect on any path. Everything else keeps a typed
    refusal.
    """
    facts_by_addr: dict[int, tuple[_InsnFacts8616, ...]] = {}
    for block in blocks:
        boundary = cast(_BlockBoundary8616, block)
        try:
            block_addr = int(boundary.addr)
        except (AttributeError, TypeError, ValueError):
            continue
        facts = _block_facts_8616(block)
        if facts:
            facts_by_addr[block_addr] = facts
    predecessor_lists: dict[int, list[int]] = {}
    for source, target in successor_edges:
        predecessor_lists.setdefault(target, []).append(source)
    predecessors = {
        target: tuple(sorted(set(sources)))
        for target, sources in predecessor_lists.items()
    }
    candidates = {
        addr: facts
        for addr, facts in facts_by_addr.items()
        if facts and _indirect_terminal_operand_8616(facts[-1]) is not None
    }
    records: list[NearReturnContinuationRecord8616] = []
    premise_failure = _premise_failure_8616(premise, entry)
    if premise_failure is not None:
        for addr, facts in sorted(candidates.items()):
            records.append(
                NearReturnContinuationRecord8616(
                    addr,
                    facts[-1].address,
                    NearReturnContinuationVerdict8616.REFUSED,
                    premise_failure,
                )
            )
    else:
        records.extend(
            _candidate_records_8616(
                candidates, facts_by_addr, predecessors, entry
            )
        )
    count = len(records)
    proven = sum(
        record.verdict is NearReturnContinuationVerdict8616.PROVEN
        for record in records
    )
    return NearReturnContinuationArtifact8616(
        records=tuple(records),
        raw_fact_count=count,
        normalized_fact_count=count,
        classified_fact_count=count,
        materialized_count=proven,
        failure_count=count - proven,
        premise=(
            premise if type(premise) is NearCallFramePremise8616 else None
        ),
    )

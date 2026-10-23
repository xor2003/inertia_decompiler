"""Layer: native i386 x87 instruction semantics.

Responsibility: decode admitted x87 instructions and waiting forms at
the native boundary and preserve their complete architectural effects. Never
reinterpret lossy VEX FPU helpers as native word semantics. Pending exception delivery retains explicit obligations; unadmitted x87 updates remain refusals.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import capstone
from capstone.x86_const import X86_INS_FLDCW, X86_INS_FNSTCW, X86_INS_FNSTSW, X86_OP_MEM

from tools.dosunit.ssa.materialization import input_items, materialize_term


@dataclass(frozen=True)
class ControlWordStore:
    """Byte-admitted default-address-size FNSTCW effective address."""

    base: str | None
    index: str | None
    scale: int
    displacement: int


@dataclass(frozen=True)
class StatusWordRead:
    """Nonwaiting status-word read; no memory destination means AX."""

    destination: ControlWordStore | None


@dataclass(frozen=True)
class ControlWordLoad:
    """Byte-admitted default-address-size FLDCW memory source."""

    source: ControlWordStore


@dataclass(frozen=True)
class StatusWordClear:
    """Nonwaiting FNCLEX status-flag clear."""


@dataclass(frozen=True)
class FpuInit:
    """Nonwaiting FNINIT full-unit initialization."""


@dataclass(frozen=True)
class FpuWait:
    """FWAIT (0x9B): the pending-exception check with no state effect."""


@dataclass(frozen=True)
class WaitForm:
    """9B-prefixed waiting variant of an architectural non-checking form.

    FINIT/FCLEX/FSTENV/FSAVE/FSTCW/FSTSW deliver any pending
    unmasked exception before executing — exactly their FN* sibling's normal
    effects preceded by the checking obligation.
    """

    inner: NativeX87Instruction


@dataclass(frozen=True)
class FpuNop:
    """FNOP checks pending exceptions and records the instruction environment."""


if TYPE_CHECKING:
    from tools.dosunit.architectures.flat32_x87_arith import X87ArithInstruction
    from tools.dosunit.architectures.flat32_x87_stack import X87StackInstruction

    type NativeX87Instruction = (
        ControlWordStore | StatusWordRead | ControlWordLoad | StatusWordClear | FpuInit
        | FpuNop | FpuWait | WaitForm | X87StackInstruction | X87ArithInstruction
    )
else:
    type NativeX87Instruction = (
        ControlWordStore | StatusWordRead | ControlWordLoad | StatusWordClear | FpuInit
        | FpuNop | FpuWait | WaitForm | Any
    )

# Declared Pentium-class FLDCW reserved-bit policy, observed on the recorded
# host probe and in Bochs 5c357adef5bc62e1ddf7f43a8488e84d48316c44
# (bochs/cpu/fpu/fpu.cc): keep bits 0-5 and 8-12, force bit 6 set, clear bits
# 7 and 13-15. Unicorn executes FLDCW but presents UC_X86_REG_FPCW
# byte-swapped relative to the stored word, does not normalize the reserved
# bits and does not recompute the ES/B summary bits, so it is not a usable
# oracle for this declared policy.
FLDCW_RESERVED_MASK: int = 0x1F3F
FLDCW_RESERVED_SET: int = 0x0040
FLDCW_RESERVED_POLICY: str = "pentium_class_bochs"

# Exception flag and summary bits of the status word.
X87_SW_EXCEPTION_MASK: int = 0x003F
X87_SW_SUMMARY_BUSY: int = 0x8080
X87_SW_SUMMARY_BUSY_CLEAR: int = 0x7F7F

# Every x87 instruction except the architectural FN* non-checking set
# (FNINIT, FNCLEX, FNSTCW, FNSTSW, FNSTENV, FNSAVE) first delivers any
# pending unmasked exception: (sw & ~cw & 0x003f) != 0 means the instruction
# never reaches its normal continuation and #MF is delivered instead. The
# native bodies model only the non-trapping continuation; the obligation is
# serialized as a premise and propagates to a public conditional verdict.
X87_PREMISE_NO_PENDING_UNMASKED: str = "x87_no_unmasked_pending_exception"
X87_PREMISE_CPU_POLICY: str = "x87_cpu_policy_pentium_class"


def _premise_pending() -> dict[str, str]:
    """Serialize the pending-unmasked-exception checking contract.

    The authoritative domain is the typed ``x87_pending_check`` obligation
    bound per site; this record documents the contract only, so it carries
    no unbound entry-register text that could be mistaken for the bound
    predicate.
    """
    return {
        "kind": X87_PREMISE_NO_PENDING_UNMASKED,
        "contract": "site obligations require (sw & ~cw & 0x003f) == 0 at each checking instruction",
        "effect": "otherwise the instruction traps to #MF instead of executing",
    }


def _premise_cpu_policy(detail: str) -> dict[str, str]:
    """Serialize a declared Pentium-class CPU-policy premise."""
    return {"kind": X87_PREMISE_CPU_POLICY, "policy": FLDCW_RESERVED_POLICY, "effect": detail}


# Instruction classes that execute the x87 pending-exception check before
# their normal continuation (FLDCW, FNOP and every later checking family;
# the FN* non-checking set is exempt).
CHECKING_INSTRUCTIONS: tuple[type, ...] = (ControlWordLoad, FpuNop,
                                          FpuWait, WaitForm)


def _pending_guard_term() -> dict[str, Any]:
    """Serialize the no-unmasked-pending guard over the entry CW/SW inputs.

    The term is expressed over the owning body's own ``x87_status_word`` /
    ``x87_control_word`` inputs so every composition lane binds it to the
    exact composed state at the instruction site with the ordinary
    ``substitute_inputs`` mechanism.
    """
    status = {"op": "input", "width": 16, "name": "x87_status_word"}
    control = {"op": "input", "width": 16, "name": "x87_control_word"}
    masks = {"op": "and", "width": 16, "args": [
        {"op": "not", "width": 16, "args": [control]}, _constant(X87_SW_EXCEPTION_MASK, 16)]}
    pending = {"op": "and", "width": 16, "args": [status, masks]}
    return {"op": "eq", "width": 1, "args": [pending, _constant(0, 16)]}


def pending_check_obligation(instruction: NativeX87Instruction, *, address: int) -> dict[str, Any] | None:
    """Serialize this instruction's typed pending-exception obligation.

    Returns ``None`` for the architectural non-checking FN* forms.  The
    returned record carries the instruction address and a bound-agnostic
    guard term; composition binds the term to the composed state reaching
    this exact site before the comparison domain enforces it.
    """
    from tools.dosunit.architectures.flat32_x87_arith import X87_ARITH_CHECKING
    from tools.dosunit.architectures.flat32_x87_stack import X87_STACK_CHECKING
    if not isinstance(instruction, CHECKING_INSTRUCTIONS + X87_STACK_CHECKING + X87_ARITH_CHECKING):
        return None
    return {
        "kind": "x87_pending_check",
        "address": address,
        "predicate": _pending_guard_term(),
    }


def bind_x87_obligations(
    part: dict[str, Any], incoming_state: dict[str, dict[str, Any]],
    *, site: dict[str, Any] | None = None,
    guard: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Bind a part's serialized obligations to the composed entry state.

    Each checking-instruction predicate references the part's own inputs;
    substituting the incoming state produces a predicate over the enclosing
    function's entry inputs and path composition — the honest domain in
    which the modeled normal continuation executes.  ``guard`` is the
    width-1 path condition under which this site is reached: a site behind
    a conditional branch only executes under its actual guard, so the bound
    obligation is ``ite(guard, predicate, 1)`` rather than an unconditional
    entry assumption.
    """
    from tools.dosunit.ssa.composition import substitute_inputs

    bound: list[dict[str, Any]] = []
    for obligation in part.get("obligations", ()) or ():
        predicate = obligation.get("predicate")
        if not isinstance(predicate, dict):
            continue
        term = substitute_inputs(predicate, incoming_state)
        if guard is not None:
            term = {
                "op": "ite", "width": 1,
                "args": [guard, term, {"op": "const", "width": 1, "value": "0x1"}],
            }
        bound.append({
            **obligation,
            **({"site": site} if site else {}),
            "predicate": term,
        })
    return bound

# FNCLEX clears IE/DE/ZE/OE/UE/PE (0-5), SF (6), ES (7) and B (15), keeping
# C0-C3 and TOP. Verified against Unicorn instruction execution.
FNCLEX_PRESERVED_MASK: int = 0x7F00

# FNINIT architectural results (SDM FINIT/FNINIT): control word 0x037F,
# status word 0, all-empty tag word and a zeroed pointer/opcode environment.
FNINIT_CONTROL_WORD: int = 0x037F
FNINIT_TAG_WORD: int = 0xFFFF
X87_ENVIRONMENT_REGISTERS: tuple[str, ...] = ("x87_fip", "x87_fcs_op", "x87_fdp", "x87_fds")

# 11-bit last-instruction opcode field recorded for D9 D0 (Bochs
# FPU_update_last_instruction: the modrm C0 bits are not part of the
# architectural opcode field).
FNOP_OPCODE: int = 0x01D0

_X87_PREFIXES = frozenset({0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65})


def unmodeled_x87_status_write(raw: bytes) -> bool:
    """Recognize an x87-family update not admitted at the native boundary.

    VEX erases or narrows several x87 state writes (FNCLEX becomes a bare
    EIP write, FLDCW keeps only fpround, FNINIT hides behind a dirty
    helper). Any instruction in the 0xD8-0xDF x87 opcode map, or FWAIT,
    that ``decode_native_x87`` does not admit must refuse rather than
    inherit a lossy VEX projection.
    """
    opcode = _x87_opcode_byte(raw)
    return opcode is not None and decode_native_x87(raw) is None


def _x87_opcode_byte(raw: bytes) -> int | None:
    """Return the first x87-map or WAIT opcode byte after legacy prefixes."""
    index = 0
    while index < len(raw) and raw[index] in _X87_PREFIXES:
        index += 1
    if index >= len(raw):
        return None
    byte = raw[index]
    if byte == 0x9B or 0xD8 <= byte <= 0xDF:
        return byte
    return None


def decode_native_x87(raw: bytes) -> NativeX87Instruction | None:
    """Decode one admitted x87 instruction, standalone FWAIT, or waiting form.

    Default-address-size forms and recognized waiting variants are admitted;
    other prefixes remain unadmitted.
    """
    if raw[:1] == b"\x9b":
        return _decode_waiting_form(raw)
    if raw == b"\xdb\xe2":
        return StatusWordClear()
    if raw == b"\xdb\xe3":
        return FpuInit()
    if raw == b"\xd9\xd0":
        return FpuNop()
    word = decode_native_x87_word(raw)
    if word is not None:
        return word
    if raw and raw[0] == 0xD9:
        source = _decode_word_memory(raw, X86_INS_FLDCW)
        if source is not None:
            return ControlWordLoad(source)
    # Lazy import: the stack owner imports this module's shared helpers, so
    # the dependency can only resolve at call time.
    from tools.dosunit.architectures.flat32_x87_stack import decode_x87_stack
    stack = decode_x87_stack(raw)
    if stack is not None:
        return stack
    from tools.dosunit.architectures.flat32_x87_arith import decode_x87_arith
    return decode_x87_arith(raw)


def decode_native_x87_word(raw: bytes) -> ControlWordStore | StatusWordRead | None:
    """Decode exactly one unprefixed word read with default address size."""
    if raw == b"\xdf\xe0":
        return StatusWordRead(None)
    if raw and raw[0] == 0xDD:
        destination = _decode_word_memory(raw, X86_INS_FNSTSW)
        return StatusWordRead(destination) if destination is not None else None
    return decode_control_word_store(raw)


def decode_control_word_store(raw: bytes) -> ControlWordStore | None:
    """Admit exactly one unprefixed D9 /7 memory instruction.

    WAIT, segment/address overrides, truncated bytes and trailing instructions
    retain ordinary lowering. Capstone supplies decoded ModRM/SIB fields only.
    """
    if not raw or raw[0] != 0xD9:
        return None
    return _decode_word_memory(raw, X86_INS_FNSTCW)


def _decode_word_memory(raw: bytes, instruction_id: int) -> ControlWordStore | None:
    """Extract a complete native word instruction's default flat32 address."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instruction = next(decoder.disasm(raw, 0), None)
    if instruction is None or instruction.id != instruction_id or instruction.size != len(raw):
        return None
    operand = instruction.operands[0]
    if operand.type != X86_OP_MEM or operand.mem.segment:
        return None
    memory = operand.mem
    return ControlWordStore(instruction.reg_name(memory.base) if memory.base else None,
                            instruction.reg_name(memory.index) if memory.index else None,
                            memory.scale, memory.disp)


def _constant(value: int, width: int = 32) -> dict[str, Any]:
    """Return a modular flat32 constant."""
    return {"op": "const", "width": width, "value": hex(value & ((1 << width) - 1))}


def control_word_store_body(
    instruction: ControlWordStore, *, continuation: int, registers: dict[str, int],
) -> dict[str, Any]:
    """Serialize a native store with unchanged scalar state and little-endian memory.

    The control word is an independent full-width architectural input.
    Unsupported x87 writers must refuse rather than reuse an entry value.
    """
    return native_x87_word_body(instruction, continuation=continuation, registers=registers)


def native_x87_word_body(
    instruction: ControlWordStore | StatusWordRead, *, continuation: int, registers: dict[str, int],
) -> dict[str, Any]:
    """Read a complete x87 word, preserving memory or the high half of EAX.

    Status includes TOP and all condition/exception bits as an architectural
    input. Unmodeled x87 writers remain rejected by ordinary lowering.
    """
    return native_x87_body(instruction, continuation=continuation, registers=registers)


def native_x87_body(
    instruction: NativeX87Instruction, *, continuation: int, registers: dict[str, int],
    address: int | None = None,
) -> dict[str, Any]:
    """Serialize one admitted x87 instruction's non-trapping continuation.

    ``address`` is the instruction's own address and is required by
    instructions that update the last-instruction environment (FNOP);
    it defaults to ``continuation - 2``, exact for every two-byte admitted
    form. Every output not written by the instruction stays an independent
    architectural input. The control word, status word (with TOP and all
    condition/exception bits), tag word and pointer/opcode environment are
    full-width state; lossy VEX projections are never reused as their
    values. Checking instructions serialize their entry predicate into
    ``summary["premises"]`` for the verdict owners.
    """
    if address is None:
        address = continuation - (1 if isinstance(instruction, FpuWait) else 2)
    state: dict[str, dict[str, Any]] = {
        name: {"op": "input", "width": width, "name": name} for name, width in registers.items()
    }
    memory = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    state["memory"] = memory
    summary: dict[str, Any] = {"kind": _native_x87_kind(instruction)}
    pre = dict(state)
    _apply_x87_effects(instruction, state, memory, summary, address)
    checking = pending_check_obligation(instruction, address=address)
    if checking is not None:
        # Observable pending-#MF control flow: a checking instruction
        # delivers the exception BEFORE executing, so with a pending
        # unmasked exception every effect (registers, tags, TOP, env
        # pointers, memory stores) is suppressed.  Non-checking FN*
        # forms still run unconditionally.  Delivery-to-handler itself
        # stays with the typed obligation/verdict owners; eip/ip model
        # the comparison continuation and are not gated.
        sw0, cw0 = pre["x87_status_word"], pre["x87_control_word"]
        masks = {"op": "and", "width": 16, "args": [
            {"op": "not", "width": 16, "args": [cw0]},
            _constant(X87_SW_EXCEPTION_MASK, 16)]}
        pending = {"op": "and", "width": 16, "args": [sw0, masks]}
        guard = {"op": "eq", "width": 1,
                 "args": [pending, _constant(0, 16)]}
        for name, term in state.items():
            if name in pre and term is not pre[name] and term != pre[name]:
                state[name] = {"op": "ite", "width": term["width"],
                               "args": [guard, term, pre[name]]}
    state["eip"] = _constant(continuation)
    state["ip"] = state["eip"]
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    outputs = {name: materialize_term(term, assignments=assignments, memo=memo)
               for name, term in state.items()}
    obligations = [pending_check_obligation(instruction, address=address)]
    return {"outputs": outputs, "assignments": assignments,
            "inputs": input_items(outputs.values(), assignments),
            "obligations": [item for item in obligations if item is not None],
            "summary": summary}


def _apply_x87_effects(
    instruction: NativeX87Instruction, state: dict[str, dict[str, Any]],
    memory: dict[str, Any], summary: dict[str, Any], address: int,
) -> None:
    """Write one admitted instruction's architectural effects into the state.

    Only the named outputs change; every other output remains its input.
    """
    from tools.dosunit.architectures.flat32_x87_stack import apply_x87_stack_effects, is_x87_stack_instruction
    if is_x87_stack_instruction(instruction):
        apply_x87_stack_effects(instruction, state, memory, summary, address)
        return
    from tools.dosunit.architectures.flat32_x87_arith import apply_x87_arith_effects, is_x87_arith_instruction
    if is_x87_arith_instruction(instruction):
        apply_x87_arith_effects(instruction, state, memory, summary, address)
        return
    if isinstance(instruction, (StatusWordRead, ControlWordStore)):
        _word_store_effects(instruction, state, memory)
    elif isinstance(instruction, ControlWordLoad):
        _fldcw_effects(instruction, state, memory, summary)
    elif isinstance(instruction, StatusWordClear):
        state["x87_status_word"] = {"op": "and", "width": 16, "args": [
            {"op": "input", "width": 16, "name": "x87_status_word"},
            _constant(FNCLEX_PRESERVED_MASK, 16)]}
        summary["premises"] = [_premise_cpu_policy(
            "FNCLEX preserves C0-C3 and TOP exactly as the declared Pentium-class model "
            "(Bochs partial status word); the SDM leaves the condition codes undefined"
        )]
    elif isinstance(instruction, FpuInit):
        state["x87_control_word"] = _constant(FNINIT_CONTROL_WORD, 16)
        state["x87_status_word"] = _constant(0, 16)
        state["x87_tag_word"] = _constant(FNINIT_TAG_WORD, 16)
        for name in X87_ENVIRONMENT_REGISTERS:
            state[name] = _constant(0, 32)
    elif isinstance(instruction, (FpuWait, WaitForm)):
        _wait_effects(instruction, state, memory, summary, address)
    elif isinstance(instruction, FpuNop):
        # Pentium-class contract: FNOP is a checking instruction (premise)
        # and records its own address and opcode in the last-instruction
        # environment (Bochs FPU_update_last_instruction; register-form
        # instructions do not update FDP/FDS).
        state["x87_fip"] = _constant(address)
        state["x87_fcs_op"] = {"op": "or", "width": 32, "args": [
            _constant(FNOP_OPCODE << 16), {"op": "zext", "width": 32, "args": [
                {"op": "input", "width": 16, "name": "cs"}]}]}
        summary["premises"] = [_premise_pending()]
    else:
        raise ValueError(f"unsupported native x87 instruction: {instruction!r}")


def _decode_waiting_form(raw: bytes) -> NativeX87Instruction | None:
    """Decode FWAIT and 9B-prefixed waiting variants of non-checking FN*."""
    if raw == b"\x9b":
        return FpuWait()
    inner = decode_native_x87(raw[1:])
    # Only the architectural non-checking FN* set gains the check from
    # the 9B prefix; a checking op after 9B is two instructions.
    from tools.dosunit.architectures.flat32_x87_arith import EnvStore
    # Only nonchecking FN* forms gain a 9B waiting variant; 9B in front of
    # a checking instruction (incl. FLDENV/FRSTOR) is two instructions.
    if isinstance(inner, (FpuInit, StatusWordClear, ControlWordStore,
                          StatusWordRead, EnvStore)):
        return WaitForm(inner)
    return None


def _word_store_effects(instruction: StatusWordRead | ControlWordStore,
                        state: dict[str, dict[str, Any]],
                        memory: dict[str, Any]) -> None:
    """FNSTSW/FNSTCW: copy the 16-bit word to AX or to the memory slot."""
    word_name = "x87_status_word" if isinstance(instruction, StatusWordRead) else "x87_control_word"
    word = {"op": "input", "width": 16, "name": word_name}
    if isinstance(instruction, StatusWordRead):
        destination = instruction.destination
        if destination is None:
            preserved = {"op": "and", "width": 32, "args": [
                {"op": "input", "width": 32, "name": "eax"}, _constant(0xFFFF0000)]}
            state["eax"] = {"op": "or", "width": 32, "args": [
                preserved, {"op": "zext", "width": 32, "args": [word]}]}
        else:
            state["memory"] = {"op": "storele", "width": 0, "args": [memory, _word_address(destination), word]}
    else:
        state["memory"] = {"op": "storele", "width": 0, "args": [memory, _word_address(instruction), word]}


def _fldcw_effects(instruction: ControlWordLoad,
                   state: dict[str, dict[str, Any]], memory: dict[str, Any],
                   summary: dict[str, Any]) -> None:
    """FLDCW: reserved-bit normalization plus the ES/B recompute."""
    loaded = {"op": "loadle", "width": 16, "args": [memory, _word_address(instruction.source)]}
    masked = {"op": "and", "width": 16, "args": [loaded, _constant(FLDCW_RESERVED_MASK, 16)]}
    new_cw = {"op": "or", "width": 16, "args": [masked, _constant(FLDCW_RESERVED_SET, 16)]}
    state["x87_control_word"] = new_cw
    # After the new masks are installed the FPU recomputes whether an
    # exception remains unmasked and updates ES and B accordingly
    # (Bochs set/clear_unmasked_fpu_exception; Pentium-class policy).
    status = {"op": "input", "width": 16, "name": "x87_status_word"}
    unmasked = {"op": "and", "width": 16, "args": [status, {"op": "and", "width": 16, "args": [
        {"op": "not", "width": 16, "args": [new_cw]}, _constant(X87_SW_EXCEPTION_MASK, 16)]}]}
    pending = {"op": "ne", "width": 1, "args": [unmasked, _constant(0, 16)]}
    state["x87_status_word"] = {"op": "or", "width": 16, "args": [
        {"op": "and", "width": 16, "args": [status, _constant(X87_SW_SUMMARY_BUSY_CLEAR, 16)]},
        {"op": "ite", "width": 16, "args": [pending,
                                            _constant(X87_SW_SUMMARY_BUSY, 16), _constant(0, 16)]}]}
    summary["premises"] = [
        _premise_pending(),
        _premise_cpu_policy(
            "FLDCW reserved-bit normalization and the ES/B recompute follow the declared "
            "Pentium-class contract; other CPU generations may differ in reserved bits"
        ),
    ]


def _wait_effects(instruction: FpuWait | WaitForm,
                  state: dict[str, dict[str, Any]], memory: dict[str, Any],
                  summary: dict[str, Any], address: int) -> None:
    """Waiting forms: pending-exception premise plus the inner effects."""
    if isinstance(instruction, WaitForm):
        _apply_x87_effects(instruction.inner, state, memory, summary, address)
    summary["premises"] = [*summary.get("premises", []), _premise_pending()]


def _native_x87_kind(instruction: NativeX87Instruction) -> str:
    """Name the admitted instruction family for provenance records."""
    if isinstance(instruction, StatusWordRead):
        return "native_fnstsw"
    if isinstance(instruction, ControlWordStore):
        return "native_fnstcw"
    if isinstance(instruction, ControlWordLoad):
        return "native_fldcw"
    if isinstance(instruction, StatusWordClear):
        return "native_fnclex"
    if isinstance(instruction, FpuInit):
        return "native_fninit"
    if isinstance(instruction, FpuWait):
        return "native_fwait"
    if isinstance(instruction, WaitForm):
        return f"native_wait_{_native_x87_kind(instruction.inner)}"
    if isinstance(instruction, FpuNop):
        return "native_fnop"
    from tools.dosunit.architectures.flat32_x87_stack import is_x87_stack_instruction, x87_stack_kind
    if is_x87_stack_instruction(instruction):
        return x87_stack_kind(instruction)
    from tools.dosunit.architectures.flat32_x87_arith import x87_arith_kind
    return x87_arith_kind(instruction)


def _word_address(instruction: ControlWordStore) -> dict[str, Any]:
    """Construct modular base/index/displacement for a two-byte access."""
    address = _constant(instruction.displacement)
    for name, scale in ((instruction.base, 1), (instruction.index, instruction.scale)):
        if name is not None:
            term = {"op": "input", "width": 32, "name": name}
            if scale != 1:
                term = {"op": "mul", "width": 32, "args": [term, _constant(scale)]}
            address = {"op": "add", "width": 32, "args": [address, term]}
    return address

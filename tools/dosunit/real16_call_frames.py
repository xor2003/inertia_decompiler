"""Binary-derived return frames for real16 direct-call proof composition.

Layer: dosunit call proof control.
Responsibility: decode CALL operand/frame kinds from exact instruction bytes
and recover the caller CS from the actual pushed frame. No symbols, rendered
assembly, convention guesses or callee-state assumptions establish a frame.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import capstone
from capstone import x86_const

from tools.dosunit.real16_call_contracts import Real16CallRefusal
from tools.dosunit.real16_call_evidence import block_source


class CallFrameKind(StrEnum):
    """Architectural CALL frame width and presence of the saved selector."""

    NEAR16 = "near16"
    FAR16 = "far16"
    NEAR32 = "near32"
    FAR32 = "far32"

    @property
    def offset_bytes(self) -> int:
        """Number of bytes stored for the saved IP/EIP."""
        return 4 if self in {CallFrameKind.NEAR32, CallFrameKind.FAR32} else 2

    @property
    def has_saved_cs(self) -> bool:
        """Whether CALL pushed the caller selector above its saved offset."""
        return self in {CallFrameKind.FAR16, CallFrameKind.FAR32}


def decoded_call_frame(block: dict[str, Any]) -> CallFrameKind:
    """Require one exact decoded CALL at the end of the source instruction list."""
    instructions = block_source(block).get("instructions")
    if not isinstance(instructions, list) or not instructions:
        raise Real16CallRefusal("call_frame_unproved", {"reason": "instruction bytes absent"})
    last = instructions[-1]
    raw_hex = last.get("bytes") if isinstance(last, dict) else None
    if not isinstance(raw_hex, str):
        raise Real16CallRefusal("call_frame_unproved", {"reason": "instruction bytes absent"})
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as error:
        raise Real16CallRefusal("call_frame_unproved", {"reason": "malformed instruction bytes"}) from error
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    decoded = tuple(decoder.disasm(raw, 0))
    if len(decoded) != 1 or decoded[0].size != len(raw):
        raise Real16CallRefusal("call_frame_unproved", {"reason": "incomplete instruction"})
    instruction = decoded[0]
    if instruction.id not in {x86_const.X86_INS_CALL, x86_const.X86_INS_LCALL}:
        raise Real16CallRefusal("call_frame_unproved", {"reason": "decoded instruction is not CALL"})
    dword = 0x66 in instruction.prefix
    if instruction.id == x86_const.X86_INS_LCALL:
        return CallFrameKind.FAR32 if dword else CallFrameKind.FAR16
    return CallFrameKind.NEAR32 if dword else CallFrameKind.NEAR16


def _constant(value: int, width: int) -> dict[str, Any]:
    """Build an exact unsigned bitvector at the SSA JSON boundary."""
    return {"op": "const", "value": hex(value), "width": width}


def _node(operation: str, width: int, *arguments: dict[str, Any]) -> dict[str, Any]:
    """Build a typed-width SSA operation without changing address identities."""
    return {"op": operation, "width": width, "args": list(arguments)}


def caller_cs_before_call(
    frame: CallFrameKind, call_state: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Recover actual caller CS at CALL, including earlier instructions in its block.

    A near CALL leaves CS unchanged. A far CALL stores it in SS:SP above the
    return offset; select that saved word from the actual post-CALL memory.
    This captures changes before CALL and avoids comparing restored CS with
    the callee selector. Both bytes use the admitted SSA segmented stack
    address rule, including modular offsets and physical SS aliases.
    """
    if not frame.has_saved_cs:
        cs = call_state.get("cs")
        if not isinstance(cs, dict):
            raise Real16CallRefusal("call_cs_not_restored")
        return cs
    if any(name not in call_state for name in ("ss", "sp", "memory")):
        raise Real16CallRefusal("call_frame_unproved", {"reason": "stack state absent"})
    base = _node("shl", 32, _node("zext", 32, call_state["ss"]), _constant(4, 8))
    parts: list[dict[str, Any]] = []
    for index in range(2):
        offset = _node("add", 16, call_state["sp"], _constant(frame.offset_bytes + index, 16))
        address = _node("add", 32, base, _node("zext", 32, offset))
        byte = _node("loadle", 8, call_state["memory"], address)
        parts.append(_node("zext", 16, byte))
    return _node("or", 16, parts[0], _node("shl", 16, parts[1], _constant(8, 8)))

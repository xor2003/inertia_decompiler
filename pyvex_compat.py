"""Runtime compatibility patches for local pyvex/angr execution.

Layer: Frontend/runtime.
Responsibility: adapt dynamic pyvex APIs without changing decoded instruction
semantics or exposing instructions outside the requested lift boundary.
"""

from __future__ import annotations

import functools
import logging
import threading
from collections.abc import Iterator, Sequence
from typing import Any, cast, overload

from inertia_decompiler.runtime_support import AnalysisTimeout

_LOCK = threading.Lock()
_APPLIED = False


class _InstructionWindow:
    """Zero-copy view over an instruction list slice.
    Used to avoid per-instruction list allocations in GymratLifter._lift.
    """

    __slots__ = ("_end", "_seq", "_start")

    def __init__(self, seq: Sequence[object], start: int, end: int) -> None:
        self._seq = seq
        self._start = start
        self._end = end

    def reset(self, start: int, end: int) -> None:
        self._start = start
        self._end = end

    def __bool__(self) -> bool:
        return self._start < self._end

    def __len__(self) -> int:
        return self._end - self._start

    @overload
    def __getitem__(self, idx: int) -> object: ...

    @overload
    def __getitem__(self, idx: slice) -> list[object]: ...

    def __getitem__(self, idx: int | slice) -> object | list[object]:
        length = self._end - self._start
        if isinstance(idx, slice):
            lo, hi, step = idx.indices(length)
            return [self[i] for i in range(lo, hi, step)]
        if idx < 0:
            idx += length
        if idx < 0 or idx >= length:
            raise IndexError(idx)
        return self._seq[self._start + idx]

    def __iter__(self) -> Iterator[object]:
        for i in range(self._start, self._end):
            yield self._seq[i]


def _inertia_lift_preamble_8616(
    lifter: Any,  # noqa: ANN401 - dynamic pyvex GymratLifter boundary
    irsb_customizer: Any,  # noqa: ANN401 - dynamic pyvex IRSBCustomizer boundary
    jump_kind: Any,  # noqa: ANN401 - dynamic pyvex JumpKind boundary
    log: logging.Logger,
) -> tuple[Any, Any, int, bool]:
    """Prepare decoded instructions, customizer, and bounded lift window."""
    debug_enabled = log.isEnabledFor(logging.DEBUG)
    data = lifter.data
    if isinstance(data, (bytes, bytearray, memoryview)):
        lifter.thedata = data[: lifter.max_bytes]
    else:
        lifter.thedata = data[: lifter.max_bytes].encode()
    if debug_enabled:
        log.debug(repr(lifter.thedata))
    instructions = lifter.decode()

    if lifter.disasm:
        lifter.disassembly = [instr.disassemble() for instr in instructions]
    lifter.irsb.jumpkind = jump_kind.Invalid
    irsb_c = irsb_customizer(lifter.irsb)
    if debug_enabled:
        log.debug("Decoding complete.")
    max_inst = lifter.max_inst
    max_inst = len(instructions) if max_inst is None or max_inst <= 0 else min(max_inst, len(instructions))
    return instructions, irsb_c, max_inst, debug_enabled


def _inertia_lift_instruction_8616(
    instr: Any,  # noqa: ANN401 - dynamic pyvex instruction boundary
    index: int,
    max_inst: int,
    past_window: _InstructionWindow,
    future_window: _InstructionWindow,
    irsb_c: Any,  # noqa: ANN401 - dynamic pyvex IRSBCustomizer boundary
    jump_kind: Any,  # noqa: ANN401 - dynamic pyvex JumpKind boundary
    lifting_exception: type[Exception],
    log: logging.Logger,
    debug_enabled: bool,
) -> bool:
    """Lift one instruction; return True when the lift window is complete."""
    if debug_enabled:
        log.debug("Lifting instruction %s", instr.name)
    past_window.reset(0, index)
    future_window.reset(index + 1, max_inst)
    try:
        instr(irsb_c, past_window, future_window)
    except AnalysisTimeout:
        raise lifting_exception("Instruction lifting timed out")  # noqa: B904
    if irsb_c.irsb.jumpkind != jump_kind.Invalid:
        return True
    if (index + 1) == max_inst:
        instr.jump(None, irsb_c.irsb.addr + irsb_c.irsb.size)
        return True
    return False


def _inertia_no_decode_lift_8616(
    irsb_c: Any,  # noqa: ANN401 - dynamic pyvex IRSBCustomizer boundary
    vex_int_class: Any,  # noqa: ANN401 - dynamic pyvex factory boundary
    jump_kind: Any,  # noqa: ANN401 - dynamic pyvex JumpKind boundary
    lifting_exception: type[Exception],
) -> None:
    """Apply the NoDecode fallthrough contract when the window is empty."""
    irsb = irsb_c.irsb
    if len(irsb.statements) == 0:
        raise lifting_exception("Could not decode any instructions")
    irsb.jumpkind = jump_kind.NoDecode
    dst = irsb.addr + irsb.size
    dst_ty = vex_int_class(irsb.arch.bits).type
    irsb.next = irsb_c.mkconst(dst, dst_ty)


def _patch_get_type_size_8616(pyvex_const: Any) -> None:  # noqa: ANN401
    """Install the cached get_type_size adapter once."""
    if getattr(pyvex_const.get_type_size, "__name__", "") == "_inertia_cached_get_type_size":
        return
    original_get_type_size = pyvex_const.get_type_size

    @functools.cache
    def _inertia_cached_get_type_size(ty: object) -> object:
        return cast(object, original_get_type_size(ty))

    pyvex_const.get_type_size = _inertia_cached_get_type_size


def _patch_get_type_spec_size_8616(pyvex_const: Any) -> None:  # noqa: ANN401
    """Install the cached get_type_spec_size adapter once."""
    if getattr(pyvex_const.get_type_spec_size, "__name__", "") == "_inertia_cached_get_type_spec_size":
        return
    original_get_type_spec_size = pyvex_const.get_type_spec_size

    @functools.cache
    def _inertia_cached_get_type_spec_size(ty: object) -> object:
        return cast(object, original_get_type_spec_size(ty))

    pyvex_const.get_type_spec_size = _inertia_cached_get_type_spec_size


def _patch_type_meta_getattr_8616(vex_helper: Any) -> None:  # noqa: ANN401
    """Install the cached TypeMeta attribute adapter once."""
    type_meta = vex_helper.TypeMeta
    if getattr(type_meta, "_inertia_cached_getattr", False):
        return
    original_getattr = type_meta.__getattr__
    cache: dict[str, object] = {}

    def _inertia_cached_type_getattr(self: object, name: str) -> object:
        cached = cache.get(name)
        if cached is not None:
            return cached
        result = cast(object, original_getattr(self, name))
        if name.startswith("int_"):
            cache[name] = result
        return result

    type_meta.__getattr__ = _inertia_cached_type_getattr
    type_meta._inertia_cached_getattr = True


def _patch_gymrat_lift_8616(lifter_helper: Any) -> None:  # noqa: ANN401
    """Install the bounded GymratLifter._lift adapter once."""
    gymrat_lift = getattr(lifter_helper.GymratLifter, "_lift", None)
    if getattr(gymrat_lift, "__name__", "") == "_inertia_safe_lift":
        return
    JumpKind = lifter_helper.JumpKind
    IRSBCustomizer = lifter_helper.IRSBCustomizer
    LiftingException = lifter_helper.LiftingException
    vex_int_class = lifter_helper.vex_int_class
    log = lifter_helper.log

    def _inertia_safe_lift(self: Any) -> Any:  # noqa: ANN401 - dynamic pyvex monkeypatch boundary
        """Lift the requested instruction prefix with bounded lookahead."""
        instructions, irsb_c, max_inst, debug_enabled = _inertia_lift_preamble_8616(
            self, IRSBCustomizer, JumpKind, log
        )
        past_window = _InstructionWindow(instructions, 0, 0)
        future_window = _InstructionWindow(instructions, 1, max_inst)
        for i in range(max_inst):
            if _inertia_lift_instruction_8616(
                instructions[i],
                i,
                max_inst,
                past_window,
                future_window,
                irsb_c,
                JumpKind,
                LiftingException,
                log,
                debug_enabled,
            ):
                break
        else:
            _inertia_no_decode_lift_8616(irsb_c, vex_int_class, JumpKind, LiftingException)
        if debug_enabled:
            log.debug("%s", self.irsb)
        if self.dump_irsb:
            self.irsb.pp()
        return self.irsb

    lifter_helper.GymratLifter._lift = _inertia_safe_lift


def apply_pyvex_runtime_compatibility() -> None:
    """Install bounded, process-wide adapters for supported pyvex APIs."""
    global _APPLIED
    if _APPLIED:
        return

    with _LOCK:
        if _APPLIED:
            return

        try:
            from pyvex import const as pyvex_const
            from pyvex.lifting.util import lifter_helper, vex_helper
        except Exception:
            return

        _patch_get_type_size_8616(pyvex_const)
        _patch_get_type_spec_size_8616(pyvex_const)
        _patch_type_meta_getattr_8616(vex_helper)
        _patch_gymrat_lift_8616(lifter_helper)

        _APPLIED = True

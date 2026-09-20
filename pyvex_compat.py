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

        if getattr(pyvex_const.get_type_size, "__name__", "") != "_inertia_cached_get_type_size":
            original_get_type_size = pyvex_const.get_type_size

            @functools.cache
            def _inertia_cached_get_type_size(ty: object) -> object:
                return cast(object, original_get_type_size(ty))

            pyvex_const.get_type_size = _inertia_cached_get_type_size

        if getattr(pyvex_const.get_type_spec_size, "__name__", "") != "_inertia_cached_get_type_spec_size":
            original_get_type_spec_size = pyvex_const.get_type_spec_size

            @functools.cache
            def _inertia_cached_get_type_spec_size(ty: object) -> object:
                return cast(object, original_get_type_spec_size(ty))

            pyvex_const.get_type_spec_size = _inertia_cached_get_type_spec_size

        type_meta = vex_helper.TypeMeta
        if not getattr(type_meta, "_inertia_cached_getattr", False):
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

        gymrat_lift = getattr(lifter_helper.GymratLifter, "_lift", None)
        if getattr(gymrat_lift, "__name__", "") != "_inertia_safe_lift":
            JumpKind = lifter_helper.JumpKind
            IRSBCustomizer = lifter_helper.IRSBCustomizer
            LiftingException = lifter_helper.LiftingException
            vex_int_class = lifter_helper.vex_int_class
            log = lifter_helper.log

            def _inertia_safe_lift(self: Any) -> Any:  # noqa: ANN401 - dynamic pyvex monkeypatch boundary
                """Lift the requested instruction prefix with bounded lookahead."""
                debug_enabled = log.isEnabledFor(logging.DEBUG)
                data = self.data
                if isinstance(data, (bytes, bytearray, memoryview)):
                    self.thedata = data[: self.max_bytes]
                else:
                    self.thedata = data[: self.max_bytes].encode()
                if debug_enabled:
                    log.debug(repr(self.thedata))
                instructions = self.decode()

                if self.disasm:
                    self.disassembly = [instr.disassemble() for instr in instructions]
                self.irsb.jumpkind = JumpKind.Invalid
                irsb_c = IRSBCustomizer(self.irsb)
                if debug_enabled:
                    log.debug("Decoding complete.")
                max_inst = self.max_inst
                max_inst = len(instructions) if max_inst is None or max_inst <= 0 else min(max_inst, len(instructions))
                past_window = _InstructionWindow(instructions, 0, 0)
                future_window = _InstructionWindow(instructions, 1, max_inst)
                for i in range(max_inst):
                    instr = instructions[i]
                    if debug_enabled:
                        log.debug("Lifting instruction %s", instr.name)
                    past_window.reset(0, i)
                    future_window.reset(i + 1, max_inst)
                    try:
                        instr(irsb_c, past_window, future_window)
                    except AnalysisTimeout:
                        raise LiftingException("Instruction lifting timed out")  # noqa: B904
                    if irsb_c.irsb.jumpkind != JumpKind.Invalid:
                        break
                    if (i + 1) == max_inst:
                        instr.jump(None, irsb_c.irsb.addr + irsb_c.irsb.size)
                        break
                else:
                    if len(irsb_c.irsb.statements) == 0:
                        raise LiftingException("Could not decode any instructions")
                    irsb_c.irsb.jumpkind = JumpKind.NoDecode
                    dst = irsb_c.irsb.addr + irsb_c.irsb.size
                    dst_ty = vex_int_class(irsb_c.irsb.arch.bits).type
                    irsb_c.irsb.next = irsb_c.mkconst(dst, dst_ty)
                if debug_enabled:
                    log.debug("%s", self.irsb)
                if self.dump_irsb:
                    self.irsb.pp()
                return self.irsb

            lifter_helper.GymratLifter._lift = _inertia_safe_lift

        _APPLIED = True

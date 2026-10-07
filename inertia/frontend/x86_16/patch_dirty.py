"""Runtime patch to override angr VEX dirty helpers for x86 IN/OUT.

Layer: Frontend/runtime.

This module performs a best-effort monkeypatch for the runtime dirty-helper
surface. Keeping it in a separate file keeps `__init__` small.
Responsibility: register deterministic x86 IN/OUT dirty-helper fallbacks at the angr runtime boundary.
Forbidden: decompiler semantic repair, alias/type recovery, or generated-C rewrite.
Dynamic attribute boundary: getattr/setattr use here is limited to third-party
angr modules and sys.modules monkeypatch compatibility.
"""

from __future__ import annotations

import sys
import typing
from typing import Protocol

import claripy

__all__ = ["apply_patch"]


class _DirtySolver(Protocol):
    """Minimal solver surface used by x86 dirty-helper fallback callbacks."""

    def eval(self, value: object) -> int:
        """Evaluate a dirty-helper size expression."""
        ...

    def BVV(self, value: int, bits: int) -> object:
        """Create a concrete bit-vector value."""
        ...


class _DirtyState(Protocol):
    """Minimal angr state surface used by x86 dirty-helper callbacks."""

    solver: _DirtySolver


def _dirty_helper_size(state: _DirtyState, sz: object) -> int:
    try:
        return int(sz) if isinstance(sz, int) else int(state.solver.eval(sz))
    except Exception:
        return 32


def _default_in(state: _DirtyState, _portno: object, sz: object) -> tuple[object, list[object]]:
    try:
        szv = _dirty_helper_size(state, sz)
    except Exception:  # pragma: no cover - kept for third-party callback resilience.
        szv = 32
    if szv == 8:
        return claripy.BVV(0xFF, 8), []
    if szv == 16:
        return claripy.BVV(0xFFFF, 16), []
    return claripy.BVV(0xFFFFFFFF, 32), []


def _default_out(_state: _DirtyState, _portno: object, _data: object, _sz: object) -> tuple[None, list[object]]:
    return None, []


def _register_io_simprocedures_8616() -> None:
    """Register the x86 IN/OUT SimProcedures when angr is importable."""
    try:
        import angr as _angr

        from . import simprocs_io as _simprocs_io

        _angr.SIM_PROCEDURES = getattr(_angr, "SIM_PROCEDURES", {})
        _arch_key = "X86_16"
        if _arch_key not in _angr.SIM_PROCEDURES:
            _angr.SIM_PROCEDURES[_arch_key] = {}
        _angr.SIM_PROCEDURES[_arch_key]["x86g_dirtyhelper_IN"] = _simprocs_io.X86DirtyIN
        _angr.SIM_PROCEDURES[_arch_key]["x86g_dirtyhelper_OUT"] = _simprocs_io.X86DirtyOUT
    except Exception:
        # Best-effort registration; if angr is absent or API differs, continue silently.
        pass


def _patch_vex_dirty_module_8616() -> None:
    """Patch angr's VEX dirty helpers for x86 to deterministic defaults."""
    try:
        # Patch angr's VEX dirty helpers for x86 to return deterministic defaults
        # when no PortIO device is present. This overrides the engine-level helpers
        # that otherwise emit symbolic IN_... values.
        import angr.engines.vex.heavy.dirty as _dirty

        def _patched_x86g_dirtyhelper_IN(state: _DirtyState, _portno: object, sz: object) -> object:
            szv = _dirty_helper_size(state, sz)
            if szv == 8:
                return state.solver.BVV(0xFF, 8)
            if szv == 16:
                return state.solver.BVV(0xFFFF, 16)
            return state.solver.BVV(0xFFFFFFFF, 32)

        def _patched_x86g_dirtyhelper_OUT(
            _state: _DirtyState,
            _portno: object,
            _sz: object,
            _val: object,
        ) -> None:
            return None

        _dirty.x86g_dirtyhelper_IN = _patched_x86g_dirtyhelper_IN
        _dirty.x86g_dirtyhelper_OUT = _patched_x86g_dirtyhelper_OUT
    except Exception:
        pass


def _patch_loaded_module_helpers_8616() -> int:
    """Replace dirty-helper attributes on every module already imported."""
    patched = 0
    for _name, mod in list(sys.modules.items()):
        if not mod:
            continue
        try:
            if hasattr(mod, "x86g_dirtyhelper_IN"):
                typing.cast(typing.Any, mod).x86g_dirtyhelper_IN = _default_in
                patched += 1
            if hasattr(mod, "x86g_dirtyhelper_OUT"):
                typing.cast(typing.Any, mod).x86g_dirtyhelper_OUT = _default_out
                patched += 1
        except Exception:
            continue
    return patched


def apply_patch() -> int:
    """Install best-effort x86 IN/OUT dirty-helper fallbacks.

    Dynamic attribute boundary: this function patches optional attributes on
    third-party angr modules discovered through imports and sys.modules.
    """
    _register_io_simprocedures_8616()
    _patch_vex_dirty_module_8616()
    return _patch_loaded_module_helpers_8616()

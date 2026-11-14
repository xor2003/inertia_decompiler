# cython: language_level=3, infer_types=True
"""Layer: Frontend/runtime.

Responsibility: provide deterministic x86 dirty I/O SimProcedure stubs for lifting/runtime.
Forbidden: inferring decompiler semantics from port names, host devices, or I/O side effects.
"""

from __future__ import annotations
import typing
import cython

from typing import Protocol, cast

from angr.sim_procedure import SimProcedure

__all__ = ["X86DirtyIN", "X86DirtyOUT"]


class _DirtyIOSolver(Protocol):
    def eval(self, _expression: object) -> cython.longlong:
        """Evaluate a symbolic or concrete width expression."""
        ...

    def BVV(self, _value: cython.longlong, _bits: cython.longlong) -> object:
        """Build a bit-vector value for the requested width."""
        ...


@cython.ccall
def _size_bits_from_solver(size: object, solver: _DirtyIOSolver) -> cython.longlong:
    try:
        # size may be a claripy BV or a Python scalar.
        if hasattr(size, "concrete") or hasattr(size, "size"):
            return int(solver.eval(size))
        if isinstance(size, int | float | str):
            return int(size)
    except Exception:
        return 32
    return 32


class X86DirtyIN(SimProcedure):  # type: ignore[misc, unused-ignore] # dynamic angr SimProcedure base
    """SimProcedure for x86g_dirtyhelper_IN used by the x86-16 lifter.

    Returns a deterministic default value when no port device is registered.
    Signature (size_bits, port)
    """

    def run(self, size: object, port = None) -> object:
        """Return the deterministic unconstrained-port value for the requested width."""
        del port
        solver = cast(_DirtyIOSolver, self.state.solver)
        sz = _size_bits_from_solver(size, solver)

        if sz == 8:
            return solver.BVV(0xFF, 8)
        if sz == 16:
            return solver.BVV(0xFFFF, 16)
        return solver.BVV(0xFFFFFFFF, 32)


class X86DirtyOUT(SimProcedure):  # type: ignore[misc, unused-ignore] # dynamic angr SimProcedure base
    """SimProcedure stub for x86g_dirtyhelper_OUT used by the x86-16 lifter.

    Signature (size_bits, port, value)
    This is a no-op when no port device is present.
    """

    def run(self, size, port, value) -> None:
        """Ignore an OUT operation when no frontend port device is present."""
        del size, port, value
        return None

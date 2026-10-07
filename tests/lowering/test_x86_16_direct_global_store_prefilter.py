"""Tests for direct-global store candidate prefiltering."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CConstant
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.segmented_global_loads as segmented_global_loads
from inertia.lowering.segmented_global_loads import DirectGlobalSymbolRef8616


class _CodegenBoundary:
    """Minimal third-party codegen identity surface required by C nodes."""

    def __init__(self) -> None:
        self._index = 0
        self.cfunc = SimpleNamespace(addr=0x4010)
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        """Return a unique construct index."""
        self._index += 1
        return self._index

    def next_node_idx(self) -> int:
        """Return a unique node index."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Return the stable display identity used by the fixture."""
        return name


def test_non_variable_lvalue_skips_direct_global_expression_fallback(monkeypatch) -> None:
    """Only node types that can equal a generated global enter comparison."""
    codegen = _CodegenBoundary()
    lhs = CConstant(1, SimTypeShort(False), codegen=codegen)
    rhs = CConstant(2, SimTypeShort(False), codegen=codegen)
    assignment = CAssignment(lhs, rhs, codegen=codegen)
    ref = DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0)

    def refuse_fallback(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("an impossible lvalue type reached expression comparison")

    monkeypatch.setattr(
        segmented_global_loads,
        "_make_direct_global_symbol_expr_8616",
        refuse_fallback,
    )

    matched_ref, matched_rhs = segmented_global_loads._direct_global_word_assignment_8616(
        assignment,
        codegen,
        {(0xBAA, 2): ref},
    )

    assert matched_ref is None
    assert matched_rhs is None

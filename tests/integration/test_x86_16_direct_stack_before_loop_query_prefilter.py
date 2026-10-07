"""Tests for fail-closed direct-stack before-loop query prefiltering."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.real_mode_linear as real_mode_linear


class _Codegen:
    """Minimal deterministic structured-C codegen fixture."""

    def __init__(self) -> None:
        self._index = 0
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        """Return one deterministic expression index."""
        self._index += 1
        return self._index

    def next_node_idx(self) -> int:
        """Return one deterministic statement index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Keep requested test identifiers stable."""
        return name


def _stack_variable(codegen: _Codegen, offset: int) -> CVariable:
    """Build one typed stack-variable expression."""
    return CVariable(
        SimStackVariable(
            offset,
            2,
            base="bp",
            name=f"local_{abs(offset):x}",
            region=0x4010,
        ),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_absent_tag_skips_expensive_before_loop_proofs(monkeypatch) -> None:
    """An impossible loop candidate must stop at exact assignment evidence."""
    codegen = _Codegen()
    source = _stack_variable(codegen, -4)
    destination = _stack_variable(codegen, -2)
    loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    replacement = CAssignment(destination, source, codegen=codegen)

    def unexpected_expensive_query(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("expensive placement proof ran without a tagged assignment")

    monkeypatch.setattr(
        real_mode_linear,
        "_instruction_addr_range_in_node_8616",
        unexpected_expensive_query,
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_following_instruction_addr_in_node_8616",
        unexpected_expensive_query,
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_node_reads_stack_cvar_8616",
        unexpected_expensive_query,
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_candidate_function_ins_addrs_8616",
        unexpected_expensive_query,
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_structured_loopback_edges_covering_instruction_8616",
        unexpected_expensive_query,
    )

    removed = real_mode_linear._relocate_tagged_stack_move_before_proven_loop_8616(
        root,
        codegen.project,
        SimpleNamespace(blocks=()),
        0x4018,
        destination,
        source,
        replacement,
    )

    assert removed == 0
    assert root.statements == [loop]

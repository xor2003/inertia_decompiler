"""Run bounded IR arithmetic normalization around native SSA simplification.

Layer: Frontend/IR adapter.
Responsibility: sequence the IR-owned constant-displacement pass independently
of expensive native expression peepholes. It introduces no call, stack, Alias
or type recovery and does not relax semantic or recompilation validation.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, cast

import networkx as nx
from angr.ailment.block import Block
from angr.ailment.manager import Manager
from angr.analyses.decompiler.clinic import Clinic

from .ir.ail_register_displacement import RegisterDisplacementReport8616, normalize_register_displacements_8616


class _Architecture8616(Protocol):
    """Architecture identity at the native analysis boundary."""

    name: str


class _Project8616(Protocol):
    """Native project surface used only for architecture dispatch."""

    arch: _Architecture8616


class _Clinic8616(Protocol):
    """Native graph and owned arithmetic evidence for one Clinic lifecycle."""

    project: _Project8616
    _ail_graph: nx.DiGraph[Block]
    _ail_manager: Manager
    reaching_definitions: object | None
    _inertia_register_displacement_reports_8616: tuple[RegisterDisplacementReport8616, ...]


def apply_register_displacement_compatibility_8616() -> None:
    """Install the bounded pass once, delegating other architectures unchanged."""
    original = cast(Callable[[Clinic], None], Clinic._stage_post_ssa_level1_simplifications)
    if original.__name__ == "_register_displacement_stage_8616":
        return

    def _register_displacement_stage_8616(self: Clinic) -> None:
        """Normalize before propagation and again after newly exposed chains."""
        clinic = cast(_Clinic8616, self)
        if clinic.project.arch.name != "86_16":
            original(self)
            return
        before = normalize_register_displacements_8616(clinic._ail_graph, clinic._ail_manager)
        if before.materialized_count:
            clinic.reaching_definitions = None
        original(self)
        after = normalize_register_displacements_8616(clinic._ail_graph, clinic._ail_manager)
        if after.materialized_count:
            clinic.reaching_definitions = None
        clinic._inertia_register_displacement_reports_8616 = (before, after)

    Clinic._stage_post_ssa_level1_simplifications = _register_displacement_stage_8616

"""Publish immutable shared-loop exit proof at the Structuring boundary.

Layer: Structuring.
Responsibility: connect owned SSA/CFG and dispatch evidence to one codegen
surface. A published positive proof is never refreshed from a mutated AST.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, cast

from ..ir.condition_ir import ConditionIR
from ..ir.function_ssa_registry import registered_function_ssa_artifact_8616
from ..pipeline.errors import PipelineHardError
from .loop_break_topology import collect_loop_break_topology_8616
from .shared_loop_exit import (
    DispatchExit8616,
    SharedLoopExitReport8616,
    prove_shared_loop_exits_8616,
    shared_exit_fingerprint_8616,
)


class _Function8616(Protocol):
    """angr's active generated function boundary."""

    addr: int
    statements: object


class _Codegen8616(Protocol):
    """Owned proof and condition metadata at the codegen boundary."""

    cfunc: _Function8616
    _inertia_typed_conditions: object
    _inertia_shared_loop_exit_report_8616: SharedLoopExitReport8616


def shared_loop_exit_report_8616(codegen: object) -> SharedLoopExitReport8616 | None:
    """Read an owned proof or fail early on corrupt metadata."""
    try:
        result = cast(_Codegen8616, codegen)._inertia_shared_loop_exit_report_8616
    except AttributeError:
        return None
    if not isinstance(result, SharedLoopExitReport8616):
        raise PipelineHardError("shared-loop-exit: invalid owned proof report")
    return result


def publish_shared_loop_exit_report_8616(
    project: object, codegen: object, evidence: Sequence[DispatchExit8616],
) -> SharedLoopExitReport8616:
    """Prove the first positive snapshot, retaining it unchanged for replay."""
    existing = shared_loop_exit_report_8616(codegen)
    if existing is not None and existing.bindings:
        return existing
    surface = cast(_Codegen8616, codegen)
    try:
        function = surface.cfunc
        raw_conditions = surface._inertia_typed_conditions
    except AttributeError:
        return SharedLoopExitReport8616(len(evidence), ())
    facts = tuple(fact for fact in raw_conditions if isinstance(fact, ConditionIR)) if isinstance(raw_conditions, (tuple, list)) else ()
    topology = collect_loop_break_topology_8616(project, codegen)
    edges = topology.edges if topology is not None else frozenset()
    successors = {source: tuple(sorted(target for start, target in edges if start == source)) for source, _ in edges}
    report = prove_shared_loop_exits_8616(
        function.statements, evidence, facts, topology,
        registered_function_ssa_artifact_8616(project, function.addr).artifact,
        successors, lambda expression: shared_exit_fingerprint_8616(expression, project),
    )
    surface._inertia_shared_loop_exit_report_8616 = report
    return report

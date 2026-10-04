"""Preserve native direct-JMP/CALL classification at angr's CFG job boundary.

Layer: Frontend/CFG adapter.
Responsibility: submit source-proved native JMP and CALL targets as direct
discovery edges, avoiding angr's indirect-jump function-start heuristic.
Execution VEX, function-boundary heuristics for genuine indirect jumps, and
proof semantics remain owned by their existing layers.
"""
from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, cast

import pyvex
from angr.analyses.cfg.cfg_fast import CFGFast, CFGJob
from angr.knowledge_plugins.cfg.cfg_node import CFGNode
from angr.utils.constants import DEFAULT_STATEMENT

from .arch_86_16 import Arch86_16
from .frontend_cfg_direct_call import NativeDirectCallResolver8616
from .frontend_cfg_direct_jump import NativeDirectJumpResolver8616

_CreateJobs8616 = Callable[..., list[CFGJob]]
_Successors8616 = list[tuple[int, int | None, Any, str]]


def _native_job_target_8616(
    cfg: CFGFast, target: object, jumpkind: str,
    function_addr: int, irsb: pyvex.IRSB | None,
    addr: int, statement_index: int | None,
) -> object:
    """Project only a source-proved default native JMP/CALL into a direct edge."""
    if not isinstance(cfg.project.arch, Arch86_16):
        return target
    if not isinstance(irsb, pyvex.IRSB) or target is not irsb.next:
        return target
    if statement_index != DEFAULT_STATEMENT:
        return target
    if isinstance(target, (int, pyvex.expr.Const)):
        return target
    if jumpkind == "Ijk_Boring":
        resolver: NativeDirectJumpResolver8616 | NativeDirectCallResolver8616 = (
            NativeDirectJumpResolver8616(cfg.project)
        )
    elif jumpkind == "Ijk_Call":
        resolver = NativeDirectCallResolver8616(cfg.project)
    else:
        return target
    resolved, targets = resolver.resolve(cfg, addr, function_addr, irsb, jumpkind)
    return targets[0] if resolved and len(targets) == 1 else target


def _make_native_job_adapter_8616(original: _CreateJobs8616) -> _CreateJobs8616:
    """Wrap the third-party discovery call without changing its VEX argument."""
    @wraps(original)
    def create_jobs(
        cfg: CFGFast, target: object, jumpkind: str,
        current_function_addr: int, irsb: pyvex.IRSB | None,
        addr: int, cfg_node: CFGNode, ins_addr: int | None,
        stmt_idx: int | None, all_successors: _Successors8616 | None,
    ) -> list[CFGJob]:
        """Pass native direct-edge evidence to the existing CFG job owner."""
        projected = _native_job_target_8616(
            cfg, target, jumpkind, current_function_addr, irsb, addr, stmt_idx,
        )
        return original(
            cfg, projected, jumpkind, current_function_addr, irsb,
            addr, cfg_node, ins_addr, stmt_idx, all_successors,
        )

    # This marker belongs to the third-party method/plugin boundary. It
    # prevents repeated platform bootstrap from nesting adapters.
    cast(Any, create_jobs)._inertia_native_direct_jobs_8616 = True
    return create_jobs


def register_native_direct_job_adapter_8616() -> None:
    """Install one architecture-filtered adapter at angr's discovery boundary."""
    current = CFGFast._create_jobs
    # Dynamic plugin boundary: angr's active callable marker is optional.
    if getattr(current, "_inertia_native_direct_jobs_8616", False):
        return
    CFGFast._create_jobs = _make_native_job_adapter_8616(current)

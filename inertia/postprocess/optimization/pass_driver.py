"""Layer: Rewrite/Postprocess cleanup.

Responsibility: run cleanup optimization passes after semantics have been recovered.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
The codegen and C AST objects cross a dynamic third-party angr boundary; keep
dynamic attribute access limited to that boundary and diagnostic counters.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from inertia.widening.widening_copyprop_8616 import _widening_copy_propagation_8616
from inertia.widening.widening_memory_fold_8616 import _widening_store_to_load_forwarding_8616

from .const_prop import _constant_propagation_8616
from .dce import _dead_code_elimination_8616
from .dead_setup import _prune_dead_setup_carriers_8616
from .local_declarations import dedupe_equivalent_stack_local_declarations_8616
from .trivial_copy import prune_adjacent_temporary_copy_assignments_8616

__all__ = [
    "OPTIMIZATION_PASSES",
    "OptimizationPassSpec",
    "_normalize_cfunc_root_for_optimization_8616",
    "_run_optimization_passes_8616",
    "describe_x86_16_optimization_passes",
]


# Monkey-patch: CStatements is not iterable in angr, so tuple(CStatements(...))
# fails.  Optimization pass walkers call tuple(getattr(node, 'statements', ()))
# on the root, which hits this.  Add __iter__ so the walkers work without
# having to corrupt cfunc.statements (which needs to stay a CStatements for
# c_repr_chunks() during C text rendering).
from angr.analyses.decompiler.structured_codegen.c import CStatements as _CStatements

if not hasattr(_CStatements, "__iter__"):
    cast(Any, _CStatements).__iter__ = lambda self: iter(self.statements)


def _normalize_cfunc_root_for_optimization_8616(codegen: object) -> None:
    """No-op: CStatements is now iterable via the module-level monkey-patch.

    The codegen object crosses a dynamic third-party angr boundary, so cfunc and
    statement-wrapper attributes are probed dynamically here.

    Previously this function replaced cfunc.statements (a CStatements wrapper)
    with a raw list, which broke c_repr_chunks() downstream.
    The monkey-patch above makes tuple(CStatements) work natively.

    Kept as a hook point for future optimization setup.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return
    if not isinstance(getattr(cfunc, "statements", None), _CStatements):
        return


@dataclass(frozen=True, slots=True)
class OptimizationPassSpec:
    """Declared cleanup optimization pass and human-readable ownership summary."""

    name: str
    func: Callable[..., bool]
    description: str


OPTIMIZATION_PASSES: tuple[OptimizationPassSpec, ...] = (
    OptimizationPassSpec(
        "equivalent_stack_local_declarations",
        dedupe_equivalent_stack_local_declarations_8616,
        "Remove equivalent duplicate stack-local declarations",
    ),
    OptimizationPassSpec(
        "const_prop",
        _constant_propagation_8616,
        "Fold constant sub-expressions",
    ),
    OptimizationPassSpec(
        "widening_copy_prop",
        _widening_copy_propagation_8616,
        "Propagate copies using alias storage domains (Widening)",
    ),
    OptimizationPassSpec(
        "widening_memory_fold",
        _widening_store_to_load_forwarding_8616,
        "Forward store values to loads using alias domains (Widening)",
    ),
    OptimizationPassSpec(
        "adjacent_temporary_copy_prune",
        prune_adjacent_temporary_copy_assignments_8616,
        "Collapse adjacent temporary copy carriers",
    ),
    OptimizationPassSpec(
        "dce",
        _dead_code_elimination_8616,
        "Eliminate dead assignments",
    ),
    OptimizationPassSpec(
        "dead_setup_prune",
        _prune_dead_setup_carriers_8616,
        "Prune dead setup/staging carrier assignments (typed def-use)",
    ),
)

def describe_x86_16_optimization_passes() -> tuple[tuple[str, str], ...]:
    """Return the cleanup optimization inventory for tests and diagnostics."""
    return tuple((spec.name, spec.description) for spec in OPTIMIZATION_PASSES)


def _run_optimization_passes_8616(codegen: object) -> bool:
    """Run optimization passes on codegen.

    The codegen object crosses a dynamic third-party angr boundary; this driver
    only reads dynamic codegen shape and diagnostic counters after semantic
    recovery has already completed.

    Returns True if any pass modified the codegen.
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    # Normalize: unwrap CStatements before passes walk the tree.
    # Some angr codegen produces CStatements objects that are not iterable.
    _normalize_cfunc_root_for_optimization_8616(codegen)

    changed = False
    for spec in OPTIMIZATION_PASSES:
        if spec.func(codegen):
            changed = True
            if os.environ.get("INERTIA_DEBUG_OPTIMIZATION", "").strip().lower() in {"1", "true", "yes", "on"}:
                print(f"[optimization] pass_changed={spec.name}", file=sys.stderr, flush=True)
        elif os.environ.get("INERTIA_DEBUG_OPTIMIZATION", "").strip().lower() in {"1", "true", "yes", "on"}:
            print(f"[optimization] pass_stable={spec.name}", file=sys.stderr, flush=True)
    if os.environ.get("INERTIA_DEBUG_OPTIMIZATION", "").strip().lower() in {"1", "true", "yes", "on"}:
        print(
            "[optimization] counters "
            f"dce_candidates={int(getattr(codegen, 'dce_candidates', 0) or 0)} "
            f"dce_deleted={int(getattr(codegen, 'dce_deleted', 0) or 0)} "
            f"dce_keep_live_use={int(getattr(codegen, 'dce_keep_live_use', 0) or 0)} "
            f"dce_keep_side_effect={int(getattr(codegen, 'dce_keep_side_effect', 0) or 0)} "
            f"dce_keep_protected={int(getattr(codegen, 'dce_keep_protected', 0) or 0)} "
            f"dce_keep_observable={int(getattr(codegen, 'dce_keep_observable', 0) or 0)} "
            f"dce_keep_unknown={int(getattr(codegen, 'dce_keep_unknown', 0) or 0)} "
            f"dce_duplicate_assignment_candidates="
            f"{int(getattr(codegen, 'dce_duplicate_assignment_candidates', 0) or 0)} "
            f"dce_duplicate_assignment_deleted="
            f"{int(getattr(codegen, 'dce_duplicate_assignment_deleted', 0) or 0)} "
            f"dce_duplicate_assignment_refused="
            f"{int(getattr(codegen, 'dce_duplicate_assignment_refused', 0) or 0)}",
            file=sys.stderr,
            flush=True,
        )

    return changed

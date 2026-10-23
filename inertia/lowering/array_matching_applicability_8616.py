"""Applicability probe for the x86-16 array-expression matching pass.

Layer: Types/Lowering.
Responsibility: prove whether ``apply_x86_16_array_expression_matching`` can
change the current C AST. Returns ``False`` for
``DecompilerStructuringPassSpec.applicable`` only when the induction-loop
rewrite cannot visit a ``CForLoop``/``CWhileLoop`` node under the exact
traversal the rewrite performs. Unknown input stays applicable.

The probe is read-only on the AST. On a proven no-op it still publishes the
same ``_inertia_array_matching_*`` diagnostics an executed no-op pass leaves,
by running the pass's own shared runner with a no-op rewrite step. If metadata
publication takes the pass's error path, the probe stays applicable so the
real pass owns error reporting and its semantic-validation record.

Scheduling preconditions belong to the structuring stage, not this probe.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CForLoop, CWhileLoop

from inertia.lowering.c_ast_utils import (
    CTraversalContractError8616,
    _replace_c_children_8616,
)

# Dynamic boundary: shares the pass metadata runner across the dynamic angr
# codegen boundary.
from inertia.lowering.type_array_matching import _run_array_expression_matching_8616

__all__ = ["array_expression_matching_applicable_8616"]

_REWRITE_TARGET_TYPES_8616: tuple[type, type] = (CForLoop, CWhileLoop)


class _RewriteTargetFound8616(Exception):
    """Private early-exit signal: one rewrite-target node already proves applicability."""


def _rewrite_target_present_8616(codegen: object) -> bool | None:
    """Return whether the induction-loop rewrite can visit a loop node.

    Mirrors ``_rewrite_induction_loops_8616``: ``transform`` is applied to
    ``cfunc.statements`` itself and then to every structured node
    ``_replace_c_children_8616`` visits. Only ``CForLoop``/``CWhileLoop``
    inputs can set ``changed``, so a completed traversal that visits none
    proves the rewrite returns ``False`` without mutating the AST; the first
    visited target already proves applicability, so detection aborts early
    through the private ``_RewriteTargetFound8616`` signal. The detection
    transform returns each node unchanged, so the replacement traversal
    performs no writes and visits exactly the nodes the rewrite would visit.
    ``None`` means the shared traversal could not prove coverage; the caller
    must keep the pass applicable.
    """
    # Dynamic boundary: third-party angr codegen exposes cfunc optionally.
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    try:
        root = cfunc.statements
    except AttributeError:
        return None

    if isinstance(root, _REWRITE_TARGET_TYPES_8616):
        return True

    def _detect(node: object) -> object:
        if isinstance(node, _REWRITE_TARGET_TYPES_8616):
            raise _RewriteTargetFound8616
        return node

    try:
        _replace_c_children_8616(root, _detect)
    except _RewriteTargetFound8616:
        return True
    except CTraversalContractError8616:
        return None
    return False


def array_expression_matching_applicable_8616(codegen: object) -> bool:
    """Return ``False`` only when the array-matching pass is a proven no-op.

    A missing ``cfunc`` mirrors the pass's own early return with no side
    effects. A completed read-only traversal that visits no
    ``CForLoop``/``CWhileLoop`` on an AST the pass will actually observe
    proves the induction-loop rewrite cannot change anything; the probe then
    publishes the pass's metadata through the shared runner and reports the
    pass inapplicable. Unknown traversal state and metadata-publication failure all stay applicable so
    the real pass retains its error and validation behavior.
    """
    # Dynamic boundary: third-party angr codegen exposes cfunc optionally.
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    has_target = _rewrite_target_present_8616(codegen)
    if has_target is not False:
        return True

    original_root = cfunc.statements
    rewrite_reached = False

    def _loop_free_rewrite_step_8616(target_codegen: object) -> bool:
        """Recheck the same AST after metadata callbacks; never change it."""
        nonlocal rewrite_reached
        # Dynamic boundary: third-party angr codegen can replace its cfunc.
        current_cfunc = getattr(target_codegen, "cfunc", None)
        if current_cfunc is not cfunc:
            return False
        try:
            if current_cfunc.statements is not original_root:
                return False
        except AttributeError:
            return False
        rewrite_reached = _rewrite_target_present_8616(target_codegen) is False
        return False

    _run_array_expression_matching_8616(codegen, _loop_free_rewrite_step_8616)
    # The rewrite step runs only when metadata publication succeeded. A
    # publication failure keeps the pass applicable so the real run re-enters
    # the same error path, preserving ``_inertia_array_matching_error``
    # reporting and the semantic-validation record exactly.
    return not rewrite_reached

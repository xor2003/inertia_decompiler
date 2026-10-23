"""Applicability probe for the combined subview/copy-propagation pass.

Layer: Widening.
Responsibility: prove whether the combined structuring pass
``_run_structuring_widening_copy_propagation_8616`` (contained stack subviews
then widening copy propagation) can change the current C AST. Returns False
for ``DecompilerStructuringPassSpec.applicable`` only when both transforms are
proven unable to change the AST. Unknown input stays applicable.

Consumes the exact transformation decision logic of both passes; it does not
reimplement their criteria. Probe execution is read-only on the AST, alias
facts, scopes, and codegen diagnostic counters; only a proven no-op publishes
the same zero-work diagnostics an executed no-op pass would have left.

"""

from __future__ import annotations

from .stack_subview_projection import (
    _finish_stack_subview_stats_8616,
    stack_subview_projection_probe_8616,
)
from .widening_copyprop_8616 import (
    publish_copyprop_probe_diagnostics_8616,
    widening_copy_propagation_probe_8616,
)


def widening_subview_copyprop_applicable_8616(codegen: object) -> bool:
    """Return False only when both combined transforms are proven no-ops.

    The combined pass runs stack-subview materialization first and copy
    propagation second. Subview materialization is a pure function of the
    current AST and Widening artifact; when its probe proves a no-op, the
    copy-propagation probe observes exactly the AST the real pass would see,
    so both probes returning proven-no-op proves the combined pass returns
    ``False`` with no AST change. Unknown input remains applicable.
    """
    subview_evidence = stack_subview_projection_probe_8616(codegen)
    if subview_evidence is None:
        return True
    copyprop_evidence = widening_copy_propagation_probe_8616(codegen)
    if copyprop_evidence is None:
        return True
    # Documented zero-work diagnostics: replay exactly what an executed no-op
    # pass would have published, so consumers see identical evidence.
    if subview_evidence.stats is not None:
        _finish_stack_subview_stats_8616(codegen, subview_evidence.stats)
    if copyprop_evidence.diagnostics is not None:
        publish_copyprop_probe_diagnostics_8616(codegen, copyprop_evidence.diagnostics)
    return False


__all__ = ["widening_subview_copyprop_applicable_8616"]

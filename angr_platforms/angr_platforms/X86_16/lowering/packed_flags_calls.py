"""Consume exact binary callee status summaries at structured calls.

Layer: Types/Lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

Responsibility: consume binary callee flag summaries at structured call nodes.
An exact target with no status inputs can preserve a dead-carrier proof. Unknown
targets or summaries refuse it. This does not make calls pure or removable.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CStatement

from ..ir.status_flag_lift_context import StatusFlagLiftArtifact8616, resolve_status_flag_lift_artifact_8616
from ..semantics.status_flag_contracts import StatusFlag8616
from ..widening.segmented_load_identity import segmented_load_identity_8616


def flag_artifact_for_structured_root_8616(root: object) -> StatusFlagLiftArtifact8616 | None:
    """Resolve function-owned evidence at the third-party codegen boundary."""
    if not isinstance(root, CStatement) or root.codegen is None:
        return None
    try:
        codegen = root.codegen
        resolved = resolve_status_flag_lift_artifact_8616(codegen.project, codegen.cfunc.addr)
    except AttributeError:
        return None
    return resolved.artifact if resolved is not None else None


def call_has_no_implicit_status_inputs_8616(
    call: CFunctionCall, artifact: StatusFlagLiftArtifact8616 | None,
) -> bool:
    """Require a typed memory projection or an exact binary callee summary."""
    if segmented_load_identity_8616(call) is not None:
        return True
    if artifact is None or call.callee_func is None:
        return False
    target = call.callee_func.addr
    attached_target = call.tags.get("inertia_target_addr_8616", target)
    if not isinstance(target, int) or attached_target != target:
        return False
    effects = tuple(effect for address, effect in artifact.callee_effects if address == target)
    return len(effects) == 1 and effects[0].reads == StatusFlag8616.NONE

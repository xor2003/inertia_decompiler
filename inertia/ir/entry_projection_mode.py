"""Select which conditional entry facts a consumer explicitly requests.

Layer: IR.
Responsibility: distinguish control-only projections from fresh outgoing CALL
selector discharge. A mode requests work; it conveys no evidence or trust.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""
from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .near_call_jump_scope import NearCallJumpScope8616
    from .real16_invocation_domain import Real16InvocationDomain8616


class EntryProjectionMode8616(StrEnum):
    """Requested evidence surface of one independently authenticated operation."""

    CONTROL_ONLY = "control_only"
    CALL_TARGETS = "call_targets"


def entry_projection_mode_for_scope_8616(
    scope: Real16InvocationDomain8616 | NearCallJumpScope8616,
) -> EntryProjectionMode8616:
    """Select supported projections from the exact typed entry authority.

    Declared entries with retained selector projections request fresh native
    target admission. Other invocation entries retain control only. This
    policy requests evidence; record presence never authenticates the scope.
    """
    # Deferred import: the entry-domain owner is staged against the same
    # package and loads after this module inside the importer fan-in.
    from .entry_domain_call_preservation import EntryDomainCallPreservation8616
    from .near_call_jump_scope import NearCallJumpScope8616
    from .real16_invocation_domain import Real16InvocationDomain8616

    if type(scope) is NearCallJumpScope8616:
        return EntryProjectionMode8616.CALL_TARGETS
    if type(scope) is Real16InvocationDomain8616:
        if scope.entry_call_preservations and all(
            type(record) is EntryDomainCallPreservation8616
            and record.selector_projection is not None
            for record in scope.entry_call_preservations
        ):
            return EntryProjectionMode8616.CALL_TARGETS
        return EntryProjectionMode8616.CONTROL_ONLY
    raise TypeError("entry projection mode requires an exact typed entry scope")

"""Replay only Lowering consumers invalidated by return-value replacement.

Layer: Types/lowering.
Responsibility: prune stack-lowered register carriers made dead by an owned
return mutation, then republish every surviving typed register declaration.
Consumes alias, widening, and typed facts. This module does not replay stack,
segment, global, call-argument, or condition semantic recovery.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from .dead_register_carriers import prune_unread_stack_lowered_register_carriers_8616
from .register_local_declarations import (
    RegisterLocalDeclarationResult8616,
    materialize_typed_register_locals_8616,
)

__all__ = [
    "ReturnLivenessReplayResult8616",
    "replay_return_liveness_lowering_8616",
]


@dataclass(frozen=True, slots=True)
class ReturnLivenessReplayResult8616:
    """Typed result of one bounded return-liveness replay."""

    carrier_prune_changed: bool
    register_locals: RegisterLocalDeclarationResult8616

    @property
    def changed(self) -> bool:
        """Return whether liveness cleanup or declaration publication changed."""
        return self.carrier_prune_changed or self.register_locals.changed


def replay_return_liveness_lowering_8616(
    codegen: object,
) -> ReturnLivenessReplayResult8616:
    """Replay only the consumers invalidated by a pure return replacement."""
    carrier_prune_changed = prune_unread_stack_lowered_register_carriers_8616(codegen)
    register_locals = materialize_typed_register_locals_8616(codegen)
    return ReturnLivenessReplayResult8616(carrier_prune_changed, register_locals)

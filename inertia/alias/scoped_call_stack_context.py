"""Explicit callsite-keyed scoped evidence overlay for the Alias solver.

Layer: Alias.
Responsibility: bind each physical callsite to its retained
``IRScopedCallStackCoordinates8616`` carrier plus the caller and callee
invocation domains that authenticated it. The overlay never mutates or
re-seals source IR: the raw artifact keeps every pending refusal marker and
its instructions carry no scoped scalar. A delta map is produced only under
an offered caller domain that shares provenance with EVERY bound caller
execution — each binding then projects its own retained callee pair. The
supplied artifact must be the exact callsite artifact each chain bound at
link time, and every overlaid CALL must still match its carrier's physical
source, target and frame. One unprovable binding refuses the whole map
rather than guessing zero.
Owns storage identity. Do not perform semantics decoding, IR production,
lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

from dataclasses import dataclass, field

from inertia.ir.core import IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.real16_invocation_domain import (
    Real16CallChainLink8616,
    Real16InvocationDomain8616,
    same_real16_entry_scope_8616,
)
from inertia.ir.scoped_call_stack_coordinates import (
    IRScopedCallStackCoordinates8616,
)

__all__ = [
    "ScopedCallEntryBinding8616",
    "ScopedCallStackContext8616",
    "prove_scoped_call_stack_context_8616",
]


@dataclass(frozen=True, slots=True)
class ScopedCallEntryBinding8616:
    """One callsite's retained carrier and the two authenticating domains."""

    carrier: IRScopedCallStackCoordinates8616
    caller_scope: Real16InvocationDomain8616 = field(compare=False, repr=False)
    callee_scope: Real16InvocationDomain8616 = field(compare=False, repr=False)

    @property
    def callsite_addr(self) -> int | None:
        """Read the bound callsite from the physical coordinate record."""
        coordinates = self.carrier.coordinates
        return None if coordinates is None else coordinates.callsite_addr


def _call_row_matches_carrier_8616(
    call: IRInstr,
    carrier: IRScopedCallStackCoordinates8616,
) -> bool:
    """Bind the carrier's physical record to this exact CALL instruction."""
    coordinates = carrier.coordinates
    if coordinates is None or carrier.effect is None:
        return False
    if (coordinates.source is None or coordinates.return_addr is None
            or coordinates.return_frame_bytes is None):
        return False
    if (not coordinates.source.matches_call(call)
            or coordinates.callsite_addr != call.addr
            or type(coordinates.target_addr) is not int):
        return False
    target = call.args[0] if call.args else None
    if (isinstance(target, IRValue) and target.space is MemSpace.CONST
            and target.const != coordinates.target_addr):
        return False
    return bool(
        carrier.effect.callsite_addr == coordinates.callsite_addr
        and carrier.effect.target_addr == coordinates.target_addr
    )


def _artifact_binds_callsite_8616(
    artifact: IRFunctionArtifact,
    callee_scope: Real16InvocationDomain8616,
) -> bool:
    """Require the artifact the callee chain authenticated at link time.

    The retained link carries the identical registered caller artifact its
    census bound — a foreign or rebuilt artifact, even one decoding to the
    same text, is not that provenance.
    """
    chain = callee_scope.chain
    return (
        type(chain) is Real16CallChainLink8616
        and chain.callsite_artifact is artifact
    )


@dataclass(frozen=True, slots=True)
class ScopedCallStackContext8616:
    """Immutable per-callsite bindings consumed by the scoped solver path."""

    bindings: tuple[ScopedCallEntryBinding8616, ...] = ()

    def for_callsite(self, callsite_addr: int | None) -> ScopedCallEntryBinding8616 | None:
        """Return the binding owned by one exact callsite, never by prefix."""
        for binding in self.bindings:
            if binding.callsite_addr == callsite_addr:
                return binding
        return None

    def call_deltas_for(
        self,
        offered_caller_scope: object,
        artifact: IRFunctionArtifact | None,
    ) -> dict[int, int] | None:
        """Project every bound callsite delta for one caller execution.

        The offered caller domain must share entry provenance with every
        bound caller scope — that is the single caller execution the
        bindings belong to. Each binding still projects through its own
        retained caller/callee pair, so distinct physical calls keep
        distinct callee domains. The supplied artifact must be the exact
        callsite artifact each callee chain bound, and each callsite's
        actual CALL row must still satisfy the carrier's physical source,
        target and frame. Any failure refuses the entire map.
        """
        if (
            type(offered_caller_scope) is not Real16InvocationDomain8616
            or offered_caller_scope.failure is not None
            or type(artifact) is not IRFunctionArtifact
        ):
            return None
        instructions = {
            instr.addr: instr
            for block in artifact.blocks
            for instr in block.instrs
            if instr.addr is not None
        }
        deltas: dict[int, int] = {}
        for binding in self.bindings:
            callsite = binding.callsite_addr
            if callsite is None:
                return None
            if not same_real16_entry_scope_8616(
                offered_caller_scope, binding.caller_scope,
            ):
                return None
            if not _artifact_binds_callsite_8616(artifact, binding.callee_scope):
                return None
            call = instructions.get(callsite)
            if (
                call is None or call.op != "CALL"
                or not _call_row_matches_carrier_8616(call, binding.carrier)
            ):
                return None
            delta = binding.carrier.net_sp_delta_for(
                binding.caller_scope, binding.callee_scope,
            )
            if delta is None:
                return None
            deltas[callsite] = delta
        return deltas


def prove_scoped_call_stack_context_8616(
    bindings: tuple[ScopedCallEntryBinding8616, ...],
) -> ScopedCallStackContext8616 | None:
    """Authenticate one binding set; conflicting callsites refuse.

    Every carrier must be an accepted scoped publication retaining both its
    physical record and its effect, and every binding's declared domains
    must share provenance with the carrier's authenticated scope pair — a
    binding may not relabel another pair onto a valid carrier. Two bindings
    claiming one callsite, or a binding without a callsite, refuse the
    whole context rather than picking a winner.
    """
    seen: set[int] = set()
    for binding in bindings:
        if type(binding) is not ScopedCallEntryBinding8616:
            return None
        carrier = binding.carrier
        if type(carrier) is not IRScopedCallStackCoordinates8616:
            return None
        effect = carrier.effect
        if (
            carrier.failure is not None
            or carrier.coordinates is None
            or effect is None
            or type(binding.caller_scope) is not Real16InvocationDomain8616
            or type(binding.callee_scope) is not Real16InvocationDomain8616
        ):
            return None
        if not (
            same_real16_entry_scope_8616(binding.caller_scope, effect.caller_scope)
            and same_real16_entry_scope_8616(binding.callee_scope, effect.callee_scope)
        ):
            return None
        callsite = binding.callsite_addr
        if callsite is None or callsite in seen:
            return None
        seen.add(callsite)
    return ScopedCallStackContext8616(tuple(bindings))

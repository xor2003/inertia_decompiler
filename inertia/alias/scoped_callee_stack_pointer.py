"""Prove a callee's returning SP transfer under one authenticated entry scope.

Layer: Alias.
Responsibility: consume ``IRBoundaryCoverageResult8616.complete_for(scope)``
together with the scope's authenticated entry register state, then run the
existing must-state stack solver over the scope's live effective blocks and
retain the entry-SP displacement on every returning edge. Numeric register
constants seeded from the chain are plain data values; they never become
SP-relative coordinates. The result stays scope-bound: it can never be read
as a context-free displacement, and every accessor re-authenticates the
offered scope, the retained coverage and the derived transfers.
Owns storage identity. Do not perform lowering, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from inertia.ir.core import IRBlock
from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616
from inertia.ir.near_return_continuation_view import ScopedNearReturnContinuationView8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    Real16CallChainLink8616,
    Real16InvocationDomain8616,
    same_real16_entry_scope_8616,
)
from inertia.ir.scoped_function_ir_view import (
    ScopedFunctionCFGProjection8616,
    ScopedFunctionIRView8616,
)
from inertia.semantics.register_value_preservation import register_value_family_8616

from .callee_stack_pointer import _word_delta_8616
from .segment_stack_restore import _solve_stack_states
from .stack_pointer_snapshots import _GENERAL_WORD_REGISTERS

_EXTERNAL_OPS_8616 = frozenset({"CALL", "INT", "INTERRUPT", "SYSCALL", "IRET"})
_SEEDABLE_REGISTERS_8616 = frozenset(
    member
    for register in sorted(_GENERAL_WORD_REGISTERS)
    for member in register_value_family_8616(register)
)


class ScopedCalleeStackPointerFailure8616(StrEnum):
    """Why a scope-bound returning SP transfer could not be established."""

    COVERAGE_INCOMPLETE = "coverage_incomplete"
    SCOPE_ABSENT = "scope_absent"
    SCOPE_UNBOUND = "scope_unbound"
    ENTRY_STATE_UNPROVEN = "entry_state_unproven"
    ENTRY_SEED_CONFLICT = "entry_seed_conflict"
    PROJECTION_REFUSED = "projection_refused"
    ENTRY_REENTERED = "entry_reentered"
    EXTERNAL_EFFECT = "external_effect"
    RETURN_UNPROVEN = "return_unproven"
    STACK_POINTER_UNKNOWN = "stack_pointer_unknown"
    RETURN_DELTAS_DISAGREE = "return_deltas_disagree"


@dataclass(frozen=True, slots=True)
class ScopedCalleeStackPointerResult8616:
    """A scope-bound returning-SP transfer, or one explicit refusal.

    ``coverage`` and ``scope`` retain the exact objects the transfer was
    proved from; both are provenance bindings, not authorization. Reading
    the delta requires ``complete_for(offered)`` under a scope that shares
    provenance with the retained one, while the retained coverage still
    authenticates and a fresh solve reproduces the retained transfers.
    """

    coverage: IRBoundaryCoverageResult8616 | None
    scope: Real16InvocationDomain8616 | None = field(
        default=None, compare=False, repr=False,
    )
    failure: ScopedCalleeStackPointerFailure8616 | None = None
    detail: str = ""
    return_transfers: tuple[tuple[int, int], ...] = ()
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 1

    def _retained_transfer_is_accepted(self) -> bool:
        """Require an accepted publication, independently of its source."""
        counts = (
            self.raw_fact_count, self.normalized_fact_count,
            self.classified_fact_count, self.materialized_count,
            self.failure_count,
        )
        return bool(
            self.failure is None and counts == (1, 1, 1, 1, 0)
            and all(type(count) is int for count in counts)
        )

    @property
    def complete(self) -> bool:
        """Scoped evidence is never context-free; see ``complete_for``."""
        return self.complete_for(None)

    def complete_for(
        self, offered_scope: object,
    ) -> bool:
        """Authorize only under shared entry provenance and fresh evidence.

        The offered scope must be a typed invocation domain sharing
        provenance with the retained one, the retained coverage must still
        authenticate under it, and a fresh scoped solve must reproduce the
        retained transfers bit-for-bit. A foreign scope, a mutated surface,
        or a stale view revokes the verdict.
        """
        if not self._retained_transfer_is_accepted():
            return False
        if self.coverage is None or self.scope is None:
            return False
        if type(offered_scope) is not Real16InvocationDomain8616:
            return False
        if not same_real16_entry_scope_8616(offered_scope, self.scope):
            return False
        if not self.coverage.complete_for(offered_scope):
            return False
        failure, transfers, _detail = _scoped_return_transfers_8616(
            self.coverage, offered_scope,
        )
        return failure is None and transfers == self.return_transfers

    @property
    def observed_return_sp_delta(self) -> int | None:
        """Expose the retained delta for inventories without authorization."""
        if not self._retained_transfer_is_accepted() or not self.return_transfers:
            return None
        return self.return_transfers[0][1]

    def return_sp_delta_for(self, offered_scope: object) -> int | None:
        """Return the scoped entry-to-after-RET displacement only when proven."""
        return self.observed_return_sp_delta if self.complete_for(offered_scope) else None


def _seed_registers_8616(
    scope: Real16InvocationDomain8616,
) -> tuple[dict[str, int] | None, ScopedCalleeStackPointerFailure8616 | None, str]:
    """Extract authenticated entry register facts from the retained chain.

    Call-chained scopes transport the parent census's callsite register
    words; declared-entry scopes transport the declaration's fixed
    registers. Both keep the chain's own completeness obligation; anything
    else is not usable entry evidence. Only general word-register family
    members are seedable — frame and selector registers carry distinct
    coordinate meanings and are never numeric constants here.
    """
    link = scope.chain
    pairs: tuple[tuple[str, int], ...] | None = None
    if type(link) is Real16CallChainLink8616:
        if not link.complete:
            return None, ScopedCalleeStackPointerFailure8616.ENTRY_STATE_UNPROVEN, "chain_incomplete"
        pairs = link.call_state
    elif type(link) is DeclaredFunctionEntryLink8616:
        if not link.admission.complete:
            return None, ScopedCalleeStackPointerFailure8616.ENTRY_STATE_UNPROVEN, "admission_incomplete"
        pairs = link.admission.spec.registers
    if pairs is None:
        return None, ScopedCalleeStackPointerFailure8616.ENTRY_STATE_UNPROVEN, "chain_kind"
    seed: dict[str, int] = {}
    for name, word in pairs:
        if type(name) is not str or type(word) is not int:
            return None, ScopedCalleeStackPointerFailure8616.ENTRY_SEED_CONFLICT, "pair_shape"
        key = name.lower()
        if key not in _SEEDABLE_REGISTERS_8616:
            continue
        if word < 0 or word > 0xFFFF or (key in seed and seed[key] != word):
            return None, ScopedCalleeStackPointerFailure8616.ENTRY_SEED_CONFLICT, key
        seed[key] = word
    return seed, None, ""


def _live_scoped_blocks_8616(
    projection: ScopedFunctionCFGProjection8616,
) -> tuple[tuple[IRBlock, ...] | None, dict[int, tuple[int, ...]], ScopedCalleeStackPointerFailure8616 | None]:
    """Restrict the authenticated projection to its live effective surface.

    Unreachable block addresses stay on the shared artifact's pending
    records; they are only excluded from the solved graph. A pending
    refusal on a live block, or an edge leaving the live set, means the
    conditioned surface is not closed and the transfer refuses.
    """
    unreachable = projection.unreachable_block_addrs
    live = tuple(block for block in projection.blocks if block.addr not in unreachable)
    live_addrs = frozenset(block.addr for block in live)
    if not live or projection.function_addr not in live_addrs:
        return None, {}, ScopedCalleeStackPointerFailure8616.PROJECTION_REFUSED
    if any(
        addr in live_addrs and projection.pending[addr] for addr in projection.pending
    ):
        return None, {}, ScopedCalleeStackPointerFailure8616.RETURN_UNPROVEN
    successors: dict[int, tuple[int, ...]] = {}
    for block in live:
        outgoing = tuple(projection.successors.get(block.addr, ()))
        if any(target not in live_addrs for target in outgoing):
            return None, {}, ScopedCalleeStackPointerFailure8616.PROJECTION_REFUSED
        successors[block.addr] = outgoing
    return live, successors, None


def _scoped_exit_blocks_8616(
    live: tuple[IRBlock, ...],
    successors: Mapping[int, tuple[int, ...]],
) -> tuple[tuple[IRBlock, ...] | None, ScopedCalleeStackPointerFailure8616 | None]:
    """Require every scoped exit to be exactly one final RET."""
    exits = tuple(block for block in live if not successors[block.addr])
    mid_ret = any(
        instruction.op == "RET" and index != len(block.instrs) - 1
        for block in live
        for index, instruction in enumerate(block.instrs)
    )
    terminal_ret_with_flow = any(
        successors[block.addr] and block.instrs and block.instrs[-1].op == "RET"
        for block in live
    )
    if (
        not exits
        or any(not block.instrs or block.instrs[-1].op != "RET" for block in exits)
        or mid_ret
        or terminal_ret_with_flow
    ):
        return None, ScopedCalleeStackPointerFailure8616.RETURN_UNPROVEN
    return exits, None


def _scoped_projection_8616(
    coverage: IRBoundaryCoverageResult8616,
    scope: Real16InvocationDomain8616,
) -> tuple[ScopedFunctionCFGProjection8616 | None, ScopedCalleeStackPointerFailure8616 | None]:
    """Authenticate the coverage under the scope and yield its projection."""
    if not coverage.complete_for(scope):
        return None, ScopedCalleeStackPointerFailure8616.COVERAGE_INCOMPLETE
    view = coverage.scoped_view
    if type(view) not in (ScopedNearReturnContinuationView8616, ScopedFunctionIRView8616):
        return None, ScopedCalleeStackPointerFailure8616.SCOPE_UNBOUND
    typed_view = cast(
        ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616, view
    )
    projection = typed_view.cfg_projection_for(scope)
    if projection is None:
        return None, ScopedCalleeStackPointerFailure8616.PROJECTION_REFUSED
    if projection.source_artifact is not coverage.artifact:
        return None, ScopedCalleeStackPointerFailure8616.SCOPE_UNBOUND
    return projection, None


def _exit_transfers_8616(
    coverage: IRBoundaryCoverageResult8616,
    scope: Real16InvocationDomain8616,
    live: tuple[IRBlock, ...],
    successors: Mapping[int, tuple[int, ...]],
    exits: tuple[IRBlock, ...],
) -> tuple[ScopedCalleeStackPointerFailure8616 | None, tuple[tuple[int, int], ...], str]:
    """Seed authenticated entry constants and read a common exit delta."""
    seed, seed_failure, detail = _seed_registers_8616(scope)
    if seed_failure is not None or seed is None:
        return seed_failure, (), detail
    states = _solve_stack_states(
        coverage.artifact,
        entry_constants=seed,
        scoped_blocks=live,
        scoped_successors=successors,
    )
    transfers: list[tuple[int, int]] = []
    for block in sorted(exits, key=lambda item: item.addr):
        delta = states[block.addr].sp_delta
        if delta is None:
            return ScopedCalleeStackPointerFailure8616.STACK_POINTER_UNKNOWN, (), ""
        transfers.append((block.addr, _word_delta_8616(delta)))
    retained = tuple(transfers)
    if len({delta for _, delta in retained}) != 1:
        return ScopedCalleeStackPointerFailure8616.RETURN_DELTAS_DISAGREE, retained, ""
    return None, retained, ""


def _scoped_return_transfers_8616(
    coverage: IRBoundaryCoverageResult8616,
    scope: Real16InvocationDomain8616,
) -> tuple[ScopedCalleeStackPointerFailure8616 | None, tuple[tuple[int, int], ...], str]:
    """Solve the scope's live surface and collect a common returning delta."""
    projection, failure = _scoped_projection_8616(coverage, scope)
    if projection is None or failure is not None:
        return failure, (), ""
    live, successors, failure = _live_scoped_blocks_8616(projection)
    if live is None or failure is not None:
        return failure, (), ""
    if any(
        coverage.artifact.function_addr in outgoing for outgoing in successors.values()
    ):
        return ScopedCalleeStackPointerFailure8616.ENTRY_REENTERED, (), ""
    if any(
        row.op in _EXTERNAL_OPS_8616 for block in live for row in block.instrs
    ):
        return ScopedCalleeStackPointerFailure8616.EXTERNAL_EFFECT, (), ""
    exits, failure = _scoped_exit_blocks_8616(live, successors)
    if exits is None or failure is not None:
        return failure, (), ""
    return _exit_transfers_8616(coverage, scope, live, successors, exits)


def prove_scoped_callee_stack_pointer_8616(
    coverage: IRBoundaryCoverageResult8616 | None,
    consuming_scope: Real16InvocationDomain8616 | None,
) -> ScopedCalleeStackPointerResult8616:
    """Publish one scope-bound returning-SP transfer or a typed refusal.

    The offered scope must be a typed invocation domain; the retained
    coverage must still authenticate under it (``coverage.complete_for``),
    its scoped view must yield a projection owning the identical raw
    artifact, and the chain must carry proven entry register facts. The
    solve runs on the live effective surface only — pending unreachable
    markers on the shared artifact are never removed or ignored.
    """
    if consuming_scope is None:
        return ScopedCalleeStackPointerResult8616(
            coverage, None, ScopedCalleeStackPointerFailure8616.SCOPE_ABSENT, "",
        )
    if type(consuming_scope) is not Real16InvocationDomain8616:
        return ScopedCalleeStackPointerResult8616(
            coverage, None, ScopedCalleeStackPointerFailure8616.SCOPE_UNBOUND, "",
        )
    if type(coverage) is not IRBoundaryCoverageResult8616:
        return ScopedCalleeStackPointerResult8616(
            None, consuming_scope, ScopedCalleeStackPointerFailure8616.COVERAGE_INCOMPLETE, "",
        )
    failure, transfers, detail = _scoped_return_transfers_8616(coverage, consuming_scope)
    accepted = int(failure is None)
    return ScopedCalleeStackPointerResult8616(
        coverage,
        consuming_scope,
        failure,
        detail,
        transfers,
        1,
        1,
        accepted,
        accepted,
        1 - accepted,
    )

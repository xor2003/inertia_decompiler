"""Prove a leaf callee's returning SP transfer from its complete IR.

Layer: Alias.
Responsibility: consume authoritative instruction/CFG coverage and the existing
stack-state solver, retaining the SP displacement on every returning edge.
The displacement includes the machine RET updates already present in the IR.
It is not inferred from a return immediate or a calling-convention name.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616

from .bp_preservation import _return_blocks_8616
from .segment_stack_restore import _solve_stack_states


class CalleeStackPointerFailure8616(StrEnum):
    """Why a complete returning SP transfer could not be established."""

    COVERAGE_INCOMPLETE = "coverage_incomplete"
    ENTRY_REENTERED = "entry_reentered"
    EXTERNAL_EFFECT = "external_effect"
    RETURN_UNPROVEN = "return_unproven"
    STACK_POINTER_UNKNOWN = "stack_pointer_unknown"
    RETURN_DELTAS_DISAGREE = "return_deltas_disagree"


def _word_delta_8616(value: int) -> int:
    """Express one modular word displacement in signed affine coordinates."""
    return ((value + 0x8000) & 0xFFFF) - 0x8000


def _return_transfers_8616(
    coverage: IRBoundaryCoverageResult8616,
) -> tuple[CalleeStackPointerFailure8616 | None, tuple[tuple[int, int], ...]]:
    """Collect a common returning delta without assuming balanced bodies."""
    if not coverage.complete:
        return CalleeStackPointerFailure8616.COVERAGE_INCOMPLETE, ()
    artifact = coverage.artifact
    if any(artifact.function_addr in block.successor_addrs for block in artifact.blocks):
        return CalleeStackPointerFailure8616.ENTRY_REENTERED, ()
    if any(row.op in {"CALL", "INT", "INTERRUPT", "SYSCALL", "IRET"}
           for block in artifact.blocks for row in block.instrs):
        return CalleeStackPointerFailure8616.EXTERNAL_EFFECT, ()
    exits = _return_blocks_8616(artifact)
    if exits is None:
        return CalleeStackPointerFailure8616.RETURN_UNPROVEN, ()
    states = _solve_stack_states(artifact)
    transfers: list[tuple[int, int]] = []
    for block in sorted(exits, key=lambda item: item.addr):
        delta = states[block.addr].sp_delta
        if delta is None:
            return CalleeStackPointerFailure8616.STACK_POINTER_UNKNOWN, ()
        transfers.append((block.addr, _word_delta_8616(delta)))
    retained = tuple(transfers)
    if len({delta for _, delta in retained}) != 1:
        return CalleeStackPointerFailure8616.RETURN_DELTAS_DISAGREE, retained
    return None, retained


@dataclass(frozen=True, slots=True)
class CalleeStackPointerResult8616:
    """A source-bound whole-callee transfer, or one explicit refusal."""

    coverage: IRBoundaryCoverageResult8616
    failure: CalleeStackPointerFailure8616 | None
    return_transfers: tuple[tuple[int, int], ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    def _retained_transfer_is_accepted(self) -> bool:
        """Require an accepted publication, independently of its current source."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        return bool(
            self.failure is None and counts == (1, 1, 1, 1, 0)
            and all(type(count) is int for count in counts)
        )

    @property
    def complete(self) -> bool:
        """Recheck body identity and transfers before authorizing a consumer."""
        if not self._retained_transfer_is_accepted():
            return False
        failure, transfers = _return_transfers_8616(self.coverage)
        return failure is None and transfers == self.return_transfers

    @property
    def observed_return_sp_delta(self) -> int | None:
        """Expose the retained transfer value without authorizing its currency.

        Structural inventories may count this fact without replaying its proof.
        Consumers requiring a current effect must use return_sp_delta or complete.
        """
        if not self._retained_transfer_is_accepted() or not self.return_transfers:
            return None
        return self.return_transfers[0][1]

    @property
    def return_sp_delta(self) -> int | None:
        """Return the entry-to-after-RET displacement only with a valid proof."""
        return self.observed_return_sp_delta if self.complete else None


def prove_callee_stack_pointer_8616(
    coverage: IRBoundaryCoverageResult8616,
) -> CalleeStackPointerResult8616:
    """Publish one retained transfer or an atomic conservative non-result."""
    failure, transfers = _return_transfers_8616(coverage)
    accepted = int(failure is None)
    return CalleeStackPointerResult8616(
        coverage, failure, transfers, 1, 1, accepted, accepted, 1 - accepted,
    )

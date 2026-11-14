# cython: language_level=3, infer_types=True
"""Retain positive discarded-return proofs across storage-contract resolution.

Layer: Types/Lowering.
Responsibility: distinguish an exact unused-result observation from absent
return collection. A closed caller census with an independent discard witness
can seed an empty SCC output; missing observations never constitute proof.
Consumes typed caller-use facts, not instruction text or generated C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
import dataclasses
import operator
CallsiteStorageTrials8616 = typing.TypeVar("CallsiteStorageTrials8616")
FunctionStorageContract8616 = typing.TypeVar("FunctionStorageContract8616")
FunctionStorageTrials8616 = typing.TypeVar("FunctionStorageTrials8616")

if TYPE_CHECKING:
    from .interprocedural_storage_contracts import (
        CallsiteStorageTrials8616,
        FunctionStorageContract8616,
        FunctionStorageTrials8616,
    )


@dataclasses.dataclass(frozen=True, )
class DiscardedReturnTrial8616:
    """One exact callee's result proven unobserved by the named caller."""

    callee_addr: cython.longlong
    observation: CallerReturnUseFact8616

    @property
    def is_complete(self) -> cython.bint:
        """Refuse unknown, recursive-pass-through and contradictory use facts."""
        fact = self.observation
        unobserved = (
            fact.verdict is CallerReturnUseVerdict8616.UNUSED
            and fact.kind not in {CallsiteReturnUseKind8616.VALUE, CallsiteReturnUseKind8616.CONDITION}
            and fact.observed_value_view is None
            and fact.byte_extension is None
        )
        return self.callee_addr >= 0 and fact.classified and unobserved

    def belongs_to(self, callee_addr: cython.longlong, caller_addr: cython.longlong, callsite_addr: cython.longlong) -> cython.bint:
        """Require the original observation to identify its containing trial."""
        return (
            self.is_complete and operator.eq(self.callee_addr, callee_addr)
            and operator.eq(self.observation.caller_addr, caller_addr)
            and operator.eq(self.observation.callsite_addr, callsite_addr)
        )


@cython.ccall
def _discard_or_recursive_8616(
    site: CallsiteStorageTrials8616, recursive_callers: object,
) -> cython.bint:
    """Require one exclusive, complete discard or internal pass-through proof."""
    if site.returns:
        return False
    if site.discarded_return is not None:
        return not site.return_passthroughs and site.discarded_return.belongs_to(
            site.callee_addr, site.caller_addr, site.callsite_addr,
        )
    return (
        site.caller_addr in recursive_callers
        and len(site.return_passthroughs) == 1
        and site.return_passthroughs[0].belongs_to(site.callee_addr, site.caller_addr, site.callsite_addr)
    )


def discarded_return_census_proves_empty_8616(
    trials: FunctionStorageTrials8616, recursive_callers: object,
) -> cython.bint:
    """Require a closed census and an independent seed, not a recursion cycle."""
    expected = trials.expected_callsite_addrs
    observed = tuple(sorted(site.callsite_addr for site in iter(trials.callsites)))
    closed = (
        trials.caller_census_complete and bool(trials.callsites)
        and operator.eq(len(set(expected)), len(expected)) and operator.eq(tuple(sorted(expected)), observed)
    )
    independent_discard = any(
        site.caller_addr not in recursive_callers and site.discarded_return is not None
        for site in iter(trials.callsites)
    )
    return closed and independent_discard and all(
        operator.eq(site.callee_addr, trials.function_addr) and _discard_or_recursive_8616(site, recursive_callers)
        for site in iter(trials.callsites)
    )


class DiscardedReturnPublicationFailure8616(StrEnum):
    """Typed reasons why a discarded-result proof cannot be published."""

    BINDING_MISMATCH = "binding_mismatch"
    INVALID_PROOF = "invalid_proof"
    EMPTY_SEED_UNPROVEN = "empty_seed_unproven"


def discarded_return_publication_failure_8616(
    contract: FunctionStorageContract8616,
    trials: FunctionStorageTrials8616,
    recursive_callers: object,
) -> DiscardedReturnPublicationFailure8616 | None:
    """Check immutable proof retention before the atomic publication boundary."""
    proof: object
    binding: object
    sites = {site.callsite_addr: site for site in iter(trials.callsites)}
    if operator.ne(tuple(sorted(sites)), tuple(sorted(binding.callsite_addr for binding in iter(contract.callsites)))):
        return DiscardedReturnPublicationFailure8616.BINDING_MISMATCH
    for binding in contract.callsites:
        site = sites[binding.callsite_addr]
        proof = binding.discarded_return
        if operator.ne(binding.caller_addr, site.caller_addr) or operator.ne(proof, site.discarded_return):
            return DiscardedReturnPublicationFailure8616.BINDING_MISMATCH
        if proof is not None:
            contradictory_use = bool(binding.returns or binding.return_passthroughs)
            if contradictory_use or not proof.belongs_to(contract.function_addr, binding.caller_addr, binding.callsite_addr):
                return DiscardedReturnPublicationFailure8616.INVALID_PROOF
    recursive_empty = not contract.outputs and any(site.return_passthroughs for site in iter(trials.callsites))
    if recursive_empty and not discarded_return_census_proves_empty_8616(trials, recursive_callers):
        return DiscardedReturnPublicationFailure8616.EMPTY_SEED_UNPROVEN
    return None

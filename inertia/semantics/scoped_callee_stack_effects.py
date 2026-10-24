"""Scope-bound callee stack effect for one authenticated call chain.

Layer: Semantics.
Responsibility: bind the physical decoded CALL coordinates (callsite,
return address, target, frame kind) to an Alias-owned scoped returning-SP
proof, and require BOTH the retained caller domain and the retained callee
domain to re-authenticate before projecting the displacement. Possession of
a callee chain is caller evidence only — it does not authorize a different
caller consumer; the offered caller scope must share provenance with the
retained chain parent, the offered callee scope must share provenance with
the retained body scope, and the chain must still link this exact callsite
on this project. Numeric address equality alone is never sufficient.
Context-free accessors stay closed: a scoped result can never publish a
universal displacement or feed a universal scalar field.
Owns call-effect semantics. Do not perform alias-state, IR projection,
frontend decode, lowering, rewrite, postprocess, or CLI/reporting work here.
Owns instruction effects, flags, branch meaning, and expression interpretation
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from inertia.alias.scoped_callee_stack_pointer import (
    ScopedCalleeStackPointerResult8616,
    prove_scoped_callee_stack_pointer_8616,
)
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
)
from inertia.frontend.x86_16.synthetic_call_stub_evidence import (
    is_synthetic_call_stub_8616,
)
from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616
from inertia.ir.real16_invocation_domain import (
    Real16CallChainLink8616,
    Real16InvocationDomain8616,
    same_real16_entry_scope_8616,
)

from .callsite_summary import CallsiteMachineFrameKind8616
from .direct_ret_call_effect import direct_call_target_is_bound_8616

__all__ = [
    "ScopedCalleeStackCallFailure8616",
    "ScopedCalleeStackCallResult8616",
    "prove_scoped_direct_callee_stack_effect_8616",
]


class ScopedCalleeStackCallFailure8616(StrEnum):
    """Typed reason a scoped call cannot consume the callee SP proof."""

    SCOPE_ABSENT = "scope_absent"
    CALLER_SCOPE_UNBOUND = "caller_scope_unbound"
    CALLEE_SCOPE_UNBOUND = "callee_scope_unbound"
    CALL_CHAIN_UNBOUND = "call_chain_unbound"
    CALL_TARGET_UNPROVEN = "call_target_unproven"
    SYNTHETIC_BODY = "synthetic_body"
    COVERAGE_MISSING = "coverage_missing"
    BODY_REFUSED = "body_refused"


@dataclass(frozen=True, slots=True)
class ScopedCalleeStackCallResult8616:
    """Physical call identity, dual scope bindings, and the scoped body proof.

    ``caller_scope`` is the retained parent domain the chain was derived
    from; ``callee_scope`` is the retained callee domain the body proof ran
    under. Neither authorizes anything alone: projection requires offered
    scopes sharing exact provenance with both, plus a still-current physical
    CALL binding and a fresh body re-solve under the offered callee scope.
    """

    project: object = field(compare=False, repr=False)
    callsite_addr: int | None = None
    return_addr: int | None = None
    target_addr: int | None = None
    frame_kind: CallsiteMachineFrameKind8616 | None = None
    body: ScopedCalleeStackPointerResult8616 | None = field(
        default=None, compare=False, repr=False,
    )
    caller_scope: Real16InvocationDomain8616 | None = field(
        default=None, compare=False, repr=False,
    )
    callee_scope: Real16InvocationDomain8616 | None = field(
        default=None, compare=False, repr=False,
    )
    failure: ScopedCalleeStackCallFailure8616 | None = None
    detail: str = ""
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 1

    def _retained_call_is_accepted(self) -> bool:
        """Require published call evidence rather than a retained refusal."""
        counts = (
            self.raw_fact_count, self.normalized_fact_count,
            self.classified_fact_count, self.materialized_count,
            self.failure_count,
        )
        return bool(
            self.failure is None and counts == (1, 1, 1, 1, 0)
            and all(type(count) is int for count in counts)
        )

    def _call_identity_is_current(self) -> bool:
        """Recheck the physical CALL binding against the live source surface."""
        if not self._retained_call_is_accepted() or self.body is None:
            return False
        if self.target_addr is None or is_synthetic_call_stub_8616(
            self.project, self.target_addr,
        ):
            return False
        coverage = self.body.coverage
        if coverage is None:
            return False
        return bool(
            coverage.boundary.project is self.project
            and coverage.artifact.function_addr == self.target_addr
            and direct_call_target_is_bound_8616(
                self.project, self.callsite_addr, self.return_addr,
                self.target_addr, self.frame_kind,
            )
        )

    @property
    def complete(self) -> bool:
        """Scoped evidence is never context-free; see ``complete_for``."""
        return self.complete_for(None, None)

    def complete_for(
        self,
        offered_caller_scope: object,
        offered_callee_scope: object,
    ) -> bool:
        """Authorize only under both retained scope provenances, fresh.

        The offered callee scope must share the retained body scope's
        provenance and still chain to the offered caller scope on this
        callsite; the offered caller scope must share the retained parent
        domain's provenance. The physical CALL binding is re-read, and the
        Alias body re-solves under the offered callee scope — byte drift or
        a foreign chain revokes the verdict.
        """
        if not self._retained_call_is_accepted() or self.body is None:
            return False
        if self.caller_scope is None or self.callee_scope is None:
            return False
        if not self._offered_scopes_bind_8616(offered_caller_scope, offered_callee_scope):
            return False
        if not self._call_identity_is_current():
            return False
        return self.body.complete_for(offered_callee_scope)

    def _offered_scopes_bind_8616(
        self,
        offered_caller_scope: object,
        offered_callee_scope: object,
    ) -> bool:
        """Require both offered scopes to share retained provenance and link.

        The offered callee scope must share the retained body scope and carry
        a call chain whose decoded row binds this exact callsite and target
        and whose parent shares provenance with the offered caller scope,
        which itself must share the retained caller domain.
        """
        if type(offered_caller_scope) is not Real16InvocationDomain8616:
            return False
        if type(offered_callee_scope) is not Real16InvocationDomain8616:
            return False
        if not same_real16_entry_scope_8616(offered_callee_scope, self.callee_scope):
            return False
        if not same_real16_entry_scope_8616(offered_caller_scope, self.caller_scope):
            return False
        link = offered_callee_scope.chain
        if type(link) is not Real16CallChainLink8616:
            return False
        row = link.callsite
        if type(row) is not DecodedDirectCallsite8616:
            return False
        if row.callsite_addr != self.callsite_addr or row.target_addr != self.target_addr:
            return False
        return same_real16_entry_scope_8616(link.parent, offered_caller_scope)

    @property
    def observed_return_sp_delta(self) -> int | None:
        """Expose retained Alias data for inventories without authorization."""
        if not self._retained_call_is_accepted() or self.body is None:
            return None
        return self.body.observed_return_sp_delta

    def return_sp_delta_for(
        self,
        offered_caller_scope: object,
        offered_callee_scope: object,
    ) -> int | None:
        """Project the displacement only under both authenticated scopes."""
        if not self.complete_for(offered_caller_scope, offered_callee_scope):
            return None
        assert self.body is not None
        return self.body.return_sp_delta_for(offered_callee_scope)


def _failure_result_8616(
    project: object,
    callsite_addr: int | None,
    return_addr: int | None,
    target_addr: int | None,
    frame_kind: CallsiteMachineFrameKind8616 | None,
    failure: ScopedCalleeStackCallFailure8616,
    detail: str = "",
    *,
    caller_scope: Real16InvocationDomain8616 | None = None,
    callee_scope: Real16InvocationDomain8616 | None = None,
) -> ScopedCalleeStackCallResult8616:
    """Publish one atomic scoped non-result with closed refusal counters."""
    return ScopedCalleeStackCallResult8616(
        project, callsite_addr, return_addr, target_addr, frame_kind,
        None, caller_scope, callee_scope, failure, detail,
        1, 1, 0, 0, 1,
    )


def prove_scoped_direct_callee_stack_effect_8616(
    project: object,
    callsite_addr: int | None,
    return_addr: int | None,
    target_addr: int | None,
    frame_kind: CallsiteMachineFrameKind8616 | None,
    *,
    caller_scope: Real16InvocationDomain8616 | None,
    callee_scope: Real16InvocationDomain8616 | None,
    coverage: IRBoundaryCoverageResult8616 | None,
) -> ScopedCalleeStackCallResult8616:
    """Publish a scope-bound returning call effect or a typed refusal.

    The callee scope must carry a ``Real16CallChainLink8616`` whose decoded
    callsite row binds exactly this callsite and target, and whose parent
    shares provenance with the offered caller scope. The physical CALL is
    bound by the shared direct-target owner, synthetic stubs refuse, and the
    body proof must accept the retained scoped coverage under the callee
    scope. Nothing here relaxes universal coverage or fabricates entry state.
    """
    if type(callee_scope) is not Real16InvocationDomain8616:
        return _failure_result_8616(
            project, callsite_addr, return_addr, target_addr, frame_kind,
            ScopedCalleeStackCallFailure8616.SCOPE_ABSENT,
            caller_scope=caller_scope, callee_scope=None,
        )
    if type(caller_scope) is not Real16InvocationDomain8616:
        return _failure_result_8616(
            project, callsite_addr, return_addr, target_addr, frame_kind,
            ScopedCalleeStackCallFailure8616.CALLER_SCOPE_UNBOUND,
            caller_scope=None, callee_scope=callee_scope,
        )
    link = callee_scope.chain
    if (
        type(link) is not Real16CallChainLink8616
        or not same_real16_entry_scope_8616(caller_scope, link.parent)
    ):
        return _failure_result_8616(
            project, callsite_addr, return_addr, target_addr, frame_kind,
            ScopedCalleeStackCallFailure8616.CALLER_SCOPE_UNBOUND,
            caller_scope=caller_scope, callee_scope=callee_scope,
        )
    row = link.callsite
    chain_bound = (
        type(row) is DecodedDirectCallsite8616
        and row.callsite_addr == callsite_addr
        and row.target_addr == target_addr
        and not row.is_far
        and link.complete
        and callee_scope.complete
    )
    if not chain_bound:
        return _failure_result_8616(
            project, callsite_addr, return_addr, target_addr, frame_kind,
            ScopedCalleeStackCallFailure8616.CALL_CHAIN_UNBOUND,
            caller_scope=caller_scope, callee_scope=callee_scope,
        )
    if (
        type(target_addr) is int
        and is_synthetic_call_stub_8616(project, target_addr)
    ):
        return _failure_result_8616(
            project, callsite_addr, return_addr, target_addr, frame_kind,
            ScopedCalleeStackCallFailure8616.SYNTHETIC_BODY,
            caller_scope=caller_scope, callee_scope=callee_scope,
        )
    if not direct_call_target_is_bound_8616(
        project, callsite_addr, return_addr, target_addr, frame_kind,
    ):
        return _failure_result_8616(
            project, callsite_addr, return_addr, target_addr, frame_kind,
            ScopedCalleeStackCallFailure8616.CALL_TARGET_UNPROVEN,
            caller_scope=caller_scope, callee_scope=callee_scope,
        )
    if type(coverage) is not IRBoundaryCoverageResult8616:
        return _failure_result_8616(
            project, callsite_addr, return_addr, target_addr, frame_kind,
            ScopedCalleeStackCallFailure8616.COVERAGE_MISSING,
            caller_scope=caller_scope, callee_scope=callee_scope,
        )
    body = prove_scoped_callee_stack_pointer_8616(coverage, callee_scope)
    if body.failure is not None:
        return _failure_result_8616(
            project, callsite_addr, return_addr, target_addr, frame_kind,
            ScopedCalleeStackCallFailure8616.BODY_REFUSED,
            body.failure.value,
            caller_scope=caller_scope, callee_scope=callee_scope,
        )
    if not (
        coverage.boundary.project is project
        and coverage.artifact.function_addr == target_addr
    ):
        return _failure_result_8616(
            project, callsite_addr, return_addr, target_addr, frame_kind,
            ScopedCalleeStackCallFailure8616.COVERAGE_MISSING,
            caller_scope=caller_scope, callee_scope=callee_scope,
        )
    return ScopedCalleeStackCallResult8616(
        project, callsite_addr, return_addr, target_addr, frame_kind,
        body, caller_scope, callee_scope, None, "",
        1, 1, 1, 1, 0,
    )

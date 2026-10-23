"""Scoped callee stack call effect — native declared-context controls.

The Semantics adapter binds the physical decoded CALL row to an Alias
scoped returning-SP proof and requires BOTH the offered caller scope and the
offered callee scope to share retained provenance before projecting a
displacement. The fixture is a declared-environment world, not TYPES.EXE.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import angr
import pytest

from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.semantics.callsite_summary import CallsiteMachineFrameKind8616
from inertia.semantics.scoped_callee_stack_effects import (
    ScopedCalleeStackCallFailure8616,
    ScopedCalleeStackCallResult8616,
    prove_scoped_direct_callee_stack_effect_8616,
)
from tests.support.scoped_stack_fixture import (
    CALLEE,
    CALLEE_LOOP,
    CALLEE_LOOP_CX,
    CALLSITE,
    RETURN_ADDR,
    build_scoped_stack_parts_8616,
)

pytestmark = pytest.mark.decompiler


def _accepted(ax_seed: int, code: bytes) -> tuple[dict[str, object], ScopedCalleeStackCallResult8616]:
    """Build one declared world and its accepted scoped call effect."""
    parts = build_scoped_stack_parts_8616(ax_seed, code)
    result = prove_scoped_direct_callee_stack_effect_8616(
        parts["project"], CALLSITE, RETURN_ADDR, CALLEE,
        CallsiteMachineFrameKind8616.NEAR,
        caller_scope=cast(Real16InvocationDomain8616, parts["caller_domain"]),
        callee_scope=cast(Real16InvocationDomain8616, parts["callee_domain"]),
        coverage=cast(object, parts["coverage"]),  # type: ignore[arg-type]
    )
    return parts, result


def test_scoped_call_effect_positive_ax0(tmp_path: Path) -> None:
    """Authenticated caller+callee scopes project the +2 returning delta."""
    parts, result = _accepted(0, CALLEE_LOOP)
    caller = parts["caller_domain"]
    callee = parts["callee_domain"]
    assert result.failure is None
    assert result.complete_for(caller, callee) is True
    assert result.return_sp_delta_for(caller, callee) == 2


def test_scoped_call_effect_varied_seed_ax4(tmp_path: Path) -> None:
    """AX=4 seed projects -2; the delta tracks real transported evidence."""
    parts, result = _accepted(4, CALLEE_LOOP)
    caller = parts["caller_domain"]
    callee = parts["callee_domain"]
    assert result.failure is None
    assert result.return_sp_delta_for(caller, callee) == -2


def test_absent_and_wrong_scopes_refuse(tmp_path: Path) -> None:
    """Missing or mistyped scopes refuse at construction and at access."""
    parts, result = _accepted(0, CALLEE_LOOP)
    caller = parts["caller_domain"]
    callee = parts["callee_domain"]
    no_callee = prove_scoped_direct_callee_stack_effect_8616(
        parts["project"], CALLSITE, RETURN_ADDR, CALLEE,
        CallsiteMachineFrameKind8616.NEAR,
        caller_scope=cast(Real16InvocationDomain8616, caller),
        callee_scope=None,
        coverage=cast(object, parts["coverage"]),  # type: ignore[arg-type]
    )
    assert no_callee.failure is ScopedCalleeStackCallFailure8616.SCOPE_ABSENT
    no_caller = prove_scoped_direct_callee_stack_effect_8616(
        parts["project"], CALLSITE, RETURN_ADDR, CALLEE,
        CallsiteMachineFrameKind8616.NEAR,
        caller_scope=None,
        callee_scope=cast(Real16InvocationDomain8616, callee),
        coverage=cast(object, parts["coverage"]),  # type: ignore[arg-type]
    )
    assert no_caller.failure is ScopedCalleeStackCallFailure8616.CALLER_SCOPE_UNBOUND
    assert result.complete_for(None, callee) is False
    assert result.complete_for(caller, None) is False
    assert result.return_sp_delta_for(None, callee) is None
    assert result.return_sp_delta_for(caller, object()) is None


def test_foreign_and_swapped_scopes_refuse(tmp_path: Path) -> None:
    """Foreign provenance and role-swapped domains never authorize."""
    parts_a, result_a = _accepted(0, CALLEE_LOOP)
    parts_b = build_scoped_stack_parts_8616(0, CALLEE_LOOP)
    caller_a, callee_a = parts_a["caller_domain"], parts_a["callee_domain"]
    caller_b, callee_b = parts_b["caller_domain"], parts_b["callee_domain"]
    assert result_a.return_sp_delta_for(caller_a, callee_a) == 2
    assert result_a.complete_for(caller_b, callee_a) is False
    assert result_a.complete_for(caller_a, callee_b) is False
    assert result_a.return_sp_delta_for(caller_b, callee_b) is None
    # Role swap: the callee domain offered as caller scope is typed but wrong.
    assert result_a.complete_for(callee_a, callee_a) is False
    foreign = prove_scoped_direct_callee_stack_effect_8616(
        parts_a["project"], CALLSITE, RETURN_ADDR, CALLEE,
        CallsiteMachineFrameKind8616.NEAR,
        caller_scope=cast(Real16InvocationDomain8616, caller_b),
        callee_scope=cast(Real16InvocationDomain8616, callee_b),
        coverage=cast(object, parts_a["coverage"]),  # type: ignore[arg-type]
    )
    assert foreign.failure is not None


def test_wrong_physical_coordinates_refuse(tmp_path: Path) -> None:
    """Shifted callsite, wrong target, wrong return, wrong frame all refuse."""
    parts = build_scoped_stack_parts_8616(0, CALLEE_LOOP)
    caller = cast(Real16InvocationDomain8616, parts["caller_domain"])
    callee = cast(Real16InvocationDomain8616, parts["callee_domain"])
    coverage = cast(object, parts["coverage"])

    def attempt(callsite, return_addr, target, frame):
        return prove_scoped_direct_callee_stack_effect_8616(
            parts["project"], callsite, return_addr, target, frame,
            caller_scope=caller, callee_scope=callee,
            coverage=coverage,  # type: ignore[arg-type]
        )

    assert attempt(CALLSITE + 1, RETURN_ADDR, CALLEE,
                   CallsiteMachineFrameKind8616.NEAR).failure is not None
    assert attempt(CALLSITE, RETURN_ADDR, CALLEE + 4,
                   CallsiteMachineFrameKind8616.NEAR).failure is not None
    assert attempt(CALLSITE, RETURN_ADDR + 1, CALLEE,
                   CallsiteMachineFrameKind8616.NEAR).failure is not None
    assert attempt(CALLSITE, RETURN_ADDR, CALLEE,
                   CallsiteMachineFrameKind8616.FAR).failure is not None


def test_retained_byte_mutation_revokes(tmp_path: Path) -> None:
    """In-place caller/callee byte drift after proof revokes the accessor."""
    parts, result = _accepted(0, CALLEE_LOOP)
    caller = parts["caller_domain"]
    callee = parts["callee_domain"]
    assert result.return_sp_delta_for(caller, callee) == 2
    project = cast(angr.Project, parts["project"])
    assert bytes(project.loader.memory.load(0x1076, 2)) == b"\x2b\xd8"
    project.loader.memory.store(0x1076, b"\x2b\xd9")
    assert bytes(project.loader.memory.load(0x1076, 2)) == b"\x2b\xd9"
    assert result.complete_for(caller, callee) is False
    assert result.return_sp_delta_for(caller, callee) is None

    parts_b, result_b = _accepted(0, CALLEE_LOOP)
    caller_b = parts_b["caller_domain"]
    callee_b = parts_b["callee_domain"]
    assert result_b.return_sp_delta_for(caller_b, callee_b) == 2
    project_b = cast(angr.Project, parts_b["project"])
    project_b.loader.memory.store(0x1021, b"\x07\x00")
    assert result_b.complete_for(caller_b, callee_b) is False
    assert result_b.return_sp_delta_for(caller_b, callee_b) is None


def test_forged_result_fields_revoked(tmp_path: Path) -> None:
    """Fabricated coordinates, counters, and scope bindings refuse on access."""
    parts, result = _accepted(0, CALLEE_LOOP)
    caller = parts["caller_domain"]
    callee = parts["callee_domain"]
    forged_callsite = replace(result, callsite_addr=CALLSITE + 1)
    assert forged_callsite.complete_for(caller, callee) is False
    assert forged_callsite.return_sp_delta_for(caller, callee) is None
    forged_counts = replace(result, materialized_count=9)
    assert forged_counts.complete_for(caller, callee) is False
    forged_scope = replace(result, caller_scope=cast(
        Real16InvocationDomain8616, callee))
    assert forged_scope.complete_for(caller, callee) is False


def test_context_free_never_authorizes(tmp_path: Path) -> None:
    """No context-free accessor exists; observed stays diagnostic-only."""
    _parts, result = _accepted(0, CALLEE_LOOP)
    assert result.complete is False
    assert not hasattr(result, "return_sp_delta")
    assert result.observed_return_sp_delta == 2  # retained diagnostic only


def test_raw_pending_coverage_body_refused(tmp_path: Path) -> None:
    """Unscoped/pending coverage cannot satisfy the body proof."""
    parts = build_scoped_stack_parts_8616(0, CALLEE_LOOP)
    refused = prove_scoped_direct_callee_stack_effect_8616(
        parts["project"], CALLSITE, RETURN_ADDR, CALLEE,
        CallsiteMachineFrameKind8616.NEAR,
        caller_scope=cast(Real16InvocationDomain8616, parts["caller_domain"]),
        callee_scope=cast(Real16InvocationDomain8616, parts["callee_domain"]),
        coverage=cast(object, parts["raw_coverage"]),  # type: ignore[arg-type]
    )
    assert refused.failure is ScopedCalleeStackCallFailure8616.BODY_REFUSED
    assert refused.detail != ""


def test_foreign_callee_bytes_refuse(tmp_path: Path) -> None:
    """A different project's callee body is foreign provenance, not drift."""
    parts_a, result_a = _accepted(0, CALLEE_LOOP)
    parts_b = build_scoped_stack_parts_8616(0, CALLEE_LOOP_CX)
    foreign = prove_scoped_direct_callee_stack_effect_8616(
        parts_a["project"], CALLSITE, RETURN_ADDR, CALLEE,
        CallsiteMachineFrameKind8616.NEAR,
        caller_scope=cast(Real16InvocationDomain8616, parts_b["caller_domain"]),
        callee_scope=cast(Real16InvocationDomain8616, parts_b["callee_domain"]),
        coverage=cast(object, parts_a["coverage"]),  # type: ignore[arg-type]
    )
    assert foreign.failure is not None
    assert result_a.complete_for(
        parts_b["caller_domain"], parts_b["callee_domain"]) is False

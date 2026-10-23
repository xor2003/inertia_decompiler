"""Scoped callee returning-SP proof — declared-context native fixtures.

Builds the same minimal conditional world the local-call investigation used:
a declared caller entry (``mov ax,K; call callee; ret``) chained across one
decoded near-call edge into a callee whose continuation performs
``pop cx; mov bx,sp; sub bx,ax; mov sp,bx; jmp cx``. The scoped callee-SP
owner must return ``+2 - K`` under the authenticated scope only, refuse
absent/foreign scopes, and never expose a context-free displacement.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import angr
import pytest

from inertia.alias.callee_stack_pointer import prove_callee_stack_pointer_8616
from inertia.alias.scoped_callee_stack_pointer import (
    ScopedCalleeStackPointerFailure8616,
    prove_scoped_callee_stack_pointer_8616,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.ir.real16_invocation_domain import (
    Real16CallChainLink8616,
    prove_fresh_real16_chained_invocation_domain_8616,
)
from tests.support.scoped_stack_fixture import (
    CALLEE,
    CALLEE_CLEAN_RET,
    CALLEE_CLOBBER,
    CALLEE_LOOP,
    CALLEE_LOOP_CX,
    CONT_BLOCK,
    build_scoped_stack_fixture_8616,
    build_scoped_stack_parts_8616,
)

pytestmark = pytest.mark.decompiler


def test_scoped_delta_under_authenticated_chain(tmp_path: Path) -> None:
    """pop+mov-bx-sp+sub-bx-ax+mov-sp-bx returns +2 when the chain proves AX=0."""
    scope, coverage, _raw, artifact = build_scoped_stack_fixture_8616(0, CALLEE_LOOP)
    result = prove_scoped_callee_stack_pointer_8616(coverage, scope)
    assert result.failure is None
    assert result.return_transfers == ((CONT_BLOCK, 2),)
    assert result.return_sp_delta_for(scope) == 2
    assert coverage.artifact is artifact


def test_scoped_delta_tracks_varied_numeric_seed(tmp_path: Path) -> None:
    """An independently varied valid seed must not collapse to a hardcoded +2."""
    scope, coverage, _raw, _artifact = build_scoped_stack_fixture_8616(4, CALLEE_LOOP)
    result = prove_scoped_callee_stack_pointer_8616(coverage, scope)
    assert result.failure is None
    assert result.return_transfers == ((CONT_BLOCK, -2),)
    assert result.return_sp_delta_for(scope) == -2


def test_absent_and_foreign_scope_refuse(tmp_path: Path) -> None:
    """No scope, a non-domain scope, and a foreign domain all refuse."""
    scope, coverage, _raw, _artifact = build_scoped_stack_fixture_8616(0, CALLEE_LOOP)
    absent = prove_scoped_callee_stack_pointer_8616(coverage, None)
    assert absent.failure is ScopedCalleeStackPointerFailure8616.SCOPE_ABSENT
    wrong_kind = prove_scoped_callee_stack_pointer_8616(coverage, object())  # type: ignore[arg-type]
    assert wrong_kind.failure is ScopedCalleeStackPointerFailure8616.SCOPE_UNBOUND
    foreign_scope, _foreign_cov, _f_raw, _f_art = build_scoped_stack_fixture_8616(4, CALLEE_LOOP)
    stale = prove_scoped_callee_stack_pointer_8616(coverage, foreign_scope)
    assert stale.failure is ScopedCalleeStackPointerFailure8616.COVERAGE_INCOMPLETE
    accepted = prove_scoped_callee_stack_pointer_8616(coverage, scope)
    assert accepted.return_sp_delta_for(foreign_scope) is None
    assert accepted.complete_for(foreign_scope) is False


def test_unseeded_register_keeps_sp_unknown(tmp_path: Path) -> None:
    """Without proven AX evidence the transfer stays unknown, never guessed."""
    scope, coverage, _raw, _artifact = build_scoped_stack_fixture_8616(None, CALLEE_LOOP)
    result = prove_scoped_callee_stack_pointer_8616(coverage, scope)
    assert result.failure is ScopedCalleeStackPointerFailure8616.STACK_POINTER_UNKNOWN


def test_branch_clobber_join_kills_coordinate(tmp_path: Path) -> None:
    """A reached predecessor rewriting AX drops the numeric fact at the join."""
    scope, coverage, _raw, _artifact = build_scoped_stack_fixture_8616(0, CALLEE_CLOBBER)
    result = prove_scoped_callee_stack_pointer_8616(coverage, scope)
    assert result.failure is ScopedCalleeStackPointerFailure8616.STACK_POINTER_UNKNOWN


def test_unproved_coverage_still_refuses(tmp_path: Path) -> None:
    """The universal/pending coverage cannot supply a scoped transfer."""
    scope, _coverage, raw_coverage, _artifact = build_scoped_stack_fixture_8616(0, CALLEE_LOOP)
    result = prove_scoped_callee_stack_pointer_8616(raw_coverage, scope)
    assert result.failure is ScopedCalleeStackPointerFailure8616.COVERAGE_INCOMPLETE
    universal = prove_callee_stack_pointer_8616(raw_coverage)
    assert universal.return_sp_delta is None


def test_scoped_result_never_context_free(tmp_path: Path) -> None:
    """A successful scoped result must not read as a universal displacement."""
    scope, coverage, _raw, artifact = build_scoped_stack_fixture_8616(0, CALLEE_LOOP)
    result = prove_scoped_callee_stack_pointer_8616(coverage, scope)
    assert result.failure is None
    assert result.complete is False
    assert result.return_sp_delta_for(None) is None
    assert result.complete_for(None) is False
    refusals_before = tuple(
        (block.addr, tuple(refusal.kind for refusal in block.refusals))
        for block in artifact.blocks
    )
    assert coverage.artifact is artifact
    refusals_after = tuple(
        (block.addr, tuple(refusal.kind for refusal in block.refusals))
        for block in artifact.blocks
    )
    assert refusals_after == refusals_before


def test_same_address_foreign_project_refuses(tmp_path: Path) -> None:
    """Identical bytes under a different project must not authorize.

    A numeric head address coincidence is not evidence: the scope binds its
    retained artifact/boundary objects, so a foreign project's domain
    revokes both the publication and accessor replay.
    """
    scope_a, coverage_a, _raw_a, _art_a = build_scoped_stack_fixture_8616(0, CALLEE_LOOP)
    scope_b, coverage_b, _raw_b, _art_b = build_scoped_stack_fixture_8616(0, CALLEE_LOOP)
    result_a = prove_scoped_callee_stack_pointer_8616(coverage_a, scope_a)
    assert result_a.return_sp_delta_for(scope_a) == 2
    foreign = prove_scoped_callee_stack_pointer_8616(coverage_a, scope_b)
    assert foreign.failure is ScopedCalleeStackPointerFailure8616.COVERAGE_INCOMPLETE
    assert result_a.complete_for(scope_b) is False
    assert result_a.return_sp_delta_for(scope_b) is None
    foreign_cov = prove_scoped_callee_stack_pointer_8616(coverage_b, scope_a)
    assert foreign_cov.failure is ScopedCalleeStackPointerFailure8616.COVERAGE_INCOMPLETE


def test_universal_coverage_never_authorizes_scope(tmp_path: Path) -> None:
    """A context-free complete coverage must not become scoped evidence.

    ``complete_for`` on a universal coverage ignores the offered entry; the
    scoped proof must therefore refuse before consuming entry constants.
    """
    scope, _coverage, _raw, _artifact = build_scoped_stack_fixture_8616(0, CALLEE_LOOP)
    _clean_scope, _clean_cov, clean_raw, _clean_artifact = build_scoped_stack_fixture_8616(
        None, CALLEE_CLEAN_RET, needs_scope=False)
    assert clean_raw.complete is True
    universal = prove_callee_stack_pointer_8616(clean_raw)
    assert universal.return_sp_delta == 4  # pop cx (+2) then machine RET (+2)
    scoped = prove_scoped_callee_stack_pointer_8616(clean_raw, scope)
    assert scoped.failure is ScopedCalleeStackPointerFailure8616.SCOPE_UNBOUND
    assert scoped.complete_for(scope) is False
    assert scoped.return_sp_delta_for(scope) is None


def test_foreign_callee_bytes_refuse(tmp_path: Path) -> None:
    """A different project's callee bytes are foreign provenance, not staleness.

    This is a cross-world refusal: the scope binds its own retained artifact,
    so offering another world's domain against retained coverage refuses.
    In-place byte mutation on the original read surface is covered by the
    retained-evidence freshness tests below.
    """
    scope_a, coverage_a, _raw_a, _art_a = build_scoped_stack_fixture_8616(0, CALLEE_LOOP)
    scope_b, _coverage_b, _raw_b, _art_b = build_scoped_stack_fixture_8616(0, CALLEE_LOOP_CX)
    result_a = prove_scoped_callee_stack_pointer_8616(coverage_a, scope_a)
    assert result_a.return_sp_delta_for(scope_a) == 2
    stale = prove_scoped_callee_stack_pointer_8616(coverage_a, scope_b)
    assert stale.failure is ScopedCalleeStackPointerFailure8616.COVERAGE_INCOMPLETE
    assert result_a.complete_for(scope_b) is False
    assert result_a.return_sp_delta_for(scope_b) is None


def test_tampered_call_state_never_authorizes(tmp_path: Path) -> None:
    """A chain forged with a different transported AX must not complete.

    The parent-census replay inside fresh-domain derivation is the binding
    check: tampered call_state either kills the domain outright or fails
    the coverage replay under it.
    """
    parts = build_scoped_stack_parts_8616(0, CALLEE_LOOP)
    chain = cast(Real16CallChainLink8616, parts["chain"])
    tampered_state = tuple(
        (name, 7) if name == "ax" else (name, word)
        for name, word in chain.call_state
    )
    bad_chain = replace(chain, call_state=tampered_state)
    bad_domain = prove_fresh_real16_chained_invocation_domain_8616(
        cast(angr.Project, parts["project"]), None, CALLEE,
        boot=parts["boot"], boot_recompute=parts["recompute"],  # type: ignore[arg-type]
        chain=bad_chain)
    if bad_domain is None or bad_domain.failure is not None:
        return
    refused = prove_scoped_callee_stack_pointer_8616(
        cast(object, parts["coverage"]), bad_domain)  # type: ignore[arg-type]
    assert refused.failure is ScopedCalleeStackPointerFailure8616.COVERAGE_INCOMPLETE


def test_forged_retained_transfer_revoked_on_access(tmp_path: Path) -> None:
    """Fabricated retained transfers/counters never pass accessor replay."""
    scope, coverage, _raw, _artifact = build_scoped_stack_fixture_8616(0, CALLEE_LOOP)
    result = prove_scoped_callee_stack_pointer_8616(coverage, scope)
    assert result.failure is None
    forged_delta = replace(result, return_transfers=((CONT_BLOCK, 3),))
    assert forged_delta.complete_for(scope) is False
    assert forged_delta.return_sp_delta_for(scope) is None
    forged_counts = replace(result, materialized_count=7)
    assert forged_counts.complete_for(scope) is False
    assert forged_counts.return_sp_delta_for(scope) is None


def test_forged_success_from_failed_base_revoked(tmp_path: Path) -> None:
    """A refusal rewritten as a success must fail its fresh re-solve."""
    scope, coverage, _raw, _artifact = build_scoped_stack_fixture_8616(None, CALLEE_LOOP)
    refused = prove_scoped_callee_stack_pointer_8616(coverage, scope)
    assert refused.failure is ScopedCalleeStackPointerFailure8616.STACK_POINTER_UNKNOWN
    forged = replace(
        refused, failure=None, detail="",
        return_transfers=((CONT_BLOCK, 2),),
        classified_fact_count=1, materialized_count=1, failure_count=0,
    )
    assert forged.observed_return_sp_delta == 2  # retained diagnostic only
    assert forged.complete_for(scope) is False
    assert forged.return_sp_delta_for(scope) is None
    assert forged.complete is False


def test_retained_callee_byte_mutation_revokes(tmp_path: Path) -> None:
    """Mutating the original project's callee bytes must revoke retained proof.

    Pre-mutation the proof is accepted; after the original read surface
    changes (``sub bx,ax`` → ``sub bx,cx`` at 0x1076), the same retained
    coverage and same original scope must fail everywhere — fresh producer,
    ``complete_for``, and ``return_sp_delta_for``.
    """
    parts = build_scoped_stack_parts_8616(0, CALLEE_LOOP)
    scope = cast(object, parts["callee_domain"])
    coverage = cast(object, parts["coverage"])
    result = prove_scoped_callee_stack_pointer_8616(coverage, scope)  # type: ignore[arg-type]
    assert result.return_sp_delta_for(scope) == 2
    project = cast(angr.Project, parts["project"])
    before = bytes(project.loader.memory.load(0x1076, 2))
    assert before == b"\x2b\xd8"  # original retained sub bx,ax bytes
    project.loader.memory.store(0x1076, b"\x2b\xd9")
    assert bytes(project.loader.memory.load(0x1076, 2)) == b"\x2b\xd9"
    assert result.complete_for(scope) is False
    assert result.return_sp_delta_for(scope) is None
    fresh = prove_scoped_callee_stack_pointer_8616(coverage, scope)  # type: ignore[arg-type]
    assert fresh.failure is not None


def test_retained_caller_byte_mutation_revokes(tmp_path: Path) -> None:
    """Mutating the original caller's seed write must revoke retained proof.

    ``mov ax,0`` operand bytes at 0x1021 become ``mov ax,7``; the parent
    replay inside the domain re-derivation must observe the drift and the
    retained result must refuse under the same original scope.
    """
    parts = build_scoped_stack_parts_8616(0, CALLEE_LOOP)
    scope = cast(object, parts["callee_domain"])
    coverage = cast(object, parts["coverage"])
    result = prove_scoped_callee_stack_pointer_8616(coverage, scope)  # type: ignore[arg-type]
    assert result.return_sp_delta_for(scope) == 2
    project = cast(angr.Project, parts["project"])
    before = bytes(project.loader.memory.load(0x1021, 2))
    assert before == b"\x00\x00"  # original mov ax,0 operand
    project.loader.memory.store(0x1021, b"\x07\x00")
    assert bytes(project.loader.memory.load(0x1021, 2)) == b"\x07\x00"
    assert result.complete_for(scope) is False
    assert result.return_sp_delta_for(scope) is None
    fresh = prove_scoped_callee_stack_pointer_8616(coverage, scope)  # type: ignore[arg-type]
    assert fresh.failure is not None

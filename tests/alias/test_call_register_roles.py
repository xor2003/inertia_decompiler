"""Tests for the canonical Alias CALL register-preservation decision."""

from __future__ import annotations

import pytest

from inertia.alias.call_register_roles import (
    CallRegisterPreservationVerdict8616,
    call_role_preserves_register_8616,
    decide_call_register_preservation_8616,
)
from inertia.alias.register_reaching_source import RegisterReachingSourceVerdict8616
from inertia.cli.project_loading import _build_project_from_bytes
from inertia.semantics.call_register_role_contracts import (
    CALL_REGISTER_ROLE_KINDS_8616,
    FULL_DOMAIN_MASK_8616,
    TRACKED_REGISTER_DOMAIN_NAMES_8616,
    CallRegisterDomainBits8616,
    CallRegisterRoleCoverage8616,
    CallRegisterRoleEvidence8616,
    CallRegisterRoleFailure8616,
    CallRegisterRoleKind8616,
    CallRegisterRolesFact8616,
)
from inertia.semantics.call_register_roles import (
    build_callsite_register_role_fact_8616,
)
from inertia.semantics.callsite_register_provenance import (
    recover_register_source_before_instruction_8616,
)

KIND = CallRegisterRoleKind8616
COVERAGE = CallRegisterRoleCoverage8616


pytestmark = pytest.mark.decompiler

def _refused_role(kind: KIND) -> CallRegisterRoleEvidence8616:
    return CallRegisterRoleEvidence8616(
        kind,
        COVERAGE.UNKNOWN_REFUSE,
        (),
        (),
        (CallRegisterRoleFailure8616.CALLEE_EVIDENCE_MISSING,),
        1,
        1,
        0,
        0,
        1,
    )


def _fact_with_may_clobber(
    ax_bits: tuple[int, int],
    *,
    complete: bool = True,
) -> CallRegisterRolesFact8616:
    """Build a fact whose only decided role evidence is may-clobber."""
    domains = tuple(
        CallRegisterDomainBits8616(
            name,
            *(ax_bits if name == "AX" else (FULL_DOMAIN_MASK_8616, 0)
              if complete else (0, 0)),
        )
        for name in TRACKED_REGISTER_DOMAIN_NAMES_8616
    )
    decided = sum(entry.known_bits != 0 for entry in domains)
    evidence = CallRegisterRoleEvidence8616(
        KIND.MAY_CLOBBER,
        COVERAGE.COMPLETE if complete else COVERAGE.PARTIAL,
        domains,
        (),
        () if complete else (CallRegisterRoleFailure8616.CALLEE_COVERAGE_PARTIAL,),
        len(TRACKED_REGISTER_DOMAIN_NAMES_8616),
        len(TRACKED_REGISTER_DOMAIN_NAMES_8616),
        decided,
        decided,
        len(TRACKED_REGISTER_DOMAIN_NAMES_8616) - decided,
    )
    roles = tuple(
        evidence if kind is KIND.MAY_CLOBBER else _refused_role(kind)
        for kind in CALL_REGISTER_ROLE_KINDS_8616
    )
    return CallRegisterRolesFact8616(
        0x1000, 0, 0x1000, 0x1010, 0x1003, roles, ()
    )


def test_complete_clean_clobber_evidence_preserves_view() -> None:
    fact = _fact_with_may_clobber((0xFFFF, 0))
    for register in ("ax", "al", "ah"):
        decision = decide_call_register_preservation_8616(fact, register)
        assert decision.verdict is CallRegisterPreservationVerdict8616.PRESERVED
        assert decision.preserves
        assert decision.classified_fact_count == decision.materialized_count == 1
        assert decision.failure_count == 0


def test_low_byte_write_spoils_ax_and_al_but_preserves_ah() -> None:
    fact = _fact_with_may_clobber((0xFFFF, 0x00FF))
    assert decide_call_register_preservation_8616(fact, "al").verdict is (
        CallRegisterPreservationVerdict8616.SPOILED
    )
    assert decide_call_register_preservation_8616(fact, "ax").verdict is (
        CallRegisterPreservationVerdict8616.SPOILED
    )
    assert decide_call_register_preservation_8616(fact, "ah").verdict is (
        CallRegisterPreservationVerdict8616.PRESERVED
    )


def test_undecided_view_bits_refuse_preservation() -> None:
    fact = _fact_with_may_clobber((0x00FF, 0), complete=False)
    decision = decide_call_register_preservation_8616(fact, "ax")
    assert decision.verdict is CallRegisterPreservationVerdict8616.UNKNOWN_REFUSE
    assert decision.undecided_bits == 0xFF00
    assert decision.classified_fact_count == 0
    assert decision.materialized_count == 0
    assert decision.failure_count == 1
    # The decided-clean low byte is still provably preserved on its own.
    assert call_role_preserves_register_8616(fact, "al")


def test_unsupported_views_refuse_instead_of_truncating() -> None:
    fact = _fact_with_may_clobber((0xFFFF, 0))
    for register in ("eax", "ss", "ds", "bogus"):
        decision = decide_call_register_preservation_8616(fact, register)
        assert decision.verdict is CallRegisterPreservationVerdict8616.UNKNOWN_REFUSE
        assert not decision.preserves


def test_other_roles_never_masquerade_as_preservation() -> None:
    """Input/dead/result evidence cannot substitute for may-clobber proof."""
    fact = _fact_with_may_clobber((0xFFFF, 0xFFFF))
    spoiled = decide_call_register_preservation_8616(fact, "si")
    # SI evidence in the fixture lives on AX only; SI is decided clean.
    assert spoiled.verdict is CallRegisterPreservationVerdict8616.PRESERVED
    ax = decide_call_register_preservation_8616(fact, "ax")
    assert ax.verdict is CallRegisterPreservationVerdict8616.SPOILED


def test_refused_clobber_evidence_refuses_preservation() -> None:
    roles = tuple(_refused_role(kind) for kind in CALL_REGISTER_ROLE_KINDS_8616)
    fact = CallRegisterRolesFact8616(0x1000, 0, 0x1000, 0x1010, 0x1003, roles, ())
    decision = decide_call_register_preservation_8616(fact, "ax")
    assert decision.verdict is CallRegisterPreservationVerdict8616.UNKNOWN_REFUSE
    assert not decision.preserves


def _project(code: bytes):
    return _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)


def test_reaching_source_crosses_multi_block_callee() -> None:
    """Complete no-write evidence in a real multi-block callee preserves SI."""
    caller = bytes.fromhex("56 be 92 00 e8 09 00 56 c3")
    pad = b"\x90" * (0x1010 - 0x1000 - len(caller))
    callee = bytes.fromhex("85 c0 74 01 90 c3")  # test ax,ax; jz; nop; ret
    project = _project(caller + pad + callee)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]

    result = recover_register_source_before_instruction_8616(
        function, instruction_addr=0x1007, register="si",
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert result.source == ("imm", 146)


def test_reaching_source_killed_by_multi_block_callee_write() -> None:
    """A write on one callee branch spoils the register on every path."""
    caller = bytes.fromhex("56 be 92 00 e8 09 00 56 c3")
    pad = b"\x90" * (0x1010 - 0x1000 - len(caller))
    # callee: test ax,ax; jz 0x1017; mov si,1; ret; ret
    callee = bytes.fromhex("85 c0 74 03 be 01 00 c3 c3")
    project = _project(caller + pad + callee)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]

    result = recover_register_source_before_instruction_8616(
        function, instruction_addr=0x1007, register="si",
    )

    assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.source is None


def test_al_write_spoils_ax_and_al_but_preserves_ah() -> None:
    """Caller-side view overlap: AL write kills AX/AL while AH survives."""
    caller = bytes.fromhex("b4 92 e8 0b 00 88 e1 c3")  # mov ah,0x92; call; mov cl,ah; ret
    pad = b"\x90" * (0x1010 - 0x1000 - len(caller))
    callee = bytes.fromhex("b0 07 c3")  # mov al,7; ret
    project = _project(caller + pad + callee)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]

    high = recover_register_source_before_instruction_8616(
        function, instruction_addr=0x1005, register="ah",
    )
    word = recover_register_source_before_instruction_8616(
        function, instruction_addr=0x1005, register="ax",
    )
    low = recover_register_source_before_instruction_8616(
        function, instruction_addr=0x1005, register="al",
    )

    assert high.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert high.source == ("imm", 146)
    assert word.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert low.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE


def test_unknown_callee_effects_still_kill(monkeypatch) -> None:
    """An undecodable call target refuses preservation as before."""
    caller = bytes.fromhex("56 be 92 00 e8 02 00 56 c3 c3")
    project = _project(caller)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]
    monkeypatch.setattr(
        "inertia.semantics.callsite_register_provenance."
        "resolve_direct_call_target_from_instruction_8616",
        lambda _project, _instruction: 0x2000,
    )

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x2000,
    )
    decision = decide_call_register_preservation_8616(fact, "si")
    assert decision.verdict is CallRegisterPreservationVerdict8616.UNKNOWN_REFUSE

    result = recover_register_source_before_instruction_8616(
        function, instruction_addr=0x1007, register="si",
    )
    assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.source is None


def test_partial_coverage_preserves_fully_decided_view() -> None:
    """A partial role census still proves a view whose bits are decided."""
    domains = tuple(
        CallRegisterDomainBits8616(
            name,
            FULL_DOMAIN_MASK_8616 if name == "SI" else 0x00FF,
            0,
        )
        for name in TRACKED_REGISTER_DOMAIN_NAMES_8616
    )
    decided = sum(entry.known_bits != 0 for entry in domains)
    evidence = CallRegisterRoleEvidence8616(
        KIND.MAY_CLOBBER,
        COVERAGE.PARTIAL,
        domains,
        (),
        (CallRegisterRoleFailure8616.CALLEE_COVERAGE_PARTIAL,),
        len(TRACKED_REGISTER_DOMAIN_NAMES_8616),
        len(TRACKED_REGISTER_DOMAIN_NAMES_8616),
        decided,
        decided,
        len(TRACKED_REGISTER_DOMAIN_NAMES_8616) - decided,
    )
    fact = CallRegisterRolesFact8616(
        0x1000,
        0,
        0x1000,
        0x1010,
        0x1003,
        tuple(
            evidence if kind is KIND.MAY_CLOBBER else _refused_role(kind)
            for kind in CALL_REGISTER_ROLE_KINDS_8616
        ),
        (),
    )

    si = decide_call_register_preservation_8616(fact, "si")
    ax = decide_call_register_preservation_8616(fact, "ax")
    assert si.verdict is CallRegisterPreservationVerdict8616.PRESERVED
    assert si.preserves
    assert ax.verdict is CallRegisterPreservationVerdict8616.UNKNOWN_REFUSE
    assert not ax.preserves

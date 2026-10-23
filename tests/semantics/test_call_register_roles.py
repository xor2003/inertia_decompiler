"""Tests for the four distinct register roles of an exact CALL."""

from __future__ import annotations

from dataclasses import replace

import pytest

from inertia.cli.project_loading import _build_project_from_bytes
from inertia.ir import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from inertia.ir.core import IRCallOutputProvenance8616
from inertia.semantics.call_output_contracts import (
    CallOutputFact8616,
    CallOutputShape8616,
    CallOutputVerdict8616,
)
from inertia.semantics.call_outputs import materialize_call_outputs_8616
from inertia.semantics.call_register_role_contracts import (
    TRACKED_REGISTER_DOMAIN_NAMES_8616,
    CallRegisterDomainBits8616,
    CallRegisterRoleCoverage8616,
    CallRegisterRoleEvidence8616,
    CallRegisterRoleFailure8616,
    CallRegisterRoleKind8616,
    CallRegisterRolesArtifact8616,
    CallRegisterRolesFact8616,
    CallRegisterRoleStats8616,
)
from inertia.semantics.call_register_roles import (
    build_call_register_roles_8616,
    build_callsite_register_role_fact_8616,
)
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.register_source_block_inventory import (
    collect_register_source_block_inventory_8616,
)

KIND = CallRegisterRoleKind8616
COVERAGE = CallRegisterRoleCoverage8616
FAILURE = CallRegisterRoleFailure8616


pytestmark = pytest.mark.decompiler

def _domain_mask(evidence, name: str) -> tuple[int, int]:
    entry = evidence.domain_bits(name)
    assert entry is not None
    return entry.known_bits, entry.role_bits


def _project(code: bytes):
    return _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)


def _caller_function(project):
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    return cfg.kb.functions[0x1000]


def test_domain_bits_reject_role_bits_outside_decided_mask() -> None:
    """A role bit on undecided coverage is contradictory evidence."""
    with pytest.raises(ValueError):
        CallRegisterDomainBits8616("AX", 0x00FF, 0xFF00)
    with pytest.raises(ValueError):
        CallRegisterDomainBits8616("EAX", 0xFFFF, 0)
    with pytest.raises(ValueError):
        CallRegisterDomainBits8616("AX", -1, 0)


def test_roles_fact_requires_one_evidence_per_kind() -> None:
    """The fact must carry exactly the four ordered role evidences."""
    refused = build_callsite_register_role_fact_8616(None, callsite_addr=None)
    fact = CallRegisterRolesFact8616(
        0x1000, 2, 0x1004, 0x1010, 0x1007,
        refused.roles,
        (),
    )
    assert fact.role(KIND.MAY_CLOBBER).coverage is COVERAGE.UNKNOWN_REFUSE
    with pytest.raises(ValueError):
        CallRegisterRolesFact8616(
            0x1000, 2, 0x1004, 0x1010, 0x1007,
            fact.roles[:3],
            (),
        )


def test_refused_role_reports_no_positive_classification() -> None:
    """An all-refused role keeps classified and materialized at zero."""
    fact = build_callsite_register_role_fact_8616(None, callsite_addr=0x1004)
    for evidence in fact.roles:
        if evidence.coverage is COVERAGE.UNKNOWN_REFUSE:
            assert evidence.classified_fact_count == 0
            assert evidence.materialized_count == 0
            assert evidence.failure_count == 1
            assert evidence.failures
    assert fact.role(KIND.MAY_CLOBBER).coverage is COVERAGE.UNKNOWN_REFUSE
    assert fact.role(KIND.CALLER_DEAD).coverage is COVERAGE.UNKNOWN_REFUSE
    assert fact.role(KIND.RESULT).coverage is COVERAGE.UNKNOWN_REFUSE


def test_one_block_leaf_callee_proves_distinct_roles() -> None:
    """A binary leaf callee keeps independent input and clobber masks."""
    caller = bytes.fromhex("56 be 92 00 e8 02 00 56 c3 c3")
    project = _project(caller)

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x1009,
    )

    clobber = fact.role(KIND.MAY_CLOBBER)
    assert clobber.coverage is COVERAGE.COMPLETE
    assert _domain_mask(clobber, "SI") == (0xFFFF, 0)
    assert _domain_mask(clobber, "AX") == (0xFFFF, 0)
    assert _domain_mask(clobber, "SP") == (0xFFFF, 0xFFFF)


def test_multi_block_callee_proves_no_write_and_ax_input() -> None:
    """A real multi-block callee proves complete coverage and joins reads."""
    caller = bytes.fromhex("56 be 92 00 e8 09 00 56 c3")
    pad = b"\x90" * (0x1010 - 0x1000 - len(caller))
    callee = bytes.fromhex("85 c0 74 01 90 c3")  # test ax,ax; jz; nop; ret
    project = _project(caller + pad + callee)

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x1010,
    )

    clobber = fact.role(KIND.MAY_CLOBBER)
    assert clobber.coverage is COVERAGE.COMPLETE
    assert _domain_mask(clobber, "SI") == (0xFFFF, 0)
    assert _domain_mask(clobber, "SP") == (0xFFFF, 0xFFFF)
    input_role = fact.role(KIND.INPUT)
    assert input_role.coverage is COVERAGE.COMPLETE
    assert _domain_mask(input_role, "AX") == (0xFFFF, 0xFFFF)
    assert _domain_mask(input_role, "SP") == (0xFFFF, 0xFFFF)
    assert _domain_mask(input_role, "SI") == (0xFFFF, 0)
    assert input_role.witnesses


def test_al_write_invalidates_ax_and_al_but_not_ah() -> None:
    """Subregister overlap stays coherent across a callee byte write."""
    caller = bytes.fromhex("b4 92 e8 0b 00 88 e1 c3")
    pad = b"\x90" * (0x1010 - 0x1000 - len(caller))
    callee = bytes.fromhex("b0 07 c3")  # mov al, 7; ret
    project = _project(caller + pad + callee)

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1002, target_addr=0x1010,
    )

    clobber = fact.role(KIND.MAY_CLOBBER)
    assert clobber.coverage is COVERAGE.COMPLETE
    assert _domain_mask(clobber, "AX") == (0xFFFF, 0x00FF)


def test_zero_idiom_clobbers_without_being_an_input() -> None:
    """xor si,si consumes no incoming SI but still spoils the register."""
    caller = bytes.fromhex("56 be 92 00 e8 02 00 56 c3")
    callee = bytes.fromhex("31 f6 c3")  # xor si,si; ret
    project = _project(caller + callee)

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x1009,
    )

    clobber = fact.role(KIND.MAY_CLOBBER)
    assert clobber.coverage is COVERAGE.COMPLETE
    assert _domain_mask(clobber, "SI") == (0xFFFF, 0xFFFF)
    input_role = fact.role(KIND.INPUT)
    assert _domain_mask(input_role, "SI") == (0xFFFF, 0)


def test_callee_read_before_write_marks_input() -> None:
    """add si,ax reads the incoming SI value before overwriting it."""
    caller = bytes.fromhex("56 be 92 00 e8 02 00 56 c3")
    callee = bytes.fromhex("01 c6 c3")  # add si,ax; ret
    project = _project(caller + callee)

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x1009,
    )

    input_role = fact.role(KIND.INPUT)
    assert input_role.coverage is COVERAGE.COMPLETE
    assert _domain_mask(input_role, "SI") == (0xFFFF, 0xFFFF)
    assert _domain_mask(input_role, "AX") == (0xFFFF, 0xFFFF)
    assert _domain_mask(fact.role(KIND.MAY_CLOBBER), "SI") == (0xFFFF, 0xFFFF)


def test_nested_call_keeps_partial_coverage() -> None:
    """A nested unknown call never silently proves absence of effects."""
    caller = bytes.fromhex("56 be 92 00 e8 02 00 56 c3")
    callee = bytes.fromhex("e8 01 00 c3 c3")  # call 0x100d; ret; ret
    project = _project(caller + callee)

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x1009,
    )

    clobber = fact.role(KIND.MAY_CLOBBER)
    assert clobber.coverage is COVERAGE.PARTIAL
    assert FAILURE.CALLEE_TRANSFER_UNSUPPORTED in clobber.failures
    assert _domain_mask(clobber, "SI") == (0xFFFF, 0xFFFF)


def test_loop_in_callee_converges_and_preserves_disjoint_register() -> None:
    """A bounded callee loop converges; untouched registers stay clean."""
    caller = bytes.fromhex("56 be 92 00 e8 02 00 56 c3")
    # callee: xor cx,cx; inc cx; cmp cx,3; jne -6 -> inc; ret
    callee = bytes.fromhex("31 c9 41 83 f9 03 75 fa c3")
    project = _project(caller + callee)

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x1009,
    )

    clobber = fact.role(KIND.MAY_CLOBBER)
    assert clobber.coverage is COVERAGE.COMPLETE
    assert _domain_mask(clobber, "CX") == (0xFFFF, 0xFFFF)
    assert _domain_mask(clobber, "SI") == (0xFFFF, 0)


def test_out_of_image_target_refuses_callee_roles() -> None:
    """An undecodable target retains a typed refusal, not empty masks."""
    caller = bytes.fromhex("56 be 92 00 e8 02 00 56 c3 c3")
    project = _project(caller)

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x2000,
    )

    clobber = fact.role(KIND.MAY_CLOBBER)
    assert clobber.coverage is COVERAGE.UNKNOWN_REFUSE
    assert clobber.classified_fact_count == 0
    assert FAILURE.CALLEE_EVIDENCE_MISSING in clobber.failures


def test_synthetic_stub_consumes_only_registered_abi_views() -> None:
    """The synthetic ABI proves preserved/clobbered views, inputs stay refused."""
    from inertia.frontend.x86_16.synthetic_call_stub_evidence import (
        record_synthetic_call_stubs_8616,
    )

    caller = bytes.fromhex(
        "56 be 92 00 e8 09 00 56 e8 06 00 83 c4 02 5e c3 c3 c3"
    )
    project = _project(caller)
    record_synthetic_call_stubs_8616(project, frozenset({0x1010, 0x1011}))

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x1010,
    )

    clobber = fact.role(KIND.MAY_CLOBBER)
    assert clobber.coverage is COVERAGE.PARTIAL
    assert _domain_mask(clobber, "SI") == (0xFFFF, 0)
    assert _domain_mask(clobber, "AX") == (0xFFFF, 0xFFFF)
    assert _domain_mask(clobber, "SP") == (0, 0)
    assert fact.role(KIND.INPUT).coverage is COVERAGE.UNKNOWN_REFUSE


def _ir_artifact() -> IRFunctionArtifact:
    return IRFunctionArtifact(
        0x1000,
        (
            IRBlock(
                0x1000,
                (
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=0x2000, size=2),),
                        addr=0x1003,
                    ),
                ),
                successor_addrs=(0x1006,),
            ),
            IRBlock(
                0x1006,
                (
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.TMP, name="t0", size=2, source_tmp=0),
                        (IRValue(MemSpace.REG, name="ax", size=2),),
                        size=2,
                        addr=0x1006,
                    ),
                ),
            ),
        ),
    )


def _summary(**kwargs) -> CallsiteSummary8616:
    values = {
        "callsite_addr": 0x1003,
        "target_addr": 0x2000,
        "return_addr": 0x1006,
        "kind": "direct_near",
        "arg_count": 0,
        "arg_widths": (),
        "stack_cleanup": 0,
        "return_register": "ax",
        "return_used": True,
        "return_shape": "dx_ax",
    }
    values.update(kwargs)
    return CallsiteSummary8616(**values)


def test_result_role_binds_only_to_the_exact_output_fact() -> None:
    """Proven DX:AX outputs become result bits; no callee evidence is needed."""
    artifact = _ir_artifact()
    summaries = {0x1003: _summary()}
    outputs = materialize_call_outputs_8616(artifact, summaries)

    roles = build_call_register_roles_8616(
        None, None, outputs.function, summaries, outputs,
    )

    assert isinstance(roles, CallRegisterRolesArtifact8616)
    fact = roles.facts[0]
    result = fact.role(KIND.RESULT)
    assert result.coverage is COVERAGE.COMPLETE
    assert _domain_mask(result, "AX") == (0xFFFF, 0xFFFF)
    assert _domain_mask(result, "DX") == (0xFFFF, 0xFFFF)
    assert _domain_mask(result, "SI") == (0xFFFF, 0)
    assert {r.register for r in fact.results} == {"ax", "dx"}
    assert roles.stats.closed


def test_result_role_refuses_mismatched_identity() -> None:
    """An output fact bound to a different call never becomes a result."""
    foreign_fact = CallOutputFact8616(
        0x9999,
        0,
        0x9999,
        0x2000,
        0x999C,
        CallOutputShape8616.AX,
        (),
        CallOutputVerdict8616.PROVEN,
        None,
    )
    fact = build_callsite_register_role_fact_8616(
        None,
        callsite_addr=0x1003,
        call_block_addr=0x1000,
        call_instr_index=0,
        target_addr=0x2000,
        return_block_addr=0x1006,
        output_fact=foreign_fact,
    )

    result = fact.role(KIND.RESULT)
    assert result.coverage is COVERAGE.UNKNOWN_REFUSE
    assert FAILURE.OUTPUT_FACT_MISMATCH in result.failures
    assert fact.results == ()


def test_result_role_refuses_unproven_output_fact() -> None:
    artifact = _ir_artifact()
    summaries = {0x1003: _summary(return_shape=None)}
    outputs = materialize_call_outputs_8616(artifact, summaries)

    roles = build_call_register_roles_8616(
        None, None, outputs.function, summaries, outputs,
    )

    result = roles.facts[0].role(KIND.RESULT)
    assert result.coverage is COVERAGE.UNKNOWN_REFUSE
    assert FAILURE.OUTPUT_FACT_REFUSED in result.failures
    assert roles.facts[0].results == ()


def test_result_role_refuses_unsupported_wide_view() -> None:
    """A 32-bit output view refuses instead of truncating into AX."""
    artifact = _ir_artifact()
    outputs = materialize_call_outputs_8616(artifact, {0x1003: _summary()})
    wide = outputs.facts[0]
    wide_output = IRValue(
        MemSpace.REG,
        name="eax",
        size=4,
        call_output=IRCallOutputProvenance8616(
            callsite_addr=0x1003,
            target_addr=0x2000,
            shape=CallOutputShape8616.AX,
        ),
    )
    wide_fact = CallOutputFact8616(
        wide.call_block_addr,
        wide.call_instr_index,
        wide.callsite_addr,
        wide.target_addr,
        wide.return_block_addr,
        wide.shape,
        (wide_output,),
        wide.verdict,
        None,
    )
    fact = build_callsite_register_role_fact_8616(
        None,
        callsite_addr=0x1003,
        call_block_addr=0x1000,
        call_instr_index=0,
        target_addr=0x2000,
        return_block_addr=0x1006,
        output_fact=wide_fact,
    )

    result = fact.role(KIND.RESULT)
    assert result.coverage is COVERAGE.UNKNOWN_REFUSE
    assert FAILURE.OUTPUT_VIEW_UNSUPPORTED in result.failures
    assert fact.results == ()


def test_caller_dead_bits_require_every_continuation_to_overwrite() -> None:
    """BX killed before any read is dead; AX exposed at RET stays live."""
    caller = bytes.fromhex("e8 0d 00 bb 01 00 c3")  # call; mov bx,1; ret
    pad = b"\x90" * (0x1010 - 0x1000 - len(caller))
    callee = bytes.fromhex("c3")
    project = _project(caller + pad + callee)
    function = _caller_function(project)
    inventory = collect_register_source_block_inventory_8616(function)

    fact = build_callsite_register_role_fact_8616(
        project,
        callsite_addr=0x1000,
        target_addr=0x1010,
        caller_inventory=inventory,
    )

    dead = fact.role(KIND.CALLER_DEAD)
    assert dead.coverage is COVERAGE.COMPLETE
    assert _domain_mask(dead, "BX") == (0xFFFF, 0xFFFF)
    assert _domain_mask(dead, "AX") == (0xFFFF, 0)


def test_caller_dead_refuses_when_value_is_read_first() -> None:
    """A continuation that reads the register can never prove it dead."""
    caller = bytes.fromhex("e8 0d 00 50 c3")  # call; push ax; ret
    pad = b"\x90" * (0x1010 - 0x1000 - len(caller))
    callee = bytes.fromhex("c3")
    project = _project(caller + pad + callee)
    inventory = collect_register_source_block_inventory_8616(
        _caller_function(project)
    )

    fact = build_callsite_register_role_fact_8616(
        project,
        callsite_addr=0x1000,
        target_addr=0x1010,
        caller_inventory=inventory,
    )

    dead = fact.role(KIND.CALLER_DEAD)
    assert dead.coverage is COVERAGE.COMPLETE
    assert _domain_mask(dead, "AX") == (0xFFFF, 0)
    assert _domain_mask(dead, "BX") == (0xFFFF, 0)


def test_caller_dead_join_reads_keep_return_value_live() -> None:
    """A join that reads the register keeps it live even past other writes."""
    caller = bytes.fromhex(
        "e8 10 00 "  # call 0x1013
        "85 c0 "     # test ax,ax
        "74 03 "     # jz 0x100a
        "bb 01 00 "  # mov bx,1
        "89 da "     # mov dx,bx      (0x100a; joins, reads bx)
        "c3"         # ret            (0x100c)
    )
    pad = b"\x90" * (0x1013 - 0x1000 - len(caller))
    callee = bytes.fromhex("c3")
    project = _project(caller + pad + callee)
    inventory = collect_register_source_block_inventory_8616(
        _caller_function(project)
    )

    fact = build_callsite_register_role_fact_8616(
        project,
        callsite_addr=0x1000,
        target_addr=0x1013,
        caller_inventory=inventory,
    )

    dead = fact.role(KIND.CALLER_DEAD)
    assert dead.coverage is COVERAGE.COMPLETE
    # DX is overwritten at the join before any read; BX is read there.
    assert _domain_mask(dead, "DX") == (0xFFFF, 0xFFFF)
    assert _domain_mask(dead, "BX") == (0xFFFF, 0)
    assert _domain_mask(dead, "AX") == (0xFFFF, 0)


def test_caller_dead_proves_bits_killed_on_both_joined_paths() -> None:
    """BX overwritten on both arms of a join is caller-dead."""
    caller = bytes.fromhex(
        "e8 11 00 "  # call 0x1014
        "85 c0 "     # test ax,ax
        "74 03 "     # jz 0x100a
        "bb 01 00 "  # mov bx,1
        "bb 02 00 "  # mov bx,2       (0x100a; joins)
        "c3"         # ret            (0x100d)
    )
    pad = b"\x90" * (0x1014 - 0x1000 - len(caller))
    callee = bytes.fromhex("c3")
    project = _project(caller + pad + callee)
    inventory = collect_register_source_block_inventory_8616(
        _caller_function(project)
    )

    fact = build_callsite_register_role_fact_8616(
        project,
        callsite_addr=0x1000,
        target_addr=0x1014,
        caller_inventory=inventory,
    )

    dead = fact.role(KIND.CALLER_DEAD)
    assert dead.coverage is COVERAGE.COMPLETE
    assert _domain_mask(dead, "BX") == (0xFFFF, 0xFFFF)
    assert _domain_mask(dead, "AX") == (0xFFFF, 0)


def test_caller_dead_needs_caller_evidence() -> None:
    """No caller inventory keeps the caller-dead role a typed refusal."""
    caller = bytes.fromhex("56 be 92 00 e8 02 00 56 c3 c3")
    project = _project(caller)

    fact = build_callsite_register_role_fact_8616(
        project, callsite_addr=0x1004, target_addr=0x1009,
    )

    dead = fact.role(KIND.CALLER_DEAD)
    assert dead.coverage is COVERAGE.UNKNOWN_REFUSE
    assert FAILURE.CALLER_EVIDENCE_MISSING in dead.failures


def test_artifact_attaches_roles_to_call_outputs() -> None:
    """build_semantic_function_ssa path keeps roles coherent on outputs."""
    from dataclasses import replace

    artifact = _ir_artifact()
    summaries = {0x1003: _summary()}
    outputs = materialize_call_outputs_8616(artifact, summaries)
    roles = build_call_register_roles_8616(
        None, None, outputs.function, summaries, outputs,
    )
    attached = replace(outputs, register_roles=roles)

    assert outputs.register_roles is None
    assert attached.complete
    assert attached.register_roles is roles
    assert attached.to_dict()["register_roles"]["facts"][0]["callsite_addr"] == 0x1003

    foreign = replace(roles, function_addr=0x7777)
    mismatched = replace(outputs, register_roles=foreign)
    assert not mismatched.complete


def test_refused_evidence_cannot_publish_decided_bits() -> None:
    """UNKNOWN_REFUSE carrying a decided mask is contradictory evidence."""
    domain_count = len(TRACKED_REGISTER_DOMAIN_NAMES_8616)
    with pytest.raises(ValueError):
        CallRegisterRoleEvidence8616(
            KIND.INPUT,
            COVERAGE.UNKNOWN_REFUSE,
            (CallRegisterDomainBits8616("AX", 0xFFFF, 0),),
            (),
            (FAILURE.CALLEE_EVIDENCE_MISSING,),
            domain_count,
            domain_count,
            0,
            0,
            domain_count,
        )


def test_complete_evidence_cannot_retain_failures() -> None:
    """COMPLETE coverage cannot carry unresolved failure reasons."""
    domain_count = len(TRACKED_REGISTER_DOMAIN_NAMES_8616)
    with pytest.raises(ValueError):
        CallRegisterRoleEvidence8616(
            KIND.INPUT,
            COVERAGE.COMPLETE,
            tuple(
                CallRegisterDomainBits8616(name, 0xFFFF, 0)
                for name in TRACKED_REGISTER_DOMAIN_NAMES_8616
            ),
            (),
            (FAILURE.CALLEE_EVIDENCE_MISSING,),
            domain_count,
            domain_count,
            domain_count,
            domain_count,
            0,
        )


def test_partial_evidence_must_retain_typed_failures() -> None:
    """PARTIAL coverage without failure reasons is contradictory."""
    domain_count = len(TRACKED_REGISTER_DOMAIN_NAMES_8616)
    with pytest.raises(ValueError):
        CallRegisterRoleEvidence8616(
            KIND.INPUT,
            COVERAGE.PARTIAL,
            (CallRegisterDomainBits8616("AX", 0xFFFF, 0),),
            (),
            (),
            domain_count,
            domain_count,
            1,
            1,
            domain_count - 1,
        )


def test_artifact_stats_must_match_retained_fact_census() -> None:
    """Zero stats over refused facts is not an authentic artifact."""
    refused = build_callsite_register_role_fact_8616(None, callsite_addr=None)
    with pytest.raises(ValueError):
        CallRegisterRolesArtifact8616(
            0x1000,
            (refused,),
            CallRegisterRoleStats8616(),
        )


def _proven_ax_fact() -> CallOutputFact8616:
    origin = IRCallOutputProvenance8616(0x1003, 0x2000, CallOutputShape8616.AX)
    value = IRValue(MemSpace.REG, name="ax", size=2, call_output=origin)
    return CallOutputFact8616(
        0x1000,
        0,
        0x1003,
        0x2000,
        0x1006,
        CallOutputShape8616.AX,
        (value,),
        CallOutputVerdict8616.PROVEN,
        None,
    )


def _result_coverage(output_fact: CallOutputFact8616):
    fact = build_callsite_register_role_fact_8616(
        None,
        callsite_addr=0x1003,
        call_block_addr=0x1000,
        call_instr_index=0,
        target_addr=0x2000,
        return_block_addr=0x1006,
        output_fact=output_fact,
    )
    return fact


def test_result_role_refuses_foreign_inner_provenance() -> None:
    """An output value produced by a different call cannot claim the result."""
    base = _proven_ax_fact()
    foreign = replace(
        base,
        outputs=(
            replace(
                base.outputs[0],
                call_output=replace(
                    base.outputs[0].call_output, callsite_addr=0x9999
                ),
            ),
        ),
    )
    fact = _result_coverage(foreign)
    result = fact.role(KIND.RESULT)
    assert result.coverage is COVERAGE.UNKNOWN_REFUSE
    assert fact.results == ()


def test_result_role_refuses_wrong_output_width() -> None:
    """A one-byte AX value cannot stand in for the 16-bit result view."""
    base = _proven_ax_fact()
    narrow = replace(base, outputs=(replace(base.outputs[0], size=1),))
    fact = _result_coverage(narrow)
    result = fact.role(KIND.RESULT)
    assert result.coverage is COVERAGE.UNKNOWN_REFUSE
    assert fact.results == ()


def test_result_role_refuses_shape_cardinality_mismatch() -> None:
    """A DX:AX shape with only an AX value is contradictory evidence."""
    base = _proven_ax_fact()
    pair = replace(base, shape=CallOutputShape8616.DX_AX)
    fact = _result_coverage(pair)
    result = fact.role(KIND.RESULT)
    assert result.coverage is COVERAGE.UNKNOWN_REFUSE
    assert fact.results == ()


def test_result_role_accepts_valid_inner_provenance() -> None:
    """The canonical proven AX fact still produces its result role."""
    fact = _result_coverage(_proven_ax_fact())
    result = fact.role(KIND.RESULT)
    assert result.coverage is COVERAGE.COMPLETE
    assert [entry.register for entry in fact.results] == ["ax"]
    assert fact.results[0].shape is CallOutputShape8616.AX


def test_role_artifact_cannot_move_between_output_snapshots() -> None:
    """Roles for one output census are not coherent on another snapshot."""
    artifact = _ir_artifact()
    old_summary = _summary()
    assert old_summary.target_addr is not None
    new_target = old_summary.target_addr + 0x1000
    new_blocks = []
    for block in artifact.blocks:
        instructions = []
        for instruction in block.instrs:
            if instruction.op == "CALL":
                operand = instruction.args[0]
                assert isinstance(operand, IRValue)
                instruction = replace(
                    instruction,
                    args=(replace(operand, const=new_target),),
                )
            instructions.append(instruction)
        new_blocks.append(replace(block, instrs=tuple(instructions)))
    new_source = replace(artifact, blocks=tuple(new_blocks))
    new_summary = replace(old_summary, target_addr=new_target)
    old_outputs = materialize_call_outputs_8616(
        artifact, {old_summary.callsite_addr: old_summary}
    )
    new_outputs = materialize_call_outputs_8616(
        new_source, {new_summary.callsite_addr: new_summary}
    )
    assert old_outputs.complete and new_outputs.complete

    old_roles = build_call_register_roles_8616(
        None, None, old_outputs.function, {old_summary.callsite_addr: old_summary}, old_outputs,
    )
    borrowed = replace(new_outputs, register_roles=old_roles)
    assert old_roles.facts[0].target_addr != new_outputs.facts[0].target_addr
    assert not borrowed.complete


def test_output_prefix_insertions_keep_source_call_indexes() -> None:
    """CALL origin indexes bind to the source snapshot, not the enriched IR."""
    blocks = (
        *(
            IRBlock(
                address,
                (
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=target, size=4),),
                        addr=address,
                    ),
                ),
                successor_addrs=(address + 3,),
            )
            for address, target in ((0x1000, 0x2000), (0x1003, 0x2100))
        ),
        IRBlock(0x1006, (IRInstr("RET", None, (), addr=0x1006),)),
    )
    source = IRFunctionArtifact(0x1000, blocks)
    summaries = {
        address: CallsiteSummary8616(
            callsite_addr=address,
            target_addr=target,
            return_addr=address + 3,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_shape="ax",
        )
        for address, target in ((0x1000, 0x2000), (0x1003, 0x2100))
    }
    outputs = materialize_call_outputs_8616(source, summaries)
    assert outputs.complete

    roles = build_call_register_roles_8616(
        None, None, outputs.function, summaries, outputs,
    )
    assert len(roles.facts) == 2
    for fact in roles.facts:
        assert [entry.register for entry in fact.results] == ["ax"]
    assert roles.authenticates_output_facts(outputs.facts)


def test_pipeline_retains_result_after_real_prefix_insertion() -> None:
    """Two real CALLs keep proven results through build_semantic_function_ssa."""
    from inertia.semantics.call_stack_effect_pipeline import (
        build_semantic_function_ssa_8616,
    )

    caller = bytes.fromhex("e8 0f 00 89 c3 e8 0a 00 89 c3 c3")
    pad = b"\x90" * (0x1012 - 0x1000 - len(caller))
    callee = bytes.fromhex("85 c0 74 01 90 c3")
    project = _project(caller + pad + callee)
    function = _caller_function(project)

    _effects, outputs, _ssa = build_semantic_function_ssa_8616(project, function)
    roles = outputs.register_roles
    assert roles is not None
    proven = [fact for fact in outputs.facts if fact.shape is not None]
    assert len(proven) == 2
    role_by_callsite = {fact.callsite_addr: fact for fact in roles.facts}
    for output_fact in proven:
        role_fact = role_by_callsite[output_fact.callsite_addr]
        assert role_fact.call_instr_index == output_fact.call_instr_index
        assert [entry.register for entry in role_fact.results] == ["ax"]
    assert roles.authenticates_output_facts(outputs.facts)


def test_partial_role_coverage_is_not_artifact_complete() -> None:
    """Coherent partial masks keep the bound snapshot usable but not complete."""
    from inertia.semantics.call_register_roles import _role_evidence_8616

    source = _ir_artifact()
    summary = _summary(return_used=False, return_shape=None)
    outputs = materialize_call_outputs_8616(source, {summary.callsite_addr: summary})
    assert outputs.complete
    call = outputs.facts[0]
    names = TRACKED_REGISTER_DOMAIN_NAMES_8616
    roles = []
    for kind in KIND:
        partial = kind is KIND.INPUT
        known = [
            0xFF if partial and name in {"AX", "BX", "CX", "DX"} else 0xFFFF
            for name in names
        ]
        roles.append(
            _role_evidence_8616(
                kind,
                complete=not partial,
                known=known,
                role=known if partial else [0] * len(names),
                witnesses={0x2000},
                failures=(FAILURE.CALLEE_COVERAGE_PARTIAL,) if partial else (),
            )
        )
    stats = CallRegisterRoleStats8616(
        raw_fact_count=sum(role.raw_fact_count for role in roles),
        normalized_fact_count=sum(role.normalized_fact_count for role in roles),
        classified_fact_count=sum(role.classified_fact_count for role in roles),
        materialized_count=sum(role.materialized_count for role in roles),
        failure_count=sum(role.failure_count for role in roles),
    )
    fact = CallRegisterRolesFact8616(
        call.call_block_addr,
        call.call_instr_index,
        call.callsite_addr,
        call.target_addr,
        call.return_block_addr,
        tuple(roles),
        (),
    )
    artifact = CallRegisterRolesArtifact8616(
        source.function_addr,
        (fact,),
        stats,
        output_facts=outputs.facts,
        source_function=source,
        output_function=outputs.function,
    )
    bound = replace(outputs, register_roles=artifact)

    assert roles[0].coverage is COVERAGE.PARTIAL
    assert artifact.stats.complete
    assert not artifact.complete
    assert bound.complete


def test_complete_role_coverage_marks_artifact_complete() -> None:
    """A fully decided census still reports the artifact complete."""
    from inertia.semantics.call_register_roles import _role_evidence_8616

    source = _ir_artifact()
    summary = _summary(return_used=False, return_shape=None)
    outputs = materialize_call_outputs_8616(source, {summary.callsite_addr: summary})
    call = outputs.facts[0]
    names = TRACKED_REGISTER_DOMAIN_NAMES_8616
    roles = tuple(
        _role_evidence_8616(
            kind,
            complete=True,
            known=[0xFFFF] * len(names),
            role=[0] * len(names),
            witnesses={0x2000},
            failures=(),
        )
        for kind in KIND
    )
    stats = CallRegisterRoleStats8616(
        raw_fact_count=sum(role.raw_fact_count for role in roles),
        normalized_fact_count=sum(role.normalized_fact_count for role in roles),
        classified_fact_count=sum(role.classified_fact_count for role in roles),
        materialized_count=sum(role.materialized_count for role in roles),
        failure_count=sum(role.failure_count for role in roles),
    )
    fact = CallRegisterRolesFact8616(
        call.call_block_addr,
        call.call_instr_index,
        call.callsite_addr,
        call.target_addr,
        call.return_block_addr,
        roles,
        (),
    )
    artifact = CallRegisterRolesArtifact8616(
        source.function_addr,
        (fact,),
        stats,
        output_facts=outputs.facts,
        source_function=source,
        output_function=outputs.function,
    )
    bound = replace(outputs, register_roles=artifact)

    assert artifact.complete
    assert bound.complete


def test_caller_dead_never_certifies_dead_bits_under_missing_branch() -> None:
    """A removed read branch cannot leave BX certified dead."""
    from inertia.semantics.call_register_roles import (
        build_callsite_register_role_fact_8616 as _build_fact,
    )

    # call; test ax,ax; jz read; mov bx,1; jmp return; read: push bx; return: ret
    caller = bytes.fromhex("e8 1d 00 85 c0 74 05 bb 01 00 eb 01 53 c3")
    project = _project(caller + b"\x90" * (0x20 - len(caller)) + b"\xc3")
    inventory = collect_register_source_block_inventory_8616(
        _caller_function(project)
    )
    assert inventory.complete
    full = _build_fact(
        project,
        callsite_addr=0x1000,
        target_addr=0x1020,
        caller_inventory=inventory,
    )
    blocks = tuple(
        block for block in inventory.blocks if block.block_addr != 0x100C
    )
    assert len(blocks) == len(inventory.blocks) - 1
    partial = replace(
        inventory,
        blocks=blocks,
        materialized_count=len(blocks),
        failure_count=1,
    )
    gap = _build_fact(
        project,
        callsite_addr=0x1000,
        target_addr=0x1020,
        caller_inventory=partial,
    )

    before = full.role(KIND.CALLER_DEAD).domain_bits("BX")
    after = gap.role(KIND.CALLER_DEAD).domain_bits("BX")
    assert before is not None and before.role_bits == 0
    assert after is not None
    assert gap.role(KIND.CALLER_DEAD).coverage is COVERAGE.PARTIAL
    assert after.role_bits == 0
    assert after.known_bits == 0

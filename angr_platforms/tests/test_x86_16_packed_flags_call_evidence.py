"""Prune flag cycles only when binary callee evidence closes implicit reads."""

from copy import copy
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import status_flag_lift_context
from angr_platforms.X86_16.ir.status_flag_lift_codec import (
    decode_status_flag_lift_artifact_8616,
    encode_status_flag_lift_artifact_8616,
)
from angr_platforms.X86_16.ir.status_flag_lift_context import StatusFlagLiftArtifact8616
from angr_platforms.X86_16.lowering.packed_flags_liveness import prune_unobserved_flag_cycles_8616
from angr_platforms.X86_16.semantics.status_flag_contracts import StatusFlag8616, StatusFlagEffect8616
from test_x86_16_packed_flags_state import _Codegen


def test_lift_artifact_retains_callee_effects_through_persistence():
    effects = ((0x200, StatusFlagEffect8616(reads=StatusFlag8616.CARRY)),)
    artifact = StatusFlagLiftArtifact8616(0x100, (), frozenset(), callee_effects=effects)
    assert decode_status_flag_lift_artifact_8616(encode_status_flag_lift_artifact_8616(artifact)) == artifact


@pytest.mark.parametrize("payload", [
    None, "unproven", [{}],
    [{"target": True, "reads": 0, "overwrites": 0}],
    [{"target": 0x200, "reads": 1 << 20, "overwrites": 0}],
    [{"target": 0x200, "reads": 0, "overwrites": 0}] * 2,
])
def test_malformed_callee_publication_never_proves_a_call(payload):
    artifact = StatusFlagLiftArtifact8616(0x100, (), frozenset())
    encoded = encode_status_flag_lift_artifact_8616(artifact)
    encoded["callee_effects"] = payload
    restored = decode_status_flag_lift_artifact_8616(encoded)
    assert restored is not None
    assert restored.callee_effects == ()


def test_narrower_lift_keeps_preservation_sites_but_refreshes_callee_uncertainty():
    previous = StatusFlagLiftArtifact8616(
        0x100, (), frozenset({0x110, 0x120}),
        callee_effects=((0x200, StatusFlagEffect8616()),),
    )
    function = SimpleNamespace(info={
        "status_flag_lift_artifact_8616": encode_status_flag_lift_artifact_8616(previous),
    })
    session = status_flag_lift_context.StatusFlagLiftSession8616(
        0x100, (), frozenset({0x110}),
        callee_effects=((0x200, StatusFlagEffect8616(reads=StatusFlag8616.CARRY)),),
    )
    status_flag_lift_context._publish_stats_8616(function, session)
    restored = status_flag_lift_context.published_status_flag_lift_artifact_8616(function)
    assert restored.packed_preservation_addresses == previous.packed_preservation_addresses
    assert restored.callee_effects == session.callee_effects


@pytest.mark.parametrize("consumer", ["none", "argument", "return"])
@pytest.mark.parametrize("call_kind", ["proven", "carry", "missing", "indirect", "conflict"])
def test_flag_component_through_temporary_respects_call_and_value_consumers(consumer, call_kind):
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    word = SimTypeShort(False)
    flags = c.CVariable(SimRegisterVariable(36, 2, ident="flags", region=0x100),
                        variable_type=word, codegen=codegen)
    temporary = c.CVariable(SimRegisterVariable(4096, 2, ident="carrier", region=0x100),
                            variable_type=word, codegen=codegen)
    other = c.CVariable(SimRegisterVariable(4098, 2, ident="unrelated", region=0x100),
                        variable_type=word, codegen=codegen)
    constant = c.CConstant(0xFFFE, word, codegen=codegen)
    produce = c.CAssignment(temporary, c.CBinaryOp("And", copy(flags), constant, codegen=codegen),
                            codegen=codegen)
    update = c.CAssignment(flags, copy(temporary), codegen=codegen)
    unrelated = c.CAssignment(other, constant, codegen=codegen)
    target = None if call_kind == "indirect" else SimpleNamespace(addr=0x200)
    call = c.CFunctionCall("arbitrary_label", target,
                          [copy(temporary)] if consumer == "argument" else [], codegen=codegen,
                          tags={"inertia_target_addr_8616": 0x300 if call_kind == "conflict" else 0x200})
    result = c.CReturn(copy(temporary) if consumer == "return" else constant, codegen=codegen)
    root = c.CStatements([produce, update, unrelated, call, result], codegen=codegen)
    effects = () if call_kind == "missing" else (
        (0x200, StatusFlagEffect8616(
            reads=StatusFlag8616.CARRY if call_kind == "carry" else StatusFlag8616.NONE,
        )),
    )
    artifact = StatusFlagLiftArtifact8616(0x100, (), frozenset(), callee_effects=effects)

    stats = prune_unobserved_flag_cycles_8616(root, 36, lift_artifact=artifact)

    removed = consumer == "none" and call_kind == "proven"
    assert (produce not in root.statements) is removed
    assert (update not in root.statements) is removed
    assert unrelated in root.statements
    assert call in root.statements
    assert stats.materialized_count == (2 if removed else 0)

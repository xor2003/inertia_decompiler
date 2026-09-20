"""Constant GP effects survive folded address uses without weakening proofs."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.gp_constant_restore import (
    ConstantRestorePublication8616,
    _constant_write_matches,
    publish_constant_gp_restore_8616,
)
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_assignment_8616
from angr_platforms.X86_16.lowering.gp_stack_restore_identity import _runtime_restore_word_8616
from angr_platforms.X86_16.lowering.segment_register_state import runtime_segment_state_cvar_8616
from test_x86_16_gp_stack_restore import _artifact, _Codegen


@pytest.mark.parametrize("value", [0, 0x1234, 0xffff])
@pytest.mark.parametrize("simplified", [False, True])
def test_constant_restore_preserves_register_effect_and_replays(value, simplified):
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    fact = replace(_artifact().facts[0], restore_register="bx", constant_value=value)
    segment = runtime_segment_state_cvar_8616(
        "es", codegen=codegen, variable_type=SimTypeShort(False), function_addr=0x1000,
    )
    sibling = c.CAssignment(segment, c.CConstant(7, SimTypeShort(False), codegen=codegen),
                            codegen=codegen, tags={"ins_addr": fact.restore_instruction_addr})
    root = c.CStatements([sibling], codegen=codegen)
    assert publish_constant_gp_restore_8616(codegen, (root,), fact, 0x1000) is ConstantRestorePublication8616.INSERTED
    assert root.statements[0] is sibling
    assert _runtime_restore_word_8616(root.statements[1], "bx").value == value
    if simplified and value == 0:
        publication = root.statements[1]
        publication.rhs = publication.rhs.lhs
    assert publish_constant_gp_restore_8616(codegen, (root,), fact, 0x1000) is ConstantRestorePublication8616.EXISTING
    assert len(root.statements) == 2


@pytest.mark.parametrize("case", ["unknown", "missing", "ambiguous", "effectful", "wrong_origin", "sibling_call"])
def test_constant_restore_refuses_unproved_placement(case):
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    fact = replace(_artifact().facts[0], constant_value=None if case == "unknown" else 0)
    segment = runtime_segment_state_cvar_8616(
        "es", codegen=codegen, variable_type=SimTypeShort(False), function_addr=0x1000,
    )
    value = (c.CFunctionCall("effect", None, [], codegen=codegen) if case == "effectful"
             else c.CConstant(7, SimTypeShort(False), codegen=codegen))
    sibling = c.CAssignment(segment, value, codegen=codegen,
                            tags={"ins_addr": fact.restore_instruction_addr + (case == "wrong_origin")})
    statements = [] if case == "missing" else [sibling, sibling] if case == "ambiguous" else [sibling]
    if case == "sibling_call":
        statements.append(c.CFunctionCall("effect", None, [], codegen=codegen,
                                          tags={"ins_addr": fact.restore_instruction_addr}))
    root = c.CStatements(list(statements), codegen=codegen)
    assert publish_constant_gp_restore_8616(codegen, (root,), fact, 0x1000) is ConstantRestorePublication8616.REFUSED
    assert root.statements == statements


@pytest.mark.parametrize("register,mask,value,expected", [
    ("bx", 0xffff0000, 0, True),
    ("ax", 0xffff0000, 0, False),
    ("bx", 0xffffff00, 0, False),
    ("bx", 0xffff0000, 1, False),
])
def test_simplified_constant_restore_requires_exact_parent_and_mask(register, mask, value, expected):
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    fact = replace(_artifact().facts[0], restore_register="bx", constant_value=value)
    publication = runtime_gp_state_assignment_8616(
        register, c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen, function_addr=0x1000,
    )
    publication.rhs = c.CBinaryOp("And", publication.lhs,
                                  c.CConstant(mask, publication.lhs.variable_type, codegen=codegen), codegen=codegen)
    assert _constant_write_matches(publication, fact) is expected

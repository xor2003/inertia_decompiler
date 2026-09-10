"""Require complete, instruction-owned byte projections for a saved BP word."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.frame_prologue_carriers import is_exact_push_bp_carrier_8616

_ENTRY = 0x4010


@pytest.mark.parametrize("variant", ["complete", "missing", "wrong_shift", "wrong_slot", "wrong_source", "wrong_instruction", "no_frame", "duplicate", "conflicting", "duplicate_low"])
def test_saved_bp_byte_pair_requires_complete_evidence(variant):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(project=project, next_node_idx=lambda: 1, next_ident=lambda name: name, cstyle_null_cmp=False)

    def constant(value):
        return CConstant(value, SimTypeShort(False), codegen=codegen)

    def register(name, vvar_id):
        offset, width = project.arch.registers[name]
        return CVariable(SimRegisterVariable(offset, width), variable_type=SimTypeShort(False), vvar_id=vvar_id, codegen=codegen)

    def binary(op, lhs, rhs):
        return CBinaryOp(op, lhs, rhs, codegen=codegen)

    source = register("bp", 1)
    low_slot = CVariable(SimStackVariable(-2, 1, base="bp"), variable_type=SimTypeChar(False), codegen=codegen)
    low = CAssignment(low_slot, source, codegen=codegen, tags={"ins_addr": _ENTRY})
    anchor = CVariable(SimStackVariable(0, 1, base="bp"), variable_type=SimTypeChar(False), codegen=codegen)
    reference = CUnaryOp("Reference", anchor, codegen=codegen)
    offset = binary("Sub", reference, constant(2 if variant == "wrong_slot" else 1))
    address = binary("Add", binary("Shl", register("ss", 2), constant(4)), offset)
    from angr.analyses.decompiler.structured_codegen.c import CTypeCast

    pointer = CTypeCast(SimTypeShort(False), SimTypePointer(SimTypeChar(False)), address, codegen=codegen)
    high_slot = CUnaryOp("Dereference", pointer, codegen=codegen)
    high_value = binary("Shr", register("bp", 3) if variant == "wrong_source" else source, constant(7 if variant == "wrong_shift" else 8))
    high = CAssignment(high_slot, high_value, codegen=codegen, tags={"ins_addr": _ENTRY + (variant == "wrong_instruction")})
    statements = [low] if variant == "missing" else [low, high]
    if variant == "duplicate":
        statements.append(CAssignment(high_slot, high_value, codegen=codegen, tags={"ins_addr": _ENTRY}))
    if variant == "conflicting":
        statements.append(CAssignment(high_slot, constant(0), codegen=codegen, tags={"ins_addr": _ENTRY}))
    if variant == "duplicate_low":
        statements.append(CAssignment(low_slot, source, codegen=codegen, tags={"ins_addr": _ENTRY}))
    root = CStatements(statements, codegen=codegen)

    assert is_exact_push_bp_carrier_8616(
        low, root, project, _ENTRY, canonical_frame_proven=variant != "no_frame", codegen=codegen,
    ) is (variant == "complete")
    assert root.statements == statements

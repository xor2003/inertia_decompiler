"""Whole-body sum reconstruction must not erase unrelated storage effects."""

from types import SimpleNamespace

import capstone
import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CFunctionCall, CReturn, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16 import decompiler_postprocess_stage as stage
from test_x86_16_structuring_return_chains import _const, _DummyCodegen

_FUNCTION_ADDR = 0x1000


@pytest.mark.parametrize("extra", [None, "stack", "runtime", "call", "same-offset"])
def test_global_sum_reconstruction_keeps_unconsumed_effects(monkeypatch, extra):
    codegen = _DummyCodegen()
    total = CVariable(SimStackVariable(-2, 2, base="bp"), variable_type=SimTypeShort(False), codegen=codegen)
    index = CVariable(SimStackVariable(-4, 2, base="bp"), variable_type=SimTypeShort(False), codegen=codegen)
    statements = [CAssignment(total, _const(0, codegen), codegen=codegen)]
    if extra:
        variable = (SimMemoryVariable(0x8000, 4) if extra == "runtime"
                    else SimStackVariable(-2 if extra == "same-offset" else -6, 2, base="bp"))
        lhs = CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
        rhs = (CFunctionCall(_const(0x3000, codegen), None, [], codegen=codegen)
               if extra == "call" else _const(7, codegen))
        statements.append(CAssignment(lhs, rhs, codegen=codegen))
    statements.append(CReturn(total, codegen=codegen))
    original = CStatements(statements, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=_FUNCTION_ADDR, statements=original)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    # A generic word accumulator over a byte table, with explicit loop edges.
    binary = bytes.fromhex("a10002 8946fe c746fc0000 eb03 ff46fc 837efc04 7c02 eb0e "
                           "8b5efc 8a870003 30e4 0146fe ebe7 8b46fe c3")
    instructions = list(decoder.disasm(binary, _FUNCTION_ADDR))
    monkeypatch.setattr(stage, "_linear_function_insns_for_codegen_8616", lambda *_: instructions)
    monkeypatch.setattr(stage, "_cod_metadata_for_codegen_function_8616", lambda *_: None)
    monkeypatch.setattr(stage, "_cod_global_name_refs_by_address_8616", lambda *_, **__: {})
    monkeypatch.setattr(stage, "_resolve_one_hop_jmp_target_8616", lambda _, target: target)
    monkeypatch.setattr(stage, "_branch_target_return_expr_8616", lambda *_: total)
    monkeypatch.setattr(stage, "_named_stack_expr_from_evidence_8616",
                        lambda _, __, offset, ___: {-2: total, -4: index}[offset])
    monkeypatch.setattr(stage, "_global_cvar_8616", lambda *_, **__: total)
    monkeypatch.setattr(stage, "record_global_declaration_spec_8616", lambda *_, **__: None)

    if extra:
        assert stage._materialize_global_byte_index_sum_loop_8616(codegen.project, codegen) is False
        assert codegen.cfunc.statements is original
    else:
        assert stage._materialize_global_byte_index_sum_loop_8616(codegen.project, codegen) is True

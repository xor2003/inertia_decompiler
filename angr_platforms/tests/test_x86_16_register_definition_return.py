"""Keep folded register-return evidence exact and conservative."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.semantics.register_definition_return import unchanged_register_return_site_8616

_RETURN_SITE = 0x1004

def _artifact(tail=()):
    definition = IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (), addr=0x1000)
    returned = IRInstr("RET", None, (), addr=_RETURN_SITE)
    return IRFunctionArtifact(0x1000, (IRBlock(0x1000, (definition, *tail, returned)),))


def test_definition_reaches_exact_return():
    assert unchanged_register_return_site_8616(_artifact(), 0x1000, "ax") == _RETURN_SITE


@pytest.mark.parametrize("register", ["al", "ah", "ax", "eax"])
def test_overlapping_write_refuses(register):
    clobber = IRInstr("MOV", IRValue(MemSpace.REG, name=register, size=2), (), addr=0x1002)
    assert unchanged_register_return_site_8616(_artifact((clobber,)), 0x1000, "ax") is None


@pytest.mark.parametrize("operation", ["CALL", "JMP", "CJMP", "UNSUPPORTED"])
def test_unproven_control_transfer_refuses(operation):
    transfer = IRInstr(operation, None, (), addr=0x1002)
    assert unchanged_register_return_site_8616(_artifact((transfer,)), 0x1000, "ax") is None


def test_ambiguous_or_missing_definition_refuses():
    artifact = _artifact()
    assert unchanged_register_return_site_8616(artifact, 0x999, "ax") is None
    duplicate = replace(artifact, blocks=artifact.blocks * 2)
    assert unchanged_register_return_site_8616(duplicate, 0x1000, "ax") is None

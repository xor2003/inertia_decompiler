"""Keep folded register-return evidence exact and conservative."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir import IRBlock, IRFunctionArtifact, IRInstr, IRRefusal, IRValue, MemSpace
from angr_platforms.X86_16.semantics.register_definition_return import (
    unchanged_register_return_path_8616,
    unchanged_register_return_site_8616,
)

_RETURN_SITE = 0x1004
_DEFINITION_SITE = 0x1000

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


def _shared_epilogue_artifact():
    original = _artifact()
    definition, returned = original.blocks[0].instrs
    return replace(original, blocks=(
        IRBlock(0x1000, (definition,), successor_addrs=(0x1002,)),
        IRBlock(0x1002, (), successor_addrs=(_RETURN_SITE,)),
        IRBlock(_RETURN_SITE, (returned,)),
        IRBlock(0x2000, (replace(definition, addr=0x2000),), successor_addrs=(_RETURN_SITE,)),
    ))


def test_exact_cfg_chain_reaches_shared_epilogue():
    """Another predecessor does not clobber the value on this exact path."""
    assert unchanged_register_return_site_8616(_shared_epilogue_artifact(), 0x1000, "ax") == _RETURN_SITE
    proof = unchanged_register_return_path_8616(_shared_epilogue_artifact(), 0x1000, "ax")
    assert proof is not None
    assert proof.definition_addr == _DEFINITION_SITE
    assert proof.register == "ax"
    assert proof.block_addrs == (0x1000, 0x1002, _RETURN_SITE)
    assert proof.return_addr == _RETURN_SITE


@pytest.mark.parametrize("corruption", ["missing", "branch", "cycle", "clobber", "call", "refusal", "duplicate"])
def test_unproven_epilogue_path_refuses(corruption):
    artifact = _shared_epilogue_artifact()
    blocks = list(artifact.blocks)
    connector = blocks[1]
    if corruption == "missing":
        blocks[1] = replace(connector, successor_addrs=(0x9999,))
    elif corruption == "branch":
        blocks[1] = replace(connector, successor_addrs=(_RETURN_SITE, 0x2000))
    elif corruption == "cycle":
        blocks[1] = replace(connector, successor_addrs=(0x1000,))
    elif corruption == "clobber":
        blocks[1] = replace(connector, instrs=(IRInstr("MOV", IRValue(MemSpace.REG, name="ah", size=1), (), addr=0x1002),))
    elif corruption == "call":
        blocks[1] = replace(connector, instrs=(IRInstr("CALL", None, (), addr=0x1002),))
    elif corruption == "refusal":
        blocks[1] = replace(connector, refusals=(IRRefusal("unsupported", "unknown effect"),))
    else:
        blocks.append(connector)

    assert unchanged_register_return_site_8616(replace(artifact, blocks=tuple(blocks)), 0x1000, "ax") is None


@pytest.mark.parametrize("operation", ["CALL", "UNSUPPORTED"])
def test_same_instruction_address_does_not_hide_later_effects(operation):
    effect = IRInstr(operation, None, (), addr=0x1000)
    assert unchanged_register_return_site_8616(_artifact((effect,)), 0x1000, "ax") is None


def test_return_with_outgoing_cfg_edge_refuses():
    artifact = _artifact()
    block = replace(artifact.blocks[0], successor_addrs=(0x2000,))
    assert unchanged_register_return_site_8616(replace(artifact, blocks=(block,)), 0x1000, "ax") is None


@pytest.mark.parametrize("corruption", ["width", "partial", "unknown-definition", "duplicate-definition", "refusal", "late-effect", "missing-return-address"])
def test_malformed_definition_or_return_refuses(corruption):
    artifact = _artifact()
    block = artifact.blocks[0]
    definition, returned = block.instrs
    if corruption == "width":
        block = replace(block, instrs=(replace(definition, dst=replace(definition.dst, size=1)), returned))
    elif corruption == "partial":
        block = replace(block, instrs=(replace(definition, dst=replace(definition.dst, name="al", size=1)), returned))
    elif corruption == "unknown-definition":
        block = replace(block, instrs=(replace(definition, op="UNSUPPORTED"), returned))
    elif corruption == "duplicate-definition":
        block = replace(block, instrs=(definition, definition, returned))
    elif corruption == "refusal":
        artifact = replace(artifact, refusals=(IRRefusal("unsupported", "unknown effect"),))
    elif corruption == "late-effect":
        block = replace(block, instrs=(*block.instrs, IRInstr("STORE", None, (), addr=0x1006)))
    else:
        block = replace(block, instrs=(definition, replace(returned, addr=None)))

    assert unchanged_register_return_site_8616(replace(artifact, blocks=(block,)), 0x1000, "ax") is None

"""Binary-only distinction between pointer dereferences and scalar indexes."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.lowering.near_pointer_argument import (
    collect_near_pointer_argument_facts_8616,
)
from angr_platforms.X86_16.lowering.segmented_global_loads import _capstone_memory_view_8616
from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from capstone.x86_const import X86_OP_MEM, X86_REG_DS, X86_REG_SS


def _facts(hex_bytes):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    instructions = tuple(
        SimpleNamespace(insn=instruction)
        for instruction in decoder.disasm(bytes.fromhex(hex_bytes), 0x2000)
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(addr=0x2000, capstone=SimpleNamespace(insns=instructions)),),
    )
    return collect_near_pointer_argument_facts_8616(function)


def test_direct_argument_dereference_proves_near_pointer():
    # mov si,[bp+8]; mov byte ptr [si],0xbb
    facts = _facts("8b7608 c604bb")
    assert len(facts) == 1
    assert facts[0].stack_offset == 8
    assert facts[0].dereference_ins_addr == 0x2003
    assert facts[0].access_width_bytes == 1


@pytest.mark.parametrize(("hex_bytes", "register", "exact"), [
    ("8b7608 c600bb", "si", True),  # pointer SI, scalar BX index
    ("8b5e08 c600bb", "bx", True),  # pointer BX, scalar SI index
    ("8b7608 89f3 c607bb", "bx", True),  # copied pointer carrier
    ("8b7608 01de c604bb", "si", False),  # ADD changes the address value
    ("8b7608 01de 89f3 c607bb", "bx", False),  # copy must retain uncertainty
])
def test_pointer_fact_retains_exact_current_carrier(hex_bytes, register, exact):
    """Pointer classification alone must not authorize replacing an adjusted base."""
    facts = _facts(hex_bytes)
    assert len(facts) == 1
    assert facts[0].carrier_register_name == register
    assert facts[0].carrier_value_is_exact is exact


def test_two_pointer_carriers_do_not_choose_an_arbitrary_base():
    """Two loaded pointers in one address have no unique argument base."""
    assert _facts("8b7608 8b5e0a c600bb") == ()


@pytest.mark.parametrize("hex_bytes", [
    "8b7608 c642afbb",  # mov si,[bp+8]; mov byte ptr [bp+si-81],0xbb
    "8b7608 8d4404",  # mov si,[bp+8]; lea ax,[si+4]
])
def test_scalar_stack_index_or_lea_is_not_pointer_dereference(hex_bytes):
    assert _facts(hex_bytes) == ()


@pytest.mark.parametrize(("hex_bytes", "segment"), [
    ("c642afbb", X86_REG_SS),  # default SS:[bp+si-81]
    ("3ec642afbb", X86_REG_DS),  # explicit DS overrides the BP default
    ("c604bb", X86_REG_DS),  # default DS:[si]
    ("36c604bb", X86_REG_SS),  # explicit SS:[si]
    ("67c60428bb", X86_REG_DS),  # EBP as SIB index does not select SS
    ("67c6440500bb", X86_REG_SS),  # EBP as SIB base selects SS
])
def test_decoded_memory_view_preserves_effective_segment(hex_bytes, segment):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    instruction = next(decoder.disasm(bytes.fromhex(hex_bytes), 0x2000))
    operand = next(operand for operand in instruction.operands if operand.type == X86_OP_MEM)
    assert _capstone_memory_view_8616(operand.mem).segment == segment

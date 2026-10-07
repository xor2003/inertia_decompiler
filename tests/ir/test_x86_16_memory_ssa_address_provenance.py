"""Protect register-read provenance through memory-SSA version assignment.

Layer: IR tests.
Responsibility: verify versioning changes memory identity only, not the scalar
read snapshots needed by frame-origin and register-live-in consumers.
"""

from dataclasses import replace

import pytest
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.register_live_in import register_live_in_names_8616
from inertia.ir.ssa import build_x86_16_block_local_ssa
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.ir.ssa_memory_ranges import versioned_memory_address_8616
from tests.fixtures.x86_16_logical_memory_fixtures import lift_ir_artifact


def _address():
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=-4,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
        expr=("frame-read",),
        base_values=(IRValue(MemSpace.REG, name="bp", size=2, version=3, source_tmp=7),),
    )


@pytest.mark.parametrize("version", [0, 1, 17])
def test_memory_version_assignment_preserves_all_address_evidence(version):
    """A memory version must never replace the address's register-read version."""
    address = _address()

    versioned = versioned_memory_address_8616(address, version)

    assert versioned == replace(address, version=version)
    assert versioned.base_values is address.base_values
    assert address.version is None


@pytest.mark.parametrize("operation", ["LOAD", "STORE"])
def test_function_memory_ssa_retains_access_read_snapshots(operation):
    """An accepted exact stack range retains its pre-memory-SSA scalar snapshot."""
    address = _address()
    instruction = (
        IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (address,), size=2)
        if operation == "LOAD"
        else IRInstr("STORE", None, (address, IRValue(MemSpace.CONST, const=5, size=2)), size=2)
    )
    block = IRBlock(addr=0x1000, instrs=(instruction,))
    scalar_ssa = build_x86_16_block_local_ssa(block)
    original_address = scalar_ssa.instrs[0].args[0]

    function_ssa = build_x86_16_function_ssa(IRFunctionArtifact(0x1000, blocks=(block,)))

    actual = function_ssa.blocks[0].instrs[0].args[0]
    assert isinstance(actual, IRAddress)
    assert isinstance(actual.version, int)
    assert replace(actual, version=None) == original_address
    assert function_ssa.memory_stats.complete
    assert function_ssa.memory_stats.failure_count == 0
    assert register_live_in_names_8616(
        function_ssa, {"bp": ("ebp", 0, 2)},
    ) == frozenset({"ebp"})


@pytest.mark.parametrize("code", ["8b4602c3", "5589e58b46fe8946fc89ec5dc3"])
def test_lifted_bp_accesses_keep_their_exact_register_reads(code):
    """Real instruction bytes must survive scalar and memory SSA coherently."""
    artifact = lift_ir_artifact(bytes.fromhex(code))
    scalar_blocks = {block.addr: build_x86_16_block_local_ssa(block) for block in artifact.blocks}

    function_ssa = build_x86_16_function_ssa(artifact)

    checked = 0
    for block in function_ssa.blocks:
        for index, instruction in enumerate(block.instrs):
            if instruction.op not in {"LOAD", "STORE"}:
                continue
            address = instruction.args[0]
            if not isinstance(address, IRAddress) or address.version is None:
                continue
            original = scalar_blocks[block.addr].instrs[index].args[0]
            assert isinstance(original, IRAddress) and original.base_values
            assert replace(address, version=None) == original
            checked += 1
    assert checked > 0

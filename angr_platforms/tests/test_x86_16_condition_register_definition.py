"""Condition operands must follow CFG definitions, not address proximity."""

from types import SimpleNamespace

import capstone
import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16 import decompiler_postprocess_typed_conditions as typed
from angr_platforms.X86_16 import register_source_block_inventory as inventory_owner
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.register_source_block_inventory import (
    RegisterSourceBlockEvidence8616,
    RegisterSourceBlockInventory8616,
)


def _block(address, predecessors, data):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    return RegisterSourceBlockEvidence8616(
        address,
        predecessors,
        tuple(
            SimpleNamespace(address=insn.address, mnemonic=insn.mnemonic, insn=insn)
            for insn in decoder.disasm(data, address)
        ),
    )


@pytest.mark.parametrize(
    ("blocks", "definitions", "sink", "expected"),
    [
        # The physically adjacent arm does not reach the comparison.
        (((0x1000, (), b"\xb8\x01\x00"),
          (0x1010, (0x1000,), b"\xb8\x02\x00\xc3"),
          (0x1020, (0x1000,), b"\x3d\x45\x00")),
         (0x1000, 0x1010), 0x1020, 0x1000),
        # A backward edge can carry a definition at a greater numeric address.
        (((0x1000, (), b"\x90"),
          (0x1030, (0x1000,), b"\xb8\x01\x00"),
          (0x1020, (0x1030,), b"\x3d\x45\x00")),
         (0x1030,), 0x1020, 0x1030),
        # Conflicting definitions at a merge cannot be chosen by address.
        (((0x1000, (), b"\xb8\x01\x00"),
          (0x1010, (0x1000,), b"\xb8\x02\x00"),
          (0x1020, (0x1000, 0x1010), b"\x3d\x45\x00")),
         (0x1000, 0x1010), 0x1020, None),
        # An unrepresented partial write kills the previous full-register view.
        (((0x1000, (), b"\xb8\x01\x00\xb0\x02\x3d\x45\x00"),),
         (0x1000,), 0x1005, None),
        # A partial write cannot become a whole-word definition merely by tag.
        (((0x1000, (), b"\xb8\x01\x00\xb0\x02\x3d\x45\x00"),),
         (0x1000, 0x1003), 0x1005, None),
        # Unknown calls kill prior definitions, but explicit call results bind.
        (((0x1000, (), b"\xb8\x01\x00\xe8\x00\x00\x3d\x45\x00"),),
         (0x1000,), 0x1006, None),
        (((0x1000, (), b"\xb8\x01\x00\xe8\x00\x00\x3d\x45\x00"),),
         (0x1000, 0x1003), 0x1006, 0x1003),
        # Writes after the queried boundary still matter on loop backedges.
        (((0x1000, (), b"\xb8\x01\x00"),
          (0x1010, (0x1000, 0x1010), b"\x3d\x45\x00\xb8\x02\x00")),
         (0x1000, 0x1013), 0x1010, None),
    ],
)
def test_condition_operand_requires_unique_reaching_definition(
    monkeypatch, blocks, definitions, sink, expected,
):
    evidence = tuple(_block(*block) for block in blocks)
    count = len(evidence)
    inventory = RegisterSourceBlockInventory8616(
        0x1000, evidence, count, count, count, count, 0,
    )
    monkeypatch.setattr(
        inventory_owner, "collect_register_source_block_inventory_8616",
        lambda _function: inventory,
    )
    function = SimpleNamespace(addr=0x1000)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kw: function)),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000), project=project,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        next_idx=lambda _name: 0,
    )
    expressions = {
        (address, "ax", 2): CConstant(address, SimTypeShort(False), codegen=codegen)
        for address in definitions
    }
    monkeypatch.setattr(typed, "_register_exprs_by_ins_addr_8616", lambda *_args: expressions)
    operand = IRValue(MemSpace.REG, name="ax", size=2)
    condition = ConditionIR("eq", operand, producer_insn=sink, src_insn=sink)

    result = typed._build_c_expr_for_operand(project, operand, codegen, condition)

    if expected is None:
        assert result is None
    else:
        assert result is expressions[(expected, "ax", 2)]

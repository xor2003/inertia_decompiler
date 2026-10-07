from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import IRInstr, IRValue, MemSpace
from inertia.ir.ssa_function import (
    SSAFunctionArtifact,
    SSAIncomingValue,
    SSAPhiNode,
    build_x86_16_function_ssa,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401

from inertia.alias.carry_borrow_projection import (
    project_carry_borrow_aliases_8616,
)
from inertia.semantics.carry_borrow_contracts import CarryBorrowFailure8616
from inertia.semantics.carry_borrow_links import analyze_carry_borrow_links_8616
from inertia.widening.carry_borrow_values import widen_carry_borrow_values_8616


def _lift_ssa(code: bytes) -> SSAFunctionArtifact:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    return build_x86_16_function_ssa(build_x86_16_ir_function_artifact(project, function))


def _split_carry_artifact() -> SSAFunctionArtifact:
    artifact = _lift_ssa(bytes.fromhex("01 d8 11 ca c3"))
    block = artifact.blocks[0]
    low = tuple(instruction for instruction in block.instrs if instruction.addr == 0x1000)
    high = tuple(instruction for instruction in block.instrs if instruction.addr != 0x1000)
    return replace(
        artifact,
        blocks=(
            replace(block, instrs=low, bindings=()),
            replace(block, addr=0x1002, instrs=high, bindings=()),
        ),
        predecessor_map={0x1000: (), 0x1002: (0x1000,)},
    )


def _phi_carry_artifact(*, conflicting: bool) -> SSAFunctionArtifact:
    artifact = _split_carry_artifact()
    link = analyze_carry_borrow_links_8616(artifact).links[0]
    low_flags = link.flags_definition.instruction.dst
    flags_read_source = link.flags_read.instruction.args[0]
    assert low_flags is not None and isinstance(flags_read_source, IRValue)
    assert low_flags.version is not None
    other_version = low_flags.version + 1
    other_flags = replace(low_flags, version=other_version)
    phi_target = replace(flags_read_source, version=other_version + 1)
    blocks = {block.addr: block for block in artifact.blocks}
    high = blocks[0x1002]
    high_instructions = list(high.instrs)
    high_instructions[link.flags_read.instr_index] = replace(
        link.flags_read.instruction,
        args=(phi_target,),
    )
    middle_instructions = (
        (
            IRInstr(
                "MOV",
                other_flags,
                (IRValue(MemSpace.CONST, const=0, size=2),),
                size=2,
            ),
        )
        if conflicting
        else ()
    )
    middle = replace(
        blocks[0x1000],
        addr=0x1001,
        instrs=middle_instructions,
        bindings=(),
    )
    phi = SSAPhiNode(
        block_addr=0x1002,
        key=(MemSpace.REG.value, "flags", low_flags.offset),
        target=phi_target,
        incoming=(
            SSAIncomingValue(0x1000, low_flags),
            SSAIncomingValue(0x1001, other_flags if conflicting else low_flags),
        ),
    )
    return replace(
        artifact,
        blocks=(blocks[0x1000], middle, replace(high, instrs=tuple(high_instructions))),
        phi_nodes=(phi,),
        predecessor_map={0x1000: (), 0x1001: (0x1000,), 0x1002: (0x1000, 0x1001)},
    )


def _assert_full_widening(artifact: SSAFunctionArtifact) -> None:
    semantics = analyze_carry_borrow_links_8616(artifact)
    assert semantics.complete
    assert semantics.stats.raw_fact_count == semantics.stats.materialized_count == 1
    aliases = project_carry_borrow_aliases_8616(semantics)
    assert aliases.complete
    assert aliases.stats.raw_fact_count == aliases.stats.materialized_count == 1
    widening = widen_carry_borrow_values_8616(aliases)
    assert widening.complete
    assert widening.stats.raw_fact_count == widening.stats.materialized_count == 1


def test_cross_block_carry_from_dominating_flags_reaches_widening() -> None:
    artifact = _split_carry_artifact()

    _assert_full_widening(artifact)

    link = analyze_carry_borrow_links_8616(artifact).links[0]
    assert link.low_result_write.block_addr == link.flags_definition.block_addr == 0x1000
    assert link.high_result_write.block_addr == link.flags_read.block_addr == 0x1002


def test_semantics_refuses_cross_block_carry_with_incomplete_predecessors() -> None:
    artifact = _split_carry_artifact()

    refused = analyze_carry_borrow_links_8616(
        replace(artifact, predecessor_map={0x1000: (), 0x1002: ()})
    )

    assert refused.complete
    assert refused.stats.failure_count == 1
    assert refused.resolutions[0].failure is CarryBorrowFailure8616.CFG_PREDECESSOR_MISMATCH


def test_equivalent_flags_phi_reaches_widening() -> None:
    _assert_full_widening(_phi_carry_artifact(conflicting=False))


def test_semantics_refuses_conflicting_flags_phi_inputs() -> None:
    refused = analyze_carry_borrow_links_8616(_phi_carry_artifact(conflicting=True))

    assert refused.complete
    assert refused.stats.failure_count == 1
    assert refused.resolutions[0].failure is CarryBorrowFailure8616.FLAGS_PHI_CONFLICT

"""Shared real-lifter fixtures for typed wide call-output tests."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    IRCallOutputProvenance8616,
    IRCallOutputShape8616,
    IRInstr,
    IRValue,
    MemSpace,
)
from inertia.ir.logical_memory_rebase import (
    rebase_logical_memory_prefix_insertions_8616,
)
from inertia.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.stack_memory_ssa import (
    lower_x86_16_stack_memory_ssa_alias_artifact,
)

from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.widening.carry_borrow_pipeline import (
    build_carry_borrow_widening_pipeline_8616,
)
from inertia.widening.stack_memory_objects import (
    build_x86_16_stack_memory_object_widening_artifact,
)

WIDE_STACK_ADD = bytes.fromhex("03 46 04 13 56 06 89 46 fc 89 56 fe c3")


def lift_after_dx_ax_call(
    *,
    high_callsite_addr: int = 0xFF0,
    retain_high_provenance: bool = True,
    code: bytes = bytes.fromhex("01 d8 11 ca c3"),
) -> SSAFunctionArtifact:
    """Lift one block and inject an exact Semantics-owned DX:AX call output."""
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
    artifact = build_x86_16_ir_function_artifact(project, function)
    block = artifact.blocks[0]
    provenances = (
        IRCallOutputProvenance8616(
            callsite_addr=0xFF0,
            target_addr=0x2000,
            shape=IRCallOutputShape8616.DX_AX,
        ),
        (
            IRCallOutputProvenance8616(
                callsite_addr=high_callsite_addr,
                target_addr=0x2000,
                shape=IRCallOutputShape8616.DX_AX,
            )
            if retain_high_provenance
            else None
        ),
    )
    outputs = tuple(
        IRInstr(
            "CALL_OUTPUT",
            IRValue(
                MemSpace.REG,
                name=name,
                size=2,
                expr=("call_output", "dx_ax", "0xff0"),
                call_output=provenance,
            ),
            (IRValue(MemSpace.CONST, const=0x2000, size=4),),
            size=2,
            addr=0xFF0,
        )
        for name, provenance in zip(("ax", "dx"), provenances, strict=True)
    )
    rewritten_blocks = (replace(block, instrs=(*outputs, *block.instrs)),)
    enriched = replace(
        artifact,
        blocks=rewritten_blocks,
        logical_memory=rebase_logical_memory_prefix_insertions_8616(
            artifact.logical_memory,
            prefix_lengths={block.addr: len(outputs)},
            rewritten_blocks=rewritten_blocks,
        ),
    )
    return build_x86_16_function_ssa(enriched)


def wide_assignment_fixture(
    *,
    callsite_tag: int = 0xFF0,
    include_source: bool = True,
    mixed_carrier: bool = False,
    nested_carrier_group: bool = False,
    unrelated_nested_statement: bool = False,
) -> tuple[SimpleNamespace, CStatements, CFunctionCall, CVariable | None]:
    """Build one real IR-to-Lowering wide call-output fixture."""
    function_ssa = lift_after_dx_ax_call(code=WIDE_STACK_ADD)
    stack_alias = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)
    pipeline = build_carry_borrow_widening_pipeline_8616(function_ssa, stack_alias)
    indices = iter(range(1, 100))
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
        next_idx=lambda _name: next(indices),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : next(indices))
    source_variable = SimStackVariable(2, 4, base="bp", name="wait", region=0x1000)
    source = (
        CVariable(source_variable, variable_type=SimTypeLong(False), codegen=codegen)
        if include_source
        else None
    )
    call = CFunctionCall(
        0x2000,
        None,
        [],
        tags={"ins_addr": callsite_tag},
        codegen=codegen,
    )
    carriers: list[object] = []
    for address in (0x1000, 0x1003, 0x1006, 0x1009):
        expression = (
            CFunctionCall(0x3000, None, [], tags={"ins_addr": address}, codegen=codegen)
            if mixed_carrier and address == 0x1000
            else CConstant(
                address,
                SimTypeShort(False),
                tags={"ins_addr": address},
                codegen=codegen,
            )
        )
        carriers.append(
            CExpressionStatement(expression, tags={"ins_addr": address}, codegen=codegen)
        )
    if unrelated_nested_statement:
        carriers.insert(
            1,
            CExpressionStatement(
                CConstant(7, SimTypeShort(False), tags={"ins_addr": 0x1100}, codegen=codegen),
                tags={"ins_addr": 0x1100},
                codegen=codegen,
            ),
        )
    call_group = CStatements([CExpressionStatement(call, codegen=codegen)], codegen=codegen)
    carrier_group = CStatements(carriers, codegen=codegen)
    root = (
        CStatements([call_group, carrier_group], codegen=codegen)
        if nested_carrier_group
        else CStatements([*call_group.statements, *carriers], codegen=codegen)
    )
    variables_in_use = {source_variable: source} if source is not None else {}
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        variables_in_use=variables_in_use,
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen._inertia_stack_memory_ssa_alias_artifact = stack_alias
    codegen._inertia_stack_memory_object_widening_artifact = (
        build_x86_16_stack_memory_object_widening_artifact(stack_alias)
    )
    codegen._inertia_carry_borrow_widening_pipeline_8616 = pipeline
    codegen._inertia_vex_ir_frame = FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=-2,
            detail="test fixture",
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        )
    )
    assert lower_x86_16_stack_memory_ssa_alias_artifact(codegen) is not None
    return codegen, root, call, source


__all__ = ["WIDE_STACK_ADD", "lift_after_dx_ax_call", "wide_assignment_fixture"]

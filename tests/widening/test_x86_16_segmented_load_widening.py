from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import IRAddress, IRInstr, IRValue, MemSpace
from inertia.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
from capstone.x86_const import X86_INS_MOV, X86_OP_MEM, X86_OP_REG

from inertia.widening.segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_identity_8616,
    segmented_load_tags_8616,
)
from inertia.widening.segmented_load_widening import (
    _decoded_segmented_word_mov_addr_8616,
    apply_segmented_load_widening_8616,
    join_adjacent_segmented_load_identities_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.cfunc = SimpleNamespace(addr=0x10560)

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _identity(space: MemSpace, offset: int, *, width: int = 1) -> SegmentedLoadIdentity8616:
    return SegmentedLoadIdentity8616(space=space, offset=offset, width=width, region=0x10560)


def test_decoded_segmented_word_mov_requires_exact_register_and_memory_widths() -> None:
    instruction_addr = 0x10570
    instruction = SimpleNamespace(
        id=X86_INS_MOV,
        address=instruction_addr,
        operands=(
            SimpleNamespace(type=X86_OP_REG, size=2, reg=1),
            SimpleNamespace(type=X86_OP_MEM, size=2),
        ),
        reg_name=lambda register_id: "si" if register_id == 1 else "",
    )

    assert _decoded_segmented_word_mov_addr_8616(SimpleNamespace(insn=instruction)) == instruction_addr
    instruction.operands[1].size = 1
    assert _decoded_segmented_word_mov_addr_8616(SimpleNamespace(insn=instruction)) is None


def test_join_adjacent_segmented_load_identities_proves_one_word() -> None:
    joined = join_adjacent_segmented_load_identities_8616(
        _identity(MemSpace.DS, 0x0BA2),
        _identity(MemSpace.DS, 0x0BA3),
    )

    assert joined == SegmentedLoadIdentity8616(
        space=MemSpace.DS,
        offset=0x0BA2,
        width=2,
        region=0x10560,
    )


def test_join_adjacent_segmented_load_identities_refuses_different_spaces() -> None:
    joined = join_adjacent_segmented_load_identities_8616(
        _identity(MemSpace.DS, 0x0BA2),
        _identity(MemSpace.ES, 0x0BA3),
    )

    assert joined is None


def test_join_adjacent_segmented_load_identities_refuses_gap_and_wrap() -> None:
    assert (
        join_adjacent_segmented_load_identities_8616(
            _identity(MemSpace.DS, 0x0BA2),
            _identity(MemSpace.DS, 0x0BA4),
        )
        is None
    )


def test_segmented_load_widening_materializes_and_retains_exact_identity() -> None:
    codegen = _Codegen()
    ds = CVariable(SimRegisterVariable(22, 2, name="ds"), codegen=codegen)
    low_offset = CConstant(0x0BA2, SimTypeShort(False), codegen=codegen)
    high_offset = CConstant(0x0BA3, SimTypeShort(False), codegen=codegen)
    low_identity = _identity(MemSpace.DS, 0x0BA2)
    high_identity = _identity(MemSpace.DS, 0x0BA3)
    low = CFunctionCall(
        "SEG_U8",
        None,
        [ds, low_offset],
        codegen=codegen,
        tags=segmented_load_tags_8616(
            low_identity,
            existing={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
        ),
    )
    high = CFunctionCall(
        "SEG_U8",
        None,
        [ds, high_offset],
        codegen=codegen,
        tags=segmented_load_tags_8616(
            high_identity,
            existing={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
        ),
    )
    expression = CBinaryOp(
        "Or",
        low,
        CBinaryOp(
            "Shl",
            high,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([expression], codegen=codegen)
    codegen.cfunc.body = root
    codegen.cfunc.statements = root

    changed = apply_segmented_load_widening_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements.statements[0]
    assert isinstance(result, CFunctionCall)
    assert segmented_load_identity_8616(result) == SegmentedLoadIdentity8616(
        MemSpace.DS,
        0x0BA2,
        2,
        0x10560,
    )
    assert codegen._inertia_segmented_load_widening_report_8616.materialized_count == 1
    assert (
        join_adjacent_segmented_load_identities_8616(
            _identity(MemSpace.DS, 0xFFFF),
            _identity(MemSpace.DS, 0),
        )
        is None
    )


def test_segmented_load_widening_joins_ssa_proven_statement_byte_pair() -> None:
    """A MOV reg16,[seg:index] byte decomposition becomes one typed word load."""
    codegen = _Codegen()
    instruction_addr = 0x10570
    bx_offset, bx_size = codegen.project.arch.registers["bx"]
    si_offset, si_size = codegen.project.arch.registers["si"]
    address = IRAddress(
        MemSpace.ES,
        base_values=(IRValue(MemSpace.REG, name="bx", offset=bx_offset, size=bx_size),),
    )
    block = SSABlock(
        addr=instruction_addr,
        instrs=(
            IRInstr(
                "MOV",
                IRValue(MemSpace.REG, name="si", offset=si_offset, size=si_size),
                (address,),
                2,
                instruction_addr,
            ),
        ),
        bindings=(),
    )
    artifact = SSAFunctionArtifact(
        function_addr=codegen.cfunc.addr,
        blocks=(block,),
        predecessor_map={instruction_addr: ()},
    )
    codegen.project._inertia_function_ssa_artifacts_8616 = {codegen.cfunc.addr: artifact}
    codegen.project._inertia_function_ssa_stages_8616 = {
        codegen.cfunc.addr: FunctionSSAArtifactStage8616.IR,
    }
    es_offset, es_size = codegen.project.arch.registers["es"]
    es = CVariable(SimRegisterVariable(es_offset, es_size, name="es"), codegen=codegen)
    bx = CVariable(SimRegisterVariable(bx_offset, bx_size, name="bx"), codegen=codegen)
    source_tags = {
        "inertia_x86_16_runtime_segment_helper": "SEG_U8",
        "inertia_source_instruction_addrs": (instruction_addr,),
    }
    statement_tags = {"ins_addr": instruction_addr}
    low = CFunctionCall("SEG_U8", None, [es, bx], codegen=codegen, tags=source_tags)
    high = CFunctionCall(
        "SEG_U8",
        None,
        [
            es,
            CBinaryOp(
                "Add",
                bx,
                CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
        tags=source_tags,
    )
    low_tmp = CVariable(
        SimTemporaryVariable(1, 1),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_tmp = CVariable(
        SimTemporaryVariable(2, 1),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    si = CVariable(
        SimRegisterVariable(si_offset, si_size, name="si"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(low_tmp, low, codegen=codegen, tags=statement_tags),
            CAssignment(high_tmp, high, codegen=codegen, tags=statement_tags),
            CAssignment(
                si,
                CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
                tags=statement_tags,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc.body = root
    codegen.cfunc.statements = root

    assert apply_segmented_load_widening_8616(codegen) is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs is si
    assert isinstance(assignment.rhs, CFunctionCall)
    assert assignment.rhs.callee_target == "SEG_U16"
    assert assignment.rhs.args == [es, bx]
    report = codegen._inertia_segmented_load_widening_report_8616
    assert report.raw_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_segmented_load_widening_coalesces_proven_overwide_byte_lanes() -> None:
    """A proven word MOV is not emitted as two overlapping word helpers."""
    codegen = _Codegen()
    instruction_addr = 0x10580
    bx_offset, bx_size = codegen.project.arch.registers["bx"]
    si_offset, si_size = codegen.project.arch.registers["si"]
    address = IRAddress(
        MemSpace.DS,
        base_values=(IRValue(MemSpace.REG, name="bx", offset=bx_offset, size=bx_size),),
    )
    block = SSABlock(
        addr=instruction_addr,
        instrs=(
            IRInstr(
                "MOV",
                IRValue(MemSpace.REG, name="si", offset=si_offset, size=si_size),
                (address,),
                2,
                instruction_addr,
            ),
        ),
        bindings=(),
    )
    codegen.project._inertia_function_ssa_artifacts_8616 = {
        codegen.cfunc.addr: SSAFunctionArtifact(
            function_addr=codegen.cfunc.addr,
            blocks=(block,),
            predecessor_map={instruction_addr: ()},
        )
    }
    codegen.project._inertia_function_ssa_stages_8616 = {
        codegen.cfunc.addr: FunctionSSAArtifactStage8616.IR,
    }
    ds_offset, ds_size = codegen.project.arch.registers["ds"]
    ds = CVariable(SimRegisterVariable(ds_offset, ds_size, name="ds"), codegen=codegen)
    bx = CVariable(SimRegisterVariable(bx_offset, bx_size, name="bx"), codegen=codegen)
    low_offset = CBinaryOp(
        "Add",
        CConstant(0x931F, SimTypeShort(False), codegen=codegen),
        bx,
        codegen=codegen,
    )
    high_offset = CBinaryOp(
        "Add",
        CConstant(0x9320, SimTypeShort(False), codegen=codegen),
        bx,
        codegen=codegen,
    )
    tags = {
        "inertia_x86_16_runtime_segment_helper": "SEG_U16",
        "inertia_source_instruction_addrs": (instruction_addr,),
    }
    low = CFunctionCall("SEG_U16", None, [ds, low_offset], codegen=codegen, tags=dict(tags))
    high = CFunctionCall("SEG_U16", None, [ds, high_offset], codegen=codegen, tags=dict(tags))
    expression = CBinaryOp(
        "Or",
        low,
        CBinaryOp(
            "Shl",
            high,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([expression], codegen=codegen)
    codegen.cfunc.body = root
    codegen.cfunc.statements = root

    changed = apply_segmented_load_widening_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements.statements[0]
    assert isinstance(result, CFunctionCall)
    assert result.callee_target == "SEG_U16"
    assert result.args[1] is low_offset

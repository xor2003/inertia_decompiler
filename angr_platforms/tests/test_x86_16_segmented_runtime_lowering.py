from __future__ import annotations

from collections import OrderedDict
from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CDoWhileLoop,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CMultiStatementExpression,
    CStatements,
    CStructField,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
    CWhileLoop,
)
from angr.sim_type import SimStruct, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_stage import _is_direct_stack_update_materialization_delta_8616
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRLogicalMemoryArtifact8616,
    IRLogicalMemoryStats8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
    MemSpace,
    SegmentOrigin,
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
    build_x86_16_segment_state_artifact,
)
from angr_platforms.X86_16.lowering import real_mode_linear, segmented_memory_lowering
from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveExpressionOp8616,
    DirectStackMoveSourceKind8616,
    DirectStackUpdateFact8616,
    DirectStackUpdateOp8616,
    DirectStackUpdateSourceKind8616,
    DirectStackWriteClassification8616,
    RealModeLinearStackAccess8616,
    _direct_stack_move_instruction_facts_8616,
    _direct_stack_update_instruction_facts_8616,
    _filter_direct_stack_update_facts_for_active_function_8616,
    _restore_same_block_stack_move_order_8616,
    _same_stack_move_rhs_8616,
    _tree_has_stack_assignment_for_instruction_addr_8616,
    _tree_has_stack_move_assignment_8616,
    lower_stable_ss_linear_stack_dereferences_8616,
    materialize_direct_global_incdec_instructions_8616,
    materialize_direct_stack_incdec_instructions_8616,
    materialize_direct_stack_mov_instructions_8616,
    prune_call_return_frame_stack_assignments_8616,
    prune_callee_saved_stack_spills_8616,
    prune_consumed_call_push_stack_assignments_8616,
    prune_frame_prologue_stack_assignments_8616,
    prune_materialized_call_push_stack_assignments_8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from angr_platforms.X86_16.lowering.segment_register_state import (
    runtime_segment_push_source_cvar_8616,
)
from angr_platforms.X86_16.lowering.segmented_memory_lowering import (
    NearPointerArgumentFact8616,
    NearPointerArgumentRefusalReason8616,
    apply_runtime_segment_lowering_8616,
    lower_runtime_segment_access_8616,
    lower_runtime_segment_address_8616,
    materialize_runtime_helper_segment_carriers_8616,
)
from angr_platforms.X86_16.lowering.stack_aggregate_objects import StackAggregateObjectFact8616
from angr_platforms.X86_16.lowering.storage_identity_facts import (
    GlobalStorageIdentityFact8616,
    StorageIdentityEvidenceKind8616,
    global_storage_identity_facts_8616,
)
from angr_platforms.X86_16.pipeline.architecture_guard import assert_final_c_quality_8616
from angr_platforms.X86_16.pipeline.contracts import PipelineHardError, assert_pipeline_contracts_8616
from angr_platforms.X86_16.structuring.direct_stack_move_loop_entries import (
    materialize_direct_stack_move_loop_entry_ownership_8616,
    place_direct_stack_move_loop_entry_assignment_8616,
)
from angr_platforms.X86_16.validation_dataflow import validate_structured_def_use_8616
from angr_platforms.X86_16.widening.segmented_load_identity import segmented_load_identity_8616
from capstone.x86_const import (
    X86_GRP_JUMP,
    X86_GRP_RET,
    X86_INS_ADC,
    X86_INS_ADD,
    X86_INS_CALL,
    X86_INS_CBW,
    X86_INS_CDQ,
    X86_INS_DEC,
    X86_INS_IDIV,
    X86_INS_INC,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_INS_OR,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_INS_RETF,
    X86_INS_SAR,
    X86_INS_SHL,
    X86_INS_SUB,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_CS,
    X86_REG_CX,
    X86_REG_DI,
    X86_REG_DS,
    X86_REG_DX,
    X86_REG_INVALID,
    X86_REG_SI,
    X86_REG_SP,
)

import inertia_decompiler.recompile_check as recompile_check
from inertia_decompiler.cli_arg_parser import _build_cli_argument_parser
from inertia_decompiler.recompile_check import check_c_recompiles_8616


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _project():
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _DummyCodegen(project)
    root = CStatements([], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        arg_list=[],
        variables_in_use={},
        unified_local_vars={},
    )
    return project, codegen


def _reg_operand(reg, *, size=2):
    return SimpleNamespace(type=X86_OP_REG, size=size, reg=reg)


def _bp_mem_operand(offset: int, *, size=2):
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=size,
        mem=SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=offset),
    )


def _bp_indexed_mem_operand(offset: int, index: int, *, size: int = 1):
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=size,
        mem=SimpleNamespace(base=X86_REG_BP, index=index, scale=1, disp=offset),
    )


def _reg_indirect_mem_operand(register: int, *, size: int = 2):
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=size,
        mem=SimpleNamespace(base=register, index=X86_REG_INVALID, scale=1, disp=0),
    )


def _global_mem_operand(displacement: int, *, size: int = 2):
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=size,
        mem=SimpleNamespace(
            base=X86_REG_INVALID,
            index=X86_REG_INVALID,
            scale=1,
            disp=displacement,
        ),
    )


def _imm_operand(value: int, *, size=2):
    return SimpleNamespace(type=X86_OP_IMM, size=size, imm=value)


def test_stable_ss_linear_positive_bp_access_requires_arg_evidence():
    _project_obj, codegen = _project()

    refused = stack_cvar_for_stable_ss_linear_access_8616(
        codegen,
        RealModeLinearStackAccess8616(4, 2),
    )

    assert refused is None
    assert codegen._inertia_positive_bp_stack_access_without_arg_evidence_refused_8616 == 1

    arg_var = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x4010)
    arg_cvar = CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.arg_list = [arg_cvar]
    codegen.cfunc.variables_in_use[arg_var] = arg_cvar

    materialized = stack_cvar_for_stable_ss_linear_access_8616(
        codegen,
        RealModeLinearStackAccess8616(4, 2),
    )

    assert materialized is arg_cvar


def test_direct_stack_cvar_width_preserves_signed_prototype_arg_type():
    project, codegen = _project()
    signed_type = SimTypeShort(True).with_arch(project.arch)
    codegen.cfunc.functy = SimTypeFunction([signed_type], SimTypeShort(False), arg_names=("a",)).with_arch(project.arch)
    arg_var = SimStackVariable(4, 2, base="bp", name="a", region=0x4010)
    arg_cvar = CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)

    real_mode_linear._ensure_stack_cvar_min_width_8616(codegen, arg_cvar, 2)

    assert arg_cvar.variable_type.signed is True


def test_lower_stable_ss_linear_stack_dereferences_returns_materialized_local():
    project, codegen = _project()
    local_var = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010)
    local_cvar = CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[local_var] = local_cvar
    ss = CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    bp = CVariable(
        SimRegisterVariable(project.arch.registers["bp"][0], 2, name="bp"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    linear = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ss, CConstant(4, SimTypeShort(False), codegen=codegen), codegen=codegen),
        CBinaryOp("Sub", bp, CConstant(2, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    deref = CUnaryOp("Dereference", linear, codegen=codegen)
    dst = CVariable(SimRegisterVariable(0x80, 2, name="dst"), variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(CAssignment(dst, deref, codegen=codegen))

    assert lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project) is True

    lowered_rhs = codegen.cfunc.statements.statements[0].rhs
    assert lowered_rhs is local_cvar


class _BytesMemory:
    def __init__(self, base: int, data: bytes):
        self.base = base
        self.data = data

    def load(self, addr: int, size: int):
        start = int(addr) - self.base
        return self.data[start : start + int(size)]


def test_direct_stack_call_target_candidates_include_padding_prologue() -> None:
    class _Functions:
        @staticmethod
        def function(*, addr: int, create: bool):
            assert create is False
            names = {
                0x1075B: "sub_1075b",
                0x10768: "sub_10768",
            }
            name = names.get(addr)
            return SimpleNamespace(addr=addr, name=name) if name is not None else None

    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=_BytesMemory(
                0x1075B,
                b"\x90" * 13 + b"\x55\x8b\xec",
            ),
        ),
        kb=SimpleNamespace(functions=_Functions(), labels={}),
    )

    call_name, _callee, target = (
        real_mode_linear._callee_name_for_direct_stack_move_8616(
            project,
            0x1075B,
        )
    )

    assert call_name == "sub_10768"
    assert target == 0x10768


def test_direct_stack_instruction_facts_fall_back_to_linear_function_bytes():
    # mov ax, [bp+4]; mov [bp-6], ax; inc word [bp-6]
    code = bytes.fromhex("8b46048946faff46fa")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x1000, code)),
    )
    function = SimpleNamespace(addr=0x1000, size=len(code), name="copy_and_inc")

    move_facts = _direct_stack_move_instruction_facts_8616(project, function)
    update_facts = _direct_stack_update_instruction_facts_8616(project, function)

    assert len(move_facts) == 1
    assert move_facts[0].dst_offset == -6
    assert move_facts[0].source_kind is DirectStackMoveSourceKind8616.STACK_SLOT
    assert move_facts[0].source_register_offset == 0
    assert move_facts[0].source_offset == 4
    assert move_facts[0].ins_addr == 0x1003
    assert len(update_facts) == 1
    assert update_facts[0].offset == -6
    assert update_facts[0].delta == 1
    assert update_facts[0].ins_addr == 0x1006


def test_direct_stack_write_inventory_distinguishes_stale_tag_from_unclassified_store() -> None:
    # push bp; mov bp, sp; sub sp, 2; mov byte ptr [bp-2], al
    code = bytes.fromhex("558bec83ec028846fe")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x1000, code)),
    )
    function = SimpleNamespace(addr=0x1000, size=len(code), name="entry_then_store")
    codegen = SimpleNamespace(_inertia_callsite_summary_inventory_8616={})

    facts = real_mode_linear._direct_stack_move_instruction_facts_for_codegen_8616(
        codegen,
        project,
        function,
    )

    assert facts == ()
    inventory = codegen._inertia_direct_stack_write_inventory_8616
    assert (
        inventory.classify(ins_addr=0x1000, dst_offset=-2, width=2)
        is DirectStackWriteClassification8616.PROVEN_NOT_WRITE
    )
    assert (
        inventory.classify(ins_addr=0x1006, dst_offset=-2, width=1)
        is DirectStackWriteClassification8616.EXACT_WRITE
    )
    assert inventory.failure_count == 0


def test_direct_stack_instruction_facts_extend_to_exact_callsite_inventory_return() -> None:
    # mov [bp-4], 0; mov [bp-2], 1; call next
    code = bytes.fromhex("c746fc0000c746fe0100e80000")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x1000, code)),
    )
    function = SimpleNamespace(addr=0x1000, size=5, name="partial_cfg_function")
    summary = CallsiteSummary8616(
        0x100A,
        0x100D,
        0x100D,
        "direct_near",
        0,
        (),
        0,
        None,
        False,
    )
    codegen = SimpleNamespace(_inertia_callsite_summary_inventory_8616={0x100A: summary})

    facts = real_mode_linear._direct_stack_move_instruction_facts_for_codegen_8616(
        codegen,
        project,
        function,
    )

    assert tuple((fact.ins_addr, fact.dst_offset, fact.source_value) for fact in facts) == (
        (0x1000, -4, 0),
        (0x1005, -2, 1),
    )
    evidence = codegen._inertia_direct_stack_move_extent_evidence_8616
    assert evidence.raw_fact_count == 1
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_fact_count == 1
    assert evidence.materialized_count == 1
    assert evidence.failure_count == 0
    assert evidence.original_end == 0x1005
    assert evidence.proven_end == 0x100D
    assert evidence.recovered_fact_count == 1


def test_direct_stack_instruction_facts_collect_binary_stack_expression():
    # mov ax, [bp+4]; add ax, [bp+6]; mov [bp-2], ax
    code = bytes.fromhex("8b46040346068946fe")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x1000, code)),
    )
    function = SimpleNamespace(addr=0x1000, size=len(code), name="add_stack_words")

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.dst_offset == -2
    assert fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR
    assert fact.source_offset == 4
    assert fact.source_rhs_offset == 6
    assert fact.source_op is DirectStackMoveExpressionOp8616.ADD


def test_direct_stack_instruction_facts_collect_indexed_byte_store_with_global_index():
    # mov si, word ptr [0x0ba2]; mov byte ptr [bp+si-44], 0
    code = bytes.fromhex("8b36a20bc642d400")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x1000, code)),
    )
    function = SimpleNamespace(addr=0x1000, size=len(code), name="terminate_local_row")

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.dst_offset == -44
    assert fact.width == 1
    assert fact.source_kind is DirectStackMoveSourceKind8616.IMMEDIATE
    assert fact.source_value == 0
    assert fact.dst_index_global_displacement == 0x0BA2
    assert fact.dst_index_stack_offset is None
    assert fact.dst_index_immediate is None
    assert fact.dst_index_scale == 1
    assert fact.ins_addr == 0x1004


def test_direct_stack_update_facts_recover_register_mediated_store():
    # mov ax, [bp-6]; inc ax; mov [bp-6], ax
    code = bytes.fromhex("8b46fa408946fa")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x1000, code)),
    )
    function = SimpleNamespace(addr=0x1000, size=len(code), name="register_inc_store")

    update_facts = _direct_stack_update_instruction_facts_8616(project, function)

    assert len(update_facts) == 1
    assert update_facts[0].offset == -6
    assert update_facts[0].source_kind is DirectStackUpdateSourceKind8616.STACK_SLOT
    assert update_facts[0].source_offset == -6
    assert update_facts[0].delta == 1
    assert update_facts[0].ins_addr == 0x1004


def test_direct_stack_update_facts_leave_cross_slot_expression_to_move_facts():
    # mov ax, [bp+4]; inc ax; mov [bp-2], ax
    code = bytes.fromhex("8b4604408946fe")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x1000, code)),
    )
    function = SimpleNamespace(addr=0x1000, size=len(code), name="cross_slot_inc_store")

    update_facts = _direct_stack_update_instruction_facts_8616(project, function)
    move_facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert update_facts == ()
    assert len(move_facts) == 1
    assert move_facts[0].dst_offset == -2
    assert move_facts[0].source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_EXPR
    assert move_facts[0].source_offset == 4
    assert move_facts[0].source_op is DirectStackMoveExpressionOp8616.ADD
    assert move_facts[0].source_immediate == 1


def test_direct_stack_instruction_facts_use_linear_bytes_when_covering_block_lacks_capstone():
    # call clock; add ax,[bp+4]; adc dx,[bp+6]; mov [bp-4],ax; mov [bp-2],dx
    code = bytes.fromhex("e838040346041356068946fc8956fe")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x100B, code)),
        kb=SimpleNamespace(labels={0x1446: "_clock"}),
    )
    empty_covering_block = SimpleNamespace(addr=0x100B, size=len(code), capstone=SimpleNamespace(insns=()))
    function = SimpleNamespace(addr=0x100B, size=len(code), name="sleep_like", blocks=(empty_covering_block,))

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH
    assert fact.dst_offset == -4
    assert fact.width == 4
    assert fact.source_offset == 4
    assert fact.source_call_target == 0x1446
    assert fact.source_call_name == "clock"
    assert fact.ins_addr == 0x1014


def test_direct_stack_instruction_facts_deduplicate_overlapping_linear_bytes():
    # call clock; add ax,[bp+4]; adc dx,[bp+6]; mov [bp-4],ax; mov [bp-2],dx
    code = bytes.fromhex("e838040346041356068946fc8956fe")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x100B, code)),
        kb=SimpleNamespace(labels={0x1446: "_clock"}),
    )
    project.arch.capstone.detail = True
    partial_insns = tuple(project.arch.capstone.disasm(code[:3], 0x100B))
    partial_block = SimpleNamespace(addr=0x100B, size=3, capstone=SimpleNamespace(insns=partial_insns))
    function = SimpleNamespace(addr=0x100B, size=len(code), name="sleep_like", blocks=(partial_block,))

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    assert facts[0].source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH
    assert facts[0].dst_offset == -4
    assert facts[0].source_call_name == "clock"


def test_direct_stack_instruction_facts_use_typed_zero_arg_callsite_for_unknown_callee():
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    code = bytes.fromhex("e838040346041356068946fc8956fe")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x100B, code)),
        kb=SimpleNamespace(functions=_Functions(), labels={}),
    )
    function = SimpleNamespace(addr=0x100B, size=len(code), name="sleep_like")
    summary = CallsiteSummary8616(
        callsite_addr=0x100B,
        target_addr=0x1446,
        return_addr=0x100E,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        return_shape="dx_ax",
    )

    assert _direct_stack_move_instruction_facts_8616(project, function) == ()

    facts = _direct_stack_move_instruction_facts_8616(
        project,
        function,
        {summary.callsite_addr: summary},
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH
    assert fact.source_call_name == "sub_1446"
    assert fact.source_call_target == 0x1446
    assert fact.source_offset == 4
    assert fact.dst_offset == -4
    assert fact.width == 4


def test_direct_stack_move_instruction_facts_collect_signed_byte_stack_source():
    load_byte = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AL, size=1), _bp_mem_operand(-8, size=1)),
    )
    sign_extend = SimpleNamespace(address=0x4013, id=X86_INS_CBW, operands=())
    store = SimpleNamespace(
        address=0x4014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _reg_operand(X86_REG_AX)),
    )
    project = SimpleNamespace(arch=Arch86_16())
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load_byte, sign_extend, store))),),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.dst_offset == -6
    assert fact.width == 2
    assert fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT
    assert fact.source_offset == -8
    assert fact.source_access_width == 1
    assert fact.source_sign_extend is True
    assert fact.ins_addr == 0x4014


def test_materialize_direct_stack_mov_reload_preserves_stack_slot_identity():
    project, codegen = _project()
    source_var = SimStackVariable(-8, 2, base="bp", name="barTemp", region=0x4010)
    target_var = SimStackVariable(-6, 2, base="bp", name="iLength", region=0x4010)
    source_cvar = CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_cvar = CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    ax_cvar = _reg(project, "ax", codegen)
    codegen.cfunc.variables_in_use[source_var] = source_cvar
    codegen.cfunc.variables_in_use[target_var] = target_cvar

    tagged_store = CAssignment(
        target_cvar,
        ax_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x4014},
    )
    guard = CIfElse(
        [
            (
                CBinaryOp(
                    "CmpLE",
                    ax_cvar,
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    # This guard models the folded reload, not an unproven later register use.
    guard.tags = {"ins_addr": 0x4017}
    codegen.cfunc.statements.statements.extend((tagged_store, guard))

    load_byte = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AL, size=1), _bp_mem_operand(-8, size=1)),
    )
    sign_extend = SimpleNamespace(address=0x4013, id=X86_INS_CBW, operands=())
    store = SimpleNamespace(
        address=0x4014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _reg_operand(X86_REG_AX)),
    )
    reload = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-6)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(load_byte, sign_extend, store, reload),
                )
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    stack_store, register_reload, final_guard = codegen.cfunc.statements.statements
    assert isinstance(stack_store, CAssignment)
    assert stack_store.lhs is target_cvar
    assert isinstance(stack_store.rhs, CTypeCast)
    assert isinstance(stack_store.rhs.dst_type, SimTypeChar)
    assert stack_store.rhs.dst_type.signed is True
    assert stack_store.rhs.expr is source_cvar
    assert isinstance(register_reload, CAssignment)
    assert register_reload.lhs.variable.name == "ax"
    assert register_reload.rhs is target_cvar
    assert final_guard is guard
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["reload_materialized_count"] == 1
    assert stats["reload_failure_count"] == 0


def test_register_read_classification_reuses_memoized_subtree(monkeypatch):
    project, codegen = _project()
    ax_cvar = _reg(project, "ax", codegen)
    expr = CBinaryOp(
        "Add",
        ax_cvar,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    classifications = 0
    original = real_mode_linear._same_register_cvar_name_8616

    def count_classification(node, reg_name):
        nonlocal classifications
        classifications += 1
        return original(node, reg_name)

    monkeypatch.setattr(real_mode_linear, "_same_register_cvar_name_8616", count_classification)
    memo: dict[int, bool] = {}

    assert real_mode_linear._node_reads_register_name_8616(expr, "ax", memo=memo) is True
    first_classifications = classifications
    assert real_mode_linear._node_reads_register_name_8616(expr, "ax", memo=memo) is True

    assert first_classifications == 1
    assert classifications == first_classifications


def test_direct_stack_move_signed_byte_source_projects_promoted_aggregate_field():
    project, codegen = _project()
    aggregate_type = SimStruct(
        OrderedDict((('field_0', SimTypeChar(False)), ('field_1', SimTypeChar(False)))),
        name='work_entry',
        pack=True,
    ).with_arch(project.arch)
    source_var = SimStackVariable(-8, 2, base="bp", name="barTemp", region=0x4010)
    source = CVariable(source_var, variable_type=aggregate_type, codegen=codegen)
    codegen.cfunc.variables_in_use[source_var] = source
    fact = real_mode_linear.DirectStackMoveFact8616(
        dst_offset=-6,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.STACK_SLOT,
        ins_addr=0x4014,
        source_offset=-8,
        source_access_width=1,
        source_sign_extend=True,
    )

    expr = real_mode_linear._direct_stack_move_source_expr_8616(codegen, fact)

    assert isinstance(expr, CTypeCast)
    assert isinstance(expr.expr, CVariableField)
    assert expr.expr.variable is source
    assert expr.expr.field.field == "field_0"


def test_direct_stack_move_signed_word_arg_source_projects_local_slot():
    project, codegen = _project()
    codegen.cfunc.functy = SimTypeFunction(
        (SimTypeShort(True).with_arch(project.arch), SimTypeShort(False).with_arch(project.arch)),
        SimTypeShort(False),
        arg_names=("a", "b"),
    ).with_arch(project.arch)
    source_var = SimStackVariable(4, 2, base="bp", name="a", region=0x4010)
    source_cvar = CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)
    local_var = SimStackVariable(-6, 2, base="bp", name="local_6", region=0x4010)
    local_cvar = CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[source_var] = source_cvar
    codegen.cfunc.variables_in_use[local_var] = local_cvar

    load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    store = SimpleNamespace(
        address=0x4012,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),),
    )
    def place_assignment(_fact, assignment):
        codegen.cfunc.statements.statements.append(assignment)
        return True

    codegen._inertia_direct_stack_move_branch_placement_service_8616 = place_assignment

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements
    assignment = codegen.cfunc.statements.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs is local_cvar
    assert assignment.lhs.variable_type == SimTypeShort(True).with_arch(project.arch)


def test_direct_stack_move_duplicate_check_matches_structural_indexed_rhs():
    project, codegen = _project()  # noqa: RUF059
    dst_var = SimStackVariable(-4, 2, base="bp", name="pivot", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    global_var = SimMemoryVariable(0x0BAA, 2, name="abarWork")
    index_var = SimStackVariable(6, 2, base="bp", name="iHigh", region=0x4010)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar

    existing_rhs = CIndexedVariable(
        CVariable(global_var, variable_type=SimTypeShort(False), codegen=codegen),
        CVariable(index_var, variable_type=SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(CAssignment(dst_cvar, existing_rhs, codegen=codegen))

    fresh_rhs = CIndexedVariable(
        CVariable(global_var, variable_type=SimTypeShort(False), codegen=codegen),
        CVariable(index_var, variable_type=SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    assert _tree_has_stack_move_assignment_8616(codegen.cfunc.statements, dst_cvar, fresh_rhs)


def test_direct_stack_move_duplicate_check_matches_structural_aggregate_field_rhs():
    project, codegen = _project()
    aggregate_type = SimStruct(
        OrderedDict((("field_0", SimTypeChar(False)), ("field_1", SimTypeChar(False)))),
        name="work_entry",
        pack=True,
    ).with_arch(project.arch)
    dst_var = SimStackVariable(-6, 2, base="bp", name="iLength", region=0x4010)
    source_var = SimStackVariable(-8, 2, base="bp", name="barTemp", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    source = CVariable(source_var, variable_type=aggregate_type, codegen=codegen)
    existing_rhs = CVariableField(
        source,
        CStructField(aggregate_type, 0, "field_0", codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(CAssignment(dst_cvar, existing_rhs, codegen=codegen))
    fresh_source = CVariable(source_var, variable_type=aggregate_type, codegen=codegen)
    fresh_rhs = CVariableField(
        fresh_source,
        CStructField(aggregate_type, 0, "field_0", codegen=codegen),
        codegen=codegen,
    )

    assert _tree_has_stack_move_assignment_8616(codegen.cfunc.statements, dst_cvar, fresh_rhs)


def test_direct_stack_move_duplicate_check_matches_instruction_and_destination():
    project, codegen = _project()
    dst_var = SimStackVariable(-4, 2, base="bp", name="pivot", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    existing = CAssignment(
        dst_cvar,
        CVariable(SimMemoryVariable(0x0BAA, 2, name="abarWork"), variable_type=SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x106E},
    )
    codegen.cfunc.statements.statements.append(existing)

    assert _tree_has_stack_assignment_for_instruction_addr_8616(
        codegen.cfunc.statements,
        project,
        0x106E,
        dst_cvar,
    )


def test_direct_stack_move_wide_call_return_uses_original_project_for_rebased_call_target():
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    original_project = SimpleNamespace(
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1137E: "_clock"}),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=_Functions()),
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0xFF38,
    )
    call = SimpleNamespace(address=0x100B, id=X86_INS_CALL, operands=(_imm_operand(0x1446),))
    add = SimpleNamespace(
        address=0x100E,
        id=X86_INS_ADD,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    adc = SimpleNamespace(
        address=0x1011,
        id=X86_INS_ADC,
        operands=(_reg_operand(X86_REG_DX), _bp_mem_operand(6)),
    )
    mov_lo = SimpleNamespace(
        address=0x1014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    mov_hi = SimpleNamespace(
        address=0x1017,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(capstone=SimpleNamespace(insns=(add, adc, mov_lo, mov_hi))),
        )
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH
    assert fact.dst_offset == -4
    assert fact.width == 4
    assert fact.source_offset == 4
    assert fact.source_call_target == 0x1137E
    assert fact.source_call_name == "clock"
    assert fact.source_call_ins_addr == 0x100B
    assert fact.source_low_arith_ins_addr == 0x100E
    assert fact.source_high_arith_ins_addr == 0x1011
    assert fact.dst_high_ins_addr == 0x1017


def test_materialize_wide_call_return_consumes_following_low_half_call_assignment():
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    project, codegen = _project()
    original_project = SimpleNamespace(
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1137E: "_clock"}),
    )
    project.kb = SimpleNamespace(functions=_Functions(), labels={})
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0xFF38
    low_goal = CVariable(
        SimStackVariable(-4, 2, base="bp", name="goal"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.extend(
        [
            CAssignment(low_goal, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CAssignment(
                low_goal,
                CFunctionCall("clock", None, [], codegen=codegen),
                codegen=codegen,
                tags={"ins_addr": 0x100B},
            ),
        ]
    )
    call = SimpleNamespace(address=0x100B, id=X86_INS_CALL, operands=(_imm_operand(0x1446),))
    add = SimpleNamespace(
        address=0x100E,
        id=X86_INS_ADD,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    adc = SimpleNamespace(
        address=0x1011,
        id=X86_INS_ADC,
        operands=(_reg_operand(X86_REG_DX), _bp_mem_operand(6)),
    )
    mov_lo = SimpleNamespace(
        address=0x1014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    mov_hi = SimpleNamespace(
        address=0x1017,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(capstone=SimpleNamespace(insns=(add, adc, mov_lo, mov_hi))),
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert isinstance(stmt.rhs, CBinaryOp)
    assert isinstance(stmt.lhs.variable, SimStackVariable)
    assert stmt.lhs.variable.size == 4
    assert stmt.rhs.op == "Add"
    assert isinstance(stmt.rhs.lhs, CFunctionCall)
    assert stmt.rhs.lhs.callee_target == "clock"
    assert stmt.rhs.lhs.tags["ins_addr"] == 0x100B

    replayed_carrier = CAssignment(
        low_goal,
        CFunctionCall("clock", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100B},
    )
    codegen.cfunc.statements.statements.append(replayed_carrier)

    replay_changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert replay_changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assert replayed_carrier not in codegen.cfunc.statements.statements


def test_materialize_wide_call_return_replaces_degraded_call_statement():
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    project, codegen = _project()
    original_project = SimpleNamespace(
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1137E: "_clock"}),
    )
    project.kb = SimpleNamespace(functions=_Functions(), labels={})
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0xFF38
    degraded_call = CFunctionCall(
        "clock",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x100B},
    )
    codegen.cfunc.statements.statements.append(degraded_call)
    call = SimpleNamespace(address=0x100B, id=X86_INS_CALL, operands=(_imm_operand(0x1446),))
    add = SimpleNamespace(
        address=0x100E,
        id=X86_INS_ADD,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    adc = SimpleNamespace(
        address=0x1011,
        id=X86_INS_ADC,
        operands=(_reg_operand(X86_REG_DX), _bp_mem_operand(6)),
    )
    mov_lo = SimpleNamespace(
        address=0x1014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    mov_hi = SimpleNamespace(
        address=0x1017,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(capstone=SimpleNamespace(insns=(add, adc, mov_lo, mov_hi))),
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert isinstance(stmt.lhs.variable, SimStackVariable)
    assert stmt.lhs.variable.size == 4
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert isinstance(stmt.rhs.lhs, CFunctionCall)
    assert stmt.rhs.lhs.callee_target == "clock"
    assert stmt.rhs.lhs.tags["ins_addr"] == 0x100B
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["wide_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0

    replayed_call = CFunctionCall(
        "clock",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x100B},
    )
    codegen.cfunc.statements.statements.append(replayed_call)

    replay_changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert replay_changed is True
    assert codegen.cfunc.statements.statements == [stmt]
    assert stats["wide_call_statement_materialized_count"] == 1
    assert stats["wide_call_replay_pruned_count"] == 1
    assert stats["already_materialized_count"] == 1


def test_materialize_wide_call_return_consumes_exact_split_word_decomposition():
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    project, codegen = _project()
    original_project = SimpleNamespace(
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1137E: "_clock"}),
    )
    project.kb = SimpleNamespace(functions=_Functions(), labels={})
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0xFF38
    low_goal = CVariable(
        SimStackVariable(-4, 2, base="bp", name="goal"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    add_result = CVariable(
        SimRegisterVariable(0, 2, name="ax_after_add"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_result = CVariable(
        SimRegisterVariable(4, 2, name="dx_after_adc"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_goal = CVariable(
        SimStackVariable(-2, 2, base="bp", name="goal_high"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stale_low_goal = CVariable(
        SimStackVariable(2, 2, base="bp", name="misbound_goal_low"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    unrelated_result = CVariable(
        SimRegisterVariable(8, 2, name="unrelated"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    side_effect_result = CVariable(
        SimRegisterVariable(10, 2, name="side_effect_result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    low_call = CAssignment(
        low_goal,
        CFunctionCall("clock", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100B},
    )
    add_residue = CAssignment(
        add_result,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100E},
    )
    adc_residue = CAssignment(
        high_result,
        add_result,
        codegen=codegen,
        tags={"ins_addr": 0x1011},
    )
    high_store_residue = CAssignment(
        high_goal,
        high_result,
        codegen=codegen,
        tags={"ins_addr": 0x1017},
    )
    low_store_residue = CAssignment(
        stale_low_goal,
        add_result,
        codegen=codegen,
        tags={"ins_addr": 0x1014},
    )
    unrelated = CAssignment(
        unrelated_result,
        CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1012},
    )
    side_effecting = CAssignment(
        side_effect_result,
        CFunctionCall("observe", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100E},
    )
    codegen.cfunc.statements.statements.extend(
        [
            low_call,
            add_residue,
            adc_residue,
            low_store_residue,
            high_store_residue,
            unrelated,
            side_effecting,
        ]
    )
    call = SimpleNamespace(address=0x100B, id=X86_INS_CALL, operands=(_imm_operand(0x1446),))
    add = SimpleNamespace(
        address=0x100E,
        id=X86_INS_ADD,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    adc = SimpleNamespace(
        address=0x1011,
        id=X86_INS_ADC,
        operands=(_reg_operand(X86_REG_DX), _bp_mem_operand(6)),
    )
    mov_lo = SimpleNamespace(
        address=0x1014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    mov_hi = SimpleNamespace(
        address=0x1017,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(capstone=SimpleNamespace(insns=(add, adc, mov_lo, mov_hi))),
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert add_residue not in statements
    assert adc_residue not in statements
    assert low_store_residue not in statements
    assert high_store_residue not in statements
    assert unrelated in statements
    assert side_effecting in statements
    assert codegen._inertia_direct_stack_move_lowering_8616["wide_call_decomposition_pruned_count"] == 4


def test_materialize_wide_call_return_rebinds_later_low_half_condition_read():
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    project, codegen = _project()
    original_project = SimpleNamespace(
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1137E: "_clock"}),
    )
    project.kb = SimpleNamespace(functions=_Functions(), labels={})
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0xFF38
    low_goal = CVariable(
        SimStackVariable(-4, 2, base="bp", name="goal"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    low_assign = CAssignment(low_goal, CFunctionCall("clock", None, [], codegen=codegen), codegen=codegen)
    condition = CBinaryOp(
        "CmpLE",
        CFunctionCall("clock", None, [], codegen=codegen),
        low_goal,
        codegen=codegen,
    )
    loop = CWhileLoop(condition, CStatements([], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements.extend([low_assign, loop])
    call = SimpleNamespace(address=0x100B, id=X86_INS_CALL, operands=(_imm_operand(0x1446),))
    add = SimpleNamespace(
        address=0x100E,
        id=X86_INS_ADD,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    adc = SimpleNamespace(
        address=0x1011,
        id=X86_INS_ADC,
        operands=(_reg_operand(X86_REG_DX), _bp_mem_operand(6)),
    )
    mov_lo = SimpleNamespace(
        address=0x1014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    mov_hi = SimpleNamespace(
        address=0x1017,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(capstone=SimpleNamespace(insns=(add, adc, mov_lo, mov_hi))),
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert isinstance(stmt.lhs.variable, SimStackVariable)
    assert stmt.lhs.variable.size == 4
    assert isinstance(loop.condition.rhs, CBinaryOp)
    assert loop.condition.rhs.op == "And"
    assert isinstance(loop.condition.rhs.lhs, CVariable)
    assert loop.condition.rhs.lhs.variable is stmt.lhs.variable
    assert loop.condition.rhs.lhs.variable.size == 4


def test_materialize_direct_global_inc_instruction_from_binary_evidence():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})
    placeholder_var = SimRegisterVariable(0, 2, name="ax")
    placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            placeholder,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable.name == "counter"
    assert stmt.lhs.variable.addr == 0x1234
    assert stmt.lhs.tags["ins_addr"] == 0x4018
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert stmt.rhs.lhs.tags["ins_addr"] == 0x4018
    assert global_storage_identity_facts_8616(codegen) == (
        GlobalStorageIdentityFact8616(
            space=MemSpace.DS,
            offset=0x1234,
            width=2,
            name="counter",
            evidence_addr=0x4018,
            kind=StorageIdentityEvidenceKind8616.DIRECT_GLOBAL_UPDATE,
        ),
    )


def test_materialize_direct_global_update_replaces_switch_case_tag_in_place():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})
    placeholder = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    tagged_assignment = CAssignment(
        placeholder,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    case_body = CStatements([tagged_assignment], codegen=codegen)
    switch = CSwitchCase(_const(1, codegen), [(1, case_body)], None, codegen=codegen)
    codegen.cfunc.statements.statements.append(switch)
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),),
    )

    changed = materialize_direct_global_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == [switch]
    assert len(case_body.statements) == 1
    materialized = case_body.statements[0]
    assert isinstance(materialized, CAssignment)
    assert materialized.lhs.variable.name == "counter"
    assert materialized.tags["ins_addr"] == 0x4018
    assert codegen._inertia_direct_global_update_lowering_8616["replaced_count"] == 1
    assert codegen._inertia_direct_global_update_lowering_8616["inserted_count"] == 0


def test_direct_global_update_replay_preserves_binary_proven_dword_carry():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x132: "g_0132"})
    dword_var = SimMemoryVariable(0x132, 4, name="g_0132", region=0x4010)
    dword_cvar = CVariable(
        dword_var,
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    dword_update = CAssignment(
        dword_cvar,
        CBinaryOp(
            "Add",
            dword_cvar,
            CConstant(30, SimTypeLong(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    case_body = CStatements([dword_update], codegen=codegen)
    switch = CSwitchCase(_const(1, codegen), [(1, case_body)], None, codegen=codegen)
    codegen.cfunc.statements.statements.append(switch)
    low_mem = SimpleNamespace(
        base=X86_REG_INVALID,
        index=X86_REG_INVALID,
        disp=0x132,
    )
    high_mem = SimpleNamespace(
        base=X86_REG_INVALID,
        index=X86_REG_INVALID,
        disp=0x134,
    )
    low = SimpleNamespace(
        address=0x4018,
        size=5,
        id=X86_INS_ADD,
        operands=(
            SimpleNamespace(type=X86_OP_MEM, size=2, mem=low_mem),
            _imm_operand(30),
        ),
    )
    high = SimpleNamespace(
        address=0x401D,
        size=5,
        id=X86_INS_ADC,
        operands=(
            SimpleNamespace(type=X86_OP_MEM, size=2, mem=high_mem),
            _imm_operand(0),
        ),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(low, high))),),
    )

    changed = materialize_direct_global_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is False
    assert case_body.statements == [dword_update]
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["already_materialized_count"] == 1
    assert stats["consumed_fact_count"] == 1
    assert stats["replaced_count"] == 0


def test_materialize_direct_global_inc_instruction_is_idempotent():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})
    placeholder_var = SimRegisterVariable(0, 2, name="ax")
    placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            placeholder,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    first_changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)
    first_stmt = codegen.cfunc.statements.statements[0]
    second_changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert first_changed is True
    assert second_changed is False
    assert codegen.cfunc.statements.statements[0] is first_stmt
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["materialized_count"] == 1
    assert stats["already_materialized_count"] == 1
    assert stats["failure_count"] == 0
    assert global_storage_identity_facts_8616(codegen) == (
        GlobalStorageIdentityFact8616(
            space=MemSpace.DS,
            offset=0x1234,
            width=2,
            name="counter",
            evidence_addr=0x4018,
            kind=StorageIdentityEvidenceKind8616.DIRECT_GLOBAL_UPDATE,
        ),
    )


def test_materialize_direct_global_add_refuses_duplicate_rebased_global_assignment():
    project, codegen = _project()
    existing_var = SimMemoryVariable(0x10048, 2, name="seen", region=0x4010)
    existing_cvar = CVariable(existing_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[existing_var] = existing_cvar
    codegen.cfunc.unified_local_vars[existing_var] = {(existing_cvar, SimTypeShort(False))}
    codegen.cfunc.statements.statements.append(
        CAssignment(
            existing_cvar,
            CBinaryOp(
                "Add",
                existing_cvar,
                CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x0048)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=2)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_ADD, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 1
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["already_materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_global_add_renames_generated_target_to_same_addr_source_name():
    project, codegen = _project()
    generated_var = SimMemoryVariable(0x0048, 2, name="g_48", region=0x4010)
    generated = CVariable(generated_var, variable_type=SimTypeShort(False), codegen=codegen)
    source_var = SimMemoryVariable(0x0048, 2, name="_S104_seen", region=0x4010)
    source = CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            generated,
            CBinaryOp(
                "Add",
                source,
                CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x0048)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=2)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_ADD, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable.name == "_S104_seen"
    assert stmt.rhs.lhs.variable.name == "_S104_seen"
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["already_materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_global_inc_consumes_one_fact_once_for_duplicate_tags():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})
    for reg_name in ("ax", "bx"):
        placeholder_var = SimRegisterVariable(0, 2, name=reg_name)
        placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
        codegen.cfunc.statements.statements.append(
            CAssignment(
                placeholder,
                CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
                tags={"ins_addr": 0x4018},
            )
        )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    materialized = [
        stmt
        for stmt in statements
        if isinstance(stmt, CAssignment)
        and isinstance(getattr(stmt, "lhs", None), CVariable)
        and stmt.lhs.variable.name == "counter"
    ]
    assert len(materialized) == 1
    stmt = materialized[0]
    assert stmt.lhs.variable.addr == 0x1234
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"

    second_changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert second_changed is False
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    materialized = [
        stmt
        for stmt in statements
        if isinstance(stmt, CAssignment)
        and isinstance(getattr(stmt, "lhs", None), CVariable)
        and stmt.lhs.variable.name == "counter"
    ]
    assert len(materialized) == 1
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["materialized_count"] == 1
    assert stats["consumed_fact_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_global_inc_materializes_distinct_same_global_facts():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})
    for ins_addr, reg_name in ((0x4018, "ax"), (0x4020, "bx")):
        placeholder_var = SimRegisterVariable(0, 2, name=reg_name)
        placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
        codegen.cfunc.statements.statements.append(
            CAssignment(
                placeholder,
                CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
                tags={"ins_addr": ins_addr},
            )
        )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    first_insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    second_insn = SimpleNamespace(address=0x4020, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(first_insn, second_insn))),),
    )

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    materialized = [
        stmt
        for stmt in codegen.cfunc.statements.statements
        if isinstance(stmt, CAssignment)
        and isinstance(getattr(stmt, "lhs", None), CVariable)
        and stmt.lhs.variable.name == "counter"
    ]
    assert len(materialized) == 2
    assert {stmt.tags["ins_addr"] for stmt in materialized} == {0x4018, 0x4020}
    assert all(isinstance(stmt.rhs, CBinaryOp) and stmt.rhs.op == "Add" for stmt in materialized)

    second_changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert second_changed is False
    assert len(
        [
            stmt
            for stmt in codegen.cfunc.statements.statements
            if isinstance(stmt, CAssignment)
            and isinstance(getattr(stmt, "lhs", None), CVariable)
            and stmt.lhs.variable.name == "counter"
        ]
    ) == 2
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["materialized_count"] == 2
    assert stats["consumed_fact_count"] == 2
    assert stats["failure_count"] == 0


def test_materialize_direct_global_inc_refuses_guard_condition_rewrite():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})

    placeholder_var = SimRegisterVariable(0, 2, name="ax")
    statement_placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    condition_placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    statement_assignment = CAssignment(
        statement_placeholder,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    condition_assignment = CAssignment(
        condition_placeholder,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    if_stmt = CIfElse([(condition_assignment, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition = condition_assignment
    codegen.cfunc.statements.statements.extend([statement_assignment, if_stmt])

    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs.variable.name == "counter"
    assert if_stmt.condition is condition_assignment
    assert if_stmt.condition_and_nodes[0][0] is condition_assignment


def test_materialize_direct_global_add_immediate_instruction_from_binary_evidence():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x0048: "seen"})
    placeholder_var = SimRegisterVariable(0, 2, name="ax")
    placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            placeholder,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x0048)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=2)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_ADD, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable.name == "seen"
    assert stmt.lhs.variable.addr == 0x0048
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert stmt.rhs.rhs.value == 2


def test_materialize_direct_global_inc_redecodes_blocks_without_capstone_details():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})
    placeholder_var = SimRegisterVariable(0, 2, name="ax")
    placeholder = CVariable(placeholder_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            placeholder,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    decoded_block = SimpleNamespace(capstone=SimpleNamespace(insns=(insn,)))
    project.factory = SimpleNamespace(block=lambda *_args, **_kwargs: decoded_block)
    sparse_block = SimpleNamespace(addr=0x4010, size=4, capstone=SimpleNamespace(insns=()))
    function = SimpleNamespace(addr=0x4010, blocks=(sparse_block,))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable.name == "counter"
    assert stmt.lhs.variable.addr == 0x1234


def test_materialize_direct_global_inc_refuses_without_tagged_site():
    project, codegen = _project()
    unknown_call = SimpleNamespace(address=0x4014, id=X86_INS_CALL, operands=(_imm_operand(0x2000),))
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(
        addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(unknown_call, insn))),)
    )

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen.cfunc.statements.statements == []


def test_materialize_direct_global_inc_inserts_before_next_tagged_statement():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})
    later_var = SimRegisterVariable(0, 2, name="ax")
    later = CVariable(later_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            later,
            CConstant(7, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4020},
        )
    )
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    inserted = statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable.name == "counter"
    assert inserted.lhs.variable.addr == 0x1234
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Add"
    assert statements[1].lhs.variable.name == "ax"
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["materialized_count"] == 1
    assert stats["inserted_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_global_inc_stays_inside_binary_proven_inner_loop():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})
    condition = CBinaryOp(
        "CmpLE",
        _reg(project, "ax", codegen),
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1058},
    )
    guard = CIfElse(
        [(condition, CStatements([], codegen=codegen))],
        codegen=codegen,
    )
    inner_loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x1041}),
        None,
        guard,
        codegen=codegen,
    )
    outer_body = CStatements([inner_loop], codegen=codegen)
    outer_loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x101D}),
        None,
        outer_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(outer_loop)

    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    update = SimpleNamespace(
        address=0x104A,
        id=X86_INS_INC,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem),),
        groups=(),
    )
    inner_backedge = SimpleNamespace(
        address=0x1085,
        id=0,
        operands=(_imm_operand(0x103E),),
        groups=(X86_GRP_JUMP,),
    )
    outer_backedge = SimpleNamespace(
        address=0x10AC,
        id=0,
        operands=(_imm_operand(0x1013),),
        groups=(X86_GRP_JUMP,),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(update, inner_backedge, outer_backedge)),
            ),
        ),
    )

    changed = materialize_direct_global_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert outer_body.statements == [inner_loop]
    assert isinstance(inner_loop.body, CStatements)
    assert len(inner_loop.body.statements) == 2
    inserted = inner_loop.body.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable.name == "counter"
    assert inner_loop.body.statements[1] is guard
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["loop_inserted_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_global_inc_refuses_outer_backedge_as_inner_scope_proof():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x1234: "counter"})
    condition = CBinaryOp(
        "CmpLE",
        _reg(project, "ax", codegen),
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1058},
    )
    guard = CIfElse(
        [(condition, CStatements([], codegen=codegen))],
        codegen=codegen,
    )
    inner_loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x1041}),
        None,
        guard,
        codegen=codegen,
    )
    outer_body = CStatements([inner_loop], codegen=codegen)
    outer_loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x101D}),
        None,
        outer_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(outer_loop)

    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    update = SimpleNamespace(
        address=0x104A,
        id=X86_INS_INC,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem),),
        groups=(),
    )
    outer_backedge = SimpleNamespace(
        address=0x10AC,
        id=0,
        operands=(_imm_operand(0x1013),),
        groups=(X86_GRP_JUMP,),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(update, outer_backedge))),),
    )

    changed = materialize_direct_global_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is False
    assert outer_body.statements == [inner_loop]
    assert inner_loop.body is guard
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["loop_inserted_count"] == 0
    assert stats["failure_count"] == 1


def test_materialize_direct_global_inc_inserts_at_body_start_after_stack_probe_prefix_without_tags():
    project, codegen = _project()
    project.kb = SimpleNamespace(labels={0x2000: "aNchkstk", 0x1234: "counter"})
    later_var = SimRegisterVariable(0, 2, name="ax")
    later = CVariable(later_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(
            later,
            CConstant(7, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    )
    push_bp = SimpleNamespace(address=0x4010, id=X86_INS_PUSH, operands=(_reg_operand(X86_REG_BP),))
    mov_ax = SimpleNamespace(address=0x4011, id=X86_INS_MOV, operands=(_reg_operand(X86_REG_AX), _imm_operand(2)))
    call_probe = SimpleNamespace(address=0x4014, id=X86_INS_CALL, operands=(_imm_operand(0x2000),))
    mem = SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x1234)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    inc_global = SimpleNamespace(address=0x4017, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(push_bp, mov_ax, call_probe, inc_global))),),
    )

    changed = materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    inserted = statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable.name == "counter"
    assert inserted.lhs.variable.addr == 0x1234
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Add"
    assert statements[1].lhs.variable.name == "ax"
    stats = codegen._inertia_direct_global_update_lowering_8616
    assert stats["materialized_count"] == 1
    assert stats["body_start_inserted_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_inc_instruction_replaces_tagged_loop_iterator():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    init = CAssignment(stack_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    bad_iterator = CAssignment(
        stack_cvar,
        CBinaryOp("Shr", stack_cvar, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    loop = CForLoop(
        init,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        bad_iterator,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen._inertia_direct_stack_update_lowering_8616 == {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
        "refused_count": 0,
        "conflicting_tagged_assignment_removed_count": 0,
    }
    assert isinstance(loop.iterator, CAssignment)
    assert loop.iterator.lhs.variable is stack_var
    assert isinstance(loop.iterator.rhs, CBinaryOp)
    assert loop.iterator.rhs.op == "Add"
    assert loop.iterator.rhs.rhs.value == 1
    lane = codegen._inertia_direct_stack_update_lane_8616
    assert lane.raw == 1
    assert lane.normalized == 1
    assert lane.classified == 1
    assert lane.materialized == 1
    assert lane.failures == 0
    assert_pipeline_contracts_8616(codegen)


def test_materialize_direct_stack_inc_replaces_unique_dirty_rhs_tag_in_while_body():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}
    dirty_rhs = CDirtyExpression(
        SimpleNamespace(varid=17, name="vvar_17"),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    dirty_update = CAssignment(stack_cvar, dirty_rhs, codegen=codegen)
    loop_body = CStatements([dirty_update], codegen=codegen)
    loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        loop_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)
    update = SimpleNamespace(
        address=0x4018,
        id=X86_INS_INC,
        operands=(_bp_mem_operand(-2),),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(update,))),),
    )

    changed = materialize_direct_stack_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert len(loop_body.statements) == 1
    replacement = loop_body.statements[0]
    assert isinstance(replacement, CAssignment)
    assert replacement is not dirty_update
    assert replacement.lhs.variable is stack_var
    assert isinstance(replacement.rhs, CBinaryOp)
    assert replacement.rhs.op == "Add"
    assert replacement.rhs.lhs.variable is stack_var
    assert replacement.rhs.rhs.value == 1
    assert replacement.tags == {"ins_addr": 0x4018}
    assert codegen._inertia_direct_stack_update_lowering_8616["materialized_count"] == 1
    assert codegen._inertia_direct_stack_update_lowering_8616["failure_count"] == 0


def test_materialize_direct_stack_inc_refuses_duplicate_dirty_rhs_tags():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}
    dirty_updates = tuple(
        CAssignment(
            stack_cvar,
            CDirtyExpression(
                SimpleNamespace(varid=varid, name=f"vvar_{varid}"),
                codegen=codegen,
                tags={"ins_addr": 0x4018},
            ),
            codegen=codegen,
        )
        for varid in (17, 18)
    )
    codegen.cfunc.statements.statements.extend(dirty_updates)
    update = SimpleNamespace(
        address=0x4018,
        id=X86_INS_INC,
        operands=(_bp_mem_operand(-2),),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(update,))),),
    )

    changed = materialize_direct_stack_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is False
    assert tuple(codegen.cfunc.statements.statements) == dirty_updates
    assert codegen._inertia_direct_stack_update_lowering_8616["materialized_count"] == 0
    assert codegen._inertia_direct_stack_update_lowering_8616["failure_count"] == 1


def test_materialize_direct_stack_inc_does_not_reuse_untagged_update_across_two_sites():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}
    existing = CAssignment(
        stack_cvar,
        CBinaryOp(
            "Add",
            stack_cvar,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(existing)
    updates = tuple(
        SimpleNamespace(
            address=address,
            id=X86_INS_INC,
            operands=(_bp_mem_operand(-2),),
        )
        for address in (0x4018, 0x4028)
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=updates)),),
    )

    changed = materialize_direct_stack_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [existing]
    assert codegen._inertia_direct_stack_update_lowering_8616["raw_fact_count"] == 2
    assert codegen._inertia_direct_stack_update_lowering_8616["materialized_count"] == 0
    assert codegen._inertia_direct_stack_update_lowering_8616["failure_count"] == 2


def test_materialize_repeated_direct_stack_inc_replaces_each_binary_anchored_while_latch():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}
    loops = []
    instructions = []
    dirty_updates = []
    for update_addr in (0x4018, 0x4028):
        guard_addr = update_addr + 1
        guard = CIfElse(
            [
                (
                    CBinaryOp(
                        "CmpLT",
                        stack_cvar,
                        CConstant(7, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                        tags={"ins_addr": guard_addr},
                    ),
                    CStatements([], codegen=codegen),
                )
            ],
            codegen=codegen,
        )
        dirty_update = CAssignment(
            stack_cvar,
            CDirtyExpression(
                SimpleNamespace(varid=update_addr, name=f"vvar_{update_addr:x}"),
                codegen=codegen,
            ),
            codegen=codegen,
        )
        loop_body = CStatements([guard, dirty_update], codegen=codegen)
        loop = CWhileLoop(
            CConstant(1, SimTypeShort(False), codegen=codegen),
            loop_body,
            codegen=codegen,
        )
        codegen.cfunc.statements.statements.append(loop)
        loops.append(loop)
        dirty_updates.append(dirty_update)
        instructions.extend(
            (
                SimpleNamespace(
                    address=update_addr,
                    size=1,
                    id=X86_INS_INC,
                    operands=(_bp_mem_operand(-2),),
                ),
                SimpleNamespace(
                    address=guard_addr,
                    size=2,
                    operands=(_bp_mem_operand(-2),),
                ),
            )
        )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=tuple(instructions)),
            ),
        ),
    )

    changed = materialize_direct_stack_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    for loop, dirty_update, update_addr in zip(
        loops,
        dirty_updates,
        (0x4018, 0x4028),
        strict=True,
    ):
        replacement = loop.body.statements[1]
        assert isinstance(replacement, CAssignment)
        assert replacement is not dirty_update
        assert replacement.lhs.variable is stack_var
        assert isinstance(replacement.rhs, CBinaryOp)
        assert replacement.rhs.op == "Add"
        assert replacement.rhs.lhs.variable is stack_var
        assert replacement.rhs.rhs.value == 1
        assert replacement.tags == {"ins_addr": update_addr}
    stats = codegen._inertia_direct_stack_update_lowering_8616
    assert stats["raw_fact_count"] == 2
    assert stats["materialized_count"] == 2
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_inc_removes_disproven_tagged_body_alias_after_proven_iterator():
    project, codegen = _project()
    iterator_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stale_var = SimStackVariable(-4, 2, base="bp", name="stale", region=0x4010)
    iterator_cvar = CVariable(iterator_var, variable_type=SimTypeShort(False), codegen=codegen)
    stale_cvar = CVariable(stale_var, variable_type=SimTypeShort(False), codegen=codegen)
    register_cvar = _reg(project, "dx", codegen)
    for stack_var, stack_cvar in ((iterator_var, iterator_cvar), (stale_var, stale_cvar)):
        codegen.cfunc.variables_in_use[stack_var] = stack_cvar
        codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    initializer = CAssignment(
        iterator_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    iterator = CAssignment(
        iterator_cvar,
        CBinaryOp(
            "Add",
            iterator_cvar,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    stale_alias = CAssignment(
        stale_cvar,
        CBinaryOp(
            "Add",
            stale_cvar,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    differently_tagged_stack_write = CAssignment(
        stale_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4019},
    )
    same_tag_register_write = CAssignment(
        register_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    body = CStatements(
        [stale_alias, differently_tagged_stack_write, same_tag_register_write],
        codegen=codegen,
    )
    loop = CForLoop(
        initializer,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        iterator,
        body,
        codegen=codegen,
    )
    loop.tags["ins_addr"] = 0x401B
    codegen.cfunc.statements.statements.append(loop)

    update = SimpleNamespace(
        address=0x4018,
        size=3,
        id=X86_INS_INC,
        operands=(_bp_mem_operand(-2),),
    )
    guard = SimpleNamespace(
        address=0x401B,
        size=3,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2)),
    )
    instructions = (update, guard)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    changed = materialize_direct_stack_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert loop.iterator is iterator
    assert body.statements == [differently_tagged_stack_write, same_tag_register_write]
    assert codegen._inertia_direct_stack_update_lowering_8616 == {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
        "refused_count": 0,
        "conflicting_tagged_assignment_removed_count": 1,
    }
    assert_pipeline_contracts_8616(codegen)


def test_materialize_direct_stack_inc_separates_shared_iterators_by_binary_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}
    placeholder_var = CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="high_byte_carrier"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    shared_iterator = CAssignment(
        placeholder_var,
        CBinaryOp(
            "Shr",
            placeholder_var,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )

    def make_loop(guard_addr: int) -> CForLoop:
        initializer = CAssignment(
            stack_cvar,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        condition = CVariable(
            stack_var,
            variable_type=SimTypeShort(False),
            codegen=codegen,
            tags={"ins_addr": guard_addr},
        )
        loop = CForLoop(
            initializer,
            condition,
            shared_iterator,
            CStatements([], codegen=codegen),
            codegen=codegen,
        )
        loop.tags["ins_addr"] = guard_addr
        return loop

    first_loop = make_loop(0x401B)
    second_loop = make_loop(0x403B)
    codegen.cfunc.statements.statements.extend((first_loop, second_loop))
    first_update = SimpleNamespace(
        address=0x4018,
        size=3,
        id=X86_INS_INC,
        operands=(_bp_mem_operand(-2),),
    )
    first_guard = SimpleNamespace(
        address=0x401B,
        size=3,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2)),
    )
    second_update = SimpleNamespace(
        address=0x4038,
        size=3,
        id=X86_INS_INC,
        operands=(_bp_mem_operand(-2),),
    )
    second_guard = SimpleNamespace(
        address=0x403B,
        size=3,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2)),
    )
    instructions = (first_update, first_guard, second_update, second_guard)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_direct_global_update_ordered_insns_8616",
        lambda _project_obj, _function_obj: instructions,
    )

    changed = materialize_direct_stack_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert first_loop.iterator is not second_loop.iterator
    for loop, expected_addr in ((first_loop, 0x4018), (second_loop, 0x4038)):
        assert isinstance(loop.iterator, CAssignment)
        assert loop.iterator.tags["ins_addr"] == expected_addr
        assert loop.iterator.lhs.variable is stack_var
        assert isinstance(loop.iterator.rhs, CBinaryOp)
        assert loop.iterator.rhs.op == "Add"
        assert loop.iterator.rhs.rhs.value == 1
    assert codegen.cfunc.statements.statements == [first_loop, second_loop]
    stats = codegen._inertia_direct_stack_update_lowering_8616
    assert stats["raw_fact_count"] == 2
    assert stats["classified_fact_count"] == 2
    assert stats["materialized_count"] == 2
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_inc_instruction_replaces_tagged_iterator_expression():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    init = CAssignment(stack_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    placeholder_var = CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="i"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    placeholder_var.tags = {"ins_addr": 0x4018}
    loop = CForLoop(
        init,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        placeholder_var,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert isinstance(loop.iterator, CAssignment)
    assert loop.iterator.lhs.variable is stack_var
    assert isinstance(loop.iterator.rhs, CBinaryOp)
    assert loop.iterator.rhs.op == "Add"
    assert loop.iterator.rhs.rhs.value == 1


def test_materialize_direct_stack_inc_instruction_inserts_at_loop_body_start_after_condition():
    project, codegen = _project()
    counter_var = SimStackVariable(-4, 2, base="bp", name="iCompares", region=0x4010)
    counter_cvar = CVariable(counter_var, variable_type=SimTypeShort(False), codegen=codegen)
    iter_var = SimStackVariable(-2, 2, base="bp", name="iRowNext", region=0x4010)
    iter_cvar = CVariable(iter_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[counter_var] = counter_cvar
    codegen.cfunc.variables_in_use[iter_var] = iter_cvar
    codegen.cfunc.unified_local_vars[counter_var] = {(counter_cvar, SimTypeShort(False))}

    condition = CBinaryOp(
        "CmpLT",
        iter_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4067},
    )
    call = CFunctionCall("DrawTime", None, [iter_cvar], codegen=codegen, tags={"ins_addr": 0x4095})
    guarded_body = CStatements([CExpressionStatement(call, codegen=codegen)], codegen=codegen)
    guarded = CIfElse(
        [(CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x4083}), guarded_body)],
        codegen=codegen,
    )
    loop_body = CStatements([guarded], codegen=codegen)
    loop = CForLoop(
        None,
        condition,
        None,
        loop_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    inc = SimpleNamespace(address=0x4072, id=X86_INS_INC, operands=(_bp_mem_operand(-4),))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(inc,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    inserted = loop_body.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is counter_var
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Add"
    assert loop_body.statements[1] is guarded


def test_materialize_direct_stack_inc_instruction_inserts_in_containing_loop_body():
    project, codegen = _project()
    counter_var = SimStackVariable(-4, 2, base="bp", name="iCompares", region=0x4010)
    counter_cvar = CVariable(counter_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[counter_var] = counter_cvar
    codegen.cfunc.unified_local_vars[counter_var] = {(counter_cvar, SimTypeShort(False))}

    prior = CAssignment(
        CVariable(SimStackVariable(-6, 2, base="bp", name="iRowMin"), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4060},
    )
    later = CFunctionCall("DrawTime", None, [], codegen=codegen, tags={"ins_addr": 0x4095})
    loop_body = CStatements([prior, CExpressionStatement(later, codegen=codegen)], codegen=codegen)
    loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        None,
        loop_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    inc = SimpleNamespace(address=0x4072, id=X86_INS_INC, operands=(_bp_mem_operand(-4),))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(inc,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    inserted = loop_body.statements[1]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is counter_var
    assert loop_body.statements[0] is prior
    assert isinstance(loop_body.statements[2], CExpressionStatement)


def test_materialize_direct_stack_inc_instruction_inserts_at_untagged_while_tail():
    project, codegen = _project()
    iter_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    iter_cvar = CVariable(iter_var, variable_type=SimTypeShort(False), codegen=codegen)
    limit_var = SimStackVariable(4, 2, base="bp", name="limit", region=0x4010)
    limit_cvar = CVariable(limit_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[iter_var] = iter_cvar
    codegen.cfunc.variables_in_use[limit_var] = limit_cvar
    codegen.cfunc.unified_local_vars[iter_var] = {(iter_cvar, SimTypeShort(False))}

    first_guard = CIfElse(
        [
            (
                CBinaryOp("CmpLE", limit_cvar, iter_cvar, codegen=codegen, tags={"ins_addr": 0x4081}),
                CStatements(
                    [
                        CExpressionStatement(
                            CFunctionCall("break_guard_a", None, [], codegen=codegen, tags={"ins_addr": 0x4088}),
                            codegen=codegen,
                        )
                    ],
                    codegen=codegen,
                ),
            )
        ],
        codegen=codegen,
    )
    second_guard = CIfElse(
        [
            (
                CBinaryOp("CmpGT", iter_cvar, CConstant(7, SimTypeShort(False), codegen=codegen), codegen=codegen, tags={"ins_addr": 0x4091}),
                CStatements(
                    [
                        CExpressionStatement(
                            CFunctionCall("break_guard_b", None, [], codegen=codegen, tags={"ins_addr": 0x4099}),
                            codegen=codegen,
                        )
                    ],
                    codegen=codegen,
                ),
            )
        ],
        codegen=codegen,
    )
    loop_body = CStatements([first_guard, second_guard], codegen=codegen)
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), loop_body, codegen=codegen)
    codegen.cfunc.statements.statements.append(loop)

    inc = SimpleNamespace(address=0x409e, id=X86_INS_INC, operands=(_bp_mem_operand(-2),))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(inc,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    inserted = loop_body.statements[-1]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is iter_var
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Add"
    assert inserted.rhs.rhs.value == 1
    assert loop_body.statements[:2] == [first_guard, second_guard]


def test_materialize_direct_stack_inc_ignores_unrendered_while_iterator_compat_field():
    project, codegen = _project()
    iter_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    iter_cvar = CVariable(iter_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[iter_var] = iter_cvar
    codegen.cfunc.unified_local_vars[iter_var] = {(iter_cvar, SimTypeShort(False))}
    hidden_update = CAssignment(
        iter_cvar,
        CBinaryOp(
            "Add",
            iter_cvar,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x409E},
    )
    visible_body_stmt = CExpressionStatement(
        CFunctionCall(
            "body_effect",
            None,
            [],
            codegen=codegen,
            tags={"ins_addr": 0x4099},
        ),
        codegen=codegen,
    )
    loop_body = CStatements([visible_body_stmt], codegen=codegen)
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), loop_body, codegen=codegen)
    loop.iteration = hidden_update
    codegen.cfunc.statements.statements.append(loop)
    inc = SimpleNamespace(address=0x409E, id=X86_INS_INC, operands=(_bp_mem_operand(-2),))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(inc,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert loop.iteration is hidden_update
    assert len(loop_body.statements) == 2
    assert loop_body.statements[0] is visible_body_stmt
    inserted = loop_body.statements[1]
    assert isinstance(inserted, CAssignment)
    assert inserted is not hidden_update
    assert inserted.lhs.variable is iter_var
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Add"


def test_materialize_direct_stack_inc_before_condition_uses_proven_loopback():
    project, codegen = _project()
    real_arch = project.arch
    jump = SimpleNamespace(
        address=0x40A0,
        mnemonic="jmp",
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x4094),),
    )

    class _ArchProxy:
        capstone = SimpleNamespace(disasm=lambda _code, _start: (jump,))

        def __getattr__(self, name: str):
            return getattr(real_arch, name)

    project.arch = _ArchProxy()
    project.loader = SimpleNamespace(memory=SimpleNamespace(load=lambda _start, _size: b"\x90" * 32))
    iter_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    iter_cvar = CVariable(iter_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[iter_var] = iter_cvar
    codegen.cfunc.unified_local_vars[iter_var] = {(iter_cvar, SimTypeShort(False))}
    guard = CIfElse(
        [
            (
                CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x4097}),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    body_effect = CExpressionStatement(
        CFunctionCall("body_effect", None, [], codegen=codegen, tags={"ins_addr": 0x40A0}),
        codegen=codegen,
    )
    loop_body = CStatements([guard, body_effect], codegen=codegen)
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), loop_body, codegen=codegen)
    codegen.cfunc.statements.statements.append(loop)
    inc = SimpleNamespace(address=0x4094, id=X86_INS_INC, operands=(_bp_mem_operand(-2),))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(inc,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert loop_body.statements[:2] == [guard, body_effect]
    inserted = loop_body.statements[-1]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is iter_var
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Add"


def test_materialize_direct_stack_inc_instruction_inserts_rebased_untagged_while_tail():
    project, codegen = _project()
    project._inertia_original_linear_delta = 0xFCE0
    iter_var = SimStackVariable(-6, 2, base="bp", name="iUp", region=0x1000)
    iter_cvar = CVariable(iter_var, variable_type=SimTypeShort(False), codegen=codegen)
    pivot_var = SimStackVariable(-4, 2, base="bp", name="iBreak", region=0x1000)
    pivot_cvar = CVariable(pivot_var, variable_type=SimTypeShort(False), codegen=codegen)
    limit_var = SimStackVariable(-2, 2, base="bp", name="iDown", region=0x1000)
    limit_cvar = CVariable(limit_var, variable_type=SimTypeShort(False), codegen=codegen)
    for variable, cvar in ((iter_var, iter_cvar), (pivot_var, pivot_cvar), (limit_var, limit_cvar)):
        codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.unified_local_vars[iter_var] = {(iter_cvar, SimTypeShort(False))}

    first_guard = CIfElse(
        [
            (
                CBinaryOp("CmpGT", limit_cvar, iter_cvar, codegen=codegen, tags={"ins_addr": 0x10D57}),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    second_guard = CIfElse(
        [
            (
                CBinaryOp("CmpLE", iter_cvar, pivot_cvar, codegen=codegen, tags={"ins_addr": 0x10D69}),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    loop_body = CStatements([first_guard, second_guard], codegen=codegen)
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), loop_body, codegen=codegen)
    codegen.cfunc.statements.statements.append(loop)

    inc = SimpleNamespace(address=0x108E, id=X86_INS_INC, operands=(_bp_mem_operand(-6),))
    function = SimpleNamespace(addr=0x1000, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(inc,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    inserted = loop_body.statements[-1]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is iter_var
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Add"
    assert inserted.rhs.rhs.value == 1
    assert loop_body.statements[:2] == [first_guard, second_guard]


def test_materialize_direct_stack_inc_instruction_replaces_proven_untagged_for_iterator():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    init = CAssignment(stack_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    condition = CBinaryOp("CmpLT", stack_cvar, CConstant(10, SimTypeShort(False), codegen=codegen), codegen=codegen)
    placeholder_var = CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="j"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    loop = CForLoop(
        init,
        condition,
        placeholder_var,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert isinstance(loop.iterator, CAssignment)
    assert loop.iterator.lhs.variable is stack_var
    assert isinstance(loop.iterator.rhs, CBinaryOp)
    assert loop.iterator.rhs.op == "Add"
    assert loop.iterator.rhs.rhs.value == 1


def test_materialize_direct_stack_inc_instruction_replaces_stack_slot_iterator_expression():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    init = CAssignment(stack_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    condition = CBinaryOp("CmpLT", stack_cvar, CConstant(10, SimTypeShort(False), codegen=codegen), codegen=codegen)
    loop = CForLoop(
        init,
        condition,
        stack_cvar,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert isinstance(loop.iterator, CAssignment)
    assert loop.iterator.lhs.variable is stack_var
    assert isinstance(loop.iterator.rhs, CBinaryOp)
    assert loop.iterator.rhs.op == "Add"
    assert loop.iterator.rhs.rhs.value == 1


def test_direct_stack_update_validation_delta_accepts_loop_body_write_evidence():
    codegen = SimpleNamespace(
        _inertia_direct_stack_update_lowering_8616={"materialized_count": 1},
        _inertia_direct_stack_update_evidence_8616=(
            (
                ("offset", -4),
                ("width", 2),
                ("delta", 1),
                ("ins_addr", 0x4018),
            ),
        ),
    )
    validation = {
        "delta": {
            "stack_writes": {"added": ("stack_slot:SS:BP-0x4:size2",), "removed": ()},
            "control_flow_effects": {
                "added": ("for-body-writes:CmpLT(stack_slot:SS:BP-0x2:size2,expr_cycle):stack_slot:SS:BP-0x4:size2",),
                "removed": (),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_update_validation_delta_accepts_dowhile_guard_loop_write_evidence():
    codegen = SimpleNamespace(
        _inertia_direct_stack_update_lowering_8616={"materialized_count": 2},
        _inertia_direct_stack_update_evidence_8616=(
            (
                ("offset", -6),
                ("width", 2),
                ("delta", 1),
                ("ins_addr", 0x109e),
            ),
            (
                ("offset", -2),
                ("width", 2),
                ("delta", -1),
                ("ins_addr", 0x10C5),
            ),
        ),
    )
    validation = {
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x6:size2",),
                "removed": (),
            },
            "control_flow_effects": {
                "added": (
                    "dowhile-body-writes:CmpLE(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):"
                    "global:0xbaa,global:0xbab,stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2",
                    "while-body-writes:const:True:stack_slot:SS:BP-0x2:size2",
                    "while-body-writes:const:True:stack_slot:SS:BP-0x6:size2",
                ),
                "removed": (
                    "dowhile-body-writes:CmpLE(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP-0x6:size2):"
                    "global:0xbaa,global:0xbab,stack_slot:SS:BP-0x2:size2",
                ),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(codegen, validation) is True


def test_materialize_direct_stack_inc_instruction_removes_duplicate_tagged_assignments():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.unified_local_vars[stack_var] = {(stack_cvar, SimTypeShort(False))}

    first_bad = CAssignment(
        stack_cvar,
        CBinaryOp("Shr", stack_cvar, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    second_bad = CAssignment(
        stack_cvar,
        CBinaryOp("Shr", stack_cvar, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.extend([first_bad, second_bad])

    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable is stack_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert stmt.rhs.rhs.value == 1


def test_materialize_direct_stack_add_stack_slot_replaces_tagged_assignment():
    project, codegen = _project()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    total_cvar = CVariable(total_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[total_var] = total_cvar
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    codegen.cfunc.unified_local_vars[total_var] = {(total_cvar, SimTypeShort(False))}
    codegen.cfunc.unified_local_vars[i_var] = {(i_cvar, SimTypeShort(False))}

    bad_stmt = CAssignment(
        i_cvar,
        CBinaryOp("Add", i_cvar, _reg(project, "ax", codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    load = SimpleNamespace(
        address=0x4015,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-4)),
    )
    update = SimpleNamespace(
        address=0x4018,
        id=X86_INS_ADD,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, update))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen._inertia_direct_stack_update_lowering_8616 == {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
        "refused_count": 0,
        "conflicting_tagged_assignment_removed_count": 0,
    }
    evidence = codegen._inertia_direct_stack_update_evidence_8616
    assert dict(evidence[0])["source_kind"] is DirectStackUpdateSourceKind8616.STACK_SLOT
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable is total_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert stmt.rhs.lhs.variable is total_var
    assert stmt.rhs.rhs.variable is i_var


def test_direct_stack_update_blocks_append_linear_block_when_existing_block_has_partial_insns(monkeypatch):
    project = object()
    first_insn = SimpleNamespace(address=0x1000)
    later_insn = SimpleNamespace(address=0x1010)
    partial = SimpleNamespace(addr=0x1000, size=0x300, capstone=SimpleNamespace(insns=(first_insn,)))
    linear = SimpleNamespace(addr=0x1000, size=0x40, capstone=SimpleNamespace(insns=(first_insn, later_insn)))
    function = SimpleNamespace(addr=0x1000, blocks=(partial,))

    monkeypatch.setattr(real_mode_linear, "_linear_capstone_function_block_8616", lambda _project, _function: (linear,))

    blocks = real_mode_linear._direct_global_update_blocks_8616(project, function)

    assert blocks == (partial, linear)


def test_direct_stack_update_facts_recompute_empty_cache_when_instruction_evidence_appears():
    project = SimpleNamespace()
    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x1018, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),),
        _inertia_direct_stack_update_instruction_facts_8616=(),
    )

    facts = _direct_stack_update_instruction_facts_8616(project, function)

    assert facts == (DirectStackUpdateFact8616(-4, 2, 1, 0x1018),)


def test_materialize_direct_stack_or_accepts_existing_assignment_as_consumed_evidence():
    project, codegen = _project()
    mask_var = SimStackVariable(-2, 2, base="bp", name="mask", region=0x4010)
    mask_cvar = CVariable(mask_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[mask_var] = mask_cvar
    codegen.cfunc.unified_local_vars[mask_var] = {(mask_cvar, SimTypeShort(False))}
    existing = CAssignment(
        mask_cvar,
        CBinaryOp(
            "Or",
            mask_cvar,
            CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(existing)
    update = SimpleNamespace(
        address=0x1039,
        id=X86_INS_OR,
        operands=(_bp_mem_operand(-2), _imm_operand(4)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(update,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen._inertia_direct_stack_update_lowering_8616 == {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
        "refused_count": 0,
        "conflicting_tagged_assignment_removed_count": 0,
    }
    evidence = dict(codegen._inertia_direct_stack_update_evidence_8616[0])
    assert evidence["operation"] is DirectStackUpdateOp8616.OR
    assert evidence["ins_addr"] == 0x1039
    assert codegen.cfunc.statements.statements == [existing]


def test_materialize_direct_stack_inc_accepts_existing_assignment_as_consumed_evidence():
    project, codegen = _project()
    j_var = SimStackVariable(-6, 2, base="bp", name="j", region=0x4010)
    j_cvar = CVariable(j_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[j_var] = j_cvar
    codegen.cfunc.unified_local_vars[j_var] = {(j_cvar, SimTypeShort(False))}
    existing = CAssignment(
        j_cvar,
        CBinaryOp(
            "Add",
            j_cvar,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(existing)
    update = SimpleNamespace(
        address=0x1030,
        id=X86_INS_INC,
        operands=(_bp_mem_operand(-6),),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(update,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen._inertia_direct_stack_update_lowering_8616 == {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
        "refused_count": 0,
        "conflicting_tagged_assignment_removed_count": 0,
    }
    evidence = dict(codegen._inertia_direct_stack_update_evidence_8616[0])
    assert evidence["operation"] is DirectStackUpdateOp8616.ARITHMETIC
    assert evidence["ins_addr"] == 0x1030
    assert codegen.cfunc.statements.statements == [existing]


def test_materialize_direct_stack_add_indexed_pointer_source_replaces_tagged_assignment():
    project, codegen = _project()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    src_var = SimStackVariable(4, 2, base="bp", name="src", region=0x4010)
    total_cvar = CVariable(total_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypePointer(SimTypeShort(False)), codegen=codegen)
    codegen.cfunc.variables_in_use[total_var] = total_cvar
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    codegen.cfunc.unified_local_vars[total_var] = {(total_cvar, SimTypeShort(False))}
    codegen.cfunc.unified_local_vars[i_var] = {(i_cvar, SimTypeShort(False))}
    codegen.cfunc.unified_local_vars[src_var] = {(src_cvar, SimTypePointer(SimTypeShort(False)))}

    bad_stmt = CAssignment(
        total_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    bx_load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(-4)),
    )
    bx_scale = SimpleNamespace(
        address=0x4013,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1)),
    )
    si_load = SimpleNamespace(
        address=0x4015,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(4)),
    )
    indexed_load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(
            _reg_operand(X86_REG_AX),
            SimpleNamespace(
                type=X86_OP_MEM,
                size=2,
                mem=SimpleNamespace(base=X86_REG_BX, index=X86_REG_SI, disp=0),
            ),
        ),
    )
    update = SimpleNamespace(
        address=0x4018,
        id=X86_INS_ADD,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(bx_load, bx_scale, si_load, indexed_load, update))),),
    )

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    evidence = dict(codegen._inertia_direct_stack_update_evidence_8616[0])
    assert evidence["source_kind"] is DirectStackUpdateSourceKind8616.INDEXED_POINTER
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable is total_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Add"
    assert stmt.rhs.lhs.variable is total_var
    assert isinstance(stmt.rhs.rhs, CIndexedVariable)
    assert stmt.rhs.rhs.variable.variable is src_var
    assert stmt.rhs.rhs.index.variable is i_var


def test_lower_stable_stack_rewrites_seg_ptr_indexed_bp_address_argument():
    project, codegen = _project()
    ach_var = SimStackVariable(-44, 1, base="bp", name="achT", region=0x4010)
    i_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    ach_cvar = CVariable(ach_var, variable_type=SimTypeChar(False), codegen=codegen)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[ach_var] = ach_cvar
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    codegen.cfunc.unified_local_vars[ach_var] = {(ach_cvar, SimTypeChar(False))}
    codegen.cfunc.unified_local_vars[i_var] = {(i_cvar, SimTypeShort(False))}

    offset = CBinaryOp("Add", ach_cvar, i_cvar, codegen=codegen)
    ptr_arg = CFunctionCall("SEG_PTR", None, [_reg(project, "ds", codegen), offset], codegen=codegen)
    call = CFunctionCall("memset", None, [ptr_arg, _const(32, codegen), _const(4, codegen)], codegen=codegen)
    codegen.cfunc.statements.statements.append(call)
    indexed_bp_access = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(
            _reg_operand(X86_REG_AX),
            SimpleNamespace(
                type=X86_OP_MEM,
                size=1,
                mem=SimpleNamespace(base=X86_REG_BP, index=X86_REG_SI, disp=-44),
            ),
        ),
    )
    codegen._inertia_current_function_8616 = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(indexed_bp_access,))),),
    )

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is True
    rewritten = call.args[0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "Add"
    assert isinstance(rewritten.lhs, CTypeCast)
    assert isinstance(rewritten.rhs, CVariable)
    assert rewritten.rhs.variable is i_var
    assert "SEG_PTR" not in str(rewritten)


def test_lower_stable_stack_preserves_unrelated_cast_expression():
    project, codegen = _project()
    ax = _reg(project, "ax", codegen)
    bx = _reg(project, "bx", codegen)
    rhs = CTypeCast(
        SimTypeShort(False),
        SimTypeShort(False),
        CBinaryOp("Add", ax, bx, codegen=codegen),
        codegen=codegen,
    )
    target_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    target = CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[target_var] = target
    codegen.cfunc.unified_local_vars[target_var] = {(target, SimTypeShort(False))}
    assignment = CAssignment(target, rhs, codegen=codegen)
    codegen.cfunc.statements.statements.append(assignment)

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is False
    assert assignment.rhs is rhs
    assert isinstance(assignment.rhs, CTypeCast)


def test_materialize_direct_stack_or_immediate_replaces_tagged_assignment():
    project, codegen = _project()
    mask_var = SimStackVariable(-2, 2, base="bp", name=None, region=0x4010)
    mask_cvar = CVariable(mask_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[mask_var] = mask_cvar
    codegen.cfunc.unified_local_vars[mask_var] = {(mask_cvar, SimTypeShort(False))}

    bad_stmt = CAssignment(
        mask_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    update = SimpleNamespace(
        address=0x4018,
        id=X86_INS_OR,
        operands=(_bp_mem_operand(-2), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0x20)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(update,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    evidence = codegen._inertia_direct_stack_update_evidence_8616
    assert dict(evidence[0])["operation"] is DirectStackUpdateOp8616.OR
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs.variable is mask_var
    assert isinstance(stmt.lhs.variable.name, str)
    assert stmt.lhs.variable.name.isidentifier()
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Or"
    assert stmt.rhs.lhs.variable is mask_var
    assert stmt.rhs.rhs.value == 0x20


def test_materialize_direct_stack_or_immediate_refuses_unguarded_fallback_insertion():
    project, codegen = _project()
    mask_var = SimStackVariable(-2, 2, base="bp", name="mask", region=0x4010)
    mask_cvar = CVariable(mask_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[mask_var] = mask_cvar
    codegen.cfunc.unified_local_vars[mask_var] = {(mask_cvar, SimTypeShort(False))}

    later_stmt = CAssignment(
        mask_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    guarded_later = CIfElse(
        [
            (
                CConstant(1, SimTypeShort(False), codegen=codegen),
                CStatements([later_stmt], codegen=codegen),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(guarded_later)

    update = SimpleNamespace(
        address=0x4018,
        id=X86_INS_OR,
        operands=(_bp_mem_operand(-2), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0x20)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(update,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen._inertia_direct_stack_update_lowering_8616 == {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
        "refused_count": 1,
        "conflicting_tagged_assignment_removed_count": 0,
    }
    guarded_body = guarded_later.condition_and_nodes[0][1]
    assert guarded_body.statements == [later_stmt]
    assert not hasattr(codegen, "_inertia_direct_stack_update_evidence_8616")


def test_materialize_direct_stack_mov_immediate_instruction_replaces_tagged_assignment():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    bad_stmt = CAssignment(
        stack_cvar,
        _reg(project, "di", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is stack_var
    assert isinstance(stmt.rhs, CConstant)
    assert stmt.rhs.value == 0
    lane = codegen._inertia_direct_stack_mov_lane_8616
    assert lane.raw == 1
    assert lane.normalized == 1
    assert lane.classified == 1
    assert lane.materialized == 1
    assert lane.failures == 0
    assert_pipeline_contracts_8616(codegen)


def test_materialize_direct_stack_mov_indexes_local_array_with_proven_global_load():
    project, codegen = _project()
    local_var = SimStackVariable(-44, 44, base="bp", name="achT", region=0x4010)
    local_cvar = CVariable(local_var, variable_type=SimTypeChar(False), codegen=codegen)
    index_var = SimMemoryVariable(0x0BA2, 2, name="cRow", region=0x4010)
    index_cvar = CVariable(index_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[local_var] = local_cvar
    codegen.cfunc.variables_in_use[index_var] = index_cvar
    codegen.cfunc.statements.statements.extend(
        (
            CExpressionStatement(index_cvar, codegen=codegen),
            CAssignment(
                local_cvar,
                _reg(project, "di", codegen),
                codegen=codegen,
                tags={"ins_addr": 0x4014},
            ),
        )
    )
    load_index = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_SI), SimpleNamespace(
            type=X86_OP_MEM,
            size=2,
            mem=SimpleNamespace(base=X86_REG_INVALID, index=X86_REG_INVALID, disp=0x0BA2),
        )),
    )
    store = SimpleNamespace(
        address=0x4014,
        id=X86_INS_MOV,
        operands=(_bp_indexed_mem_operand(-44, X86_REG_SI), _imm_operand(0, size=1)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load_index, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(stmt, CAssignment)
    assert isinstance(stmt.lhs, CIndexedVariable)
    assert stmt.lhs.variable is local_cvar
    assert stmt.lhs.index is index_cvar
    assert isinstance(stmt.rhs, CConstant)
    assert stmt.rhs.value == 0
    assert "Array" in type(local_cvar.variable_type).__name__
    assert local_cvar.variable_type.length == 44
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned short", "g_0BA2", None),)
    assert_pipeline_contracts_8616(codegen)


def test_materialize_direct_stack_mov_classified_refusal_fails_pipeline_contract(monkeypatch):
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.statements.statements.append(
        CAssignment(
            stack_cvar,
            _reg(project, "di", codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    insn = SimpleNamespace(
        address=0x4018,
        id=X86_INS_MOV,
        operands=(
            SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem),
            SimpleNamespace(type=X86_OP_IMM, size=2, imm=0),
        ),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    real_replace_tagged = real_mode_linear._replace_tagged_statement_assignment_8616
    monkeypatch.setattr(real_mode_linear, "_replace_tagged_statement_assignment_8616", lambda *_, **__: False)
    monkeypatch.setattr(real_mode_linear, "_insert_at_do_while_body_start_8616", lambda *_, **__: False)
    monkeypatch.setattr(real_mode_linear, "_insert_into_conditional_branch_for_direct_stack_move_8616", lambda *_, **__: False)
    monkeypatch.setattr(real_mode_linear, "_replace_precontrol_stack_assignment_8616", lambda *_, **__: False)
    monkeypatch.setattr(real_mode_linear, "_insert_after_nearest_preceding_tagged_statement_8616", lambda *_, **__: False)
    monkeypatch.setattr(real_mode_linear, "_insert_before_nearest_following_tagged_statement_8616", lambda *_, **__: False)

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    lane = codegen._inertia_direct_stack_mov_lane_8616
    assert lane.classified == 1
    assert lane.materialized == 0
    assert lane.failures == 1
    with pytest.raises(PipelineHardError, match="direct_stack_mov: 1 facts classified but 0 materialized"):
        assert_pipeline_contracts_8616(codegen)

    monkeypatch.setattr(
        real_mode_linear,
        "_replace_tagged_statement_assignment_8616",
        real_replace_tagged,
    )
    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert codegen._inertia_direct_stack_move_lowering_8616["failure_count"] == 1
    lane = codegen._inertia_direct_stack_mov_lane_8616
    assert lane.raw == 1
    assert lane.classified == 1
    assert lane.materialized == 1
    assert lane.failures == 0
    assert_pipeline_contracts_8616(codegen)


def test_materialize_direct_stack_mov_replaces_one_tagged_carrier_per_instruction():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    for reg_name in ("di", "si"):
        codegen.cfunc.statements.statements.append(
            CAssignment(
                stack_cvar,
                _reg(project, reg_name, codegen),
                codegen=codegen,
                tags={"ins_addr": 0x4018},
            )
        )

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    replacements = [
        stmt
        for stmt in codegen.cfunc.statements.statements
        if isinstance(stmt, CAssignment) and isinstance(stmt.rhs, CConstant) and stmt.rhs.value == 0
    ]
    assert len(replacements) == 1


def test_materialize_direct_stack_mov_reconciles_tagged_clones_after_replay() -> None:
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.statements.statements.append(
        CAssignment(
            stack_cvar,
            _reg(project, "di", codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),),
    )

    assert materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )
    codegen.cfunc.statements.statements.extend(
        (
            CAssignment(
                stack_cvar,
                _reg(project, "di", codegen),
                codegen=codegen,
                tags={"ins_addr": 0x4018},
            ),
            CAssignment(
                stack_cvar,
                _reg(project, "si", codegen),
                codegen=codegen,
                tags={"inertia_relocated_from_ins_addr": 0x4018},
            ),
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assignments = [
        statement
        for statement in codegen.cfunc.statements.statements
        if isinstance(statement, CAssignment)
    ]
    assert len(assignments) == 1
    assert isinstance(assignments[0].rhs, CConstant)
    assert assignments[0].rhs.value == 0


def test_materialize_direct_stack_mov_zero_immediate_stays_constant_even_with_base_label():
    project, codegen = _project()
    project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x10000))
    project._inertia_lst_metadata = SimpleNamespace(code_labels={0x10000: "_sum_to"})
    stack_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    bad_stmt = CAssignment(
        stack_cvar,
        _reg(project, "di", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is stack_var
    assert isinstance(stmt.rhs, CConstant)
    assert stmt.rhs.value == 0


def test_materialize_direct_stack_mov_scalar_immediate_refuses_padding_function_alias(
    monkeypatch,
):
    project, codegen = _project()
    project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x10000))
    project._inertia_lst_metadata = SimpleNamespace(code_labels={0x10010: "_main"})
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    codegen.cfunc.statements.statements.append(
        CAssignment(
            stack_cvar,
            _reg(project, "di", codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        )
    )
    monkeypatch.setattr(
        real_mode_linear,
        "canonicalize_x86_16_padding_call_target_8616",
        lambda _project, target: 0x10010 if target == 0x10001 else target,
    )

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=1)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt.rhs, CConstant)
    assert stmt.rhs.value == 1
    assert isinstance(stmt.lhs.variable_type, SimTypeShort)
    assert not hasattr(codegen, "_inertia_callsite_prototype_decls")


def test_materialize_direct_stack_mov_immediate_to_known_function_infers_near_symbol():
    project, codegen = _project()
    project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x10000))
    project._inertia_lst_metadata = SimpleNamespace(code_labels={0x10010: "_inc_one"})
    stack_var = SimStackVariable(-2, 2, base="bp", name="fn", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    bad_stmt = CAssignment(
        stack_cvar,
        _reg(project, "di", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0x10)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is stack_var
    assert isinstance(stmt.rhs, CVariable)
    assert stmt.rhs.variable.name == "inc_one"
    assert stmt.rhs.variable.addr == 0x10010
    assert isinstance(stmt.lhs.variable_type, SimTypePointer)
    assert isinstance(stmt.lhs.variable_type.pts_to, SimTypeFunction)
    assert isinstance(stmt.rhs.variable_type, SimTypePointer)
    assert isinstance(stmt.rhs.variable_type.pts_to, SimTypeFunction)
    assert codegen._inertia_callsite_prototype_decls == ("unsigned short inc_one(unsigned short a0);",)
    assert codegen._inertia_function_pointer_target_prototype_decl_count_8616 == 1


def test_materialize_direct_stack_mov_prunes_unsupported_function_pointer_overwrite():
    project, codegen = _project()
    project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x10000))
    project._inertia_lst_metadata = SimpleNamespace(code_labels={0x10010: "_inc_one", 0x10028: "_dec_one"})
    fn_var = SimStackVariable(-2, 2, base="bp", name="fn", region=0x4010)
    fn_type = SimTypePointer(SimTypeFunction([SimTypeShort(False)], SimTypeShort(False), variadic=False))
    fn_cvar = CVariable(fn_var, variable_type=fn_type, codegen=codegen)
    which_var = SimStackVariable(4, 2, base="bp", name="which", region=0x4010)
    which_cvar = CVariable(which_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[fn_var] = fn_cvar
    codegen.cfunc.variables_in_use[which_var] = which_cvar

    then_store = CAssignment(fn_cvar, _reg(project, "di", codegen), codegen=codegen, tags={"ins_addr": 0x4018})
    else_store = CAssignment(fn_cvar, _reg(project, "si", codegen), codegen=codegen, tags={"ins_addr": 0x4020})
    branch = CIfElse(
        [(which_cvar, CStatements([then_store], codegen=codegen))],
        else_node=CStatements([else_store], codegen=codegen),
        codegen=codegen,
    )
    unsupported = CAssignment(fn_cvar, which_cvar, codegen=codegen, tags={"ins_addr": 0x4024})
    codegen.cfunc.statements.statements.extend([branch, unsupported])

    dst = _bp_mem_operand(-2)
    inc_store = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, _imm_operand(0x10)))
    dec_store = SimpleNamespace(address=0x4020, id=X86_INS_MOV, operands=(dst, _imm_operand(0x28)))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(inc_store, dec_store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen._inertia_direct_stack_move_lowering_8616[
        "unsupported_function_pointer_assignment_pruned_count"
    ] == 1
    assert codegen.cfunc.statements.statements == [branch]
    then_stmt = branch.condition_and_nodes[0][1].statements[0]
    else_stmt = branch.else_node.statements[0]
    assert then_stmt.rhs.variable.name == "inc_one"
    assert else_stmt.rhs.variable.name == "dec_one"
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short inc_one(unsigned short a0);",
        "unsigned short dec_one(unsigned short a0);",
    )


def test_materialize_direct_stack_mov_immediate_places_function_pointer_stores_in_empty_if_else():
    project, codegen = _project()
    project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x10000))
    project._inertia_lst_metadata = SimpleNamespace(code_labels={0x10010: "_inc_one", 0x10028: "_dec_one"})
    fn_var = SimStackVariable(-2, 2, base="bp", name="fn", region=0x4010)
    fn_type = SimTypePointer(SimTypeFunction([SimTypeShort(False)], SimTypeShort(False), variadic=False))
    fn_cvar = CVariable(fn_var, variable_type=fn_type, codegen=codegen)
    which_var = SimStackVariable(4, 2, base="bp", name="which", region=0x4010)
    which_cvar = CVariable(which_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[fn_var] = fn_cvar
    codegen.cfunc.variables_in_use[which_var] = which_cvar

    branch = CIfElse(
        [
            (
                CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x400F}),
                CStatements([], codegen=codegen),
            )
        ],
        else_node=CStatements([], codegen=codegen),
        codegen=codegen,
    )
    unsupported = CAssignment(fn_cvar, which_cvar, codegen=codegen, tags={"ins_addr": 0x4024})
    codegen.cfunc.statements.statements.extend([branch, unsupported])

    dst = _bp_mem_operand(-2)
    insns = (
        SimpleNamespace(address=0x400F, mnemonic="jne", operands=(_imm_operand(0x4014),)),
        SimpleNamespace(address=0x4011, mnemonic="jmp", operands=(_imm_operand(0x401C),)),
        SimpleNamespace(address=0x4014, id=X86_INS_MOV, mnemonic="mov", operands=(dst, _imm_operand(0x10))),
        SimpleNamespace(address=0x4019, mnemonic="jmp", operands=(_imm_operand(0x4023),)),
        SimpleNamespace(address=0x401C, id=X86_INS_MOV, mnemonic="mov", operands=(dst, _imm_operand(0x28))),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=insns)),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [branch]
    then_stmt = branch.condition_and_nodes[0][1].statements[0]
    else_stmt = branch.else_node.statements[0]
    assert then_stmt.rhs.variable.name == "inc_one"
    assert else_stmt.rhs.variable.name == "dec_one"


def test_materialize_direct_stack_mov_immediate_inserts_missing_setup_before_loop_without_dup_init():
    project, codegen = _project()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    total_cvar = CVariable(total_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[total_var] = total_cvar
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    i_init = CAssignment(
        i_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CForLoop(
        i_init,
        CBinaryOp("CmpLT", i_cvar, CConstant(6, SimTypeShort(False), codegen=codegen), codegen=codegen),
        CAssignment(
            i_cvar,
            CBinaryOp("Add", i_cvar, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4018},
        ),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    total_store = SimpleNamespace(
        address=0x400B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)),
    )
    i_store = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)),
    )
    function = SimpleNamespace(
        addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(total_store, i_store))),)
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    inserted = statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is total_var
    assert isinstance(inserted.rhs, CConstant)
    assert inserted.rhs.value == 0
    assert statements[1] is loop
    assert codegen._inertia_direct_stack_move_lowering_8616["materialized_count"] == 1
    assert codegen._inertia_direct_stack_move_lowering_8616["already_materialized_count"] == 1


def test_materialize_direct_stack_mov_immediate_precedes_precontrol_read_before_while():
    project, codegen = _project()
    i_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    child_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    child_cvar = CVariable(child_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    codegen.cfunc.variables_in_use[child_var] = child_cvar
    child_assignment = CAssignment(
        child_cvar,
        CBinaryOp("Shl", i_cvar, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4015},
    )
    loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.extend((child_assignment, loop))

    store = SimpleNamespace(
        address=0x400B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)),
    )
    first_control = SimpleNamespace(
        address=0x4020,
        groups=(X86_GRP_JUMP,),
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x4030),),
    )
    function = SimpleNamespace(
        addr=0x4000,
        blocks=(SimpleNamespace(addr=0x400B, capstone=SimpleNamespace(insns=(store, first_control))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 3
    inserted = statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is i_cvar
    assert isinstance(inserted.rhs, CConstant)
    assert inserted.rhs.value == 0
    assert statements[1:] == [child_assignment, loop]


def test_materialize_repeated_stack_expression_moves_assignment_into_while_body():
    project, codegen = _project()
    i_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    child_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    marker_var = SimRegisterVariable(project.arch.registers["bx"][0], 2, name="bx")
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    child_cvar = CVariable(child_var, variable_type=SimTypeShort(False), codegen=codegen)
    marker_cvar = CVariable(marker_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    codegen.cfunc.variables_in_use[child_var] = child_cvar
    misplaced_init = CAssignment(
        i_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100B},
    )
    repeated_assignment = CAssignment(
        child_cvar,
        CBinaryOp("Shl", i_cvar, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1015},
    )
    body_marker = CAssignment(
        marker_cvar,
        i_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x1020},
    )
    loop_body = CStatements([misplaced_init, body_marker], codegen=codegen)
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), loop_body, codegen=codegen)
    codegen.cfunc.statements.statements.extend((repeated_assignment, loop))

    ax = _reg_operand(X86_REG_AX)
    init_store = SimpleNamespace(
        address=0x100B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _imm_operand(0)),
    )
    load = SimpleNamespace(address=0x1010, id=X86_INS_MOV, operands=(ax, _bp_mem_operand(-2)))
    shift = SimpleNamespace(address=0x1013, id=X86_INS_SHL, operands=(ax, _imm_operand(1, size=1)))
    store = SimpleNamespace(address=0x1015, id=X86_INS_MOV, operands=(_bp_mem_operand(-4), ax))
    body_insn = SimpleNamespace(
        address=0x1020,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _reg_operand(X86_REG_BX)),
    )
    loopback = SimpleNamespace(
        address=0x1090,
        groups=(X86_GRP_JUMP,),
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x1010),),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x100B,
                capstone=SimpleNamespace(insns=(init_store, load, shift, store, body_insn, loopback)),
            ),
        ),
    )
    codegen._inertia_direct_stack_move_branch_placement_service_8616 = (
        lambda fact, assignment: place_direct_stack_move_loop_entry_assignment_8616(
            project,
            codegen,
            function,
            fact,
            assignment,
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    relocated_init = statements[0]
    assert isinstance(relocated_init, CAssignment)
    assert relocated_init.lhs.variable is i_var
    assert isinstance(relocated_init.rhs, CConstant)
    assert relocated_init.rhs.value == 0
    assert statements[1] is loop
    relocated = loop_body.statements[0]
    assert isinstance(relocated, CAssignment)
    assert relocated.lhs.variable is child_var
    assert isinstance(relocated.rhs, CBinaryOp)
    assert relocated.rhs.op == "Shl"
    assert loop_body.statements[1] is body_marker


def test_materialize_repeated_stack_expression_precedes_live_loop_carrier():
    project, codegen = _project()
    i_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    child_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    live_var = SimRegisterVariable(project.arch.registers["bx"][0], 2, name="bx")
    marker_var = SimRegisterVariable(project.arch.registers["dx"][0], 2, name="dx")
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    child_cvar = CVariable(child_var, variable_type=SimTypeShort(False), codegen=codegen)
    live_cvar = CVariable(live_var, variable_type=SimTypeShort(False), codegen=codegen)
    marker_cvar = CVariable(marker_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    codegen.cfunc.variables_in_use[child_var] = child_cvar

    live_read = CAssignment(live_cvar, child_cvar, codegen=codegen)
    misplaced_definition = CAssignment(
        child_cvar,
        CBinaryOp("Shl", i_cvar, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1015},
    )
    body_marker = CAssignment(
        marker_cvar,
        i_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x1020},
    )
    loop_body = CStatements([live_read, misplaced_definition, body_marker], codegen=codegen)
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), loop_body, codegen=codegen)
    codegen.cfunc.statements.statements.append(loop)

    ax = _reg_operand(X86_REG_AX)
    load = SimpleNamespace(address=0x1010, id=X86_INS_MOV, operands=(ax, _bp_mem_operand(-2)))
    shift = SimpleNamespace(address=0x1013, id=X86_INS_SHL, operands=(ax, _imm_operand(1, size=1)))
    store = SimpleNamespace(address=0x1015, id=X86_INS_MOV, operands=(_bp_mem_operand(-4), ax))
    body_insn = SimpleNamespace(
        address=0x1020,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_DX), _reg_operand(X86_REG_DX)),
    )
    loopback = SimpleNamespace(
        address=0x1090,
        groups=(X86_GRP_JUMP,),
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x1010),),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1010,
                capstone=SimpleNamespace(insns=(load, shift, store, body_insn, loopback)),
            ),
        ),
    )
    codegen._inertia_direct_stack_move_branch_placement_service_8616 = (
        lambda fact, assignment: place_direct_stack_move_loop_entry_assignment_8616(
            project,
            codegen,
            function,
            fact,
            assignment,
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(loop_body.statements) == 3
    relocated = loop_body.statements[0]
    assert isinstance(relocated, CAssignment)
    assert relocated.lhs.variable is child_var
    assert isinstance(relocated.rhs, CBinaryOp)
    assert relocated.rhs.op == "Shl"
    assert loop_body.statements[1:] == [live_read, body_marker]

    materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    child_definitions = [
        statement
        for statement in loop_body.statements
        if isinstance(statement, CAssignment)
        and isinstance(statement.lhs, CVariable)
        and statement.lhs.variable is child_var
    ]
    assert child_definitions == [relocated]
    assert loop_body.statements[0] is relocated
    assert loop_body.statements[1] is live_read


def test_materialize_stack_expression_does_not_precede_live_read_without_loopback():
    project, codegen = _project()
    i_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    child_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    live_var = SimRegisterVariable(project.arch.registers["bx"][0], 2, name="bx")
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    child_cvar = CVariable(child_var, variable_type=SimTypeShort(False), codegen=codegen)
    live_cvar = CVariable(live_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    codegen.cfunc.variables_in_use[child_var] = child_cvar

    live_read = CAssignment(live_cvar, child_cvar, codegen=codegen)
    tagged_definition = CAssignment(
        child_cvar,
        CBinaryOp("Shl", i_cvar, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1015},
    )
    loop_body = CStatements([live_read, tagged_definition], codegen=codegen)
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), loop_body, codegen=codegen)
    codegen.cfunc.statements.statements.append(loop)

    ax = _reg_operand(X86_REG_AX)
    load = SimpleNamespace(address=0x1010, id=X86_INS_MOV, operands=(ax, _bp_mem_operand(-2)))
    shift = SimpleNamespace(address=0x1013, id=X86_INS_SHL, operands=(ax, _imm_operand(1, size=1)))
    store = SimpleNamespace(address=0x1015, id=X86_INS_MOV, operands=(_bp_mem_operand(-4), ax))
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1010,
                capstone=SimpleNamespace(insns=(load, shift, store)),
            ),
        ),
    )

    materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert loop_body.statements[0] is live_read
    assert isinstance(loop_body.statements[1], CAssignment)
    assert loop_body.statements[1].lhs.variable is child_var


def test_materialize_direct_stack_mov_replaces_tagged_stale_for_initializer_carrier():
    project, codegen = _project()
    dst_var = SimStackVariable(-6, 2, base="bp", name="i", region=0x4010)
    stale_var = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    stale_cvar = CVariable(stale_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[stale_var] = stale_cvar
    stale_init = CAssignment(
        stale_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x400B},
    )
    loop = CForLoop(
        stale_init,
        CBinaryOp("CmpLT", dst_cvar, CConstant(6, SimTypeShort(False), codegen=codegen), codegen=codegen),
        None,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)
    store = SimpleNamespace(
        address=0x400B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _imm_operand(0)),
    )
    function = SimpleNamespace(
        addr=0x4000,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(store,))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [loop]
    assert isinstance(loop.initializer, CAssignment)
    assert loop.initializer.lhs is dst_cvar
    assert isinstance(loop.initializer.rhs, CConstant)
    assert loop.initializer.rhs.value == 0


def test_materialize_direct_stack_mov_stale_evidence_keeps_existing_for_initializer():
    project, codegen = _project()
    changed_var = SimStackVariable(-6, 2, base="bp", name="changed", region=0x4010)
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    changed_cvar = CVariable(changed_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[changed_var] = changed_cvar
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    i_init = CAssignment(
        i_cvar,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1010},
    )
    loop = CForLoop(
        i_init,
        CBinaryOp("CmpLT", i_cvar, CConstant(6, SimTypeShort(False), codegen=codegen), codegen=codegen),
        CAssignment(
            i_cvar,
            CBinaryOp("Add", i_cvar, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            codegen=codegen,
        ),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    changed_store = SimpleNamespace(
        address=0x100B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _imm_operand(0)),
    )
    i_store = SimpleNamespace(
        address=0x1010,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _imm_operand(1)),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(changed_store, i_store))),),
    )

    def _evidence(offset: int, value: int, ins_addr: int):
        return (
            ("dst_offset", offset),
            ("width", 2),
            ("source_kind", DirectStackMoveSourceKind8616.IMMEDIATE),
            ("source_value", value),
            ("source_offset", None),
            ("source_op", None),
            ("source_immediate", None),
            ("source_call_target", None),
            ("source_call_name", None),
            ("source_call_ins_addr", None),
            ("source_segment_name", None),
            ("source_displacement", None),
            ("source_index_offset", None),
            ("source_index_shift", None),
            ("source_access_width", None),
            ("source_sign_extend", False),
            ("ins_addr", ins_addr),
        )

    codegen._inertia_direct_stack_move_evidence_8616 = (
        _evidence(-6, 0, 0x100B),
        _evidence(-4, 1, 0x1010),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    assert isinstance(statements[0], CAssignment)
    assert statements[0].lhs is changed_cvar
    assert statements[1] is loop
    assert loop.initializer is i_init
    assert codegen._inertia_direct_stack_move_lowering_8616["stale_evidence_rematerialized_count"] == 1
    assert codegen._inertia_direct_stack_move_lowering_8616["already_materialized_count"] == 1


def test_materialize_direct_stack_mov_prefers_used_stack_slot_identity():
    project, codegen = _project()
    generic_var = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010)
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    i_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    generic_cvar = CVariable(generic_var, variable_type=SimTypeShort(False), codegen=codegen)
    total_cvar = CVariable(total_var, variable_type=SimTypeShort(False), codegen=codegen)
    i_cvar = CVariable(i_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[generic_var] = generic_cvar
    codegen.cfunc.variables_in_use[total_var] = total_cvar
    codegen.cfunc.variables_in_use[i_var] = i_cvar
    later_use = CAssignment(
        total_cvar,
        CBinaryOp("Add", total_cvar, i_cvar, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(later_use)

    total_store = SimpleNamespace(
        address=0x400B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(total_store,))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    inserted = codegen.cfunc.statements.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is total_var
    assert codegen.cfunc.statements.statements[1] is later_use


def test_materialize_direct_stack_mov_stack_copy_instruction_replaces_tagged_assignment():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    bad_stmt = CAssignment(
        dst_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x401A},
    )
    codegen.cfunc.statements.statements.append(bad_stmt)

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert stmt.rhs is src_cvar


def test_materialize_direct_stack_mov_stack_copy_inserts_before_nested_loop_when_tagged_carrier_disappeared():
    project, codegen = _project()
    cur_var = SimStackVariable(-6, 2, base="bp", name="iRowCur", region=0x4010)
    next_var = SimStackVariable(-2, 2, base="bp", name="iRowNext", region=0x4010)
    limit_var = SimMemoryVariable(0xB7E, 2, name="cRow", region=0x4010)
    cur_cvar = CVariable(cur_var, variable_type=SimTypeShort(False), codegen=codegen)
    next_cvar = CVariable(next_var, variable_type=SimTypeShort(False), codegen=codegen)
    limit_cvar = CVariable(limit_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[cur_var] = cur_cvar
    codegen.cfunc.variables_in_use[next_var] = next_cvar
    codegen.cfunc.variables_in_use[limit_var] = limit_cvar

    guard = CIfElse(
        [
            (
                CBinaryOp(
                    "CmpGE",
                    next_cvar,
                    limit_cvar,
                    codegen=codegen,
                    tags={"ins_addr": 0x1031},
                ),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    inner_loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CStatements([guard], codegen=codegen),
        codegen=codegen,
    )
    outer_body = CStatements([inner_loop], codegen=codegen)
    outer_loop = CForLoop(
        CAssignment(cur_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen),
        CBinaryOp("CmpLT", cur_cvar, limit_cvar, codegen=codegen, tags={"ins_addr": 0x1016}),
        CAssignment(
            cur_cvar,
            CBinaryOp("Add", cur_cvar, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x1083},
        ),
        outer_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(outer_loop)

    load = SimpleNamespace(
        address=0x1028,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-6)),
    )
    store = SimpleNamespace(
        address=0x102B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert outer_body.statements[1] is inner_loop
    inserted = outer_body.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is next_var
    assert inserted.rhs is cur_cvar
    assert inner_loop.body.statements[0] is guard


def test_materialize_direct_stack_mov_relocates_tagged_copy_after_nested_loop_read():
    project, codegen = _project()
    cur_var = SimStackVariable(-6, 2, base="bp", name="iRow", region=0x4010)
    next_var = SimStackVariable(-2, 2, base="bp", name="iRowTmp", region=0x4010)
    prior_var = SimStackVariable(-8, 2, base="bp", name="barTemp", region=0x4010)
    cur_cvar = CVariable(cur_var, variable_type=SimTypeShort(False), codegen=codegen)
    next_cvar = CVariable(next_var, variable_type=SimTypeShort(False), codegen=codegen)
    prior_cvar = CVariable(prior_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[cur_var] = cur_cvar
    codegen.cfunc.variables_in_use[next_var] = next_cvar
    codegen.cfunc.variables_in_use[prior_var] = prior_cvar

    guard = CIfElse(
        [
            (
                CBinaryOp(
                    "CmpEQ",
                    next_cvar,
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    late_carrier = CAssignment(
        next_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x102B},
    )
    inner_loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x1031}),
        CStatements([guard, late_carrier], codegen=codegen),
        codegen=codegen,
    )
    prior_relocated = CAssignment(
        prior_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"inertia_relocated_from_ins_addr": 0x1020},
    )
    outer_body = CStatements([prior_relocated, inner_loop], codegen=codegen)
    outer_loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        None,
        outer_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(outer_loop)

    load = SimpleNamespace(
        address=0x1028,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-6)),
    )
    store = SimpleNamespace(
        address=0x102B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(outer_body.statements) == 3
    assert outer_body.statements[0] is prior_relocated
    relocated = outer_body.statements[1]
    assert isinstance(relocated, CAssignment)
    assert relocated.lhs is next_cvar
    assert relocated.rhs is cur_cvar
    assert outer_body.statements[2] is inner_loop
    assert inner_loop.body.statements == [guard]
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["read_before_tagged_assignment_relocated_count"] == 1

    regenerated_late_carrier = CAssignment(
        next_cvar,
        cur_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x102B},
    )
    inner_loop.body.statements.append(regenerated_late_carrier)
    duplicate_relocation = CAssignment(
        next_cvar,
        cur_cvar,
        codegen=codegen,
        tags={"inertia_relocated_from_ins_addr": 0x102B},
    )

    removed = real_mode_linear._relocate_tagged_stack_move_before_proven_loop_8616(
        codegen.cfunc.statements,
        project,
        function,
        0x102B,
        next_cvar,
        cur_cvar,
        duplicate_relocation,
    )

    assert removed == 1
    assert outer_body.statements == [prior_relocated, relocated, inner_loop]
    assert inner_loop.body.statements == [guard]


def test_materialize_direct_stack_mov_keeps_outer_loop_store_inside_enclosing_backedge():
    project, codegen = _project()
    project._inertia_original_linear_delta = 0xF000
    source_var = SimStackVariable(-8, 2, base="bp", name="barTemp", region=0x4010)
    target_var = SimStackVariable(-6, 2, base="bp", name="iLength", region=0x4010)
    source_cvar = CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_cvar = CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[source_var] = source_cvar
    codegen.cfunc.variables_in_use[target_var] = target_cvar

    guard = CIfElse(
        [
            (
                CBinaryOp(
                    "CmpLE",
                    source_cvar,
                    target_cvar,
                    codegen=codegen,
                    tags={"ins_addr": 0x1040},
                ),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    inner_loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CStatements([guard], codegen=codegen),
        codegen=codegen,
    )
    late_carrier = CAssignment(
        target_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1032},
    )
    outer_body = CStatements([inner_loop, late_carrier], codegen=codegen)
    outer_loop = CForLoop(
        None,
        CConstant(
            1,
            SimTypeShort(False),
            codegen=codegen,
            tags={"ins_addr": 0x101D},
        ),
        None,
        outer_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(outer_loop)

    load = SimpleNamespace(
        address=0x102F,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-8)),
        groups=(),
    )
    store = SimpleNamespace(
        address=0x1032,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _reg_operand(X86_REG_AX)),
        groups=(),
    )
    inner_backedge = SimpleNamespace(
        address=0x1085,
        id=0,
        operands=(_imm_operand(0x1038),),
        groups=(X86_GRP_JUMP,),
    )
    outer_backedge = SimpleNamespace(
        address=0x10AC,
        id=0,
        operands=(_imm_operand(0x1013),),
        groups=(X86_GRP_JUMP,),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(load, store, inner_backedge, outer_backedge),
                )
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == [outer_loop]
    assert len(outer_body.statements) == 2
    relocated = outer_body.statements[0]
    assert isinstance(relocated, CAssignment)
    assert relocated.lhs is target_cvar
    assert relocated.rhs is source_cvar
    assert outer_body.statements[1] is inner_loop
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["read_before_tagged_assignment_relocated_count"] == 1


def test_materialize_direct_stack_mov_refuses_nested_backedge_as_outer_scope_proof():
    project, codegen = _project()
    source_var = SimStackVariable(-8, 2, base="bp", name="barTemp", region=0x4010)
    target_var = SimStackVariable(-6, 2, base="bp", name="iLength", region=0x4010)
    source_cvar = CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_cvar = CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[source_var] = source_cvar
    codegen.cfunc.variables_in_use[target_var] = target_cvar

    guard = CIfElse(
        [
            (
                CBinaryOp(
                    "CmpLE",
                    source_cvar,
                    target_cvar,
                    codegen=codegen,
                    tags={"ins_addr": 0x1040},
                ),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    inner_loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CStatements([guard], codegen=codegen),
        codegen=codegen,
    )
    late_carrier = CAssignment(
        target_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1032},
    )
    outer_body = CStatements([inner_loop, late_carrier], codegen=codegen)
    outer_loop = CForLoop(
        None,
        CConstant(
            1,
            SimTypeShort(False),
            codegen=codegen,
            tags={"ins_addr": 0x101D},
        ),
        None,
        outer_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(outer_loop)

    load = SimpleNamespace(
        address=0x102F,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-8)),
        groups=(),
    )
    store = SimpleNamespace(
        address=0x1032,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _reg_operand(X86_REG_AX)),
        groups=(),
    )
    inner_backedge = SimpleNamespace(
        address=0x1085,
        id=0,
        operands=(_imm_operand(0x1038),),
        groups=(X86_GRP_JUMP,),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(load, store, inner_backedge)),
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == [outer_loop]
    assert outer_body.statements[0] is inner_loop
    materialized = outer_body.statements[1]
    assert isinstance(materialized, CAssignment)
    assert materialized.lhs is target_cvar
    assert materialized.rhs is source_cvar
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats.get("read_before_tagged_assignment_relocated_count", 0) == 0


def test_materialize_direct_stack_mov_keeps_posttest_loop_copy_in_body():
    project, codegen = _project()
    source_var = SimStackVariable(-6, 2, base="bp", name="iRow", region=0x4010)
    target_var = SimStackVariable(-2, 2, base="bp", name="iSwitch", region=0x4010)
    source_cvar = CVariable(source_var, variable_type=SimTypeShort(False), codegen=codegen)
    target_cvar = CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[source_var] = source_cvar
    codegen.cfunc.variables_in_use[target_var] = target_cvar

    tagged_carrier = CAssignment(
        target_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x102B},
    )
    loop = CDoWhileLoop(
        CBinaryOp(
            "CmpNE",
            target_cvar,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x1031},
        ),
        CStatements([tagged_carrier], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    load = SimpleNamespace(
        address=0x1028,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-6)),
    )
    store = SimpleNamespace(
        address=0x102B,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [loop]
    assert len(loop.body.statements) == 1
    materialized = loop.body.statements[0]
    assert isinstance(materialized, CAssignment)
    assert materialized.lhs is target_cvar
    assert materialized.rhs is source_cvar
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats.get("read_before_tagged_assignment_relocated_count", 0) == 0


def test_materialize_direct_stack_mov_relocates_fallback_copy_after_nested_loop_read(monkeypatch):
    project, codegen = _project()
    monkeypatch.setattr(real_mode_linear, "_strict_same_instruction_block_8616", lambda *_args: True)
    cur_var = SimStackVariable(-6, 2, base="bp", name="iRow", region=0x4010)
    next_var = SimStackVariable(-2, 2, base="bp", name="iRowTmp", region=0x4010)
    cur_cvar = CVariable(cur_var, variable_type=SimTypeShort(False), codegen=codegen)
    next_cvar = CVariable(next_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[cur_var] = cur_cvar
    codegen.cfunc.variables_in_use[next_var] = next_cvar

    predecessor = CAssignment(
        cur_cvar,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4017},
    )
    guard = CIfElse(
        [
            (
                CBinaryOp(
                    "CmpEQ",
                    next_cvar,
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    inner_loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x4020}),
        CStatements([predecessor, guard], codegen=codegen),
        codegen=codegen,
    )
    outer_body = CStatements([inner_loop], codegen=codegen)
    outer_loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        None,
        outer_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(outer_loop)

    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-6)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(outer_body.statements) == 2
    relocated = outer_body.statements[0]
    assert isinstance(relocated, CAssignment)
    assert relocated.lhs is next_cvar
    assert relocated.rhs is cur_cvar
    assert outer_body.statements[1] is inner_loop
    assert inner_loop.body.statements == [predecessor, guard]
    assert predecessor.lhs is cur_cvar
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["read_before_tagged_assignment_relocated_count"] == 1


def test_materialize_direct_stack_mov_shifted_stack_source_replaces_tagged_assignment():
    project, codegen = _project()
    dst_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    src_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    bad_stmt = CAssignment(dst_cvar, _reg(project, "ax", codegen), codegen=codegen, tags={"ins_addr": 0x401D})
    codegen.cfunc.statements.statements.append(bad_stmt)

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    shift = SimpleNamespace(
        address=0x401A,
        id=X86_INS_SHL,
        operands=(ax_src, SimpleNamespace(type=X86_OP_IMM, size=1, imm=1)),
    )
    store = SimpleNamespace(
        address=0x401D,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(
        addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, shift, store))),)
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Shl"
    assert stmt.rhs.lhs is src_cvar
    assert stmt.rhs.rhs.value == 1


def test_collects_scaled_indexed_stack_store_from_adjusted_stack_value() -> None:
    project, _codegen = _project()
    instructions = (
        SimpleNamespace(
            address=0x4010,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2)),
        ),
        SimpleNamespace(
            address=0x4013,
            id=X86_INS_INC,
            operands=(_reg_operand(X86_REG_AX),),
        ),
        SimpleNamespace(
            address=0x4014,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-2)),
        ),
        SimpleNamespace(
            address=0x4017,
            id=X86_INS_SHL,
            operands=(_reg_operand(X86_REG_SI), _imm_operand(1, size=1)),
        ),
        SimpleNamespace(
            address=0x4019,
            id=X86_INS_MOV,
            operands=(
                _bp_indexed_mem_operand(-90, X86_REG_SI, size=2),
                _reg_operand(X86_REG_AX),
            ),
        ),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_EXPR
    assert fact.source_offset == -2
    assert fact.source_immediate == 1
    assert fact.dst_offset == -90
    assert fact.dst_index_stack_offset == -2
    assert fact.dst_index_byte_scale == 2


def test_collects_global_decrement_into_stack_slot() -> None:
    project, _codegen = _project()
    instructions = (
        SimpleNamespace(
            address=0x4010,
            id=X86_INS_MOV,
            operands=(
                _reg_operand(X86_REG_AX),
                _global_mem_operand(0x0BA2),
            ),
        ),
        SimpleNamespace(
            address=0x4013,
            id=X86_INS_DEC,
            operands=(_reg_operand(X86_REG_AX),),
        ),
        SimpleNamespace(
            address=0x4014,
            id=X86_INS_MOV,
            operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
        ),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.GLOBAL_EXPR
    assert fact.source_global_displacement == 0x0BA2
    assert fact.source_op is DirectStackMoveExpressionOp8616.ADD
    assert fact.source_immediate == -1
    assert fact.dst_offset == -4


def test_materializes_global_decrement_into_stack_slot() -> None:
    project, codegen = _project()
    codegen._func = SimpleNamespace(info={})
    dst_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.statements.statements.append(
        CAssignment(
            dst_cvar,
            _reg(project, "ax", codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4014},
        )
    )
    instructions = (
        SimpleNamespace(
            address=0x4010,
            id=X86_INS_MOV,
            operands=(
                _reg_operand(X86_REG_AX),
                _global_mem_operand(0x0BA2),
            ),
        ),
        SimpleNamespace(
            address=0x4013,
            id=X86_INS_DEC,
            operands=(_reg_operand(X86_REG_AX),),
        ),
        SimpleNamespace(
            address=0x4014,
            id=X86_INS_MOV,
            operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
        ),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assignment = codegen.cfunc.statements.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs is dst_cvar
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Sub"
    assert isinstance(assignment.rhs.lhs, CVariable)
    assert isinstance(assignment.rhs.lhs.variable, SimMemoryVariable)
    assert assignment.rhs.lhs.variable.addr == 0x0BA2
    assert assignment.rhs.rhs.value == 1


def test_materializes_global_decrement_between_structured_loops() -> None:
    project, codegen = _project()
    codegen._func = SimpleNamespace(info={})
    dst_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    first_loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CStatements(
            [
                CExpressionStatement(
                    CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                    tags={"ins_addr": 0x400F},
                )
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    second_loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CStatements(
            [
                CExpressionStatement(
                    dst_cvar,
                    codegen=codegen,
                    tags={"ins_addr": 0x4020},
                )
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.extend((first_loop, second_loop))
    instructions = (
        SimpleNamespace(
            address=0x4010,
            id=X86_INS_MOV,
            operands=(
                _reg_operand(X86_REG_AX),
                _global_mem_operand(0x0BA2),
            ),
        ),
        SimpleNamespace(
            address=0x4013,
            id=X86_INS_DEC,
            operands=(_reg_operand(X86_REG_AX),),
        ),
        SimpleNamespace(
            address=0x4014,
            id=X86_INS_MOV,
            operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
        ),
    )
    function = SimpleNamespace(
        addr=0x4000,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert statements[0] is first_loop
    assert statements[2] is second_loop
    inserted = statements[1]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is dst_cvar
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Sub"


def test_collects_indexed_stack_aggregate_load_into_scalar_slot() -> None:
    project, _codegen = _project()
    instructions = (
        SimpleNamespace(
            address=0x4010,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-118)),
        ),
        SimpleNamespace(
            address=0x4013,
            id=X86_INS_SHL,
            operands=(_reg_operand(X86_REG_SI), _imm_operand(1, size=1)),
        ),
        SimpleNamespace(
            address=0x4015,
            id=X86_INS_MOV,
            operands=(
                _reg_operand(X86_REG_AX),
                _bp_indexed_mem_operand(-90, X86_REG_SI, size=2),
            ),
        ),
        SimpleNamespace(
            address=0x4018,
            id=X86_INS_MOV,
            operands=(_bp_mem_operand(-114), _reg_operand(X86_REG_AX)),
        ),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT
    assert fact.source_aggregate_base_offset == -90
    assert fact.source_index_offset == -118
    assert fact.source_index_byte_scale == 2
    assert fact.source_access_width == 2
    assert fact.dst_offset == -114


def test_collects_indexed_stack_aggregate_element_copy() -> None:
    project, _codegen = _project()
    instructions = (
        SimpleNamespace(
            address=0x4010,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-4)),
        ),
        SimpleNamespace(
            address=0x4013,
            id=X86_INS_SHL,
            operands=(_reg_operand(X86_REG_SI), _imm_operand(1, size=1)),
        ),
        SimpleNamespace(
            address=0x4015,
            id=X86_INS_MOV,
            operands=(
                _reg_operand(X86_REG_AX),
                _bp_indexed_mem_operand(-90, X86_REG_SI, size=2),
            ),
        ),
        SimpleNamespace(
            address=0x4018,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-118)),
        ),
        SimpleNamespace(
            address=0x401B,
            id=X86_INS_SHL,
            operands=(_reg_operand(X86_REG_SI), _imm_operand(1, size=1)),
        ),
        SimpleNamespace(
            address=0x401D,
            id=X86_INS_MOV,
            operands=(
                _bp_indexed_mem_operand(-90, X86_REG_SI, size=2),
                _reg_operand(X86_REG_AX),
            ),
        ),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT
    assert fact.source_index_offset == -4
    assert fact.source_index_byte_scale == 2
    assert fact.dst_index_stack_offset == -118
    assert fact.dst_index_byte_scale == 2


def test_restores_same_block_aggregate_copy_before_update_across_nested_statements() -> None:
    project, codegen = _project()
    instructions = (
        SimpleNamespace(
            address=0x4010,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-4)),
        ),
        SimpleNamespace(
            address=0x4013,
            id=X86_INS_SHL,
            operands=(_reg_operand(X86_REG_SI), _imm_operand(1, size=1)),
        ),
        SimpleNamespace(
            address=0x4015,
            id=X86_INS_MOV,
            operands=(
                _reg_operand(X86_REG_AX),
                _bp_indexed_mem_operand(-90, X86_REG_SI, size=2),
            ),
        ),
        SimpleNamespace(
            address=0x4018,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-118)),
        ),
        SimpleNamespace(
            address=0x401B,
            id=X86_INS_SHL,
            operands=(_reg_operand(X86_REG_SI), _imm_operand(1, size=1)),
        ),
        SimpleNamespace(
            address=0x401D,
            id=X86_INS_MOV,
            operands=(
                _bp_indexed_mem_operand(-90, X86_REG_SI, size=2),
                _reg_operand(X86_REG_AX),
            ),
        ),
        SimpleNamespace(
            address=0x4020,
            id=X86_INS_DEC,
            operands=(_bp_mem_operand(-4),),
        ),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )
    function._inertia_instruction_block_addr_map_8616 = {
        instruction.address: 0x4010 for instruction in instructions
    }
    fact = _direct_stack_move_instruction_facts_8616(project, function)[0]
    function._inertia_direct_stack_update_instruction_facts_8616 = (
        DirectStackUpdateFact8616(-4, 2, -1, 0x4020),
    )
    codegen._func = function
    value_type = SimTypeShort(False)
    aggregate_var = SimStackVariable(-90, 86, base="bp", name="aTemp", region=0x4010)
    source_index_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    destination_index_var = SimStackVariable(-118, 2, base="bp", name="iRand", region=0x4010)
    aggregate = CVariable(aggregate_var, variable_type=value_type, codegen=codegen)
    source_index = CVariable(source_index_var, variable_type=value_type, codegen=codegen)
    destination_index = CVariable(destination_index_var, variable_type=value_type, codegen=codegen)
    codegen.cfunc.variables_in_use[source_index_var] = source_index
    source_expr = CIndexedVariable(aggregate, source_index, variable_type=value_type, codegen=codegen)
    destination_expr = CIndexedVariable(
        aggregate,
        destination_index,
        variable_type=value_type,
        codegen=codegen,
    )
    move_assignment = CAssignment(destination_expr, source_expr, codegen=codegen)
    update_assignment = CAssignment(
        source_index,
        CBinaryOp(
            "Sub",
            source_index,
            CConstant(1, value_type, codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    update_container = CStatements([update_assignment], codegen=codegen)
    move_container = CStatements([move_assignment], codegen=codegen)
    codegen.cfunc.statements.statements.extend((update_container, move_container))

    changed = _restore_same_block_stack_move_order_8616(
        codegen.cfunc.statements,
        codegen,
        project,
        function,
        fact,
        destination_expr,
        source_expr,
    )

    assert changed is True
    assert update_container.statements == [move_assignment, update_assignment]
    assert move_container.statements == []


def test_materialize_direct_stack_mov_signed_half_stack_source_replaces_tagged_assignment():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    bad_stmt = CAssignment(dst_cvar, _reg(project, "ax", codegen), codegen=codegen, tags={"ins_addr": 0x401A})
    codegen.cfunc.statements.statements.append(bad_stmt)

    load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-4)),
    )
    sign_extend = SimpleNamespace(address=0x4013, id=X86_INS_CDQ, operands=())
    subtract_sign = SimpleNamespace(
        address=0x4014,
        id=X86_INS_SUB,
        operands=(_reg_operand(X86_REG_AX), _reg_operand(X86_REG_DX)),
    )
    signed_shift = SimpleNamespace(
        address=0x4016,
        id=X86_INS_SAR,
        operands=(_reg_operand(X86_REG_AX), _imm_operand(1, size=1)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(load, sign_extend, subtract_sign, signed_shift, store))),
        ),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    assert facts[0].source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_EXPR
    assert facts[0].source_op is DirectStackMoveExpressionOp8616.SIGNED_DIV2
    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Div"
    assert isinstance(stmt.rhs.lhs, CTypeCast)
    assert stmt.rhs.lhs.dst_type.signed is True
    assert stmt.rhs.lhs.expr is src_cvar
    assert stmt.rhs.rhs.value == 2


def test_materialize_direct_stack_mov_signed_half_inserts_before_first_stack_use_without_tagged_stmt():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    body = CStatements(
        [
            CIfElse(
                [
                    (
                        CBinaryOp(
                            "CmpLE", dst_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen
                        ),
                        CStatements([], codegen=codegen),
                    )
                ],
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    loop = CForLoop(
        CAssignment(src_cvar, CConstant(7, SimTypeShort(False), codegen=codegen), codegen=codegen),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CAssignment(src_cvar, dst_cvar, codegen=codegen),
        body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-4)),
    )
    sign_extend = SimpleNamespace(address=0x4013, id=X86_INS_CDQ, operands=())
    subtract_sign = SimpleNamespace(
        address=0x4014,
        id=X86_INS_SUB,
        operands=(_reg_operand(X86_REG_AX), _reg_operand(X86_REG_DX)),
    )
    signed_shift = SimpleNamespace(
        address=0x4016,
        id=X86_INS_SAR,
        operands=(_reg_operand(X86_REG_AX), _imm_operand(1, size=1)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(load, sign_extend, subtract_sign, signed_shift, store))),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert isinstance(body.statements[0], CAssignment)
    assert body.statements[0].lhs.variable is dst_var
    assert isinstance(body.statements[0].rhs, CBinaryOp)
    assert body.statements[0].rhs.op == "Div"
    assert body.statements[1].__class__ is CIfElse


def test_materialize_direct_stack_mov_signed_half_inserts_before_outer_branch_first_use():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    branch = CIfElse(
        [
            (
                CConstant(1, SimTypeShort(False), codegen=codegen),
                CStatements([], codegen=codegen),
            )
        ],
        else_node=CStatements([CExpressionStatement(dst_cvar, codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    body = CStatements([branch], codegen=codegen)
    loop = CForLoop(
        CAssignment(src_cvar, CConstant(7, SimTypeShort(False), codegen=codegen), codegen=codegen),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CAssignment(src_cvar, dst_cvar, codegen=codegen),
        body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(loop)

    load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-4)),
    )
    sign_extend = SimpleNamespace(address=0x4013, id=X86_INS_CDQ, operands=())
    subtract_sign = SimpleNamespace(
        address=0x4014,
        id=X86_INS_SUB,
        operands=(_reg_operand(X86_REG_AX), _reg_operand(X86_REG_DX)),
    )
    signed_shift = SimpleNamespace(
        address=0x4016,
        id=X86_INS_SAR,
        operands=(_reg_operand(X86_REG_AX), _imm_operand(1, size=1)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(load, sign_extend, subtract_sign, signed_shift, store))),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert isinstance(body.statements[0], CAssignment)
    assert body.statements[0].lhs.variable is dst_var
    assert body.statements[1] is branch
    assert isinstance(branch.else_node.statements[0], CExpressionStatement)


def test_materialize_direct_stack_mov_recurses_into_nested_statements_before_first_stack_use():
    project, codegen = _project()
    dst_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    src_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    init = CAssignment(src_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    nested = CStatements(
        [
            CIfElse(
                [
                    (
                        CBinaryOp(
                            "CmpGT", dst_cvar, CConstant(7, SimTypeShort(False), codegen=codegen), codegen=codegen
                        ),
                        CStatements([], codegen=codegen),
                    )
                ],
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.extend([init, nested])

    load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2)),
    )
    shift = SimpleNamespace(
        address=0x4013,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_AX), _imm_operand(1, size=1)),
    )
    store = SimpleNamespace(
        address=0x4015,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, shift, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [init, nested]
    assert isinstance(nested.statements[0], CAssignment)
    assert nested.statements[0].lhs.variable is dst_var
    assert isinstance(nested.statements[0].rhs, CBinaryOp)
    assert nested.statements[0].rhs.op == "Shl"
    assert nested.statements[1].__class__ is CIfElse


def test_materialize_direct_stack_mov_reload_inserts_source_expr_before_register_use_without_tagged_assignment():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="i", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    si_cvar = _reg(project, "si", codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    guard = CIfElse(
        [
            (
                CBinaryOp("CmpLE", si_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    guard.tags = {"ins_addr": 0x401D}
    codegen.cfunc.statements.statements.append(guard)

    load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-4)),
    )
    sign_extend = SimpleNamespace(address=0x4013, id=X86_INS_CDQ, operands=())
    subtract_sign = SimpleNamespace(
        address=0x4014,
        id=X86_INS_SUB,
        operands=(_reg_operand(X86_REG_AX), _reg_operand(X86_REG_DX)),
    )
    signed_shift = SimpleNamespace(
        address=0x4016,
        id=X86_INS_SAR,
        operands=(_reg_operand(X86_REG_AX), _imm_operand(1, size=1)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    reload = SimpleNamespace(
        address=0x401D,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-2)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(load, sign_extend, subtract_sign, signed_shift, store, reload))
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 3
    stack_store, register_reload, final_guard = statements
    assert isinstance(stack_store, CAssignment)
    assert stack_store.lhs.variable is dst_var
    assert isinstance(register_reload, CAssignment)
    assert register_reload.lhs.variable.name == "si"
    assert isinstance(register_reload.rhs, CBinaryOp)
    assert register_reload.rhs.op == "Div"
    assert isinstance(register_reload.rhs.lhs, CTypeCast)
    assert register_reload.rhs.lhs.expr is src_cvar
    assert final_guard is guard
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["reload_materialized_count"] == 1
    assert stats["reload_failure_count"] == 0


def test_aggregate_reload_refuses_unscoped_source_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    project, codegen = _project()
    codegen._func = SimpleNamespace(info={})
    array_var = SimStackVariable(-90, 86, base="bp", name="aTemp", region=0x4010)
    index_var = SimStackVariable(-118, 2, base="bp", name="iRand", region=0x4010)
    dst_var = SimStackVariable(-114, 2, base="bp", name="iLength", region=0x4010)
    array_cvar = CVariable(
        array_var,
        variable_type=real_mode_linear.SimTypeFixedSizeArray(SimTypeShort(False), 43),
        codegen=codegen,
    )
    index_cvar = CVariable(index_var, variable_type=SimTypeShort(False), codegen=codegen)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    ax_cvar = _reg(project, "ax", codegen)
    codegen.cfunc.variables_in_use.update(
        {
            array_var: array_cvar,
            index_var: index_cvar,
            dst_var: dst_cvar,
        }
    )
    aggregate = StackAggregateObjectFact8616(-90, 86, 2, 118, 0, 3, (-90,), -4, 2)
    codegen._inertia_stack_aggregate_object_facts_8616 = (aggregate,)
    codegen._inertia_stack_aggregate_cvars_8616 = {-90: array_cvar}
    monkeypatch.setattr(
        real_mode_linear,
        "materialize_stack_aggregate_objects_8616",
        lambda *_args, **_kwargs: False,
    )
    bad_store = CAssignment(
        dst_cvar,
        ax_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    guard = CIfElse(
        [
            (
                CBinaryOp(
                    "CmpLE",
                    ax_cvar,
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    guard.tags = {"ins_addr": 0x401B}
    codegen.cfunc.statements.statements.extend((bad_store, guard))
    instructions = (
        SimpleNamespace(
            address=0x4010,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-118)),
        ),
        SimpleNamespace(
            address=0x4013,
            id=X86_INS_SHL,
            operands=(_reg_operand(X86_REG_SI), _imm_operand(1, size=1)),
        ),
        SimpleNamespace(
            address=0x4015,
            id=X86_INS_MOV,
            operands=(
                _reg_operand(X86_REG_AX),
                _bp_indexed_mem_operand(-90, X86_REG_SI, size=2),
            ),
        ),
        SimpleNamespace(
            address=0x4018,
            id=X86_INS_MOV,
            operands=(_bp_mem_operand(-114), _reg_operand(X86_REG_AX)),
        ),
        SimpleNamespace(
            address=0x401B,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-114)),
        ),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    store = codegen.cfunc.statements.statements[0]
    assert isinstance(store, CAssignment)
    assert isinstance(store.rhs, CIndexedVariable)
    assert store.rhs.variable is array_cvar
    assert codegen.cfunc.statements.statements[1] is guard
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["aggregate_reload_unscoped_fallback_refused_count"] == 1
    assert stats["reload_failure_count"] == 1


def test_materialize_direct_stack_mov_reload_after_update_does_not_replay_initial_stack_store():
    project, codegen = _project()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x4010)
    total_cvar = CVariable(total_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[total_var] = total_cvar
    init = CAssignment(
        total_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    update = CAssignment(
        total_cvar,
        CBinaryOp("Add", total_cvar, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    use = CExpressionStatement(total_cvar, codegen=codegen, tags={"ins_addr": 0x4020})
    codegen.cfunc.statements.statements.extend([init, update, use])

    store = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _imm_operand(0)),
    )
    intervening_update = SimpleNamespace(address=0x4018, id=X86_INS_INC, operands=(_bp_mem_operand(-2),))
    reload = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(store, intervening_update, reload))),),
    )

    materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assignments_to_total = [
        stmt
        for stmt in codegen.cfunc.statements.statements
        if isinstance(stmt, CAssignment) and stmt.lhs is total_cvar
    ]
    assert len(assignments_to_total) == 2
    assert isinstance(assignments_to_total[0].rhs, CConstant)
    assert assignments_to_total[0].rhs.value == 0
    assert assignments_to_total[1] is update


def test_materialize_direct_stack_mov_reload_does_not_duplicate_existing_stack_store():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="up", region=0x4010)
    src_var = SimStackVariable(4, 2, base="bp", name="low", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    existing = CAssignment(dst_cvar, src_cvar, codegen=codegen, tags={"ins_addr": 0x4010})
    use = CExpressionStatement(dst_cvar, codegen=codegen, tags={"ins_addr": 0x4020})
    codegen.cfunc.statements.statements.extend([existing, use])

    load = SimpleNamespace(
        address=0x400D,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    store = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    reload = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2)),
    )
    function = SimpleNamespace(
        addr=0x4000,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store, reload))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 2
    assignment = codegen.cfunc.statements.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs is dst_cvar
    assert assignment.rhs is src_cvar
    assert codegen.cfunc.statements.statements[1] is use
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["reload_materialized_count"] == 0
    assert stats["reload_already_materialized_count"] == 1
    assert stats["reload_stack_slot_visible_guard_already_present_count"] == 1
    assert stats["reload_failure_count"] == 0


def test_materialize_direct_stack_mov_segmented_byte_source_replaces_tagged_assignment():
    project, codegen = _project()
    dst_var = SimStackVariable(-4, 2, base="bp", name="iBreak", region=0x4010)
    index_var = SimStackVariable(6, 2, base="bp", name="iHigh", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    index_cvar = CVariable(index_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[index_var] = index_cvar
    codegen.cfunc.arg_list = [index_cvar]
    bad_stmt = CAssignment(dst_cvar, _reg(project, "ax", codegen), codegen=codegen, tags={"ins_addr": 0x401A})
    codegen.cfunc.statements.statements.append(bad_stmt)

    load_index = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(6)),
    )
    shift_index = SimpleNamespace(
        address=0x4013,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1, size=1)),
    )
    load_byte = SimpleNamespace(
        address=0x4016,
        id=X86_INS_MOV,
        operands=(
            _reg_operand(X86_REG_AL, size=1),
            SimpleNamespace(
                type=X86_OP_MEM,
                size=1,
                mem=SimpleNamespace(base=X86_REG_BX, index=X86_REG_INVALID, disp=0xB4C),
            ),
        ),
    )
    sign_extend = SimpleNamespace(address=0x4019, id=X86_INS_CBW, operands=())
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(load_index, shift_index, load_byte, sign_extend, store))),
        ),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.SEGMENTED_MEMORY
    assert fact.source_segment_name == "ds"
    assert fact.source_displacement == 0xB4C
    assert fact.source_index_offset == 6
    assert fact.source_index_shift == 1
    assert fact.source_access_width == 1
    assert fact.source_sign_extend is True
    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert isinstance(stmt.rhs, CFunctionCall)
    assert stmt.rhs.callee_target == "SEG_U8"
    assert stmt.rhs.args[0].variable.name == "ds"
    assert isinstance(stmt.rhs.args[1], CBinaryOp)


def test_materialize_direct_stack_mov_signed_idiv_remainder_replaces_tagged_assignment():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    auxiliary_lhs = CVariable(
        SimRegisterVariable(8, 2, name="ir_aux"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(
        CAssignment(
            auxiliary_lhs,
            CFunctionCall(
                "_INSERT",
                None,
                [
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    CConstant(2, SimTypeShort(False), codegen=codegen),
                    divisor_cvar,
                ],
                codegen=codegen,
            ),
            codegen=codegen,
            tags={"ins_addr": 0x4016},
        )
    )
    bad_stmt = CAssignment(dst_cvar, _reg(project, "dx", codegen), codegen=codegen, tags={"ins_addr": 0x4020})
    codegen.cfunc.statements.statements.append(bad_stmt)

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    assert facts[0].source_kind is DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER
    assert facts[0].source_op is DirectStackMoveExpressionOp8616.MOD
    assert facts[0].source_offset == -4
    assert facts[0].source_immediate == 1
    assert facts[0].source_call_ins_addr == 0x4010
    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    stmt = codegen.cfunc.statements.statements[0]
    assert stmt.lhs.variable is dst_var
    assert isinstance(stmt.rhs, CBinaryOp)
    assert stmt.rhs.op == "Mod"
    assert isinstance(stmt.rhs.lhs, CTypeCast)
    assert isinstance(stmt.rhs.lhs.expr, CFunctionCall)
    assert stmt.rhs.lhs.expr.callee_target == "rand"
    assert stmt.rhs.lhs.expr.tags["ins_addr"] == 0x4010
    assert isinstance(stmt.rhs.rhs, CTypeCast)
    assert isinstance(stmt.rhs.rhs.expr, CBinaryOp)
    assert stmt.rhs.rhs.expr.op == "Add"
    assert stmt.rhs.rhs.expr.lhs is divisor_cvar
    assert stmt.rhs.rhs.expr.rhs.value == 1
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_auxiliary_insert_pruned_count"] == 1


def test_materialize_signed_idiv_prunes_standalone_insert_with_nested_window_tag() -> None:
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(
        dst_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    divisor_cvar = CVariable(
        divisor_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    adjusted_divisor = CBinaryOp(
        "Add",
        divisor_cvar,
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    insert = CFunctionCall(
        "_INSERT",
        None,
        [
            _reg(project, "ax", codegen),
            _const(2, codegen),
            adjusted_divisor,
        ],
        codegen=codegen,
    )
    insert_statement = CExpressionStatement(insert, codegen=codegen)
    bad_store = CAssignment(
        dst_cvar,
        _reg(project, "dx", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    codegen.cfunc.statements.statements.extend([insert_statement, bad_store])

    call = SimpleNamespace(
        address=0x4010,
        id=X86_INS_CALL,
        operands=(_imm_operand(0x5000),),
    )
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(
        address=0x4016,
        id=X86_INS_INC,
        operands=(_reg_operand(X86_REG_CX),),
    )
    sign_extend = SimpleNamespace(
        address=0x4017,
        id=X86_INS_CDQ,
        operands=(),
    )
    idiv = SimpleNamespace(
        address=0x4018,
        id=X86_INS_IDIV,
        operands=(_reg_operand(X86_REG_CX),),
    )
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(
                        load_divisor,
                        inc_divisor,
                        sign_extend,
                        idiv,
                        store_remainder,
                    )
                )
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    materialized = codegen.cfunc.statements.statements[0]
    assert isinstance(materialized, CAssignment)
    assert materialized.lhs is dst_cvar
    assert isinstance(materialized.rhs, CBinaryOp)
    assert materialized.rhs.op == "Mod"
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_auxiliary_insert_pruned_count"] == 1

    codegen.cfunc.statements.statements.insert(0, insert_statement)
    replay_changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert replay_changed is True
    assert codegen.cfunc.statements.statements == [materialized]
    replay_stats = codegen._inertia_direct_stack_move_lowering_8616
    assert replay_stats["idiv_auxiliary_insert_pruned_count"] == 2

    carrier_call = CExpressionStatement(
        CFunctionCall(
            "rand",
            None,
            [],
            codegen=codegen,
            tags={"ins_addr": 0x4010},
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements[:0] = [carrier_call, insert_statement]
    assert materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )
    assert len(codegen.cfunc.statements.statements) == 1
    remaining = codegen.cfunc.statements.statements[0]
    assert isinstance(remaining, CAssignment)
    assert isinstance(remaining.rhs, CBinaryOp)
    assert remaining.rhs.op == "Mod"


def test_materialize_direct_stack_mov_signed_idiv_remainder_replaces_nested_insert_artifact():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    wrong_lhs_var = SimStackVariable(0x74, 2, base="bp", name="arg_74", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    wrong_lhs_cvar = CVariable(wrong_lhs_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[wrong_lhs_var] = wrong_lhs_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    insert_artifact = CFunctionCall(
        "_INSERT",
        None,
        [
            _reg(project, "ax", codegen),
            _const(2, codegen),
            CBinaryOp("Add", divisor_cvar, _const(1, codegen), codegen=codegen),
        ],
        codegen=codegen,
    )
    bad_stmt = CAssignment(
        wrong_lhs_cvar,
        CBinaryOp("Mod", insert_artifact, divisor_cvar, codegen=codegen),
        codegen=codegen,
    )
    tagged_store = CAssignment(dst_cvar, _reg(project, "dx", codegen), codegen=codegen, tags={"ins_addr": 0x4020})
    loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        None,
        CStatements([bad_stmt], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.extend([tagged_store, loop])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    tagged_rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(tagged_rewritten, CAssignment)
    assert isinstance(tagged_rewritten.rhs, CBinaryOp)
    assert tagged_rewritten.rhs.op == "Mod"
    rewritten = loop.body.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs.variable is dst_var
    assert isinstance(rewritten.rhs, CBinaryOp)
    assert rewritten.rhs.op == "Mod"
    assert isinstance(rewritten.rhs.lhs, CTypeCast)
    assert isinstance(rewritten.rhs.lhs.expr, CFunctionCall)
    assert rewritten.rhs.lhs.expr.callee_target == "rand"
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["materialized_count"] == 1
    assert stats["idiv_artifact_materialized_count"] == 1
    assert stats["idiv_artifact_stack_lhs_bridge_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_reuses_call_result_and_reload():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    ax_cvar = _reg(project, "ax", codegen)
    si_cvar = _reg(project, "si", codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    call_stmt = CAssignment(
        ax_cvar,
        CFunctionCall("rand", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    bad_store = CAssignment(dst_cvar, _reg(project, "dx", codegen), codegen=codegen, tags={"ins_addr": 0x4020})
    bad_reload = CAssignment(
        si_cvar,
        CBinaryOp("Add", _reg(project, "dx", codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4023},
    )
    codegen.cfunc.statements.statements.extend([call_stmt, bad_store, bad_reload])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    reload_remainder = SimpleNamespace(
        address=0x4023,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-0x76)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(load_divisor, inc_divisor, sign_extend, idiv, store_remainder, reload_remainder)
                )
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    store_stmt = codegen.cfunc.statements.statements[0]
    reload_stmt = codegen.cfunc.statements.statements[1]
    assert len(codegen.cfunc.statements.statements) == 2
    assert isinstance(store_stmt.rhs, CBinaryOp)
    assert isinstance(store_stmt.rhs.lhs, CTypeCast)
    assert isinstance(store_stmt.rhs.lhs.expr, CFunctionCall)
    assert store_stmt.rhs.lhs.expr.callee_target == "rand"
    assert reload_stmt.lhs is si_cvar
    assert reload_stmt.rhs is dst_cvar
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["call_result_reused_count"] == 1
    assert stats["idiv_duplicate_store_pruned_count"] == 1
    assert stats["reload_raw_fact_count"] == 1
    assert stats["reload_materialized_count"] == 1
    assert stats["reload_failure_count"] == 0

    materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )
    assert codegen.cfunc.statements.statements[0] is store_stmt
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_replay_moves_late_store_to_callsite():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    use_var = SimStackVariable(-8, 2, base="bp", name="selected", region=0x4010)
    dst_cvar = CVariable(
        dst_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    divisor_cvar = CVariable(
        divisor_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    use_cvar = CVariable(
        use_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_cvar = _reg(project, "ax", codegen)
    for variable, cvar in (
        (dst_var, dst_cvar),
        (divisor_var, divisor_cvar),
        (use_var, use_cvar),
    ):
        codegen.cfunc.variables_in_use[variable] = cvar
    call = SimpleNamespace(
        address=0x4010,
        id=X86_INS_CALL,
        operands=(_imm_operand(0x5000),),
    )
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(
        address=0x4016,
        id=X86_INS_INC,
        operands=(_reg_operand(X86_REG_CX),),
    )
    sign_extend = SimpleNamespace(
        address=0x4017,
        id=X86_INS_CDQ,
        operands=(),
    )
    idiv = SimpleNamespace(
        address=0x4018,
        id=X86_INS_IDIV,
        operands=(_reg_operand(X86_REG_CX),),
    )
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(
                        call,
                        load_divisor,
                        inc_divisor,
                        sign_extend,
                        idiv,
                        store_remainder,
                    )
                ),
            ),
        ),
    )
    initial_call = CAssignment(
        ax_cvar,
        CFunctionCall("rand", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    initial_store = CAssignment(
        dst_cvar,
        _reg(project, "dx", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    codegen.cfunc.statements.statements.extend((initial_call, initial_store))
    assert materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )
    materialized_store = codegen.cfunc.statements.statements[0]
    assert isinstance(materialized_store, CAssignment)
    assert materialized_store.lhs is dst_cvar

    replay_call = CAssignment(
        ax_cvar,
        CFunctionCall("rand", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    use_before_store = CAssignment(
        use_cvar,
        dst_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x4023},
    )
    codegen.cfunc.statements.statements[:] = [
        replay_call,
        use_before_store,
        materialized_store,
    ]

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 2
    replayed_store = statements[0]
    assert isinstance(replayed_store, CAssignment)
    assert replayed_store.lhs is dst_cvar
    assert isinstance(replayed_store.rhs, CBinaryOp)
    assert replayed_store.rhs.op == "Mod"
    assert isinstance(replayed_store.rhs.lhs, CTypeCast)
    assert isinstance(replayed_store.rhs.lhs.expr, CFunctionCall)
    assert statements[1] is use_before_store
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_duplicate_store_pruned_count"] >= 1
    assert stats["failure_count"] == 0


def test_same_stack_move_rhs_matches_only_exact_direct_calls():
    _project_obj, codegen = _project()
    arg = CConstant(1, SimTypeShort(False), codegen=codegen)

    exact_lhs = CFunctionCall("rand", None, [arg], codegen=codegen)
    exact_rhs = CFunctionCall("_rand", None, [arg], codegen=codegen)
    different_target = CFunctionCall("other", None, [arg], codegen=codegen)
    different_arg = CFunctionCall(
        "rand",
        None,
        [CConstant(2, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    unresolved_lhs = CFunctionCall(CVariable(None, codegen=codegen), None, [], codegen=codegen)
    unresolved_rhs = CFunctionCall(CVariable(None, codegen=codegen), None, [], codegen=codegen)

    assert _same_stack_move_rhs_8616(exact_lhs, exact_rhs)
    assert not _same_stack_move_rhs_8616(exact_lhs, different_target)
    assert not _same_stack_move_rhs_8616(exact_lhs, different_arg)
    assert not _same_stack_move_rhs_8616(unresolved_lhs, unresolved_rhs)


def test_materialize_direct_stack_mov_signed_idiv_adds_visible_guard_after_tagged_store():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    ax_cvar = _reg(project, "ax", codegen)
    si_cvar = _reg(project, "si", codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    call_stmt = CAssignment(
        ax_cvar,
        CFunctionCall("rand", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    bad_store = CAssignment(dst_cvar, _reg(project, "dx", codegen), codegen=codegen, tags={"ins_addr": 0x4020})
    use_stmt = CAssignment(si_cvar, dst_cvar, codegen=codegen, tags={"ins_addr": 0x4023})
    loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        None,
        CStatements([use_stmt], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.extend([call_stmt, bad_store, loop])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(call, load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten_call = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten_call, CAssignment)
    assert rewritten_call.lhs is dst_cvar
    assert isinstance(rewritten_call.rhs, CBinaryOp)
    assert isinstance(rewritten_call.rhs.lhs, CTypeCast)
    assert isinstance(rewritten_call.rhs.lhs.expr, CFunctionCall)
    assert codegen.cfunc.statements.statements == [rewritten_call, loop]
    assert loop.body.statements[0] is use_stmt
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["idiv_duplicate_store_pruned_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_reload_accepts_existing_stack_guard_without_register_use():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    next_var = SimStackVariable(-8, 2, base="bp", name="nextUse", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    next_cvar = CVariable(next_var, variable_type=SimTypeShort(False), codegen=codegen)
    ax_cvar = _reg(project, "ax", codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    codegen.cfunc.variables_in_use[next_var] = next_cvar
    call_stmt = CAssignment(
        ax_cvar,
        CFunctionCall("rand", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    bad_store = CAssignment(dst_cvar, _reg(project, "dx", codegen), codegen=codegen, tags={"ins_addr": 0x4020})
    following_stmt = CAssignment(
        next_cvar,
        CConstant(3, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4024},
    )
    codegen.cfunc.statements.statements.extend([call_stmt, bad_store, following_stmt])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    reload_remainder = SimpleNamespace(
        address=0x4023,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_SI), _bp_mem_operand(-0x76)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(call, load_divisor, inc_divisor, sign_extend, idiv, store_remainder, reload_remainder)
                )
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten_store = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten_store, CAssignment)
    assert isinstance(rewritten_store.rhs, CBinaryOp)
    assert isinstance(rewritten_store.rhs.lhs, CTypeCast)
    assert isinstance(rewritten_store.rhs.lhs.expr, CFunctionCall)
    assert codegen.cfunc.statements.statements == [rewritten_store, following_stmt]
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_duplicate_store_pruned_count"] == 1
    assert stats["reload_stack_slot_visible_guard_already_present_count"] == 1
    assert stats["reload_materialized_count"] == 0
    assert stats["reload_already_materialized_count"] == 1
    assert stats["reload_failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_inserts_before_first_destination_use():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    ax_cvar = _reg(project, "ax", codegen)
    si_cvar = _reg(project, "si", codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    call_stmt = CAssignment(
        ax_cvar,
        CFunctionCall("rand", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    use_stmt = CAssignment(si_cvar, dst_cvar, codegen=codegen, tags={"ins_addr": 0x4023})
    loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        None,
        CStatements([use_stmt], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.extend([call_stmt, loop])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=(call,))),
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten_call = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten_call, CAssignment)
    assert rewritten_call.lhs is dst_cvar
    assert isinstance(rewritten_call.rhs, CBinaryOp)
    assert rewritten_call.rhs.op == "Mod"
    assert isinstance(rewritten_call.rhs.lhs, CTypeCast)
    assert isinstance(rewritten_call.rhs.lhs.expr, CFunctionCall)
    assert loop.body.statements[0] is use_stmt
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_replaces_degraded_call_statement():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    call_stmt = CFunctionCall("rand", None, [], codegen=codegen, tags={"ins_addr": 0x4010})
    decrement_stmt = CAssignment(
        divisor_cvar,
        CBinaryOp("Sub", divisor_cvar, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4024},
    )
    codegen.cfunc.statements.statements.extend([call_stmt, decrement_stmt])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(call, load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs is dst_cvar
    assert isinstance(rewritten.rhs, CBinaryOp)
    assert rewritten.rhs.op == "Mod"
    assert isinstance(rewritten.rhs.lhs, CTypeCast)
    assert isinstance(rewritten.rhs.lhs.expr, CFunctionCall)
    assert rewritten.rhs.lhs.expr.callee_target == "rand"
    assert codegen.cfunc.statements.statements[1] is decrement_stmt
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_degraded_call_keeps_inline_call_when_ax_carrier_exists():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    ax_cvar = _reg(project, "ax", codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    ax_call_stmt = CAssignment(
        ax_cvar,
        CFunctionCall("rand", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    degraded_call_stmt = CFunctionCall("rand", None, [], codegen=codegen, tags={"ins_addr": 0x4010})
    decrement_stmt = CAssignment(
        divisor_cvar,
        CBinaryOp("Sub", divisor_cvar, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4024},
    )
    codegen.cfunc.statements.statements.extend([ax_call_stmt, degraded_call_stmt, decrement_stmt])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(call, load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[1]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs is dst_cvar
    assert isinstance(rewritten.rhs, CBinaryOp)
    assert isinstance(rewritten.rhs.lhs, CTypeCast)
    assert isinstance(rewritten.rhs.lhs.expr, CFunctionCall)
    assert rewritten.rhs.lhs.expr.callee_target == "rand"
    assert rewritten.rhs.lhs.expr is not ax_cvar
    assert codegen.cfunc.statements.statements[2] is decrement_stmt
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["call_result_reused_count"] == 1
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_replaces_wrapped_degraded_call_statement():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    wrapped_call_stmt = CExpressionStatement(
        CFunctionCall("rand", None, [], codegen=codegen, tags={"ins_addr": 0x4010}),
        codegen=codegen,
    )
    decrement_stmt = CAssignment(
        divisor_cvar,
        CBinaryOp("Sub", divisor_cvar, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4024},
    )
    codegen.cfunc.statements.statements.extend([wrapped_call_stmt, decrement_stmt])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(call, load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs is dst_cvar
    assert isinstance(rewritten.rhs, CBinaryOp)
    assert isinstance(rewritten.rhs.lhs, CTypeCast)
    assert isinstance(rewritten.rhs.lhs.expr, CFunctionCall)
    assert rewritten.rhs.lhs.expr.callee_target == "rand"
    assert codegen.cfunc.statements.statements[1] is decrement_stmt
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_replaces_unique_untagged_degraded_call_statement():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    wrapped_call_stmt = CExpressionStatement(CFunctionCall("rand", None, [], codegen=codegen), codegen=codegen)
    decrement_stmt = CAssignment(
        divisor_cvar,
        CBinaryOp("Sub", divisor_cvar, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4024},
    )
    codegen.cfunc.statements.statements.extend([wrapped_call_stmt, decrement_stmt])

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(call, load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs is dst_cvar
    assert isinstance(rewritten.rhs, CBinaryOp)
    assert isinstance(rewritten.rhs.lhs, CTypeCast)
    assert isinstance(rewritten.rhs.lhs.expr, CFunctionCall)
    assert rewritten.rhs.lhs.expr.callee_target == "rand"
    assert codegen.cfunc.statements.statements[1] is decrement_stmt
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_matches_call_target_alias_for_degraded_call_statement():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    wrapped_call_stmt = CExpressionStatement(CFunctionCall("rand", None, [], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(wrapped_call_stmt)

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(call, load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )
    facts = list(_direct_stack_move_instruction_facts_8616(project, function))
    assert len(facts) == 1
    facts[0] = replace(facts[0], source_call_name="sub_5000")
    function._inertia_direct_stack_move_instruction_facts_8616 = tuple(facts)

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs is dst_cvar
    assert isinstance(rewritten.rhs, CBinaryOp)
    assert isinstance(rewritten.rhs.lhs, CTypeCast)
    assert isinstance(rewritten.rhs.lhs.expr, CFunctionCall)
    assert rewritten.rhs.lhs.expr.callee_target == "rand"
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_matches_rebased_numeric_call_target():
    project, codegen = _project()
    project._inertia_original_linear_delta = 0x10000
    project.kb = SimpleNamespace(functions=None, labels={0x15000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    numeric_target = CConstant(0x5000, SimTypeShort(False), codegen=codegen)
    numeric_call = CFunctionCall(numeric_target, None, [], codegen=codegen, tags={"ins_addr": 0x4010})
    codegen.cfunc.statements.statements.append(numeric_call)

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(call, load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )
    facts = list(_direct_stack_move_instruction_facts_8616(project, function))
    assert len(facts) == 1
    facts[0] = replace(
        facts[0],
        source_call_target=0x15000,
        source_call_name="rand",
    )
    function._inertia_direct_stack_move_instruction_facts_8616 = tuple(facts)

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs is dst_cvar
    assert isinstance(rewritten.rhs, CBinaryOp)
    assert isinstance(rewritten.rhs.lhs, CTypeCast)
    assert isinstance(rewritten.rhs.lhs.expr, CFunctionCall)
    assert rewritten.rhs.lhs.expr.callee_target == "rand"
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_consumes_ax_call_carrier_assignment():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    ax_cvar = _reg(project, "ax", codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    ax_call_stmt = CAssignment(
        ax_cvar,
        CFunctionCall("rand", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    codegen.cfunc.statements.statements.append(ax_call_stmt)

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(call, load_divisor, inc_divisor, sign_extend, idiv, store_remainder))
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs is dst_cvar
    assert isinstance(rewritten.rhs, CBinaryOp)
    assert isinstance(rewritten.rhs.lhs, CTypeCast)
    assert isinstance(rewritten.rhs.lhs.expr, CFunctionCall)
    assert rewritten.rhs.lhs.expr.callee_target == "rand"
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["call_result_reused_count"] == 1
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_signed_idiv_consumes_exact_tagged_ssa_call_carrier():
    project, codegen = _project()
    project.kb = SimpleNamespace(functions=None, labels={0x5000: "_rand"})
    dst_var = SimStackVariable(-0x76, 2, base="bp", name="iRand", region=0x4010)
    divisor_var = SimStackVariable(-4, 2, base="bp", name="iRowMax", region=0x4010)
    carrier_var = SimMemoryVariable(0x1234, 2, name="vvar_81", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    divisor_cvar = CVariable(divisor_var, variable_type=SimTypeShort(False), codegen=codegen)
    carrier_cvar = CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[divisor_var] = divisor_cvar
    codegen.cfunc.variables_in_use[carrier_var] = carrier_cvar
    codegen.cfunc.statements.statements.append(
        CAssignment(
            carrier_cvar,
            CFunctionCall("sub_4000", None, [], codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4010},
        )
    )

    call = SimpleNamespace(address=0x4010, id=X86_INS_CALL, operands=(_imm_operand(0x5000),))
    load_divisor = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_CX), _bp_mem_operand(-4)),
    )
    inc_divisor = SimpleNamespace(address=0x4016, id=X86_INS_INC, operands=(_reg_operand(X86_REG_CX),))
    sign_extend = SimpleNamespace(address=0x4017, id=X86_INS_CDQ, operands=())
    idiv = SimpleNamespace(address=0x4018, id=X86_INS_IDIV, operands=(_reg_operand(X86_REG_CX),))
    store_remainder = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-0x76), _reg_operand(X86_REG_DX)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(
                        call,
                        load_divisor,
                        inc_divisor,
                        sign_extend,
                        idiv,
                        store_remainder,
                    )
                )
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
    )

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    rewritten = codegen.cfunc.statements.statements[0]
    assert isinstance(rewritten, CAssignment)
    assert rewritten.lhs is dst_cvar
    assert isinstance(rewritten.rhs, CBinaryOp)
    assert isinstance(rewritten.rhs.lhs, CTypeCast)
    assert isinstance(rewritten.rhs.lhs.expr, CFunctionCall)
    assert rewritten.rhs.lhs.expr.callee_target == "rand"
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["idiv_call_statement_materialized_count"] == 1
    assert stats["materialized_count"] == 1
    assert stats["failure_count"] == 0


def test_materialize_direct_stack_mov_shifted_stack_source_inserts_before_following_nested_tagged_statement():
    project, codegen = _project()
    dst_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    src_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    guard_var = SimRegisterVariable(0, 2, name="flags")
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    guard_cvar = CVariable(guard_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    outer_anchor = CAssignment(
        src_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    following_guard = CAssignment(
        guard_cvar,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    nested_body = CStatements([following_guard], codegen=codegen)
    codegen.cfunc.statements.statements.extend([outer_anchor, nested_body])

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    shift = SimpleNamespace(
        address=0x401A,
        id=X86_INS_SHL,
        operands=(ax_src, SimpleNamespace(type=X86_OP_IMM, size=1, imm=1)),
    )
    store = SimpleNamespace(
        address=0x401D,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(
        addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, shift, store))),)
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [outer_anchor, nested_body]
    assert len(nested_body.statements) == 2
    inserted = nested_body.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is dst_cvar
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Shl"
    assert nested_body.statements[1] is following_guard


def test_materialize_direct_stack_mov_immediate_replaces_untagged_precontrol_assignment():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    bad_stmt = CAssignment(stack_cvar, _reg(project, "di", codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(bad_stmt)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    first_control = SimpleNamespace(
        address=0x4020,
        groups=(X86_GRP_JUMP,),
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x4030),),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn, first_control))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt.rhs, CConstant)
    assert stmt.rhs.value == 0


def test_materialize_direct_stack_mov_immediate_descends_nested_precontrol_statements():
    project, codegen = _project()
    stack_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    stack_cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stack_var] = stack_cvar
    nested = CStatements([CAssignment(stack_cvar, _reg(project, "di", codegen), codegen=codegen)], codegen=codegen)
    codegen.cfunc.statements.statements.append(nested)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst = SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem)
    src = SimpleNamespace(type=X86_OP_IMM, size=2, imm=0)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_MOV, operands=(dst, src))
    first_control = SimpleNamespace(
        address=0x4020,
        groups=(X86_GRP_JUMP,),
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x4030),),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn, first_control))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    stmt = nested.statements[0]
    assert isinstance(stmt.rhs, CConstant)
    assert stmt.rhs.value == 0


def test_materialize_direct_stack_mov_stack_copy_inserts_after_nearest_preceding_tagged_statement():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    anchor_var = SimStackVariable(-6, 2, base="bp", name="anchor", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    anchor_cvar = CVariable(anchor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    codegen.cfunc.variables_in_use[anchor_var] = anchor_cvar
    anchor = CAssignment(
        anchor_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4019},
    )
    codegen.cfunc.statements.statements.append(anchor)

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    inserted = codegen.cfunc.statements.statements[1]
    assert inserted.lhs is dst_cvar
    assert inserted.rhs is src_cvar


def test_materialize_direct_stack_mov_stack_copy_uses_nested_child_tag_same_block():
    project, codegen = _project()
    dst_var = SimStackVariable(-6, 2, base="bp", name="iSwitch", region=0x4010)
    src_var = SimStackVariable(-2, 2, base="bp", name="iRow", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    call = CFunctionCall("SwapBars", None, [], codegen=codegen, tags={"ins_addr": 0x4063})
    guarded_body = CStatements([CExpressionStatement(call, codegen=codegen)], codegen=codegen)
    guard = CConstant(1, SimTypeShort(False), codegen=codegen)
    if_stmt = CIfElse([(guard, guarded_body)], codegen=codegen)
    codegen.cfunc.statements.statements.append(if_stmt)

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-6)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    push_setup = SimpleNamespace(address=0x4063, id=X86_INS_PUSH, operands=(_reg_operand(X86_REG_AX),))
    call_insn = SimpleNamespace(address=0x4067, id=X86_INS_CALL, size=3, operands=(_imm_operand(0x2000),))
    load = SimpleNamespace(
        address=0x406D,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x4070,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(addr=0x4063, capstone=SimpleNamespace(insns=(push_setup, call_insn))),
            SimpleNamespace(addr=0x406A, capstone=SimpleNamespace(insns=(load, store))),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [if_stmt]
    assert len(guarded_body.statements) == 2
    inserted = guarded_body.statements[1]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is dst_cvar
    assert inserted.rhs is src_cvar


def test_materialize_direct_stack_mov_immediate_nested_insert_is_idempotent():
    project, codegen = _project()
    dst_var = SimStackVariable(-6, 2, base="bp", name="changed", region=0x4010)
    anchor_var = SimStackVariable(-2, 2, base="bp", name="anchor", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    anchor_cvar = CVariable(anchor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[anchor_var] = anchor_cvar
    anchor = CAssignment(
        anchor_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1063},
    )
    guarded_body = CStatements([anchor], codegen=codegen)
    guard = CConstant(1, SimTypeShort(False), codegen=codegen)
    if_stmt = CIfElse([(guard, guarded_body)], codegen=codegen)
    codegen.cfunc.statements.statements.append(if_stmt)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-6)
    anchor_insn = SimpleNamespace(address=0x1063, id=X86_INS_PUSH, operands=(_reg_operand(X86_REG_AX),))
    store = SimpleNamespace(
        address=0x1067,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _imm_operand(1)),
    )
    store.operands[0].mem = dst_mem
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x1063, capstone=SimpleNamespace(insns=(anchor_insn, store))),),
    )

    first = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    second = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert first is True
    assert second is False
    changed_assignments = [
        stmt
        for stmt in guarded_body.statements
        if isinstance(stmt, CAssignment) and getattr(stmt, "lhs", None) is dst_cvar
    ]
    assert len(changed_assignments) == 1
    assert getattr(changed_assignments[0].rhs, "value", None) == 1
    assert codegen._inertia_direct_stack_move_lowering_8616["already_materialized_count"] == 1


def test_materialize_direct_stack_mov_rematerializes_stale_evidence_after_rollback():
    project, codegen = _project()
    dst_var = SimStackVariable(-6, 2, base="bp", name="changed", region=0x4010)
    anchor_var = SimStackVariable(-2, 2, base="bp", name="anchor", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    anchor_cvar = CVariable(anchor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[anchor_var] = anchor_cvar
    anchor = CAssignment(
        anchor_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1063},
    )
    guarded_body = CStatements([anchor], codegen=codegen)
    if_stmt = CIfElse([(CConstant(1, SimTypeShort(False), codegen=codegen), guarded_body)], codegen=codegen)
    codegen.cfunc.statements.statements.append(if_stmt)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-6)
    anchor_insn = SimpleNamespace(address=0x1063, id=X86_INS_PUSH, operands=(_reg_operand(X86_REG_AX),))
    store = SimpleNamespace(
        address=0x1067,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _imm_operand(1)),
    )
    store.operands[0].mem = dst_mem
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x1063, capstone=SimpleNamespace(insns=(anchor_insn, store))),),
    )

    first = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    guarded_body.statements = [stmt for stmt in guarded_body.statements if getattr(stmt, "lhs", None) is not dst_cvar]
    second = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert first is True
    assert second is True
    changed_assignments = [
        stmt
        for stmt in guarded_body.statements
        if isinstance(stmt, CAssignment) and getattr(stmt, "lhs", None) is dst_cvar
    ]
    assert len(changed_assignments) == 1
    assert getattr(changed_assignments[0].rhs, "value", None) == 1
    assert codegen._inertia_direct_stack_move_lowering_8616["stale_evidence_rematerialized_count"] == 1


def test_materialize_direct_stack_mov_stack_copy_replaces_post_call_cleanup_artifact():
    project, codegen = _project()
    dst_var = SimStackVariable(-6, 2, base="bp", name="iSwitch", region=0x4010)
    src_var = SimStackVariable(-2, 2, base="bp", name="iRow", region=0x4010)
    cleanup_var = SimRegisterVariable(0x200, 2, name="sp_cleanup")
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    cleanup_cvar = CVariable(cleanup_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    call = CFunctionCall("SwapBars", None, [], codegen=codegen, tags={"ins_addr": 0x4067})
    cleanup = CAssignment(
        cleanup_cvar,
        CBinaryOp(
            "Add",
            cleanup_cvar,
            CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x406A},
    )
    guarded_body = CStatements([CExpressionStatement(call, codegen=codegen), cleanup], codegen=codegen)
    guard = CConstant(1, SimTypeShort(False), codegen=codegen)
    if_stmt = CIfElse([(guard, guarded_body)], codegen=codegen)
    codegen.cfunc.statements.statements.append(if_stmt)

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-6)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    call_insn = SimpleNamespace(address=0x4067, id=X86_INS_CALL, size=3, operands=(_imm_operand(0x2000),))
    cleanup_insn = SimpleNamespace(address=0x406A, id=X86_INS_ADD, operands=())
    load = SimpleNamespace(
        address=0x406D,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x4070,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(addr=0x4067, capstone=SimpleNamespace(insns=(call_insn, cleanup_insn, load, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [if_stmt]
    assert len(guarded_body.statements) == 2
    replaced = guarded_body.statements[1]
    assert isinstance(replaced, CAssignment)
    assert replaced.lhs is dst_cvar
    assert replaced.rhs is src_cvar


def test_materialize_direct_stack_mov_stack_copy_appends_before_do_while_condition():
    project, codegen = _project()
    dst_var = SimStackVariable(-4, 2, base="bp", name="iLimit", region=0x4010)
    src_var = SimStackVariable(-6, 2, base="bp", name="iSwitch", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    inner_call = CFunctionCall("SwapBars", None, [], codegen=codegen, tags={"ins_addr": 0x4068})
    inner_body = CStatements([CExpressionStatement(inner_call, codegen=codegen)], codegen=codegen)
    while_loop = CDoWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x4072}),
        inner_body,
        codegen=codegen,
    )
    condition = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x4080})
    do_body = CStatements([while_loop], codegen=codegen)
    do_loop = CDoWhileLoop(condition, do_body, codegen=codegen)
    codegen.cfunc.statements.statements.append(do_loop)

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-6)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4076,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x4079,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(addr=0x4068, capstone=SimpleNamespace(insns=())),
            SimpleNamespace(addr=0x4076, capstone=SimpleNamespace(insns=(load, store))),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [do_loop]
    assert len(do_body.statements) == 2
    inserted = do_body.statements[1]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is dst_cvar
    assert inserted.rhs is src_cvar
    assert len(inner_body.statements) == 1


def test_materialize_direct_stack_mov_arg_copy_inserts_before_precontrol_loop():
    project, codegen = _project()
    low_var = SimStackVariable(4, 2, base="bp", name="low", region=0x4010)
    up_var = SimStackVariable(-4, 2, base="bp", name="up", region=0x4010)
    low_cvar = CVariable(low_var, variable_type=SimTypeShort(False), codegen=codegen)
    up_cvar = CVariable(up_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[low_var] = low_cvar
    codegen.cfunc.variables_in_use[up_var] = up_cvar
    loop_condition = CVariable(
        up_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x1010},
    )
    loop = CWhileLoop(loop_condition, CStatements([], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(loop)

    ax_dst = _reg_operand(X86_REG_AX)
    ax_src = _reg_operand(X86_REG_AX)
    load = SimpleNamespace(
        address=0x100B,
        id=X86_INS_MOV,
        operands=(ax_dst, _bp_mem_operand(4)),
    )
    store = SimpleNamespace(
        address=0x100E,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-4), ax_src),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x100B, capstone=SimpleNamespace(insns=(load, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    inserted = codegen.cfunc.statements.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is up_cvar
    assert inserted.rhs is low_cvar
    assert codegen.cfunc.statements.statements[1] is loop


def test_materialize_direct_stack_mov_adjusted_arg_copy_inserts_before_precontrol_loop():
    project, codegen = _project()
    high_var = SimStackVariable(6, 2, base="bp", name="high", region=0x4010)
    down_var = SimStackVariable(-6, 2, base="bp", name="down", region=0x4010)
    high_cvar = CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    down_cvar = CVariable(down_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[high_var] = high_cvar
    codegen.cfunc.variables_in_use[down_var] = down_cvar
    loop_condition = CVariable(
        down_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x1010},
    )
    loop = CWhileLoop(loop_condition, CStatements([], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(loop)

    ax_dst = _reg_operand(X86_REG_AX)
    ax_src = _reg_operand(X86_REG_AX)
    load = SimpleNamespace(
        address=0x100B,
        id=X86_INS_MOV,
        operands=(ax_dst, _bp_mem_operand(6)),
    )
    decrement = SimpleNamespace(
        address=0x100E,
        id=X86_INS_DEC,
        operands=(ax_dst,),
    )
    store = SimpleNamespace(
        address=0x100F,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), ax_src),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x100B, capstone=SimpleNamespace(insns=(load, decrement, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    inserted = codegen.cfunc.statements.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is down_cvar
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Sub"
    assert inserted.rhs.lhs is high_cvar
    assert inserted.rhs.rhs.value == 1
    assert codegen.cfunc.statements.statements[1] is loop


def test_materialize_direct_stack_mov_adjusted_arg_copy_prefers_precontrol_over_nested_use():
    project, codegen = _project()
    high_var = SimStackVariable(6, 2, base="bp", name="high", region=0x4010)
    down_var = SimStackVariable(-6, 2, base="bp", name="down", region=0x4010)
    guard_var = SimRegisterVariable(0, 2, name="flags")
    high_cvar = CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    down_cvar = CVariable(down_var, variable_type=SimTypeShort(False), codegen=codegen)
    guard_cvar = CVariable(guard_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[high_var] = high_cvar
    codegen.cfunc.variables_in_use[down_var] = down_cvar
    inner_loop = CForLoop(
        None,
        CBinaryOp("CmpGT", down_cvar, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen),
        None,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    outer_loop = CWhileLoop(
        guard_cvar,
        CStatements([inner_loop], codegen=codegen),
        codegen=codegen,
    )
    outer_loop.tags["ins_addr"] = 0x100C
    codegen.cfunc.statements.statements.append(outer_loop)

    ax_dst = _reg_operand(X86_REG_AX)
    ax_src = _reg_operand(X86_REG_AX)
    load = SimpleNamespace(address=0x100B, id=X86_INS_MOV, operands=(ax_dst, _bp_mem_operand(6)))
    decrement = SimpleNamespace(address=0x100E, id=X86_INS_DEC, operands=(ax_dst,))
    store = SimpleNamespace(address=0x100F, id=X86_INS_MOV, operands=(_bp_mem_operand(-6), ax_src))
    branch = SimpleNamespace(address=0x1011, id=0, groups=(X86_GRP_JUMP,), operands=())
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x100B, capstone=SimpleNamespace(insns=(load, decrement, store, branch))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    inserted = codegen.cfunc.statements.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is down_cvar
    assert isinstance(inserted.rhs, CBinaryOp)
    assert inserted.rhs.op == "Sub"
    assert inserted.rhs.lhs is high_cvar
    assert inserted.rhs.rhs.value == 1
    assert codegen.cfunc.statements.statements[1] is outer_loop
    assert outer_loop.body.statements == [inner_loop]


def test_materialize_direct_stack_mov_segmented_source_refuses_without_structuring_cfg_proof():
    project, codegen = _project()
    high_var = SimStackVariable(6, 2, base="bp", name="high", region=0x4010)
    pivot_var = SimStackVariable(-2, 2, base="bp", name="pivot", region=0x4010)
    high_cvar = CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    pivot_cvar = CVariable(pivot_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[high_var] = high_cvar
    codegen.cfunc.variables_in_use[pivot_var] = pivot_cvar
    codegen.cfunc.arg_list = [high_cvar]
    loop_condition = CVariable(
        SimRegisterVariable(0, 2, name="flags"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x1010},
    )
    loop = CWhileLoop(loop_condition, CStatements([], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(loop)

    bx_dst = _reg_operand(X86_REG_BX)
    bx_src = _reg_operand(X86_REG_BX)
    ax_src = _reg_operand(X86_REG_AX)
    load_index = SimpleNamespace(address=0x100B, id=X86_INS_MOV, operands=(bx_dst, _bp_mem_operand(6)))
    shift_index = SimpleNamespace(address=0x100E, id=X86_INS_SHL, operands=(bx_src, _imm_operand(1, size=1)))
    load_pivot = SimpleNamespace(
        address=0x1011,
        id=X86_INS_MOV,
        operands=(
            _reg_operand(X86_REG_AX),
            SimpleNamespace(
                type=X86_OP_MEM,
                size=2,
                mem=SimpleNamespace(base=X86_REG_BX, index=X86_REG_INVALID, disp=0xB4C),
            ),
        ),
    )
    store = SimpleNamespace(address=0x1015, id=X86_INS_MOV, operands=(_bp_mem_operand(-2), ax_src))
    branch = SimpleNamespace(address=0x1018, id=0, groups=(X86_GRP_JUMP,), operands=())
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x100B,
                capstone=SimpleNamespace(insns=(load_index, shift_index, load_pivot, store, branch)),
            ),
        ),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen.cfunc.statements.statements == [loop]
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["segmented_memory_scope_refused_count"] == 1
    assert stats["materialized_count"] == 0
    assert stats["failure_count"] == 1


def test_materialize_direct_stack_mov_removes_duplicate_tagged_carrier_overwrite():
    project, codegen = _project()
    high_var = SimStackVariable(6, 2, base="bp", name="high", region=0x4010)
    pivot_var = SimStackVariable(-4, 2, base="bp", name="pivot", region=0x4010)
    high_cvar = CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    pivot_cvar = CVariable(pivot_var, variable_type=SimTypeShort(False), codegen=codegen)
    stale_a = CVariable(
        SimRegisterVariable(0x40, 2, name="vvar_483"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stale_b = CVariable(
        SimRegisterVariable(0x42, 2, name="vvar_484"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[high_var] = high_cvar
    codegen.cfunc.variables_in_use[pivot_var] = pivot_cvar
    codegen.cfunc.statements.statements.extend(
        (
            CAssignment(pivot_cvar, stale_a, codegen=codegen, tags={"ins_addr": 0x100E}),
            CAssignment(pivot_cvar, stale_b, codegen=codegen, tags={"ins_addr": 0x100E}),
        )
    )

    ax_dst = _reg_operand(X86_REG_AX)
    ax_src = _reg_operand(X86_REG_AX)
    load = SimpleNamespace(address=0x100B, id=X86_INS_MOV, operands=(ax_dst, _bp_mem_operand(6)))
    store = SimpleNamespace(address=0x100E, id=X86_INS_MOV, operands=(_bp_mem_operand(-4), ax_src))
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x100B, capstone=SimpleNamespace(insns=(load, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(stmt, CAssignment)
    assert stmt.lhs is pivot_cvar
    assert stmt.rhs is high_cvar


def test_materialize_direct_stack_mov_arg_copy_inserts_inside_else_after_prior_stack_assignment():
    project, codegen = _project()
    high_var = SimStackVariable(6, 2, base="bp", name="high", region=0x4010)
    up_var = SimStackVariable(-6, 2, base="bp", name="up", region=0x4010)
    pivot_var = SimStackVariable(-4, 2, base="bp", name="pivot", region=0x4010)
    high_cvar = CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    up_cvar = CVariable(up_var, variable_type=SimTypeShort(False), codegen=codegen)
    pivot_cvar = CVariable(pivot_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[high_var] = high_cvar
    codegen.cfunc.variables_in_use[up_var] = up_cvar
    codegen.cfunc.variables_in_use[pivot_var] = pivot_cvar
    pivot_assignment = CAssignment(
        pivot_cvar,
        high_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x100E},
    )
    loop_condition = CVariable(
        up_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x1016},
    )
    loop = CWhileLoop(loop_condition, CStatements([], codegen=codegen), codegen=codegen)
    else_body = CStatements([pivot_assignment, loop], codegen=codegen)
    if_stmt = CIfElse(
        [
            (CConstant(0, SimTypeShort(False), codegen=codegen), CStatements([], codegen=codegen)),
            (None, else_body),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(if_stmt)

    ax_dst = _reg_operand(X86_REG_AX)
    ax_src = _reg_operand(X86_REG_AX)
    load = SimpleNamespace(
        address=0x1011,
        id=X86_INS_MOV,
        operands=(ax_dst, _bp_mem_operand(6)),
    )
    store = SimpleNamespace(
        address=0x1014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), ax_src),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x100E, capstone=SimpleNamespace(insns=(load, store))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert else_body.statements[0] is pivot_assignment
    inserted = else_body.statements[1]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is up_cvar
    assert inserted.rhs is high_cvar
    assert else_body.statements[2] is loop


def test_materialize_direct_stack_mov_immediate_inserts_at_do_while_body_start():
    project, codegen = _project()
    changed_var = SimStackVariable(-6, 2, base="bp", name="changed", region=0x4010)
    changed_cvar = CVariable(changed_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[changed_var] = changed_cvar
    body_stmt = CExpressionStatement(
        CFunctionCall("body_step", None, [], codegen=codegen, tags={"ins_addr": 0x106C}),
        codegen=codegen,
    )
    condition = CVariable(
        changed_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x106C},
    )
    do_body = CStatements([body_stmt], codegen=codegen)
    do_loop = CDoWhileLoop(condition, do_body, codegen=codegen)
    codegen.cfunc.statements.statements.append(do_loop)

    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-6)
    store = SimpleNamespace(
        address=0x100B,
        id=X86_INS_MOV,
        operands=(
            SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem),
            SimpleNamespace(type=X86_OP_IMM, size=2, imm=0),
        ),
    )
    loopback = SimpleNamespace(
        address=0x106C,
        groups=(X86_GRP_JUMP,),
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x100B),),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x100B, capstone=SimpleNamespace(insns=(store, loopback))),),
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert len(do_body.statements) == 2
    inserted = do_body.statements[0]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs is changed_cvar
    assert inserted.rhs.value == 0
    assert do_body.statements[1] is body_stmt


def test_do_while_shared_condition_boundary_refuses_without_exact_loopback():
    project, codegen = _project()
    changed_var = SimStackVariable(-6, 2, base="bp", name="changed", region=0x4010)
    changed_cvar = CVariable(changed_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[changed_var] = changed_cvar
    body_stmt = CExpressionStatement(
        CFunctionCall("body_step", None, [], codegen=codegen, tags={"ins_addr": 0x106C}),
        codegen=codegen,
    )
    condition = CVariable(
        changed_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x106C},
    )
    do_body = CStatements([body_stmt], codegen=codegen)
    do_loop = CDoWhileLoop(condition, do_body, codegen=codegen)
    codegen.cfunc.statements.statements.append(do_loop)
    assignment = CAssignment(
        changed_cvar,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100B},
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x100B, capstone=SimpleNamespace(insns=())),),
    )

    changed = real_mode_linear._insert_at_do_while_body_start_8616(
        codegen.cfunc.statements,
        project,
        function,
        0x100B,
        assignment,
    )

    assert changed is False
    assert do_body.statements == [body_stmt]


def test_materialize_direct_stack_mov_stack_copy_inserts_at_repeated_do_while_body_start():
    project, codegen = _project()
    low_var = SimStackVariable(4, 2, base="bp", name="iLow", region=0x4010)
    high_var = SimStackVariable(6, 2, base="bp", name="iHigh", region=0x4010)
    up_var = SimStackVariable(-6, 2, base="bp", name="iUp", region=0x4010)
    down_var = SimStackVariable(-2, 2, base="bp", name="iDown", region=0x4010)
    low_cvar = CVariable(low_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_cvar = CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    up_cvar = CVariable(up_var, variable_type=SimTypeShort(False), codegen=codegen)
    down_cvar = CVariable(down_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[low_var] = low_cvar
    codegen.cfunc.variables_in_use[high_var] = high_cvar
    codegen.cfunc.variables_in_use[up_var] = up_cvar
    codegen.cfunc.variables_in_use[down_var] = down_cvar
    body_stmt = CExpressionStatement(
        CFunctionCall("body_step", None, [], codegen=codegen, tags={"ins_addr": 0x1017}),
        codegen=codegen,
        tags={"ins_addr": 0x1017},
    )
    condition = CBinaryOp(
        "CmpLT",
        up_cvar,
        down_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x106B},
    )
    do_body = CStatements([body_stmt], codegen=codegen)
    do_loop = CDoWhileLoop(condition, do_body, codegen=codegen)
    stale_up = CAssignment(up_cvar, low_cvar, codegen=codegen, tags={"ins_addr": 0x100E})
    stale_down = CAssignment(down_cvar, high_cvar, codegen=codegen, tags={"ins_addr": 0x1014})
    codegen.cfunc.statements.statements.extend((stale_up, stale_down, do_loop))

    load = SimpleNamespace(address=0x100B, id=X86_INS_MOV, operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)))
    store = SimpleNamespace(address=0x100E, id=X86_INS_MOV, operands=(_bp_mem_operand(-6), _reg_operand(X86_REG_AX)))
    high_load = SimpleNamespace(
        address=0x1011,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(6)),
    )
    down_store = SimpleNamespace(
        address=0x1014,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-2), _reg_operand(X86_REG_AX)),
    )
    loopback = SimpleNamespace(
        address=0x106C,
        groups=(X86_GRP_JUMP,),
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x100B),),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x100B,
                capstone=SimpleNamespace(insns=(load, store, high_load, down_store, loopback)),
            ),
        ),
    )
    codegen._inertia_direct_stack_move_branch_placement_service_8616 = (
        lambda fact, assignment: place_direct_stack_move_loop_entry_assignment_8616(
            project,
            codegen,
            function,
            fact,
            assignment,
        )
    )
    codegen._inertia_direct_stack_move_branch_ownership_replay_8616 = (
        lambda: materialize_direct_stack_move_loop_entry_ownership_8616(
            project,
            codegen,
            function,
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [do_loop]
    assert len(do_body.statements) == 3
    up_assignment = do_body.statements[0]
    down_assignment = do_body.statements[1]
    assert isinstance(up_assignment, CAssignment)
    assert up_assignment.lhs is up_cvar
    assert up_assignment.rhs is low_cvar
    assert isinstance(down_assignment, CAssignment)
    assert down_assignment.lhs is down_cvar
    assert down_assignment.rhs is high_cvar
    assert do_body.statements[2] is body_stmt

    do_body.statements[:2] = []
    codegen.cfunc.statements.statements[:0] = [up_assignment, down_assignment]

    replay_changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert replay_changed is True
    assert codegen.cfunc.statements.statements == [do_loop]
    assert [assignment.lhs for assignment in do_body.statements[:2]] == [up_cvar, down_cvar]
    assert [assignment.rhs for assignment in do_body.statements[:2]] == [low_cvar, high_cvar]
    assert do_body.statements[2] is body_stmt


def test_repeated_do_body_stack_copy_precedes_nested_pretest_loop():
    project, codegen = _project()
    low_var = SimStackVariable(4, 2, base="bp", name="iLow", region=0x4010)
    high_var = SimStackVariable(6, 2, base="bp", name="iHigh", region=0x4010)
    up_var = SimStackVariable(-6, 2, base="bp", name="iUp", region=0x4010)
    low_cvar = CVariable(low_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_cvar = CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    up_cvar = CVariable(up_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[low_var] = low_cvar
    codegen.cfunc.variables_in_use[high_var] = high_cvar
    codegen.cfunc.variables_in_use[up_var] = up_cvar

    nested_marker = CExpressionStatement(
        CFunctionCall("scan", None, [up_cvar], codegen=codegen, tags={"ins_addr": 0x1011}),
        codegen=codegen,
        tags={"ins_addr": 0x1011},
    )
    nested_body = CStatements([nested_marker], codegen=codegen)
    nested_loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        nested_body,
        codegen=codegen,
    )
    do_body = CStatements([nested_loop], codegen=codegen)
    do_loop = CDoWhileLoop(
        CBinaryOp(
            "CmpLT",
            up_cvar,
            high_cvar,
            codegen=codegen,
            tags={"ins_addr": 0x106B},
        ),
        do_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(do_loop)

    load = SimpleNamespace(
        address=0x100B,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(4)),
    )
    store = SimpleNamespace(
        address=0x100E,
        id=X86_INS_MOV,
        operands=(_bp_mem_operand(-6), _reg_operand(X86_REG_AX)),
    )
    loopback = SimpleNamespace(
        address=0x106C,
        groups=(X86_GRP_JUMP,),
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x100B),),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x100B,
                capstone=SimpleNamespace(insns=(load, store, loopback)),
            ),
        ),
    )
    codegen._inertia_direct_stack_move_branch_placement_service_8616 = (
        lambda fact, assignment: place_direct_stack_move_loop_entry_assignment_8616(
            project,
            codegen,
            function,
            fact,
            assignment,
        )
    )

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is True
    assert codegen.cfunc.statements.statements == [do_loop]
    assert len(do_body.statements) == 2
    relocated = do_body.statements[0]
    assert isinstance(relocated, CAssignment)
    assert relocated.lhs is up_cvar
    assert relocated.rhs is low_cvar
    assert do_body.statements[1] is nested_loop
    assert nested_body.statements == [nested_marker]


def test_prune_consumed_call_push_stack_assignments_removes_misplaced_pure_carrier():
    project, codegen = _project()
    down_var = SimStackVariable(-2, 2, base="bp", name="iDown", region=0x4010)
    down_cvar = CVariable(down_var, variable_type=SimTypeShort(False), codegen=codegen)
    carrier = _reg(project, "ax", codegen)
    false_push_write = CAssignment(
        down_cvar,
        CBinaryOp(
            "Add",
            carrier,
            CConstant(2892, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    independent_write = CAssignment(
        down_cvar,
        carrier,
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.extend((false_push_write, independent_write))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(address=0x4016, id=X86_INS_PUSH),
                        SimpleNamespace(address=0x4018, id=X86_INS_MOV),
                    )
                ),
            ),
        ),
    )

    changed = prune_consumed_call_push_stack_assignments_8616(
        project,
        codegen,
        frozenset({0x4016}),
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == [independent_write]
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_prune_consumed_call_push_reaches_switch_case_bodies():
    project, codegen = _project()
    local_var = SimStackVariable(-2, 2, base="bp", name="index", region=0x4010)
    local_cvar = CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    carrier = _reg(project, "ax", codegen)
    push_write = CAssignment(
        local_cvar,
        carrier,
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    preserved_write = CAssignment(
        local_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    case_body = CStatements([push_write, preserved_write], codegen=codegen)
    switch = CSwitchCase(_const(1, codegen), [(1, case_body)], None, codegen=codegen)
    codegen.cfunc.statements.statements.append(switch)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(address=0x4016, id=X86_INS_PUSH),
                        SimpleNamespace(address=0x4018, id=X86_INS_MOV),
                    )
                ),
            ),
        ),
    )

    changed = prune_consumed_call_push_stack_assignments_8616(
        project,
        codegen,
        frozenset({0x4016}),
        function=function,
    )

    assert changed is True
    assert case_body.statements == [preserved_write]
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_prune_consumed_call_push_removes_nested_condition_mse_carrier():
    project, codegen = _project()
    index_var = SimStackVariable(-2, 2, base="bp", name="index", region=0x4010)
    index_cvar = CVariable(index_var, variable_type=SimTypeShort(False), codegen=codegen)
    push_carrier = CAssignment(
        index_cvar,
        CConstant(0x68, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    condition = CMultiStatementExpression(
        CStatements([push_carrier], codegen=codegen),
        CBinaryOp(
            "CmpEQ",
            CFunctionCall(
                "is_flag",
                None,
                [index_cvar, CConstant(0x68, SimTypeShort(False), codegen=codegen)],
                codegen=codegen,
            ),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    guard = CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements.statements.append(guard)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=0x4016, id=X86_INS_PUSH),)
                ),
            ),
        ),
    )

    changed = prune_consumed_call_push_stack_assignments_8616(
        project,
        codegen,
        frozenset({0x4016}),
        function=function,
    )

    assert changed is True
    assert condition.stmts.statements == []
    assert condition.expr.lhs.args[0] is index_cvar
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_prune_consumed_call_push_keeps_nested_condition_mse_near_match():
    project, codegen = _project()
    local_var = SimStackVariable(-2, 2, base="bp", name="index", region=0x4010)
    local_cvar = CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    ordinary_assignment = CAssignment(
        local_cvar,
        CConstant(0x68, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    condition = CMultiStatementExpression(
        CStatements([ordinary_assignment], codegen=codegen),
        CBinaryOp(
            "CmpEQ",
            local_cvar,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(
        CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(address=0x4016, id=X86_INS_PUSH),
                        SimpleNamespace(address=0x4018, id=X86_INS_MOV),
                    )
                ),
            ),
        ),
    )

    changed = prune_consumed_call_push_stack_assignments_8616(
        project,
        codegen,
        frozenset({0x4016}),
        function=function,
    )

    assert changed is False
    assert condition.stmts.statements == [ordinary_assignment]
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert stats.raw_fact_count == 0
    assert stats.materialized_count == 0


def test_prune_consumed_call_push_stack_assignments_decodes_outside_cfg_blocks():
    project, codegen = _project()
    local_var = SimStackVariable(-2, 2, base="bp", name="index", region=0x4010)
    local_cvar = CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    false_push_write = CAssignment(
        local_cvar,
        CConstant(0x68, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    codegen.cfunc.statements.statements.append(false_push_write)
    push = SimpleNamespace(address=0x4016, id=X86_INS_PUSH)
    project.factory = SimpleNamespace(
        block=lambda addr, num_inst=1, opt_level=0: SimpleNamespace(
            capstone=SimpleNamespace(insns=(push,) if addr == 0x4016 else ())
        )
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(addr=0x4010, capstone=SimpleNamespace(insns=())),),
    )

    changed = prune_consumed_call_push_stack_assignments_8616(
        project,
        codegen,
        frozenset({0x4016}),
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_prune_consumed_call_push_removes_exact_ss_store_and_sp_carrier():
    project, codegen = _project()
    sp_cvar = _reg(project, "sp", codegen)
    ss_cvar = _reg(project, "ss", codegen)
    push_addr = 0x4016
    sp_carrier = CAssignment(
        sp_cvar,
        CBinaryOp(
            "Sub",
            sp_cvar,
            CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": push_addr},
    )
    stack_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [
                ss_cvar,
                CBinaryOp(
                    "Add",
                    sp_cvar,
                    CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        ),
        CBinaryOp(
            "Shr",
            _reg(project, "ax", codegen),
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": push_addr},
    )
    codegen.cfunc.statements.statements.extend((sp_carrier, stack_store))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=push_addr, id=X86_INS_PUSH),)
                ),
            ),
        ),
    )

    changed = prune_consumed_call_push_stack_assignments_8616(
        project,
        codegen,
        frozenset({push_addr}),
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (2, 2, 2, 2, 0)


def test_prune_consumed_call_push_accepts_lowered_runtime_ss_store() -> None:
    project, codegen = _project()
    push_addr = 0x4016
    runtime_ss = runtime_segment_push_source_cvar_8616(
        "ss",
        codegen=codegen,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        function_addr=0x4010,
    )
    assert runtime_ss is not None
    stack_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [
                runtime_ss,
                CConstant(0x1234, SimTypeShort(False), codegen=codegen),
            ],
            codegen=codegen,
        ),
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": push_addr},
    )
    codegen.cfunc.statements.statements.append(stack_store)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(
                            address=push_addr,
                            id=X86_INS_PUSH,
                        ),
                    )
                ),
            ),
        ),
    )

    changed = prune_consumed_call_push_stack_assignments_8616(
        project,
        codegen,
        frozenset({push_addr}),
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_prune_materialized_call_push_replay_follows_nested_exact_callsite_identity():
    project, codegen = _project()
    push_addr = 0x4016
    nested_call_addr = 0x4018
    sp_cvar = _reg(project, "sp", codegen)
    ss_cvar = _reg(project, "ss", codegen)
    sp_carrier = CAssignment(
        sp_cvar,
        CBinaryOp(
            "Sub",
            sp_cvar,
            CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": push_addr},
    )
    stack_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [
                ss_cvar,
                CBinaryOp(
                    "Add",
                    sp_cvar,
                    CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        ),
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": push_addr},
    )
    nested_call = CFunctionCall(
        "aNldiv",
        None,
        [CConstant(7, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
        tags={"ins_addr": nested_call_addr},
    )
    outer_call = CFunctionCall(
        "sprintf",
        None,
        [nested_call],
        codegen=codegen,
    )
    call_statement = CExpressionStatement(outer_call, codegen=codegen)
    codegen.cfunc.statements.statements.extend((sp_carrier, stack_store, call_statement))
    summary = CallsiteSummary8616(
        nested_call_addr,
        0x5000,
        nested_call_addr + 3,
        "direct_near",
        1,
        (2,),
        2,
        "ax",
        True,
        push_arg_instruction_addrs=(push_addr,),
        stack_cleanup_instruction_addr=0x401B,
    )
    codegen._inertia_callsite_summary_inventory_8616 = {nested_call_addr: summary}
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=push_addr, id=X86_INS_PUSH),)
                ),
            ),
        ),
    )

    changed = prune_materialized_call_push_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == [call_statement]
    replay = codegen._inertia_materialized_call_push_replay_8616
    assert (
        replay.raw_fact_count,
        replay.normalized_fact_count,
        replay.classified_fact_count,
        replay.materialized_count,
        replay.failure_count,
        replay.consumed_push_instruction_count,
    ) == (1, 1, 1, 1, 0, 1)
    cleanup_replay = codegen._inertia_materialized_call_cleanup_replay_8616
    assert (
        cleanup_replay.raw_fact_count,
        cleanup_replay.normalized_fact_count,
        cleanup_replay.classified_fact_count,
        cleanup_replay.materialized_count,
        cleanup_replay.failure_count,
        cleanup_replay.consumed_cleanup_instruction_count,
    ) == (1, 1, 1, 1, 0, 1)
    assert (
        codegen._inertia_consumed_call_cleanup_carrier_ins_addrs_8616
        == frozenset({0x401B})
    )
    prune = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert (
        prune.raw_fact_count,
        prune.normalized_fact_count,
        prune.classified_fact_count,
        prune.materialized_count,
        prune.failure_count,
    ) == (2, 2, 2, 2, 0)


def test_prune_materialized_call_push_replay_follows_condition_mse_statements():
    project, codegen = _project()
    push_addr = 0x4016
    callsite_addr = 0x4018
    sp_cvar = _reg(project, "sp", codegen)
    sp_carrier = CAssignment(
        sp_cvar,
        CBinaryOp(
            "Sub",
            sp_cvar,
            CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": push_addr},
    )
    condition_call = CFunctionCall(
        "sub_5000",
        None,
        [CConstant(7, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
        tags={"ins_addr": callsite_addr},
    )
    condition_mse = CMultiStatementExpression(
        CStatements(
            [CExpressionStatement(condition_call, codegen=codegen)],
            codegen=codegen,
        ),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    condition = CIfElse(
        [
            (
                condition_mse,
                CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.extend((sp_carrier, condition))
    codegen._inertia_callsite_summary_inventory_8616 = {
        callsite_addr: CallsiteSummary8616(
            callsite_addr,
            0x5000,
            callsite_addr + 3,
            "direct_near",
            1,
            (2,),
            2,
            "ax",
            True,
            push_arg_instruction_addrs=(push_addr,),
        )
    }
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=push_addr, id=X86_INS_PUSH),)
                ),
            ),
        ),
    )

    changed = prune_materialized_call_push_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == [condition]
    replay = codegen._inertia_materialized_call_push_replay_8616
    assert (
        replay.raw_fact_count,
        replay.normalized_fact_count,
        replay.classified_fact_count,
        replay.materialized_count,
        replay.failure_count,
        replay.consumed_push_instruction_count,
    ) == (1, 1, 1, 1, 0, 1)


def test_materialized_call_cleanup_replay_refuses_missing_instruction_identity():
    project, codegen = _project()
    callsite_addr = 0x4018
    call = CFunctionCall(
        "sub_5000",
        None,
        [CConstant(7, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
        tags={"ins_addr": callsite_addr},
    )
    codegen.cfunc.statements.statements.append(
        CExpressionStatement(call, codegen=codegen)
    )
    codegen._inertia_callsite_summary_inventory_8616 = {
        callsite_addr: CallsiteSummary8616(
            callsite_addr,
            0x5000,
            callsite_addr + 3,
            "direct_near",
            1,
            (2,),
            2,
            "ax",
            True,
        )
    }

    changed = prune_materialized_call_push_stack_assignments_8616(
        project,
        codegen,
    )

    assert changed is False
    cleanup_replay = codegen._inertia_materialized_call_cleanup_replay_8616
    assert (
        cleanup_replay.raw_fact_count,
        cleanup_replay.normalized_fact_count,
        cleanup_replay.classified_fact_count,
        cleanup_replay.materialized_count,
        cleanup_replay.failure_count,
        cleanup_replay.consumed_cleanup_instruction_count,
    ) == (0, 0, 0, 0, 0, 0)
    assert (
        codegen._inertia_consumed_call_cleanup_carrier_ins_addrs_8616
        == frozenset()
    )


def test_prune_consumed_call_push_refuses_non_ss_segment_store():
    project, codegen = _project()
    ds_cvar = _reg(project, "ds", codegen)
    push_addr = 0x4016
    global_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [ds_cvar, CConstant(0x1234, SimTypeShort(False), codegen=codegen)],
            codegen=codegen,
        ),
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": push_addr},
    )
    codegen.cfunc.statements.statements.append(global_store)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=push_addr, id=X86_INS_PUSH),)
                ),
            ),
        ),
    )

    changed = prune_consumed_call_push_stack_assignments_8616(
        project,
        codegen,
        frozenset({push_addr}),
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [global_store]
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_prune_call_return_frame_stack_assignments_removes_exact_call_carrier():
    project, codegen = _project()
    local_var = SimStackVariable(-2, 2, base="bp", name="index", region=0x4010)
    local_cvar = CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    false_return_frame_write = CAssignment(
        local_cvar,
        CConstant(0x4019, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    independent_write = CAssignment(
        local_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x401A},
    )
    codegen.cfunc.statements.statements.extend((false_return_frame_write, independent_write))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(address=0x4016, id=X86_INS_CALL),
                        SimpleNamespace(address=0x401A, id=X86_INS_MOV),
                    )
                ),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4016: 0x4019},
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == [independent_write]
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_prune_call_return_frame_reaches_switch_case_bodies():
    project, codegen = _project()
    local_var = SimStackVariable(-2, 2, base="bp", name="index", region=0x4010)
    local_cvar = CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    return_frame_write = CAssignment(
        local_cvar,
        CConstant(0x4019, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    preserved_write = CAssignment(
        local_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x401A},
    )
    case_body = CStatements([return_frame_write, preserved_write], codegen=codegen)
    switch = CSwitchCase(_const(1, codegen), [(1, case_body)], None, codegen=codegen)
    codegen.cfunc.statements.statements.append(switch)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(address=0x4016, id=X86_INS_CALL),
                        SimpleNamespace(address=0x401A, id=X86_INS_MOV),
                    )
                ),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4016: 0x4019},
        function=function,
    )

    assert changed is True
    assert case_body.statements == [preserved_write]
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_prune_call_return_frame_removes_exact_far_call_cs_byte_carriers():
    project, codegen = _project()
    ss_cvar = _reg(project, "ss", codegen)
    cs_cvar = _reg(project, "cs", codegen)
    low_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [ss_cvar, CConstant(0xFFFA, SimTypeShort(False), codegen=codegen)],
            codegen=codegen,
        ),
        cs_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    high_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [ss_cvar, CConstant(0xFFFB, SimTypeShort(False), codegen=codegen)],
            codegen=codegen,
        ),
        CBinaryOp(
            "Shr",
            cs_cvar,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    codegen.cfunc.statements.statements.extend((low_store, high_store))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=0x4016, id=X86_INS_LCALL),)
                ),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4016: 0x401B},
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (2, 2, 2, 2, 0)


def test_prune_call_return_frame_removes_only_exact_indexed_ss_cs_carriers():
    project, codegen = _project()
    cs_cvar = _reg(project, "cs", codegen)

    def indexed_stack_lvalue(
        offset: int,
        *,
        segment_name: str = "ss",
        scale: int = 16,
    ) -> CIndexedVariable:
        """Build the flattened indexed stack-store shape emitted by angr."""
        stack_cvar = CVariable(
            SimStackVariable(
                offset,
                1,
                base="bp",
                name=f"carrier_{offset}",
                region=0x4010,
            ),
            variable_type=SimTypeChar(),
            codegen=codegen,
        )
        return CIndexedVariable(
            CUnaryOp("Reference", stack_cvar, codegen=codegen),
            CBinaryOp(
                "Mul",
                CConstant(scale, SimTypeShort(False), codegen=codegen),
                _reg(project, segment_name, codegen),
                codegen=codegen,
            ),
            variable_type=SimTypeChar(),
            codegen=codegen,
        )

    low_store = CAssignment(
        indexed_stack_lvalue(-8),
        cs_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    high_store = CAssignment(
        indexed_stack_lvalue(-7),
        CBinaryOp(
            "Shr",
            cs_cvar,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    wrong_segment = CAssignment(
        indexed_stack_lvalue(-6, segment_name="ds"),
        cs_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    wrong_scale = CAssignment(
        indexed_stack_lvalue(-5, scale=8),
        cs_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    codegen.cfunc.statements.statements.extend(
        (low_store, high_store, wrong_segment, wrong_scale)
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=0x4016, id=X86_INS_LCALL),)
                ),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4016: 0x401B},
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == [wrong_segment, wrong_scale]
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (2, 2, 2, 2, 0)


def test_prune_call_return_frame_removes_linked_push_cs_virtual_byte_carriers():
    project, codegen = _project()
    ss_cvar = _reg(project, "ss", codegen)
    carrier_cvar = CVariable(
        SimStackVariable(-8, 2, base="bp", name="carrier", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    low_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [ss_cvar, CConstant(0xFFFA, SimTypeShort(False), codegen=codegen)],
            codegen=codegen,
        ),
        carrier_cvar,
        codegen=codegen,
        tags={"ins_addr": 0x4015},
    )
    high_store = CAssignment(
        CFunctionCall(
            "SEG_U8",
            None,
            [ss_cvar, CConstant(0xFFFB, SimTypeShort(False), codegen=codegen)],
            codegen=codegen,
        ),
        CBinaryOp(
            "Shr",
            carrier_cvar,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4015},
    )
    codegen.cfunc.statements.statements.extend((low_store, high_store))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(
                            address=0x4015,
                            id=X86_INS_PUSH,
                            size=1,
                            operands=(_reg_operand(X86_REG_CS),),
                        ),
                        SimpleNamespace(address=0x4016, id=X86_INS_CALL),
                    )
                ),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4016: 0x4019},
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (2, 2, 2, 2, 0)


def test_prune_call_return_frame_refuses_nonadjacent_push_cs_and_call():
    project, codegen = _project()
    destination = CVariable(
        SimStackVariable(-4, 2, base="bp", name="return_segment", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        CVariable(
            SimStackVariable(-8, 2, base="bp", name="carrier", region=0x4010),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4015},
    )
    codegen.cfunc.statements.statements.append(assignment)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(
                            address=0x4015,
                            id=X86_INS_PUSH,
                            size=1,
                            operands=(_reg_operand(X86_REG_CS),),
                        ),
                        SimpleNamespace(address=0x4016, id=X86_INS_MOV),
                        SimpleNamespace(address=0x4017, id=X86_INS_CALL),
                    )
                ),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4017: 0x401A},
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [assignment]
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


def test_prune_call_return_frame_refuses_non_cs_push_before_call():
    project, codegen = _project()
    destination = CVariable(
        SimStackVariable(-4, 2, base="bp", name="return_segment", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        _reg(project, "cs", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4015},
    )
    codegen.cfunc.statements.statements.append(assignment)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(
                            address=0x4015,
                            id=X86_INS_PUSH,
                            size=1,
                            operands=(_reg_operand(X86_REG_AX),),
                        ),
                        SimpleNamespace(address=0x4016, id=X86_INS_CALL),
                    )
                ),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4016: 0x4019},
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [assignment]
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


@pytest.mark.parametrize(("instruction_id", "register_name"), ((X86_INS_CALL, "cs"), (X86_INS_LCALL, "ds")))
def test_prune_call_return_frame_refuses_unproven_segment_carrier(
    instruction_id: int,
    register_name: str,
):
    project, codegen = _project()
    destination = CVariable(
        SimStackVariable(-4, 2, base="bp", name="return_segment", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        _reg(project, register_name, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    codegen.cfunc.statements.statements.append(assignment)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=0x4016, id=instruction_id),)
                ),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4016: 0x401B},
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [assignment]
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


def test_prune_call_return_frame_stack_assignments_ignores_nonconstant_call_result():
    project, codegen = _project()
    destination = CVariable(
        SimStackVariable(-2, 2, base="bp", name="result", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call_result = CVariable(
        SimStackVariable(4, 2, base="bp", name="argument", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source_assignment = CAssignment(
        destination,
        call_result,
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    codegen.cfunc.statements.statements.append(source_assignment)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(insns=(SimpleNamespace(address=0x4016, id=X86_INS_CALL),)),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4016: 0x4019},
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [source_assignment]
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert stats.raw_fact_count == 0
    assert stats.normalized_fact_count == 0
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


def test_prune_frame_prologue_stack_assignments_removes_exact_push_bp_carrier():
    project, codegen = _project()
    saved_frame_var = SimStackVariable(2, 2, base="bp", name="saved_frame", region=0x4010)
    frame_anchor_var = SimStackVariable(0, 2, base="bp", name="frame_anchor", region=0x4010)
    saved_frame = CVariable(saved_frame_var, variable_type=SimTypeShort(False), codegen=codegen)
    frame_anchor = CVariable(frame_anchor_var, variable_type=SimTypeShort(False), codegen=codegen)
    artifact = CAssignment(
        saved_frame,
        CUnaryOp("Reference", frame_anchor, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    nested = CStatements([artifact], codegen=codegen)
    codegen.cfunc.statements.statements.append(nested)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(
                            address=0x4010,
                            size=1,
                            id=X86_INS_PUSH,
                            operands=(_reg_operand(X86_REG_BP),),
                        ),
                        SimpleNamespace(
                            address=0x4011,
                            size=2,
                            id=X86_INS_MOV,
                            operands=(_reg_operand(X86_REG_BP), _reg_operand(X86_REG_SP)),
                        ),
                    )
                ),
            ),
        ),
    )

    changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is True
    assert nested.statements == []
    stats = codegen._inertia_frame_prologue_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)

    changed_again = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed_again is False
    assert codegen._inertia_frame_prologue_carrier_prune_8616 == stats


def test_prune_frame_prologue_stack_assignments_removes_typed_bp_dirty_carrier():
    project, codegen = _project()
    saved_frame = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    bp_offset = project.arch.registers["bp"][0]
    artifact = CAssignment(
        saved_frame,
        CDirtyExpression(SimpleNamespace(reg=bp_offset, bits=16), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    codegen.cfunc.statements.statements.append(artifact)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(
                            address=0x4010,
                            size=1,
                            id=X86_INS_PUSH,
                            operands=(_reg_operand(X86_REG_BP),),
                        ),
                        SimpleNamespace(
                            address=0x4011,
                            size=2,
                            id=X86_INS_MOV,
                            operands=(_reg_operand(X86_REG_BP), _reg_operand(X86_REG_SP)),
                        ),
                    )
                ),
            ),
        ),
    )

    changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    assert codegen._inertia_frame_prologue_carrier_prune_8616 == real_mode_linear.FramePrologueCarrierPrune8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def test_prune_frame_prologue_stack_assignments_refuses_non_bp_dirty_carrier():
    project, codegen = _project()
    saved_frame = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_offset = project.arch.registers["ax"][0]
    artifact = CAssignment(
        saved_frame,
        CDirtyExpression(SimpleNamespace(reg=ax_offset, bits=16), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    codegen.cfunc.statements.statements.append(artifact)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(
                            address=0x4010,
                            size=1,
                            id=X86_INS_PUSH,
                            operands=(_reg_operand(X86_REG_BP),),
                        ),
                        SimpleNamespace(
                            address=0x4011,
                            size=2,
                            id=X86_INS_MOV,
                            operands=(_reg_operand(X86_REG_BP), _reg_operand(X86_REG_SP)),
                        ),
                    )
                ),
            ),
        ),
    )

    changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [artifact]


def test_prune_frame_prologue_stack_assignments_refuses_non_bp_push():
    project, codegen = _project()
    saved_frame = CVariable(
        SimStackVariable(2, 2, base="bp", name="saved_frame", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    frame_anchor = CVariable(
        SimStackVariable(0, 2, base="bp", name="frame_anchor", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    artifact = CAssignment(
        saved_frame,
        CUnaryOp("Reference", frame_anchor, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    codegen.cfunc.statements.statements.append(artifact)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(
                            address=0x4010,
                            size=1,
                            id=X86_INS_PUSH,
                            operands=(_reg_operand(X86_REG_AX),),
                        ),
                        SimpleNamespace(
                            address=0x4011,
                            size=2,
                            id=X86_INS_MOV,
                            operands=(_reg_operand(X86_REG_BP), _reg_operand(X86_REG_SP)),
                        ),
                    )
                ),
            ),
        ),
    )

    changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [artifact]
    stats = codegen._inertia_frame_prologue_carrier_prune_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0


def test_callee_saved_frame_evidence_retries_after_incomplete_decode(monkeypatch):
    project, _codegen = _project()
    function = SimpleNamespace(addr=0x4010)
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda *, addr, create: function if addr == function.addr else None)
    )
    push_di = SimpleNamespace(
        address=0x4014,
        id=X86_INS_PUSH,
        operands=(_reg_operand(X86_REG_DI),),
        reg_name=lambda reg: "di" if reg == X86_REG_DI else "",
    )
    pop_di = SimpleNamespace(
        address=0x4030,
        id=X86_INS_POP,
        operands=(_reg_operand(X86_REG_DI),),
        reg_name=lambda reg: "di" if reg == X86_REG_DI else "",
    )
    ret = SimpleNamespace(address=0x4031, id=X86_INS_RET, operands=())
    current_insns = [push_di]

    monkeypatch.setattr(
        real_mode_linear,
        "_direct_global_update_blocks_8616",
        lambda _project, _function: (
            SimpleNamespace(capstone=SimpleNamespace(insns=tuple(current_insns))),
        ),
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_capstone_insns_for_direct_global_update_8616",
        lambda _project, block: block.capstone.insns,
    )

    assert real_mode_linear._callee_saved_register_names_from_frame_evidence_8616(project, function.addr) == frozenset()
    assert project._inertia_decode_function_insns_cache_8616 == {}
    assert project._inertia_callee_saved_register_names_cache_8616 == {}

    current_insns[:] = [push_di, pop_di, ret]

    assert real_mode_linear._callee_saved_register_names_from_frame_evidence_8616(project, function.addr) == frozenset(
        {"di"}
    )
    assert project._inertia_decode_function_insns_cache_8616[(function.addr, 0x100)] == (push_di, pop_di, ret)
    assert project._inertia_callee_saved_register_names_cache_8616[function.addr] == frozenset({"di"})


def test_callee_saved_frame_evidence_accepts_far_return_and_segment_pair(monkeypatch):
    project, _codegen = _project()
    function = SimpleNamespace(addr=0x4010)
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda *, addr, create: function if addr == function.addr else None
        )
    )
    push_ds = SimpleNamespace(
        address=0x4010,
        id=X86_INS_PUSH,
        groups=(),
        operands=(_reg_operand(X86_REG_DS),),
        reg_name=lambda reg: "ds" if reg == X86_REG_DS else "",
        regs_access=lambda: ((X86_REG_DS,), ()),
    )
    pop_ds = SimpleNamespace(
        address=0x4020,
        id=X86_INS_POP,
        groups=(),
        operands=(_reg_operand(X86_REG_DS),),
        reg_name=lambda reg: "ds" if reg == X86_REG_DS else "",
        regs_access=lambda: ((), (X86_REG_DS,)),
    )
    retf = SimpleNamespace(
        address=0x4021,
        id=X86_INS_RETF,
        groups=(X86_GRP_RET,),
        operands=(),
    )
    trailing = SimpleNamespace(address=0x4022, id=X86_INS_MOV, groups=(), operands=())
    monkeypatch.setattr(
        real_mode_linear,
        "_direct_global_update_blocks_8616",
        lambda _project, _function: (
            SimpleNamespace(
                capstone=SimpleNamespace(insns=(push_ds, pop_ds, retf, trailing))
            ),
        ),
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_capstone_insns_for_direct_global_update_8616",
        lambda _project, block: block.capstone.insns,
    )

    decoded = real_mode_linear._decode_function_insns_8616(
        project,
        function.addr,
        function=function,
    )

    assert decoded == (push_ds, pop_ds, retf)
    assert real_mode_linear._callee_saved_register_names_from_frame_evidence_8616(
        project,
        function.addr,
        function=function,
    ) == frozenset({"ds"})


def test_callee_saved_frame_evidence_deduplicates_and_rejects_post_pop_write(monkeypatch):
    from capstone.x86_const import X86_INS_INC

    project, _codegen = _project()
    function = SimpleNamespace(addr=0x4010)
    push_si = SimpleNamespace(
        address=0x4010,
        id=X86_INS_PUSH,
        operands=(_reg_operand(X86_REG_SI),),
        reg_name=lambda reg: "si" if reg == X86_REG_SI else "",
        regs_access=lambda: ((), ()),
    )
    push_di = SimpleNamespace(
        address=0x4011,
        id=X86_INS_PUSH,
        operands=(_reg_operand(X86_REG_DI),),
        reg_name=lambda reg: "di" if reg == X86_REG_DI else "",
        regs_access=lambda: ((), ()),
    )
    pop_di = SimpleNamespace(
        address=0x4020,
        id=X86_INS_POP,
        operands=(_reg_operand(X86_REG_DI),),
        reg_name=lambda reg: "di" if reg == X86_REG_DI else "",
        regs_access=lambda: ((), (X86_REG_DI,)),
    )
    pop_si = SimpleNamespace(
        address=0x4021,
        id=X86_INS_POP,
        operands=(_reg_operand(X86_REG_SI),),
        reg_name=lambda reg: "si" if reg == X86_REG_SI else "",
        regs_access=lambda: ((), (X86_REG_SI,)),
    )
    inc_si = SimpleNamespace(
        address=0x4022,
        id=X86_INS_INC,
        operands=(_reg_operand(X86_REG_SI),),
        reg_name=lambda reg: "si" if reg == X86_REG_SI else "",
        regs_access=lambda: ((X86_REG_SI,), (X86_REG_SI,)),
    )
    ret = SimpleNamespace(address=0x4023, id=X86_INS_RET, operands=())
    decoded = (push_si, push_si, push_di, push_di, pop_di, pop_di, pop_si, pop_si, inc_si, inc_si, ret)
    monkeypatch.setattr(real_mode_linear, "_decode_function_insns_8616", lambda *_args, **_kwargs: decoded)

    assert real_mode_linear._callee_saved_register_names_from_frame_evidence_8616(
        project,
        function.addr,
        function=function,
    ) == frozenset({"di"})


def test_prune_frame_round_trip_before_explicit_register_update(monkeypatch):
    """Prune SI stack transport while retaining the later INC assignment."""
    from angr_platforms.X86_16.lowering.callee_saved_frame import (
        CalleeSavedFramePairSemantics8616,
    )
    from capstone.x86_const import X86_INS_INC

    project, codegen = _project()
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    si = CVariable(
        SimRegisterVariable(project.arch.registers["si"][0], 2, name="si"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    push_assignment = CAssignment(local, si, codegen=codegen, tags={"ins_addr": 0x4010})
    pop_assignment = CAssignment(si, local, codegen=codegen, tags={"ins_addr": 0x4021})
    increment_assignment = CAssignment(si, si, codegen=codegen, tags={"ins_addr": 0x4022})
    codegen.cfunc.statements.statements.extend(
        (push_assignment, pop_assignment, increment_assignment)
    )

    def _si_insn(address: int, instruction_id: int) -> SimpleNamespace:
        return SimpleNamespace(
            address=address,
            id=instruction_id,
            operands=(_reg_operand(X86_REG_SI),),
            reg_name=lambda reg: "si" if reg == X86_REG_SI else "",
            regs_access=lambda: (
                (X86_REG_SI,),
                (X86_REG_SI,) if instruction_id != X86_INS_PUSH else (),
            ),
        )

    decoded = (
        _si_insn(0x4010, X86_INS_PUSH),
        _si_insn(0x4021, X86_INS_POP),
        _si_insn(0x4022, X86_INS_INC),
        SimpleNamespace(address=0x4023, id=X86_INS_RET, operands=()),
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_decode_function_insns_8616",
        lambda *_args, **_kwargs: decoded,
    )

    assert prune_callee_saved_stack_spills_8616(codegen, project) is True
    assert codegen.cfunc.statements.statements == [increment_assignment]
    record = codegen._inertia_callee_saved_frame_prune_record_8616
    assert {fact.pair_semantics for fact in record.evidence} == {
        CalleeSavedFramePairSemantics8616.RESTORED_BEFORE_UPDATE
    }


def test_prune_callee_saved_stack_spills_refuses_mismatched_restore(monkeypatch):
    project, codegen = _project()
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    di = CVariable(
        SimRegisterVariable(project.arch.registers["di"][0], 2, name="di"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(local, di, codegen=codegen, tags={"ins_addr": 0x4014})
    codegen.cfunc.statements.statements.append(assignment)
    push_di = SimpleNamespace(
        address=0x4014,
        id=X86_INS_PUSH,
        operands=(_reg_operand(X86_REG_DI),),
        reg_name=lambda reg: "di" if reg == X86_REG_DI else "",
    )
    pop_si = SimpleNamespace(
        address=0x4030,
        id=X86_INS_POP,
        operands=(_reg_operand(X86_REG_SI),),
        reg_name=lambda reg: "si" if reg == X86_REG_SI else "",
    )
    ret = SimpleNamespace(address=0x4031, id=X86_INS_RET, operands=())
    monkeypatch.setattr(
        real_mode_linear,
        "_decode_function_insns_8616",
        lambda _project, _addr, limit=0x100, function=None: (push_di, pop_si, ret),
    )

    assert prune_callee_saved_stack_spills_8616(codegen, project) is False
    assert codegen.cfunc.statements.statements == [assignment]
    assert project._inertia_callee_saved_register_names_cache_8616 == {}


def test_prune_callee_saved_stack_spills_uses_current_structuring_function(monkeypatch):
    project, codegen = _project()
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    di = CVariable(
        SimRegisterVariable(project.arch.registers["di"][0], 2, name="di"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(local, di, codegen=codegen, tags={"ins_addr": 0x4014})
    codegen.cfunc.statements.statements.append(assignment)
    push_di = SimpleNamespace(
        address=0x4014,
        id=X86_INS_PUSH,
        operands=(_reg_operand(X86_REG_DI),),
        reg_name=lambda reg: "di" if reg == X86_REG_DI else "",
    )
    pop_di = SimpleNamespace(
        address=0x4030,
        id=X86_INS_POP,
        operands=(_reg_operand(X86_REG_DI),),
        reg_name=lambda reg: "di" if reg == X86_REG_DI else "",
    )
    ret = SimpleNamespace(address=0x4031, id=X86_INS_RET, operands=())
    stale_function = SimpleNamespace(addr=0x4010, evidence=(push_di,))
    current_function = SimpleNamespace(addr=0x4010, evidence=(push_di, pop_di, ret))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda *, addr, create: stale_function if addr == 0x4010 else None)
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_direct_global_update_blocks_8616",
        lambda _project, function: (
            SimpleNamespace(capstone=SimpleNamespace(insns=function.evidence)),
        ),
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_capstone_insns_for_direct_global_update_8616",
        lambda _project, block: block.capstone.insns,
    )

    assert prune_callee_saved_stack_spills_8616(
        codegen,
        project,
        function=current_function,
    ) is True
    assert codegen.cfunc.statements.statements == []
    assert project._inertia_callee_saved_register_names_cache_8616[
        (current_function.addr, id(current_function))
    ] == frozenset({"di"})


def test_prune_callee_saved_stack_spills_refuses_later_argument_push(monkeypatch):
    project, codegen = _project()
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    di = CVariable(
        SimRegisterVariable(project.arch.registers["di"][0], 2, name="di"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(local, di, codegen=codegen, tags={"ins_addr": 0x4020})
    codegen.cfunc.statements.statements.append(assignment)

    def _di_insn(address: int, instruction_id: int) -> SimpleNamespace:
        return SimpleNamespace(
            address=address,
            id=instruction_id,
            operands=(_reg_operand(X86_REG_DI),),
            reg_name=lambda reg: "di" if reg == X86_REG_DI else "",
        )

    push_di = _di_insn(0x4014, X86_INS_PUSH)
    argument_push_di = _di_insn(0x4020, X86_INS_PUSH)
    pop_di = _di_insn(0x4030, X86_INS_POP)
    ret = SimpleNamespace(address=0x4031, id=X86_INS_RET, operands=())
    monkeypatch.setattr(
        real_mode_linear,
        "_decode_function_insns_8616",
        lambda _project, _addr, limit=0x100, function=None: (
            push_di,
            argument_push_di,
            pop_di,
            ret,
        ),
    )

    assert prune_callee_saved_stack_spills_8616(codegen, project) is False
    assert codegen.cfunc.statements.statements == [assignment]


@pytest.mark.parametrize(
    ("instruction_id", "rhs_value"),
    (
        (X86_INS_MOV, 0x4019),
        (X86_INS_CALL, 0x4020),
    ),
)
def test_prune_call_return_frame_stack_assignments_refuses_near_matches(
    instruction_id: int,
    rhs_value: int,
):
    project, codegen = _project()
    local_var = SimStackVariable(-2, 2, base="bp", name="index", region=0x4010)
    local_cvar = CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    assignment = CAssignment(
        local_cvar,
        CConstant(rhs_value, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    codegen.cfunc.statements.statements.append(assignment)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(insns=(SimpleNamespace(address=0x4016, id=instruction_id),)),
            ),
        ),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x4016: 0x4019},
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [assignment]
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


def test_materialize_direct_stack_mov_stack_copy_is_idempotent():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    anchor_var = SimStackVariable(-6, 2, base="bp", name="anchor", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    anchor_cvar = CVariable(anchor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    codegen.cfunc.variables_in_use[anchor_var] = anchor_cvar
    codegen.cfunc.statements.statements.append(
        CAssignment(
            anchor_cvar,
            CConstant(7, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4019},
        )
    )

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),))

    first = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)
    second = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert first is True
    assert second is False
    assignments = [
        stmt
        for stmt in codegen.cfunc.statements.statements
        if isinstance(stmt, CAssignment) and getattr(stmt, "lhs", None) is dst_cvar
    ]
    assert len(assignments) == 1
    assert assignments[0].rhs is src_cvar


def test_materialize_direct_stack_mov_refuses_duplicate_across_transparent_statement_wrapper():
    project, codegen = _project()
    dst_var = SimStackVariable(-2, 2, base="bp", name="i", region=0x4010)
    src_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    anchor_var = SimStackVariable(-6, 2, base="bp", name="anchor", region=0x4010)
    dst_cvar = CVariable(dst_var, variable_type=SimTypeShort(False), codegen=codegen)
    src_cvar = CVariable(src_var, variable_type=SimTypeShort(False), codegen=codegen)
    anchor_cvar = CVariable(anchor_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[dst_var] = dst_cvar
    codegen.cfunc.variables_in_use[src_var] = src_cvar
    codegen.cfunc.variables_in_use[anchor_var] = anchor_cvar
    anchor = CAssignment(
        anchor_cvar,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4019},
    )
    existing = CAssignment(dst_cvar, src_cvar, codegen=codegen)
    nested_existing = CStatements([existing], codegen=codegen)
    codegen.cfunc.statements.statements.extend([anchor, nested_existing])

    src_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-4)
    dst_mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    ax_dst = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    ax_src = SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX)
    load = SimpleNamespace(
        address=0x4017,
        id=X86_INS_MOV,
        operands=(ax_dst, SimpleNamespace(type=X86_OP_MEM, size=2, mem=src_mem)),
    )
    store = SimpleNamespace(
        address=0x401A,
        id=X86_INS_MOV,
        operands=(SimpleNamespace(type=X86_OP_MEM, size=2, mem=dst_mem), ax_src),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),))

    changed = materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen.cfunc.statements.statements == [anchor, nested_existing]
    assert nested_existing.statements == [existing]
    assert codegen._inertia_direct_stack_move_lowering_8616["already_materialized_count"] == 1
    assert codegen._inertia_direct_stack_move_lowering_8616["failure_count"] == 0


def test_materialize_direct_stack_dec_refuses_without_tagged_assignment():
    project, codegen = _project()
    mem = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    operand = SimpleNamespace(type=X86_OP_MEM, size=2, mem=mem)
    insn = SimpleNamespace(address=0x4018, id=X86_INS_DEC, operands=(operand,))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),))

    changed = materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)

    assert changed is False
    assert codegen._inertia_direct_stack_update_lowering_8616["raw_fact_count"] == 1
    assert codegen._inertia_direct_stack_update_lowering_8616["classified_fact_count"] == 1
    assert codegen._inertia_direct_stack_update_lowering_8616["materialized_count"] == 0
    assert codegen._inertia_direct_stack_update_lowering_8616["failure_count"] == 1
    lane = codegen._inertia_direct_stack_update_lane_8616
    assert lane.classified == 1
    assert lane.materialized == 0
    assert lane.failures == 1
    with pytest.raises(PipelineHardError, match="direct_stack_update: 1 facts classified but 0 materialized"):
        assert_pipeline_contracts_8616(codegen)


def test_direct_stack_update_facts_filter_broad_slice_to_active_function():
    project = SimpleNamespace(_inertia_tv_active_function_addr=0x1200)
    function = SimpleNamespace(addr=0x1000)
    before = DirectStackUpdateFact8616(-2, 2, 1, 0x1010)
    active = DirectStackUpdateFact8616(-2, 2, 1, 0x1210)

    filtered = _filter_direct_stack_update_facts_for_active_function_8616(project, function, (before, active))

    assert filtered == (active,)


def test_direct_stack_update_facts_filter_keeps_exact_region_facts_for_original_active_addr():
    project = SimpleNamespace(_inertia_tv_active_function_addr=0x10054, _inertia_original_linear_delta=0xF054)
    function = SimpleNamespace(addr=0x1000)
    exact_fact = DirectStackUpdateFact8616(-4, 2, 1, 0x1018)

    filtered = _filter_direct_stack_update_facts_for_active_function_8616(project, function, (exact_fact,))

    assert filtered == (exact_fact,)


def _const(value: int, codegen, sim_type=None):
    return CConstant(value, sim_type or SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _seg_linear(project, seg_name: str, offset_expr, codegen, *, shl: bool = False):
    segment = _reg(project, seg_name, codegen)
    scale = _const(4 if shl else 16, codegen)
    op = "Shl" if shl else "Mul"
    return CBinaryOp("Add", CBinaryOp(op, segment, scale, codegen=codegen), offset_expr, codegen=codegen)


def test_lower_runtime_segment_access_rewrites_ds_word_dereference_to_seg_u16():
    project, codegen = _project()
    operand = _seg_linear(project, "ds", _const(0x0BA2, codegen), codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)
    expr.tags = {"ins_addr": 0x4042}

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U16"
    assert lowered.args[0].variable.name == "ds"
    assert lowered.args[1].value == 0x0BA2
    identity = segmented_load_identity_8616(lowered)
    assert identity is not None
    assert identity.space is MemSpace.DS
    assert identity.offset == 0x0BA2
    assert identity.width == 2
    assert identity.region == codegen.cfunc.addr
    assert lowered.tags["inertia_source_instruction_addrs"] == (0x4042,)


def _logical_ds_access(
    *,
    function_addr: int,
    insn_addr: int,
    ordinal: int,
    width: int,
) -> IRLogicalMemoryAccess8616:
    """Build one complete logical DS access for width-projection tests."""
    address = IRAddress(
        MemSpace.DS,
        base=("si",),
        size=width,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    slices = tuple(
        IRMemoryExecutionSlice8616(
            block_addr=insn_addr,
            instr_index=index,
            insn_addr=insn_addr,
            source_byte_offset=index,
            address=IRAddress(
                MemSpace.DS,
                base=("si",),
                offset=index,
                size=1,
                status=AddressStatus.STABLE,
                segment_origin=SegmentOrigin.PROVEN,
            ),
        )
        for index in range(width)
    )
    return IRLogicalMemoryAccess8616(
        key=IRLogicalMemoryAccessKey8616(
            function_addr=function_addr,
            block_addr=insn_addr,
            insn_addr=insn_addr,
            access_ordinal=ordinal,
        ),
        kind=IRMemoryAccessKind8616.WRITE,
        address=address,
        address_bits=16,
        execution_slices=slices,
    )


def _publish_logical_accesses(
    project: object,
    *,
    function_addr: int,
    accesses: tuple[IRLogicalMemoryAccess8616, ...],
) -> None:
    """Publish one closed SSA logical-memory artifact on a test project."""
    logical = IRLogicalMemoryArtifact8616(
        function_addr=function_addr,
        accesses=accesses,
        refusals=(),
        stats=IRLogicalMemoryStats8616(
            raw_fact_count=len(accesses),
            normalized_fact_count=len(accesses),
            classified_fact_count=len(accesses),
            materialized_count=len(accesses),
        ),
    )
    project._inertia_function_ssa_artifacts_8616 = {
        function_addr: SSAFunctionArtifact(
            function_addr=function_addr,
            blocks=(),
            logical_memory=logical,
        )
    }
    project._inertia_function_ssa_stages_8616 = {}


@pytest.mark.parametrize("logical_width,rendered_byte", ((1, False), (2, True)))
def test_lower_runtime_segment_access_prefers_exact_ir_byte_store_width(logical_width, rendered_byte):
    """Narrow a proven byte access, but never widen a word's byte fragment."""
    project, codegen = _project()
    codegen.cfunc.functy = SimpleNamespace(args=())
    insn_addr = 0x4042
    _publish_logical_accesses(
        project,
        function_addr=codegen.cfunc.addr,
        accesses=(
            _logical_ds_access(
                function_addr=codegen.cfunc.addr,
                insn_addr=insn_addr,
                ordinal=0,
                width=logical_width,
            ),
        ),
    )
    operand = _seg_linear(project, "ds", _reg(project, "si", codegen), codegen)
    operand._type = SimTypePointer(SimTypeChar(False) if rendered_byte else SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)
    expr.tags = {"ins_addr": insn_addr}

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U8"
    if rendered_byte:
        return
    lane = codegen._inertia_segmented_access_width_lane_8616
    assert lane.raw_fact_count == 1
    assert lane.normalized_fact_count == 1
    assert lane.classified_fact_count == 1
    assert lane.materialized_count == 1
    assert lane.failure_count == 0


def test_lower_runtime_segment_access_refuses_ambiguous_ir_store_width():
    """Conflicting logical widths remain visible and do not guess a helper."""
    project, codegen = _project()
    codegen.cfunc.functy = SimpleNamespace(args=())
    insn_addr = 0x4042
    _publish_logical_accesses(
        project,
        function_addr=codegen.cfunc.addr,
        accesses=tuple(
            _logical_ds_access(
                function_addr=codegen.cfunc.addr,
                insn_addr=insn_addr,
                ordinal=ordinal,
                width=width,
            )
            for ordinal, width in enumerate((1, 2))
        ),
    )
    operand = _seg_linear(project, "ds", _reg(project, "si", codegen), codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)
    expr.tags = {"ins_addr": insn_addr}

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U16"
    lane = codegen._inertia_segmented_access_width_lane_8616
    assert lane.raw_fact_count == 1
    assert lane.normalized_fact_count == 1
    assert lane.classified_fact_count == 1
    assert lane.materialized_count == 0
    assert lane.failure_count == 1
    with pytest.raises(PipelineHardError, match="segmented_access_width"):
        assert_pipeline_contracts_8616(codegen)


def test_lower_runtime_segment_access_rewrites_zero_plus_pointer_arg_to_indexed_load():
    project, codegen = _project()
    arg_var = SimStackVariable(4, 2, base="bp", name="bar1", region=0x4010)
    arg_type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    arg_cvar = CVariable(arg_var, variable_type=arg_type, codegen=codegen)
    codegen.cfunc.arg_list = [arg_cvar]
    codegen.cfunc.functy = SimTypeFunction([arg_type], SimTypeShort(False), arg_names=["bar1"]).with_arch(
        project.arch
    )
    offset = CBinaryOp("Add", _const(0, codegen), arg_cvar, codegen=codegen)
    operand = _seg_linear(project, "ds", offset, codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CIndexedVariable)
    assert lowered.variable is arg_cvar
    assert isinstance(lowered.index, CConstant)
    assert lowered.index.value == 0


def test_lower_runtime_segment_access_rewrites_scaled_pointer_arg_to_indexed_load():
    project, codegen = _project()
    arg_var = SimStackVariable(6, 2, base="bp", name="argv", region=0x4010)
    arg_type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    arg_cvar = CVariable(arg_var, variable_type=arg_type, codegen=codegen)
    index_cvar = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [arg_cvar]
    codegen.cfunc.functy = SimTypeFunction([arg_type], SimTypeShort(False), arg_names=["argv"]).with_arch(
        project.arch
    )
    scaled_index = CBinaryOp("Shl", index_cvar, _const(1, codegen), codegen=codegen)
    offset = CBinaryOp("Add", arg_cvar, scaled_index, codegen=codegen)
    operand = _seg_linear(project, "ds", offset, codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CIndexedVariable)
    assert lowered.variable is arg_cvar
    assert lowered.index is index_cvar


def test_lower_runtime_segment_access_refines_provisional_pointer_pointee_from_exact_fact():
    project, codegen = _project()
    arg_var = SimStackVariable(6, 2, base="bp", name="dst", region=0x4010)
    provisional_type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    arg_cvar = CVariable(arg_var, variable_type=provisional_type, codegen=codegen)
    index_cvar = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [arg_cvar]
    codegen.cfunc.functy = SimTypeFunction(
        [provisional_type], SimTypeShort(False), arg_names=["dst"]
    ).with_arch(project.arch)
    codegen._inertia_near_pointer_argument_facts_8616 = (
        NearPointerArgumentFact8616(6, 0x4014, 0x4018, 1),
    )
    codegen._inertia_near_pointer_argument_classified_offsets_8616 = set()
    codegen._inertia_near_pointer_argument_materialized_offsets_8616 = set()
    offset = CBinaryOp("Add", arg_cvar, index_cvar, codegen=codegen)
    operand = _seg_linear(project, "ds", offset, codegen)
    operand._type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)

    lowered = lower_runtime_segment_access_8616(
        CUnaryOp("Dereference", operand, codegen=codegen),
        target="portable-flat",
    )

    assert isinstance(lowered, CIndexedVariable), (
        arg_cvar.variable_type,
        codegen._inertia_near_pointer_argument_classified_offsets_8616,
        codegen._inertia_near_pointer_argument_materialized_offsets_8616,
    )
    assert isinstance(arg_cvar.variable_type.pts_to, SimTypeChar)
    assert isinstance(codegen.cfunc.functy.args[0].pts_to, SimTypeChar)


def test_lower_runtime_segment_access_refuses_pointer_arg_with_wrong_index_scale():
    project, codegen = _project()
    arg_var = SimStackVariable(6, 2, base="bp", name="argv", region=0x4010)
    arg_type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    arg_cvar = CVariable(arg_var, variable_type=arg_type, codegen=codegen)
    index_cvar = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [arg_cvar]
    codegen.cfunc.functy = SimTypeFunction([arg_type], SimTypeShort(False), arg_names=["argv"]).with_arch(
        project.arch
    )
    wrong_scale = CBinaryOp("Shl", index_cvar, _const(2, codegen), codegen=codegen)
    offset = CBinaryOp("Add", arg_cvar, wrong_scale, codegen=codegen)
    operand = _seg_linear(project, "ds", offset, codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U16"


def test_lower_runtime_segment_access_does_not_drop_unparsed_proven_index():
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    argv_var = SimStackVariable(6, 2, base="bp", name="argv", region=0x4010)
    argv_cvar = CVariable(argv_var, variable_type=scalar_type, codegen=codegen)
    index_cvar = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [argv_cvar]
    codegen.cfunc.functy = SimTypeFunction(
        [scalar_type],
        SimTypeShort(False),
        arg_names=["argv"],
    ).with_arch(project.arch)
    codegen._inertia_near_pointer_argument_facts_8616 = (
        NearPointerArgumentFact8616(
            stack_offset=6,
            carrier_load_ins_addr=0x4014,
            dereference_ins_addr=0x4018,
            access_width_bytes=2,
        ),
    )
    codegen._inertia_near_pointer_argument_classified_offsets_8616 = set()
    codegen._inertia_near_pointer_argument_materialized_offsets_8616 = set()
    unproven_scale = CBinaryOp(
        "Shl",
        index_cvar,
        _const(2, codegen),
        codegen=codegen,
    )
    offset = CBinaryOp("Add", argv_cvar, unproven_scale, codegen=codegen)
    operand = _seg_linear(project, "ds", offset, codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U16"
    assert argv_cvar.variable_type is scalar_type


def test_apply_runtime_segment_lowering_joins_register_carrier_by_instruction_fact():
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    argv = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [argv]
    codegen.cfunc.functy = SimTypeFunction(
        [scalar_type],
        SimTypeShort(False),
        arg_names=["argv"],
    ).with_arch(project.arch)
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [_reg(project, "ds", codegen), _reg(project, "bx", codegen)],
        codegen=codegen,
        tags={
            "inertia_x86_16_runtime_segment_helper": "SEG_U16",
            "inertia_source_instruction_addrs": (0x4018,),
        },
    )
    codegen.cfunc.statements.statements.append(CExpressionStatement(helper, codegen=codegen))
    load_argv = SimpleNamespace(
        address=0x4014,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(6)),
    )
    dereference_argv = SimpleNamespace(
        address=0x4018,
        id=X86_INS_PUSH,
        operands=(_reg_indirect_mem_operand(X86_REG_BX),),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(
                addr=0x4014,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(insn=load_argv),
                        SimpleNamespace(insn=dereference_argv),
                    )
                ),
            ),
        )
    )
    project.kb = SimpleNamespace(functions=SimpleNamespace(get=lambda _addr: function))

    changed = apply_runtime_segment_lowering_8616(codegen)
    lowered = codegen.cfunc.statements.statements[0].expr

    assert changed is True
    assert isinstance(lowered, CIndexedVariable)
    assert lowered.variable is argv
    assert isinstance(lowered.index, CConstant)
    assert lowered.index.value == 0
    assert isinstance(argv.variable_type, SimTypePointer)
    assert isinstance(codegen.cfunc.functy.args[0], SimTypePointer)


def test_apply_runtime_segment_lowering_consumes_typed_pointer_register_store_carrier():
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    argv = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    bx = _reg(project, "bx", codegen)
    value = CVariable(
        SimRegisterVariable(*project.arch.registers["ax"], name="value"),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [argv]
    codegen.cfunc.functy = SimTypeFunction(
        [scalar_type],
        SimTypeShort(False),
        arg_names=["argv"],
    ).with_arch(project.arch)
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [_reg(project, "ds", codegen), bx],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U16"},
    )
    codegen.cfunc.statements.statements.extend(
        [
            CAssignment(bx, argv, codegen=codegen),
            CAssignment(helper, value, codegen=codegen),
        ]
    )
    load_argv = SimpleNamespace(
        address=0x4014,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(6)),
    )
    store_argv = SimpleNamespace(
        address=0x4018,
        id=X86_INS_MOV,
        operands=(_reg_indirect_mem_operand(X86_REG_BX), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(
                addr=0x4014,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(insn=load_argv),
                        SimpleNamespace(insn=store_argv),
                    )
                ),
            ),
        )
    )
    project.kb = SimpleNamespace(functions=SimpleNamespace(get=lambda _addr: function))

    changed = apply_runtime_segment_lowering_8616(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    result = codegen.cfunc.statements.statements[0]
    assert isinstance(result, CAssignment)
    assert isinstance(result.lhs, CIndexedVariable)
    assert result.lhs.variable is argv
    assert isinstance(result.lhs.index, CConstant)
    assert result.lhs.index.value == 0
    assert result.rhs is value


def test_apply_runtime_segment_lowering_reassembles_pointer_word_store_byte_pair():
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    argv = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    bx = _reg(project, "bx", codegen)
    value = CVariable(
        SimRegisterVariable(*project.arch.registers["ax"], name="value"),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [argv]
    codegen.cfunc.functy = SimTypeFunction(
        [scalar_type],
        SimTypeShort(False),
        arg_names=["argv"],
    ).with_arch(project.arch)
    low_helper = CFunctionCall(
        "SEG_U8",
        None,
        [_reg(project, "ds", codegen), bx],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
    )
    high_helper = CFunctionCall(
        "SEG_U8",
        None,
        [
            _reg(project, "ds", codegen),
            CBinaryOp("Add", bx, _const(1, codegen), codegen=codegen),
        ],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
    )
    codegen.cfunc.statements.statements.extend(
        [
            CAssignment(bx, argv, codegen=codegen),
            CAssignment(low_helper, value, codegen=codegen),
            CAssignment(
                high_helper,
                CBinaryOp("Shr", value, _const(8, codegen), codegen=codegen),
                codegen=codegen,
            ),
        ]
    )
    load_argv = SimpleNamespace(
        address=0x4014,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(6)),
    )
    store_argv = SimpleNamespace(
        address=0x4018,
        id=X86_INS_MOV,
        operands=(_reg_indirect_mem_operand(X86_REG_BX), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(
                addr=0x4014,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(insn=load_argv),
                        SimpleNamespace(insn=store_argv),
                    )
                ),
            ),
        )
    )
    project.kb = SimpleNamespace(functions=SimpleNamespace(get=lambda _addr: function))

    changed = apply_runtime_segment_lowering_8616(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    result = codegen.cfunc.statements.statements[0]
    assert isinstance(result, CAssignment)
    assert isinstance(result.lhs, CIndexedVariable)
    assert result.lhs.variable is argv
    assert isinstance(result.lhs.index, CConstant)
    assert result.lhs.index.value == 0
    assert result.rhs is value


def test_runtime_segment_lowering_materializes_one_word_store_from_ir_width():
    """One logical word write must not become two word-pointer elements."""
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    argv = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    bx = _reg(project, "bx", codegen)
    value = CVariable(
        SimRegisterVariable(*project.arch.registers["ax"], name="value"),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [argv]
    codegen.cfunc.functy = SimTypeFunction(
        [scalar_type],
        SimTypeShort(False),
        arg_names=["argv"],
    ).with_arch(project.arch)
    low_operand = _seg_linear(project, "ds", bx, codegen)
    low_operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    low_lhs = CUnaryOp("Dereference", low_operand, codegen=codegen)
    high_operand = _seg_linear(
        project,
        "ds",
        CBinaryOp("Add", bx, _const(1, codegen), codegen=codegen),
        codegen,
    )
    high_operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    high_lhs = CUnaryOp("Dereference", high_operand, codegen=codegen)
    store_addr = 0x4018
    low_lhs.tags = {"ins_addr": store_addr}
    high_lhs.tags = {"ins_addr": store_addr}
    codegen.cfunc.statements.statements.extend(
        [
            CAssignment(bx, argv, codegen=codegen),
            CAssignment(low_lhs, value, codegen=codegen),
            CAssignment(
                high_lhs,
                CBinaryOp("Shr", value, _const(8, codegen), codegen=codegen),
                codegen=codegen,
            ),
        ]
    )
    load_argv = SimpleNamespace(
        address=0x4014,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(6)),
    )
    store_argv = SimpleNamespace(
        address=store_addr,
        id=X86_INS_MOV,
        operands=(_reg_indirect_mem_operand(X86_REG_BX), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(
                addr=0x4014,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(insn=load_argv),
                        SimpleNamespace(insn=store_argv),
                    )
                ),
            ),
        )
    )
    project.kb = SimpleNamespace(functions=SimpleNamespace(get=lambda _addr: function))
    _publish_logical_accesses(
        project,
        function_addr=codegen.cfunc.addr,
        accesses=(
            _logical_ds_access(
                function_addr=codegen.cfunc.addr,
                insn_addr=store_addr,
                ordinal=0,
                width=2,
            ),
        ),
    )

    changed = apply_runtime_segment_lowering_8616(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    result = codegen.cfunc.statements.statements[0]
    assert isinstance(result, CAssignment)
    assert isinstance(result.lhs, CIndexedVariable)
    assert result.lhs.variable is argv
    assert isinstance(result.lhs.index, CConstant)
    assert result.lhs.index.value == 0
    assert result.rhs is value


def test_lower_runtime_segment_access_joins_cloned_argument_to_canonical_pointer_type():
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    canonical_argv = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x4010),
        variable_type=pointer_type,
        codegen=codegen,
    )
    cloned_argv = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [canonical_argv]
    codegen.cfunc.functy = SimTypeFunction(
        [pointer_type],
        SimTypeShort(False),
        arg_names=["argv"],
    ).with_arch(project.arch)
    offset = CBinaryOp(
        "Add",
        cloned_argv,
        CBinaryOp("Shl", index, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    operand = _seg_linear(project, "ds", offset, codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="portable-flat")

    assert isinstance(lowered, CIndexedVariable)
    assert lowered.variable is cloned_argv
    assert lowered.index is index
    assert cloned_argv.variable_type is pointer_type


def test_runtime_segment_carrier_refuses_to_override_explicit_ds_with_stack_offset_proof():
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="argument", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    explicit_ds = _reg(project, "ds", codegen)
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [
            explicit_ds,
            CBinaryOp("Add", _const(0, codegen), argument, codegen=codegen),
        ],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U16"},
    )
    codegen.cfunc.arg_list = [argument]
    codegen.cfunc.statements.statements.append(CExpressionStatement(helper, codegen=codegen))

    changed = materialize_runtime_helper_segment_carriers_8616(codegen, project=project)

    assert changed is False
    assert helper.args[0] is explicit_ds
    assert codegen._inertia_runtime_helper_segment_carrier_candidate_count_8616 == 1
    assert codegen._inertia_runtime_helper_segment_carrier_materialized_count_8616 == 0
    assert codegen._inertia_runtime_helper_segment_carrier_refused_count_8616 == 1


def test_apply_runtime_segment_lowering_promotes_only_binary_proven_pointer_argument():
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    argc = CVariable(
        SimStackVariable(4, 2, base="bp", name="argc", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    argv = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [argc, argv]
    codegen.cfunc.functy = SimTypeFunction(
        [scalar_type, scalar_type],
        SimTypeShort(False),
        arg_names=["argc", "argv"],
    ).with_arch(project.arch)
    local_a = CVariable(SimStackVariable(-2, 2, base="bp", name="a"), codegen=codegen)
    local_b = CVariable(SimStackVariable(-4, 2, base="bp", name="b"), codegen=codegen)
    local_c = CVariable(SimStackVariable(-6, 2, base="bp", name="c"), codegen=codegen)
    index = CVariable(
        SimStackVariable(-8, 2, base="bp", name="index"),
        variable_type=scalar_type,
        codegen=codegen,
    )
    argc_operand = _seg_linear(project, "ds", CBinaryOp("Add", _const(0, codegen), argc, codegen=codegen), codegen)
    argc_operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    argv_helper = CFunctionCall(
        "SEG_U16",
        None,
        [
            _reg(project, "ds", codegen),
            CBinaryOp("Add", _const(0, codegen), argv, codegen=codegen),
        ],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U16"},
    )
    indexed_argv_helper = CFunctionCall(
        "SEG_U16",
        None,
        [
            _reg(project, "ds", codegen),
            CBinaryOp(
                "Add",
                argv,
                CBinaryOp("Shl", index, _const(1, codegen), codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U16"},
    )
    codegen.cfunc.statements.statements.extend(
        [
            CAssignment(local_a, CUnaryOp("Dereference", argc_operand, codegen=codegen), codegen=codegen),
            CAssignment(local_b, argv_helper, codegen=codegen),
            CAssignment(local_c, indexed_argv_helper, codegen=codegen),
        ]
    )
    load_argv = SimpleNamespace(
        address=0x1000,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(6)),
    )
    dereference_argv = SimpleNamespace(
        address=0x1003,
        id=X86_INS_PUSH,
        operands=(_reg_indirect_mem_operand(X86_REG_BX),),
    )
    function = SimpleNamespace(
        prototype=codegen.cfunc.functy,
        blocks=(
            SimpleNamespace(
                addr=0x1000,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(insn=load_argv),
                        SimpleNamespace(insn=dereference_argv),
                    )
                ),
            ),
        )
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(get=lambda _addr: function),
    )

    changed = apply_runtime_segment_lowering_8616(codegen)

    assert changed is True
    first, second, third = codegen.cfunc.statements.statements
    assert isinstance(first.rhs, CFunctionCall)
    assert first.rhs.callee_target == "SEG_U16"
    assert isinstance(second.rhs, CIndexedVariable)
    assert isinstance(third.rhs, CIndexedVariable)
    assert third.rhs.variable is argv
    assert third.rhs.index is index
    assert not isinstance(argc.variable_type, SimTypePointer)
    assert isinstance(argv.variable_type, SimTypePointer)
    assert not isinstance(codegen.cfunc.functy.args[0], SimTypePointer)
    assert isinstance(codegen.cfunc.functy.args[1], SimTypePointer)
    assert isinstance(function.prototype.args[1], SimTypePointer)
    stats = codegen._inertia_near_pointer_argument_stats_8616
    assert (stats.raw_fact_count, stats.normalized_fact_count, stats.classified_fact_count,
            stats.materialized_count, stats.failure_count) == (1, 1, 1, 1, 0)
    argv.variable_type = scalar_type
    codegen.cfunc.functy = SimTypeFunction(
        [scalar_type, scalar_type],
        SimTypeShort(False),
        arg_names=["argc", "argv"],
    ).with_arch(project.arch)

    assert apply_runtime_segment_lowering_8616(codegen) is True
    assert isinstance(argv.variable_type, SimTypePointer)
    assert isinstance(codegen.cfunc.functy.args[1], SimTypePointer)


def test_apply_runtime_segment_lowering_appends_exact_trailing_pointer_argument():
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    argc = CVariable(
        SimStackVariable(4, 2, base="bp", name="argc", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    argv = CVariable(
        SimStackVariable(6, 2, base="bp", name="local_3", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [argc]
    codegen.cfunc.functy = SimTypeFunction(
        [scalar_type],
        SimTypeShort(False),
        arg_names=["argc"],
    ).with_arch(project.arch)
    codegen.cfunc.variables_in_use = {
        argc.variable: argc,
        argv.variable: argv,
        index.variable: index,
    }
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [
            _reg(project, "ds", codegen),
            CBinaryOp(
                "Add",
                argv,
                CBinaryOp("Shl", index, _const(1, codegen), codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U16"},
    )
    codegen.cfunc.statements.statements.append(CExpressionStatement(helper, codegen=codegen))
    load_argv = SimpleNamespace(
        address=0x1000,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(6)),
    )
    dereference_argv = SimpleNamespace(
        address=0x1003,
        id=X86_INS_PUSH,
        operands=(_reg_indirect_mem_operand(X86_REG_BX),),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(
                addr=0x1000,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(insn=load_argv),
                        SimpleNamespace(insn=dereference_argv),
                    )
                ),
            ),
        )
    )
    project.kb = SimpleNamespace(functions=SimpleNamespace(get=lambda _addr: function))

    changed = apply_runtime_segment_lowering_8616(codegen)

    assert changed is True
    assert len(codegen.cfunc.arg_list) == 2
    assert codegen.cfunc.arg_list[1] is argv
    assert argv.variable.name == "arg_6"
    assert isinstance(argv.variable_type, SimTypePointer)
    assert len(codegen.cfunc.functy.args) == 2
    assert isinstance(codegen.cfunc.functy.args[1], SimTypePointer)
    lowered = codegen.cfunc.statements.statements[0].expr
    assert isinstance(lowered, CIndexedVariable)
    assert lowered.variable is argv
    assert lowered.index is index
    assert codegen._inertia_near_pointer_argument_stats_8616.refusals == ()


def test_apply_runtime_segment_lowering_refuses_noncontiguous_pointer_argument():
    project, codegen = _project()
    scalar_type = SimTypeShort(False).with_arch(project.arch)
    argc = CVariable(
        SimStackVariable(4, 2, base="bp", name="argc", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    candidate = CVariable(
        SimStackVariable(8, 2, base="bp", name="local_4", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [argc]
    codegen.cfunc.functy = SimTypeFunction(
        [scalar_type],
        SimTypeShort(False),
        arg_names=["argc"],
    ).with_arch(project.arch)
    codegen.cfunc.variables_in_use = {argc.variable: argc, candidate.variable: candidate}
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [
            _reg(project, "ds", codegen),
            CBinaryOp("Add", _const(0, codegen), candidate, codegen=codegen),
        ],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U16"},
    )
    codegen.cfunc.statements.statements.append(CExpressionStatement(helper, codegen=codegen))
    load_candidate = SimpleNamespace(
        address=0x1000,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _bp_mem_operand(8)),
    )
    dereference_candidate = SimpleNamespace(
        address=0x1003,
        id=X86_INS_PUSH,
        operands=(_reg_indirect_mem_operand(X86_REG_BX),),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(
                addr=0x1000,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(insn=load_candidate),
                        SimpleNamespace(insn=dereference_candidate),
                    )
                ),
            ),
        )
    )
    project.kb = SimpleNamespace(functions=SimpleNamespace(get=lambda _addr: function))

    changed = apply_runtime_segment_lowering_8616(codegen)

    assert changed is False
    assert codegen.cfunc.arg_list == [argc]
    assert not isinstance(candidate.variable_type, SimTypePointer)
    unchanged = codegen.cfunc.statements.statements[0].expr
    assert isinstance(unchanged, CFunctionCall)
    refusal = codegen._inertia_near_pointer_argument_stats_8616.refusals
    assert len(refusal) == 1
    assert refusal[0].reason is NearPointerArgumentRefusalReason8616.NO_CANONICAL_ARGUMENT
    assert refusal[0].stack_offset == 8


def test_lower_runtime_segment_access_rewrites_es_byte_runtime_offset_to_seg_u8():
    project, codegen = _project()
    di = _reg(project, "di", codegen)
    offset = CBinaryOp("Add", di, _const(4, codegen), codegen=codegen)
    operand = _seg_linear(project, "es", offset, codegen, shl=True)
    operand._type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
    expr = CUnaryOp("Dereference", operand, codegen=codegen)

    lowered = lower_runtime_segment_access_8616(expr, target="msc-dos")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U8"
    assert lowered.args[0].variable.name == "es"
    assert isinstance(lowered.args[1], CBinaryOp)
    assert lowered.args[1].op == "Add"


def test_lower_runtime_segment_access_resolves_single_assignment_ss_address_carrier():
    project, codegen = _project()
    ss = _reg(project, "ss", codegen)
    seg_carrier = CVariable(SimRegisterVariable(0x220, 2, name="vvar_31"), codegen=codegen)
    offset_carrier = CVariable(SimRegisterVariable(0x222, 2, name="vvar_1225"), codegen=codegen)
    address_carrier = CVariable(SimRegisterVariable(0x224, 2, name="vvar_1237"), codegen=codegen)
    result = CVariable(SimStackVariable(-2, 1, base="bp", name="local_2", region=0x4010), codegen=codegen)
    scaled_segment = CBinaryOp("Shl", seg_carrier, _const(4, codegen), codegen=codegen)
    address_value = CBinaryOp("Add", scaled_segment, offset_carrier, codegen=codegen)
    operand = CBinaryOp("Add", address_carrier, _const(1, codegen), codegen=codegen)
    operand._type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
    deref = CUnaryOp("Dereference", operand, codegen=codegen)
    codegen.cfunc.statements.statements.extend(
        [
            CAssignment(seg_carrier, ss, codegen=codegen),
            CAssignment(address_carrier, address_value, codegen=codegen),
            CAssignment(result, deref, codegen=codegen),
        ]
    )

    lowered = lower_runtime_segment_access_8616(deref, target="msc-dos")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "SEG_U8"
    assert lowered.args[0] is seg_carrier
    assert isinstance(lowered.args[1], CBinaryOp)
    assert int(getattr(codegen, "_inertia_runtime_segment_carrier_resolved_count_8616", 0)) >= 1


def test_lower_runtime_segment_address_rewrites_to_mk_fp():
    project, codegen = _project()
    bx = _reg(project, "bx", codegen)
    expr = _seg_linear(project, "ds", bx, codegen)

    lowered = lower_runtime_segment_address_8616(expr, target="portable-flat")

    assert isinstance(lowered, CFunctionCall)
    assert lowered.callee_target == "MK_FP"
    assert lowered.args[0].variable.name == "ds"
    assert lowered.args[1] is bx


def test_runtime_segment_entrypoints_refuse_container_before_matching(monkeypatch):
    """Container visits must leave nested expression matching to child traversal."""
    project, codegen = _project()
    nested_address = _seg_linear(project, "ds", _const(0x160, codegen), codegen)
    destination = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        codegen=codegen,
    )
    assignment = CAssignment(destination, nested_address, codegen=codegen)

    def fail_on_nested_probe(*_args, **_kwargs):
        raise AssertionError("container matching reached the segmented-expression matcher")

    monkeypatch.setattr(segmented_memory_lowering, "_match_segmented_memory_expr_8616", fail_on_nested_probe)

    assert lower_runtime_segment_access_8616(assignment, target="portable-flat") is None
    assert lower_runtime_segment_address_8616(assignment, target="portable-flat") is None


def test_apply_runtime_segment_lowering_rewrites_nested_ds_accesses():
    project, codegen = _project()
    result_var = CVariable(SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010), codegen=codegen)
    operand = _seg_linear(project, "ds", _const(2978, codegen), codegen)
    operand._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    deref = CUnaryOp("Dereference", operand, codegen=codegen)
    stmt = CAssignment(result_var, CBinaryOp("Sub", deref, _const(1, codegen), codegen=codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements([stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")

    assert changed is True
    lowered_rhs = codegen.cfunc.statements.statements[0].rhs.lhs
    assert isinstance(lowered_rhs, CFunctionCall)
    assert lowered_rhs.callee_target == "SEG_U16"


def test_runtime_segment_lowering_materializes_ir_proven_ds_live_in_as_global_state():
    project, codegen = _project()
    ds = _reg(project, "ds", codegen)
    helper = CFunctionCall("SEG_U8", None, [ds, _const(0x0B4C, codegen)], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(helper, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen.cfunc.unified_local_vars = {ds.variable: {(ds, SimTypeShort(False))}}
    ir_artifact = IRFunctionArtifact(
        function_addr=0x4010,
        blocks=(IRBlock(addr=0x4010),),
    )
    codegen._inertia_segment_state_artifact = build_x86_16_segment_state_artifact(
        ir_artifact,
        function_ssa=build_x86_16_function_ssa(ir_artifact),
    )
    project._inertia_rewrite_cache = {
        "segment_reg_name": {id(ds): None},
        "segmented_addr_expr": {id(helper): None},
        "unrelated": {1: "keep"},
    }

    changed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")

    assert changed is True
    lowered_helper = codegen.cfunc.statements.statements[0].expr
    assert isinstance(lowered_helper, CFunctionCall)
    lowered_segment = lowered_helper.args[0]
    assert isinstance(lowered_segment, CVariable)
    assert isinstance(lowered_segment.variable, SimMemoryVariable)
    assert lowered_segment.variable.name == "inertia_ds"
    assert codegen.cfunc.unified_local_vars == {}
    assert project._inertia_rewrite_cache == {"unrelated": {1: "keep"}}
    stats = codegen._inertia_segment_register_state_lowering_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)
    assert validate_structured_def_use_8616(
        codegen.cfunc.statements,
        segment_register_offsets=frozenset(
            project.arch.registers[name][0] for name in ("cs", "ds", "es", "ss")
        ),
    ).issues == ()


def test_runtime_segment_lowering_materializes_register_origin_dirty_ds_live_in():
    project, codegen = _project()
    dirty_ds = CDirtyExpression(
        SimpleNamespace(
            varid=20,
            oident=project.arch.registers["ds"][0],
            category=VirtualVariableCategory.REGISTER,
        ),
        codegen=codegen,
    )
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [dirty_ds, _const(0x0B46, codegen)],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(helper, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    ir_artifact = IRFunctionArtifact(
        function_addr=0x4010,
        blocks=(IRBlock(addr=0x4010),),
    )
    codegen._inertia_segment_state_artifact = build_x86_16_segment_state_artifact(
        ir_artifact,
        function_ssa=build_x86_16_function_ssa(ir_artifact),
    )

    changed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")

    assert changed is True
    lowered_helper = codegen.cfunc.statements.statements[0].expr
    assert isinstance(lowered_helper, CFunctionCall)
    lowered_segment = lowered_helper.args[0]
    assert isinstance(lowered_segment, CVariable)
    assert isinstance(lowered_segment.variable, SimMemoryVariable)
    assert lowered_segment.variable.name == "inertia_ds"
    stats = codegen._inertia_segment_register_state_lowering_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_runtime_segment_lowering_refuses_tmp_dirty_oident_collision():
    project, codegen = _project()
    dirty_tmp = CDirtyExpression(
        SimpleNamespace(
            varid=20,
            oident=project.arch.registers["ds"][0],
            category=VirtualVariableCategory.TMP,
        ),
        codegen=codegen,
    )
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [dirty_tmp, _const(0x0B46, codegen)],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(helper, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    ir_artifact = IRFunctionArtifact(
        function_addr=0x4010,
        blocks=(IRBlock(addr=0x4010),),
    )
    codegen._inertia_segment_state_artifact = build_x86_16_segment_state_artifact(
        ir_artifact,
        function_ssa=build_x86_16_function_ssa(ir_artifact),
    )

    changed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")

    assert changed is False
    unchanged_helper = codegen.cfunc.statements.statements[0].expr
    assert isinstance(unchanged_helper, CFunctionCall)
    assert unchanged_helper.args[0] is dirty_tmp
    stats = codegen._inertia_segment_register_state_lowering_stats_8616
    assert stats.raw_fact_count == 0
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0


def test_runtime_segment_lowering_resolves_dirty_ds_copy_chain_before_helper_materialization():
    project, codegen = _project()
    dirty_ds = CDirtyExpression(
        SimpleNamespace(
            varid=20,
            oident=project.arch.registers["ds"][0],
            category=VirtualVariableCategory.REGISTER,
        ),
        codegen=codegen,
    )
    first_carrier = CDirtyExpression(
        SimpleNamespace(
            varid=1268,
            oident=0,
            category=VirtualVariableCategory.TMP,
        ),
        codegen=codegen,
    )
    second_carrier = CDirtyExpression(
        SimpleNamespace(
            varid=1269,
            oident=1,
            category=VirtualVariableCategory.TMP,
        ),
        codegen=codegen,
    )
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [second_carrier, _const(0x0B46, codegen)],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first_carrier, dirty_ds, codegen=codegen),
            CAssignment(second_carrier, first_carrier, codegen=codegen),
            CExpressionStatement(helper, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    direct_load = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(
            _reg_operand(X86_REG_AX),
            _global_mem_operand(0x0B46),
        ),
    )
    codegen._func = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4020,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(insn=direct_load),),
                ),
            ),
        ),
    )
    ir_artifact = IRFunctionArtifact(
        function_addr=0x4010,
        blocks=(IRBlock(addr=0x4010),),
    )
    codegen._inertia_segment_state_artifact = build_x86_16_segment_state_artifact(
        ir_artifact,
        function_ssa=build_x86_16_function_ssa(ir_artifact),
    )

    changed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")
    replayed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")

    assert changed is True
    assert replayed is False
    lowered_helper = codegen.cfunc.statements.statements[2].expr
    assert isinstance(lowered_helper, CFunctionCall)
    lowered_segment = lowered_helper.args[0]
    assert isinstance(lowered_segment, CVariable)
    assert isinstance(lowered_segment.variable, SimMemoryVariable)
    assert lowered_segment.variable.name == "inertia_ds"
    assert codegen._inertia_runtime_helper_segment_carrier_materialized_count_8616 >= 1


def test_runtime_segment_push_source_materializes_explicit_ss_state():
    project, codegen = _project()

    materialized = runtime_segment_push_source_cvar_8616(
        "ss",
        codegen=codegen,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        function_addr=0x4010,
    )

    assert isinstance(materialized, CVariable)
    assert isinstance(materialized.variable, SimMemoryVariable)
    assert materialized.variable.name == "inertia_ss"
    assert materialized.variable.region == 0x4010


def test_apply_runtime_segment_lowering_prunes_pure_address_self_assignment():
    project, codegen = _project()
    address = _seg_linear(project, "ds", _const(0x160, codegen), codegen)
    stmt = CAssignment(address, address, codegen=codegen)
    codegen.cfunc.statements = CStatements([stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_runtime_segment_lowering_8616(codegen, target="portable-flat")

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    assert codegen._inertia_runtime_segment_address_self_assign_candidates_8616 == 1
    assert codegen._inertia_runtime_segment_address_self_assign_pruned_8616 == 1
    assert codegen._inertia_runtime_segment_address_self_assign_refused_8616 == 0


def test_runtime_segment_self_assignment_prune_accepts_statements_only_cfunc():
    class _StatementsOnlyCFunction:
        __slots__ = ("statements",)

        def __init__(self, statements):
            self.statements = statements

    project, codegen = _project()
    address = _seg_linear(project, "ds", _const(0x160, codegen), codegen)
    lowered_address = lower_runtime_segment_address_8616(address, target="portable-flat")
    assert lowered_address is not None
    stmt = CAssignment(lowered_address, lowered_address, codegen=codegen)
    root = CStatements([stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc = _StatementsOnlyCFunction(root)

    changed = segmented_memory_lowering._prune_runtime_segment_address_self_assignments_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    assert not hasattr(codegen.cfunc, "body")


def test_runtime_segment_self_assignment_prune_reaches_switch_case_bodies():
    project, codegen = _project()
    address = _seg_linear(project, "ds", _const(0x160, codegen), codegen)
    lowered_address = lower_runtime_segment_address_8616(address, target="portable-flat")
    assert lowered_address is not None
    identity = CAssignment(lowered_address, lowered_address, codegen=codegen)
    preserved = CAssignment(lowered_address, _const(7, codegen), codegen=codegen)
    case_body = CStatements([identity, preserved], addr=0x4010, codegen=codegen)
    switch = CSwitchCase(_const(1, codegen), [(1, case_body)], None, codegen=codegen)
    codegen.cfunc.statements = CStatements([switch], addr=0x4010, codegen=codegen)

    changed = segmented_memory_lowering._prune_runtime_segment_address_self_assignments_8616(codegen)

    assert changed is True
    assert case_body.statements == [preserved]
    assert codegen._inertia_runtime_segment_address_self_assign_candidates_8616 == 2
    assert codegen._inertia_runtime_segment_address_self_assign_pruned_8616 == 1
    assert codegen._inertia_runtime_segment_address_self_assign_refused_8616 == 1


def test_apply_runtime_segment_lowering_preserves_ss_stack_dereferences():
    project, codegen = _project()
    ss = _reg(project, "ss", codegen)
    stack_ref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CUnaryOp(
                "Reference",
                CVariable(SimStackVariable(-2, 2, base="bp", name="local", region=0x4010), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    assert lower_runtime_segment_access_8616(stack_ref, target="portable-flat") is None


def test_architecture_guard_rejects_raw_linear_segment_arithmetic():
    with pytest.raises(Exception):  # noqa: B017
        assert_final_c_quality_8616("x = *((unsigned short *)((ds << 4) + 2978));", function_addr=0x10498)


def test_architecture_guard_ignores_forbidden_tokens_inside_comments():
    assert_final_c_quality_8616(
        "int f(void)\n"
        "{\n"
        "    /* forbidden example, not emitted code: ds << 4 and stack[0xfffc] */\n"
        "    /// previous leak shape: *((ds << 4) + 2978)\n"
        "    return SEG_U16(ds, 2978);\n"
        "}\n",
        function_addr=0x10498,
    )


def test_architecture_guard_accepts_segment_helpers():
    assert_final_c_quality_8616("x = SEG_U16(ds, 2978);\ny = MK_FP(es, di + 4);\n", function_addr=0x10498)


def test_architecture_guard_rejects_unreachable_call_after_return():
    with pytest.raises(Exception):  # noqa: B017
        assert_final_c_quality_8616(
            "int f(void)\n{\n    helper();\n    return 2;\n    aNchkstk();\n}\n",
            function_addr=0x1000,
        )


def test_architecture_guard_rejects_unary_not_shift_precedence_leak():
    with pytest.raises(Exception):  # noqa: B017
        assert_final_c_quality_8616(
            "int f(void)\n{\n    if (!clPause >> 16)\n        return 1;\n    return 0;\n}\n",
            function_addr=0x1000,
        )
    with pytest.raises(Exception):  # noqa: B017
        assert_final_c_quality_8616(
            "int f(void)\n{\n    if (!(clPause) >> 16)\n        return 1;\n    return 0;\n}\n",
            function_addr=0x1000,
        )


def test_architecture_guard_accepts_conditional_single_line_return_before_call():
    assert_final_c_quality_8616(
        "int f(int x)\n"
        "{\n"
        "    while (1)\n"
        "    {\n"
        "        if (x == 0)\n"
        "            return 0;\n"
        "        helper();\n"
        "    }\n"
        "}\n",
        function_addr=0x1000,
    )


def test_segment_linearization_through_tmp_is_rejected():
    with pytest.raises(Exception):  # noqa: B017
        assert_final_c_quality_8616(
            "unsigned short tmp;\nunsigned long linear;\ntmp = ss;\nlinear = tmp << 4;\n",
            function_addr=0x10498,
        )
    with pytest.raises(Exception):  # noqa: B017
        assert_final_c_quality_8616(
            "unsigned short tmp;\nunsigned long linear;\ntmp = ds;\nlinear = tmp * 16;\n",
            function_addr=0x10498,
        )
    assert_final_c_quality_8616(
        "p = SEG_PTR(ds, off);\nx = SEG_U16(ds, off);\ny = MK_FP(ds, off);\n",
        function_addr=0x10498,
    )


def test_architecture_guard_accepts_generic_value_percolatedown_arg():
    assert_final_c_quality_8616(
        "short HeapSort(void)\n{\n    PercolateDown(3);\n}\n",
        function_addr=0x10970,
    )


def test_architecture_guard_accepts_generic_value_swapbars_args():
    assert_final_c_quality_8616(
        "short HeapSort(void)\n{\n    SwapBars(i, 0);\n}\n",
        function_addr=0x10970,
    )


def test_architecture_guard_accepts_heapsort_pointer_and_value_arg_shapes():
    assert_final_c_quality_8616(
        "short HeapSort(void)\n"
        "{\n"
        "    PercolateUp(i);\n"
        "    Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + (i << 1)));\n"
        "    SwapBars(0, i);\n"
        "    PercolateDown(i - 1);\n"
        "}\n",
        function_addr=0x10970,
    )


def test_architecture_guard_accepts_decimal_generated_arg_names():
    assert_final_c_quality_8616(
        "void PercolateDown(int arg_4)\n"
        "{\n"
        "    unsigned short iChild;\n"
        "    if (iChild <= arg_4)\n"
        "        SwapBars(0, iChild);\n"
        "}\n",
        function_addr=0x10A88,
    )


def test_architecture_guard_does_not_infer_semantics_from_arg_names():
    assert_final_c_quality_8616(
        "void bad(int arg_fffe)\n{\n    SwapBars(0, arg_fffe);\n}\n",
        function_addr=0x10A88,
    )


def test_architecture_guard_rejects_heapsort_stack_placeholder_noise():
    with pytest.raises(Exception):  # noqa: B017
        assert_final_c_quality_8616(
            "short HeapSort(void)\n"
            "{\n"
            "    char s_4;\n"
            "    vvar_23 = &s_4 + 2;\n"
            "    Swaps(SEG_PTR(ds, 2892), SEG_PTR(ds, 2892 + (i << 1)));\n"
            "    SwapBars(0, i);\n"
            "    PercolateDown(i - 1);\n"
            "}\n",
            function_addr=0x10970,
        )


def test_render_c_runtime_header_portable_flat_exposes_seg_macros():
    header = render_c_runtime_header_8616("portable-flat")

    assert "extern uint8_t inertia_memory[];" in header
    assert "#define SEG_U16(seg, off)" in header
    assert "#define MEM_U16(ptr)" in header
    assert "#define MK_FP(seg, off)" in header


def test_render_c_runtime_header_msc_dos_uses_far_mk_fp():
    header = render_c_runtime_header_8616("msc-dos")

    assert "#include <DOS.H>" in header
    assert "typedef signed long    int32_t;" in header
    assert "#define MK_FP(seg, off) ((uint8_t far *)" in header
    assert "SEG_U16" in header
    assert "MEM_U16" in header
    assert "far *)MK_FP" in header


def test_cli_arg_parser_accepts_c_target():
    parser = _build_cli_argument_parser()

    args = parser.parse_args(["sample.exe", "--c-target", "msc-dos"])

    assert args.c_target == "msc-dos"


def test_recompile_check_accepts_simple_portable_flat_c():
    result = check_c_recompiles_8616(
        "int demo(unsigned short ds) { return (int)SEG_U16(ds, 0x0BA2); }\n",
        target="portable-flat",
    )

    assert result.passed is True, result.stderr


def test_recompile_check_msc51_accepts_portable_signed_fixed_width_aliases():
    result = check_c_recompiles_8616(
        "int32_t aNldiv(int32_t dividend, int32_t divisor);\n"
        "int32_t demo(void) { return aNldiv(900L, 30L); }\n",
        target="msc-dos",
    )

    assert result.passed is True, result.stderr


def test_recompile_check_msc51_uses_strict_kvikdos_drive_mounts(monkeypatch, tmp_path):
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("", encoding="utf-8")
    msc_root = tmp_path / "Microsoft C v5.1"
    (msc_root / "BIN").mkdir(parents=True)
    captured = {}

    def _fake_run(command, **_kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout="c:\\GEN.C\n", stderr="Microsoft C\n")

    monkeypatch.setattr(recompile_check, "_resolve_kvikdos_path", lambda: kvikdos)
    monkeypatch.setattr(recompile_check, "_resolve_msc51_root", lambda: msc_root)
    monkeypatch.setattr(recompile_check.subprocess, "run", _fake_run)

    result = check_c_recompiles_8616("int main(void) { return 0; }\n", target="msc-dos")

    command = captured["command"]
    assert result.passed is True
    assert command[1].startswith("--mount=c:")
    assert command[1].endswith("/")
    assert command[2] == f"--mount=e:{msc_root}/"
    assert "--path-dos=e:\\BIN" in command
    assert "--prog=e:\\BIN\\CL.EXE" in command
    assert "e:\\BIN\\CL.EXE" in command
    assert "c:\\GEN.C" in command


def test_recompile_check_msc51_retries_transient_kvikdos_failure(monkeypatch, tmp_path):
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("", encoding="utf-8")
    msc_root = tmp_path / "Microsoft C v5.1"
    (msc_root / "BIN").mkdir(parents=True)
    calls = {"count": 0}

    def _fake_run(_command, **_kwargs):
        if _command[-1] == "--kvm-check":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        calls["count"] += 1
        if calls["count"] == 1:
            return SimpleNamespace(
                returncode=252,
                stdout="fatal: unexpected KVM exit: reason=9\n",
                stderr="Microsoft C\n",
            )
        return SimpleNamespace(returncode=0, stdout="c:\\GEN.C\n", stderr="Microsoft C\n")

    monkeypatch.setattr(recompile_check, "_resolve_kvikdos_path", lambda: kvikdos)
    monkeypatch.setattr(recompile_check, "_resolve_msc51_root", lambda: msc_root)
    monkeypatch.setattr(recompile_check.subprocess, "run", _fake_run)

    result = check_c_recompiles_8616("int main(void) { return 0; }\n", target="msc-dos")

    assert result.passed is True
    assert calls["count"] == 2


def test_recompile_check_msc51_sanitizes_c99_line_comments():
    payload = recompile_check._compile_input_payload_8616(
        'int demo(void) { return 1; } // ax\n/// /* source sidecar */\nchar *url = "http://example";\n',
        target="msc-dos",
    )

    assert "// ax" not in payload
    assert "/* ax */" in payload
    assert "///" not in payload
    assert "source sidecar" in payload
    assert '"http://example"' in payload


def test_recompile_check_msc51_dedupes_existing_runtime_typedefs():
    payload = recompile_check._compile_input_payload_8616(
        "typedef long clock_t;\n"
        "typedef long time_t;\n"
        "typedef unsigned short uint16_t;\n"
        "clock_t clock(void);\n"
        "void Sleep(clock_t wait) { }\n",
        target="msc-dos",
    )

    assert payload.count("typedef long clock_t;") == 1
    assert payload.count("typedef long time_t;") == 1
    assert payload.count("typedef unsigned short uint16_t;") == 1
    assert "void Sleep(clock_t wait)" in payload


def test_recompile_check_msc51_accepts_uppercase_existing_dos_header():
    payload = recompile_check._compile_input_payload_8616(
        "#include <DOS.H>\n#define SEG_U8(seg, off) (*(uint8_t far *)MK_FP((seg), (off)))\n",
        target="msc-dos",
    )

    assert payload.count("#include <DOS.H>") == 1

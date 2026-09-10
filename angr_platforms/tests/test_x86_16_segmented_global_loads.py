from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimTypeChar, SimTypePointer, SimTypeShort, TypeRef
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.cod_extract import CODGlobalAddressRef, CODGlobalRef
from angr_platforms.X86_16.codegen_metadata import GlobalDeclarationArrayExtent8616
from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.segment_contract import (
    SegmentAccessFact,
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentFunctionContract,
)
from angr_platforms.X86_16.lowering import segmented_global_loads as segmented_global_loads_module
from angr_platforms.X86_16.lowering.global_declarations import (
    GlobalDeclarationCType8616,
    NamedAggregateDeclarationCType8616,
    record_global_declaration_spec_8616,
    record_scalar_global_declaration_spec_8616,
)
from angr_platforms.X86_16.lowering.near_pointer_argument import NearPointerArgumentFact8616
from angr_platforms.X86_16.lowering.segment_register_state import (
    runtime_segment_push_source_cvar_8616,
)
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    CompareRegisterGlobalCarrierEvidence8616,
    DirectGlobalBooleanStoreEvidence8616,
    DirectGlobalCallReturnStoreEvidence8616,
    DirectGlobalSymbolRef8616,
    DirectGlobalUpdateEvidence8616,
    DirectSegmentedGlobalLoadEvidence8616,
    DirectSegmentedGlobalStoreEvidence8616,
    DwordGlobalZeroTestEvidence8616,
    DwordGlobalZeroTestMaterializationRecord8616,
    GlobalAddressLiteralEvidence8616,
    IndexedSegmentedGlobalEvidence8616,
    IndexedSegmentedGlobalLoadConsumer8616,
    IndexedSegmentedGlobalLoadSiteEvidence8616,
    IndexedSegmentedGlobalStackStore8616,
    IndexedSegmentedGlobalStoreEvidence8616,
    NamedGlobalEvidence8616,
    SegmentedGlobalLoadStats8616,
    SignedRemainderStackSource8616,
    _cod_direct_global_refs_8616,
    _cod_indexed_global_refs_8616,
    _cod_offset_global_refs_8616,
    _collect_direct_global_boolean_store_evidence_8616,
    _collect_direct_global_call_return_store_evidence_8616,
    _collect_global_address_literal_evidence_8616,
    _collect_global_address_symbol_refs_8616,
    _collect_synthetic_direct_global_symbol_refs_8616,
    _constant_int_8616,
    _direct_global_symbol_name_facts_8616,
    _indexed_evidence_from_direct_symbol_refs_8616,
    _make_direct_global_symbol_expr_8616,
    _make_indexed_global_expr_8616,
    _materialize_direct_global_zero_test_or_expr_8616,
    _materialized_sidecar_free_dword_update_refs_8616,
    _merge_direct_global_symbol_refs_8616,
    _sidecar_free_boolean_store_refs_8616,
    _sidecar_free_dword_update_refs_8616,
    materialize_compare_register_global_carriers_from_evidence_8616,
    materialize_direct_global_symbol_stores_from_evidence_8616,
    materialize_indexed_segmented_global_loads_from_evidence_8616,
    materialize_named_segmented_global_loads_8616,
    reapply_proven_named_global_aggregate_types_8616,
    reconcile_registered_named_global_aggregate_declarations_8616,
    recover_compare_register_global_carriers_8616,
    recover_direct_segmented_global_load_evidence_8616,
    recover_direct_segmented_global_store_evidence_8616,
    recover_dword_global_zero_test_evidence_8616,
    recover_indexed_segmented_global_evidence_8616,
    recover_indexed_segmented_global_load_site_evidence_8616,
    recover_indexed_segmented_global_store_evidence_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.lowering.storage_identity_facts import (
    GlobalStorageIdentityFact8616,
    StorageIdentityEvidenceKind8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.structuring.simple_loop_recovery import InsnSummary8616
from capstone.x86_const import (
    X86_INS_ADD,
    X86_INS_CALL,
    X86_INS_CMP,
    X86_INS_CWD,
    X86_INS_IDIV,
    X86_INS_INC,
    X86_INS_MOV,
    X86_INS_SHL,
    X86_INS_SUB,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_DL,
    X86_REG_DX,
    X86_REG_ES,
    X86_REG_INVALID,
    X86_REG_SP,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cfunc = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.max_str_len = None

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _DummyVariableManager:
    def __init__(self):
        self.types = {}
        self.variable_to_types = {}
        self.variables = []

    def set_variable_type(
        self,
        variable,
        type_,
        *,
        name=None,
        override_bot=True,
        all_unified=False,
    ):
        del override_bot, all_unified
        self.variable_to_types[variable] = self.types[name] if name is not None else type_

    def get_variables(self, sort=None, collapse_same_ident=False):
        del sort, collapse_same_ident
        return tuple(self.variables)


def test_indexed_materializer_exposes_typed_validation_evidence(monkeypatch):
    evidence = (IndexedSegmentedGlobalEvidence8616(0x132, "clPause", 0, 2),)
    load_site = IndexedSegmentedGlobalLoadSiteEvidence8616(
        0x132,
        2,
        -4,
        1,
        0x1057,
        destination_register="ax",
        index_stack_width=2,
    )
    project = SimpleNamespace()
    codegen = _DummyCodegen()
    monkeypatch.setattr(segmented_global_loads_module, "_active_function_8616", lambda *_args: None)
    monkeypatch.setattr(
        segmented_global_loads_module,
        "recover_indexed_segmented_global_evidence_8616",
        lambda *_args, **_kwargs: evidence,
    )
    monkeypatch.setattr(segmented_global_loads_module, "_collect_direct_global_symbol_refs_8616", lambda *_args: ())
    monkeypatch.setattr(segmented_global_loads_module, "_collect_global_address_symbol_refs_8616", lambda *_args: ())
    monkeypatch.setattr(segmented_global_loads_module, "_collect_global_address_literal_evidence_8616", lambda *_args: ())
    monkeypatch.setattr(
        segmented_global_loads_module,
        "recover_indexed_segmented_global_load_site_evidence_8616",
        lambda *_args: (load_site,),
    )
    monkeypatch.setattr(
        segmented_global_loads_module,
        "recover_indexed_segmented_global_store_evidence_8616",
        lambda *_args: (),
    )

    def _materialize(*_args, stats, consumed_load_sites, **_kwargs):
        stats.record_indexed(segmented_global_loads_module.IndexedSegmentedGlobalDecision8616.MATERIALIZED)
        stats.indexed_load_site_materialized_count += 1
        consumed_load_sites.append(load_site)
        return True

    monkeypatch.setattr(
        segmented_global_loads_module,
        "materialize_indexed_segmented_global_loads_from_evidence_8616",
        _materialize,
    )

    changed = segmented_global_loads_module.materialize_indexed_segmented_global_loads_8616(project, codegen)
    replay_changed = segmented_global_loads_module.materialize_indexed_segmented_global_loads_8616(project, codegen)

    assert changed is True
    assert replay_changed is True
    assert codegen._inertia_indexed_global_evidence_8616 == evidence
    assert codegen._inertia_segmented_global_load_stats_8616.indexed_materialized_count == 1
    record = codegen._inertia_indexed_global_materialization_record_8616
    assert record.evidence == evidence
    assert record.materialized_count == 2
    read_record = codegen._inertia_indexed_global_read_carrier_record_8616
    assert read_record.evidence == (load_site,)
    assert read_record.raw_fact_count == 2
    assert read_record.normalized_fact_count == 2
    assert read_record.classified_fact_count == 2
    assert read_record.materialized_count == 2
    assert read_record.failure_count == 0


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _ds(project, codegen):
    reg_offset, reg_size = project.arch.registers["ds"]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name="ds"), codegen=codegen)


def _stack(offset: int, codegen, *, name: str = "local"):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name), codegen=codegen)


def _mem(addr: int, codegen, *, name: str | None = None):
    return CVariable(SimMemoryVariable(addr, 1, name=name or f"mem_{addr:04x}"), codegen=codegen)


def _mem_word(addr: int, codegen, *, name: str | None = None):
    return CVariable(
        SimMemoryVariable(addr, 2, name=name or f"mem_{addr:04x}"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _dirty(varid: int, codegen):
    return CDirtyExpression(SimpleNamespace(varid=varid, name=f"vvar_{varid}"), codegen=codegen)


def _dirty_with_oident(varid: int, oident: int, codegen):
    return CDirtyExpression(SimpleNamespace(varid=varid, oident=oident, name=f"vvar_{varid}"), codegen=codegen)


def _ref(expr, codegen):
    return CUnaryOp("Reference", expr, codegen=codegen)


def _deref(expr, codegen):
    return CUnaryOp("Dereference", expr, codegen=codegen)


def _reg(project, codegen, name: str):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _reg_operand(reg, *, size=2):
    return SimpleNamespace(type=X86_OP_REG, size=size, reg=reg)


def _mem_operand(base, disp: int, *, size=2, index=X86_REG_INVALID, segment=X86_REG_INVALID):
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=size,
        mem=SimpleNamespace(base=base, index=index, segment=segment, disp=disp),
    )


def _imm_operand(value: int, *, size=1):
    return SimpleNamespace(type=X86_OP_IMM, size=size, imm=value)


def _global_indexed(name: str, base_addr: int, index, codegen):
    base = CVariable(
        SimMemoryVariable(base_addr, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    return CIndexedVariable(base, index, variable_type=SimTypeShort(False), codegen=codegen)


def test_segmented_global_load_materializes_named_ds_word_global():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    rhs = CFunctionCall(
        "SEG_U16",
        None,
        [_ds(project, codegen), _const(0x42, codegen)],
        codegen=codegen,
        tags={"inertia_source_instruction_addrs": (0x4010,)},
    )
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = assignment
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_named_segmented_global_loads_8616(project, codegen, {0x42: ("g_rows", 2)})

    assert changed is True
    assert isinstance(assignment.rhs, CVariable)
    assert assignment.rhs.name == "g_rows"
    assert assignment.rhs.tags["inertia_source_instruction_addrs"] == (0x4010,)
    assert codegen._inertia_segmented_global_load_stats_8616.materialized_count == 1
    materialized_rhs = assignment.rhs

    assert materialize_named_segmented_global_loads_8616(project, codegen, {0x42: ("g_rows", 2)}) is False
    assert assignment.rhs is materialized_rhs


def test_direct_segmented_global_load_evidence_preserves_default_ds_and_es_override():
    project = SimpleNamespace(arch=Arch86_16())
    ds_load = SimpleNamespace(
        address=0x108DB,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _mem_operand(X86_REG_INVALID, 0x0BA2)),
    )
    es_load = SimpleNamespace(
        address=0x108E0,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _mem_operand(X86_REG_INVALID, 0x0BA4, segment=X86_REG_ES)),
    )
    store = SimpleNamespace(
        address=0x108E5,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_INVALID, 0x0BA6), _reg_operand(X86_REG_AX)),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(ds_load, es_load, store)))
    function = SimpleNamespace(blocks=(block,))

    evidence = recover_direct_segmented_global_load_evidence_8616(project, function)

    assert evidence == (
        DirectSegmentedGlobalLoadEvidence8616(0x0BA2, 2, MemSpace.DS, 0x108DB),
        DirectSegmentedGlobalLoadEvidence8616(0x0BA4, 2, MemSpace.ES, 0x108E0),
    )


def test_direct_segmented_global_store_evidence_preserves_default_ds_and_es_override():
    project = SimpleNamespace(arch=Arch86_16())
    ds_store = SimpleNamespace(
        address=0x1057C,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_INVALID, 0x0B46), _imm_operand(1, size=2)),
    )
    es_store = SimpleNamespace(
        address=0x10582,
        id=X86_INS_MOV,
        operands=(
            _mem_operand(X86_REG_INVALID, 0x0132, segment=X86_REG_ES),
            _imm_operand(30, size=2),
        ),
    )
    load = SimpleNamespace(
        address=0x10588,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _mem_operand(X86_REG_INVALID, 0x0134)),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(ds_store, es_store, load)))
    function = SimpleNamespace(blocks=(block,))

    evidence = recover_direct_segmented_global_store_evidence_8616(project, function)

    assert evidence == (
        DirectSegmentedGlobalStoreEvidence8616(0x0B46, 2, MemSpace.DS, 0x1057C, 1),
        DirectSegmentedGlobalStoreEvidence8616(0x0132, 2, MemSpace.ES, 0x10582, 30),
    )


def test_direct_segmented_global_store_evidence_tracks_constant_register_address_and_value():
    project = SimpleNamespace(arch=Arch86_16())
    clear_bx = SimpleNamespace(
        address=0x1000,
        id=X86_INS_SUB,
        operands=(_reg_operand(X86_REG_BX), _reg_operand(X86_REG_BX)),
    )
    load_es = SimpleNamespace(
        address=0x1002,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_ES), _reg_operand(X86_REG_BX)),
    )
    load_bx = SimpleNamespace(
        address=0x1004,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(0x417, size=2)),
    )
    store = SimpleNamespace(
        address=0x1007,
        id=X86_INS_MOV,
        operands=(
            _mem_operand(X86_REG_BX, 0, segment=X86_REG_ES),
            _reg_operand(X86_REG_ES),
        ),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(clear_bx, load_es, load_bx, store)))
    function = SimpleNamespace(blocks=(block,))

    evidence = recover_direct_segmented_global_store_evidence_8616(project, function)

    assert evidence == (
        DirectSegmentedGlobalStoreEvidence8616(0x0417, 2, MemSpace.ES, 0x1007, 0, 0),
    )


def test_anonymous_direct_immediate_store_replaces_misidentified_function_symbol():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    overwide_lvalue = CFunctionCall(
        "SEG_U32",
        None,
        [_ds(project, codegen), _const(0x7001, codegen)],
        codegen=codegen,
    )
    assignment = CAssignment(
        overwide_lvalue,
        CConstant(
            0x49,
            SimTypeShort(False),
            reference_values={},
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x107A7},
    )
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1079C, statements=root, body=root)
    evidence = (
        DirectSegmentedGlobalStoreEvidence8616(0x7001, 1, MemSpace.DS, 0x107A7, 0x49),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=evidence,
        project=project,
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.lhs, CFunctionCall)
    assert assignment.lhs.callee_target == "SEG_U8"
    assert isinstance(assignment.rhs, CConstant)
    assert assignment.rhs.value == 0x49
    assert assignment.rhs.reference_values is None
    assert stats.anonymous_direct_store_classified_fact_count == 1
    assert stats.anonymous_direct_store_materialized_count == 1
    assert stats.anonymous_direct_store_failure_count == 0


def test_anonymous_direct_immediate_store_resegments_exact_tagged_dereference():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    assignment = CAssignment(
        _deref(_const(0x2461B, codegen), codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10028},
    )
    assignment.lhs._type = SimTypeChar(False).with_arch(project.arch)
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x10000, statements=root, body=root)
    evidence = (
        DirectSegmentedGlobalStoreEvidence8616(0x007B, 1, MemSpace.DS, 0x10028, 0),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=evidence,
        project=project,
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.lhs, CFunctionCall)
    assert assignment.lhs.callee_target == "SEG_U8"
    assert assignment.lhs.args[0].variable.name == "ds"
    assert assignment.lhs.args[1].value == 0x007B
    assert isinstance(assignment.rhs, CConstant)
    assert assignment.rhs.value == 0
    assert assignment.tags["ins_addr"] == 0x10028
    assert stats.anonymous_direct_store_classified_fact_count == 1
    assert stats.anonymous_direct_store_materialized_count == 1
    assert stats.anonymous_direct_store_failure_count == 0


def test_anonymous_direct_word_store_projects_stack_address_to_guest_offset():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    local = CVariable(
        SimStackVariable(-4, 1, base="bp", name="local_4", region=0x10000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    lvalue = CFunctionCall(
        "SEG_U16",
        None,
        [_ds(project, codegen), _const(0x0030, codegen)],
        codegen=codegen,
    )
    assignment = CAssignment(
        lvalue,
        CUnaryOp("AddressOf", local, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10015},
    )
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x10000, statements=root, body=root)
    evidence = (
        DirectSegmentedGlobalStoreEvidence8616(0x0030, 2, MemSpace.DS, 0x10015),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=evidence,
        project=project,
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CFunctionCall)
    assert assignment.rhs.callee_target == "PTR_U16"
    assert assignment.rhs.args[0].op == "AddressOf"
    assert stats.anonymous_direct_store_classified_fact_count == 1
    assert stats.anonymous_direct_store_materialized_count == 1
    assert stats.anonymous_direct_store_failure_count == 0


def test_anonymous_direct_word_store_folds_exact_instruction_byte_pair_and_replays():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    tags = {"ins_addr": 0x1057C}
    low = CAssignment(
        _mem(0x0B46, codegen, name="mem_0B46"),
        _const(1, codegen),
        codegen=codegen,
        tags=tags,
    )
    high = CAssignment(
        _mem(0x0B47, codegen, name="mem_0B47"),
        _const(0, codegen),
        codegen=codegen,
        tags=tags,
    )
    root = CStatements([low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x10560, statements=root, body=root)
    evidence = (DirectSegmentedGlobalStoreEvidence8616(0x0B46, 2, MemSpace.DS, 0x1057C),)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=evidence,
        project=project,
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CFunctionCall)
    assert assignment.lhs.callee_target == "SEG_U16"
    assert assignment.lhs.args[0].variable.name == "ds"
    assert assignment.lhs.args[1].value == 0x0B46
    assert assignment.rhs.value == 1
    assert assignment.tags["ins_addr"] == 0x1057C
    assert stats.anonymous_direct_store_raw_fact_count == 1
    assert stats.anonymous_direct_store_normalized_fact_count == 1
    assert stats.anonymous_direct_store_classified_fact_count == 1
    assert stats.anonymous_direct_store_materialized_count == 1
    assert stats.anonymous_direct_store_failure_count == 0

    replay_stats = SegmentedGlobalLoadStats8616()
    replay_changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=evidence,
        project=project,
        stats=replay_stats,
    )

    assert replay_changed is False
    assert len(root.statements) == 1
    assert replay_stats.anonymous_direct_store_classified_fact_count == 1
    assert replay_stats.anonymous_direct_store_materialized_count == 1
    assert replay_stats.anonymous_direct_store_failure_count == 0
    assert replay_stats.refused_no_evidence == 0


def test_anonymous_direct_word_store_uses_instruction_proven_unresolved_byte_pair():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    tags = {"ins_addr": 0x1014}
    low = CAssignment(
        _deref(_dirty(41, codegen), codegen),
        CBinaryOp("Sub", _dirty(7, codegen), _dirty(7, codegen), codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    high = CAssignment(
        _deref(_dirty(42, codegen), codegen),
        CBinaryOp(
            "Shr",
            CBinaryOp("Sub", _dirty(7, codegen), _dirty(7, codegen), codegen=codegen),
            _const(8, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags=tags,
    )
    root = CStatements([low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    evidence = (
        DirectSegmentedGlobalStoreEvidence8616(0x0417, 2, MemSpace.ES, 0x1014, 0, 0),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=evidence,
        project=project,
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CFunctionCall)
    assert assignment.lhs.callee_target == "SEG_U16"
    assert isinstance(assignment.lhs.args[0], CConstant)
    assert assignment.lhs.args[0].value == 0
    assert assignment.lhs.args[1].value == 0x0417
    assert isinstance(assignment.rhs, CConstant)
    assert assignment.rhs.value == 0
    assert assignment.tags["ins_addr"] == 0x1014
    assert stats.anonymous_direct_store_classified_fact_count == 1
    assert stats.anonymous_direct_store_materialized_count == 1
    assert stats.anonymous_direct_store_failure_count == 0


def test_anonymous_direct_word_store_resolves_unique_dirty_byte_pair_source():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    tags = {"ins_addr": 0x102EE}
    carrier_definition = CAssignment(
        _dirty(198, codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    low = CAssignment(
        _mem(0x0BAA, codegen, name="mem_0BAA"),
        _dirty(198, codegen),
        codegen=codegen,
        tags=tags,
    )
    high = CAssignment(
        _mem(0x0BAB, codegen, name="mem_0BAB"),
        CBinaryOp("Shr", _dirty(198, codegen), _const(8, codegen), codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    root = CStatements([carrier_definition, low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x102E0, statements=root, body=root)
    evidence = (DirectSegmentedGlobalStoreEvidence8616(0x0BAA, 2, MemSpace.DS, 0x102EE),)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=evidence,
        project=project,
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 2
    assignment = root.statements[1]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CFunctionCall)
    assert assignment.lhs.callee_target == "SEG_U16"
    assert assignment.lhs.args[0].variable.name == "ds"
    assert assignment.lhs.args[1].value == 0x0BAA
    assert isinstance(assignment.rhs, CConstant)
    assert assignment.rhs.value == 0
    assert stats.anonymous_direct_store_classified_fact_count == 1
    assert stats.anonymous_direct_store_materialized_count == 1
    assert stats.anonymous_direct_store_failure_count == 0


@pytest.mark.parametrize("op", ("Mull", "Mod"))
def test_anonymous_direct_word_store_accepts_unique_pure_recombined_source_once(op):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    tags = {"ins_addr": 0x10421}
    source = CBinaryOp(
        op,
        _stack(-2, codegen, name="local_2"),
        _const(-1, codegen),
        codegen=codegen,
    )
    carrier_definition = CAssignment(
        _dirty(534, codegen),
        source,
        codegen=codegen,
    )
    low = CAssignment(
        _mem(0x0B46, codegen, name="mem_0B46"),
        _dirty(534, codegen),
        codegen=codegen,
        tags=tags,
    )
    high = CAssignment(
        _mem(0x0B47, codegen, name="mem_0B47"),
        CBinaryOp("Shr", _dirty(534, codegen), _const(8, codegen), codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    root = CStatements([carrier_definition, low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x102E0, statements=root, body=root)
    evidence = (DirectSegmentedGlobalStoreEvidence8616(0x0B46, 2, MemSpace.DS, 0x10421),)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=evidence,
        project=project,
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 2
    assignment = root.statements[1]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CFunctionCall)
    assert assignment.lhs.callee_target == "SEG_U16"
    assert assignment.lhs.args[1].value == 0x0B46
    assert assignment.rhs is source
    assert stats.anonymous_direct_store_classified_fact_count == 1
    assert stats.anonymous_direct_store_materialized_count == 1
    assert stats.anonymous_direct_store_failure_count == 0


def test_anonymous_direct_word_store_refuses_ambiguous_segment_evidence():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    tags = {"ins_addr": 0x1057C}
    low = CAssignment(_mem(0x0B46, codegen), _const(1, codegen), codegen=codegen, tags=tags)
    high = CAssignment(_mem(0x0B47, codegen), _const(0, codegen), codegen=codegen, tags=tags)
    root = CStatements([low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x10560, statements=root, body=root)
    evidence = (
        DirectSegmentedGlobalStoreEvidence8616(0x0B46, 2, MemSpace.DS, 0x1057C),
        DirectSegmentedGlobalStoreEvidence8616(0x0B46, 2, MemSpace.ES, 0x1057C),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=evidence,
        project=project,
        stats=stats,
    )

    assert changed is False
    assert root.statements == [low, high]
    assert stats.anonymous_direct_store_raw_fact_count == 2
    assert stats.anonymous_direct_store_normalized_fact_count == 2
    assert stats.anonymous_direct_store_classified_fact_count == 0
    assert stats.anonymous_direct_store_materialized_count == 0


def test_anonymous_direct_word_store_fails_closed_after_classifying_unsafe_pair():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    tags = {"ins_addr": 0x1057C}
    low = CAssignment(
        _mem(0x0B46, codegen),
        CFunctionCall("side_effect", None, [], codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    high = CAssignment(_mem(0x0B47, codegen), _const(0, codegen), codegen=codegen, tags=tags)
    root = CStatements([low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x10560, statements=root, body=root)
    evidence = (DirectSegmentedGlobalStoreEvidence8616(0x0B46, 2, MemSpace.DS, 0x1057C),)
    stats = SegmentedGlobalLoadStats8616()

    with pytest.raises(
        PipelineHardError,
        match="classified anonymous direct segmented-global stores were not materialized",
    ):
        materialize_direct_global_symbol_stores_from_evidence_8616(
            codegen,
            (),
            anonymous_direct_stores=evidence,
            project=project,
            stats=stats,
        )

    assert root.statements == [low, high]
    assert stats.anonymous_direct_store_classified_fact_count == 1
    assert stats.anonymous_direct_store_materialized_count == 0
    assert stats.anonymous_direct_store_failure_count == 1


def test_anonymous_direct_global_cvariable_materializes_scalar_without_touching_lvalue():
    class _Functions:
        def __init__(self, function):
            self._function = function

        def function(self, *, addr=None, create=False, **_kwargs):
            del addr, create
            return self._function

    load = SimpleNamespace(
        address=0x108DB,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _mem_operand(X86_REG_INVALID, 0x0BA2)),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(load,)))
    function = SimpleNamespace(addr=0x108D0, blocks=(block,))
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=_Functions(function), labels={}),
    )
    codegen = _DummyCodegen()
    loaded = _mem_word(0x0BA2, codegen)
    destination = _stack(-4, codegen)
    load_assignment = CAssignment(destination, loaded, codegen=codegen)
    untouched_lvalue = _mem_word(0x0BA2, codegen)
    store_assignment = CAssignment(untouched_lvalue, _const(7, codegen), codegen=codegen)
    root = CStatements([load_assignment, store_assignment], addr=0x108D0, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x108D0, statements=root, body=root)

    changed = materialize_named_segmented_global_loads_8616(project, codegen, {})

    assert changed is True
    assert isinstance(load_assignment.rhs, CVariable)
    assert load_assignment.rhs.variable.name == "g_0BA2"
    assert store_assignment.lhs is untouched_lvalue
    stats = codegen._inertia_segmented_global_load_stats_8616
    assert stats.anonymous_direct_raw_fact_count == 1
    assert stats.anonymous_direct_normalized_fact_count == 1
    assert stats.anonymous_direct_classified_fact_count == 1
    assert stats.anonymous_direct_materialized_count == 1
    assert stats.anonymous_direct_failure_count == 0

    assert materialize_named_segmented_global_loads_8616(project, codegen, {}) is False
    assert isinstance(load_assignment.rhs, CVariable)
    assert load_assignment.rhs.variable.name == "g_0BA2"


def test_compare_register_global_carrier_evidence_from_direct_load_cmp():
    summaries = [
        InsnSummary8616("mov", "reg", "ax", "direct_mem", 0x42, 2, 2),
        InsnSummary8616("cmp", "bp_mem", -4, "reg", "ax", 2, 2),
    ]

    evidence = recover_compare_register_global_carriers_8616(summaries)

    assert evidence == (CompareRegisterGlobalCarrierEvidence8616("ax", 0x42, 2),)


def test_compare_register_global_carrier_materializes_cmp_operand():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    cmp_expr = CBinaryOp("CmpGE", _stack(-4, codegen, name="i"), _reg(project, codegen, "ax"), codegen=codegen)
    root = CStatements([cmp_expr], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_compare_register_global_carriers_from_evidence_8616(
        project,
        codegen,
        (NamedGlobalEvidence8616(0x42, "g_rows", 2),),
        (CompareRegisterGlobalCarrierEvidence8616("ax", 0x42, 2),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(cmp_expr.rhs, CVariable)
    assert cmp_expr.rhs.name == "g_rows"
    assert stats.compare_register_materialized_count == 1


def test_dword_global_zero_test_evidence_from_high_low_or_jcc():
    summaries = [
        InsnSummary8616("mov", "reg", "ax", "direct_mem", 0x134, 2, 2),
        InsnSummary8616("or", "reg", "ax", "direct_mem", 0x132, 2, 2),
        InsnSummary8616("jne", "imm", 0x4010, "none", None, 2, 0),
    ]

    evidence = recover_dword_global_zero_test_evidence_8616(summaries)

    assert evidence == (DwordGlobalZeroTestEvidence8616(0x132, 0x132, 0x134, "ax"),)


def test_dword_global_zero_test_or_condition_materializes_scalar():
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010)
    low_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    cl_pause = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    low_projection = CBinaryOp("And", cl_pause, _const(0xFFFF, codegen), codegen=codegen)
    condition = CBinaryOp(
        "Or",
        CBinaryOp("Or", _dirty(1081, codegen), low_projection, codegen=codegen),
        low_projection,
        codegen=codegen,
    )

    replacement = _materialize_direct_global_zero_test_or_expr_8616(
        codegen,
        condition,
        {
            (0x132, 2): low_ref,
            (0x134, 2): high_ref,
            (0x132, 4): dword_ref,
        },
        (DwordGlobalZeroTestEvidence8616(0x132, 0x132, 0x134, "ax"),),
    )

    assert isinstance(replacement, CVariable)
    assert replacement.variable.name == "clPause"
    assert replacement.variable.size == 4


def test_dword_global_zero_test_replay_materializes_complete_projection_pair():
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010)
    low_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    cl_pause = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    low_projection = CBinaryOp("And", cl_pause, _const(0xFFFF, codegen), codegen=codegen)
    high_projection = CBinaryOp("Shr", cl_pause, _const(16, codegen), codegen=codegen)
    evidence = (DwordGlobalZeroTestEvidence8616(0x132, 0x132, 0x134, "ax"),)
    direct_refs = {
        (0x132, 2): low_ref,
        (0x134, 2): high_ref,
        (0x132, 4): dword_ref,
    }

    replacement = _materialize_direct_global_zero_test_or_expr_8616(
        codegen,
        CBinaryOp("Or", high_projection, low_projection, codegen=codegen),
        direct_refs,
        evidence,
    )
    refused_half = _materialize_direct_global_zero_test_or_expr_8616(
        codegen,
        CBinaryOp("Or", low_projection, low_projection, codegen=codegen),
        direct_refs,
        evidence,
    )

    assert isinstance(replacement, CVariable)
    assert replacement.variable.name == "clPause"
    assert replacement.variable.size == 4
    assert refused_half is None


def test_indexed_segmented_global_load_materializes_array_element():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    offset = CBinaryOp("Add", _const(0x42, codegen), scaled_i, codegen=codegen)
    rhs = CFunctionCall("SEG_U16", None, [_ds(project, codegen), offset], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2),),
        stats=stats,
    )

    assert changed is True
    assert assignment.rhs.variable.name == "g_work"
    assert isinstance(assignment.rhs.index, CBinaryOp)
    assert assignment.rhs.index.op == "Sub"
    assert stats.indexed_materialized_count == 1


def test_sidecar_free_indexed_global_recovery_uses_exact_binary_identities():
    summaries = [
        InsnSummary8616(
            "mov",
            op0_kind="reg",
            op0_value="ax",
            op1_kind="indexed_mem",
            op1_value=0x08F0,
            op1_size=2,
        ),
        InsnSummary8616(
            "mov",
            op0_kind="indexed_mem",
            op0_value=0x0B4C,
            op1_kind="reg",
            op1_value="ax",
            op0_size=2,
        ),
        InsnSummary8616(
            "mov",
            op0_kind="reg",
            op0_value="dx",
            op1_kind="indexed_mem",
            op1_value=0x08F0,
            op1_size=2,
        ),
    ]

    evidence = recover_indexed_segmented_global_evidence_8616(summaries, None)

    assert evidence == (
        IndexedSegmentedGlobalEvidence8616(0x08F0, "g_08F0", 0, 2),
        IndexedSegmentedGlobalEvidence8616(0x0B4C, "g_0B4C", 0, 2),
    )


def test_indexed_global_summary_refuses_same_instruction_near_pointer_fact():
    summaries = [
        InsnSummary8616(
            "mov",
            op0_kind="indexed_mem",
            op0_value=0,
            op1_kind="reg",
            op1_value="ax",
            op0_size=2,
            address=0x1053,
        )
    ]
    facts = (
        NearPointerArgumentFact8616(
            stack_offset=10,
            carrier_load_ins_addr=0x1050,
            dereference_ins_addr=0x1053,
            access_width_bytes=2,
        ),
    )

    evidence = recover_indexed_segmented_global_evidence_8616(
        summaries,
        None,
        near_pointer_facts=facts,
    )

    assert evidence == ()


def test_unify_sidecar_free_indexed_global_evidence_uses_store_affinity():
    fallback: tuple[IndexedSegmentedGlobalEvidence8616, ...] = (
        IndexedSegmentedGlobalEvidence8616(0x08F0, "g_08F0", 0, 2),
    )
    primary: tuple[IndexedSegmentedGlobalEvidence8616, ...] = (
        IndexedSegmentedGlobalEvidence8616(0x0B4A, "g_0B4A", 0, 2),
        IndexedSegmentedGlobalEvidence8616(0x0B4C, "g_0B4C", 0, 2),
        IndexedSegmentedGlobalEvidence8616(0x0B4A, "g_0B4A", 0, 1),
    )
    store_evidence = (
        IndexedSegmentedGlobalStoreEvidence8616(
            base_offset=0x0B4C,
            width=2,
            index_stack_offset=-4,
            index_shift=1,
            ins_addr=0x10871,
            source_base_offset=0x0B4A,
            source_width=2,
            source_index_stack_offset=-4,
            source_index_shift=1,
            source_stack_offset=None,
            source_stack_width=None,
            source_signed_remainder=None,
        ),
    )

    unified = segmented_global_loads_module._unify_sidecar_free_indexed_evidence_8616(
        primary,
        fallback,
        store_evidence=store_evidence,
    )

    assert IndexedSegmentedGlobalEvidence8616(0x0B4A, "g_0B4C", -2, 2) in unified
    assert IndexedSegmentedGlobalEvidence8616(0x0B4C, "g_0B4C", 0, 2) in unified
    assert IndexedSegmentedGlobalEvidence8616(0x08F0, "g_08F0", 0, 2) in unified


def test_indexed_global_recovery_refuses_mismatched_sidecar_join():
    summaries = [
        InsnSummary8616(
            "mov",
            op0_kind="reg",
            op0_value="ax",
            op1_kind="indexed_mem",
            op1_value=0x08F0,
            op1_size=2,
        ),
        InsnSummary8616(
            "mov",
            op0_kind="indexed_mem",
            op0_value=0x0B4C,
            op1_kind="reg",
            op1_value="ax",
            op0_size=2,
        ),
    ]
    cod_metadata = SimpleNamespace(
        global_refs=(
            SimpleNamespace(
                indexed=True,
                name="abarPerm",
                relative_disp=0,
                width=2,
            ),
        ),
    )

    assert recover_indexed_segmented_global_evidence_8616(summaries, cod_metadata) == ()


def test_indexed_segmented_global_load_materializes_array_element_in_if_condition():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_row_min = _stack(-6, codegen, name="iRowMin")
    i_row_next = _stack(-2, codegen, name="iRowNext")
    min_offset = CBinaryOp("Add", _const(0x56, codegen), CBinaryOp("Shl", i_row_min, _const(1, codegen), codegen=codegen), codegen=codegen)
    next_offset = CBinaryOp("Add", _const(0x56, codegen), CBinaryOp("Shl", i_row_next, _const(1, codegen), codegen=codegen), codegen=codegen)
    condition = CBinaryOp(
        "CmpGT",
        CFunctionCall("SEG_U16", None, [_ds(project, codegen), min_offset], codegen=codegen),
        CFunctionCall("SEG_U16", None, [_ds(project, codegen), next_offset], codegen=codegen),
        codegen=codegen,
    )
    body = CStatements([CAssignment(i_row_min, i_row_next, codegen=codegen)], addr=0x4014, codegen=codegen)
    if_stmt = CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    root = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x56, "g_demo_len", 0, 2),),
        stats=stats,
    )

    assert changed is True
    rewritten_condition = if_stmt.condition_and_nodes[0][0]
    assert rewritten_condition.lhs.variable.name == "g_demo_len"
    assert rewritten_condition.lhs.index is i_row_min
    assert rewritten_condition.rhs.variable.name == "g_demo_len"
    assert rewritten_condition.rhs.index is i_row_next
    assert stats.indexed_materialized_count == 2


def test_indexed_segmented_global_load_folds_raw_byte_pair_word_load():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_row_next = _stack(-2, codegen, name="iRowNext")
    scaled = CBinaryOp("Shl", i_row_next, _const(1, codegen), codegen=codegen)
    low = _deref(CBinaryOp("Add", _ref(_mem(0x56, codegen), codegen), scaled, codegen=codegen), codegen)
    high = _deref(CBinaryOp("Add", _ref(_mem(0x57, codegen), codegen), scaled, codegen=codegen), codegen)
    word = CBinaryOp(
        "Or",
        low,
        CBinaryOp("Shl", high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    assignment = CAssignment(_stack(-4, codegen, name="tmp"), word, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x56, "g_demo_len", 0, 2),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CIndexedVariable)
    assert assignment.rhs.variable.name == "g_demo_len"
    assert assignment.rhs.index is i_row_next
    assert stats.indexed_materialized_count == 1


def test_indexed_segmented_global_load_materializes_direct_constant_global():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    rhs = CFunctionCall("SEG_U16", None, [_ds(project, codegen), _const(0xBA2, codegen)], codegen=codegen)
    condition = CBinaryOp("CmpGT", rhs, _stack(-2, codegen, name="i"), codegen=codegen)
    root = CStatements([condition], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0xBA2, "cRow", 0, 2),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(condition.lhs, CVariable)
    assert condition.lhs.name == "cRow"
    assert stats.indexed_materialized_count == 1


def test_indexed_segmented_global_assignment_preserves_read_write_access_roles():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    lhs = CFunctionCall(
        "SEG_U16",
        None,
        [_ds(project, codegen), _const(0xBA2, codegen)],
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    rhs = CFunctionCall(
        "SEG_U16",
        None,
        [_ds(project, codegen), _const(0xBA2, codegen)],
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    assignment = CAssignment(lhs, rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x4010,
        accesses=tuple(
            SegmentAccessFact(
                block_addr=instruction_addr,
                instruction_addr=instruction_addr,
                kind=access_kind,
                address=IRAddress(
                    space=MemSpace.DS,
                    offset=0xBA2,
                    size=2,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
                segment_register="ds",
                physical_source="ds",
                verdict=SegmentFactVerdict.PROVEN,
            )
            for instruction_addr, access_kind in (
                (0x4010, SegmentAccessKind.WRITE),
                (0x4020, SegmentAccessKind.READ),
            )
        ),
    )

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0xBA2, "cRow", 0, 2),),
    )

    assert changed is True
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.name == "cRow"
    assert isinstance(assignment.rhs, CVariable)
    assert assignment.rhs.name == "cRow"
    assert codegen._inertia_segment_access_lowering_stats_8616.materialized_count == 2


@pytest.mark.parametrize("materializer", ("named", "indexed"))
def test_segmented_global_assignment_treats_lvalue_address_as_read(materializer):
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    pointer_load = CFunctionCall(
        "SEG_U16",
        None,
        [_ds(project, codegen), _const(0x7002, codegen)],
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    lhs = CFunctionCall(
        "SEG_U8",
        None,
        [
            _ds(project, codegen),
            CBinaryOp("Add", _const(8, codegen), pointer_load, codegen=codegen),
        ],
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    assignment = CAssignment(lhs, _const(50, codegen), codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x4010,
        accesses=(
            SegmentAccessFact(
                block_addr=0x4010,
                instruction_addr=0x4010,
                kind=SegmentAccessKind.READ,
                address=IRAddress(
                    space=MemSpace.DS,
                    offset=0x7002,
                    size=2,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
                segment_register="ds",
                physical_source="ds",
                verdict=SegmentFactVerdict.PROVEN,
            ),
        ),
    )

    if materializer == "named":
        changed = materialize_named_segmented_global_loads_8616(
            project,
            codegen,
            {0x7002: ("Rp3D", 2)},
        )
    else:
        changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
            project,
            codegen,
            (IndexedSegmentedGlobalEvidence8616(0x7002, "Rp3D", 0, 2),),
        )

    assert changed is True
    assert isinstance(assignment.lhs, CFunctionCall)
    offset = assignment.lhs.args[1]
    assert isinstance(offset, CBinaryOp)
    assert isinstance(offset.rhs, CVariable)
    assert offset.rhs.name == "Rp3D"


def test_indexed_direct_subword_replay_retains_exact_segment_access_provenance(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [_ds(project, codegen), _const(0x134, codegen)],
        codegen=codegen,
        tags={"inertia_source_instruction_addrs": (0x4010,)},
    )
    condition = CBinaryOp("CmpLE", helper, _const(0, codegen), codegen=codegen)
    root = CStatements([condition], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x4010,
        accesses=tuple(
            SegmentAccessFact(
                block_addr=instruction_addr,
                instruction_addr=instruction_addr,
                kind=SegmentAccessKind.READ,
                address=IRAddress(
                    space=MemSpace.DS,
                    offset=0x134,
                    size=2,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
                segment_register="ds",
                physical_source="ds",
                verdict=SegmentFactVerdict.PROVEN,
            )
            for instruction_addr in (0x4010, 0x4020)
        ),
    )

    first_changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x134, "clPause", 2, 2),),
    )

    assert first_changed is True
    assert isinstance(condition.lhs, CIndexedVariable)
    assert condition.lhs.tags["inertia_source_instruction_addrs"] == (0x4010,)

    refs = (
        DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2),
        DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0),
    )
    monkeypatch.setattr(
        segmented_global_loads_module,
        "_collect_direct_global_symbol_refs_8616",
        lambda *_args: refs,
    )
    monkeypatch.setattr(
        segmented_global_loads_module,
        "_collect_synthetic_direct_global_symbol_refs_8616",
        lambda *_args: (),
    )

    replay_changed = materialize_named_segmented_global_loads_8616(project, codegen, {})

    assert replay_changed is True
    assert isinstance(condition.lhs, CBinaryOp)
    assert condition.lhs.op == "Shr"
    assert condition.lhs.tags["inertia_source_instruction_addrs"] == (0x4010,)


def test_indexed_segmented_global_pointer_materializes_array_address():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    offset = CBinaryOp("Add", _const(0x42, codegen), scaled_i, codegen=codegen)
    rhs = CFunctionCall("SEG_PTR", None, [_ds(project, codegen), offset], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 1),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CUnaryOp)
    assert assignment.rhs.op == "Reference"
    assert assignment.rhs.operand.variable.name == "g_work"
    assert assignment.rhs.operand.index is i_var
    assert stats.indexed_materialized_count == 1


def test_indexed_segmented_global_pointer_refuses_shape_only_aggregate_type():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    offset = CBinaryOp("Add", _const(0x42, codegen), scaled_i, codegen=codegen)
    pointer = CFunctionCall("SEG_PTR", None, [_ds(project, codegen), offset], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), pointer, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x40, "g_work", -2, 1),
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2),
        ),
    )

    assert changed is True
    assert isinstance(assignment.rhs, CUnaryOp)
    assert assignment.rhs.op == "Reference"
    assert isinstance(assignment.rhs.operand, CIndexedVariable)
    assert isinstance(assignment.rhs.operand.type, SimTypeShort)
    assert isinstance(assignment.rhs.type, SimTypePointer)
    assert isinstance(assignment.rhs.type.pts_to, SimTypeShort)
    assert assignment.rhs.type.c_repr(name="arg") == "unsigned short *arg"
    assert codegen._inertia_global_declaration_specs_8616 == (
        (
            "unsigned short",
            "g_work",
            GlobalDeclarationArrayExtent8616.UNKNOWN,
        ),
    )


def test_named_global_aggregate_declaration_replays_after_type_store_appears():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    offset = CBinaryOp("Add", _const(0x42, codegen), scaled_i, codegen=codegen)
    pointer = CFunctionCall("SEG_PTR", None, [_ds(project, codegen), offset], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), pointer, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    assert materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x40, "g_work", -2, 1),
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2, "g_work"),
        ),
    )
    assert isinstance(assignment.rhs, CUnaryOp)
    assert isinstance(assignment.rhs.operand, CIndexedVariable)
    equivalent = segmented_global_loads_module._two_byte_global_struct_type_8616("g_work")
    assignment.rhs.operand._type = TypeRef(equivalent.name, equivalent)
    assert codegen._inertia_global_declaration_specs_8616[0][0].startswith("struct g_work_entry")

    variable_manager = _DummyVariableManager()
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variable_manager=variable_manager,
    )

    assert reapply_proven_named_global_aggregate_types_8616(codegen) is True
    assert codegen._inertia_global_declaration_specs_8616 == (
        (
            "g_work_entry",
            "g_work",
            GlobalDeclarationArrayExtent8616.UNKNOWN,
        ),
    )
    assert isinstance(variable_manager.types["g_work_entry"], TypeRef)
    stats = codegen._inertia_named_global_aggregate_type_replay_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_named_global_aggregate_replay_refuses_without_type_store():
    codegen = _DummyCodegen()
    codegen._inertia_named_global_aggregate_type_facts_8616 = (
        segmented_global_loads_module.NamedGlobalAggregateTypeFact8616(
            "g_work",
            segmented_global_loads_module._two_byte_global_struct_type_8616("g_work"),
            1,
        ),
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010)

    assert reapply_proven_named_global_aggregate_types_8616(codegen) is False
    stats = codegen._inertia_named_global_aggregate_type_replay_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


def test_named_global_aggregate_reconciles_rollback_restored_inline_declaration():
    codegen = _DummyCodegen()
    struct_type = segmented_global_loads_module._two_byte_global_struct_type_8616("g_work")
    variable_manager = _DummyVariableManager()
    variable_manager.types[struct_type.name] = TypeRef(struct_type.name, struct_type)
    codegen.cfunc = SimpleNamespace(addr=0x4010, variable_manager=variable_manager)
    codegen._inertia_named_global_aggregate_type_facts_8616 = (
        segmented_global_loads_module.NamedGlobalAggregateTypeFact8616("g_work", struct_type, 1),
    )
    codegen._inertia_global_declaration_specs_8616 = (
        ("struct g_work_entry { unsigned char field_0; unsigned char field_1; }", "g_work", 1),
    )

    assert reconcile_registered_named_global_aggregate_declarations_8616(codegen) is True
    assert codegen._inertia_global_declaration_specs_8616 == (("g_work_entry", "g_work", 1),)
    assert codegen._inertia_named_type_definitions_8616 == (
        "typedef struct g_work_entry {\n    char field_0;\n    char field_1;\n} g_work_entry;",
    )
    stats = codegen._inertia_named_global_aggregate_declaration_reconcile_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_named_global_aggregate_reconcile_refuses_mismatched_registered_type():
    codegen = _DummyCodegen()
    struct_type = segmented_global_loads_module._two_byte_global_struct_type_8616("g_work")
    other_type = segmented_global_loads_module._two_byte_global_struct_type_8616("other")
    variable_manager = _DummyVariableManager()
    variable_manager.types[struct_type.name] = TypeRef(struct_type.name, other_type)
    codegen.cfunc = SimpleNamespace(addr=0x4010, variable_manager=variable_manager)
    codegen._inertia_named_global_aggregate_type_facts_8616 = (
        segmented_global_loads_module.NamedGlobalAggregateTypeFact8616("g_work", struct_type, 1),
    )
    inline = "struct g_work_entry { unsigned char field_0; unsigned char field_1; }"
    codegen._inertia_global_declaration_specs_8616 = ((inline, "g_work", 1),)

    assert reconcile_registered_named_global_aggregate_declarations_8616(codegen) is False
    assert codegen._inertia_global_declaration_specs_8616 == ((inline, "g_work", 1),)
    stats = codegen._inertia_named_global_aggregate_declaration_reconcile_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


def test_named_global_aggregate_reconcile_initializes_empty_declaration_contract():
    codegen = _DummyCodegen()

    changed = reconcile_registered_named_global_aggregate_declarations_8616(codegen)

    assert changed is False
    assert codegen._inertia_global_declaration_specs_8616 == ()


def test_indexed_segmented_global_materializes_heapsort_call_and_loop_shape():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    c_row_load = CFunctionCall("SEG_U16", None, [_ds(project, codegen), _const(0xBA2, codegen)], codegen=codegen)
    first_condition = CBinaryOp("CmpGT", c_row_load, i_var, codegen=codegen)
    first_loop = CForLoop(
        CAssignment(i_var, _const(1, codegen), codegen=codegen),
        first_condition,
        CAssignment(i_var, CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    base_ptr = CFunctionCall("SEG_PTR", None, [_ds(project, codegen), _const(0xB4C, codegen)], codegen=codegen)
    indexed_offset = CBinaryOp(
        "Add",
        CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen),
        _const(0xB4C, codegen),
        codegen=codegen,
    )
    indexed_ptr = CFunctionCall("SEG_PTR", None, [_ds(project, codegen), indexed_offset], codegen=codegen)
    swap_call = CFunctionCall("Swaps", None, [base_ptr, indexed_ptr], codegen=codegen)
    second_loop = CForLoop(None, CBinaryOp("CmpGT", i_var, _const(0, codegen), codegen=codegen), None, CStatements([swap_call], codegen=codegen), codegen=codegen)
    root = CStatements([first_loop, second_loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0xBA2, "cRow", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0xB4C, "abarWork", 0, 2),
        ),
        stats=stats,
    )

    assert changed is True
    assert isinstance(first_condition.lhs, CVariable)
    assert first_condition.lhs.name == "cRow"
    assert isinstance(swap_call.args[0], CUnaryOp)
    assert swap_call.args[0].op == "Reference"
    assert swap_call.args[0].operand.variable.name == "abarWork"
    assert _constant_int_8616(swap_call.args[0].operand.index) == 0
    assert isinstance(swap_call.args[1], CUnaryOp)
    assert swap_call.args[1].op == "Reference"
    assert swap_call.args[1].operand.variable.name == "abarWork"
    assert swap_call.args[1].operand.index is i_var
    assert stats.indexed_materialized_count == 3


def test_segment_pointer_over_indexed_near_pointer_table_materializes_table_element():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    codegen._inertia_global_declaration_specs_8616 = (("unsigned short", "aszMenu", 1),)
    i_var = _stack(-4, codegen, name="i")
    indexed = _global_indexed("aszMenu", 0x136, i_var, codegen)
    call = CFunctionCall(
        "outtext",
        None,
        [CFunctionCall("SEG_PTR", None, [_ds(project, codegen), indexed], codegen=codegen)],
        codegen=codegen,
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x136, "aszMenu", 0, 2),),
        stats=stats,
    )

    assert changed is True
    assert call.args[0] is indexed
    assert stats.indexed_materialized_count == 1
    assert codegen._inertia_global_declaration_specs_8616 == (("char *", "aszMenu", 1),)


def test_segment_pointer_over_raw_indexed_near_pointer_load_materializes_table_element():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    codegen._inertia_global_declaration_specs_8616 = (("unsigned short", "aszMenu", 1),)
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    offset = CBinaryOp("Add", _const(0x136, codegen), scaled_i, codegen=codegen)
    table_load = CFunctionCall("SEG_U16", None, [_ds(project, codegen), offset], codegen=codegen)
    call = CFunctionCall(
        "outtext",
        None,
        [CFunctionCall("SEG_PTR", None, [_ds(project, codegen), table_load], codegen=codegen)],
        codegen=codegen,
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x136, "aszMenu", 0, 2),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(call.args[0], CIndexedVariable)
    assert call.args[0].variable.variable.name == "aszMenu"
    assert call.args[0].index is i_var
    assert stats.indexed_materialized_count == 1
    assert codegen._inertia_global_declaration_specs_8616 == (("char *", "aszMenu", 1),)


def test_indexed_segmented_byte_field_load_keeps_byte_access_with_array_address():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    offset = CBinaryOp("Add", _const(0x42, codegen), scaled_i, codegen=codegen)
    rhs = CFunctionCall("SEG_U8", None, [_ds(project, codegen), offset], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 1),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_0"
    assert isinstance(assignment.rhs.variable, CIndexedVariable)
    assert assignment.rhs.variable.variable.name == "g_work"
    assert assignment.rhs.variable.index is i_var
    assert stats.indexed_materialized_count == 1


def test_direct_symbol_ref_evidence_materializes_constant_and_indexed_segment_pointers():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    indexed_offset = CBinaryOp("Add", _const(0x42, codegen), scaled_i, codegen=codegen)
    call = CFunctionCall(
        "Swaps",
        None,
        [
            CFunctionCall("SEG_PTR", None, [_ds(project, codegen), _const(0x42, codegen)], codegen=codegen),
            CFunctionCall("SEG_PTR", None, [_ds(project, codegen), indexed_offset], codegen=codegen),
        ],
        codegen=codegen,
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()
    evidence = _indexed_evidence_from_direct_symbol_refs_8616(
        (DirectGlobalSymbolRef8616(0x42, "g_work", 0, 2, 0),)
    )

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        evidence,
        stats=stats,
    )

    assert changed is True
    first, second = call.args
    assert isinstance(first, CUnaryOp)
    assert first.op == "Reference"
    assert first.operand.variable.name == "g_work"
    assert first.operand.index.value == 0
    assert isinstance(second, CUnaryOp)
    assert second.op == "Reference"
    assert second.operand.variable.name == "g_work"
    assert second.operand.index is i_var
    assert stats.indexed_materialized_count == 2


def test_direct_symbol_ref_evidence_materializes_indexed_segment_pointer_with_element_displacement():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    indexed_offset = CBinaryOp("Add", _const(0x44, codegen), scaled_i, codegen=codegen)
    call = CFunctionCall(
        "Swaps",
        None,
        [CFunctionCall("SEG_PTR", None, [_ds(project, codegen), indexed_offset], codegen=codegen)],
        codegen=codegen,
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()
    evidence = _indexed_evidence_from_direct_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0x42, "g_work", 0, 2, 0),
            DirectGlobalSymbolRef8616(0x44, "g_work", 2, 2, 0),
        )
    )

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        evidence,
        stats=stats,
    )

    assert changed is True
    (arg,) = call.args
    assert isinstance(arg, CUnaryOp)
    assert arg.op == "Reference"
    assert arg.operand.variable.name == "g_work"
    assert isinstance(arg.operand.index, CBinaryOp)
    assert arg.operand.index.op == "Add"
    assert arg.operand.index.lhs is i_var
    assert arg.operand.index.rhs.value == 1
    assert stats.indexed_materialized_count == 1


def test_indexed_evidence_prefers_field_displacement_over_conflicting_same_offset_word_ref():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    indexed_offset = CBinaryOp("Add", _const(0x44, codegen), scaled_i, codegen=codegen)
    call = CFunctionCall(
        "Swaps",
        None,
        [CFunctionCall("SEG_PTR", None, [_ds(project, codegen), indexed_offset], codegen=codegen)],
        codegen=codegen,
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 2, 1),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        ),
        stats=stats,
    )

    assert changed is True
    (arg,) = call.args
    assert isinstance(arg, CUnaryOp)
    assert arg.op == "Reference"
    assert arg.operand.variable.name == "g_work"
    assert isinstance(arg.operand.index, CBinaryOp)
    assert arg.operand.index.op == "Add"
    assert arg.operand.index.lhs is i_var
    assert arg.operand.index.rhs.value == 1
    assert stats.indexed_materialized_count == 1


def test_indexed_byte_load_prefers_word_stride_projection_when_word_array_evidence_exists():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    indexed_offset = CBinaryOp("Add", _const(0x42, codegen), scaled_i, codegen=codegen)
    rhs = CFunctionCall("SEG_U8", None, [_ds(project, codegen), indexed_offset], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 1),
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2),
        ),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_0"
    assert isinstance(assignment.rhs.variable, CIndexedVariable)
    assert assignment.rhs.variable.variable.name == "g_work"
    assert assignment.rhs.variable.index is i_var
    assert codegen._inertia_global_declaration_specs_8616 == (
        (
            "struct g_work_entry { unsigned char field_0; unsigned char field_1; }",
            "g_work",
            GlobalDeclarationArrayExtent8616.UNKNOWN,
        ),
    )
    assert stats.indexed_materialized_count == 1


def test_indexed_byte_load_accepts_lowered_runtime_ds_state() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    index = _stack(-4, codegen, name="i")
    offset = CBinaryOp(
        "Add",
        _const(0x42, codegen),
        CBinaryOp("Shl", index, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    runtime_ds = runtime_segment_push_source_cvar_8616(
        "ds",
        codegen=codegen,
        variable_type=SimTypeShort(False),
        function_addr=0x4010,
    )
    assert runtime_ds is not None
    rhs = CFunctionCall("SEG_U8", None, [runtime_ds, offset], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 1),
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2),
        ),
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_0"


def test_indexed_byte_load_refuses_lowered_runtime_es_state() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    index = _stack(-4, codegen, name="i")
    offset = CBinaryOp(
        "Add",
        _const(0x42, codegen),
        CBinaryOp("Shl", index, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    runtime_es = runtime_segment_push_source_cvar_8616(
        "es",
        codegen=codegen,
        variable_type=SimTypeShort(False),
        function_addr=0x4010,
    )
    assert runtime_es is not None
    rhs = CFunctionCall("SEG_U8", None, [runtime_es, offset], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 1),
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2),
        ),
    )

    assert changed is False
    assert assignment.rhs is rhs


def test_indexed_word_load_propagates_proven_struct_type_to_stack_copy():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="iRow")
    bar_temp = _stack(-8, codegen, name="barTemp")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    indexed_offset = CBinaryOp("Add", _const(0x42, codegen), scaled_i, codegen=codegen)
    rhs = CFunctionCall("SEG_U16", None, [_ds(project, codegen), indexed_offset], codegen=codegen)
    assignment = CAssignment(bar_temp, rhs, codegen=codegen)
    i_length = _stack(-6, codegen, name="iLength")
    indexed_low_byte = CTypeCast(
        None,
        SimTypeChar(True),
        CFunctionCall("SEG_U16", None, [_ds(project, codegen), indexed_offset], codegen=codegen),
        codegen=codegen,
    )
    stack_low_byte = CTypeCast(SimTypeShort(False), SimTypeChar(True), bar_temp, codegen=codegen)
    indexed_byte_assignment = CAssignment(i_length, indexed_low_byte, codegen=codegen)
    stack_byte_assignment = CAssignment(i_length, stack_low_byte, codegen=codegen)
    stale_aggregate_assignment = CAssignment(
        i_length,
        CFunctionCall("SEG_U16", None, [_ds(project, codegen), indexed_offset], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements(
        [assignment, indexed_byte_assignment, stack_byte_assignment, stale_aggregate_assignment],
        addr=0x4010,
        codegen=codegen,
    )
    hidden_bar_temp = SimStackVariable(-8, 2, base="bp", name="barTemp_hidden")
    variable_manager = _DummyVariableManager()
    variable_manager.variables.extend((bar_temp.variable, hidden_bar_temp))
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={bar_temp.variable: bar_temp},
        unified_local_vars={},
        variable_manager=variable_manager,
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x40, "g_work", -2, 1),
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2, "g_work"),
        ),
        load_site_evidence=(
            IndexedSegmentedGlobalLoadSiteEvidence8616(
                0x42,
                2,
                -2,
                1,
                0x4010,
                (IndexedSegmentedGlobalStackStore8616(-8, 2, 0x4014),),
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CIndexedVariable)
    assert isinstance(assignment.rhs.type, SimStruct)
    assert isinstance(bar_temp.variable_type, SimStruct)
    assert not isinstance(i_length.variable_type, SimStruct)
    assert assignment.rhs.type == bar_temp.variable_type
    assert isinstance(indexed_byte_assignment.rhs, CTypeCast)
    assert isinstance(indexed_byte_assignment.rhs.expr, CVariableField)
    assert indexed_byte_assignment.rhs.expr.field.field == "field_0"
    assert isinstance(indexed_byte_assignment.rhs.expr.variable, CIndexedVariable)
    assert isinstance(stack_byte_assignment.rhs, CTypeCast)
    assert isinstance(stack_byte_assignment.rhs.expr, CVariableField)
    assert stack_byte_assignment.rhs.expr.field.field == "field_0"
    assert stack_byte_assignment.rhs.expr.variable is bar_temp
    assert codegen._inertia_global_declaration_specs_8616 == (
        (
            "g_work_entry",
            "g_work",
            GlobalDeclarationArrayExtent8616.UNKNOWN,
        ),
    )
    registered_type = codegen.cfunc.variable_manager.types["g_work_entry"]
    assert isinstance(registered_type, TypeRef)
    assert registered_type.type == assignment.rhs.type
    assert codegen.cfunc.variable_manager.variable_to_types[bar_temp.variable] == registered_type
    assert codegen.cfunc.variable_manager.variable_to_types[hidden_bar_temp] == registered_type
    assert codegen.show_local_types is True
    assert stats.indexed_stack_aggregate_type_promoted_count == 1
    assert stats.indexed_stack_aggregate_byte_cast_projected_count == 2
    copy_facts = (
        segmented_global_loads_module.indexed_global_stack_aggregate_copy_facts_8616(
            codegen
        )
    )
    assert len(copy_facts) == 1
    copy_fact = copy_facts[0]
    assert copy_fact.source_global_offset == 0x42
    assert copy_fact.source_index_base == "bp"
    assert copy_fact.source_index_offset == -2
    assert copy_fact.source_index_adjustment == 0
    assert copy_fact.destination_base == "bp"
    assert copy_fact.destination_offset == -8
    assert copy_fact.width == 2
    assert copy_fact.struct_type == assignment.rhs.type
    assert copy_fact.load_ins_addr == 0x4010
    assert copy_fact.store_ins_addr == 0x4014

    segmented_global_loads_module._promote_stack_value_expr_to_width_8616(codegen, bar_temp, 2)

    assert isinstance(bar_temp.variable_type, SimStruct)
    assert codegen.cfunc.variable_manager.variable_to_types[bar_temp.variable] == registered_type

    bar_temp.variable_type = SimTypeShort(False)
    codegen.cfunc.variable_manager.variable_to_types[bar_temp.variable] = SimTypeShort(False)
    codegen.cfunc.variable_manager.variable_to_types[hidden_bar_temp] = SimTypeShort(False)
    stack_byte_assignment.rhs = bar_temp

    assert segmented_global_loads_module.reapply_proven_stack_aggregate_types_8616(codegen) is True
    assert isinstance(bar_temp.variable_type, SimStruct)
    assert isinstance(codegen.cfunc.variable_manager.variable_to_types[bar_temp.variable], TypeRef)
    replay_stats = codegen._inertia_stack_aggregate_type_replay_stats_8616
    assert replay_stats.raw_fact_count == 1
    assert replay_stats.normalized_fact_count == 1
    assert replay_stats.classified_fact_count == 1
    assert replay_stats.materialized_count == 1
    assert replay_stats.failure_count == 0
    assert segmented_global_loads_module.reapply_proven_stack_aggregate_field_projections_8616(codegen) is True
    assert isinstance(stack_byte_assignment.rhs, CTypeCast)
    assert isinstance(stack_byte_assignment.rhs.expr, CVariableField)
    assert stack_byte_assignment.rhs.expr.field.field == "field_0"
    projection_stats = codegen._inertia_stack_aggregate_field_projection_replay_stats_8616
    assert projection_stats.raw_fact_count == 1
    assert projection_stats.normalized_fact_count == 1
    assert projection_stats.classified_fact_count == 1
    assert projection_stats.materialized_count == 1
    assert projection_stats.failure_count == 0


def test_indexed_word_load_refuses_aggregate_without_function_type_store():
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010)
    index = _stack(-2, codegen, name="iRow")
    byte_evidence = IndexedSegmentedGlobalEvidence8616(0x40, "g_work", -2, 1)
    word_evidence = IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2)

    result = segmented_global_loads_module._make_indexed_global_value_expr_8616(
        codegen,
        word_evidence,
        index,
        {
            (0x40, 1): byte_evidence,
            (0x42, 2): word_evidence,
        },
    )

    assert isinstance(result, CIndexedVariable)
    assert isinstance(result.type, SimTypeShort)
    assert codegen._inertia_global_declaration_specs_8616 == (
        (
            "unsigned short",
            "g_work",
            GlobalDeclarationArrayExtent8616.UNKNOWN,
        ),
    )
    assert not hasattr(codegen, "show_local_types")


def test_indexed_byte_load_keeps_element_displacement_when_projecting_word_array_evidence():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    indexed_offset = CBinaryOp("Add", _const(0x44, codegen), scaled_i, codegen=codegen)
    rhs = CFunctionCall("SEG_U8", None, [_ds(project, codegen), indexed_offset], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 2, 1),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        ),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_0"
    assert isinstance(assignment.rhs.variable, CIndexedVariable)
    assert assignment.rhs.variable.variable.name == "g_work"
    assert isinstance(assignment.rhs.variable.index, CBinaryOp)
    assert assignment.rhs.variable.index.op == "Add"
    assert assignment.rhs.variable.index.lhs is i_var
    assert assignment.rhs.variable.index.rhs.value == 1
    assert stats.indexed_materialized_count == 1


def test_cod_offset_global_refs_ignore_listing_text():
    metadata = SimpleNamespace(
        cod_raw_entries=(
            {"offset": 0x9A9, "text": "add\tax,OFFSET DGROUP:_g_work"},
            {"offset": 0x9AD, "text": "mov\tax,OFFSET DGROUP:_g_work+2"},
        )
    )

    refs = _cod_offset_global_refs_8616(metadata)

    assert refs == ()


def test_cod_offset_global_refs_use_structured_address_refs():
    metadata = SimpleNamespace(
        global_address_refs=(
            CODGlobalAddressRef(0x9A9, "g_work", 0, 2, b"\xb8\x42\x00"),
            CODGlobalAddressRef(0x9AD, "g_work", 2, 2, b"\xb8\x44\x00"),
        )
    )

    refs = _cod_offset_global_refs_8616(metadata)

    assert refs == ((0x9A9, "g_work", 0), (0x9AD, "g_work", 2))


def test_offset_symbol_refs_ignore_cod_listing_text():
    metadata = SimpleNamespace(
        cod_raw_entries=(
            {"offset": 0x960, "text": "push\tbp"},
            {"offset": 0x9A9, "text": "add\tax,OFFSET DGROUP:_g_work"},
            {"offset": 0x9AD, "text": "mov\tax,OFFSET DGROUP:_g_work"},
        )
    )
    summaries = [
        InsnSummary8616("push", "reg", "bp", address=0x1000),
        InsnSummary8616("mov", "bp_mem", -2, "imm", 1, 2, 2, address=0x100B),
        InsnSummary8616("add", "reg", "ax", "imm", 0x42, 2, 2, address=0x1049),
        InsnSummary8616("mov", "reg", "ax", "imm", 0x42, 2, 2, address=0x104D),
        InsnSummary8616("mov", "reg", "ax", "imm", 0, 2, 2, address=0x9BA),
    ]

    refs = _collect_global_address_symbol_refs_8616(metadata, summaries)
    evidence = _indexed_evidence_from_direct_symbol_refs_8616(refs)

    assert refs == ()
    assert evidence == ()


def test_offset_symbol_refs_use_structured_address_refs_and_summary_immediate():
    metadata = SimpleNamespace(
        instruction_offsets=(0x960, 0x9A9),
        global_address_refs=(CODGlobalAddressRef(0x9A9, "g_work", 0, 2, b"\xb8\x42\x00"),),
    )
    summaries = [
        InsnSummary8616("push", "reg", "bp", address=0x1000),
        InsnSummary8616("mov", "reg", "ax", "imm", 0x42, 2, 2, address=0x1049),
    ]

    refs = _collect_global_address_symbol_refs_8616(metadata, summaries)
    evidence = _indexed_evidence_from_direct_symbol_refs_8616(refs)

    assert refs == (
        DirectGlobalSymbolRef8616(0x42, "g_work", 0, 1, 0),
        DirectGlobalSymbolRef8616(0x42, "g_work", 0, 2, 0),
    )
    assert evidence == (
        IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 1),
        IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 2),
    )


def test_structured_address_literal_materializes_segment_pointer_to_string_constant():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    call = CFunctionCall(
        "sprintf",
        None,
        [
            CVariable(SimStackVariable(-80, 80, name="achTiming"), codegen=codegen),
            CFunctionCall("SEG_PTR", None, [_ds(project, codegen), _const(0x17D, codegen)], codegen=codegen),
        ],
        codegen=codegen,
    )
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (),
        address_literals=(GlobalAddressLiteralEvidence8616(0x17D, "%7.i  %4.i  %4.i"),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(call.args[1], CConstant)
    rendered = "".join(chunk for chunk, _node in call.args[1].c_repr_chunks())
    assert rendered == '"%7.i  %4.i  %4.i"'
    assert stats.indexed_materialized_count == 1


def test_collect_global_address_literal_evidence_matches_summary_immediate():
    metadata = SimpleNamespace(
        instruction_offsets=(0x4C8, 0x4CF),
        global_address_refs=(CODGlobalAddressRef(0x4CF, "SG604", 0, 2, b"\xb8\x3b\x01", "%7.i  %4.i  %4.i"),),
    )
    summaries = [
        InsnSummary8616("push", "reg", "bp", address=0x10498),
        InsnSummary8616("mov", "reg", "ax", "imm", 0x17D, 2, 2, address=0x104A1),
    ]

    evidence = _collect_global_address_literal_evidence_8616(metadata, summaries)

    assert evidence == (GlobalAddressLiteralEvidence8616(0x17D, "%7.i  %4.i  %4.i"),)


def test_indexed_segmented_global_store_evidence_recovers_shifted_stack_index():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    load_index = SimpleNamespace(
        address=0x1050,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _mem_operand(X86_REG_BP, -4)),
    )
    scale_index = SimpleNamespace(
        address=0x1053,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1)),
    )
    store = SimpleNamespace(
        address=0x1057,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_BX, 0x42), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x1050, capstone=SimpleNamespace(insns=(load_index, scale_index, store))),),
    )

    evidence = recover_indexed_segmented_global_store_evidence_8616(project, function)

    assert evidence == (IndexedSegmentedGlobalStoreEvidence8616(0x42, 2, -4, 1, 0x1057),)


def test_indexed_global_store_refuses_binary_proven_pointer_argument():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    load_pointer = SimpleNamespace(
        address=0x1050,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _mem_operand(X86_REG_BP, 10)),
    )
    indirect_store = SimpleNamespace(
        address=0x1053,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_BX, 0), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(SimpleNamespace(addr=0x1050, capstone=SimpleNamespace(insns=(load_pointer, indirect_store))),),
    )

    evidence = recover_indexed_segmented_global_store_evidence_8616(project, function)

    assert evidence == ()


def test_indexed_segmented_global_load_site_evidence_recovers_shifted_stack_index():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    load_index = SimpleNamespace(
        address=0x1050,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _mem_operand(X86_REG_BP, -4)),
    )
    scale_index = SimpleNamespace(
        address=0x1053,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1)),
    )
    load = SimpleNamespace(
        address=0x1057,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _mem_operand(X86_REG_BX, 0x42)),
    )
    store = SimpleNamespace(
        address=0x105A,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_BP, -8), _reg_operand(X86_REG_AX)),
    )
    overwrite_low = SimpleNamespace(
        address=0x105D,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AL, size=1), _mem_operand(X86_REG_BP, -8, size=1)),
    )
    stale_alias_store = SimpleNamespace(
        address=0x1060,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_BP, -6), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1050,
                capstone=SimpleNamespace(
                    insns=(load_index, scale_index, load, store, overwrite_low, stale_alias_store)
                ),
            ),
        ),
    )

    evidence = recover_indexed_segmented_global_load_site_evidence_8616(project, function)

    assert evidence == (
        IndexedSegmentedGlobalLoadSiteEvidence8616(
            0x42,
            2,
            -4,
            1,
            0x1057,
            (IndexedSegmentedGlobalStackStore8616(-8, 2, 0x105A),),
            destination_register="ax",
            index_stack_width=2,
        ),
    )


def test_indexed_load_site_evidence_recovers_comparison_memory_consumer():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    load_index = SimpleNamespace(
        address=0x1050,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _mem_operand(X86_REG_BP, -4)),
    )
    scale_index = SimpleNamespace(
        address=0x1053,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1)),
    )
    compare = SimpleNamespace(
        address=0x1057,
        id=X86_INS_CMP,
        operands=(_mem_operand(X86_REG_BX, 0x42, size=1), _reg_operand(X86_REG_AL, size=1)),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1050,
                capstone=SimpleNamespace(insns=(load_index, scale_index, compare)),
            ),
        ),
    )

    evidence = recover_indexed_segmented_global_load_site_evidence_8616(project, function)

    assert evidence == (
        IndexedSegmentedGlobalLoadSiteEvidence8616(
            0x42,
            1,
            -4,
            1,
            0x1057,
            destination_register=None,
            index_stack_width=2,
            consumer=IndexedSegmentedGlobalLoadConsumer8616.COMPARISON,
        ),
    )


def test_indexed_load_site_materializes_raw_dereference_without_vvar_shape_guessing():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    raw_pointer = CBinaryOp(
        "Add",
        CFunctionCall("MK_FP", None, [_dirty(10, codegen), _const(0, codegen)], codegen=codegen),
        _dirty(11, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1057},
    )
    index_var = _stack(-4, codegen, name="i")
    index_seed = CAssignment(index_var, _const(0, codegen), codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), _deref(raw_pointer, codegen), codegen=codegen)
    root = CStatements([index_seed, assignment], addr=0x1050, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1050, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 1),),
        load_site_evidence=(IndexedSegmentedGlobalLoadSiteEvidence8616(0x42, 1, -4, 1, 0x1057),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_0"
    assert assignment.rhs.variable.variable.name == "g_work"
    assert assignment.rhs.variable.index.variable.name == "i"
    assert stats.indexed_load_site_materialized_count == 1


def test_indexed_segmented_global_store_evidence_recovers_source_index():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    load_source_index = SimpleNamespace(
        address=0x1050,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _mem_operand(X86_REG_BP, -6)),
    )
    scale_source_index = SimpleNamespace(
        address=0x1053,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1)),
    )
    load_source = SimpleNamespace(
        address=0x1057,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _mem_operand(X86_REG_BX, 0x44)),
    )
    load_store_index = SimpleNamespace(
        address=0x105B,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _mem_operand(X86_REG_BP, -4)),
    )
    scale_store_index = SimpleNamespace(
        address=0x105E,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1)),
    )
    store = SimpleNamespace(
        address=0x1062,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_BX, 0x44), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1050,
                capstone=SimpleNamespace(
                    insns=(
                        load_source_index,
                        scale_source_index,
                        load_source,
                        load_store_index,
                        scale_store_index,
                        store,
                    )
                ),
            ),
        ),
    )

    evidence = recover_indexed_segmented_global_store_evidence_8616(project, function)

    assert evidence == (IndexedSegmentedGlobalStoreEvidence8616(0x44, 2, -4, 1, 0x1062, 0x44, 2, -6, 1),)


def test_indexed_segmented_global_store_evidence_recovers_stack_source():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    load_source = SimpleNamespace(
        address=0x1050,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _mem_operand(X86_REG_BP, -8)),
    )
    load_store_index = SimpleNamespace(
        address=0x1053,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _mem_operand(X86_REG_BP, -4)),
    )
    scale_store_index = SimpleNamespace(
        address=0x1056,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1)),
    )
    store = SimpleNamespace(
        address=0x105A,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_BX, 0x44), _reg_operand(X86_REG_AX)),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1050,
                capstone=SimpleNamespace(insns=(load_source, load_store_index, scale_store_index, store)),
            ),
        ),
    )

    evidence = recover_indexed_segmented_global_store_evidence_8616(project, function)

    assert evidence == (
        IndexedSegmentedGlobalStoreEvidence8616(
            0x44,
            2,
            -4,
            1,
            0x105A,
            source_stack_offset=-8,
            source_stack_width=2,
        ),
    )


def test_indexed_segmented_global_store_evidence_recovers_signed_remainder_source() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    load_dividend = SimpleNamespace(
        address=0x1050,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_AX), _mem_operand(X86_REG_BP, -4)),
    )
    sign_extend = SimpleNamespace(address=0x1053, id=X86_INS_CWD, operands=())
    divide = SimpleNamespace(
        address=0x1054,
        id=X86_INS_IDIV,
        operands=(_mem_operand(X86_REG_BP, -6),),
    )
    adjust = SimpleNamespace(
        address=0x1057,
        id=X86_INS_INC,
        operands=(_reg_operand(X86_REG_DL, size=1),),
    )
    load_store_index = SimpleNamespace(
        address=0x1059,
        id=X86_INS_MOV,
        operands=(_reg_operand(X86_REG_BX), _mem_operand(X86_REG_BP, -2)),
    )
    scale_store_index = SimpleNamespace(
        address=0x105C,
        id=X86_INS_SHL,
        operands=(_reg_operand(X86_REG_BX), _imm_operand(1)),
    )
    store = SimpleNamespace(
        address=0x1060,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_BX, 0x45, size=1), _reg_operand(X86_REG_DL, size=1)),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1050,
                capstone=SimpleNamespace(
                    insns=(
                        load_dividend,
                        sign_extend,
                        divide,
                        adjust,
                        load_store_index,
                        scale_store_index,
                        store,
                    )
                ),
            ),
        ),
    )

    evidence = recover_indexed_segmented_global_store_evidence_8616(project, function)

    assert evidence == (
        IndexedSegmentedGlobalStoreEvidence8616(
            0x45,
            1,
            -2,
            1,
            0x1060,
            source_signed_remainder=SignedRemainderStackSource8616(-4, -6, 2, 1),
        ),
    )


def test_indexed_word_store_lvalue_materializes_source_index_evidence():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    up_var = _stack(-4, codegen, name="up")
    down_var = _stack(-6, codegen, name="down")
    lhs = _global_indexed("g_work", 0x44, up_var, codegen)
    rhs = _global_indexed("g_work", 0x44, up_var, codegen)
    assignment = CAssignment(lhs, rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={
            up_var.variable: up_var,
            down_var.variable: down_var,
        },
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),),
        store_evidence=(IndexedSegmentedGlobalStoreEvidence8616(0x44, 2, -4, 1, 0x1062, 0x44, 2, -6, 1),),
        stats=stats,
    )

    assert changed is True
    assert assignment.lhs.index is up_var
    assert assignment.rhs.index is down_var
    assert stats.indexed_store_lvalue_materialized_count == 1


def test_indexed_word_store_preserves_exact_sidecar_free_affine_source() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    index_var = _stack(-4, codegen, name="row")
    lhs = _global_indexed("g_0044", 0x44, index_var, codegen)
    rhs = _global_indexed(
        "g_0044",
        0x44,
        CBinaryOp("Sub", index_var, _const(18, codegen), codegen=codegen),
        codegen,
    )
    assignment = CAssignment(lhs, rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={index_var.variable: index_var},
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x44, "g_0044", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0x20, "g_0020", 0, 2),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x1062,
                0x20,
                2,
                -4,
                1,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CIndexedVariable)
    assert isinstance(assignment.rhs.variable, CVariable)
    assert isinstance(assignment.rhs.variable.variable, SimMemoryVariable)
    assert assignment.rhs.variable.variable.addr == 0x20
    assert assignment.rhs.variable.name == "g_0020"
    assert assignment.rhs.index is index_var
    assert stats.indexed_store_affine_source_raw_fact_count == 1
    assert stats.indexed_store_affine_source_classified_count == 1
    assert stats.indexed_store_affine_source_materialized_count == 1
    assert stats.indexed_store_affine_source_failure_count == 0


def test_indexed_word_store_rebases_immediately_adjacent_affine_source() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    index_var = _stack(-4, codegen, name="row")
    assignment = CAssignment(
        _global_indexed("g_0044", 0x44, index_var, codegen),
        _global_indexed("g_0042", 0x42, index_var, codegen),
        codegen=codegen,
    )
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={index_var.variable: index_var},
    )

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x44, "g_0044", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0x42, "g_0042", 0, 2),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x1062,
                0x42,
                2,
                -4,
                1,
            ),
        ),
    )

    assert changed is True
    assert isinstance(assignment.rhs, CIndexedVariable)
    assert assignment.rhs.variable.name == "g_0044"
    assert isinstance(assignment.rhs.index, CBinaryOp)
    assert assignment.rhs.index.op == "Sub"
    assert assignment.rhs.index.lhs is index_var
    assert _constant_int_8616(assignment.rhs.index.rhs) == 1


def test_indexed_word_store_keeps_named_source_identity() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    index_var = _stack(-4, codegen, name="row")
    assignment = CAssignment(
        _global_indexed("destination", 0x44, index_var, codegen),
        _global_indexed("source", 0x42, index_var, codegen),
        codegen=codegen,
    )
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={index_var.variable: index_var},
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x44, "destination", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0x42, "source", 0, 2),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x1062,
                0x42,
                2,
                -4,
                1,
            ),
        ),
        stats=stats,
    )

    assert changed is False
    assert isinstance(assignment.rhs, CIndexedVariable)
    assert assignment.rhs.variable.name == "source"
    assert assignment.rhs.index is index_var
    assert stats.indexed_store_affine_source_raw_fact_count == 1
    assert stats.indexed_store_affine_source_classified_count == 0
    assert stats.indexed_store_affine_source_materialized_count == 0
    assert stats.indexed_store_affine_source_failure_count == 0


def test_indexed_word_store_lvalue_materializes_from_store_index_evidence():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    bad_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v17"), codegen=codegen)
    lhs = _global_indexed(
        "g_work",
        0x44,
        CBinaryOp("Sub", bad_carrier, _const(1, codegen), codegen=codegen),
        codegen,
    )
    rhs = _global_indexed("g_work", 0x44, i_var, codegen)
    assignment = CAssignment(lhs, rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2),),
        store_evidence=(IndexedSegmentedGlobalStoreEvidence8616(0x42, 2, -4, 1, 0x1057),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.lhs.index, CBinaryOp)
    assert assignment.lhs.index.op == "Sub"
    assert assignment.lhs.index.lhs is i_var
    assert stats.indexed_store_lvalue_materialized_count == 1


def test_indexed_word_store_lvalue_joins_multiple_facts_by_instruction_address():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    row_tmp = _stack(-4, codegen, name="row_tmp")
    stale_row_tmp = _stack(-4, codegen, name="local_2")
    bar_temp = _stack(-8, codegen, name="barTemp")
    body_assignment = CAssignment(
        _global_indexed("g_work", 0x44, stale_row_tmp, codegen),
        bar_temp,
        codegen=codegen,
        tags={"ins_addr": 0x106A},
    )
    post_assignment = CAssignment(
        _global_indexed("g_work", 0x44, stale_row_tmp, codegen),
        _global_indexed("g_work", 0x42, row_tmp, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1091},
    )
    body = CStatements([body_assignment], codegen=codegen)
    root = CStatements([body, post_assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={
            row_tmp.variable: row_tmp,
            bar_temp.variable: bar_temp,
        },
        variable_manager=_DummyVariableManager(),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 1, "BAR"),
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2, "BAR"),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2, "BAR"),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x1091,
                source_stack_offset=-8,
                source_stack_width=2,
            ),
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x106A,
                0x42,
                2,
                -4,
                1,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert isinstance(body_assignment.rhs, CIndexedVariable)
    assert body_assignment.rhs.variable.name == "g_work"
    assert isinstance(body_assignment.rhs.index, CBinaryOp)
    assert body_assignment.rhs.index.op == "Sub"
    assert body_assignment.rhs.index.lhs is row_tmp
    assert isinstance(body_assignment.rhs.type, SimStruct)
    assert body_assignment.lhs.index is row_tmp
    assert post_assignment.rhs is bar_temp
    assert post_assignment.lhs.index is row_tmp
    assert stats.indexed_store_lvalue_materialized_count == 2
    assert stats.indexed_refused_shape_mismatch == 0


def test_indexed_word_store_lvalue_refuses_ambiguous_untagged_facts():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    row_tmp = _stack(-4, codegen, name="row_tmp")
    bar_temp = _stack(-8, codegen, name="barTemp")
    original_rhs = _global_indexed("g_work", 0x44, row_tmp, codegen)
    assignment = CAssignment(
        _global_indexed("g_work", 0x44, row_tmp, codegen),
        original_rhs,
        codegen=codegen,
    )
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={
            row_tmp.variable: row_tmp,
            bar_temp.variable: bar_temp,
        },
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x1091,
                source_stack_offset=-8,
                source_stack_width=2,
            ),
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x106A,
                0x42,
                2,
                -4,
                1,
            ),
        ),
        stats=stats,
    )

    assert changed is False
    assert assignment.rhs is original_rhs
    assert stats.indexed_store_lvalue_materialized_count == 0
    assert stats.indexed_refused_shape_mismatch == 1


def test_indexed_memory_helper_load_materializes_array_element():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    ptr = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_i, codegen=codegen)
    rhs = CFunctionCall("MEM_U16", None, [ptr], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),),
        stats=stats,
    )

    assert changed is True
    assert assignment.rhs.variable.name == "g_work"
    assert assignment.rhs.index is i_var
    assert stats.indexed_materialized_count == 1


def test_indexed_global_store_lvalue_materializes_rhs_memory_helper_source():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="iRow")
    dst = CIndexedVariable(
        CVariable(
            SimMemoryVariable(0xB4C, 2, name="abarWork"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        i_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    src_ptr = CBinaryOp("Add", _ref(_mem(0x8F0, codegen), codegen), scaled_i, codegen=codegen)
    src = CFunctionCall("MEM_U16", None, [src_ptr], codegen=codegen)
    assignment = CAssignment(dst, src, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root, variables_in_use={})
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x8F0, "abarPerm", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0xB4C, "abarWork", 0, 2),
        ),
        store_evidence=(IndexedSegmentedGlobalStoreEvidence8616(0xB4C, 2, -2, 1, 0x106B2),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CIndexedVariable)
    assert assignment.rhs.variable.name == "abarPerm"
    assert assignment.rhs.index is i_var
    assert stats.indexed_materialized_count == 1


def test_indexed_global_store_source_carrier_read_is_removed_after_materialization():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="iRow")
    stale_index = CVariable(SimRegisterVariable(0x200, 2, name="local_0"), codegen=codegen)
    stale_scaled = CBinaryOp("Mul", stale_index, _const(2, codegen), codegen=codegen)
    stale_ptr = CBinaryOp("Add", _ref(_mem(0x8F0, codegen), codegen), stale_scaled, codegen=codegen)
    stale_read = CExpressionStatement(
        CFunctionCall("MEM_U16", None, [stale_ptr], codegen=codegen),
        codegen=codegen,
    )
    dst = CIndexedVariable(
        CVariable(
            SimMemoryVariable(0xB4C, 2, name="abarWork"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        i_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    src_ptr = CBinaryOp("Add", _ref(_mem(0x8F0, codegen), codegen), scaled_i, codegen=codegen)
    src = CFunctionCall("MEM_U16", None, [src_ptr], codegen=codegen)
    assignment = CAssignment(dst, src, codegen=codegen)
    root = CStatements([stale_read, assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root, variables_in_use={})
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x8F0, "abarPerm", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0xB4C, "abarWork", 0, 2),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(0xB4C, 2, -2, 1, 0x106B2, 0x8F0, 2, -2, 1),
        ),
        stats=stats,
    )

    assert changed is True
    assert root.statements == [assignment]
    assert isinstance(assignment.rhs, CIndexedVariable)
    assert assignment.rhs.variable.name == "abarPerm"
    assert assignment.rhs.index is i_var
    assert stats.indexed_store_source_carrier_removed_count == 1


def test_indexed_word_store_pair_reruns_lvalue_source_materialization():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    row_var = _stack(-2, codegen, name="iRow")
    source_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v8"), codegen=codegen)
    index_carrier = CVariable(SimRegisterVariable(0x202, 2, name="v9"), codegen=codegen)
    scaled_row = CBinaryOp("Mul", row_var, _const(2, codegen), codegen=codegen)
    source_ptr = CBinaryOp("Add", _ref(_mem(0x8F0, codegen), codegen), scaled_row, codegen=codegen)
    source_load = CFunctionCall("MEM_U16", None, [source_ptr], codegen=codegen)
    copy_source = CAssignment(source_carrier, source_load, codegen=codegen)
    copy_index = CAssignment(index_carrier, scaled_row, codegen=codegen)
    low_ptr = CBinaryOp("Add", _ref(_mem(0xB4C, codegen), codegen), index_carrier, codegen=codegen)
    high_ptr = CBinaryOp("Add", _ref(_mem(0xB4D, codegen), codegen), index_carrier, codegen=codegen)
    low_store = CAssignment(_deref(low_ptr, codegen), source_carrier, codegen=codegen)
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", source_carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy_source, copy_index, low_store, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root, variables_in_use={})
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x8F0, "abarPerm", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0xB4C, "abarWork", 0, 2),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(0xB4C, 2, -2, 1, 0x106B2, 0x8F0, 2, -2, 1),
        ),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 3
    folded = root.statements[-1]
    assert isinstance(folded, CAssignment)
    assert isinstance(folded.lhs, CIndexedVariable)
    assert folded.lhs.variable.name == "abarWork"
    assert folded.lhs.index is row_var
    assert isinstance(folded.rhs, CIndexedVariable)
    assert folded.rhs.variable.name == "abarPerm"
    assert folded.rhs.index is row_var
    assert stats.indexed_store_materialized_count == 1
    assert stats.indexed_store_lvalue_materialized_count == 0

    materialized_rhs = folded.rhs
    folded.lhs.index = CVariable(row_var.variable, variable_type=row_var.variable_type, codegen=codegen)
    rerun_stats = SegmentedGlobalLoadStats8616()
    rerun_changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x8F0, "abarPerm", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0xB4C, "abarWork", 0, 2),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(0xB4C, 2, -2, 1, 0x106B2, 0x8F0, 2, -2, 1),
        ),
        stats=rerun_stats,
    )

    assert rerun_changed is False
    assert folded.rhs is materialized_rhs
    assert rerun_stats.indexed_store_lvalue_materialized_count == 0


def test_indexed_word_store_pairs_preserve_provenance_across_reverse_structured_order():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    row_tmp = _stack(-4, codegen, name="iRowTmp")
    stale_row_tmp = _stack(-4, codegen, name="local_2")
    bar_temp = _stack(-8, codegen, name="barTemp")
    source_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v15"), codegen=codegen)
    scaled_source_index = CBinaryOp("Mul", row_tmp, _const(2, codegen), codegen=codegen)
    source_ptr = CBinaryOp(
        "Add",
        _ref(_mem(0x42, codegen), codegen),
        scaled_source_index,
        codegen=codegen,
    )
    copy_source = CAssignment(
        source_carrier,
        CFunctionCall("MEM_U16", None, [source_ptr], codegen=codegen),
        codegen=codegen,
    )

    def _store_pair(source: object, ins_addr: int) -> tuple[CAssignment, CAssignment]:
        scaled_destination_index = CBinaryOp(
            "Mul",
            stale_row_tmp,
            _const(2, codegen),
            codegen=codegen,
        )
        low_ptr = CBinaryOp(
            "Add",
            _ref(_mem(0x44, codegen), codegen),
            scaled_destination_index,
            codegen=codegen,
        )
        high_ptr = CBinaryOp(
            "Add",
            _ref(_mem(0x45, codegen), codegen),
            scaled_destination_index,
            codegen=codegen,
        )
        return (
            CAssignment(
                _deref(low_ptr, codegen),
                source,
                codegen=codegen,
                tags={"ins_addr": ins_addr},
            ),
            CAssignment(
                _deref(high_ptr, codegen),
                CBinaryOp("Shr", source, _const(8, codegen), codegen=codegen),
                codegen=codegen,
                tags={"ins_addr": ins_addr},
            ),
        )

    post_low, post_high = _store_pair(bar_temp, 0x1091)
    body_low, body_high = _store_pair(source_carrier, 0x106A)
    root = CStatements(
        [copy_source, post_low, post_high, body_low, body_high],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={
            row_tmp.variable: row_tmp,
            bar_temp.variable: bar_temp,
        },
        variable_manager=_DummyVariableManager(),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 1, "BAR"),
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2, "BAR"),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2, "BAR"),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x106A,
                0x42,
                2,
                -4,
                1,
            ),
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x1091,
                source_stack_offset=-8,
                source_stack_width=2,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    folded_by_addr = {
        assignment.tags["ins_addr"]: assignment
        for assignment in root.statements
        if isinstance(assignment, CAssignment) and "ins_addr" in assignment.tags
    }
    post_assignment = folded_by_addr[0x1091]
    body_assignment = folded_by_addr[0x106A]
    assert isinstance(post_assignment.lhs, CIndexedVariable)
    assert post_assignment.lhs.index is row_tmp
    assert post_assignment.rhs is bar_temp
    assert isinstance(body_assignment.lhs, CIndexedVariable)
    assert body_assignment.lhs.index is row_tmp
    assert isinstance(body_assignment.rhs, CIndexedVariable)
    assert isinstance(body_assignment.rhs.type, SimStruct)
    assert body_assignment.rhs.index.lhs is row_tmp
    assert stats.indexed_store_materialized_count == 2
    assert stats.indexed_store_lvalue_materialized_count == 2
    assert stats.indexed_refused_shape_mismatch == 0


def test_indexed_word_store_pair_folds_direct_low_source_with_equivalent_high_carrier():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    row_var = _stack(-2, codegen, name="iRow")
    source_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v15"), codegen=codegen)
    index_carrier = CVariable(SimRegisterVariable(0x202, 2, name="v16"), codegen=codegen)
    scaled_row = CBinaryOp("Mul", row_var, _const(2, codegen), codegen=codegen)
    source_ptr_a = CBinaryOp("Add", _ref(_mem(0x8F0, codegen), codegen), scaled_row, codegen=codegen)
    source_ptr_b = CBinaryOp("Add", _ref(_mem(0x8F0, codegen), codegen), scaled_row, codegen=codegen)
    copy_source = CAssignment(
        source_carrier,
        CFunctionCall("MEM_U16", None, [source_ptr_a], codegen=codegen),
        codegen=codegen,
    )
    copy_index = CAssignment(index_carrier, scaled_row, codegen=codegen)
    low_ptr = CBinaryOp("Add", _ref(_mem(0xB4C, codegen), codegen), index_carrier, codegen=codegen)
    high_ptr = CBinaryOp("Add", _ref(_mem(0xB4D, codegen), codegen), index_carrier, codegen=codegen)
    low_store = CAssignment(
        _deref(low_ptr, codegen),
        CFunctionCall("MEM_U16", None, [source_ptr_b], codegen=codegen),
        codegen=codegen,
    )
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", source_carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy_source, copy_index, low_store, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root, variables_in_use={})
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x8F0, "abarPerm", 0, 2),
            IndexedSegmentedGlobalEvidence8616(0xB4C, "abarWork", 0, 2),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(0xB4C, 2, -2, 1, 0x106B2, 0x8F0, 2, -2, 1),
        ),
        stats=stats,
    )

    assert changed is True
    folded = root.statements[-1]
    assert isinstance(folded, CAssignment)
    assert folded.lhs.variable.name == "abarWork"
    assert folded.lhs.index is row_var
    assert folded.rhs.variable.name == "abarPerm"
    assert folded.rhs.index is row_var
    assert stats.indexed_store_materialized_count == 1


def test_indexed_byte_memory_helper_load_materializes_low_byte_from_word_stride():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    ptr = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_i, codegen=codegen)
    rhs = CFunctionCall("MEM_U8", None, [ptr], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),),
    )

    assert changed is True
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "And"
    assert isinstance(assignment.rhs.lhs, CIndexedVariable)
    assert assignment.rhs.lhs.variable.name == "g_work"
    assert assignment.rhs.lhs.index is i_var
    assert assignment.rhs.rhs.value == 0xFF


def test_indexed_byte_memory_helper_load_materializes_low_byte_from_indexed_global_reference():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    rhs = CFunctionCall("MEM_U8", None, [_ref(_global_indexed("g_work", 0x44, i_var, codegen), codegen)], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 1),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        ),
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_0"
    assert isinstance(assignment.rhs.variable, CIndexedVariable)
    assert assignment.rhs.variable.variable.name == "g_work"
    assert assignment.rhs.variable.index is i_var


def test_indexed_byte_memory_helper_load_uses_typed_indexed_global_reference_without_word_evidence():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    indexed = _global_indexed("g_work", 0x44, i_var, codegen)
    rhs = CFunctionCall("MEM_U8", None, [_ref(indexed, codegen)], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 1),),
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_0"
    assert isinstance(assignment.rhs.variable, CIndexedVariable)
    assert assignment.rhs.variable.variable.name == "g_work"
    assert assignment.rhs.variable.index is i_var


def test_indexed_byte_segment_load_uses_adjacent_stride_evidence_for_field():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)
    rhs = CFunctionCall(
        "SEG_U8",
        None,
        [_ds(project, codegen), CBinaryOp("Add", _const(0x44, codegen), scaled_i, codegen=codegen)],
        codegen=codegen,
    )
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(
                0x44, "g_work", 0, 1, aggregate_type_name="g_family"
            ),
            IndexedSegmentedGlobalEvidence8616(0x46, "g_work", 0, 2),
        ),
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_0"
    assert isinstance(assignment.rhs.variable, CIndexedVariable)
    assert assignment.rhs.variable.type.name == "g_family_entry"
    assert assignment.rhs.variable.variable.name == "g_work"
    assert assignment.rhs.variable.index is i_var


def test_indexed_byte_memory_helper_load_materializes_high_byte_from_word_stride():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), scaled_i, codegen=codegen)
    rhs = CFunctionCall("MEM_U8", None, [ptr], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 1),
            IndexedSegmentedGlobalEvidence8616(0x45, "g_work", 1, 1),
        ),
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_1"
    assert isinstance(assignment.rhs.variable, CIndexedVariable)
    assert assignment.rhs.variable.variable.name == "g_work"
    assert assignment.rhs.variable.index is i_var


def test_indexed_byte_store_lvalue_materializes_high_byte_from_word_stride_with_index_copy():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    index_carrier = CVariable(SimRegisterVariable(0x202, 2, name="v61"), codegen=codegen)
    scaled_i = CBinaryOp("Shl", index_carrier, _const(1, codegen), codegen=codegen)
    copy_index = CAssignment(index_carrier, i_var, codegen=codegen)
    ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), scaled_i, codegen=codegen)
    assignment = CAssignment(_deref(ptr, codegen), _const(7, codegen), codegen=codegen)
    root = CStatements([copy_index, assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 1),
            IndexedSegmentedGlobalEvidence8616(0x45, "g_work", 1, 1),
        ),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.lhs, CFunctionCall)
    assert assignment.lhs.callee_target == "MEM_U8"
    address = assignment.lhs.args[0]
    assert isinstance(address, CBinaryOp)
    assert address.op == "Add"
    assert address.rhs.value == 1
    assert isinstance(address.lhs, CUnaryOp)
    assert isinstance(address.lhs.operand, CIndexedVariable)
    assert address.lhs.operand.variable.name == "g_work"
    index_var = address.lhs.operand.index.variable
    assert isinstance(index_var, SimStackVariable)
    assert index_var.offset == -4
    assert stats.indexed_byte_store_lvalue_materialized_count == 1


def test_indexed_byte_store_lvalue_does_not_resolve_mutable_stack_index_as_copy():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    prior_value = _mem(0x120, codegen, name="prior_value")
    assign_index = CAssignment(i_var, prior_value, codegen=codegen)
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    ptr = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_i, codegen=codegen)
    assignment = CAssignment(_deref(ptr, codegen), _const(7, codegen), codegen=codegen)
    root = CStatements([assign_index, assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 1),
            IndexedSegmentedGlobalEvidence8616(0x45, "g_work", 1, 1),
        ),
    )

    assert changed is True
    assert isinstance(assignment.lhs, CFunctionCall)
    address = assignment.lhs.args[0]
    assert isinstance(address, CUnaryOp)
    assert isinstance(address.operand, CIndexedVariable)
    assert address.operand.index is i_var


def test_indexed_byte_store_lvalue_prefers_unique_decoded_stack_index():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    evidenced_index = _stack(-2, codegen, name="i")
    wrong_raw_index = _stack(0, codegen, name="wrong_index")
    initialize_index = CAssignment(evidenced_index, _const(0, codegen), codegen=codegen)
    scaled_wrong_index = CBinaryOp("Mul", wrong_raw_index, _const(2, codegen), codegen=codegen)
    ptr = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_wrong_index, codegen=codegen)
    assignment = CAssignment(_deref(ptr, codegen), _const(7, codegen), codegen=codegen)
    root = CStatements([initialize_index, assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 1),
            IndexedSegmentedGlobalEvidence8616(0x45, "g_work", 1, 1),
        ),
        store_evidence=(IndexedSegmentedGlobalStoreEvidence8616(0x44, 1, -2, 1, 0x4010),),
    )

    assert changed is True
    assert isinstance(assignment.lhs, CFunctionCall)
    address = assignment.lhs.args[0]
    assert isinstance(address, CUnaryOp)
    assert isinstance(address.operand, CIndexedVariable)
    assert address.operand.index is evidenced_index


def test_indexed_byte_store_materializes_exact_stack_source() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    evidenced_index = _stack(-2, codegen, name="i")
    source = _stack(-4, codegen, name="iLength")
    scaled_index = CBinaryOp("Mul", evidenced_index, _const(2, codegen), codegen=codegen)
    ptr = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_index, codegen=codegen)
    assignment = CAssignment(
        _deref(ptr, codegen),
        _const(0xA5, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={
            evidenced_index.variable: evidenced_index,
            source.variable: source,
        },
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                1,
                -2,
                1,
                0x4020,
                source_stack_offset=-4,
                source_stack_width=1,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert assignment.rhs is source
    assert stats.indexed_byte_store_lvalue_materialized_count == 1
    assert stats.indexed_byte_store_source_materialized_count == 1


def test_instruction_backed_mk_fp_byte_stores_materialize_exact_lvalues_and_sources() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    index = _stack(-2, codegen, name="iRow")
    source = _stack(-114, codegen, name="iLength")
    divisor = _stack(-116, codegen, name="iColorMax")

    def _raw_store(ins_addr: int, rhs: object) -> CAssignment:
        pointer = CBinaryOp(
            "Add",
            CFunctionCall(
                "MK_FP",
                None,
                [_dirty(ins_addr, codegen), _const(0, codegen)],
                codegen=codegen,
            ),
            _dirty(ins_addr + 1, codegen),
            codegen=codegen,
        )
        return CAssignment(
            _deref(pointer, codegen),
            rhs,
            codegen=codegen,
            tags={"ins_addr": ins_addr},
        )

    low_store = _raw_store(0x1063A, _dirty(90, codegen))
    constant_high_store = _raw_store(0x1064C, _const(7, codegen))
    remainder_high_store = _raw_store(0x10662, _dirty(91, codegen))
    root = CStatements(
        [low_store, constant_high_store, remainder_high_store],
        addr=0x10560,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x10560,
        statements=root,
        body=root,
        variables_in_use={
            index.variable: index,
            source.variable: source,
            divisor.variable: divisor,
        },
    )
    evidence = (
        IndexedSegmentedGlobalEvidence8616(0x8F0, "g_08F0", 0, 1),
        IndexedSegmentedGlobalEvidence8616(0x8F1, "g_08F1", 0, 1),
    )
    store_evidence = (
        IndexedSegmentedGlobalStoreEvidence8616(
            0x8F0,
            1,
            -2,
            1,
            0x1063A,
            source_stack_offset=-114,
            source_stack_width=1,
        ),
        IndexedSegmentedGlobalStoreEvidence8616(0x8F1, 1, -2, 1, 0x1064C),
        IndexedSegmentedGlobalStoreEvidence8616(
            0x8F1,
            1,
            -2,
            1,
            0x10662,
            source_signed_remainder=SignedRemainderStackSource8616(
                -114,
                -116,
                2,
                1,
            ),
        ),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        evidence,
        store_evidence=store_evidence,
        stats=stats,
    )

    assert changed is True
    assert isinstance(low_store.lhs, CVariableField)
    assert low_store.lhs.field.field == "field_0"
    assert isinstance(low_store.lhs.variable, CIndexedVariable)
    assert low_store.lhs.variable.variable.name == "g_08F0"
    assert low_store.lhs.variable.index is index
    assert low_store.rhs is source
    assert isinstance(constant_high_store.lhs, CVariableField)
    assert constant_high_store.lhs.field.field == "field_0"
    assert isinstance(constant_high_store.lhs.variable, CIndexedVariable)
    assert constant_high_store.lhs.variable.variable.name == "g_08F1"
    assert constant_high_store.lhs.variable.index is index
    assert isinstance(constant_high_store.rhs, CConstant)
    assert constant_high_store.rhs.value == 7
    assert isinstance(remainder_high_store.lhs, CVariableField)
    assert isinstance(remainder_high_store.lhs.variable, CIndexedVariable)
    assert remainder_high_store.lhs.variable.variable.name == "g_08F1"
    assert remainder_high_store.lhs.variable.index is index
    assert isinstance(remainder_high_store.rhs, CBinaryOp)
    assert remainder_high_store.rhs.op == "Add"
    assert isinstance(remainder_high_store.rhs.lhs, CBinaryOp)
    assert remainder_high_store.rhs.lhs.op == "Mod"
    assert isinstance(remainder_high_store.rhs.lhs.lhs, CTypeCast)
    assert remainder_high_store.rhs.lhs.lhs.expr is source
    assert isinstance(remainder_high_store.rhs.lhs.rhs, CTypeCast)
    assert remainder_high_store.rhs.lhs.rhs.expr is divisor
    assert stats.indexed_store_instruction_classified_count == 3
    assert stats.indexed_store_instruction_materialized_count == 3
    assert stats.indexed_store_instruction_failure_count == 0

    rerun_stats = SegmentedGlobalLoadStats8616()
    rerun_changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        evidence,
        store_evidence=store_evidence,
        stats=rerun_stats,
    )

    assert rerun_changed is False
    assert rerun_stats.indexed_store_instruction_classified_count == 3
    assert rerun_stats.indexed_store_instruction_materialized_count == 3
    assert rerun_stats.indexed_store_instruction_failure_count == 0


def test_instruction_backed_mk_fp_store_refuses_ambiguous_statement_join() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    index = _stack(-2, codegen, name="iRow")
    pointer = CBinaryOp(
        "Add",
        CFunctionCall(
            "MK_FP",
            None,
            [_dirty(1, codegen), _const(0, codegen)],
            codegen=codegen,
        ),
        _dirty(2, codegen),
        codegen=codegen,
    )
    first_store = CAssignment(
        _deref(pointer, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1064C},
    )
    second_store = CAssignment(
        _deref(pointer, codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1064C},
    )
    root = CStatements([first_store, second_store], addr=0x10560, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x10560,
        statements=root,
        body=root,
        variables_in_use={index.variable: index},
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x8F1, "g_08F1", 0, 1),),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(
                0x8F1,
                1,
                -2,
                1,
                0x1064C,
            ),
        ),
        stats=stats,
    )

    assert changed is False
    assert isinstance(first_store.lhs, CUnaryOp)
    assert isinstance(second_store.lhs, CUnaryOp)
    assert stats.indexed_store_instruction_classified_count == 0
    assert stats.indexed_store_instruction_materialized_count == 0
    assert stats.indexed_store_instruction_failure_count == 1


def test_instruction_backed_mk_fp_store_fails_closed_for_missing_proven_source() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    index = _stack(-2, codegen, name="iRow")
    pointer = CBinaryOp(
        "Add",
        CFunctionCall(
            "MK_FP",
            None,
            [_dirty(1, codegen), _const(0, codegen)],
            codegen=codegen,
        ),
        _dirty(2, codegen),
        codegen=codegen,
    )
    store = CAssignment(
        _deref(pointer, codegen),
        _dirty(3, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1063A},
    )
    root = CStatements([store], addr=0x10560, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x10560,
        statements=root,
        body=root,
        variables_in_use={index.variable: index},
    )
    stats = SegmentedGlobalLoadStats8616()

    with pytest.raises(
        PipelineHardError,
        match="classified instruction-backed indexed-global stores",
    ):
        materialize_indexed_segmented_global_loads_from_evidence_8616(
            project,
            codegen,
            (IndexedSegmentedGlobalEvidence8616(0x8F0, "g_08F0", 0, 1),),
            store_evidence=(
                IndexedSegmentedGlobalStoreEvidence8616(
                    0x8F0,
                    1,
                    -2,
                    1,
                    0x1063A,
                    source_stack_offset=-114,
                    source_stack_width=1,
                ),
            ),
            stats=stats,
        )

    assert isinstance(store.lhs, CUnaryOp)
    assert stats.indexed_store_instruction_classified_count == 1
    assert stats.indexed_store_instruction_materialized_count == 0
    assert stats.indexed_store_instruction_failure_count == 1


def test_indexed_byte_store_materializes_signed_remainder_source() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    evidenced_index = _stack(-2, codegen, name="i")
    dividend = _stack(-4, codegen, name="iLength")
    divisor = _stack(-6, codegen, name="iColorMax")
    scaled_index = CBinaryOp("Mul", evidenced_index, _const(2, codegen), codegen=codegen)
    ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), scaled_index, codegen=codegen)
    assignment = CAssignment(
        _deref(ptr, codegen),
        _const(0xA5, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={
            evidenced_index.variable: evidenced_index,
            dividend.variable: dividend,
            divisor.variable: divisor,
        },
    )
    stats = SegmentedGlobalLoadStats8616()

    evidence = (
        IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        IndexedSegmentedGlobalEvidence8616(0x45, "g_work", 1, 1),
    )
    store_evidence = (
        IndexedSegmentedGlobalStoreEvidence8616(
            0x45,
            1,
            -2,
            1,
            0x4020,
            source_signed_remainder=SignedRemainderStackSource8616(-4, -6, 2, 1),
        ),
    )
    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        evidence,
        store_evidence=store_evidence,
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert isinstance(assignment.rhs.lhs, CBinaryOp)
    assert assignment.rhs.lhs.op == "Mod"
    assert isinstance(assignment.rhs.lhs.lhs, CSemanticCast8616)
    assert assignment.rhs.lhs.lhs.expr is dividend
    assert isinstance(assignment.rhs.lhs.rhs, CSemanticCast8616)
    assert assignment.rhs.lhs.rhs.expr is divisor
    assert isinstance(assignment.rhs.rhs, CConstant)
    assert assignment.rhs.rhs.value == 1
    assert stats.indexed_byte_store_source_materialized_count == 1
    materialized_rhs = assignment.rhs
    rerun_stats = SegmentedGlobalLoadStats8616()
    materialize_indexed_segmented_global_loads_from_evidence_8616(
        project, codegen, evidence, store_evidence=store_evidence, stats=rerun_stats
    )
    assert assignment.rhs is materialized_rhs
    assert rerun_stats.indexed_byte_store_source_materialized_count == 0


def test_indexed_byte_pair_store_materializes_word_array_assignment():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    tmp_var = _stack(-2, codegen, name="tmp")
    carrier_value = CVariable(SimRegisterVariable(0x200, 2, name="v17"), codegen=codegen)
    carrier_index = CVariable(SimRegisterVariable(0x202, 2, name="v18"), codegen=codegen)
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    copy_value = CAssignment(carrier_value, tmp_var, codegen=codegen)
    copy_index = CAssignment(carrier_index, scaled_i, codegen=codegen)
    low_ptr = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), carrier_index, codegen=codegen)
    high_ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), carrier_index, codegen=codegen)
    low_store = CAssignment(_deref(low_ptr, codegen), tmp_var, codegen=codegen)
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", carrier_value, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy_value, copy_index, low_store, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 3
    folded = root.statements[-1]
    assert isinstance(folded, CAssignment)
    assert folded.lhs.variable.name == "g_work"
    assert folded.lhs.index is i_var
    assert folded.rhs is tmp_var
    assert stats.indexed_store_materialized_count == 1


def test_indexed_byte_pair_store_matches_memory_helper_low_lvalue():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    tmp_var = _stack(-2, codegen, name="tmp")
    carrier_value = CVariable(SimRegisterVariable(0x200, 2, name="v17"), codegen=codegen)
    carrier_index = CVariable(SimRegisterVariable(0x202, 2, name="v18"), codegen=codegen)
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    copy_value = CAssignment(carrier_value, tmp_var, codegen=codegen)
    copy_index = CAssignment(carrier_index, scaled_i, codegen=codegen)
    low_indexed = _global_indexed("g_work", 0x44, i_var, codegen)
    low_store = CAssignment(
        CFunctionCall("MEM_U8", None, [_ref(low_indexed, codegen)], codegen=codegen),
        tmp_var,
        codegen=codegen,
    )
    high_ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), carrier_index, codegen=codegen)
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", carrier_value, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy_value, copy_index, low_store, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 3
    folded = root.statements[-1]
    assert isinstance(folded, CAssignment)
    assert folded.lhs.variable.name == "g_work"
    assert folded.lhs.index is i_var
    assert folded.rhs is tmp_var
    assert stats.indexed_store_materialized_count == 1


def test_indexed_byte_pair_store_uses_store_evidence_for_clobbered_global_source():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    row_var = _stack(-2, codegen, name="row")
    row_tmp = _stack(-4, codegen, name="row_tmp")
    source_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v14"), codegen=codegen)
    index_carrier = CVariable(SimRegisterVariable(0x202, 2, name="v15"), codegen=codegen)
    scaled_row = CBinaryOp("Mul", row_var, _const(2, codegen), codegen=codegen)
    copy_index = CAssignment(index_carrier, scaled_row, codegen=codegen)
    low_indexed = _global_indexed("g_work", 0x44, row_var, codegen)
    low_source = _global_indexed(
        "g_work",
        0x44,
        CBinaryOp("Sub", row_var, _const(1, codegen), codegen=codegen),
        codegen,
    )
    low_store = CAssignment(
        CFunctionCall("MEM_U8", None, [_ref(low_indexed, codegen)], codegen=codegen),
        low_source,
        codegen=codegen,
    )
    clobber_source = CAssignment(source_carrier, _const(0, codegen), codegen=codegen)
    high_ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), index_carrier, codegen=codegen)
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", source_carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy_index, low_store, clobber_source, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={
            row_var.variable: row_var,
            row_tmp.variable: row_tmp,
        },
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        ),
        store_evidence=(IndexedSegmentedGlobalStoreEvidence8616(0x44, 2, -4, 1, 0x106A, 0x42, 2, -4, 1),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 3
    folded = root.statements[1]
    assert isinstance(folded, CAssignment)
    assert folded.lhs.variable.name == "g_work"
    assert folded.lhs.index is row_tmp
    assert folded.rhs.variable.name == "g_work"
    assert isinstance(folded.rhs.index, CBinaryOp)
    assert folded.rhs.index.op == "Sub"
    assert folded.rhs.index.lhs is row_tmp
    assert root.statements[2] is clobber_source
    assert stats.indexed_store_materialized_count == 1


def test_indexed_byte_pair_store_uses_store_evidence_for_stack_source():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    row_var = _stack(-2, codegen, name="row")
    row_tmp = _stack(-4, codegen, name="row_tmp")
    bar_temp = _stack(-8, codegen, name="barTemp")
    low_artifact = CVariable(
        SimStackVariable(6, 1, base="bp", name="arg_6"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    source_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v18"), codegen=codegen)
    index_carrier = CVariable(SimRegisterVariable(0x202, 2, name="v19"), codegen=codegen)
    scaled_row = CBinaryOp("Mul", row_var, _const(2, codegen), codegen=codegen)
    copy_source = CAssignment(source_carrier, bar_temp, codegen=codegen)
    copy_index = CAssignment(index_carrier, scaled_row, codegen=codegen)
    low_indexed = _global_indexed("g_work", 0x44, row_var, codegen)
    low_store = CAssignment(
        CFunctionCall("MEM_U8", None, [_ref(low_indexed, codegen)], codegen=codegen),
        low_artifact,
        codegen=codegen,
    )
    high_ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), index_carrier, codegen=codegen)
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", source_carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy_source, copy_index, low_store, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={
            row_var.variable: row_var,
            row_tmp.variable: row_tmp,
            bar_temp.variable: bar_temp,
        },
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(
                0x44,
                2,
                -4,
                1,
                0x1091,
                source_stack_offset=-8,
                source_stack_width=2,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 3
    folded = root.statements[-1]
    assert isinstance(folded, CAssignment)
    assert folded.lhs.variable.name == "g_work"
    assert folded.lhs.index is row_tmp
    assert folded.rhs is bar_temp
    assert stats.indexed_store_materialized_count == 1


def test_indexed_byte_pair_store_folds_across_independent_assignment():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    tmp_var = _stack(-2, codegen, name="tmp")
    changed_var = _stack(-6, codegen, name="changed")
    carrier_value = CVariable(SimRegisterVariable(0x200, 2, name="v19"), codegen=codegen)
    carrier_index = CVariable(SimRegisterVariable(0x202, 2, name="v21"), codegen=codegen)
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    copy_value = CAssignment(carrier_value, tmp_var, codegen=codegen)
    copy_index = CAssignment(carrier_index, scaled_i, codegen=codegen)
    low_ptr = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), carrier_index, codegen=codegen)
    high_ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), carrier_index, codegen=codegen)
    low_store = CAssignment(_deref(low_ptr, codegen), tmp_var, codegen=codegen)
    changed = CAssignment(changed_var, _const(1, codegen), codegen=codegen)
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", carrier_value, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy_value, copy_index, low_store, changed, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    folded = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),),
        stats=stats,
    )

    assert folded is True
    assert len(root.statements) == 4
    assert root.statements[-2].lhs.variable.name == "g_work"
    assert root.statements[-2].rhs is tmp_var
    assert root.statements[-1] is changed
    assert stats.indexed_store_materialized_count == 1


def test_indexed_byte_pair_store_matches_materialized_global_source():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    source_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v14"), codegen=codegen)
    index_carrier = CVariable(SimRegisterVariable(0x202, 2, name="v15"), codegen=codegen)
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    source_ptr_for_copy = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_i, codegen=codegen)
    source_ptr_for_store = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_i, codegen=codegen)
    source_read_for_copy = CFunctionCall("MEM_U16", None, [source_ptr_for_copy], codegen=codegen)
    source_read_for_store = CFunctionCall("MEM_U16", None, [source_ptr_for_store], codegen=codegen)
    copy_source = CAssignment(source_carrier, source_read_for_copy, codegen=codegen)
    copy_index = CAssignment(index_carrier, scaled_i, codegen=codegen)
    low_ptr = CBinaryOp("Add", _ref(_mem(0x42, codegen), codegen), index_carrier, codegen=codegen)
    high_ptr = CBinaryOp("Add", _ref(_mem(0x43, codegen), codegen), index_carrier, codegen=codegen)
    low_store = CAssignment(_deref(low_ptr, codegen), source_read_for_store, codegen=codegen)
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", source_carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy_source, copy_index, low_store, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        ),
        stats=stats,
    )

    assert changed is True
    folded = root.statements[-1]
    assert isinstance(folded, CAssignment)
    assert folded.lhs.variable.name == "g_work"
    assert isinstance(folded.lhs.index, CBinaryOp)
    assert folded.lhs.index.op == "Sub"
    assert folded.rhs.variable.name == "g_work"
    assert folded.rhs.index is i_var
    assert stats.indexed_store_materialized_count == 1


def test_indexed_byte_pair_store_uses_high_byte_source_when_low_is_frame_artifact():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    down_var = _stack(-6, codegen, name="down")
    pivot_var = _stack(-2, codegen, name="pivot")
    low_artifact = CVariable(
        SimStackVariable(0, 2, base="bp", name="frame_base"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v30"), codegen=codegen)
    index_carrier = CVariable(SimRegisterVariable(0x202, 2, name="v32"), codegen=codegen)
    scaled_down = CBinaryOp("Shl", down_var, _const(1, codegen), codegen=codegen)
    copy_source = CAssignment(source_carrier, pivot_var, codegen=codegen)
    copy_index = CAssignment(index_carrier, scaled_down, codegen=codegen)
    low_ptr = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), index_carrier, codegen=codegen)
    high_ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), index_carrier, codegen=codegen)
    low_store = CAssignment(_deref(low_ptr, codegen), low_artifact, codegen=codegen)
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", source_carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy_source, copy_index, low_store, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),),
        stats=stats,
    )

    assert changed is True
    folded = root.statements[-1]
    assert isinstance(folded, CAssignment)
    assert folded.lhs.variable.name == "g_work"
    assert folded.lhs.index is down_var
    assert folded.rhs is pivot_var
    assert stats.indexed_store_materialized_count == 1


def test_indexed_byte_pair_store_materializes_two_swap_pairs():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    tmp_var = CVariable(
        SimStackVariable(-2, 1, base="bp", name="tmp"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    source_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v14"), codegen=codegen)
    first_index_carrier = CVariable(SimRegisterVariable(0x202, 2, name="v15"), codegen=codegen)
    tmp_carrier = CVariable(SimRegisterVariable(0x204, 2, name="v16"), codegen=codegen)
    second_index_carrier = CVariable(SimRegisterVariable(0x206, 2, name="v17"), codegen=codegen)
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    source_ptr_for_copy = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_i, codegen=codegen)
    source_ptr_for_store = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_i, codegen=codegen)
    copy_source = CAssignment(
        source_carrier, CFunctionCall("MEM_U16", None, [source_ptr_for_copy], codegen=codegen), codegen=codegen
    )
    copy_first_index = CAssignment(first_index_carrier, scaled_i, codegen=codegen)
    first_low_ptr = CBinaryOp("Add", _ref(_mem(0x42, codegen), codegen), first_index_carrier, codegen=codegen)
    first_high_ptr = CBinaryOp("Add", _ref(_mem(0x43, codegen), codegen), first_index_carrier, codegen=codegen)
    first_low = CAssignment(
        _deref(first_low_ptr, codegen),
        CFunctionCall("MEM_U16", None, [source_ptr_for_store], codegen=codegen),
        codegen=codegen,
    )
    first_high = CAssignment(
        _deref(first_high_ptr, codegen),
        CBinaryOp("Shr", source_carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    copy_tmp = CAssignment(tmp_carrier, tmp_var, codegen=codegen)
    copy_second_index = CAssignment(second_index_carrier, scaled_i, codegen=codegen)
    second_low_ptr = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), second_index_carrier, codegen=codegen)
    second_high_ptr = CBinaryOp("Add", _ref(_mem(0x45, codegen), codegen), second_index_carrier, codegen=codegen)
    second_low = CAssignment(_deref(second_low_ptr, codegen), tmp_var, codegen=codegen)
    second_high = CAssignment(
        _deref(second_high_ptr, codegen),
        CBinaryOp("Shr", tmp_carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements(
        [copy_source, copy_first_index, first_low, first_high, copy_tmp, copy_second_index, second_low, second_high],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        ),
        stats=stats,
    )

    assert changed is True
    folded = [stmt for stmt in root.statements if isinstance(stmt, CAssignment) and hasattr(stmt.lhs, "index")]
    assert len(folded) == 2
    assert folded[0].lhs.index.op == "Sub"
    assert folded[0].rhs.variable.name == "g_work"
    assert folded[0].rhs.index is i_var
    assert folded[1].lhs.index is i_var
    assert folded[1].rhs is tmp_var
    assert tmp_var.variable.size == 2
    assert isinstance(tmp_var.variable_type, SimTypeShort)
    assert stats.indexed_store_materialized_count == 2

    late_stats = SegmentedGlobalLoadStats8616()
    changed_late = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        ),
        store_evidence=(
            IndexedSegmentedGlobalStoreEvidence8616(0x44, 2, -4, 1, 0x110C),
            IndexedSegmentedGlobalStoreEvidence8616(0x42, 2, -4, 1, 0x1100),
        ),
        stats=late_stats,
    )

    assert changed_late is False
    assert folded[0].lhs.index.op == "Sub"
    assert folded[0].rhs.variable.name == "g_work"
    assert folded[0].rhs.index is i_var
    assert folded[1].lhs.index is i_var
    assert folded[1].rhs is tmp_var
    assert late_stats.indexed_store_lvalue_materialized_count == 0


def test_indexed_byte_pair_store_syncs_duplicate_cfunc_roots():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    source_carrier = CVariable(SimRegisterVariable(0x200, 2, name="v14"), codegen=codegen)
    index_carrier = CVariable(SimRegisterVariable(0x202, 2, name="v15"), codegen=codegen)
    scaled_i = CBinaryOp("Mul", i_var, _const(2, codegen), codegen=codegen)
    source_ptr_for_copy = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_i, codegen=codegen)
    source_ptr_for_store = CBinaryOp("Add", _ref(_mem(0x44, codegen), codegen), scaled_i, codegen=codegen)
    copy_source = CAssignment(
        source_carrier, CFunctionCall("MEM_U16", None, [source_ptr_for_copy], codegen=codegen), codegen=codegen
    )
    copy_index = CAssignment(index_carrier, scaled_i, codegen=codegen)
    low_ptr = CBinaryOp("Add", _ref(_mem(0x42, codegen), codegen), index_carrier, codegen=codegen)
    high_ptr = CBinaryOp("Add", _ref(_mem(0x43, codegen), codegen), index_carrier, codegen=codegen)
    low_store = CAssignment(
        _deref(low_ptr, codegen),
        CFunctionCall("MEM_U16", None, [source_ptr_for_store], codegen=codegen),
        codegen=codegen,
    )
    high_store = CAssignment(
        _deref(high_ptr, codegen),
        CBinaryOp("Shr", source_carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    body_root = CStatements([copy_source, copy_index, low_store, high_store], addr=0x4010, codegen=codegen)
    stale_root = CStatements([copy_source, copy_index, low_store, high_store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=body_root, statements=stale_root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0x42, "g_work", -2, 2),
            IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        ),
        stats=stats,
    )

    assert changed is True
    assert codegen.cfunc.body is body_root
    assert codegen.cfunc.statements is body_root
    folded = body_root.statements[-1]
    assert isinstance(folded, CAssignment)
    assert folded.lhs.variable.name == "g_work"
    assert isinstance(folded.lhs.index, CBinaryOp)
    assert folded.lhs.index.op == "Sub"
    assert folded.rhs.variable.name == "g_work"
    assert folded.rhs.index is i_var


def test_cod_indexed_global_refs_ignore_listing_text():
    metadata = SimpleNamespace(
        cod_raw_entries=(
            {"text": "mov\tax,WORD PTR _g_work[si]"},
            {"text": "cmp\tWORD PTR _g_work[bx-2],ax"},
        )
    )

    refs = _cod_indexed_global_refs_8616(metadata)

    assert refs == ()


def test_cod_indexed_global_refs_use_structured_global_refs():
    metadata = SimpleNamespace(
        global_refs=(
            CODGlobalRef(
                offset=0xA0B,
                name="abarWork",
                relative_disp=0,
                width=1,
                indexed=True,
                instruction_bytes=bytes.fromhex("8a840000"),
            ),
            CODGlobalRef(
                offset=0xA0F,
                name="abarWork",
                relative_disp=0,
                width=1,
                indexed=True,
                instruction_bytes=bytes.fromhex("38870000"),
            ),
            CODGlobalRef(
                offset=0xA12,
                name="iCompares",
                relative_disp=0,
                width=2,
                indexed=False,
                instruction_bytes=bytes.fromhex("ff060000"),
            ),
        ),
        cod_raw_entries=({"text": "mov\tax,WORD PTR _ignored[si]"},),
    )

    refs = _cod_indexed_global_refs_8616(metadata)

    assert refs == (("abarWork", 0, 1), ("abarWork", 0, 1))


def test_cod_direct_global_refs_ignore_listing_text():
    metadata = SimpleNamespace(
        cod_raw_entries=(
            {"text": "mov\tax,WORD PTR _g_rows"},
            {"text": "mov\tax,WORD PTR _g_work[si]"},
            {"text": "cmp\tWORD PTR _g_work[bx-2],ax"},
            {"text": "add\tax,WORD PTR _g_work+10"},
        )
    )

    refs = _cod_direct_global_refs_8616(metadata)

    assert refs == ()


def test_cod_direct_global_refs_use_structured_static_global_refs():
    metadata = SimpleNamespace(
        global_refs=(
            CODGlobalRef(
                offset=11,
                name="_S104_seen",
                relative_disp=0,
                width=2,
                indexed=False,
                instruction_bytes=bytes.fromhex("8306060002"),
            ),
            CODGlobalRef(
                offset=16,
                name="_S104_seen",
                relative_disp=0,
                width=2,
                indexed=False,
                instruction_bytes=bytes.fromhex("a10600"),
            ),
        ),
        cod_raw_entries=({"text": "add\tWORD PTR $S104_seen,2"},),
    )

    refs = _cod_direct_global_refs_8616(metadata)

    assert refs == (("_S104_seen", 0, 2), ("_S104_seen", 0, 2))


def test_direct_global_cvariable_materializes_array_element_from_symbol_ref():
    class _Memory:
        def load(self, addr, size):
            assert addr == 0x4010
            # add ax, word ptr [0x004e]; add ax, word ptr [0x0044]
            return b"\x03\x06\x4e\x00\x03\x06\x44\x00"[:size]

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(labels={}),
        loader=SimpleNamespace(memory=_Memory()),
    )
    codegen = _DummyCodegen()
    left = CVariable(
        SimMemoryVariable(0x4E, 2, name="g_004E"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    right = CVariable(
        SimMemoryVariable(0x44, 2, name="g_0044"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expr = CBinaryOp("Add", left, right, codegen=codegen)
    root = CStatements([expr], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, size=8, statements=root, body=root)

    changed = materialize_named_segmented_global_loads_8616(project, codegen, {0x44: ("g_work", 12)})

    assert changed is True
    assert isinstance(expr.lhs, CIndexedVariable)
    assert expr.lhs.variable.name == "g_work"
    assert expr.lhs.index.value == 5
    assert isinstance(expr.rhs, CIndexedVariable)
    assert expr.rhs.index.value == 0


@pytest.mark.parametrize(
    ("physical_source", "verdict", "should_lower"),
    (
        ("ds", SegmentFactVerdict.PROVEN, True),
        ("es", SegmentFactVerdict.PROVEN, False),
        (None, SegmentFactVerdict.UNKNOWN_REFUSE, False),
    ),
)
def test_direct_global_cvariable_requires_entry_ds_physical_source(
    physical_source,
    verdict,
    should_lower,
):
    class _Memory:
        def load(self, addr, size):
            assert addr == 0x4010
            return b"\x03\x06\x4e\x00"[:size]

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(labels={}),
        loader=SimpleNamespace(memory=_Memory()),
    )
    codegen = _DummyCodegen()
    direct = CVariable(
        SimMemoryVariable(0x4E, 2, name="g_004E"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    expr = CBinaryOp("Add", direct, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen)
    root = CStatements([expr], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, size=4, statements=root, body=root)
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x4010,
        accesses=(
            SegmentAccessFact(
                block_addr=0x4010,
                instruction_addr=0x4010,
                kind=SegmentAccessKind.READ,
                address=IRAddress(
                    space=MemSpace.DS,
                    offset=0x4E,
                    size=2,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
                segment_register="ds",
                physical_source=physical_source,
                verdict=verdict,
            ),
        ),
    )

    changed = materialize_named_segmented_global_loads_8616(project, codegen, {0x44: ("g_work", 12)})

    assert changed is should_lower
    assert isinstance(expr.lhs, CIndexedVariable) is should_lower
    if not should_lower:
        assert expr.lhs is direct
    assert codegen._inertia_segment_access_lowering_stats_8616.failure_count == int(
        verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    )


def test_global_declaration_specs_merge_duplicate_array_extents():
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010)
    direct_ref = DirectGlobalSymbolRef8616(0x4E, "g_work", 10, 2, 10)

    _make_direct_global_symbol_expr_8616(codegen, direct_ref, 2)
    _make_indexed_global_expr_8616(
        codegen,
        IndexedSegmentedGlobalEvidence8616(0x44, "g_work", 0, 2),
        _stack(-4, codegen, name="i"),
    )

    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned short", "g_work", 6),)


def test_registered_named_aggregate_replaces_its_inline_declaration():
    codegen = _DummyCodegen()
    inline = "struct g_work_entry { unsigned char field_0; unsigned char field_1; }"
    codegen._inertia_global_declaration_specs_8616 = ((inline, "g_work", 1),)

    record_global_declaration_spec_8616(
        codegen,
        ctype=NamedAggregateDeclarationCType8616(
            type_name="g_work_entry",
            inline_definition=inline,
            registered=True,
        ),
        name="g_work",
        array_len=1,
    )

    assert codegen._inertia_global_declaration_specs_8616 == (("g_work_entry", "g_work", 1),)


def test_named_aggregate_does_not_replace_unrelated_struct_declaration():
    codegen = _DummyCodegen()
    unrelated = "struct other_entry { unsigned short value; }"
    codegen._inertia_global_declaration_specs_8616 = ((unrelated, "g_work", 1),)

    record_global_declaration_spec_8616(
        codegen,
        ctype=NamedAggregateDeclarationCType8616(
            type_name="g_work_entry",
            inline_definition="struct g_work_entry { unsigned char field_0; unsigned char field_1; }",
            registered=True,
        ),
        name="g_work",
        array_len=1,
    )

    assert codegen._inertia_global_declaration_specs_8616 == ((unrelated, "g_work", 1),)


def test_unregistered_named_aggregate_cannot_downgrade_registered_declaration():
    codegen = _DummyCodegen()
    codegen._inertia_global_declaration_specs_8616 = (("g_work_entry", "g_work", 1),)

    record_global_declaration_spec_8616(
        codegen,
        ctype=NamedAggregateDeclarationCType8616(
            type_name="g_work_entry",
            inline_definition="struct g_work_entry { unsigned char field_0; unsigned char field_1; }",
            registered=False,
        ),
        name="g_work",
        array_len=1,
    )

    assert codegen._inertia_global_declaration_specs_8616 == (("g_work_entry", "g_work", 1),)


def test_direct_word_refs_derive_scalar_dword_global_ref():
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0xB48, "clFinish", 0, 2, 2),
            DirectGlobalSymbolRef8616(0xB4A, "clFinish", 2, 2, 2),
        )
    )

    assert DirectGlobalSymbolRef8616(0xB48, "clFinish", 0, 4, 0) in refs


def test_named_dword_derivation_replaces_generated_scalar_identity():
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2),
            DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2),
        ),
        (DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 4, 0),),
    )

    assert DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0) in refs
    assert DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 4, 0) not in refs


def test_direct_dword_scalar_ref_with_high_word_evidence_does_not_render_single_element_array():
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010)
    direct_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 2)

    expr = _make_direct_global_symbol_expr_8616(codegen, direct_ref, 4)

    assert isinstance(expr, CVariable)
    assert expr.variable.name == "clPause"
    assert expr.variable.size == 4
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned long", "clPause", None),)


def test_binary_proven_scalar_declaration_replaces_equal_width_one_element_view():
    codegen = _DummyCodegen()
    codegen._inertia_global_declaration_specs_8616 = (("unsigned short", "g_index", 1),)

    record_scalar_global_declaration_spec_8616(
        codegen,
        ctype=GlobalDeclarationCType8616.UNSIGNED_SHORT,
        name="g_index",
    )

    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned short", "g_index", None),)


def test_direct_dword_global_load_materializes_from_adjacent_word_refs():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    rhs = CFunctionCall("SEG_U32", None, [_ds(project, codegen), _const(0xB48, codegen)], codegen=codegen)
    assignment = CAssignment(_stack(-4, codegen, name="elapsed"), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0xB48, "clFinish", 0, 2, 2),
            DirectGlobalSymbolRef8616(0xB4A, "clFinish", 2, 2, 2),
        )
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        _indexed_evidence_from_direct_symbol_refs_8616(refs),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariable)
    assert assignment.rhs.variable.name == "clFinish"
    assert assignment.rhs.variable.size == 4
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned long", "clFinish", None),)


def test_direct_dword_subword_cvariables_materialize_as_scalar_projections_from_instruction_refs():
    class _Memory:
        def load(self, addr, size):
            assert addr == 0x4010
            # cmp word ptr [0x0132], 900; cmp word ptr [0x0134], 0
            return b"\x81\x3e\x32\x01\x84\x03\x83\x3e\x34\x01\x00"[:size]

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(labels={}),
        loader=SimpleNamespace(memory=_Memory()),
    )
    codegen = _DummyCodegen()
    low_condition = CBinaryOp("CmpEQ", _mem(0x132, codegen, name="mem_0132"), _const(900, codegen), codegen=codegen)
    high_condition = CBinaryOp("CmpEQ", _mem(0x134, codegen, name="mem_0134"), _const(0, codegen), codegen=codegen)
    root = CStatements([low_condition, high_condition], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, size=11, statements=root, body=root)

    changed = materialize_named_segmented_global_loads_8616(project, codegen, {0x132: ("clPause", 4)})

    assert changed is True
    assert isinstance(low_condition.lhs, CBinaryOp)
    assert low_condition.lhs.op == "And"
    assert low_condition.lhs.lhs.variable.name == "clPause"
    assert low_condition.lhs.rhs.value == 0xFFFF
    assert isinstance(high_condition.lhs, CBinaryOp)
    assert high_condition.lhs.op == "Shr"
    assert high_condition.lhs.lhs.variable.name == "clPause"
    assert high_condition.lhs.rhs.value == 16
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned long", "clPause", None),)


def test_direct_dword_subword_replay_retains_exact_segment_access_provenance(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    high_word = CVariable(
        SimMemoryVariable(0x134, 2, name="mem_0134"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
        tags={"inertia_source_instruction_addrs": (0x4010,)},
    )
    condition = CBinaryOp("CmpLE", high_word, _const(0, codegen), codegen=codegen)
    root = CStatements([condition], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x4010,
        accesses=tuple(
            SegmentAccessFact(
                block_addr=instruction_addr,
                instruction_addr=instruction_addr,
                kind=SegmentAccessKind.READ,
                address=IRAddress(
                    space=MemSpace.DS,
                    offset=0x134,
                    size=2,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
                segment_register="ds",
                physical_source="ds",
                verdict=SegmentFactVerdict.PROVEN,
            )
            for instruction_addr in (0x4010, 0x4020)
        ),
    )
    high_ref = DirectGlobalSymbolRef8616(
        offset=0x134,
        name="clPause",
        relative_disp=2,
        width=2,
        max_relative_disp=2,
    )
    scalar_ref = DirectGlobalSymbolRef8616(
        offset=0x132,
        name="clPause",
        relative_disp=0,
        width=4,
        max_relative_disp=0,
    )
    refs = [high_ref]
    monkeypatch.setattr(
        segmented_global_loads_module,
        "_collect_direct_global_symbol_refs_8616",
        lambda *_args: tuple(refs),
    )
    monkeypatch.setattr(
        segmented_global_loads_module,
        "_collect_synthetic_direct_global_symbol_refs_8616",
        lambda *_args: (),
    )

    first_changed = materialize_named_segmented_global_loads_8616(project, codegen, {})

    assert first_changed is True
    assert isinstance(condition.lhs, CIndexedVariable)
    assert condition.lhs.tags["inertia_source_instruction_addrs"] == (0x4010,)

    refs.append(scalar_ref)
    replay_changed = materialize_named_segmented_global_loads_8616(project, codegen, {})

    assert replay_changed is True
    assert isinstance(condition.lhs, CBinaryOp)
    assert condition.lhs.op == "Shr"
    assert condition.lhs.tags["inertia_source_instruction_addrs"] == (0x4010,)


def test_dword_zero_test_replay_records_closed_materialization_evidence():
    class _Memory:
        def load(self, addr, size):
            assert addr == 0x4010
            # mov ax,[0134]; or ax,[0132]; jne +0
            return b"\xa1\x34\x01\x0b\x06\x32\x01\x75\x00"[:size]

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(labels={}),
        loader=SimpleNamespace(memory=_Memory()),
    )
    codegen = _DummyCodegen()
    condition = CBinaryOp(
        "Or",
        _mem_word(0x134, codegen, name="mem_0134"),
        _mem_word(0x132, codegen, name="mem_0132"),
        codegen=codegen,
    )
    root = CStatements([condition], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, size=9, statements=root, body=root)

    first_changed = materialize_named_segmented_global_loads_8616(
        project,
        codegen,
        {0x132: ("clPause", 4)},
    )
    replay_changed = materialize_named_segmented_global_loads_8616(
        project,
        codegen,
        {0x132: ("clPause", 4)},
    )

    assert first_changed is True
    assert replay_changed is True
    assert isinstance(root.statements[0], CVariable)
    assert root.statements[0].variable.name == "clPause"
    assert codegen._inertia_dword_global_zero_test_materialization_record_8616 == (
        DwordGlobalZeroTestMaterializationRecord8616(
            evidence=(
                DwordGlobalZeroTestEvidence8616(
                    0x132,
                    0x132,
                    0x134,
                    "ax",
                    low_instruction_addr=0x4013,
                    high_instruction_addr=0x4010,
                ),
            ),
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        )
    )


def test_direct_word_global_load_materializes_from_adjacent_byte_pair():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    rhs = CBinaryOp(
        "Or",
        _mem(0x160, codegen, name="mem_0160"),
        CBinaryOp("Shl", _mem(0x161, codegen, name="mem_0161"), _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    assignment = CAssignment(_stack(-2, codegen, name="limit"), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_named_segmented_global_loads_8616(project, codegen, {0x160: ("cszMenu", 2)})

    assert changed is True
    assert isinstance(assignment.rhs, CVariable)
    assert assignment.rhs.variable.name == "cszMenu"
    assert assignment.rhs.variable.size == 2
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned short", "cszMenu", None),)


def test_direct_word_global_load_materializes_from_dirty_byte_pair_carrier():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    pair_carrier = _dirty(20, codegen)
    pair_rhs = CBinaryOp(
        "Or",
        _mem(0x160, codegen, name="mem_0160"),
        CBinaryOp("Shl", _mem(0x161, codegen, name="mem_0161"), _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    pair_assignment = CAssignment(pair_carrier, pair_rhs, codegen=codegen)
    use_assignment = CAssignment(_stack(-2, codegen, name="limit"), pair_carrier, codegen=codegen)
    root = CStatements([pair_assignment, use_assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_named_segmented_global_loads_8616(project, codegen, {0x160: ("cszMenu", 2)})

    assert changed is True
    assert isinstance(pair_assignment.lhs, CDirtyExpression)
    assert isinstance(use_assignment.rhs, CVariable)
    assert use_assignment.rhs.variable.name == "cszMenu"
    assert use_assignment.rhs.variable.size == 2
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned short", "cszMenu", None),)


def test_direct_word_global_load_materializes_from_dirty_byte_half_carriers():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    low_carrier = _dirty(21, codegen)
    high_carrier = _dirty(22, codegen)
    pair_rhs = CBinaryOp("Or", low_carrier, high_carrier, codegen=codegen)
    statements = [
        CAssignment(low_carrier, _mem(0x160, codegen, name="mem_0160"), codegen=codegen),
        CAssignment(
            high_carrier,
            CBinaryOp("Shl", _mem(0x161, codegen, name="mem_0161"), _const(8, codegen), codegen=codegen),
            codegen=codegen,
        ),
        CAssignment(_stack(-2, codegen, name="limit"), pair_rhs, codegen=codegen),
    ]
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_named_segmented_global_loads_8616(project, codegen, {0x160: ("cszMenu", 2)})

    assert changed is True
    assert isinstance(statements[-1].rhs, CVariable)
    assert statements[-1].rhs.variable.name == "cszMenu"
    assert statements[-1].rhs.variable.size == 2
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned short", "cszMenu", None),)


def test_direct_dword_global_load_materializes_from_adjacent_word_pair():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    rhs = CBinaryOp(
        "Or",
        _mem_word(0x132, codegen, name="mem_0132"),
        CBinaryOp("Shl", _mem_word(0x134, codegen, name="mem_0134"), _const(16, codegen), codegen=codegen),
        codegen=codegen,
    )
    assignment = CAssignment(_stack(-4, codegen, name="pause"), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = materialize_named_segmented_global_loads_8616(project, codegen, {0x132: ("clPause", 4)})

    assert changed is True
    assert isinstance(assignment.rhs, CVariable)
    assert assignment.rhs.variable.name == "clPause"
    assert assignment.rhs.variable.size == 4
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned long", "clPause", None),)


def test_direct_global_symbol_store_pairs_fold_split_constant_word_store():
    codegen = _DummyCodegen()
    low = CAssignment(
        _mem(0x44, codegen, name="g_0044"),
        CConstant(9, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
    )
    high = CAssignment(
        _mem(0x45, codegen, name="g_0045"),
        CConstant(0, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0x44, "g_work", 0, 2, 14),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CIndexedVariable)
    assert assignment.lhs.variable.name == "g_work"
    assert assignment.lhs.index.value == 0
    assert assignment.rhs.value == 9
    assert stats.direct_symbol_store_materialized_count == 1
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned short", "g_work", 8),)


def test_direct_global_symbol_store_pairs_fold_split_dword_scalar_store():
    codegen = _DummyCodegen()
    low_word = CVariable(
        SimRegisterVariable(0x20, 2, name="v_ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_word = CVariable(
        SimRegisterVariable(0x22, 2, name="v_dx"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    low_low = CAssignment(_mem(0xB48, codegen, name="mem_0b48"), low_word, codegen=codegen)
    low_high = CAssignment(
        _mem(0xB49, codegen, name="mem_0b49"),
        CBinaryOp("Shr", low_word, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    high_low = CAssignment(_mem(0xB4A, codegen, name="mem_0b4a"), high_word, codegen=codegen)
    high_high = CAssignment(
        _mem(0xB4B, codegen, name="mem_0b4b"),
        CBinaryOp("Shr", high_word, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low_low, low_high, high_low, high_high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0xB48, "clFinish", 0, 2, 2),
            DirectGlobalSymbolRef8616(0xB4A, "clFinish", 2, 2, 2),
        )
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(codegen, refs, stats=stats)

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "clFinish"
    assert assignment.lhs.variable.size == 4
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Or"
    assert assignment.rhs.lhs is low_word
    assert isinstance(assignment.rhs.rhs, CBinaryOp)
    assert assignment.rhs.rhs.op == "Shl"
    assert assignment.rhs.rhs.lhs is high_word
    assert assignment.rhs.rhs.rhs.value == 16
    assert stats.direct_symbol_store_materialized_count == 3
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned long", "clFinish", None),)


def test_direct_global_symbol_store_pairs_fold_wide_call_return_scalar_store():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    low_word = CVariable(
        SimRegisterVariable(0x20, 2, name="v_ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_word = _reg(project, codegen, "dx")
    clock_call = CFunctionCall("clock", None, [], codegen=codegen)
    low_copy = CAssignment(low_word, clock_call, codegen=codegen)
    low_store = CAssignment(_mem_word(0xB48, codegen, name="mem_0b48"), low_word, codegen=codegen)
    high_store = CAssignment(_mem_word(0xB4A, codegen, name="mem_0b4a"), high_word, codegen=codegen)
    root = CStatements([low_copy, low_store, high_store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0xB48, "clFinish", 0, 2, 2),
            DirectGlobalSymbolRef8616(0xB4A, "clFinish", 2, 2, 2),
        )
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(codegen, refs, stats=stats)

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "clFinish"
    assert assignment.lhs.variable.size == 4
    assert assignment.rhs is clock_call
    assert stats.direct_symbol_store_materialized_count == 1
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned long", "clFinish", None),)


def test_collect_direct_global_call_return_store_evidence_from_instruction_triple(monkeypatch):
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1137E: "_clock"}),
    )
    call = SimpleNamespace(
        address=0x1049F,
        id=X86_INS_CALL,
        operands=(_imm_operand(0x1137E),),
    )
    low_store = SimpleNamespace(
        address=0x104A2,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_INVALID, 0xB48), _reg_operand(X86_REG_AX)),
    )
    high_store = SimpleNamespace(
        address=0x104A5,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_INVALID, 0xB4A), _reg_operand(X86_REG_DX)),
    )
    duplicate_block = SimpleNamespace(capstone=SimpleNamespace(insns=(call, low_store, high_store)))
    function = SimpleNamespace(blocks=(duplicate_block, duplicate_block))
    original_collector = segmented_global_loads_module._direct_global_update_ordered_insns_8616
    collector_calls = 0

    def counted_collector(*args, **kwargs):
        nonlocal collector_calls
        collector_calls += 1
        return original_collector(*args, **kwargs)

    monkeypatch.setattr(
        segmented_global_loads_module,
        "_direct_global_update_ordered_insns_8616",
        counted_collector,
    )

    evidence = _collect_direct_global_call_return_store_evidence_8616(project, function)
    repeated_evidence = _collect_direct_global_call_return_store_evidence_8616(project, function)

    expected = (
        DirectGlobalCallReturnStoreEvidence8616(
            offset=0xB48,
            width=4,
            source_call_name="clock",
            source_call_target=0x1137E,
            source_call_ins_addr=0x1049F,
            low_store_ins_addr=0x104A2,
            high_store_ins_addr=0x104A5,
        ),
    )
    assert evidence == expected
    assert repeated_evidence == expected
    assert collector_calls == 1


def test_collect_scalar_call_return_global_store_after_stack_cleanup(monkeypatch):
    class _Functions:
        def function(self, *, addr=None, create=False, **_kwargs):
            return None

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=_Functions(), labels={}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x12000: "_settextrows"}),
    )
    call = SimpleNamespace(
        address=0x1000F,
        id=X86_INS_CALL,
        operands=(_imm_operand(0x12000),),
    )
    cleanup = SimpleNamespace(
        address=0x10014,
        id=X86_INS_ADD,
        operands=(_reg_operand(X86_REG_SP), _imm_operand(2)),
    )
    store = SimpleNamespace(
        address=0x10017,
        id=X86_INS_MOV,
        operands=(_mem_operand(X86_REG_INVALID, 0xBA2), _reg_operand(X86_REG_AX)),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(call, cleanup, store)))
    function = SimpleNamespace(project=project, blocks=(block,))
    summary = CallsiteSummary8616(
        callsite_addr=0x1000F,
        target_addr=0x12000,
        return_addr=0x10014,
        kind="direct",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        return_store_destination=("global", 0xBA2),
        return_store_width=2,
    )
    monkeypatch.setattr(
        segmented_global_loads_module,
        "build_callsite_summary_inventory_8616",
        lambda *_args: pytest.fail("owned callsite summary should prevent recovery"),
    )

    evidence = _collect_direct_global_call_return_store_evidence_8616(
        project,
        function,
        {summary.callsite_addr: summary},
    )

    assert evidence == (
        DirectGlobalCallReturnStoreEvidence8616(
            offset=0xBA2,
            width=2,
            source_call_name="settextrows",
            source_call_target=0x12000,
            source_call_ins_addr=0x1000F,
            low_store_ins_addr=0x10017,
            high_store_ins_addr=None,
        ),
    )


def test_sidecar_free_scalar_call_return_reconnects_standalone_ax_carrier():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    codegen.project = project
    carrier = _reg(project, codegen, "ax")
    call = CFunctionCall(
        "sub_12a29",
        None,
        [CConstant(43, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
        tags={"ins_addr": 0x10021},
    )
    call_statement = CExpressionStatement(call, codegen=codegen)
    low_store = CAssignment(
        _mem(0xBA2, codegen),
        carrier,
        codegen=codegen,
        tags={"ins_addr": 0x10027},
    )
    high_store = CAssignment(
        _mem(0xBA3, codegen),
        CBinaryOp(
            "Shr",
            carrier,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x10027},
    )
    root = CStatements([call_statement, low_store, high_store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x10010, statements=root, body=root)
    evidence = DirectGlobalCallReturnStoreEvidence8616(
        offset=0xBA2,
        width=2,
        source_call_name="sub_12a29",
        source_call_target=0x12A29,
        source_call_ins_addr=0x10021,
        low_store_ins_addr=0x10027,
        high_store_ins_addr=None,
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        direct_call_return_stores=(evidence,),
        stats=stats,
    )

    assert changed is True
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs is carrier
    assert assignment.rhs is call
    assert root.statements[1:] == [low_store, high_store]
    assert stats.direct_symbol_call_return_materialized_count == 1
    assert stats.materialized_count == 1
    assert stats.refused_no_evidence == 0

    repeated_changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        direct_call_return_stores=(evidence,),
    )

    assert repeated_changed is False
    assert root.statements[0] is assignment


def test_sidecar_free_scalar_call_return_refuses_inexact_store_tag():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    codegen.project = project
    carrier = _reg(project, codegen, "ax")
    call = CFunctionCall(
        "sub_12a29",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x10021},
    )
    call_statement = CExpressionStatement(call, codegen=codegen)
    low_store = CAssignment(
        _mem(0xBA2, codegen),
        carrier,
        codegen=codegen,
        tags={"ins_addr": 0x10027},
    )
    high_store = CAssignment(
        _mem(0xBA3, codegen),
        CBinaryOp(
            "Shr",
            carrier,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x10028},
    )
    root = CStatements([call_statement, low_store, high_store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x10010, statements=root, body=root)
    evidence = DirectGlobalCallReturnStoreEvidence8616(
        offset=0xBA2,
        width=2,
        source_call_name="sub_12a29",
        source_call_target=0x12A29,
        source_call_ins_addr=0x10021,
        low_store_ins_addr=0x10027,
        high_store_ins_addr=None,
    )

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        direct_call_return_stores=(evidence,),
    )

    assert changed is False
    assert root.statements == [call_statement, low_store, high_store]


def test_scalar_call_return_global_store_consumes_only_exact_ax_carrier():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    codegen.project = project
    destination = CVariable(
        SimMemoryVariable(0xBA2, 2, name="cRow"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "settextrows",
        None,
        [CConstant(43, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    canonical = CAssignment(
        destination,
        call,
        codegen=codegen,
        tags={"ins_addr": 0x1000F},
    )
    consumed = CAssignment(
        destination,
        _reg(project, codegen, "ax"),
        codegen=codegen,
        tags={"ins_addr": 0x10017},
    )
    wrong_register = CAssignment(
        destination,
        _reg(project, codegen, "bx"),
        codegen=codegen,
        tags={"ins_addr": 0x10017},
    )
    wrong_address = CAssignment(
        destination,
        _reg(project, codegen, "ax"),
        codegen=codegen,
        tags={"ins_addr": 0x1001A},
    )
    side_effecting = CAssignment(
        destination,
        CFunctionCall("other", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10017},
    )
    root = CStatements(
        [canonical, consumed, wrong_register, wrong_address, side_effecting],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x10000, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()
    evidence = DirectGlobalCallReturnStoreEvidence8616(
        offset=0xBA2,
        width=2,
        source_call_name="settextrows",
        source_call_target=0x12000,
        source_call_ins_addr=0x1000F,
        low_store_ins_addr=0x10017,
        high_store_ins_addr=None,
    )

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0xBA2, "cRow", 0, 2, 2),),
        direct_call_return_stores=(evidence,),
        stats=stats,
    )

    assert changed is True
    assert root.statements == [canonical, wrong_register, wrong_address, side_effecting]
    assert stats.direct_symbol_call_return_carrier_removed_count == 1
    assert stats.direct_symbol_call_return_materialized_count == 1


def test_direct_global_symbol_store_pairs_fold_call_return_evidence_scalar_store():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    low_word = _reg(project, codegen, "ax")
    high_word = _reg(project, codegen, "dx")
    low_store = CAssignment(
        _mem_word(0xB48, codegen, name="mem_0b48"),
        low_word,
        codegen=codegen,
        tags={"ins_addr": 0x104A2},
    )
    high_store = CAssignment(
        _mem_word(0xB4A, codegen, name="mem_0b4a"),
        high_word,
        codegen=codegen,
        tags={"ins_addr": 0x104A5},
    )
    root = CStatements([low_store, high_store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0xB48, "clFinish", 0, 2, 2),
            DirectGlobalSymbolRef8616(0xB4A, "clFinish", 2, 2, 2),
        )
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(
            DirectGlobalCallReturnStoreEvidence8616(
                offset=0xB48,
                width=4,
                source_call_name="clock",
                source_call_target=0x1137E,
                source_call_ins_addr=0x1049F,
                low_store_ins_addr=0x104A2,
                high_store_ins_addr=0x104A5,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "clFinish"
    assert assignment.lhs.variable.size == 4
    assert isinstance(assignment.rhs, CFunctionCall)
    assert assignment.rhs.callee_target == "clock"
    assert assignment.rhs.args == []
    assert stats.direct_symbol_store_materialized_count == 1
    assert stats.direct_symbol_call_return_materialized_count == 1
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned long", "clFinish", None),)


def test_direct_global_call_return_store_prunes_stale_dx_ax_recombine():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    codegen.project = project
    low_word = _reg(project, codegen, "ax")
    high_word = _reg(project, codegen, "dx")
    low_store = CAssignment(
        _mem_word(0xB48, codegen, name="mem_0b48"),
        low_word,
        codegen=codegen,
        tags={"ins_addr": 0x104A2},
    )
    high_store = CAssignment(
        _mem_word(0xB4A, codegen, name="mem_0b4a"),
        high_word,
        codegen=codegen,
        tags={"ins_addr": 0x104A5},
    )
    stale_recombine = CAssignment(
        CVariable(SimMemoryVariable(0xB48, 4, name="clFinish"), codegen=codegen),
        CBinaryOp(
            "Or",
            low_word,
            CBinaryOp(
                "Shl",
                high_word,
                CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([low_store, high_store, stale_recombine], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0xB48, "clFinish", 0, 2, 2),
            DirectGlobalSymbolRef8616(0xB4A, "clFinish", 2, 2, 2),
        )
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(
            DirectGlobalCallReturnStoreEvidence8616(
                offset=0xB48,
                width=4,
                source_call_name="clock",
                source_call_target=0x1137E,
                source_call_ins_addr=0x1049F,
                low_store_ins_addr=0x104A2,
                high_store_ins_addr=0x104A5,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clFinish"
    assert isinstance(assignment.rhs, CFunctionCall)
    assert assignment.rhs.callee_target == "clock"


def test_direct_global_call_return_store_folds_evidenced_nested_carrier_group():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    codegen.project = project
    call_result = _reg(project, codegen, "ax")
    clock_call = CFunctionCall("clock", None, [], codegen=codegen)
    call_group = CStatements(
        [
            CAssignment(
                call_result,
                clock_call,
                codegen=codegen,
                tags={"ins_addr": 0x1049F},
            )
        ],
        codegen=codegen,
    )
    clock_call.tags = SimpleNamespace(get={"ins_addr": 0x1049F}.get)
    call_group.statements[0].tags = SimpleNamespace(get={"ins_addr": 0x1049F}.get)
    stale_stack_read = CAssignment(
        _reg(project, codegen, "dx"),
        CVariable(SimStackVariable(-2, 2, base="bp", name="local_2"), codegen=codegen),
        codegen=codegen,
    )
    low_word = _reg(project, codegen, "ax")
    high_word = _reg(project, codegen, "dx")
    store_group = CStatements(
        [
            stale_stack_read,
            CAssignment(
                _reg(project, codegen, "ax"),
                low_word,
                codegen=codegen,
                tags={"ins_addr": 0x104A2},
            ),
            CAssignment(
                _reg(project, codegen, "bx"),
                low_word,
                codegen=codegen,
                tags={"ins_addr": 0x104A2},
            ),
            CAssignment(
                _reg(project, codegen, "cx"),
                high_word,
                codegen=codegen,
                tags={"ins_addr": 0x104A5},
            ),
            CAssignment(
                _reg(project, codegen, "dx"),
                high_word,
                codegen=codegen,
                tags={"ins_addr": 0x104A5},
            ),
        ],
        codegen=codegen,
    )
    root = CStatements([call_group, store_group], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0xB48, "clStart", 0, 2, 2),
            DirectGlobalSymbolRef8616(0xB4A, "clStart", 2, 2, 2),
        )
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(
            DirectGlobalCallReturnStoreEvidence8616(
                offset=0xB48,
                width=4,
                source_call_name="clock",
                source_call_target=0x1137E,
                source_call_ins_addr=0x1049F,
                low_store_ins_addr=0x104A2,
                high_store_ins_addr=0x104A5,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert call_group.statements == []
    assert len(store_group.statements) == 1
    assignment = store_group.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "clStart"
    assert assignment.rhs is clock_call
    assert stats.direct_symbol_call_return_materialized_count == 1

    repeated_changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(
            DirectGlobalCallReturnStoreEvidence8616(
                offset=0xB48,
                width=4,
                source_call_name="clock",
                source_call_target=0x1137E,
                source_call_ins_addr=0x1049F,
                low_store_ins_addr=0x104A2,
                high_store_ins_addr=0x104A5,
            ),
        ),
    )

    assert repeated_changed is False
    assert store_group.statements == [assignment]


def test_sidecar_free_dword_call_return_store_materializes_generic_global():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    codegen.project = project
    clock_call = CFunctionCall(
        "sub_1137e",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x10683},
    )
    call_group = CStatements(
        [
            CExpressionStatement(
                clock_call,
                codegen=codegen,
                tags={"ins_addr": 0x10683},
            )
        ],
        codegen=codegen,
    )
    clock_call.tags = SimpleNamespace(get={"ins_addr": 0x10683}.get)
    call_group.statements[0].tags = SimpleNamespace(get={"ins_addr": 0x10683}.get)
    stale_low = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        codegen=codegen,
    )
    stale_copy = CAssignment(_reg(project, codegen, "ax"), stale_low, codegen=codegen)
    low_store = CAssignment(
        _mem(0xBA6, codegen, name="g_ba6"),
        stale_low,
        codegen=codegen,
        tags={"ins_addr": 0x10686},
    )
    low_high_store = CAssignment(
        _mem(0xBA7, codegen, name="g_ba7"),
        CBinaryOp(
            "Shr",
            stale_low,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x10686},
    )
    dx = _reg(project, codegen, "dx")
    high_store = CAssignment(
        _mem(0xBA8, codegen, name="g_ba8"),
        dx,
        codegen=codegen,
        tags={"ins_addr": 0x10689},
    )
    high_high_store = CAssignment(
        _mem(0xBA9, codegen, name="g_ba9"),
        CBinaryOp(
            "Shr",
            dx,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x10689},
    )
    store_group = CStatements(
        [stale_copy, low_store, low_high_store, high_store, high_high_store],
        codegen=codegen,
    )
    root = CStatements([call_group, store_group], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x10678, statements=root, body=root)
    evidence = DirectGlobalCallReturnStoreEvidence8616(
        offset=0xBA6,
        width=4,
        source_call_name="sub_1137e",
        source_call_target=0x1137E,
        source_call_ins_addr=0x10683,
        low_store_ins_addr=0x10686,
        high_store_ins_addr=0x10689,
    )
    anonymous_evidence = (
        DirectSegmentedGlobalStoreEvidence8616(0xBA6, 2, MemSpace.DS, 0x10686),
        DirectSegmentedGlobalStoreEvidence8616(0xBA8, 2, MemSpace.DS, 0x10689),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        direct_call_return_stores=(evidence,),
        anonymous_direct_stores=anonymous_evidence,
        project=project,
        stats=stats,
    )

    assert changed is True
    assert call_group.statements == []
    assert len(store_group.statements) == 1
    assignment = store_group.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "g_0BA6"
    assert assignment.lhs.variable.size == 4
    assert assignment.rhs is clock_call
    assert stats.direct_symbol_call_return_materialized_count == 1
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned long", "g_0BA6", None),
    )

    repeated_changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        direct_call_return_stores=(evidence,),
        anonymous_direct_stores=anonymous_evidence,
        project=project,
    )

    assert repeated_changed is False
    assert store_group.statements == [assignment]
    assert assignment.lhs.variable.size == 4


def test_sidecar_free_dword_update_refs_require_exact_adjacent_carry_word():
    summaries = [
        InsnSummary8616("add", "direct_mem", 0x132, "imm", 30, 2, 2, 0x10408),
        InsnSummary8616("adc", "direct_mem", 0x134, "imm", 0, 2, 2, 0x1040D),
    ]

    refs = _sidecar_free_dword_update_refs_8616(summaries)

    assert refs == (
        DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 4, 0),
        DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 2, 2),
        DirectGlobalSymbolRef8616(0x134, "g_0132", 2, 2, 2),
    )


def test_sidecar_free_dword_update_refs_wait_for_materialized_low_word_identity():
    codegen = _DummyCodegen()
    summaries = [
        InsnSummary8616("add", "direct_mem", 0x132, "imm", 30, 2, 2, 0x10408),
        InsnSummary8616("adc", "direct_mem", 0x134, "imm", 0, 2, 2, 0x1040D),
    ]

    assert _materialized_sidecar_free_dword_update_refs_8616(codegen, summaries) == ()

    codegen._inertia_global_storage_identity_facts_8616 = (
        GlobalStorageIdentityFact8616(
            space=MemSpace.DS,
            offset=0x132,
            width=2,
            name="g_0132",
            evidence_addr=0x10408,
            kind=StorageIdentityEvidenceKind8616.DIRECT_GLOBAL_UPDATE,
        ),
    )
    assert _materialized_sidecar_free_dword_update_refs_8616(codegen, summaries) == ()

    switch = CSwitchCase(_const(1, codegen), [], None, codegen=codegen)
    root = CStatements([switch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    assert _materialized_sidecar_free_dword_update_refs_8616(
        codegen,
        summaries,
    ) == _sidecar_free_dword_update_refs_8616(summaries)


@pytest.mark.parametrize(
    "high",
    (
        InsnSummary8616("adc", "direct_mem", 0x136, "imm", 0, 2, 2, 0x1040D),
        InsnSummary8616("adc", "direct_mem", 0x134, "imm", 1, 2, 2, 0x1040D),
        InsnSummary8616("sbb", "direct_mem", 0x134, "imm", 0, 2, 2, 0x1040D),
    ),
)
def test_sidecar_free_dword_update_refs_refuse_nonmatching_high_word(
    high: InsnSummary8616,
):
    summaries = [
        InsnSummary8616("add", "direct_mem", 0x132, "imm", 30, 2, 2, 0x10408),
        high,
    ]

    assert _sidecar_free_dword_update_refs_8616(summaries) == ()


def test_direct_global_symbol_store_pairs_fold_call_return_evidence_from_byte_stores():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    ax_offset, ax_size = project.arch.registers["ax"]
    dx_offset, dx_size = project.arch.registers["dx"]
    low_word = CVariable(
        SimRegisterVariable(ax_offset, ax_size, name="v9"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_word = CVariable(
        SimRegisterVariable(dx_offset, dx_size, name="v11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    low_low = CAssignment(
        _mem(0xB48, codegen, name="mem_0b48"),
        low_word,
        codegen=codegen,
        tags={"ins_addr": 0x104A2},
    )
    low_high = CAssignment(
        _mem(0xB49, codegen, name="mem_0b49"),
        CBinaryOp("Shr", low_word, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x104A2},
    )
    high_low = CAssignment(
        _mem(0xB4A, codegen, name="mem_0b4a"),
        high_word,
        codegen=codegen,
        tags={"ins_addr": 0x104A5},
    )
    high_high = CAssignment(
        _mem(0xB4B, codegen, name="mem_0b4b"),
        CBinaryOp("Shr", high_word, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x104A5},
    )
    root = CStatements([low_low, low_high, high_low, high_high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0xB48, "clFinish", 0, 2, 2),
            DirectGlobalSymbolRef8616(0xB4A, "clFinish", 2, 2, 2),
        )
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(
            DirectGlobalCallReturnStoreEvidence8616(
                offset=0xB48,
                width=4,
                source_call_name="clock",
                source_call_target=0x1137E,
                source_call_ins_addr=0x1049F,
                low_store_ins_addr=0x104A2,
                high_store_ins_addr=0x104A5,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "clFinish"
    assert assignment.lhs.variable.size == 4
    assert isinstance(assignment.rhs, CFunctionCall)
    assert assignment.rhs.callee_target == "clock"
    assert assignment.rhs.args == []
    assert stats.direct_symbol_call_return_materialized_count == 1


def test_direct_global_symbol_store_pairs_consume_evidenced_call_carrier_from_byte_stores():
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _DummyCodegen()
    ax_offset, ax_size = project.arch.registers["ax"]
    dx_offset, dx_size = project.arch.registers["dx"]
    call_carrier = CVariable(
        SimRegisterVariable(ax_offset, ax_size, name="v10"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    low_word = CVariable(
        SimRegisterVariable(ax_offset, ax_size, name="v9"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_word = CVariable(
        SimRegisterVariable(dx_offset, dx_size, name="v11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    unrelated_var = CVariable(
        SimRegisterVariable(0x40, 2, name="unrelated"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call_copy = CAssignment(
        call_carrier,
        CFunctionCall("clock", None, [], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1049F},
    )
    unrelated_copy = CAssignment(
        unrelated_var,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    low_low = CAssignment(
        _mem(0xB48, codegen, name="mem_0b48"),
        low_word,
        codegen=codegen,
        tags={"ins_addr": 0x104A2},
    )
    low_high = CAssignment(
        _mem(0xB49, codegen, name="mem_0b49"),
        CBinaryOp("Shr", low_word, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x104A2},
    )
    high_low = CAssignment(
        _mem(0xB4A, codegen, name="mem_0b4a"),
        high_word,
        codegen=codegen,
        tags={"ins_addr": 0x104A5},
    )
    high_high = CAssignment(
        _mem(0xB4B, codegen, name="mem_0b4b"),
        CBinaryOp("Shr", high_word, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x104A5},
    )
    root = CStatements([call_copy, unrelated_copy, low_low, low_high, high_low, high_high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    refs = _merge_direct_global_symbol_refs_8616(
        (
            DirectGlobalSymbolRef8616(0xB48, "clFinish", 0, 2, 2),
            DirectGlobalSymbolRef8616(0xB4A, "clFinish", 2, 2, 2),
        )
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(
            DirectGlobalCallReturnStoreEvidence8616(
                offset=0xB48,
                width=4,
                source_call_name="clock",
                source_call_target=0x1137E,
                source_call_ins_addr=0x1049F,
                low_store_ins_addr=0x104A2,
                high_store_ins_addr=0x104A5,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 2
    assert root.statements[0] is unrelated_copy
    assignment = root.statements[1]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "clFinish"
    assert isinstance(assignment.rhs, CFunctionCall)
    assert assignment.rhs.callee_target == "clock"
    assert stats.direct_symbol_call_return_materialized_count == 1


def test_direct_global_symbol_store_pairs_fold_copied_constant_word_store():
    codegen = _DummyCodegen()
    low_tmp = CVariable(
        SimRegisterVariable(0x20, 2, name="v_low"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_tmp = CVariable(
        SimRegisterVariable(0x22, 2, name="v_high"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    low_copy = CAssignment(low_tmp, CConstant(30, SimTypeShort(False), codegen=codegen), codegen=codegen)
    high_copy = CAssignment(high_tmp, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    low = CAssignment(_mem(0x132, codegen, name="mem_0132"), low_tmp, codegen=codegen)
    high = CAssignment(_mem(0x133, codegen, name="mem_0133"), high_tmp, codegen=codegen)
    root = CStatements([low_copy, high_copy, low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 3
    assignment = root.statements[2]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CIndexedVariable)
    assert assignment.lhs.variable.name == "clPause"
    assert assignment.lhs.index.value == 0
    assert assignment.rhs.value == 30
    assert stats.direct_symbol_store_materialized_count == 1


def test_direct_global_symbol_store_pairs_fold_dirty_copied_constant_word_store():
    codegen = _DummyCodegen()
    carrier = _dirty(204, codegen)
    copy = CAssignment(carrier, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    low = CAssignment(_mem(0xBAA, codegen, name="mem_0BAA"), carrier, codegen=codegen)
    high = CAssignment(
        _mem(0xBAB, codegen, name="mem_0BAB"),
        CBinaryOp("Shr", carrier, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([copy, low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x42DE, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 2
    assignment = root.statements[1]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "iCompares"
    assert assignment.rhs.value == 0
    assert stats.direct_symbol_store_materialized_count == 1


def test_direct_global_symbol_store_pairs_fold_shifted_constant_high_byte():
    codegen = _DummyCodegen()
    word_value = CConstant(30, SimTypeShort(False), codegen=codegen)
    low = CAssignment(
        _mem(0x132, codegen, name="mem_0132"),
        word_value,
        codegen=codegen,
    )
    high = CAssignment(
        _mem(0x133, codegen, name="mem_0133"),
        CBinaryOp("Shr", word_value, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CIndexedVariable)
    assert assignment.lhs.variable.name == "clPause"
    assert assignment.lhs.index.value == 0
    assert assignment.rhs.value == 30
    assert stats.direct_symbol_store_materialized_count == 1


def test_direct_global_symbol_store_pairs_fold_split_word_increment():
    codegen = _DummyCodegen()
    old_word = CBinaryOp(
        "Or",
        _mem(0xBAA, codegen, name="mem_0BAA"),
        CBinaryOp(
            "Shl",
            _mem(0xBAB, codegen, name="mem_0BAB"),
            _const(8, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    word_value = CBinaryOp("Add", old_word, _const(1, codegen), codegen=codegen)
    low = CAssignment(_mem(0xBAA, codegen, name="mem_0BAA"), word_value, codegen=codegen)
    high = CAssignment(
        _mem(0xBAB, codegen, name="mem_0BAB"),
        CBinaryOp("Shr", word_value, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "iCompares"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.lhs.variable.name == "iCompares"
    assert assignment.rhs.rhs.value == 1
    assert stats.direct_symbol_store_materialized_count == 1


def test_direct_global_name_facts_include_update_only_storage_without_overriding_named_ref():
    facts = _direct_global_symbol_name_facts_8616(
        (DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0),),
        (
            DirectGlobalUpdateEvidence8616(0xBA4, 2, 1),
            DirectGlobalUpdateEvidence8616(0xBAA, 2, 1),
        ),
    )

    assert tuple((fact.offset, fact.width, fact.name) for fact in facts) == (
        (0xBA4, 2, "g_0BA4"),
        (0xBAA, 2, "iCompares"),
    )


def test_direct_global_symbol_store_pairs_use_update_evidence_for_damaged_byte_carrier():
    codegen = _DummyCodegen()
    old_word = CBinaryOp(
        "Or",
        _mem(0xBAB, codegen, name="mem_0BAB"),
        CBinaryOp(
            "Shl",
            _mem(0xBAB, codegen, name="mem_0BAB"),
            _const(8, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    word_value = CBinaryOp("Add", old_word, _const(1, codegen), codegen=codegen)
    low = CAssignment(_mem(0xBAA, codegen, name="mem_0BAA"), word_value, codegen=codegen)
    high = CAssignment(
        _mem(0xBAB, codegen, name="mem_0BAB"),
        CBinaryOp("Shr", word_value, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0),),
        direct_updates=(DirectGlobalUpdateEvidence8616(0xBAA, 2, 1),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "iCompares"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.lhs.variable.name == "iCompares"
    assert assignment.rhs.rhs.value == 1
    assert stats.direct_symbol_store_materialized_count == 1
    assert stats.direct_symbol_update_materialized_count == 1


def test_direct_global_dword_update_folds_low_word_update_with_high_byte_pair():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    low_value = CBinaryOp(
        "Add",
        _make_direct_global_symbol_expr_8616(codegen, low_ref, 2),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(_make_direct_global_symbol_expr_8616(codegen, low_ref, 2), low_value, codegen=codegen)
    high_low = CAssignment(_mem(0x134, codegen, name="mem_0134"), _mem(0x134, codegen), codegen=codegen)
    high_high = CAssignment(
        _mem(0x135, codegen, name="mem_0135"),
        CBinaryOp("Shr", _mem(0x134, codegen), _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low, high_low, high_high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert assignment.lhs.variable.size == 4
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.lhs.variable.name == "clPause"
    assert assignment.rhs.rhs.value == 30
    assert stats.direct_symbol_update_materialized_count == 1


def test_direct_global_dword_update_folds_generated_low_word_name_with_dword_parent():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    low_value = CBinaryOp(
        "Add",
        _make_direct_global_symbol_expr_8616(codegen, low_ref, 2),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(_make_direct_global_symbol_expr_8616(codegen, low_ref, 2), low_value, codegen=codegen)
    high_low = CAssignment(_mem(0x134, codegen, name="mem_0134"), _mem(0x134, codegen), codegen=codegen)
    high_high = CAssignment(
        _mem(0x135, codegen, name="mem_0135"),
        CBinaryOp("Shr", _mem(0x134, codegen), _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low, high_low, high_high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.lhs.variable.name == "clPause"
    assert assignment.rhs.rhs.value == 30
    assert stats.direct_symbol_update_materialized_count == 1


def test_direct_global_dword_update_folds_generated_low_word_with_long_carrier_gap():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    low_value = CBinaryOp(
        "Add",
        _make_direct_global_symbol_expr_8616(codegen, low_ref, 2),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(_make_direct_global_symbol_expr_8616(codegen, low_ref, 2), low_value, codegen=codegen)
    carriers = [
        CAssignment(_dirty(3000 + index, codegen), _const(index, codegen), codegen=codegen) for index in range(40)
    ]
    high_low = CAssignment(_mem(0x134, codegen, name="mem_0134"), _dirty(3100, codegen), codegen=codegen)
    high_high = CAssignment(_mem(0x135, codegen, name="mem_0135"), _dirty(3101, codegen), codegen=codegen)
    root = CStatements([low, *carriers, high_low, high_high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.rhs.value == 30
    assert stats.direct_symbol_update_materialized_count == 1


def test_direct_global_dword_update_folds_low_word_update_with_carry_temporaries():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)

    def tmp(varid: int):
        return _dirty(varid, codegen)

    low_value = CBinaryOp(
        "Add",
        _make_direct_global_symbol_expr_8616(codegen, low_ref, 2),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(_make_direct_global_symbol_expr_8616(codegen, low_ref, 2), low_value, codegen=codegen)
    carry_seed = CAssignment(tmp(2043), _const(0, codegen), codegen=codegen)
    carry_flags = CAssignment(tmp(2044), tmp(9), codegen=codegen)
    carry_shift = CAssignment(
        tmp(2045),
        CBinaryOp("Shr", tmp(2044), _const(0, codegen), codegen=codegen),
        codegen=codegen,
    )
    carry_bit = CAssignment(
        tmp(2047),
        CBinaryOp("And", _const(1, codegen), tmp(2045), codegen=codegen),
        codegen=codegen,
    )
    high_word = CAssignment(
        tmp(2050),
        CBinaryOp(
            "Add",
            CBinaryOp(
                "Add",
                CBinaryOp("Shr", _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4), _const(16, codegen), codegen=codegen),
                tmp(2043),
                codegen=codegen,
            ),
            tmp(2047),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    high_carry = CAssignment(
        tmp(2064),
        CBinaryOp("Shr", tmp(2050), _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    high_low = CAssignment(_mem(0x134, codegen, name="mem_0134"), tmp(2050), codegen=codegen)
    high_high = CAssignment(_mem(0x135, codegen, name="mem_0135"), tmp(2064), codegen=codegen)
    root = CStatements(
        [low, carry_seed, carry_flags, carry_shift, carry_bit, high_word, high_carry, high_low, high_high],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.lhs.variable.name == "clPause"
    assert assignment.rhs.rhs.value == 30
    assert stats.direct_symbol_update_materialized_count == 1


def test_direct_global_dword_update_folds_low_word_with_upper_word_carry():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)

    def tmp(varid: int):
        return _dirty(varid, codegen)

    low_rhs = CBinaryOp(
        "Add",
        CBinaryOp(
            "And",
            _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4),
            _const(0xFFFF, codegen),
            codegen=codegen,
        ),
        _const(30, codegen),
        codegen=codegen,
    )
    low_byte = CAssignment(_mem(0x132, codegen, name="mem_0132"), low_rhs, codegen=codegen)
    carry_seed = CAssignment(tmp(1404), _const(0, codegen), codegen=codegen)
    carry_flags = CAssignment(tmp(1408), CBinaryOp("And", _const(1, codegen), tmp(9), codegen=codegen), codegen=codegen)
    high_word_tmp = CAssignment(
        tmp(1411),
        CBinaryOp(
            "Add",
            CBinaryOp(
                "Add",
                CBinaryOp(
                    "Shr",
                    _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4),
                    _const(16, codegen),
                    codegen=codegen,
                ),
                tmp(1404),
                codegen=codegen,
            ),
            tmp(1408),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    ptr_arg = tmp(1387)
    self_ptr_lhs = CFunctionCall("MK_FP", None, [ptr_arg, _const(0, codegen)], codegen=codegen)
    self_ptr_rhs = CFunctionCall("MK_FP", None, [ptr_arg, _const(0, codegen)], codegen=codegen)
    self_pointer_carrier = CAssignment(self_ptr_lhs, self_ptr_rhs, codegen=codegen)
    upper_word = CAssignment(_mem_word(0x134, codegen, name="mem_0134"), tmp(1411), codegen=codegen)
    trailing_flag = CAssignment(tmp(1487), CBinaryOp("Xor", tmp(1411), _const(0, codegen), codegen=codegen), codegen=codegen)
    root = CStatements(
        [low_byte, carry_seed, carry_flags, high_word_tmp, self_pointer_carrier, upper_word, trailing_flag],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert assignment.lhs.variable.size == 4
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.lhs.variable.name == "clPause"
    assert assignment.rhs.rhs.value == 30
    assert stats.direct_symbol_update_materialized_count == 1


def test_direct_global_dword_update_folds_long_msc_flag_suffix_after_scalar_store():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)

    def tmp(varid: int):
        return _dirty(varid, codegen)

    cl_pause = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    low_rhs = CBinaryOp(
        "Add",
        CBinaryOp("And", cl_pause, _const(0xFFFF, codegen), codegen=codegen),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(_make_direct_global_symbol_expr_8616(codegen, low_ref, 2), low_rhs, codegen=codegen)
    carry = CAssignment(tmp(5000), _const(0, codegen), codegen=codegen)
    upper_rhs = CBinaryOp(
        "Or",
        CBinaryOp("And", cl_pause, _const(0xFFFF, codegen), codegen=codegen),
        CBinaryOp(
            "Shl",
            CBinaryOp(
                "And",
                CBinaryOp(
                    "Add",
                    CBinaryOp("Shr", cl_pause, _const(16, codegen), codegen=codegen),
                    tmp(5000),
                    codegen=codegen,
                ),
                _const(0xFFFF, codegen),
                codegen=codegen,
            ),
            _const(16, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    upper = CAssignment(cl_pause, upper_rhs, codegen=codegen)
    suffix = [CAssignment(tmp(5001), tmp(5000), codegen=codegen)]
    for index in range(5002, 5088):
        suffix.append(CAssignment(tmp(index), tmp(index - 1), codegen=codegen))  # noqa: PERF401
    root = CStatements([low, carry, upper, *suffix], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.rhs.value == 30
    assert stats.direct_symbol_update_materialized_count == 1


def test_direct_global_dword_update_consumes_consecutive_scalar_high_word_writes():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)

    def dword():
        return _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)

    def masked_scalar(mask: int):
        return CBinaryOp("And", dword(), _const(mask, codegen), codegen=codegen)

    low_update = CAssignment(
        dword(),
        CBinaryOp(
            "Or",
            masked_scalar(0xFFFF0000),
            CBinaryOp(
                "And",
                CBinaryOp("Add", masked_scalar(0xFFFF), _const(30, codegen), codegen=codegen),
                _const(0xFFFF, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    high_word = _dirty(1401, codegen)
    high_byte = _dirty(1415, codegen)
    high_word_copy = CAssignment(high_word, _const(0, codegen), codegen=codegen)
    high_byte_copy = CAssignment(high_byte, _const(0, codegen), codegen=codegen)

    def high_store(value):
        return CAssignment(
            dword(),
            CBinaryOp(
                "Or",
                masked_scalar(0xFFFF),
                CBinaryOp("Shl", value, _const(16, codegen), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        )

    root = CStatements(
        [low_update, high_word_copy, high_store(high_word), high_byte_copy, high_store(high_byte)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.rhs.value == 30
    assert stats.direct_symbol_update_materialized_count == 1


def test_direct_global_dword_update_folds_dword_indexed_subword_lvalues():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    cl_pause = CVariable(SimMemoryVariable(0x132, 4, name="clPause"), codegen=codegen)
    low_lvalue = CIndexedVariable(cl_pause, _const(0, codegen), codegen=codegen)
    high_lvalue = CIndexedVariable(cl_pause, _const(1, codegen), codegen=codegen)
    low_rhs = CBinaryOp(
        "Add",
        CBinaryOp(
            "And",
            _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4),
            _const(0xFFFF, codegen),
            codegen=codegen,
        ),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(low_lvalue, low_rhs, codegen=codegen)
    carry_seed = CAssignment(_dirty(1404, codegen), _const(0, codegen), codegen=codegen)
    high = CAssignment(
        high_lvalue,
        CBinaryOp(
            "Add",
            CBinaryOp(
                "Shr",
                _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4),
                _const(16, codegen),
                codegen=codegen,
            ),
            _dirty(1404, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([low, carry_seed, high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.rhs.value == 30
    assert stats.direct_symbol_update_materialized_count == 1


def test_direct_global_dword_update_ignores_unrelated_dirty_oident_collision():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "g_0132", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    cl_pause = CVariable(SimMemoryVariable(0x132, 4, name="clPause"), codegen=codegen)
    low_lvalue = CIndexedVariable(cl_pause, _const(0, codegen), codegen=codegen)
    high_lvalue = CIndexedVariable(cl_pause, _const(1, codegen), codegen=codegen)
    low_rhs = CBinaryOp(
        "Add",
        CBinaryOp("And", _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4), _const(0xFFFF, codegen), codegen=codegen),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(low_lvalue, low_rhs, codegen=codegen)
    colliding_gap_carrier = CAssignment(_dirty_with_oident(1374, 12, codegen), _const(0, codegen), codegen=codegen)
    high = CAssignment(
        high_lvalue,
        CBinaryOp(
            "Add",
            CBinaryOp("Shr", _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4), _const(16, codegen), codegen=codegen),
            _dirty_with_oident(1374, 12, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    unrelated_live_use = CExpressionStatement(
        CFunctionCall("sink", None, [_dirty_with_oident(16, 12, codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low, colliding_gap_carrier, high, unrelated_live_use], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 2
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert root.statements[1] is unrelated_live_use


def test_direct_global_store_removes_tuple_switch_segment_pointer_self_assignment():
    codegen = _DummyCodegen()
    direct_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    ptr_arg = _dirty(1387, codegen)
    self_ptr_lhs = CFunctionCall("MK_FP", None, [ptr_arg, _const(0, codegen)], codegen=codegen)
    self_ptr_rhs = CFunctionCall("MK_FP", None, [ptr_arg, _const(0, codegen)], codegen=codegen)
    self_pointer_carrier = CAssignment(self_ptr_lhs, self_ptr_rhs, codegen=codegen)
    live_assignment = CAssignment(_dirty(1, codegen), _const(7, codegen), codegen=codegen)
    case_body = CStatements([self_pointer_carrier, live_assignment], codegen=codegen)
    switch = CSwitchCase(_dirty(2, codegen), [(33, case_body)], None, codegen=codegen)
    root = CStatements([switch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (direct_ref,),
        stats=stats,
    )

    assert changed is True
    assert case_body.statements == [live_assignment]
    assert stats.direct_symbol_segment_pointer_self_assignment_removed_count == 1


def test_direct_global_dword_update_preserves_live_carriers_while_removing_high_byte_stores():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)

    def tmp(varid: int):
        return _dirty(varid, codegen)

    low_value = CBinaryOp(
        "Add",
        _make_direct_global_symbol_expr_8616(codegen, low_ref, 2),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(_make_direct_global_symbol_expr_8616(codegen, low_ref, 2), low_value, codegen=codegen)
    carry_seed = CAssignment(tmp(2043), _const(0, codegen), codegen=codegen)
    high_word = CAssignment(
        tmp(2050),
        CBinaryOp(
            "Add",
            CBinaryOp("Shr", _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4), _const(16, codegen), codegen=codegen),
            tmp(2043),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    high_low = CAssignment(_mem(0x134, codegen, name="mem_0134"), tmp(2050), codegen=codegen)
    high_high = CAssignment(_mem(0x135, codegen, name="mem_0135"), _const(0, codegen), codegen=codegen)
    live_use = CExpressionStatement(CFunctionCall("sink", None, [tmp(2050)], codegen=codegen), codegen=codegen)
    root = CStatements([low, carry_seed, high_word, high_low, high_high, live_use], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, 30),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 4
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.lhs.variable.name == "clPause"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert root.statements[1] is carry_seed
    assert root.statements[2] is high_word
    assert root.statements[3] is live_use


def test_direct_global_dword_update_folds_low_word_sub_with_high_byte_pair():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    low_value = CBinaryOp(
        "Sub",
        _make_direct_global_symbol_expr_8616(codegen, low_ref, 2),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(_make_direct_global_symbol_expr_8616(codegen, low_ref, 2), low_value, codegen=codegen)
    high_low = CAssignment(_mem(0x134, codegen, name="mem_0134"), _mem(0x134, codegen), codegen=codegen)
    high_high = CAssignment(
        _mem(0x135, codegen, name="mem_0135"),
        CBinaryOp("Shr", _mem(0x134, codegen), _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low, high_low, high_high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, -30),),
        stats=stats,
    )

    assert changed is True
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Sub"
    assert assignment.rhs.rhs.value == 30


def test_direct_global_dword_update_selects_matching_delta_from_mixed_evidence():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    low_value = CBinaryOp(
        "Sub",
        _make_direct_global_symbol_expr_8616(codegen, low_ref, 2),
        _const(30, codegen),
        codegen=codegen,
    )
    low = CAssignment(_make_direct_global_symbol_expr_8616(codegen, low_ref, 2), low_value, codegen=codegen)
    high_low = CAssignment(_mem(0x134, codegen, name="mem_0134"), _mem(0x134, codegen), codegen=codegen)
    high_high = CAssignment(
        _mem(0x135, codegen, name="mem_0135"),
        CBinaryOp("Shr", _mem(0x134, codegen), _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([low, high_low, high_high], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(
            DirectGlobalUpdateEvidence8616(0x132, 2, 30),
            DirectGlobalUpdateEvidence8616(0x132, 2, -30),
        ),
        stats=stats,
    )

    assert changed is True
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Sub"
    assert assignment.rhs.rhs.value == 30


def test_direct_global_low_word_store_to_dword_scalar_emits_preserving_scalar_assignment():
    codegen = _DummyCodegen()
    low_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 2, 2)
    high_ref = DirectGlobalSymbolRef8616(0x134, "clPause", 2, 2, 2)
    dword_ref = DirectGlobalSymbolRef8616(0x132, "clPause", 0, 4, 0)
    low_lvalue = _make_direct_global_symbol_expr_8616(codegen, low_ref, 2)
    low_rhs = CBinaryOp(
        "Sub",
        _make_direct_global_symbol_expr_8616(codegen, low_ref, 2),
        _const(30, codegen),
        codegen=codegen,
    )
    assignment = CAssignment(low_lvalue, low_rhs, codegen=codegen)
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (low_ref, high_ref, dword_ref),
        direct_updates=(DirectGlobalUpdateEvidence8616(0x132, 2, -30),),
        stats=stats,
    )

    assert changed is True
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "clPause"
    assert assignment.lhs.variable.size == 4
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Or"
    assert isinstance(assignment.rhs.lhs, CBinaryOp)
    assert assignment.rhs.lhs.op == "And"
    assert assignment.rhs.lhs.lhs.variable.name == "clPause"
    assert assignment.rhs.lhs.rhs.value == 0xFFFF0000
    assert isinstance(assignment.rhs.rhs, CBinaryOp)
    assert assignment.rhs.rhs.op == "And"
    assert isinstance(assignment.rhs.rhs.lhs, CTypeCast)
    casted_update = assignment.rhs.rhs.lhs.expr
    assert isinstance(casted_update, CBinaryOp)
    assert casted_update.op == "Sub"
    assert isinstance(casted_update.lhs, CBinaryOp)
    assert casted_update.lhs.op == "And"
    assert casted_update.lhs.lhs.variable.name == "clPause"
    assert casted_update.rhs.value == 30
    assert stats.direct_symbol_store_materialized_count == 1


def test_direct_global_word_store_evidence_widens_low_byte_lvalue():
    codegen = _DummyCodegen()
    ref = DirectGlobalSymbolRef8616(0xB46, "fSound", 0, 2, 0)
    assignment = CAssignment(_mem(0xB46, codegen, name="mem_0B46"), _const(1, codegen), codegen=codegen)
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (ref,),
        stats=stats,
    )

    assert changed is True
    assert assignment.lhs.variable.name == "fSound"
    assert assignment.lhs.variable.size == 2
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned short", "fSound", None),)


def test_collect_direct_global_boolean_store_evidence_from_sbb_neg_idiom():
    summaries = [
        InsnSummary8616(
            "cmp",
            op0_kind="direct_mem",
            op0_value=0xB46,
            op1_kind="imm",
            op1_value=1,
            op0_size=2,
            address=0x10418,
        ),
        InsnSummary8616(
            "sbb",
            op0_kind="reg",
            op0_value="ax",
            op1_kind="reg",
            op1_value="ax",
            op0_size=2,
            op1_size=2,
            address=0x1041D,
        ),
        InsnSummary8616(
            "neg",
            op0_kind="reg",
            op0_value="ax",
            op0_size=2,
            address=0x1041F,
        ),
        InsnSummary8616(
            "mov",
            op0_kind="direct_mem",
            op0_value=0xB46,
            op1_kind="reg",
            op1_value="ax",
            op0_size=2,
            op1_size=2,
            address=0x1234,
        ),
    ]

    evidence = _collect_direct_global_boolean_store_evidence_8616(summaries)

    assert evidence == (
        DirectGlobalBooleanStoreEvidence8616(
            source_offset=0xB46,
            source_width=2,
            compare_value=1,
            dest_offset=0xB46,
            dest_width=2,
            store_ins_addr=0x1234,
            compare_ins_addr=0x10418,
            sbb_ins_addr=0x1041D,
            neg_ins_addr=0x1041F,
        ),
    )
    assert evidence[0].carrier_ins_addrs == (0x10418, 0x1041D, 0x1041F)


def test_sidecar_free_boolean_store_refs_cover_source_and_destination():
    evidence = (
        DirectGlobalBooleanStoreEvidence8616(
            source_offset=0xB46,
            source_width=2,
            compare_value=1,
            dest_offset=0xB48,
            dest_width=2,
            store_ins_addr=0x10421,
        ),
    )

    assert _sidecar_free_boolean_store_refs_8616(evidence) == (
        DirectGlobalSymbolRef8616(0xB46, "g_0B46", 0, 2, 0),
        DirectGlobalSymbolRef8616(0xB48, "g_0B48", 0, 2, 0),
    )


def test_direct_global_boolean_store_evidence_materializes_explicit_condition_assignment():
    codegen = _DummyCodegen()
    ref = DirectGlobalSymbolRef8616(0xB46, "fSound", 0, 2, 0)
    assignment = CAssignment(
        _mem_word(0xB46, codegen, name="mem_0B46"),
        _reg(SimpleNamespace(arch=Arch86_16()), codegen, "ax"),
        codegen=codegen,
        tags={"ins_addr": 0x1234},
    )
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (ref,),
        direct_boolean_stores=(
            DirectGlobalBooleanStoreEvidence8616(
                source_offset=0xB46,
                source_width=2,
                compare_value=1,
                dest_offset=0xB46,
                dest_width=2,
                store_ins_addr=0x1234,
                compare_ins_addr=0x10418,
                sbb_ins_addr=0x1041D,
                neg_ins_addr=0x1041F,
            ),
        ),
        stats=stats,
    )

    assert changed is True
    assert assignment.lhs.variable.name == "fSound"
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "CmpLT"
    assert assignment.rhs.lhs.variable.name == "fSound"
    assert assignment.rhs.rhs.value == 1
    assert stats.direct_symbol_boolean_store_materialized_count == 1
    assert (
        codegen._inertia_consumed_direct_global_boolean_carrier_ins_addrs_8616
        == frozenset({0x10418, 0x1041D, 0x1041F})
    )


def test_direct_global_boolean_store_prunes_same_instruction_switch_artifact():
    codegen = _DummyCodegen()
    ref = DirectGlobalSymbolRef8616(0xB46, "fSound", 0, 2, 0)
    canonical = CAssignment(
        _mem_word(0xB46, codegen, name="mem_0B46"),
        _reg(SimpleNamespace(arch=Arch86_16()), codegen, "ax"),
        codegen=codegen,
        tags={"ins_addr": 0x1234},
    )
    duplicate = CAssignment(
        _mem_word(0xB46, codegen, name="mem_0B46"),
        CBinaryOp(
            "Or",
            CBinaryOp("And", _dirty(521, codegen), _const(0xFF, codegen), codegen=codegen),
            CBinaryOp(
                "Shl",
                CBinaryOp(
                    "And",
                    CBinaryOp("Shr", _dirty(521, codegen), _const(8, codegen), codegen=codegen),
                    _const(0xFF, codegen),
                    codegen=codegen,
                ),
                _const(8, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x1234},
    )
    case_body = CStatements([canonical, duplicate], codegen=codegen)
    switch = CSwitchCase(_dirty(2, codegen), [(84, case_body)], None, codegen=codegen)
    root = CStatements([switch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (ref,),
        direct_boolean_stores=(
            DirectGlobalBooleanStoreEvidence8616(0xB46, 2, 1, 0xB46, 2, store_ins_addr=0x1234),
        ),
        stats=stats,
    )

    assert changed is True
    assert case_body.statements == [canonical]
    assert canonical.rhs.op == "CmpLT"
    assert stats.direct_symbol_boolean_duplicate_pruned_count == 1


def test_direct_global_boolean_store_keeps_different_instruction_assignment():
    codegen = _DummyCodegen()
    ref = DirectGlobalSymbolRef8616(0xB46, "fSound", 0, 2, 0)
    canonical = CAssignment(
        _mem_word(0xB46, codegen, name="mem_0B46"),
        _reg(SimpleNamespace(arch=Arch86_16()), codegen, "ax"),
        codegen=codegen,
        tags={"ins_addr": 0x1234},
    )
    independent = CAssignment(
        _mem_word(0xB46, codegen, name="mem_0B46"),
        _const(7, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1235},
    )
    root = CStatements([canonical, independent], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (ref,),
        direct_boolean_stores=(
            DirectGlobalBooleanStoreEvidence8616(0xB46, 2, 1, 0xB46, 2, store_ins_addr=0x1234),
        ),
        stats=stats,
    )

    assert changed is True
    assert root.statements == [canonical, independent]
    assert stats.direct_symbol_boolean_duplicate_pruned_count == 0


def test_direct_global_boolean_store_removes_stale_high_byte_merge():
    codegen = _DummyCodegen()
    ref = DirectGlobalSymbolRef8616(0xB46, "fSound", 0, 2, 0)
    f_sound = _make_direct_global_symbol_expr_8616(codegen, ref, 2)
    flag_carrier = _dirty(523, codegen)
    bool_store = CAssignment(
        f_sound,
        CBinaryOp("CmpLT", f_sound, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    high_merge = CAssignment(
        _make_direct_global_symbol_expr_8616(codegen, ref, 2),
        CBinaryOp(
            "Or",
            CBinaryOp(
                "And",
                _make_direct_global_symbol_expr_8616(codegen, ref, 2),
                _const(0xFF, codegen),
                codegen=codegen,
            ),
            CBinaryOp(
                "Shl",
                CBinaryOp(
                    "And",
                    CBinaryOp("Shr", flag_carrier, _const(8, codegen), codegen=codegen),
                    _const(0xFF, codegen),
                    codegen=codegen,
                ),
                _const(8, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    live_assignment = CAssignment(_dirty(1, codegen), _const(7, codegen), codegen=codegen)
    root = CStatements([bool_store, high_merge, live_assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (ref,),
        direct_boolean_stores=(DirectGlobalBooleanStoreEvidence8616(0xB46, 2, 1, 0xB46, 2),),
        stats=stats,
    )

    assert changed is True
    assert root.statements == [bool_store, live_assignment]
    assert stats.direct_symbol_boolean_store_materialized_count >= 1


def test_synthetic_direct_global_refs_require_matching_direct_memory_operand():
    summaries = [
        InsnSummary8616("inc", op0_kind="direct_mem", op0_value=0xBAA, op0_size=2),
        InsnSummary8616("mov", op0_kind="reg", op0_value="ax", op1_kind="direct_mem", op1_value=0xBC0, op1_size=1),
    ]

    refs = _collect_synthetic_direct_global_symbol_refs_8616(
        {
            0xBAA: ("iCompares", 2),
            0xBC0: ("byteGlobal", 2),
            0xBEE: ("notAccessed", 2),
        },
        summaries,
    )

    assert refs == (
        DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0),
        DirectGlobalSymbolRef8616(0xBC0, "byteGlobal", 0, 1, 1),
    )


def test_synthetic_direct_global_ref_materializes_segment_helper_load():
    class _Memory:
        def load(self, addr, size):
            assert addr == 0x4010
            # cmp word ptr [0x0ba2], ax
            return b"\x39\x06\xa2\x0b"[:size]

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(labels={}),
        loader=SimpleNamespace(memory=_Memory()),
    )
    codegen = _DummyCodegen()
    segment_carrier = CVariable(
        SimRegisterVariable(0x77, 2, name="v6"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    rhs = CFunctionCall("SEG_U16", None, [segment_carrier, _const(0xBA2, codegen)], codegen=codegen)
    assignment = CAssignment(_stack(-2, codegen), rhs, codegen=codegen)
    root = CStatements([assignment], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, size=4, statements=root, body=root)

    changed = materialize_named_segmented_global_loads_8616(
        project,
        codegen,
        {0xBA2: ("cRow", 2)},
    )

    assert changed is True
    assert isinstance(assignment.rhs, CVariable)
    assert assignment.rhs.name == "cRow"
    stats = codegen._inertia_segmented_global_load_stats_8616
    assert stats.direct_symbol_raw_fact_count == 1
    assert stats.direct_symbol_materialized_count == 1


def test_direct_global_symbol_store_drops_redundant_high_byte_projection():
    codegen = _DummyCodegen()
    v12 = CVariable(SimRegisterVariable(12, 2, name="v12"), variable_type=SimTypeShort(False), codegen=codegen)
    v13 = CVariable(SimRegisterVariable(13, 2, name="v13"), variable_type=SimTypeShort(False), codegen=codegen)
    word_value = CBinaryOp(
        "Add",
        CBinaryOp(
            "Or",
            v12,
            CBinaryOp("Mul", v13, CConstant(0x100, SimTypeShort(False), codegen=codegen), codegen=codegen),
            codegen=codegen,
        ),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    word_store = CAssignment(_mem_word(0xBAA, codegen, name="g_0baa"), word_value, codegen=codegen)
    high_store = CAssignment(
        _mem(0xBAB, codegen, name="mem_0bab"),
        CBinaryOp("Shr", word_value, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([word_store, high_store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.addr == 0xBAA
    assert assignment.rhs is word_value
    assert stats.direct_symbol_store_materialized_count == 1


def test_direct_global_high_byte_cleanup_visits_shared_ast_node_once(monkeypatch):
    codegen = _DummyCodegen()
    shared_statement = SimpleNamespace()
    shared_body = CStatements([shared_statement, SimpleNamespace()], codegen=codegen)
    root = CStatements(
        [SimpleNamespace(body=shared_body), SimpleNamespace(body=shared_body)],
        codegen=codegen,
    )
    visits = 0

    def record_visit(stmt, _codegen, _direct_by_offset, **_kwargs):
        nonlocal visits
        if stmt is shared_statement:
            visits += 1
        return None, None

    monkeypatch.setattr(
        segmented_global_loads_module,
        "_direct_global_word_assignment_8616",
        record_visit,
    )

    changed = segmented_global_loads_module._remove_direct_global_redundant_high_byte_stores_8616(
        root,
        codegen,
        {},
        SegmentedGlobalLoadStats8616(),
    )

    assert changed is False
    assert visits == 1


def test_direct_global_high_byte_cleanup_reuses_comparison_expressions(monkeypatch):
    codegen = _DummyCodegen()
    lhs = SimpleNamespace()
    root = CStatements(
        [
            CAssignment(lhs, _const(1, codegen), codegen=codegen),
            SimpleNamespace(),
            CAssignment(lhs, _const(2, codegen), codegen=codegen),
            SimpleNamespace(),
        ],
        codegen=codegen,
    )
    ref = DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0)
    constructions = 0

    def make_comparison(*_args, **_kwargs):
        nonlocal constructions
        constructions += 1
        return SimpleNamespace()

    monkeypatch.setattr(
        segmented_global_loads_module,
        "_make_direct_global_symbol_expr_8616",
        make_comparison,
    )

    changed = segmented_global_loads_module._remove_direct_global_redundant_high_byte_stores_8616(
        root,
        codegen,
        {(0xBAA, 2): ref},
        SegmentedGlobalLoadStats8616(),
    )

    assert changed is False
    assert constructions == 1


def test_direct_global_word_assignment_uses_exact_identity_before_expression_fallback(monkeypatch):
    codegen = _DummyCodegen()
    rhs = _const(7, codegen)
    assignment = CAssignment(_mem_word(0xBAA, codegen, name="iCompares"), rhs, codegen=codegen)
    ref = DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0)

    def refuse_fallback(*_args, **_kwargs):
        raise AssertionError("exact direct-global identity must not use expression fallback")

    monkeypatch.setattr(
        segmented_global_loads_module,
        "_make_direct_global_symbol_expr_8616",
        refuse_fallback,
    )

    matched_ref, matched_rhs = segmented_global_loads_module._direct_global_word_assignment_8616(
        assignment,
        codegen,
        {(0xBAA, 2): ref},
    )

    assert matched_ref is ref
    assert matched_rhs is rhs


def test_direct_global_symbol_store_materializes_segment_helper_lvalue_and_drops_high_byte_projection():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    segment = _reg(project, codegen, "ds")
    word_load = CFunctionCall("SEG_U16", None, [segment, _const(0xBAA, codegen)], codegen=codegen)
    word_value = CBinaryOp("Add", word_load, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen)
    word_store = CAssignment(
        CFunctionCall("SEG_U16", None, [segment, _const(0xBAA, codegen)], codegen=codegen),
        word_value,
        codegen=codegen,
    )
    high_store = CAssignment(
        CFunctionCall("SEG_U8", None, [segment, _const(0xBAB, codegen)], codegen=codegen),
        CBinaryOp("Shr", word_value, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([word_store, high_store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0),),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "iCompares"
    assert assignment.rhs is word_value
    assert stats.direct_symbol_store_materialized_count == 2


def test_direct_global_symbol_store_drops_redundant_for_initializer_high_byte_projection():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    segment = _reg(project, codegen, "ds")
    global_word = _mem_word(0xBAA, codegen, name="iCompares")
    word_value = CBinaryOp(
        "Add",
        global_word,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    word_store = CAssignment(global_word, word_value, codegen=codegen)
    initializer_value = CBinaryOp(
        "Add",
        CFunctionCall("SEG_U16", None, [segment, _const(0xBAA, codegen)], codegen=codegen),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    initializer = CAssignment(
        CFunctionCall("SEG_U8", None, [segment, _const(0xBAB, codegen)], codegen=codegen),
        CBinaryOp("Shr", initializer_value, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    loop = CForLoop(initializer, CConstant(1, SimTypeShort(False), codegen=codegen), None, CStatements([], codegen=codegen), codegen=codegen)
    root = CStatements([word_store, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (DirectGlobalSymbolRef8616(0xBAA, "iCompares", 0, 2, 0),),
        stats=stats,
    )

    assert changed is True
    assert loop.initializer is None
    assert stats.direct_symbol_store_materialized_count == 1

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CStatements,
    CStructField,
    CSwitchCase,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.lowering.segmented_global_loads import (
    DirectSegmentedGlobalStoreEvidence8616,
    materialize_direct_global_symbol_stores_from_evidence_8616,
)
from archinfo import ArchX86

from inertia.validation.tail_validation import (
    refresh_x86_16_final_semantic_validation_8616,
    x86_16_tail_validation_snapshot_passed,
)
from inertia.validation.validation_required_memory_effects import (
    validate_required_memory_effects_8616,
)
from inertia.widening.segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_tags_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=ArchX86())
        root = CStatements([], codegen=self)
        self.cfunc = SimpleNamespace(
            addr=0x1000,
            arg_list=[],
            statements=root,
            variables_in_use={},
            unified_local_vars={},
        )
        self._inertia_required_direct_segmented_global_stores_8616 = ()
        self._inertia_tail_validation_snapshot = {}

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _required_store() -> DirectSegmentedGlobalStoreEvidence8616:
    return DirectSegmentedGlobalStoreEvidence8616(
        offset=0x134,
        width=2,
        space=MemSpace.DS,
        ins_addr=0x10588,
    )


def _segment_variable(codegen: _Codegen, segment_name: str) -> CVariable:
    return CVariable(
        SimRegisterVariable(
            codegen.project.arch.registers[segment_name][0],
            2,
            name=segment_name,
        ),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _seg_store(
    codegen: _Codegen,
    *,
    segment_name: str,
    offset: int,
    width: int,
) -> CAssignment:
    helper_name = {1: "SEG_U8", 2: "SEG_U16"}[width]
    lvalue = CFunctionCall(
        helper_name,
        None,
        [
            _segment_variable(codegen, segment_name),
            CConstant(offset, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    return CAssignment(
        lvalue,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10588},
    )


def _indexed_seg_store(
    codegen: _Codegen,
    *,
    segment_name: str = "ds",
    base: int = 0x356,
    ins_addr: int | None = 0x11195,
) -> CAssignment:
    """Build one byte store through a typed additive segmented offset."""
    index = CVariable(
        SimRegisterVariable(codegen.project.arch.registers["si"][0], 2, name="si"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    offset = CBinaryOp(
        "Add",
        CConstant(base, SimTypeShort(False), codegen=codegen),
        index,
        codegen=codegen,
    )
    lvalue = CFunctionCall(
        "SEG_U8",
        None,
        [_segment_variable(codegen, segment_name), offset],
        codegen=codegen,
    )
    tags = {"ins_addr": ins_addr} if ins_addr is not None else None
    return CAssignment(
        lvalue,
        CConstant(0, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags=tags,
    )


def _nested_segment_store(codegen: _Codegen, source_offset: int) -> CAssignment:
    """Build one ES store whose exact runtime segment comes from DS memory."""
    source = CFunctionCall(
        "SEG_U16",
        None,
        [_segment_variable(codegen, "ds"), CConstant(source_offset, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
        tags=segmented_load_tags_8616(
            SegmentedLoadIdentity8616(MemSpace.DS, source_offset, 2, codegen.cfunc.addr)
        ),
    )
    lvalue = CFunctionCall(
        "SEG_U16",
        None,
        [source, CConstant(2, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
        tags=segmented_load_tags_8616(
            SegmentedLoadIdentity8616(MemSpace.ES, 2, 2, codegen.cfunc.addr)
        ),
    )
    return CAssignment(lvalue, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)


def _segment_source(offset: int) -> IRAddress:
    """Build the typed DS source used by a required far-memory effect."""
    return IRAddress(
        MemSpace.DS,
        offset=offset,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _validate(codegen: _Codegen):
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        _required_store(),
    )
    return validate_required_memory_effects_8616(
        codegen.project,
        codegen,
        codegen.cfunc.statements,
    )


def test_required_memory_effect_reports_missing_binary_proven_store() -> None:
    codegen = _Codegen()

    report = _validate(codegen)

    assert report.passed is False
    assert report.materialized_count == 0
    assert report.failure_count == 1
    assert report.issue_tokens() == (
        "missing-required-memory-write:ds:0x0134:width=2:ins=0x10588",
    )


def test_direct_store_lowering_publishes_final_memory_obligations() -> None:
    codegen = _Codegen()
    required = _required_store()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        (),
        anonymous_direct_stores=(required,),
        project=codegen.project,
    )

    assert changed is False
    assert codegen._inertia_required_direct_segmented_global_stores_8616 == (
        required,
    )
    assert _validate(codegen).passed is False


def test_required_memory_effect_accepts_exact_word_store() -> None:
    codegen = _Codegen()
    codegen.cfunc.statements.statements.append(
        _seg_store(codegen, segment_name="ds", offset=0x134, width=2)
    )

    report = _validate(codegen)

    assert report.passed is True
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_required_memory_effect_accepts_two_exact_byte_stores() -> None:
    codegen = _Codegen()
    codegen.cfunc.statements.statements.extend(
        (
            _seg_store(codegen, segment_name="ds", offset=0x134, width=1),
            _seg_store(codegen, segment_name="ds", offset=0x135, width=1),
        )
    )

    report = _validate(codegen)

    assert report.passed is True
    assert report.materialized_count == 1


def test_required_memory_effect_accepts_same_instruction_affine_store() -> None:
    codegen = _Codegen()
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        DirectSegmentedGlobalStoreEvidence8616(
            offset=0x356,
            width=1,
            space=MemSpace.DS,
            ins_addr=0x11195,
        ),
    )
    codegen.cfunc.statements.statements.append(_indexed_seg_store(codegen))

    report = validate_required_memory_effects_8616(
        codegen.project,
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is True
    assert report.materialized_count == 1


@pytest.mark.parametrize(
    ("segment_name", "base", "ins_addr"),
    (("es", 0x356, 0x11195), ("ds", 0x357, 0x11195), ("ds", 0x356, None)),
)
def test_required_memory_effect_rejects_unproven_affine_store(
    segment_name: str,
    base: int,
    ins_addr: int | None,
) -> None:
    codegen = _Codegen()
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        DirectSegmentedGlobalStoreEvidence8616(
            offset=0x356,
            width=1,
            space=MemSpace.DS,
            ins_addr=0x11195,
        ),
    )
    codegen.cfunc.statements.statements.append(
        _indexed_seg_store(
            codegen,
            segment_name=segment_name,
            base=base,
            ins_addr=ins_addr,
        )
    )

    report = validate_required_memory_effects_8616(
        codegen.project,
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.materialized_count == 0


def test_required_memory_effect_accepts_typed_ds_global_store() -> None:
    codegen = _Codegen()
    codegen.cfunc.statements.statements.append(
        CAssignment(
            CVariable(
                SimMemoryVariable(0x134, 2, name="counter", region=0x1000),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": 0x10588},
        )
    )

    assert _validate(codegen).passed is True


def test_required_memory_effect_accepts_nested_aggregate_field_store() -> None:
    codegen = _Codegen()
    byte_fields = SimStruct(
        {"low": SimTypeChar(False), "high": SimTypeChar(False)},
        name="ByteFields",
        pack=True,
    ).with_arch(codegen.project.arch)
    aggregate = SimStruct(
        {"bytes": byte_fields},
        name="Aggregate",
        pack=True,
    ).with_arch(codegen.project.arch)
    base = CVariable(
        SimMemoryVariable(0x134, 2, name="aggregate", region=0x1000),
        variable_type=aggregate,
        codegen=codegen,
    )
    bytes_field = CVariableField(
        base,
        CStructField(aggregate, 0, "bytes", codegen=codegen),
        codegen=codegen,
    )
    high_field = CVariableField(
        bytes_field,
        CStructField(byte_fields, 1, "high", codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(
        CAssignment(
            high_field,
            CConstant(0, SimTypeChar(False), codegen=codegen),
            codegen=codegen,
        )
    )
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        DirectSegmentedGlobalStoreEvidence8616(
            offset=0x135,
            width=1,
            space=MemSpace.DS,
            ins_addr=0x10588,
        ),
    )

    report = validate_required_memory_effects_8616(
        codegen.project,
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is True
    assert report.materialized_count == 1


def test_required_memory_effect_accepts_widened_adjacent_word_stores() -> None:
    codegen = _Codegen()
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        DirectSegmentedGlobalStoreEvidence8616(
            offset=0xBA6,
            width=2,
            space=MemSpace.DS,
            ins_addr=0x10686,
        ),
        DirectSegmentedGlobalStoreEvidence8616(
            offset=0xBA8,
            width=2,
            space=MemSpace.DS,
            ins_addr=0x10689,
        ),
    )
    codegen.cfunc.statements.statements.append(
        CAssignment(
            CVariable(
                SimMemoryVariable(0xBA6, 2, name="clock_value", region=0x1000),
                variable_type=SimTypeLong(False),
                codegen=codegen,
            ),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    )

    report = validate_required_memory_effects_8616(
        codegen.project,
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is True
    assert report.materialized_count == 2


def test_required_memory_effect_preserves_repeated_write_multiplicity() -> None:
    codegen = _Codegen()
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        _required_store(),
        DirectSegmentedGlobalStoreEvidence8616(
            offset=0x134,
            width=2,
            space=MemSpace.DS,
            ins_addr=0x10590,
        ),
    )
    codegen.cfunc.statements.statements.append(
        _seg_store(codegen, segment_name="ds", offset=0x134, width=2)
    )

    report = validate_required_memory_effects_8616(
        codegen.project,
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.materialized_count == 1
    assert report.failure_count == 1


def test_required_memory_effect_counts_writes_in_distinct_switch_cases() -> None:
    codegen = _Codegen()
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        _required_store(),
        DirectSegmentedGlobalStoreEvidence8616(
            offset=0x134, width=2, space=MemSpace.DS, ins_addr=0x10590
        ),
    )
    cases = [
        (value, CStatements([_seg_store(codegen, segment_name="ds", offset=0x134, width=2)], codegen=codegen))
        for value in (1, 2)
    ]
    codegen.cfunc.statements.statements.append(
        CSwitchCase(CConstant(0, SimTypeShort(False), codegen=codegen), cases, None, codegen=codegen)
    )

    report = validate_required_memory_effects_8616(
        codegen.project, codegen, codegen.cfunc.statements
    )

    assert report.passed is True
    assert report.materialized_count == 2


def test_required_memory_effect_counts_writes_in_if_and_else_branches() -> None:
    codegen = _Codegen()
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        _required_store(),
        DirectSegmentedGlobalStoreEvidence8616(
            offset=0x134, width=2, space=MemSpace.DS, ins_addr=0x10590
        ),
    )
    true_node = CStatements(
        [_seg_store(codegen, segment_name="ds", offset=0x134, width=2)],
        codegen=codegen,
    )
    else_node = CStatements(
        [_seg_store(codegen, segment_name="ds", offset=0x134, width=2)],
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(
        CIfElse(
            [(CConstant(1, SimTypeShort(False), codegen=codegen), true_node)],
            else_node=else_node,
            codegen=codegen,
        )
    )

    report = validate_required_memory_effects_8616(
        codegen.project, codegen, codegen.cfunc.statements
    )

    assert report.passed is True
    assert report.materialized_count == 2


@pytest.mark.parametrize(
    ("segment_name", "offset"),
    (("es", 0x134), ("ds", 0x135)),
)
def test_required_memory_effect_rejects_cross_segment_or_partial_coverage(
    segment_name: str,
    offset: int,
) -> None:
    codegen = _Codegen()
    codegen.cfunc.statements.statements.append(
        _seg_store(codegen, segment_name=segment_name, offset=offset, width=1)
    )

    report = _validate(codegen)

    assert report.passed is False
    assert report.materialized_count == 0


def test_required_memory_effect_rejects_collapsed_runtime_segment_sources() -> None:
    codegen = _Codegen()
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        DirectSegmentedGlobalStoreEvidence8616(
            2, 2, MemSpace.ES, 0x1004, segment_source=_segment_source(0x700A)
        ),
        DirectSegmentedGlobalStoreEvidence8616(
            2, 2, MemSpace.ES, 0x100F, segment_source=_segment_source(0x700C)
        ),
    )
    codegen.cfunc.statements.statements.extend(
        (_nested_segment_store(codegen, 0x700A), _nested_segment_store(codegen, 0x700A))
    )

    report = validate_required_memory_effects_8616(codegen.project, codegen, codegen.cfunc.statements)

    assert report.passed is False
    assert report.materialized_count == 1
    assert report.failure_count == 1


def test_required_memory_effect_accepts_distinct_runtime_segment_sources() -> None:
    codegen = _Codegen()
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        DirectSegmentedGlobalStoreEvidence8616(
            2, 2, MemSpace.ES, 0x1004, segment_source=_segment_source(0x700A)
        ),
        DirectSegmentedGlobalStoreEvidence8616(
            2, 2, MemSpace.ES, 0x100F, segment_source=_segment_source(0x700C)
        ),
    )
    codegen.cfunc.statements.statements.extend(
        (_nested_segment_store(codegen, 0x700A), _nested_segment_store(codegen, 0x700C))
    )

    report = validate_required_memory_effects_8616(codegen.project, codegen, codegen.cfunc.statements)

    assert report.passed is True
    assert report.materialized_count == 2


def test_final_semantic_refresh_persists_required_memory_effect_failure() -> None:
    codegen = _Codegen()
    codegen._inertia_required_direct_segmented_global_stores_8616 = (
        _required_store(),
    )

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    assert report.passed is False
    assert report.required_memory_effects.failure_count == 1
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot,
        expected_stages=("postprocess",),
    ) is False
    semantic_failures = codegen._inertia_tail_validation_snapshot["postprocess"][
        "semantic_failures"
    ]
    assert semantic_failures["required_memory_effects"] == (
        "missing-required-memory-write:ds:0x0134:width=2:ins=0x10588",
    )
    assert "missing-required-memory-write:ds:0x0134:width=2:ins=0x10588" in (
        codegen._inertia_tail_validation_snapshot["postprocess"]["summary_text"]
    )

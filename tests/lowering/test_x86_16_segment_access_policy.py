from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.structuring.decompiler_structuring_stage import _build_decompiler_structuring_passes
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.ir.segment_contract import (
    SegmentAccessFact,
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentFunctionContract,
)
from inertia.lowering.real_mode_linear import (
    lower_stable_ds_es_linear_global_dereferences_8616,
)
from inertia.lowering.segment_access_policy import (
    SegmentAccessLoweringDecision8616,
    SegmentAccessLoweringStats8616,
    classify_codegen_segment_access_8616,
    classify_local_segment_access_8616,
    record_segment_access_lowering_result_8616,
)
from inertia.lowering.segmented_global_loads import (
    materialize_named_segmented_global_loads_8616,
)
from inertia.lowering.segmented_memory_lowering import (
    NearPointerArgumentFact8616,
    SegmentedMemoryExpr,
    _near_pointer_arg_access_8616,
)


class _Codegen:
    def __init__(self, project: object) -> None:
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


def _access(
    *,
    instruction_addr: int,
    segment_register: str,
    physical_source: str | None,
    offset: int = 0x1234,
    width: int = 2,
    verdict: SegmentFactVerdict = SegmentFactVerdict.PROVEN,
) -> SegmentAccessFact:
    space = MemSpace.DS if segment_register == "ds" else MemSpace.ES
    return SegmentAccessFact(
        block_addr=0x1000,
        instruction_addr=instruction_addr,
        kind=SegmentAccessKind.READ,
        address=IRAddress(
            space=space,
            offset=offset,
            size=width,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
        segment_register=segment_register,
        physical_source=physical_source,
        verdict=verdict,
    )


def _contract(*facts: SegmentAccessFact) -> SegmentFunctionContract:
    return SegmentFunctionContract(function_addr=0x1000, accesses=facts)


def _segmented_deref(
    codegen: _Codegen,
    segment_register: str,
    *,
    instruction_addr: int,
    offset: int = 0x1234,
) -> CUnaryOp:
    project = codegen.project
    assert isinstance(project, SimpleNamespace)
    reg_offset, reg_size = project.arch.registers[segment_register]
    segment = CVariable(
        SimRegisterVariable(reg_offset, reg_size, name=segment_register),
        codegen=codegen,
    )
    pointer_type = SimTypePointer(SimTypeShort(False))
    address = CBinaryOp(
        "Add",
        CBinaryOp(
            "Mul",
            segment,
            CConstant(16, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        CConstant(offset, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    return CUnaryOp(
        "Dereference",
        CTypeCast(SimTypeShort(False), pointer_type, address, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": instruction_addr},
    )


def _lowering_fixture(
    *,
    segment_register: str,
    physical_source: str | None,
    verdict: SegmentFactVerdict = SegmentFactVerdict.PROVEN,
) -> tuple[SimpleNamespace, _Codegen, CUnaryOp]:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    deref = _segmented_deref(codegen, segment_register, instruction_addr=0x1010)
    assignment = CAssignment(
        deref,
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([assignment], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
    )
    codegen._inertia_segment_function_contract = _contract(
        _access(
            instruction_addr=0x1010,
            segment_register=segment_register,
            physical_source=physical_source,
            verdict=verdict,
        )
    )
    return project, codegen, deref


def test_local_policy_selects_exact_instruction_from_conflicting_sites() -> None:
    contract = _contract(
        _access(instruction_addr=0x1010, segment_register="ds", physical_source="ds"),
        _access(instruction_addr=0x1020, segment_register="ds", physical_source="0xb800"),
    )

    proven = classify_local_segment_access_8616(
        contract,
        instruction_addrs=frozenset({0x1010}),
        segment_register="ds",
        offset=0x1234,
        width=2,
    )
    ambiguous = classify_local_segment_access_8616(
        contract,
        segment_register="ds",
        offset=0x1234,
        width=2,
    )

    assert proven.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert proven.stats.classified_fact_count == proven.stats.materialized_count == 1
    assert ambiguous.decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE
    assert ambiguous.stats.failure_count == 1


def test_local_policy_keeps_proven_non_ds_source_segmented() -> None:
    result = classify_local_segment_access_8616(
        _contract(_access(instruction_addr=0x1010, segment_register="es", physical_source="es")),
        instruction_addrs=frozenset({0x1010}),
        segment_register="es",
        offset=0x1234,
        width=2,
    )

    assert result.decision is SegmentAccessLoweringDecision8616.EXPLICIT_SEGMENTED
    assert result.stats.materialized_count == 1


def test_codegen_policy_refuses_unknown_local_access_and_records_closed_census() -> None:
    _project, codegen, deref = _lowering_fixture(
        segment_register="ds",
        physical_source=None,
        verdict=SegmentFactVerdict.UNKNOWN_REFUSE,
    )

    result = classify_codegen_segment_access_8616(
        codegen,
        deref,
        segment_register="ds",
        offset=0x1234,
        width=2,
    )
    record_segment_access_lowering_result_8616(codegen, result)

    assert result.decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE
    assert codegen._inertia_segment_access_lowering_stats_8616 == SegmentAccessLoweringStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        failure_count=1,
    )


def test_global_lowering_consumes_local_ds_must_proof() -> None:
    _project, codegen, _deref = _lowering_fixture(segment_register="ds", physical_source="ds")

    assert lower_stable_ds_es_linear_global_dereferences_8616(codegen) is True

    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimMemoryVariable)
    assert lhs.variable.addr == 0x1234


def test_global_lowering_preserves_es_override_and_unknown_ds_access() -> None:
    _project, es_codegen, es_deref = _lowering_fixture(segment_register="es", physical_source="es")
    _project, unknown_codegen, unknown_deref = _lowering_fixture(
        segment_register="ds",
        physical_source=None,
        verdict=SegmentFactVerdict.UNKNOWN_REFUSE,
    )

    assert lower_stable_ds_es_linear_global_dereferences_8616(es_codegen) is False
    assert es_codegen.cfunc.statements.statements[0].lhs is es_deref
    assert lower_stable_ds_es_linear_global_dereferences_8616(unknown_codegen) is False
    assert unknown_codegen.cfunc.statements.statements[0].lhs is unknown_deref


def test_main_structuring_path_builds_local_contract_before_segment_consumers() -> None:
    names = tuple(spec.name for spec in _build_decompiler_structuring_passes())

    assert names.index("_segment_function_contract_8616") < names.index(
        "_segmented_memory_reasoning_8616"
    )


def test_named_global_materializer_cannot_bypass_unknown_local_ds_fact() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _Codegen(project)
    reg_offset, reg_size = project.arch.registers["ds"]
    segment = CVariable(
        SimRegisterVariable(reg_offset, reg_size, name="ds"),
        codegen=codegen,
    )
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [segment, CConstant(0x1234, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
        tags={"ins_addr": 0x1010},
    )
    assignment = CAssignment(
        CVariable(SimStackVariable(-2, 2, base="bp"), codegen=codegen),
        helper,
        codegen=codegen,
    )
    root = CStatements([assignment], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    codegen._inertia_segment_function_contract = _contract(
        _access(
            instruction_addr=0x1010,
            segment_register="ds",
            physical_source=None,
            verdict=SegmentFactVerdict.UNKNOWN_REFUSE,
        )
    )

    changed = materialize_named_segmented_global_loads_8616(
        project,
        codegen,
        {0x1234: ("g_value", 2)},
    )

    assert changed is False
    assert assignment.rhs is helper
    assert codegen._inertia_segment_access_lowering_stats_8616.failure_count >= 1


def test_near_pointer_lowering_requires_exact_entry_ds_identity() -> None:
    for physical_source, verdict, should_lower in (
        ("ds", SegmentFactVerdict.PROVEN, True),
        ("es", SegmentFactVerdict.PROVEN, False),
        (None, SegmentFactVerdict.UNKNOWN_REFUSE, False),
    ):
        project = SimpleNamespace(arch=Arch86_16())
        codegen = _Codegen(project)
        pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
        pointer_arg = CVariable(
            SimStackVariable(4, 2, base="bp", name="values"),
            variable_type=pointer_type,
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(arg_list=[pointer_arg])
        codegen._inertia_near_pointer_argument_facts_8616 = (
            NearPointerArgumentFact8616(
                stack_offset=4,
                carrier_load_ins_addr=0x100C,
                dereference_ins_addr=0x1010,
                access_width_bytes=2,
            ),
        )
        codegen._inertia_segment_function_contract = _contract(
            _access(
                instruction_addr=0x1010,
                segment_register="ds",
                physical_source=physical_source,
                width=2,
                verdict=verdict,
            )
        )
        matched = SegmentedMemoryExpr(
            space="DS",
            segment_expr=pointer_arg,
            offset_expr=pointer_arg,
            width_bits=16,
            access="read",
        )
        provenance = CFunctionCall(
            "SEG_U16",
            None,
            (),
            codegen=codegen,
            tags={"ins_addr": 0x1010},
        )

        lowered = _near_pointer_arg_access_8616(
            matched,
            codegen,
            provenance_node=provenance,
        )

        assert isinstance(lowered, CIndexedVariable) is should_lower

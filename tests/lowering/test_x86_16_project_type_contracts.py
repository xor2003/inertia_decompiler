from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    CallsiteSummary8616,
    record_caller_return_use_evidence_8616,
)
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.lowering.callsite_prototype_declarations import (
    _joined_return_type_8616,
)
from inertia.lowering.project_global_object_layout import (
    collect_project_direct_global_object_layout_evidence_8616,
)
from inertia.lowering.project_global_signedness import (
    ProjectGlobalOrderingView8616,
    recover_project_global_signedness_evidence_8616,
)
from inertia.lowering.segmented_global_loads import (
    _project_direct_global_scalar_refs_8616,
    _sidecar_free_project_direct_global_scalar_refs_8616,
)
from capstone.x86_const import (
    X86_INS_CALL,
    X86_INS_CMP,
    X86_INS_JBE,
    X86_INS_JLE,
    X86_INS_MOV,
    X86_INS_NOP,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_DX,
    X86_REG_ES,
)

from inertia.semantics.direct_call_result_storage import (
    recover_direct_call_result_storage_facts_8616,
)
from inertia.semantics.direct_global_ordering import (
    DirectGlobalOrdering8616,
    recover_direct_global_ordering_facts_8616,
)
from inertia.widening.global_object_layout import (
    DirectGlobalStorageView8616,
    recover_direct_global_object_layout_evidence_8616,
)


def _direct_view(function_addr: int, offset: int, width: int) -> DirectGlobalStorageView8616:
    return DirectGlobalStorageView8616(
        function_addr=function_addr,
        address=IRAddress(
            space=MemSpace.DS,
            offset=offset,
            size=width,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    )


@dataclass(frozen=True, slots=True)
class _DirectFact:
    offset: int
    width: int


class _Project:
    def __init__(self, original_project: object) -> None:
        self._inertia_original_project = original_project
        self._inertia_caller_function_ranges_8616 = ((0x1000, 0x1010), (0x1100, 0x1110))


def _instruction(instruction_id: int, address: int, *operands: object) -> SimpleNamespace:
    return SimpleNamespace(instruction_id=instruction_id, address=address, operands=operands)


def _register(register: int) -> SimpleNamespace:
    return SimpleNamespace(kind=X86_OP_REG, register=register, size=2, immediate=None, memory=None)


def _immediate(value: int) -> SimpleNamespace:
    return SimpleNamespace(kind=X86_OP_IMM, register=None, size=2, immediate=value, memory=None)


def _direct_word(offset: int, *, segment: int = 0) -> SimpleNamespace:
    memory = SimpleNamespace(segment=segment, base=0, index=0, displacement=offset)
    return SimpleNamespace(kind=X86_OP_MEM, register=None, size=2, immediate=None, memory=memory)


def _direct_call(target: int, address: int = 0x1000) -> SimpleNamespace:
    operand = SimpleNamespace(kind=X86_OP_IMM, register=None, size=2, immediate=target, memory=None)
    return _instruction(X86_INS_CALL, address, operand)


def test_direct_call_ax_dx_stores_prove_one_dword_object() -> None:
    instructions = (
        _direct_call(0x2200),
        _instruction(X86_INS_MOV, 0x1003, _direct_word(0xBA6), _register(X86_REG_AX)),
        _instruction(X86_INS_MOV, 0x1006, _direct_word(0xBA8), _register(X86_REG_DX)),
    )

    facts = recover_direct_call_result_storage_facts_8616(instructions)

    assert len(facts) == 1
    assert (
        facts[0].offset,
        facts[0].width,
        facts[0].source_call_target,
        facts[0].source_call_ins_addr,
        facts[0].low_store_ins_addr,
        facts[0].high_store_ins_addr,
    ) == (
        0xBA6,
        4,
        0x2200,
        0x1000,
        0x1003,
        0x1006,
    )


def test_direct_call_result_storage_refuses_gaps_wrong_registers_and_es() -> None:
    low = _instruction(X86_INS_MOV, 0x1003, _direct_word(0xBA6), _register(X86_REG_AX))
    high = _instruction(X86_INS_MOV, 0x1006, _direct_word(0xBA8), _register(X86_REG_DX))
    wrong_high = _instruction(X86_INS_MOV, 0x1006, _direct_word(0xBA8), _register(X86_REG_AX))
    es_low = _instruction(X86_INS_MOV, 0x1003, _direct_word(0xBA6, segment=X86_REG_ES), _register(X86_REG_AX))
    gap = _instruction(X86_INS_NOP, 0x1002)

    assert recover_direct_call_result_storage_facts_8616((_direct_call(0x2200), low, wrong_high)) == ()
    assert recover_direct_call_result_storage_facts_8616((_direct_call(0x2200), es_low, high)) == ()
    assert recover_direct_call_result_storage_facts_8616((_direct_call(0x2200), gap, low, high)) == ()


def test_direct_global_ordering_classifies_signed_and_unsigned_jcc() -> None:
    compare = _instruction(X86_INS_CMP, 0x1010, _direct_word(0x202), _immediate(0))

    signed = recover_direct_global_ordering_facts_8616(
        (compare, _instruction(X86_INS_JLE, 0x1015))
    )
    unsigned = recover_direct_global_ordering_facts_8616(
        (compare, _instruction(X86_INS_JBE, 0x1015))
    )

    assert len(signed) == len(unsigned) == 1
    assert (signed[0].offset, signed[0].ordering) == (0x202, DirectGlobalOrdering8616.SIGNED)
    assert unsigned[0].ordering is DirectGlobalOrdering8616.UNSIGNED


def test_direct_global_ordering_refuses_non_ds_comparison() -> None:
    compare = _instruction(
        X86_INS_CMP,
        0x1010,
        _direct_word(0x202, segment=X86_REG_ES),
        _immediate(0),
    )

    assert recover_direct_global_ordering_facts_8616(
        (compare, _instruction(X86_INS_JLE, 0x1015))
    ) == ()


def test_project_signedness_joins_only_proven_high_word_and_refuses_conflict() -> None:
    layout = recover_direct_global_object_layout_evidence_8616(
        (_direct_view(0x1000, 0x200, 4),)
    )
    compare = _instruction(X86_INS_CMP, 0x1010, _direct_word(0x202), _immediate(0))
    signed_fact = recover_direct_global_ordering_facts_8616(
        (compare, _instruction(X86_INS_JLE, 0x1015))
    )[0]
    unsigned_fact = recover_direct_global_ordering_facts_8616(
        (compare, _instruction(X86_INS_JBE, 0x1015))
    )[0]

    signed = recover_project_global_signedness_evidence_8616(
        layout,
        (ProjectGlobalOrderingView8616(0x1000, signed_fact),),
    )
    conflict = recover_project_global_signedness_evidence_8616(
        layout,
        (
            ProjectGlobalOrderingView8616(0x1000, signed_fact),
            ProjectGlobalOrderingView8616(0x1100, unsigned_fact),
        ),
    )

    assert len(signed.contracts) == 1
    assert signed.contracts[0].base_offset == 0x200
    assert signed.contracts[0].ordering is DirectGlobalOrdering8616.SIGNED
    assert signed.classified_fact_count == signed.materialized_count == 1
    assert conflict.contracts == ()
    assert conflict.conflicting_base_offsets == (0x200,)
    assert conflict.classified_fact_count == conflict.materialized_count == 0
    assert conflict.failure_count == 2


def test_direct_layout_joins_same_wide_base_across_functions() -> None:
    evidence = recover_direct_global_object_layout_evidence_8616(
        (
            _direct_view(0x1000, 0x200, 4),
            _direct_view(0x1100, 0x200, 4),
        )
    )

    assert len(evidence.layouts) == 1
    assert evidence.layouts[0].address == IRAddress(
        space=MemSpace.DS,
        offset=0x200,
        size=4,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    assert evidence.layouts[0].proof_function_addrs == (0x1000, 0x1100)
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 2
    assert evidence.classified_fact_count == 2
    assert evidence.materialized_count == 1
    assert evidence.failure_count == 0


def test_direct_layout_refuses_overlapping_wide_bases() -> None:
    evidence = recover_direct_global_object_layout_evidence_8616(
        (
            _direct_view(0x1000, 0x200, 4),
            _direct_view(0x1100, 0x202, 4),
        )
    )

    assert evidence.layouts == ()
    assert evidence.classified_fact_count == 2
    assert evidence.materialized_count == 0
    assert evidence.failure_count == 2


def test_project_direct_layout_uses_original_binary_and_caches() -> None:
    original_project = object()
    project = _Project(original_project)
    seen_projects: list[object] = []

    def collect(source_project: object, function: object) -> tuple[_DirectFact, ...]:
        seen_projects.append(source_project)
        return (_DirectFact(0x200, 4),) if function.addr == 0x1000 else ()

    first = collect_project_direct_global_object_layout_evidence_8616(project, (collect,))
    second = collect_project_direct_global_object_layout_evidence_8616(project, (collect,))

    assert first is second
    assert seen_projects == [original_project, original_project]
    assert tuple(layout.address.offset for layout in first.layouts) == (0x200,)


def test_project_direct_layout_materializes_low_and_high_word_refs() -> None:
    evidence = recover_direct_global_object_layout_evidence_8616(
        (_direct_view(0x1000, 0x200, 4),)
    )
    project = SimpleNamespace(
        _inertia_project_direct_global_object_layout_evidence_8616=evidence,
    )

    refs = _project_direct_global_scalar_refs_8616(project)

    assert tuple(
        (ref.offset, ref.name, ref.relative_disp, ref.width, ref.max_relative_disp)
        for ref in refs
    ) == (
        (0x200, "g_0200", 0, 4, 0),
        (0x200, "g_0200", 0, 2, 2),
        (0x202, "g_0200", 2, 2, 2),
    )


def test_project_direct_layout_defers_to_stronger_cod_object_refs() -> None:
    evidence = recover_direct_global_object_layout_evidence_8616(
        (_direct_view(0x1000, 0x200, 4),)
    )
    project = SimpleNamespace(
        _inertia_project_direct_global_object_layout_evidence_8616=evidence,
    )
    metadata = SimpleNamespace(
        global_refs=(
            SimpleNamespace(
                indexed=False,
                name="known_object",
                relative_disp=0,
                width=4,
            ),
        )
    )

    assert _sidecar_free_project_direct_global_scalar_refs_8616(project, metadata) == ()


def _summary(*, return_used: bool) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=0x2000,
        return_addr=0x1013,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=return_used,
        return_shape="ax",
    )


def _caller_evidence(verdict: CallerReturnUseVerdict8616) -> CallerReturnUseEvidence8616:
    closed = verdict is not CallerReturnUseVerdict8616.UNKNOWN
    return CallerReturnUseEvidence8616(
        target_addr=0x2000,
        verdict=verdict,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2 if closed else 1,
        materialized_count=2 if closed else 1,
        failure_count=0 if closed else 1,
        used_callsite_count=2 if verdict is CallerReturnUseVerdict8616.USED else 0,
        unused_callsite_count=2 if verdict is CallerReturnUseVerdict8616.UNUSED else 0,
        callsite_addrs=(0x1010, 0x1020),
    )


def test_closed_unused_caller_evidence_overrides_false_local_ax_use() -> None:
    project = SimpleNamespace()
    summary = _summary(return_used=True)
    record_caller_return_use_evidence_8616(
        project,
        0x2000,
        _caller_evidence(CallerReturnUseVerdict8616.UNUSED),
    )

    assert _joined_return_type_8616(project, summary, (summary,)) == "int"


def test_incomplete_caller_evidence_does_not_override_local_ax_use() -> None:
    project = SimpleNamespace()
    summary = _summary(return_used=True)
    record_caller_return_use_evidence_8616(
        project,
        0x2000,
        _caller_evidence(CallerReturnUseVerdict8616.UNKNOWN),
    )

    assert _joined_return_type_8616(project, summary, (summary,)) == "unsigned short"

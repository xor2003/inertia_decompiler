from dataclasses import replace
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunctionCall, CIndexedVariable, CVariable
from angr.sim_type import SimTypeChar, SimTypeFixedSizeArray, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsitePushSourceKind8616, CallsiteSummary8616
from inertia.lowering.callsite_pointer_tables import (
    callsite_pointer_table_argument_type_8616,
    materialize_callsite_pointer_table_types_8616,
)

from inertia.lowering.codegen_metadata import GlobalDeclarationArrayExtent8616


class _Codegen:
    def __init__(self, project: object) -> None:
        self.project = project
        self._next_index = 0
        self._inertia_global_declaration_specs_8616 = (("unsigned short", "g_table", 1),)

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _summary(callsite: int, first_source: tuple, *, target: int = 0x2000) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite,
        target_addr=target,
        return_addr=callsite + 3,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        push_arg_sources=(
            (CallsitePushSourceKind8616.SEGMENT.value, "ds"),
            first_source,
        ),
    )


def _segment(project: object, codegen: _Codegen) -> CVariable:
    reg_offset, reg_size = project.arch.registers["ds"]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name="ds"), codegen=codegen)


def _candidate(codegen: _Codegen) -> CIndexedVariable:
    base = CVariable(
        SimMemoryVariable(0x136, 2, name="g_table"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    index = CConstant(1, SimTypeShort(False), codegen=codegen)
    return CIndexedVariable(base, index, variable_type=SimTypeShort(False), codegen=codegen)


def _stack_array(codegen: _Codegen, element_type: object) -> CVariable:
    return CVariable(
        SimStackVariable(-0x12, 16, base="bp", name="local_12"),
        variable_type=SimTypeFixedSizeArray(element_type, 16),
        codegen=codegen,
    )


def test_materializes_global_pointer_table_from_same_slot_stack_anchor() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    candidate = _candidate(codegen)
    segment = _segment(project, codegen)
    candidate_call = CFunctionCall("callee", None, [candidate, segment], codegen=codegen)
    anchor_call = CFunctionCall(
        "callee",
        None,
        [_stack_array(codegen, SimTypeChar(False)), segment],
        codegen=codegen,
    )

    changed = materialize_callsite_pointer_table_types_8616(
        project,
        codegen,
        (
            (
                candidate_call,
                _summary(
                    0x1010,
                    (CallsitePushSourceKind8616.GLOBAL_INDEX_VALUE.value, 0x136, 2),
                ),
            ),
            (
                anchor_call,
                _summary(
                    0x1020,
                    (CallsitePushSourceKind8616.BP_ADDRESS.value, -0x12),
                ),
            ),
        ),
    )

    assert changed is True
    assert isinstance(candidate.type, SimTypeShort)
    pointer_type = callsite_pointer_table_argument_type_8616(codegen, candidate)
    assert isinstance(pointer_type, SimTypePointer)
    assert isinstance(pointer_type.pts_to, SimTypeChar)
    assert isinstance(candidate.variable.type, SimTypeShort)
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("char *", "g_table", GlobalDeclarationArrayExtent8616.UNKNOWN),
    )
    stats = codegen._inertia_callsite_pointer_table_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (4, 2, 1, 1, 0)


def test_refuses_global_pointer_table_without_exact_segment_companion() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    candidate = _candidate(codegen)
    call = CFunctionCall(
        "callee",
        None,
        [candidate, CConstant(0, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    summary = _summary(
        0x1010,
        (CallsitePushSourceKind8616.GLOBAL_INDEX_VALUE.value, 0x136, 2),
    )
    summary = replace(
        summary,
        push_arg_sources=(
            (CallsitePushSourceKind8616.IMMEDIATE.value, 0),
            summary.push_arg_sources[1],
        ),
    )

    changed = materialize_callsite_pointer_table_types_8616(project, codegen, ((call, summary),))

    assert changed is False
    assert isinstance(candidate.type, SimTypeShort)
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned short", "g_table", 1),)


def test_refuses_global_pointer_table_with_conflicting_anchor_types() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    candidate = _candidate(codegen)
    segment = _segment(project, codegen)
    calls = (
        (
            CFunctionCall("callee", None, [candidate, segment], codegen=codegen),
            _summary(0x1010, (CallsitePushSourceKind8616.GLOBAL_INDEX_VALUE.value, 0x136, 2)),
        ),
        (
            CFunctionCall("callee", None, [_stack_array(codegen, SimTypeChar(False)), segment], codegen=codegen),
            _summary(0x1020, (CallsitePushSourceKind8616.BP_ADDRESS.value, -0x12)),
        ),
        (
            CFunctionCall("callee", None, [_stack_array(codegen, SimTypeShort(False)), segment], codegen=codegen),
            _summary(0x1030, (CallsitePushSourceKind8616.BP_ADDRESS.value, -0x12)),
        ),
    )

    changed = materialize_callsite_pointer_table_types_8616(project, codegen, calls)

    assert changed is False
    assert isinstance(candidate.type, SimTypeShort)
    assert codegen._inertia_callsite_pointer_table_stats_8616.failure_count == 1

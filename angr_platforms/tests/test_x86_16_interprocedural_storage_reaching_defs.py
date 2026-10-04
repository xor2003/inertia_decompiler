"""Real IR/SSA tests for interprocedural call-argument definition proof."""

from __future__ import annotations

import io
from dataclasses import replace

import angr
from angr_platforms.X86_16.analysis_helpers import CallTargetKind8616, resolve_direct_call_target_from_instruction_8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
)
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    build_boundary_direct_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir import MemSpace
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.logical_memory_write_value import (
    LogicalWordWriteValueKind8616,
    trace_logical_word_write_values_8616,
)
from angr_platforms.X86_16.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)
from angr_platforms.X86_16.ir.vex_import import (
    build_x86_16_ir_function_artifact,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    StorageIdentityKind8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_reaching_defs import (
    CallArgumentDefinitionFailure8616,
    CallArgumentDefinitionVerdict8616,
    resolve_call_argument_reaching_definition_8616,
)
from archinfo import ArchX86


def _lift_ssa(code: bytes) -> tuple[SSAFunctionArtifact, angr.Project, DecodedDirectCallsiteIndex8616]:
    """Retain native bytes, a closed caller boundary and its decoded index."""
    project = angr.Project(
        io.BytesIO(code + b"\xc3"),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(code) + 1)
    assert function is not None
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert not artifact.refusals
    publish_function_ir_artifact_8616(project, artifact)
    index = build_boundary_direct_callsite_index_8616(
        function,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    return build_x86_16_function_ssa(artifact), project, index


def _summary(
    *,
    callsite_addr: int,
    target_addr: int,
    push_addr: int,
    source: tuple[object, ...],
) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=target_addr,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=None,
        return_register=None,
        return_used=None,
        push_arg_sources=(source,),
        push_arg_instruction_addrs=(push_addr,),
    )


def test_immediate_argument_resolves_exact_store_and_call_use() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("6a05e80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.failure is None
    assert result.stats.complete
    assert len(result.definitions) == 2
    assert tuple(definition.value.size for definition in result.definitions) == (1, 1)
    assert result.definitions[0].value.const == 5
    assert tuple(definition.instr_addr for definition in result.definitions) == (0x1000, 0x1000)
    assert result.affine_expression is not None
    assert result.affine_expression.constant == 5
    assert result.use is not None
    assert result.use.callsite_addr == 0x1002


def test_wide_logical_argument_resolves_two_physical_push_definitions() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("6a026a01e80000"))
    summary = CallsiteSummary8616(
        callsite_addr=0x1004,
        target_addr=0x1007,
        return_addr=0x1007,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=None,
        push_arg_sources=(
            (CallsitePushSourceKind8616.IMMEDIATE.value, 2),
            (CallsitePushSourceKind8616.IMMEDIATE.value, 1),
        ),
        push_arg_instruction_addrs=(0x1000, 0x1002),
        logical_arg_widths=(4,),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.failure is None
    assert result.stats.complete
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    assert tuple(definition.value.size for definition in result.definitions) == (1, 1, 1, 1)
    assert tuple(definition.value.const for definition in result.definitions) == (1, None, 2, None)
    assert result.affine_expression is None
    assert tuple(definition.instr_addr for definition in result.definitions) == (
        0x1002,
        0x1002,
        0x1000,
        0x1000,
    )


def test_far_callback_argument_resolves_two_bp_word_sources() -> None:
    """A callee-proven far pointer must retain both source stack words in SSA."""
    code = bytes.fromhex(
        "55 8b ec 83 ec 04 c7 46 fc 00 00 c7 46 fe 00 10 "
        "ff 76 08 ff 76 fe ff 76 fc 9a 34 00 00 10 83 c4 06 8b e5 5d cb"
    )
    ssa, project, callsite_index = _lift_ssa(code)
    summary = CallsiteSummary8616(
        callsite_addr=0x1019,
        target_addr=0x10034,
        return_addr=0x101E,
        kind=CallTargetKind8616.DIRECT_FAR_CALL,
        arg_count=3,
        arg_widths=(2, 2, 2),
        stack_cleanup=6,
        return_register="ax",
        return_used=True,
        push_arg_sources=(("bp", 8, 2), ("bp", -2, 2), ("bp", -4, 2)),
        push_arg_instruction_addrs=(0x1010, 0x1013, 0x1016),
        logical_arg_widths=(4, 2),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.stats.complete
    assert result.use is not None and result.use.callsite_addr == 0x1019
    storages = tuple(definition.source_storage for definition in result.definitions)
    assert len(storages) == 4
    assert all(storage is not None and storage.kind is StorageIdentityKind8616.STACK for storage in storages)
    assert tuple(storage.address.offset for storage in storages if storage is not None and storage.address) == (
        -4, -3, -2, -1,
    )
    writes = trace_logical_word_write_values_8616(ssa)
    assert writes.closed
    local_words = {
        fact.access.address.offset: (fact.kind, fact.constant)
        for fact in writes.facts
        if fact.access.address.space is MemSpace.SS and fact.access.address.base == ("bp",)
    }
    assert local_words[-4] == (LogicalWordWriteValueKind8616.CONSTANT_ZERO, 0)
    assert local_words[-2] == (LogicalWordWriteValueKind8616.CONSTANT_WORD, 0x1000)


def test_bp_value_argument_resolves_exact_stack_load() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("ff7604e80000"))
    summary = _summary(
        callsite_addr=0x1003,
        target_addr=0x1006,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.BP_VALUE.value, 4),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert len(result.definitions) == 2
    storages = tuple(definition.source_storage for definition in result.definitions)
    assert all(storage is not None for storage in storages)
    assert all(storage.kind is StorageIdentityKind8616.STACK for storage in storages if storage)
    assert tuple(storage.address.offset for storage in storages if storage and storage.address) == (4, 5)
    assert all(storage.address.space is MemSpace.SS for storage in storages if storage and storage.address)


def test_bp_value_without_authoritative_logical_access_refuses() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("ff7604e80000"))
    ssa = replace(ssa, logical_memory=None)
    summary = _summary(
        callsite_addr=0x1003,
        target_addr=0x1006,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.BP_VALUE.value, 4),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    assert result.stats.raw_fact_count == result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_global_word_argument_retains_two_exact_memory_pieces() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("ff360012e80000"))
    summary = _summary(
        callsite_addr=0x1004,
        target_addr=0x1007,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.GLOBAL_VALUE.value, 0x1200, 2),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert len(result.definitions) == 2
    storages = tuple(definition.source_storage for definition in result.definitions)
    assert all(storage is not None for storage in storages)
    assert all(storage.kind is StorageIdentityKind8616.MEMORY for storage in storages if storage)
    assert tuple(storage.address.offset for storage in storages if storage and storage.address) == (
        0x1200,
        0x1201,
    )
    assert all(storage.address.space is MemSpace.DS for storage in storages if storage and storage.address)


def test_bp_address_argument_requires_matching_ssa_origin() -> None:
    summary = _summary(
        callsite_addr=0x1004,
        target_addr=0x1007,
        push_addr=0x1003,
        source=(CallsitePushSourceKind8616.BP_ADDRESS.value, -4),
    )

    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("8d46fc50e80000"))
    proven = resolve_call_argument_reaching_definition_8616(
        ssa,
        summary,
        0, project=project, callsite_index=callsite_index)
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("b8341250e80000"))
    contradicted = resolve_call_argument_reaching_definition_8616(
        ssa,
        summary,
        0, project=project, callsite_index=callsite_index)

    assert proven.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert tuple(
        definition.source_storage.address.offset
        for definition in proven.definitions
        if definition.source_storage is not None
        and definition.source_storage.address is not None
    ) == (-4, -3)
    assert contradicted.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert contradicted.failure is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    assert contradicted.stats.classified_fact_count == 0
    assert contradicted.stats.materialized_count == 0


def test_signed_immediate_retains_two_byte_definitions_as_one_logical_fact() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("6affe80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, -1),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    assert tuple(definition.value.size for definition in result.definitions) == (1, 1)
    assert result.definitions[0].value.const == 0xFFFF


def test_immediate_source_mismatch_refuses_all_physical_pieces() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("6a05e80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 6),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    assert result.stats.raw_fact_count == result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_missing_push_definition_refuses_after_normalization() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("6a05e80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1001,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_call_output_source_refuses_until_output_ssa_is_modeled() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("50e80000"))
    summary = _summary(
        callsite_addr=0x1001,
        target_addr=0x1004,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.RETURN_REGISTER.value, "ax"),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallArgumentDefinitionFailure8616.UNMODELED_CALL_OUTPUT
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0


def test_call_target_conflict_refuses_before_source_classification() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("6a05e80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x2222,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.CONFLICT
    assert result.failure is CallArgumentDefinitionFailure8616.CALL_TARGET_CONFLICT
    assert result.stats.normalized_fact_count == 0
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0


def test_real_mode_offset_target_matches_linked_census_target() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("6a05e80000"))
    original = angr.Project(
        io.BytesIO(bytes.fromhex("6a05e80000c3")),
        # This image supplies full-width loader coordinates only. Native
        # instructions are decoded/proved in the retained Arch86_16 slice.
        main_opts={"backend": "blob", "arch": ArchX86(), "base_addr": 0x11000, "entry_point": 0x11000},
        auto_load_libs=False,
    )
    # These are the third-party project extensions used by exact rebased slices.
    vars(project)["_inertia_original_project"] = original
    vars(project)["_inertia_original_linear_delta"] = 0x10000
    summary = replace(
        _summary(
            callsite_addr=0x1002,
            target_addr=0x11005,
            push_addr=0x1000,
            source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
        ),
        target_addr=None,
    )

    result = resolve_call_argument_reaching_definition_8616(
        ssa,
        summary,
        0,
        project=project,
        expected_target_addr=0x11005, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.stats.complete


def test_proven_push_definitions_retain_their_logical_push_root() -> None:
    """Every physical reaching definition must carry the proven push root."""
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("6a05e80000"))
    summary = _summary(
        callsite_addr=0x1002,
        target_addr=0x1005,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.IMMEDIATE.value, 5),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert len(result.definitions) == 2
    roots = set()
    for index, definition in enumerate(result.definitions):
        logical = definition.logical_push
        assert logical is not None
        assert logical.complete
        assert logical.width == 2
        assert logical.root.const == 5
        assert len(logical.slices) == 2
        assert all(item.site.instr.addr == 0x1000 for item in logical.slices)
        assert logical.slices[index].site.block.addr == definition.block_addr
        assert logical.slices[index].site.instr_index == definition.instr_index
        assert logical.slices[index].value == definition.value
        roots.add(logical.root)
    assert len(roots) == 1


def test_each_physical_push_retains_its_own_push_bound_root() -> None:
    """Retained roots stay bound to the exact push instruction they came from."""
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("6a026a01e80000"))
    summary = CallsiteSummary8616(
        callsite_addr=0x1004,
        target_addr=0x1007,
        return_addr=0x1007,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=None,
        push_arg_sources=(
            (CallsitePushSourceKind8616.IMMEDIATE.value, 2),
            (CallsitePushSourceKind8616.IMMEDIATE.value, 1),
        ),
        push_arg_instruction_addrs=(0x1000, 0x1002),
        logical_arg_widths=(4,),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    pushes = {definition.instr_addr: definition.logical_push for definition in result.definitions}
    assert set(pushes) == {0x1000, 0x1002}
    for push_addr, logical in pushes.items():
        assert logical is not None
        assert logical.complete
        assert logical.width == 2
        assert len(logical.slices) == 2
        assert all(item.site.instr.addr == push_addr for item in logical.slices)
    first, second = pushes[0x1000], pushes[0x1002]
    assert first is not None and second is not None
    assert first.root.const == 2
    assert second.root.const == 1


def test_nonconstant_bp_address_push_retains_original_register_root() -> None:
    """A proven LEA/PUSH carries the actual SSA Value, not a fabricated constant."""
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("8d46fc50e80000"))
    result = resolve_call_argument_reaching_definition_8616(
        ssa,
        _summary(callsite_addr=0x1004, target_addr=0x1007, push_addr=0x1003,
                 source=(CallsitePushSourceKind8616.BP_ADDRESS, -4)),
        0, project=project, callsite_index=callsite_index)
    assert result.stats.complete and result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    for definition in result.definitions:
        logical = definition.logical_push
        assert logical is not None and logical.complete
        assert logical.root.const is None and logical.root.size == 2
        assert logical.root.space is MemSpace.REG
        assert logical.definition_slice(definition) is not None


def test_load_source_definitions_leave_logical_push_transport_absent() -> None:
    """Paths without a proven push root expose no whole-word transport."""
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("ff7604e80000"))
    summary = _summary(
        callsite_addr=0x1003,
        target_addr=0x1006,
        push_addr=0x1000,
        source=(CallsitePushSourceKind8616.BP_VALUE.value, 4),
    )

    result = resolve_call_argument_reaching_definition_8616(ssa, summary, 0, project=project, callsite_index=callsite_index)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert len(result.definitions) == 2
    assert all(definition.logical_push is None for definition in result.definitions)

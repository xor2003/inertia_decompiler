"""Real IR/SSA tests for exact interprocedural call-output producers."""

from __future__ import annotations

import io

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)
from inertia.ir.vex_import import (
    build_x86_16_ir_function_artifact,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.interprocedural_storage_contracts import (
    StorageDefinitionKind8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
)
from inertia.lowering.interprocedural_storage_return_defs import (
    CallOutputDefinitionFailure8616,
    CallOutputDefinitionVerdict8616,
    resolve_call_output_definitions_8616,
)
from archinfo import ArchX86

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    build_boundary_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616


def _lift_ssa(code: bytes) -> tuple[SSAFunctionArtifact, angr.Project, DecodedDirectCallsiteIndex8616]:
    """Retain native CALL bytes, complete boundary, raw IR and decoded index."""
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


def _fact(
    verdict: CallerReturnUseVerdict8616 = CallerReturnUseVerdict8616.USED,
    *,
    callsite_addr: int = 0x1000,
) -> CallerReturnUseFact8616:
    return CallerReturnUseFact8616(
        caller_addr=0x1000,
        callsite_addr=callsite_addr,
        verdict=verdict,
        kind=(
            CallsiteReturnUseKind8616.CONDITION
            if verdict is CallerReturnUseVerdict8616.USED
            else CallsiteReturnUseKind8616.CLOBBERED
        ),
        witness_instruction_addr=0x1003,
    )


def _register(name: str, width: int = 2) -> StorageIdentity8616:
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=width,
        register=name,
    )


def test_exact_call_output_is_versionless_and_provenance_bound() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("e80000"))
    result = resolve_call_output_definitions_8616(
        ssa,
        _fact(),
        0x1003,
        (0x1003,),
        (_register("ax"),), project=project, callsite_index=callsite_index)

    assert result.verdict is CallOutputDefinitionVerdict8616.PROVEN
    assert result.complete
    assert result.stats.complete
    definition = result.definitions[0]
    assert definition.definition_kind is StorageDefinitionKind8616.CALL_OUTPUT
    assert definition.instr_addr == 0x1000
    assert definition.value.name == "ax"
    assert definition.value.version is None
    assert definition.value.const is None
    assert result.provenance is not None
    assert result.provenance.function_addr == 0x1003
    assert result.provenance.definition_addr == 0x1000


def test_split_output_pieces_share_one_call_provenance() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("e80000"))
    result = resolve_call_output_definitions_8616(
        ssa,
        _fact(),
        0x1003,
        (0x1003,),
        (_register("ax"), _register("dx")), project=project, callsite_index=callsite_index)

    assert result.complete
    assert tuple(item.value.name for item in result.definitions) == ("ax", "dx")
    assert all(item.instr_addr == 0x1000 for item in result.definitions)
    assert result.stats.raw_fact_count == result.stats.materialized_count == 2


def test_target_comparison_does_not_flatten_to_low_16_bits() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("e80000"))
    result = resolve_call_output_definitions_8616(
        ssa,
        _fact(),
        0x11003,
        (0x11003,),
        (_register("ax"),), project=project, callsite_index=callsite_index)

    assert result.verdict is CallOutputDefinitionVerdict8616.CONFLICT
    assert result.failure is CallOutputDefinitionFailure8616.CALL_TARGET_CONFLICT
    assert not result.definitions
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0


def test_real_mode_offset_target_matches_linked_target_with_project_evidence() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("e80000"))
    original = angr.Project(
        io.BytesIO(bytes.fromhex("e80000c3")),
        # Full-width original-image coordinates only; the active slice
        # supplies all 16-bit native decoding and instruction proof.
        main_opts={"backend": "blob", "arch": ArchX86(), "base_addr": 0x11000, "entry_point": 0x11000},
        auto_load_libs=False,
    )
    vars(project)["_inertia_original_project"] = original
    vars(project)["_inertia_original_linear_delta"] = 0x10000

    result = resolve_call_output_definitions_8616(
        ssa,
        _fact(),
        0x11003,
        (0x11003,),
        (_register("ax"),),
        project=project, callsite_index=callsite_index)

    assert result.verdict is CallOutputDefinitionVerdict8616.PROVEN
    assert result.complete


def test_unknown_return_use_refuses_before_call_materialization() -> None:
    fact = CallerReturnUseFact8616(
        caller_addr=0x1000,
        callsite_addr=0x1000,
        verdict=CallerReturnUseVerdict8616.UNKNOWN,
        kind=None,
        witness_instruction_addr=None,
    )

    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("e80000"))
    result = resolve_call_output_definitions_8616(
        ssa,
        fact,
        0x1003,
        (0x1003,),
        (_register("ax"),), project=project, callsite_index=callsite_index)

    assert result.verdict is CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallOutputDefinitionFailure8616.RETURN_USE_UNKNOWN
    assert not result.definitions


def test_unused_return_refuses_output_definition() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("e80000"))
    result = resolve_call_output_definitions_8616(
        ssa,
        _fact(CallerReturnUseVerdict8616.UNUSED),
        0x1003,
        (0x1003,),
        (_register("ax"),), project=project, callsite_index=callsite_index)

    assert result.verdict is CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallOutputDefinitionFailure8616.RETURN_NOT_OBSERVED


def test_missing_callsite_refuses_without_fabricating_definition() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("e80000"))
    result = resolve_call_output_definitions_8616(
        ssa,
        _fact(callsite_addr=0x1001),
        0x1003,
        (0x1003,),
        (_register("ax"),), project=project, callsite_index=callsite_index)

    assert result.verdict is CallOutputDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallOutputDefinitionFailure8616.CALLSITE_NOT_FOUND
    assert not result.definitions


def test_duplicate_output_storage_is_a_typed_conflict() -> None:
    ssa, project, callsite_index = _lift_ssa(bytes.fromhex("e80000"))
    result = resolve_call_output_definitions_8616(
        ssa,
        _fact(),
        0x1003,
        (0x1003,),
        (_register("ax"), _register("ax")), project=project, callsite_index=callsite_index)

    assert result.verdict is CallOutputDefinitionVerdict8616.CONFLICT
    assert result.failure is CallOutputDefinitionFailure8616.OUTPUT_STORAGE_CONFLICT
    assert not result.definitions

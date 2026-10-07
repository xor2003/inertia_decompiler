"""Real-lifter tests for cross-block returned-pointer evidence."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

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
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
)
from inertia.lowering.interprocedural_storage_return_defs import (
    resolve_call_output_definitions_8616,
)
from inertia.lowering.interprocedural_storage_return_pointer import (
    classify_pointer_return_storage_8616,
)
from inertia.lowering.interprocedural_storage_return_type_contracts import (
    ReturnStorageTypeFailure8616,
    ReturnStorageTypeResult8616,
    ReturnStorageTypeVerdict8616,
)

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    build_boundary_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616

CALLER_ADDR = 0x1000
CALLSITE_ADDR = 0x1000
WITNESS_ADDR = 0x1003
CALLEE_ADDR = 0x1030
CALL_BYTES = bytes.fromhex("e82d00")


def _fact() -> CallerReturnUseFact8616:
    return CallerReturnUseFact8616(
        caller_addr=CALLER_ADDR,
        callsite_addr=CALLSITE_ADDR,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=CallsiteReturnUseKind8616.VALUE,
        witness_instruction_addr=WITNESS_ADDR,
    )


def _lift_ssa(
    code_after_call: str,
    block_addrs: set[int],
) -> tuple[SSAFunctionArtifact, StorageReachingDefinition8616]:
    """Bind the genuine CALL producer before tests corrupt downstream CFG evidence."""
    code = CALL_BYTES + bytes.fromhex(code_after_call)
    project = angr.Project(
        io.BytesIO(code.ljust(CALLEE_ADDR - CALLER_ADDR, b"\x90") + b"\xc3"),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": CALLER_ADDR,
            "entry_point": CALLER_ADDR,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(
        addr=CALLER_ADDR,
        block_addrs_set=block_addrs,
        info={},
    )
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert not artifact.refusals
    publish_function_ir_artifact_8616(project, artifact)
    boundary = exact_function_range_boundary_8616(project, CALLER_ADDR, CALLER_ADDR + len(code))
    assert boundary is not None
    index = build_boundary_direct_callsite_index_8616(
        boundary,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    ssa = build_x86_16_function_ssa(artifact)
    return ssa, _definition(ssa, _fact(), project, index)


def _definition(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
    project: angr.Project,
    callsite_index: DecodedDirectCallsiteIndex8616,
) -> StorageReachingDefinition8616:
    register = StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=2,
        register="ax",
    )
    result = resolve_call_output_definitions_8616(
        artifact,
        fact,
        CALLEE_ADDR,
        (CALLEE_ADDR,),
        (register,),
        project=project,
        callsite_index=callsite_index,
    )
    assert result.complete, result
    return result.definitions[0]


def _classify(
    artifact: SSAFunctionArtifact,
    definition: StorageReachingDefinition8616,
) -> ReturnStorageTypeResult8616:
    fact = _fact()
    return classify_pointer_return_storage_8616(
        artifact,
        fact,
        definition,
    )


def _compatible_phi_artifact() -> tuple[SSAFunctionArtifact, StorageReachingDefinition8616]:
    return _lift_ssa(
        "89c683fa00740489f3eb0489f3eb008b0fc3",
        {0x1000, 0x1003, 0x100A, 0x100E, 0x1012},
    )


def test_direct_cfg_edge_retains_exact_pointer_carrier() -> None:
    artifact, definition = _lift_ssa(
        "89c3eb01908b0fc3",
        {0x1000, 0x1003, 0x1008},
    )

    result = _classify(artifact, definition)

    assert result.verdict is ReturnStorageTypeVerdict8616.PROVEN
    assert result.complete
    assert result.pointer_use is not None
    assert result.pointer_use.dereference_instruction_addr == 0x1008
    assert tuple((edge.source_block_addr, edge.target_block_addr) for edge in result.pointer_use.cfg_edges) == (
        (0x1003, 0x1008),
    )
    assert not result.pointer_use.phis


def test_all_predecessor_phi_retains_exact_inputs() -> None:
    result = _classify(*_compatible_phi_artifact())

    assert result.verdict is ReturnStorageTypeVerdict8616.PROVEN
    assert result.complete
    assert result.pointer_use is not None
    assert result.pointer_use.dereference_instruction_addr == 0x1012
    assert len(result.pointer_use.phis) == 1
    phi = result.pointer_use.phis[0]
    assert phi.complete
    assert phi.block_addr == 0x1012
    assert phi.carrier_register == "bx"
    assert tuple(item.source_block_addr for item in phi.incoming) == (0x100A, 0x100E)


def test_clobbered_predecessor_refuses_join() -> None:
    artifact, definition = _lift_ssa(
        "89c383fa00740431dbeb02eb008b0fc3",
        {0x1000, 0x1003, 0x100A, 0x100E, 0x1010},
    )

    result = _classify(artifact, definition)

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_CFG_JOIN_CONFLICT
    assert result.pointer_use is None


def test_mismatched_phi_input_is_a_typed_conflict() -> None:
    artifact, definition = _compatible_phi_artifact()
    register_phis = tuple(phi for phi in artifact.phi_nodes if phi.target.name == "bx")
    assert len(register_phis) == 1
    phi = register_phis[0]
    first = phi.incoming[0]
    assert isinstance(first.value.version, int)
    changed_first = replace(
        first,
        value=replace(first.value, version=first.value.version + 1),
    )
    changed_phi = replace(phi, incoming=(changed_first, *phi.incoming[1:]))
    changed_phis = tuple(changed_phi if item == phi else item for item in artifact.phi_nodes)

    result = _classify(replace(artifact, phi_nodes=changed_phis), definition)

    assert result.verdict is ReturnStorageTypeVerdict8616.CONFLICT
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_PHI_CONFLICT
    assert result.pointer_use is None


def test_incomplete_predecessor_map_refuses_cfg_flow() -> None:
    artifact, definition = _lift_ssa(
        "89c3eb01908b0fc3",
        {0x1000, 0x1003, 0x1008},
    )
    incomplete = replace(
        artifact,
        predecessor_map={0x1000: (), 0x1003: ()},
    )

    result = _classify(incomplete, definition)

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_CFG_INCOMPLETE


def test_reachable_cfg_cycle_refuses_without_fixed_point_guessing() -> None:
    artifact, definition = _lift_ssa(
        "89c3ebfe8b0fc3",
        {0x1000, 0x1003, 0x1005},
    )

    result = _classify(artifact, definition)

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_CFG_CYCLE
    assert result.pointer_use is None

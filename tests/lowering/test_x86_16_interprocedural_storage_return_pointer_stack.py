"""Real IR/Alias/Widening tests for returned pointers spilled to the stack."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.ir import IRValue, MemSpace
from inertia.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.interprocedural_storage_contracts import (
    StorageDefinitionKind8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
)
from inertia.lowering.interprocedural_storage_return_pointer import (
    classify_pointer_return_storage_8616,
)
from inertia.lowering.interprocedural_storage_return_pointer_witness import (
    pointer_return_witness_use_8616,
)
from inertia.lowering.interprocedural_storage_return_type_contracts import (
    ReturnStorageTypeVerdict8616,
)

CALLER_ADDR = 0x1000
CALLSITE_ADDR = 0x1000
WITNESS_ADDR = 0x1003


def _fact() -> CallerReturnUseFact8616:
    return CallerReturnUseFact8616(
        caller_addr=CALLER_ADDR,
        callsite_addr=CALLSITE_ADDR,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=CallsiteReturnUseKind8616.VALUE,
        witness_instruction_addr=WITNESS_ADDR,
    )


def _lift_witness_body(code: bytes) -> SSAFunctionArtifact:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": WITNESS_ADDR,
            "entry_point": WITNESS_ADDR,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=CALLER_ADDR, block_addrs_set={WITNESS_ADDR}, info={})
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert not artifact.refusals
    return build_x86_16_function_ssa(artifact)


def _register_storage() -> StorageIdentity8616:
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=2,
        register="ax",
    )


def _direct_call_output_definition() -> StorageReachingDefinition8616:
    return StorageReachingDefinition8616(
        value=IRValue(MemSpace.REG, name="ax", size=2),
        block_addr=CALLER_ADDR,
        instr_index=0,
        instr_addr=CALLSITE_ADDR,
        source_storage=_register_storage(),
        definition_kind=StorageDefinitionKind8616.CALL_OUTPUT,
    )


def test_alias_versioned_stack_spill_and_reload_proves_pointer_return() -> None:
    artifact = _lift_witness_body(bytes.fromhex("8946fe31c08b5efe8b0fc3"))

    result = classify_pointer_return_storage_8616(
        artifact,
        _fact(),
        _direct_call_output_definition(),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.PROVEN
    assert result.complete
    assert result.pointer_use is not None
    assert result.pointer_use.carrier_register == "bx"
    assert len(result.pointer_use.stack_transfers) == 2
    spill, reload = result.pointer_use.stack_transfers
    assert spill.storage_version == reload.storage_version
    uses, conflict = pointer_return_witness_use_8616(
        artifact,
        _fact(),
        result.pointer_use,
        (_register_storage(),),
    )
    assert conflict is False
    assert uses is not None
    assert uses[0].instr_addr == WITNESS_ADDR
    assert uses[0].instr_index == 0


def test_full_stack_overwrite_breaks_returned_pointer_lineage() -> None:
    artifact = _lift_witness_body(bytes.fromhex("8946fe31c0c746fe34128b5efe8b0fc3"))

    result = classify_pointer_return_storage_8616(
        artifact,
        _fact(),
        _direct_call_output_definition(),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.pointer_use is None


def test_partial_stack_overwrite_breaks_returned_pointer_lineage() -> None:
    artifact = _lift_witness_body(bytes.fromhex("8946fe31c0c646ff128b5efe8b0fc3"))

    result = classify_pointer_return_storage_8616(
        artifact,
        _fact(),
        _direct_call_output_definition(),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.pointer_use is None

"""Real IR/SSA tests for exact near-pointer return-use proof."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from angr.sim_type import SimTypeChar
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.ir import AddressStatus, IRAddress
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
import inertia.lowering.interprocedural_storage_return_trial_materialization as materialization
from inertia.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageContract8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageSlotContract8616,
    StorageTrialFailureKind8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from inertia.lowering.interprocedural_storage_return_defs import (
    resolve_call_output_definitions_8616,
)
from inertia.lowering.interprocedural_storage_return_pointer import (
    classify_pointer_return_storage_8616,
    proven_pointer_return_pointee_width_8616,
)
from inertia.lowering.interprocedural_storage_return_type_contracts import (
    ReturnStorageTypeFailure8616,
    ReturnStorageTypeVerdict8616,
)
from inertia.lowering.interprocedural_storage_simtypes import (
    StorageSimTypeFailureKind8616,
    StorageSimTypeVerdict8616,
    storage_contract_return_type_8616,
)
from inertia.lowering.interprocedural_storage_slot_join import (
    join_storage_slot_contracts_8616,
)
from inertia.lowering.near_pointer_type import near_pointer_type_8616

from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from inertia.semantics.call_target_evidence_8616 import resolve_call_target_evidence_8616

CALLER_ADDR = 0x1000
CALLSITE_ADDR = 0x1000
WITNESS_ADDR = 0x1003
CALLEE_ADDR = 0x1013


def _fact(
    *,
    witness: int = WITNESS_ADDR,
    kind: CallsiteReturnUseKind8616 = CallsiteReturnUseKind8616.VALUE,
) -> CallerReturnUseFact8616:
    return CallerReturnUseFact8616(
        caller_addr=CALLER_ADDR,
        callsite_addr=CALLSITE_ADDR,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=kind,
        witness_instruction_addr=witness,
    )


def _register(name: str = "ax", width: int = 2) -> StorageIdentity8616:
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=width,
        register=name,
    )


def _lift_ssa(code_after_call: bytes) -> tuple[SSAFunctionArtifact, angr.Project]:
    """Retain the caller's native project and byte-backed callee evidence."""
    code = bytes.fromhex("e81000") + code_after_call
    assert len(code) <= CALLEE_ADDR - CALLER_ADDR
    image = code + bytes(CALLEE_ADDR - CALLER_ADDR - len(code)) + bytes.fromhex("c3")
    project = angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": CALLER_ADDR,
            "entry_point": CALLER_ADDR,
        },
        auto_load_libs=False,
    )
    caller = exact_function_range_boundary_8616(project, CALLER_ADDR, CALLER_ADDR + len(code))
    callee = exact_function_range_boundary_8616(project, CALLEE_ADDR, CALLEE_ADDR + 1)
    assert caller is not None and callee is not None
    artifact = build_x86_16_ir_function_artifact(project, caller)
    callee_artifact = build_x86_16_ir_function_artifact(project, callee)
    assert not artifact.refusals and not callee_artifact.refusals
    publish_function_ir_artifact_8616(project, artifact)
    publish_function_ir_artifact_8616(project, callee_artifact)
    build_boundary_direct_callsite_index_8616(
        caller,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    return build_x86_16_function_ssa(artifact), project


def _definition(
    artifact: SSAFunctionArtifact,
    fact: CallerReturnUseFact8616,
    *,
    project: object | None = None,
) -> StorageReachingDefinition8616:
    """Resolve a carrier with the native project when its target is symbolic."""
    evidence = None if project is None else resolve_call_target_evidence_8616(project, CALLER_ADDR)
    result = resolve_call_output_definitions_8616(
        artifact,
        fact,
        CALLEE_ADDR,
        (CALLEE_ADDR,),
        (_register(),),
        project=project,
        callsite_index=None if evidence is None or not evidence.complete else evidence.callsite_index,
        projection=None if evidence is None or not evidence.complete else evidence.projection,
    )
    assert result.complete
    return result.definitions[0]


def _with_address_status(
    artifact: SSAFunctionArtifact,
    status: AddressStatus,
) -> SSAFunctionArtifact:
    changed = False
    blocks = []
    for block in artifact.blocks:
        instructions = []
        for instruction in block.instrs:
            arguments = tuple(
                replace(argument, status=status) if isinstance(argument, IRAddress) else argument
                for argument in instruction.args
            )
            changed = changed or arguments != instruction.args
            instructions.append(replace(instruction, args=arguments))
        blocks.append(replace(block, instrs=tuple(instructions)))
    assert changed
    return replace(artifact, blocks=tuple(blocks))


def test_ax_copy_to_bx_then_ds_load_proves_pointer_return() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact, project=project),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.PROVEN
    assert result.complete
    assert result.signedness is StorageTrialSignedness8616.NOT_APPLICABLE
    assert result.value_class is StorageTrialValueClass8616.POINTER
    assert result.pointer_use is not None
    assert result.pointer_use.carrier_register == "bx"
    assert result.pointer_use.address.space.value == "ds"
    assert result.pointer_use.dereference_instruction_addr == 0x1005
    assert any(step.target.name == "bx" for step in result.pointer_use.aliases)


def test_word_dereference_width_survives_return_trial_to_c_type(monkeypatch) -> None:
    """One exact returned AX pointer-to-word use must not decay to void pointer."""
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    monkeypatch.setattr(
        materialization,
        "semantic_function_ssa_artifact_at_address_8616",
        lambda *_args, **_kwargs: SimpleNamespace(artifact=artifact),
    )

    trials, failure = materialization.materialize_callsite_return_trials_8616(
        project, CALLEE_ADDR, fact, (_register(),), (CALLEE_ADDR,), {},
    )

    assert failure is None
    assert trials is not None and len(trials) == 1
    assert trials[0].pointee_width_bytes == 2
    pointer_use = trials[0].pointer_use
    assert pointer_use is not None and pointer_use.complete
    assert pointer_use.caller_addr == trials[0].caller_addr
    assert pointer_use.callsite_addr == trials[0].callsite_addr
    assert pointer_use.address.space.value == "ds"
    assert pointer_use.dereference_instruction_addr == 0x1005
    assert pointer_use.aliases
    assert trials[0].is_complete
    slots, join_failure = join_storage_slot_contracts_8616(
        (CallsiteStorageTrials8616(CALLER_ADDR, CALLEE_ADDR, CALLSITE_ADDR, returns=trials),),
        StorageTrialRole8616.RETURN,
    )
    assert join_failure is None
    assert slots is not None and len(slots) == 1
    assert slots[0].pointee_width_bytes == 2
    contract = FunctionStorageContract8616(CALLEE_ADDR, (), slots, 0, ())
    return_type = storage_contract_return_type_8616(contract, Arch86_16())
    assert return_type.accepted
    assert return_type.c_type == "unsigned short *"


def test_retained_pointer_use_requires_exact_trial_binding(monkeypatch) -> None:
    """Foreign callers, calls, witnesses and scalar roles cannot borrow a pointer proof."""
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    monkeypatch.setattr(
        materialization,
        "semantic_function_ssa_artifact_at_address_8616",
        lambda *_args, **_kwargs: SimpleNamespace(artifact=artifact),
    )
    trials, failure = materialization.materialize_callsite_return_trials_8616(
        project, CALLEE_ADDR, fact, (_register(),), (CALLEE_ADDR,), {},
    )
    assert failure is None and trials is not None
    trial = trials[0]
    pointer_use = trial.pointer_use
    assert pointer_use is not None and trial.is_complete
    corrupted_uses = (
        replace(pointer_use, caller_addr=pointer_use.caller_addr + 1),
        replace(pointer_use, callsite_addr=pointer_use.callsite_addr + 1),
        replace(pointer_use, witness_instruction_addr=pointer_use.witness_instruction_addr + 1),
        replace(pointer_use, address=replace(pointer_use.address, status=AddressStatus.UNKNOWN)),
    )
    for corrupted in corrupted_uses:
        assert not replace(trial, pointer_use=corrupted).is_complete
    assert not replace(trial, role=StorageTrialRole8616.INPUT).is_complete
    assert not replace(trial, value_class=StorageTrialValueClass8616.VALUE).is_complete


def test_conflicting_caller_dereference_widths_refuse_pointer_return(monkeypatch) -> None:
    """A byte caller and word caller cannot establish one pointee type."""
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    monkeypatch.setattr(
        materialization,
        "semantic_function_ssa_artifact_at_address_8616",
        lambda *_args, **_kwargs: SimpleNamespace(artifact=artifact),
    )
    trials, failure = materialization.materialize_callsite_return_trials_8616(
        project, CALLEE_ADDR, fact, (_register(),), (CALLEE_ADDR,), {},
    )
    assert failure is None and trials is not None
    pointer_use = trials[0].pointer_use
    assert pointer_use is not None
    word_site = CallsiteStorageTrials8616(
        CALLER_ADDR, CALLEE_ADDR, CALLSITE_ADDR, returns=trials,
    )
    byte_site = CallsiteStorageTrials8616(
        CALLER_ADDR + 0x100, CALLEE_ADDR, CALLSITE_ADDR + 0x100,
        returns=(
            replace(
                trials[0],
                caller_addr=CALLER_ADDR + 0x100,
                callsite_addr=CALLSITE_ADDR + 0x100,
                reaching_definition=replace(
                    trials[0].reaching_definition,
                    instr_addr=CALLSITE_ADDR + 0x100,
                ),
                use=replace(trials[0].use, callsite_addr=CALLSITE_ADDR + 0x100),
                pointee_width_bytes=1,
                pointer_use=replace(
                    pointer_use,
                    caller_addr=CALLER_ADDR + 0x100,
                    callsite_addr=CALLSITE_ADDR + 0x100,
                ),
            ),
        ),
    )
    assert byte_site.returns[0].is_complete

    slots, join_failure = join_storage_slot_contracts_8616(
        (word_site, byte_site), StorageTrialRole8616.RETURN,
    )

    assert slots is None
    assert join_failure is StorageTrialFailureKind8616.POINTEE_WIDTH_CONFLICT


def test_missing_logical_operand_does_not_infer_width_from_byte_slice() -> None:
    """Pointer class may be proven while pointee width remains unknown."""
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    result = classify_pointer_return_storage_8616(
        artifact, fact, _definition(artifact, fact, project=project),
    )
    assert result.complete and result.pointer_use is not None
    assert result.pointer_use.address.size == 1

    width = proven_pointer_return_pointee_width_8616(
        replace(artifact, logical_memory=None), result.pointer_use,
    )

    assert width is None
    slot = StorageSlotContract8616(
        role=StorageTrialRole8616.RETURN,
        logical_index=0,
        pieces=(_register(),),
        signedness=StorageTrialSignedness8616.NOT_APPLICABLE,
        value_class=StorageTrialValueClass8616.POINTER,
    )
    projected = storage_contract_return_type_8616(
        FunctionStorageContract8616(CALLEE_ADDR, (), (slot,), 0, ()),
        Arch86_16(),
    )
    assert projected.verdict is StorageSimTypeVerdict8616.REFUSED
    assert projected.failures == (StorageSimTypeFailureKind8616.POINTEE_WIDTH_UNKNOWN,)


def test_existing_pointer_with_conflicting_pointee_width_is_refused() -> None:
    """A concrete prior byte pointee cannot override a proved word access."""
    arch = Arch86_16()
    slot = StorageSlotContract8616(
        role=StorageTrialRole8616.RETURN,
        logical_index=0,
        pieces=(_register(),),
        signedness=StorageTrialSignedness8616.NOT_APPLICABLE,
        value_class=StorageTrialValueClass8616.POINTER,
        pointee_width_bytes=2,
    )
    prior = near_pointer_type_8616(SimTypeChar(signed=False).with_arch(arch), arch)

    projected = storage_contract_return_type_8616(
        FunctionStorageContract8616(CALLEE_ADDR, (), (slot,), 0, ()),
        arch,
        existing_type=prior,
    )

    assert projected.verdict is StorageSimTypeVerdict8616.REFUSED
    assert projected.failures == (StorageSimTypeFailureKind8616.POINTEE_WIDTH_CONFLICT,)


def test_ax_copy_to_si_then_ds_store_proves_pointer_return() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c6890cc3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact, project=project),
    )

    assert result.complete
    assert result.pointer_use is not None
    assert result.pointer_use.carrier_register == "si"
    assert result.pointer_use.dereference_instruction_addr == 0x1005


def test_mixed_base_address_refuses_pointer_class() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c38b08c3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact, project=project),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_ADDRESS_AMBIGUOUS
    assert result.pointer_use is None


def test_clobbered_alias_refuses_later_dereference() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c331db8b0fc3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact, project=project),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_ALIAS_CLOBBERED


def test_scalar_copy_without_dereference_does_not_prove_pointer() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c389d9c3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact, project=project),
    )

    assert result.failure is ReturnStorageTypeFailure8616.POINTER_DEREFERENCE_NOT_FOUND
    assert result.value_class is None


def test_wrong_witness_and_non_value_use_refuse_before_alias_scan() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    definition = _definition(artifact, fact, project=project)

    wrong_witness = classify_pointer_return_storage_8616(
        artifact,
        _fact(witness=0x1004),
        definition,
    )
    wrong_kind = classify_pointer_return_storage_8616(
        artifact,
        _fact(kind=CallsiteReturnUseKind8616.CONDITION),
        definition,
    )

    assert wrong_witness.failure is ReturnStorageTypeFailure8616.POINTER_WITNESS_NOT_FOUND
    assert wrong_kind.failure is ReturnStorageTypeFailure8616.RETURN_USE_NOT_VALUE


def test_call_output_identity_conflict_refuses_pointer_proof() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    definition = _definition(artifact, fact, project=project)

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        replace(definition, instr_addr=0x1001),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.CONFLICT
    assert result.failure is ReturnStorageTypeFailure8616.CALL_OUTPUT_DEFINITION_CONFLICT


def test_versioned_call_output_refuses_pointer_proof() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    definition = _definition(artifact, fact, project=project)

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        replace(definition, value=replace(definition.value, version=0)),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.CALL_OUTPUT_DEFINITION_UNKNOWN


def test_provisional_segmented_address_refuses_pointer_proof() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    artifact = _with_address_status(artifact, AddressStatus.PROVISIONAL)
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        artifact,
        fact,
        _definition(artifact, fact, project=project),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_ADDRESS_UNKNOWN


def test_duplicate_witness_blocks_are_a_typed_conflict() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()
    conflicting = replace(artifact, blocks=artifact.blocks + artifact.blocks)

    result = classify_pointer_return_storage_8616(
        conflicting,
        fact,
        _definition(artifact, fact, project=project),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.CONFLICT
    assert result.failure is ReturnStorageTypeFailure8616.POINTER_WITNESS_CONFLICT


def test_caller_identity_mismatch_is_a_typed_conflict() -> None:
    artifact, project = _lift_ssa(bytes.fromhex("89c38b0fc3"))
    fact = _fact()

    result = classify_pointer_return_storage_8616(
        replace(artifact, function_addr=0x2000),
        fact,
        _definition(artifact, fact, project=project),
    )

    assert result.verdict is ReturnStorageTypeVerdict8616.CONFLICT
    assert result.failure is ReturnStorageTypeFailure8616.CALLER_IDENTITY_CONFLICT

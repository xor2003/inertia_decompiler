"""Production return storage-trial collection over real lifted IR and SSA."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseEvidence8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY, Lifter86_16  # noqa: F401
from inertia.lowering.interprocedural_storage_collection_contracts import (
    FunctionInputStorageTrialCollection8616,
    StorageTrialCollectionVerdict8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
)
from inertia.lowering.interprocedural_storage_return_collection_contracts import (
    FunctionReturnStorageTrialCollection8616,
    ReturnStorageTrialCollectionFailureKind8616,
)
from inertia.lowering.interprocedural_storage_return_trial_collection import (
    collect_function_return_storage_trials_8616,
)
from inertia.lowering.interprocedural_storage_return_type_contracts import (
    ReturnStorageTypeFailure8616,
)
from inertia.lowering.interprocedural_storage_simtypes import (
    StorageSimTypeVerdict8616,
    storage_contract_return_type_8616,
)
from inertia.lowering.interprocedural_storage_solver import (
    resolve_program_storage_trials_8616,
)
from tests.lowering.x86_16_native_call_fixtures import retain_native_call_index_8616

CALLER_ADDR = 0x1000
CALLSITE_ADDR = 0x1000
CALLEE_ADDR = 0x1020


class _Functions8616:
    """Exact fake function manager over real angr block lifting."""

    def __init__(self, functions: tuple[object, ...]) -> None:
        self._functions = functions

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return the unique exact function address, if present."""
        return next(
            (
                function
                for function in self._functions
                if isinstance(function, SimpleNamespace) and function.addr == addr
            ),
            None,
        )


def _project(
    caller_code: bytes,
    caller_blocks: set[int],
    callee_code: bytes = bytes.fromhex("b80100c3"),
) -> tuple[angr.Project, SimpleNamespace]:
    """Build one real-lifter caller/callee project with exact boundaries."""
    padding = bytes(CALLEE_ADDR - CALLER_ADDR - len(caller_code))
    lifted = angr.Project(
        io.BytesIO(caller_code + padding + callee_code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": CALLER_ADDR,
            "entry_point": CALLER_ADDR,
        },
        auto_load_libs=False,
    )
    caller = SimpleNamespace(
        addr=CALLER_ADDR,
        block_addrs_set=caller_blocks,
        blocks=tuple(lifted.factory.block(address, opt_level=0) for address in sorted(caller_blocks)),
        info={},
    )
    callee = SimpleNamespace(
        addr=CALLEE_ADDR,
        block_addrs_set={CALLEE_ADDR},
        info={},
    )
    lifted.kb.functions = _Functions8616((caller, callee))
    retain_native_call_index_8616(lifted, CALLER_ADDR, CALLER_ADDR + len(caller_code))
    return lifted, callee


def _inputs() -> FunctionInputStorageTrialCollection8616:
    """Build one complete zero-argument input census for the real callsite."""
    trials = FunctionStorageTrials8616(
        function_addr=CALLEE_ADDR,
        caller_census_complete=True,
        expected_callsite_addrs=(CALLSITE_ADDR,),
        callsites=(
            CallsiteStorageTrials8616(
                caller_addr=CALLER_ADDR,
                callee_addr=CALLEE_ADDR,
                callsite_addr=CALLSITE_ADDR,
                stack_delta=0,
            ),
        ),
    )
    return FunctionInputStorageTrialCollection8616(
        verdict=StorageTrialCollectionVerdict8616.PROVEN,
        trials=trials,
        failures=(),
        stats=StorageTrialStats8616(1, 1, 1, 1),
    )


def _evidence(
    kind: CallsiteReturnUseKind8616,
    witness: int,
    *,
    verdict: CallerReturnUseVerdict8616 = CallerReturnUseVerdict8616.USED,
) -> CallerReturnUseEvidence8616:
    """Build one structurally closed exact caller-use census."""
    fact = CallerReturnUseFact8616(
        caller_addr=CALLER_ADDR,
        callsite_addr=CALLSITE_ADDR,
        verdict=verdict,
        kind=kind,
        witness_instruction_addr=witness,
    )
    used = int(verdict is CallerReturnUseVerdict8616.USED)
    unused = int(verdict is CallerReturnUseVerdict8616.UNUSED)
    return CallerReturnUseEvidence8616(
        target_addr=CALLEE_ADDR,
        verdict=verdict,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=used,
        unused_callsite_count=unused,
        callsite_addrs=(CALLSITE_ADDR,),
        facts=(fact,),
    )


def _collect(
    project: angr.Project,
    callee: SimpleNamespace,
    evidence: CallerReturnUseEvidence8616,
) -> FunctionReturnStorageTrialCollection8616:
    """Collect with an isolated typed-condition cache."""
    original_cache = Instruction_ANY._inertia_module_condition_cache
    Instruction_ANY._inertia_module_condition_cache = {}
    try:
        return collect_function_return_storage_trials_8616(
            project,
            callee,
            _inputs(),
            evidence,
        )
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache


def test_signed_ax_condition_materializes_solver_ready_return_trial() -> None:
    project, callee = _project(
        bytes.fromhex("e81d0083f8007c0190c3"),
        {0x1000, 0x1003, 0x1008, 0x1009},
    )

    result = _collect(
        project,
        callee,
        _evidence(CallsiteReturnUseKind8616.CONDITION, 0x1003),
    )

    assert result.complete, result.failures
    assert result.stats.complete
    trial = result.trials.callsites[0].returns[0]
    assert trial.storage.register == "ax"
    assert trial.use.instr_addr == 0x1003
    assert trial.signedness is StorageTrialSignedness8616.SIGNED
    assert trial.value_class is StorageTrialValueClass8616.VALUE
    contract = resolve_program_storage_trials_8616((result.trials,)).contract_for(
        CALLEE_ADDR
    )
    assert contract is not None
    assert tuple(piece.register for piece in contract.outputs[0].pieces) == ("ax",)


def test_ax_alias_to_segmented_load_materializes_pointer_return_trial() -> None:
    project, callee = _project(
        bytes.fromhex("e81d0089c38b0fc3"),
        {0x1000, 0x1003},
    )

    result = _collect(
        project,
        callee,
        _evidence(CallsiteReturnUseKind8616.VALUE, 0x1003),
    )

    assert result.complete
    trial = result.trials.callsites[0].returns[0]
    assert trial.signedness is StorageTrialSignedness8616.NOT_APPLICABLE
    assert trial.value_class is StorageTrialValueClass8616.POINTER
    assert trial.reaching_definition.instr_addr == CALLSITE_ADDR


def test_closed_unused_return_preserves_callsite_without_output_trial() -> None:
    project, callee = _project(
        bytes.fromhex("e81d00b80000c3"),
        {0x1000, 0x1003},
    )

    result = _collect(
        project,
        callee,
        _evidence(
            CallsiteReturnUseKind8616.CLOBBERED,
            0x1003,
            verdict=CallerReturnUseVerdict8616.UNUSED,
        ),
    )

    assert result.complete
    assert result.trials.callsites[0].returns == ()
    contract = resolve_program_storage_trials_8616((result.trials,)).contract_for(
        CALLEE_ADDR
    )
    assert contract is not None and contract.outputs == ()


@pytest.mark.parametrize(
    ("caller_code", "caller_blocks", "caller_edges"),
    (
        (
            bytes.fromhex("e81d00803e341200750190c3"),
            {0x1000, 0x1003, 0x100A, 0x100B},
            ((0x1000, 0x1003), (0x1003, 0x100A), (0x1003, 0x100B)),
        ),
        (
            bytes.fromhex("e81d00a0341288c380fb00750190c3"),
            {0x1000, 0x1003, 0x100D, 0x100E},
            ((0x1000, 0x1003), (0x1003, 0x100D), (0x1003, 0x100E), (0x100D, 0x100E)),
        ),
    ),
    ids=("direct-memory-condition", "same-block-register-copy-condition"),
)
def test_global_condition_materializes_live_out_without_c_return(
    caller_code: bytes,
    caller_blocks: set[int],
    caller_edges: tuple[tuple[int, int], ...],
) -> None:
    project, callee = _project(
        caller_code,
        caller_blocks,
        bytes.fromhex("b001a23412c3"),
    )
    caller = project.kb.functions._functions[0]
    caller.graph = SimpleNamespace(edges=caller_edges)

    result = _collect(
        project,
        callee,
        _evidence(
            CallsiteReturnUseKind8616.CLOBBERED,
            0x1003,
            verdict=CallerReturnUseVerdict8616.UNUSED,
        ),
    )

    assert result.complete, result.failures[0].live_out_failure
    callsite = result.trials.callsites[0]
    assert callsite.returns == ()
    assert len(callsite.live_outs) == 1
    assert len(callsite.memory_effects) == 1
    assert callsite.memory_effects[0].complete is True
    assert callsite.live_outs[0].storage.address is not None
    assert callsite.live_outs[0].storage.address.offset == 0x1234
    contract = resolve_program_storage_trials_8616((result.trials,)).contract_for(CALLEE_ADDR)
    assert contract is not None
    assert contract.outputs == () and len(contract.memory_outputs) == 1
    assert contract.callsites[0].memory_effects == callsite.memory_effects
    return_type = storage_contract_return_type_8616(contract, Arch86_16())
    assert return_type.verdict is StorageSimTypeVerdict8616.UNPROVEN


def test_corrupt_return_census_refuses_without_partial_contract() -> None:
    project, callee = _project(
        bytes.fromhex("e81d0083f8007c0190c3"),
        {0x1000, 0x1003, 0x1008, 0x1009},
    )
    evidence = replace(
        _evidence(CallsiteReturnUseKind8616.CONDITION, 0x1003),
        used_callsite_count=0,
    )

    result = _collect(project, callee, evidence)

    assert not result.complete
    assert result.trials.callsites == ()
    assert result.failures[0].kind is (
        ReturnStorageTrialCollectionFailureKind8616.INCOMPLETE_RETURN_CENSUS
    )
    assert resolve_program_storage_trials_8616((result.trials,)).contract_for(
        CALLEE_ADDR
    ) is None


def test_dx_ax_condition_refuses_until_split_type_use_is_proven() -> None:
    project, callee = _project(
        bytes.fromhex("e81d0083f8007c0190c3"),
        {0x1000, 0x1003, 0x1008, 0x1009},
        bytes.fromhex("b80100ba0200c3"),
    )

    result = _collect(
        project,
        callee,
        _evidence(CallsiteReturnUseKind8616.CONDITION, 0x1003),
    )

    assert not result.complete
    assert result.trials.callsites == ()
    failure = result.failures[0]
    assert failure.kind is ReturnStorageTrialCollectionFailureKind8616.RETURN_TYPE_REFUSED
    assert failure.type_failure is ReturnStorageTypeFailure8616.SPLIT_CONDITION_NOT_FOUND


def test_dx_ax_wide_condition_materializes_exact_split_return_uses() -> None:
    project, callee = _project(
        bytes.fromhex("e81d003b56fe7e02eb097d02eb063b46fc7601c3c3"),
        {0x1000, 0x1003, 0x1008, 0x100A, 0x100C, 0x100E, 0x1013, 0x1014},
        bytes.fromhex("b80100ba0200c3"),
    )

    result = _collect(
        project,
        callee,
        _evidence(CallsiteReturnUseKind8616.CONDITION, 0x1003),
    )

    assert result.complete, result.failures
    assert result.failures == ()
    assert result.stats == StorageTrialStats8616(1, 1, 1, 1)
    returns = result.trials.callsites[0].returns
    assert tuple(
        (
            trial.storage.register,
            trial.use.block_addr,
            trial.use.instr_index,
            trial.use.instr_addr,
        )
        for trial in returns
    ) == (
        ("ax", 0x100E, 0, 0x100E),
        ("dx", 0x1003, 0, 0x1003),
    )
    assert all(trial.signedness is StorageTrialSignedness8616.SIGNED for trial in returns)
    assert all(trial.value_class is StorageTrialValueClass8616.VALUE for trial in returns)
    contract = resolve_program_storage_trials_8616((result.trials,)).contract_for(CALLEE_ADDR)
    assert contract is not None
    assert tuple(piece.register for piece in contract.outputs[0].pieces) == ("ax", "dx")


def test_exact_function_and_target_identity_conflicts_are_typed() -> None:
    project, callee = _project(
        bytes.fromhex("e81d0083f8007c0190c3"),
        {0x1000, 0x1003, 0x1008, 0x1009},
    )

    wrong_function = _collect(
        project,
        SimpleNamespace(
            addr=0x1030,
            block_addrs_set=callee.block_addrs_set,
            info={},
        ),
        _evidence(CallsiteReturnUseKind8616.CONDITION, 0x1003),
    )
    wrong_target = _collect(
        project,
        callee,
        replace(
            _evidence(CallsiteReturnUseKind8616.CONDITION, 0x1003),
            target_addr=0x1030,
        ),
    )

    assert wrong_function.verdict is StorageTrialCollectionVerdict8616.CONFLICT
    assert wrong_function.failures[0].kind is (
        ReturnStorageTrialCollectionFailureKind8616.FUNCTION_IDENTITY_CONFLICT
    )
    assert wrong_target.verdict is StorageTrialCollectionVerdict8616.CONFLICT
    assert wrong_target.failures[0].kind is (
        ReturnStorageTrialCollectionFailureKind8616.RETURN_TARGET_CONFLICT
    )

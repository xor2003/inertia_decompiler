"""Real-lifter tests for deferred recursive return pass-through trials."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseEvidence8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir import IRValue, MemSpace
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering.interprocedural_storage_collection_contracts import (
    FunctionInputStorageTrialCollection8616,
    StorageTrialCollectionVerdict8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageDefinitionKind8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrial8616,
    StorageTrialFailureKind8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
    ValueProvenance8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_passthrough import (
    materialize_return_passthrough_trial_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_passthrough_contracts import (
    ReturnPassThroughTrialFailure8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_return_trial_collection import (
    collect_function_return_storage_trials_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_solver import (
    resolve_program_storage_trials_8616,
)

FUNCTION_ADDR = 0x1000
CALLSITE_ADDR = 0x1000
RETURN_ADDR = 0x1003


class _Graph8616:
    """Exact post-call function graph for the recursive fixture."""

    def __init__(self) -> None:
        self.nodes = (
            SimpleNamespace(addr=CALLSITE_ADDR, size=3),
            SimpleNamespace(addr=RETURN_ADDR, size=1),
        )
        self._nodes_by_addr = {node.addr: node for node in self.nodes}

    def successors(self, node: SimpleNamespace) -> tuple[SimpleNamespace, ...]:
        """Return the unique post-call edge to the terminal return."""
        addresses = (RETURN_ADDR,) if node.addr == CALLSITE_ADDR else ()
        return tuple(self._nodes_by_addr[address] for address in addresses)


class _Functions8616:
    """Exact function manager for one recursive function."""

    def __init__(self, function: SimpleNamespace) -> None:
        self._function = function

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return the existing function only at its exact address."""
        assert create is False
        return self._function if addr == self._function.addr else None


def _project_and_function() -> tuple[angr.Project, SimpleNamespace]:
    """Lift `call self; ret` with exact SSA and post-call CFG boundaries."""
    lifted = angr.Project(
        io.BytesIO(bytes.fromhex("e8fdffc3")),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": FUNCTION_ADDR,
            "entry_point": FUNCTION_ADDR,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(
        addr=FUNCTION_ADDR,
        block_addrs_set={CALLSITE_ADDR, RETURN_ADDR},
        graph=_Graph8616(),
        info={},
    )
    # Only the function inventory is a fixture; native bytes, loader, arch and
    # project identity remain those of the real source-backed project.
    lifted.kb.functions = _Functions8616(function)
    boundary = exact_function_range_boundary_8616(lifted, FUNCTION_ADDR, RETURN_ADDR + 1)
    assert boundary is not None
    build_boundary_direct_callsite_index_8616(
        boundary,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(lifted, instruction),
    )
    return lifted, function


def _fact(*, witness: int = RETURN_ADDR) -> CallerReturnUseFact8616:
    """Build the retained recursive caller-return observation."""
    return CallerReturnUseFact8616(
        caller_addr=FUNCTION_ADDR,
        callsite_addr=CALLSITE_ADDR,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=CallsiteReturnUseKind8616.FUNCTION_RETURN,
        witness_instruction_addr=witness,
        excluded_recursive_passthrough=True,
    )


def _evidence(fact: CallerReturnUseFact8616) -> CallerReturnUseEvidence8616:
    """Build a closed census whose only fact is the recursive pass-through."""
    return CallerReturnUseEvidence8616(
        target_addr=FUNCTION_ADDR,
        verdict=CallerReturnUseVerdict8616.UNKNOWN,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=0,
        materialized_count=0,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=0,
        callsite_addrs=(CALLSITE_ADDR,),
        facts=(fact,),
        excluded_callsite_count=1,
    )


def _inputs() -> FunctionInputStorageTrialCollection8616:
    """Build one complete zero-argument recursive callsite census."""
    return FunctionInputStorageTrialCollection8616(
        verdict=StorageTrialCollectionVerdict8616.PROVEN,
        trials=FunctionStorageTrials8616(
            function_addr=FUNCTION_ADDR,
            caller_census_complete=True,
            expected_callsite_addrs=(CALLSITE_ADDR,),
            callsites=(
                CallsiteStorageTrials8616(
                    caller_addr=FUNCTION_ADDR,
                    callee_addr=FUNCTION_ADDR,
                    callsite_addr=CALLSITE_ADDR,
                    stack_delta=0,
                ),
            ),
        ),
        failures=(),
        stats=StorageTrialStats8616(1, 1, 1, 1),
    )


def _direct_ax_return_trial(
    *,
    caller_addr: int = 0x2000,
    callsite_addr: int = 0x2010,
) -> StorageTrial8616:
    """Build one complete nonrecursive caller seed for the AX return slot."""
    storage = StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=2,
        register="ax",
    )
    return StorageTrial8616(
        callee_addr=FUNCTION_ADDR,
        caller_addr=caller_addr,
        callsite_addr=callsite_addr,
        role=StorageTrialRole8616.RETURN,
        logical_index=0,
        piece_index=0,
        piece_count=1,
        storage=storage,
        reaching_definition=StorageReachingDefinition8616(
            value=IRValue(space=MemSpace.REG, name="ax", size=2),
            block_addr=caller_addr,
            instr_index=0,
            instr_addr=callsite_addr,
            source_storage=storage,
            definition_kind=StorageDefinitionKind8616.CALL_OUTPUT,
        ),
        use=StorageUseEvidence8616(
            block_addr=caller_addr,
            instr_index=1,
            instr_addr=callsite_addr + 3,
            callsite_addr=callsite_addr,
        ),
        signedness=StorageTrialSignedness8616.SIGNED,
        value_class=StorageTrialValueClass8616.VALUE,
        provenance=ValueProvenance8616(
            function_addr=FUNCTION_ADDR,
            definition_addr=callsite_addr,
            token=callsite_addr,
        ),
    )


def test_recursive_passthrough_retains_exact_ssa_call_and_semantic_return() -> None:
    project, _function = _project_and_function()

    result = materialize_return_passthrough_trial_8616(
        project,
        FUNCTION_ADDR,
        _fact(),
        (FUNCTION_ADDR,),
    )

    assert result.complete
    assert result.trial is not None
    assert result.trial.call_block_addr == CALLSITE_ADDR
    assert result.trial.callsite_addr == CALLSITE_ADDR
    assert result.trial.target_addr == FUNCTION_ADDR
    assert result.trial.return_instruction_addr == RETURN_ADDR
    assert result.trial.path_block_addrs == (CALLSITE_ADDR, RETURN_ADDR)


def test_recursive_passthrough_refuses_mismatched_return_witness() -> None:
    project, _function = _project_and_function()

    result = materialize_return_passthrough_trial_8616(
        project,
        FUNCTION_ADDR,
        _fact(witness=0x1002),
        (FUNCTION_ADDR,),
    )

    assert not result.complete
    assert result.trial is None
    assert result.failure is ReturnPassThroughTrialFailure8616.RETURN_WITNESS_CONFLICT


def test_return_collector_retains_deferred_trial_but_solver_refuses_without_seed() -> None:
    project, function = _project_and_function()

    collection = collect_function_return_storage_trials_8616(
        project,
        function,
        _inputs(),
        _evidence(_fact()),
    )

    assert collection.complete
    assert collection.stats.complete
    assert collection.trials.callsites[0].returns == ()
    assert len(collection.trials.callsites[0].return_passthroughs) == 1
    resolution = resolve_program_storage_trials_8616((collection.trials,))
    function_resolution = resolution.resolutions[0]
    assert function_resolution.contract is None
    assert function_resolution.failures == (
        StorageTrialFailureKind8616.PASSTHROUGH_OUTPUT_UNRESOLVED,
    )


def test_direct_output_seed_resolves_recursive_passthrough_at_scc_fixed_point() -> None:
    project, _function = _project_and_function()
    passthrough_result = materialize_return_passthrough_trial_8616(
        project,
        FUNCTION_ADDR,
        _fact(),
        (FUNCTION_ADDR,),
    )
    passthrough = passthrough_result.trial
    assert passthrough_result.complete
    assert passthrough is not None
    direct_return = _direct_ax_return_trial()
    trials = FunctionStorageTrials8616(
        function_addr=FUNCTION_ADDR,
        caller_census_complete=True,
        expected_callsite_addrs=(CALLSITE_ADDR, direct_return.callsite_addr),
        callsites=(
            CallsiteStorageTrials8616(
                caller_addr=FUNCTION_ADDR,
                callee_addr=FUNCTION_ADDR,
                callsite_addr=CALLSITE_ADDR,
                return_passthroughs=(passthrough,),
                stack_delta=0,
            ),
            CallsiteStorageTrials8616(
                caller_addr=direct_return.caller_addr,
                callee_addr=FUNCTION_ADDR,
                callsite_addr=direct_return.callsite_addr,
                returns=(direct_return,),
                stack_delta=0,
            ),
        ),
    )

    resolution = resolve_program_storage_trials_8616((trials,))

    assert resolution.iterations_by_scc == (3,)
    assert resolution.stats.complete
    contract = resolution.contract_for(FUNCTION_ADDR)
    assert contract is not None
    assert len(contract.outputs) == 1
    assert tuple(piece.register for piece in contract.outputs[0].pieces) == ("ax",)
    recursive_binding = contract.callsites[0]
    assert recursive_binding.callsite_addr == CALLSITE_ADDR
    assert recursive_binding.returns == ()
    assert recursive_binding.return_passthroughs == (passthrough,)


def test_direct_and_passthrough_evidence_at_one_callsite_conflicts() -> None:
    project, _function = _project_and_function()
    passthrough_result = materialize_return_passthrough_trial_8616(
        project,
        FUNCTION_ADDR,
        _fact(),
        (FUNCTION_ADDR,),
    )
    passthrough = passthrough_result.trial
    assert passthrough is not None
    direct_return = _direct_ax_return_trial(
        caller_addr=FUNCTION_ADDR,
        callsite_addr=CALLSITE_ADDR,
    )
    trials = FunctionStorageTrials8616(
        function_addr=FUNCTION_ADDR,
        caller_census_complete=True,
        expected_callsite_addrs=(CALLSITE_ADDR,),
        callsites=(
            CallsiteStorageTrials8616(
                caller_addr=FUNCTION_ADDR,
                callee_addr=FUNCTION_ADDR,
                callsite_addr=CALLSITE_ADDR,
                returns=(direct_return,),
                return_passthroughs=(passthrough,),
                stack_delta=0,
            ),
        ),
    )

    result = resolve_program_storage_trials_8616((trials,)).resolutions[0]

    assert result.contract is None
    assert result.failures == (StorageTrialFailureKind8616.CALLSITE_SET_CONFLICT,)


def test_symbolic_passthrough_refuses_without_retained_decoded_census() -> None:
    """A symbolic CALL cannot borrow an unretained target from the CFG."""
    project, _function = _project_and_function()
    del project._inertia_decoded_callsite_indexes_8616
    result = materialize_return_passthrough_trial_8616(
        project, FUNCTION_ADDR, _fact(), (FUNCTION_ADDR,),
    )
    assert not result.complete
    assert result.trial is None
    assert result.failure is ReturnPassThroughTrialFailure8616.CALL_TARGET_UNKNOWN


def test_symbolic_passthrough_refuses_an_unrelated_admitted_callee() -> None:
    """Native self-call evidence cannot discharge another callee relation."""
    project, _function = _project_and_function()
    result = materialize_return_passthrough_trial_8616(
        project, FUNCTION_ADDR + 0x100, _fact(), (FUNCTION_ADDR + 0x100,),
    )
    assert not result.complete
    assert result.trial is None
    assert result.failure is ReturnPassThroughTrialFailure8616.CALL_TARGET_UNKNOWN

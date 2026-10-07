"""Bind callee-entry DS runtime selectors only on exact replayable evidence."""

from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable
from inertia.ir import SegmentOrigin
from inertia.ir.segment_call_preservation import (
    SegmentCallPreservationResult8616,
)
from inertia.ir.segment_state_transfer import (
    SegmentRegisterState,
    SegmentValueKind8616,
)
from inertia.lowering.near_return_entry_selector import (
    NearReturnEntrySelector8616,
    NearReturnEntrySelectorFailure8616,
    bind_near_return_entry_selector_8616,
)
from inertia.lowering.near_return_segment_use import (
    NearReturnSegmentUse8616,
    NearReturnSegmentUseFailure8616,
    bind_near_return_data_segment_use_8616,
)
from inertia.lowering.near_return_selector import _unsigned_int_bits_8616
from inertia.lowering.segment_register_state import (
    runtime_segment_name_for_variable_8616,
    runtime_segment_state_cvar_8616,
)
from tests.lowering.test_x86_16_near_return_segment_use import _receipt


class _Codegen(SimpleNamespace):
    """Minimal structured-codegen boundary for focused selector binding tests."""

    _index = 0

    def next_node_idx(self) -> int:
        """Return one deterministic node index."""
        self._index += 1
        return self._index

    def next_ident(self, name: str) -> str:
        """Return the requested deterministic identifier."""
        return name


def _bound(
    caller_write: bool = False,
    callee_write: bool = False,
) -> tuple[NearReturnSegmentUse8616, SegmentCallPreservationResult8616, angr.Project]:
    """Return the segment-use receipt chain built on the real binary."""
    use, preservation, project = _receipt(
        caller_write=caller_write, callee_write=callee_write
    )
    segment_use = bind_near_return_data_segment_use_8616(use, preservation, (preservation,))
    return segment_use, preservation, project


def _callee_codegen(
    project: angr.Project, preservation: SegmentCallPreservationResult8616
) -> _Codegen:
    """Return a codegen surface naming the proven callee on the real project."""
    callee_addr = preservation.callee.coverage.artifact.function_addr
    return _Codegen(cfunc=SimpleNamespace(addr=callee_addr), project=project)


def test_entry_selector_binds_proven_callee_entry_ds() -> None:
    """A complete receipt plus exact callee codegen yields a bound selector."""
    segment_use, preservation, project = _bound()
    assert segment_use.complete
    codegen = _callee_codegen(project, preservation)
    result = bind_near_return_entry_selector_8616(codegen, segment_use)
    assert result.complete
    assert (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
    ) == (1, 1, 1, 1, 0)
    callee_addr = preservation.callee.coverage.artifact.function_addr
    assert result.callee_addr == callee_addr and result.codegen is codegen
    selector = result.selector
    assert type(selector) is structured_c.CVariable and selector.codegen is codegen
    assert selector.variable_type is result.selector_type
    assert _unsigned_int_bits_8616(selector.variable_type, 16)
    variable = selector.variable
    assert isinstance(variable, SimMemoryVariable)
    assert runtime_segment_name_for_variable_8616(variable) == "ds"
    assert variable.region == callee_addr and variable.size == 2


def test_selector_replay_does_not_allocate_codegen_nodes() -> None:
    """Repeated proof inspection must not change the codegen allocation state."""
    segment_use, preservation, project = _bound()
    codegen = _callee_codegen(project, preservation)
    result = bind_near_return_entry_selector_8616(codegen, segment_use)
    before = codegen._index
    assert result.complete
    assert result.complete
    assert codegen._index == before


@pytest.mark.parametrize(
    "mode", ("wrong_callee", "missing_cfunc", "missing_project", "foreign_project")
)
def test_entry_selector_refuses_unbound_codegen(mode: str) -> None:
    """Codegen surfaces that cannot name the proven callee refuse."""
    segment_use, preservation, project = _bound()
    callee_addr = preservation.callee.coverage.artifact.function_addr
    cfunc = SimpleNamespace(addr=0x1000 if mode == "wrong_callee" else callee_addr)
    codegen = _Codegen(cfunc=cfunc, project=project)
    if mode == "missing_cfunc":
        codegen = _Codegen(project=project)
    elif mode == "missing_project":
        codegen = _Codegen(cfunc=cfunc)
    elif mode == "foreign_project":
        codegen = _Codegen(cfunc=cfunc, project=SimpleNamespace(arch=project.arch))
    result = bind_near_return_entry_selector_8616(codegen, segment_use)
    expected = {
        "wrong_callee": NearReturnEntrySelectorFailure8616.CALLEE_MISMATCH,
        "missing_cfunc": NearReturnEntrySelectorFailure8616.CODEGEN_SURFACE_UNPROVEN,
        "missing_project": NearReturnEntrySelectorFailure8616.CODEGEN_SURFACE_UNPROVEN,
        "foreign_project": NearReturnEntrySelectorFailure8616.PROJECT_MISMATCH,
    }[mode]
    assert result.failure is expected and not result.complete
    assert result.classified_fact_count == result.materialized_count == 0
    assert result.failure_count == 1


@pytest.mark.parametrize("mode", ("missing", "replaced"))
def test_entry_selector_refuses_stale_registered_ir(mode: str) -> None:
    """A registry that no longer holds the proven callee artifact refuses."""
    segment_use, preservation, project = _bound()
    codegen = _callee_codegen(project, preservation)
    callee_addr = preservation.callee.coverage.artifact.function_addr
    registry = vars(project)["_inertia_function_ir_artifacts_8616"]
    if mode == "missing":
        del registry[callee_addr]
    else:
        registry[callee_addr] = replace(preservation.callee.coverage.artifact)
    # The registered segment-preservation receipt already rechecks raw IR.
    # Refusal therefore happens upstream, before the local registry join.
    assert not segment_use.complete
    result = bind_near_return_entry_selector_8616(codegen, segment_use)
    assert result.failure is NearReturnEntrySelectorFailure8616.SEGMENT_USE_INCOMPLETE
    assert not result.complete and result.failure_count == 1
    assert result.classified_fact_count == result.materialized_count == 0


def test_entry_selector_refuses_lost_architectural_live_in() -> None:
    """A preserved entry identity without live-in provenance cannot bind."""
    segment_use, preservation, project = _bound()
    codegen = _callee_codegen(project, preservation)
    callee_addr = preservation.callee.coverage.artifact.function_addr
    state = preservation.callee.state
    entry = state.entry_states[callee_addr]["ds"]
    assert entry.origin is SegmentOrigin.PROVEN
    state.entry_states[callee_addr]["ds"] = SegmentRegisterState(
        "ds", SegmentValueKind8616.MERGED_PROVEN, "ds", SegmentOrigin.PROVEN
    )
    # Preservation still holds: the same proven source reaches every exit.
    assert segment_use.complete
    result = bind_near_return_entry_selector_8616(codegen, segment_use)
    assert result.failure is NearReturnEntrySelectorFailure8616.ENTRY_LIVE_IN_UNPROVEN
    assert not result.complete and result.failure_count == 1


@pytest.mark.parametrize("mode", ("caller_write", "callee_write"))
def test_entry_selector_refuses_incomplete_segment_use(mode: str) -> None:
    """An unproven receipt cannot reach the selector at all."""
    segment_use, preservation, project = _bound(
        caller_write=mode == "caller_write", callee_write=mode == "callee_write"
    )
    assert not segment_use.complete
    codegen = _callee_codegen(project, preservation)
    result = bind_near_return_entry_selector_8616(codegen, segment_use)
    assert result.failure is NearReturnEntrySelectorFailure8616.SEGMENT_USE_INCOMPLETE
    assert result.upstream_failure is segment_use.failure
    assert (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
    ) == (1, 0, 0, 0, 1)
    assert not result.complete


def _mutated_result(mode: str) -> NearReturnEntrySelector8616:
    """Return one bound result with exactly one obligation corrupted."""
    segment_use, preservation, project = _bound()
    codegen = _callee_codegen(project, preservation)
    callee_addr = preservation.callee.coverage.artifact.function_addr
    result = bind_near_return_entry_selector_8616(codegen, segment_use)
    assert result.complete
    selector = result.selector
    assert selector is not None
    variable = selector.variable
    assert isinstance(variable, SimMemoryVariable)
    if mode == "mutated_type":
        selector.variable_type = SimTypeLong(False).with_arch(project.arch)
    elif mode == "foreign_variable":
        selector.variable = SimMemoryVariable(
            variable.addr + 2,
            variable.size,
            name=variable.name,
            region=variable.region,
            category=variable.category,
        )
    elif mode == "named_local":
        selector.variable = SimMemoryVariable(
            variable.addr, variable.size, name=variable.name, region=variable.region
        )
    elif mode == "wrong_region":
        variable.region = 0x1000
    elif mode == "swapped_cvar_codegen":
        foreign = _Codegen(cfunc=SimpleNamespace(addr=callee_addr), project=project)
        result = replace(
            result,
            selector=runtime_segment_state_cvar_8616(
                "ds",
                codegen=foreign,
                variable_type=SimTypeShort(False),
                function_addr=callee_addr,
            ),
        )
    elif mode == "detached_codegen":
        result = replace(
            result,
            codegen=_Codegen(cfunc=SimpleNamespace(addr=callee_addr), project=project),
        )
    elif mode == "other_callee":
        result = replace(result, callee_addr=0x1000)
    elif mode == "upstream_failure":
        result = replace(result, upstream_failure=NearReturnSegmentUseFailure8616.CALL_UNBOUND)
    elif mode == "stale_registry":
        del vars(project)["_inertia_function_ir_artifacts_8616"][callee_addr]
    else:
        result = replace(result, segment_use=replace(segment_use, materialized_count=0))
    return result


@pytest.mark.parametrize(
    "mode",
    (
        "mutated_type",
        "foreign_variable",
        "named_local",
        "wrong_region",
        "swapped_cvar_codegen",
        "detached_codegen",
        "other_callee",
        "stale_registry",
        "stale_receipt",
        "upstream_failure",
    ),
)
def test_complete_recheck_refuses_mutated_selector_or_receipt(mode: str) -> None:
    """The retained binding replays every obligation before consumption."""
    assert not _mutated_result(mode).complete

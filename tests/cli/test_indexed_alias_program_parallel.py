from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from inertia.ir.core import IRFunctionArtifact
from inertia.ir.function_ir_registry import (
    registered_function_ir_artifact_8616,
)
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactStage8616,
    registered_function_ssa_artifact_8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact

from inertia.alias.indexed_address_program import (
    IndexedAliasFunctionEvidence8616,
    IndexedAliasFunctionRefusal8616,
    IndexedAliasFunctionSelection8616,
    IndexedAliasProgramFailureKind8616,
    assemble_indexed_alias_program_evidence_8616,
)
import inertia.cli.indexed_alias_program_parallel as indexed_alias_program_parallel
from inertia.cli.indexed_alias_program_parallel import (
    build_indexed_alias_program_evidence_bounded_8616,
    indexed_alias_program_worker_count_8616,
)


def _refusal(function_addr: int) -> IndexedAliasFunctionRefusal8616:
    return IndexedAliasFunctionRefusal8616(
        function_addr,
        IndexedAliasProgramFailureKind8616.FUNCTION_MISSING,
        "test function is unavailable",
    )


def test_program_assembly_closes_and_orders_exact_results() -> None:
    program = assemble_indexed_alias_program_evidence_8616(
        (_refusal(0x2000), _refusal(0x1000)),
        (0x1000, 0x2000),
    )

    assert program.closed
    assert tuple(item.function_addr for item in program.refusals) == (
        0x1000,
        0x2000,
    )
    assert program.stats.raw_fact_count == program.stats.failure_count == 2


def test_program_assembly_refuses_missing_result() -> None:
    with pytest.raises(ValueError, match="do not match selections"):
        assemble_indexed_alias_program_evidence_8616(
            (_refusal(0x1000),),
            (0x1000, 0x2000),
        )


def test_worker_policy_requires_explicit_enablement_with_memory_cap(monkeypatch) -> None:
    monkeypatch.setattr(os, "cpu_count", lambda: 16)
    monkeypatch.delenv("INERTIA_INDEXED_ALIAS_WORKERS", raising=False)

    assert indexed_alias_program_worker_count_8616(1) == 1
    assert indexed_alias_program_worker_count_8616(20) == 1
    assert indexed_alias_program_worker_count_8616(20, max_workers=2) == 2

    monkeypatch.setenv("INERTIA_INDEXED_ALIAS_WORKERS", "3")
    assert indexed_alias_program_worker_count_8616(20) == 3
    monkeypatch.setenv("INERTIA_INDEXED_ALIAS_WORKERS", "invalid")
    assert indexed_alias_program_worker_count_8616(20) == 1


def test_bounded_workers_return_deterministic_closed_refusals(monkeypatch) -> None:
    class _DeterministicJobPool:
        def __init__(self, *, max_workers, worker_func, name_prefix) -> None:
            assert max_workers == 2
            assert name_prefix == "indexed_alias"
            self.worker_func = worker_func

        def run_unordered(self, jobs):
            return tuple(
                (job_id, self.worker_func(payload))
                for job_id, payload in reversed(jobs)
            )

        def shutdown(self) -> None:
            return None

    def _unexpected_sequential(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("eligible bounded build must not fall back to serial")

    monkeypatch.setattr(
        indexed_alias_program_parallel,
        "build_indexed_alias_program_evidence_8616",
        _unexpected_sequential,
    )
    monkeypatch.setattr(
        indexed_alias_program_parallel,
        "PreforkJobPool",
        _DeterministicJobPool,
    )
    selections = tuple(
        IndexedAliasFunctionSelection8616(address, None)
        for address in (0x3000, 0x1000, 0x2000)
    )

    program = build_indexed_alias_program_evidence_bounded_8616(
        SimpleNamespace(),
        selections,
        max_workers=2,
    )

    assert program.closed
    assert tuple(item.function_addr for item in program.refusals) == (
        0x1000,
        0x2000,
        0x3000,
    )


def test_bounded_workers_fall_back_when_job_set_is_incomplete(monkeypatch) -> None:
    class _IncompleteJobPool:
        def __init__(self, *, max_workers, worker_func, name_prefix) -> None:
            assert max_workers == 2
            assert name_prefix == "indexed_alias"
            self.worker_func = worker_func

        def run_unordered(self, jobs):
            job_id, payload = jobs[0]
            return ((job_id, self.worker_func(payload)),)

        def shutdown(self) -> None:
            return None

    fallback_calls: list[tuple[int, ...]] = []

    def _sequential_fallback(_project, selections):
        addresses = tuple(selection.function_addr for selection in selections)
        fallback_calls.append(addresses)
        return assemble_indexed_alias_program_evidence_8616(
            tuple(_refusal(address) for address in addresses),
            addresses,
        )

    monkeypatch.setattr(
        indexed_alias_program_parallel,
        "build_indexed_alias_program_evidence_8616",
        _sequential_fallback,
    )
    monkeypatch.setattr(
        indexed_alias_program_parallel,
        "PreforkJobPool",
        _IncompleteJobPool,
    )
    selections = tuple(
        IndexedAliasFunctionSelection8616(address, None)
        for address in (0x2000, 0x1000)
    )

    program = build_indexed_alias_program_evidence_bounded_8616(
        SimpleNamespace(),
        selections,
        max_workers=2,
    )

    assert program.closed
    assert fallback_calls == [(0x1000, 0x2000)]


def test_parent_republishes_worker_ir_and_ssa(monkeypatch) -> None:
    project = SimpleNamespace()
    function_addr = 0x1000
    function_evidence = object.__new__(IndexedAliasFunctionEvidence8616)
    raw_ir = IRFunctionArtifact(function_addr, ())
    raw_ssa = SSAFunctionArtifact(function_addr, ())
    rebuilt: list[IRFunctionArtifact] = []

    def _build_ssa(artifact: IRFunctionArtifact) -> SSAFunctionArtifact:
        rebuilt.append(artifact)
        return raw_ssa

    monkeypatch.setattr(
        indexed_alias_program_parallel,
        "build_x86_16_function_ssa",
        _build_ssa,
    )
    bundle = indexed_alias_program_parallel._IndexedAliasFunctionBundle8616(
        function_evidence,
        raw_ir,
    )

    indexed_alias_program_parallel._publish_parent_artifacts_8616(project, bundle)

    assert registered_function_ir_artifact_8616(project, function_addr).artifact is raw_ir
    registered_ssa = registered_function_ssa_artifact_8616(project, function_addr)
    assert rebuilt == [raw_ir]
    assert registered_ssa.artifact is raw_ssa
    assert registered_ssa.stage is FunctionSSAArtifactStage8616.IR

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
import inertia.lowering.fixed_stack_probe_frames as fixed_stack_probe_frames
import inertia.lowering.stack_probe_callsite_lowering as stack_probe_callsite_lowering
from inertia.lowering.fixed_stack_probe_frames import lower_fixed_stack_probe_frames_8616


def test_stack_probe_replay_uses_supplied_codegen_current_project(monkeypatch) -> None:
    """The bound replay must not capture an obsolete project or codegen."""
    first_project, second_project = object(), object()
    codegen = SimpleNamespace(project=first_project)
    calls = []

    def lower(project, actual_codegen):
        calls.append((project, actual_codegen))
        return project is second_project

    monkeypatch.setattr(stack_probe_callsite_lowering, "lower_fixed_stack_probe_callsite_artifacts_8616", lower)
    replay = stack_probe_callsite_lowering.replay_fixed_stack_probe_callsite_artifacts_8616
    assert replay(codegen) is False
    codegen.project = second_project
    assert replay(codegen) is True
    assert calls == [(first_project, codegen), (second_project, codegen)]


def _fixed_probe_codegen(
    *,
    allocation_size: int,
    local_offset: int = -2,
    stack_probe_helper: bool = True,
    return_used: bool = False,
) -> tuple[SimpleNamespace, CStatements, CFunctionCall]:
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_idx=lambda _name: 0,
        project=SimpleNamespace(arch=Arch86_16()),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    call = CFunctionCall(
        "chkstk",
        SimpleNamespace(addr=0x11222),
        [],
        tags={"ins_addr": 0x1006},
        codegen=codegen,
    )
    local = CVariable(
        SimStackVariable(local_offset, 2, base="bp", name="local_2", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(
        local,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements(
        [CExpressionStatement(call, codegen=codegen), assignment],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1006,
            target_addr=0x11222,
            return_addr=0x1009,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=return_used,
            stack_probe_helper=stack_probe_helper,
            stack_probe_allocation_size=allocation_size,
        )
    }
    return codegen, root, call


def test_lowers_fixed_unused_probe_covered_by_recovered_bp_frame() -> None:
    codegen, root, call = _fixed_probe_codegen(allocation_size=2)

    stats = lower_fixed_stack_probe_frames_8616(codegen)

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.recovered_frame_extent == 2
    assert all(
        not (isinstance(statement, CExpressionStatement) and statement.expr is call)
        for statement in root.statements
    )


def test_refuses_name_only_probe_without_typed_helper_evidence() -> None:
    codegen, root, call = _fixed_probe_codegen(
        allocation_size=2,
        stack_probe_helper=False,
    )

    stats = lower_fixed_stack_probe_frames_8616(codegen)

    assert stats.raw_fact_count == 0
    assert stats.materialized_count == 0
    assert any(
        isinstance(statement, CExpressionStatement) and statement.expr is call
        for statement in root.statements
    )


def test_zero_typed_probe_facts_refuse_ast_traversal(monkeypatch) -> None:
    """No typed input facts must close the evidence loop without AST work."""
    codegen, _root, _call = _fixed_probe_codegen(
        allocation_size=2,
        stack_probe_helper=False,
    )

    def refuse_walk(_root: object) -> Iterator[object]:
        raise AssertionError("zero fixed-probe facts must not traverse the AST")
        yield

    monkeypatch.setattr(
        fixed_stack_probe_frames,
        "_iter_c_nodes_deep_8616",
        refuse_walk,
    )

    stats = lower_fixed_stack_probe_frames_8616(codegen)

    assert stats == fixed_stack_probe_frames.FixedStackProbeFrameLoweringStats8616(
        0, 0, 0, 0, 0, 0, 0
    )


def test_positive_typed_probe_facts_use_one_ast_census(monkeypatch) -> None:
    """Positive evidence must share one read-only AST census."""
    codegen, _root, _call = _fixed_probe_codegen(allocation_size=2)
    original = fixed_stack_probe_frames._iter_c_nodes_deep_8616
    walk_count = 0

    def counted_walk(root: object) -> Iterator[object]:
        nonlocal walk_count
        walk_count += 1
        yield from original(root)

    monkeypatch.setattr(
        fixed_stack_probe_frames,
        "_iter_c_nodes_deep_8616",
        counted_walk,
    )

    stats = lower_fixed_stack_probe_frames_8616(codegen)

    assert stats.materialized_count == 1
    assert walk_count == 1


def test_refuses_probe_not_covered_by_frame_or_with_live_return() -> None:
    shallow_codegen, shallow_root, shallow_call = _fixed_probe_codegen(allocation_size=4)
    live_codegen, live_root, live_call = _fixed_probe_codegen(allocation_size=2, return_used=True)

    shallow_stats = lower_fixed_stack_probe_frames_8616(shallow_codegen)
    live_stats = lower_fixed_stack_probe_frames_8616(live_codegen)

    assert shallow_stats.classified_fact_count == 0
    assert live_stats.classified_fact_count == 0
    assert any(
        isinstance(statement, CExpressionStatement) and statement.expr is shallow_call
        for statement in shallow_root.statements
    )
    assert any(
        isinstance(statement, CExpressionStatement) and statement.expr is live_call
        for statement in live_root.statements
    )


def test_lowers_assigned_fixed_probe_when_return_is_unused() -> None:
    codegen, root, call = _fixed_probe_codegen(allocation_size=2)
    carrier = CVariable(
        SimRegisterVariable(0, 4, name="eax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    root.statements[0] = CAssignment(carrier, call, codegen=codegen)

    stats = lower_fixed_stack_probe_frames_8616(codegen)

    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert all(
        not (isinstance(statement, CAssignment) and statement.rhs is call)
        for statement in root.statements
    )

from __future__ import annotations

from types import SimpleNamespace

from inertia.semantics.callsite_summary import CallsiteSummary8616
import inertia.lowering.callee_argument_count_evidence as count_module
import inertia.lowering.callee_callsite_census as census_module
import inertia.lowering.callee_range_callsite_facts as range_module
from inertia.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountVerdict8616,
    collect_callee_argument_count_evidence_8616,
)

from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from inertia.frontend.x86_16.frontend_function_boundary_index import (
    ExactFunctionRangeInventory8616,
)
from inertia.widening.stack_argument_widths import (
    WideStackArgumentWidthEvidence8616,
)


def _summary(callsite_addr: int, target_addr: int, argument_count: int) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=callsite_addr + 3,
        kind="near",
        arg_count=argument_count,
        arg_widths=(2,) * argument_count,
        stack_cleanup=argument_count * 2,
        return_register=None,
        return_used=False,
        push_arg_sources=tuple(("imm", index) for index in range(argument_count)),
    )


def _project() -> SimpleNamespace:
    functions = [
        SimpleNamespace(name="caller_a", addr=0x100),
        SimpleNamespace(name="caller_b", addr=0x120),
    ]
    return SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(values=lambda: functions)),
    )


def test_callee_argument_count_evidence_proves_zero_from_all_callers(monkeypatch) -> None:
    project = _project()
    targets = {
        "caller_a": [SimpleNamespace(callsite_addr=0x110, target_addr=0x200, return_addr=0x113, kind="near")],
        "caller_b": [SimpleNamespace(callsite_addr=0x120, target_addr=0x200, return_addr=0x123, kind="near")],
    }
    summaries = {0x110: _summary(0x110, 0x200, 0), 0x120: _summary(0x120, 0x200, 0)}
    monkeypatch.setattr(census_module, "collect_neighbor_call_targets", lambda function: targets[function.name])
    monkeypatch.setattr(census_module, "summarize_x86_16_callsite", lambda _function, addr: summaries[addr])

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
    assert evidence.argument_count == 0
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 2
    assert evidence.classified_fact_count == evidence.materialized_count == 2
    assert evidence.failure_count == 0
    assert evidence.closes_census is True
    assert tuple(fact.caller_addr for fact in evidence.callsite_facts) == (0x100, 0x120)
    assert tuple(fact.caller_function.name for fact in evidence.callsite_facts) == (
        "caller_a",
        "caller_b",
    )


def test_callee_argument_count_evidence_refuses_incomplete_caller_census(monkeypatch) -> None:
    project = _project()
    targets = {
        "caller_a": [SimpleNamespace(callsite_addr=0x110, target_addr=0x200, return_addr=0x113, kind="near")],
        "caller_b": [SimpleNamespace(callsite_addr=0x120, target_addr=0x200, return_addr=0x123, kind="near")],
    }
    summaries = {0x110: _summary(0x110, 0x200, 0), 0x120: None}
    monkeypatch.setattr(census_module, "collect_neighbor_call_targets", lambda function: targets[function.name])
    monkeypatch.setattr(census_module, "summarize_x86_16_callsite", lambda _function, addr: summaries[addr])

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.UNKNOWN
    assert evidence.argument_count is None
    assert evidence.raw_fact_count == 2
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_fact_count == evidence.materialized_count == 1
    assert evidence.failure_count == 1
    assert evidence.closes_census is False


def test_callee_argument_count_evidence_preserves_one_push_per_logical_argument(monkeypatch) -> None:
    project = _project()
    target = SimpleNamespace(callsite_addr=0x110, target_addr=0x200, return_addr=0x113, kind="near")
    monkeypatch.setattr(census_module, "collect_neighbor_call_targets", lambda _function: [target])
    monkeypatch.setattr(
        census_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x200, 2),
    )

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
    assert evidence.argument_count == 2


def test_callee_argument_count_evidence_groups_word_pushes_from_closed_callee_widening(
    monkeypatch,
) -> None:
    callers = [SimpleNamespace(name="caller_a", addr=0x100)]
    callee = SimpleNamespace(addr=0x200)
    manager = SimpleNamespace(
        values=lambda: callers,
        function=lambda *, addr, create=False: callee if addr == 0x200 else None,
    )
    project = SimpleNamespace(kb=SimpleNamespace(functions=manager))
    target = SimpleNamespace(callsite_addr=0x110, target_addr=0x200, return_addr=0x113, kind="near")
    monkeypatch.setattr(census_module, "collect_neighbor_call_targets", lambda _function: [target])
    monkeypatch.setattr(
        census_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x200, 2),
    )
    monkeypatch.setattr(
        count_module,
        "collect_wide_stack_argument_width_evidence_8616",
        lambda _project, _function: WideStackArgumentWidthEvidence8616(1, 1, (4,)),
    )

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
    assert evidence.argument_count == 1
    assert evidence.closes_census is True
    assert evidence.callsite_summaries[0].logical_arg_widths == (4,)
    assert evidence.callsite_facts[0].summary is evidence.callsite_summaries[0]


def test_callee_argument_count_evidence_accepts_one_unknown_source_word(monkeypatch) -> None:
    project = _project()
    target = SimpleNamespace(callsite_addr=0x110, target_addr=0x200, return_addr=0x113, kind="near")
    summary = _summary(0x110, 0x200, 1)
    summary = CallsiteSummary8616(
        **{
            **summary.to_dict(),
            "push_arg_sources": (None,),
        }
    )
    monkeypatch.setattr(census_module, "collect_neighbor_call_targets", lambda _function: [target])
    monkeypatch.setattr(census_module, "summarize_x86_16_callsite", lambda _function, _addr: summary)

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
    assert evidence.argument_count == 1
    assert evidence.failure_count == 0


def test_callee_argument_count_evidence_uses_active_project_entry_aliases(monkeypatch) -> None:
    project = _project()
    project._inertia_caller_target_aliases_8616 = (0x200, 0x1F0)
    alias_target = SimpleNamespace(callsite_addr=0x110, target_addr=0x1F0, return_addr=0x113, kind="near")
    monkeypatch.setattr(census_module, "collect_neighbor_call_targets", lambda _function: [alias_target])
    monkeypatch.setattr(
        census_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x1F0, 0),
    )

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
    assert evidence.argument_count == 0
    assert evidence.callsite_addrs == (0x110,)


def test_callee_argument_count_evidence_refuses_unrelated_entry_aliases(monkeypatch) -> None:
    project = _project()
    project._inertia_caller_target_aliases_8616 = (0x200, 0x1F0)
    alias_target = SimpleNamespace(
        callsite_addr=0x110,
        target_addr=0x1F0,
        return_addr=0x113,
        kind="near",
    )
    monkeypatch.setattr(
        census_module,
        "collect_neighbor_call_targets",
        lambda _function: [alias_target],
    )
    monkeypatch.setattr(
        census_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x1F0, 0),
    )

    evidence = collect_callee_argument_count_evidence_8616(project, 0x300)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.UNKNOWN
    assert evidence.raw_fact_count == 0
    assert evidence.callsite_addrs == ()


def test_callee_argument_count_evidence_keeps_distinct_linear_segments(monkeypatch) -> None:
    project = _project()
    other_segment_target = SimpleNamespace(
        callsite_addr=0x110,
        target_addr=0x137E,
        return_addr=0x113,
        kind="near",
    )
    monkeypatch.setattr(
        census_module,
        "collect_neighbor_call_targets",
        lambda _function: [other_segment_target],
    )
    monkeypatch.setattr(
        census_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x137E, 1),
    )

    evidence = collect_callee_argument_count_evidence_8616(project, 0x1137E)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.UNKNOWN
    assert evidence.raw_fact_count == 0
    assert evidence.callsite_addrs == ()


def test_callee_argument_count_evidence_reports_conflicting_callers(monkeypatch) -> None:
    project = _project()
    targets = {
        "caller_a": [SimpleNamespace(callsite_addr=0x110, target_addr=0x200, return_addr=0x113, kind="near")],
        "caller_b": [SimpleNamespace(callsite_addr=0x120, target_addr=0x200, return_addr=0x123, kind="near")],
    }
    summaries = {0x110: _summary(0x110, 0x200, 0), 0x120: _summary(0x120, 0x200, 1)}
    monkeypatch.setattr(census_module, "collect_neighbor_call_targets", lambda function: targets[function.name])
    monkeypatch.setattr(census_module, "summarize_x86_16_callsite", lambda _function, addr: summaries[addr])

    evidence = collect_callee_argument_count_evidence_8616(project, 0x200)

    assert evidence.verdict is CalleeArgumentCountVerdict8616.CONFLICT
    assert evidence.argument_count is None
    assert evidence.failure_count == 1


def test_range_census_canonicalizes_padding_target_before_matching(monkeypatch) -> None:
    instruction = SimpleNamespace(address=0x110, mnemonic="call", operands=())
    disassembler = SimpleNamespace(
        detail=False,
        disasm=lambda _code, _address: (instruction,),
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(capstone=disassembler),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _addr, size: bytes(size))),
    )
    caller = ExactFunctionRangeBoundary8616(
        project=project,
        addr=0x100,
        size=0x20,
        block_addrs_set=frozenset({0x100, 0x110}),
        reachable_instruction_addrs=frozenset({0x100, 0x110}),
        successor_edges=((0x100, 0x110),),
    )
    monkeypatch.setattr(
        range_module,
        "exact_function_range_inventory_8616",
        lambda _project, ranges: ExactFunctionRangeInventory8616(ranges, (caller,)),
    )
    monkeypatch.setattr(
        range_module,
        "_direct_call_target_8616",
        lambda _instruction: 0x1F0,
    )
    monkeypatch.setattr(
        range_module,
        "canonicalize_x86_16_padding_call_target_8616",
        lambda _project, target: 0x200 if target == 0x1F0 else target,
    )
    monkeypatch.setattr(
        range_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x200, 2),
    )

    facts = range_module.collect_range_callsite_facts_for_target_8616(
        project,
        0x200,
        ((0x100, 0x120),),
    )

    assert tuple(fact.callsite_addr for fact in facts) == (0x110,)
    assert tuple(fact.caller_addr for fact in facts) == (0x100,)
    assert facts[0].caller_function.addr == 0x100
    assert facts[0].caller_function.size == 0x20
    assert facts[0].caller_function.project is project
    assert facts[0].caller_function.block_addrs_set == frozenset({0x100, 0x110})


def test_range_census_builds_boundaries_only_for_matching_callers(monkeypatch) -> None:
    calls_by_addr = {
        0x100: SimpleNamespace(address=0x110, mnemonic="call", operands=()),
        0x300: SimpleNamespace(address=0x310, mnemonic="call", operands=()),
    }
    disassembler = SimpleNamespace(
        detail=False,
        disasm=lambda _code, address: (calls_by_addr[address],),
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(capstone=disassembler),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _addr, size: bytes(size))),
    )
    caller = ExactFunctionRangeBoundary8616(
        project=project,
        addr=0x100,
        size=0x20,
        block_addrs_set=frozenset({0x100}),
        reachable_instruction_addrs=frozenset({0x110}),
        successor_edges=(),
    )
    observed_ranges: list[tuple[tuple[int, int], ...]] = []

    def inventory(_project, ranges):
        observed_ranges.append(ranges)
        return ExactFunctionRangeInventory8616(ranges, (caller,))

    monkeypatch.setattr(range_module, "exact_function_range_inventory_8616", inventory)
    monkeypatch.setattr(
        range_module,
        "_direct_call_target_8616",
        lambda instruction: 0x200 if instruction.address == 0x110 else 0x400,
    )
    monkeypatch.setattr(
        range_module,
        "canonicalize_x86_16_padding_call_target_8616",
        lambda _project, target: target,
    )
    monkeypatch.setattr(
        range_module,
        "summarize_x86_16_callsite",
        lambda _function, _addr: _summary(0x110, 0x200, 1),
    )

    facts = range_module.collect_range_callsite_facts_for_target_8616(
        project,
        0x200,
        ((0x100, 0x120), (0x300, 0x320)),
    )

    assert observed_ranges == [((0x100, 0x120),)]
    assert tuple(fact.callsite_addr for fact in facts) == (0x110,)


def test_range_census_decodes_exact_ranges_once_across_callee_queries(monkeypatch) -> None:
    calls_by_addr = {
        0x100: SimpleNamespace(address=0x110, mnemonic="call", operands=()),
        0x300: SimpleNamespace(address=0x310, mnemonic="call", operands=()),
    }
    decoded_ranges: list[int] = []

    def disasm(_code, address):
        decoded_ranges.append(address)
        return (calls_by_addr[address],)

    project = SimpleNamespace(
        arch=SimpleNamespace(capstone=SimpleNamespace(detail=False, disasm=disasm)),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _addr, size: bytes(size))),
    )
    callers = {
        0x100: ExactFunctionRangeBoundary8616(
            project=project,
            addr=0x100,
            size=0x20,
            block_addrs_set=frozenset({0x100}),
            reachable_instruction_addrs=frozenset({0x110}),
            successor_edges=(),
        ),
        0x300: ExactFunctionRangeBoundary8616(
            project=project,
            addr=0x300,
            size=0x20,
            block_addrs_set=frozenset({0x300}),
            reachable_instruction_addrs=frozenset({0x310}),
            successor_edges=(),
        ),
    }
    monkeypatch.setattr(
        range_module,
        "exact_function_range_inventory_8616",
        lambda _project, ranges: ExactFunctionRangeInventory8616(
            ranges,
            tuple(callers[start] for start, _end in ranges),
        ),
    )
    monkeypatch.setattr(
        range_module,
        "_direct_call_target_8616",
        lambda instruction: 0x200 if instruction.address == 0x110 else 0x400,
    )
    monkeypatch.setattr(
        range_module,
        "canonicalize_x86_16_padding_call_target_8616",
        lambda _project, target: target,
    )
    monkeypatch.setattr(
        range_module,
        "summarize_x86_16_callsite",
        lambda _function, addr: _summary(addr, 0x200 if addr == 0x110 else 0x400, 1),
    )
    ranges = ((0x100, 0x120), (0x300, 0x320))

    first = range_module.collect_range_callsite_facts_for_target_8616(project, 0x200, ranges)
    second = range_module.collect_range_callsite_facts_for_target_8616(project, 0x400, ranges)

    assert decoded_ranges == [0x100, 0x300]
    assert tuple(fact.callsite_addr for fact in first) == (0x110,)
    assert tuple(fact.callsite_addr for fact in second) == (0x310,)

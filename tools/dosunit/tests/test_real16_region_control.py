"""Full-selector region control reification and retained refusal controls."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function
from tools.dosunit.tests.test_real16_call_composition import _lower
from unicorn import UC_ARCH_X86, UC_MODE_16
from unicorn.unicorn import Uc
from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_IP

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallLimits,
    Real16CallRefusal,
    const_term,
    initial_state,
)
from tools.dosunit.compare.real16_call_evidence import group_lookup
from tools.dosunit.compare.real16_region_control import (
    RegionControlReason,
    resolve_region_control,
    resolve_region_poststate,
)

CODE = b"\x90" * 17 + bytes.fromhex("ebed")
FUNCTION_ID = "demo.exe:jump"


def _state(tmp_path: Path) -> tuple[FunctionCtx, dict[str, Any]]:
    """Lift a genuine MZ whose terminal JMP crosses a paragraph backwards."""
    module = bytearray(0x300)
    module[0x200:0x200 + len(CODE)] = CODE
    document = _lower(
        tmp_path, bytes(module),
        [_edge_function(FUNCTION_ID, "jump", offset=0x200, size=len(CODE))],
        "body",
    )
    _contexts, ctx = group_lookup(document, FUNCTION_ID)
    block = ctx.blocks[0]
    session = ComposeSession.with_deadline(Real16CallLimits(), 10000)
    state = S._compose_block_outputs(
        block, block["outputs"], initial_state(), compose_stats=session.stats,
    )
    assert const_term(state["control_ip"]) is None
    return ctx, state


def test_actual_symbolic_backedge_resolves_over_all_entry_aliases(tmp_path: Path) -> None:
    """A fetched root proves the backward edge without choosing numeric CS."""
    ctx, state = _state(tmp_path)
    session = ComposeSession.with_deadline(Real16CallLimits(), 10000)
    preserved = {name: term for name, term in state.items() if name not in {"ip", "control_ip"}}
    result = resolve_region_poststate(state, frozenset({ctx.entry_linear}), ctx, session)
    assert const_term(result["control_ip"]) == ctx.entry_linear
    assert const_term(result["ip"]) == ctx.entry_linear & 0xFFFF
    assert state["control_ip"] is not result["control_ip"]
    assert all(result[name] is term for name, term in preserved.items())
    for name in ("raw_fact_count", "normalized_fact_count", "classified_fact_count", "materialized_count"):
        assert session.stats[f"region_control_{name}"] == 1
    assert session.stats["region_control_failure_count"] == 0


def test_isolated_same_jump_retains_native_wrap_countermodel(tmp_path: Path) -> None:
    """Removing root-fetch evidence must retain the larger selector domain."""
    rooted_ctx, state = _state(tmp_path)
    # This is a local coordinate theorem, not a fabricated source-bound
    # function proof. Reuse the actual lifted terminal and change only the
    # theorem's entry premise to that same terminal's physical address.
    ctx = replace(rooted_ctx, entry_linear=rooted_ctx.entry_linear + 17)
    session = ComposeSession.with_deadline(Real16CallLimits(), 10000)
    target = ctx.entry_linear - 17
    with pytest.raises(Real16CallRefusal) as caught:
        resolve_region_control(state["control_ip"], frozenset({target}), ctx, session)
    assert caught.value.reason == RegionControlReason.UNPROVED.value
    assert session.stats["region_control_classified_fact_count"] == 1
    assert session.stats["region_control_materialized_count"] == 0
    assert session.stats["region_control_failure_count"] == 1

    guest = Uc(UC_ARCH_X86, UC_MODE_16)
    guest.mem_map(0, 0x20000)
    guest.mem_write(target, CODE)
    selector = ctx.entry_linear // 16
    guest.reg_write(UC_X86_REG_CS, selector)
    guest.reg_write(UC_X86_REG_IP, ctx.entry_linear - selector * 16)
    guest.emu_start(ctx.entry_linear, 0, count=1)
    actual = guest.reg_read(UC_X86_REG_CS) * 16 + guest.reg_read(UC_X86_REG_IP)
    assert actual == target + 0x10000
    assert actual != target


def test_proved_control_cannot_hide_incoherent_legacy_ip(tmp_path: Path) -> None:
    """A successful full-width target theorem cannot erase a word-IP mutation."""
    ctx, state = _state(tmp_path)
    corrupted = {**state, "ip": {"op": "const", "width": 16, "value": "0x9999"}}
    session = ComposeSession.with_deadline(Real16CallLimits(), 10000)
    with pytest.raises(Real16CallRefusal) as caught:
        resolve_region_poststate(corrupted, frozenset({ctx.entry_linear}), ctx, session)
    assert caught.value.reason == RegionControlReason.PROJECTION.value
    assert corrupted["ip"]["value"] == "0x9999"


@pytest.mark.parametrize("budget", ["deadline", "terms", "compositions"])
def test_region_control_never_replenishes_existing_limits(tmp_path: Path, budget: str) -> None:
    """Term, composition and absolute-deadline limits all remain fail closed."""
    ctx, state = _state(tmp_path)
    limits = Real16CallLimits()
    if budget == "terms":
        limits = replace(limits, max_term_nodes=1)
    elif budget == "compositions":
        limits = replace(limits, max_compositions=0)
    session = ComposeSession.with_deadline(limits, 10000)
    if budget == "deadline":
        session.stats["deadline"] = 0.0
    with pytest.raises((Real16CallRefusal, S.LowerFailure)):
        resolve_region_control(state["control_ip"], frozenset({ctx.entry_linear}), ctx, session)


def test_unknown_control_and_foreign_literal_are_never_metadata_guesses() -> None:
    """Neither a free full-width input nor a conflicting literal can be routed."""
    ctx = FunctionCtx(FUNCTION_ID, "jump", 0x1200, {}, 2, "unused")
    for term in (
        {"op": "input", "width": 32, "name": "eax"},
        {"op": "const", "width": 32, "value": "0x9999"},
    ):
        session = ComposeSession.with_deadline(Real16CallLimits(), 10000)
        with pytest.raises(Real16CallRefusal):
            resolve_region_control(term, frozenset({0x1200}), ctx, session)


def test_branch_guard_order_and_constant_fast_path_survive() -> None:
    """True/false targets and guards stay ordered; no proof query is needed."""
    ctx = FunctionCtx(FUNCTION_ID, "branch", 0x1200, {}, 4, "unused")
    guard = {"op": "input", "width": 1, "name": "zf"}
    term = {"op": "ite", "width": 32, "args": [
        guard, {"op": "const", "width": 32, "value": "0x1202"},
        {"op": "const", "width": 32, "value": "0x1204"},
    ]}
    session = ComposeSession.with_deadline(Real16CallLimits(), 10000)
    proof = resolve_region_control(term, frozenset({0x1202, 0x1204}), ctx, session)
    assert proof.resolved["args"][0] is guard
    assert [const_term(arm) for arm in proof.resolved["args"][1:]] == [0x1202, 0x1204]
    assert proof.counters.raw_fact_count == proof.counters.materialized_count == 2
    assert proof.counters.failure_count == 0

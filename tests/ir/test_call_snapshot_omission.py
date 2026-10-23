"""Layer: IR tests.
Responsibility: preserve call evidence while omitting discarded owned replays.

Regression coverage for the ``call_replay_unobserved`` slice: an ordinary owned
CALL row's discarded snapshot replay may be omitted because the mandatory
fixpoint transfer already ran the identical consult on the identical
converged entry. Interrupt/service rows, foreign consult chains, unknown
effects, branch observers and call-cut blocks always retain replay.
"""

import time
from collections.abc import Callable

import pytest

import inertia.ir.real16_edge_feasibility8616 as edge
from inertia.frontend.x86_16.interrupt_contract import interrupt_core_addr_8616
from inertia.ir.core import IRBlock, IRCondition, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.real16_path_memory8616 import PathMemory8616
from inertia.ir.real16_repeated_store8616 import RepeatedStoreStatus8616
from inertia.ir.ssa_function import build_x86_16_ir_predecessor_map

pytestmark = pytest.mark.decompiler

ApplyCall = Callable[[IRInstr, dict[str, int], PathMemory8616], bool]


def _value(value: int) -> IRValue:
    """One word constant for focused dataflow controls."""
    return IRValue(MemSpace.CONST, const=value, size=2)


def _branch(addr: int, register: str, value: int, target: int) -> IRInstr:
    """Typed equality branch; no rendered-text recovery."""
    return IRInstr(
        "CJMP", None,
        (IRCondition("eq", (IRValue(MemSpace.REG, name=register, size=2), _value(value)), width_bits=16), _value(target)),
        addr=addr,
    )


def _scalar(addr: int, register: str = "cx") -> IRInstr:
    """A pure register-transfer row with a fully owned scalar effect."""
    return IRInstr(
        "Iop_Add16", IRValue(MemSpace.REG, name=register, size=2),
        (_value(1), _value(1)), size=2, addr=addr,
    )


def _ordinary_call(addr: int, target: int) -> IRInstr:
    """An ordinary typed CALL row (word const target, no destination)."""
    return IRInstr("CALL", None, (_value(target),), addr=addr)


def _artifact() -> IRFunctionArtifact:
    """Branch head into a CALL-only arm and a CALL+branch arm, then callsite."""
    return IRFunctionArtifact(0, (
        IRBlock(0, (_branch(0, "ax", 0, 10),), successor_addrs=(10, 20)),
        IRBlock(10, (
            *(_scalar(11 + offset) for offset in range(6)),
            _ordinary_call(17, 40),
        ), successor_addrs=(30,)),
        IRBlock(20, (
            _ordinary_call(21, 41),
            _branch(22, "bx", 0, 28),
        ), successor_addrs=(28, 30)),
        IRBlock(28, (_scalar(28, "di"),), successor_addrs=(30,)),
        IRBlock(30, (_ordinary_call(30, 50),)),
    ))


def _recording_repeat(
    consulted: list[int],
) -> Callable[[IRBlock, dict[str, int], PathMemory8616, bool | None], RepeatedStoreStatus8616]:
    """A repeat hook that records every consultation, always non-candidate."""
    def apply_repeat(
        block: IRBlock, _registers: dict[str, int],
        _memory: PathMemory8616, _direction: bool | None,
    ) -> RepeatedStoreStatus8616:
        consulted.append(block.addr)
        return RepeatedStoreStatus8616.NOT_APPLICABLE
    return apply_repeat


def _recording_call(consulted: list[int]) -> ApplyCall:
    """An ordinary-call hook that records every consulted row address."""
    def apply_call(
        instruction: IRInstr, _registers: dict[str, int], _memory: PathMemory8616,
    ) -> bool:
        consulted.append(instruction.addr)
        return True
    return apply_call


def _feasible(
    *,
    artifact: IRFunctionArtifact | None = None,
    apply_repeat: Callable | None = None,
    apply_call: ApplyCall | None = None,
    repeat_consult_noop: Callable[[IRBlock], bool] | None = None,
    call_replay_unobserved: Callable[[IRInstr], bool] | None = None,
    call_cut: object | None = None,
    work: int = 10000,
) -> edge.Real16EdgeFeasibility8616:
    """Bounded known-bits run over the shared typed fixture."""
    if artifact is None:
        artifact = _artifact()
    kwargs: dict[str, object] = {}
    if repeat_consult_noop is not None:
        kwargs["repeat_consult_noop"] = repeat_consult_noop
    if call_replay_unobserved is not None:
        kwargs["call_replay_unobserved"] = call_replay_unobserved
    if call_cut is not None:
        kwargs["call_cut"] = call_cut
    return edge.invocation_feasible_scope_8616(
        artifact=artifact, dangerous=frozenset(b.addr for b in artifact.blocks),
        predecessor_map=build_x86_16_ir_predecessor_map(artifact),
        head_addr=0, call_block_addr=30, callsite_addr=30,
        seed={}, seed_memory=PathMemory8616(),
        apply_service=lambda *_: False,
        apply_repeat=apply_repeat, apply_call=apply_call,
        iteration_limit=64, deadline=time.monotonic() + 5, work_limit=work,
        **kwargs,
    )


def _same_result(a: edge.Real16EdgeFeasibility8616, b: edge.Real16EdgeFeasibility8616) -> None:
    """Every published field but charged work must match exactly."""
    assert a.converged == b.converged
    assert a.live_blocks == b.live_blocks
    assert a.infeasible_edges == b.infeasible_edges
    assert a.evaluated_cjmps == b.evaluated_cjmps


def test_owned_call_only_blocks_omit_discarded_call_consult() -> None:
    """A proven-confined CALL row drops only its second-pass consultation."""
    base_repeat: list[int] = []
    owned_repeat: list[int] = []
    base_calls: list[int] = []
    owned_calls: list[int] = []
    baseline = _feasible(
        apply_repeat=_recording_repeat(base_repeat),
        apply_call=_recording_call(base_calls),
    )
    result = _feasible(
        apply_repeat=_recording_repeat(owned_repeat),
        apply_call=_recording_call(owned_calls),
        repeat_consult_noop=lambda _block: True,
        call_replay_unobserved=lambda _instruction: True,
    )
    _same_result(baseline, result)
    assert result.work_units < baseline.work_units
    # CALL-only blocks 10 and 30 lose only the discarded replay consult;
    # the mandatory fixpoint transfer still consulted each row at least once.
    for addr in (17, 30):
        assert owned_calls.count(addr) < base_calls.count(addr)
        assert owned_calls.count(addr) >= 1
    # The branch-observed CALL in block 20 keeps its obligatory replay consult.
    assert base_calls.count(21) >= 2
    assert owned_calls.count(21) == base_calls.count(21)


def test_declined_call_verdict_keeps_every_consult() -> None:
    """A per-row False verdict retains the unconditional observable replay."""
    base_calls: list[int] = []
    declined_calls: list[int] = []
    baseline = _feasible(
        apply_repeat=_recording_repeat([]),
        apply_call=_recording_call(base_calls),
    )
    declined = _feasible(
        apply_repeat=_recording_repeat([]),
        apply_call=_recording_call(declined_calls),
        repeat_consult_noop=lambda _block: True,
        call_replay_unobserved=lambda _instruction: False,
    )
    _same_result(baseline, declined)
    assert sorted(declined_calls) == sorted(base_calls)
    # Classification still pays its per-block selection fee.
    assert declined.work_units > baseline.work_units


def test_call_cut_block_keeps_obligatory_replay() -> None:
    """A requested cut on a CALL-only block suppresses the row verdict there."""
    artifact = _artifact()
    call_only = artifact.blocks[1]
    cut = edge.Real16CallCutRequest8616(
        artifact=artifact, block=call_only,
        index=len(call_only.instrs) - 1, instruction=call_only.instrs[-1],
    )
    base_calls: list[int] = []
    owned_calls: list[int] = []
    baseline = _feasible(
        artifact=artifact, apply_call=_recording_call(base_calls), call_cut=cut,
    )
    owned = _feasible(
        artifact=artifact, apply_call=_recording_call(owned_calls),
        repeat_consult_noop=lambda _block: True,
        call_replay_unobserved=lambda _instruction: True, call_cut=cut,
    )
    assert baseline.call_cut is not None
    assert owned.call_cut is not None
    assert owned.call_cut.instruction is cut.instruction
    assert owned.call_cut.registers == baseline.call_cut.registers
    assert owned.call_cut.memory_known == baseline.call_cut.memory_known
    assert owned.call_cut.memory_unknown == baseline.call_cut.memory_unknown
    assert owned.call_cut.direction == baseline.call_cut.direction
    # The cut block replayed: its CALL row consult count is unchanged.
    assert owned_calls.count(17) == base_calls.count(17)
    assert base_calls.count(17) >= 2


def test_no_hook_call_only_blocks_still_omit() -> None:
    """Without apply_call the CALL row has no consult at all: still confined."""
    baseline = _feasible()
    owned = _feasible(
        repeat_consult_noop=lambda _block: True,
        call_replay_unobserved=lambda _instruction: True,
    )
    _same_result(baseline, owned)
    assert owned.work_units < baseline.work_units


def test_call_noop_domain_verdicts() -> None:
    """The owned verdict binds handler identity, row shape and interrupt rows."""
    owner = _domain()
    ordinary = _ordinary_call(30, 40)
    interrupt = IRInstr(
        "CALL", None,
        (IRValue(MemSpace.CONST, const=interrupt_core_addr_8616(0x21), size=2),),
        addr=30,
    )
    malformed = IRInstr("CALL", _value(1), (_value(40),), addr=30)
    row_noop = owner._snapshot_call_unobserved_8616(None, None)
    assert row_noop is not None
    # No handler at all: an ordinary CALL consult is trivially confined.
    assert row_noop(ordinary) is True
    # Interrupt/service rows and non-ordinary targets stay observable.
    assert row_noop(interrupt) is False
    assert row_noop(malformed) is False
    assert row_noop(IRInstr("MOV", None, (_value(1),), addr=30)) is False

    from tests.ir import test_caller_protective_footprint as geometry

    ctx = geometry._context()
    ctx.initial_memory = None
    call = _ordinary_call(100, 40)
    block = IRBlock(100, (call,))
    artifact = IRFunctionArtifact(100, (block,))
    rows = {id(call): (block, call)}
    binding = owner._feasibility_call_handler_8616(
        ctx, artifact, geometry._boundary(ctx, artifact), rows,
    )
    assert binding is not None
    row_noop = owner._snapshot_call_unobserved_8616(binding, binding)
    assert row_noop is not None
    # The canonical binding's consult is confined even for a bound selected
    # row: the fixpoint already ran it. The terminal verdict stays stricter —
    # that consult is not inert, only discarded.
    assert row_noop(call) is True
    assert binding.terminal_noop(call) is False
    initial_memory = ctx.initial_memory
    ctx.initial_memory = object()
    assert row_noop(call) is False
    ctx.initial_memory = initial_memory
    assert row_noop(call) is True
    # A foreign apply callable never gains the confinement verdict.
    foreign = owner._snapshot_call_unobserved_8616(binding, lambda *_args: False)
    assert foreign is not None
    assert foreign(call) is False
    assert foreign(ordinary) is False


def test_call_noop_rebound_producer_declines_per_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every rebound consulted binding drops the confinement verdict."""
    owner = _domain()
    ordinary = _ordinary_call(30, 40)
    row_noop = owner._snapshot_call_unobserved_8616(None, None)
    assert row_noop is not None
    assert row_noop(ordinary) is True
    checked = [
        (owner, "_feasibility_call_handler_8616"),
        (owner, "_feasibility_call_rows_8616"),
        (owner, "interrupt_call_vector_8616"),
        (edge, "interrupt_call_vector_8616"),
        (edge, "_ordinary_call_target_8616"),
        (edge, "_kb_snapshot_observed_8616"),
        (edge, "_kb_block_exit_8616"),
        (edge, "_kb_transfer_effect_8616"),
    ]
    for module, name in checked:
        original = getattr(module, name)
        monkeypatch.setattr(module, name, lambda *args, **kwargs: None)
        assert row_noop(ordinary) is False, name
        monkeypatch.setattr(module, name, original)
        assert row_noop(ordinary) is True, name


def _domain() -> object:
    """Import the invocation-domain owner module."""
    import inertia.ir.real16_invocation_domain as owner
    return owner


@pytest.mark.parametrize('helper', [
    '_feasibility_call_scratch_8616', '_feasibility_call_effect_8616',
    '_consume_cross_call_boundary_8616', '_census_callee_bytes_8616',
])
def test_rebound_call_chain_keeps_snapshot_observed(monkeypatch, helper):
    owner = _domain()
    from tests.ir import test_caller_protective_footprint as geometry

    ctx = geometry._context()
    ctx.initial_memory = None
    row = _ordinary_call(100, 40)
    block = IRBlock(100, (row,))
    artifact = IRFunctionArtifact(100, (block,))
    binding = owner._feasibility_call_handler_8616(
        ctx, artifact, geometry._boundary(ctx, artifact), {id(row): (block, row)})
    assert binding is not None
    predicate = owner._snapshot_call_unobserved_8616(binding, binding)
    assert predicate is not None
    assert predicate(row)
    monkeypatch.setattr(owner, helper, lambda *args, **kwargs: False)
    assert not predicate(row), f'rebound {helper} remains eligible for omission'

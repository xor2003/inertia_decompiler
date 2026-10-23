"""Owned snapshot omission preserves observers, state, and census accounting."""

import time
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

import inertia.ir.real16_edge_feasibility8616 as edge
import inertia.ir.real16_repeated_store8616 as repeat_owner
from inertia.frontend.x86_16.interrupt_contract import interrupt_core_addr_8616
from inertia.ir.core import IRAddress, IRBlock, IRCondition, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.real16_path_memory8616 import PathMemory8616
from inertia.ir.real16_repeated_store8616 import RepeatedStoreStatus8616
from inertia.ir.ssa_function import build_x86_16_ir_predecessor_map

pytestmark = pytest.mark.decompiler


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


def _pure(addr: int, rows: int = 6) -> IRBlock:
    """A branchless scalar-transfer block with no externally observable replay."""
    instrs = tuple(
        IRInstr(
            "Iop_Add16", IRValue(MemSpace.REG, name="cx", size=2),
            (_value(1), _value(offset)), size=2, addr=addr + offset,
        )
        for offset in range(rows)
    )
    return IRBlock(addr, instrs, successor_addrs=(30,))


def _rep_shaped(addr: int) -> IRBlock:
    """Single-row block shaped like a one-instruction repeated store."""
    return IRBlock(
        addr,
        (IRInstr("Iop_Add16", IRValue(MemSpace.REG, name="di", size=2),
                 (_value(1), _value(1)), size=2, addr=addr),),
        successor_addrs=(addr + 2,),
    )


def _load_block(addr: int) -> IRBlock:
    """Pure block whose only external consultation is a LOAD row."""
    load = IRInstr("LOAD", IRValue(MemSpace.TMP, source_tmp=1, size=2),
                   (IRAddress(space=MemSpace.DS, offset=0x40, size=2),), size=2, addr=addr)
    store = IRInstr("Iop_Add16", IRValue(MemSpace.REG, name="bx", size=2),
                    (_value(1), _value(2)), size=2, addr=addr + 1)
    return IRBlock(addr, (load, store), successor_addrs=(30,))


def _artifact() -> IRFunctionArtifact:
    """Branch into two pure arms meeting a REP-shaped block then a CALL."""
    return IRFunctionArtifact(0, (
        IRBlock(0, (_branch(0, "ax", 0, 10),), successor_addrs=(10, 20)),
        _pure(10, rows=5),
        IRBlock(20, _pure(20, rows=4).instrs, successor_addrs=(28,)),
        _rep_shaped(28),
        IRBlock(30, (IRInstr("CALL", None, (_value(40),), addr=30),)),
    ))


def _recording_repeat(
    consulted: list[int],
    applied: frozenset[int] = frozenset(),
) -> Callable[[IRBlock, dict[str, int], PathMemory8616, bool | None], RepeatedStoreStatus8616]:
    """A repeat hook that records every consultation."""
    def apply_repeat(
        block: IRBlock, _registers: dict[str, int],
        _memory: PathMemory8616, _direction: bool | None,
    ) -> RepeatedStoreStatus8616:
        consulted.append(block.addr)
        if block.addr in applied:
            return RepeatedStoreStatus8616.APPLIED
        return RepeatedStoreStatus8616.NOT_APPLICABLE
    return apply_repeat


def _feasible(
    *,
    artifact: IRFunctionArtifact | None = None,
    read_load: Callable | None = None,
    apply_repeat: Callable | None = None,
    repeat_consult_noop: Callable[[IRBlock], bool] | None = None,
    load_reader_readonly: Callable[[], bool] | None = None,
    terminal_call_noop: Callable[[IRInstr], bool] | None = None,
    call_cut: object | None = None,
    work: int = 10000,
) -> edge.Real16EdgeFeasibility8616:
    """Bounded known-bits run over the shared typed fixture."""
    if artifact is None:
        artifact = _artifact()
    kwargs: dict[str, object] = {}
    if repeat_consult_noop is not None:
        kwargs["repeat_consult_noop"] = repeat_consult_noop
    if load_reader_readonly is not None:
        kwargs["load_reader_readonly"] = load_reader_readonly
    if terminal_call_noop is not None:
        kwargs["terminal_call_noop"] = terminal_call_noop
    if call_cut is not None:
        kwargs["call_cut"] = call_cut
    return edge.invocation_feasible_scope_8616(
        artifact=artifact, dangerous=frozenset(b.addr for b in artifact.blocks),
        predecessor_map=build_x86_16_ir_predecessor_map(artifact),
        head_addr=0, call_block_addr=30, callsite_addr=30,
        seed={"ax": 0}, seed_memory=PathMemory8616(),
        apply_service=lambda *_: False, read_load=read_load,
        apply_repeat=apply_repeat,
        iteration_limit=64, deadline=time.monotonic() + 5, work_limit=work,
        **kwargs,
    )


def _same_result(a: edge.Real16EdgeFeasibility8616, b: edge.Real16EdgeFeasibility8616) -> None:
    """Every published field but charged work must match exactly."""
    assert a.converged == b.converged
    assert a.live_blocks == b.live_blocks
    assert a.infeasible_edges == b.infeasible_edges
    assert a.evaluated_cjmps == b.evaluated_cjmps


def test_noop_predicates_omit_only_pure_noncandidates() -> None:
    """Pure non-candidate replays drop; observed/candidate blocks keep theirs."""
    base_consulted: list[int] = []
    owned_consulted: list[int] = []
    baseline = _feasible(apply_repeat=_recording_repeat(base_consulted))
    result = _feasible(
        apply_repeat=_recording_repeat(owned_consulted),
        repeat_consult_noop=lambda block: block.addr != 28,
    )
    _same_result(baseline, result)
    assert result.work_units < baseline.work_units
    # Surviving pure arms lose only the discarded second-pass consultation.
    for addr in (10, 20):
        assert owned_consulted.count(addr) < base_consulted.count(addr)
    # Observed blocks and the REP-shaped block keep identical consultations.
    for addr in (0, 28, 30):
        assert owned_consulted.count(addr) == base_consulted.count(addr)


def test_candidate_verdict_keeps_obligatory_consultation() -> None:
    """A block the predicate cannot prove a no-op is consulted in both passes."""
    consulted: list[int] = []
    result = _feasible(
        apply_repeat=_recording_repeat(consulted, frozenset({28})),
        repeat_consult_noop=lambda block: block.addr != 28,
    )
    assert result.converged
    assert consulted.count(28) >= 2


def test_load_blocks_omit_only_while_reader_readonly() -> None:
    """The LOAD leg is a per-moment verdict, not a construction-time flag."""
    artifact = IRFunctionArtifact(0, (
        IRBlock(0, (_branch(0, "ax", 0, 10),), successor_addrs=(10, 20)),
        _load_block(10),
        IRBlock(20, _pure(20, rows=3).instrs, successor_addrs=(30,)),
        IRBlock(30, (IRInstr("CALL", None, (_value(40),), addr=30),)),
    ))
    loads_seen: list[int] = []

    def read_load(instruction: IRInstr, _span: tuple[int, int] | None,
                  _memory: PathMemory8616) -> int | None:
        loads_seen.append(instruction.addr)
        return None

    consulted: list[int] = []
    baseline = _feasible(
        artifact=artifact, read_load=read_load,
        apply_repeat=_recording_repeat(consulted),
    )
    owned_loads: list[int] = []
    owned_consulted: list[int] = []

    def owned_read(instruction: IRInstr, _span: tuple[int, int] | None,
                   _memory: PathMemory8616) -> int | None:
        owned_loads.append(instruction.addr)
        return None

    result = _feasible(
        artifact=artifact, read_load=owned_read,
        apply_repeat=_recording_repeat(owned_consulted),
        repeat_consult_noop=lambda _block: True,
        load_reader_readonly=lambda: True,
    )
    _same_result(baseline, result)
    # Honest per-classification charging makes a two-row wash legitimate;
    # the consultation count is the strict evidence of the omission.
    assert result.work_units <= baseline.work_units
    # LOAD block 10 omitted its discarded consult; observable verdicts hold.
    assert owned_loads.count(10) < loads_seen.count(10)

    # A readonly verdict that declines keeps hooked LOADs observable while
    # the non-LOAD pure arm may still omit its discarded replay.
    declined_loads: list[int] = []
    declined = _feasible(
        artifact=artifact,
        read_load=lambda instruction, _span, _memory: declined_loads.append(instruction.addr),
        apply_repeat=_recording_repeat([]),
        repeat_consult_noop=lambda _block: True,
        load_reader_readonly=lambda: False,
    )
    _same_result(baseline, declined)
    # Four retained snapshot selections still pay their preparation fee.
    assert declined.work_units == baseline.work_units + 4
    assert declined_loads.count(10) == loads_seen.count(10)


def test_observed_classification_still_governs_omission() -> None:
    """A True repeat verdict never omits CJMP/CALL/unknown-op replays."""
    base_consulted: list[int] = []
    owned_consulted: list[int] = []
    baseline = _feasible(apply_repeat=_recording_repeat(base_consulted))
    result = _feasible(
        apply_repeat=_recording_repeat(owned_consulted),
        repeat_consult_noop=lambda _block: True,
    )
    _same_result(baseline, result)
    # Branch head and CALL block replay identically even under True verdicts.
    for addr in (0, 30):
        assert owned_consulted.count(addr) == base_consulted.count(addr)


def test_generic_path_without_predicates_unchanged() -> None:
    """Absent predicates keep every in-scope consultation observable."""
    consulted: list[int] = []
    result = _feasible(apply_repeat=_recording_repeat(consulted))
    assert result.converged
    assert consulted.count(10) >= 2
    assert consulted.count(30) >= 2


def test_exhausted_round_publishes_nothing() -> None:
    """A partial walk under the owned predicates still yields no pruning."""
    result = _feasible(
        apply_repeat=_recording_repeat([]),
        repeat_consult_noop=lambda _block: True,
        work=2,
    )
    assert not result.converged
    assert not result.infeasible_edges


def test_terminal_call_exempt_only_with_paired_noop() -> None:
    """The exact terminal CALL row omits only under a proven-inert consult."""
    base_consulted: list[int] = []
    owned_consulted: list[int] = []
    baseline = _feasible(apply_repeat=_recording_repeat(base_consulted))
    # Block 30's only row is the terminal CALL at the stopping coordinate;
    # a paired no-op verdict makes its discarded replay provably unobserved.
    result = _feasible(
        apply_repeat=_recording_repeat(owned_consulted),
        repeat_consult_noop=lambda _block: True,
        terminal_call_noop=lambda _instruction: True,
    )
    _same_result(baseline, result)
    assert result.work_units < baseline.work_units
    assert owned_consulted.count(30) < base_consulted.count(30)
    # The same block without the verdict keeps its obligatory replay.
    generic = _feasible(
        apply_repeat=_recording_repeat([]),
        repeat_consult_noop=lambda _block: True,
    )
    _same_result(baseline, generic)
    assert generic.work_units > result.work_units


def test_terminal_call_exemption_controls() -> None:
    """Earlier CALLs, requested cuts, declining verdicts, wrong coordinates."""
    artifact = _artifact()
    terminal = artifact.blocks[-1].instrs[-1]

    # A declining no-op verdict retains the replay, matching the leg that
    # never received the terminal verdict at all.
    generic = _feasible(
        apply_repeat=_recording_repeat([]),
        repeat_consult_noop=lambda _block: True,
    )
    declined = _feasible(
        apply_repeat=_recording_repeat([]),
        repeat_consult_noop=lambda _block: True,
        terminal_call_noop=lambda _instruction: False,
    )
    _same_result(generic, declined)
    assert declined.work_units == generic.work_units

    # A requested cut on the same block keeps the terminal consult observable.
    cut = edge.Real16CallCutRequest8616(
        artifact=artifact, block=artifact.blocks[-1],
        index=0, instruction=terminal,
    )
    cut_run = _feasible(
        apply_repeat=_recording_repeat([]),
        repeat_consult_noop=lambda _block: True,
        terminal_call_noop=lambda _instruction: True,
        call_cut=cut,
    )
    assert cut_run.work_units >= declined.work_units

    # An earlier CALL in the terminal block keeps the whole replay observed.
    earlier = IRFunctionArtifact(0, (
        artifact.blocks[0], artifact.blocks[1], artifact.blocks[2],
        artifact.blocks[3],
        IRBlock(30, (
            IRInstr("CALL", None, (_value(40),), addr=29),
            IRInstr("CALL", None, (_value(40),), addr=30),
        ), successor_addrs=(31,)),
    ))
    earlier_base_consulted: list[int] = []
    earlier_owned_consulted: list[int] = []
    earlier_base = _feasible(
        artifact=earlier, apply_repeat=_recording_repeat(earlier_base_consulted),
    )
    earlier_owned = _feasible(
        artifact=earlier,
        apply_repeat=_recording_repeat(earlier_owned_consulted),
        repeat_consult_noop=lambda _block: True,
        terminal_call_noop=lambda _instruction: True,
    )
    _same_result(earlier_base, earlier_owned)
    assert earlier_owned_consulted.count(30) == earlier_base_consulted.count(30)

    # A CALL at the stopping coordinate that is not the last row stays observed.
    midcall = IRFunctionArtifact(0, (
        artifact.blocks[0], artifact.blocks[1], artifact.blocks[2],
        artifact.blocks[3],
        IRBlock(30, (
            IRInstr("CALL", None, (_value(40),), addr=30),
            IRInstr("Iop_Add16", IRValue(MemSpace.REG, name="cx", size=2),
                    (_value(1), _value(1)), size=2, addr=31),
        ), successor_addrs=(32,)),
    ))
    mid_base_consulted: list[int] = []
    mid_owned_consulted: list[int] = []
    mid_base = _feasible(
        artifact=midcall, apply_repeat=_recording_repeat(mid_base_consulted),
    )
    mid_owned = _feasible(
        artifact=midcall,
        apply_repeat=_recording_repeat(mid_owned_consulted),
        repeat_consult_noop=lambda _block: True,
        terminal_call_noop=lambda _instruction: True,
    )
    _same_result(mid_base, mid_owned)
    assert mid_owned_consulted.count(30) == mid_base_consulted.count(30)


def test_terminal_call_noop_domain_verdicts() -> None:
    """The paired verdict binds the handler object, never the address alone."""
    owner = _domain()
    ordinary = IRInstr("CALL", None, (_value(40),), addr=30)
    interrupt = IRInstr(
        "CALL", None,
        (IRValue(MemSpace.CONST, const=interrupt_core_addr_8616(0x21), size=2),),
        addr=30,
    )
    # No handler at all: an ordinary terminal CALL consult is trivially inert.
    call_noop = owner._snapshot_terminal_noop_8616(None, None)
    assert call_noop is not None
    assert call_noop(ordinary) is True
    # An interrupt/service row always stays observable.
    assert call_noop(interrupt) is False

    from tests.ir import test_caller_protective_footprint as geometry

    ctx = geometry._context()
    artifact, selected, rows = geometry._artifact()
    binding = owner._feasibility_call_handler_8616(
        ctx, artifact, geometry._boundary(ctx, artifact), rows,
    )
    assert binding is not None
    call_noop = owner._snapshot_terminal_noop_8616(binding, binding)
    assert call_noop is not None
    assert call_noop(ordinary) is True
    assert binding.terminal_noop(selected) is False
    # No arbitrary apply/rejection callbacks can construct an owned handler.
    with pytest.raises(TypeError):
        owner._FeasibilityCallBinding8616(lambda *_: False, lambda *_: True)
    # A foreign apply callable never gains the exemption.
    call_noop = owner._snapshot_terminal_noop_8616(binding, lambda *_args: False)
    assert call_noop is not None
    assert call_noop(ordinary) is False


def _domain() -> object:
    """Import the (possibly overlaid) invocation-domain owner module."""
    import inertia.ir.real16_invocation_domain as owner
    return owner


def _native() -> object:
    """Import the real declared-resize census fixture helpers."""
    import tests.ir.test_x86_16_declared_resize_boundary as native
    return native


def _world_ctx(tmp_path: Path) -> object:
    """A real census context with authenticated byte manifest fields."""
    from tests.ir import test_callee_local_feasibility as calfeas

    ctx, _proof = calfeas.world(tmp_path, calfeas.SHARED)
    ctx.deadline = time.monotonic() + 30
    ctx.work_units = 0
    return ctx


def test_factory_admits_canonical_and_declines_exhausted(tmp_path: Path) -> None:
    """Owned hooks exist under the live boundary; exhaustion never arms them."""
    owner = _domain()
    hooks = owner._snapshot_omission_hooks_8616
    ctx = _world_ctx(tmp_path)
    pair = hooks(ctx)
    assert pair is not None
    repeat_noop, load_readonly = pair
    assert repeat_noop(_pure(10)) is True
    assert load_readonly() is True
    ctx.deadline = 0.0
    assert hooks(ctx) is None
    ctx.deadline = time.monotonic() + 30
    ctx.work_units = ctx.work_limit + 1
    assert hooks(ctx) is None


def test_repeat_noop_structural_verdicts(tmp_path: Path) -> None:
    """Current manifest bytes and block shape decide candidacy per call."""
    owner = _domain()
    ctx = _world_ctx(tmp_path)
    pair = owner._snapshot_omission_hooks_8616(ctx)
    assert pair is not None
    repeat_noop, _ = pair
    rep = _rep_shaped(28)
    assert repeat_noop(_pure(10)) is True          # multi-row: impossible
    assert repeat_noop(rep) is True                # no fetched bytes: no-op
    ctx.machine_bytes[28] = b"\xf3\xab"
    assert repeat_noop(rep) is False               # possible REP: obligatory
    ctx.machine_bytes[28] = b"\x90"
    assert repeat_noop(rep) is True                # fall-through mismatch
    ctx.machine_bytes[28] = "not-bytes"            # type: ignore[assignment]
    assert repeat_noop(rep) is False               # foreign bytes: decline


def test_ctx_field_replacement_declines_per_call(tmp_path: Path) -> None:
    """Replaced project/manifest/initial-memory state keeps observability."""
    owner = _domain()
    ctx = _world_ctx(tmp_path)
    pair = owner._snapshot_omission_hooks_8616(ctx)
    assert pair is not None
    repeat_noop, load_readonly = pair
    block = _pure(10)
    assert repeat_noop(block) is True
    original_project = ctx.project
    ctx.project = SimpleNamespace()
    assert repeat_noop(block) is False
    ctx.project = original_project
    assert repeat_noop(block) is True
    # A swapped *dict* manifest is re-read: verdict follows current contents.
    ctx.machine_bytes = {28: b"\xf3\xab"}
    assert repeat_noop(_rep_shaped(28)) is False
    ctx.machine_bytes = MappingProxyType({})  # type: ignore[assignment]
    assert repeat_noop(block) is False
    ctx.machine_bytes = {}
    assert repeat_noop(block) is True
    # Foreign initial memory drops only the LOAD leg, not the repeat leg.
    assert load_readonly() is True
    ctx.initial_memory = SimpleNamespace()
    assert load_readonly() is False
    assert repeat_noop(block) is True


def test_rebound_binding_declines_per_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every rebound consulted binding keeps the generic observable path."""
    owner = _domain()
    ctx = _world_ctx(tmp_path)
    pair = owner._snapshot_omission_hooks_8616(ctx)
    assert pair is not None
    repeat_noop, load_readonly = pair
    call_noop = owner._snapshot_terminal_noop_8616(None, None)
    assert call_noop is not None
    block = _pure(10)
    call_row = IRInstr("CALL", None, (_value(40),), addr=30)
    checked = [
        (owner, "_apply_repeated_store_8616"),
        (owner, "native_repeated_store_8616"),
        (owner, "repeated_store_candidate_shape_8616"),
        (owner, "path_load_value_8616"),
        (owner, "_native_instr_equal_8616"),
        (owner, "interrupt_call_vector_8616"),
        (owner, "_feasibility_call_handler_8616"),
        (owner, "_feasibility_call_rows_8616"),
        (repeat_owner, "repeated_store_candidate_shape_8616"),
        (repeat_owner, "decoded_repeated_store_8616"),
        (PathMemory8616, "taint"),
        (edge, "interrupt_call_vector_8616"),
        (edge, "path_memory_tainted_8616"),
        (edge, "_kb_snapshot_observed_8616"),
        (edge, "scalar_instruction_effect_8616"),
        (edge, "_kb_block_exit_8616"),
        (edge, "_kb_repeat_exit_8616"),
        (edge, "_kb_transfer_effect_8616"),
    ]
    for module, name in checked:
        original = getattr(module, name)
        assert repeat_noop(block) is True, name
        assert load_readonly() is True, name
        assert call_noop(call_row) is True, name
        monkeypatch.setattr(module, name, lambda *args, **kwargs: None)
        assert repeat_noop(block) is False, name
        assert load_readonly() is False, name
        assert call_noop(call_row) is False, name
        monkeypatch.setattr(module, name, original)
        assert repeat_noop(block) is True, name


def test_real_root_census_charges_strictly_less_owned_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Actual root census: identical outputs/counters, strictly less work.

    On production both legs run the unchanged census: identical verdicts and
    counters still hold, but the work assertion fails because no omission
    exists — the red is measured real work, not a missing helper.
    """
    owner = _domain()
    native = _native()
    # mov ax,0; cmp; je over a dead arm of three pusha (one 515-row pure
    # block) and a jmp; mov cx,0; jcxz; call cx; call; ret — a large pure
    # arm whose discarded snapshot replay is real charged work.
    caller = bytes.fromhex(
        "b80000 83f800 7405 606060 eb03 b90000 e302 ffd1 e80100 c3"
    )
    census = owner._census_invocation_8616
    runs: dict[str, dict[str, object]] = {}

    def leg(name: str, foreign_native: bool) -> None:
        receipts: list[tuple[object, int, tuple[int, int, int, int, int]]] = []
        eligible: list[int] = []
        real_scope = owner.invocation_feasible_scope_8616

        def scope_wrapper(*args: object, **kwargs: object) -> object:
            noop = kwargs.get("repeat_consult_noop")
            if noop is not None:
                def counted(block: IRBlock) -> bool:
                    verdict = noop(block)
                    if verdict:
                        eligible.append(block.addr)
                    return verdict
                kwargs["repeat_consult_noop"] = counted
            return real_scope(*args, **kwargs)

        def capture(ctx: object, *args: object, **kwargs: object) -> object:
            before = ctx.work_units
            out = census(ctx, *args, **kwargs)
            receipts.append((out, ctx.work_units - before, (
                len(ctx.raw_facts), len(ctx.normalized_facts),
                len(ctx.classified_facts), len(ctx.materialized_facts),
                ctx.failures,
            )))
            return out

        if foreign_native:
            # A rebound native consult boundary declines every predicate,
            # reproducing the generic census under unchanged inputs.
            monkeypatch.setattr(owner, "native_repeated_store_8616", lambda *a, **k: None)
        monkeypatch.setattr(owner, "invocation_feasible_scope_8616", scope_wrapper)
        monkeypatch.setattr(owner, "_census_invocation_8616", capture)
        boot = native._boot(caller)
        project, _raw, coverage = native._world(boot, len(caller))
        premise = native._resize_premise(
            project, coverage, native.MODULE_BASE + len(caller) - 4, boot, (),
        )
        runs[name] = {
            "complete": premise.complete,
            "edges": premise.infeasible_edges,
            "receipts": receipts,
            "eligible": sorted(set(eligible)),
        }
        monkeypatch.undo()

    leg("generic", True)
    leg("owned", False)
    generic, owned = runs["generic"], runs["owned"]
    assert generic["complete"] == owned["complete"]
    assert generic["edges"] == owned["edges"]
    greceipts = generic["receipts"]
    oreceipts = owned["receipts"]
    assert greceipts and len(greceipts) == len(oreceipts)
    # Same census outcome and all five evidence counters per derivation.
    assert [r[0] for r in greceipts] == [r[0] for r in oreceipts]
    assert [r[2] for r in greceipts] == [r[2] for r in oreceipts]
    gwork = sum(r[1] for r in greceipts)
    owork = sum(r[1] for r in oreceipts)
    print(f"census work: generic={gwork} owned={owork} eligible={owned['eligible']}")
    assert gwork > owork


def test_rebound_native_keeps_generic_work_on_real_census(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A foreign repeat-consult binding declines: identical ordinary census."""
    owner = _domain()
    native = _native()
    caller = bytes.fromhex(
        "b80000 83f800 7405 606060 eb03 b90000 e302 ffd1 e80100 c3"
    )
    census = owner._census_invocation_8616
    receipts: list[tuple[object, int, tuple[int, int, int, int, int]]] = []

    def capture(ctx: object, *args: object, **kwargs: object) -> object:
        before = ctx.work_units
        out = census(ctx, *args, **kwargs)
        receipts.append((out, ctx.work_units - before, (
            len(ctx.raw_facts), len(ctx.normalized_facts),
            len(ctx.classified_facts), len(ctx.materialized_facts),
            ctx.failures,
        )))
        return out

    monkeypatch.setattr(owner, "_census_invocation_8616", capture)
    monkeypatch.setattr(owner, "native_repeated_store_8616", lambda *a, **k: None)
    boot = native._boot(caller)
    project, _raw, coverage = native._world(boot, len(caller))
    premise = native._resize_premise(
        project, coverage, native.MODULE_BASE + len(caller) - 4, boot, (),
    )
    assert premise.complete
    assert receipts
    # Foreign binding declined the whole policy: census still succeeds and
    # every ledger closed identically to an ordinary complete census.
    assert all(r[0] is None for r in receipts)
    assert all(r[2] == receipts[0][2] for r in receipts)

"""Native-bound callee branch pruning preserves conservative return accounting."""

import time
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from inertia.frontend.x86_16.mz_static_boot import mz_static_boot_8616
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.segment_effect_closure import SegmentEffectClosureResult8616, prove_segment_effect_closure_8616
from inertia.ir.segment_state import build_x86_16_segment_state_artifact
from tests.ir import test_x86_16_invocation_edge_feasibility as native

pytestmark = pytest.mark.decompiler


@dataclass(frozen=True)
class CalleeProof:
    """Only the real bound closure used by this local simulation unit."""

    callee: SegmentEffectClosureResult8616


def world(
    tmp_path: Path, code: bytes, *, load_segment: int = native.LOAD_SEGMENT, entry_offset: int = 0,
) -> tuple[owner._PathCensusContext8616, CalleeProof]:
    """Build native MZ coverage, a complete closure, and the authenticated byte census."""
    mz = native._build_mz(bytes(entry_offset) + code, entry_ip=entry_offset)
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(mz)
    head = (load_segment << 4) + entry_offset
    project = native._build_project(fixture, force_blob=False, base_addr=load_segment, entry_point=head)
    assert project.loader.main_object.mz_load_segment == load_segment
    assert project.entry == head
    coverage = native._coverage(project, head)
    state = build_x86_16_segment_state_artifact(coverage.artifact)
    closure = prove_segment_effect_closure_8616(coverage, state)
    assert closure.complete
    boot = mz_static_boot_8616(mz, load_segment)
    ctx = owner._PathCensusContext8616(
        project=project,
        selector=load_segment,
        image=boot.image,
        boot=boot,
        chain=None,
        call_preservations=(),
        entry_call_preservations=(),
        declared_services=(),
        environment_digest=None,
        environment=None,
        arena=None,
        service_consumptions=[],
        stop_block_addr=None,
        callsite_addr=None,
        callsite_call_state=None,
        callsite_memory=None,
        manifest=set(),
        machine_bytes={},
        native_blocks={},
        checked_stores=0,
        censused_callees=set(),
        raw_facts=set(),
        normalized_facts=set(),
        classified_facts=set(),
        materialized_facts=set(),
        failures=0,
        work_units=0,
        work_limit=20000,
        deadline=time.monotonic() + 20,
    )
    proof = CalleeProof(closure)
    assert owner._census_callee_bytes_8616(ctx, proof) is None
    return ctx, proof


# cmp ax,0; jne alternative; mov ax,1; jmp shared; alternative:mov ax,2; shared:ret
SHARED = bytes.fromhex("83f8007505b80100eb03b80200c3")
MULTIPLE = bytes.fromhex("83f8007504b80100c3b80200c3")
BACKWARD_JOIN = bytes.fromhex("83f8007406b80100eb00c3b80200ebfa")


def test_backward_join_fits_budget_without_provisional_return(tmp_path: Path) -> None:
    """Acyclic joins consume both parent states before simulating the return."""
    ctx, proof = world(tmp_path, BACKWARD_JOIN)
    ctx.work_units = ctx.accounted_work_units = 0
    ctx.work_limit = 500
    seed = owner._PathState8616(
        {"cs": native.LOAD_SEGMENT, "ss": native.LOAD_SEGMENT + 0x10, "esp": 0x100},
        owner.PathMemory8616(),
    )
    result = owner._simulate_callee_8616(ctx, proof, seed)
    assert isinstance(result, dict), result
    terminal = proof.callee.return_block_addrs[0]
    assert result[terminal].registers.get("ax") is None
    assert set(result) == {block.addr for block in proof.callee.coverage.artifact.blocks}
    assert ctx.work_units <= 500
    assert ctx.raw_facts == ctx.normalized_facts == ctx.classified_facts == ctx.materialized_facts
    assert ctx.failures == 0


@pytest.mark.parametrize("value,expected", [(0, 1), (5, 2), (None, None)])
def test_shared_return_native_callee(tmp_path: Path, value: int | None, expected: int | None) -> None:
    """Known call-state AX selects one value; an omitted AX keeps the must-meet unknown."""
    ctx, proof = world(tmp_path, SHARED)
    regs = {"cs": native.LOAD_SEGMENT, "ss": native.LOAD_SEGMENT + 0x10, "esp": 0x100}
    if value is not None:
        regs["ax"] = value
    result = owner._simulate_callee_8616(ctx, proof, owner._PathState8616(regs, owner.PathMemory8616()))
    assert isinstance(result, dict), result
    terminal = proof.callee.return_block_addrs[0]
    got = result[terminal].registers.get("ax")
    assert (None if got is None else got & 0xFFFF) == expected
    assert set(proof.callee.return_block_addrs) <= set(result)
    if value is None:
        assert len(result) == len(proof.callee.coverage.artifact.blocks)
    else:
        assert len(result) < len(proof.callee.coverage.artifact.blocks)
    assert len(ctx.classified_facts) == len(ctx.materialized_facts) + ctx.failures


def test_multiple_returns_keep_complete_scope(tmp_path: Path) -> None:
    """No optimization drops a return still required by the unchanged closure contract."""
    ctx, proof = world(tmp_path, MULTIPLE)
    assert len(proof.callee.return_block_addrs) == 2
    seed = owner._PathState8616(
        {"ax": 0, "cs": native.LOAD_SEGMENT, "ss": native.LOAD_SEGMENT + 0x10, "esp": 0x100}, owner.PathMemory8616()
    )
    result = owner._simulate_callee_8616(ctx, proof, seed)
    assert isinstance(result, dict), result
    assert set(proof.callee.return_block_addrs) <= set(result)


def test_corrupt_native_binding_refuses(tmp_path: Path) -> None:
    """A changed native row never grants feasibility-based acceptance."""
    ctx, proof = world(tmp_path, SHARED)
    native_blocks = ctx.native_blocks[proof.callee.coverage.artifact.function_addr]
    head = proof.callee.coverage.artifact.function_addr
    block = native_blocks[head]
    native_blocks[head] = replace(block, instrs=block.instrs[:-1])
    seed = owner._PathState8616(
        {"ax": 0, "cs": native.LOAD_SEGMENT, "ss": native.LOAD_SEGMENT + 0x10, "esp": 0x100}, owner.PathMemory8616()
    )
    result = owner._simulate_callee_8616(ctx, proof, seed)
    assert result is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN


@pytest.mark.parametrize(
    "limit_state,expected_calls",
    [("no_branch", 0), ("over", 0), ("deadline", 0), ("over_and_deadline", 0), ("exact", 1)],
)
def test_local_feasibility_budget_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit_state: str, expected_calls: int
) -> None:
    """Straight-line code adds no walk; exhausted budgets refuse before feasibility setup."""
    ctx, proof = world(tmp_path, bytes.fromhex("b80100c3") if limit_state == "no_branch" else SHARED)
    calls = 0
    original = owner.invocation_feasible_scope_8616

    def observe(**kwargs: object) -> owner.Real16EdgeFeasibility8616:
        nonlocal calls
        calls += 1
        return original(**kwargs)

    monkeypatch.setattr(owner, "invocation_feasible_scope_8616", observe)
    if limit_state in {"over", "exact"}:
        ctx.work_units = ctx.work_limit + int(limit_state == "over")
    elif limit_state in {"deadline", "over_and_deadline"}:
        ctx.deadline = 0
        if limit_state == "over_and_deadline":
            ctx.work_units = ctx.work_limit + 1
    result = owner._simulate_callee_8616(
        ctx,
        proof,
        owner._PathState8616(
            {"ax": 0, "cs": native.LOAD_SEGMENT, "ss": native.LOAD_SEGMENT + 0x10, "esp": 0x100}, owner.PathMemory8616()
        ),
    )
    assert calls == expected_calls
    if limit_state == "no_branch":
        assert isinstance(result, dict)
        assert result[proof.callee.return_block_addrs[0]].registers["ax"] == 1

    else:
        expected = (
            owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
            if limit_state in {"deadline", "over_and_deadline"}
            else owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
        )
        assert result is expected


@pytest.mark.parametrize("word,expected", [(0, 1), (5, 2)])
def test_seed_memory_load_selects_callee_branch(tmp_path: Path, word: int, expected: int) -> None:
    """The same native-bound LOAD reads the caller's live memory overlay for pruning."""
    ctx, proof = world(tmp_path, bytes.fromhex("b800108ed8a10001") + SHARED)
    environment = native._env(ctx.boot.source)
    ctx.initial_memory = owner.invocation_initial_memory_8616(
        environment,
        owner.declared_environment_digest_8616(environment),
        ctx.image.chunks,
    )
    assert ctx.initial_memory is not None
    memory = owner.PathMemory8616()
    memory.apply_write(native.BASE + 0x100, 2, word.to_bytes(2, "little"))
    seed = owner._PathState8616(
        {"ds": native.LOAD_SEGMENT, "cs": native.LOAD_SEGMENT, "ss": native.LOAD_SEGMENT + 0x10, "esp": 0x100}, memory
    )
    result = owner._simulate_callee_8616(ctx, proof, seed)
    assert isinstance(result, dict), result
    assert result[proof.callee.return_block_addrs[0]].registers["ax"] == expected


def test_read_only_branchless_load_fits_native_callee_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discarded read-only LOAD snapshots cannot consume the final proof unit."""
    ctx, proof = world(tmp_path, bytes.fromhex("b800108ed8a10001eb00") + SHARED)
    environment = native._env(ctx.boot.source)
    ctx.initial_memory = owner.invocation_initial_memory_8616(
        environment, owner.declared_environment_digest_8616(environment), ctx.image.chunks,
    )
    assert ctx.initial_memory is not None
    memory = owner.PathMemory8616()
    memory.apply_write(native.BASE + 0x100, 2, b"\x00\x00")
    seed = owner._PathState8616(
        {"ds": native.LOAD_SEGMENT, "cs": native.LOAD_SEGMENT,
         "ss": native.LOAD_SEGMENT + 0x10, "esp": 0x100}, memory,
    )
    ctx.work_units = ctx.accounted_work_units = 0
    ctx.work_limit = 840
    result = owner._simulate_callee_8616(ctx, proof, seed)
    assert isinstance(result, dict), result
    assert result[proof.callee.return_block_addrs[0]].registers["ax"] == 1

    assert memory.known[native.BASE + 0x100] == 0
    assert ctx.work_units <= 840
    assert ctx.raw_facts == ctx.normalized_facts == ctx.classified_facts == ctx.materialized_facts
    assert ctx.failures == 0

    observable = replace(
        ctx, work_units=0, accounted_work_units=0, work_limit=20000,
        raw_facts=set(), normalized_facts=set(), classified_facts=set(),
        materialized_facts=set(), failures=0,
    )
    original = owner.invocation_feasible_scope_8616

    def replay(**kwargs: object) -> owner.Real16EdgeFeasibility8616:
        """Compare every exit and ledger against the original observable-reader policy."""
        kwargs["load_snapshot_replay"] = owner.LoadSnapshotReplay8616.OBSERVABLE
        return original(**kwargs)

    monkeypatch.setattr(owner, "invocation_feasible_scope_8616", replay)
    baseline = owner._simulate_callee_8616(observable, proof, seed)
    assert isinstance(baseline, dict), baseline
    assert baseline == result
    assert observable.raw_facts == ctx.raw_facts
    assert observable.normalized_facts == ctx.normalized_facts
    assert observable.classified_facts == ctx.classified_facts
    assert observable.materialized_facts == ctx.materialized_facts
    assert observable.failures == ctx.failures == 0
    assert ctx.work_units < observable.work_units


CLASSIFIER = bytes.fromhex(
    "558bec8b56040bd27d05b8ffffeb170bd2750433c0ebf683fa0a7d05b80100ebecb80200ebe75dc3"
)


@pytest.mark.parametrize("load_segment", [0x1A2, 0x200])
def test_universally_normalized_classifier_binds_native_census(tmp_path: Path, load_segment: int) -> None:
    """Backward JMP normalization must retain independent native effect binding."""
    ctx, proof = world(tmp_path, CLASSIFIER, load_segment=load_segment, entry_offset=0x2C2)
    artifact = proof.callee.coverage.artifact
    normalized = tuple(block for block in artifact.blocks if any(
        row.op == "JMP" and row.args[0].space is owner.MemSpace.CONST
        for row in block.instrs))
    assert normalized
    assert all(owner._native_block_bound_8616(ctx.native_blocks[artifact.function_addr][block.addr], block)
               for block in normalized)
    from inertia.ir.real16_initial_memory8616 import InvocationInitialMemory8616

    stack_base = (load_segment + 0x10) << 4
    ctx.initial_memory = InvocationInitialMemory8616(((stack_base, bytes(0x102) + b"\x07\x00" + bytes(0x100)),))
    seed = owner._PathState8616(
        {"cs": load_segment, "ss": load_segment + 0x10, "esp": 0x100, "ebp": 0},
        owner.PathMemory8616(),
    )
    result = owner._simulate_callee_8616(ctx, proof, seed)
    assert isinstance(result, dict), result
    returned = result[proof.callee.return_block_addrs[0]].registers
    assert owner._register_read_8616("dx", returned) == 7
    assert owner._register_read_8616("bp", returned) == 0
    assert owner._register_read_8616("sp", returned) == 0x102
    assert ctx.failures == 0
    assert ctx.raw_facts == ctx.normalized_facts == ctx.classified_facts == ctx.materialized_facts
    # AX remains conservative because branch feasibility joins distinct return
    # values. This regression proves native binding, not additional precision.



@pytest.mark.parametrize("mutation", ["target", "proof_producer", "native_byte"])
def test_normalized_classifier_rejects_changed_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Fresh normalization never admits a forged target, byte, or producer."""
    from inertia.ir import vex_import

    ctx, proof = world(tmp_path, CLASSIFIER, load_segment=0x1A2, entry_offset=0x2C2)
    artifact = proof.callee.coverage.artifact
    block = next(block for block in artifact.blocks if any(
        row.op == "JMP" and row.args[0].space is owner.MemSpace.CONST for row in block.instrs))
    jump = next(row for row in block.instrs if row.op == "JMP")
    if mutation == "target":
        object.__setattr__(jump.args[0], "const", jump.args[0].const + 1)
        assert owner._bind_path_block_before_transfer_8616(ctx, artifact, block, None) is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
        return
    if mutation == "proof_producer":
        canonical = vex_import.prove_entry_jump_domains_8616

        def replaced(*args: object, **kwargs: object) -> object:
            return canonical(*args, **kwargs)

        monkeypatch.setattr(vex_import, "prove_entry_jump_domains_8616", replaced)
    else:
        ctx.project.loader.memory.store(jump.addr, b"\x90\x90")
    ctx.censused_callees.clear()
    assert owner._census_callee_bytes_8616(ctx, proof) is not None

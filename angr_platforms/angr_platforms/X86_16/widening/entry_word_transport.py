"""Transport one proven entry-stack word to a later 16-bit MOV definition.

Layer: Widening.
Responsibility: orchestrate the targeted word-transport proof. The engine
replays the canonical ``entry_stack_word_values`` proof at its seed index
against the identical raw artifact, builds its own block-local SSA per cone
block, and drives the closed per-block transfer (``entry_word_transport_state``)
over the deterministic acyclic target cone (``entry_word_transport_flow``).
Every entry-reachable predecessor must agree; unseeded, clobbered, divergent,
cyclic, or malformed evidence refuses closed. Off-target exits are retained but
never treated as closure. The fact is conditional on remaining inside the
supplied acyclic cone; unknown exits are not proved unable to reenter.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..ir.core import IRFunctionArtifact, IRInstr, IRValue, MemSpace
from ..ir.ssa import SSABlock, build_x86_16_block_local_ssa
from ..ir.ssa_function import build_x86_16_ir_predecessor_map
from .entry_stack_word_value_contracts import (
    EntryStackWord8616,
    EntryStackWordProof8616,
    EntryStackWordVerdict8616,
)
from .entry_stack_word_values import prove_entry_stack_word_value_8616
from .entry_word_transport_contracts import (
    EntryWordSite8616,
    EntryWordTransport8616,
    EntryWordTransportProof8616,
    EntryWordTransportRefusal8616,
    EntryWordTransportVerdict8616,
    EntryWordTraversalStats8616,
)
from .entry_word_transport_contracts import (
    EntryWordTransportRefusalKind8616 as Refusal,
)
from .entry_word_transport_flow import (
    cone_traversal_8616,
    meet_incoming_words_8616,
)
from .entry_word_transport_state import (
    TransportRun8616,
    full_word_register_8616,
    plain_destination_8616,
    transfer_block_8616,
)


def _refused_8616(
    artifact: IRFunctionArtifact,
    word_proof: EntryStackWordProof8616,
    reasons: list[EntryWordTransportRefusal8616],
    *,
    raw: int = 0,
    normalized: int = 0,
) -> EntryWordTransportProof8616:
    """Retain a closed typed non-result rather than inventing a transport."""
    return EntryWordTransportProof8616(
        artifact=artifact, word_proof=word_proof,
        refusals=tuple(reasons),
        raw_fact_count=1, normalized_fact_count=int(raw > 0),
        classified_fact_count=int(raw > 0), failure_count=1,
        traversal=EntryWordTraversalStats8616(raw, normalized, len(reasons)),
    )


def _refusal_proof_8616(
    artifact: IRFunctionArtifact,
    word_proof: EntryStackWordProof8616,
    kind: Refusal,
    *,
    block_addr: int,
    index: int | None = None,
) -> EntryWordTransportProof8616:
    """Wrap one typed refusal reason as the whole proof non-result."""
    return _refused_8616(artifact, word_proof, [
        EntryWordTransportRefusal8616(kind, kind.value, block_addr, index),
    ])


@dataclass(frozen=True, slots=True)
class _Seed8616:
    """The replayed canonical seed fact plus its lowercase register name."""

    fact: EntryStackWord8616
    name: str


def _seed_obligation_8616(
    artifact: IRFunctionArtifact,
    word_proof: EntryStackWordProof8616,
    target_block_addr: int,
) -> _Seed8616 | EntryWordTransportProof8616:
    """Bind the seed to a replayed canonical full-word REG entry definition."""
    def refuse(kind: Refusal) -> EntryWordTransportProof8616:
        return _refusal_proof_8616(
            artifact, word_proof, kind, block_addr=target_block_addr,
        )

    fact = word_proof.fact
    if (
        word_proof.artifact is not artifact
        or word_proof.byte_proof.artifact is not artifact
    ):
        return refuse(Refusal.CROSS_ARTIFACT_PROOF)
    if word_proof.verdict is not EntryStackWordVerdict8616.PROVEN or fact is None:
        return refuse(Refusal.SEED_NOT_PROVEN)
    replayed = prove_entry_stack_word_value_8616(
        artifact, word_proof.byte_proof, fact.instr_index,
    )
    if replayed != word_proof:
        return refuse(Refusal.STALE_WORD_PROOF)
    if fact.block_addr != artifact.function_addr:
        return refuse(Refusal.SEED_OUTSIDE_ENTRY)
    if fact.target_space is not MemSpace.REG or not full_word_register_8616(
        fact.target_name
    ):
        return refuse(Refusal.SEED_NOT_FULL_WORD_REGISTER)
    if fact.target_name is None:
        return refuse(Refusal.SEED_NOT_FULL_WORD_REGISTER)
    return _Seed8616(fact=fact, name=fact.target_name.lower())


@dataclass(frozen=True, slots=True)
class _Cone8616:
    """The proven acyclic target cone plus its block index and predecessors."""

    by_addr: dict[int, int]
    pred_map: dict[int, tuple[int, ...]]
    order: list[int]
    exits: tuple[int, ...]


def _cone_obligation_8616(
    artifact: IRFunctionArtifact,
    word_proof: EntryStackWordProof8616,
    target_block_addr: int,
) -> _Cone8616 | EntryWordTransportProof8616:
    """Index the artifact blocks and prove an acyclic entry-to-target cone."""
    def refuse(kind: Refusal) -> EntryWordTransportProof8616:
        return _refusal_proof_8616(
            artifact, word_proof, kind, block_addr=target_block_addr,
        )

    by_addr: dict[int, int] = {}
    for position, block in enumerate(artifact.blocks):
        if block.addr in by_addr:
            return refuse(Refusal.AMBIGUOUS_BLOCK_ADDR)
        by_addr[block.addr] = position
    if artifact.function_addr not in by_addr:
        return refuse(Refusal.MISSING_ENTRY_BLOCK)
    if target_block_addr not in by_addr:
        return refuse(Refusal.MISSING_TARGET_BLOCK)
    pred_map = build_x86_16_ir_predecessor_map(artifact)
    order, exits, failure = cone_traversal_8616(
        artifact, by_addr, pred_map, target_block_addr,
    )
    if failure is not None or order is None:
        return refuse(failure or Refusal.UNREACHABLE_TARGET)
    return _Cone8616(by_addr, pred_map, order, exits)


@dataclass(slots=True)
class _Traversal8616:
    """Accumulated cone traversal: target run, diagnostics, and census."""

    run: TransportRun8616
    refusals: list[EntryWordTransportRefusal8616]
    raw: int
    normalized: int
    poisoned: bool


def _traverse_cone_8616(
    *,
    artifact: IRFunctionArtifact,
    cone: _Cone8616,
    ssa: dict[int, SSABlock],
    seed: _Seed8616,
    target_block_addr: int,
    target_instr_index: int,
) -> _Traversal8616:
    """Drive the per-block transfer over the cone in topological order."""
    exits_state: dict[int, dict[str, bool] | None] = {}
    refusals: list[EntryWordTransportRefusal8616] = []
    raw = normalized = 0
    final_run: TransportRun8616 | None = None
    poisoned = False
    for addr in cone.order:
        if addr == artifact.function_addr:
            entry_regs: dict[str, bool] | None = {}
        else:
            entry_regs = meet_incoming_words_8616(
                cone.pred_map, exits_state, addr,
            )
        is_target = addr == target_block_addr
        run, exit_regs = transfer_block_8616(
            block_addr=addr,
            ssa_instrs=ssa[addr].instrs,
            entry_regs=entry_regs,
            stop_index=(
                target_instr_index if is_target else len(ssa[addr].instrs)
            ),
            seed_index=(
                seed.fact.instr_index if addr == seed.fact.block_addr else None
            ),
            seed_name=seed.name,
            seed_version=seed.fact.target_version,
            successor_addrs=artifact.blocks[cone.by_addr[addr]].successor_addrs,
        )
        raw += run.raw
        normalized += run.normalized
        refusals.extend(run.refusals)
        if is_target:
            final_run = run
            poisoned = entry_regs is None
        else:
            exits_state[addr] = exit_regs
    assert final_run is not None
    return _Traversal8616(final_run, refusals, raw, normalized, poisoned)


def _site_refusal_8616(
    kind: Refusal,
    detail: str,
    block_addr: int,
    index: int,
) -> list[EntryWordTransportRefusal8616]:
    """One refusal diagnostic bound to the selected target site."""
    return [EntryWordTransportRefusal8616(kind, detail, block_addr, index)]


def _selected_site_refusals_8616(
    *,
    target: IRInstr,
    run: TransportRun8616,
    block_addr: int,
    index: int,
) -> list[EntryWordTransportRefusal8616]:
    """Refuse the selected site unless it reads the proven word into a reg.

    Check order is contractual: scalar MOV shape, full-word width, scalar
    operand, then the tracked word resolution against the transfer state.
    """
    destination = target.dst
    if (
        target.op != "MOV" or destination is None
        or not plain_destination_8616(destination)
        or destination.space is not MemSpace.REG
    ):
        return _site_refusal_8616(
            Refusal.NON_SCALAR_TARGET,
            "selected site is not a scalar MOV reg def", block_addr, index,
        )
    if (
        destination.size != 2 or target.size != destination.size
        or not full_word_register_8616(destination.name)
    ):
        return _site_refusal_8616(
            Refusal.UNSUPPORTED_TARGET_WIDTH,
            "destination is not a full 16-bit register", block_addr, index,
        )
    if len(target.args) != 1 or not isinstance(target.args[0], IRValue):
        return _site_refusal_8616(
            Refusal.UNSUPPORTED_OPERAND,
            "mov source is not a scalar value", block_addr, index,
        )
    resolved_mark = len(run.refusals)
    resolved = run.read_word(target.args[0])
    read_refusals = run.refusals[resolved_mark:]
    if resolved is None:
        return [*read_refusals, *_site_refusal_8616(
            Refusal.UNSUPPORTED_OPERAND,
            "unsupported decorated source view", block_addr, index,
        )]
    if resolved:
        return list(read_refusals)
    source = target.args[0]
    defined = (
        source.source_tmp in run.temps
        if source.space is MemSpace.TMP
        else (source.name or "").lower() in run.regs
    )
    kind = Refusal.WORD_CLOBBERED if defined else Refusal.DIVERGENT_INCOMING_WORD
    return [*read_refusals, *_site_refusal_8616(
        kind, "source does not carry the proven word on all paths",
        block_addr, index,
    )]


def _proven_fact_8616(
    *,
    seed: _Seed8616,
    cone: _Cone8616,
    target: IRInstr,
    target_block_addr: int,
    target_instr_index: int,
) -> EntryWordTransport8616:
    """Assemble the conditional cone-scoped transport fact, never closure."""
    destination = target.dst
    assert destination is not None
    return EntryWordTransport8616(
        source=EntryWordSite8616(
            seed.fact.block_addr, seed.fact.instr_index,
            seed.fact.instruction_addr,
        ),
        target=EntryWordSite8616(
            target_block_addr, target_instr_index, target.addr,
        ),
        seed_register=seed.name,
        target_space=destination.space,
        target_tmp=destination.source_tmp,
        target_name=destination.name,
        target_version=destination.version,
        traversed_blocks=tuple(cone.order),
        retained_exits=cone.exits,
    )


def prove_entry_word_transport_8616(
    artifact: IRFunctionArtifact,
    word_proof: EntryStackWordProof8616,
    target_block_addr: int,
    target_instr_index: int,
) -> EntryWordTransportProof8616:
    """Prove the selected MOV destination carries the canonical entry word.

    Rejects cross-artifact, stale, or fabricated proofs by replaying the
    canonical word proof at its seed index. The seed must be a full 16-bit
    architectural REG definition in the unique entry block; the result asserts
    only the selected destination value, never a return or callee closure.
    """
    seed = _seed_obligation_8616(artifact, word_proof, target_block_addr)
    if isinstance(seed, EntryWordTransportProof8616):
        return seed
    cone = _cone_obligation_8616(artifact, word_proof, target_block_addr)
    if isinstance(cone, EntryWordTransportProof8616):
        return cone
    ssa = {
        addr: build_x86_16_block_local_ssa(artifact.blocks[cone.by_addr[addr]])
        for addr in cone.order
    }
    if not 0 <= target_instr_index < len(ssa[target_block_addr].instrs):
        return _refusal_proof_8616(
            artifact, word_proof, Refusal.BAD_TARGET_INDEX,
            block_addr=target_block_addr, index=target_instr_index,
        )
    traversal = _traverse_cone_8616(
        artifact=artifact, cone=cone, ssa=ssa, seed=seed,
        target_block_addr=target_block_addr,
        target_instr_index=target_instr_index,
    )
    if traversal.poisoned and target_block_addr != artifact.function_addr:
        refusals = [*traversal.refusals, EntryWordTransportRefusal8616(
            Refusal.UNSEEDED_PREDECESSOR,
            "a target predecessor bypasses the seed", target_block_addr,
        )]
        return _refused_8616(
            artifact, word_proof, refusals,
            raw=traversal.raw, normalized=traversal.normalized,
        )
    target = ssa[target_block_addr].instrs[target_instr_index]
    refusals = [*traversal.refusals, *_selected_site_refusals_8616(
        target=target, run=traversal.run,
        block_addr=target_block_addr, index=target_instr_index,
    )]
    if refusals:
        return _refused_8616(
            artifact, word_proof, refusals,
            raw=traversal.raw, normalized=traversal.normalized,
        )
    result = _proven_fact_8616(
        seed=seed, cone=cone, target=target,
        target_block_addr=target_block_addr,
        target_instr_index=target_instr_index,
    )
    return EntryWordTransportProof8616(
        artifact=artifact, word_proof=word_proof,
        verdict=EntryWordTransportVerdict8616.PROVEN, fact=result,
        raw_fact_count=1, normalized_fact_count=1,
        classified_fact_count=1, materialized_count=1,
        traversal=EntryWordTraversalStats8616(
            traversal.raw, traversal.normalized, 0,
        ),
    )

"""Layer: validation CFG superblock adapter.

Responsibility: prove call-free flat32 CFGs with finite split/merged blocks
and checked register permutations at interior cutpoints. Finite
single-entry/single-exit chains collapse into superblock summaries composed
through actual VEX SSA; branch and return boundaries keep full machine state
and closed successor token maps. A chain-only cycle is refused, never
removed or turned into a terminal. Calls, faults and indirect control stay
outside this slice.
"""

from __future__ import annotations

import importlib
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from tools.dosunit.cutpoint_state_relations import CutpointRelation, CutpointStateRelation
from tools.dosunit.flat32_environment_coverage import environment_parts
from tools.dosunit.flat32_invariant_proof import record_invariant_proof
from tools.dosunit.flat32_invariant_retry import retry_entry_invariants
from tools.dosunit.flat32_region_attempts import compare_attempt as _compare_attempt
from tools.dosunit.flat32_region_attempts import comparison_deadline
from tools.dosunit.flat32_relation_evidence import attempt_record as _attempt_record
from tools.dosunit.memory_invariant_obligations import MemoryInvariantProof
from tools.dosunit.memory_relation_proposals import propose_entry_memory_relations
from tools.dosunit.memory_state_invariants import MemoryInvariant, MemoryInvariantRefusal
from tools.dosunit.memory_state_relations import MemoryPermutation, MemoryRelationRefusal
from tools.dosunit.paired_region_graph import (
    CollapsedRegion,
    RegionExitKind,
    RegionGraphReason,
    RegionGraphRefusal,
    RegionNode,
)
from tools.dosunit.proof_scope import ProofScope
from tools.dosunit.region_pairing import propose_paired_regions
from tools.dosunit.register_affine_relations import propose_entry_relation
from tools.dosunit.register_state_relations import (
    IDENTITY_RELATION,
    MachineState,
    RegisterRelationRefusal,
)
from tools.dosunit.ssa_constant_terms import constant_bitvector

if TYPE_CHECKING:
    import angr




def _seams() -> tuple[Any, Any, Any, Any]:
    """Resolve the driver's flat32 adapter/cfg/catalog/verdict modules.

    The artifact directories are not a package: each driver puts its own
    directory on ``sys.path`` before calling, so this one implementation
    serves the MSC8 and BC5 copies without hard-coding either.
    """
    return (
        importlib.import_module("flat32_adapter"),
        importlib.import_module("flat32_cfg"),
        importlib.import_module("flat32_catalog"),
        importlib.import_module("flat32_verdict"),
    )


# The common owner retains graph/progress semantics for both architectures.
type _Superblock = CollapsedRegion


def _initial_state(adapter: Any) -> dict[str, dict[str, Any]]:  # noqa: ANN401
    """Full symbolic machine state: every flat32 register plus whole memory."""
    state = {name: {"op": "input", "name": name, "width": width} for name, width in adapter.REG32.values()}
    state["memory"] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    return state


def _check_composition_inputs(
    superblock: _Superblock, member_docs: list[dict[str, Any]], internal_tokens: tuple[int, ...],
) -> None:
    """Require all real members and one checked continuation per internal edge."""
    if not member_docs or len(member_docs) != len(superblock.members):
        raise RegionGraphRefusal(RegionGraphReason.MEMBERS)
    if len(internal_tokens) != len(member_docs) - 1:
        raise RegionGraphRefusal(RegionGraphReason.PROGRESS_MISSING)


def _compose_superblock(
    superblock: _Superblock,
    member_docs: list[dict[str, Any]],
    *,
    name: str,
    module: str,
    outputs: tuple[str, ...],
    adapter: Any,  # noqa: ANN401
    refusal: type[Exception],
    relation: CutpointRelation = IDENTITY_RELATION,
    is_entry: bool = False,
    reenters_entry: bool = False,
    internal_tokens: tuple[int, ...],
    invariant: MemoryInvariant | None = None,
    invariant_proofs: list[MemoryInvariantProof] | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Compose member transitions into one superblock doc under the token map."""
    _check_composition_inputs(superblock, member_docs, internal_tokens)
    state = _initial_state(adapter)
    if not is_entry:
        if invariant is not None:
            state = invariant.apply(state)
        state = relation.candidate_inputs(state)
    for index, member in enumerate(member_docs):
        member_outputs = member.get("outputs", {})
        if member.get("trap_exits") or "io" in member_outputs:
            raise refusal("unsupported_effect_in_superblock")
        state = adapter.S._compose_block_outputs(member, member_outputs, state)
        if index < len(internal_tokens):
            control = constant_bitvector(state['eip'])
            if control != (internal_tokens[index], 32):
                raise RegionGraphRefusal(RegionGraphReason.PROGRESS)
    if superblock.kind is not RegionExitKind.RETURN:
        state = relation.continuing_outputs(state, control_field="eip", reenters_entry=reenters_entry)
        record_invariant_proof(invariant, state, invariant_proofs, adapter=adapter,
                               refusal=refusal, deadline=deadline, is_entry=is_entry,
                               reenters_entry=reenters_entry)
    observed = outputs if superblock.kind is RegionExitKind.RETURN else tuple(name for name, _ in adapter.REG32.values())
    terms: dict[str, Any] = {"memory": state["memory"]}
    for reg in observed:
        if reg not in state:
            raise refusal(f"missing_state:{reg}")
        terms[reg] = state[reg]
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    term_cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    materialized = {
        reg: adapter.S._materialize_json_term(term, assignments=assignments, memo=memo, term_cache=term_cache)
        for reg, term in terms.items()
    }
    entry = {"linear": hex(superblock.members[0])}
    return {
        "id": f"{module}:{name}",
        "function": {"id": f"{module}:{name}", "name": name},
        "part": {"kind": "superblock", "index": 0, "entry_delta": "0x0"},
        "entry": entry,
        "function_entry": entry,
        "source": {"jumpkind": superblock.kind.value, "reblocked_members": len(superblock.members)},
        "inputs": adapter.S._term_input_items(materialized.values(), assignments),
        "outputs": materialized,
        "assignments": assignments,
    }


def _lower_superblocks(
    blocks: dict[int, Any],
    superblocks: list[_Superblock],
    ordered: list[int],
    module: str,
    outputs: tuple[str, ...],
    adapter: Any,  # noqa: ANN401
    refusal: type[Exception],
    relation: CutpointRelation = IDENTITY_RELATION,
    *, invariant: MemoryInvariant | None = None,
    invariant_proofs: list[MemoryInvariantProof] | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Lower each paired superblock; edge tokens are pair positions, not addrs."""
    pair_index = {sb_index: index for index, sb_index in enumerate(ordered)}
    # Retained cutpoints and temporary interior PCs are different concepts.
    # Shared interior guards have no unique owner and their tokens never escape
    # the finite composed transition. Each internal continuation is checked.
    tokens = {superblocks[index].members[0]: pair_index[index] for index in ordered}
    for address in sorted(set(blocks) - set(tokens)):
        tokens[address] = len(tokens)
    full_state = tuple(name for name, _ in adapter.REG32.values())
    functions: list[dict[str, Any]] = []
    for index, sb_index in enumerate(ordered):
        member_docs: list[dict[str, Any]] = []
        with adapter.installed(tokens):
            for address in superblocks[sb_index].members:
                body = adapter.S._lower_irsb(
                    blocks[address].irsb, output_regs=full_state, max_assignments_per_function=4096
                )
                if isinstance(body, adapter.S.LowerFailure):
                    raise refusal(f"{body.reason}: {body.message}")
                member_docs.append(body)
        functions.append(
            _compose_superblock(
                superblocks[sb_index],
                member_docs,
                name=f"sb_{index}",
                module=module,
                outputs=outputs,
                adapter=adapter,
                refusal=refusal,
                relation=relation, is_entry=index == 0,
                reenters_entry=any(tokens[target] == 0 for target in superblocks[sb_index].exits),
                internal_tokens=tuple(tokens[address] for address in superblocks[sb_index].members[1:]),
                invariant=invariant, invariant_proofs=invariant_proofs, deadline=deadline,
            )
        )
    return {"functions": functions}


def compare_reblocked_cfg(
    projects: tuple[angr.Project, angr.Project],
    oracle_range: tuple[int, int],
    candidate_range: tuple[int, int],
    outputs: tuple[str, ...],
    timeout_ms: int,
    max_blocks: int = 128,
    *,
    name: str = "reblocked",
    invariant: MemoryInvariant | None = None,
    total_deadline: float | None = None,
) -> dict[str, Any]:
    """Prove a paired flat32 CFG modulo straight-line reblocking.

    Both sides are discovered as real VEX CFGs, unconditional single-entry
    chains collapse into composed superblock transitions, and the paired
    superblock induction is discharged by the SSA/Z3 comparator. Any wider
    graph difference, chain cycle, call, fault or indirect edge refuses.
    """
    deadline = comparison_deadline(timeout_ms, total_deadline)
    adapter, cfg, catalog, verdict = _seams()
    outputs = tuple(dict.fromkeys((*outputs, *adapter.OUTPUT_REGS[2:])))
    oracle, candidate = projects
    invariant_proofs: list[MemoryInvariantProof] = []
    original: MachineState | None = None
    try:
        oblocks = cfg.discover(oracle, *oracle_range, max_blocks)
        cblocks = cfg.discover(candidate, *candidate_range, max_blocks)
        # Driver block objects are a dynamic adapter boundary; the shared owner
        # consumes only typed nodes and never relies on a compiler/library name.
        o_nodes = {address: RegionNode(address, tuple(block.successors), RegionExitKind(block.irsb.jumpkind))
                   for address, block in oblocks.items()}
        c_nodes = {address: RegionNode(address, tuple(block.successors), RegionExitKind(block.irsb.jumpkind))
                   for address, block in cblocks.items()}
        graph = propose_paired_regions(o_nodes, c_nodes, oracle_range[0], candidate_range[0])
        o_sbs, c_sbs, pairs = list(graph.oracle.regions), list(graph.candidate.regions), list(graph.pairs)
        ossa = _lower_superblocks(
            oblocks, o_sbs, [left for left, _ in pairs], "oracle", outputs, adapter, cfg.CfgRefusal,
            invariant=invariant, invariant_proofs=invariant_proofs, deadline=deadline,
        )
        cssa = _lower_superblocks(
            cblocks, c_sbs, [right for _, right in pairs], "candidate", outputs, adapter, cfg.CfgRefusal,
            invariant=invariant,
        )
    except cfg.CfgRefusal as error:
        return {"function": {"name": name}, "status": verdict.Status.REFUSED, "reason": str(error)}
    except (RegionGraphRefusal, MemoryInvariantRefusal) as error:
        return {"function": {"name": name}, "status": verdict.Status.REFUSED, "reason": error.reason.value}
    status, compared, verdicts = _compare_attempt(ossa, cssa, deadline, adapter, catalog, verdict,
                                                tuple(invariant_proofs))
    attempts = [_attempt_record(IDENTITY_RELATION, status, compared, verdicts, len(pairs), invariant, tuple(invariant_proofs))]
    selected: CutpointRelation = IDENTITY_RELATION
    proposal_reason = None
    memory_proposal_reason = None
    if status is not verdict.Status.PASSED:
        # Entry matching proposes a map; the solver must discharge all rows.
        original_entry: MachineState = adapter.S._compose_block_outputs(ossa["functions"][0], ossa["functions"][0]["outputs"],
                                                                       _initial_state(adapter))
        original = original_entry
        rebuilt = adapter.S._compose_block_outputs(cssa["functions"][0], cssa["functions"][0]["outputs"],
                                                   _initial_state(adapter))
        eligible = {name: width for name, width in adapter.REG32.values() if name in adapter.GPRS and name != "esp"}
        proposal = propose_entry_relation(original_entry, rebuilt, eligible)
        proposal_reason = proposal.reason
        if proposal.relation is not None and not proposal.relation.is_identity:
            try:
                cssa = _lower_superblocks(cblocks, c_sbs, [right for _, right in pairs],
                                         "candidate", outputs, adapter, cfg.CfgRefusal, proposal.relation,
                                         invariant=invariant)
                status, compared, verdicts = _compare_attempt(ossa, cssa, deadline, adapter, catalog, verdict,
                                                            tuple(invariant_proofs))
                selected = proposal.relation
                attempts.append(_attempt_record(selected, status, compared, verdicts, len(pairs), invariant, tuple(invariant_proofs)))
            except (cfg.CfgRefusal, RegisterRelationRefusal, RegionGraphRefusal) as error:
                attempts.append(_attempt_record(proposal.relation, verdict.Status.REFUSED,
                                                {"reason": str(error)}, [], len(pairs), invariant, tuple(invariant_proofs)))
        # A discharged register relation finishes the proposal search.
        memory_proposals = () if status is verdict.Status.PASSED else propose_entry_memory_relations(original_entry, rebuilt)
        for memory_proposal in memory_proposals:
            memory_proposal_reason = memory_proposal.reason
            if memory_proposal.relation is not None and not memory_proposal.relation.is_identity:
                state_relation = CutpointStateRelation(memory_proposal.relation)
                try:
                    cssa = _lower_superblocks(cblocks, c_sbs, [right for _, right in pairs],
                                             "candidate", outputs, adapter, cfg.CfgRefusal, state_relation,
                                             invariant=invariant)
                    status, compared, verdicts = _compare_attempt(ossa, cssa, deadline, adapter, catalog, verdict,
                                                                tuple(invariant_proofs))
                    selected = state_relation
                    attempts.append(_attempt_record(selected, status, compared, verdicts, len(pairs), invariant, tuple(invariant_proofs)))
                except (cfg.CfgRefusal, MemoryRelationRefusal, RegionGraphRefusal) as error:
                    attempts.append(_attempt_record(state_relation, verdict.Status.REFUSED,
                                                    {"reason": str(error)}, [], len(pairs), invariant, tuple(invariant_proofs)))
            if status is verdict.Status.PASSED:
                break
    selected_registers = selected.registers if isinstance(selected, CutpointStateRelation) else selected
    result = {
        "function": {"name": name},
        "graph_evidence": asdict(graph.evidence),
        "status": status,
        "reason": "reblocked_cfg_induction",
        "proof_scope": ProofScope.CUTPOINT_SIMULATION,
        "register_relation": [asdict(binding) for binding in selected_registers.bindings],
        "memory_relation": asdict(selected.memory) if isinstance(selected, CutpointStateRelation) else None,
        "memory_proposal_reason": memory_proposal_reason,
        "memory_invariant": asdict(invariant) if invariant is not None else None,
        "memory_invariant_proofs": [asdict(proof) for proof in invariant_proofs],
        "relation_attempts": attempts,
        "proposal_reason": proposal_reason,
        "counters": _attempt_record(selected, status, compared, verdicts, len(pairs), invariant, tuple(invariant_proofs))["counters"],
        "superblock_pairs": [
            {
                "oracle": [hex(address) for address in o_sbs[left].members],
                "candidate": [hex(address) for address in c_sbs[right].members],
            }
            for left, right in pairs
        ],
        "environment_coverage": {"oracle": environment_parts(oblocks),
                                 "candidate": environment_parts(cblocks)},
        "oracle_ssa": ossa,
        "candidate_ssa": cssa,
        "block_compare": compared,
        "block_verdicts": verdicts,
    }
    return retry_entry_invariants(
        result, original, selected.memory if isinstance(selected, CutpointStateRelation) else MemoryPermutation(),
        explicit=invariant, deadline=deadline,
        compare=lambda proposed, remaining: compare_reblocked_cfg(
            projects, oracle_range, candidate_range, outputs, remaining, max_blocks,
            name=name, invariant=proposed, total_deadline=deadline,
        ),
    )

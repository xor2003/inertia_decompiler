"""Layer: validation table-target evidence.

Responsibility: compare bounded returning table targets over equal entry
state using native i386 VEX and the existing SSA solver. Dispatch reachability
and equality of state arriving at those targets remain separate obligations.
"""

from __future__ import annotations

import copy
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, cast

import archinfo
import pefile
import pyvex

from tools.comparator.table_checks import read_pe_bytes, read_pe_window
from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.architectures.flat32_enter_lifter import ensure_flat32_enter_lifter
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation, observe_completed_pair
from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal
from tools.dosunit.compare.flat32_call_execution import _prove_return_target
from tools.dosunit.compare.flat32_call_lowering import _check_exits, _first_exit_instruction_count, _static_next
from tools.dosunit.compare.flat32_call_repeat import repeat_boundary_count_from_bytes
from tools.dosunit.compare.flat32_constant_branches import BranchValue, ConstantBranchProof, constant_branch
from tools.dosunit.contracts.binary_environment import requires_environment_contract
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.ssa.composition import compose_block_outputs, merge_states
from tools.dosunit.ssa.materialization import input_items, materialize_term


@dataclass(frozen=True, slots=True)
class _TargetControlPath:
    """Track branch evidence independently on each native execution path."""

    visits: dict[int, tuple[int, int]] = field(default_factory=dict)
    constant_edges: int = 0
    symbolic_edges: int = 0

    def admits(self, address: int) -> bool:
        """Revisit only after a nonempty entirely constant-controlled loop traversal."""
        previous = self.visits.get(address)
        return (previous is None or
                (self.constant_edges > previous[0] and self.symbolic_edges == previous[1]))

    def enter(self, address: int) -> _TargetControlPath:
        """Record the latest visit without changing sibling or caller paths."""
        return replace(self, visits={**self.visits, address: (self.constant_edges, self.symbolic_edges)})

    def branch(self, *, proved: bool) -> _TargetControlPath:
        """Carry only the evidence for the exact edge followed by this path."""
        return replace(self, constant_edges=self.constant_edges + int(proved),
                       symbolic_edges=self.symbolic_edges + int(not proved))



@dataclass(slots=True)
class _TargetProofCache:
    """Bounded immutable-code/guard reuse within one paired-target obligation set."""

    blocks: dict[tuple[bytes, int], tuple[dict[str, Any] | None, dict[str, object], int | None]] = field(default_factory=dict)
    branches: dict[str, ConstantBranchProof] = field(default_factory=dict)
    hits: int = 0

    def lower(self, image: bytes, address: int) -> tuple[dict[str, Any] | None, dict[str, object], int | None]:
        """Reuse input-state-independent lowering; keep per-visit receipt facts separate."""
        key = image, address
        result = self.blocks.get(key)
        if result is None:
            result = _mapped_target_block(image, address)
            if len(self.blocks) < 256:
                self.blocks[key] = result
        else:
            self.hits += 1
        document, facts, successor = result
        return document, copy.deepcopy(facts), successor


def _target_irsb(raw: bytes, address: int, arch: archinfo.ArchX86) -> pyvex.IRSB:
    """Retain only instructions through the first native conditional exit."""
    # The pyvex protocol stub disagrees with the accepted archinfo object types.
    irsb = pyvex.IRSB(raw, address, cast(Any, arch), opt_level=0)
    if irsb.size == 0 or irsb.jumpkind not in {"Ijk_Ret", "Ijk_Boring", "Ijk_Call"}:
        return irsb
    instruction_count = _first_exit_instruction_count(irsb)
    repeat_count = repeat_boundary_count_from_bytes(
        irsb, lambda at, size: raw[at - address:at - address + size],
    )
    if repeat_count is not None:
        instruction_count = min(instruction_count, repeat_count) if instruction_count is not None else repeat_count
    if instruction_count is not None:
        irsb = pyvex.IRSB(raw, address, cast(Any, arch), opt_level=0, max_inst=instruction_count)
    return irsb


def _target_block(image: bytes, address: int) -> tuple[dict[str, Any] | None, dict[str, object], int | None]:
    """Lift one effect-complete block ending in a return or static direct transfer."""
    ensure_flat32_enter_lifter()
    raw = read_pe_window(image, address, 128, executable=True)
    arch = archinfo.ArchX86()
    if arch.ip_offset is None:
        raise ValueError("i386 architecture has no instruction pointer offset")
    irsb = _target_irsb(raw, address, arch)
    facts: dict[str, object] = {"address": hex(address), "byte_count": int(irsb.size),
                                "jumpkind": str(irsb.jumpkind)}
    if irsb.size == 0:
        return None, {**facts, "pending": "target cannot be decoded"}, None
    code = read_pe_bytes(image, address, int(irsb.size), executable=True)
    facts["instruction_bytes"] = code.hex()
    if irsb.jumpkind not in {"Ijk_Ret", "Ijk_Boring", "Ijk_Call"}:
        return None, {**facts, "pending": "target requires unsupported transfer composition"}, None
    try:
        exits = _check_exits(irsb, int(arch.ip_offset))
    except CallCompositionRefusal as error:
        return None, {**facts, "pending": str(error)}, None
    if exits and irsb.jumpkind != "Ijk_Boring":
        return None, {**facts, "pending": "conditional exit before call or return requires separate blocks"}, None
    facts["conditional_targets"] = [hex(target) for target in exits]
    successor = None if irsb.jumpkind == "Ijk_Ret" else _static_next(irsb)
    if irsb.jumpkind != "Ijk_Ret" and successor is None:
        return None, {**facts, "pending": "target requires indirect transfer composition"}, None
    if irsb.jumpkind == "Ijk_Call":
        facts.update(callsite=int(irsb.instruction_addresses[-1]), fallthrough=address + int(irsb.size))
    if requires_environment_contract(irsb):
        return None, {**facts, "pending": "target requires an external environment contract"}, None
    architecture = flat32_register_architecture()
    outputs = (*(name for name, _width in architecture.registers if name != "eip"), "ip")
    lowered = S._lower_irsb(irsb, output_regs=outputs, max_assignments_per_function=4096,
                            architecture=architecture)
    if isinstance(lowered, S.LowerFailure):
        return None, {**facts, "pending": lowered.reason, "detail": lowered.message}, None
    # The shared lowerer omits unchanged memory; observe it explicitly so a
    # write on only one side compares against the original array, not output sets.
    lowered["outputs"].setdefault("memory", {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8})
    facts["observed_outputs"] = sorted(lowered["outputs"])
    return lowered, facts, successor


def _mapped_target_block(image: bytes, address: int) -> tuple[dict[str, Any] | None, dict[str, object], int | None]:
    """Translate malformed or unmapped native target input into explicit missing evidence."""
    try:
        return _target_block(image, address)
    except (pefile.PEFormatError, ValueError) as error:
        raise S.LowerFailure("target leaves mapped executable bytes", str(error)) from error


def _call_continuation(
    block: dict[str, object], target: int, state: dict[str, dict[str, Any]], path: _TargetControlPath,
    visit: Callable[[int, dict[str, dict[str, Any]], _TargetControlPath], dict[str, dict[str, Any]]],
    deadline: float, calls: list[dict[str, object]], input_constraints: list[dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """Inline native callee effects and reuse the shared exact return-target proof."""
    returned = visit(target, state, path)
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    if remaining_ms <= 0:
        raise S.LowerFailure("target chain cycle or composition deadline", "no time remains for return proof")
    fallthrough = cast(int, block["fallthrough"])
    _prove_return_target(returned["ip"], fallthrough, timeout_ms=min(250, remaining_ms),
                         callsite=cast(int, block["callsite"]), call_block=int(str(block["address"]), 0),
                         target=target, callee="", input_constraints=input_constraints)
    calls.append({"callsite": hex(cast(int, block["callsite"])), "target": hex(target),
                  "fallthrough": hex(fallthrough), "return_target_proved": True})
    return visit(fallthrough, returned, path)


def _follow_target_control(
    control: dict[str, Any], state: dict[str, dict[str, Any]], path: _TargetControlPath,
    visit: Callable[[int, dict[str, dict[str, Any]], _TargetControlPath], dict[str, dict[str, Any]]],
    stats: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Evaluate both sides of finite direct control and merge all observations."""
    if control.get("op") == "const":
        raw = control["value"]
        return visit(int(raw, 0) if isinstance(raw, str) else int(raw), state, path)
    if control.get("op") != "ite":
        raise S.LowerFailure("target requires indirect transfer composition", "control is not a direct-target tree")
    guard, taken, otherwise = control["args"]
    proof = constant_branch(guard, cache=stats["branch_cache"])
    if proof.value is not BranchValue.UNKNOWN:
        stats["constant_branch_checks"].append(proof.to_document())
        selected = taken if proof.value is BranchValue.TRUE else otherwise
        return _follow_target_control(selected, state, path.branch(proved=True), visit, stats)
    path = path.branch(proved=False)
    left = _follow_target_control(taken, state, path, visit, stats)
    right = _follow_target_control(otherwise, state, path, visit, stats)
    return merge_states(guard, left, right, compose_stats=stats)


def _returning_block(
    image: bytes, address: int, *, incoming_state: dict[str, dict[str, Any]] | None = None,
    input_constraints: list[dict[str, Any]] | None = None,
    proof_cache: _TargetProofCache | None = None,
) -> tuple[dict[str, Any] | None, dict[str, object]]:
    """Compose at most 16 block visits; publish only fully closed native return paths."""
    blocks: list[dict[str, object]] = []
    deadline = time.monotonic() + 2.0
    proof_cache = proof_cache if proof_cache is not None else _TargetProofCache()
    initial_hits = proof_cache.hits
    branch_checks: list[dict[str, object]] = []
    stats: dict[str, Any] = {"deadline": deadline, "constant_branch_checks": branch_checks,
                             "branch_cache": proof_cache.branches}
    calls: list[dict[str, object]] = []
    facts: dict[str, object] = {"address": hex(address), "blocks": blocks, "call_sites": calls,
                                "constant_branch_checks": branch_checks}
    initial = {} if incoming_state is None else incoming_state

    def visit(current: int, incoming: dict[str, dict[str, Any]], path: _TargetControlPath) -> dict[str, dict[str, Any]]:
        """Compose one path; siblings keep independent state and cycle ancestry."""
        if not path.admits(current) or time.monotonic() >= deadline:
            raise S.LowerFailure("target chain cycle or composition deadline", "target composition budget exhausted")
        if len(blocks) >= 16:
            reason = "target chain cycle or composition deadline" if current in path.visits else "target chain block limit"
            raise S.LowerFailure(reason, "at most 16 block visits are admitted")
        lowered, block, successor = proof_cache.lower(image, current)
        facts["lowering_cache_hits"] = proof_cache.hits - initial_hits
        blocks.append(block)
        facts["jumpkind"] = block["jumpkind"]
        if lowered is None:
            raise S.LowerFailure(str(block["pending"]), str(block.get("detail", "target lowering incomplete")))
        state = compose_block_outputs(lowered, lowered["outputs"], incoming, compose_stats=stats)
        if successor is None:
            return state
        if block["jumpkind"] == "Ijk_Call":
            return _call_continuation(block, successor, state, path.enter(current), visit, deadline, calls, input_constraints)
        return _follow_target_control(state["ip"], state, path.enter(current), visit, stats)

    try:
        state = visit(address, initial, _TargetControlPath())
    except S.LowerFailure as error:
        return None, {**facts, "pending": error.reason, "detail": error.message}
    except CallCompositionRefusal as error:
        return None, {**facts, "pending": str(error),
                      "return_target_failure": error.evidence.to_document() if error.evidence is not None else None}
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    outputs = {name: materialize_term(term, assignments=assignments, memo=memo) for name, term in state.items()}
    facts.update(byte_count=sum(cast(int, block["byte_count"]) for block in blocks),
                 observed_outputs=sorted(outputs), blocks_composed=len(blocks), return_targets_proved=len(calls))
    return {"outputs": outputs, "assignments": assignments,
            "inputs": input_items(outputs.values(), assignments)}, facts


def _observe_under_guards(
    left: dict[str, Any], right: dict[str, Any],
    guards: tuple[dict[str, Any], dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Prove equal guards and all effects on their common reachable domain.

    Outside that domain both observations use the original effects. No effect
    is discarded on reachable inputs; guard equality is itself an output proof.
    This masks observations only, never callee return-address obligations.
    """
    original = compose_block_outputs(left, left["outputs"], {})
    candidate = compose_block_outputs(right, right["outputs"], {})
    candidate = merge_states(guards[1], candidate, original, compose_stats={})
    documents = []
    for state, guard in zip((original, candidate), guards, strict=True):
        assignments: list[dict[str, Any]] = []
        memo: dict[str, str] = {}
        state = {**state, "dispatch_reached": guard}
        outputs = {name: materialize_term(term, assignments=assignments, memo=memo)
                   for name, term in state.items()}
        documents.append({"outputs": outputs, "assignments": assignments,
                          "inputs": input_items(outputs.values(), assignments)})
    return documents[0], documents[1]


def check_returning_targets(
    original_image: bytes, candidate_image: bytes, correspondence: dict[int, int],
    *, incoming_states: tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]] | None = None,
    entry_domain: Flat32ProofDomain | None = None,
    observation_guards: tuple[dict[str, Any], dict[str, Any]] | None = None,
    abi_observation: Flat32AbiObservation | None = None,
) -> dict[str, object]:
    """Compare each unique declared pair once, without dropping flags or memory.

    Success is a block lemma under equal incoming machine state, not evidence
    that either root actually supplies that state. Unsupported control remains
    visible as incomplete partial evidence and never becomes assumed equality.
    Optional incoming states are exact root-prefix compositions. A root domain
    applies only to those root inputs, never to independent target-entry ESP.
    """
    if incoming_states is None and (entry_domain is not None or observation_guards is not None):
        raise ValueError("root domain and observation guards require composed incoming states")
    if abi_observation is not None and incoming_states is None:
        raise ValueError("ABI observations require complete root-composed returns")
    constraints = entry_domain.constraints() if entry_domain is not None else None
    left_state, right_state = incoming_states if incoming_states is not None else (None, None)
    pairs: list[dict[str, object]] = []
    proof_cache = _TargetProofCache()
    for original_address, candidate_address in sorted(correspondence.items()):
        left, original = _returning_block(original_image, original_address, incoming_state=left_state,
                                          input_constraints=constraints, proof_cache=proof_cache)
        right, candidate = _returning_block(candidate_image, candidate_address, incoming_state=right_state,
                                            input_constraints=constraints, proof_cache=proof_cache)
        row: dict[str, object] = {"original": original, "candidate": candidate, "status": "incomplete"}
        if left is not None and right is not None:
            row.update(_compare_returned_pair(left, right, abi_observation, observation_guards, constraints))
        pairs.append(row)
    status = "checked"
    if any(row["status"] == "mismatch" for row in pairs):
        status = "mismatch"
    elif not pairs or any(row["status"] == "incomplete" for row in pairs):
        status = "incomplete"
    result: dict[str, object] = {"status": status, "scope": "returning_target_blocks", "pairs": pairs,
            "entry_relation": "equal modeled registers and memory at each paired target",
            "pending_conditions": ["root dispatch reaches paired targets with this entry-state relation"]}
    if incoming_states is not None:
        result.update(scope="root_composed_target_paths", entry_relation="exact composed state from equal root inputs")
    if entry_domain is not None:
        result["entry_domain_assumptions"] = entry_domain.assumption_document()
    if observation_guards is not None:
        result["observation_guards"] = list(observation_guards)
    return result


def _completed_abi_pair(
    left: dict[str, Any], right: dict[str, Any], contract: Flat32AbiObservation,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Select the declared ABI only after native execution has reached root returns.

    Flags and scratch values remain available throughout composition. The
    table lifter names return control ip rather than the ABI contract's eip.
    Memory remains observed under the existing explicit stack-lifetime premise.
    """
    outputs = {*contract.outputs(), "ip", "memory"}
    left = {**left, "outputs": {name: value for name, value in left["outputs"].items() if name in outputs}}
    right = {**right, "outputs": {name: value for name, value in right["outputs"].items() if name in outputs}}
    return observe_completed_pair(left, right, contract)


def _compare_returned_pair(
    left: dict[str, Any], right: dict[str, Any], abi_observation: Flat32AbiObservation | None,
    observation_guards: tuple[dict[str, Any], dict[str, Any]] | None,
    constraints: list[dict[str, Any]] | None,
) -> dict[str, object]:
    """Compare completed executions under the declared observations and exact guards."""
    facts: dict[str, object] = {}
    if abi_observation is not None:
        left, right, premise = _completed_abi_pair(left, right, abi_observation)
        facts["abi_observation"] = premise
    if observation_guards is not None:
        left, right = _observe_under_guards(left, right, observation_guards)
    result = S._compare_functions(left, right, timeout_ms=1000, input_constraints=constraints)
    return {**facts, "solver_result": result,
            "status": {"passed": "checked", "failed": "mismatch"}.get(result["status"], "incomplete")}

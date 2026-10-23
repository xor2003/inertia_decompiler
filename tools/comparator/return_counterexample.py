"""Layer: validation bounded root counterexamples.

Responsibility: find differing declared registers or memory bytes on two completed native
root-to-return paths. Bounded agreement can never establish equivalence.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, cast

from tools.comparator.table_checks import read_pe_bytes
from tools.comparator.table_target_checks import _mapped_target_block
from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import _term_nodes
from tools.dosunit.compare.flat32_constant_branches import BranchValue, constant_branch
from tools.dosunit.compare.flat32_scan_iteration import lower_scan_body, scan_repeat_guard
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.contracts.repeat_string_contracts import RepeatArchitecture, decode_repeat_summary
from tools.dosunit.ssa.composition import compose_block_outputs, merge_states
from tools.dosunit.ssa.materialization import input_items, materialize_term
from tools.dosunit.ssa.x86_flag_dependencies import project_flag_dependencies

MAX_DEPTH: int = 4
MEMORY_DEPTH: int = 12
MEMORY_BLOCK_VISITS: int = 3
MAX_VISITS: int = 64
MAX_NODES: int = 50000


class CounterexampleStatus(StrEnum):
    """Search results never include an equivalence-success status."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    INCOMPLETE = "incomplete"


def _constant(value: int, width: int = 1) -> dict[str, Any]:
    """Make a fixed-width SSA literal."""
    return {"op": "const", "width": width, "value": hex(value)}


@dataclass
class _Search:
    """Bound one image while retaining exact path conditions through merges."""

    image: bytes
    entry: int
    size: int
    deadline: float
    output_registers: tuple[str, ...] = ("eax",)
    observe_memory: bool = False
    visits: int = 0
    clipped: int = 0
    frontier_returns: int = 0
    blocks: dict[int, tuple[dict[str, Any] | None, dict[str, object], int | None]] = field(default_factory=dict)

    scan_bodies: dict[int, dict[str, Any]] = field(default_factory=dict)

    @property
    def depth_limit(self) -> int:
        """Give byte refutation a deeper path under unchanged total work limits."""
        return MEMORY_DEPTH if self.observe_memory else MAX_DEPTH

    @property
    def block_visit_limit(self) -> int:
        """Bound loop unfolding per path without treating truncation as return."""
        return MEMORY_BLOCK_VISITS if self.observe_memory else 1

    def stop(self, state: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Mark an unproved path; its values cannot supply a counterexample."""
        self.clipped += 1
        return {**{name: state[name] for name in (*self.output_registers, *(("memory",) if self.observe_memory else ()))}, "ip": state["ip"], "returned": _constant(0)}

    def follow(self, control: dict[str, Any], state: dict[str, dict[str, Any]], depth: int, path: tuple[int, ...]) -> dict[str, dict[str, Any]]:
        """Split native direct-control guards without guessing indirect targets."""
        if control.get("op") == "const":
            raw = control["value"]
            return self.visit(int(raw, 0) if isinstance(raw, str) else int(raw), state, depth, path)
        if control.get("op") != "ite":
            return self.stop(state)
        guard, taken, otherwise = control["args"]
        literal = constant_branch(guard).value
        if literal is BranchValue.TRUE:
            return self.follow(taken, state, depth, path)
        if literal is BranchValue.FALSE:
            return self.follow(otherwise, state, depth, path)
        left, right = self.follow(taken, state, depth, path), self.follow(otherwise, state, depth, path)
        merged: dict[str, dict[str, Any]] = merge_states(guard, left, right, compose_stats={"deadline": self.deadline})
        return merged

    def bounded_repeat(
        self, address: int, incoming: dict[str, dict[str, Any]], depth: int, path: tuple[int, ...],
    ) -> dict[str, dict[str, Any]] | None:
        """Explore exact zero-count REP and bounded native scalar SCAS iterations."""
        if not self.observe_memory or address + 2 > self.entry + self.size or depth == self.depth_limit:
            return None
        raw = read_pe_bytes(self.image, address, 2, executable=True)
        record = {"bytes": raw.hex(), "size": 2, "address": {"linear": hex(address)}}
        if decode_repeat_summary([record], architecture=RepeatArchitecture.FLAT32) is None:
            return None
        guard = {"op": "eq", "width": 1, "args": [incoming["ecx"], _constant(0, 32)]}
        literal = constant_branch(guard).value
        resumed = None
        next_path = (*path, address)
        if literal is not BranchValue.FALSE:
            resumed = self.visit(address + 2, {**incoming, "ip": _constant(address + 2, 32)},
                                 depth + 1, next_path)
        if literal is BranchValue.TRUE:
            assert resumed is not None
            return resumed
        if raw in (b"\xf2\xae", b"\xf3\xae", b"\xf2\xaf", b"\xf3\xaf"):
            if address not in self.scan_bodies:
                self.scan_bodies[address] = lower_scan_body(raw, address)
            body = self.scan_bodies[address]
            state = compose_block_outputs(body, body["outputs"], incoming, compose_stats={"deadline": self.deadline})
            continuation = scan_repeat_guard(raw, incoming, state)
            control = {"op": "ite", "width": 32, "args": [
                continuation, _constant(address, 32), _constant(address + 2, 32),
            ]}
            stepped = self.follow(control, state, depth + 1, next_path)
        else:
            stepped = self.stop(incoming)
        if resumed is None:
            return stepped
        merged: dict[str, dict[str, Any]] = merge_states(
            guard, resumed, stepped, compose_stats={"deadline": self.deadline},
        )
        return merged

    def visit(self, address: int, incoming: dict[str, dict[str, Any]], depth: int, path: tuple[int, ...]) -> dict[str, dict[str, Any]]:
        """Explore bounded control depth, closing actual RET blocks at its frontier.

        A terminal frontier consumes the same visit, expression and deadline
        budgets. It cannot follow another edge or synthesize a return.
        """
        if time.monotonic() >= self.deadline:
            raise S.LowerFailure("counterexample_deadline", "bounded root search deadline")
        if (path.count(address) >= self.block_visit_limit or depth > self.depth_limit
                or self.visits >= MAX_VISITS or not self.entry <= address < self.entry + self.size):
            return self.stop(incoming)
        self.visits += 1
        if address not in self.blocks:
            self.blocks[address] = _mapped_target_block(self.image, address)
        lowered, facts, _ = self.blocks[address]
        if address + int(cast(int, facts["byte_count"])) > self.entry + self.size:
            return self.stop(incoming)
        repeated = self.bounded_repeat(address, incoming, depth, path)
        if repeated is not None:
            return repeated
        if lowered is None or facts["jumpkind"] not in ("Ijk_Ret", "Ijk_Boring"):
            return self.stop(incoming)
        if depth == self.depth_limit and facts["jumpkind"] != "Ijk_Ret":
            # Closing a real return needs no further control exploration.
            # Branches, calls and even unconditional jumps stay clipped.
            return self.stop(incoming)
        state = compose_block_outputs(lowered, lowered["outputs"], incoming, compose_stats={"deadline": self.deadline})
        if _term_nodes(state, MAX_NODES) > MAX_NODES:
            raise S.LowerFailure("counterexample_expression_limit", "root expression budget")
        if facts["jumpkind"] == "Ijk_Ret":
            self.frontier_returns += int(depth == self.depth_limit)
            return {**{name: state[name] for name in (*self.output_registers, *(("memory",) if self.observe_memory else ()))}, "ip": state["ip"], "returned": _constant(1)}
        return self.follow(state["ip"], state, depth + 1, (*path, address))

    def run(self) -> dict[str, dict[str, Any]]:
        """Start both sides from identically named symbolic root inputs."""
        state: dict[str, dict[str, Any]] = {name: {"op": "input", "name": name, "width": width}
                 for name, width in flat32_register_architecture().registers if name != "eip"}
        state["memory"] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
        state["ip"] = _constant(self.entry, 32)
        return self.visit(self.entry, state, 0, ())


def _observation_document(terms: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Materialize declared return registers, retaining every memory dependency."""
    assignments: list[dict[str, Any]] = []
    memo: dict[str, Any] = {}
    outputs = {name: materialize_term(project_flag_dependencies(term), assignments=assignments, memo=memo) for name, term in terms.items()}
    return {"outputs": outputs, "assignments": assignments, "inputs": input_items(outputs.values(), assignments)}


def _returned_guard(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Require both paths to reach RET and return to the root caller slot."""
    root_return = {"op": "loadle", "width": 32, "args": [
        {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
        {"op": "input", "name": "esp", "width": 32}]}
    guard = {"op": "and", "width": 1, "args": [left["returned"], right["returned"]]}
    for state in (left, right):
        equal = {"op": "eq", "width": 1, "args": [state["ip"], root_return]}
        guard = {"op": "and", "width": 1, "args": [guard, equal]}
    # VEX's direction delta encodes architectural DF as +1 or -1. A
    # counterexample must not rely on another value of this internal register.
    direction = {"op": "input", "name": "d", "width": 32}
    valid_direction = {"op": "or", "width": 1, "args": [
        {"op": "eq", "width": 1, "args": [direction, _constant(1, 32)]},
        {"op": "eq", "width": 1, "args": [direction, _constant(0xFFFFFFFF, 32)]},
    ]}
    return {"op": "and", "width": 1, "args": [guard, valid_direction]}


def _witness_status(proof: dict[str, Any], output_registers: tuple[str, ...]) -> CounterexampleStatus:
    """Require a concrete declared-output SAT difference, never a structural failure label."""
    if proof["status"] == "passed":
        return CounterexampleStatus.NOT_FOUND
    changed = [item for item in proof.get("mismatches", [])
               if item.get("kind") == "output_expr_changed" and item.get("reg") in output_registers]
    if proof["status"] == "failed" and any(
            isinstance(item.get("oracle_value"), str) and isinstance(item.get("candidate_value"), str)
            and item["oracle_value"] != item["candidate_value"] for item in changed):
        return CounterexampleStatus.FOUND
    return CounterexampleStatus.INCOMPLETE


def find_return_counterexample(
    original: bytes, candidate: bytes, original_range: tuple[int, int], candidate_range: tuple[int, int],
    *, entry_domain: Flat32ProofDomain | None = None,
    output_registers: tuple[str, ...] = ("eax",),
    memory_addresses: tuple[int, ...] = (),
) -> dict[str, Any]:
    """Search declared register/byte observations; never promote bounded agreement.

    Both root states share registers and symbolic memory. Unvisited, unsupported
    or clipped paths are excluded on BOTH sides. Register differences at cutpoints or
    at only one completed return are therefore not accepted as counterexamples.
    """
    if any(size <= 0 or not 0 <= entry < entry + size <= 0x100000000 for entry, size in (original_range, candidate_range)):
        raise ValueError("counterexample ranges must be nonempty i386 extents")
    if not output_registers or len(set(output_registers)) != len(output_registers) or not set(output_registers) <= {"eax", "edx"}:
        raise ValueError("return counterexamples support distinct full-width EAX/EDX observations")
    if (len(set(memory_addresses)) != len(memory_addresses)
            or any(type(address) is not int or not 0 <= address < 2**32 for address in memory_addresses)):
        raise ValueError("counterexample memory addresses must be distinct uint32 integers")
    deadline = time.monotonic() + 2.0
    searches = (_Search(original, *original_range, deadline, output_registers, bool(memory_addresses)),
                _Search(candidate, *candidate_range, deadline, output_registers, bool(memory_addresses)))
    result: dict[str, Any] = {
        "status": CounterexampleStatus.INCOMPLETE, "equivalence_proved": False,
        "scope": ("full_width_eax_on_paired_root_returns" if output_registers == ("eax",)
                  else "declared_full_width_registers_on_paired_root_returns"),
        "output_registers": list(output_registers), "bounds": {"depth": searches[0].depth_limit, "terminal_frontier_only": True,
                    "block_visits_per_path": searches[0].block_visit_limit, "visits_per_side": MAX_VISITS},
        "image_sha256": [hashlib.sha256(image).hexdigest() for image in (original, candidate)],
        "ranges": [list(original_range), list(candidate_range)],
    }
    if memory_addresses:
        result["memory_addresses"] = [hex(address) for address in memory_addresses]
        result["scope"] = "declared_registers_and_memory_bytes_on_paired_root_returns"
    try:
        left, right = (search.run() for search in searches)
        guard = _returned_guard(left, right)
        for state in (left, right):
            for address in memory_addresses:
                state[f"memory_byte_{address:08x}"] = {
                    "op": "loadle", "width": 8, "args": [state["memory"], _constant(address, 32)],
                }
        outputs = (*output_registers, *(f"memory_byte_{address:08x}" for address in memory_addresses))
        observed = {name: {"op": "ite", "width": left[name]["width"], "args": [guard, right[name], left[name]]}
                    for name in outputs}
        if _term_nodes(observed, MAX_NODES) > MAX_NODES:
            raise S.LowerFailure("counterexample_expression_limit", "merged root observation budget")
        proof = S._compare_functions(_observation_document({name: left[name] for name in outputs}),
                                     _observation_document(observed), timeout_ms=1000, capture_memory_model=True,
                                     input_constraints=entry_domain.constraints() if entry_domain is not None else None)
        result["solver_result"] = proof
        result["status"] = _witness_status(proof, outputs)
    except S.LowerFailure as error:
        result["reason"] = error.reason
    result["work"] = [{"visited_blocks": search.visits, "clipped_paths": search.clipped, "frontier_returns": search.frontier_returns} for search in searches]
    if entry_domain is not None:
        result["entry_domain"] = entry_domain.assumption_document()
    return result


def attach_return_counterexamples(
    report: dict[str, Any], original: bytes, candidate: bytes, eligible_names: set[str],
    *, entry_domain: Flat32ProofDomain | None = None,
    output_registers: tuple[str, ...] = ("eax",),
    memory_addresses: tuple[int, ...] = (),
) -> None:
    """Replace only refusals with SAT witnesses at declared root-return observations."""
    for row in report["results"]:
        name = row["function"]["name"]
        if row["status"] != "refused" or name not in eligible_names:
            continue
        ranges = report["function_ranges"]
        if name not in ranges["oracle"] or name not in ranges["candidate"]:
            continue
        evidence = find_return_counterexample(original, candidate, tuple(ranges["oracle"][name]),
                                               tuple(ranges["candidate"][name]), entry_domain=entry_domain,
                                               output_registers=output_registers, memory_addresses=memory_addresses)
        if evidence["status"] == CounterexampleStatus.FOUND:
            strict = dict(row)
            memory_changed = _witness_status(
                evidence["solver_result"], tuple(f"memory_byte_{address:08x}" for address in memory_addresses),
            ) is CounterexampleStatus.FOUND
            row.update(status="failed", reason=("root_return_memory_counterexample" if memory_changed
                                               else "root_return_value_counterexample"), backend_status="failed",
                       proof_scope="complete_function", proof_method="bounded_root_return_counterexample",
                       strict_function_result=strict)
        row["root_counterexample"] = evidence

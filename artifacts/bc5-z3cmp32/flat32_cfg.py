"""Layer: validation CFG adapter.

Responsibility: prove closed, bijectively matched i386 CFGs by block induction.
Every internal edge compares full modeled machine state and the entire memory
array. Returns compare the chosen ABI observables. Calls, faults, indirect
jumps and unmatched graphs refuse; loops are not bounded-unrolled into proofs.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

import angr
import pyvex
from flat32_adapter import ARCH, OUTPUT_REGS, REG32, S, installed
from flat32_catalog import mapping
from flat32_verdict import Status, aggregate, checked_results

from tools.dosunit.flat32_cfg_lifting import CfgLiftingRefusal, lift_cfg_block
from tools.dosunit.proof_contracts import ProofStatus, legacy_status_for, proof_status_from_legacy
from tools.dosunit.proof_scope import ProofScope, admit_scope_status


@dataclass(frozen=True)
class Block:
    """Byte-backed VEX block and its ordered direct successor addresses."""

    address: int
    irsb: pyvex.IRSB
    successors: tuple[int, ...]


class CfgRefusal(ValueError):
    """A named unsupported proof boundary, never interpreted as equality."""


def static_next(irsb: pyvex.IRSB) -> int | None:
    """Resolve only constant copies through VEX temps/registers on fallthrough."""
    temps: dict[int, int | None] = {}
    registers: dict[int, int | None] = {}

    def value(expr: pyvex.expr.IRExpr) -> int | None:
        """Follow typed const/Get/RdTmp copies; arithmetic needs another proof."""
        if isinstance(expr, pyvex.expr.Const):
            return int(expr.con.value)
        if isinstance(expr, pyvex.expr.RdTmp):
            return temps.get(expr.tmp)
        if isinstance(expr, pyvex.expr.Get):
            return registers.get(expr.offset)
        return None

    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.WrTmp):
            temps[statement.tmp] = value(statement.data)
        elif isinstance(statement, pyvex.stmt.Put):
            registers[statement.offset] = value(statement.data)
    return value(irsb.next)


def direct_successors(irsb: pyvex.IRSB) -> tuple[int, ...]:
    """Read typed VEX edges, refusing exception exits and indirect transfers."""
    if irsb.jumpkind not in {"Ijk_Boring", "Ijk_Ret"}:
        raise CfgRefusal("call_or_exception_boundary")
    exits = [statement for statement in irsb.statements if isinstance(statement, pyvex.stmt.Exit)]
    if any(statement.jumpkind != "Ijk_Boring" for statement in exits):
        raise CfgRefusal("exception_edge")
    seen_exit = False
    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.Exit):
            seen_exit = True
        elif (
            seen_exit
            and statement.tag not in {"Ist_IMark", "Ist_WrTmp", "Ist_NoOp"}
            and (not isinstance(statement, pyvex.stmt.Put) or statement.offset != ARCH.ip_offset)
        ):
            raise CfgRefusal("effect_after_conditional_exit")
    if irsb.jumpkind == "Ijk_Ret":
        if exits:
            raise CfgRefusal("conditional_return_block")
        return ()
    fallthrough = static_next(irsb)
    if fallthrough is None:
        raise CfgRefusal("indirect_jump")
    return tuple([int(statement.dst.value) for statement in exits] + [fallthrough])


def discover(project: angr.Project, start: int, size: int, max_blocks: int) -> dict[int, Block]:
    """Close the reachable CFG inside declared bounds without following callees."""
    pending = deque([start])
    blocks: dict[int, Block] = {}
    while pending:
        address = pending.popleft()
        if address in blocks:
            continue
        if not start <= address < start + size:
            raise CfgRefusal("edge_outside_declared_function")
        if len(blocks) >= max_blocks:
            raise CfgRefusal("block_limit")
        try:
            irsb = lift_cfg_block(project, address, start + size - address)
        except CfgLiftingRefusal as error:
            raise CfgRefusal(error.reason.value) from error
        from tools.dosunit.binary_environment import requires_environment_contract

        if requires_environment_contract(irsb):
            raise CfgRefusal("external_environment_contract_required")
        if not isinstance(irsb, pyvex.IRSB):
            raise CfgRefusal("non_vex_lifter")
        successors = direct_successors(irsb)
        blocks[address] = Block(address, irsb, successors)
        pending.extend(successors)
    return blocks


def pair_graphs(
    oracle: dict[int, Block], candidate: dict[int, Block], oracle_start: int, candidate_start: int
) -> list[tuple[int, int]]:
    """Construct and validate a successor-order-preserving graph bijection."""
    pending = deque([(oracle_start, candidate_start)])
    forward: dict[int, int] = {}
    backward: dict[int, int] = {}
    pairs: list[tuple[int, int]] = []
    while pending:
        left, right = pending.popleft()
        if left in forward:
            if forward[left] != right:
                raise CfgRefusal("cfg_not_bijective")
            continue
        if right in backward:
            raise CfgRefusal("cfg_not_bijective")
        oblock, cblock = oracle[left], candidate[right]
        if oblock.irsb.jumpkind != cblock.irsb.jumpkind or len(oblock.successors) != len(cblock.successors):
            raise CfgRefusal("cfg_shape_mismatch")
        forward[left], backward[right] = right, left
        pairs.append((left, right))
        pending.extend(zip(oblock.successors, cblock.successors, strict=True))
    if len(pairs) != len(oracle) or len(pairs) != len(candidate):
        raise CfgRefusal("cfg_not_closed")
    return pairs


def lower_blocks(
    blocks: dict[int, Block], addresses: list[int], module: str, outputs: tuple[str, ...]
) -> dict[str, Any]:
    """Keep full state on internal edges and stable canonical 32-bit edge tokens."""
    targets = {address: index for index, address in enumerate(addresses)}
    functions: list[dict[str, Any]] = []
    with installed(targets):
        for index, address in enumerate(addresses):
            block = blocks[address]
            observed = outputs if block.irsb.jumpkind == "Ijk_Ret" else tuple(name for name, _ in REG32.values())
            body = S._lower_irsb(block.irsb, output_regs=observed, max_assignments_per_function=4096)
            if isinstance(body, S.LowerFailure):
                raise CfgRefusal(f"{body.reason}: {body.message}")
            name = f"block_{index}"
            functions.append(
                {
                    "id": f"{module}:{name}",
                    "function": {"id": f"{module}:{name}", "name": name},
                    "part": {"kind": "block", "index": 0, "entry_delta": "0x0"},
                    "entry": {"linear": hex(address)},
                    "function_entry": {"linear": hex(address)},
                    "source": {"jumpkind": block.irsb.jumpkind, "machine_code_size": block.irsb.size},
                    **body,
                }
            )
    return {"functions": functions}


def compare_cfg(
    oracle: angr.Project,
    candidate: angr.Project,
    *,
    name: str,
    oracle_range: tuple[int, int],
    candidate_range: tuple[int, int],
    outputs: tuple[str, ...],
    timeout_ms: int,
    max_blocks: int = 128,
    normalization: dict[int, int] | None = None,
) -> dict[str, Any]:
    """Prove matching CFGs including loops by checking every inductive edge relation."""
    outputs = tuple(dict.fromkeys((*outputs, *OUTPUT_REGS[2:])))
    try:
        oblocks = discover(oracle, *oracle_range, max_blocks)
        cblocks = discover(candidate, *candidate_range, max_blocks)
        pairs = pair_graphs(oblocks, cblocks, oracle_range[0], candidate_range[0])
        ossa = lower_blocks(oblocks, [left for left, _ in pairs], "oracle", outputs)
        cssa = lower_blocks(cblocks, [right for _, right in pairs], "candidate", outputs)
    except CfgRefusal as error:
        return {"function": {"name": name}, "status": Status.REFUSED, "reason": str(error)}
    if normalization:
        for function in cssa["functions"]:
            function["_constant_normalization"] = normalization
            function["_constant_normalization_reasons"] = dict.fromkeys(normalization, "global_reloc")
    with installed():
        compared = S.compare_ssa_documents(
            oracle=ossa,
            candidate=cssa,
            mapping_document=mapping("oracle", "candidate", [f"block_{i}" for i in range(len(pairs))]),
            timeout_ms=timeout_ms,
            max_solver_assignments=4096,
            max_solver_inputs=64,
            max_solver_memory_stores=256,
            skip_binary_equal=False,
            allow_aliased_call_targets=False,
            enable_callee_lemmas=False,
            enable_region_equality=False,
            enable_connectivity=False,
        )
    expected = {f"block_{i}": f"oracle:block_{i}" for i in range(len(pairs))}
    verdicts = checked_results(expected, compared, relocation=normalization)
    backend_status = aggregate(verdicts)
    admitted = admit_scope_status(proof_status_from_legacy(backend_status) or ProofStatus.UNKNOWN,
                                 ProofScope.CUTPOINT_SIMULATION)
    status = Status(legacy_status_for(admitted))
    return {
        "function": {"name": name},
        "status": status,
        "reason": "matched_cfg_induction",
        "proof_scope": ProofScope.CUTPOINT_SIMULATION,
        "backend_status": backend_status,
        "block_pairs": [[hex(left), hex(right)] for left, right in pairs],
        "oracle_ssa": ossa,
        "candidate_ssa": cssa,
        "block_compare": compared,
        "block_verdicts": verdicts,
    }

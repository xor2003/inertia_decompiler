"""Layer: validation CFG adapter.

Responsibility: prove closed, bijectively matched i386 CFGs by block induction.
Every internal edge compares full modeled machine state and the entire memory
array. Returns compare the chosen ABI observables. Calls, faults, indirect
jumps and unmatched graphs refuse; loops are not bounded-unrolled into proofs.
"""

from __future__ import annotations

from typing import Any

import angr

from tools.comparator.catalog import mapping
from tools.comparator.cfg import (
    ARCH as ARCH,
)
from tools.comparator.cfg import (
    REG32 as REG32,
)
from tools.comparator.cfg import (
    Block as Block,
)
from tools.comparator.cfg import (
    CfgRefusal as CfgRefusal,
)
from tools.comparator.cfg import (
    direct_successors as direct_successors,
)
from tools.comparator.cfg import (
    discover as discover,
)
from tools.comparator.cfg import (
    lower_blocks as lower_blocks,
)
from tools.comparator.cfg import (
    pair_graphs as pair_graphs,
)
from tools.comparator.cfg import (
    static_next as static_next,
)
from tools.comparator.native import OUTPUT_REGS, S
from tools.comparator.verdict import Status, aggregate, checked_results
from tools.dosunit.contracts.comparison import EXPLICIT_COMPARISON_POLICY
from tools.dosunit.contracts.proof_contracts import ProofStatus, legacy_status_for, proof_status_from_legacy
from tools.dosunit.contracts.proof_scope import ProofScope, admit_scope_status


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
        comparison_policy=EXPLICIT_COMPARISON_POLICY,
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

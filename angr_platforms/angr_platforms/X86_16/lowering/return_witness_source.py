"""Verify source identity before grouping multiple SSA reads as one witness.

Layer: Types/Lowering.
Responsibility: require distinct retained VEX statements for an instruction-level
return-use projection. Address equality alone cannot merge synthetic duplicates.
Consumes typed IR provenance; does not classify returns or mutate codegen.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from ..ir.ssa_function import SSAFunctionArtifact


def distinct_return_witness_sources_8616(
    artifact: SSAFunctionArtifact,
    candidates: tuple[tuple[int, int, int], ...],
) -> bool:
    """Require one exact, unique source statement per selected SSA operation."""
    sites = set(candidates)
    if not sites or len(sites) != len(candidates):
        return False
    origins: list[tuple[int, int]] = []
    for block in artifact.blocks:
        for index, instruction in enumerate(block.instrs):
            if (block.addr, index, instruction.addr) not in sites:
                continue
            origin = instruction.origin
            if origin is None:
                return False
            if (
                type(origin.block_addr) is not int
                or origin.block_addr != block.addr
                or type(origin.statement_index) is not int
                or origin.statement_index < 0
            ):
                return False
            origins.append((origin.block_addr, origin.statement_index))
    return len(origins) == len(candidates) and len(set(origins)) == len(origins)

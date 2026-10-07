"""Resolve carry flag definitions across exact function-SSA CFG paths.

Layer: Semantics.
Responsibility: prove that one register-flags definition reaches a carry chain
through a complete predecessor map and compatible phi inputs. This module does
not infer aliases, widen values, lower types, or inspect rendered text.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.ir.core import IRValue, MemSpace
from inertia.ir.ssa_function import SSAFunctionArtifact

from .carry_borrow_contracts import (
    CarryBorrowDefinitionSite8616,
    CarryBorrowFailure8616,
)
from .carry_borrow_ssa import CarryBorrowDefinitions8616, single_source_8616


@dataclass(frozen=True, slots=True)
class CarryBorrowBlockSSA8616:
    """Exact carry-relevant definitions retained for one SSA block."""

    block_addr: int
    sites: tuple[CarryBorrowDefinitionSite8616, ...]
    definitions: CarryBorrowDefinitions8616


@dataclass(frozen=True, slots=True)
class CarryBorrowFlagsDefinition8616:
    """One flags definition and the block-local SSA context that owns it."""

    site: CarryBorrowDefinitionSite8616
    block: CarryBorrowBlockSSA8616


@dataclass(frozen=True, slots=True)
class CarryBorrowFlagsResolution8616:
    """A dominating flags definition or a typed CFG/phi refusal."""

    definition: CarryBorrowFlagsDefinition8616 | None = None
    failure: CarryBorrowFailure8616 | None = None


def build_carry_borrow_block_ssa_8616(
    artifact: SSAFunctionArtifact,
) -> tuple[CarryBorrowBlockSSA8616, ...]:
    """Build deterministic block-local temporary definition contexts."""
    blocks: list[CarryBorrowBlockSSA8616] = []
    for block in sorted(artifact.blocks, key=lambda item: item.addr):
        sites = tuple(
            CarryBorrowDefinitionSite8616(block.addr, index, instruction)
            for index, instruction in enumerate(block.instrs)
        )
        definitions = {
            site.instruction.dst.source_tmp: site
            for site in sites
            if site.instruction.dst is not None and site.instruction.dst.source_tmp is not None
        }
        blocks.append(CarryBorrowBlockSSA8616(block.addr, sites, definitions))
    return tuple(blocks)


def _register_identity(value: IRValue) -> tuple[MemSpace, str | None, int, int | None]:
    return (value.space, value.name, value.size, value.version)


def _same_register(lhs: IRValue, rhs: IRValue) -> bool:
    return (
        lhs.space is MemSpace.REG
        and rhs.space is MemSpace.REG
        and _register_identity(lhs) == _register_identity(rhs)
    )


def _dominators_8616(artifact: SSAFunctionArtifact) -> dict[int, frozenset[int]] | None:
    block_addrs = frozenset(block.addr for block in artifact.blocks)
    predecessors = artifact.predecessor_map
    if (
        artifact.function_addr not in block_addrs
        or frozenset(predecessors) != block_addrs
        or predecessors.get(artifact.function_addr) != ()
        or any(pred not in block_addrs for preds in predecessors.values() for pred in preds)
    ):
        return None
    all_blocks = frozenset(block_addrs)
    dominators: dict[int, frozenset[int]] = {
        addr: frozenset({addr}) if addr == artifact.function_addr else all_blocks
        for addr in block_addrs
    }
    changed = True
    while changed:
        changed = False
        for addr in sorted(block_addrs - {artifact.function_addr}):
            preds = predecessors[addr]
            if not preds:
                return None
            common = set(dominators[preds[0]])
            for pred in preds[1:]:
                common.intersection_update(dominators[pred])
            updated = frozenset({addr, *common})
            if updated != dominators[addr]:
                dominators[addr] = updated
                changed = True
    return dominators


def _direct_definition(
    value: IRValue,
    use_block_addr: int,
    blocks: tuple[CarryBorrowBlockSSA8616, ...],
    dominators: dict[int, frozenset[int]],
) -> CarryBorrowFlagsDefinition8616 | None:
    matches = tuple(
        CarryBorrowFlagsDefinition8616(site, block)
        for block in blocks
        if block.block_addr in dominators[use_block_addr]
        for site in block.sites
        if site.instruction.dst is not None
        and _same_register(site.instruction.dst, value)
        and site.instruction.dst.name == "flags"
    )
    return matches[0] if len(matches) == 1 else None


def _same_block_definition(
    flags_read: CarryBorrowDefinitionSite8616,
    block: CarryBorrowBlockSSA8616,
) -> CarryBorrowFlagsDefinition8616 | None:
    value = single_source_8616(flags_read)
    if value is None:
        return None
    matches = tuple(
        site
        for site in block.sites
        if site.instr_index < flags_read.instr_index
        and site.instruction.dst is not None
        and _same_register(site.instruction.dst, value)
        and site.instruction.dst.name == "flags"
    )
    return CarryBorrowFlagsDefinition8616(matches[0], block) if len(matches) == 1 else None


def resolve_carry_flags_definition_8616(
    artifact: SSAFunctionArtifact,
    flags_read: CarryBorrowDefinitionSite8616,
    use_block: CarryBorrowBlockSSA8616,
    blocks: tuple[CarryBorrowBlockSSA8616, ...],
) -> CarryBorrowFlagsResolution8616:
    """Resolve one exact same-block, dominating, or phi-carried flags definition."""
    same_block = _same_block_definition(flags_read, use_block)
    if same_block is not None:
        return CarryBorrowFlagsResolution8616(definition=same_block)
    flags_value = single_source_8616(flags_read)
    if flags_value is None:
        return CarryBorrowFlagsResolution8616(
            failure=CarryBorrowFailure8616.FLAGS_DEFINITION_MISSING
        )
    dominators = _dominators_8616(artifact)
    if dominators is None or use_block.block_addr not in dominators:
        return CarryBorrowFlagsResolution8616(
            failure=CarryBorrowFailure8616.CFG_PREDECESSOR_MISMATCH
        )
    phis = tuple(
        phi
        for phi in artifact.phi_nodes
        if phi.block_addr == use_block.block_addr and _same_register(phi.target, flags_value)
    )
    if len(phis) > 1:
        return CarryBorrowFlagsResolution8616(
            failure=CarryBorrowFailure8616.FLAGS_PHI_CONFLICT
        )
    if phis:
        phi = phis[0]
        expected_predecessors = artifact.predecessor_map[use_block.block_addr]
        if tuple(sorted(item.source_block_addr for item in phi.incoming)) != expected_predecessors:
            return CarryBorrowFlagsResolution8616(
                failure=CarryBorrowFailure8616.CFG_PREDECESSOR_MISMATCH
            )
        definitions = tuple(
            _direct_definition(item.value, item.source_block_addr, blocks, dominators)
            for item in phi.incoming
        )
        if not definitions or any(item is None for item in definitions):
            return CarryBorrowFlagsResolution8616(
                failure=CarryBorrowFailure8616.FLAGS_DEFINITION_MISSING
            )
        first = definitions[0]
        if first is None or any(item != first for item in definitions[1:]):
            return CarryBorrowFlagsResolution8616(
                failure=CarryBorrowFailure8616.FLAGS_PHI_CONFLICT
            )
        return CarryBorrowFlagsResolution8616(definition=first)
    definition = _direct_definition(flags_value, use_block.block_addr, blocks, dominators)
    if definition is None:
        return CarryBorrowFlagsResolution8616(
            failure=CarryBorrowFailure8616.FLAGS_DEFINITION_MISSING
        )
    return CarryBorrowFlagsResolution8616(definition=definition)


__all__ = [
    "CarryBorrowBlockSSA8616",
    "CarryBorrowFlagsDefinition8616",
    "CarryBorrowFlagsResolution8616",
    "build_carry_borrow_block_ssa_8616",
    "resolve_carry_flags_definition_8616",
]

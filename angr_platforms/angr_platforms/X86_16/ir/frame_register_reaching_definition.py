"""Retain one exact BP definition across the supplied function SSA graph.

Layer: IR.
Responsibility: bind a bare word BP read to the same defining instruction on
every supplied predecessor path, consuming explicit Semantics CALL preservation.
This bounded transport proof does not infer missing CFG edges, register effects,
frame coordinates, aliases, pointer types, or a compiler ABI. The upstream
function artifact remains responsible for its binary CFG census.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..arch_86_16 import Arch86_16
from .core import IRValue, MemSpace
from .indexed_address_contracts import IndexedAddressDefinitionSite8616
from .scalar_affine_contracts import (
    ScalarAffineEntryRegister8616,
    ScalarAffineFailure8616,
    ScalarAffineTraceStats8616,
)
from .scalar_definitions import ScalarDefinition8616, scalar_definition_key_8616
from .ssa import SSABlock
from .ssa_function import SSAFunctionArtifact

_FRAME_FAMILIES = {
    name: frozenset({register.name, *(view for view, _offset, _size in register.subregisters)})
    for name in ("bp", "sp") for register in Arch86_16.register_list
    if name in {register.name, *(view for view, _offset, _size in register.subregisters)}
}
_BP_FAMILY = _FRAME_FAMILIES["bp"]


def frame_register_family_8616(register: str) -> frozenset[str]:
    """Derive frame-register overlap names from the authoritative architecture."""
    return _FRAME_FAMILIES.get(register, frozenset())


@dataclass(frozen=True, slots=True)
class FrameRegisterDefinitionTrace8616:
    """Exact reaching BP definition, entry leaf, or closed atomic refusal."""

    definition: ScalarDefinition8616 | None
    preservation_sites: tuple[IndexedAddressDefinitionSite8616, ...]
    failure: ScalarAffineFailure8616 | None
    stats: ScalarAffineTraceStats8616
    entry_register: ScalarAffineEntryRegister8616 | None = None

    @property
    def complete(self) -> bool:
        """Require one retained result and exact preservation-site identities."""
        source_complete = (
            self.definition.complete if self.definition is not None and self.entry_register is None
            else self.definition is None and self.entry_register is not None
            and self.entry_register.complete and self.entry_register.register_name == "bp"
        )
        return bool(source_complete and self.failure is None and self.stats.complete and all(
            site.complete for site in self.preservation_sites
        ))


@dataclass(slots=True)
class _ReachingEvidence8616:
    """Finite graph-walk state retaining every observed source and CALL."""

    definitions: dict[tuple[int, int], ScalarDefinition8616] = field(default_factory=dict)
    calls: dict[tuple[int, int], IndexedAddressDefinitionSite8616] = field(default_factory=dict)
    entry_leaf: bool = False


def is_bare_word_bp_read_8616(value: IRValue) -> bool:
    """Return whether a read names current BP rather than an immutable capture."""
    return bool(
        value.space is MemSpace.REG and value.name == "bp" and value.size == 2
        and isinstance(value.version, int) and not isinstance(value.version, bool)
        and value.version >= 0 and value.offset == 0 and not value.expr
        and value.source_tmp is None and value.const is None and value.index is None
        and value.index_shift == 0 and value.call_output is None
        and value.memory_access_size is None
    )


def _refuse_8616(failure: ScalarAffineFailure8616) -> FrameRegisterDefinitionTrace8616:
    """Retain one refused transport obligation without a partial definition."""
    return FrameRegisterDefinitionTrace8616(None, (), failure, ScalarAffineTraceStats8616(1, 1, 1, 0, 1))


def _scan_prefix_8616(
    block: SSABlock, limit: int, evidence: _ReachingEvidence8616,
) -> tuple[bool, ScalarAffineFailure8616 | None]:
    """Scan backwards until a BP definition or the predecessor boundary."""
    for index in range(limit - 1, -1, -1):
        instruction = block.instrs[index]
        if instruction.op == "CALL":
            effect = instruction.call_stack_effect
            if instruction.addr is None or effect is None or not (effect.complete and effect.bp_preserved):
                return False, ScalarAffineFailure8616.SOURCE_UNPROVEN
            evidence.calls[(block.addr, index)] = IndexedAddressDefinitionSite8616(
                block.addr, index, instruction.addr, instruction.op,
            )
            continue
        destination = instruction.dst
        if destination is None or destination.space is not MemSpace.REG or destination.name not in _BP_FAMILY:
            continue
        if not is_bare_word_bp_read_8616(destination) or instruction.size != 2 or instruction.addr is None:
            return False, ScalarAffineFailure8616.WIDTH_CONFLICT
        evidence.definitions[(block.addr, index)] = ScalarDefinition8616(block.addr, index, instruction)
        return True, None
    return False, None


def _walk_predecessors_8616(
    artifact: SSAFunctionArtifact, blocks: dict[int, SSABlock],
    block_addr: int, before_index: int, evidence: _ReachingEvidence8616,
) -> ScalarAffineFailure8616 | None:
    """Close the finite backward slice, including preserving loop edges."""
    pending = [(block_addr, before_index)]
    visited: set[tuple[int, int]] = set()
    while pending:
        address, limit = pending.pop()
        if (address, limit) in visited:
            continue
        visited.add((address, limit))
        found, failure = _scan_prefix_8616(blocks[address], limit, evidence)
        if failure is not None:
            return failure
        if found:
            continue
        predecessors = artifact.predecessor_map[address]
        if address == artifact.function_addr:
            if address != block_addr or predecessors:
                return ScalarAffineFailure8616.SOURCE_UNPROVEN
            evidence.entry_leaf = True
        elif not predecessors:
            return ScalarAffineFailure8616.SOURCE_UNPROVEN
        pending.extend((pred, len(blocks[pred].instrs)) for pred in reversed(predecessors))
    return None


def _graph_blocks_8616(artifact: SSAFunctionArtifact, block_addr: int) -> dict[int, SSABlock] | None:
    """Validate supplied predecessor identities and refuse incomplete blocks."""
    blocks = {block.addr: block for block in artifact.blocks}
    if (len(blocks) != len(artifact.blocks) or artifact.function_addr not in blocks
            or block_addr not in blocks or set(artifact.predecessor_map) != set(blocks)):
        return None
    if any(block.refusals for block in artifact.blocks) or any(
        pred not in blocks for preds in artifact.predecessor_map.values() for pred in preds
    ):
        return None
    return blocks


def _local_definition_trace_8616(
    block: SSABlock, value: IRValue, before_index: int,
    entry_register: ScalarAffineEntryRegister8616 | None,
) -> FrameRegisterDefinitionTrace8616 | None:
    """Retain local definitions without inventing a whole-function CFG claim."""
    evidence = _ReachingEvidence8616()
    found, failure = _scan_prefix_8616(block, before_index, evidence)
    if failure is not None:
        return _refuse_8616(failure)
    if found:
        return _finish_trace_8616(evidence, value, block.addr)
    if entry_register is None:
        return None
    if value.version != 0:
        return _refuse_8616(ScalarAffineFailure8616.DEFINITION_CONFLICT)
    return FrameRegisterDefinitionTrace8616(
        None, tuple(evidence.calls[key] for key in sorted(evidence.calls)), None,
        ScalarAffineTraceStats8616(1, 1, 1, 1, 0), entry_register,
    )


def _finish_trace_8616(
    evidence: _ReachingEvidence8616, value: IRValue, block_addr: int,
) -> FrameRegisterDefinitionTrace8616:
    """Publish only a unique definition with coherent local SSA identity."""
    if len(evidence.definitions) > 1 or (evidence.definitions and evidence.entry_leaf):
        return _refuse_8616(ScalarAffineFailure8616.DEFINITION_CONFLICT)
    definition = next(iter(evidence.definitions.values()), None)
    if definition is None and not evidence.entry_leaf:
        return _refuse_8616(ScalarAffineFailure8616.DEFINITION_MISSING)
    if definition is None and value.version != 0:
        return _refuse_8616(ScalarAffineFailure8616.DEFINITION_CONFLICT)
    if definition is not None:
        destination = definition.instruction.dst
        assert destination is not None
        if definition.block_addr == block_addr and scalar_definition_key_8616(value) != scalar_definition_key_8616(destination):
            return _refuse_8616(ScalarAffineFailure8616.DEFINITION_CONFLICT)
        if definition.block_addr != block_addr and value.version != 0:
            return _refuse_8616(ScalarAffineFailure8616.DEFINITION_CONFLICT)
    return FrameRegisterDefinitionTrace8616(
        definition, tuple(evidence.calls[key] for key in sorted(evidence.calls)), None,
        ScalarAffineTraceStats8616(1, 1, 1, 1, 0),
    )


def resolve_bp_reaching_definition_8616(
    artifact: SSAFunctionArtifact, value: IRValue, *, block_addr: int, before_index: int,
) -> FrameRegisterDefinitionTrace8616:
    """Prove one exact BP origin on every supplied incoming path.

    Distinct definitions refuse even when their shapes happen to match. Calls
    without explicit BP preservation refuse even if their SSA destination is
    absent. Cycles close only when the whole slice reaches a unique definition;
    an entry-register leaf is admitted solely in the actual entry block.
    """
    if not is_bare_word_bp_read_8616(value):
        return _refuse_8616(ScalarAffineFailure8616.ROOT_UNPROVEN)
    candidates = tuple(block for block in artifact.blocks if block.addr == block_addr)
    if len(candidates) != 1 or candidates[0].refusals:
        return _refuse_8616(ScalarAffineFailure8616.SOURCE_UNPROVEN)
    if not 0 <= before_index <= len(candidates[0].instrs):
        return _refuse_8616(ScalarAffineFailure8616.ROOT_UNPROVEN)
    entry_register = (
        ScalarAffineEntryRegister8616(artifact.function_addr, "bp", 2)
        if block_addr == artifact.function_addr and artifact.predecessor_map.get(block_addr) == ()
        else None
    )
    local = _local_definition_trace_8616(candidates[0], value, before_index, entry_register)
    if local is not None:
        return local
    blocks = _graph_blocks_8616(artifact, block_addr)
    if blocks is None:
        return _refuse_8616(ScalarAffineFailure8616.SOURCE_UNPROVEN)
    if not 0 <= before_index <= len(blocks[block_addr].instrs):
        return _refuse_8616(ScalarAffineFailure8616.ROOT_UNPROVEN)
    evidence = _ReachingEvidence8616()
    failure = _walk_predecessors_8616(artifact, blocks, block_addr, before_index, evidence)
    return _refuse_8616(failure) if failure is not None else _finish_trace_8616(evidence, value, block_addr)


__all__ = [
    "FrameRegisterDefinitionTrace8616", "frame_register_family_8616",
    "is_bare_word_bp_read_8616", "resolve_bp_reaching_definition_8616",
]

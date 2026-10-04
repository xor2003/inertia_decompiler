"""Check every raw STORE during an indexed induction lifetime.

Layer: IR.
Responsibility: refuse unaccounted induction mutations, including byte lanes
and unclassified expressions, before a loop-range candidate materializes.
Logical segment names alone do not prove physical disjointness. This owner
does not infer aliases, invent call effects, or modify generated code.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from ..semantics.register_value_preservation import register_value_family_8616
from .core import AddressStatus, IRAddress, IRInstr, MemSpace, SegmentOrigin
from .indexed_address_range_witnesses import IndexedInductionSourceIdentity8616
from .logical_memory_contracts import IRMemoryExecutionSlice8616
from .logical_memory_write_value import LogicalWordWriteValueFact8616
from .scalar_instruction_effects import ScalarInstructionEffectKind8616, scalar_instruction_effect_8616
from .ssa_function import SSAFunctionArtifact

# A wide EBP write changes the low BP word just as surely as a BP write.
# Register overlap is architectural evidence, not a spelling convention.
_FRAME_STORAGE_FAMILY: frozenset[str] = (
    register_value_family_8616("bp") | register_value_family_8616("ss")
)


class IndexedInductionEffectVerdict8616(StrEnum):
    """Exact raw-effect classification; unknown effects remain refused."""

    ACCOUNTED = "accounted"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class IndexedInductionEffect8616:
    """Retain the raw instruction and its exact lifetime census site."""

    block_addr: int
    instr_index: int
    instruction: IRInstr
    verdict: IndexedInductionEffectVerdict8616


@dataclass(frozen=True, slots=True)
class IndexedInductionWriteCensus8616:
    """Closed raw-effect accounting, not a caller-bound address-range proof."""

    induction_source: IndexedInductionSourceIdentity8616
    expected_lanes: tuple[IRMemoryExecutionSlice8616, ...]
    raw_sites: tuple[tuple[int, int], ...]
    effects: tuple[IndexedInductionEffect8616, ...]
    region: tuple[int, ...]
    checked_blocks: tuple[int, ...]
    refused_blocks: tuple[int, ...]
    header: int
    loop_blocks: tuple[int, ...]
    initializer_block: int
    initializer_dominates_header: bool
    function_addr: int

    @property
    def raw_fact_count(self) -> int:
        """Count every retained raw instruction in the induction lifetime."""
        return len(self.raw_sites)

    @property
    def normalized_fact_count(self) -> int:
        """Normalization preserves every exact raw instruction site."""
        return len(self.effects)

    @property
    def classified_fact_count(self) -> int:
        """Count effects whose disposition was explicitly classified."""
        return len(self.effects)

    @property
    def materialized_count(self) -> int:
        """Count effects proven to preserve the exact induction storage."""
        return sum(effect.verdict is IndexedInductionEffectVerdict8616.ACCOUNTED
                   for effect in self.effects)

    @property
    def failure_count(self) -> int:
        """Keep every refused effect visible in the original denominator."""
        return self.raw_fact_count - self.materialized_count

    @property
    def complete(self) -> bool:
        """Recheck retained effect classifications and expected write sites."""
        expected = {(lane.block_addr, lane.instr_index): lane for lane in self.expected_lanes}
        sites = {(effect.block_addr, effect.instr_index) for effect in self.effects}
        if self.refused_blocks or self.region != self.checked_blocks:
            return False
        if not self.initializer_dominates_header or self.header not in self.loop_blocks:
            return False
        if not expected or len(sites) != len(self.effects) or not set(expected) <= sites:
            return False
        if sites != set(self.raw_sites) or len(sites) != self.raw_fact_count:
            return False
        return self.failure_count == 0 and all(
            _instruction_accounted_8616(
                effect.instruction, (effect.block_addr, effect.instr_index),
                expected, self.induction_source,
            ) for effect in self.effects
        )

    def matches_lifetime(
        self, function_addr: int, identity: IndexedInductionSourceIdentity8616,
        init_write: LogicalWordWriteValueFact8616,
        step_write: LogicalWordWriteValueFact8616,
        loop_blocks: tuple[int, ...], header: int,
    ) -> bool:
        """Bind this census to the exact induction, byte writes and loop."""
        expected = tuple(lane.execution_slice for write in (init_write, step_write)
                         for lane in write.lanes)
        return (
            self.complete and self.induction_source == identity
            and self.function_addr == function_addr
            and init_write.access.key.function_addr == function_addr
            and step_write.access.key.function_addr == function_addr
            and self.expected_lanes == expected and self.header == header
            and self.loop_blocks == loop_blocks
            and self.initializer_block == init_write.access.key.block_addr
            and {self.initializer_block, *loop_blocks} <= set(self.region)
        )


def _same_pre_ssa_lane_8616(raw: IRAddress, logical: IRAddress) -> bool:
    """Bind retained pre-SSA lanes across only the owner's earned renaming.

    Logical execution slices precede SSA version assignment. Preserve all
    address decorations and VEX temporary identity; erase only new versions.
    """
    if len(raw.base_values) != len(logical.base_values):
        return False
    temporary_identity = all(
        left.source_tmp == right.source_tmp
        and left.memory_access_insn == right.memory_access_insn
        for left, right in zip(raw.base_values, logical.base_values, strict=True)
    )
    original = replace(raw, version=None, base_values=tuple(
        replace(value, version=None) for value in raw.base_values
    ))
    return temporary_identity and original == logical


def _disjoint_stack_bytes_8616(
    address: IRAddress, identity: IndexedInductionSourceIdentity8616,
) -> bool:
    """Prove separation only for exact offsets in the same BP stack frame."""
    canonical = (
        address.space is MemSpace.SS and address.base == ("bp",)
        and address.status is AddressStatus.STABLE
        and address.segment_origin is SegmentOrigin.PROVEN
    )
    if address.expr is not None and address.expr != ("segmented_linear", "ss", "bp"):
        return False
    if not canonical or type(address.offset) is not int or not 0 < address.size <= 65536:
        return False
    source_bytes = {(identity.offset + offset) & 0xFFFF for offset in range(identity.width)}
    return all((address.offset + offset) & 0xFFFF not in source_bytes
               for offset in range(address.size))


def _initialization_region_8616(
    artifact: SSAFunctionArtifact, loop_blocks: tuple[int, ...],
    header: int, initializer: int,
) -> set[int]:
    """Retain every preheader path back to the dominating initializer."""
    region = {initializer, *loop_blocks}
    pending = list(artifact.predecessor_map[header])
    while pending:
        node = pending.pop()
        if node in region:
            continue
        region.add(node)
        pending.extend(artifact.predecessor_map[node])
    return region


def _instruction_accounted_8616(
    instruction: IRInstr, site: tuple[int, int],
    expected: dict[tuple[int, int], IRMemoryExecutionSlice8616],
    identity: IndexedInductionSourceIdentity8616,
) -> bool:
    """Bind one expected STORE or prove its effect cannot mutate induction."""
    frame_changed = (instruction.dst is not None and instruction.dst.space is MemSpace.REG
                     and instruction.dst.name in _FRAME_STORAGE_FAMILY)
    if instruction.op == "CALL" or frame_changed:
        return False
    if instruction.op != "STORE":
        effect = scalar_instruction_effect_8616(instruction)
        return site not in expected and effect.kind is not ScalarInstructionEffectKind8616.UNKNOWN
    address = instruction.args[0] if instruction.args else None
    if not isinstance(address, IRAddress):
        return False
    lane = expected.get(site)
    if lane is None:
        return _disjoint_stack_bytes_8616(address, identity)
    return instruction.addr == lane.insn_addr and _same_pre_ssa_lane_8616(address, lane.address)


def collect_indexed_induction_write_census_8616(
    artifact: SSAFunctionArtifact,
    identity: IndexedInductionSourceIdentity8616,
    loop_blocks: tuple[int, ...],
    header: int,
    init_write: LogicalWordWriteValueFact8616,
    step_write: LogicalWordWriteValueFact8616,
    *, initializer_dominates_header: bool,
) -> IndexedInductionWriteCensus8616:
    """Check raw effects, not just successfully classified logical word writes.

    Every preheader path after initialization and every loop block is checked.
    Only the exact proven initializer/increment byte slices may mutate the
    induction storage. Unknown calls, frame changes and cross-selector stores
    require additional proof and are refused here rather than guessed safe.
    """
    expected = {
        (lane.execution_slice.block_addr, lane.execution_slice.instr_index): lane.execution_slice
        for write in (init_write, step_write) for lane in write.lanes
    }
    init_block = init_write.access.key.block_addr
    init_start = min(lane.execution_slice.instr_index for lane in init_write.lanes)
    region = _initialization_region_8616(artifact, loop_blocks, header, init_block)
    effects: list[IndexedInductionEffect8616] = []
    checked_blocks: list[int] = []
    refused_blocks: list[int] = []
    for block in artifact.blocks:
        if block.addr not in region:
            continue
        checked_blocks.append(block.addr)
        if block.refusals:
            refused_blocks.append(block.addr)
        for index, instruction in enumerate(block.instrs):
            if block.addr == init_block and index < init_start:
                continue
            site = (block.addr, index)
            accounted = _instruction_accounted_8616(instruction, site, expected, identity)
            verdict = (IndexedInductionEffectVerdict8616.ACCOUNTED if accounted
                       else IndexedInductionEffectVerdict8616.REFUSED)
            effects.append(IndexedInductionEffect8616(block.addr, index, instruction, verdict))
    return IndexedInductionWriteCensus8616(
        identity, tuple(expected.values()),
        tuple((effect.block_addr, effect.instr_index) for effect in effects),
        tuple(effects), tuple(sorted(region)),
        tuple(sorted(checked_blocks)), tuple(sorted(refused_blocks)),
        header, loop_blocks, init_block, initializer_dominates_header,
        artifact.function_addr,
    )

"""Typed fixtures for indexed global-object range tests."""

from __future__ import annotations

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.indexed_address_contracts import (
    IndexedAddressAccessKind8616,
    IndexedAddressDefinitionSite8616,
    IndexedAddressEvidence8616,
    IndexedAddressFact8616,
    IndexedAddressStats8616,
)
from inertia.ir.indexed_address_range_contracts import (
    IndexedLoopGuardPolarity8616,
    IndexedLoopGuardRelation8616,
    IndexedLoopGuardWitness8616,
    IndexedLoopProofSite8616,
    IndexedLoopRangeCandidate8616,
    IndexedNaturalLoopWitness8616,
    canonical_induction_source_identity_8616,
)
from inertia.ir.indexed_address_range_evidence import (
    collect_indexed_loop_range_evidence_8616,
)
from inertia.ir.indexed_induction_write_census import (
    IndexedInductionEffect8616,
    IndexedInductionEffectVerdict8616,
    IndexedInductionWriteCensus8616,
)
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
)
from inertia.ir.logical_memory_value_trace import (
    LogicalMemoryValueTrace8616,
)
from inertia.ir.logical_memory_write_value import (
    LogicalWordWriteLaneProof8616,
    LogicalWordWriteValueFact8616,
    LogicalWordWriteValueKind8616,
)

from inertia.alias.indexed_address_access_classification import (
    classify_indexed_alias_accesses_8616,
)
from inertia.alias.indexed_address_access_contracts import (
    IndexedAliasAccessEvidence8616,
)
from inertia.alias.indexed_address_copy_contracts import (
    IndexedAliasCopyFact8616,
)
from inertia.alias.indexed_address_projection import (
    project_indexed_address_aliases_8616,
)
from inertia.alias.indexed_address_range_contracts import (
    IndexedAliasLoopRangeEvidence8616,
)
from inertia.alias.indexed_address_range_projection import (
    project_indexed_loop_ranges_to_alias_8616,
)
from inertia.widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)
from inertia.widening.indexed_global_object_range_recovery import (
    recover_bounded_global_object_ranges_8616,
)
from inertia.widening.indexed_global_object_ranges import (
    BoundedGlobalObjectRangeEvidence8616,
)

FUNCTION_ADDR = 0x100
LOOP_HEADER = 0x110
LOOP_LATCH = 0x120


def _logical_write_8616(
    address: IRAddress,
    block_addr: int,
    instr_index: int,
    instr_addr: int,
    kind: LogicalWordWriteValueKind8616,
) -> LogicalWordWriteValueFact8616:
    """Return one complete logical zero or increment write witness."""
    slices = tuple(
        IRMemoryExecutionSlice8616(
            block_addr,
            instr_index + offset,
            instr_addr,
            offset,
            IRAddress(
                address.space,
                address.base,
                address.offset + offset,
                1,
                address.status,
                address.segment_origin,
            ),
        )
        for offset in range(2)
    )
    access = IRLogicalMemoryAccess8616(
        IRLogicalMemoryAccessKey8616(FUNCTION_ADDR, block_addr, instr_addr, 0),
        IRMemoryAccessKind8616.WRITE,
        address,
        16,
        slices,
    )
    lanes = tuple(
        LogicalWordWriteLaneProof8616(
            execution_slice,
            IRValue(MemSpace.CONST, const=0, size=1),
            (
                IndexedAddressDefinitionSite8616(
                    block_addr,
                    execution_slice.instr_index,
                    instr_addr,
                    "MOV",
                ),
            ),
        )
        for execution_slice in slices
    )
    assert len(lanes) == 2
    if kind is LogicalWordWriteValueKind8616.CONSTANT_ZERO:
        return LogicalWordWriteValueFact8616(access, kind, 0, lanes)
    source_site = IndexedAddressDefinitionSite8616(
        block_addr,
        instr_index,
        instr_addr,
        "Iop_Or16",
    )
    source_trace = LogicalMemoryValueTrace8616(
        address,
        (
            IndexedAddressDefinitionSite8616(
                block_addr,
                instr_index,
                instr_addr,
                "LOAD",
            ),
        ),
        None,
    )
    return LogicalWordWriteValueFact8616(
        access,
        kind,
        1,
        lanes,
        source_site,
        source_trace,
    )


def indexed_fact_8616(
    base: int,
    instr_index: int,
    *,
    space: MemSpace = MemSpace.DS,
    width: int = 2,
    shift: int = 1,
    kind: IndexedAddressAccessKind8616 = IndexedAddressAccessKind8616.LOAD,
) -> IndexedAddressFact8616:
    """Return one exact synthetic indexed-address fact."""
    index = IRValue(MemSpace.REG, name="bx", size=2, version=1)
    source = IRAddress(
        MemSpace.SS,
        ("bp",),
        -2,
        2,
        AddressStatus.STABLE,
        SegmentOrigin.PROVEN,
    )
    instr_addr = LOOP_LATCH + instr_index
    return IndexedAddressFact8616(
        FUNCTION_ADDR,
        LOOP_LATCH,
        instr_index,
        instr_addr,
        kind,
        IRAddress(
            space,
            ("bx",),
            base,
            width,
            AddressStatus.STABLE,
            SegmentOrigin.PROVEN,
            base_values=(index,),
        ),
        index,
        source,
        shift,
        (
            IndexedAddressDefinitionSite8616(
                LOOP_LATCH,
                instr_index - 1,
                instr_addr - 1,
                "LOAD",
            ),
        ),
    )


def indexed_accesses_8616(
    *facts: IndexedAddressFact8616,
) -> IndexedAliasAccessEvidence8616:
    """Project synthetic indexed facts through the real Alias classifiers."""
    count = len(facts)
    source = IndexedAddressEvidence8616(
        FUNCTION_ADDR,
        facts,
        (),
        IndexedAddressStats8616(count, count, count, count, 0),
    )
    return classify_indexed_alias_accesses_8616(
        project_indexed_address_aliases_8616(source)
    )


def indexed_range_candidate_8616(
    fact: IndexedAddressFact8616,
    upper_bound: int = 4,
) -> IndexedLoopRangeCandidate8616:
    """Return one complete canonical constant-bound loop witness."""
    identity = canonical_induction_source_identity_8616(fact.index_source)
    assert identity is not None
    init_write = _logical_write_8616(
        fact.index_source,
        FUNCTION_ADDR,
        0,
        0x101,
        LogicalWordWriteValueKind8616.CONSTANT_ZERO,
    )
    step_write = _logical_write_8616(
        fact.index_source,
        LOOP_LATCH,
        40,
        0x148,
        LogicalWordWriteValueKind8616.OLD_LOGICAL_WORD_PLUS_ONE,
    )
    # These synthetic tests supply a closed two-write lifetime; binary-backed
    # tests independently cover producer discovery and unclassified effects.
    lanes = tuple(lane.execution_slice for write in (init_write, step_write)
                  for lane in write.lanes)
    effects = tuple(IndexedInductionEffect8616(
        lane.block_addr, lane.instr_index,
        IRInstr("STORE", None, (lane.address, IRValue(MemSpace.CONST, const=0, size=1)),
                size=1, addr=lane.insn_addr),
        IndexedInductionEffectVerdict8616.ACCOUNTED,
    ) for lane in lanes)
    region = (FUNCTION_ADDR, LOOP_HEADER, LOOP_LATCH)
    census = IndexedInductionWriteCensus8616(
        identity, lanes, tuple((effect.block_addr, effect.instr_index) for effect in effects),
        effects, region, region, (), LOOP_HEADER, (LOOP_HEADER, LOOP_LATCH),
        FUNCTION_ADDR, True, FUNCTION_ADDR,
    )
    return IndexedLoopRangeCandidate8616(
        fact,
        identity,
        0,
        1,
        upper_bound,
        True,
        IndexedLoopProofSite8616(0x100, 0, 0x101),
        IndexedLoopProofSite8616(LOOP_LATCH, 40, 0x148),
        IndexedLoopProofSite8616(LOOP_HEADER, 0, 0x111),
        IndexedLoopProofSite8616(
            fact.block_addr,
            fact.instr_index,
            fact.instr_addr,
        ),
        IndexedNaturalLoopWitness8616(
            LOOP_HEADER,
            LOOP_LATCH,
            (LOOP_HEADER, LOOP_LATCH),
            LOOP_LATCH,
            LOOP_HEADER,
            True,
            True,
            ((FUNCTION_ADDR, LOOP_HEADER),),
            ((LOOP_HEADER, 0x130),),
        ),
        IndexedLoopGuardWitness8616(
            IndexedLoopGuardRelation8616.UNSIGNED_LT,
            IndexedLoopGuardPolarity8616.CONTINUE_WHEN_TRUE,
            LOOP_HEADER,
            LOOP_LATCH,
            0x130,
            True,
            True,
            ConditionIR(
                "ult",
                IRValue(MemSpace.SS, offset=-2, size=2),
                IRValue(MemSpace.CONST, const=upper_bound, size=2),
                block_addr=LOOP_HEADER,
                src_insn=0x111,
                taken_target=LOOP_LATCH,
                fallthrough_target=0x130,
            ),
        ),
        init_write,
        step_write,
        census,
    )


def alias_ranges_8616(
    candidates: tuple[IndexedLoopRangeCandidate8616, ...],
    accesses: IndexedAliasAccessEvidence8616,
) -> IndexedAliasLoopRangeEvidence8616:
    """Project closed synthetic IR ranges through Alias."""
    ir_ranges = collect_indexed_loop_range_evidence_8616(
        FUNCTION_ADDR,
        candidates,
    )
    return project_indexed_loop_ranges_to_alias_8616(ir_ranges, accesses)


def widen_indexed_ranges_8616(
    facts: tuple[IndexedAddressFact8616, ...],
    candidates: tuple[IndexedLoopRangeCandidate8616, ...],
    copies: tuple[IndexedAliasCopyFact8616, ...] = (),
    layouts: GlobalObjectLayoutEvidence8616 | None = None,
) -> BoundedGlobalObjectRangeEvidence8616:
    """Run the real Alias-to-Widening path for one synthetic fixture."""
    accesses = indexed_accesses_8616(*facts)
    if layouts is None:
        materialized = tuple(
            dict.fromkeys(
                GlobalObjectLayout8616(
                    IRAddress(
                        fact.address.space,
                        offset=fact.address.offset,
                        size=fact.address.size,
                        status=AddressStatus.STABLE,
                        segment_origin=SegmentOrigin.PROVEN,
                    ),
                    fact.address.size,
                    tuple(range(fact.address.size)),
                    fact.address.offset,
                )
                for fact in facts
                if fact.address.space is MemSpace.DS
            )
        )
        count = len(materialized)
        layouts = GlobalObjectLayoutEvidence8616(
            materialized,
            count,
            count,
            count,
            count,
        )
    return recover_bounded_global_object_ranges_8616(
        alias_ranges_8616(candidates, accesses),
        layouts,
        copies,
    )


__all__ = [
    "FUNCTION_ADDR",
    "alias_ranges_8616",
    "indexed_accesses_8616",
    "indexed_fact_8616",
    "indexed_range_candidate_8616",
    "widen_indexed_ranges_8616",
]

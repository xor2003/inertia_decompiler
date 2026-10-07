from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CConstant
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.ir.segment_contract import (
    SegmentAccessFact,
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentFunctionContract,
)
from inertia.lowering.segment_access_policy import (
    SegmentAccessLoweringDecision8616,
    SegmentAccessLoweringResult8616,
    classify_codegen_segment_access_8616,
    classify_local_segment_access_8616,
)


class _Codegen:
    def __init__(self, contract: SegmentFunctionContract) -> None:
        self._idx = 0
        self.project = type("Project", (), {"arch": Arch86_16()})()
        self._inertia_segment_function_contract = contract

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _byte_fact(
    offset: int,
    *,
    instruction_addr: int = 0x1010,
    kind: SegmentAccessKind = SegmentAccessKind.READ,
    source: str | None = "ds",
    verdict: SegmentFactVerdict = SegmentFactVerdict.PROVEN,
    block_addr: int = 0x1000,
) -> SegmentAccessFact:
    return SegmentAccessFact(
        block_addr=block_addr,
        instruction_addr=instruction_addr,
        kind=kind,
        address=IRAddress(
            space=MemSpace.DS,
            base=("bx",),
            offset=offset,
            size=1,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
            expr=("segmented_linear", "ds", "bx"),
        ),
        segment_register="ds",
        physical_source=source,
        verdict=verdict,
    )


def _classify(
    *facts: SegmentAccessFact,
    instruction_addrs: frozenset[int] = frozenset({0x1010}),
    access_kind: SegmentAccessKind | None = None,
    offset: int | None = None,
) -> SegmentAccessLoweringResult8616:
    contract = SegmentFunctionContract(function_addr=0x1000, accesses=facts)
    return classify_local_segment_access_8616(
        contract,
        instruction_addrs=instruction_addrs,
        access_kind=access_kind,
        segment_register="ds",
        offset=offset,
        width=2,
    )


def test_segment_access_policy_joins_exact_proven_byte_pair() -> None:
    result = _classify(_byte_fact(0), _byte_fact(1))

    assert result.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert result.stats.raw_fact_count == 2
    assert result.stats.normalized_fact_count == 2
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_segment_access_policy_joins_unique_byte_pair_without_instruction_provenance() -> None:
    result = _classify(
        _byte_fact(68),
        _byte_fact(69),
        instruction_addrs=frozenset(),
        offset=68,
    )

    assert result.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert tuple(fact.address.offset for fact in result.facts) == (68, 69)


def test_segment_access_policy_refuses_ambiguous_byte_pairs_without_instruction_provenance() -> None:
    result = _classify(
        _byte_fact(68),
        _byte_fact(69),
        _byte_fact(68, instruction_addr=0x1020),
        _byte_fact(69, instruction_addr=0x1020),
        instruction_addrs=frozenset(),
        offset=68,
    )

    assert result.decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE
    assert result.stats.raw_fact_count == 4
    assert result.stats.normalized_fact_count == 0
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_segment_access_policy_refuses_incomplete_or_incoherent_byte_pair() -> None:
    cases = (
        (_byte_fact(0),),
        (_byte_fact(0), _byte_fact(1, source=None, verdict=SegmentFactVerdict.UNKNOWN_REFUSE)),
        (_byte_fact(0), _byte_fact(1, kind=SegmentAccessKind.WRITE)),
    )
    for facts in cases:
        assert _classify(*facts).decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE


def test_segment_access_policy_selects_read_from_rmw_byte_fragments() -> None:
    facts = (
        _byte_fact(0, kind=SegmentAccessKind.READ),
        _byte_fact(1, kind=SegmentAccessKind.READ),
        _byte_fact(0, kind=SegmentAccessKind.WRITE),
        _byte_fact(1, kind=SegmentAccessKind.WRITE),
    )

    ambiguous = _classify(*facts)
    read = _classify(*facts, access_kind=SegmentAccessKind.READ)
    write = _classify(*facts, access_kind=SegmentAccessKind.WRITE)

    assert ambiguous.decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE
    assert read.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert write.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert {fact.kind for fact in read.facts} == {SegmentAccessKind.READ}
    assert {fact.kind for fact in write.facts} == {SegmentAccessKind.WRITE}


def test_codegen_policy_uses_unique_access_in_jcc_owned_block() -> None:
    contract = SegmentFunctionContract(
        function_addr=0x1000,
        accesses=(_byte_fact(0x132), _byte_fact(0x133)),
    )
    codegen = _Codegen(contract)
    branch_owned = CConstant(
        0,
        SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x1015, "vex_block_addr": 0x1000},
    )

    result = classify_codegen_segment_access_8616(
        codegen,
        branch_owned,
        access_kind=SegmentAccessKind.READ,
        segment_register="ds",
        offset=0x132,
        width=2,
    )

    assert result.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert {fact.instruction_addr for fact in result.facts} == {0x1010}


def test_codegen_policy_refuses_ambiguous_accesses_in_jcc_owned_block() -> None:
    contract = SegmentFunctionContract(
        function_addr=0x1000,
        accesses=(
            _byte_fact(0x132),
            _byte_fact(0x133),
            _byte_fact(0x132, instruction_addr=0x1012),
            _byte_fact(0x133, instruction_addr=0x1012),
        ),
    )
    codegen = _Codegen(contract)
    branch_owned = CConstant(
        0,
        SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x1015, "vex_block_addr": 0x1000},
    )

    result = classify_codegen_segment_access_8616(
        codegen,
        branch_owned,
        access_kind=SegmentAccessKind.READ,
        segment_register="ds",
        offset=0x132,
        width=2,
    )

    assert result.decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE

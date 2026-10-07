from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    AddressStatus,
    IndexedAddressEvidence8616,
    IndexedAddressStats8616,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
    build_x86_16_function_ssa,
    build_x86_16_ir_function_artifact,
    collect_indexed_address_evidence_8616,
)
from inertia.lowering.indexed_address_collector_parity import (
    compare_indexed_address_collectors_8616,
)
from inertia.lowering.indexed_address_parity_inventory import (
    build_indexed_address_function_parity_report_8616,
    classify_indexed_address_mismatches_8616,
)
from inertia.lowering.indexed_address_parity_inventory_contracts import (
    IndexedAddressCollectorSide8616,
    IndexedAddressMismatchKind8616,
)
from inertia.lowering.segmented_global_loads import (
    IndexedSegmentedGlobalLoadSiteEvidence8616,
)

from inertia.alias.indexed_address_projection import (
    project_indexed_address_aliases_8616,
)

INDEXED_LOAD = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 8b 76 fe d1 e6 8b 84 00 02 c9 c3"
)


def _fixture() -> tuple[angr.Project, object]:
    project = angr.Project(
        io.BytesIO(INDEXED_LOAD),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    return project, SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})


def test_function_inventory_closes_for_exact_real_collectors() -> None:
    project, function = _fixture()

    report = build_indexed_address_function_parity_report_8616(project, function)

    assert report.closed
    assert report.exact
    assert report.mismatches == ()
    assert report.ir_stats.raw_fact_count == 2


def test_identity_conflict_is_classified_on_exact_instruction_site() -> None:
    project, function = _fixture()
    artifact = build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )
    alias_evidence = project_indexed_address_aliases_8616(
        collect_indexed_address_evidence_8616(artifact)
    )
    conflicting = IndexedSegmentedGlobalLoadSiteEvidence8616(
        base_offset=0x200,
        width=1,
        index_stack_offset=-2,
        index_shift=1,
        ins_addr=0x1010,
    )
    parity = compare_indexed_address_collectors_8616(
        alias_evidence,
        (conflicting,),
        (),
    )

    mismatches = classify_indexed_address_mismatches_8616(alias_evidence, parity)

    assert len(mismatches) == 2
    assert {mismatch.side for mismatch in mismatches} == {
        IndexedAddressCollectorSide8616.ALIAS,
        IndexedAddressCollectorSide8616.LEGACY,
    }
    assert all(
        mismatch.kind is IndexedAddressMismatchKind8616.IDENTITY_CONFLICT
        and mismatch.counterpart_keys
        and mismatch.complete
        for mismatch in mismatches
    )


def test_alias_only_key_without_legacy_candidate_is_explicit() -> None:
    project, function = _fixture()
    artifact = build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )
    alias_evidence = project_indexed_address_aliases_8616(
        collect_indexed_address_evidence_8616(artifact)
    )
    parity = compare_indexed_address_collectors_8616(alias_evidence, (), ())

    mismatches = classify_indexed_address_mismatches_8616(alias_evidence, parity)

    assert len(mismatches) == 1
    assert mismatches[0].side is IndexedAddressCollectorSide8616.ALIAS
    assert (
        mismatches[0].kind
        is IndexedAddressMismatchKind8616.ALIAS_ONLY_NO_LEGACY_CANDIDATE
    )
    assert mismatches[0].complete


def test_legacy_only_key_retains_matching_typed_ir_refusal() -> None:
    index = IRValue(MemSpace.REG, name="si", size=2, version=0)
    address = IRAddress(
        MemSpace.DS,
        base=("si",),
        offset=0x200,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(index,),
    )
    artifact = build_x86_16_function_ssa(
        IRFunctionArtifact(
            0x1000,
            (
                IRBlock(
                    0x1000,
                    (
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.TMP, name="t0", size=2),
                            (address,),
                            size=2,
                            addr=0x1000,
                        ),
                    ),
                ),
            ),
        )
    )
    ir_evidence = collect_indexed_address_evidence_8616(artifact)
    duplicated_ir_evidence = IndexedAddressEvidence8616(
        ir_evidence.function_addr,
        (),
        (ir_evidence.refusals[0], ir_evidence.refusals[0]),
        IndexedAddressStats8616(2, 2, 2, 0, 2),
    )
    alias_evidence = project_indexed_address_aliases_8616(
        duplicated_ir_evidence
    )
    legacy = IndexedSegmentedGlobalLoadSiteEvidence8616(
        base_offset=0x200,
        width=2,
        index_stack_offset=-2,
        index_shift=1,
        ins_addr=0x1000,
    )
    parity = compare_indexed_address_collectors_8616(alias_evidence, (legacy,), ())

    mismatches = classify_indexed_address_mismatches_8616(alias_evidence, parity)

    assert len(mismatches) == 1
    assert mismatches[0].kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_IR_REFUSED
    assert len(mismatches[0].ir_failures) == 2
    assert mismatches[0].complete


def test_legacy_only_key_retains_matching_typed_alias_refusals() -> None:
    project, function = _fixture()
    artifact = build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )
    ir_evidence = collect_indexed_address_evidence_8616(artifact)
    duplicated_ir_evidence = IndexedAddressEvidence8616(
        ir_evidence.function_addr,
        (ir_evidence.facts[0], ir_evidence.facts[0]),
        (),
        IndexedAddressStats8616(2, 2, 2, 2, 0),
    )
    alias_evidence = project_indexed_address_aliases_8616(
        duplicated_ir_evidence
    )
    legacy = IndexedSegmentedGlobalLoadSiteEvidence8616(
        base_offset=0x200,
        width=2,
        index_stack_offset=-2,
        index_shift=1,
        ins_addr=0x1010,
    )
    parity = compare_indexed_address_collectors_8616(alias_evidence, (legacy,), ())

    mismatches = classify_indexed_address_mismatches_8616(alias_evidence, parity)

    assert len(mismatches) == 1
    assert mismatches[0].kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_ALIAS_REFUSED
    assert len(mismatches[0].alias_failures) == 2
    assert mismatches[0].complete


def test_legacy_only_key_without_upstream_candidate_is_explicit() -> None:
    project, function = _fixture()
    artifact = build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )
    alias_evidence = project_indexed_address_aliases_8616(
        collect_indexed_address_evidence_8616(artifact)
    )
    legacy = IndexedSegmentedGlobalLoadSiteEvidence8616(
        base_offset=0x300,
        width=2,
        index_stack_offset=-4,
        index_shift=1,
        ins_addr=0x1020,
    )
    parity = compare_indexed_address_collectors_8616(alias_evidence, (legacy,), ())

    mismatches = classify_indexed_address_mismatches_8616(alias_evidence, parity)

    assert any(
        mismatch.side is IndexedAddressCollectorSide8616.LEGACY
        and mismatch.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_NO_IR_CANDIDATE
        for mismatch in mismatches
    )

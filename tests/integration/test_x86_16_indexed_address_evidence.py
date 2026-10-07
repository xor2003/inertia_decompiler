from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    AddressStatus,
    IndexedAddressAccessKind8616,
    IndexedAddressFailureKind8616,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
    build_x86_16_ir_function_artifact,
    collect_indexed_address_evidence_8616,
)

INDEXED_LOAD = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 8b 76 fe d1 e6 8b 84 00 02 c9 c3"
)
INDEXED_STORE = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 8b 76 fe d1 e6 88 84 00 02 c9 c3"
)
MULTI_TERM_LOAD = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 8b 76 fe d1 e6 8b 80 00 02 c9 c3"
)


def _lift(code: bytes) -> SSAFunctionArtifact:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    return build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )


def test_real_lifter_retains_versioned_index_and_stack_shift_path() -> None:
    evidence = collect_indexed_address_evidence_8616(_lift(INDEXED_LOAD))

    assert evidence.closed
    assert evidence.refusals == ()
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.normalized_fact_count == 1
    assert evidence.stats.classified_fact_count == 1
    assert evidence.stats.materialized_count == 1
    assert evidence.stats.failure_count == 0
    assert evidence.stats.coalesced_fact_count == 1
    fact = evidence.facts[0]
    assert fact.kind is IndexedAddressAccessKind8616.LOAD
    assert fact.address.space is MemSpace.DS
    assert fact.address.offset == 0x200
    assert fact.address.base == ("si",)
    assert fact.index_value.name == "si"
    assert fact.index_value.version == 1
    assert fact.index_source.space is MemSpace.SS
    assert fact.index_source.base == ("bp",)
    assert fact.index_source.offset == -2
    assert fact.index_shift == 1
    assert fact.definition_path[-1].op == "LOAD"


def test_real_lifter_retains_index_proof_for_store_effect() -> None:
    evidence = collect_indexed_address_evidence_8616(_lift(INDEXED_STORE))

    assert evidence.closed
    assert evidence.refusals == ()
    assert len(evidence.facts) == 1
    assert evidence.facts[0].kind is IndexedAddressAccessKind8616.STORE
    assert evidence.facts[0].instr_addr == 0x1010
    assert evidence.facts[0].address.size == 1


def test_multiple_dynamic_address_terms_refuse_without_partial_fact() -> None:
    evidence = collect_indexed_address_evidence_8616(_lift(MULTI_TERM_LOAD))

    assert evidence.closed
    assert evidence.facts == ()
    assert evidence.refusals
    assert all(
        refusal.failure is IndexedAddressFailureKind8616.MULTIPLE_DYNAMIC_TERMS
        for refusal in evidence.refusals
    )


def test_unproven_index_definition_refuses_without_guessing() -> None:
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

    evidence = collect_indexed_address_evidence_8616(artifact)

    assert evidence.closed
    assert evidence.facts == ()
    assert (
        evidence.refusals[0].failure
        is IndexedAddressFailureKind8616.INDEX_DEFINITION_MISSING
    )


def test_direct_segmented_access_is_outside_indexed_candidate_census() -> None:
    address = IRAddress(
        MemSpace.DS,
        offset=0x200,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
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

    evidence = collect_indexed_address_evidence_8616(artifact)

    assert evidence.closed
    assert evidence.facts == evidence.refusals == ()
    assert evidence.stats.raw_fact_count == 0

"""Binary multi-register address normalization and proof corruption controls."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.affine_indexed_address import prove_affine_indexed_address_8616
from angr_platforms.X86_16.ir.core import MemSpace
from angr_platforms.X86_16.ir.indexed_address_access_normalization import normalize_indexed_address_accesses_8616
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from x86_16_logical_memory_fixtures import lift_ir_artifact


def _source(extra: str = ""):
    code = bytes.fromhex(f"55 89 e5 8b 5e 04 8b 76 fe d1 e6 {extra} 8b 00 c3")
    artifact = build_x86_16_function_ssa(lift_ir_artifact(code))
    accesses = normalize_indexed_address_accesses_8616(artifact).accesses
    assert len(accesses) == 1
    return artifact, accesses[0]


def test_loaded_base_and_scaled_load_are_retained_without_pointer_role_guess() -> None:
    artifact, access = _source()
    proof = prove_affine_indexed_address_8616(artifact, access)
    assert proof.complete and proof.constant == 0
    assert proof.access.address.space is MemSpace.DS
    assert tuple((term.source.offset, term.coefficient) for term in proof.terms) == ((4, 1), (-2, 2))
    assert (proof.stats.raw_fact_count, proof.stats.normalized_fact_count,
            proof.stats.classified_fact_count, proof.stats.materialized_count,
            proof.stats.failure_count, proof.stats.coalesced_fact_count) == (2, 1, 1, 1, 0, 1)
    assert not replace(proof, components=()).complete
    changed = replace(proof.components[0], terms=tuple(
        replace(term, coefficient=2) for term in proof.components[0].terms))
    assert not replace(proof, components=(changed, *proof.components[1:])).complete
    assert not replace(proof, stats=replace(proof.stats, materialized_count=0)).complete


@pytest.mark.parametrize("defect", ("members", "provenance", "missing_component"))
def test_foreign_normalization_record_refuses(defect: str) -> None:
    artifact, access = _source()
    if defect == "members":
        access = replace(access, member_instr_indices=(access.instr_index,))
    elif defect == "provenance":
        values = access.address.base_values
        access = replace(access, address=replace(access.address, base_values=(
            replace(values[0], source_tmp=99999), *values[1:])))
    else:
        access = replace(access, address=replace(access.address, base_values=access.address.base_values[:1]))
    proof = prove_affine_indexed_address_8616(artifact, access)
    assert not proof.complete and proof.failure is not None
    assert proof.constant is None and not proof.terms


def test_unsupported_component_does_not_publish_partial_address() -> None:
    artifact, access = _source("f7 d3")  # NOT BX is not supported by the affine owner.
    proof = prove_affine_indexed_address_8616(artifact, access)
    assert not proof.complete and proof.failure is not None
    assert proof.constant is None and not proof.terms

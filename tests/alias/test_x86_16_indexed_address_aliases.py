from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.structuring.decompiler_structuring_stage import (
    DECOMPILER_STRUCTURING_PASSES,
)
from inertia.ir import (
    IndexedAddressAccessKind8616,
    IndexedAddressEvidence8616,
    IndexedAddressStats8616,
    MemSpace,
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
    build_x86_16_ir_function_artifact,
    collect_indexed_address_evidence_8616,
)
from inertia.ir.indexed_address_pipeline import (
    apply_x86_16_indexed_address_evidence_8616,
)
from inertia.pipeline.errors import PipelineHardError

from inertia.alias.alias_model_impl import (
    AliasFailure,
    alias_facts_for_ir_address_8616,
)
from inertia.alias.indexed_address_access_classification import (
    classify_indexed_alias_accesses_8616,
)
from inertia.alias.indexed_address_access_contracts import (
    IndexedAliasAccessEvidence8616,
    IndexedAliasAccessFailureKind8616,
    IndexedAliasAccessRole8616,
)
from inertia.alias.indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
    IndexedAddressAliasFailureKind8616,
)
from inertia.alias.indexed_address_projection import (
    apply_x86_16_indexed_address_aliases_8616,
    project_indexed_address_aliases_8616,
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
POINTER_ARGUMENT_LOAD = bytes.fromhex("55 89 e5 8b 5e 04 8b 07 5d c3")


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


def _evidence(code: bytes) -> IndexedAddressEvidence8616:
    return collect_indexed_address_evidence_8616(_lift(code))


def test_indexed_load_projects_symbolic_target_and_exact_stack_source() -> None:
    result = project_indexed_address_aliases_8616(_evidence(INDEXED_LOAD))

    assert result.closed
    assert result.refusals == ()
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    fact = result.facts[0]
    assert fact.complete
    assert fact.source.kind is IndexedAddressAccessKind8616.LOAD
    assert fact.storage.space is MemSpace.DS
    assert fact.storage.base_offset == 0x200
    assert fact.storage.width == 2
    assert fact.storage.index_shift == 1
    assert fact.storage.index_source_range.space is MemSpace.SS
    assert fact.storage.index_source_range.offset == -2


def test_indexed_store_projects_without_turning_width_into_a_type() -> None:
    result = project_indexed_address_aliases_8616(_evidence(INDEXED_STORE))

    assert result.closed
    assert result.facts[0].source.kind is IndexedAddressAccessKind8616.STORE
    assert result.facts[0].storage.width == 1


def test_ds_and_es_indexed_families_remain_distinct() -> None:
    source = _evidence(INDEXED_LOAD)
    ds_result = project_indexed_address_aliases_8616(source)
    es_fact = replace(
        source.facts[0],
        address=replace(source.facts[0].address, space=MemSpace.ES),
    )
    es_source = replace(source, facts=(es_fact,))

    es_result = project_indexed_address_aliases_8616(es_source)

    assert es_result.closed
    assert ds_result.facts[0].storage.family_key != es_result.facts[0].storage.family_key


def test_ir_refusal_is_retained_as_one_alias_refusal() -> None:
    result = project_indexed_address_aliases_8616(_evidence(MULTI_TERM_LOAD))

    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count > 0
    assert result.stats.raw_fact_count == result.stats.failure_count
    assert (
        result.refusals[0].failure
        is IndexedAddressAliasFailureKind8616.UPSTREAM_REFUSAL
    )
    assert result.refusals[0].source_refusal is not None


def test_duplicate_machine_identity_refuses_every_duplicate() -> None:
    source = _evidence(INDEXED_LOAD)
    duplicated = IndexedAddressEvidence8616(
        source.function_addr,
        (source.facts[0], source.facts[0]),
        (),
        IndexedAddressStats8616(2, 2, 2, 2, 0),
    )

    result = project_indexed_address_aliases_8616(duplicated)

    assert result.closed
    assert result.facts == ()
    assert result.stats.failure_count == 2
    assert all(
        refusal.failure is IndexedAddressAliasFailureKind8616.DUPLICATE_ACCESS
        for refusal in result.refusals
    )


def test_generic_alias_api_refuses_to_collapse_dynamic_ds_address() -> None:
    address = _evidence(INDEXED_LOAD).facts[0].address

    result = alias_facts_for_ir_address_8616(address)

    assert isinstance(result, AliasFailure)
    assert result.space == "DS"
    assert "symbolic Alias projection" in result.reason


def test_alias_access_classifies_real_direct_argument_dereference_as_pointer() -> None:
    result = classify_indexed_alias_accesses_8616(
        project_indexed_address_aliases_8616(_evidence(POINTER_ARGUMENT_LOAD))
    )

    assert result.closed
    assert result.refusals == ()
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    assert result.facts[0].role is IndexedAliasAccessRole8616.POINTER_RELATIVE
    assert result.facts[0].is_pointer_argument


def test_alias_access_classifies_scaled_nonzero_base_as_global_indexed() -> None:
    result = classify_indexed_alias_accesses_8616(
        project_indexed_address_aliases_8616(_evidence(INDEXED_LOAD))
    )

    assert result.closed
    assert result.refusals == ()
    assert result.facts[0].role is IndexedAliasAccessRole8616.GLOBAL_INDEXED
    assert not result.facts[0].is_pointer_argument


def test_alias_access_refuses_unscaled_displaced_form_as_ambiguous() -> None:
    source = _evidence(POINTER_ARGUMENT_LOAD)
    displaced_fact = replace(
        source.facts[0],
        address=replace(source.facts[0].address, offset=2),
    )
    projected = project_indexed_address_aliases_8616(replace(source, facts=(displaced_fact,)))

    result = classify_indexed_alias_accesses_8616(projected)

    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert (
        result.refusals[0].failure
        is IndexedAliasAccessFailureKind8616.AMBIGUOUS_ADDRESS_FORM
    )


def test_alias_access_retains_upstream_refusal_in_closed_accounting() -> None:
    source = project_indexed_address_aliases_8616(_evidence(MULTI_TERM_LOAD))

    result = classify_indexed_alias_accesses_8616(source)

    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count == result.stats.failure_count
    assert result.refusals[0].failure is IndexedAliasAccessFailureKind8616.UPSTREAM_REFUSAL


def test_main_path_attaches_ir_then_alias_evidence() -> None:
    codegen = SimpleNamespace(_inertia_vex_ir_function_ssa=_lift(INDEXED_LOAD))

    assert not apply_x86_16_indexed_address_evidence_8616(None, codegen)
    assert not apply_x86_16_indexed_address_aliases_8616(None, codegen)

    result = codegen._inertia_indexed_address_alias_evidence_8616
    assert isinstance(result, IndexedAddressAliasEvidence8616)
    assert result.closed
    assert len(result.facts) == 1
    access_result = codegen._inertia_indexed_address_alias_access_evidence_8616
    assert isinstance(access_result, IndexedAliasAccessEvidence8616)
    assert access_result.closed
    assert access_result.source is result


def test_alias_main_path_hard_fails_when_ir_owner_was_skipped() -> None:
    codegen = SimpleNamespace(_inertia_vex_ir_function_ssa=_lift(INDEXED_LOAD))

    with pytest.raises(PipelineHardError, match="IR evidence is missing"):
        apply_x86_16_indexed_address_aliases_8616(None, codegen)


def test_structuring_registry_orders_indexed_ir_before_alias() -> None:
    names = tuple(spec.name for spec in DECOMPILER_STRUCTURING_PASSES)

    ir_index = names.index("_indexed_address_ir_evidence_8616")
    alias_index = names.index("_indexed_address_alias_evidence_8616")
    widening_index = names.index("_carry_borrow_widening_artifact_8616")
    assert ir_index < alias_index < widening_index

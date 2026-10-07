from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
    build_x86_16_ir_function_artifact,
    collect_indexed_address_evidence_8616,
)
from inertia.lowering.indexed_address_collector_parity import (
    IndexedAddressCollectorParityStatus8616,
    compare_indexed_address_collectors_8616,
)
from inertia.lowering.segmented_global_loads import (
    IndexedSegmentedGlobalLoadSiteEvidence8616,
    recover_indexed_segmented_global_load_site_evidence_8616,
    recover_indexed_segmented_global_store_evidence_8616,
)

from inertia.alias.indexed_address_projection import (
    project_indexed_address_aliases_8616,
)

INDEXED_LOAD = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 8b 76 fe d1 e6 8b 84 00 02 c9 c3"
)
INDEXED_STORE = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 8b 76 fe d1 e6 88 84 00 02 c9 c3"
)


def _fixture(code: bytes) -> tuple[angr.Project, object, SSAFunctionArtifact]:
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
    artifact = build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )
    return project, function, artifact


def _compare_real_collectors(code: bytes):
    project, function, artifact = _fixture(code)
    alias_evidence = project_indexed_address_aliases_8616(
        collect_indexed_address_evidence_8616(artifact)
    )
    return compare_indexed_address_collectors_8616(
        alias_evidence,
        recover_indexed_segmented_global_load_site_evidence_8616(project, function),
        recover_indexed_segmented_global_store_evidence_8616(project, function),
    )


def test_real_indexed_load_collectors_have_exact_identity_parity() -> None:
    result = _compare_real_collectors(INDEXED_LOAD)

    assert result.closed
    assert result.exact
    assert result.status is IndexedAddressCollectorParityStatus8616.EXACT
    assert result.stats.matched_key_count == 1


def test_real_indexed_store_collectors_have_exact_identity_parity() -> None:
    result = _compare_real_collectors(INDEXED_STORE)

    assert result.closed
    assert result.exact
    assert result.status is IndexedAddressCollectorParityStatus8616.EXACT
    assert result.stats.matched_key_count == 1


def test_parity_census_reports_legacy_superset_without_selecting_it() -> None:
    _project, _function, artifact = _fixture(INDEXED_LOAD)
    alias_evidence = project_indexed_address_aliases_8616(
        collect_indexed_address_evidence_8616(artifact)
    )
    legacy = IndexedSegmentedGlobalLoadSiteEvidence8616(
        base_offset=0x202,
        width=2,
        index_stack_offset=-2,
        index_shift=1,
        ins_addr=0x1010,
    )

    result = compare_indexed_address_collectors_8616(alias_evidence, (legacy,), ())

    assert result.closed
    assert not result.exact
    assert result.status is IndexedAddressCollectorParityStatus8616.DIVERGED
    assert result.stats.alias_only_count == result.stats.legacy_only_count == 1


def test_duplicate_legacy_keys_remain_visible_in_parity_stats() -> None:
    project, function, artifact = _fixture(INDEXED_LOAD)
    alias_evidence = project_indexed_address_aliases_8616(
        collect_indexed_address_evidence_8616(artifact)
    )
    legacy = recover_indexed_segmented_global_load_site_evidence_8616(project, function)

    result = compare_indexed_address_collectors_8616(
        alias_evidence,
        (*legacy, *legacy),
        (),
    )

    assert result.closed
    assert not result.exact
    assert result.stats.duplicate_key_count == 1

"""Layer: Tests.

Responsibility: prevent stale loaded bytes and lifter semantics from entering
SSA through a warm disk cache, while retaining unchanged-input reuse.
"""

from pathlib import Path
from typing import Any

import pytest
from test_flat32_comparator_lane import _driver_lane
from test_flat32_loaded_byte_boundaries import pe32_bytes
from test_real16_binary_compare import LEAF, _exe

from tools.dosunit import ssa_provenance
from tools.dosunit import straightline_ssa as ssa
from tools.dosunit.vex_cache_identity import vex_cache_identity


def _lower(exe: Path, catalog: dict[str, Any], cache: Path, project: Any) -> dict[str, Any]:
    """Lower the exact supplied loaded image with normal production cache admission."""
    return ssa.lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, cache_dir=cache,
        lifter_project=project, output_regs=("ax", "sp"),
    )


def test_changed_loaded_code_cannot_reuse_cached_vex(tmp_path: Path) -> None:
    """Same file/address, different loaded bytes must miss and match fresh lifting."""
    exe, catalog = _exe(tmp_path, "loaded", LEAF, 6)
    project = ssa._load_lifter_project(exe)
    cache = tmp_path / "cache"
    first = _lower(exe, catalog, cache, project)
    assert first["counters"]["lifter_cache_writes"] == 1
    # A separately loaded/relocated image has no previous engine-local IRSBs.
    project = ssa._load_lifter_project(exe)
    address = project.loader.main_object.mapped_base + 0x204
    assert project.loader.memory.load(address, 1) == b"\x01"
    project.loader.memory.store(address, b"\x02")
    changed = _lower(exe, catalog, cache, project)
    fresh = _lower(exe, catalog, tmp_path / "fresh", project)
    assert changed["counters"]["lifter_cache_hits"] == 0
    assert changed["functions"] == fresh["functions"]
    assert changed["functions"] != first["functions"]


def test_changed_semantic_owner_invalidates_disk_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Transitive source changes cannot reuse VEX merely because the EXE matches."""
    exe, catalog = _exe(tmp_path, "semantic", LEAF, 6)
    project = ssa._load_lifter_project(exe)
    cache = tmp_path / "cache"
    monkeypatch.setattr(ssa_provenance, "_semantic_hash", lambda: "before")
    first = _lower(exe, catalog, cache, project)
    warm = _lower(exe, catalog, cache, project)
    assert warm["counters"]["lifter_cache_hits"] == 1
    assert warm["functions"] == first["functions"]
    monkeypatch.setattr(ssa_provenance, "_semantic_hash", lambda: "after")
    changed = _lower(exe, catalog, cache, project)
    assert changed["counters"]["lifter_cache_hits"] == 0
    assert changed["counters"]["lifter_cache_writes"] == 1
    assert changed["functions"] == first["functions"]


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_pe32_cache_parity_and_loaded_code_invalidation(tmp_path: Path, driver: str) -> None:
    """Both PE32 adapters reuse unchanged lifts and reject a different loaded image."""
    code = bytes.fromhex("b807000000c3")
    exe = tmp_path / "candidate.exe"
    exe.write_bytes(pe32_bytes(code))
    with _driver_lane(driver) as lane, lane.adapter.installed(region=True):
        project = lane.adapter.load32(exe)
        catalog = lane.catalog.catalog("candidate.exe", {"f": (0x401000, len(code))}, 0x400000)

        def lower(cache: Path, image: Any) -> dict[str, Any]:
            return ssa.lower_straightline_ssa_document(
                exe_path=exe, functions_catalog=catalog, cache_dir=cache,
                lifter_project=image, output_regs=("eax", "esp"),
            )

        first = lower(tmp_path / "cache", project)
        warm = lower(tmp_path / "cache", project)
        assert first["counters"]["lifter_cache_writes"] == 1
        assert warm["counters"]["lifter_cache_hits"] == 1
        assert first["functions"] == warm["functions"]
        changed_project = lane.adapter.load32(exe)
        changed_project.loader.memory.store(0x401001, b"\x08")
        changed = lower(tmp_path / "cache", changed_project)
        fresh = lower(tmp_path / "fresh", changed_project)
        assert changed["counters"]["lifter_cache_hits"] == 0
        assert changed["functions"] == fresh["functions"]
        assert changed["functions"] != first["functions"]
        verdict = ssa.compare_ssa_documents(oracle=first, candidate=changed, skip_binary_equal=False)
        assert verdict["summary"]["failed"] == 1, verdict


def test_decode_domain_and_semantic_option_are_part_of_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same bytes in different PC domains cannot share a lifting identity."""
    from angr_platforms.X86_16.control_coordinates import ControlAddressDomain

    exe, _catalog = _exe(tmp_path, "domain", LEAF, 6)
    project = ssa._load_lifter_project(exe)
    monkeypatch.setenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", "0")
    before = vex_cache_identity(project)
    domain = project.arch.control_address_domain
    alternative = next(item for item in ControlAddressDomain if item != domain)
    monkeypatch.setattr(project.arch, "control_address_domain", alternative)
    assert vex_cache_identity(project) != before
    monkeypatch.setattr(project.arch, "control_address_domain", domain)
    assert vex_cache_identity(project) == before
    monkeypatch.setenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", "1")
    assert vex_cache_identity(project) != before

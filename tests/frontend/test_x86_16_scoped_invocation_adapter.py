"""Staged regression for the declared-ProgramBoot scoped-invocation adapter.

Layer: tests.
Responsibility: prove the staged dosunit adapter authenticates a declared
``ProgramBoot`` against the loaded project, derives the bounded
header-rooted invocation inventory without any function catalog, installs
the typed invocation source only after complete preparation, and refuses
changed mapped bytes, foreign boots, missing boundaries and exhausted
budgets while clearing any previously installed authority.
"""

from __future__ import annotations

from itertools import repeat
from pathlib import Path

import pytest
from inertia.ir.function_ir_registry import (
    registered_function_ir_artifact_8616,
)

from inertia.frontend.x86_16.frontend_invocation_inventory import (
    InvocationInventoryBudget8616,
    InvocationInventoryStatus8616,
)
from inertia.frontend.x86_16.mz_invocation_source import mz_invocation_source_8616
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange
from tools.dosunit.catalog.real16_scoped_invocation import (
    DeclaredInvocationStatus8616,
    _authenticated_image_bytes_8616,
    install_declared_invocation_source_8616,
)
from tools.dosunit.tests.test_x86_16_scoped_native_inputs import (
    BASE,
    CALL_RANGES,
    CALLER,
    CALLER_CODE,
    ISLAND,
    JUMP_HEAD,
    LEAF,
    LEAF_CODE,
    STUB,
    STUB_CODE,
    _assert_loader_bytes,
    _build_environment,
    _build_image,
    _build_mz,
    _make_boot,
    _make_project,
    _premise,
    _records,
)
from tools.dosunit.tests.test_x86_16_scoped_native_inputs import world as world

ISLAND_CODE = b"\xc3"
OPEN_HEAD = BASE + 0x180


def _world(tmp_path: Path) -> tuple[object, bytes, object]:
    """Rebuild the native fixture's project/boot pair through its helpers."""
    image = _build_image(
        (
            (LEAF, LEAF_CODE),
            (CALLER, CALLER_CODE),
            (ISLAND, ISLAND_CODE),
            (STUB, STUB_CODE),
        )
    )
    boot, mz = _make_boot(image, STUB - BASE, CALL_RANGES)
    project = _make_project(mz, tmp_path)
    _assert_loader_bytes(project, boot, CALL_RANGES)
    return boot, mz, project


def _installed_source(project: object) -> object:
    """Read the project invocation-source slot as installed or absent."""
    return getattr(project, "_inertia_real16_invocation_source_8616", None)


def test_declared_boot_installs_header_rooted_source(tmp_path: Path) -> None:
    """Positive: MZ-header startup is indexed without any catalog."""
    boot, _mz, project = _world(tmp_path)
    result = install_declared_invocation_source_8616(project, boot)
    assert result.status is DeclaredInvocationStatus8616.INSTALLED
    assert result.installed
    source = _installed_source(project)
    assert source is result.source
    assert source is not None and source.boot is boot
    inventory = result.inventory
    assert inventory is not None and inventory.ready
    assert inventory.status is InvocationInventoryStatus8616.READY
    assert inventory.entry == STUB
    assert inventory.boundary_heads == (STUB, CALLER, LEAF)
    assert inventory.stats.closed
    assert inventory.stats.failure_count == 0
    assert inventory.out_of_image_target_count == 0
    index = result.source.callsite_index
    caller_rows = index.for_target(CALLER)
    assert len(caller_rows) == 1
    assert caller_rows[0].caller_start == STUB
    assert caller_rows[0].callsite_addr == STUB
    assert caller_rows[0].target_addr == CALLER
    assert not caller_rows[0].is_far
    leaf_rows = index.for_target(LEAF)
    assert len(leaf_rows) == 1
    assert leaf_rows[0].caller_start == CALLER
    assert leaf_rows[0].callsite_addr == CALLER


def test_installed_source_admits_scoped_premise(world: tuple) -> None:
    """Positive: the installed source feeds the existing premise path."""
    boot, project, _sb, _sa, _stub_index, boundary, artifact = world
    result = install_declared_invocation_source_8616(project, boot)
    assert result.installed
    records = _records(project, artifact, boundary)
    offered = _premise(project, artifact, boundary, JUMP_HEAD, records)
    assert offered is not None
    assert offered.complete


def test_adapter_refuses_foreign_boot_type(tmp_path: Path) -> None:
    """Negative: a non-ProgramBoot input refuses and clears a prior install."""
    boot, _mz, project = _world(tmp_path)
    first = install_declared_invocation_source_8616(project, boot)
    assert first.installed
    refused = install_declared_invocation_source_8616(project, object())
    assert refused.status is DeclaredInvocationStatus8616.BOOT_TYPE_REFUSED
    assert refused.source is None
    assert _installed_source(project) is None


@pytest.mark.parametrize("loaded", (4, [0, 0, 0, 0], b"\0" * 4, bytearray(4), memoryview(bytes(4))))
def test_mapped_memory_requires_bytes_like_result(loaded: object) -> None:
    """An integer or iterable cannot masquerade as mapped zero bytes."""
    boot = program_from_mz_bytes(
        _build_mz(bytes(4), entry_ip=0, maxalloc=0x40),
        _build_environment(),
        code_ranges=(LinearRange(BASE, 4),),
    )

    class LoaderMemory:
        def load(self, address: int, size: int) -> object:
            assert (address, size) == (BASE, 4)
            return loaded

    mismatch = _authenticated_image_bytes_8616(LoaderMemory(), boot)
    assert mismatch == (None if isinstance(loaded, (bytes, bytearray, memoryview)) else BASE)


def test_adapter_refuses_changed_mapped_bytes(tmp_path: Path) -> None:
    """Negative: a boot bound to other source bytes cannot authenticate."""
    boot, _mz, _project = _world(tmp_path)
    changed = _build_image(
        (
            (LEAF, bytes.fromhex("b8 35 12 c3")),
            (CALLER, CALLER_CODE),
            (ISLAND, ISLAND_CODE),
            (STUB, STUB_CODE),
        )
    )
    changed_mz = _build_mz(changed, entry_ip=STUB - BASE)
    other = _make_project(changed_mz, tmp_path)
    result = install_declared_invocation_source_8616(other, boot)
    assert result.status is DeclaredInvocationStatus8616.IMAGE_MISMATCH_REFUSED
    assert result.refusal_addr == BASE
    assert result.source is None
    assert _installed_source(other) is None


def test_adapter_refuses_foreign_boot(tmp_path: Path) -> None:
    """Negative: a self-consistent boot for other bytes cannot authenticate."""
    _boot, _mz, project = _world(tmp_path)
    changed = _build_image(
        (
            (LEAF, bytes.fromhex("b8 35 12 c3")),
            (CALLER, CALLER_CODE),
            (ISLAND, ISLAND_CODE),
            (STUB, STUB_CODE),
        )
    )
    foreign_boot, _changed_mz = _make_boot(changed, STUB - BASE, CALL_RANGES)
    result = install_declared_invocation_source_8616(project, foreign_boot)
    assert result.status is DeclaredInvocationStatus8616.IMAGE_MISMATCH_REFUSED
    assert result.refusal_addr == BASE
    assert _installed_source(project) is None


def test_adapter_refuses_unmapped_root(tmp_path: Path) -> None:
    """Negative: an extra root outside the mapped image refuses closed."""
    boot, _mz, project = _world(tmp_path)
    result = install_declared_invocation_source_8616(
        project, boot, extra_entries=(0x90000,)
    )
    assert result.status is DeclaredInvocationStatus8616.INVENTORY_REFUSED
    inventory = result.inventory
    assert inventory is not None
    assert inventory.status is InvocationInventoryStatus8616.BOUNDARY_MISSING
    assert inventory.refusal_addr == 0x90000
    assert _installed_source(project) is None


def test_adapter_refuses_open_boundary(tmp_path: Path) -> None:
    """Negative: an in-image root that cannot close its boundary refuses."""
    image = _build_image(
        (
            (LEAF, LEAF_CODE),
            (CALLER, CALLER_CODE),
            (ISLAND, ISLAND_CODE),
            (STUB, STUB_CODE),
            (OPEN_HEAD, b"\xff\xe0"),
        )
    )
    open_ranges = (*CALL_RANGES, LinearRange(OPEN_HEAD, 2))
    boot, mz = _make_boot(image, STUB - BASE, open_ranges)
    project = _make_project(mz, tmp_path)
    result = install_declared_invocation_source_8616(
        project, boot, extra_entries=(OPEN_HEAD,)
    )
    assert result.status is DeclaredInvocationStatus8616.INVENTORY_REFUSED
    inventory = result.inventory
    assert inventory is not None
    assert inventory.status is InvocationInventoryStatus8616.BOUNDARY_MISSING
    assert inventory.refusal_addr == OPEN_HEAD
    assert _installed_source(project) is None


def test_adapter_refuses_exhausted_boundary_budget(tmp_path: Path) -> None:
    """Negative: a boundary budget below the reachable corpus refuses."""
    boot, _mz, project = _world(tmp_path)
    result = install_declared_invocation_source_8616(
        project,
        boot,
        budget=InvocationInventoryBudget8616(max_boundaries=1),
    )
    assert result.status is DeclaredInvocationStatus8616.INVENTORY_REFUSED
    inventory = result.inventory
    assert inventory is not None
    assert inventory.status is InvocationInventoryStatus8616.BUDGET_BOUNDARIES
    assert inventory.refusal_addr == CALLER
    assert _installed_source(project) is None


def test_adapter_refuses_exhausted_instruction_budget(tmp_path: Path) -> None:
    """Negative: an instruction budget below the first boundary refuses."""
    boot, _mz, project = _world(tmp_path)
    result = install_declared_invocation_source_8616(
        project,
        boot,
        budget=InvocationInventoryBudget8616(max_instructions=1),
    )
    assert result.status is DeclaredInvocationStatus8616.INVENTORY_REFUSED
    inventory = result.inventory
    assert inventory is not None
    assert inventory.status is InvocationInventoryStatus8616.BUDGET_INSTRUCTIONS
    assert inventory.refusal_addr == STUB
    assert _installed_source(project) is None


def test_adapter_refuses_root_flood_and_clears_authority(tmp_path: Path) -> None:
    """An unbounded duplicate-root stream cannot retain a prior install."""
    boot, _mz, project = _world(tmp_path)
    assert install_declared_invocation_source_8616(project, boot).installed
    result = install_declared_invocation_source_8616(
        project, boot, extra_entries=repeat(STUB),
        budget=InvocationInventoryBudget8616(max_root_inputs=8),
    )
    assert result.status is DeclaredInvocationStatus8616.INVENTORY_REFUSED
    assert result.inventory.status is InvocationInventoryStatus8616.BUDGET_ROOT_INPUTS
    assert not result.inventory.stats.closed
    assert _installed_source(project) is None


def test_entry_projection_matches_boot(tmp_path: Path) -> None:
    """Positive: the adapter-derived entry equals the MZ header projection."""
    boot, _mz, project = _world(tmp_path)
    result = install_declared_invocation_source_8616(project, boot)
    assert result.installed
    projection = mz_invocation_source_8616(boot.source, boot.image.load_segment)
    assert result.entry_linear == projection.entry_linear == STUB
    assert result.boot_sha256 == boot.boot_sha256


def test_installed_source_preserves_registry_identity(world: tuple) -> None:
    """Positive: install changes only the source slot, never the registry."""
    boot, project, _sb, _sa, _stub_index, _boundary, _artifact = world
    caller_before = registered_function_ir_artifact_8616(project, CALLER)
    stub_before = registered_function_ir_artifact_8616(project, STUB)
    result = install_declared_invocation_source_8616(project, boot)
    assert result.installed
    caller_after = registered_function_ir_artifact_8616(project, CALLER)
    stub_after = registered_function_ir_artifact_8616(project, STUB)
    assert caller_after.verdict == caller_before.verdict
    assert caller_after.artifact is caller_before.artifact
    assert stub_after.verdict == stub_before.verdict
    assert stub_after.artifact is stub_before.artifact
    assert _installed_source(project) is result.source


@pytest.mark.parametrize("failure", ("root", "budget", "resolver"))
def test_failed_preparation_clears_previous_authority(tmp_path: Path, failure: str) -> None:
    """Malformed input or a resolver defect cannot retain old proof authority."""
    boot, _mz, project = _world(tmp_path)
    assert install_declared_invocation_source_8616(project, boot).installed

    def broken_resolver(_instruction: object) -> int | None:
        raise RuntimeError("resolver defect")

    with pytest.raises((TypeError, RuntimeError)):
        if failure == "root":
            install_declared_invocation_source_8616(project, boot, extra_entries=(None,))
        elif failure == "budget":
            install_declared_invocation_source_8616(project, boot, budget=object())
        else:
            install_declared_invocation_source_8616(
                project, boot, direct_target_resolver=broken_resolver
            )
    assert _installed_source(project) is None

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import inertia.cli.function_ir_ssa_cache_identity as identity
from inertia import ir, semantics
from inertia.cli.cache_source_manifest import (
    FUNCTION_IR_SSA_CACHE_SOURCE_FILES,
)
from inertia.cli.function_ir_ssa_source_scope import (
    frontend_cache_source_files_8616,
)
from inertia.frontend.x86_16 import lifter_backend

_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class _Node:
    addr: int
    size: int


@dataclass(frozen=True)
class _Graph:
    nodes: tuple[_Node, ...]
    edges: tuple[tuple[_Node, _Node], ...] = ()


@dataclass(frozen=True)
class _Function:
    addr: int
    block_addrs_set: set[int]
    graph: _Graph


class _Memory:
    def load(self, addr: int, size: int) -> bytes:
        return bytes((addr + offset) & 0xFF for offset in range(size))


@dataclass(frozen=True)
class _Loader:
    memory: _Memory = field(default_factory=_Memory)


@dataclass(frozen=True)
class _Arch:
    name: str = "86_16"
    bits: int = 32
    memory_endness: str = "Iend_LE"


@dataclass(frozen=True)
class _Project:
    loader: _Loader = field(default_factory=_Loader)
    arch: _Arch = field(default_factory=_Arch)


def _relative_source_paths() -> set[str]:
    return {
        path.relative_to(_ROOT).as_posix()
        for path in FUNCTION_IR_SSA_CACHE_SOURCE_FILES
    }


def test_function_ir_ssa_source_scope_has_exact_layer_owners() -> None:
    paths = _relative_source_paths()
    ir_paths = {
        path.relative_to(_ROOT).as_posix()
        for path in (
            Path(ir.__file__).parent
        ).rglob("*.py")
    }

    assert ir_paths <= paths
    assert set(frontend_cache_source_files_8616(_ROOT)) <= set(FUNCTION_IR_SSA_CACHE_SOURCE_FILES)
    assert {
        "pyvex_compat.py",
        "angr_platforms/__init__.py",
        "angr_platforms/angr_platforms/__init__.py",
        "angr_platforms/angr_platforms/import_identity.py",
        "inertia/frontend/x86_16/frontend_block_inventory.py",
        "inertia/frontend/x86_16/frontend_capstone_decode.py",
        "inertia/frontend/x86_16/lift_86_16.py",
        "inertia/ir/analysis/alias.py",
        "inertia/ir/analysis/stack_frame_ir.py",
        "inertia/ir/address_ir_8616.py",
        "inertia/semantics/compiler_helpers.py",
        "inertia/semantics/callee_name_normalization.py",
        "inertia/pipeline/errors.py",
        (Path(semantics.__file__).parent / "status_flag_liveness.py").relative_to(_ROOT).as_posix(),
        lifter_backend.LIFTER_SOURCE,
    } <= paths
    assert {
        "inertia/semantics/callsite_summary.py",
        "inertia/lowering/analysis_helpers.py",
        "inertia/postprocess/decompiler_postprocess_stage.py",
        "inertia/lowering/register_local_declarations.py",
        "inertia/structuring/condition_lowering.py",
        "inertia/semantics/compiler_helpers.py",
        "inertia/ir/analysis/alias.py",
        "inertia/pipeline/errors.py",
        "inertia/ir/address_ir_8616.py",
        "inertia/frontend/x86_16/lift_86_16.py",
    }.isdisjoint(paths)
    # IR additions must remain cache dependencies; a fixed file count is not
    # an architectural boundary. Reject downstream layer ownership directly.
    downstream_layers = {"alias", "widening", "lowering", "structuring", "postprocess"}
    for source in paths:
        assert downstream_layers.isdisjoint(Path(source).parts), source


def test_declared_frontend_changes_invalidate_key_but_unlisted_changes_do_not(
    tmp_path, monkeypatch,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    declared = tmp_path / "dependency.py"
    declared.write_text("# original dependency\n")
    unrelated = declared.with_name("unrelated.py")
    unrelated.write_text("# unrelated\n")
    monkeypatch.setattr(
        identity, "FUNCTION_IR_SSA_CACHE_SOURCE_FILES",
        (declared,),
    )
    node = _Node(0x1000, 2)
    function = _Function(0x1000, {0x1000}, _Graph((node,)))

    def fresh_key():
        # Source hashes are memoized for one frozen-source process; clearing
        # models the next process after an edit without asserting a layout.
        identity._cache_source_digest.cache_clear()
        return identity.function_ir_ssa_cache_key_8616(_Project(), function)

    try:
        original = fresh_key()
        assert original is not None
        unrelated.write_text("# unrelated edit\n")
        assert fresh_key() == original
        declared.write_text("# changed dependency\n")
        assert fresh_key() != original
    finally:
        identity._cache_source_digest.cache_clear()


def test_function_ir_ssa_key_uses_versioned_exact_source_scope(
    monkeypatch,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    observed: list[tuple[Path, ...]] = []

    def record_sources(paths: tuple[Path, ...]) -> str:
        observed.append(paths)
        return "exact-source-digest"

    monkeypatch.setattr(identity, "_cache_source_digest", record_sources)
    node = _Node(0x1000, 2)
    key = identity.function_ir_ssa_cache_key_8616(
        _Project(),
        _Function(0x1000, {0x1000}, _Graph((node,))),
    )

    assert key is not None
    assert key["schema"] == 2
    assert key["source_sha256"] == "exact-source-digest"
    assert observed == [FUNCTION_IR_SSA_CACHE_SOURCE_FILES]

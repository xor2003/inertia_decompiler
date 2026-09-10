from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import inertia_decompiler.function_ir_ssa_cache_identity as identity
from inertia_decompiler.cache_source_manifest import (
    FUNCTION_IR_SSA_CACHE_SOURCE_FILES,
)

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
            _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "ir"
        ).rglob("*.py")
    }

    assert ir_paths <= paths
    assert {
        "pyvex_compat.py",
        "angr_platforms/angr_platforms/X86_16/frontend_block_inventory.py",
        "angr_platforms/angr_platforms/X86_16/frontend_capstone_decode.py",
        "angr_platforms/angr_platforms/X86_16/lift_86_16.py",
        "angr_platforms/angr_platforms/X86_16/direction_step.py",
        "angr_platforms/angr_platforms/X86_16/analysis/alias.py",
        "angr_platforms/angr_platforms/X86_16/analysis/stack_frame_ir.py",
        "angr_platforms/angr_platforms/X86_16/semantics/status_flag_liveness.py",
    } <= paths
    assert {
        "angr_platforms/angr_platforms/X86_16/callsite_summary.py",
        "angr_platforms/angr_platforms/X86_16/analysis_helpers.py",
        "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py",
        "angr_platforms/angr_platforms/X86_16/lowering/register_local_declarations.py",
        "angr_platforms/angr_platforms/X86_16/structuring/condition_lowering.py",
    }.isdisjoint(paths)
    assert len(paths) < 150


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

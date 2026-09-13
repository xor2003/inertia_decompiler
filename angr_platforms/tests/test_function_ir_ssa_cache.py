from __future__ import annotations

import base64
import hashlib
import pickle
from dataclasses import dataclass
from pathlib import Path

import pytest
from angr_platforms.X86_16.ir.core import IRBlock, IRCallStackEffect8616, IRInstr
from angr_platforms.X86_16.ir.function_artifact import IRFunctionArtifact
from angr_platforms.X86_16.ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    function_ssa_artifact_for_boundary_8616,
    publish_function_ssa_artifact_8616,
    registered_function_ssa_artifact_8616,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa

import inertia_decompiler.cache as cache_module
import inertia_decompiler.function_ir_ssa_cache as ir_ssa_cache
import inertia_decompiler.function_ir_ssa_cache_codec as ir_ssa_codec
from inertia_decompiler.function_ir_ssa_cache import (
    FunctionIRSSABundle8616,
    FunctionIRSSACacheFailure8616,
    FunctionIRSSACacheVerdict8616,
    function_ir_ssa_cache_key_8616,
    hydrate_function_ir_ssa_catalog_8616,
    load_function_ir_ssa_cache_8616,
    store_function_ir_ssa_cache_8616,
    store_function_ir_ssa_catalog_8616,
)
from inertia_decompiler.function_ir_ssa_cache_codec import (
    function_ir_ssa_bundle_from_record_8616,
    function_ir_ssa_bundle_record_8616,
)


@pytest.mark.parametrize("bp_preserved", [False, True])
def test_call_frame_register_proof_survives_ir_cache_transport(bp_preserved):
    effect = IRCallStackEffect8616(net_stack_delta=0, complete=True, bp_preserved=bp_preserved)
    ir = IRFunctionArtifact(0x1000, (IRBlock(0x1000, (
        IRInstr("CALL", None, (), addr=0x1000, call_stack_effect=effect),
    )),))
    bundle = FunctionIRSSABundle8616(ir, build_x86_16_function_ssa(ir))
    record = function_ir_ssa_bundle_record_8616(bundle)

    restored = function_ir_ssa_bundle_from_record_8616(record, ir.function_addr)

    assert restored.ir.blocks[0].instrs[0].call_stack_effect == effect
    assert effect.to_dict()["bp_preserved"] is bp_preserved


def test_ir_cache_rejects_schema_before_frame_register_proofs():
    record = function_ir_ssa_bundle_record_8616(_bundle(0x1000))
    record["schema"] = 3

    with pytest.raises(ValueError, match="unsupported function IR/SSA cache schema"):
        function_ir_ssa_bundle_from_record_8616(record, 0x1000)


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
    def __init__(self, values: dict[int, int]) -> None:
        self.values = dict(values)

    def load(self, addr: int, size: int) -> bytes:
        return bytes(self.values[addr + offset] for offset in range(size))


@dataclass(frozen=True)
class _Arch:
    name: str = "86_16"
    bits: int = 32
    memory_endness: str = "Iend_LE"


@dataclass(frozen=True)
class _Loader:
    memory: _Memory


class _Project:
    def __init__(self, values: dict[int, int]) -> None:
        self.arch = _Arch()
        self.loader = _Loader(_Memory(values))


def _function(addr: int, data: bytes) -> tuple[_Function, dict[int, int]]:
    node = _Node(addr, len(data))
    values = {addr + offset: value for offset, value in enumerate(data)}
    return _Function(addr, {addr}, _Graph((node,))), values


def _bundle(function_addr: int) -> FunctionIRSSABundle8616:
    ir = IRFunctionArtifact(
        function_addr,
        blocks=(IRBlock(function_addr),),
    )
    return FunctionIRSSABundle8616(ir, build_x86_16_function_ssa(ir))


def _enable_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(
        cache_module,
        "DECOMPILATION_CACHE_DIR",
        tmp_path / "cache",
    )


def test_function_cache_key_invalidates_only_changed_function_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _enable_cache(monkeypatch, tmp_path)
    first, first_values = _function(0x1000, b"\x90\xc3")
    second, second_values = _function(0x2000, b"\x55\xc3")
    original = _Project({**first_values, **second_values, 0x3000: 0xAA})
    unrelated_changed = _Project(
        {**first_values, **second_values, 0x3000: 0xBB}
    )
    first_changed = _Project(
        {**first_values, **second_values, 0x1000: 0xCC, 0x3000: 0xAA}
    )

    first_key = function_ir_ssa_cache_key_8616(original, first)
    second_key = function_ir_ssa_cache_key_8616(original, second)

    assert first_key is not None
    assert second_key is not None
    assert function_ir_ssa_cache_key_8616(unrelated_changed, first) == first_key
    assert function_ir_ssa_cache_key_8616(unrelated_changed, second) == second_key
    assert function_ir_ssa_cache_key_8616(first_changed, first) != first_key
    assert function_ir_ssa_cache_key_8616(first_changed, second) == second_key


def test_function_cache_key_includes_exact_cfg_edges(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _enable_cache(monkeypatch, tmp_path)
    first = _Node(0x1000, 1)
    second = _Node(0x1001, 1)
    values = {0x1000: 0x90, 0x1001: 0xC3}
    connected = _Function(
        0x1000,
        {0x1000, 0x1001},
        _Graph((first, second), ((first, second),)),
    )
    disconnected = _Function(
        0x1000,
        {0x1000, 0x1001},
        _Graph((first, second)),
    )

    assert function_ir_ssa_cache_key_8616(
        _Project(values), connected
    ) != function_ir_ssa_cache_key_8616(_Project(values), disconnected)


def test_function_ir_ssa_codec_is_deterministic_and_round_trips(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _enable_cache(monkeypatch, tmp_path)
    function, values = _function(0x1000, b"\x90\xc3")
    cache_key = function_ir_ssa_cache_key_8616(_Project(values), function)
    assert cache_key is not None
    bundle = _bundle(function.addr)
    ssa_build_count = 0
    original_ssa_builder = ir_ssa_codec.build_x86_16_function_ssa

    def build_ssa(artifact: IRFunctionArtifact):
        nonlocal ssa_build_count
        ssa_build_count += 1
        return original_ssa_builder(artifact)

    monkeypatch.setattr(ir_ssa_codec, "build_x86_16_function_ssa", build_ssa)

    first_record = function_ir_ssa_bundle_record_8616(bundle)
    second_record = function_ir_ssa_bundle_record_8616(bundle)
    stored = store_function_ir_ssa_cache_8616(cache_key, bundle)
    restored = load_function_ir_ssa_cache_8616(cache_key, function.addr)

    assert first_record == second_record
    assert "projection_sha256" not in first_record
    assert isinstance(
        pickle.loads(base64.b64decode(str(first_record["payload"]))),
        IRFunctionArtifact,
    )
    assert stored.verdict is FunctionIRSSACacheVerdict8616.STORED
    assert restored.verdict is FunctionIRSSACacheVerdict8616.HIT
    assert restored.bundle == bundle
    assert ssa_build_count == 1


def test_function_ir_ssa_cache_rejects_class_outside_ir_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pickle.dumps(eval, protocol=5)
    record = {
        "schema": function_ir_ssa_bundle_record_8616(_bundle(0x1000))["schema"],
        "payload": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    monkeypatch.setattr(ir_ssa_cache, "_load_cache_json", lambda *_args: record)

    result = load_function_ir_ssa_cache_8616({}, 0x1000)

    assert result.verdict is FunctionIRSSACacheVerdict8616.REFUSED
    assert result.failure is FunctionIRSSACacheFailure8616.MALFORMED_ENTRY


def test_function_ir_ssa_cache_rejects_payload_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = function_ir_ssa_bundle_record_8616(_bundle(0x1000))
    record["payload_sha256"] = "invalid"
    monkeypatch.setattr(ir_ssa_cache, "_load_cache_json", lambda *_args: record)

    result = load_function_ir_ssa_cache_8616({}, 0x1000)

    assert result.verdict is FunctionIRSSACacheVerdict8616.REFUSED
    assert result.failure is FunctionIRSSACacheFailure8616.MALFORMED_ENTRY


def test_catalog_hydration_prevents_ir_and_ssa_rebuild(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _enable_cache(monkeypatch, tmp_path)
    function, values = _function(0x1000, b"\x90\xc3")
    source_project = _Project(values)
    bundle = _bundle(function.addr)
    assert (
        publish_function_ir_artifact_8616(source_project, bundle.ir).verdict
        is FunctionIRArtifactVerdict8616.PROVEN
    )
    assert (
        publish_function_ssa_artifact_8616(
            source_project,
            bundle.ssa,
            FunctionSSAArtifactStage8616.IR,
        ).verdict
        is FunctionSSAArtifactVerdict8616.PROVEN
    )
    stored = store_function_ir_ssa_catalog_8616(source_project, (function,))
    assert stored.stats.closed
    assert stored.stats.materialized_count == 1

    restored_project = _Project(values)
    hydrated = hydrate_function_ir_ssa_catalog_8616(
        restored_project,
        (function,),
    )
    assert hydrated.stats.closed
    assert hydrated.stats.materialized_count == 1
    assert (
        registered_function_ir_artifact_8616(
            restored_project,
            function.addr,
        ).artifact
        == bundle.ir
    )
    assert (
        registered_function_ssa_artifact_8616(
            restored_project,
            function.addr,
        ).artifact
        == bundle.ssa
    )

    monkeypatch.setattr(
        "angr_platforms.X86_16.ir.function_ssa_registry.build_x86_16_ir_function_artifact",
        lambda *_args: pytest.fail("valid hydration must prevent VEX rebuilding"),
    )
    resolution = function_ssa_artifact_for_boundary_8616(
        restored_project,
        function.addr,
        function,
    )
    assert resolution.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    assert resolution.artifact == bundle.ssa

    monkeypatch.setattr(
        ir_ssa_cache,
        "function_ir_ssa_bundle_record_8616",
        lambda *_args: pytest.fail("hydrated hits must not be serialized again"),
    )
    retained = store_function_ir_ssa_catalog_8616(
        restored_project,
        (function,),
        already_hydrated=hydrated,
    )
    assert retained.stats.closed
    assert retained.results[0].verdict is FunctionIRSSACacheVerdict8616.HIT

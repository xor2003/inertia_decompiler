from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from inertia.ir.condition_cache_relift import (
    ConditionCacheReliftFailureReason8616,
    ConditionReliftBlock8616,
    relift_function_condition_cache_8616,
)
from inertia.ir.condition_cache_relift_cache import (
    ConditionReliftArtifactCache8616,
    ConditionReliftCacheRequest8616,
)
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from pytest import MonkeyPatch

from inertia.cli.project_loading import _build_project
from tools.dev.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"
SLEEP_BLOCK_ADDRS = (
    0x10F38,
    0x10F41,
    0x10F46,
    0x10F52,
    0x10F55,
    0x10F5A,
    0x10F5D,
    0x10F5F,
    0x10F62,
    0x10F67,
    0x10F6A,
    0x10F6D,
)
SLEEP_CONDITION_BLOCKS = frozenset({0x10F55, 0x10F5D, 0x10F62})


def test_exact_relift_cache_requires_same_bytes_and_architecture(monkeypatch: MonkeyPatch) -> None:
    from inertia.ir import condition_cache_relift as relift
    from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY

    block_addr = 0x2200
    payload = bytearray(b"\x90\x90")
    arch = object()
    lifts: list[tuple[bytes, object]] = []
    condition = ConditionIR(
        "ne",
        "ax",
        0,
        source=("cmp", "jne"),
        src_insn=block_addr,
        block_addr=block_addr,
    )

    def load(_address: int, size: int) -> bytes:
        return bytes(payload[:size])

    def direct_lift(data: bytes, address: int, architecture: object) -> None:
        lifts.append((data, architecture))
        Instruction_ANY._inertia_module_condition_cache[address] = [condition]

    project = SimpleNamespace(arch=arch, loader=SimpleNamespace(memory=SimpleNamespace(load=load)))
    blocks = (ConditionReliftBlock8616(block_addr, 2),)
    expected = frozenset({block_addr})
    monkeypatch.setattr(relift, "_direct_lift_8616", direct_lift)

    first = relift_function_condition_cache_8616(project, blocks, expected)
    second = relift_function_condition_cache_8616(project, blocks, expected)
    payload[0] = 0x91
    changed_bytes = relift_function_condition_cache_8616(project, blocks, expected)
    project.arch = object()
    changed_arch = relift_function_condition_cache_8616(project, blocks, expected)

    assert first is not None and first.stats.complete
    assert second is first
    assert changed_bytes is not first
    assert changed_arch is not changed_bytes
    assert lifts == [(b"\x90\x90", arch), (b"\x91\x90", arch), (b"\x91\x90", project.arch)]


def test_exact_relift_cache_reuses_typed_missing_condition_refusals(monkeypatch: MonkeyPatch) -> None:
    from inertia.ir import condition_cache_relift as relift

    lifts: list[int] = []
    project = SimpleNamespace(
        arch=object(),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _address, size: bytes(size))),
    )
    blocks = (ConditionReliftBlock8616(0x2300, 2),)
    monkeypatch.setattr(relift, "_direct_lift_8616", lambda _data, address, _arch: lifts.append(address))

    first = relift_function_condition_cache_8616(project, blocks, frozenset({0x2300}))
    second = relift_function_condition_cache_8616(project, blocks, frozenset({0x2300}))

    assert first is not None and not first.stats.complete
    assert second is first
    assert first.failures[0].reason is ConditionCacheReliftFailureReason8616.EXPECTED_CONDITION_MISSING
    assert lifts == [0x2300]


def test_exact_relift_cache_refuses_vex_lift_failures(monkeypatch: MonkeyPatch) -> None:
    from inertia.ir import condition_cache_relift as relift

    lifts: list[int] = []
    project = SimpleNamespace(
        arch=object(),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _address, size: bytes(size))),
    )
    blocks = (ConditionReliftBlock8616(0x2400, 2),)

    def fail_lift(_data: bytes, address: int, _arch: object) -> None:
        lifts.append(address)
        msg = "synthetic lift failure"
        raise RuntimeError(msg)

    monkeypatch.setattr(relift, "_direct_lift_8616", fail_lift)

    first = relift_function_condition_cache_8616(project, blocks, frozenset({0x2400}))
    second = relift_function_condition_cache_8616(project, blocks, frozenset({0x2400}))

    assert first is not None and not first.stats.complete
    assert second is not None and not second.stats.complete
    assert first.failures[0].reason is ConditionCacheReliftFailureReason8616.VEX_LIFT_FAILED
    assert second.failures[0].reason is ConditionCacheReliftFailureReason8616.VEX_LIFT_FAILED
    assert lifts == [0x2400, 0x2400]


def test_exact_relift_cache_evicts_oldest_entry() -> None:
    cache = ConditionReliftArtifactCache8616[str](max_entries=2)
    arch = object()
    requests = tuple(
        ConditionReliftCacheRequest8616(((address, 1, bytes([address])),), frozenset())
        for address in range(3)
    )

    for index, request in enumerate(requests):
        cache.publish(arch, request, str(index))

    assert cache.lookup(arch, requests[0]) is None
    assert cache.lookup(arch, requests[1]) == "1"
    assert cache.lookup(arch, requests[2]) == "2"


def test_exact_relift_refuses_missing_expected_condition_and_restores_lifter_state(monkeypatch) -> None:
    from inertia.ir import condition_cache_relift as relift
    from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY

    condition_cache: dict[int, list[ConditionIR]] = {0x2000: []}
    pending_sources: dict[int, object] = {}
    affine_state: dict[str, object] = {"sentinel": object()}
    affine_snapshots: dict[int, object] = {0x2000: object()}
    index_state: dict[str, object] = {"sentinel": object()}
    value_state: dict[tuple[int, str], object] = {(0x2000, "ax"): object()}
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", condition_cache)
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", pending_sources)
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_affine_state_8616", affine_state)
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_affine_state_snapshots_8616", affine_snapshots)
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_index_reg_state_8616", index_state)
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", value_state)
    monkeypatch.setattr(relift, "_direct_lift_8616", lambda *_args: None)
    project = SimpleNamespace(
        arch=object(),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _addr, size: bytes(size))),
    )

    artifact = relift_function_condition_cache_8616(
        project,
        (ConditionReliftBlock8616(0x1000, 2),),
        frozenset({0x1000}),
    )

    assert artifact is not None
    assert not artifact.stats.complete
    assert artifact.stats.raw_fact_count == 1
    assert artifact.stats.classified_fact_count == 1
    assert artifact.stats.materialized_count == 0
    assert artifact.stats.failure_count == 1
    assert artifact.failures[0].reason is ConditionCacheReliftFailureReason8616.EXPECTED_CONDITION_MISSING
    assert Instruction_ANY._inertia_module_condition_cache is condition_cache
    assert Instruction_ANY._inertia_pending_condition_sources_by_addr is pending_sources
    assert Instruction_ANY._inertia_condition_reg_affine_state_8616 is affine_state
    assert Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 is affine_snapshots
    assert Instruction_ANY._inertia_condition_index_reg_state_8616 is index_state
    assert Instruction_ANY._inertia_condition_reg_value_state_8616 is value_state


def test_sortd_sleep_exact_relift_recovers_all_condition_owners_after_empty_cache(tmp_path: Path) -> None:
    from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY

    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))
    project = _build_project(isolated_binary, force_blob=False, base_addr=0x1000, entry_point=0x1000)
    blocks = tuple(
        ConditionReliftBlock8616(address, int(project.factory.block(address, opt_level=0).size))
        for address in SLEEP_BLOCK_ADDRS
    )
    original_cache = Instruction_ANY._inertia_module_condition_cache
    original_pending = Instruction_ANY._inertia_pending_condition_sources_by_addr
    poisoned_cache: dict[int, list[ConditionIR]] = {address: [] for address in SLEEP_CONDITION_BLOCKS}
    Instruction_ANY._inertia_module_condition_cache = poisoned_cache
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {}
    try:
        artifact = relift_function_condition_cache_8616(project, blocks, SLEEP_CONDITION_BLOCKS)
    finally:
        restored_cache = Instruction_ANY._inertia_module_condition_cache
        restored_pending = Instruction_ANY._inertia_pending_condition_sources_by_addr
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert artifact is not None
    assert artifact.stats.complete
    assert artifact.stats.raw_fact_count == 3
    assert artifact.stats.materialized_count == 3
    assert artifact.stats.failure_count == 0
    cache = artifact.condition_cache()
    assert {address: [condition.op for condition in cache[address]] for address in SLEEP_CONDITION_BLOCKS} == {
        0x10F55: ["sle"],
        0x10F5D: ["sge"],
        0x10F62: ["ule"],
    }
    assert restored_cache is poisoned_cache
    assert restored_pending == {}


def test_transfer_refreshes_empty_condition_owner_cache_without_pending_evidence() -> None:
    from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY

    condition = ConditionIR(
        "ne",
        IRValue(MemSpace.REG, name="ax", size=2),
        IRValue(MemSpace.CONST, const=0, size=2),
        source=("cmp", "jne"),
        src_insn=0x4014,
        block_addr=0x4010,
        taken_target=0x4020,
        fallthrough_target=0x4016,
    )
    terminal = SimpleNamespace(
        address=0x4014,
        size=2,
        mnemonic="jne",
        operands=(SimpleNamespace(imm=0x4020),),
    )
    function = SimpleNamespace(
        block_addrs_set={0x4010},
        blocks=(SimpleNamespace(addr=0x4010, capstone=SimpleNamespace(insns=(SimpleNamespace(insn=terminal),))),),
        graph=None,
    )
    relifted: list[int] = []

    def lift_block(address: int, **_kwargs: object) -> None:
        relifted.append(address)
        Instruction_ANY._inertia_module_condition_cache[address] = [condition]

    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)),
        factory=SimpleNamespace(block=lift_block),
    )
    original_cache = Instruction_ANY._inertia_module_condition_cache
    original_pending = Instruction_ANY._inertia_pending_condition_sources_by_addr
    Instruction_ANY._inertia_module_condition_cache = {0x4010: []}
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {}
    try:
        codegen = SimpleNamespace()
        transferred = transfer_typed_conditions_to_codegen_8616(project, 0x4010, codegen)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert relifted == [0x4010]
    assert transferred == 1
    assert codegen._inertia_typed_conditions == [condition]


def test_transfer_rejects_complete_ambient_cache_from_rebased_sibling(monkeypatch: MonkeyPatch) -> None:
    from inertia.ir import condition_cache_relift as relift
    from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY

    def condition(lhs: str) -> ConditionIR:
        return ConditionIR(
            "ne",
            lhs,
            2,
            source=("cmp", "jne"),
            src_insn=0x4014,
            block_addr=0x4010,
            taken_target=0x4020,
            fallthrough_target=0x4016,
        )

    stale = condition("sibling")
    current = condition("current")
    terminal = SimpleNamespace(
        address=0x4014,
        size=2,
        mnemonic="jne",
        operands=(SimpleNamespace(imm=0x4020),),
    )
    block = SimpleNamespace(
        addr=0x4010,
        size=6,
        capstone=SimpleNamespace(insns=(SimpleNamespace(insn=terminal),)),
    )
    function = SimpleNamespace(block_addrs_set={0x4010}, blocks=(block,), graph=None)
    project = SimpleNamespace(
        arch=object(),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _addr, size: bytes(size))),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)),
    )

    def direct_lift(_data: bytes, address: int, _arch: object) -> None:
        Instruction_ANY._inertia_module_condition_cache[address] = [current]

    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {0x4010: [stale]})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(relift, "_direct_lift_8616", direct_lift)

    codegen = SimpleNamespace()
    transferred = transfer_typed_conditions_to_codegen_8616(project, 0x4010, codegen)

    assert transferred == 1
    assert codegen._inertia_typed_conditions == [current]
    assert Instruction_ANY._inertia_module_condition_cache == {0x4010: [stale]}

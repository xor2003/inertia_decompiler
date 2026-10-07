from __future__ import annotations

from types import SimpleNamespace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_cache_relift import (
    ConditionReliftBlock8616,
    relift_function_condition_cache_8616,
)
from inertia.ir.condition_cache_relift_cache import (
    ConditionReliftArtifactCache8616,
    ConditionReliftCacheRequest8616,
)
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from pytest import MonkeyPatch


class _EquivalentLiftArchitecture:
    """Test boundary with explicit equivalent lift semantics."""

    def __init__(self, bits: int) -> None:
        self.bits = bits

    def lifting_semantics_key_8616(self) -> tuple[object, ...]:
        """Return the exact test lift configuration."""
        return type(self), self.bits


def _request() -> ConditionReliftCacheRequest8616:
    """Return one exact immutable relift request."""
    return ConditionReliftCacheRequest8616(
        ((0x1000, 2, b"\x90\x90"),),
        frozenset({0x1000}),
    )


def test_relift_cache_reuses_equivalent_owned_architectures() -> None:
    cache = ConditionReliftArtifactCache8616[str](max_entries=2)
    request = _request()

    cache.publish(_EquivalentLiftArchitecture(16), request, "artifact")

    assert cache.lookup(_EquivalentLiftArchitecture(16), request) == "artifact"
    assert cache.lookup(_EquivalentLiftArchitecture(32), request) is None


def test_relift_cache_keeps_identity_for_unknown_architectures() -> None:
    cache = ConditionReliftArtifactCache8616[str](max_entries=2)
    request = _request()
    first = object()

    cache.publish(first, request, "artifact")

    assert cache.lookup(first, request) == "artifact"
    assert cache.lookup(object(), request) is None


def test_x86_16_lift_key_distinguishes_semantic_runtime_configuration(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.delenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", raising=False)
    first = Arch86_16()
    equivalent = Arch86_16()
    widened = Arch86_16()
    widened.bits = 32

    assert first.lifting_semantics_key_8616() == equivalent.lifting_semantics_key_8616()
    assert first.lifting_semantics_key_8616() != widened.lifting_semantics_key_8616()
    baseline_key = first.lifting_semantics_key_8616()
    monkeypatch.setenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", "1")
    assert first.lifting_semantics_key_8616() != baseline_key


def test_exact_relift_reuses_artifact_across_equivalent_x86_16_arches(
    monkeypatch: MonkeyPatch,
) -> None:
    from inertia.ir import condition_cache_relift as relift
    from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY

    block_addr = 0x7E10
    lifts: list[int] = []
    condition = ConditionIR(
        "ne",
        IRValue(MemSpace.REG, name="ax", size=2),
        IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=block_addr,
        block_addr=block_addr,
    )

    def direct_lift(_data: bytes, address: int, _arch: object) -> None:
        """Publish one complete condition as the custom lifter would."""
        lifts.append(address)
        Instruction_ANY._inertia_module_condition_cache[address] = [condition]

    monkeypatch.setattr(relift, "_direct_lift_8616", direct_lift)
    memory = SimpleNamespace(load=lambda _address, size: bytes(size))
    first_project = SimpleNamespace(
        arch=Arch86_16(), loader=SimpleNamespace(memory=memory)
    )
    second_project = SimpleNamespace(
        arch=Arch86_16(), loader=SimpleNamespace(memory=memory)
    )
    blocks = (ConditionReliftBlock8616(block_addr, 2),)
    expected = frozenset({block_addr})

    first = relift_function_condition_cache_8616(first_project, blocks, expected)
    second = relift_function_condition_cache_8616(second_project, blocks, expected)

    assert first is not None and first.stats.complete
    assert second is first
    assert lifts == [block_addr]

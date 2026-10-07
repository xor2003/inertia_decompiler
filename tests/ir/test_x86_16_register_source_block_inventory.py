"""Tests for immutable register-source CFG input reuse."""

from __future__ import annotations

from types import SimpleNamespace

from inertia.semantics.register_source_block_inventory import (
    collect_register_source_block_inventory_8616,
)


class _Graph:
    def __init__(self, nodes: tuple[object, ...]) -> None:
        self.nodes = nodes
        self.predecessor_map: dict[int, tuple[object, ...]] = {}

    def predecessors(self, node: object) -> tuple[object, ...]:
        return self.predecessor_map.get(node.addr, ())


class _Factory:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, int]] = []

    def block(self, addr: int, *, size: int, opt_level: int) -> object:
        self.calls.append((addr, size, opt_level))
        instruction = SimpleNamespace(address=addr, mnemonic="nop")
        return SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)))


def test_inventory_reuses_decode_until_cfg_generation_changes() -> None:
    first = SimpleNamespace(addr=0x1000, size=2)
    second = SimpleNamespace(addr=0x1002, size=2)
    graph = _Graph((first, second))
    graph.predecessor_map[0x1002] = (first,)
    factory = _Factory()
    project = SimpleNamespace(factory=factory)
    function = SimpleNamespace(
        addr=0x1000,
        size=4,
        blocks=(first, second),
        block_addrs_set={0x1000, 0x1002},
        graph=graph,
        project=project,
    )

    initial = collect_register_source_block_inventory_8616(function)
    repeated = collect_register_source_block_inventory_8616(function)

    assert initial.complete
    assert repeated == initial
    assert factory.calls == [(0x1000, 2, 0), (0x1002, 2, 0)]
    assert initial.blocks[1].predecessors == (0x1000,)

    graph.predecessor_map[0x1002] = ()
    changed = collect_register_source_block_inventory_8616(function)

    assert changed.complete
    assert changed.blocks[1].predecessors == ()
    assert factory.calls == [
        (0x1000, 2, 0),
        (0x1002, 2, 0),
        (0x1000, 2, 0),
        (0x1002, 2, 0),
    ]


def test_inventory_refuses_missing_cfg_block_owner() -> None:
    node = SimpleNamespace(addr=0x1000, size=2)
    graph = _Graph((node,))
    factory = _Factory()
    project = SimpleNamespace(factory=factory)
    function = SimpleNamespace(
        addr=0x1000,
        size=4,
        blocks=(node,),
        block_addrs_set={0x1000, 0x1002},
        graph=graph,
        project=project,
    )

    inventory = collect_register_source_block_inventory_8616(function)

    assert not inventory.complete
    assert inventory.failure_count == 1
    assert factory.calls == [(0x1000, 2, 0)]

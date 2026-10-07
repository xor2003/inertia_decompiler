from __future__ import annotations

from inertia.frontend.x86_16.frontend_capstone_decode import DirectCapstoneBlock8616
from inertia.cli.cli_function_discovery import _collect_stitched_blocks_and_edges_8616
from inertia.cli.project_loading import _build_project_from_bytes


def test_stitched_discovery_uses_direct_blocks_without_vex(monkeypatch) -> None:
    base = 0x3000
    project = _build_project_from_bytes(
        bytes.fromhex("750290c3c3"),
        base_addr=base,
        entry_point=base,
    )

    def refuse_vex(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("closed direct discovery must not enter VEX")

    monkeypatch.setattr(project.factory, "block", refuse_vex)

    blocks, edges = _collect_stitched_blocks_and_edges_8616(
        project,
        base,
        base,
        base + 5,
    )

    assert tuple(blocks) == (base, base + 2, base + 4)
    assert all(isinstance(block, DirectCapstoneBlock8616) for block in blocks.values())
    assert blocks[base].bytes == bytes.fromhex("7502")
    assert blocks[base].capstone.insns == blocks[base].instructions
    assert edges == {(base, base + 2), (base, base + 4)}


def test_stitched_discovery_falls_back_when_direct_decode_refuses(monkeypatch) -> None:
    base = 0x4000
    project = _build_project_from_bytes(b"\xf4", base_addr=base, entry_point=base)
    factory_block = project.factory.block
    factory_calls = 0

    def count_vex(*args: object, **kwargs: object) -> object:
        nonlocal factory_calls
        factory_calls += 1
        return factory_block(*args, **kwargs)

    monkeypatch.setattr(project.factory, "block", count_vex)

    blocks, edges = _collect_stitched_blocks_and_edges_8616(
        project,
        base,
        base,
        base + 1,
    )

    assert factory_calls == 1
    assert tuple(blocks) == (base,)
    assert not isinstance(blocks[base], DirectCapstoneBlock8616)
    assert edges == set()

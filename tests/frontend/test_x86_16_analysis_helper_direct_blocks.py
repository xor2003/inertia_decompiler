from __future__ import annotations

from inertia.frontend.x86_16.frontend_capstone_block import DirectCapstoneBlock8616
from inertia.lowering.analysis_helpers import (
    _analysis_project_block_8616,
    resolve_direct_call_target_from_block,
)
from inertia.cli.project_loading import _build_project_from_bytes


def test_analysis_helper_uses_direct_frontend_block_without_vex(monkeypatch) -> None:
    base = 0x3000
    project = _build_project_from_bytes(
        bytes.fromhex("e80100c3c3"),
        base_addr=base,
        entry_point=base,
    )

    def refuse_vex(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("Capstone-only analysis helper must not enter VEX")

    monkeypatch.setattr(project.factory, "block", refuse_vex)

    block = _analysis_project_block_8616(project, base)

    assert isinstance(block, DirectCapstoneBlock8616)
    assert resolve_direct_call_target_from_block(project, base) == base + 4


def test_analysis_helper_retains_vex_fallback_for_direct_refusal(monkeypatch) -> None:
    base = 0x4000
    project = _build_project_from_bytes(b"\xf4", base_addr=base, entry_point=base)
    factory_block = project.factory.block
    factory_calls = 0

    def count_vex(*args: object, **kwargs: object) -> object:
        nonlocal factory_calls
        factory_calls += 1
        return factory_block(*args, **kwargs)

    monkeypatch.setattr(project.factory, "block", count_vex)

    block = _analysis_project_block_8616(project, base)

    assert not isinstance(block, DirectCapstoneBlock8616)
    assert factory_calls == 1

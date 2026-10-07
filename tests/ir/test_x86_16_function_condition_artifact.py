from __future__ import annotations

from inertia.ir.condition_cache_relift import (
    ConditionCacheReliftArtifact8616,
    ConditionCacheReliftStats8616,
    ConditionReliftBlock8616,
)
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRValue, MemSpace
from inertia.ir.function_condition_artifact import (
    build_ir_function_condition_artifact_8616,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa
from pytest import MonkeyPatch


def test_condition_artifact_clips_overlap_and_survives_ssa(
    monkeypatch: MonkeyPatch,
) -> None:
    import inertia.ir.function_condition_artifact as owner

    condition = ConditionIR(
        "ult",
        IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
        IRValue(MemSpace.CONST, const=4, size=2),
        block_addr=0x100,
        src_insn=0x102,
        producer_insn=0x100,
        taken_target=0x104,
        fallthrough_target=0x108,
    )
    captured: list[tuple[ConditionReliftBlock8616, ...]] = []

    def relift(
        _project: object,
        blocks: tuple[ConditionReliftBlock8616, ...],
        expected: frozenset[int],
    ) -> ConditionCacheReliftArtifact8616:
        captured.append(blocks)
        assert expected == frozenset({0x100})
        return ConditionCacheReliftArtifact8616(
            tuple(
                (block.address, (condition,) if block.address == 0x100 else ())
                for block in blocks
            ),
            (),
            (),
            ConditionCacheReliftStats8616(1, 1, 1, 1, 0),
        )

    monkeypatch.setattr(owner, "relift_function_condition_cache_8616", relift)
    blocks = (
        IRBlock(0x100, successor_addrs=(0x104, 0x108)),
        IRBlock(0x104, successor_addrs=(0x108,)),
        IRBlock(0x108),
    )
    evidence = build_ir_function_condition_artifact_8616(
        object(),
        0x100,
        (
            ConditionReliftBlock8616(0x100, 8),
            ConditionReliftBlock8616(0x104, 4),
            ConditionReliftBlock8616(0x108, 2),
        ),
        blocks,
    )

    assert evidence is not None
    assert evidence.complete
    assert captured[0][0] == ConditionReliftBlock8616(0x100, 4)
    assert evidence.conditions_for_block(0x100) == (condition,)
    function = IRFunctionArtifact(0x100, blocks, condition_evidence=evidence)
    ssa = build_x86_16_function_ssa(function)
    assert ssa.condition_evidence is evidence
    serialized = ssa.to_dict()["condition_evidence"]
    assert isinstance(serialized, dict)
    assert serialized["complete"] is True
    assert serialized["expected_condition_blocks"] == [0x100]


def test_condition_artifact_refuses_missing_expected_owner(
    monkeypatch: MonkeyPatch,
) -> None:
    import inertia.ir.function_condition_artifact as owner

    monkeypatch.setattr(
        owner,
        "relift_function_condition_cache_8616",
        lambda _project, blocks, _expected: ConditionCacheReliftArtifact8616(
            tuple((block.address, ()) for block in blocks),
            (),
            (),
            ConditionCacheReliftStats8616(1, 1, 1, 0, 1),
        ),
    )
    evidence = build_ir_function_condition_artifact_8616(
        object(),
        0x100,
        (ConditionReliftBlock8616(0x100, 2),),
        (IRBlock(0x100, successor_addrs=(0x102, 0x104)),),
    )

    assert evidence is not None
    assert not evidence.complete
    assert evidence.conditions_for_block(0x100) == ()


def test_condition_artifact_uses_only_complete_matching_capture(
    monkeypatch: MonkeyPatch,
) -> None:
    import inertia.ir.function_condition_artifact as owner

    condition = ConditionIR(
        "ne",
        "ax",
        0,
        src_insn=0x100,
        block_addr=0x100,
    )
    captured = ConditionCacheReliftArtifact8616(
        ((0x100, (condition,)),),
        (),
        (),
        ConditionCacheReliftStats8616(1, 1, 1, 1, 0),
    )
    monkeypatch.setattr(
        owner,
        "relift_function_condition_cache_8616",
        lambda *_args: (_ for _ in ()).throw(AssertionError("unexpected relift")),
    )

    evidence = build_ir_function_condition_artifact_8616(
        object(),
        0x100,
        (ConditionReliftBlock8616(0x100, 2),),
        (IRBlock(0x100, successor_addrs=(0x102, 0x104)),),
        captured,
    )

    assert evidence is not None
    assert evidence.complete
    assert evidence.source is captured


def test_condition_artifact_relifts_incomplete_capture(
    monkeypatch: MonkeyPatch,
) -> None:
    import inertia.ir.function_condition_artifact as owner

    incomplete = ConditionCacheReliftArtifact8616(
        ((0x100, ()),),
        (),
        (),
        ConditionCacheReliftStats8616(0, 0, 0, 0, 0),
    )
    replacement = ConditionCacheReliftArtifact8616(
        ((0x100, ()),),
        (),
        (),
        ConditionCacheReliftStats8616(1, 1, 1, 0, 1),
    )
    monkeypatch.setattr(
        owner,
        "relift_function_condition_cache_8616",
        lambda *_args: replacement,
    )

    evidence = build_ir_function_condition_artifact_8616(
        object(),
        0x100,
        (ConditionReliftBlock8616(0x100, 2),),
        (IRBlock(0x100, successor_addrs=(0x102, 0x104)),),
        incomplete,
    )

    assert evidence is not None
    assert evidence.source is replacement

from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace
from inertia.ir.ssa import build_x86_16_block_local_ssa


def test_block_local_ssa_reuses_the_same_immutable_block_projection() -> None:
    block = IRBlock(
        addr=0x1000,
        instrs=(
            IRInstr(
                "MOV",
                IRValue(MemSpace.REG, name="ax", size=2),
                (IRValue(MemSpace.CONST, const=1, size=2),),
                size=2,
            ),
        ),
    )

    first = build_x86_16_block_local_ssa(block)

    assert build_x86_16_block_local_ssa(block) is first


def test_block_local_ssa_cache_does_not_merge_equal_distinct_provenance() -> None:
    def _block(source_tmp: int) -> IRBlock:
        return IRBlock(
            addr=0x1000,
            instrs=(
                IRInstr(
                    "MOV",
                    IRValue(
                        MemSpace.TMP,
                        name="t0",
                        size=2,
                        source_tmp=source_tmp,
                    ),
                    (IRValue(MemSpace.CONST, const=1, size=2),),
                    size=2,
                ),
            ),
        )

    first_block = _block(1)
    second_block = _block(2)
    assert first_block == second_block

    first = build_x86_16_block_local_ssa(first_block)
    second = build_x86_16_block_local_ssa(second_block)

    assert first is not second
    assert first.instrs[0].dst is not None
    assert second.instrs[0].dst is not None
    assert first.instrs[0].dst.source_tmp == 1
    assert second.instrs[0].dst.source_tmp == 2

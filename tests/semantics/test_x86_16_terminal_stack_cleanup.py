from __future__ import annotations

from types import SimpleNamespace

from angr.errors import SimEngineError

from inertia.semantics.terminal_stack_cleanup import (
    TerminalReturnFrameKind8616,
    collect_terminal_stack_cleanup_evidence_8616,
    terminal_stack_cleanup_at_address_8616,
)


class _Factory:
    def __init__(self, blocks: dict[int, object]) -> None:
        self.blocks = blocks

    def block(self, address: int, *, opt_level: int) -> object:
        assert opt_level == 0
        return self.blocks[address]


def _insn(address: int, mnemonic: str, *, size: int = 1, target: int | None = None) -> object:
    operands = () if target is None else (SimpleNamespace(type=2, imm=target),)
    return SimpleNamespace(address=address, size=size, mnemonic=mnemonic, operands=operands)


def _ret(address: int, cleanup: int) -> object:
    return SimpleNamespace(
        address=address,
        size=3,
        mnemonic="ret",
        operands=(SimpleNamespace(type=2, imm=cleanup),),
    )


def _wrapped(insn: object) -> object:
    """Wrap one fake instruction like angr's Capstone instruction surface."""
    return SimpleNamespace(
        address=insn.address,
        size=insn.size,
        mnemonic=insn.mnemonic,
        insn=insn,
    )


def test_terminal_stack_cleanup_refuses_conflicting_return_paths() -> None:
    branch = _insn(0x1000, "je", size=2, target=0x1010)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(branch,))),
        0x1002: SimpleNamespace(capstone=SimpleNamespace(insns=(_ret(0x1002, 4),))),
        0x1010: SimpleNamespace(capstone=SimpleNamespace(insns=(_ret(0x1010, 6),))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    evidence = collect_terminal_stack_cleanup_evidence_8616(project, function)

    assert evidence.complete is True
    assert evidence.cleanup_amounts == frozenset({4, 6})
    assert evidence.consistent_cleanup is None


def test_terminal_stack_cleanup_accepts_consistent_return_paths() -> None:
    branch = _insn(0x1000, "je", size=2, target=0x1010)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(branch,))),
        0x1002: SimpleNamespace(capstone=SimpleNamespace(insns=(_ret(0x1002, 4),))),
        0x1010: SimpleNamespace(capstone=SimpleNamespace(insns=(_ret(0x1010, 4),))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    evidence = collect_terminal_stack_cleanup_evidence_8616(project, function)

    assert evidence.complete is True
    assert evidence.consistent_cleanup == 4
    assert evidence.consistent_return_frame_kind is TerminalReturnFrameKind8616.NEAR
    assert evidence.raw_fact_count == evidence.materialized_count == 2


def test_terminal_stack_cleanup_visits_shared_branch_suffix_once() -> None:
    """A diamond chain has one return fact, not exponentially many paths."""
    blocks: dict[int, object] = {}
    for index in range(8):
        branch_addr = 0x1000 + index * 0x20
        join_addr = branch_addr + 0x10
        blocks[branch_addr] = SimpleNamespace(
            capstone=SimpleNamespace(
                insns=(_insn(branch_addr, "je", size=2, target=branch_addr + 8),)
            )
        )
        for arm_addr in (branch_addr + 2, branch_addr + 8):
            blocks[arm_addr] = SimpleNamespace(
                capstone=SimpleNamespace(insns=(_insn(arm_addr, "jmp", target=join_addr),))
            )
        join_insn = (
            _insn(join_addr, "jmp", target=branch_addr + 0x20)
            if index < 7
            else _ret(join_addr, 6)
        )
        blocks[join_addr] = SimpleNamespace(capstone=SimpleNamespace(insns=(join_insn,)))

    class _CountingFactory(_Factory):
        def __init__(self, code_blocks: dict[int, object]) -> None:
            super().__init__(code_blocks)
            self.loads: dict[int, int] = {}

        def block(self, address: int, *, opt_level: int) -> object:
            self.loads[address] = self.loads.get(address, 0) + 1
            return super().block(address, opt_level=opt_level)

    factory = _CountingFactory(blocks)
    project = SimpleNamespace(factory=factory)
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    evidence = collect_terminal_stack_cleanup_evidence_8616(project, function)

    assert evidence.complete is True
    assert evidence.consistent_cleanup == 6
    assert evidence.raw_fact_count == evidence.materialized_count == 1
    assert factory.loads == dict.fromkeys(blocks, 1)


def test_terminal_stack_cleanup_refuses_incomplete_successor() -> None:
    branch = _insn(0x1000, "je", size=2, target=0x1010)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(branch,))),
        0x1002: SimpleNamespace(capstone=SimpleNamespace(insns=(_ret(0x1002, 4),))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    evidence = collect_terminal_stack_cleanup_evidence_8616(project, function)

    assert evidence.complete is False
    assert evidence.consistent_cleanup is None
    assert evidence.failure_count == 1


def test_bodyless_stack_cleanup_requires_direct_terminal_block() -> None:
    direct_project = SimpleNamespace(
        factory=_Factory(
            {0x2000: SimpleNamespace(capstone=SimpleNamespace(insns=(_ret(0x2000, 8),)))}
        )
    )
    branch_project = SimpleNamespace(
        factory=_Factory(
            {0x2000: SimpleNamespace(capstone=SimpleNamespace(insns=(_insn(0x2000, "jmp", target=0x2010),)))}
        )
    )

    assert terminal_stack_cleanup_at_address_8616(direct_project, 0x2000).consistent_cleanup == 8
    assert terminal_stack_cleanup_at_address_8616(branch_project, 0x2000).complete is False


def test_bodyless_stack_cleanup_preserves_far_return_frame_kind() -> None:
    """A complete RETF body publishes its far machine-frame contract."""
    project = SimpleNamespace(
        factory=_Factory(
            {
                0x2000: SimpleNamespace(
                    capstone=SimpleNamespace(insns=(_insn(0x2000, "retf"),))
                )
            }
        )
    )

    evidence = terminal_stack_cleanup_at_address_8616(project, 0x2000)

    assert evidence.complete is True
    assert evidence.consistent_cleanup == 0
    assert evidence.consistent_return_frame_kind is TerminalReturnFrameKind8616.FAR


def test_complete_bodyless_stack_cleanup_is_cached_per_project() -> None:
    factory = _Factory(
        {0x2000: SimpleNamespace(capstone=SimpleNamespace(insns=(_ret(0x2000, 8),)))}
    )
    project = SimpleNamespace(factory=factory)

    first = terminal_stack_cleanup_at_address_8616(project, 0x2000)
    factory.blocks.clear()
    second = terminal_stack_cleanup_at_address_8616(project, 0x2000)

    assert first.complete is True
    assert second is first


def test_incomplete_bodyless_stack_cleanup_is_not_cached() -> None:
    factory = _Factory(
        {0x2000: SimpleNamespace(capstone=SimpleNamespace(insns=(_insn(0x2000, "jmp", target=0x2010),)))}
    )
    project = SimpleNamespace(factory=factory)

    first = terminal_stack_cleanup_at_address_8616(project, 0x2000)
    factory.blocks[0x2010] = SimpleNamespace(capstone=SimpleNamespace(insns=(_ret(0x2010, 8),)))
    function = SimpleNamespace(addr=0x2000, block_addrs_set={0x2000, 0x2010})
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda **_kwargs: function),
    )
    second = terminal_stack_cleanup_at_address_8616(project, 0x2000)

    assert first.complete is False
    assert second.complete is True
    assert second.consistent_cleanup == 8


def test_bodyless_stack_cleanup_follows_complete_loaded_binary_cfg() -> None:
    blocks = {
        0x2000: SimpleNamespace(
            addr=0x2000,
            size=2,
            capstone=SimpleNamespace(
                insns=(_wrapped(_insn(0x2000, "je", size=2, target=0x2010)),)
            ),
        ),
        0x2002: SimpleNamespace(
            addr=0x2002,
            size=3,
            capstone=SimpleNamespace(insns=(_wrapped(_ret(0x2002, 8)),)),
        ),
        0x2010: SimpleNamespace(
            addr=0x2010,
            size=3,
            capstone=SimpleNamespace(insns=(_wrapped(_ret(0x2010, 8)),)),
        ),
    }
    loaded = SimpleNamespace(min_addr=0x2000, max_addr=0x2012)
    project = SimpleNamespace(
        factory=_Factory(blocks),
        loader=SimpleNamespace(find_object_containing=lambda _address: loaded),
    )

    evidence = terminal_stack_cleanup_at_address_8616(project, 0x2000)

    assert evidence.complete is True
    assert evidence.consistent_cleanup == 8
    assert evidence.raw_fact_count == evidence.materialized_count == 2


def test_bodyless_stack_cleanup_refuses_inaccessible_decode() -> None:
    class _MissingFactory:
        def block(self, _address: int, *, opt_level: int) -> object:
            assert opt_level == 0
            raise SimEngineError("No bytes in memory")

    evidence = terminal_stack_cleanup_at_address_8616(
        SimpleNamespace(factory=_MissingFactory()),
        0x11222,
    )

    assert evidence.complete is False
    assert evidence.raw_fact_count == evidence.failure_count == 1
    assert evidence.consistent_cleanup is None

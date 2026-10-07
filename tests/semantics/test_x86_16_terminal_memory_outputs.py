from __future__ import annotations

from types import SimpleNamespace

from inertia.ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact

from inertia.semantics.terminal_memory_output_contracts import (
    TerminalMemoryOutputDisposition8616,
    TerminalMemoryOutputFailure8616,
)
from inertia.semantics.terminal_memory_outputs import (
    collect_terminal_memory_output_evidence_8616,
)


class _Factory:
    def __init__(self, terminal_mnemonics: dict[int, str]) -> None:
        self._terminal_mnemonics = terminal_mnemonics

    def block(self, address: int, *, opt_level: int) -> object:
        assert opt_level == 0
        instruction = SimpleNamespace(mnemonic=self._terminal_mnemonics[address])
        return SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)))


def _project(**terminal_mnemonics: str) -> object:
    return SimpleNamespace(
        factory=_Factory({int(address, 16): mnemonic for address, mnemonic in terminal_mnemonics.items()})
    )


def _store(
    address: int,
    *,
    space: MemSpace = MemSpace.DS,
    offset: int = 0x1234,
    size: int = 1,
    base: tuple[str, ...] = (),
) -> IRInstr:
    target = IRAddress(
        space=space,
        base=base,
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
    )
    value = IRValue(MemSpace.REG, name="al", size=size)
    return IRInstr("STORE", None, (target, value), size=size, addr=address)


def _artifact(
    blocks: tuple[SSABlock, ...],
    predecessor_map: dict[int, tuple[int, ...]],
) -> SSAFunctionArtifact:
    return SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=blocks,
        predecessor_map=predecessor_map,
    )


def _block(address: int, *instructions: IRInstr) -> SSABlock:
    return SSABlock(address, instructions, ())


def test_direct_byte_store_reaching_return_is_must_write() -> None:
    artifact = _artifact((_block(0x1000, _store(0x1000)),), {0x1000: ()})

    evidence = collect_terminal_memory_output_evidence_8616(
        _project(**{"1000": "ret"}), artifact
    )

    assert evidence.complete is True
    assert evidence.stats.raw_fact_count == evidence.stats.materialized_count == 1
    assert len(evidence.must_write_facts) == 1
    fact = evidence.must_write_facts[0]
    assert fact.key == (MemSpace.DS, 0x1234, 1)
    assert fact.store_sites[0].instr_addr == 0x1000


def test_store_on_only_one_return_path_remains_conditional() -> None:
    artifact = _artifact(
        (
            _block(0x1000),
            _block(0x1010, _store(0x1010)),
            _block(0x1020),
        ),
        {0x1000: (), 0x1010: (0x1000,), 0x1020: (0x1000,)},
    )

    evidence = collect_terminal_memory_output_evidence_8616(
        _project(**{"1010": "ret", "1020": "ret"}), artifact
    )

    assert evidence.complete is True
    assert len(evidence.facts) == 1
    fact = evidence.facts[0]
    assert fact.disposition is TerminalMemoryOutputDisposition8616.CONDITIONAL
    assert fact.terminal_block_addrs == (0x1010, 0x1020)
    assert fact.definitely_written_terminal_block_addrs == (0x1010,)


def test_same_range_written_on_every_branch_is_must_write() -> None:
    artifact = _artifact(
        (
            _block(0x1000),
            _block(0x1010, _store(0x1010)),
            _block(0x1020, _store(0x1020)),
        ),
        {0x1000: (), 0x1010: (0x1000,), 0x1020: (0x1000,)},
    )

    evidence = collect_terminal_memory_output_evidence_8616(
        _project(**{"1010": "ret", "1020": "ret"}), artifact
    )

    assert evidence.complete is True
    assert evidence.must_write_facts[0].key == (MemSpace.DS, 0x1234, 1)
    assert len(evidence.must_write_facts[0].store_sites) == 2
    assert evidence.must_write_facts[0].definitely_written_terminal_block_addrs == (
        0x1010,
        0x1020,
    )


def test_ds_and_es_ranges_remain_distinct_outputs() -> None:
    artifact = _artifact(
        (_block(0x1000, _store(0x1000), _store(0x1001, space=MemSpace.ES)),),
        {0x1000: ()},
    )

    evidence = collect_terminal_memory_output_evidence_8616(
        _project(**{"1000": "ret"}), artifact
    )

    assert evidence.complete is True
    assert {fact.key for fact in evidence.must_write_facts} == {
        (MemSpace.DS, 0x1234, 1),
        (MemSpace.ES, 0x1234, 1),
    }


def test_overlapping_direct_views_remain_separate_semantics_facts() -> None:
    artifact = _artifact(
        (
            _block(
                0x1000,
                _store(0x1000, offset=0x1234, size=2),
                _store(0x1001, offset=0x1235),
            ),
        ),
        {0x1000: ()},
    )

    evidence = collect_terminal_memory_output_evidence_8616(
        _project(**{"1000": "ret"}), artifact
    )

    assert evidence.complete is True
    assert {fact.key for fact in evidence.must_write_facts} == {
        (MemSpace.DS, 0x1234, 2),
        (MemSpace.DS, 0x1235, 1),
    }


def test_indirect_same_space_store_does_not_erase_direct_output() -> None:
    artifact = _artifact(
        (_block(0x1000, _store(0x1000), _store(0x1001, base=("bx",))),),
        {0x1000: ()},
    )

    evidence = collect_terminal_memory_output_evidence_8616(
        _project(**{"1000": "ret"}), artifact
    )

    assert evidence.complete is True
    assert evidence.failure is None
    assert tuple(fact.key for fact in evidence.facts) == ((MemSpace.DS, 0x1234, 1),)


def test_incomplete_cfg_and_non_return_terminal_refuse_atomically() -> None:
    incomplete = _artifact((_block(0x1000, _store(0x1000)),), {})
    bad_terminal = _artifact((_block(0x1000, _store(0x1000)),), {0x1000: ()})

    incomplete_evidence = collect_terminal_memory_output_evidence_8616(
        _project(**{"1000": "ret"}), incomplete
    )
    terminal_evidence = collect_terminal_memory_output_evidence_8616(
        _project(**{"1000": "jmp"}), bad_terminal
    )

    assert incomplete_evidence.failure is TerminalMemoryOutputFailure8616.CFG_INCOMPLETE
    assert terminal_evidence.failure is TerminalMemoryOutputFailure8616.TERMINAL_NOT_RETURN
    assert incomplete_evidence.facts == terminal_evidence.facts == ()

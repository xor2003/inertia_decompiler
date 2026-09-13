from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.semantics import terminal_pointer_outputs
from angr_platforms.X86_16.semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputDisposition8616,
    TerminalPointerOutputFailure8616,
)
from angr_platforms.X86_16.semantics.terminal_pointer_outputs import (
    collect_terminal_pointer_output_evidence_8616,
)

FUNCTION = 0x1000
WORD_BYTES = 2
NEGATIVE_OUTPUT_OFFSET = -2


def _decode_terminals(
    monkeypatch: pytest.MonkeyPatch,
    mnemonics: dict[int, str],
) -> None:
    def _decode(project: object, address: int, *, opt_level: int) -> tuple[object, ...]:
        assert project is not None
        assert opt_level == 0
        return (SimpleNamespace(mnemonic=mnemonics[address]),)

    monkeypatch.setattr(
        terminal_pointer_outputs,
        "decoded_block_instructions_8616",
        _decode,
    )


def _register(name: str, version: int) -> IRValue:
    return IRValue(MemSpace.REG, name=name, size=2, version=version)


def _store(
    instr_addr: int,
    *,
    space: MemSpace = MemSpace.DS,
    base: tuple[str, ...] = ("bx",),
    base_values: tuple[IRValue, ...] | None = None,
    offset: int = 4,
    width: int = 1,
    segment_origin: SegmentOrigin = SegmentOrigin.PROVEN,
) -> IRInstr:
    values = (_register("bx", 0),) if base_values is None else base_values
    address = IRAddress(
        space=space,
        base=base,
        offset=offset,
        size=width,
        status=AddressStatus.STABLE,
        segment_origin=segment_origin,
        base_values=values,
    )
    value = IRValue(MemSpace.REG, name="al" if width == 1 else "ax", size=width)
    return IRInstr("STORE", None, (address, value), size=width, addr=instr_addr)


def _block(address: int, *instructions: IRInstr) -> SSABlock:
    return SSABlock(address, instructions, ())


def _artifact(
    blocks: tuple[SSABlock, ...],
    predecessor_map: dict[int, tuple[int, ...]],
) -> SSAFunctionArtifact:
    return SSAFunctionArtifact(
        function_addr=FUNCTION,
        blocks=blocks,
        predecessor_map=predecessor_map,
    )


def test_pointer_store_reaching_return_is_must_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _decode_terminals(monkeypatch, {FUNCTION: "ret"})
    artifact = _artifact(
        (_block(FUNCTION, _store(FUNCTION, offset=NEGATIVE_OUTPUT_OFFSET, width=WORD_BYTES)),),
        {FUNCTION: ()},
    )

    evidence = collect_terminal_pointer_output_evidence_8616(object(), artifact)

    assert evidence.complete is True
    assert evidence.stats.raw_fact_count == evidence.stats.materialized_count == 1
    assert len(evidence.must_write_facts) == 1
    fact = evidence.must_write_facts[0]
    assert fact.key == (MemSpace.DS, "bx", 0, -2, 2)
    assert fact.segment is MemSpace.DS
    assert fact.base_register == "bx"
    assert fact.base_version == 0
    assert fact.relative_offset == NEGATIVE_OUTPUT_OFFSET
    assert fact.width == WORD_BYTES
    assert fact.store_sites[0].instr_addr == FUNCTION
    assert fact.terminal_block_addrs == fact.definitely_written_terminal_block_addrs == (
        FUNCTION,
    )


def test_pointer_store_on_only_one_return_path_is_conditional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _decode_terminals(monkeypatch, {0x1010: "ret", 0x1020: "ret"})
    artifact = _artifact(
        (
            _block(FUNCTION),
            _block(0x1010, _store(0x1010)),
            _block(0x1020),
        ),
        {FUNCTION: (), 0x1010: (FUNCTION,), 0x1020: (FUNCTION,)},
    )

    evidence = collect_terminal_pointer_output_evidence_8616(object(), artifact)

    assert evidence.complete is True
    assert len(evidence.facts) == 1
    fact = evidence.facts[0]
    assert fact.disposition is TerminalPointerOutputDisposition8616.CONDITIONAL
    assert fact.terminal_block_addrs == (0x1010, 0x1020)
    assert fact.definitely_written_terminal_block_addrs == (0x1010,)


def test_conditional_word_write_stays_conditional_at_shared_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A joined epilogue does not prove that both incoming paths wrote output."""
    success, failure, epilogue = 0x1010, 0x1020, 0x1030
    _decode_terminals(monkeypatch, {epilogue: "ret"})
    artifact = _artifact(
        (
            _block(FUNCTION),
            _block(success, _store(success, offset=0, width=WORD_BYTES)),
            _block(failure),
            _block(epilogue),
        ),
        {
            FUNCTION: (),
            success: (FUNCTION,),
            failure: (FUNCTION,),
            epilogue: (success, failure),
        },
    )

    evidence = collect_terminal_pointer_output_evidence_8616(object(), artifact)

    assert evidence.complete is True
    assert len(evidence.facts) == 1
    fact = evidence.facts[0]
    assert fact.disposition is TerminalPointerOutputDisposition8616.CONDITIONAL
    assert fact.width == WORD_BYTES
    assert fact.terminal_block_addrs == (epilogue,)
    assert fact.definitely_written_terminal_block_addrs == ()
    assert evidence.must_write_facts == ()


def test_separate_base_ssa_versions_remain_separate_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _decode_terminals(monkeypatch, {FUNCTION: "ret"})
    artifact = _artifact(
        (
            _block(
                FUNCTION,
                _store(FUNCTION, base_values=(_register("bx", 0),)),
                _store(FUNCTION + 2, base_values=(_register("bx", 1),)),
            ),
        ),
        {FUNCTION: ()},
    )

    evidence = collect_terminal_pointer_output_evidence_8616(object(), artifact)

    assert evidence.complete is True
    assert {fact.key for fact in evidence.must_write_facts} == {
        (MemSpace.DS, "bx", 0, 4, 1),
        (MemSpace.DS, "bx", 1, 4, 1),
    }
    assert all(fact.definitely_written_terminal_block_addrs == (FUNCTION,) for fact in evidence.facts)


def test_direct_ds_and_ss_stores_are_not_pointer_outputs() -> None:
    artifact = _artifact(
        (
            _block(
                FUNCTION,
                _store(FUNCTION, base=(), base_values=()),
                _store(
                    FUNCTION + 2,
                    space=MemSpace.SS,
                    base=("sp",),
                    base_values=(_register("sp", 0),),
                ),
            ),
        ),
        {FUNCTION: ()},
    )

    evidence = collect_terminal_pointer_output_evidence_8616(object(), artifact)

    assert evidence.complete is True
    assert evidence.facts == ()
    assert evidence.stats.raw_fact_count == 0


@pytest.mark.parametrize(
    ("base", "base_values", "segment_origin"),
    (
        (
            ("bx", "si"),
            (_register("bx", 0), _register("si", 0)),
            SegmentOrigin.PROVEN,
        ),
        (("bx",), (_register("bx", 0),), SegmentOrigin.DEFAULTED),
    ),
)
def test_ambiguous_or_unproven_indirect_alias_refuses_atomically(
    base: tuple[str, ...],
    base_values: tuple[IRValue, ...],
    segment_origin: SegmentOrigin,
) -> None:
    artifact = _artifact(
        (
            _block(
                FUNCTION,
                _store(FUNCTION),
                _store(
                    FUNCTION + 2,
                    base=base,
                    base_values=base_values,
                    segment_origin=segment_origin,
                ),
            ),
        ),
        {FUNCTION: ()},
    )

    evidence = collect_terminal_pointer_output_evidence_8616(object(), artifact)

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failure is TerminalPointerOutputFailure8616.ALIAS_CONFLICT
    assert evidence.stats.failure_count == 1


def test_width_ambiguous_indirect_alias_refuses_atomically() -> None:
    conflicting = replace(_store(FUNCTION + 2, offset=3), size=2)
    artifact = _artifact(
        (_block(FUNCTION, _store(FUNCTION), conflicting),),
        {FUNCTION: ()},
    )

    evidence = collect_terminal_pointer_output_evidence_8616(object(), artifact)

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failure is TerminalPointerOutputFailure8616.ALIAS_CONFLICT


def test_incomplete_cfg_refuses_atomically() -> None:
    artifact = _artifact((_block(FUNCTION, _store(FUNCTION)),), {})

    evidence = collect_terminal_pointer_output_evidence_8616(object(), artifact)

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failure is TerminalPointerOutputFailure8616.CFG_INCOMPLETE


def test_non_return_terminal_refuses_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _decode_terminals(monkeypatch, {FUNCTION: "jmp"})
    artifact = _artifact((_block(FUNCTION, _store(FUNCTION)),), {FUNCTION: ()})

    evidence = collect_terminal_pointer_output_evidence_8616(object(), artifact)

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failure is TerminalPointerOutputFailure8616.TERMINAL_NOT_RETURN

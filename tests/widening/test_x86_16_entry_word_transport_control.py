"""Independent conditional-control and implicit-IP effect controls.

Layer: Widening regression tests.
Responsibility: preserve unrelated data words without treating control writes,
side-exit fallthrough-only data effects or missing CFG edges as closed proof.
"""

from __future__ import annotations

from inertia.ir.core import IRBlock, IRFunctionArtifact
import inertia.widening.entry_word_transport as _TRANSPORT
from tests.widening.test_x86_16_entry_word_transport import (
    ENTRY_8616,
    EXTERNAL,
    LEFT,
    SEED_INDEX,
    TARGET,
    _artifact,
    _block,
    _cjmp,
    _const,
    _mov,
    _reg,
    _seed_instrs,
)

from inertia.alias.entry_stack_bytes import prove_entry_stack_bytes_8616
from inertia.widening.entry_stack_word_values import prove_entry_stack_word_value_8616


def _prove(blocks: list[IRBlock], source_register: str = "cx") -> object:
    """Replay real Alias/Word owners, not a fabricated successful seed."""
    artifact = _artifact(blocks)
    assert isinstance(artifact, IRFunctionArtifact)
    word = prove_entry_stack_word_value_8616(
        artifact, prove_entry_stack_bytes_8616(artifact), SEED_INDEX,
    )
    assert word.fact is not None
    assert word.fact.target_name == source_register
    return _TRANSPORT.prove_entry_word_transport_8616(artifact, word, TARGET, 0)


def test_terminal_conditional_preserves_unrelated_word_register() -> None:
    """The explicit IP write must not erase an unchanged captured CX word."""
    proof = _prove([
        _block(ENTRY_8616, _seed_instrs(), (LEFT,)),
        _block(LEFT, [_cjmp(TARGET)], (TARGET, EXTERNAL)),
        _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ])
    assert proof.verdict is _TRANSPORT.EntryWordTransportVerdict8616.PROVEN


def test_conditional_rewrites_ip_word() -> None:
    """A conditional transfer cannot preserve a prior word held in IP itself."""
    proof = _prove([
        _block(ENTRY_8616, _seed_instrs("ip"), (LEFT,)),
        _block(LEFT, [_cjmp(TARGET)], (TARGET, EXTERNAL)),
        _block(TARGET, [_mov(_reg("dx"), _reg("ip"))], (EXTERNAL,)),
    ], source_register="ip")
    assert proof.verdict is _TRANSPORT.EntryWordTransportVerdict8616.REFUSED


def test_early_conditional_must_not_apply_post_exit_restore_to_taken_edge() -> None:
    """The taken edge sees CX=0; only fallthrough executes CX=SI restore."""
    proof = _prove([
        _block(ENTRY_8616, _seed_instrs(), (LEFT,)),
        _block(LEFT, [
            _mov(_reg("si"), _reg("cx")),
            _mov(_reg("cx"), _const(0)),
            _cjmp(TARGET),
            _mov(_reg("cx"), _reg("si")),
        ], (TARGET, EXTERNAL)),
        _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ])
    assert proof.verdict is _TRANSPORT.EntryWordTransportVerdict8616.REFUSED


def test_conditional_target_missing_from_cfg_refuses() -> None:
    """A branch destination cannot disappear from the recorded exit inventory."""
    proof = _prove([
        _block(ENTRY_8616, _seed_instrs(), (LEFT,)),
        _block(LEFT, [_cjmp(TARGET + 128)], (TARGET, EXTERNAL)),
        _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ])
    assert proof.verdict is _TRANSPORT.EntryWordTransportVerdict8616.REFUSED


def test_conditional_with_literal_ip_fallthrough_preserves_cx() -> None:
    """A normal VEX final fallthrough IP assignment cannot corrupt CX."""
    proof = _prove([
        _block(ENTRY_8616, _seed_instrs(), (LEFT,)),
        _block(LEFT, [
            _cjmp(TARGET), _mov(_reg("ip"), _const(EXTERNAL)),
        ], (TARGET, EXTERNAL)),
        _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ])
    assert proof.verdict is _TRANSPORT.EntryWordTransportVerdict8616.PROVEN


def test_post_conditional_ip_restore_must_not_reach_taken_edge() -> None:
    """Only fallthrough restores captured CX into IP, not the taken edge."""
    proof = _prove([
        _block(ENTRY_8616, [*_seed_instrs(), _mov(_reg("ip"), _reg("cx"))], (LEFT,)),
        _block(LEFT, [
            _cjmp(TARGET), _mov(_reg("ip"), _reg("cx")),
        ], (TARGET, EXTERNAL)),
        _block(TARGET, [_mov(_reg("dx"), _reg("ip"))], (EXTERNAL,)),
    ])
    assert proof.verdict is _TRANSPORT.EntryWordTransportVerdict8616.REFUSED

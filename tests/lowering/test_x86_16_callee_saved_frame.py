from __future__ import annotations

from types import SimpleNamespace

from inertia.lowering.callee_saved_frame import callee_saved_frame_pairs_8616
from capstone.x86_const import (
    X86_INS_CALL,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_OP_REG,
    X86_REG_DI,
    X86_REG_SI,
)


def _instruction(address: int, instruction_id: int, register_id: int | None = None) -> SimpleNamespace:
    names = {X86_REG_DI: "di", X86_REG_SI: "si"}
    operands = () if register_id is None else (SimpleNamespace(type=X86_OP_REG, reg=register_id),)
    return SimpleNamespace(
        address=address,
        id=instruction_id,
        operands=operands,
        reg_name=lambda value: names.get(value, ""),
    )


def test_callee_saved_frame_pairs_normalize_duplicate_decode_facts() -> None:
    push_di = _instruction(0x1010, X86_INS_PUSH, X86_REG_DI)
    push_si = _instruction(0x1011, X86_INS_PUSH, X86_REG_SI)
    pop_si = _instruction(0x1020, X86_INS_POP, X86_REG_SI)
    pop_di = _instruction(0x1021, X86_INS_POP, X86_REG_DI)
    ret = _instruction(0x1022, X86_INS_RET)

    pairs = callee_saved_frame_pairs_8616(
        (push_di, push_di, push_si, push_si, pop_si, pop_si, pop_di, pop_di, ret),
        frozenset(("di", "si")),
    )

    assert [(pair.register_name, pair.push_addr, pair.pop_addr) for pair in pairs] == [
        ("di", 0x1010, 0x1021),
        ("si", 0x1011, 0x1020),
    ]


def test_callee_saved_frame_pairs_keep_later_argument_push_outside_frame() -> None:
    pairs = callee_saved_frame_pairs_8616(
        (
            _instruction(0x1010, X86_INS_PUSH, X86_REG_DI),
            _instruction(0x1018, X86_INS_PUSH, X86_REG_DI),
            _instruction(0x1020, X86_INS_POP, X86_REG_DI),
            _instruction(0x1021, X86_INS_RET),
        ),
        frozenset(("di",)),
    )

    assert pairs[0].instruction_addresses == frozenset((0x1010, 0x1020))


def test_callee_saved_frame_pairs_accept_explicit_caller_saved_register_pair() -> None:
    register_ax = 100
    push_ax = SimpleNamespace(
        address=0x1010,
        id=X86_INS_PUSH,
        operands=(SimpleNamespace(type=X86_OP_REG, reg=register_ax),),
        reg_name=lambda value: "ax" if value == register_ax else "",
    )
    pop_ax = SimpleNamespace(
        address=0x1020,
        id=X86_INS_POP,
        operands=(SimpleNamespace(type=X86_OP_REG, reg=register_ax),),
        reg_name=lambda value: "ax" if value == register_ax else "",
    )

    pairs = callee_saved_frame_pairs_8616(
        (push_ax, pop_ax, _instruction(0x1021, X86_INS_RET)),
        frozenset(("ax",)),
    )

    assert [(pair.register_name, pair.push_addr, pair.pop_addr) for pair in pairs] == [
        ("ax", 0x1010, 0x1020)
    ]


def test_callee_saved_frame_pairs_keep_sequential_pairs_for_one_register() -> None:
    pairs = callee_saved_frame_pairs_8616(
        (
            _instruction(0x1010, X86_INS_PUSH, X86_REG_DI),
            _instruction(0x1020, X86_INS_POP, X86_REG_DI),
            _instruction(0x1030, X86_INS_PUSH, X86_REG_DI),
            _instruction(0x1040, X86_INS_POP, X86_REG_DI),
            _instruction(0x1041, X86_INS_RET),
        ),
        frozenset(("di",)),
    )

    assert [(pair.push_addr, pair.pop_addr) for pair in pairs] == [
        (0x1010, 0x1020),
        (0x1030, 0x1040),
    ]


def test_callee_saved_frame_pairs_keep_push_before_call_as_argument_with_delayed_cleanup() -> None:
    """A matching late POP cannot steal an exact PUSH/CALL argument pair."""
    pairs = callee_saved_frame_pairs_8616(
        (
            _instruction(0x1010, X86_INS_PUSH, X86_REG_DI),
            _instruction(0x1020, X86_INS_POP, X86_REG_DI),
            _instruction(0x1030, X86_INS_PUSH, X86_REG_DI),
            _instruction(0x1031, X86_INS_CALL),
            _instruction(0x1040, X86_INS_PUSH, X86_REG_SI),
            _instruction(0x1041, X86_INS_CALL),
            _instruction(0x1050, X86_INS_POP, X86_REG_SI),
            _instruction(0x1051, X86_INS_POP, X86_REG_DI),
            _instruction(0x1052, X86_INS_RET),
        ),
        frozenset(("di", "si")),
    )

    assert [(pair.register_name, pair.push_addr, pair.pop_addr) for pair in pairs] == [
        ("di", 0x1010, 0x1020),
    ]

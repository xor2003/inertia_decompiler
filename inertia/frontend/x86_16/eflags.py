"""Layer: Frontend/runtime.

Responsibility: expose flag register accessors for lifter and emulator instruction behavior.
Forbidden: postprocess flag cleanup, condition recovery, or validation acceptance.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from pyvex.lifting.util.vex_helper import Type

from inertia.frontend.x86_16.regs import reg16_t, reg32_t
from inertia.semantics.status_flag_contracts import (
    INCDEC_STATUS_FLAG_WRITES_8616,
    SHIFT_COUNT_MANY_STATUS_FLAG_WRITES_8616,
    SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616,
    STATUS_FLAGS_8616,
    StatusFlag8616,
)

# pyvex's VexValue operator stubs expose raw RdTmp/list results even though the
# runtime syntax wrapper returns another value wrapper. Keep that third-party
# mismatch isolated behind one explicit frontend boundary type.
type VexExpr = Any
type FlagValue = int | VexExpr
type FlagValueFactory = Callable[[], FlagValue]
type StatusFlagValueFactories = tuple[tuple[StatusFlag8616, FlagValueFactory], ...]


class Eflags:
    """Flag-operation mixin backed by an instruction/emulator value host.

    The declared callables are supplied by the concrete emulator host. Their
    values remain dynamic because pyvex expression types are not a stable owned
    Inertia contract.
    """

    get_gpreg: Callable[[object], FlagValue]
    set_gpreg: Callable[[object, FlagValue], None]
    constant: Callable[..., VexExpr]
    _vv: Callable[[object], VexExpr]
    lifter_instruction: Any

    def __init__(self) -> None:
        """Initialize the stateless flag-operation mixin."""
        # self.eflags = 0

    def get_eflags(self) -> FlagValue:
        """Return the host's 32-bit EFLAGS value."""
        return self.get_gpreg(reg32_t.EFLAGS)

    def set_eflags(self, v: FlagValue) -> None:
        """Store a 32-bit EFLAGS value on the host."""
        self.set_gpreg(reg32_t.EFLAGS, v)

    def get_flags(self) -> FlagValue:
        """Return the host's 16-bit FLAGS value."""
        return self.get_gpreg(reg16_t.FLAGS)

    def set_flags(self, v: FlagValue) -> None:
        """Store a 16-bit FLAGS value on the host."""
        self.set_gpreg(reg16_t.FLAGS, v)

    def get_flag(self, idx: int) -> VexExpr:
        """Return one FLAGS bit as a one-bit pyvex value."""
        flags = cast(VexExpr, self.get_gpreg(reg16_t.FLAGS))
        return flags[idx].cast_to(Type.int_1)

    def is_carry(self) -> VexExpr:
        """Return the carry flag value."""
        return self.get_flag(0)

    def is_parity(self) -> VexExpr:
        """Return the parity flag value."""
        return self.get_flag(2)

    def is_zero(self) -> VexExpr:
        """Return the zero flag value."""
        return self.get_flag(6)

    def is_sign(self) -> VexExpr:
        """Return the sign flag value."""
        return self.get_flag(7)

    def is_overflow(self) -> VexExpr:
        """Return the overflow flag value."""
        return self.get_flag(11)

    def is_interrupt(self) -> VexExpr:
        """Return the interrupt-enable flag value."""
        return self.get_flag(9)

    def is_direction(self) -> VexExpr:
        """Return the direction flag value."""
        return self.get_flag(10)

    def set_flag(self, flags: FlagValue, idx: int, value: FlagValue) -> VexExpr:
        """Return FLAGS with one indexed bit replaced."""
        flags16 = self.constant(flags, Type.int_16) if isinstance(flags, int) else flags.cast_to(Type.int_16)
        value16 = self.constant(value, Type.int_1) if isinstance(value, int) else value.cast_to(Type.int_1)
        clear_mask = self.constant((~(1 << idx)) & 0xFFFF, Type.int_16)
        bit_mask = self.constant((1 << idx) & 0xFFFF, Type.int_16)
        return (flags16 & clear_mask) | ((value16.cast_to(Type.int_16) << idx) & bit_mask)

    def set_carry(self, flags: FlagValue, carry: FlagValue) -> VexExpr:
        """Return FLAGS with the carry bit replaced."""
        return self.set_flag(flags, 0, carry)

    def set_parity(self, flags: FlagValue, parity: FlagValue) -> VexExpr:
        """Return FLAGS with the parity bit replaced."""
        return self.set_flag(flags, 2, parity)

    def set_zero(self, flags: FlagValue, zero: FlagValue) -> VexExpr:
        """Return FLAGS with the zero bit replaced."""
        return self.set_flag(flags, 6, zero)

    def set_sign(self, flags: FlagValue, sign: FlagValue) -> VexExpr:
        """Return FLAGS with the sign bit replaced."""
        return self.set_flag(flags, 7, sign)

    def set_overflow(self, flags: FlagValue, over: FlagValue) -> VexExpr:
        """Return FLAGS with the overflow bit replaced."""
        return self.set_flag(flags, 11, over)

    def set_interrupt(self, interrupt: FlagValue) -> None:
        """Store the interrupt-enable flag on the host."""
        flags = self.get_gpreg(reg16_t.FLAGS)
        interrupt = self.constant(interrupt, Type.int_1)
        flags = self.set_flag(flags, 9, interrupt)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def set_direction(self, direction: FlagValue) -> None:
        """Store the direction flag on the host."""
        flags = self.get_gpreg(reg16_t.FLAGS)
        direction = self.constant(direction, Type.int_1)
        flags = self.set_flag(flags, 10, direction)
        self.set_gpreg(reg16_t.FLAGS, flags)

    @staticmethod
    def _wider_type(ty: object) -> object:
        if ty == Type.int_8:
            return Type.int_16
        if ty == Type.int_16:
            return Type.int_32
        if ty == Type.int_32:
            return Type.int_64
        raise ValueError(f"unsupported arithmetic width: {ty!r}")

    def _count8(self, count: FlagValue) -> VexExpr:
        return self.constant(count, Type.int_8) if isinstance(count, int) else count.cast_to(Type.int_8)

    def _mask_shift_count(self, count: FlagValue) -> VexExpr:
        return self._count8(count) & self.constant(0x1F, Type.int_8)

    @staticmethod
    def _const_u8_value(v: FlagValue) -> int | None:
        if isinstance(v, int):
            return v & 0xFF
        try:
            return cast(int, v.value & 0xFF)
        except (AttributeError, ValueError):
            return None

    def _ite(self, cond: FlagValue, when_true: VexExpr, when_false: VexExpr) -> VexExpr:
        cond_expr = cast(VexExpr, self.constant(cond, Type.int_1) if isinstance(cond, int) else cond.cast_to(Type.int_1))
        expr = self.lifter_instruction.irsb_c.ite(
            cond_expr.rdt,
            when_true.rdt,
            when_false.rdt,
        )
        return self._vv(expr)

    def _adjust_flag(self, v1: VexExpr, v2: VexExpr, result: VexExpr) -> VexExpr:
        one = self.constant(1, result.ty)
        return (((v1 ^ v2) ^ result) >> 4 & one).cast_to(Type.int_1)

    def _live_status_flag_writes_8616(self, written: StatusFlag8616) -> StatusFlag8616:
        """Return status bits that the active liveness proof still requires."""
        normalized_written = written & STATUS_FLAGS_8616
        if self.lifter_instruction is None:
            return normalized_written
        try:
            dead_writes = StatusFlag8616(
                self.lifter_instruction.status_flag_dead_write_mask_8616(written)
            )
        except (AttributeError, TypeError, ValueError):
            return normalized_written
        return normalized_written & ~dead_writes

    def _set_live_status_flags_8616(
        self,
        flags: FlagValue,
        live_writes: StatusFlag8616,
        values: StatusFlagValueFactories,
        *,
        written: StatusFlag8616 | None = None,
    ) -> VexExpr:
        """Pack live equations and zero dead bits that this instruction defines."""
        selected = tuple((flag, value) for flag, value in values if live_writes & flag)
        if not selected:
            return cast(VexExpr, flags)
        flags16 = self.constant(flags, Type.int_16) if isinstance(flags, int) else flags.cast_to(Type.int_16)
        live_mask = sum(int(flag) for flag, _value in selected)
        written_mask = int(written if written is not None else live_writes)
        packed = self.constant(0, Type.int_16)
        for flag, value_factory in selected:
            value = value_factory()
            value1 = self.constant(value, Type.int_1) if isinstance(value, int) else value.cast_to(Type.int_1)
            packed |= value1.cast_to(Type.int_16) << (int(flag).bit_length() - 1)
        return (flags16 & self.constant((~written_mask) & 0xFFFF, Type.int_16)) | (
            packed & self.constant(live_mask, Type.int_16)
        )

    def _status_flag_write_is_dead_8616(self, written: StatusFlag8616) -> bool:
        """Return whether every status bit written by this instruction is dead."""
        return bool(self._live_status_flag_writes_8616(written) == StatusFlag8616.NONE)

    def update_eflags_inc(self, v1: VexExpr) -> None:
        """Update arithmetic flags for an increment result."""
        live_writes = self._live_status_flag_writes_8616(INCDEC_STATUS_FLAG_WRITES_8616)
        if live_writes == StatusFlag8616.NONE:
            return
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + self.constant(1, v1.ty)

        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (StatusFlag8616.PARITY, lambda: self.chk_parity(result)),
                (StatusFlag8616.AUXILIARY, lambda: self._adjust_flag(v1, self.constant(1, v1.ty), result)),
                (StatusFlag8616.ZERO, lambda: result == 0),
                (StatusFlag8616.SIGN, lambda: result[size - 1]),
                (StatusFlag8616.OVERFLOW, lambda: v1 == self.constant((1 << (size - 1)) - 1, v1.ty)),
            ),
            written=INCDEC_STATUS_FLAG_WRITES_8616,
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_add(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for an addition result."""
        live_writes = self._live_status_flag_writes_8616(STATUS_FLAGS_8616)
        if live_writes == StatusFlag8616.NONE:
            return
        v2_expr = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + v2_expr
        wide = self._wider_type(v1.ty)

        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (
                    StatusFlag8616.CARRY,
                    lambda: (
                        (v1.cast_to(wide) + v2_expr.cast_to(wide)) >> size & self.constant(1, wide)
                    ).cast_to(Type.int_1),
                ),
                (StatusFlag8616.PARITY, lambda: self.chk_parity(result)),
                (StatusFlag8616.AUXILIARY, lambda: self._adjust_flag(v1, v2_expr, result)),
                (StatusFlag8616.ZERO, lambda: result == 0),
                (StatusFlag8616.SIGN, lambda: result[size - 1]),
                (
                    StatusFlag8616.OVERFLOW,
                    lambda: (
                        ((~(v1 ^ v2_expr)) & (v1 ^ result)) >> (size - 1) & self.constant(1, v1.ty)
                    ).cast_to(Type.int_1),
                ),
            ),
            written=STATUS_FLAGS_8616,
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_adc(self, v1: VexExpr, v2: FlagValue, carry: FlagValue) -> None:
        """Update arithmetic flags for addition with carry."""
        live_writes = self._live_status_flag_writes_8616(STATUS_FLAGS_8616)
        if live_writes == StatusFlag8616.NONE:
            return
        v2_expr = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        carry_expr = cast(
            VexExpr,
            self.constant(carry, v1.ty) if isinstance(carry, int) else carry.cast_to(v1.ty),
        )
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + v2_expr + carry_expr
        wide = self._wider_type(v1.ty)
        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (
                    StatusFlag8616.CARRY,
                    lambda: (
                        (v1.cast_to(wide) + v2_expr.cast_to(wide) + carry_expr.cast_to(wide))
                        >> size
                        & self.constant(1, wide)
                    ).cast_to(Type.int_1),
                ),
                (StatusFlag8616.PARITY, lambda: self.chk_parity(result)),
                (StatusFlag8616.AUXILIARY, lambda: self._adjust_flag(v1, v2_expr, result)),
                (StatusFlag8616.ZERO, lambda: result == 0),
                (StatusFlag8616.SIGN, lambda: result[size - 1]),
                (
                    StatusFlag8616.OVERFLOW,
                    lambda: (
                        ((~(v1 ^ v2_expr)) & (v1 ^ result)) >> (size - 1) & self.constant(1, v1.ty)
                    ).cast_to(Type.int_1),
                ),
            ),
            written=STATUS_FLAGS_8616,
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def _update_eflags_logical_8616(self, result: VexExpr) -> None:
        """Materialize only live status bits for a logical-operation result."""
        live_writes = self._live_status_flag_writes_8616(STATUS_FLAGS_8616)
        if live_writes == StatusFlag8616.NONE:
            return
        flags = self.get_gpreg(reg16_t.FLAGS)
        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (StatusFlag8616.CARRY, lambda: self.constant(0)),
                (StatusFlag8616.PARITY, lambda: self.chk_parity(result)),
                (StatusFlag8616.AUXILIARY, lambda: self.constant(0, Type.int_1)),
                (StatusFlag8616.ZERO, lambda: result == 0),
                (StatusFlag8616.SIGN, lambda: result[result.width - 1]),
                (StatusFlag8616.OVERFLOW, lambda: self.constant(0)),
            ),
            written=STATUS_FLAGS_8616,
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_or(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a bitwise OR result."""
        v2_expr = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        self._update_eflags_logical_8616(v1 | v2_expr)

    def update_eflags_and(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a bitwise AND result."""
        v2_expr = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        self._update_eflags_logical_8616(v1 & v2_expr)

    def update_eflags_sub(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a subtraction result."""
        live_writes = self._live_status_flag_writes_8616(STATUS_FLAGS_8616)
        if live_writes == StatusFlag8616.NONE:
            return
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2
        size = v1.width

        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (StatusFlag8616.CARRY, lambda: (v1 < v2).cast_to(Type.int_1)),
                (StatusFlag8616.PARITY, lambda: self.chk_parity(result)),
                (StatusFlag8616.AUXILIARY, lambda: self._adjust_flag(v1, v2, result)),
                (StatusFlag8616.ZERO, lambda: result == 0),
                (StatusFlag8616.SIGN, lambda: result[size - 1]),
                (
                    StatusFlag8616.OVERFLOW,
                    lambda: (
                        ((v1 ^ v2) & (v1 ^ result)) >> (size - 1) & self.constant(1, v1.ty)
                    ).cast_to(Type.int_1),
                ),
            ),
            written=STATUS_FLAGS_8616,
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_sbb(self, v1: VexExpr, v2: FlagValue, c: FlagValue) -> None:
        """Update arithmetic flags for subtraction with borrow."""
        live_writes = self._live_status_flag_writes_8616(STATUS_FLAGS_8616)
        if live_writes == StatusFlag8616.NONE:
            return
        v2_expr = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        c_expr = cast(VexExpr, self.constant(c, v1.ty) if isinstance(c, int) else c.cast_to(v1.ty))
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2_expr - c_expr
        size = v1.width
        wider = self._wider_type(v1.ty)
        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (
                    StatusFlag8616.CARRY,
                    lambda: (
                        v1.cast_to(wider) < (v2_expr.cast_to(wider) + c_expr.cast_to(wider))
                    ).cast_to(Type.int_1),
                ),
                (StatusFlag8616.PARITY, lambda: self.chk_parity(result)),
                (StatusFlag8616.AUXILIARY, lambda: self._adjust_flag(v1, v2_expr, result)),
                (StatusFlag8616.ZERO, lambda: result == 0),
                (StatusFlag8616.SIGN, lambda: result[size - 1]),
                (
                    StatusFlag8616.OVERFLOW,
                    lambda: (
                        ((v1 ^ v2_expr) & (v1 ^ result)) >> (size - 1) & self.constant(1, v1.ty)
                    ).cast_to(Type.int_1),
                ),
            ),
            written=STATUS_FLAGS_8616,
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_xor(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a bitwise XOR result."""
        v2_expr = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        self._update_eflags_logical_8616(v1 ^ v2_expr)

    def update_eflags_neg(self, v2: VexExpr) -> None:
        """Update arithmetic flags for a negation result."""
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v2.width
        zero = self.constant(0, v2.ty)
        result = (zero - v2).cast_to(v2.ty)

        flags = self.set_carry(flags, v2 != 0)
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(zero, v2, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, v2 == self.constant(1 << (size - 1), v2.ty))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_dec(self, v1: VexExpr) -> None:
        """Update arithmetic flags for a decrement result."""
        live_writes = self._live_status_flag_writes_8616(INCDEC_STATUS_FLAG_WRITES_8616)
        if live_writes == StatusFlag8616.NONE:
            return
        v2 = self.constant(1, v1.ty)
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2
        size = v1.width

        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (StatusFlag8616.PARITY, lambda: self.chk_parity(result)),
                (StatusFlag8616.AUXILIARY, lambda: self._adjust_flag(v1, v2, result)),
                (StatusFlag8616.ZERO, lambda: result == 0),
                (StatusFlag8616.SIGN, lambda: result[size - 1]),
                (StatusFlag8616.OVERFLOW, lambda: v1 == self.constant(1 << (size - 1), v1.ty)),
            ),
            written=INCDEC_STATUS_FLAG_WRITES_8616,
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_mul(self, v1: VexExpr, v2: VexExpr) -> None:
        """Update arithmetic flags for an unsigned multiply result."""
        type1 = v1.ty
        flags = self.get_gpreg(reg16_t.FLAGS)
        wide_type = self._wider_type(type1)
        result = v1.cast_to(wide_type) * v2.cast_to(wide_type)
        size = v1.width
        high_nonzero = ((result >> size) != self.constant(0, wide_type)).cast_to(Type.int_1)

        flags = self.set_carry(flags, high_nonzero)
        flags = self.set_zero(flags, result.cast_to(type1) == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, high_nonzero)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_imul(self, v1: VexExpr, v2: FlagValue) -> None:
        """Update arithmetic flags for a signed multiply result."""
        v2_expr = cast(VexExpr, self.constant(v2, v1.ty) if isinstance(v2, int) else v2)
        type1 = v1.ty
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        wide_type = Type.int_64 if size == 32 else Type.int_32
        result = v1.widen_signed(wide_type) * v2_expr.widen_signed(wide_type)

        low = result.cast_to(type1)
        high = (result >> self.constant(size, Type.int_8)).cast_to(type1)
        sign_ext = self._ite(
            low[size - 1].cast_to(Type.int_1),
            self.constant((1 << size) - 1, type1),
            self.constant(0, type1),
        ).cast_to(type1)
        sign_ext_ok = (high == sign_ext).cast_to(Type.int_1)
        cfof = (sign_ext_ok == self.constant(0, Type.int_1)).cast_to(Type.int_1)
        flags = self.set_carry(flags, cfof)
        flags = self.set_overflow(flags, cfof)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_shl(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for a logical left shift."""
        const_count = self._const_u8_value(c)
        masked_const_count = None if const_count is None else const_count & 0x1F
        defined_writes = (
            SHIFT_COUNT_MANY_STATUS_FLAG_WRITES_8616
            if masked_const_count is not None and masked_const_count > 1
            else SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616
        )
        live_writes = self._live_status_flag_writes_8616(defined_writes)
        if live_writes == StatusFlag8616.NONE:
            return
        if masked_const_count and masked_const_count <= v.width:
            flags = self.get_gpreg(reg16_t.FLAGS)
            count = self.constant(masked_const_count, Type.int_8)
            result = v << count if live_writes & ~StatusFlag8616.CARRY else None
            carry_live = StatusFlag8616.CARRY | (
                StatusFlag8616.OVERFLOW if masked_const_count == 1 else StatusFlag8616.NONE
            )
            cf = (
                (v >> self.constant(v.width - masked_const_count, Type.int_8))[0].cast_to(Type.int_1)
                if live_writes & carry_live
                else None
            )
            values: StatusFlagValueFactories = (
                (StatusFlag8616.CARRY, lambda: cast(VexExpr, cf)),
                (StatusFlag8616.PARITY, lambda: self.chk_parity(cast(VexExpr, result))),
                (StatusFlag8616.ZERO, lambda: (cast(VexExpr, result) == 0).cast_to(Type.int_1)),
                (StatusFlag8616.SIGN, lambda: cast(VexExpr, result)[v.width - 1].cast_to(Type.int_1)),
            )
            if masked_const_count == 1:
                values += (
                    (
                        StatusFlag8616.OVERFLOW,
                        lambda: (
                        cast(VexExpr, result)[v.width - 1].cast_to(Type.int_1) ^ cast(VexExpr, cf)
                    ).cast_to(Type.int_1),
                    ),
                )
            flags = self._set_live_status_flags_8616(flags, live_writes, values)
            self.set_gpreg(reg16_t.FLAGS, flags)
            return
        c = self._mask_shift_count(c)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v.width
        unchanged = c == self.constant(0, Type.int_8)
        result = v << c if live_writes & ~StatusFlag8616.CARRY else None
        cf = (
            (v >> (self.constant(size, Type.int_8) - c))[0].cast_to(Type.int_1)
            if live_writes & (StatusFlag8616.CARRY | StatusFlag8616.OVERFLOW)
            else None
        )
        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (StatusFlag8616.CARRY, lambda: self._ite(unchanged, self.get_flag(0), cast(VexExpr, cf))),
                (
                    StatusFlag8616.PARITY,
                    lambda: self._ite(unchanged, self.get_flag(2), self.chk_parity(cast(VexExpr, result))),
                ),
                (
                    StatusFlag8616.ZERO,
                    lambda: self._ite(
                        unchanged, self.get_flag(6), (cast(VexExpr, result) == 0).cast_to(Type.int_1)
                    ),
                ),
                (
                    StatusFlag8616.SIGN,
                    lambda: self._ite(
                        unchanged, self.get_flag(7), cast(VexExpr, result)[size - 1].cast_to(Type.int_1)
                    ),
                ),
                (
                    StatusFlag8616.OVERFLOW,
                    lambda: self._ite(
                        unchanged,
                        self.get_flag(11),
                        self._ite(
                            c == self.constant(1, Type.int_8),
                            (
                                cast(VexExpr, result)[size - 1].cast_to(Type.int_1) ^ cast(VexExpr, cf)
                            ).cast_to(Type.int_1),
                            self.get_flag(11),
                        ),
                    ),
                ),
            ),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_double_shift(self, v: VexExpr, result: VexExpr, c: FlagValue, *, left: bool) -> None:
        """Update defined SHLD/SHRD flags from the combined double-shift result."""
        count = self._mask_shift_count(c)
        width = v.width
        defined = count <= self.constant(width, Type.int_8)
        active = defined & (count != self.constant(0, Type.int_8))
        one = count == self.constant(1, Type.int_8)
        if left:
            carry = (v >> (self.constant(width, Type.int_8) - count))[0].cast_to(Type.int_1)
            overflow = (result[width - 1].cast_to(Type.int_1) ^ carry).cast_to(Type.int_1)
        else:
            carry = (v >> (count - self.constant(1, Type.int_8)))[0].cast_to(Type.int_1)
            overflow = (v[width - 1].cast_to(Type.int_1) ^ result[width - 1].cast_to(Type.int_1)).cast_to(
                Type.int_1
            )
        flags = self.get_gpreg(reg16_t.FLAGS)
        flags = self.set_carry(flags, self._ite(active, carry, self.get_flag(0)))
        flags = self.set_parity(flags, self._ite(active, self.chk_parity(result), self.get_flag(2)))
        flags = self.set_zero(flags, self._ite(active, (result == 0).cast_to(Type.int_1), self.get_flag(6)))
        flags = self.set_sign(flags, self._ite(active, result[width - 1].cast_to(Type.int_1), self.get_flag(7)))
        flags = self.set_overflow(flags, self._ite(one, overflow, self.get_flag(11)))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_rol(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for a left rotate."""
        size = v.width
        masked = self._mask_shift_count(c)
        c = masked % self.constant(size, Type.int_8)
        result = (v << c) | (v >> (self.constant(size, Type.int_8) - c))
        flags = self.get_gpreg(reg16_t.FLAGS)
        unchanged = masked == self.constant(0, Type.int_8)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), result[0].cast_to(Type.int_1)))
        flags = self.set_overflow(
            flags,
            self._ite(unchanged, self.get_flag(11), (result[size - 1] ^ result[0]).cast_to(Type.int_1)),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_ror(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for a right rotate."""
        size = v.width
        masked = self._mask_shift_count(c)
        c = masked % self.constant(size, Type.int_8)
        result = (v >> c) | (v << (self.constant(size, Type.int_8) - c))
        flags = self.get_gpreg(reg16_t.FLAGS)
        unchanged = masked == self.constant(0, Type.int_8)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), result[size - 1].cast_to(Type.int_1)))
        flags = self.set_overflow(
            flags,
            self._ite(unchanged, self.get_flag(11), (result[size - 1] ^ result[size - 2]).cast_to(Type.int_1)),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_shr(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for a logical right shift."""
        const_count = self._const_u8_value(c)
        masked_const_count = None if const_count is None else const_count & 0x1F
        defined_writes = (
            SHIFT_COUNT_MANY_STATUS_FLAG_WRITES_8616
            if masked_const_count is not None and masked_const_count > 1
            else SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616
        )
        live_writes = self._live_status_flag_writes_8616(defined_writes)
        if live_writes == StatusFlag8616.NONE:
            return
        if const_count == 1:
            flags = self.get_gpreg(reg16_t.FLAGS)
            result = v >> self.constant(1, Type.int_8) if live_writes & ~(
                StatusFlag8616.CARRY | StatusFlag8616.OVERFLOW
            ) else None
            flags = self._set_live_status_flags_8616(
                flags,
                live_writes,
                (
                    (StatusFlag8616.CARRY, lambda: v[0].cast_to(Type.int_1)),
                    (StatusFlag8616.PARITY, lambda: self.chk_parity(cast(VexExpr, result))),
                    (StatusFlag8616.ZERO, lambda: (cast(VexExpr, result) == 0).cast_to(Type.int_1)),
                    (StatusFlag8616.SIGN, lambda: cast(VexExpr, result)[v.width - 1].cast_to(Type.int_1)),
                    (StatusFlag8616.OVERFLOW, lambda: v[v.width - 1].cast_to(Type.int_1)),
                ),
            )
            self.set_gpreg(reg16_t.FLAGS, flags)
            return
        c = self._mask_shift_count(c)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v.width
        unchanged = c == self.constant(0, Type.int_8)
        result = v >> c if live_writes & (StatusFlag8616.PARITY | StatusFlag8616.ZERO | StatusFlag8616.SIGN) else None
        cf = (
            (v >> (c - self.constant(1, Type.int_8)))[0].cast_to(Type.int_1)
            if live_writes & StatusFlag8616.CARRY
            else None
        )
        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (StatusFlag8616.CARRY, lambda: self._ite(unchanged, self.get_flag(0), cast(VexExpr, cf))),
                (
                    StatusFlag8616.PARITY,
                    lambda: self._ite(unchanged, self.get_flag(2), self.chk_parity(cast(VexExpr, result))),
                ),
                (
                    StatusFlag8616.ZERO,
                    lambda: self._ite(
                        unchanged, self.get_flag(6), (cast(VexExpr, result) == 0).cast_to(Type.int_1)
                    ),
                ),
                (
                    StatusFlag8616.SIGN,
                    lambda: self._ite(
                        unchanged, self.get_flag(7), cast(VexExpr, result)[size - 1].cast_to(Type.int_1)
                    ),
                ),
                (
                    StatusFlag8616.OVERFLOW,
                    lambda: self._ite(
                        unchanged,
                        self.get_flag(11),
                        self._ite(
                            c == self.constant(1, Type.int_8), v[size - 1].cast_to(Type.int_1), self.get_flag(11)
                        ),
                    ),
                ),
            ),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_sar(self, v: VexExpr, c: FlagValue) -> None:
        """Update arithmetic flags for an arithmetic right shift."""
        const_count = self._const_u8_value(c)
        masked_const_count = None if const_count is None else const_count & 0x1F
        defined_writes = (
            SHIFT_COUNT_MANY_STATUS_FLAG_WRITES_8616
            if masked_const_count is not None and masked_const_count > 1
            else SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616
        )
        live_writes = self._live_status_flag_writes_8616(defined_writes)
        if live_writes == StatusFlag8616.NONE:
            return
        if const_count == 1:
            flags = self.get_gpreg(reg16_t.FLAGS)
            result = v.sar(self.constant(1, Type.int_8)) if live_writes & ~(
                StatusFlag8616.CARRY | StatusFlag8616.OVERFLOW
            ) else None
            flags = self._set_live_status_flags_8616(
                flags,
                live_writes,
                (
                    (StatusFlag8616.CARRY, lambda: v[0].cast_to(Type.int_1)),
                    (StatusFlag8616.PARITY, lambda: self.chk_parity(cast(VexExpr, result))),
                    (StatusFlag8616.ZERO, lambda: (cast(VexExpr, result) == 0).cast_to(Type.int_1)),
                    (StatusFlag8616.SIGN, lambda: cast(VexExpr, result)[v.width - 1].cast_to(Type.int_1)),
                    (StatusFlag8616.OVERFLOW, lambda: self.constant(0, Type.int_1)),
                ),
            )
            self.set_gpreg(reg16_t.FLAGS, flags)
            return
        c = self._mask_shift_count(c)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v.width
        unchanged = c == self.constant(0, Type.int_8)
        result = v.sar(c) if live_writes & (StatusFlag8616.PARITY | StatusFlag8616.ZERO | StatusFlag8616.SIGN) else None
        cf = (
            v.sar(c - self.constant(1, Type.int_8))[0].cast_to(Type.int_1)
            if live_writes & StatusFlag8616.CARRY
            else None
        )
        flags = self._set_live_status_flags_8616(
            flags,
            live_writes,
            (
                (StatusFlag8616.CARRY, lambda: self._ite(unchanged, self.get_flag(0), cast(VexExpr, cf))),
                (
                    StatusFlag8616.PARITY,
                    lambda: self._ite(unchanged, self.get_flag(2), self.chk_parity(cast(VexExpr, result))),
                ),
                (
                    StatusFlag8616.ZERO,
                    lambda: self._ite(
                        unchanged, self.get_flag(6), (cast(VexExpr, result) == 0).cast_to(Type.int_1)
                    ),
                ),
                (
                    StatusFlag8616.SIGN,
                    lambda: self._ite(
                        unchanged, self.get_flag(7), cast(VexExpr, result)[size - 1].cast_to(Type.int_1)
                    ),
                ),
                (
                    StatusFlag8616.OVERFLOW,
                    lambda: self._ite(unchanged, self.get_flag(11), self.constant(0, Type.int_1)),
                ),
            ),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def chk_parity(self, v: FlagValue) -> VexExpr:
        """Return one when the low byte has even parity."""
        v = self.constant(v, Type.int_8) if isinstance(v, int) else v.cast_to(Type.int_8)
        parity = v ^ (v >> self.constant(4, Type.int_8))
        parity = parity ^ (parity >> self.constant(2, Type.int_8))
        parity = parity ^ (parity >> self.constant(1, Type.int_8))
        return ((~parity) & self.constant(1, Type.int_8)).cast_to(Type.int_1)

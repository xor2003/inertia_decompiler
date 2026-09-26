"""Layer: Helper boundary.

Responsibility: decode operands into segmented IR addresses plus execution-only linear addresses.
Forbidden: flattening SS/DS/ES into semantic storage identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from pyvex.lifting.util.vex_helper import Type

from .ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .regs import reg16_t, reg32_t, sgreg_t


class _AddressValue(Protocol):
    """VEX helper value operations used while computing effective addresses."""

    def __add__(self, _other: object) -> _AddressValue:
        """Return this address value plus another helper value."""
        ...

    def __mul__(self, _other: int) -> _AddressValue:
        """Return this address value multiplied by a scale."""
        ...


class _AddressingEmulator(Protocol):
    """Frontend emulator surface needed by addressing helpers."""

    def constant(self, value: int, _ty: object) -> _AddressValue:
        """Return a VEX constant wrapper."""
        ...

    def get_gpreg(self, reg: object) -> _AddressValue:
        """Read a general-purpose register value."""
        ...

    def v2p(self, segment: object, offset: object) -> object:
        """Return an execution-linear address for segment:offset."""
        ...

    def convert_ss_vaddr(self, offset: object) -> object:
        """Return an execution-linear SS-relative address."""
        ...

    def get_data8(self, segment: object, offset: object) -> object:
        """Read 8-bit segmented data."""
        ...

    def get_data16(self, segment: object, offset: object) -> object:
        """Read 16-bit segmented data."""
        ...

    def get_data32(self, segment: object, offset: object) -> object:
        """Read 32-bit segmented data."""
        ...

    def put_data8(self, segment: object, offset: object, value: object) -> None:
        """Write 8-bit segmented data."""
        ...

    def put_data16(self, segment: object, offset: object, value: object) -> None:
        """Write 16-bit segmented data."""
        ...

    def put_data32(self, segment: object, offset: object, value: object) -> None:
        """Write 32-bit segmented data."""
        ...


class _ExpressionFactory(Protocol):
    """pyvex expression constructor shape used when rebuilding expression args."""

    def __call__(self, _op: object, _args: object) -> object:
        """Build a pyvex expression with a replacement argument list."""
        ...


class _ModRM(Protocol):
    """Decoded ModRM fields consumed by addressing helpers."""

    mod: int
    rm: int


class _SIB(Protocol):
    """Decoded SIB fields consumed by 32-bit addressing helpers."""

    base: int
    index: int
    scale: int


def operand_width_bits(mode32: bool, chsz_op: bool = False) -> int:
    """Return the operand width after applying the operand-size override bit."""
    return 32 if mode32 ^ bool(chsz_op) else 16


def address_width_bits(mode32: bool, chsz_ad: bool = False) -> int:
    """Return the address width after applying the address-size override bit."""
    return 32 if mode32 ^ bool(chsz_ad) else 16


@dataclass(frozen=True)
class WidthProfile:
    """Operand/address width pair for a decode mode."""

    operand_bits: int
    address_bits: int

    @property
    def operand_bytes(self) -> int:
        """Return operand width in bytes."""
        return self.operand_bits // 8

    @property
    def address_bytes(self) -> int:
        """Return address width in bytes."""
        return self.address_bits // 8


def decode_width_profile(mode32: bool, chsz_op: bool = False, chsz_ad: bool = False) -> WidthProfile:
    """Build a width profile from mode and override-prefix bits."""
    return WidthProfile(
        operand_bits=operand_width_bits(mode32, chsz_op),
        address_bits=address_width_bits(mode32, chsz_ad),
    )


@dataclass(frozen=True)
class DecodeWidthMatrixCase:
    """Named decode-width matrix row used by diagnostics and tests."""

    name: str
    mode32: bool
    chsz_op: bool
    chsz_ad: bool
    profile: WidthProfile


DECODE_WIDTH_MATRIX: tuple[DecodeWidthMatrixCase, ...] = (
    DecodeWidthMatrixCase("16/16", False, False, False, decode_width_profile(False, False, False)),
    DecodeWidthMatrixCase("32/16", False, True, False, decode_width_profile(False, True, False)),
    DecodeWidthMatrixCase("16/32", False, False, True, decode_width_profile(False, False, True)),
    DecodeWidthMatrixCase("32/32", True, False, False, decode_width_profile(True, False, False)),
)


def decode_width_case(mode32: bool, chsz_op: bool = False, chsz_ad: bool = False) -> DecodeWidthMatrixCase:
    """Return the named width-matrix case for mode and override-prefix bits."""
    for case in DECODE_WIDTH_MATRIX:
        if case.mode32 == mode32 and case.chsz_op == chsz_op and case.chsz_ad == chsz_ad:
            return case
    raise ValueError(f"unsupported width case: mode32={mode32} chsz_op={chsz_op} chsz_ad={chsz_ad}")


def decode_width_case_for_profile(operand_bits: int, address_bits: int) -> DecodeWidthMatrixCase:
    """Return the named width-matrix case for an explicit width profile."""
    for case in DECODE_WIDTH_MATRIX:
        if case.profile.operand_bits == operand_bits and case.profile.address_bits == address_bits:
            return case
    raise ValueError(f"unsupported width profile: operand_bits={operand_bits} address_bits={address_bits}")


def displacement_width_bits(mod: int, rm: int, address_bits: int) -> int | None:
    """Return displacement width for a ModRM memory operand, if any."""
    if address_bits == 16:
        if mod == 0 and rm == 6:
            return 16
        if mod == 1:
            return 8
        if mod == 2:
            return 16
        return None
    if mod == 0 and rm == 5:
        return 32
    if mod == 1:
        return 8
    if mod == 2:
        return 32
    return None


def signed_displacement(value: int, width_bits: int) -> int:
    """Sign-extend an unsigned displacement of the requested bit width."""
    mask = (1 << width_bits) - 1
    value &= mask
    sign_bit = 1 << (width_bits - 1)
    if value & sign_bit:
        return value - (1 << width_bits)
    return value


def type_for_bits(width_bits: int) -> object:
    """Return the VEX helper integer type for a bit width."""
    if width_bits == 8:
        return Type.int_8
    if width_bits == 16:
        return Type.int_16
    if width_bits == 32:
        return Type.int_32
    raise ValueError(f"unsupported width: {width_bits}")


def address_step(emu: object, step_bytes: int, address_bits: int = 16) -> _AddressValue:
    """Return a VEX constant step for address arithmetic."""
    return cast(_AddressingEmulator, emu).constant(step_bytes, type_for_bits(address_bits))


def describe_x86_16_decode_width_matrix() -> tuple[tuple[str, int, int], ...]:
    """Return compact decode-width matrix rows for diagnostics."""
    return tuple((case.name, case.profile.operand_bits, case.profile.address_bits) for case in DECODE_WIDTH_MATRIX)


def describe_x86_16_mixed_width_extension_surface() -> dict[str, object]:
    """Describe the mixed-width decode surface exposed to tests and reports."""
    return {
        "matrix": tuple(
            {
                "name": case.name,
                "operand_bits": case.profile.operand_bits,
                "address_bits": case.profile.address_bits,
                "mode32": case.mode32,
                "chsz_op": case.chsz_op,
                "chsz_ad": case.chsz_ad,
            }
            for case in DECODE_WIDTH_MATRIX
        ),
        "supported_pairs": tuple(
            (case.profile.operand_bits, case.profile.address_bits) for case in DECODE_WIDTH_MATRIX
        ),
        "address_widths": tuple(sorted({case.profile.address_bits for case in DECODE_WIDTH_MATRIX})),
        "operand_widths": tuple(sorted({case.profile.operand_bits for case in DECODE_WIDTH_MATRIX})),
    }


def describe_x86_16_mixed_width_instruction_surface() -> dict[str, object]:
    """Describe how mixed-width facts are consumed by instruction helpers."""
    return {
        "boundary": "mixed-width decode facts feed shared helpers instead of handler-local branches",
        "consumer_paths": (
            "angr_platforms/X86_16/parse.py",
            "angr_platforms/X86_16/exec.py",
            "angr_platforms/X86_16/instruction.py",
            "angr_platforms/X86_16/instr16.py",
            "angr_platforms/X86_16/instr32.py",
        ),
        "validated_by": (
            "tests/test_x86_16_addressing_helpers.py",
            "tests/test_x86_16_decode_metadata.py",
            "tests/test_x86_16_instruction_core_factoring.py",
        ),
        "matrix": describe_x86_16_mixed_width_extension_surface()["matrix"],
    }


def linear_address(emu: object, segment: object, offset: object) -> object:
    """Return the execution-only linear address for a segment:offset pair."""
    # EXECUTION ONLY. Forbidden for alias/type/rewrite semantics.
    return cast(_AddressingEmulator, emu).v2p(segment, offset)


def resolve_memory_operand_8616(
    emu: object,
    seg: object,
    addr: object,
    width_bits: int,
    *,
    address_bits: int = 16,
) -> ResolvedMemoryOperand:
    """Resolve a memory operand into execution-linear and semantic segmented forms."""
    # EXECUTION ONLY: exec_linear is computed for the engine, not for semantics.
    # Alias/type/structuring layers MUST use operand.ir_address() instead.
    emulator = cast(_AddressingEmulator, emu)
    if isinstance(seg, sgreg_t) and seg == sgreg_t.SS:
        exec_linear = emulator.convert_ss_vaddr(addr)
    else:
        exec_linear = emulator.v2p(seg, addr)
    return ResolvedMemoryOperand(seg, addr, exec_linear, width_bits, address_bits)


@dataclass(frozen=True)
class ResolvedMemoryOperand:
    """Resolved memory operand carrying execution and semantic address views."""

    segment: object
    offset: object
    exec_linear: object
    width_bits: int
    address_bits: int

    @property
    def linear(self) -> object:
        """Deprecated: use exec_linear for execution-only linear address.

        This property exists only for backward compatibility.
        Forbidden for alias/type/rewrite semantics — use ir_address() instead.
        """
        return self.exec_linear

    def ir_address(self, *, expr: tuple[str, ...] | None = None) -> IRAddress:
        """Semantic IR address — the ONLY path for alias/type/structuring layers."""
        return self.typed_address(expr=expr)

    def assert_semantic_safe(self) -> None:
        """Block accidental use of linear address in semantic layers.

        Raises PipelineHardError if exec_linear leaks into non-execution code.
        AGENTS rule #3: segmented memory; exec_linear is execution-only.
        """
        from .ir.core import IRAddress
        from .pipeline.errors import PipelineHardError

        if isinstance(self.exec_linear, IRAddress):
            raise PipelineHardError(
                "exec_linear must not be an IRAddress — linear is execution-only, use ir_address() for semantic layers",
                layer="addressing",
            )

    def _segment_address_fields(self) -> tuple[object, bool, bool, tuple[str, ...], int, object]:
        """Compute space, stability, base, size, and segment origin for this access."""
        space_map = {
            sgreg_t.SS: MemSpace.SS,
            sgreg_t.DS: MemSpace.DS,
            sgreg_t.ES: MemSpace.ES,
            sgreg_t.CS: MemSpace.UNKNOWN,
            MemSpace.SS: MemSpace.SS,
            MemSpace.DS: MemSpace.DS,
            MemSpace.ES: MemSpace.ES,
            MemSpace.UNKNOWN: MemSpace.UNKNOWN,
        }
        segment = self.segment
        space = (
            space_map.get(segment, MemSpace.UNKNOWN)
            if isinstance(segment, (sgreg_t, MemSpace))
            else MemSpace.UNKNOWN
        )
        explicit_segment = isinstance(self.segment, (sgreg_t, MemSpace)) and space != MemSpace.UNKNOWN
        stable = explicit_segment and space in {MemSpace.SS, MemSpace.DS, MemSpace.ES}
        base: tuple[str, ...]
        if isinstance(self.segment, sgreg_t):
            base = (self.segment.name.lower(),)
        elif isinstance(self.segment, MemSpace) and self.segment != MemSpace.UNKNOWN:
            base = (self.segment.value,)
        else:
            base = ()

        size = max(1, self.width_bits // 8) if isinstance(self.width_bits, int) and self.width_bits > 0 else 0
        seg_origin = (
            SegmentOrigin.PROVEN
            if explicit_segment
            else (SegmentOrigin.DEFAULTED if space != MemSpace.UNKNOWN else SegmentOrigin.UNKNOWN)
        )
        return space, explicit_segment, stable, base, size, seg_origin

    def _raw_offset_and_tmp_defs(self) -> tuple[object, dict[int, object] | None]:
        """Unwrap the VexValue offset and resolve RdTmp chains through the IRSB."""
        offset_raw = self.offset
        tmp_defs = None
        # Dynamic boundary: offset may be a third-party pyvex VexValue wrapper.
        if hasattr(self.offset, "rdt"):
            # Dynamic boundary: third-party pyvex VexValue exposes rdt dynamically.
            offset_raw = getattr(self.offset, "rdt", self.offset)
            # Dynamic boundary: pyvex customizers expose IRSB state at runtime.
            irsb_c = getattr(self.offset, "irsb_c", None)
            if irsb_c is not None:
                tmp_defs = _build_tmp_defs_from_irsb(irsb_c)
                offset_raw = _resolve_rdtmp_chain(offset_raw, tmp_defs)
        return offset_raw, tmp_defs

    def typed_address(self, *, expr: tuple[str, ...] | None = None) -> IRAddress:
        """Return a segmented IR address for alias/type/structuring consumers.

        Dynamic boundary: third-party pyvex expressions expose runtime fields
        such as rdt, irsb_c, op, args, tmp, and register offsets.
        """

        def _impl() -> IRAddress:
            """Build an IRAddress from third-party pyvex dynamic-boundary fields."""
            space, _explicit_segment, stable, base, size, seg_origin = self._segment_address_fields()
            offset_raw, tmp_defs = self._raw_offset_and_tmp_defs()

            # Integer offset
            if isinstance(offset_raw, int):
                # IMPORTANT:
                # SS memory activity is not automatically a stack variable.
                #
                # The following are intentionally PROVISIONAL:
                #   - push/pop traffic
                #   - transient SP movement
                #   - call frame setup
                #   - unresolved symbolic SP expressions
                #
                # Only proven frame-relative accesses
                # (BP+const or proven SP+stable_delta+const)
                # may become STABLE stack slots.
                #
                # AGENTS rule:
                # stack activity != materializable variable
                if space == MemSpace.SS and not base:
                    base = ("ss",)
                # DS/ES:int — stable memory address
                return IRAddress(
                    space=space,
                    base=base,
                    offset=offset_raw,
                    size=size,
                    status=AddressStatus.STABLE if stable else AddressStatus.PROVISIONAL,
                    segment_origin=seg_origin,
                    expr=expr,
                )

            # Symbolic offset — try to extract BP-relative constant
            extracted = extract_bp_relative_offset_8616(offset_raw, tmp_defs=tmp_defs)
            if extracted is not None:
                offset_val, _bp_base = extracted
                # BP-relative stack slot: STABLE status, base = ("bp",)
                if space == MemSpace.SS:
                    base = ("bp",)
                return IRAddress(
                    space=space,
                    base=base,
                    offset=offset_val,
                    size=size,
                    status=AddressStatus.STABLE,
                    segment_origin=seg_origin,
                    expr=None,
                )

            # Not BP-relative: return PROVISIONAL — do NOT fake offset 0
            return IRAddress(
                space=space,
                base=base,
                offset=0,
                size=size,
                status=AddressStatus.PROVISIONAL,
                segment_origin=seg_origin,
                expr=(str(self.offset),) if self.offset is not None else expr,
            )

        return _impl()


def default_segment_for_modrm16(mod: int, rm: int) -> sgreg_t:
    """Return the default segment register for a 16-bit ModRM operand."""
    if rm in (2, 3):
        return sgreg_t.SS
    if rm == 6 and mod != 0:
        return sgreg_t.SS
    return sgreg_t.DS


def default_segment_for_modrm32(mod: int, rm: int, sib_base: int | None = None) -> sgreg_t:
    """Return the default segment register for a 32-bit ModRM/SIB operand."""
    if rm == 4 and sib_base is not None:
        if sib_base == 4 or (sib_base == 5 and mod != 0):
            return sgreg_t.SS
        return sgreg_t.DS
    if rm == 5 and mod != 0:
        return sgreg_t.SS
    return sgreg_t.DS


def modrm16_effective_offset(emu: object, modrm: _ModRM, disp8: int, disp16: int) -> _AddressValue:
    """Compute the 16-bit effective offset expression for a ModRM operand."""
    emulator = cast(_AddressingEmulator, emu)
    addr = emulator.constant(0, Type.int_16)

    if modrm.mod == 1:
        addr = addr + emulator.constant(signed_displacement(disp8, 8) & 0xFFFF, Type.int_16)
    elif modrm.mod == 2:
        addr = addr + emulator.constant(disp16, Type.int_16)

    rm = modrm.rm
    if rm in (0, 1, 7):
            addr = addr + emulator.get_gpreg(reg16_t.BX)
    elif rm in (2, 3, 6):
        if modrm.mod == 0 and rm == 6:
            addr = addr + emulator.constant(disp16, Type.int_16)
        else:
            addr = addr + emulator.get_gpreg(reg16_t.BP)

    if rm < 6:
        addr = addr + emulator.get_gpreg(reg16_t.DI) if rm % 2 else addr + emulator.get_gpreg(reg16_t.SI)

    return addr


def modrm32_effective_offset(
    emu: object, modrm: _ModRM, sib: _SIB, disp8: int, disp32: int
) -> _AddressValue:
    """Compute the 32-bit effective offset expression for a ModRM/SIB operand."""
    emulator = cast(_AddressingEmulator, emu)
    addr = emulator.constant(0, Type.int_32)

    if modrm.mod == 1:
        addr = addr + emulator.constant(signed_displacement(disp8, 8) & 0xFFFFFFFF, Type.int_32)
    elif modrm.mod == 2:
        addr = addr + emulator.constant(disp32, Type.int_32)

    rm = modrm.rm
    if rm == 4:
        if sib.base == 5 and modrm.mod == 0:
            base = emulator.constant(disp32, Type.int_32)
        elif sib.base == 4:
            base = emulator.get_gpreg(reg32_t.ESP)
        else:
            base = emulator.get_gpreg(reg32_t(sib.base))
        index = emulator.constant(0, Type.int_32) if sib.index == 4 else emulator.get_gpreg(reg32_t(sib.index))
        addr = addr + base + index * (1 << sib.scale)
        return addr

    if rm == 5 and modrm.mod == 0:
        return addr + emulator.constant(disp32, Type.int_32)
    return addr + emulator.get_gpreg(reg32_t(rm))


def resolve_modrm16_address(
    emu: object, modrm: _ModRM, disp8: int, disp16: int
) -> tuple[sgreg_t, object]:
    """Resolve a 16-bit ModRM memory address to segment and offset expression."""
    segment = default_segment_for_modrm16(modrm.mod, modrm.rm)
    return segment, modrm16_effective_offset(emu, modrm, disp8, disp16)


def resolve_modrm32_address(
    emu: object, modrm: _ModRM, sib: _SIB, disp8: int, disp32: int
) -> tuple[sgreg_t, object]:
    """Resolve a 32-bit ModRM/SIB memory address to segment and offset expression."""
    segment = default_segment_for_modrm32(modrm.mod, modrm.rm, sib.base if modrm.rm == 4 else None)
    return segment, modrm32_effective_offset(emu, modrm, sib, disp8, disp32)


def resolve_linear_operand(
    emu: object, segment: sgreg_t, offset: object, width_bits: int, address_bits: int
) -> ResolvedMemoryOperand:
    """Resolve an already-decoded operand while keeping linear address execution-only."""
    # EXECUTION ONLY
    return ResolvedMemoryOperand(segment, offset, linear_address(emu, segment, offset), width_bits, address_bits)


def load_resolved_operand(emu: object, operand: ResolvedMemoryOperand) -> object:
    """Load a value from a resolved segmented operand."""
    emulator = cast(_AddressingEmulator, emu)
    if operand.width_bits == 8:
        return emulator.get_data8(operand.segment, operand.offset)
    if operand.width_bits == 16:
        return emulator.get_data16(operand.segment, operand.offset)
    if operand.width_bits == 32:
        return emulator.get_data32(operand.segment, operand.offset)
    raise ValueError(f"unsupported resolved operand width: {operand.width_bits}")


def store_resolved_operand(emu: object, operand: ResolvedMemoryOperand, value: object) -> None:
    """Store a value through a resolved segmented operand."""
    emulator = cast(_AddressingEmulator, emu)
    if operand.width_bits == 8:
        emulator.put_data8(operand.segment, operand.offset, value)
        return
    if operand.width_bits == 16:
        emulator.put_data16(operand.segment, operand.offset, value)
        return
    if operand.width_bits == 32:
        emulator.put_data32(operand.segment, operand.offset, value)
        return
    raise ValueError(f"unsupported resolved operand width: {operand.width_bits}")


def load_word_pair16(
    emu: object, segment: sgreg_t, offset: object, address_bits: int = 16
) -> tuple[object, object]:
    """Load two adjacent 16-bit words from segmented memory."""
    emulator = cast(_AddressingEmulator, emu)
    if isinstance(offset, int):
        offset = emulator.constant(offset, type_for_bits(address_bits))
    offset_value = cast(_AddressValue, offset)
    step = address_step(emu, 2, address_bits)
    first = emulator.get_data16(segment, offset_value)
    second = emulator.get_data16(segment, offset_value + step)
    return first, second


def load_far_pointer(
    emu: object, segment: sgreg_t, offset: object, operand_bits: int, address_bits: int = 16
) -> tuple[object, object]:
    """Load a far pointer with a 16- or 32-bit offset plus 16-bit segment."""
    emulator = cast(_AddressingEmulator, emu)
    if isinstance(offset, int):
        offset = emulator.constant(offset, type_for_bits(address_bits))
    offset_value = cast(_AddressValue, offset)
    step = address_step(emu, operand_bits // 8, address_bits)
    if operand_bits == 16:
        far_offset = emulator.get_data16(segment, offset_value)
    elif operand_bits == 32:
        far_offset = emulator.get_data32(segment, offset_value)
    else:
        raise ValueError(f"unsupported far pointer operand width: {operand_bits}")
    far_segment = emulator.get_data16(segment, offset_value + step)
    return far_offset, far_segment


def load_far_pointer16(
    emu: object, segment: sgreg_t, offset: object, address_bits: int = 16
) -> tuple[object, object]:
    """Load a legacy 16:16 far pointer."""
    return load_word_pair16(emu, segment, offset, address_bits=address_bits)


def _build_tmp_defs_from_irsb(irsb_c: object) -> dict[int, object]:
    """Build a tmp_index → WrTmp statement mapping from an IRSB or IRSBCustomizer.

    Dynamic boundary: third-party pyvex IRSB objects expose statements and tmp
    fields dynamically.
    """
    tmp_defs: dict[int, object] = {}
    if irsb_c is None:
        return tmp_defs
    # Dynamic boundary: pyvex customizers and IRSBs expose statements at runtime.
    # Unwrap IRSBCustomizer to underlying IRSB
    irsb = getattr(irsb_c, "irsb", irsb_c)
    stmts = getattr(irsb, "statements", None) or ()
    for stmt in stmts:
        # Dynamic boundary: pyvex WrTmp statements expose tmp numbers dynamically.
        stmt_tmp = getattr(stmt, "tmp", None)
        if isinstance(stmt_tmp, int):
            tmp_defs[stmt_tmp] = stmt
    return tmp_defs


def _resolve_rdtmp_chain(expr: object, tmp_defs: dict[int, object]) -> object:
    """Resolve RdTmp nodes to their defining expressions, recursively.

    Dynamic boundary: third-party pyvex expression objects expose class names,
    op, args, tmp, and statement data dynamically.
    """
    if not isinstance(tmp_defs, dict) or not tmp_defs:
        return expr

    # Dynamic boundary: pyvex expression classes expose names and fields dynamically.
    class_name = getattr(type(expr), "__name__", "")
    if "RdTmp" in class_name:
        tmp_idx = getattr(expr, "tmp", None)
        if isinstance(tmp_idx, int) and tmp_idx in tmp_defs:
            stmt = tmp_defs[tmp_idx]
            stmt_expr = getattr(stmt, "data", None)
            if stmt_expr is not None:
                # Recursively resolve — the defining expression may contain RdTmps too
                return _resolve_rdtmp_chain(stmt_expr, tmp_defs)

    # For Binop/Unop/etc, resolve args recursively
    # Dynamic boundary: pyvex expression args/op are runtime attributes.
    args = getattr(expr, "args", None)
    if args is not None:
        resolved_args = [_resolve_rdtmp_chain(a, tmp_defs) for a in args]
        if resolved_args != list(args):
            factory = cast(_ExpressionFactory, type(expr))
            # Dynamic boundary: third-party pyvex expressions expose op dynamically.
            new_expr = factory(getattr(expr, "op", None), resolved_args)
            return new_expr

    return expr


def extract_bp_relative_offset_8616(
    offset_expr: object, *, tmp_defs: dict[int, object] | None = None
) -> tuple[int, tuple[str, ...]] | None:
    """Extract a proven BP-relative constant offset from a VEX offset expression.

    Dynamic boundary: third-party pyvex Binop/Get/Const nodes expose op and args
    dynamically.
    """

    def _impl() -> tuple[int, tuple[str, ...]] | None:
        """Match BP-relative forms through third-party pyvex dynamic-boundary fields."""
        nonlocal offset_expr
        # Resolve RdTmp → defining expression if tmp_defs available
        if tmp_defs is not None:
            offset_expr = _resolve_rdtmp_chain(offset_expr, tmp_defs)

        # Integer offset: pass through
        if isinstance(offset_expr, int):
            return (offset_expr, ("bp",))

        # VEX expression: try to match BP +/- const pattern
        # Dynamic boundary: pyvex Binop/Const/Get nodes expose op and args at runtime.
        op = getattr(offset_expr, "op", None)
        if op is None:
            return None

        op_str = str(op)
        args = getattr(offset_expr, "args", None) or []

        if len(args) < 2:
            # Unary or single-arg — check if it's just BP
            for arg in args:
                if _is_bp_reg(arg, tmp_defs=tmp_defs):
                    return (0, ("bp",))
            return None

        # Flatten nested Add/Sub chains into terms
        collected = _collect_add_sub_terms(offset_expr, tmp_defs=tmp_defs)
        if collected is None:
            return _bp_add_sub_fallback_8616(op_str, args, tmp_defs)

        terms, const = collected

        # Accept: BP (+ SI/DI) + const
        has_bp = any(_is_bp_reg(term, tmp_defs=tmp_defs) for term in terms)
        non_reg_terms = [t for t in terms if not _is_bp_reg(t, tmp_defs=tmp_defs) and not _is_index_reg_8616(t)]

        if has_bp and not non_reg_terms:
            # BP only or BP + index: accept
            return (const & 0xFFFF, ("bp",))

        return None

    return _impl()


def _collect_add_sub_terms(
    expr: object,
    *,
    tmp_defs: dict[int, object] | None = None,
) -> tuple[list[object], int] | None:
    """Flatten supported pyvex add/sub expression trees into terms and constants.

    Dynamic boundary: third-party pyvex expression trees expose op, tag, con,
    args, and register fields dynamically.
    """

    def _impl() -> tuple[list[object], int] | None:
        """Flatten terms through third-party pyvex dynamic-boundary fields."""
        nonlocal expr
        # Resolve RdTmp chains through tmp_defs first
        if tmp_defs is not None:
            expr = _resolve_rdtmp_chain(expr, tmp_defs)

        # Dynamic boundary: pyvex expression trees expose op/tag/con/args dynamically.
        op = getattr(expr, "op", None)
        if op is None:
            return _leaf_add_sub_terms(expr)

        op_str = str(op)
        args = getattr(expr, "args", None) or []
        if not args:
            return None

        if op_str in {"Iop_Add16", "Iop_Add32"}:
            return _combine_add_sub_terms(args, tmp_defs=tmp_defs, subtract=False)
        if op_str in {"Iop_Sub16", "Iop_Sub32"}:
            return _combine_add_sub_terms(args, tmp_defs=tmp_defs, subtract=True)

        if isinstance(expr, int):
            return ([], expr & 0xFFFF)
        reg_offset = getattr(expr, "reg", None)
        if isinstance(reg_offset, int):
            return ([expr], 0)

        return None

    return _impl()


def _bp_add_sub_fallback_8616(
    op_str: str, args: list[object], tmp_defs: dict[int, object] | None
) -> tuple[int, tuple[str, ...]] | None:
    """Match the simple two-argument ``BP +/- const`` VEX pattern."""
    # Fallback to simple 2-arg patterns
    left, right = args[0], args[1]
    if op_str in {"Iop_Add16", "Iop_Add32"}:
        if _is_bp_reg(left, tmp_defs=tmp_defs) and isinstance(right, int):
            return (right & 0xFFFF, ("bp",))
        if isinstance(left, int) and _is_bp_reg(right, tmp_defs=tmp_defs):
            return (left & 0xFFFF, ("bp",))
    if op_str in {"Iop_Sub16", "Iop_Sub32"}:  # noqa: SIM102
        if _is_bp_reg(left, tmp_defs=tmp_defs) and isinstance(right, int):
            return (-(right & 0xFFFF), ("bp",))
    return None


def _leaf_add_sub_terms(expr: object) -> tuple[list[object], int]:
    """Classify a leaf expression as a term or a folded constant."""
    # Leaf expression: VEX Get, RdTmp, Const, or int literal.
    # These are atomic terms — return them as a single-term list.
    # Handle VEX Const objects (tag=Iex_Const, .con.value)
    tag = getattr(expr, "tag", None)
    if tag == "Iex_Const":
        con = getattr(expr, "con", None)
        if con is not None:
            val = getattr(con, "value", None)
            if isinstance(val, int):
                return ([], val & 0xFFFF)
    if isinstance(expr, int):
        return ([], expr & 0xFFFF)
    return ([expr], 0)


def _combine_add_sub_terms(
    args: list[object],
    *,
    tmp_defs: dict[int, object] | None,
    subtract: bool,
) -> tuple[list[object], int] | None:
    """Combine both sides of an add/sub node into flattened terms and a folded constant."""
    left_res = _collect_add_sub_terms(args[0], tmp_defs=tmp_defs)
    right_res = _collect_add_sub_terms(args[1], tmp_defs=tmp_defs)
    if left_res is None or right_res is None:
        return ([args[0], args[1]], 0)
    left_terms, left_const = left_res
    right_terms, right_const = right_res
    if left_terms is not None and right_terms is not None:
        folded = (left_const - right_const) if subtract else (left_const + right_const)
        return (left_terms + right_terms, folded & 0xFFFF)
    # One side may be non-decomposable; treat it as a term
    if left_terms is not None:
        return ([*left_terms, args[1]], left_const & 0xFFFF)
    if right_terms is not None:
        return ([*right_terms, args[0]], ((-right_const) if subtract else right_const) & 0xFFFF)
    return ([args[0], args[1]], 0)


def _is_index_reg_8616(expr: object) -> bool:
    """Check if a VEX expression is SI or DI.

    Dynamic boundary: third-party pyvex Get nodes expose class names and offsets
    dynamically.

    VEX guest state offsets (from archinfo arch_from_id('x86_16')):
      si → offset=32
      di → offset=36
    The reg16_t enum values (SI=6, DI=7) are NOT VEX guest offsets.
    """
    # Dynamic boundary: pyvex Get nodes expose class names and offsets at runtime.
    class_name = getattr(type(expr), "__name__", "")
    if "Get" in class_name:
        offset = getattr(expr, "offset", None)
        if isinstance(offset, int) and offset in {12, 14, 32, 36}:
            return True

    # Obsolete path: reg16_t enum values (never matched VEX expressions)
    reg_offset = getattr(expr, "reg", None)
    return bool(isinstance(reg_offset, int) and reg_offset in {6, 7})


def _is_bp_reg(expr: object, *, tmp_defs: dict[int, object] | None = None) -> bool:
    """Check if a VEX expression is a BP register reference.

    Dynamic boundary: third-party pyvex RdTmp/Get nodes expose class names,
    tmp definitions, statement data, and register offsets dynamically.

    BP appears as a pyvex Get for the BP guest-state offset, or as an RdTmp
    whose definition resolves to that Get. The old reg16_t enum value is
    intentionally treated only as legacy rescue evidence.
    """

    def _impl() -> bool:
        """Classify BP through third-party pyvex dynamic-boundary fields."""
        # Dynamic boundary: pyvex RdTmp/Get nodes expose class names and fields dynamically.
        class_name = getattr(type(expr), "__name__", "")

        # RdTmp: resolve through tmp_defs if available
        if "RdTmp" in class_name and tmp_defs is not None:
            tmp_idx = getattr(expr, "tmp", None)
            if isinstance(tmp_idx, int):
                stmt = tmp_defs.get(tmp_idx)
                if stmt is not None:
                    stmt_expr = getattr(stmt, "data", None) or getattr(stmt, "expr", None)
                    if stmt_expr is not None:
                        return _is_bp_reg(stmt_expr, tmp_defs=tmp_defs)

        # Direct Get node: VEX guest state offset 28 = bp
        if "Get" in class_name:
            offset = getattr(expr, "offset", None)
            if isinstance(offset, int) and offset in {10, 28}:
                return True

        # Obsolete path: reg16_t enum value (never matched VEX expressions)
        reg_offset = getattr(expr, "reg", None)
        return bool(isinstance(reg_offset, int) and reg_offset == 5)

    return _impl()


def advance_ip16(emu: object, byte_count: int) -> _AddressValue:
    """Return IP advanced by a byte count in 16-bit mode."""
    emulator = cast(_AddressingEmulator, emu)
    return emulator.get_gpreg(reg16_t.IP) + emulator.constant(byte_count, Type.int_16)


def advance_eip32(emu: object, byte_count: int) -> _AddressValue:
    """Return EIP advanced by a byte count in 32-bit mode."""
    emulator = cast(_AddressingEmulator, emu)
    return emulator.get_gpreg(reg32_t.EIP) + emulator.constant(byte_count, Type.int_32)

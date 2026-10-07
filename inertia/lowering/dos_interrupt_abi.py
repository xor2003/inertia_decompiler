"""Define typed aggregate contracts for standard DOS interrupt wrappers.

Layer: Types/Lowering.
Responsibility: expose the documented C ABI, aggregate layouts, and declarations
for resolved ``int86``/``intdos`` family calls. A resolved external helper
identity is ABI evidence; this module never substitutes helper behavior or
infers an ABI from a sample, COD object name, rendered C, or source text.

Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Any, cast

from angr.sim_type import SimStruct, SimType, SimTypeChar, SimTypeShort, SimUnion
from archinfo import Arch

__all__ = [
    "DosInterruptAbiArgumentKind8616",
    "DosInterruptAbiContract8616",
    "DosInterruptAggregateTypes8616",
    "dos_interrupt_abi_contract_8616",
    "dos_interrupt_aggregate_type_definitions_8616",
    "dos_interrupt_aggregate_types_8616",
    "dos_interrupt_prototype_declaration_8616",
]


class DosInterruptAbiArgumentKind8616(Enum):
    """Logical argument classes in DOS interrupt wrapper ABIs."""

    VALUE_U16 = "value_u16"
    REGS = "regs"
    SREGS = "sregs"

    @property
    def is_aggregate(self) -> bool:
        """Return whether this argument points to a typed aggregate object."""
        return self in {self.REGS, self.SREGS}


@dataclass(frozen=True, slots=True)
class DosInterruptAbiContract8616:
    """One resolved standard helper ABI in source argument order."""

    canonical_name: str
    argument_kinds: tuple[DosInterruptAbiArgumentKind8616, ...]


@dataclass(frozen=True, slots=True)
class DosInterruptAggregateTypes8616:
    """Architecture-bound DOS register aggregate types used by C lowering."""

    regs: SimUnion
    regs_words: SimStruct
    regs_bytes: SimStruct
    sregs: SimStruct


_ABI_CONTRACTS_8616: dict[str, DosInterruptAbiContract8616] = {
    "intdos": DosInterruptAbiContract8616(
        "intdos",
        (DosInterruptAbiArgumentKind8616.REGS, DosInterruptAbiArgumentKind8616.REGS),
    ),
    "intdosx": DosInterruptAbiContract8616(
        "intdosx",
        (
            DosInterruptAbiArgumentKind8616.REGS,
            DosInterruptAbiArgumentKind8616.REGS,
            DosInterruptAbiArgumentKind8616.SREGS,
        ),
    ),
    "int86": DosInterruptAbiContract8616(
        "int86",
        (
            DosInterruptAbiArgumentKind8616.VALUE_U16,
            DosInterruptAbiArgumentKind8616.REGS,
            DosInterruptAbiArgumentKind8616.REGS,
        ),
    ),
    "int86x": DosInterruptAbiContract8616(
        "int86x",
        (
            DosInterruptAbiArgumentKind8616.VALUE_U16,
            DosInterruptAbiArgumentKind8616.REGS,
            DosInterruptAbiArgumentKind8616.REGS,
            DosInterruptAbiArgumentKind8616.SREGS,
        ),
    ),
}


def dos_interrupt_abi_contract_8616(name: str | None) -> DosInterruptAbiContract8616 | None:
    """Return the standard ABI for one exact resolved external helper name."""
    if not isinstance(name, str):
        return None
    return _ABI_CONTRACTS_8616.get(name.strip().lstrip("_").lower())


def dos_interrupt_prototype_declaration_8616(name: str | None) -> str | None:
    """Return the exact C declaration for a resolved DOS interrupt wrapper."""
    contract = dos_interrupt_abi_contract_8616(name)
    if contract is None or not isinstance(name, str):
        return None
    call_name = name.strip()
    arguments = {
        "intdos": "union REGS *in, union REGS *out",
        "intdosx": "union REGS *in, union REGS *out, struct SREGS *sreg",
        "int86": "int intno, union REGS *in, union REGS *out",
        "int86x": "int intno, union REGS *in, union REGS *out, struct SREGS *sreg",
    }[contract.canonical_name]
    return f"int {call_name}({arguments});"


def dos_interrupt_aggregate_types_8616(arch: Arch) -> DosInterruptAggregateTypes8616:
    """Build architecture-bound REGS and SREGS layouts for field projection."""
    word: SimType = SimTypeShort(False)
    byte: SimType = SimTypeChar(False)
    regs_words = SimStruct(
        OrderedDict((name, word) for name in ("ax", "bx", "cx", "dx", "si", "di", "cflag")),
        name="REGS_WORDS",
        pack=True,
    ).with_arch(arch)
    regs_bytes = SimStruct(
        OrderedDict((name, byte) for name in ("al", "ah", "bl", "bh", "cl", "ch", "dl", "dh")),
        name="REGS_BYTES",
        pack=True,
    ).with_arch(arch)
    regs = SimUnion({"x": regs_words, "h": regs_bytes}, name="REGS").with_arch(arch)
    # Third-party boundary: SimUnion._with_arch() drops its name and CStructField
    # expects a ``fields`` mapping even for a union container.
    regs.name = "REGS"
    cast(Any, regs).fields = regs.members
    sregs = SimStruct(
        OrderedDict((name, word) for name in ("es", "cs", "ss", "ds")),
        name="SREGS",
        pack=True,
    ).with_arch(arch)
    return DosInterruptAggregateTypes8616(regs, regs_words, regs_bytes, sregs)


def dos_interrupt_aggregate_type_definitions_8616(
    kinds: tuple[DosInterruptAbiArgumentKind8616, ...],
) -> tuple[str, ...]:
    """Return complete C definitions required by aggregate argument kinds."""
    definitions: list[str] = []
    if DosInterruptAbiArgumentKind8616.REGS in kinds:
        definitions.append(
            "typedef union REGS {\n"
            "    struct { unsigned short ax, bx, cx, dx, si, di, cflag; } x;\n"
            "    struct { unsigned char al, ah, bl, bh, cl, ch, dl, dh; } h;\n"
            "} REGS;"
        )
    if DosInterruptAbiArgumentKind8616.SREGS in kinds:
        definitions.append(
            "typedef struct SREGS {\n"
            "    unsigned short es, cs, ss, ds;\n"
            "} SREGS;"
        )
    return tuple(definitions)

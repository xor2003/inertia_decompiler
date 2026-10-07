"""Bounded declared returning-import service contracts for PE32 program boot.

Layer: dosunit PE32 import/service contracts.
Responsibility: own the typed contract for one deliberately narrow returning
import service class — a no-argument, DWORD-returning call routed through a
genuine import directory's import address table — and the raw PE32 metadata
parse that binds each caller-declared service to the actual IAT slots the
binary's own import directory declares. This is a visible synthetic
environment assumption: the declared response and the declared
volatile-register/flag policy are caller-supplied premises, never a claim
about any real Windows implementation. Ordinal, forwarded, bound, delay,
TLS, load-config and CLR import shapes, malformed tables and ambiguous
coverage are typed refusals, never skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast

import pefile

IMPORT_DIRECTORY_INDEX: int = 1
"""Optional-header data-directory index of the import descriptor table."""

IAT_DIRECTORY_INDEX: int = 12
"""Optional-header data-directory index of the import address table."""

MAX_IMPORT_DESCRIPTORS: int = 8
"""Bounded count of import descriptors the intake admits."""

MAX_IMPORT_SLOTS: int = 32
"""Bounded total IAT slot count across every descriptor."""

MAX_IMPORT_BINDINGS: int = 16
"""Bounded count of caller-declared services per environment."""

MAX_IMPORT_NAME_BYTES: int = 128
"""Bounded length of a normalized imported symbol or DLL name."""

_DLL_NAME = re.compile(r"[a-z0-9_.$-]+\.dll\Z")
_SYMBOL_NAME = re.compile(r"[A-Za-z0-9_.$?@-]+\Z")


class ImportResultKind(StrEnum):
    """The declared response shape of a returning import service."""

    DECLARED_DWORD = "declared_dword"
    SHARED_OPAQUE = "shared_opaque"


class ServiceFlagsPolicy(StrEnum):
    """The declared EFLAGS effect of a returning import service."""

    PRESERVED = "preserved"
    OPAQUE = "opaque"


SERVICE_VOLATILE_REGISTERS: frozenset[str] = frozenset({"ecx", "edx"})
"""The caller-clobberable registers a declared service may name; ``eax``
is the result register and nonvolatile registers are always preserved."""


def _checked_ascii(value: object, name: str) -> str:
    """Validate a bounded printable-ASCII declaration field."""
    if not isinstance(value, str) or not value or not _ascii(value) or len(value) > MAX_IMPORT_NAME_BYTES:
        raise ValueError(f"{name} must be a bounded ASCII name")
    return value


def _ascii(value: str) -> bool:
    """Report whether ``value`` is pure printable ASCII."""
    try:
        value.encode("ascii", "strict")
    except UnicodeEncodeError:
        return False
    return all(0x21 <= ord(char) <= 0x7E for char in value)


@dataclass(frozen=True, slots=True)
class PeImportResult:
    """The caller-declared DWORD response of one returning service.

    ``DECLARED_DWORD`` binds an exact constant response; ``SHARED_OPAQUE``
    declares the response an unconstrained shared symbolic input of the
    comparison — an explicit unknown, never a guessed Windows value.
    """

    kind: ImportResultKind
    value: int | None = None

    def __post_init__(self) -> None:
        """Require the declared shape to match the declared value."""
        if not isinstance(self.kind, ImportResultKind):
            raise ValueError("service result requires a typed ImportResultKind")
        if self.kind is ImportResultKind.DECLARED_DWORD:
            if isinstance(self.value, bool) or not isinstance(self.value, int) or not 0 <= self.value <= 0xFFFFFFFF:
                raise ValueError("declared dword results require a 32-bit value")
        elif self.value is not None:
            raise ValueError("opaque results declare no concrete value")


@dataclass(frozen=True, slots=True)
class PeImportService:
    """One caller-declared no-argument DWORD-returning import service.

    ``dll`` is normalized to lowercase ASCII; ``name`` retains the exact
    case-sensitive export spelling from the PE import directory.
    ``address`` is the declared synthetic service
    boundary written into the sealed loaded IAT; it is an environment
    premise like the exit gateway, never an arbitrary gateway passed off as
    Windows coverage. ``volatile`` names the subset of ``ecx``/``edx`` the
    service is declared to clobber into opaque shared inputs — undeclared
    registers are declared preserved. ``flags`` declares whether the lazy
    flag state is preserved or becomes opaque.
    """

    dll: str
    name: str
    address: int
    result: PeImportResult
    volatile: tuple[str, ...]
    flags: ServiceFlagsPolicy

    def __post_init__(self) -> None:
        """Validate and normalize the declared service contract."""
        object.__setattr__(self, "dll", _checked_ascii(self.dll, "service dll").lower())
        object.__setattr__(self, "name", _checked_ascii(self.name, "service name"))
        if not _DLL_NAME.match(self.dll):
            raise ValueError("service dll must be a normalized *.dll module name")
        if not _SYMBOL_NAME.match(self.name):
            raise ValueError("service name must be a normalized import symbol")
        if isinstance(self.address, bool) or not isinstance(self.address, int) or not 0 <= self.address <= 0xFFFFFFFF:
            raise ValueError("service address must be a 32-bit unsigned integer")
        if not isinstance(self.result, PeImportResult):
            raise ValueError("service requires a typed PeImportResult")
        if not isinstance(self.flags, ServiceFlagsPolicy):
            raise ValueError("service requires a typed ServiceFlagsPolicy")
        seen: set[str] = set()
        ordered: list[str] = []
        for register in self.volatile:
            if not isinstance(register, str) or register not in SERVICE_VOLATILE_REGISTERS:
                raise ValueError("service volatile set may only declare ecx/edx")
            if register not in seen:
                seen.add(register)
                ordered.append(register)
        object.__setattr__(self, "volatile", tuple(ordered))

    def key(self) -> tuple[str, str]:
        """Return the normalized import identity ``(dll, name)``."""
        return (self.dll, self.name)

    def label(self) -> str:
        """Return the ``dll!name`` observation identity of this service."""
        return f"{self.dll}!{self.name}"

    def declared_fields(self) -> dict[str, object]:
        """Project every declared premise into a canonical evidence record."""
        result: dict[str, object] = {"kind": self.result.kind.value}
        if self.result.kind is ImportResultKind.DECLARED_DWORD:
            result["value"] = self.result.value
        return {
            "dll": self.dll,
            "name": self.name,
            "address": self.address,
            "result": result,
            "volatile": list(self.volatile),
            "flags": self.flags.value,
        }


@dataclass(frozen=True, slots=True)
class PeImportBinding:
    """One declared service bound to its actual loaded IAT slots.

    ``slots`` are the loaded linear addresses of the import address table
    entries the raw import directory assigns this service — each is patched
    to ``service.address`` inside the sealed boot image.
    """

    service: PeImportService
    slots: tuple[int, ...]

    def __post_init__(self) -> None:
        """Require a typed service and a nonempty ordered slot set."""
        if not isinstance(self.service, PeImportService):
            raise ValueError("import binding requires a typed PeImportService")
        if not self.slots or any(
            isinstance(slot, bool) or not isinstance(slot, int) or not 0 <= slot <= 0xFFFFFFFF or slot % 4
            for slot in self.slots
        ):
            raise ValueError("import binding requires nonempty aligned 32-bit slots")
        if len(set(self.slots)) != len(self.slots):
            raise ValueError("import binding slots must be distinct")
        object.__setattr__(self, "slots", tuple(sorted(self.slots)))


@dataclass(frozen=True, slots=True)
class PeImportedSymbol:
    """One raw import-directory symbol and its loaded IAT slot address."""

    dll: str
    name: str
    slot: int


def _decode_import_name(raw: object, what: str) -> str:
    """Decode one raw import name without changing case-sensitive identity."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError(f"import directory {what} is not a byte string")
    try:
        text = bytes(raw).decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"import directory {what} is not ASCII") from error
    if not text or len(text) > MAX_IMPORT_NAME_BYTES:
        raise ValueError(f"import directory {what} exceeds the name budget")
    return text


def _import_directory_span(
    parsed: pefile.PE,
) -> tuple[tuple[Any, ...], tuple[int, int] | None, int, int]:
    """Validate the import and IAT directory extents against the image.

    Directories that overrun ``SizeOfImage`` are malformed evidence; a
    present IAT directory additionally bounds the admitted slot range.
    Returns ``(descriptors, iat_span, image_base, size_of_image)``.
    """
    optional = cast(Any, parsed.OPTIONAL_HEADER)
    directories = optional.DATA_DIRECTORY
    if len(directories) <= IAT_DIRECTORY_INDEX:
        raise ValueError("optional header declares too few data directories")
    size_of_image = int(optional.SizeOfImage)
    image_base = int(optional.ImageBase)
    for index in (IMPORT_DIRECTORY_INDEX, IAT_DIRECTORY_INDEX):
        entry = directories[index]
        if (entry.VirtualAddress or entry.Size) and not (
            entry.VirtualAddress >= 0
            and entry.VirtualAddress + entry.Size <= size_of_image
        ):
            raise ValueError(f"directory {index} overruns the declared image")
    iat_dir = directories[IAT_DIRECTORY_INDEX]
    iat_span: tuple[int, int] | None = None
    if iat_dir.VirtualAddress or iat_dir.Size:
        iat_span = (image_base + int(iat_dir.VirtualAddress), int(iat_dir.Size))
    import_dir = directories[IMPORT_DIRECTORY_INDEX]
    if not (import_dir.VirtualAddress or import_dir.Size):
        return (), iat_span, image_base, size_of_image
    # Dynamic third-party pefile boundary: this attribute exists only after import parsing.
    descriptors = getattr(parsed, "DIRECTORY_ENTRY_IMPORT", None)
    if not descriptors:
        raise ValueError("import directory is present but has no parseable descriptors")
    if len(descriptors) > MAX_IMPORT_DESCRIPTORS:
        raise ValueError("import descriptor count exceeds the intake budget")
    warnings = [str(item).lower() for item in parsed.get_warnings()]
    if any("import" in item or "thunk" in item or "ilt" in item or "iat" in item for item in warnings):
        raise ValueError("import directory parse reported malformed evidence")
    return tuple(descriptors), iat_span, image_base, size_of_image


def _import_symbol(
    symbol: object,
    dll: str,
    iat_span: tuple[int, int] | None,
    image_base: int,
    size_of_image: int,
) -> PeImportedSymbol:
    """Validate one raw import symbol and project its loaded IAT slot.

    Only by-name unbound symbols with agreeing ILT/IAT thunks are admitted;
    ordinal, bound or ambiguous entries are out-of-scope evidence and refuse.
    The pefile ``ImportData`` fields are dynamic third-party attributes —
    ``getattr`` confines that boundary to this intake.
    """
    if getattr(symbol, "import_by_ordinal", False):
        raise ValueError("ordinal imports are outside the declared service scope")
    if getattr(symbol, "bound", None) is not None:
        raise ValueError("bound import addresses are outside the declared service scope")
    if getattr(symbol, "struct_iat", None) is not None:
        raise ValueError("disagreeing ILT/IAT thunk tables are ambiguous")
    name = _decode_import_name(getattr(symbol, "name", None), "symbol name")
    if not _SYMBOL_NAME.match(name):
        raise ValueError("imported symbol name is not a supported form")
    slot = getattr(symbol, "address", None)
    if isinstance(slot, bool) or not isinstance(slot, int):
        raise ValueError("import slot address must be an integer")
    if not 0 <= slot <= 0xFFFFFFFF:
        raise ValueError("import slot address is outside the 32-bit space")
    if not image_base <= slot < image_base + size_of_image:
        raise ValueError("import slot is outside the declared image")
    if slot % 4:
        raise ValueError("import slot is not dword-aligned")
    if iat_span is not None and not (iat_span[0] <= slot and slot + 4 <= iat_span[0] + iat_span[1]):
        raise ValueError("import slot is outside the declared IAT range")
    return PeImportedSymbol(dll, name, slot)


def parse_pe32_imports(parsed: pefile.PE) -> tuple[PeImportedSymbol, ...]:
    """Read the raw import directory into normalized slot-bound symbols.

    Only by-name imports through a real descriptor table are admitted:
    ordinal imports, bound IAT entries, unparseable descriptors and tables
    that overrun the image or the intake budgets are malformed evidence and
    refuse rather than produce a partial binding.
    """
    descriptors, iat_span, image_base, size_of_image = _import_directory_span(parsed)
    slots: dict[int, PeImportedSymbol] = {}
    for descriptor in descriptors:
        dll = _decode_import_name(descriptor.dll, "dll name").lower()
        if not _DLL_NAME.match(dll):
            raise ValueError("import descriptor dll is not a supported module name")
        entries = tuple(descriptor.imports)
        if not entries:
            raise ValueError("import descriptor declares no symbols")
        for symbol in entries:
            admitted = _import_symbol(symbol, dll, iat_span, image_base, size_of_image)
            if admitted.slot in slots:
                raise ValueError("import slot is claimed by two symbols")
            if len(slots) >= MAX_IMPORT_SLOTS:
                raise ValueError("import slot count exceeds the intake budget")
            slots[admitted.slot] = admitted
    return tuple(slots[slot] for slot in sorted(slots))


def bind_pe32_imports(
    symbols: tuple[PeImportedSymbol, ...],
    services: tuple[PeImportService, ...],
) -> tuple[PeImportBinding, ...]:
    """Bind every admitted raw import to its exactly matching declared service.

    Coverage is exact in both directions: every imported ``dll!name`` must
    have a declared service and every declared service must bind at least
    one actual IAT slot — unknown imports or invented bindings refuse.
    """
    if not services:
        raise ValueError("declared import bindings require declared services")
    imported: dict[tuple[str, str], list[int]] = {}
    for symbol in symbols:
        imported.setdefault((symbol.dll, symbol.name), []).append(symbol.slot)
    declared = {service.key() for service in services}
    unknown = sorted(imported.keys() - declared)
    if unknown:
        raise ValueError(
            "imports lack declared services: "
            + ", ".join(f"{dll}!{name}" for dll, name in unknown)
        )
    unbound = sorted(declared - imported.keys())
    if unbound:
        raise ValueError(
            "declared services bind no admitted import: "
            + ", ".join(f"{dll}!{name}" for dll, name in unbound)
        )
    bindings: list[PeImportBinding] = []
    for service in sorted(services, key=lambda item: item.key()):
        bindings.append(PeImportBinding(service, tuple(sorted(imported[service.key()]))))
    return tuple(bindings)

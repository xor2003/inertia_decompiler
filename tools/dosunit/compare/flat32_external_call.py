"""Layer: validation external-call effects.

Responsibility: construct a conservative, explicitly declared returning i386
call transition. This is not a Windows implementation or import-target proof.
The caller must authenticate the live target and publish ``declared_fields``
before using these terms to claim conditional binary equivalence.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ExternalStackCleanup(StrEnum):
    """Owner of the declared DWORD argument area after a returning call."""

    CALLER = "caller"
    CALLEE = "callee"


class ExternalMemoryAccess(StrEnum):
    """Declared program-memory access beyond ABI argument and return slots."""

    ARBITRARY = "arbitrary"
    NONE = "none"
    RETURNED_REGION = "returned_region"
    ARGUMENT_REGION = "argument_region"


@dataclass(frozen=True)
class Flat32ExternalCall:
    """A declared returning boundary with an explicit program-memory contract.

    Arguments are DWORD stack values above the return address. The boundary
    preserves the return-address bytes, EBX/EBP/ESI/EDI and direction state;
    EAX/ECX/EDX and arithmetic flags become opaque. Every other memory byte
    may change. Other architectural state is preserved. Results depend on all incoming memory, external history and
    ordered arguments. No nonescape, allocation, success or purity is assumed.

    Normal return and these ABI obligations are premises. A countermodel of
    the opaque transition is not a witnessed Windows behavior difference.
    ``preserve_import_bindings`` additionally declares that the external
    operation leaves the supplied actual IAT slots unchanged. The binary
    composer supplies and publishes those slots; the program's own writes
    are never covered by this external-only premise.

    ``memory_access=NONE`` is a stronger, explicit premise: outside reading
    the ABI argument/return slots, the operation neither reads nor writes
    program memory. Pointer dereferences are excluded. Results and ordered
    external effects then depend on argument values and external history.
    This is not purity: the history still changes on every invocation.

    RETURNED_REGION additionally declares writes of opaque bytes only within
    the modular EAX region sized by write_size_argument, except the return
    slot. Zero EAX or size means no writes. Results read only ordered arguments
    and external history; hidden allocator state must be represented there.
    It establishes neither freshness nor zero initialization nor a Windows
    API implementation. Unrelated program memory is retained literally.

    ``preserved_memory_ranges`` explicitly frames inclusive physical-address
    intervals during this external transition only. It does not constrain a
    returned pointer, prove allocation freshness, or suppress later native stores.
    The same physical coordinates must describe the declared region on both sides.
    ``read_excluded_memory_ranges`` separately declares bytes unread by the
    external transition. ABI argument and return slots still use actual memory.
    Projection changes only opaque dependencies, never actual program memory;
    write preservation requires its own explicit frame premise.

    ARGUMENT_REGION declares a fixed-size output buffer addressed by one
    argument. Its old contents are not read. Only that modular region may
    change, except the return slot and separately declared IAT preservation.
    A valid output pointer and normal return are explicit premises.
    """

    dll: str
    name: str
    argument_count: int
    cleanup: ExternalStackCleanup
    preserve_import_bindings: bool = False
    memory_access: ExternalMemoryAccess = ExternalMemoryAccess.ARBITRARY
    write_size_argument: int | None = None
    write_address_argument: int | None = None
    write_size_bytes: int | None = None
    preserved_memory_ranges: tuple[tuple[int, int], ...] = ()
    read_excluded_memory_ranges: tuple[tuple[int, int], ...] = ()

    def __post_init__(self) -> None:
        """Reject malformed identities and unbounded or untyped ABI declarations."""
        for value in (self.dll, self.name):
            if (
                not isinstance(value, str) or not 1 <= len(value) <= 128
                or not value.isascii() or any(not 0x21 <= ord(c) <= 0x7E for c in value)
            ):
                raise ValueError("external call identity must be bounded printable ASCII")
        object.__setattr__(self, "dll", self.dll.lower())
        if (
            isinstance(self.argument_count, bool) or not isinstance(self.argument_count, int)
            or not 0 <= self.argument_count <= 32
        ):
            raise ValueError("external call requires 0..32 DWORD arguments")
        if not isinstance(self.cleanup, ExternalStackCleanup):
            raise ValueError("external call requires typed stack cleanup")
        if type(self.preserve_import_bindings) is not bool:
            raise ValueError("preserve_import_bindings must be a boolean premise")
        if not isinstance(self.memory_access, ExternalMemoryAccess):
            raise ValueError("external call requires typed memory access")

        if self.memory_access is ExternalMemoryAccess.RETURNED_REGION:
            if type(self.write_size_argument) is not int or not 0 <= self.write_size_argument < self.argument_count:
                raise ValueError("returned region requires a valid zero-based size argument")
        elif self.write_size_argument is not None:
            raise ValueError("size argument requires returned-region memory access")
        self._validate_argument_region()
        self._validate_memory_frame()

    def _validate_memory_frame(self) -> None:
        """Require bounded, ordered, disjoint inclusive physical-address ranges."""
        self._validate_read_exclusions()
        if not isinstance(self.preserved_memory_ranges, tuple) or len(self.preserved_memory_ranges) > 32:
            raise ValueError("preserved memory ranges require at most 32 immutable pairs")
        previous = -1
        for item in self.preserved_memory_ranges:
            if not isinstance(item, tuple) or len(item) != 2 or any(type(x) is not int for x in item):
                raise ValueError("preserved memory range requires two plain integers")
            first, last = item
            if not 0 <= first <= last <= 0xFFFFFFFF or first <= previous:
                raise ValueError("preserved memory ranges must be ordered, disjoint uint32 intervals")
            previous = last

    def _validate_read_exclusions(self) -> None:
        """Validate explicit unread intervals, bounded for exact SSA projection."""
        ranges = self.read_excluded_memory_ranges
        if not isinstance(ranges, tuple) or len(ranges) > 32:
            raise ValueError("read exclusions require at most 32 immutable pairs")
        previous = -1
        for item in ranges:
            if not isinstance(item, tuple) or len(item) != 2 or any(type(x) is not int for x in item):
                raise ValueError("read exclusion requires two plain integers")
            first, last = item
            if not 0 <= first <= last <= 0xFFFFFFFF or first <= previous or last - first >= 8192:
                raise ValueError("read exclusions must be ordered disjoint uint32 intervals of at most 8192 bytes")
            previous = last
        if ranges and self.memory_access is not ExternalMemoryAccess.ARBITRARY:
            raise ValueError("read exclusions require arbitrary memory access")

    def _validate_argument_region(self) -> None:
        """Require an explicit bounded output footprint, rejecting stray fields."""
        if self.memory_access is ExternalMemoryAccess.ARGUMENT_REGION:
            if type(self.write_address_argument) is not int or not 0 <= self.write_address_argument < self.argument_count:
                raise ValueError("argument region requires a valid zero-based address argument")
            if type(self.write_size_bytes) is not int or not 1 <= self.write_size_bytes <= 65536:
                raise ValueError("argument region requires 1..65536 output bytes")
        elif self.write_address_argument is not None or self.write_size_bytes is not None:
            raise ValueError("output address and size require argument-region memory access")

    def operator_prefix(self) -> str:
        """Encode identity and ABI injectively into solver-safe summary names."""
        identity = (self.dll + "\0" + self.name).encode("ascii").hex()
        suffix = "_nomem" if self.memory_access is ExternalMemoryAccess.NONE else ""
        if self.memory_access is ExternalMemoryAccess.RETURNED_REGION:
            suffix = f"_region{self.write_size_argument}"
        elif self.memory_access is ExternalMemoryAccess.ARGUMENT_REGION:
            suffix = f"_argregion{self.write_address_argument}n{self.write_size_bytes}"
        return f"summary_external_v1_{identity}_{self.argument_count}_{self.cleanup.value}_iat{int(self.preserve_import_bindings)}{suffix}"

    def declared_fields(self) -> dict[str, object]:
        """Publish the complete premise, independently of expression rendering."""
        return {
            "kind": "flat32_opaque_returning_call_v1",
            "dll": self.dll, "name": self.name,
            "argument_count": self.argument_count, "argument_width": 32,
            "cleanup": self.cleanup.value,
            "outcome": "normal_return_assumed",
            "memory": ("unchanged; only ABI argument and return slots are read"
                       if self.memory_access is ExternalMemoryAccess.NONE else "returned_eax_region_except_four_return_address_bytes"
                       if self.memory_access is ExternalMemoryAccess.RETURNED_REGION
                       else "argument_region_except_four_return_address_bytes"
                       if self.memory_access is ExternalMemoryAccess.ARGUMENT_REGION
                       else "arbitrary_except_four_return_address_bytes"),
            "memory_access": self.memory_access.value,
            **({"write_size_argument": self.write_size_argument,
                "region_contract": "zero EAX or zero size writes nothing; otherwise modular EAX..EAX+size-1",
                "region_contents": "opaque bytes depending on history and ordered arguments",
                "program_memory_reads": "ABI argument and return slots only; hidden allocator state must be in external_history",
                "freshness_assumed": False}
               if self.memory_access is ExternalMemoryAccess.RETURNED_REGION else {}),
            **({"write_address_argument": self.write_address_argument,
                "write_size_bytes": self.write_size_bytes,
                "region_contents": "opaque bytes depending on history and ordered arguments",
                "program_memory_reads": "ABI argument and return slots only",
                "region_contract": "fixed modular output region; normal return and valid output pointer assumed"}
               if self.memory_access is ExternalMemoryAccess.ARGUMENT_REGION else {}),
            "preserve_import_bindings": self.preserve_import_bindings,
            "preserved_memory_ranges": [list(item) for item in self.preserved_memory_ranges],
            "read_excluded_memory_ranges": [list(item) for item in self.read_excluded_memory_ranges],
            "read_exclusion_scope": "external transition dependencies only; ABI arguments and return control still read from actual memory; no write preservation implied",
            "memory_frame_scope": "external transition only; inclusive physical addresses; no pointer freshness or later-write premise",

            "preserved": ["ebx", "ebp", "esi", "edi", "all_other_architecture_state"],
            "opaque": ["eax", "ecx", "edx", "arithmetic_flags", "external_history"],
            "dependencies": (["memory_except_explicit_read_exclusions" if self.read_excluded_memory_ranges else "all_memory"] if self.memory_access is ExternalMemoryAccess.ARBITRARY else [])
                            + ["external_history", "ordered_arguments"],
        }


def _constant(value: int) -> dict[str, Any]:
    """Build one full-width flat32 constant."""
    return {"op": "const", "width": 32, "value": hex(value)}


def preserve_import_memory(
    changed: dict[str, Any], original: dict[str, Any], slots: tuple[int, ...],
) -> dict[str, Any]:
    """Keep every slot identity until relocation precedes range coalescing.

    Contiguous physical IAT slots need not remain contiguous or ordered under
    the candidate-to-original correspondence. Boundaries cannot be normalized
    in isolation: the exact slot list is part of the memory operation.
    """
    ordered = sorted(set(slots))
    for slot in ordered:
        if type(slot) is not int or not 0 <= slot <= 0xFFFFFFFC or slot % 4:
            raise ValueError("IAT frame requires aligned flat32 DWORD slots")
    if not ordered:
        return changed
    return {"op": "memory_preserve_slots32", "width": 0,
            "args": [changed, original, *(_constant(slot) for slot in ordered)]}


def _stack_address(stack: dict[str, Any], offset: int) -> dict[str, Any]:
    """Add a byte offset with flat32 modular address semantics."""
    return {"op": "add", "width": 32, "args": [stack, _constant(offset)]}


def external_call_state(
    contract: Flat32ExternalCall,
    incoming: Mapping[str, dict[str, Any]],
    *, import_slots: tuple[int, ...] = (),
) -> dict[str, dict[str, Any]]:
    """Apply a returning contract at callee entry, after native CALL's push.

    The same incoming operands feed every component of one opaque transition.
    The new history feeds later calls, so repeated invocations need not return
    the same value and external effects cannot disappear with unused EAX.
    By default full incoming memory remains a dependency, including stack
    bytes. Explicit NONE and RETURNED_REGION premises remove that dependency;
    extracted argument values, return control and external history remain.
    """
    memory, history, stack = incoming["memory"], incoming["io"], incoming["esp"]
    arguments = [
        {"op": "loadle", "width": 32, "args": [memory, _stack_address(stack, 4 * (index + 1))]}
        for index in range(contract.argument_count)
    ]
    dependency_memory = memory
    for first, last in contract.read_excluded_memory_ranges:
        dependency_memory = {"op": "memory_read_projection", "width": 0,
                             "args": [dependency_memory, _constant(first), _constant(last)]}
    operands = ([dependency_memory] if contract.memory_access is ExternalMemoryAccess.ARBITRARY else []) + [history, *arguments]
    prefix = contract.operator_prefix()
    post = dict(incoming)
    for register in ("eax", "ecx", "edx"):
        post[register] = {"op": prefix + "_" + register, "width": 32, "args": operands}
    flags = {"op": prefix + "_flags", "width": 32, "args": operands}
    # VEX COPY flags contract: only arithmetic flag bits enter the lazy flags.
    post["cc_op"] = _constant(0)
    post["cc_dep1"] = {"op": "and", "width": 32, "args": [flags, _constant(0x8D5)]}
    post["cc_dep2"] = _constant(0)
    post["cc_ndep"] = _constant(0)
    returned = {"op": "loadle", "width": 32, "args": [memory, stack]}
    opaque_memory = {"op": prefix + "_memory", "width": 0, "args": operands}
    post["memory"] = (memory if contract.memory_access is ExternalMemoryAccess.NONE else
                      {"op": "storele", "width": 0, "args": [opaque_memory, stack, returned]})
    if contract.memory_access is ExternalMemoryAccess.RETURNED_REGION:
        assert contract.write_size_argument is not None
        region = _returned_region_memory(memory, opaque_memory, post["eax"], arguments[contract.write_size_argument])
        post["memory"] = {"op": "storele", "width": 0, "args": [region, stack, returned]}
    if contract.memory_access is ExternalMemoryAccess.ARGUMENT_REGION:
        assert contract.write_address_argument is not None and contract.write_size_bytes is not None
        region = _fixed_output_memory(
            memory, opaque_memory, arguments[contract.write_address_argument], contract.write_size_bytes,
        )
        post["memory"] = {"op": "storele", "width": 0, "args": [region, stack, returned]}
    if contract.preserve_import_bindings:
        if not import_slots:
            raise ValueError("IAT-preserving contract requires actual import slots")
        post["memory"] = preserve_import_memory(post["memory"], memory, import_slots)
    for first, last in contract.preserved_memory_ranges:
        post["memory"] = {"op": "memory_preserve", "width": 0,
                          "args": [post["memory"], memory, _constant(first), _constant(last)]}
    post["io"] = {"op": prefix + "_history", "width": 0, "args": operands}
    popped = 4 + (4 * contract.argument_count if contract.cleanup is ExternalStackCleanup.CALLEE else 0)
    post["esp"] = _stack_address(stack, popped)
    post["ip"] = returned
    post["eip"] = returned
    return post


def _fixed_output_memory(
    original: dict[str, Any], contents: dict[str, Any], address: dict[str, Any], size: int,
) -> dict[str, Any]:
    """Use finite native stores for small fixed buffers, avoiding array lambdas.

    Chunking changes only representation. Byte addresses still wrap modulo
    2**32 and every byte outside the declared footprint remains unchanged.
    """
    if size > 64:
        return _returned_region_memory(original, contents, address, _constant(size), zero_address_is_empty=False)
    result = original
    offset = 0
    while offset < size:
        count = min(4, size - offset)
        target = _stack_address(address, offset)
        value = {"op": "loadle", "width": count * 8, "args": [contents, target]}
        result = {"op": "storele", "width": 0, "args": [result, target, value]}
        offset += count
    return result


def _returned_region_memory(
    original: dict[str, Any], contents: dict[str, Any], address: dict[str, Any], size: dict[str, Any],
    *, zero_address_is_empty: bool = True,
) -> dict[str, Any]:
    """Copy opaque bytes into the modular result region, preserving all other bytes.

    Zero result denotes failure and zero size has an empty footprint. No
    freshness, alignment, successful allocation or initialization is inferred.
    The existing exact array-range owner handles each nonwrapping piece.
    """
    last = {"op": "sub", "width": 32, "args": [address, _constant(1)]}
    last = {"op": "add", "width": 32, "args": [last, size]}

    def copy_region(memory: dict[str, Any], first: dict[str, Any], end: dict[str, Any]) -> dict[str, Any]:
        """Select new region bytes using the canonical pointwise range operator."""
        return {"op": "memory_preserve", "width": 0, "args": [memory, contents, first, end]}

    contiguous = copy_region(original, address, last)
    wrapping = copy_region(copy_region(original, address, _constant(0xFFFFFFFF)), _constant(0), last)
    selected = {"op": "ite", "width": 0, "args": [
        {"op": "uge", "width": 1, "args": [last, address]}, contiguous, wrapping]}
    active = {"op": "and", "width": 1, "args": [
        {"op": "ne", "width": 1, "args": [address, _constant(0)]},
        {"op": "ne", "width": 1, "args": [size, _constant(0)]}]}
    if not zero_address_is_empty:
        active = {"op": "ne", "width": 1, "args": [size, _constant(0)]}
    return {"op": "ite", "width": 0, "args": [active, selected, original]}

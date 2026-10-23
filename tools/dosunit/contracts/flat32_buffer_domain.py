"""Layer: flat32 proof input contracts.

Responsibility: describe explicit root memory-value ranges and stack-argument
buffers disjoint from the private frame without removing executed effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Flat32EntryMemoryRange:
    """Caller-declared unsigned value range in canonical root-entry memory.

    Addresses use the oracle coordinate system of the declared memory relation.
    Initial executable bytes do not establish this live-entry invariant. Loads
    and subsequent writes remain modeled; the bound is an explicit premise.
    """

    address: int
    width: int
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        """Reject non-native widths, invalid addresses and empty value ranges."""
        if any(type(value) is not int for value in (self.address, self.width, self.minimum, self.maximum)):
            raise ValueError("entry memory range requires plain integers")
        if not 0 <= self.address <= 0xFFFFFFFF or self.width not in (8, 16, 32):
            raise ValueError("entry memory range requires a uint32 address and width 8, 16 or 32")
        if not 0 <= self.minimum <= self.maximum < 1 << self.width:
            raise ValueError("entry memory range requires nonempty unsigned bounds")

    def obligation(self) -> dict[str, Any]:
        """Bind the range to original input memory, never to a later load."""
        value = {"op": "loadle", "width": self.width, "args": [
            {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
            {"op": "const", "width": 32, "value": hex(self.address)}]}
        predicates = [{"op": operator, "width": 1, "args": [value,
            {"op": "const", "width": self.width, "value": hex(bound)}]}
            for operator, bound in (("uge", self.minimum), ("ule", self.maximum))]
        return {"kind": "flat32_entry_memory_unsigned_range", "literal_constants": True,
                "address": hex(self.address), "width": self.width,
                "min": self.minimum, "max": self.maximum,
                "predicate": {"op": "and", "width": 1, "args": predicates},
                "scope": "canonical root entry memory only; caller-declared, not an image initializer proof"}


@dataclass(frozen=True, slots=True)
class Flat32EntryMemoryBinding:
    """A singleton entry premise translated to one side's physical address.

    Seeding is an execution view under the retained root predicate, not a
    program store or a claim about image initialization. Later writes are live.
    """

    domain: Flat32EntryMemoryRange
    local_address: int

    def __post_init__(self) -> None:
        """Admit only exact values and architectural addresses."""
        if self.domain.minimum != self.domain.maximum:
            raise ValueError("entry memory binding requires a singleton range")
        if type(self.local_address) is not int or not 0 <= self.local_address <= 0xFFFFFFFF:
            raise ValueError("entry memory binding requires a uint32 address")

    def seed(self, memory: dict[str, Any]) -> dict[str, Any]:
        """Expose known initial bytes while preserving every other input byte."""
        return {"op": "storele", "width": 0, "args": [memory,
            {"op": "const", "width": 32, "value": hex(self.local_address)},
            {"op": "const", "width": self.domain.width, "value": hex(self.domain.minimum)}]}


@dataclass(frozen=True, slots=True)
class Flat32StackDisjointBuffer:
    """Caller premise for a fixed-size buffer addressed by a DWORD argument.

    Argument zero is read from input memory at entry ESP+4. The premise binds
    only root entry memory; subsequent argument-slot writes cannot change it.
    """

    argument_index: int
    size_bytes: int

    def __post_init__(self) -> None:
        """Reject malformed indices and unbounded or empty buffer extents."""
        if type(self.argument_index) is not int or not 0 <= self.argument_index < 32:
            raise ValueError("buffer argument_index must be an integer in 0..31")
        if type(self.size_bytes) is not int or not 1 <= self.size_bytes <= 65536:
            raise ValueError("buffer size_bytes must be an integer in 1..65536")

    def obligation(self, private_stack_bytes: int) -> dict[str, Any]:
        """Serialize a literal root predicate; code relocation must not alter it."""
        if type(private_stack_bytes) is not int or not 1 <= private_stack_bytes <= 8192:
            raise ValueError("buffer premise requires a private stack extent in 1..8192")

        def const(value: int) -> dict[str, Any]:
            """Encode architectural offsets modulo the native address width."""
            return {"op": "const", "width": 32, "value": hex(value & 0xFFFFFFFF)}

        def op(name: str, width: int, *args: dict[str, Any]) -> dict[str, Any]:
            """Build an inline SSA predicate for the shared obligation solver."""
            return {"op": name, "width": width, "args": list(args)}

        esp = {"op": "input", "width": 32, "name": "esp"}
        memory = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
        pointer = op("loadle", 32, memory, op("add", 32, esp, const(4 + 4 * self.argument_index)))
        frame = op("sub", 32, esp, const(private_stack_bytes))
        # Two nonempty short circular intervals are disjoint iff neither
        # interval's start lies inside the other. This includes wrapping.
        predicate = op("and", 1,
                       op("uge", 1, op("sub", 32, pointer, frame), const(private_stack_bytes)),
                       op("uge", 1, op("sub", 32, frame, pointer), const(self.size_bytes)))
        return {"kind": "flat32_entry_buffer_stack_disjoint", "literal_constants": True,
                "argument_index": self.argument_index, "size_bytes": self.size_bytes,
                "private_stack_bytes": private_stack_bytes, "predicate": predicate,
                "scope": "root entry memory and ESP only; no callee or loop-cutpoint premise"}

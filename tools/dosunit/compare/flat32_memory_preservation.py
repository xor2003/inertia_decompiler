"""Layer: validation memory preservation.

Responsibility: discharge a bounded read's preservation from nonwrapping
unsigned write-address intervals, without evaluating stored values. Unknown
addresses, memory producers or overlapping writes yield no proof.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RegionPreservationProof:
    """A sufficient byte-region preservation proof under supplied input bounds."""

    stores_checked: int


class _RegionCheck:
    """Bound work on shared expression DAGs and retain exact address spaces."""

    def __init__(self, start: int, size: int, constraints: list[dict[str, Any]],
                 assignments: list[dict[str, Any]],
                 normalize: Callable[[int, int], int] | None = None) -> None:
        """Take only declared unsigned input bounds; never derive heap assumptions."""
        self.normalize = normalize
        self.start = start
        self.end = start + size
        self.bounds: dict[str, tuple[int, int]] = {}
        for item in constraints:
            if item.get("kind") == "unsigned_range":
                low, high = item.get("min"), item.get("max")
                if type(low) is int and type(high) is int and 0 <= low <= high < 2**32:
                    self.bounds[item["name"]] = (low, high)
        self.remaining = 256
        self.ranges: dict[int, tuple[int, int] | None] = {}
        self.memories: dict[int, bool] = {}
        self.stores_checked = 0
        self.assignments = {item["id"]: item for item in assignments}

    def resolve(self, term: dict[str, Any]) -> dict[str, Any]:
        """Resolve one canonical SSA assignment without expanding stored values."""
        return self.assignments.get(term["ref"], term) if "ref" in term else term

    def interval(self, term: dict[str, Any]) -> tuple[int, int] | None:
        """Overapproximate admitted 32-bit arithmetic only when it cannot wrap."""
        term = self.resolve(term)
        key = id(term)
        if key in self.ranges:
            return self.ranges[key]
        if self.remaining <= 0 or term.get("width") != 32:
            return None
        self.remaining -= 1
        self.ranges[key] = None
        result = self._interval(term)
        self.ranges[key] = result
        return result

    def _interval(self, term: dict[str, Any]) -> tuple[int, int] | None:
        """Bound constants, inputs, branch unions and nonwrapping arithmetic."""
        op = term.get("op")
        if op == "const":
            raw = term["value"]
            value = int(raw, 0) if isinstance(raw, str) else int(raw)
            if self.normalize is not None:
                value = self.normalize(value, 32)
            return (value, value) if 0 <= value < 2**32 else None
        if op == "input":
            return self.bounds.get(term["name"])
        args = term.get("args", [])
        if op == "ite" and len(args) == 3:
            left, right = self.interval(args[1]), self.interval(args[2])
            if left is None or right is None:
                return None
            return min(left[0], right[0]), max(left[1], right[1])
        if op == "shl" and len(args) == 2:
            return self._shift_interval(args)
        if op == "sub" and len(args) == 2 and self._same_input_pair(args):
            return 0, 0
        if op not in {"add", "sub"} or len(args) != 2:
            return None
        left, right = self.interval(args[0]), self.interval(args[1])
        if left is None or right is None:
            return None
        low, high = ((left[0] + right[0], left[1] + right[1]) if op == "add"
                     else (left[0] - right[1], left[1] - right[0]))
        return (low, high) if 0 <= low <= high < 2**32 else None

    def _same_input_pair(self, args: list[dict[str, Any]]) -> bool:
        """Recognize only equal named 32-bit scalar inputs for the zero idiom."""
        first, second = (self.resolve(arg) for arg in args)
        return (first.get("op") == second.get("op") == "input"
                and isinstance(first.get("name"), str) and bool(first["name"])
                and first.get("name") == second.get("name")
                and first.get("width") == second.get("width") == 32)

    def _shift_interval(self, args: list[dict[str, Any]]) -> tuple[int, int] | None:
        """Bound a literal left shift only when no high bit can be discarded."""
        count = self.resolve(args[1])
        width = count.get("width")
        if count.get("op") != "const" or type(width) is not int or not 0 < width <= 64:
            return None
        raw = count["value"]
        shift = (int(raw, 0) if isinstance(raw, str) else int(raw)) & ((1 << width) - 1)
        if self.normalize is not None:
            shift = self.normalize(shift, width)
        if not 0 <= shift < 32:
            return None
        source = self.interval(args[0])
        if source is None or source[1] << shift >= 2**32:
            return None
        return source[0] << shift, source[1] << shift

    def preserved(self, memory: dict[str, Any]) -> bool:
        """Require every possible memory branch to preserve the original bytes."""
        memory = self.resolve(memory)
        key = id(memory)
        if key in self.memories:
            return self.memories[key]
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        self.memories[key] = False
        result = self._preserved(memory)
        self.memories[key] = result
        return result

    def _preserved(self, memory: dict[str, Any]) -> bool:
        """Check store byte extents, including their last byte, before skipping data."""
        op = memory.get("op")
        if op == "mem_input":
            return (memory.get("name"), memory.get("addr_width"), memory.get("value_width")) == ("mem", 32, 8)
        args = memory.get("args", [])
        if op == "memory_preserve" and len(args) == 4:
            return self._framed(args)
        if op == "ite" and len(args) == 3:
            return self.preserved(args[1]) and self.preserved(args[2])
        if op != "storele" or len(args) != 3:
            return False
        width = self.resolve(args[2]).get("width")
        if type(width) is not int or width <= 0 or width % 8:
            return False
        interval = self.interval(args[1])
        if interval is None:
            return False
        low, high = interval
        end = high + width // 8
        if end > 2**32 or not (end <= self.start or low >= self.end):
            return False
        self.stores_checked += 1
        return self.preserved(args[0])

    def _framed(self, args: list[dict[str, Any]]) -> bool:
        """Follow exactly the source array selected by an explicit byte frame."""
        first, last = self.interval(args[2]), self.interval(args[3])
        if first is None or last is None:
            return False
        if first[1] <= self.start and last[0] >= self.end - 1:
            return self.preserved(args[1])
        if first[0] >= self.end or last[1] < self.start:
            return self.preserved(args[0])
        # A partial overlap needs both arrays to preserve the whole region;
        # failure remains inconclusive rather than assuming either portion.
        return self.preserved(args[0]) and self.preserved(args[1])


def prove_region_preserved(
    memory: dict[str, Any], start: int, size: int,
    constraints: list[dict[str, Any]] | None = None,
    *, assignments: list[dict[str, Any]] | None = None,
) -> RegionPreservationProof | None:
    """Prove preservation of a nonwrapping region or defer to the general solver.

    Terms may be expanded SSA DAGs or use the supplied document assignments. Stored
    values are irrelevant only after all of their destination bytes have
    been proved disjoint. This proves no initialization or external behavior.
    """
    if size <= 0 or not 0 <= start < start + size <= 2**32:
        return None
    if assignments is not None:
        identifiers = [item.get("id") for item in assignments]
        if any(not isinstance(ident, str) for ident in identifiers) or len(set(identifiers)) != len(identifiers):
            return None
    check = _RegionCheck(start, size, constraints or [], assignments or [])
    if not check.preserved(memory):
        return None
    return RegionPreservationProof(check.stores_checked)


def _preserved_read(
    item: dict[str, Any], assignments: list[dict[str, Any]], constraints: list[dict[str, Any]],
    normalize: Callable[[int, int], int] | None,
) -> dict[str, int] | None:
    """Check the entire read range against every prior write in one address domain."""
    args = item.get("args", [])
    width = item.get("width")
    if (item.get("op") not in {"loadle", "loadbe"} or len(args) != 2
            or type(width) is not int or not 0 < width <= 128 or width % 8):
        return None
    check = _RegionCheck(0, 1, constraints, assignments, normalize)
    address = check.interval(args[1])
    if address is None or address[0] != address[1] or address[0] + width // 8 > 2**32:
        return None
    check.start, check.end = address[0], address[0] + width // 8
    if not check.preserved(args[0]) or not check.stores_checked:
        return None
    return {"address": address[0], "bytes": width // 8, "stores_checked": check.stores_checked}


def simplify_preserved_root_reads(
    function: dict[str, Any], *, normalize: Callable[[int, int], int],
    check_budget: Callable[[], None],
) -> dict[str, Any]:
    """Remove read-only disjoint store prefixes in both native and normalized domains.

    This consumes the completed root's explicit input constraints. It changes
    no stores or address expressions and never fixes initial memory contents.
    Checking both domains prevents relocation maps from creating hidden aliases.
    Proof records identify each changed assignment and the preserved byte range.
    """
    assignments = function.get("assignments", [])
    constraints = function.get("input_constraints", [])
    identifiers = [item.get("id") for item in assignments]
    if ("ip" in function.get("outputs", {})
            or any(not isinstance(name, str) for name in identifiers)
            or len(set(identifiers)) != len(identifiers)):
        return function
    rewritten = []
    proofs = []
    for item in assignments:
        check_budget()
        native = _preserved_read(item, assignments, constraints, None)
        normalized = None if native is None else _preserved_read(item, assignments, constraints, normalize)
        if native is None or normalized is None:
            rewritten.append(item)
            continue
        root = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
        rewritten.append({**item, "args": [root, item["args"][1]]})
        proofs.append({"assignment": item["id"], "native": native, "normalized": normalized})
    return {**function, "assignments": rewritten, "root_read_preservation": proofs}

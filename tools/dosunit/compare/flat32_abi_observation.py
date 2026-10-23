"""Layer: validation function-boundary observations.

Responsibility: project complete flat32 summaries under an explicit scalar ABI
and private-stack lifetime premise. Execution, aliases and intermediate memory
remain untouched; only observations after the checked root return change.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from tools.comparator.abi import DEFAULT_OUTPUT_REGS
from tools.comparator.msc8_scratch import _esp_delta
from tools.dosunit.contracts.flat32_buffer_domain import Flat32EntryMemoryRange, Flat32StackDisjointBuffer
from tools.dosunit.ssa.materialization import input_items


@dataclass(frozen=True, slots=True)
class Flat32AbiObservation:
    """Caller-declared scalar return and inaccessible post-return stack extent.

    Width zero denotes void; 64 observes EDX:EAX. This contract does not apply
    to floating-point, aggregate, hidden-pointer or custom register returns.
    Excluded stack cells must not be observable after return, including via an
    escaped pointer. This lifetime premise is published, never inferred.
    """

    return_bits: int
    private_stack_bytes: int = 0
    stack_disjoint_buffers: tuple[Flat32StackDisjointBuffer, ...] = ()
    entry_memory_ranges: tuple[Flat32EntryMemoryRange, ...] = ()

    def __post_init__(self) -> None:
        """Reject unsupported return classes and unbounded stack projections."""
        if type(self.return_bits) is not int or self.return_bits not in (0, 8, 16, 32, 64):
            raise ValueError("scalar ABI return width must be 0, 8, 16, 32 or 64")
        if type(self.private_stack_bytes) is not int or not 0 <= self.private_stack_bytes <= 8192:
            raise ValueError("private stack extent must be between 0 and 8192 bytes")
        if (not isinstance(self.stack_disjoint_buffers, tuple)
                or any(not isinstance(item, Flat32StackDisjointBuffer) for item in self.stack_disjoint_buffers)
                or len(self.stack_disjoint_buffers) > 32):
            raise ValueError("stack_disjoint_buffers requires at most 32 typed buffer contracts")
        if self.stack_disjoint_buffers and not self.private_stack_bytes:
            raise ValueError("stack-disjoint buffer requires a nonempty private stack extent")
        if (not isinstance(self.entry_memory_ranges, tuple)
                or any(not isinstance(item, Flat32EntryMemoryRange) for item in self.entry_memory_ranges)
                or len(self.entry_memory_ranges) > 32):
            raise ValueError("entry_memory_ranges requires at most 32 typed memory ranges")

    def outputs(self) -> tuple[str, ...]:
        """Retain return values, stack/control, preserved registers and direction."""
        returns = ("eax", "edx") if self.return_bits == 64 else ("eax",) if self.return_bits else ()
        return (*returns, *DEFAULT_OUTPUT_REGS[2:])

    def premise(self, offsets: tuple[int, ...]) -> dict[str, Any]:
        """Publish the precise observation change and unproved lifetime domain."""
        return {
            "kind": "flat32_scalar_abi_observation", "proved": False,
            "return_bits": self.return_bits, "observed_registers": list(self.outputs()),
            "private_stack_bytes": self.private_stack_bytes,
            "excluded_stack_byte_offsets": list(offsets),
            "scope": "completed root return only; internal transitions and all memory reads unchanged",
            "lifetime_premise": "excluded stack cells are inaccessible after return, including through escaped pointers",
            "stack_disjoint_buffers": [item.obligation(self.private_stack_bytes) for item in self.stack_disjoint_buffers],
            "entry_memory_ranges": [item.obligation() for item in self.entry_memory_ranges],
        }


def _private_written_bytes(function: dict[str, Any], extent: int) -> set[int]:
    """Collect only byte cells of explicitly addressed bounded stack stores."""
    assignments = function.get("assignments", [])
    by_id = {item["id"]: item for item in assignments}
    offsets: set[int] = set()
    for item in assignments:
        if item.get("op") not in {"storele", "storebe"}:
            continue
        args = item.get("args", [])
        if len(args) != 3:
            continue
        value = by_id.get(args[2].get("ref"), args[2])
        width = value.get("width", 0)
        if not isinstance(width, int) or width <= 0 or width % 8:
            continue
        delta = _esp_delta(args[1], by_id)
        if delta is not None:
            offsets.update(offset for offset in range(delta, delta + width // 8) if -extent <= offset < 0)
    return offsets


def _observe(function: dict[str, Any], contract: Flat32AbiObservation, offsets: tuple[int, ...]) -> dict[str, Any]:
    """Copy final observations without rewriting any executed load or store."""
    result = copy.deepcopy(function)
    outputs = result["outputs"]
    assignments = result["assignments"]
    ids = {item["id"] for item in assignments}

    def append(term: dict[str, Any]) -> dict[str, Any]:
        """Materialize observations as ordinary SSA assignments with fresh IDs."""
        index = len(assignments)
        while f"abi_observation_{index}" in ids:
            index += 1
        name = f"abi_observation_{index}"
        ids.add(name)
        assignments.append({"id": name, **term})
        return {"ref": name}

    for name in ("eax", "edx", "ecx"):
        if name not in contract.outputs():
            outputs.pop(name, None)
    if contract.return_bits in (8, 16) and "eax" in outputs:
        outputs["eax"] = append({"op": "and", "width": 32, "args": [outputs["eax"],
            {"op": "const", "width": 32, "value": hex((1 << contract.return_bits) - 1)}]})
    memory: dict[str, Any] = outputs.get("memory", {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8})
    runs: list[tuple[int, int]] = []
    for offset in offsets:
        if runs and offset == runs[-1][0] + runs[-1][1]:
            start, count = runs[-1]
            runs[-1] = (start, count + 1)
        else:
            runs.append((offset, 1))
    for offset, count in runs:
        address = append({"op": "add", "width": 32, "args": [
            {"op": "input", "name": "esp", "width": 32},
            {"op": "const", "value": hex(offset & 0xFFFFFFFF), "width": 32}]})
        memory = append({"op": "storele", "width": 0, "args": [memory, address, {"op": "const", "width": 8 * count, "value": "0x0"}]})
    if offsets:
        outputs["memory"] = memory
    _attach_entry_obligations(result, contract)
    return result


def _attach_entry_obligations(result: dict[str, Any], contract: Flat32AbiObservation) -> None:
    """Bind explicit root predicates and their inputs without altering effects."""
    if not contract.stack_disjoint_buffers and not contract.entry_memory_ranges:
        return
    obligations = [item.obligation(contract.private_stack_bytes) for item in contract.stack_disjoint_buffers]
    obligations.extend(item.obligation() for item in contract.entry_memory_ranges)
    combined = list(result.get("obligations", []))
    for obligation in obligations:
        if obligation not in combined:
            combined.append(obligation)
    result["obligations"] = combined
    inputs = {item["name"]: item for item in result.get("inputs", [])}
    for item in input_items([obligation["predicate"] for obligation in obligations], []):
        if item["name"] in inputs and inputs[item["name"]] != item:
            raise ValueError("buffer premise input conflicts with root input declaration")
        inputs[item["name"]] = item
    result["inputs"] = list(inputs.values())


def observe_completed_pair(
    oracle: dict[str, Any], candidate: dict[str, Any], contract: Flat32AbiObservation,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Project both completed functions on the same union of private cells.

    Replacing final bytes on both sides is an observation projection, not an
    execution-memory split. Reads through aliases and values leaked into
    returns, public memory or external events therefore keep their effects.
    """
    offsets = tuple(sorted(_private_written_bytes(oracle, contract.private_stack_bytes)
                           | _private_written_bytes(candidate, contract.private_stack_bytes)))
    return _observe(oracle, contract, offsets), _observe(candidate, contract, offsets), contract.premise(offsets)


def apply_completed_observation(
    oracle: dict[str, Any], candidate: dict[str, Any], contract: Flat32AbiObservation | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Keep strict summaries unchanged when no caller observation is declared."""
    if contract is None:
        return oracle, candidate, None
    return observe_completed_pair(oracle, candidate, contract)


def observation_outputs(outputs: tuple[str, ...], contract: Flat32AbiObservation | None) -> tuple[str, ...]:
    """Require every ABI-preserved output even when a caller requested fewer."""
    required = contract.outputs() if contract is not None else ()
    return tuple(dict.fromkeys((*outputs, *required)))


def record_abi_observation(comparison: dict[str, Any], premise: dict[str, Any] | None) -> None:
    """Retain observation evidence and label any successful projected proof."""
    if premise is None:
        return
    comparison["abi_observation"] = premise
    if comparison.get("status") in {"passed", "conditional"}:
        comparison["assumptions"] = {**comparison.get("assumptions", {}), "abi_observation": premise}
        comparison["status"] = "conditional"
        comparison["reason"] = comparison.get("reason") or "flat32_scalar_abi_observation"

"""Layer: flat32 auxiliary return-target proof simplification.

Responsibility: simplify return reads under an explicit root buffer domain.
This does not remove stores from function outputs. The caller must retain the
returned obligations, prove their feasibility, and report conditional results.
Only exact root terms are accepted; callee-local or renamed inputs do not match.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tools.dosunit.contracts.flat32_buffer_domain import Flat32StackDisjointBuffer

type Term = dict[str, Any]
MASK: int = (1 << 32) - 1


def _constant(term: Term) -> int | None:
    if term.get("op") != "const" or term.get("width") != 32:
        return None
    value = term.get("value")
    if isinstance(value, str):
        return int(value, 0) & MASK
    if type(value) is int:
        return value & MASK
    return None


def _parts(term: Term) -> tuple[Term, int]:
    """Normalize constant address arithmetic and disjoint root-stack loads."""
    args = term.get("args", [])
    if term.get("width") == 32 and len(args) == 2:
        if term.get("op") in {"add", "sub"}:
            left, right = args
            constant = _constant(right)
            if constant is None and term["op"] == "add":
                constant, left = _constant(left), right
            if constant is not None:
                atom, offset = _parts(left)
                return atom, (offset + (constant if term["op"] == "add" else -constant)) & MASK
        if term.get("op") == "loadle":
            memory, address = args
            atom, offset = _parts(address)
            # Root argument loads following pushes still refer to entry mem.
            # Restrict this rewrite to statically disjoint ESP-relative cells.
            esp = {"op": "input","name": "esp","width": 32}
            if atom == esp:
                while memory.get("op") == "storele":
                    previous, destination, value = memory["args"]
                    store_atom, store_offset = _parts(destination)
                    width = value.get("width")
                    if store_atom != esp or type(width) is not int or not 0 < width <= 65536*8 or width % 8:
                        break
                    distance = (store_offset - offset) & MASK
                    if distance < 4 or ((-distance) & MASK) < width // 8:
                        break
                    memory = previous
                normalized = {"op": "add","width": 32,"args": [esp,{"op": "const","width": 32,"value": hex(offset)}]}
                return {"op": "loadle","width": 32,"args": [memory,normalized]}, 0
    return term, 0


def _offset(term: Term, base: Term) -> int | None:
    atom, offset = _parts(term)
    base_atom, base_offset = _parts(base)
    return (offset-base_offset)&MASK if atom == base_atom else None


@dataclass(frozen=True)
class ReadReduction:
    """Reduced read plus the explicit domain needed to justify skipped writes."""
    term: Term
    obligations: tuple[Term, ...]
    skipped_stores: int


def reduce_return_read(term: Term, domain: Flat32StackDisjointBuffer,
                       private_stack_bytes: int) -> ReadReduction:
    """Reduce one root-frame read without modifying any memory output."""
    obligation = domain.obligation(private_stack_bytes)
    # Derive the exact root terms from the same serialized domain, not from
    # names supplied by the candidate or from unchecked obligation metadata.
    delta = obligation["predicate"]["args"][0]["args"][0]
    pointer, frame = delta["args"]
    if term.get("op") != "loadle" or term.get("width") != 32:
        return ReadReduction(term, (), 0)
    memory, address = term["args"]
    offset = _offset(address, frame)
    if offset is None or offset + 4 > private_stack_bytes:
        return ReadReduction(term, (), 0)
    return _reduce_memory(term, memory, address, pointer, domain, obligation)


def _read_last_store(memory: Term, address: Term) -> Term:
    """Forward exactly matching little-endian DWORD stores, preserving others."""
    if memory.get("op") == "storele":
        _, destination, value = memory["args"]
        if isinstance(value, dict) and value.get("width") == 32 and _offset(destination, address) == 0:
            return value
    return {"op": "loadle", "width": 32, "args": [memory, address]}


def _reduce_memory(term: Term, memory: Term, address: Term, pointer: Term,
                   domain: Flat32StackDisjointBuffer, obligation: Term) -> ReadReduction:
    skipped = 0
    while memory.get("op") == "storele":
        previous, destination, value = memory["args"]
        width = value.get("width")
        displacement = _offset(destination, pointer)
        if (type(width) is not int or width <= 0 or width % 8
                or displacement is None
                or displacement + width // 8 > domain.size_bytes):
            break
        memory = previous
        skipped += 1
    if memory.get("op") == "ite":
        condition, yes, no = memory["args"]
        left = _reduce_memory(term,yes,address,pointer,domain,obligation)
        right = _reduce_memory(term,no,address,pointer,domain,obligation)
        if left.skipped_stores or right.skipped_stores:
            reduced = left.term if left.term == right.term else {
                "op": "ite","width": 32,"args": [condition,left.term,right.term]}
            return ReadReduction(reduced,(obligation,),skipped+left.skipped_stores+right.skipped_stores)
    if not skipped:
        return ReadReduction(_read_last_store(memory,address), (), 0)
    reduced = _read_last_store(memory,address)
    return ReadReduction(reduced, (obligation,), skipped)

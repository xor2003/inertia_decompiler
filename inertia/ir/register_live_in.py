# cython: language_level=3, infer_types=True
"""Layer: IR.

Responsibility: compute upward-exposed register bits across a function CFG.
Register views are supplied by the consumer's authoritative inventory; a
partial write defines only its own bits, never the complete parent register.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping

from .core import IRAddress, IRBinaryValue, IRCondition, IRValue, MemSpace
from .ssa_function import SSAFunctionArtifact
import operator
import builtins

RegisterViews = typing.TypeAliasType("RegisterViews", Mapping[str, tuple[str, int, int]])
RegisterBit = typing.TypeAliasType("RegisterBit", tuple[str, int])


@cython.ccall
def _destination_bits(value: object, views: RegisterViews) -> set[RegisterBit]:
    """Return the exact named register view written by one IR destination."""
    view: object
    if not isinstance(value, IRValue) or value.space is not MemSpace.REG or value.name is None:
        return set()
    view = views.get(value.name.lower())
    if view is None:
        return set()
    parent, shift, width = view
    return {(parent, bit) for bit in range(shift, shift + width * 8)}


@cython.ccall
def _read_bits(value: object, views: RegisterViews) -> object:
    """Collect register reads from typed values, addresses and conditions."""
    if isinstance(value, IRValue):
        return _destination_bits(value, views) | _read_bits(value.index, views)
    if isinstance(value, IRBinaryValue):
        return _read_bits(value.lhs, views) | _read_bits(value.rhs, views)
    if isinstance(value, IRAddress):
        return {bit for base in iter(value.base_values) for bit in builtins.iter(_read_bits(base, views))}
    if isinstance(value, IRCondition):
        return {bit for argument in iter(value.args) for bit in builtins.iter(_read_bits(argument, views))}
    return set()


def register_live_in_names_8616(artifact: SSAFunctionArtifact, views: RegisterViews) -> frozenset[str]:
    """Return parents whose read bits lack a definition on every incoming path."""
    addr: object
    argument: object
    block: object
    instruction: object
    universe = {(parent, bit) for parent, shift, width in builtins.iter(views.values()) for bit in range(shift, shift + 8 * width)}
    exposed: dict[cython.longlong, set[RegisterBit]] = {}
    definitions: dict[cython.longlong, set[RegisterBit]] = {}
    for block in artifact.blocks:
        defined: set[RegisterBit] = set()
        reads: set[RegisterBit] = set()
        for instruction in block.instrs:
            for argument in instruction.args:
                reads.update(_read_bits(argument, views) - defined)
            defined.update(_destination_bits(instruction.dst, views))
        exposed[block.addr] = reads
        definitions[block.addr] = defined

    entry = artifact.function_addr
    must_in = {addr: (set() if addr == entry else set(universe)) for addr in iter(definitions)}
    changed = True
    while changed:
        changed = False
        for addr in sorted(definitions):
            predecessors = tuple(pred for pred in builtins.iter(artifact.predecessor_map.get(addr, ())) if pred in definitions)
            incoming = (
                set.intersection(*(must_in[pred] | definitions[pred] for pred in iter(predecessors)))
                if addr != entry and predecessors else set()
            )
            if operator.ne(incoming, must_in[addr]):
                must_in[addr] = incoming
                changed = True
    return frozenset(parent for addr, bits in builtins.iter(exposed.items()) for parent, _bit in iter(bits - must_in[addr]))

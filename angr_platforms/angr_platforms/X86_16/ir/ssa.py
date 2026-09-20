"""Build block-local SSA over typed IR values.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, replace

from .core import IRAddress, IRAtom, IRBinaryValue, IRBlock, IRCondition, IRInstr, IRValue, MemSpace

__all__ = ["SSABinding", "SSABlock", "build_x86_16_block_local_ssa"]

_VersionKey = tuple[str, str | None, int]
_TemporarySnapshots = dict[int, IRValue]
_CurrentDefinitions = dict[_VersionKey, IRValue]


@dataclass(frozen=True, slots=True)
class SSABinding:
    """Version assigned to one typed IR value definition inside a block."""

    target: IRValue
    version: int
    instr_index: int

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "target": self.target.to_dict(),
            "version": self.version,
            "instr_index": self.instr_index,
        }


@dataclass(frozen=True, slots=True)
class SSABlock:
    """Block-local SSA view of typed IR instructions and definitions."""

    addr: int
    instrs: tuple[IRInstr, ...]
    bindings: tuple[SSABinding, ...]
    refusals: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "addr": self.addr,
            "instrs": [item.to_dict() for item in self.instrs],
            "bindings": [item.to_dict() for item in self.bindings],
            "refusals": list(self.refusals),
        }


_BLOCK_LOCAL_SSA_CACHE_MAX_ENTRIES_8616 = 128
_BLOCK_LOCAL_SSA_CACHE_LOCK_8616 = threading.RLock()
_BLOCK_LOCAL_SSA_CACHE_8616: OrderedDict[int, tuple[IRBlock, SSABlock]] = OrderedDict()


def _cached_block_local_ssa_8616(block: IRBlock) -> SSABlock | None:
    """Return a projection only for the same immutable block object."""
    key = id(block)
    with _BLOCK_LOCAL_SSA_CACHE_LOCK_8616:
        cached = _BLOCK_LOCAL_SSA_CACHE_8616.get(key)
        if cached is None:
            return None
        cached_block, result = cached
        if cached_block is not block:
            del _BLOCK_LOCAL_SSA_CACHE_8616[key]
            return None
        _BLOCK_LOCAL_SSA_CACHE_8616.move_to_end(key)
        return result


def _publish_block_local_ssa_8616(block: IRBlock, result: SSABlock) -> SSABlock:
    """Publish one bounded identity-safe immutable block projection."""
    key = id(block)
    with _BLOCK_LOCAL_SSA_CACHE_LOCK_8616:
        cached = _BLOCK_LOCAL_SSA_CACHE_8616.get(key)
        if cached is not None and cached[0] is block:
            _BLOCK_LOCAL_SSA_CACHE_8616.move_to_end(key)
            return cached[1]
        _BLOCK_LOCAL_SSA_CACHE_8616[key] = (block, result)
        _BLOCK_LOCAL_SSA_CACHE_8616.move_to_end(key)
        while len(_BLOCK_LOCAL_SSA_CACHE_8616) > _BLOCK_LOCAL_SSA_CACHE_MAX_ENTRIES_8616:
            _BLOCK_LOCAL_SSA_CACHE_8616.popitem(last=False)
    return result


def _version_key(value: IRValue) -> _VersionKey:
    """Key named registers independently of arithmetic value displacement.

    For REG values, the register name identifies storage and offset belongs to
    the expression (for example SP minus four). Memory and unnamed-register
    offsets still distinguish storage. Never erase displacement from the value.
    """
    storage_offset = 0 if value.space is MemSpace.REG and value.name is not None else value.offset
    return (value.space.value, value.name, storage_offset)


def _versioned(value: IRValue, version: int) -> IRValue:
    """Assign one SSA version without dropping value provenance."""
    return replace(value, version=version)


def _rewrite_binary_value(
    value: IRBinaryValue,
    versions: dict[_VersionKey, int],
    snapshots: _TemporarySnapshots,
    definitions: _CurrentDefinitions,
) -> IRBinaryValue:
    """Rewrite both operands of one typed binary value into current SSA versions."""
    return replace(
        value,
        lhs=_rewrite_value_expression(value.lhs, versions, snapshots, definitions),
        rhs=_rewrite_value_expression(value.rhs, versions, snapshots, definitions),
    )


def _rewrite_value_expression(
    value: IRValue | IRBinaryValue,
    versions: dict[_VersionKey, int],
    snapshots: _TemporarySnapshots,
    definitions: _CurrentDefinitions,
) -> IRValue | IRBinaryValue:
    """Rewrite a scalar or nested typed value expression into current SSA versions."""
    if isinstance(value, IRBinaryValue):
        return _rewrite_binary_value(value, versions, snapshots, definitions)
    return _rewrite_value(value, versions, snapshots, definitions)


def _rewrite_value(
    value: IRValue,
    versions: dict[_VersionKey, int],
    snapshots: _TemporarySnapshots,
    definitions: _CurrentDefinitions,
) -> IRValue:
    """Rewrite one value and its indexed-address provenance into current SSA versions."""
    if value.space in {MemSpace.CONST, MemSpace.UNKNOWN}:
        return value
    key = _version_key(value)
    snapshot = None if value.source_tmp is None else snapshots.get(value.source_tmp)
    source_definition: IRValue | None
    if (
        snapshot is not None
        and snapshot.version is not None
        and snapshot.size == value.size
        and _version_key(snapshot) == key
    ):
        version = snapshot.version
        source_definition = snapshot
    else:
        version = versions.setdefault(key, 0)
        source_definition = definitions.get(key)
    rewritten_index = (
        None
        if value.index is None
        else _rewrite_value_expression(value.index, versions, snapshots, definitions)
    )
    return replace(
        _versioned(value, version),
        index=rewritten_index,
        call_output=(
            value.call_output
            if source_definition is None
            else source_definition.call_output
        ),
    )


def _rewrite_atom(
    atom: IRAtom,
    versions: dict[_VersionKey, int],
    snapshots: _TemporarySnapshots,
    definitions: _CurrentDefinitions,
) -> IRAtom:
    """Rewrite every value-bearing IR atom without losing typed metadata."""
    if isinstance(atom, IRCondition):
        return IRCondition(
            op=atom.op,
            args=tuple(
                _rewrite_atom(arg, versions, snapshots, definitions) for arg in atom.args
            ),
            expr=atom.expr,
            width_bits=atom.width_bits,
        )
    if isinstance(atom, IRBinaryValue):
        return _rewrite_binary_value(atom, versions, snapshots, definitions)
    if isinstance(atom, IRValue):
        return _rewrite_value(atom, versions, snapshots, definitions)
    if isinstance(atom, IRAddress):
        return replace(
            atom,
            base_values=tuple(
                _rewrite_value(value, versions, snapshots, definitions)
                for value in atom.base_values
            ),
        )
    return atom


def _record_temporary_snapshot(
    instruction: IRInstr,
    destination: IRValue | None,
    arguments: tuple[IRAtom, ...],
    snapshots: _TemporarySnapshots,
) -> None:
    """Record the exact scalar version captured by one VEX temporary MOV."""
    if instruction.op != "MOV" or destination is None:
        return
    if destination.space is not MemSpace.TMP or destination.source_tmp is None:
        return
    if len(arguments) == 1 and isinstance(arguments[0], IRValue):
        snapshots[destination.source_tmp] = arguments[0]


def _build_x86_16_block_local_ssa_uncached(block: IRBlock) -> SSABlock:
    """Rewrite one typed IR block without consulting the identity cache."""
    versions: dict[_VersionKey, int] = {}
    snapshots: _TemporarySnapshots = {}
    definitions: _CurrentDefinitions = {}
    rewritten: list[IRInstr] = []
    bindings: list[SSABinding] = []
    for index, instr in enumerate(block.instrs):
        rewritten_args: list[IRAtom] = []
        for arg in instr.args:
            rewritten_args.append(_rewrite_atom(arg, versions, snapshots, definitions))
        rewritten_dst = instr.dst
        if rewritten_dst is not None and rewritten_dst.space not in {MemSpace.CONST, MemSpace.UNKNOWN}:
            key = _version_key(rewritten_dst)
            version = versions.get(key, -1) + 1
            versions[key] = version
            rewritten_dst = _versioned(rewritten_dst, version)
            definitions[key] = rewritten_dst
            bindings.append(SSABinding(target=rewritten_dst, version=version, instr_index=index))
        rewritten_args_tuple = tuple(rewritten_args)
        _record_temporary_snapshot(instr, rewritten_dst, rewritten_args_tuple, snapshots)
        rewritten.append(
            replace(
                instr,
                dst=rewritten_dst,
                args=rewritten_args_tuple,
            )
        )
    return SSABlock(addr=block.addr, instrs=tuple(rewritten), bindings=tuple(bindings))


def build_x86_16_block_local_ssa(block: IRBlock) -> SSABlock:
    """Return deterministic block-local SSA, reusing the same immutable input."""
    cached = _cached_block_local_ssa_8616(block)
    if cached is not None:
        return cached
    return _publish_block_local_ssa_8616(
        block,
        _build_x86_16_block_local_ssa_uncached(block),
    )

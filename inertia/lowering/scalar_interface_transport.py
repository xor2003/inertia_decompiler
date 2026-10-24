"""Layer: Types/lowering.

Responsibility: transport an accepted scalar callee interface, bound to its
source binary, native function bytes and generated payload, through worker IPC.
No inference from names, rendered C or source; pointer/aggregate types refuse.
Layer: Types/Lowering
Consumes alias, widening, and typed facts
Do not recover semantics from COD, source, assembly, or rendered C text
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypeShort
from archinfo import Arch

from .authoritative_function_prototypes import (
    authoritative_function_prototype_8616,
    publish_authoritative_function_prototype_8616,
)


class _Memory(Protocol):
    """Current loader memory boundary."""

    def load(self, addr: int, size: int) -> bytes:
        """Read current loaded native bytes."""
        ...


class _Object(Protocol):
    """Original native source identity boundary."""

    binary: str
    mapped_base: int


class _Loader(Protocol):
    """Native file and live memory binding."""

    main_object: _Object
    memory: _Memory


class _Functions(Protocol):
    """Existing function lookup boundary."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Look up the exact existing callee."""
        ...


class _KB(Protocol):
    """Function inventory boundary."""

    functions: _Functions


class _Project(Protocol):
    """Project-local accepted scalar interface inventory."""

    arch: Arch
    loader: _Loader
    kb: _KB
    _inertia_scalar_interfaces_8616: dict[int, ScalarInterface8616]


class _Function(Protocol):
    """Native function extent and published prototype."""

    addr: int
    size: int
    prototype: object
    block_addrs_set: set[int]

    def get_block_size(self, addr: int) -> int | None:
        """Return the retained exact native block size without relifting."""
        ...


class ScalarKind8616(StrEnum):
    """Exact C scalar spelling class, independent of physical return width."""

    CHAR = "char"
    SHORT = "short"
    INT = "int"
    LONG = "long"


@dataclass(frozen=True, slots=True)
class ScalarType8616:
    """One exact native scalar width and C signed interpretation."""
    width: int
    signed: bool
    kind: ScalarKind8616


@dataclass(frozen=True, slots=True)
class ScalarInterface8616:
    """Accepted callee interface; never authorizes effects or termination."""
    target: int
    source_sha256: str
    mapped_base: int
    arch_name: str
    arch_bits: int
    native_size: int
    native_sha256: str
    payload_sha256: str
    arguments: tuple[ScalarType8616, ...]
    result: ScalarType8616

    def to_record(self) -> dict[str, object]:
        """Encode strict scalar records on the existing JSON transport."""
        return asdict(self)


def _source(project: _Project) -> str:
    """Bind the original file bytes, not a mutable filename alone."""
    return hashlib.sha256(Path(project.loader.main_object.binary).read_bytes()).hexdigest()


def _scalar(value: object) -> ScalarType8616 | None:
    """Admit only concrete scalar machine types with known signedness."""
    kind = {SimTypeChar: ScalarKind8616.CHAR, SimTypeShort: ScalarKind8616.SHORT,
            SimTypeInt: ScalarKind8616.INT, SimTypeLong: ScalarKind8616.LONG}.get(type(value))
    if kind is None:
        return None
    value = cast(SimTypeInt | SimTypeChar, value)
    if value.size not in (8, 16, 32) or type(value.signed) is not bool:
        return None
    return ScalarType8616(value.size // 8, value.signed, kind)


def _native_extent(function: _Function, target: int) -> int | None:
    """Cover every retained block, including gaps which Function.size omits."""
    addresses = function.block_addrs_set
    if function.addr != target or not addresses or target not in addresses or len(addresses) > 4096:
        return None
    end = target
    for addr in addresses:
        size = function.get_block_size(addr)
        if type(addr) is not int or addr < target or type(size) is not int or size <= 0:
            return None
        end = max(end, addr + size)
    return end - target if 0 < end - target <= 65536 else None


def scalar_interface_for_result_8616(
    project: object, target: int, payload: str, *, function: object | None = None,
) -> ScalarInterface8616 | None:
    """Export only an already published exact-arity scalar interface."""
    surface = cast(_Project, project)
    if function is None:
        function = surface.kb.functions.function(addr=target, create=False)
    if function is None or surface.arch.name != '86_16':
        return None
    callee = cast(_Function, function)
    current = callee.prototype
    if not isinstance(current, SimTypeFunction) or current.variadic:
        return None
    prototype = authoritative_function_prototype_8616(surface, function, argument_count=len(current.args))
    native_size = _native_extent(callee, target)
    if prototype is None or prototype.variadic or native_size is None:
        return None
    args = tuple(_scalar(item) for item in prototype.args)
    result = _scalar(prototype.returnty)
    if any(item is None for item in args) or result is None:
        return None
    data = surface.loader.memory.load(target, native_size)
    if len(data) != native_size:
        return None
    return ScalarInterface8616(
        target, _source(surface), surface.loader.main_object.mapped_base,
        surface.arch.name, surface.arch.bits, native_size, hashlib.sha256(data).hexdigest(),
        hashlib.sha256(payload.encode()).hexdigest(), cast(tuple[ScalarType8616, ...], args), result,
    )


def _validate_interface_digests(record: dict[str, object]) -> None:
    """Require exact SHA-256 values at the JSON boundary."""
    for name in ('source_sha256', 'native_sha256', 'payload_sha256'):
        digest = record[name]
        if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('invalid scalar interface digest')


def scalar_interface_from_record_8616(record: object) -> ScalarInterface8616:
    """Reject malformed, partial or non-scalar interface records."""
    if not isinstance(record, dict) or set(record) != set(ScalarInterface8616.__dataclass_fields__):
        raise ValueError('invalid scalar interface fields')
    for name in ('target', 'mapped_base', 'arch_bits', 'native_size'):
        if type(record[name]) is not int or record[name] < 0:
            raise ValueError('invalid scalar interface coordinate')
    if record['arch_name'] != '86_16' or not 0 < record['native_size'] <= 65536:
        raise ValueError('unsupported scalar interface ABI')
    _validate_interface_digests(record)
    def scalar(raw: object) -> ScalarType8616:
        """Validate a single scalar record without integer/bool coercion."""
        if not isinstance(raw, dict) or set(raw) != {'width', 'signed', 'kind'}:
            raise ValueError('invalid scalar type')
        if type(raw['width']) is not int or raw['width'] not in (1, 2, 4) or type(raw['signed']) is not bool:
            raise ValueError('invalid scalar width/signedness')
        return ScalarType8616(raw['width'], raw['signed'], ScalarKind8616(raw['kind']))
    if not isinstance(record['arguments'], (list, tuple)) or len(record['arguments']) > 64:
        raise ValueError('invalid scalar argument census')
    return ScalarInterface8616(
        record['target'], record['source_sha256'], record['mapped_base'], record['arch_name'],
        record['arch_bits'], record['native_size'], record['native_sha256'], record['payload_sha256'],
        tuple(scalar(item) for item in record['arguments']), scalar(record['result']),
    )


def attach_scalar_interface_8616(project: object, receipt: ScalarInterface8616) -> None:
    """Rebind current native source before importing accepted type evidence."""
    surface = cast(_Project, project)
    if (receipt.source_sha256 != _source(surface) or receipt.mapped_base != surface.loader.main_object.mapped_base
        or receipt.arch_name != surface.arch.name or receipt.arch_bits != surface.arch.bits
        or hashlib.sha256(surface.loader.memory.load(receipt.target, receipt.native_size)).hexdigest() != receipt.native_sha256):
        raise ValueError('stale scalar interface source or ABI')
    try:
        registry = surface._inertia_scalar_interfaces_8616
    except AttributeError:
        registry = {}
        surface._inertia_scalar_interfaces_8616 = registry
    prior = registry.get(receipt.target)
    if prior is not None and prior != receipt:
        raise ValueError('conflicting scalar interface')
    def simtype(value: ScalarType8616) -> SimTypeInt | SimTypeChar:
        """Build the existing target-width SimType representation."""
        constructor = {ScalarKind8616.CHAR: SimTypeChar, ScalarKind8616.SHORT: SimTypeShort,
                       ScalarKind8616.INT: SimTypeInt, ScalarKind8616.LONG: SimTypeLong}[value.kind]
        result = constructor(value.signed).with_arch(surface.arch)
        if result.size != value.width * 8:
            raise ValueError("scalar kind/width contradict target ABI")
        return result
    prototype = SimTypeFunction(tuple(simtype(item) for item in receipt.arguments), simtype(receipt.result)).with_arch(surface.arch)
    published = publish_authoritative_function_prototype_8616(
        surface, receipt.target, prototype, source=PrototypeSource.CCA_DECOMPILER,
    )
    if published.prototype != prototype:
        raise ValueError("accepted scalar interface conflicts with stronger prototype")
    registry[receipt.target] = receipt


def scalar_interfaces_8616(project: object) -> tuple[ScalarInterface8616, ...]:
    """Return accepted typed interfaces in deterministic target order."""
    try:
        registry = cast(_Project, project)._inertia_scalar_interfaces_8616
    except AttributeError:
        return ()
    return tuple(registry[key] for key in sorted(registry))


def scalar_interface_records_8616(project: object) -> list[dict[str, object]]:
    """Export only the accepted project-local interface inventory."""
    return [receipt.to_record() for receipt in scalar_interfaces_8616(project)]


def current_scalar_interface_8616(project: object, target: int) -> ScalarInterface8616 | None:
    """Revalidate a transported source before its declaration is consumed."""
    try:
        receipt = cast(_Project, project)._inertia_scalar_interfaces_8616.get(target)
    except AttributeError:
        return None
    if receipt is not None:
        attach_scalar_interface_8616(project, receipt)
    return receipt

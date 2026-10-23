"""Authenticate the contents of a native variable-allocation publication.

Layer: Frontend/native adapter.
Responsibility: retain immutable structural snapshots of the native manager and
link maps so mutable object identity alone cannot authorize allocation reuse.
Unknown native payloads refuse instead of being reduced to identity or repr.
"""

from __future__ import annotations

import enum
import json
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Protocol, cast

from angr import ailment
from angr.calling_conventions import SimCC
from angr.sim_type import SimType
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimVariable

from inertia.lowering.allocation_convergence import (
    AllocationFingerprintRefusal,
    AllocationStructuralKey,
    NativeVariableKey,
)

type NativePublicationRecords8616 = tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class NativeAllocationKeyers8616:
    """Canonical structural serializers supplied by the native input owner."""

    variable: Callable[[SimVariable], NativeVariableKey]
    native_type: Callable[[object], AllocationStructuralKey]
    expression: Callable[[object], AllocationStructuralKey]
    convention: Callable[[object], AllocationStructuralKey | None]


@dataclass(frozen=True, slots=True)
class NativeAllocationPublication8616:
    """One accepted generation, its detached raw input and sealed contents."""

    manager: object
    variable_map: object
    graph: object
    input_graph: object
    records: NativePublicationRecords8616


class _VariableFlags8616(Protocol):
    """Installed native variable provenance and naming flags."""

    region: int | None
    renamed: bool


class _ManagerSurface8616(Protocol):
    """Consumed installed variable-manager projections."""

    _variables: Collection[SimVariable]
    variable_to_types: dict[SimVariable, SimType]
    variables_with_manual_types: Collection[SimVariable]
    _variables_to_unified_variables: dict[SimVariable, SimVariable]
    _vvarid_to_variable: dict[int, SimVariable]

    def input_variables(self) -> Collection[SimVariable]:
        """Return current native input variables."""
        ...

    def find_variables_by_stack_offset(self, offset: int) -> set[SimVariable]:
        """Read the published stack lookup index."""
        ...

    def find_variables_by_register(self, register: int) -> set[SimVariable]:
        """Read the published register lookup index."""
        ...


def _native_value_8616(
    value: object, keyers: NativeAllocationKeyers8616, depth: int = 0,
) -> object:
    """Normalize installed native payloads into finite primitive records.

    Installed angr/Rust forms are narrowed at this boundary; owned serializers
    and the resulting publication records retain explicit concrete contracts.
    """
    if depth > 128:
        raise AllocationFingerprintRefusal("recursive native publication payload")
    nested = depth + 1
    if value is None or type(value) in (bool, int, str):
        return (type(value).__name__, value)
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, (tuple, list, set, frozenset)):
        items = [_native_value_8616(item, keyers, nested) for item in value]
        if isinstance(value, (set, frozenset)):
            items.sort(key=_json_8616)
        return (type(value).__name__, tuple(items))
    if isinstance(value, dict):
        rows = [
            (_native_value_8616(key, keyers, nested), _native_value_8616(item, keyers, nested))
            for key, item in value.items()
        ]
        return ("mapping", tuple(sorted(rows, key=_json_8616)))
    return _native_object_8616(value, keyers, nested)


def _native_object_8616(value: object, keyers: NativeAllocationKeyers8616, nested: int) -> object:
    """Normalize installed variable/type/expression objects at the native boundary."""
    if isinstance(value, SimVariable):
        key = keyers.variable(value)
        flags = cast(_VariableFlags8616, value)
        return (
            "variable", id(value), key.kind, key.ident,
            _native_value_8616(key.location, keyers, nested), key.size, key.name,
            flags.region, flags.renamed,
        )
    if isinstance(value, SimType):
        return ("type", _native_value_8616(keyers.native_type(value), keyers, nested))
    if isinstance(value, SimCC):
        return ("cc", _native_value_8616(keyers.convention(value), keyers, nested))
    if isinstance(value, ailment.Expr.Expression):
        return ("expression", _native_value_8616(keyers.expression(value), keyers, nested))
    if isinstance(value, enum.Enum):
        return ("enum", type(value).__module__, type(value).__qualname__, value.name)
    raise AllocationFingerprintRefusal(
        f"unsupported native publication payload {type(value).__name__}"
    )


def _json_8616(value: object) -> str:
    """Encode only the normalized finite primitive record above."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _manager_state_8616(manager: object) -> dict[str, object]:
    """Read native variables, types, links and their consumed lookup indexes."""
    native = cast(_ManagerSurface8616, manager)
    variables = tuple(native._variables)
    stack_offsets = {var.offset for var in variables if isinstance(var, SimStackVariable)}
    registers = {var.reg for var in variables if isinstance(var, SimRegisterVariable)}
    return {
        "variables": variables,
        "types": native.variable_to_types,
        "manual_types": native.variables_with_manual_types,
        "unified": native._variables_to_unified_variables,
        "vvars": native._vvarid_to_variable,
        "inputs": tuple(native.input_variables()),
        "stack_index": {
            offset: native.find_variables_by_stack_offset(offset) for offset in stack_offsets
        },
        "register_index": {
            register: native.find_variables_by_register(register) for register in registers
        },
    }


def native_publication_records_8616(
    manager: object,
    variable_map: object,
    map_names: tuple[str, ...],
    keyers: NativeAllocationKeyers8616,
) -> NativePublicationRecords8616:
    """Snapshot every named link projection and the function manager contents."""
    records = [("manager", _json_8616(_native_value_8616(_manager_state_8616(manager), keyers)))]
    for name in map_names:
        # Dynamic third-party boundary: native map names come from the canonical list.
        mapping = getattr(variable_map, name)
        if not isinstance(mapping, dict):
            raise AllocationFingerprintRefusal(f"native publication map {name} is not a dictionary")
        records.append((name, _json_8616(_native_value_8616(mapping, keyers))))
    return tuple(records)

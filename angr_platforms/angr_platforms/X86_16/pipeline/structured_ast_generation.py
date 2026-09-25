"""Detect structured-C mutations without rendered-text comparisons.

Layer: Pipeline governance.
Responsibility: provide a neutral generation token for pipeline stages that
must validate whether a third-party angr C-AST surface changed.
Owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Dynamic boundary: generation inspects public fields on third-party angr C-AST nodes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from ..c_ast_utils import _structured_codegen_node_8616, _structured_slot_names_8616

_BOUNDARY_SEMANTIC_FIELDS_8616 = (
    "addr",
    "base",
    "bits",
    "ident",
    "length",
    "name",
    "offset",
    "op",
    "region",
    "reg",
    "signed",
    "size",
    "value",
    "variable_type",
)
_IGNORED_PUBLIC_FIELDS_8616 = frozenset({"arch", "codegen", "project"})


@dataclass(frozen=True, slots=True)
class StructuredAstGeneration8616:
    """Deterministic in-process digest of one structured-C object graph."""

    digest: str
    structured_node_count: int


class _CodegenSurface8616(Protocol):
    """Minimal dynamic angr codegen surface carrying a C function."""

    cfunc: object


class _StructuredAstGenerationBuilder8616:
    """Stream one dynamic structured-C graph into a SHA-256 generation."""

    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._seen: dict[int, int] = {}
        self._structured_node_count = 0

    def _text(self, value: str) -> None:
        """Append one length-delimited text atom to the digest."""
        encoded = value.encode("utf-8", errors="backslashreplace")
        self._digest.update(len(encoded).to_bytes(8, "little"))
        self._digest.update(encoded)

    def _reference(self, value: object) -> bool:
        """Record an object identity and report an already-seen reference."""
        marker = id(value)
        previous = self._seen.get(marker)
        if previous is not None:
            self._text("ref")
            self._text(str(previous))
            return True
        self._seen[marker] = len(self._seen) + 1
        return False

    @staticmethod
    def _public_field_names(value: object) -> tuple[str, ...]:
        """Return public fields at the dynamic structured-C boundary."""
        try:
            value_dict = value.__dict__
        except AttributeError:
            return ()
        if not isinstance(value_dict, dict):
            return ()
        return tuple(
            sorted(
                name
                for name in value_dict
                if isinstance(name, str)
                and not name.startswith("_")
                and name not in _IGNORED_PUBLIC_FIELDS_8616
            )
        )

    @staticmethod
    def _stored_fields(value: object) -> dict[str, object]:
        """Return instance storage without invoking third-party descriptors."""
        try:
            value_dict = object.__getattribute__(value, "__dict__")
        except (AttributeError, TypeError):
            return {}
        if not isinstance(value_dict, dict):
            return {}
        return value_dict

    def _fields(
        self,
        value: object,
        names: tuple[str, ...],
        *,
        stored_only: bool,
    ) -> None:
        """Append dynamic boundary fields without evaluating opaque properties."""
        stored_fields = self._stored_fields(value)
        for name in names:
            if name in stored_fields:
                field_value = stored_fields[name]
            elif stored_only:
                continue
            else:
                try:
                    field_value = getattr(value, name)
                except (AttributeError, TypeError, ValueError):
                    continue
            self._text("field")
            self._text(name)
            self._value(field_value)

    def _container_value(self, value: object) -> bool:
        """Append a mapping/set/sequence value; return False for objects."""
        if isinstance(value, Mapping):
            self._text("mapping")
            self._text(str(len(value)))
            for key, item in value.items():
                self._value(key)
                self._value(item)
            return True
        if isinstance(value, Set) and not isinstance(value, str | bytes | bytearray):
            self._text("set")
            self._text(str(len(value)))
            for item in sorted(value, key=repr):
                self._value(item)
            return True
        if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
            self._text("sequence")
            self._text(type(value).__qualname__)
            self._text(str(len(value)))
            for item in value:
                self._value(item)
            return True
        return False

    def _object_value(self, value: object) -> None:
        """Append one non-container object's typed boundary fields."""
        value_type = type(value)
        self._text(f"{value_type.__module__}.{value_type.__qualname__}")
        if _structured_codegen_node_8616(value):
            self._structured_node_count += 1
            fields = tuple(
                dict.fromkeys(
                    (*_structured_slot_names_8616(value), *self._public_field_names(value))
                )
            )
            self._fields(value, fields, stored_only=False)
            return

        public_fields = self._public_field_names(value)
        boundary_fields = tuple(
            dict.fromkeys((*_BOUNDARY_SEMANTIC_FIELDS_8616, *public_fields))
        )
        if boundary_fields:
            self._fields(value, boundary_fields, stored_only=True)
            return
        self._text("opaque")

    def _value(self, value: object) -> None:
        """Append one structured value without following known owner cycles."""
        if value is None or isinstance(value, bool | int | float | str | bytes):
            self._text(type(value).__qualname__)
            self._text(repr(value))
            return
        if isinstance(value, Enum):
            self._text("enum")
            self._text(f"{type(value).__module__}.{type(value).__qualname__}")
            self._value(value.value)
            return
        if self._reference(value):
            return
        if self._container_value(value):
            return
        self._object_value(value)

    def build(self, value: object) -> StructuredAstGeneration8616:
        """Return the completed structured-C generation for ``value``."""
        self._value(value)
        return StructuredAstGeneration8616(
            digest=self._digest.hexdigest(),
            structured_node_count=self._structured_node_count,
        )


def structured_ast_generation_8616(codegen: object) -> StructuredAstGeneration8616:
    """Build an in-process generation from the dynamic structured-C surface."""
    try:
        cfunc = cast(_CodegenSurface8616, codegen).cfunc
    except AttributeError:
        cfunc = None
    return _StructuredAstGenerationBuilder8616().build(cfunc)


__all__ = ["StructuredAstGeneration8616", "structured_ast_generation_8616"]

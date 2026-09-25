"""Layer: Rewrite/Postprocess cleanup.

Responsibility: collect reads of already-proven local storage from structured C.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ...decompiler_postprocess_utils import (
    _iter_c_node_children_8616,
    _structured_slot_names_8616,
)
from .local_liveness import local_liveness_key_8616

type LocalReadKey8616 = tuple[object, ...]


class AliasReadStorage8616(Protocol):
    """Existing alias identity consumed without reinterpreting storage."""

    identity: tuple[object, ...] | None


def _collect_variable_keys_8616(
    node: structured_c.CVariable,
    keys: set[LocalReadKey8616],
    allow_variable_read: bool,
    describe_alias_storage: Callable[[object], AliasReadStorage8616],
) -> None:
    """Record variable, unified, storage, and liveness keys for one read."""
    if not allow_variable_read or node.variable is None:
        return
    keys.add(("var", id(node.variable)))
    if node.unified_variable is not None:
        keys.add(("unified", id(node.unified_variable)))
    identity = describe_alias_storage(node).identity
    if identity is not None:
        keys.add(("storage", identity))
    liveness = local_liveness_key_8616(node)
    if liveness is not None:
        keys.add(("liveness", liveness))


def _collect_dirty_keys_8616(
    node: structured_c.CDirtyExpression,
    keys: set[LocalReadKey8616],
    allow_variable_read: bool,
) -> None:
    """Record dirty payload identity keys for one read."""
    dirty = node.dirty
    # Dynamic codegen boundary: dirty payload identity fields vary by angr version.
    varid = getattr(dirty, "varid", None)
    # Dynamic codegen boundary: dirty payloads may lack a display name.
    name = getattr(dirty, "name", None)
    if allow_variable_read:
        if isinstance(varid, int):
            keys.add(("dirty_varid", varid))
        if isinstance(name, str) and name:
            keys.add(("dirty_name", name))


def collect_local_read_keys_8616(
    node: object,
    keys: set[LocalReadKey8616],
    seen: set[int] | None = None,
    *,
    allow_variable_read: bool = True,
    structured_codegen_node: Callable[[object], bool],
    describe_alias_storage: Callable[[object], AliasReadStorage8616],
) -> None:
    """Collect value reads, including array operands and every loop component."""
    if not structured_codegen_node(node):
        return
    if seen is None:
        seen = set()
    marker = id(node)
    if marker in seen:
        return
    seen.add(marker)

    def collect(child: object, *, value_read: bool = True) -> None:
        """Keep the assignment destination/value distinction during recursion."""
        collect_local_read_keys_8616(
            child, keys, seen, allow_variable_read=value_read,
            structured_codegen_node=structured_codegen_node,
            describe_alias_storage=describe_alias_storage,
        )

    try:
        if isinstance(node, structured_c.CVariable):
            _collect_variable_keys_8616(
                node, keys, allow_variable_read, describe_alias_storage
            )
            return
        if isinstance(node, structured_c.CAssignment):
            collect(node.lhs, value_read=False)
            collect(node.rhs)
            return
        if isinstance(node, structured_c.CDirtyExpression):
            _collect_dirty_keys_8616(node, keys, allow_variable_read)
            return
        for attr in _structured_slot_names_8616(node):
            # Dynamic boundary: the shared inventory names version-dependent angr children.
            value = getattr(node, attr, None)
            for child in _iter_c_node_children_8616(value, set()):
                collect(child)
    finally:
        seen.remove(marker)

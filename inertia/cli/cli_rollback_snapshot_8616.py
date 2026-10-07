"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.

Responsibility: materialize rewrite-loop rollback snapshots of the codegen
cfunc as pickle bytes while retaining the snapshot-time boundary bindings
that ``snapshot_trusted_cfunc_8616`` bakes into a deepcopy.

Every acquire returns an independent serialized payload — nothing is reused
between passes, so no equality witness or staleness path exists. Preserved
boundary objects (codegen, project, arch) are externalized via
``persistent_id``/``persistent_load`` so they rebind by identity on load,
matching the memo contract of ``snapshot_trusted_cfunc_8616``. The recorded
``boundary_manager``/``boundary_type_store_kb`` reproduce the production
helper's copy-time ``set_manager``/``types._kb`` rebinding against the
snapshot-time bindings, so a pass that replaces the live cfunc cannot
redirect the restored graph to a different manager.
"""

from __future__ import annotations

import io
import pickle
import typing
from typing import Any

_PRESERVED_SNAPSHOT_TAG_8616 = "inertia-rollback-preserved"

_SERIALIZATION_ERRORS_8616 = (
    pickle.PickleError,
    AttributeError,
    TypeError,
    ValueError,
    IndexError,
    ImportError,
    EOFError,
    OverflowError,
    RecursionError,
)
"""Documented pickle-mechanics failures; unexpected reducer failures propagate."""


class PickledCfuncSnapshot8616(bytes):
    """Serialized cfunc payload retaining its snapshot-time boundary bindings.

    The byte payload stays opaque to callers; its binding fields reproduce what
    a deepcopy snapshot carries implicitly — the manager and type-store key
    that were live when the snapshot was taken.

    ``has_variable_manager``: the source cfunc exposed angr's
    ``variable_manager`` boundary at snapshot time.
    ``boundary_manager``: the ``VariableManager`` bound at snapshot time.
    ``boundary_type_store_kb``: the live ``types._kb`` at snapshot time.
    """

    has_variable_manager: bool
    boundary_manager: object
    boundary_type_store_kb: object

    def __new__(
        cls,
        payload: bytes,
        *,
        has_variable_manager: bool,
        boundary_manager: object,
        boundary_type_store_kb: object,
    ) -> PickledCfuncSnapshot8616:
        """Attach snapshot-time bindings to opaque payload bytes."""
        self = super().__new__(cls, payload)
        self.has_variable_manager = has_variable_manager
        self.boundary_manager = boundary_manager
        self.boundary_type_store_kb = boundary_type_store_kb
        return self


class _TrustedCfuncPickler8616(pickle.Pickler):
    """Serialize a cfunc while externalizing preserved boundary objects.

    ``persistent_id`` maps each preserved object (codegen, project, arch) to
    an index token so the same live object is rebound on load, matching the
    identity-sharing ``preserve_objects`` contract of
    ``snapshot_trusted_cfunc_8616``.
    """

    def __init__(self, buffer: io.BytesIO, preserved: tuple[object, ...]) -> None:
        """Record preserved objects by identity for ``persistent_id``."""
        super().__init__(buffer, protocol=pickle.HIGHEST_PROTOCOL)
        self._preserved_ids: dict[int, int] = {
            id(obj): idx for idx, obj in enumerate(preserved)
        }

    def persistent_id(self, obj: object) -> tuple[str, int] | None:
        """Externalize preserved boundary objects as index tokens."""
        idx = self._preserved_ids.get(id(obj))
        if idx is None:
            return None
        return (_PRESERVED_SNAPSHOT_TAG_8616, idx)


class _TrustedCfuncUnpickler8616(pickle.Unpickler):
    """Materialize a pickled cfunc, rebinding preserved boundary objects."""

    def __init__(self, buffer: io.BytesIO, preserved: tuple[object, ...]) -> None:
        """Record preserved objects resolved by ``persistent_load``."""
        super().__init__(buffer)
        self._preserved = preserved

    def persistent_load(self, pid: object) -> object:
        """Resolve a preserved-boundary token to the live preserved object."""
        if not isinstance(pid, tuple) or len(pid) != 2:
            raise pickle.UnpicklingError(f"malformed preserved snapshot token {pid!r}")
        kind, idx = typing.cast(tuple[object, object], pid)
        if (
            kind != _PRESERVED_SNAPSHOT_TAG_8616
            or not isinstance(idx, int)
            or idx >= len(self._preserved)
            or idx < 0
        ):
            raise pickle.UnpicklingError(f"unknown preserved snapshot token {pid!r}")
        return self._preserved[idx]


def pickled_trusted_cfunc_8616(
    cfunc: object,
    *,
    preserve_objects: tuple[object, ...],
) -> PickledCfuncSnapshot8616 | None:
    """Serialize the full copied state of one cfunc to opaque bytes.

    Captures exactly the state ``snapshot_trusted_cfunc_8616`` copies —
    every object reachable from the cfunc except preserved boundary objects —
    plus the same snapshot-time manager/type-store bindings that helper bakes
    into its deepcopy. The same live ``types._kb`` repair dance is kept
    because ``VariableManagerInternal.__getstate__`` clears it while
    serializing. ``None`` means the state could not be serialized; callers
    then keep the original object-level deepcopy path.
    """
    dynamic_cfunc = typing.cast(Any, cfunc)
    has_variable_manager = False
    manager: Any | None = None
    type_store: Any | None = None
    type_store_kb: Any | None = None
    try:
        boundary_manager = typing.cast(Any, dynamic_cfunc.variable_manager)
        boundary_type_store = typing.cast(Any, boundary_manager.types)
        manager = boundary_manager.manager
        type_store = boundary_type_store
        type_store_kb = boundary_type_store._kb
        has_variable_manager = True
    except AttributeError:
        # Synthetic fixtures may not expose angr's variable-manager boundary.
        pass

    buffer = io.BytesIO()
    try:
        _TrustedCfuncPickler8616(buffer, preserve_objects).dump(cfunc)
    except _SERIALIZATION_ERRORS_8616:
        # Third-party serialization boundary: any member may be unpicklable.
        return None
    finally:
        if type_store is not None:
            type_store._kb = type_store_kb
    return PickledCfuncSnapshot8616(
        buffer.getvalue(),
        has_variable_manager=has_variable_manager,
        boundary_manager=manager,
        boundary_type_store_kb=type_store_kb,
    )


def unpickle_trusted_cfunc_8616(
    snapshot: PickledCfuncSnapshot8616,
    *,
    preserve_objects: tuple[object, ...],
) -> object | None:
    """Materialize a pickled cfunc snapshot with its recorded bindings.

    Rebinds ``variable_manager`` exactly like ``snapshot_trusted_cfunc_8616``
    rebinds the deep-copied manager: against the bindings captured at
    snapshot time, never against the possibly replaced or rebound live
    cfunc. ``None`` means the payload was corrupt or the variable-manager
    boundary is absent on the materialized graph.
    """
    try:
        restored: object = _TrustedCfuncUnpickler8616(
            io.BytesIO(bytes(snapshot)), preserve_objects
        ).load()
    except _SERIALIZATION_ERRORS_8616:
        # A corrupted snapshot payload must refuse, never restore partial state.
        return None
    if snapshot.has_variable_manager:
        try:
            snapshot_manager = typing.cast(Any, restored).variable_manager
            if snapshot.boundary_manager is not None:
                snapshot_manager.set_manager(snapshot.boundary_manager)
            else:
                snapshot_manager.types._kb = snapshot.boundary_type_store_kb
        except AttributeError:
            return None
    return restored

"""Observe complete structured output at an owned pipeline publication boundary.

Layer: Pipeline governance.
Responsibility: snapshot actual third-party C-AST data and output-facing type
context without rendering C or deriving semantics. Generator and variable-manager
backreferences are execution context, not AST fields; manager-provided declaration
types are captured explicitly. Unsupported boundary data remains a typed non-result.
Owns runtime ordering, invariant checks, hard failures, and final emission gates
Do not recover semantic facts or perform IR, alias, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

import hashlib
import json
import struct
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import Enum, StrEnum
from typing import Protocol, cast

from angr import ailment
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.knowledge_plugins.functions.function import Function
from angr.rustylib.ailment import Tags
from angr.sim_type import SimType, SimTypeBottom, SimTypeFunction
from angr.sim_variable import SimVariable
from archinfo import Arch
from pyvex.arches import PyvexArch

from inertia.ir.core import IRValue
from inertia.ir.function_artifact import IRFunctionArtifact
from inertia.ir.function_readiness_contracts import function_artifact_body_digest_8616
from inertia.ir.raw_boot_blocked_prefix import _architecture_key_8616
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.carry_borrow_bit_contracts import CarryBorrowBitLoweringFact8616
from inertia.lowering.codegen_return_origin import ReturnValueOrigin8616
from inertia.lowering.stack_variable_binding import StackVariableBinding
from inertia.structuring.condition_chain_provenance import ConditionChainProvenance8616
from inertia.widening.segmented_load_identity import SegmentedLoadIdentity8616


class _NativeTagsBoundary8616(Protocol):
    """Declared mapping export of the opaque native tag container."""

    def to_dict(self) -> dict[str, object]:
        """Export native fields for the same strict recursive observation."""
        ...


class StructuredASTFailure8616(StrEnum):
    """Typed reason an actual structured output could not be observed."""

    ROOT_UNAVAILABLE = "root_unavailable"
    FIELD_UNAVAILABLE = "field_unavailable"
    FIELD_UNSUPPORTED = "field_unsupported"
    CYCLIC_AST = "cyclic_ast"
    MANAGER_UNAVAILABLE = "manager_unavailable"
    HANDOFF_OUTPUT_CHANGED = "handoff_output_changed"
    HANDOFF_GENERATOR_CHANGED = "handoff_generator_changed"
    ALREADY_HANDED_OFF = "already_handed_off"


class StructuredASTTypeSizing8616(StrEnum):
    """Observed width availability without inventing a type size."""

    OBSERVED = "observed"
    NON_OBJECT = "non_object"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class StructuredASTSnapshot8616:
    """Immutable observation of actual AST content, including declaration context."""

    function_addr: int
    payload_json: str
    digest: str
    node_visits: int

    def to_dict(self) -> dict[str, object]:
        """Expose deterministic data without retaining the mutable generator."""
        return {
            "function_addr": self.function_addr,
            "payload": json.loads(self.payload_json),
            "digest": self.digest,
            "node_visits": self.node_visits,
        }


@dataclass(frozen=True, slots=True)
class StructuredASTObservation8616:
    """Snapshot or an explicit unsupported boundary with its exact field path."""

    snapshot: StructuredASTSnapshot8616 | None
    failure: StructuredASTFailure8616 | None = None
    field_path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject contradictory or empty observation statuses at construction."""
        if (self.snapshot is None) == (self.failure is None):
            raise ValueError("AST observation requires exactly one snapshot or failure")

    @property
    def complete(self) -> bool:
        """Require a real snapshot rather than an empty success receipt."""
        return self.snapshot is not None and self.failure is None


class StructuredASTPublicationOwnership8616(StrEnum):
    """Whether a producer still owns live output or handed it to its consumer."""

    LIVE = "live"
    HANDED_TO_REWRITE = "handed_to_rewrite"


@dataclass(slots=True)
class StructuredASTPublication8616:
    """An immutable produced version with an explicit live-output handoff.

    The initial observation never changes. While the producer owns the AST,
    readiness must reobserve it. A successful handoff preserves the immutable
    consumed version while Rewrite edits its own output. A later Rewrite
    publication observes that new output independently.
    """

    codegen: object
    observation: StructuredASTObservation8616
    ownership: StructuredASTPublicationOwnership8616 = StructuredASTPublicationOwnership8616.LIVE

    def to_dict(self) -> dict[str, object]:
        """Expose version and ownership diagnostics without the live generator."""
        snapshot = self.observation.snapshot
        return {
            "function_addr": None if snapshot is None else snapshot.function_addr,
            "digest": None if snapshot is None else snapshot.digest,
            "node_visits": None if snapshot is None else snapshot.node_visits,
            "ownership": self.ownership.value,
            "failure": None if self.observation.failure is None else self.observation.failure.value,
            "field_path": list(self.observation.field_path),
        }

    def current_snapshot(self) -> StructuredASTSnapshot8616 | None:
        """Observe live producer data, or retain the explicitly consumed version."""
        if not self.observation.complete:
            return None
        if self.ownership is StructuredASTPublicationOwnership8616.HANDED_TO_REWRITE:
            return self.observation.snapshot
        return observe_structured_ast_output_8616(self.codegen).snapshot

    def handoff_to_rewrite(self, codegen: object) -> StructuredASTFailure8616 | None:
        """Release only the unchanged, representable AST to its actual consumer."""
        if self.ownership is not StructuredASTPublicationOwnership8616.LIVE:
            return StructuredASTFailure8616.ALREADY_HANDED_OFF
        if codegen is not self.codegen:
            return StructuredASTFailure8616.HANDOFF_GENERATOR_CHANGED
        if not self.observation.complete:
            assert self.observation.failure is not None
            return self.observation.failure
        current = observe_structured_ast_output_8616(codegen)
        if not current.complete:
            assert current.failure is not None
            return current.failure
        if current.snapshot != self.observation.snapshot:
            return StructuredASTFailure8616.HANDOFF_OUTPUT_CHANGED
        self.ownership = StructuredASTPublicationOwnership8616.HANDED_TO_REWRITE
        return None


def publish_structured_ast_output_8616(codegen: object) -> StructuredASTPublication8616:
    """Capture a producer output version; unavailable data remains a non-result."""
    return StructuredASTPublication8616(codegen, observe_structured_ast_output_8616(codegen))


class _TypeStore8616(Protocol):
    """Output-facing third-party manager type inventory."""

    def iter_own(self) -> Iterable[SimType]:
        """Return locally declared types used by the C emitter."""
        ...


class _VariableManager8616(Protocol):
    """Declaration type queries the real function emitter consumes."""

    types: _TypeStore8616

    def get_variable_type(self, variable: SimVariable) -> SimType | None:
        """Return an observed declaration type without inventing a default."""
        ...


class _Codegen8616(Protocol):
    """Dynamic native generator root boundary."""

    cfunc: object


class _SnapshotBoundaryError8616(Exception):
    """Carry an unsupported data boundary without swallowing implementation errors."""

    def __init__(self, failure: StructuredASTFailure8616, path: tuple[str, ...]) -> None:
        super().__init__(failure.value)
        self.failure: StructuredASTFailure8616 = failure
        self.path: tuple[str, ...] = path


def _qualified_kind_8616(value: object) -> str:
    """Name a nominal boundary type as data, never as semantic proof."""
    kind = type(value)
    return f"{kind.__module__}.{kind.__qualname__}"


def _boundary_fields_8616(value: object, path: tuple[str, ...]) -> dict[str, object]:
    """Read declared slots and dynamic fields at the third-party data boundary."""
    try:
        result: dict[str, object] = dict(vars(value))
    except TypeError:
        result = {}
    for base in type(value).__mro__:
        declared = base.__dict__.get("__slots__", ())
        slots = (declared,) if isinstance(declared, str) else declared
        for name in slots:
            if name in {"__dict__", "__weakref__"}:
                continue
            try:
                # Computed access is confined to declared third-party slots.
                result[name] = getattr(value, name)
            except AttributeError as error:
                raise _SnapshotBoundaryError8616(
                    StructuredASTFailure8616.FIELD_UNAVAILABLE, (*path, name),
                ) from error
    return result


def _type_sizing_8616(value: SimType) -> dict[str, object]:
    """Observe concrete widths, retaining non-object and unavailable type states."""
    if isinstance(value, (SimTypeBottom, SimTypeFunction)):
        return {"status": StructuredASTTypeSizing8616.NON_OBJECT}
    try:
        return {"status": StructuredASTTypeSizing8616.OBSERVED, "bits": value.size, "alignment": value.alignment}
    except (ValueError, NotImplementedError) as error:
        return {"status": StructuredASTTypeSizing8616.UNAVAILABLE, "cause": type(error).__name__}


@dataclass(slots=True)
class _StructuredASTEncoder8616:
    """Observe AST values; identities only detect recursion during this observation."""

    active: dict[int, int] = field(default_factory=dict)
    node_visits: int = 0

    def encode(self, value: object, path: tuple[str, ...]) -> object:
        """Encode actual values and explicit recursive type references."""
        if isinstance(value, Enum):
            return {"enum": _qualified_kind_8616(value), "name": value.name, "value": self.encode(value.value, path)}
        if value is None or isinstance(value, (bool, int, str)):
            return value
        if isinstance(value, float):
            return {"float64_bits": struct.pack(">d", value).hex()}
        if isinstance(value, bytes):
            return {"bytes": value.hex()}
        marker = id(value)
        if marker in self.active:
            if isinstance(value, SimType):
                return {"recursive_type": _qualified_kind_8616(value), "ancestor_distance": len(self.active) - self.active[marker]}
            raise _SnapshotBoundaryError8616(StructuredASTFailure8616.CYCLIC_AST, path)
        self.active[marker] = len(self.active)
        try:
            return self._compound(value, path)
        finally:
            self.active.pop(marker)

    def _compound(self, value: object, path: tuple[str, ...]) -> object:
        """Dispatch declared boundary interfaces without guessing unknown objects."""
        if isinstance(value, (tuple, list)):
            return [self.encode(item, (*path, str(index))) for index, item in enumerate(value)]
        if isinstance(value, Tags):
            return self.encode(cast(_NativeTagsBoundary8616, value).to_dict(), path)
        if isinstance(value, dict):
            return {"mapping": [[self.encode(key, (*path, "key")), self.encode(item, (*path, "value"))] for key, item in value.items()]}
        if isinstance(value, (set, frozenset)):
            items = [self.encode(item, (*path, "item")) for item in value]
            return {"set": sorted(items, key=lambda item: json.dumps(item, sort_keys=True))}
        if isinstance(value, structured_c.CConstruct):
            return self._node(value, path)
        if isinstance(value, ailment.Expr.VirtualVariable):
            return self._virtual_variable(value, path)
        if isinstance(value, SimType):
            return self._type(value, path)
        if isinstance(value, SimVariable):
            return self._variable(value, path)
        return self._leaf(value, path)

    def _virtual_variable(
        self, value: ailment.Expr.VirtualVariable, path: tuple[str, ...],
    ) -> object:
        """Retain every native variable field, including otherwise lossy tags.

        Native AIL variables can survive in CDirtyExpression nodes. The Rust
        wrapper exposes neither slots nor a dictionary; its byte serialization
        can replace unsupported tag objects with null. Observe the declared
        variable fields explicitly and send tags through the strict walker.
        Other unsupported AIL expression kinds remain explicit refusals.
        """
        self.node_visits += 1
        fields: dict[str, object] = {
            "idx": value.idx,
            "varid": value.varid,
            "bits": value.bits,
            "category": value.category.value,
            "oident": value.oident,
            "tags": value.tags,
        }
        return {"ail_virtual_variable": {
            name: self.encode(item, (*path, name)) for name, item in fields.items()
        }}

    def _leaf(self, value: object, path: tuple[str, ...]) -> object:
        """Capture authoritative IR and architecture leaves or refuse a foreign field."""
        if isinstance(value, PyvexArch):
            return {"vex_architecture": self.encode(_boundary_fields_8616(value, path), path)}
        if isinstance(value, type) and issubclass(value, Arch):
            return {"architecture_class": f"{value.__module__}.{value.__qualname__}"}
        if isinstance(value, Arch):
            key = self.encode(_architecture_key_8616(value), path)
            encoded = json.dumps(key, sort_keys=True, allow_nan=False)
            return {"architecture_digest": hashlib.sha256(encoded.encode("utf-8")).hexdigest()}
        owned_fact = self._owned_fact(value, path)
        if owned_fact is not None:
            return owned_fact
        if isinstance(value, IRValue):
            return {"ir_value": value.to_dict()}
        if isinstance(value, (IRFunctionArtifact, SSAFunctionArtifact)):
            digest = function_artifact_body_digest_8616(value)
            if digest is not None:
                return {"ir_body": _qualified_kind_8616(value), "digest": digest}
        if isinstance(value, Function):
            return {"function": value.addr, "name": value.name, "demangled_name": value.demangled_name, "prototype": self.encode(value.prototype, (*path, "prototype"))}
        raise _SnapshotBoundaryError8616(StructuredASTFailure8616.FIELD_UNSUPPORTED, path)

    def _owned_fact(self, value: object, path: tuple[str, ...]) -> dict[str, object] | None:
        """Project declared semantic facts without dropping any owned identity field."""
        # Runtime import keeps native materialization independent of snapshot
        # initialization while admitting only this explicit owned contract.
        from inertia.lowering.call_stack_input_contracts import CallStackInputBinding8616
        from inertia.lowering.condition_stack_projection_contracts import (
            ConditionStackProjectionFact8616,
        )
        from inertia.lowering.entry_stack_pointer_capture import (
            EntryStackPointerCapture8616,
            ScopedCallPositionAuthority8616,
        )

        if type(value) is ScopedCallPositionAuthority8616:
            result = value.result
            diagnostic = {
                "position": asdict(value.position) if value.position is not None else None,
                "caller_scope": result.caller_scope.to_dict() if result.caller_scope is not None else None,
                "callee_scope": result.callee_scope.to_dict() if result.callee_scope is not None else None,
            }
            return {"scoped_call_position": self.encode(diagnostic, path)}
        if isinstance(value, CallStackInputBinding8616) and type(value) is CallStackInputBinding8616:
            return {"call_stack_input_binding": self.encode(asdict(value), path)}
        if isinstance(value, EntryStackPointerCapture8616) and type(value) is EntryStackPointerCapture8616:
            return {"entry_sp_capture": self.encode(asdict(value), path)}
        if type(value) is ConditionChainProvenance8616:
            return {"condition_chain_provenance": {
                "jcc_addrs": self.encode(value.jcc_addrs, (*path, "jcc_addrs")),
            }}
        if type(value) is StackVariableBinding:
            return {"stack_binding": self.encode(value.to_dict(), path)}
        if isinstance(value, ReturnValueOrigin8616):
            return {"return_origin": {
                "instruction_addr": value.instruction_addr,
                "block_addr": value.block_addr,
                "width_bits": value.width_bits,
                "return_instruction_addr": value.return_instruction_addr,
                "return_block_addr": value.return_block_addr,
            }}
        if type(value) is SegmentedLoadIdentity8616:
            return {"segmented_load_identity": {
                "space": self.encode(value.space, (*path, "space")),
                "offset": value.offset,
                "width": value.width,
                "region": value.region,
            }}
        if type(value) is CarryBorrowBitLoweringFact8616:
            return {"carry_borrow_bit_lowering": {
                "function_addr": value.function_addr,
                "kind": self.encode(value.kind, (*path, "kind")),
                "low_block_addr": value.low_block_addr,
                "low_ins_addr": value.low_ins_addr,
                "high_block_addr": value.high_block_addr,
                "high_ins_addr": value.high_ins_addr,
            }}
        if type(value) is ConditionStackProjectionFact8616:
            return {"condition_stack_projection": self.encode(asdict(value), path)}
        return None

    def _node(self, value: structured_c.CConstruct, path: tuple[str, ...]) -> object:
        """Capture every node data field and explicitly project execution context."""
        self.node_visits += 1
        fields = _boundary_fields_8616(value, path)
        fields.pop("codegen", None)  # CConstruct's generator backreference, not output data.
        if isinstance(value, structured_c.CFunction):
            fields.pop("variable_manager", None)
            fields["declaration_context"] = self._declarations(value, path)
        return {"node": _qualified_kind_8616(value), "fields": {name: self.encode(item, (*path, name)) for name, item in sorted(fields.items())}}

    def _type(self, value: SimType, path: tuple[str, ...]) -> object:
        """Capture type fields, architecture basis and derived object widths."""
        sizing = _type_sizing_8616(value)
        fields = _boundary_fields_8616(value, path)
        fields["observed_sizing"] = sizing
        return {"type": _qualified_kind_8616(value), "fields": {name: self.encode(item, (*path, name)) for name, item in sorted(fields.items())}}

    def _variable(self, value: SimVariable, path: tuple[str, ...]) -> object:
        """Capture storage identities and names without Python hash memo state."""
        fields = _boundary_fields_8616(value, path)
        fields.pop("_hash", None)  # Derived Python hash cache is not variable data.
        return {"variable": _qualified_kind_8616(value), "fields": {name: self.encode(item, (*path, name)) for name, item in sorted(fields.items())}}

    def _declarations(self, root: structured_c.CFunction, path: tuple[str, ...]) -> object:
        """Capture manager data actually consumed when emitting local declarations."""
        variables = tuple(dict.fromkeys((*root.variables_in_use, *root.unified_local_vars)))
        if root.variable_manager is None:
            raise _SnapshotBoundaryError8616(StructuredASTFailure8616.MANAGER_UNAVAILABLE, path)
        manager = cast(_VariableManager8616, root.variable_manager)
        return {
            "variable_types": [(variable, manager.get_variable_type(variable)) for variable in variables],
            "local_types": tuple(manager.types.iter_own()),
        }


def observe_structured_ast_output_8616(codegen: object) -> StructuredASTObservation8616:
    """Observe a real completed function AST without using rendered C as evidence."""
    try:
        root = cast(_Codegen8616, codegen).cfunc
    except AttributeError:
        return StructuredASTObservation8616(None, StructuredASTFailure8616.ROOT_UNAVAILABLE)
    if not isinstance(root, structured_c.CFunction):
        return StructuredASTObservation8616(None, StructuredASTFailure8616.ROOT_UNAVAILABLE)
    encoder = _StructuredASTEncoder8616()
    try:
        payload = encoder.encode(root, ("cfunc",))
        encoded = json.dumps(payload, sort_keys=True, allow_nan=False)
    except _SnapshotBoundaryError8616 as error:
        return StructuredASTObservation8616(None, error.failure, error.path)
    snapshot = StructuredASTSnapshot8616(
        root.addr, encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest(), encoder.node_visits,
    )
    return StructuredASTObservation8616(snapshot)

"""Deterministic typed identity for CGoto targets in tail validation.

Layer: Tail Validation.

Responsibility: own the one authoritative structural identity of a CGoto
node's target.  Both validation projections consume it: the ``goto:``
control-flow effect token and the boundary fingerprint tuple.  Independently
regenerated targets compare equal exactly when their structured meaning is
equal; an object repr can never again inject heap addresses into validation.

The identity is a nested tuple over ``str``/``int``/``None`` leaves so it is
hashable, equality-comparable, and JSON-serializable for boundary
descriptors.  It keeps the exact AST operators, operand identities, widths,
signedness, and cast nodes that determine the computed target.  No algebraic
recovery, constant folding, or name-derived target addresses are applied.

Unsupported, cyclic, or depth/budget-exhausted subtrees fail closed into a
deterministic ``("opaque", tag, class_name)`` marker plus a typed
:class:`GotoTargetIdentityReason8616` recorded on the verdict.  The marker is
deliberately free of object ids, nonces, and per-process addresses: an
incomplete verdict can never certify equality — identical unknowns render
identically and consumers must refuse rather than infer difference from a
nonce.  A regenerated unknown therefore cannot alias a supported identity or
another function's cached result, and Python object-id reuse after node
release can never collide two distinct unknown targets into false equality.

Forbidden: semantic recovery from source, COD, assembly, or rendered C text.
Dynamic boundary: attributes are read through getattr on third-party angr
structured-C nodes, SimType objects, SimVariable objects, and ailment
VirtualVariable objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIndexedVariable,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
)
from angr.sim_type import (
    SimType,
    SimTypeArray,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypePointer,
)
from angr.sim_variable import (
    SimMemoryVariable,
    SimRegisterVariable,
    SimStackVariable,
    SimTemporaryVariable,
)

__all__ = [
    "GotoTargetIdentity8616",
    "GotoTargetIdentityReason8616",
    "goto_target_boundary_identity_8616",
    "goto_target_effect_token_8616",
    "goto_target_identity_8616",
]

# Recursive JSON-shaped identity value: nested tuples over scalar leaves.
type _GotoTargetIdentity8616 = tuple["_GotoTargetIdentity8616", ...] | str | int | None

#: Structural traversal limits; goto targets are small address expressions.
_GOTO_TARGET_MAX_DEPTH_8616: int = 64
_GOTO_TARGET_MAX_NODES_8616: int = 512
_GOTO_TYPE_MAX_DEPTH_8616: int = 8

_ID_NONE_8616: tuple[str] = ("none",)
_ID_MISSING_8616: tuple[str, str] = ("ty", "missing")


class GotoTargetIdentityReason8616(StrEnum):
    """Typed reason a CGoto target identity subtree stays unproven."""

    UNSUPPORTED_NODE = "unsupported"
    CYCLIC_TARGET = "cycle"
    BOUND_EXCEEDED = "bounded"
    MISSING_TARGET = "missing"
    UNSUPPORTED_SCALAR = "scalar"
    UNSUPPORTED_OPERATOR = "operator"
    UNSUPPORTED_VARIABLE = "variable"
    UNSUPPORTED_TYPE = "type"


@dataclass(frozen=True, slots=True)
class GotoTargetIdentity8616:
    """Typed identity verdict for one CGoto target.

    ``structural`` is the deterministic ``("goto", target, target_idx)``
    payload shared by the boundary fingerprint and the ``goto:`` effect
    token.  ``reasons`` records every unproven subtree in sorted order; an
    empty tuple means the identity is complete and may certify equality.

    An incomplete verdict carries no per-instance payload on purpose: equal
    markers never prove equal targets, so consumers must check
    :attr:`complete` (or :meth:`proves_equal`) instead of relying on token
    inequality.
    """

    structural: tuple[_GotoTargetIdentity8616, ...]
    reasons: tuple[GotoTargetIdentityReason8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether every subtree resolved to supported identity."""
        return not self.reasons

    @property
    def token(self) -> str:
        """Return the deterministic ``goto:`` effect-token rendering."""
        _, target_identity, idx_identity = self.structural
        token = f"goto:{_render_goto_identity_8616(target_identity)}"
        if idx_identity != _ID_NONE_8616:
            token += f":idx={_render_goto_identity_8616(idx_identity)}"
        return token

    def proves_equal(self, other: object) -> bool:
        """Return True only when both complete identities are equal.

        Incomplete verdicts never prove equality: an unproven target cannot
        certify that a before/after pair or a regenerated tree is the same
        computed goto, regardless of how similar the rendered markers look.
        """
        return (
            isinstance(other, GotoTargetIdentity8616)
            and self.complete
            and other.complete
            and self.structural == other.structural
        )


@dataclass(slots=True)
class _GotoTargetIdentityRun8616:
    """Bounded traversal state for one goto-target identity computation."""

    active_ids: set[int] = field(default_factory=set)
    reasons: set[GotoTargetIdentityReason8616] = field(default_factory=set)
    budget: int = _GOTO_TARGET_MAX_NODES_8616


def goto_target_identity_8616(node: object) -> GotoTargetIdentity8616:
    """Compute the typed identity verdict for one CGoto node.

    ``node`` is a CGoto at the dynamic angr boundary.  The verdict replaces
    raw target objects inside boundary fingerprint tuples and supplies the
    ``goto:`` effect token so independently regenerated trees compare equal
    only when structurally equal and never when unproven.
    """
    run = _GotoTargetIdentityRun8616()
    target = _goto_target_attr_8616(node, "target")
    target_idx = _goto_target_attr_8616(node, "target_idx")
    if target is None:
        # A CGoto without a target carries no provable destination.  Unlike a
        # legitimately absent ``target_idx`` or a nested ``None`` operand,
        # the top-level target is the identity itself, so its absence is
        # incomplete evidence rather than a known empty value.
        run.reasons.add(GotoTargetIdentityReason8616.MISSING_TARGET)
    structural = (
        "goto",
        _goto_target_value_identity_8616(target, run, 0),
        _goto_scalar_or_opaque_8616(target_idx, "idx", run),
    )
    reasons = tuple(sorted(run.reasons, key=lambda reason: reason.value))
    return GotoTargetIdentity8616(structural=structural, reasons=reasons)


def goto_target_boundary_identity_8616(node: object) -> tuple[_GotoTargetIdentity8616, ...]:
    """Return the shared ``("goto", target, target_idx)`` structured identity.

    The result replaces raw target objects inside boundary fingerprint tuples
    so independently regenerated trees hash to equal descriptors only when
    structurally equal.  Unproven targets embed a deterministic
    ``("opaque", tag, class)`` marker; callers that gate on boundary equality
    must also consult the typed verdict's ``reasons`` — equal markers never
    certify equal targets.
    """
    return goto_target_identity_8616(node).structural


def goto_target_effect_token_8616(node: object) -> str:
    """Return the ``goto:`` control-flow effect token for one CGoto node.

    Scalar ``int`` targets with no ``target_idx`` render exactly like the
    legacy token (``goto:<int>``) so the switch-loop tail-break delta
    consumer keeps its ``goto:<address>`` contract.  ``target_idx`` is
    appended whenever it is present so indexed goto identities stay distinct.
    """
    return goto_target_identity_8616(node).token


def _goto_target_attr_8616(node: object, attr: str) -> object:
    """Read one CGoto attribute across the dynamic angr boundary."""
    return getattr(node, attr, None)


def _goto_scalar_identity_8616(value: object) -> _GotoTargetIdentity8616 | None:
    """Map an exact scalar leaf type to its identity, or None otherwise."""
    if value is None:
        return _ID_NONE_8616
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("int", value)
    if type(value) is str:
        return ("str", value)
    if type(value) is float:
        return ("float", repr(value))
    return None


def _goto_scalar_or_opaque_8616(
    value: object, kind: str, run: _GotoTargetIdentityRun8616
) -> _GotoTargetIdentity8616:
    """Return a scalar identity or a deterministic opaque marker."""
    scalar = _goto_scalar_identity_8616(value)
    if scalar is not None:
        return scalar
    return _goto_opaque_identity_8616(
        kind, value, run, GotoTargetIdentityReason8616.UNSUPPORTED_SCALAR
    )


def _goto_opaque_identity_8616(
    tag: str,
    node: object,
    run: _GotoTargetIdentityRun8616,
    reason: GotoTargetIdentityReason8616,
) -> _GotoTargetIdentity8616:
    """Fail closed with a deterministic marker plus a typed refusal reason.

    The marker is deliberately process-stable and per-instance-free: unknown
    identity is never proven by differing ids or nonces, and equal markers
    only ever feed a refusal verdict, never an equality certificate.
    """
    run.reasons.add(reason)
    return ("opaque", tag, type(node).__name__)


def _goto_target_value_identity_8616(
    value: object, run: _GotoTargetIdentityRun8616, depth: int
) -> _GotoTargetIdentity8616:
    """Identity for a scalar label or a supported structured-C subtree."""
    scalar = _goto_scalar_identity_8616(value)
    if scalar is not None:
        return scalar
    return _goto_expr_identity_8616(value, run, depth)


def _goto_expr_identity_8616(
    node: object, run: _GotoTargetIdentityRun8616, depth: int
) -> _GotoTargetIdentity8616:
    """Bounded, cycle-checked dispatch over supported expression classes."""
    if depth > _GOTO_TARGET_MAX_DEPTH_8616 or run.budget <= 0:
        return _goto_opaque_identity_8616(
            "bounded", node, run, GotoTargetIdentityReason8616.BOUND_EXCEEDED
        )
    run.budget -= 1
    node_id = id(node)
    if node_id in run.active_ids:
        return _goto_opaque_identity_8616(
            "cycle", node, run, GotoTargetIdentityReason8616.CYCLIC_TARGET
        )
    run.active_ids.add(node_id)
    try:
        return _goto_expr_dispatch_8616(node, run, depth)
    finally:
        run.active_ids.discard(node_id)


def _goto_expr_type_identity_8616(node: object, run: _GotoTargetIdentityRun8616) -> _GotoTargetIdentity8616:
    """Read the node's own ``type`` attribute, tolerating absent metadata."""
    return _goto_type_identity_8616(_goto_target_attr_8616(node, "type"), 0, run)


def _goto_expr_dispatch_8616(
    node: object, run: _GotoTargetIdentityRun8616, depth: int
) -> _GotoTargetIdentity8616:
    """Encode one supported expression node or fail closed to opaque."""
    if isinstance(node, CConstant):
        return (
            "const",
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(node, "value"), "const", run),
            _goto_expr_type_identity_8616(node, run),
        )
    if isinstance(node, CVariable):
        variable = _goto_target_attr_8616(node, "unified_variable") or _goto_target_attr_8616(
            node, "variable"
        )
        return (
            "var",
            _goto_variable_identity_8616(variable, run),
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(node, "vvar_id"), "vvar", run),
            _goto_type_identity_8616(_goto_target_attr_8616(node, "variable_type"), 0, run),
        )
    if isinstance(node, CIndexedVariable):
        return (
            "idxv",
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "variable"), run, depth + 1),
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "index"), run, depth + 1),
            _goto_expr_type_identity_8616(node, run),
        )
    if isinstance(node, CVariableField):
        field_obj = _goto_target_attr_8616(node, "field")
        return (
            "vfield",
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "variable"), run, depth + 1),
            (
                "field",
                _goto_scalar_or_opaque_8616(_goto_target_attr_8616(field_obj, "field"), "field", run),
                _goto_scalar_or_opaque_8616(_goto_target_attr_8616(field_obj, "offset"), "field", run),
            ),
            bool(_goto_target_attr_8616(node, "var_is_ptr")),
            _goto_expr_type_identity_8616(node, run),
        )
    if isinstance(node, CUnaryOp):
        return (
            f"uop:{_goto_op_token_8616(_goto_target_attr_8616(node, 'op'), run)}",
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "operand"), run, depth + 1),
            _goto_expr_type_identity_8616(node, run),
        )
    if isinstance(node, CBinaryOp):
        return (
            f"bop:{_goto_op_token_8616(_goto_target_attr_8616(node, 'op'), run)}",
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "lhs"), run, depth + 1),
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "rhs"), run, depth + 1),
            _goto_expr_type_identity_8616(node, run),
        )
    if isinstance(node, CTypeCast):
        return (
            f"cast:{type(node).__name__}",
            _goto_type_identity_8616(_goto_target_attr_8616(node, "src_type"), 0, run),
            _goto_type_identity_8616(_goto_target_attr_8616(node, "dst_type"), 0, run),
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "expr"), run, depth + 1),
        )
    if isinstance(node, CITE):
        return (
            "ite",
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "cond"), run, depth + 1),
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "iftrue"), run, depth + 1),
            _goto_target_value_identity_8616(_goto_target_attr_8616(node, "iffalse"), run, depth + 1),
            _goto_expr_type_identity_8616(node, run),
        )
    if isinstance(node, CFunctionCall):
        callee_func = _goto_target_attr_8616(node, "callee_func")
        func_addr = _goto_target_attr_8616(callee_func, "addr")
        func_name = _goto_target_attr_8616(callee_func, "name")
        call_args = _goto_target_attr_8616(node, "args")
        return (
            "call",
            _goto_target_value_identity_8616(
                _goto_target_attr_8616(node, "callee_target"), run, depth + 1
            ),
            _goto_scalar_or_opaque_8616(
                func_addr if type(func_addr) is int else func_name,
                "func",
                run,
            ),
            tuple(
                _goto_target_value_identity_8616(arg, run, depth + 1)
                for arg in call_args
            )
            if isinstance(call_args, (tuple, list))
            else _ID_NONE_8616,
            _goto_expr_type_identity_8616(node, run),
        )
    return _goto_opaque_identity_8616(
        "unsupported", node, run, GotoTargetIdentityReason8616.UNSUPPORTED_NODE
    )


def _goto_op_token_8616(op: object, run: _GotoTargetIdentityRun8616) -> str:
    """Return the operator name for a supported op, or an opaque marker."""
    if type(op) is str:
        return op
    run.reasons.add(GotoTargetIdentityReason8616.UNSUPPORTED_OPERATOR)
    return f"unsupported:{type(op).__name__}"


def _goto_variable_identity_8616(
    variable: object, run: _GotoTargetIdentityRun8616
) -> _GotoTargetIdentity8616:
    """Storage identity for a CVariable's effective SimVariable."""
    if isinstance(variable, SimRegisterVariable):
        return (
            "reg",
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "reg"), "reg", run),
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "size"), "size", run),
            _goto_region_identity_8616(variable, run),
        )
    if isinstance(variable, SimStackVariable):
        return (
            "stack",
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "base"), "base", run),
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "offset"), "offset", run),
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "size"), "size", run),
            _goto_region_identity_8616(variable, run),
        )
    if isinstance(variable, SimMemoryVariable):
        return (
            "mem",
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "addr"), "addr", run),
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "size"), "size", run),
            _goto_region_identity_8616(variable, run),
        )
    if isinstance(variable, SimTemporaryVariable):
        return (
            "tmp",
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "tmp_id"), "tmp", run),
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "size"), "size", run),
        )
    var_id = _goto_target_attr_8616(variable, "varid")
    if isinstance(var_id, int) and not isinstance(var_id, bool):
        category = _goto_target_attr_8616(variable, "category")
        category_name = _goto_target_attr_8616(category, "name")
        return (
            "vvar",
            ("int", var_id),
            _goto_scalar_or_opaque_8616(category_name, "category", run),
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(variable, "oident"), "oident", run),
        )
    if variable is None:
        return _ID_NONE_8616
    return _goto_opaque_identity_8616(
        "variable", variable, run, GotoTargetIdentityReason8616.UNSUPPORTED_VARIABLE
    )


def _goto_region_identity_8616(
    variable: object, run: _GotoTargetIdentityRun8616
) -> _GotoTargetIdentity8616:
    """Region coordinate anchoring a variable to its function context."""
    return _goto_scalar_or_opaque_8616(
        _goto_target_attr_8616(variable, "region"), "region", run
    )


def _goto_type_identity_8616(
    type_: object, depth: int, run: _GotoTargetIdentityRun8616
) -> _GotoTargetIdentity8616:
    """Type identity keeping class, width, signedness, and nested targets."""
    if type_ is None:
        return _ID_MISSING_8616
    if depth > _GOTO_TYPE_MAX_DEPTH_8616:
        return _goto_opaque_identity_8616(
            "type", type_, run, GotoTargetIdentityReason8616.BOUND_EXCEEDED
        )
    if not isinstance(type_, SimType):
        return _goto_opaque_identity_8616(
            "type", type_, run, GotoTargetIdentityReason8616.UNSUPPORTED_TYPE
        )
    bits = _goto_simtype_bits_8616(type_)
    signed = _goto_target_attr_8616(type_, "signed")
    fields: list[_GotoTargetIdentity8616] = [
        type(type_).__name__,
        bits if isinstance(bits, int) else None,
        signed if isinstance(signed, bool) else None,
    ]
    if isinstance(type_, SimTypePointer):
        fields.append(
            _goto_type_identity_8616(_goto_target_attr_8616(type_, "pts_to"), depth + 1, run)
        )
    elif isinstance(type_, (SimTypeArray, SimTypeFixedSizeArray)):
        fields.append(
            _goto_scalar_or_opaque_8616(_goto_target_attr_8616(type_, "length"), "length", run)
        )
        fields.append(
            _goto_type_identity_8616(_goto_target_attr_8616(type_, "elem_type"), depth + 1, run)
        )
    elif isinstance(type_, SimTypeFunction):
        fields.append(
            _goto_type_identity_8616(_goto_target_attr_8616(type_, "returnty"), depth + 1, run)
        )
        arg_types = _goto_target_attr_8616(type_, "args")
        fields.append(
            tuple(
                _goto_type_identity_8616(arg, depth + 1, run)
                for arg in arg_types
            )
            if isinstance(arg_types, (tuple, list))
            else _ID_NONE_8616
        )
    else:
        name = _goto_target_attr_8616(type_, "name")
        if isinstance(name, str) and name:
            fields.append(("name", name))
    return tuple(fields)


def _goto_simtype_bits_8616(type_: SimType) -> int | None:
    """Best-effort bit width; SimTypeBottom and friends honestly report none."""
    try:
        bits = type_.size
    except (AttributeError, TypeError, ValueError):
        return None
    return bits if isinstance(bits, int) and bits > 0 else None


_SAFE_TOKEN_CHARS_8616 = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.$:-")


def _render_scalar_token_8616(value: str) -> str:
    """Render a leaf string bare when simple, else repr for disambiguation."""
    if value and all(ch in _SAFE_TOKEN_CHARS_8616 for ch in value):
        return value
    return repr(value)


def _render_goto_identity_leaf_8616(identity: object) -> str:
    """Render a scalar identity leaf."""
    if identity is None:
        return "none"
    if isinstance(identity, str):
        return _render_scalar_token_8616(identity)
    return str(identity)


def _render_goto_identity_8616(identity: _GotoTargetIdentity8616) -> str:
    """Render a structured identity as a deterministic token."""
    if not isinstance(identity, tuple):
        return _render_goto_identity_leaf_8616(identity)
    if not identity:
        return "empty"
    tag, args = identity[0], identity[1:]
    if tag == "opaque":
        return f"opaque:{':'.join(_render_goto_identity_8616(arg) for arg in args)}"
    if tag == "none":
        return "none"
    if tag in {"int", "bool", "float"}:
        return str(args[0])
    if tag == "str":
        return repr(args[0])
    return (
        f"{_render_scalar_token_8616(str(tag))}"
        f"({','.join(_render_goto_identity_8616(arg) for arg in args)})"
    )

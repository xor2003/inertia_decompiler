"""Validate structured-codegen def-use facts without repairing output.

Layer: Tail validation.
Responsibility: report whether materialized C AST reads have a proven prior
definition on every structured control-flow path.
Forbidden: semantic recovery, source/COD/assembly/rendered-C inspection, or AST
mutation. Missing proof is a validation failure and remains owned by the
earlier IR, alias, lowering, or structuring layer that lost it.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Protocol

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDirtyExpression,
    CDoWhileLoop,
    CExpressionStatement,
    CFakeVariable,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CReturn,
    CStatements,
    CSwitchCase,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimType, SimTypeArray, SimTypeFixedSizeArray
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from .c_ast_utils import (
    _iter_c_node_children_8616,
    _structured_codegen_node_8616,
    _structured_slot_names_8616,
)
from .lowering.physical_registers import physical_register_view_8616
from .lowering.semantic_cast import CSemanticCast8616
from .semantics.expression_analysis import (
    VirtualValueIdentityKind8616,
    describe_virtual_value_identity_8616,
)
from .structuring.indexed_stack_ranges import IndexedStackReadProof8616
from .validation.status_flag_preservation import PackedStatusFlagPreservationEvidence8616
from .validation_indexed_bytes import indexed_scalar_byte_view_8616
from .validation_predicates import PredicateToken8616, invert_predicate_token_8616
from .validation_stack_projection import validated_stack_projection_fact_8616

__all__ = [
    "DefUseCallOutputDefinition8616",
    "DefUseEntryStackRange8616",
    "DefUseIssue8616",
    "DefUseStorageKey8616",
    "DefUseStorageKind8616",
    "DefUseValidationReport8616",
    "StackVariableOffsetResolver8616",
    "validate_structured_def_use_8616",
]


# The node is an angr structured-codegen object.  Keep this dynamic only at
# the third-party AST boundary; mypyc cannot import a dataclass field typed as
# the builtin ``object`` in this package.
type OpaqueValidationNode8616 = Any


class StackVariableOffsetResolver8616(Protocol):
    """Resolve one angr stack variable to its proven machine-BP offset."""

    def __call__(self, variable: SimStackVariable, /) -> int | None:
        """Return the machine-BP offset, or refuse an unresolved identity."""
        ...


class DefUseStorageKind8616(StrEnum):
    """Storage classes supported by structured def-use validation."""

    STACK_LOCAL = "stack-local"
    REGISTER_CARRIER = "register-carrier"
    SEGMENT_CARRIER = "segment-carrier"
    VIRTUAL_CARRIER = "virtual-carrier"


@dataclass(frozen=True, order=True, slots=True)
class DefUseStorageKey8616:
    """Stable storage identity used by the def-use validator."""

    kind: DefUseStorageKind8616
    offset: int
    width: int
    region: int | None = None
    ssa_id: str = ""
    definition_trackable: bool = field(default=True, compare=False)
    display_name: str = field(default="", compare=False)

    def token(self) -> str:
        """Return a deterministic diagnostic token for this storage identity."""
        if self.kind is DefUseStorageKind8616.STACK_LOCAL:
            sign = "+" if self.offset >= 0 else "-"
            return f"{self.kind.value}:SS:BP{sign}0x{abs(self.offset):x}:size{self.width}"
        if self.kind is DefUseStorageKind8616.VIRTUAL_CARRIER:
            return f"{self.kind.value}:{self.ssa_id}:size{self.width}"
        prefix = f"{self.kind.value}:reg+0x{self.offset:x}:size{self.width}"
        if not self.definition_trackable:
            return f"{prefix}:ssa-unproven"
        return f"{prefix}:region0x{self.region:x}:ssa-{self.ssa_id}"


@dataclass(frozen=True, order=True, slots=True)
class _DefUseStorageByte8616:
    """One byte of definitely defined segmented storage."""

    kind: DefUseStorageKind8616
    offset: int
    region: int | None
    ssa_id: str

    def token(self) -> str:
        """Return a deterministic diagnostic token for this byte."""
        if self.kind is DefUseStorageKind8616.STACK_LOCAL:
            sign = "+" if self.offset >= 0 else "-"
            return f"{self.kind.value}:SS:BP{sign}0x{abs(self.offset):x}"
        if self.kind is DefUseStorageKind8616.VIRTUAL_CARRIER:
            return f"{self.kind.value}:{self.ssa_id}:byte+0x{self.offset:x}"
        return f"{self.kind.value}:reg+0x{self.offset:x}:region0x{self.region:x}:ssa-{self.ssa_id}"


@dataclass(frozen=True, slots=True)
class _DefUsePredicate8616:
    """Exact structured predicate and the storage identities it evaluates."""

    token: PredicateToken8616
    dependencies: frozenset[_DefUseStorageByte8616]


@dataclass(frozen=True, slots=True)
class _DefUseValueRead8616:
    """One evaluated C node and its normalized storage identity."""

    node: OpaqueValidationNode8616
    storage: DefUseStorageKey8616


@dataclass(slots=True)
class _DefUseFlowState8616:
    """Definitely assigned bytes plus definitions guarded by exact predicates."""

    defined: set[_DefUseStorageByte8616]
    guarded: dict[_DefUsePredicate8616, set[_DefUseStorageByte8616]]
    falls_through: bool = True

    def copy(self) -> _DefUseFlowState8616:
        """Return an independent state for one structured control-flow path."""
        return _DefUseFlowState8616(
            defined=set(self.defined),
            guarded={predicate: set(definitions) for predicate, definitions in self.guarded.items()},
            falls_through=self.falls_through,
        )


@dataclass(frozen=True, order=True, slots=True)
class DefUseIssue8616:
    """One structured read without a proven definition on every input path."""

    storage: DefUseStorageKey8616
    context: str

    def token(self) -> str:
        """Return a deterministic validation fingerprint for this issue."""
        return f"uninitialized-read:{self.storage.token()}:{self.context}"

    def semantic_token(self) -> str:
        """Return path-independent storage identity for semantic comparison."""
        return f"uninitialized-read:{self.storage.token()}"


@dataclass(frozen=True, order=True, slots=True)
class DefUseCallOutputDefinition8616:
    """One lowering-proven stack range defined by a specific call node."""

    base_offset: int
    width: int

    def storage_key(self) -> DefUseStorageKey8616:
        """Return the stack storage identity defined by the call."""
        return DefUseStorageKey8616(
            kind=DefUseStorageKind8616.STACK_LOCAL,
            offset=self.base_offset,
            width=self.width,
        )


@dataclass(frozen=True, order=True, slots=True)
class DefUseEntryStackRange8616:
    """One machine-BP argument range proven initialized at function entry."""

    base_offset: int
    width: int

    def __post_init__(self) -> None:
        """Reject locals, frame metadata, and empty argument ranges."""
        if self.base_offset < 4 or self.width <= 0:
            raise ValueError("entry stack range must be a positive-BP argument")

    def storage_key(self) -> DefUseStorageKey8616:
        """Return the validator storage identity for this argument range."""
        return DefUseStorageKey8616(
            kind=DefUseStorageKind8616.STACK_LOCAL,
            offset=self.base_offset,
            width=self.width,
        )


@dataclass(frozen=True, slots=True)
class DefUseValidationReport8616:
    """Closed-loop counters and issues from structured def-use validation."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    issues: tuple[DefUseIssue8616, ...] = ()

    @property
    def failure_count(self) -> int:
        """Return the number of reads without a proven prior definition."""
        return len(self.issues)

    @property
    def passed(self) -> bool:
        """Return whether every classified read has a proven definition."""
        return self.failure_count == 0

    def issue_tokens(self) -> tuple[str, ...]:
        """Return stable issue fingerprints for tail-validation summaries."""
        return tuple(issue.token() for issue in self.issues)

    def semantic_issue_tokens(self) -> tuple[str, ...]:
        """Return issue identities without representation-specific AST paths."""
        return tuple(issue.semantic_token() for issue in self.issues)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible closed-loop evidence report."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
            "issues": list(self.issue_tokens()),
        }


@dataclass(slots=True)
class _MutableDefUseReport8616:
    """Mutable counters used only while walking one structured AST."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    issues: list[DefUseIssue8616] = field(default_factory=list)

    def freeze(self) -> DefUseValidationReport8616:
        """Freeze counters into the public immutable validation contract."""
        return DefUseValidationReport8616(
            raw_fact_count=self.raw_fact_count,
            normalized_fact_count=self.normalized_fact_count,
            classified_fact_count=self.classified_fact_count,
            materialized_count=self.materialized_count,
            issues=tuple(self.issues),
        )


def _stack_storage_key_8616(
    node: object,
    *,
    include_arguments: bool = False,
    stack_variable_offset_resolver: StackVariableOffsetResolver8616 | None = None,
) -> DefUseStorageKey8616 | None:
    """Return an exact BP-relative value view evaluated by one C variable."""
    if not isinstance(node, CVariable):
        return None
    if isinstance(node.type, (SimTypeArray, SimTypeFixedSizeArray)):
        # Array expressions evaluate to an address. Indexed element reads need
        # their own exact offset/range proof and are not whole-object reads.
        return None
    variable = node.unified_variable
    if not isinstance(variable, SimStackVariable):
        variable = node.variable
    if not isinstance(variable, SimStackVariable):
        return None
    offset = (
        stack_variable_offset_resolver(variable)
        if stack_variable_offset_resolver is not None
        else variable.offset
    )
    if not isinstance(offset, int) or (offset >= 0 and not include_arguments):
        return None
    storage_width = variable.size if isinstance(variable.size, int) and variable.size > 0 else 1
    width = storage_width
    try:
        type_bits = node.type.size if node.type is not None else None
    except (AttributeError, ValueError):
        type_bits = None
    if isinstance(type_bits, int) and type_bits > 0:
        width = min(storage_width, max(1, (type_bits + 7) // 8))
    name = variable.name if isinstance(variable.name, str) else ""
    return DefUseStorageKey8616(
        kind=DefUseStorageKind8616.STACK_LOCAL,
        offset=offset,
        width=width,
        display_name=name,
    )


def _type_width_bytes_8616(type_: object) -> int | None:
    """Return one positive byte width from an angr C type when available."""
    if not isinstance(type_, SimType):
        return None
    try:
        type_bits = type_.size
    except (AttributeError, ValueError):
        return None
    if not isinstance(type_bits, int) or type_bits <= 0:
        return None
    return max(1, (type_bits + 7) // 8)


def _indexed_stack_storage_key_8616(
    node: object,
    *,
    dynamic_array_as_object: bool,
    include_arguments: bool = False,
    stack_variable_offset_resolver: StackVariableOffsetResolver8616 | None = None,
) -> DefUseStorageKey8616 | None:
    """Return the exact element or conservative full-object stack identity."""
    byte_view = indexed_scalar_byte_view_8616(node)
    if byte_view is not None:
        owner, byte_index = byte_view
        storage = _stack_storage_key_8616(
            owner, include_arguments=include_arguments,
            stack_variable_offset_resolver=stack_variable_offset_resolver,
        )
        if storage is not None and byte_index < storage.width:
            return replace(storage, offset=storage.offset + byte_index, width=1)
        return None
    if not isinstance(node, CIndexedVariable):
        return None
    base = node.variable
    if not isinstance(base, CVariable) or not isinstance(
        base.type,
        (SimTypeArray, SimTypeFixedSizeArray),
    ):
        return None
    variable = base.unified_variable
    if not isinstance(variable, SimStackVariable):
        variable = base.variable
    if (
        not isinstance(variable, SimStackVariable)
        or not isinstance(variable.size, int)
        or variable.size <= 0
    ):
        return None
    offset = (
        stack_variable_offset_resolver(variable)
        if stack_variable_offset_resolver is not None
        else variable.offset
    )
    if not isinstance(offset, int) or (offset >= 0 and not include_arguments):
        return None
    name = variable.name if isinstance(variable.name, str) else ""
    element_width = _type_width_bytes_8616(node.type)
    element_count = base.type.length
    array_element_width = _type_width_bytes_8616(base.type.elem_type)
    object_width = (
        array_element_width * element_count
        if array_element_width is not None
        and isinstance(element_count, int)
        and element_count > 0
        and variable.size
        in {
            array_element_width,
            array_element_width * element_count,
        }
        else None
    )
    if (
        element_width is None
        and object_width is not None
        and isinstance(element_count, int)
    ):
        element_width = object_width // element_count
    if element_width is None:
        if dynamic_array_as_object:
            return DefUseStorageKey8616(
                kind=DefUseStorageKind8616.STACK_LOCAL,
                offset=offset,
                width=object_width or variable.size,
                definition_trackable=False,
                display_name=name,
            )
        return None
    index = node.index.value if isinstance(node.index, CConstant) else None
    if isinstance(index, int) and not isinstance(index, bool):
        relative_offset = index * element_width
        if (
            index < 0
            or relative_offset < 0
            or relative_offset + element_width > (object_width or variable.size)
        ):
            if dynamic_array_as_object:
                return DefUseStorageKey8616(
                    kind=DefUseStorageKind8616.STACK_LOCAL,
                    offset=offset,
                    width=object_width or variable.size,
                    definition_trackable=False,
                    display_name=name,
                )
            return None
        offset = offset + relative_offset
        width = element_width
    elif dynamic_array_as_object and object_width is not None:
        width = object_width
    elif dynamic_array_as_object:
        return DefUseStorageKey8616(
            kind=DefUseStorageKind8616.STACK_LOCAL,
            offset=offset,
            width=object_width or variable.size,
            definition_trackable=False,
            display_name=name,
        )
    else:
        return None
    return DefUseStorageKey8616(
        kind=DefUseStorageKind8616.STACK_LOCAL,
        offset=offset,
        width=width,
        display_name=name,
    )


def _register_storage_key_8616(
    node: object,
    segment_register_offsets: frozenset[int],
) -> DefUseStorageKey8616 | None:
    """Return exact C-variable or AIL-virtual register storage identity."""
    if isinstance(node, CDirtyExpression):
        view = physical_register_view_8616(node)
        if view is None:
            return None
        identity = describe_virtual_value_identity_8616(node)
        structured_identity = (
            identity is not None
            and identity.kind is VirtualValueIdentityKind8616.VARIABLE_ID
        )
        return DefUseStorageKey8616(
            kind=(
                DefUseStorageKind8616.SEGMENT_CARRIER
                if view.reg_offset in segment_register_offsets
                else DefUseStorageKind8616.REGISTER_CARRIER
            ),
            offset=view.reg_offset,
            width=view.width,
            region=0 if structured_identity else None,
            ssa_id=(
                f"{identity.kind.value}-{identity.value}"
                if structured_identity and identity is not None
                else ""
            ),
            definition_trackable=structured_identity,
        )
    if not isinstance(node, CVariable):
        return None
    candidates = (node.unified_variable, node.variable)
    variables = tuple(candidate for candidate in candidates if isinstance(candidate, SimRegisterVariable))
    if not variables:
        return None
    variable = next(
        (
            candidate
            for candidate in variables
            if isinstance(candidate.region, int)
            and isinstance(candidate.ident, (int, str))
            and isinstance(candidate.reg, int)
            and isinstance(candidate.size, int)
            and candidate.size > 0
        ),
        variables[0],
    )
    if not isinstance(variable.reg, int) or not isinstance(variable.size, int) or variable.size <= 0:
        return None
    structured_identity = isinstance(variable.region, int) and isinstance(variable.ident, (int, str))
    ssa_id = ""
    if structured_identity:
        ssa_kind = "int" if isinstance(variable.ident, int) else "str"
        ssa_id = f"{ssa_kind}-{variable.ident}"
    name = variable.name if isinstance(variable.name, str) else ""
    return DefUseStorageKey8616(
        kind=(
            DefUseStorageKind8616.SEGMENT_CARRIER
            if variable.reg in segment_register_offsets
            else DefUseStorageKind8616.REGISTER_CARRIER
        ),
        offset=variable.reg,
        width=variable.size,
        region=variable.region if isinstance(variable.region, int) else None,
        ssa_id=ssa_id,
        definition_trackable=structured_identity,
        display_name=name,
    )


def _storage_key_8616(
    node: object,
    segment_register_offsets: frozenset[int],
    *,
    dynamic_array_as_object: bool = False,
    include_virtual_carriers: bool = False,
    include_stack_arguments: bool = False,
    stack_variable_offset_resolver: StackVariableOffsetResolver8616 | None = None,
) -> DefUseStorageKey8616 | None:
    """Return one exact architectural or opt-in virtual storage identity."""
    projection = validated_stack_projection_fact_8616(node)
    if projection is not None and (projection.view_offset < 0 or include_stack_arguments):
        return DefUseStorageKey8616(
            kind=DefUseStorageKind8616.STACK_LOCAL,
            offset=projection.view_offset,
            width=projection.view_size,
        )
    indexed_key = _indexed_stack_storage_key_8616(
        node,
        dynamic_array_as_object=dynamic_array_as_object,
        include_arguments=include_stack_arguments,
        stack_variable_offset_resolver=stack_variable_offset_resolver,
    )
    if indexed_key is not None:
        return indexed_key
    stack_key = _stack_storage_key_8616(
        node,
        include_arguments=include_stack_arguments,
        stack_variable_offset_resolver=stack_variable_offset_resolver,
    )
    if stack_key is not None:
        return stack_key
    register_key = _register_storage_key_8616(node, segment_register_offsets)
    if register_key is not None:
        return register_key
    if not include_virtual_carriers:
        return None
    virtual_identity = describe_virtual_value_identity_8616(node)
    if virtual_identity is None:
        return None
    width = _type_width_bytes_8616(node.type) if isinstance(node, CDirtyExpression) else None
    return DefUseStorageKey8616(
        kind=DefUseStorageKind8616.VIRTUAL_CARRIER,
        offset=0,
        width=width or 1,
        region=0,
        ssa_id=f"{virtual_identity.kind.value}-{virtual_identity.value}",
    )


def _semantic_partial_lvalue_storage_key_8616(
    node: object,
    segment_register_offsets: frozenset[int],
    *,
    include_stack_arguments: bool = False,
    stack_variable_offset_resolver: StackVariableOffsetResolver8616 | None = None,
) -> DefUseStorageKey8616 | None:
    """Resolve one exact byte-addressed semantic-cast assignment target."""
    if not isinstance(node, CSemanticCast8616):
        return None
    width = _type_width_bytes_8616(node.dst_type)
    expression = node.expr
    byte_offset = 0
    if isinstance(expression, CVariable):
        base = expression
    elif (
        isinstance(expression, CBinaryOp)
        and expression.op == "Shr"
        and isinstance(expression.lhs, CVariable)
        and isinstance(expression.rhs, CConstant)
        and isinstance(expression.rhs.value, int)
        and not isinstance(expression.rhs.value, bool)
        and expression.rhs.value >= 0
        and expression.rhs.value % 8 == 0
    ):
        base = expression.lhs
        byte_offset = expression.rhs.value // 8
    else:
        return None
    storage = _storage_key_8616(
        base,
        segment_register_offsets,
        include_stack_arguments=include_stack_arguments,
        stack_variable_offset_resolver=stack_variable_offset_resolver,
    )
    if width is None or storage is None or byte_offset + width > storage.width:
        return None
    return DefUseStorageKey8616(
        kind=storage.kind,
        offset=storage.offset + byte_offset,
        width=width,
        region=storage.region,
        ssa_id=storage.ssa_id,
        definition_trackable=storage.definition_trackable,
        display_name=storage.display_name,
    )


def _predicate_storage_key_8616(
    node: object,
    segment_register_offsets: frozenset[int],
    *,
    stack_variable_offset_resolver: StackVariableOffsetResolver8616 | None = None,
) -> DefUseStorageKey8616 | None:
    """Return exact stack-argument, local, or register identity for a predicate."""
    stack_key = _stack_storage_key_8616(
        node,
        include_arguments=True,
        stack_variable_offset_resolver=stack_variable_offset_resolver,
    )
    if stack_key is not None:
        return stack_key
    return _register_storage_key_8616(node, segment_register_offsets)


def _iter_value_nodes_8616(root: object) -> tuple[object, ...]:
    """Return value-evaluated AST nodes without treating ``&var`` as a read."""
    nodes: list[object] = []
    active: set[int] = set()

    def _visit(node: object) -> None:
        if not _structured_codegen_node_8616(node):
            return
        node_id = id(node)
        if node_id in active:
            return
        nodes.append(node)
        if validated_stack_projection_fact_8616(node) is not None:
            return
        if isinstance(node, CUnaryOp) and node.op == "Reference" and isinstance(node.operand, CVariable):
            return
        if isinstance(node, CFunctionCall) and node.callee_func is not None:
            # angr renders and evaluates the authoritative direct callee_func;
            # callee_target is stale compatibility storage in this form.
            active.add(node_id)
            try:
                for argument in node.args:
                    _visit(argument)
            finally:
                active.remove(node_id)
            return

        active.add(node_id)
        try:
            for attr in _structured_slot_names_8616(node):
                try:
                    # Dynamic third-party angr/codegen boundary.
                    value = getattr(node, attr)
                except Exception:
                    continue
                for child in _iter_c_node_children_8616(value, set()):
                    _visit(child)
        finally:
            active.remove(node_id)

    _visit(root)
    return tuple(nodes)


def _value_read_keys_8616(
    expr: object,
    segment_register_offsets: frozenset[int],
    *,
    include_virtual_carriers: bool = False,
    include_stack_arguments: bool = False,
    stack_variable_offset_resolver: StackVariableOffsetResolver8616 | None = None,
) -> tuple[_DefUseValueRead8616, ...]:
    """Collect tracked storage views whose stored values are evaluated."""
    if expr is None:
        return ()
    if os.environ.get("INERTIA_DEBUG_DEF_USE") == "1" and isinstance(expr, CFunctionCall):
        def _shape(node: object, depth: int = 0) -> object:
            """Render a bounded structured value shape for opt-in diagnostics."""
            if depth >= 4:
                return type(node).__name__
            if isinstance(node, CVariable):
                return (
                    "var",
                    node.name,
                    repr(node.variable),
                )
            if isinstance(node, CConstant):
                return ("const", node.value)
            if isinstance(node, CFakeVariable):
                return ("fake-var", node.name)
            if isinstance(node, CBinaryOp):
                return (
                    "binary",
                    node.op,
                    _shape(node.lhs, depth + 1),
                    _shape(node.rhs, depth + 1),
                )
            if isinstance(node, CUnaryOp):
                return ("unary", node.op, _shape(node.operand, depth + 1))
            return type(node).__name__

        logging.getLogger(__name__).warning(
            "def-use call-node callee_func=%r callee_target_type=%s callee_target=%r args=%r",
            expr.callee_func,
            type(expr.callee_target).__name__,
            expr.callee_target,
            tuple(_shape(argument) for argument in expr.args),
        )
    reads: list[_DefUseValueRead8616] = []
    for node in _iter_value_nodes_8616(expr):
        key = _storage_key_8616(
            node,
            segment_register_offsets,
            dynamic_array_as_object=True,
            include_virtual_carriers=include_virtual_carriers,
            include_stack_arguments=include_stack_arguments,
            stack_variable_offset_resolver=stack_variable_offset_resolver,
        )
        if key is None:
            continue
        reads.append(_DefUseValueRead8616(node=node, storage=key))
        if os.environ.get("INERTIA_DEBUG_DEF_USE") == "1":
            logging.getLogger(__name__).warning(
                "def-use value-node storage=%s name=%s node_type=%s variable=%r dirty=%r tags=%r",
                key.token(),
                key.display_name,
                type(node).__name__,
                node.variable if isinstance(node, CVariable) else None,
                node.dirty if isinstance(node, CDirtyExpression) else None,
                node.tags if isinstance(node, (CVariable, CDirtyExpression)) else None,
            )
    return tuple(reads)


def _storage_bytes_8616(key: DefUseStorageKey8616) -> frozenset[_DefUseStorageByte8616]:
    """Expand one alias-proven storage view into its covered byte identities."""
    return frozenset(
        _DefUseStorageByte8616(
            kind=key.kind,
            offset=offset,
            region=key.region,
            ssa_id=key.ssa_id,
        )
        for offset in range(key.offset, key.offset + key.width)
    )


def _predicate_fact_8616(
    expression: object,
    segment_register_offsets: frozenset[int],
    *,
    stack_variable_offset_resolver: StackVariableOffsetResolver8616 | None = None,
) -> _DefUsePredicate8616 | None:
    """Build an exact non-text predicate identity from structured C expressions."""
    active: set[int] = set()

    def _visit(node: object) -> tuple[PredicateToken8616, frozenset[_DefUseStorageByte8616]] | None:
        node_id = id(node)
        if node_id in active:
            return None
        if isinstance(node, CVariable):
            key = _predicate_storage_key_8616(
                node,
                segment_register_offsets,
                stack_variable_offset_resolver=stack_variable_offset_resolver,
            )
            if key is None or not key.definition_trackable:
                return None
            return (
                (
                    "storage",
                    key.kind,
                    key.offset,
                    key.width,
                    key.region,
                    key.ssa_id,
                ),
                _storage_bytes_8616(key),
            )
        if isinstance(node, CConstant):
            value = node.value
            if not isinstance(value, (bool, int, float, str, type(None))):
                return None
            return (("constant", type(value).__name__, value), frozenset())
        if not isinstance(node, (CUnaryOp, CBinaryOp)):
            return None
        active.add(node_id)
        try:
            if isinstance(node, CUnaryOp):
                operand = _visit(node.operand)
                if operand is None:
                    return None
                operand_token, dependencies = operand
                if node.op == "Not":
                    return (invert_predicate_token_8616(operand_token), dependencies)
                return (("unary", node.op, operand_token), dependencies)
            lhs = _visit(node.lhs)
            rhs = _visit(node.rhs)
            if lhs is None or rhs is None:
                return None
            lhs_token, lhs_dependencies = lhs
            rhs_token, rhs_dependencies = rhs
            return (
                ("binary", node.op, lhs_token, rhs_token),
                lhs_dependencies | rhs_dependencies,
            )
        finally:
            active.remove(node_id)

    result = _visit(expression)
    if result is None:
        return None
    token, dependencies = result
    if not dependencies:
        return None
    return _DefUsePredicate8616(token=token, dependencies=dependencies)


def _intersect_defined_8616(
    states: list[set[_DefUseStorageByte8616]],
    fallback: set[_DefUseStorageByte8616],
) -> set[_DefUseStorageByte8616]:
    if not states:
        return set(fallback)
    result = set(states[0])
    for state in states[1:]:
        result.intersection_update(state)
    return result


def _intersect_guarded_8616(
    states: list[dict[_DefUsePredicate8616, set[_DefUseStorageByte8616]]],
    fallback: dict[_DefUsePredicate8616, set[_DefUseStorageByte8616]],
) -> dict[_DefUsePredicate8616, set[_DefUseStorageByte8616]]:
    """Retain guarded definitions valid on every outgoing structured path."""
    if not states:
        return {predicate: set(definitions) for predicate, definitions in fallback.items()}
    common_predicates = set(states[0])
    for state in states[1:]:
        common_predicates.intersection_update(state)
    result: dict[_DefUsePredicate8616, set[_DefUseStorageByte8616]] = {}
    for predicate in common_predicates:
        definitions = set(states[0][predicate])
        for state in states[1:]:
            definitions.intersection_update(state[predicate])
        if definitions:
            result[predicate] = definitions
    return result


def _intersect_flow_states_8616(
    states: list[_DefUseFlowState8616],
    fallback: _DefUseFlowState8616,
) -> _DefUseFlowState8616:
    """Merge structured paths using definite and guarded intersections."""
    states = [state for state in states if state.falls_through]
    if not states:
        terminated = fallback.copy()
        terminated.falls_through = False
        return terminated
    return _DefUseFlowState8616(
        defined=_intersect_defined_8616(
            [state.defined for state in states],
            fallback.defined,
        ),
        guarded=_intersect_guarded_8616(
            [state.guarded for state in states],
            fallback.guarded,
        ),
        falls_through=True,
    )


def _invalidate_guarded_definitions_8616(
    state: _DefUseFlowState8616,
    written: frozenset[_DefUseStorageByte8616] | set[_DefUseStorageByte8616],
) -> None:
    """Drop predicate proofs whose evaluated storage may have changed."""
    if not written:
        return
    invalid = tuple(
        predicate
        for predicate in state.guarded
        if not predicate.dependencies.isdisjoint(written)
    )
    for predicate in invalid:
        del state.guarded[predicate]


def _activate_guarded_definitions_8616(
    state: _DefUseFlowState8616,
    predicate: _DefUsePredicate8616 | None,
) -> None:
    """Make definitions guarded by a proven true predicate definite in its body."""
    if predicate is None:
        return
    state.defined.update(state.guarded.get(predicate, ()))


def _inverted_predicate_fact_8616(
    predicate: _DefUsePredicate8616 | None,
) -> _DefUsePredicate8616 | None:
    """Return the exact complementary fact while preserving its dependencies."""
    if predicate is None:
        return None
    return _DefUsePredicate8616(
        token=invert_predicate_token_8616(predicate.token),
        dependencies=predicate.dependencies,
    )


def _invalidate_call_affected_guards_8616(
    expression: object,
    state: _DefUseFlowState8616,
    segment_register_offsets: frozenset[int],
    *,
    stack_variable_offset_resolver: StackVariableOffsetResolver8616 | None = None,
) -> None:
    """Invalidate guards when a call can overwrite their predicate storage."""
    value_nodes = _iter_value_nodes_8616(expression)
    if not any(isinstance(node, CFunctionCall) for node in value_nodes):
        return
    affected: set[_DefUseStorageByte8616] = set()
    for node in value_nodes:
        if not isinstance(node, CUnaryOp) or node.op != "Reference":
            continue
        key = _predicate_storage_key_8616(
            node.operand,
            segment_register_offsets,
            stack_variable_offset_resolver=stack_variable_offset_resolver,
        )
        if key is not None:
            affected.update(_storage_bytes_8616(key))
    for predicate in state.guarded:
        affected.update(
            dependency
            for dependency in predicate.dependencies
            if dependency.kind is not DefUseStorageKind8616.STACK_LOCAL
        )
    _invalidate_guarded_definitions_8616(state, affected)


def _switch_case_bodies_8616(cases: object) -> tuple[object, ...]:
    """Normalize the two CSwitchCase container shapes exposed by angr."""
    if isinstance(cases, dict):
        return tuple(cases.values())
    if isinstance(cases, (list, tuple)):
        return tuple(
            case_body
            for item in cases
            if isinstance(item, (list, tuple)) and len(item) == 2
            for _case_value, case_body in (item,)
        )
    return ()


def _debug_def_use_event_8616(
    event: str,
    key: DefUseStorageKey8616,
    defined: set[_DefUseStorageByte8616],
    *,
    context: str,
) -> None:
    """Log exact validator state when focused def-use diagnostics are enabled."""
    if os.environ.get("INERTIA_DEBUG_DEF_USE", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return
    logging.getLogger(__name__).warning(
        "def-use event=%s context=%s storage=%s defined=%s",
        event,
        context,
        key.token(),
        tuple(item.token() for item in sorted(defined)),
    )


def validate_structured_def_use_8616(
    root: object,
    *,
    call_output_definitions: Mapping[int, tuple[DefUseCallOutputDefinition8616, ...]] | None = None,
    indexed_stack_read_proofs: Mapping[int, IndexedStackReadProof8616] | None = None,
    entry_defined_stack_ranges: tuple[DefUseEntryStackRange8616, ...] = (),
    entry_defined_registers: tuple[object, ...] = (),
    segment_register_offsets: frozenset[int] = frozenset(),
    entry_defined_segment_register_offsets: frozenset[int] = frozenset(),
    packed_status_flag_preservation: PackedStatusFlagPreservationEvidence8616 | None = None,
    include_virtual_carriers: bool = False,
    stack_variable_offset_resolver: StackVariableOffsetResolver8616 | None = None,
) -> DefUseValidationReport8616:
    """Validate definitely assigned stack and register reads in structured C.

    Positive ``BP`` reads are always classified, but only explicit machine-BP
    argument ranges are initialized at entry. Register arguments are initialized
    only when the caller supplies their exact C variables. Segment carriers are
    initialized only when typed IR state proves their architectural live-in
    offsets. Other register and segment carriers without complete angr
    region/SSA identity remain classified but are not treated as defined.
    Constant indexed stack-array accesses use their exact element range.
    Dynamic indexed reads conservatively require the complete bounded array to
    be definitely assigned; a dynamic store never defines the complete array.
    Virtual carriers are opt-in because legal lowering regenerates their SSA
    identities; the final emission guard enables them after mutation stops.
    """
    report = _MutableDefUseReport8616()
    definitions_by_call = call_output_definitions or {}
    proofs_by_read = indexed_stack_read_proofs or {}
    break_exit_scopes: list[list[_DefUseFlowState8616] | None] = []

    def _check_reads(
        expr: OpaqueValidationNode8616,
        defined: set[_DefUseStorageByte8616],
        *,
        context: str,
        architectural_live_in_register_offsets: frozenset[int] = frozenset(),
    ) -> None:
        try:
            instruction_address = expr.tags.get("ins_addr")
        except AttributeError:
            instruction_address = None
        if (
            packed_status_flag_preservation is not None
            and packed_status_flag_preservation.covers_instruction(instruction_address)
        ):
            architectural_live_in_register_offsets |= frozenset(
                {packed_status_flag_preservation.register_offset}
            )
        reads = _value_read_keys_8616(
            expr,
            segment_register_offsets,
            include_virtual_carriers=include_virtual_carriers,
            include_stack_arguments=True,
            stack_variable_offset_resolver=stack_variable_offset_resolver,
        )
        report.raw_fact_count += len(reads)
        report.normalized_fact_count += len(reads)
        report.classified_fact_count += len(reads)
        for read in reads:
            key = read.storage
            proof = proofs_by_read.get(id(read.node))
            proof_matches = (
                isinstance(read.node, CIndexedVariable)
                and proof is not None
                and proof.matches(
                    read.node,
                    array_offset=key.offset,
                    array_width=key.width,
                )
            )
            segment_live_in = (
                key.kind is DefUseStorageKind8616.SEGMENT_CARRIER
                and key.offset in entry_defined_segment_register_offsets
            )
            packed_preservation_live_in = (
                key.kind is DefUseStorageKind8616.REGISTER_CARRIER
                and key.offset in architectural_live_in_register_offsets
            )
            if proof_matches or segment_live_in or packed_preservation_live_in or (
                key.definition_trackable
                and _storage_bytes_8616(key).issubset(defined)
            ):
                report.materialized_count += 1
            else:
                _debug_def_use_event_8616("issue", key, defined, context=context)
                report.issues.append(DefUseIssue8616(storage=key, context=context))

    def _check_lvalue_reads(
        lhs: object,
        defined: set[_DefUseStorageByte8616],
        *,
        context: str,
    ) -> None:
        """Validate only value-evaluated operands of an assignment lvalue."""
        if isinstance(lhs, CIndexedVariable):
            _check_reads(lhs.index, defined, context=f"{context}.index")
            base = lhs.variable
            if isinstance(base, CVariable) and isinstance(
                base.type,
                (SimTypeArray, SimTypeFixedSizeArray),
            ):
                return
            _check_reads(base, defined, context=f"{context}.base")
            return
        _check_reads(lhs, defined, context=context)

    def _apply_call_output_definitions(
        expr: object,
        state: _DefUseFlowState8616,
        *,
        context: str,
    ) -> None:
        """Apply only lowering-proven output ranges after their owning call executes."""
        _invalidate_call_affected_guards_8616(
            expr,
            state,
            segment_register_offsets,
            stack_variable_offset_resolver=stack_variable_offset_resolver,
        )
        for value_node in _iter_value_nodes_8616(expr):
            if not isinstance(value_node, CFunctionCall):
                continue
            for definition in definitions_by_call.get(id(value_node), ()):
                key = definition.storage_key()
                storage_bytes = _storage_bytes_8616(key)
                _debug_def_use_event_8616("call-define", key, state.defined, context=context)
                _invalidate_guarded_definitions_8616(state, storage_bytes)
                state.defined.update(storage_bytes)

    def _walk(
        node: object,
        incoming: _DefUseFlowState8616,
        *,
        context: str,
    ) -> _DefUseFlowState8616:
        state = incoming.copy()
        if node is None:
            return state
        if isinstance(node, CStatements):
            for index, statement in enumerate(node.statements):
                if not state.falls_through:
                    break
                state = _walk(statement, state, context=f"{context}.stmt{index}")
            return state
        if isinstance(node, CAssignment):
            if os.environ.get("INERTIA_DEBUG_DEF_USE", "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }:
                lhs_variable = node.lhs.variable if isinstance(node.lhs, CVariable) else None
                lhs_name = lhs_variable.name if isinstance(lhs_variable, SimStackVariable) else None
                lhs_offset = lhs_variable.offset if isinstance(lhs_variable, SimStackVariable) else None
                rhs_op = node.rhs.op if isinstance(node.rhs, CUnaryOp) else None
                logging.getLogger(__name__).warning(
                    "def-use assignment context=%s lhs=%s lhs_type=%s lhs_variable=%r "
                    "offset=%s rhs=%s rhs_op=%s tags=%r",
                    context,
                    lhs_name,
                    type(node.lhs).__name__,
                    lhs_variable,
                    lhs_offset,
                    type(node.rhs).__name__,
                    rhs_op,
                    node.tags,
                )
            preservation_offsets: frozenset[int] = frozenset()
            if packed_status_flag_preservation is not None and packed_status_flag_preservation.covers_instruction(
                node.tags.get("ins_addr")
            ):
                preservation_offsets = frozenset({packed_status_flag_preservation.register_offset})
            _check_reads(
                node.rhs,
                state.defined,
                context=f"{context}.rhs",
                architectural_live_in_register_offsets=preservation_offsets,
            )
            _apply_call_output_definitions(node.rhs, state, context=f"{context}.rhs")
            predicate_lhs_key = _predicate_storage_key_8616(
                node.lhs,
                segment_register_offsets,
                stack_variable_offset_resolver=stack_variable_offset_resolver,
            )
            if predicate_lhs_key is None:
                predicate_lhs_key = _semantic_partial_lvalue_storage_key_8616(
                    node.lhs,
                    segment_register_offsets,
                    include_stack_arguments=True,
                    stack_variable_offset_resolver=stack_variable_offset_resolver,
                )
            if predicate_lhs_key is not None:
                _invalidate_guarded_definitions_8616(
                    state,
                    _storage_bytes_8616(predicate_lhs_key),
                )
            lhs_key = _storage_key_8616(
                node.lhs,
                segment_register_offsets,
                include_virtual_carriers=include_virtual_carriers,
                include_stack_arguments=True,
                stack_variable_offset_resolver=stack_variable_offset_resolver,
            )
            if lhs_key is None:
                lhs_key = _semantic_partial_lvalue_storage_key_8616(
                    node.lhs,
                    segment_register_offsets,
                    include_stack_arguments=True,
                    stack_variable_offset_resolver=stack_variable_offset_resolver,
                )
            if lhs_key is None:
                _check_lvalue_reads(node.lhs, state.defined, context=f"{context}.lhs")
            elif lhs_key.definition_trackable:
                _debug_def_use_event_8616("define", lhs_key, state.defined, context=context)
                state.defined.update(_storage_bytes_8616(lhs_key))
            return state
        if isinstance(node, CExpressionStatement):
            _check_reads(node.expr, state.defined, context=f"{context}.expr")
            _apply_call_output_definitions(node.expr, state, context=f"{context}.expr")
            return state
        if isinstance(node, CReturn):
            _check_reads(node, state.defined, context=context)
            _apply_call_output_definitions(node, state, context=context)
            state.falls_through = False
            return state
        if isinstance(node, CBreak):
            if break_exit_scopes and break_exit_scopes[-1] is not None:
                break_exit_scopes[-1].append(state.copy())
            return state
        if isinstance(node, CIfElse):
            branch_states: list[_DefUseFlowState8616] = []
            branch_predicates: list[_DefUsePredicate8616 | None] = []
            for index, (condition, branch) in enumerate(node.condition_and_nodes):
                _check_reads(condition, state.defined, context=f"{context}.if{index}.condition")
                predicate = _predicate_fact_8616(
                    condition,
                    segment_register_offsets,
                    stack_variable_offset_resolver=stack_variable_offset_resolver,
                )
                branch_predicates.append(predicate)
                branch_incoming = state.copy()
                _activate_guarded_definitions_8616(branch_incoming, predicate)
                branch_states.append(
                    _walk(
                        branch,
                        branch_incoming,
                        context=f"{context}.if{index}.body",
                    )
                )
            if node.else_node is None:
                branch_states.append(state.copy())
            else:
                else_incoming = state.copy()
                if len(branch_predicates) == 1:
                    _activate_guarded_definitions_8616(
                        else_incoming,
                        _inverted_predicate_fact_8616(branch_predicates[0]),
                    )
                branch_states.append(
                    _walk(node.else_node, else_incoming, context=f"{context}.else")
                )
            merged = _intersect_flow_states_8616(branch_states, state)
            if (
                node.else_node is None
                and len(branch_states) == 2
                and len(branch_predicates) == 1
                and branch_predicates[0] is not None
            ):
                guarded_definitions = branch_states[0].defined - state.defined
                if guarded_definitions:
                    merged.guarded.setdefault(branch_predicates[0], set()).update(
                        guarded_definitions
                    )
            return merged
        if isinstance(node, CForLoop):
            initialized = _walk(node.initializer, state, context=f"{context}.for.init")
            _check_reads(node.condition, initialized.defined, context=f"{context}.for.condition")
            body_incoming = initialized.copy()
            _activate_guarded_definitions_8616(
                body_incoming,
                _predicate_fact_8616(
                    node.condition,
                    segment_register_offsets,
                    stack_variable_offset_resolver=stack_variable_offset_resolver,
                ),
            )
            break_exit_scopes.append([])
            try:
                body_state = _walk(node.body, body_incoming, context=f"{context}.for.body")
            finally:
                break_exit_scopes.pop()
            iterated = _walk(node.iterator, body_state, context=f"{context}.for.iterator")
            initialized.guarded = _intersect_guarded_8616(
                [initialized.guarded, iterated.guarded],
                initialized.guarded,
            )
            return initialized
        if isinstance(node, CWhileLoop):
            _check_reads(node.condition, state.defined, context=f"{context}.while.condition")
            body_incoming = state.copy()
            _activate_guarded_definitions_8616(
                body_incoming,
                _predicate_fact_8616(
                    node.condition,
                    segment_register_offsets,
                    stack_variable_offset_resolver=stack_variable_offset_resolver,
                ),
            )
            break_exit_states: list[_DefUseFlowState8616] = []
            break_exit_scopes.append(break_exit_states)
            try:
                body_state = _walk(node.body, body_incoming, context=f"{context}.while.body")
            finally:
                break_exit_scopes.pop()
            state.guarded = _intersect_guarded_8616(
                [state.guarded, body_state.guarded],
                state.guarded,
            )
            if (
                isinstance(node.condition, CConstant)
                and isinstance(node.condition.value, (bool, int))
                and bool(node.condition.value)
                and break_exit_states
            ):
                return _intersect_flow_states_8616(break_exit_states, state)
            return state
        if isinstance(node, CDoWhileLoop):
            break_exit_scopes.append([])
            try:
                body_state = _walk(node.body, state, context=f"{context}.do.body")
            finally:
                break_exit_scopes.pop()
            _check_reads(node.condition, body_state.defined, context=f"{context}.do.condition")
            return body_state
        if isinstance(node, CSwitchCase):
            _check_reads(node.switch, state.defined, context=f"{context}.switch.selector")
            break_exit_scopes.append(None)
            try:
                branch_states = [
                    _walk(branch, state, context=f"{context}.switch.case")
                    for branch in _switch_case_bodies_8616(node.cases)
                ]
            finally:
                break_exit_scopes.pop()
            if node.default is None:
                branch_states.append(state.copy())
            else:
                break_exit_scopes.append(None)
                try:
                    branch_states.append(_walk(node.default, state, context=f"{context}.switch.default"))
                finally:
                    break_exit_scopes.pop()
            return _intersect_flow_states_8616(branch_states, state)
        _check_reads(node, state.defined, context=context)
        _apply_call_output_definitions(node, state, context=context)
        return state

    entry_defined: set[_DefUseStorageByte8616] = set()
    for stack_range in entry_defined_stack_ranges:
        entry_defined.update(_storage_bytes_8616(stack_range.storage_key()))
    for register_node in entry_defined_registers:
        key = _register_storage_key_8616(register_node, segment_register_offsets)
        if key is not None and key.definition_trackable:
            entry_defined.update(_storage_bytes_8616(key))
    _walk(
        root,
        _DefUseFlowState8616(defined=entry_defined, guarded={}),
        context="root",
    )
    return report.freeze()

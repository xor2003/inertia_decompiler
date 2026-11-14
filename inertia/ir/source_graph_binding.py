# cython: language_level=3, infer_types=True
"""Canonical shared-DAG serialization of owned IR source surfaces.

Layer: IR.
Responsibility: owns the deterministic canonical node-table encoding that entry
jump-domain proofs bind to. A proof's source surface is an expression DAG — the
same typed value object may be referenced by many instructions — so recursion
over the DAG must emit each structural subtree once instead of duplicating
complete trees.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations
import typing

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn, TypeVar

import cython

from .core import (
    AddressStatus,
    IRActiveUnary8616,
    IRAddress,
    IRAtom,
    IRBinaryValue,
    IRBlock,
    IRCallOutputProvenance8616,
    IRCallOutputShape8616,
    IRCallStackEffect8616,
    IRCondition,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .instruction_origin import IRInstructionOrigin8616
from .source_graph_json import canonical_json_dumps_8616
import dataclasses
import operator
import builtins

__all__ = [
    "SOURCE_GRAPH_FORMAT_8616",
    "FrozenSourceNodeRecord8616",
    "ImmutableSourceGraphFacts8616",
    "SourceGraphSerializationError8616",
    "canonical_call_stack_effect_8616",
    "canonical_ir_instruction_graph_8616",
    "canonical_source_graph_8616",
    "capture_immutable_source_graph_facts_8616",
]

SOURCE_GRAPH_FORMAT_8616: str = "entry_jump_domain_source_binding_8616/v2"
"""Canonical source-binding format marker.

``v1`` was the recursive ``to_dict`` tree encoding. ``v2`` is the interned
node-table encoding; the marker lives inside the canonical payload so any
recorded ``v1`` binding digest fails replay and must refuse.
"""

_E = TypeVar("_E", bound=Enum)


class SourceGraphSerializationError8616(TypeError):
    """The owned IR surface holds a value the canonical form cannot encode.

    Raised for cyclic object graphs, mutable containers where the owned
    contract declares an immutable tuple, unrecognized payload types, and
    unknown node subclasses. It subclasses ``TypeError`` so it is the same
    failure class as the previous ``json.dumps``-level serialization
    refusal rather than a silently handled condition.
    """


@cython.ccall
def _fail(owner: object, field_name: object, value: object, expected: object) -> NoReturn:
    """Raise a typed serialization refusal naming owner, field, and payload."""
    raise SourceGraphSerializationError8616(
        f"{owner}.{field_name} must be {expected}; "
        f"got {type(value).__name__} {value!r}"
    )


def _record_atom_8616(value: object) -> object:
    """Freeze an owned shallow record value without conflating booleans and integers.

    These records contain only validated scalars and generated sequences. This
    is not an arbitrary JSON encoder; unsupported values remain typed refusals.
    """
    kind = type(value)
    if kind is int or kind is str or value is None:
        return value
    if kind is bool:
        return (bool, value)
    if type(value) is list:
        return (list, tuple(_record_atom_8616(item) for item in iter(value)))
    if isinstance(value, str):
        # JSON serializes a str subclass's contents, not its custom __str__.
        return str.__str__(value)
    _fail("source record", "value", value, "validated scalar or generated list")


@cython.ccall
def _record_key_8616(
    record: object,
    field_orders: object = None,
) -> tuple[tuple[str, ...], tuple[object, ...]]:
    """Intern sorted JSON equality without allocating a pair for every field.

    Field orders derive from actual records and may be reused within one
    encoder. Values are always read and validated afresh; this stores neither
    source objects nor proof verdicts. Field names remain part of each key so
    different schemas cannot alias even when their values happen to agree.
    """
    value: object
    name: object
    names = cython.declare(tuple)
    if field_orders is None:
        names = tuple(sorted(record))
    else:
        shape = cython.declare(tuple, tuple(record))
        cached_names = cython.declare(tuple, field_orders.get(shape))
        if cached_names is None:
            cached_names = tuple(sorted(shape))
            field_orders[shape] = cached_names
        names = cached_names
    values = cython.declare(list, [])
    for name in names:
        value = record[name]
        kind = type(value)
        if kind is int or kind is str or value is None:
            values.append(value)
        else:
            values.append(_record_atom_8616(value))
    return names, tuple(values)


@cython.cclass
class _SourceGraphEncoder8616:
    """One deterministic postorder interning pass over an owned IR surface.

    Node identity is structural: each node's shallow record resolves its
    children to canonical node ids, a typed shallow-record key supplies
    structural equality, and node ids follow first-postorder-visit order.
    Identical shared and deep-copied DAGs therefore produce identical
    encodings — object identity never enters the serialized form.

    The identity memo accelerates revisits of the exact same owned objects
    within this single call; visited objects stay pinned in ``_pinned`` so a
    recycled ``id`` cannot alias a live node. Nothing is cached across calls.
    """

    _records = cython.declare(list)
    _record_keys = cython.declare(list)
    _interned = cython.declare(dict)
    _field_orders = cython.declare(dict)
    _identity = cython.declare(dict)
    _pinned = cython.declare(list)
    _visiting = cython.declare(set)
    _retain_records = cython.declare(cython.bint)

    def __init__(self, retain_records: cython.bint = True) -> None:
        self._retain_records = retain_records
        self._records = []
        self._record_keys = []
        self._interned = {}
        self._field_orders = {}
        self._identity = {}
        self._pinned = []
        self._visiting = set()

    def prepare(self, roots: object) -> None:
        """Encode children before parents without consuming Python stack depth."""
        node: object
        pending = cython.declare(list, [(node, False) for node in builtins.iter(reversed(roots))])
        active = cython.declare(set, set())
        ready = cython.declare(object)
        while pending:
            node, ready = pending.pop()
            identity = id(node)
            if identity in self._identity:
                continue
            if ready:
                active.remove(identity)
                self._encode_ready(node)
                continue
            if identity in active:
                raise SourceGraphSerializationError8616(
                    f"cyclic {type(node).__name__} node graph"
                )
            active.add(identity)
            pending.append((node, True))
            pending.extend(
                (child, False) for child in builtins.iter(reversed(self._children(node)))
                if child is not None
            )

    @cython.ccall
    def _encode_ready(self, node: object) -> None:
        """Build a shallow record after all of its child identities are bound."""
        if (type(node) is IRValue or type(node) is IRBinaryValue
                or type(node) is IRAddress or type(node) is IRCondition):
            atom: IRAtom = node
            self._atom(atom)
        elif type(node) is IRBlock:
            self.block(node)
        elif type(node) is IRInstr:
            self._instr(node)
        elif type(node) is IRActiveUnary8616:
            self._active_unary_or_none(node)
        elif type(node) is IRCallStackEffect8616:
            self._call_stack_effect_or_none(node)
        elif type(node) is IRCallOutputProvenance8616:
            self._call_output_or_none(node)
        elif type(node) is IRInstructionOrigin8616:
            self._origin_or_none(node)
        elif type(node) is IRRefusal:
            self._refusal(node)
        else:
            _fail("source graph", "node", node, "owned IR node")

    @cython.ccall
    def _atom_children(self, node: object) -> object:
        """Retain the record builder's canonical child-field traversal order."""
        if type(node) is IRValue:
            value: IRValue = node
            return (value.index, value.call_output, value.active_unary)
        if type(node) is IRBinaryValue:
            binary: IRBinaryValue = node
            return (binary.lhs, binary.rhs)
        if type(node) is IRAddress:
            address: IRAddress = node
            return self._child_tuple(
                "IRAddress", "base_values", address.base_values)
        if type(node) is IRCondition:
            condition: IRCondition = node
            return self._child_tuple(
                "IRCondition", "args", condition.args)
        _fail("source graph", "atom", node, "owned IR atom")

    @cython.ccall
    def _children(self, node: object) -> object:
        """Select only typed graph edges; scalar validation stays in records."""
        if type(node) in (IRValue, IRBinaryValue, IRAddress, IRCondition):
            return self._atom_children(node)
        if type(node) is IRBlock:
            block: IRBlock = node
            return (
                *self._child_tuple("IRBlock", "instrs", block.instrs),
                *self._child_tuple("IRBlock", "refusals", block.refusals),
            )
        if type(node) is IRInstr:
            instr: IRInstr = node
            return (
                instr.dst,
                *self._child_tuple("IRInstr", "args", instr.args),
                instr.call_stack_effect, instr.origin,
            )
        if type(node) is IRActiveUnary8616:
            unary: IRActiveUnary8616 = node
            return (unary.operand,)
        if type(node) is IRCallStackEffect8616:
            effect: IRCallStackEffect8616 = node
            return (
                *self._child_tuple("IRCallStackEffect8616", "preserved_ranges", effect.preserved_ranges),
                *self._child_tuple("IRCallStackEffect8616", "escaped_ranges", effect.escaped_ranges),
            )
        if type(node) in (IRCallOutputProvenance8616, IRInstructionOrigin8616, IRRefusal):
            return ()
        _fail("source graph", "node", node, "owned IR node")

    @cython.ccall
    def _child_tuple(self, owner: object, field_name: object, value: object) -> object:
        """Reject malformed child containers before traversal can expand them."""
        if type(value) is not tuple:
            _fail(owner, field_name, value, "tuple of owned IR nodes")
        return value


    @property
    def records(self) -> object:
        """Interned shallow node records in canonical id order.

        Empty when this encoder was constructed with ``retain_records=False``;
        only the canonical serializer consumes it and keeps the default.
        """
        return self._records

    @property
    def record_keys(self) -> tuple[tuple[tuple[str, ...], tuple[object, ...]], ...]:
        """Frozen interned-record keys in canonical node-id order.

        Each entry is the ``(sorted field names, typed atom values)`` key
        produced while interning, so it is already deeply immutable and
        preserves the encoder's bool/int distinction without re-validating
        the mutable source records.
        """
        return tuple(self._record_keys)

    @cython.ccall
    def _intern_node(
        self, node: object, build: Callable[[], dict[str, object]],
    ) -> cython.longlong:
        """Encode one owned node structurally, interning equal subtrees."""
        memoized: object
        node_id: object
        identity = id(node)
        memoized = self._identity.get(identity)
        if memoized is not None:
            return memoized
        if identity in self._visiting:
            raise SourceGraphSerializationError8616(
                f"cyclic {type(node).__name__} node graph"
            )
        self._pinned.append(node)
        self._visiting.add(identity)
        try:
            record = build()
        finally:
            self._visiting.discard(identity)
        key = _record_key_8616(record, self._field_orders)
        node_id = self._interned.get(key)
        if node_id is None:
            node_id = len(self._record_keys)
            self._interned[key] = node_id
            if self._retain_records:
                self._records.append(record)
            self._record_keys.append(key)
        self._identity[identity] = node_id
        return node_id

    # --- scalar field evidence -------------------------------------------

    @cython.ccall
    def _int(self, owner: object, field_name: object, value: object) -> cython.longlong:
        """Require an exact ``int`` payload; ``bool`` is not an int here."""
        if type(value) is not int:
            _fail(owner, field_name, value, "int")
        return value

    @cython.ccall
    def _int_or_none(self, owner: object, field_name: object, value: object) -> int | None:
        """Require ``None`` or an exact ``int`` payload."""
        if value is None:
            return None
        return self._int(owner, field_name, value)

    @cython.ccall
    def _bool(self, owner: object, field_name: object, value: object) -> cython.bint:
        """Require an exact ``bool`` payload; it must not encode as ``1``."""
        if type(value) is not bool:
            _fail(owner, field_name, value, "bool")
        return value

    @cython.ccall
    def _str(self, owner: object, field_name: object, value: object) -> object:
        """Require a ``str`` payload (subclasses encode as their content)."""
        if not isinstance(value, str):
            _fail(owner, field_name, value, "str")
        return value

    @cython.ccall
    def _str_or_none(self, owner: object, field_name: object, value: object) -> object:
        """Require ``None`` or a ``str`` payload."""
        if value is None:
            return None
        return self._str(owner, field_name, value)

    @cython.ccall
    def _str_tuple_or_none(self,
        owner: object, field_name: object, value: object,
    ) -> object:
        """Require ``None`` or an immutable tuple of plain strings."""
        if value is None:
            return None
        if type(value) is not tuple:
            _fail(owner, field_name, value, "tuple[str, ...] | None")
        return [
            self._str(owner, field_name, item)
            for item in iter(value)
        ]

    @cython.ccall
    def _str_tuple(self, owner: object, field_name: object, value: object) -> object:
        """Require an immutable tuple of plain strings."""
        result: object
        result = self._str_tuple_or_none(
            owner, field_name, value
        )
        if result is None:
            _fail(owner, field_name, value, "tuple[str, ...]")
        return result

    @cython.ccall
    def _int_tuple(self, owner: object, field_name: object, value: object) -> list[cython.longlong]:
        """Require an immutable tuple of exact ``int`` addresses."""
        if type(value) is not tuple:
            _fail(owner, field_name, value, "tuple[int, ...]")
        return [
            self._int(owner, field_name, item)
            for item in iter(value)
        ]

    @cython.ccall
    def _enum(self,
        owner: object, field_name: object, value: object, kind: type[_E],
    ) -> object:
        """Require an exact member of one owned enum; emit its value."""
        if type(value) is not kind:
            _fail(owner, field_name, value, kind.__name__)
        result: object = value.value
        if type(result) is not str:
            _fail(owner, field_name, result, "str enum value")
        return result

    # --- owned node dispatch ------------------------------------------------

    @cython.ccall
    def _atom(self, node: IRAtom) -> cython.longlong:
        """Dispatch one typed atom by exact type; subclasses refuse."""
        if type(node) is IRValue:
            return self._value(node)
        if type(node) is IRBinaryValue:
            return self._binary(node)
        if type(node) is IRAddress:
            return self._address(node)
        if type(node) is IRCondition:
            return self._condition(node)
        _fail("IRAtom", "*", node, "owned IRAtom type")

    @cython.ccall
    def _value_or_none(self, node: object) -> int | None:
        """Dispatch a declared ``IRValue | None`` child by exact type."""
        if node is None:
            return None
        if type(node) is not IRValue:
            _fail("IRValue", "*", node, "IRValue | None")
        return self._value(node)

    @cython.ccall
    def _value_or_binary_or_none(
        self, node: object,
    ) -> int | None:
        """Dispatch a declared ``IRValue | IRBinaryValue | None`` child."""
        if node is None:
            return None
        if type(node) is IRValue:
            return self._value(node)
        if type(node) is IRBinaryValue:
            return self._binary(node)
        _fail("IRValue|IRBinaryValue", "*", node, "IRValue | IRBinaryValue | None")

    @cython.ccall
    def _value_or_binary(self, node: IRValue | IRBinaryValue) -> cython.longlong:
        """Dispatch a declared ``IRValue | IRBinaryValue`` child."""
        node_id: object
        node_id = self._value_or_binary_or_none(node)
        if node_id is None:
            _fail("IRValue|IRBinaryValue", "*", node, "IRValue | IRBinaryValue")
        return node_id

    @cython.ccall
    def _atom_tuple(self, owner: object, field_name: object, nodes: object) -> list[cython.longlong]:
        """Require an immutable tuple of typed atoms."""
        if type(nodes) is not tuple:
            _fail(owner, field_name, nodes, "tuple[IRAtom, ...]")
        return [self._atom(node) for node in iter(nodes)]

    # --- node records --------------------------------------------------------

    def _value(self, node: IRValue) -> cython.longlong:
        """Intern one ``IRValue`` with its complete field surface."""
        return self._intern_node(
            node,
            lambda: {
                "node": "value",
                "space": self._enum("IRValue", "space", node.space, MemSpace),
                "name": self._str_or_none("IRValue", "name", node.name),
                "offset": self._int("IRValue", "offset", node.offset),
                "const": self._int_or_none("IRValue", "const", node.const),
                "size": self._int("IRValue", "size", node.size),
                "version": self._int_or_none("IRValue", "version", node.version),
                "expr": self._str_tuple_or_none("IRValue", "expr", node.expr),
                "index": self._value_or_binary_or_none(node.index),
                "index_shift": self._int("IRValue", "index_shift", node.index_shift),
                "memory_access_size": self._int_or_none(
                    "IRValue", "memory_access_size", node.memory_access_size
                ),
                "memory_access_insn": self._int_or_none(
                    "IRValue", "memory_access_insn", node.memory_access_insn
                ),
                "source_tmp": self._int_or_none(
                    "IRValue", "source_tmp", node.source_tmp
                ),
                "call_output": self._call_output_or_none(node.call_output),
                "active_unary": self._active_unary_or_none(node.active_unary),
            },
        )

    def _binary(self, node: IRBinaryValue) -> cython.longlong:
        """Intern one ``IRBinaryValue`` with both operand children."""
        return self._intern_node(
            node,
            lambda: {
                "node": "binary_value",
                "op": self._str("IRBinaryValue", "op", node.op),
                "lhs": self._value_or_binary(node.lhs),
                "rhs": self._value_or_binary(node.rhs),
                "size": self._int("IRBinaryValue", "size", node.size),
            },
        )

    def _active_unary_or_none(
        self, node: object,
    ) -> int | None:
        """Intern one optional ``IRActiveUnary8616`` evidence node."""
        if node is None:
            return None
        if type(node) is not IRActiveUnary8616:
            _fail("IRValue", "active_unary", node, "IRActiveUnary8616 | None")
        return self._intern_node(
            node,
            lambda: {
                "node": "active_unary",
                "op": self._str("IRActiveUnary8616", "op", node.op),
                "operand": self._unary_operand(node.operand),
                "result_bits": self._int(
                    "IRActiveUnary8616", "result_bits", node.result_bits
                ),
            },
        )

    @cython.ccall
    def _unary_operand(self, node: IRValue) -> cython.longlong:
        """Require the declared ``IRValue`` operand of an active unary."""
        if type(node) is not IRValue:
            _fail("IRActiveUnary8616", "operand", node, "IRValue")
        return self._value(node)

    def _call_output_or_none(
        self, node: object,
    ) -> int | None:
        """Intern one optional call-output provenance node."""
        if node is None:
            return None
        if type(node) is not IRCallOutputProvenance8616:
            _fail(
                "IRValue", "call_output", node,
                "IRCallOutputProvenance8616 | None",
            )
        return self._intern_node(
            node,
            lambda: {
                "node": "call_output_provenance",
                "callsite_addr": self._int(
                    "IRCallOutputProvenance8616", "callsite_addr",
                    node.callsite_addr,
                ),
                "target_addr": self._int(
                    "IRCallOutputProvenance8616", "target_addr",
                    node.target_addr,
                ),
                "shape": self._enum(
                    "IRCallOutputProvenance8616", "shape", node.shape,
                    IRCallOutputShape8616,
                ),
            },
        )

    def _address(self, node: IRAddress) -> cython.longlong:
        """Intern one ``IRAddress`` with its complete field surface."""
        return self._intern_node(
            node,
            lambda: {
                "node": "address",
                "space": self._enum("IRAddress", "space", node.space, MemSpace),
                "base": self._str_tuple("IRAddress", "base", node.base),
                "offset": self._int("IRAddress", "offset", node.offset),
                "size": self._int("IRAddress", "size", node.size),
                "status": self._enum(
                    "IRAddress", "status", node.status, AddressStatus
                ),
                "segment_origin": self._enum(
                    "IRAddress", "segment_origin", node.segment_origin,
                    SegmentOrigin,
                ),
                "expr": self._str_tuple_or_none("IRAddress", "expr", node.expr),
                "version": self._int_or_none(
                    "IRAddress", "version", node.version
                ),
                "base_values": self._value_tuple(
                    "IRAddress", "base_values", node.base_values
                ),
            },
        )

    @cython.ccall
    def _value_tuple(
        self, owner: object, field_name: object, nodes: object,
    ) -> object:
        """Require an immutable tuple of declared ``IRValue`` children."""
        item: object
        if type(nodes) is not tuple:
            _fail(owner, field_name, nodes, "tuple[IRValue, ...]")
        result = []
        for item in nodes:
            if type(item) is not IRValue:
                _fail(owner, field_name, item, "IRValue")
            result.append(self._value(item))
        return result

    def _condition(self, node: IRCondition) -> cython.longlong:
        """Intern one ``IRCondition`` including ``compare=False`` width."""
        return self._intern_node(
            node,
            lambda: {
                "node": "condition",
                "op": self._str("IRCondition", "op", node.op),
                "args": self._atom_tuple("IRCondition", "args", node.args),
                "expr": self._str_tuple_or_none(
                    "IRCondition", "expr", node.expr
                ),
                "width_bits": self._int_or_none(
                    "IRCondition", "width_bits", node.width_bits
                ),
            },
        )

    def _call_stack_effect_or_none(
        self, node: object,
    ) -> int | None:
        """Intern effect fields and its finite coordinate value projection.

        Coordinate certificates retain external analysis scopes; only their
        typed data and current readiness enter this expression-DAG binding.
        Canonical JSON preserves scalar types without interning scope objects.
        """
        if node is None:
            return None
        if type(node) is not IRCallStackEffect8616:
            _fail(
                "IRInstr", "call_stack_effect", node,
                "IRCallStackEffect8616 | None",
            )
        return self._intern_node(
            node,
            lambda: self._call_stack_effect_record(node),
        )

    @cython.ccall
    def _call_stack_effect_record(self, node: IRCallStackEffect8616) -> dict[str, object]:
        """Share one immediate coordinate observation across both projections."""
        observation: object
        observation = None if node.stack_coordinates is None else node.stack_coordinates.observe()
        current_delta = node.net_stack_delta
        if observation is not None and operator.ne(observation.proven_net_sp_delta, current_delta):
            current_delta = None
        return {
                "node": "call_stack_effect",
                "net_stack_delta": self._int_or_none(
                    "IRCallStackEffect8616", "net_stack_delta",
                    node.net_stack_delta,
                ),
                "current_net_stack_delta": self._int_or_none(
                    "IRCallStackEffect8616", "current_net_stack_delta",
                    current_delta,
                ),
                "stack_coordinates": (
                    None if observation is None
                    else canonical_json_dumps_8616(observation.to_dict())
                ),
                "bp_preserved": self._bool(
                    "IRCallStackEffect8616", "bp_preserved", node.bp_preserved
                ),
                "preserved_ranges": self._address_tuple(
                    "IRCallStackEffect8616", "preserved_ranges",
                    node.preserved_ranges,
                ),
                "escaped_ranges": self._address_tuple(
                    "IRCallStackEffect8616", "escaped_ranges",
                    node.escaped_ranges,
                ),
                "complete": self._bool(
                    "IRCallStackEffect8616", "complete", node.complete
                ),
                "scoped_coordinates": self._bool(
                    "IRCallStackEffect8616", "scoped_coordinates",
                    node.scoped_coordinates is not None,
                ),
            }

    @cython.ccall
    def _address_tuple(
        self, owner: object, field_name: object, nodes: object,
    ) -> object:
        """Require an immutable tuple of declared ``IRAddress`` children."""
        item: object
        if type(nodes) is not tuple:
            _fail(owner, field_name, nodes, "tuple[IRAddress, ...]")
        result = []
        for item in nodes:
            if type(item) is not IRAddress:
                _fail(owner, field_name, item, "IRAddress")
            result.append(self._address(item))
        return result

    def _origin_or_none(self, node: object) -> int | None:
        """Intern one optional instruction-origin provenance node."""
        if node is None:
            return None
        if type(node) is not IRInstructionOrigin8616:
            _fail(
                "IRInstr", "origin", node, "IRInstructionOrigin8616 | None",
            )
        return self._intern_node(
            node,
            lambda: {
                "node": "instruction_origin",
                "block_addr": self._int(
                    "IRInstructionOrigin8616", "block_addr", node.block_addr
                ),
                "statement_index": self._int(
                    "IRInstructionOrigin8616", "statement_index",
                    node.statement_index,
                ),
                "address_tmp": self._int_or_none(
                    "IRInstructionOrigin8616", "address_tmp", node.address_tmp
                ),
                "is_block_next": self._bool(
                    "IRInstructionOrigin8616", "is_block_next",
                    node.is_block_next,
                ),
                "block_next_tmp": self._int_or_none(
                    "IRInstructionOrigin8616", "block_next_tmp",
                    node.block_next_tmp,
                ),
                "is_instruction_mark": self._bool(
                    "IRInstructionOrigin8616", "is_instruction_mark",
                    node.is_instruction_mark,
                ),
            },
        )

    def _instr(self, node: IRInstr) -> cython.longlong:
        """Intern one ``IRInstr`` with effect and origin provenance."""
        return self._intern_node(
            node,
            lambda: {
                "node": "instr",
                "op": self._str("IRInstr", "op", node.op),
                "dst": self._value_or_none(node.dst),
                "args": self._atom_tuple("IRInstr", "args", node.args),
                "size": self._int("IRInstr", "size", node.size),
                "addr": self._int_or_none("IRInstr", "addr", node.addr),
                "call_stack_effect": self._call_stack_effect_or_none(
                    node.call_stack_effect
                ),
                "origin": self._origin_or_none(node.origin),
            },
        )

    def _refusal(self, node: IRRefusal) -> cython.longlong:
        """Intern one ``IRRefusal`` evidence record."""
        return self._intern_node(node, lambda: _refusal_record_8616(node, self))

    def block(self, node: IRBlock) -> cython.longlong:
        """Intern one ``IRBlock`` with instr/refusal order preserved."""
        if type(node) is not IRBlock:
            _fail("blocks", "*", node, "IRBlock")
        return self._intern_node(
            node,
            lambda: {
                "node": "block",
                "addr": self._int("IRBlock", "addr", node.addr),
                "instrs": self._instr_tuple("IRBlock", "instrs", node.instrs),
                "refusals": self._refusal_tuple(
                    "IRBlock", "refusals", node.refusals
                ),
                "successor_addrs": self._int_tuple(
                    "IRBlock", "successor_addrs", node.successor_addrs
                ),
            },
        )

    @cython.ccall
    def _instr_tuple(
        self, owner: object, field_name: object, nodes: object,
    ) -> object:
        """Require an immutable tuple of declared ``IRInstr`` children."""
        item: object
        if type(nodes) is not tuple:
            _fail(owner, field_name, nodes, "tuple[IRInstr, ...]")
        result = []
        for item in nodes:
            if type(item) is not IRInstr:
                _fail(owner, field_name, item, "IRInstr")
            result.append(self._instr(item))
        return result

    @cython.ccall
    def _refusal_tuple(
        self, owner: object, field_name: object, nodes: object,
    ) -> object:
        """Require an immutable tuple of declared ``IRRefusal`` children."""
        item: object
        if type(nodes) is not tuple:
            _fail(owner, field_name, nodes, "tuple[IRRefusal, ...]")
        result = []
        for item in nodes:
            if type(item) is not IRRefusal:
                _fail(owner, field_name, item, "IRRefusal")
            result.append(self._refusal(item))
        return result


@cython.ccall
@cython.locals(encoder=_SourceGraphEncoder8616)
def _refusal_record_8616(node: IRRefusal, encoder: _SourceGraphEncoder8616) -> dict[str, object]:
    """Build the single validated shallow record for one ``IRRefusal``.

    This is the same field surface the encoder interns for block-level
    refusals; extracting it lets detached fact capture freeze one refusal
    without a second schema.
    """
    return {
        "node": "refusal",
        "kind": encoder._str("IRRefusal", "kind", node.kind),
        "detail": encoder._str("IRRefusal", "detail", node.detail),
        "block_addr": encoder._int_or_none(
            "IRRefusal", "block_addr", node.block_addr
        ),
    }


@dataclasses.dataclass(frozen=True, )
class FrozenSourceNodeRecord8616:
    """One interned node record frozen as sorted field names and typed atoms.

    ``values`` contains only the canonical encoder's validated atoms: exact
    ``int``/``str``/``None`` payloads, ``(bool, value)`` markers that keep
    booleans distinct from integers, and ``(list, (...))`` markers for
    generated sequences. The record is hashable and deeply immutable, so it
    can serve as exact refusal or node evidence in detached facts.
    """

    names: object
    values: object


@dataclasses.dataclass(frozen=True, )
class ImmutableSourceGraphFacts8616:
    """Deeply immutable canonical facts detached from one owned IR graph.

    ``roots`` and ``records`` are exactly the canonical interned node table
    ``canonical_source_graph_8616`` serializes — ordered block root ids and
    every validated field of every node — so ``==`` replays the full-field
    structural comparison rather than any hash, identity, or repr shortcut.
    Two independently captured graphs compare equal exactly when their
    canonical encodings agree, including ``compare=False`` provenance such
    as ``source_tmp`` and instruction-origin metadata.

    ``function_refusals`` and ``block_refusals`` hold the frozen function-
    and block-level refusal records the native seal's function-only-refusal
    census consumes. They are orthogonal evidence — graph equality compares
    the block surface only, matching the canonical binding contract — so
    they are excluded from ``==`` and compared explicitly by the seal.
    """

    function_addr: cython.longlong
    roots: object
    records: object
    function_refusals: object = field(
        compare=False
    )
    block_refusals: object = field(
        compare=False
    )


@cython.ccall
@cython.locals(encoder=_SourceGraphEncoder8616)
def _frozen_refusal_8616(owner: object, node: object, encoder: _SourceGraphEncoder8616) -> FrozenSourceNodeRecord8616:
    """Freeze one declared ``IRRefusal`` into typed immutable evidence."""
    if type(node) is not IRRefusal:
        _fail(owner, "*", node, "IRRefusal")
    names, values = _record_key_8616(_refusal_record_8616(node, encoder))
    return FrozenSourceNodeRecord8616(names, values)


def capture_immutable_source_graph_facts_8616(
    function_addr: cython.longlong,
    blocks: object,
    function_refusals: object = (),
) -> ImmutableSourceGraphFacts8616:
    """Detach one owned IR graph into deeply immutable canonical facts.

    The capture runs the same full field-validation encoder as the canonical
    source binding and freezes the resulting interned node table plus ordered
    roots. No source object survives: every retained value is a typed atom or
    an immutable container of atoms, so later mutation through live IR
    aliases cannot rewrite the facts, and cyclic or malformed graphs raise
    ``SourceGraphSerializationError8616`` here rather than at seal time.

    ``function_refusals`` are validated and frozen as separate evidence —
    they are not interned into the block table, keeping ``records`` equal to
    the exact canonical block surface. Block-level refusal evidence is
    collected per block for the seal's function-only-refusal census.
    """
    if type(function_addr) is not int:
        _fail(
            "capture_immutable_source_graph_facts_8616", "function_addr",
            function_addr, "int",
        )
    if not isinstance(blocks, (tuple, list)):
        _fail(
            "capture_immutable_source_graph_facts_8616", "blocks", blocks,
            "tuple[IRBlock, ...]",
        )
    if type(function_refusals) is not tuple:
        _fail(
            "capture_immutable_source_graph_facts_8616", "function_refusals",
            function_refusals, "tuple[IRRefusal, ...]",
        )
    encoder = cython.declare(
        _SourceGraphEncoder8616,
        _SourceGraphEncoder8616(retain_records=False),
    )
    encoder.prepare(blocks)
    return ImmutableSourceGraphFacts8616(
        function_addr,
        tuple(encoder.block(block) for block in iter(blocks)),
        tuple(
            FrozenSourceNodeRecord8616(names, values)
            for names, values in iter(encoder.record_keys)
        ),
        tuple(
            _frozen_refusal_8616("function_refusals", refusal, encoder)
            for refusal in iter(function_refusals)
        ),
        tuple(
            _frozen_refusal_8616("IRBlock.refusals", refusal, encoder)
            for block in iter(blocks)
            for refusal in iter(block.refusals)
        ),
    )


def source_graphs_equal_8616(
    left_addr: cython.longlong, left_blocks: object,
    right_addr: cython.longlong, right_blocks: object,
) -> cython.bint:
    """Compare full canonical surfaces within one fresh, shared traversal.

    Structural interning gives equal nodes equal IDs in this encoder, so
    comparing ordered root IDs preserves canonical-JSON equality without
    constructing either JSON document. Both graphs are validated even when
    their roots differ. Shared owned nodes are visited once in this synchronous
    operation; nothing, including identity memo entries, survives this call.
    Persistent proof bindings still use ``canonical_source_graph_8616``.
    """
    address: object
    blocks: object
    encoder = cython.declare(
        _SourceGraphEncoder8616,
        _SourceGraphEncoder8616(retain_records=False),
    )
    roots: list[tuple[cython.longlong, ...]] = []
    for address, blocks in ((left_addr, left_blocks), (right_addr, right_blocks)):
        if type(address) is not int:
            _fail("source_graphs_equal_8616", "function_addr", address, "int")
        if not isinstance(blocks, (tuple, list)):
            _fail("source_graphs_equal_8616", "blocks", blocks, "tuple[IRBlock, ...]")
        encoder.prepare(blocks)
        roots.append(tuple(encoder.block(block) for block in iter(blocks)))
    return left_addr == right_addr and operator.eq(roots[0], roots[1])


@cython.ccall
def canonical_call_stack_effect_8616(effect: IRCallStackEffect8616) -> object:
    """Encode a call effect's finite fields and live source-proof readiness.

    Reuse the exact effect projection used by full source graphs. Retained
    analysis projects authorize the current SP projection; they are not IR
    values to traverse or serialize. Callee source changes therefore remain
    visible through the checked current delta.
    """
    if type(effect) is not IRCallStackEffect8616:
        _fail("canonical_call_stack_effect_8616", "effect", effect, "IRCallStackEffect8616")
    encoder = cython.declare(_SourceGraphEncoder8616, _SourceGraphEncoder8616())
    payload: dict[str, object] = {
        "format": SOURCE_GRAPH_FORMAT_8616,
        "root": encoder._call_stack_effect_or_none(effect),
        "nodes": encoder.records,
    }
    return canonical_json_dumps_8616(payload)


@cython.ccall
def canonical_source_graph_8616(
    function_addr: cython.longlong, blocks: object,
) -> object:
    """Serialize the exact artifact surface a domain proof consumes.

    The encoding is a deterministic interned node table: every owned node is
    a shallow record whose children are canonical node ids, nodes are
    deduplicated by structure, and block order stays significant through the
    ordered ``roots`` list. The result is identical for structurally equal
    shared and deep-copied DAGs, and it distinguishes every field the owned
    ``to_dict`` surface carries — including ``compare=False`` provenance such
    as ``source_tmp``, ``memory_access_insn`` and ``width_bits``.

    Cyclic graphs, mutable nested containers, opaque payloads and unknown node
    subclasses raise ``SourceGraphSerializationError8616`` rather than
    degrading to a weaker canonical form.
    """
    if type(function_addr) is not int:
        _fail("canonical_source_graph_8616", "function_addr", function_addr, "int")
    if not isinstance(blocks, (tuple, list)):
        _fail(
            "canonical_source_graph_8616", "blocks", blocks,
            "tuple[IRBlock, ...]",
        )
    encoder = cython.declare(_SourceGraphEncoder8616, _SourceGraphEncoder8616())
    encoder.prepare(blocks)
    payload = {
        "format": SOURCE_GRAPH_FORMAT_8616,
        "function_addr": function_addr,
        "roots": [encoder.block(block) for block in iter(blocks)],
        "nodes": encoder.records,
    }
    return canonical_json_dumps_8616(payload)


def canonical_ir_instruction_graph_8616(
    instruction_groups: object, values: object,
) -> object:
    """Encode ordered instruction groups and SSA definition targets in one finite DAG.

    Group boundaries and value-root order are significant. The existing owned
    node encoder retains every instruction/value field and refuses opaque or
    cyclic nodes; no synthetic machine instructions or storage facts are added.
    """
    if type(instruction_groups) is not tuple or any(type(group) is not tuple for group in iter(instruction_groups)):
        _fail("canonical_ir_instruction_graph_8616", "instruction_groups", instruction_groups, "tuple[tuple[IRInstr, ...], ...]")
    if type(values) is not tuple or any(type(value) is not IRValue for value in iter(values)):
        _fail("canonical_ir_instruction_graph_8616", "values", values, "tuple[IRValue, ...]")
    encoder = cython.declare(_SourceGraphEncoder8616, _SourceGraphEncoder8616())
    roots = tuple(instruction for group in iter(instruction_groups) for instruction in iter(group)) + values
    encoder.prepare(roots)
    return canonical_json_dumps_8616({
        "format": "owned-ir-instruction-graph-v1",
        "instruction_groups": [[encoder._instr(instruction) for instruction in iter(group)] for group in iter(instruction_groups)],
        "values": [encoder._atom(value) for value in iter(values)],
        "nodes": encoder.records,
    })

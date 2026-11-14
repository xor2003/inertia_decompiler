# cython: language_level=3, infer_types=True
"""Native boundary adapter for restartable variable allocation.

Layer: Frontend/native adapter.
Responsibility: lower angr's dec_variables manager, Clinic recovery-stage
inputs, and AIL link map into Lowering-owned fingerprints; snapshot and restore
every native surface the recovery stage mutates; reset the per-function manager
transactionally while preserving manual-type evidence; reconcile published atom
links with the surviving graph after a rerun. Convergence policy lives in
Lowering; orchestration lives in the CLI runtime.
"""

from __future__ import annotations
import cython

import copy
import enum
import typing
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Literal

from angr import ailment
from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
from angr.sim_type import (
    SimStruct,
    SimTypeArray,
    SimTypeBottom,
    SimTypeEnum,
    SimTypeFunction,
    SimTypeNum,
    SimTypePointer,
    SimTypeReference,
    SimTypeReg,
    SimTypeString,
    SimTypeTop,
    SimTypeWString,
    SimUnion,
)
from angr.sim_variable import (
    SimComboRegisterVariable,
    SimConstantVariable,
    SimMemoryVariable,
    SimRegisterVariable,
    SimStackVariable,
    SimVariable,
)

from inertia.frontend.x86_16.allocation_publication import (
    NativeAllocationKeyers8616,
    NativeAllocationPublication8616,
    native_publication_records_8616,
)
from inertia.lowering.allocation_convergence import (
    AllocationFingerprintRefusal,
    AllocationGraphEdges,
    AllocationGraphNodes,
    AllocationInputFingerprint,
    AllocationStructuralKey,
    NativeVariableKey,
)
from inertia.lowering.analysis_helpers import _dynamic_analysis_getattr_8616
import dataclasses
import operator
import builtins
Clinic = typing.TypeVar("Clinic")
DecompilationVariableManager = typing.TypeVar("DecompilationVariableManager")
DiGraph = typing.TypeVar("DiGraph")
Project = typing.TypeVar("Project")
PrototypeSource = typing.TypeVar("PrototypeSource")
SimType = typing.TypeVar("SimType")
StackItem = typing.TypeVar("StackItem")
Typehoon = typing.TypeVar("Typehoon")

if typing.TYPE_CHECKING:
    from angr.analyses.decompiler.clinic import Clinic
    from angr.analyses.decompiler.stack_item import StackItem
    from angr.analyses.typehoon import Typehoon
    from angr.knowledge_plugins.functions.function import PrototypeSource
    from angr.knowledge_plugins.variables.variable_manager import DecompilationVariableManager
    from angr.project import Project
    from angr.sim_type import SimType
    from networkx import DiGraph

_dyn = _dynamic_analysis_getattr_8616

# variable_map dict attributes keyed by atom/statement .idx (link surfaces the
# recovery stage republishes) and by vvar id.
_VMAP_IDX_MAPS: tuple[str, ...] = (
    "_variables",
    "_variable_offsets",
    "_reference_variables",
    "_reference_variable_offsets",
    "_custom_strings",
    "_reference_values",
    "_variants",
    "_returntys",
    "_prototypes",
    "_calling_conventions",
)
_VMAP_VVAR_MAPS: tuple[str, ...] = ("_vvar_id_to_variable", "_vvar_id_to_variable_offset")


_TYPE_MAX_DEPTH = 32


@cython.ccall
def _type_size(ty: object) -> object:
    """Size field for a SimType without failing on archless instances."""
    try:
        size = _dyn(ty, "size")
    except (ValueError, AttributeError):
        return None
    return size


@cython.ccall
def _base_type_fields(ty: object) -> dict[str, object]:
    """Common distinguishing fields every supported SimType contributes."""
    return {
        "cls": type(ty).__name__,
        "size": _type_size(ty),
        "label": _scalar(_dyn(ty, "label")),
    }


def _type_key(ty: object, _depth: cython.longlong = 0) -> AllocationStructuralKey:
    """Structural key for a SimType, binding class, layout and signedness.

    Only explicit supported native forms are admitted; unknown objects and
    type graphs deeper than _TYPE_MAX_DEPTH raise AllocationFingerprintRefusal.
    """
    if ty is None:
        return ()
    if _depth > _TYPE_MAX_DEPTH:
        raise AllocationFingerprintRefusal("recursive type graph exceeds supported depth")
    fields = _base_type_fields(ty)
    _container_type_fields(ty, fields, _depth)
    return tuple((name, fields[name]) for name in builtins.iter(sorted(fields)))


def _container_type_fields(
    ty: object, fields: object, depth: cython.longlong
) -> None:
    """Populate layout fields for supported container/named SimType forms."""
    sub = depth + 1
    if isinstance(ty, SimTypeFunction):
        fields["proto"] = (
            tuple(_type_key(a, sub) for a in iter((_dyn(ty, "args") or ()))),
            _type_key(_dyn(ty, "returnty"), sub),
            tuple(_dyn(ty, "arg_names") or ()),
            bool(_dyn(ty, "variadic")),
        )
    elif isinstance(ty, (SimTypePointer, SimTypeReference)):
        fields["pts_to"] = _type_key(_dyn(ty, "pts_to"), sub)
    elif isinstance(ty, SimTypeArray):
        fields["elem_type"] = _type_key(_dyn(ty, "elem_type"), sub)
        fields["length"] = _scalar(_dyn(ty, "length"))
        fields["qualifier"] = tuple(_scalar(q) for q in iter((_dyn(ty, "qualifier") or ())))
    elif isinstance(ty, SimStruct):
        offsets = _dyn(ty, "offsets") or {}
        fields["name"] = _scalar(_dyn(ty, "name"))
        fields["struct"] = tuple(
            sorted(
                (name, _type_key(sub_ty, sub), offsets.get(name))
                for name, sub_ty in builtins.iter(dict(_dyn(ty, "fields") or {}).items())
            )
        )
    elif isinstance(ty, SimUnion):
        fields["name"] = _scalar(_dyn(ty, "name"))
        fields["union"] = tuple(
            sorted(
                (name, _type_key(sub_ty, sub))
                for name, sub_ty in builtins.iter(dict(_dyn(ty, "members") or {}).items())
            )
        )
    elif isinstance(ty, SimTypeEnum):
        fields["name"] = _scalar(_dyn(ty, "name"))
        fields["enum_members"] = tuple(sorted(tuple(dict(_dyn(ty, "members") or {}).items())))
    elif isinstance(ty, (SimTypeString, SimTypeWString)):
        fields["name"] = _scalar(_dyn(ty, "name"))
        fields["length"] = _scalar(_dyn(ty, "length"))
    elif isinstance(
        ty,
        (
            SimTypeReg,
            SimTypeNum,
            SimTypeBottom,
            SimTypeTop,
        ),
    ):
        # SimTypeInt/Char/WideChar/Bool/Fd/Float/Double/Length/NumOffset all
        # derive from SimTypeReg or SimTypeNum; class name + signedness carry
        # their distinguishing content
        fields["signed"] = _scalar(_dyn(ty, "signed"))
        fields["name"] = _scalar(_dyn(ty, "name"))
    else:
        raise AllocationFingerprintRefusal(f"unsupported type form {type(ty).__name__}")


@cython.ccall
def _variable_key(var: SimVariable) -> NativeVariableKey:
    """Structural identity of one SimVariable without rendered text."""
    if isinstance(var, SimStackVariable):
        return NativeVariableKey("stack", var.ident, var.offset, var.size, var.name)
    if isinstance(var, SimComboRegisterVariable):
        return NativeVariableKey("combo_register", var.ident, tuple(var.reg_offsets), var.size, var.name)
    if isinstance(var, SimRegisterVariable):
        return NativeVariableKey("register", var.ident, var.reg, var.size, var.name)
    if isinstance(var, SimConstantVariable):
        return NativeVariableKey("constant", var.ident, var.value, var.size, var.name)
    if isinstance(var, SimMemoryVariable):
        return NativeVariableKey("memory", var.ident, var.addr, var.size, var.name)
    if isinstance(var, SimVariable):
        return NativeVariableKey("variable", var.ident, None, var.size, var.name)
    raise AllocationFingerprintRefusal(f"unsupported variable form {type(var).__name__}")


@cython.ccall
def _scalar(value: object) -> object:
    """Key a scalar field; refuse unkeyable values instead of dropping them."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, enum.Enum):
        return value.name
    name = _dyn(value, "name")
    if isinstance(name, str):  # enum-like native object (e.g. VirtualVariableCategory)
        return (type(value).__name__, name)
    raise AllocationFingerprintRefusal(f"unsupported scalar field {type(value).__name__}")


_EXPR_KEYERS: tuple[tuple[type[Any], Callable[[object], AllocationStructuralKey]], ...] = ()


def _register_expr_keyers() -> tuple[tuple[type[Any], Callable[[object], AllocationStructuralKey]], ...]:
    E = ailment.Expr

    def _vvar(expr: object) -> AllocationStructuralKey:
        oident = _dyn(expr, "oident")
        return (
            "vvar", _dyn(expr, "varid"), _dyn(expr, "size"), _scalar(_dyn(expr, "category")),
            tuple(_scalar(x) for x in iter(oident)) if isinstance(oident, (tuple, list)) else _scalar(oident),
        )

    def _call(expr: object) -> AllocationStructuralKey:
        target = _dyn(expr, "target")
        return (
            "call",
            target if isinstance(target, str) else _expr_key(target),
            tuple(_expr_key(a) for a in iter((_dyn(expr, "args") or ()))),
            _type_key(_dyn(expr, "prototype")),
            _scalar(type(_dyn(expr, "calling_convention")).__name__),
        )

    def _phi(expr: object) -> AllocationStructuralKey:
        """Bind every predecessor, preserving an absent incoming value explicitly."""
        return (
            "phi",
            tuple(sorted(
                (src, ("absent_phi_input",) if v is None else _expr_key(v))
                for src, v in iter((_dyn(expr, "src_and_vvars") or ()))
            )),
        )

    return (
        (E.Const, lambda e: ("const", _dyn(e, "value"), _dyn(e, "bits"), _scalar(_dyn(e, "idx")))),
        (E.VirtualVariable, _vvar),
        (E.Register, lambda e: ("reg", _dyn(e, "reg_offset"), _dyn(e, "size"), _scalar(_dyn(e, "idx")))),
        (E.Tmp, lambda e: ("tmp", _dyn(e, "tmp_idx"), _dyn(e, "size"), _scalar(_dyn(e, "idx")))),
        (E.StackBaseOffset, lambda e: ("sboff", _dyn(e, "offset"), _dyn(e, "size"))),
        (E.BasePointerOffset, lambda e: ("bpoff", _dyn(e, "offset"), _dyn(e, "size"))),
        (E.Load, lambda e: ("load", _dyn(e, "size"), _scalar(_dyn(e, "endness")), _expr_key(_dyn(e, "addr")), _scalar(_dyn(e, "idx")))),
        (E.BinaryOp, lambda e: (
            "binop", _dyn(e, "op"), _dyn(e, "bits"), _dyn(e, "depth"),
            _dyn(e, "floating_point"), _dyn(e, "signed"),
            tuple(_expr_key(op) for op in builtins.iter(_dyn(e, "operands"))), _scalar(_dyn(e, "idx")),
        )),
        (E.UnaryOp, lambda e: ("unop", _dyn(e, "op"), _dyn(e, "bits"), _expr_key(_dyn(e, "operand")), _scalar(_dyn(e, "idx")))),
        (E.Convert, lambda e: (
            "conv", _dyn(e, "from_bits"), _dyn(e, "to_bits"),
            _dyn(e, "is_signed"), _expr_key(_dyn(e, "operand")), _scalar(_dyn(e, "idx")),
        )),
        (E.Reinterpret, lambda e: ("reinterp", _dyn(e, "from_bits"), _dyn(e, "to_bits"), _expr_key(_dyn(e, "operand")))),
        (E.Extract, lambda e: ("extract", _dyn(e, "bit_offset"), _dyn(e, "bits"), _expr_key(_dyn(e, "operand")))),
        (E.Insert, lambda e: ("insert", _expr_key(_dyn(e, "src")), _expr_key(_dyn(e, "dst")))),
        (E.ITE, lambda e: ("ite", _expr_key(_dyn(e, "cond")), _expr_key(_dyn(e, "iftrue")), _expr_key(_dyn(e, "iffalse")))),
        (E.Call, _call),
        (E.Phi, _phi),
        # generic Expression fallback last: only 'Reference' (pykind 6) admitted
        (ailment.Expr.Expression, _reference_key),
    )


@cython.ccall
def _reference_key(expr: object) -> AllocationStructuralKey:
    inner: object
    # rustylib 'Reference' expression: kind tag verified against pykind
    if _dyn(expr, "pykind") != 6:
        raise AllocationFingerprintRefusal(f"unsupported expression form pykind={_dyn(expr, 'pykind')}")
    inner = _dyn(expr, "expr")
    if inner is None:
        inner = _dyn(expr, "operand")
    if inner is None:
        raise AllocationFingerprintRefusal("reference expression without operand")
    return ("ref", _expr_key(inner), _scalar(_dyn(expr, "idx")))


_EXPR_KEYERS = _register_expr_keyers()


@cython.ccall
def _expr_key(expr: object) -> AllocationStructuralKey:
    """Full recursive structural key for a native AIL expression."""
    expr_cls: object
    keyer: object
    for expr_cls, keyer in _EXPR_KEYERS:
        if isinstance(expr, expr_cls):
            return keyer(expr)
    raise AllocationFingerprintRefusal(f"unsupported expression form {type(expr).__name__}/{_dyn(expr, 'pykind')}")


def _register_stmt_keyers() -> tuple[tuple[type[Any], Callable[[object], AllocationStructuralKey]], ...]:
    S = ailment.Stmt

    def _cjump(stmt: object) -> AllocationStructuralKey:
        return (
            "cjump", _dyn(stmt, "ins_addr"), _scalar(_dyn(stmt, "idx")), _expr_key(_dyn(stmt, "condition")),
            _expr_key(_dyn(stmt, "true_target")) if _dyn(stmt, "true_target") is not None else None,
            _expr_key(_dyn(stmt, "false_target")) if _dyn(stmt, "false_target") is not None else None,
        )

    def _cas(stmt: object) -> AllocationStructuralKey:
        return (
            "cas", _dyn(stmt, "ins_addr"), _scalar(_dyn(stmt, "idx")),
            tuple(
                _expr_key(e)
                for e in iter((_dyn(stmt, "addr"), _dyn(stmt, "data_lo"), _dyn(stmt, "data_hi"), _dyn(stmt, "expd_lo"), _dyn(stmt, "expd_hi"), _dyn(stmt, "old_lo"), _dyn(stmt, "old_hi")))
                if e is not None
            ),
        )

    def _sideeffect(stmt: object) -> AllocationStructuralKey:
        return (
            "sideeffect", _dyn(stmt, "ins_addr"), _scalar(_dyn(stmt, "idx")), _expr_key(_dyn(stmt, "expr")),
            _expr_key(_dyn(stmt, "ret_expr")) if _dyn(stmt, "ret_expr") is not None else None,
        )

    return (
        (S.Store, lambda s_: ("store", _dyn(s_, "ins_addr"), _scalar(_dyn(s_, "idx")), _expr_key(_dyn(s_, "addr")), _expr_key(_dyn(s_, "data")), _dyn(s_, "size"), _scalar(_dyn(s_, "endness")))),
        (S.Assignment, lambda s_: ("assign", _dyn(s_, "ins_addr"), _scalar(_dyn(s_, "idx")), _expr_key(_dyn(s_, "dst")), _expr_key(_dyn(s_, "src")))),
        (S.WeakAssignment, lambda s_: ("weak_assign", _dyn(s_, "ins_addr"), _scalar(_dyn(s_, "idx")), _expr_key(_dyn(s_, "dst")), _expr_key(_dyn(s_, "src")))),
        (S.ConditionalJump, _cjump),
        (S.Jump, lambda s_: ("jump", _dyn(s_, "ins_addr"), _scalar(_dyn(s_, "idx")), _expr_key(_dyn(s_, "target")))),
        (S.Return, lambda s_: ("return", _dyn(s_, "ins_addr"), _scalar(_dyn(s_, "idx")), tuple(_expr_key(e) for e in iter((_dyn(s_, "ret_exprs") or ()))))),
        (S.Label, lambda s_: ("label", _dyn(s_, "ins_addr"), _scalar(_dyn(s_, "idx")), _dyn(s_, "name"), _dyn(s_, "block_idx"))),
        (S.CAS, _cas),
        (S.SideEffectStatement, _sideeffect),
        (S.NoOp, lambda s_: ("noop", _dyn(s_, "ins_addr"), _scalar(_dyn(s_, "idx")))),
        (S.DirtyStatement, lambda s_: ("dirty", _dyn(s_, "ins_addr"), _scalar(_dyn(s_, "idx")), _scalar(_dyn(s_, "cee")))),
    )


_STMT_KEYERS = _register_stmt_keyers()


@cython.ccall
def _stmt_key(stmt: object) -> AllocationStructuralKey:
    """Full structural key for a native AIL statement including operands."""
    keyer: object
    stmt_cls: object
    for stmt_cls, keyer in _STMT_KEYERS:
        if isinstance(stmt, stmt_cls):
            return keyer(stmt)
    raise AllocationFingerprintRefusal(f"unsupported statement form {type(stmt).__name__}/{_dyn(stmt, 'pykind')}")


def _calling_convention_key(cc: object) -> AllocationStructuralKey | None:
    """Relevant calling-convention fields (arch, stack delta, arg registers)."""
    arch: object
    if cc is None:
        return None
    arch = _dyn(cc, "arch")
    return (
        type(cc).__name__,
        _scalar(_dyn(arch, "name")) if arch is not None else None,
        _dyn(cc, "sp_delta"),
        tuple(_scalar(a) for a in iter((_dyn(cc, "ARGS") or ()))),
        tuple(_scalar(a) for a in iter((_dyn(cc, "FP_ARGS") or ()))),
    )


class _NativeGraphBlock8616(typing.Protocol):
    """Installed AIL block input consumed by the structural graph owner."""

    addr: cython.longlong
    idx: int | None
    statements: object


class _NativeGraph8616(typing.Protocol):
    """Installed graph iteration without changing a live Clinic surface."""

    def __iter__(self) -> Iterator[_NativeGraphBlock8616]:
        """Visit supplied native blocks."""
        ...

    def edges(self, *, data: Literal[True]) -> Iterable[tuple[_NativeGraphBlock8616, _NativeGraphBlock8616, dict[str, object]]]:
        """Visit typed native edges and their structural metadata."""
        ...


def fingerprint_allocation_graph_8616(graph: object) -> tuple[AllocationGraphNodes, AllocationGraphEdges]:
    """Read exactly the supplied raw graph without swapping a live Clinic."""
    data: object
    destination: object
    source: object
    if graph is None:
        return (), ()
    native = typing.cast(_NativeGraph8616, graph)
    nodes = [(block.addr, block.idx, tuple(_stmt_key(stmt) for stmt in iter(block.statements))) for block in iter(native)]
    nodes.sort(key=lambda row: (row[0], -1 if row[1] is None else row[1]))
    edges = []
    for source, destination, data in native.edges(data=True):
        metadata = tuple(sorted((name, _scalar(value)) for name, value in builtins.iter(data.items())))
        edges.append(((source.addr, source.idx), (destination.addr, destination.idx), metadata))
    edges.sort(key=lambda row: (row[0][0], row[1][0]))
    return tuple(nodes), tuple(edges)


def fingerprint_allocation_inputs(
    clinic: Clinic, *, include_graph: cython.bint = True
) -> AllocationInputFingerprint:
    """Capture the typed structural inputs the native allocator consumes.

    ``include_graph`` binds the AIL input graph itself; use
    ``include_graph=False`` for the evidence-only projection (types, args,
    hints, prototype, calling convention) that can still be compared after
    the stage has consumed and rewritten the graph into output.

    Raises AllocationFingerprintRefusal for unsupported native forms rather
    than collapsing them into a generic bucket.
    """
    graph: object
    var: object
    func = clinic.function
    graph = clinic._ail_graph if include_graph else None
    if include_graph and graph is None:
        raise AllocationFingerprintRefusal("native recovery input graph unavailable")
    nodes, edges = fingerprint_allocation_graph_8616(graph)

    arg_vvars = tuple(
        sorted(
            (
                varid,
                _variable_key(var),
                tuple(_scalar(x) for x in iter((_dyn(vvar, "oident") or ()))),
                _dyn(vvar, "bits"),
            )
            for varid, (vvar, var) in builtins.iter((clinic.arg_vvars or {}).items())
        )
    )
    vvar_to_vvar = tuple(sorted(tuple((clinic.vvar_to_vvar or {}).items())))

    manual: list[tuple[NativeVariableKey, AllocationStructuralKey]] = []
    var_manager = clinic.project.kb.dec_variables[func.addr]
    for var in var_manager.variables_with_manual_types:
        if var in var_manager.variable_to_types:
            manual.append((_variable_key(var), _type_key(var_manager.variable_to_types[var])))
    manual_types = tuple(sorted(manual, key=lambda item: (item[0].ident or "",)))

    stack_items = tuple(
        sorted(
            (offset, item.name, item.size, item.item_type.name)
            for offset, item in builtins.iter((clinic.stack_items or {}).items())
        )
    )

    prototype = None
    if func.prototype is not None:
        prototype = (
            tuple(_type_key(a) for a in iter(func.prototype.args)),
            _type_key(func.prototype.returnty),
            tuple(func.prototype.arg_names or ()),
            bool(_dyn(func.prototype, "variadic")),
            _scalar(func.prototype_libname),
            _scalar(func.prototype_source),
            bool(func.is_prototype_guessed),
        )

    entry = clinic.entry_node_addr
    entry_key = (entry[0], entry[1]) if isinstance(entry, tuple) else _scalar(entry)

    return AllocationInputFingerprint(
        function_addr=func.addr,
        argument_variables=tuple(_variable_key(v) for v in iter((clinic.arg_list or ()))),
        argument_vvars=arg_vvars,
        vvar_to_vvar=vvar_to_vvar,
        type_hints=tuple(sorted(_type_hint_key(loc, hint) for loc, hint in iter((clinic._type_hints or ())))),
        manual_types=manual_types,
        stack_items=stack_items,
        prototype=prototype,
        calling_convention=_calling_convention_key(func.calling_convention),
        entry_node=entry_key,
        graph_nodes=tuple(nodes),
        graph_edges=tuple(edges),
    )


@cython.ccall
def _type_hint_key(loc: object, hint: object) -> tuple[str, str]:
    """Key a type-hint location without text matching.

    Only vvar ids and integer memory addr/offset forms are supported; anything
    else is an explicit fingerprint refusal rather than a None-collision.
    """
    varid = _dyn(loc, "varid")
    if isinstance(varid, int):
        return (f"vvar:{varid}", hint)
    addr = _dyn(loc, "addr")
    offset = _dyn(loc, "offset")
    if isinstance(addr, int) and isinstance(offset, int):
        return (f"mem:{addr}:{offset}", hint)
    raise AllocationFingerprintRefusal(f"unsupported type-hint location {type(loc).__name__}")


if typing.TYPE_CHECKING:
    class _NativeBlockWalker8616:
        """Typed installed walker boundary; native dispatch supplies callbacks."""

        def walk(self, block: object) -> object:
            """Visit an installed native AIL block."""
            ...
else:
    # Installed third-party walker has no complete static class declaration.
    _NativeBlockWalker8616 = ailment.AILBlockWalker


class _VariableNamingSurface8616(typing.Protocol):
    """Native names can be unset, including before allocator naming."""

    name: object
    renamed: cython.bint


class _AtomIndexCollector(_NativeBlockWalker8616):
    """Collect every atom .idx and vvar id present in the published graph."""

    def __init__(self) -> None:
        super().__init__()
        self.atom_idxs: set[cython.longlong] = set()
        self.vvar_ids: set[cython.longlong] = set()

    def _top(self, expr_idx: cython.longlong, expr: object, stmt_idx: cython.longlong, stmt: object, block: object) -> None:
        idx = _dyn(expr, "idx")
        if isinstance(idx, int):
            self.atom_idxs.add(idx)
        varid = _dyn(expr, "varid")
        if isinstance(varid, int):
            self.vvar_ids.add(varid)
        return None

    def _stmt_top(self, stmt_idx: cython.longlong, stmt: object, block: object) -> None:
        idx = _dyn(stmt, "idx")
        if isinstance(idx, int):
            self.atom_idxs.add(idx)
        return None

    def _handle_block_end(self, stmt_results: object, block: object) -> object:
        return block


@cython.dataclasses.dataclass()
class NativeAllocationCheckpoint:
    """Full native checkpoint covering every surface the stage mutates.

    ``variable_names`` snapshots the (name, renamed) fields of every variable
    in the pre-run manager plus argument variables: a failed rerun renames the
    same variable objects via unification/naming, and shallow dict copies alone
    would not undo that in-place mutation.
    """

    manager: VariableManagerInternal | None
    global_manager: VariableManagerInternal
    variable_map_maps: object
    variable_names: object
    manual_type_copies: object
    ail_graph: DiGraph
    arg_vvars: object
    vvar_to_vvar: object
    arg_list: object
    stack_items: object
    prototype: SimTypeFunction | None
    prototype_source: PrototypeSource
    prototype_libname: object
    variables_recovered: cython.bint
    typehoon: Typehoon | None
    has_typehoon: cython.bint


@cython.ccall
def capture_native_checkpoint(project: Project, clinic: Clinic) -> NativeAllocationCheckpoint:
    """Snapshot manager, link map, graph and prototype before a rerun."""
    manager: object
    func = clinic.function
    plugin = project.kb.dec_variables
    vmap = clinic.variable_map
    maps = {name: dict(_dyn(vmap, name) or {}) for name in iter(_VMAP_IDX_MAPS + _VMAP_VVAR_MAPS)}
    manager = plugin.function_managers.get(func.addr)
    ail_graph = clinic.copy_graph(clinic._ail_graph)
    names: list[tuple[SimVariable, str | None, cython.bint]] = []
    if manager is not None:
        names += [(v, v.name, v.renamed) for v in iter(manager._variables)]
    names += [(v, v.name, v.renamed) for v in iter((clinic.arg_list or ())) if isinstance(v, SimVariable)]
    # SimType objects are mutable in place (e.g. .signed); deep-copy manual-type
    # and prototype evidence so a partial run cannot corrupt the checkpoint
    manual_type_copies: list[tuple[SimVariable, SimType]] = []
    if manager is not None:
        manual_type_copies = [
            (v, copy.deepcopy(manager.variable_to_types[v]))
            for v in iter(manager.variables_with_manual_types)
            if v in manager.variable_to_types
        ]
    return NativeAllocationCheckpoint(
        manager=manager,
        manual_type_copies=manual_type_copies,
        global_manager=plugin.global_manager,
        variable_map_maps=maps,
        variable_names=names,
        ail_graph=ail_graph,
        arg_vvars=dict(clinic.arg_vvars or {}),
        vvar_to_vvar=dict(clinic.vvar_to_vvar or {}),
        arg_list=list(clinic.arg_list or ()),
        stack_items=dict(clinic.stack_items or {}),
        prototype=copy.deepcopy(func.prototype) if func.prototype is not None else None,
        prototype_source=func.prototype_source,
        prototype_libname=func.prototype_libname,
        variables_recovered=bool(_dyn(clinic, "_variables_recovered")),
        typehoon=_dyn(clinic, "typehoon"),
        has_typehoon=hasattr(clinic, "typehoon"),
    )


@cython.ccall
def restore_native_checkpoint(project: Project, clinic: Clinic, cp: NativeAllocationCheckpoint) -> None:
    """Reinstate every snapshotted native surface after a failed rerun."""
    mapping: object
    name: object
    original_name: object
    renamed: object
    ty: object
    var: object
    func = clinic.function
    plugin = project.kb.dec_variables
    if cp.manager is None:
        plugin.function_managers.pop(func.addr, None)
    else:
        plugin.function_managers[func.addr] = cp.manager
    plugin.global_manager = cp.global_manager
    vmap = clinic.variable_map
    for name, mapping in cp.variable_map_maps.items():
        # dynamic third-party boundary: map names selected from _VMAP_*_MAPS
        setattr(vmap, name, dict(mapping))
    clinic._ail_graph = cp.ail_graph
    clinic.arg_vvars = dict(cp.arg_vvars)
    clinic.vvar_to_vvar = dict(cp.vvar_to_vvar)
    clinic.arg_list = list(cp.arg_list)
    clinic.stack_items = dict(cp.stack_items)
    for var, original_name, renamed in cp.variable_names:
        naming = typing.cast(_VariableNamingSurface8616, var)
        naming.name = original_name
        naming.renamed = renamed
    if cp.manager is not None:
        for var, ty in cp.manual_type_copies:
            cp.manager.variable_to_types[var] = ty
    func.prototype = cp.prototype
    func.prototype_source = cp.prototype_source
    func.prototype_libname = cp.prototype_libname
    clinic._variables_recovered = cp.variables_recovered
    if cp.has_typehoon:
        clinic.typehoon = cp.typehoon
    elif hasattr(clinic, "typehoon"):
        del clinic.typehoon


@cython.ccall
def reset_function_variables(project: Project, func_addr: cython.longlong) -> cython.longlong:
    """Drop the function's dec_variables manager; re-apply manual-type evidence.

    Returns the number of preserved manual types.
    """
    name: object
    old: object
    ty: object
    renamed: object
    var: object
    plugin: DecompilationVariableManager = project.kb.dec_variables
    old = plugin.function_managers.get(func_addr)
    preserved: list[tuple[SimVariable, SimType, str | None, cython.bint]] = []
    if old is not None:
        for var in old.variables_with_manual_types:
            ty = old.variable_to_types.get(var)
            if ty is not None:
                preserved.append((var, ty, var.name, var.renamed))
    if func_addr in plugin.function_managers:
        del plugin.function_managers[func_addr]
    new_manager = plugin.get_function_manager(func_addr)
    for var, ty, name, renamed in preserved:
        new_manager.set_variable_type(var, ty, mark_manual=True)
        if name is not None:
            naming = typing.cast(_VariableNamingSurface8616, var)
            naming.name = name
            naming.renamed = renamed
    return len(preserved)


@cython.ccall
def prune_unpublished_links(clinic: Clinic) -> cython.longlong:
    """Drop link-map entries whose atom/vvar no longer exists in the graph."""
    block: object
    key: object
    name: object
    collector = _AtomIndexCollector()
    for block in clinic._ail_graph or ():
        collector.walk(block)
    surviving = collector.atom_idxs
    surviving_varids = collector.vvar_ids | set(clinic.arg_vvars or ())
    vmap = clinic.variable_map
    dropped = 0
    for name in _VMAP_IDX_MAPS:
        mapping = _dyn(vmap, name)
        if isinstance(mapping, dict):
            for key in list(mapping):
                if isinstance(key, int) and key not in surviving:
                    del mapping[key]
                    dropped += 1
    for name in _VMAP_VVAR_MAPS:
        mapping = _dyn(vmap, name)
        if isinstance(mapping, dict):
            for key in list(mapping):
                if isinstance(key, int) and key not in surviving_varids:
                    del mapping[key]
                    dropped += 1
    return dropped


@cython.ccall
def _publication_keyers_8616() -> NativeAllocationKeyers8616:
    """Use the canonical input serializers to seal native publication values."""
    return NativeAllocationKeyers8616(
        _variable_key, _type_key, _expr_key, _calling_convention_key,
    )


@cython.ccall
def published_handle(
    project: Project, func_addr: cython.longlong, clinic: Clinic, *, input_graph: object,
) -> NativeAllocationPublication8616:
    """Bind published objects and contents to the detached raw input consumed."""
    manager: object
    manager = project.kb.dec_variables.function_managers.get(func_addr)
    if manager is None:
        raise AllocationFingerprintRefusal("recovery published no native variable manager")
    records = native_publication_records_8616(
        manager, clinic.variable_map, _VMAP_IDX_MAPS + _VMAP_VVAR_MAPS,
        _publication_keyers_8616(),
    )
    return NativeAllocationPublication8616(
        manager, clinic.variable_map, clinic._ail_graph, input_graph, records,
    )


@cython.ccall
def publication_generation_current_8616(
    project: Project, func_addr: cython.longlong, clinic: Clinic, handle: object,
) -> cython.bint:
    """Check the native manager, map and graph generation before content reuse."""
    return (
        isinstance(handle, NativeAllocationPublication8616)
        and project.kb.dec_variables.function_managers.get(func_addr) is handle.manager
        and clinic.variable_map is handle.variable_map
        and clinic._ail_graph is handle.graph
    )


@cython.ccall
def accepted_publication_bound(
    project: Project, func_addr: cython.longlong, clinic: Clinic, handle: object,
) -> cython.bint:
    """Require the live generation AND every sealed manager/link projection."""
    if not isinstance(handle, NativeAllocationPublication8616):
        return False
    if not publication_generation_current_8616(project, func_addr, clinic, handle):
        return False
    current = native_publication_records_8616(
        handle.manager, clinic.variable_map, _VMAP_IDX_MAPS + _VMAP_VVAR_MAPS,
        _publication_keyers_8616(),
    )
    return operator.eq(current, handle.records)


@cython.ccall
def copy_input_graph(
    clinic: Clinic, *, handle: object = None,
    entry: AllocationInputFingerprint | None = None,
    accepted_output: AllocationInputFingerprint | None = None,
) -> object:
    """Retain raw graph input across same-generation non-graph revisions.

    A previously published output graph is not raw input. When its structural
    content is unchanged, recover from the saved raw graph with revised type
    evidence. A genuinely different supplied graph is a new allocator input.
    """
    source = clinic._ail_graph
    if not isinstance(handle, NativeAllocationPublication8616):
        return clinic.copy_graph(source)
    if entry is None or accepted_output is None:
        return clinic.copy_graph(source)
    same_generation = clinic._ail_graph is handle.graph and clinic.variable_map is handle.variable_map
    same_content = (
        operator.eq(entry.graph_nodes, accepted_output.graph_nodes)
        and operator.eq(entry.graph_edges, accepted_output.graph_edges)
    )
    if same_generation and same_content:
        source = typing.cast("DiGraph | None", handle.input_graph)
    return clinic.copy_graph(source)


@cython.ccall
def install_input_graph(clinic: Clinic, graph: object) -> None:
    """Replace the clinic's AIL graph with a fresh copy of retained raw input."""
    clinic._ail_graph = clinic.copy_graph(graph)


@cython.ccall
def output_surface_counts(project: Project, func_addr: cython.longlong, clinic: Clinic) -> tuple[cython.longlong, cython.longlong]:
    """(variable count, link count) currently published for the function."""
    manager: object
    plugin = project.kb.dec_variables
    manager = plugin.function_managers.get(func_addr)
    n_vars = len(manager._variables) if manager is not None else 0
    n_links = len(_dyn(clinic.variable_map, "_variables") or {})
    return n_vars, n_links

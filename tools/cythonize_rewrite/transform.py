"""Layer: Tooling/cythonize.

Responsibility: lossless libcst rewrite of plain Python into Cython pure-mode
annotated Python. The output stays valid CPython (the ``cython`` wheel shim
makes every annotation/decorator inert when interpreted) and compiles to
native code when cythonized.

Transformations applied per module (driven by ``manifest.json`` from
``census.py``):

- ``# cython: infer_types=True`` header directive.
- ``import cython`` injected after ``__future__`` imports.
- Module-level and ``cdef class`` methods: ``@cython.ccall`` (cpdef). Skipped
  for dunders, generators, async, nested functions and decorated functions.
- ``@cython.cclass`` on eligible classes; harvested ``self.<attr>`` writes
  are injected as typed class-level declarations.
- ``@dataclass`` → ``@cython.dataclasses.dataclass`` on eligible classes.
- Annotation remap at every site — params, returns, function locals,
  class attributes (cclass or dynamic), module-level ``x: T``, and the
  first arg of ``cast``/``declare``-family calls: ``int``→``cython.longlong``,
  ``float``→``cython.double``, ``bool``→``cython.bint``,
  ``complex``→``cython.doublecomplex``, applied recursively inside
  subscripts.  ``Optional[...]`` and ``X | Y`` unions keep Python types
  (Cython rejects C types there); containers and ``str``/``bytes`` stay
  bare — they are already the native Cython spellings.
- ``type X = Y`` (PEP 695) → ``X = typing.TypeAliasType("X", Y)``: eager
  evaluation, so ``__value__``/``__type_params__``/subscription semantics
  match the statement exactly (a lazy callable would leave ``__value__``
  as the thunk).  ``X[K, V]`` params become injected ``typing.TypeVar``
  names passed via ``type_params=``.  Aliases whose RHS references a name
  bound only *later* in the module rely on PEP-695 laziness — those keep
  the ``type`` statement and degrade to interpreted ``.py`` fallback like
  PEP-810 ``lazy import`` modules.
"""

from __future__ import annotations

import libcst as cst

DIRECTIVE = "# cython: language_level=3, infer_types=True"

# arg/local/return/module annotations that map to native C types.  Only
# names exported by the ``cython`` shim qualify; containers (``list``,
# ``dict``, ``tuple``, ``set``, ``frozenset``) and ``str``/``bytes`` stay
# bare — Cython already types them natively and the shim has no
# ``cython.list``-style exports.
_NATIVE = {
    "int": "longlong",
    "float": "double",
    "bool": "bint",
    "complex": "doublecomplex",
}

# subscript heads whose arguments must keep Python types: ``Optional[X]``
# and ``X | Y`` are hard Cython errors when X is a C type.  ``Union``
# accepts C-type members, so it is *not* listed here.
_UNION_HEADS = {
    "Optional", "typing.Optional", "typing_extensions.Optional",
}

# call heads whose first argument is a type position worth remapping.
# Call heads whose first argument is resolved at *compile* time by Cython's
# cython-module magic, so native type names are safe there. ``typing.cast``
# is deliberately absent: its arguments are evaluated at runtime, and
# ``import cython`` creates no runtime ``cython`` binding in compiled
# modules — ``cast(cython.longlong, x)`` raises NameError under an
# extension build.  Plain ``int``/``float`` stay correct in both modes
# because ``typing.cast`` is an identity function.
_TYPED_CALL_HEADS = {"cython.cast", "cython.declare"}

# Runtime-evaluated cast heads: first args here must keep builtin names.
_RUNTIME_CAST_HEADS = {"cast", "typing.cast", "typing_extensions.cast"}

_NATIVE_INV = {v: k for k, v in _NATIVE.items()}

# decorators on a function that forbid turning it into a cpdef callable.
_BLOCK_FDECO = frozenset(
    {
        "property", "staticmethod", "classmethod", "contextmanager",
        "asynccontextmanager", "overload", "abstractmethod", "cache",
        "lru_cache", "cached_property", "wraps", "setter", "deleter",
        "cfunc", "ccall", "locals", "cclass", "cython.cfunc",
        "cython.ccall", "cython.locals", "typing.overload",
        "abc.abstractmethod", "contextlib.contextmanager",
        "functools.lru_cache", "functools.cache", "functools.wraps",
        "dataclasses.dataclass", "cython.dataclasses.dataclass",
    }
)

_DATACLASS_DECO = {"dataclass", "dataclasses.dataclass", "cython.dataclasses.dataclass"}

# cython decorators that make a function a cdef/cpdef callable.
_CALL_DECO = {"cython.ccall", "ccall", "cython.cfunc", "cfunc"}


def _deco_name(dec: cst.Decorator) -> str:
    """Dotted name of a decorator node (``a.b.c``), '' when non-name."""
    node = dec.decorator
    if isinstance(node, cst.Call):
        node = node.func
    parts: list[str] = []
    while isinstance(node, cst.Attribute):
        parts.append(node.attr.value)
        node = node.value
    if isinstance(node, cst.Name):
        parts.append(node.value)
        return ".".join(reversed(parts))
    return ""


def _attr(expr: cst.BaseExpression, name: str) -> cst.Attribute:
    """``expr.name`` attribute access node."""
    return cst.Attribute(value=expr, attr=cst.Name(name))


def _frozen_dataclass_dec(dec: cst.Decorator) -> bool:
    """True when a dataclass decorator passes a truthy ``frozen=``."""
    inner = dec.decorator
    if not isinstance(inner, cst.Call):
        return False
    for arg in inner.args:
        if (
            arg.keyword is not None
            and arg.keyword.value == "frozen"
            and isinstance(arg.value, cst.Name)
            and arg.value.value == "True"
        ):
            return True
    return False


def _cy(name: str) -> cst.Attribute:
    """``cython.<name>`` expression node (``name`` may be ``a.b`` dotted)."""
    expr: cst.BaseExpression = cst.Name("cython")
    for part in name.split("."):
        expr = cst.Attribute(value=expr, attr=cst.Name(part))
    return expr  # type: ignore[return-value]


def _map_ann_expr(node: cst.BaseExpression) -> cst.BaseExpression:
    """Recursively remap native scalar names inside an annotation expr.

    ``int``/``float``/``bool``/``complex`` become ``cython.<C type>`` at
    every nesting level — including inside ``list[...]``/``dict[...]``/
    ``tuple[...]``/``Callable[...]`` subscripts.  Two subtrees keep Python
    types: ``Optional[...]``/``Union[...]`` heads and ``X | Y`` unions —
    Cython cannot apply those constructs to C types and rejects them.
    """
    if isinstance(node, cst.Name) and node.value in _NATIVE:
        return _cy(_NATIVE[node.value])
    if isinstance(node, cst.Subscript):
        if _ann_head(node) in _UNION_HEADS:
            return node
        changed = False
        new_slice: list[cst.SubscriptElement] = []
        for el in node.slice:
            if isinstance(el.slice, cst.Index):
                nv = _map_ann_expr(el.slice.value)
                if nv is not el.slice.value:
                    el = el.with_changes(
                        slice=el.slice.with_changes(value=nv)
                    )
                    changed = True
            new_slice.append(el)
        if changed:
            return node.with_changes(slice=new_slice)
    return node


def _map_annotation(
    ann: cst.Annotation | None, *, allow_native: bool = True
) -> cst.Annotation | None:
    """Rewrite native scalar annotations to cython types, recursively.

    Anything not matching is returned unchanged so the source keeps its
    readable hint while Cython treats it as an object-typed slot.
    """
    if ann is None or not allow_native:
        return ann
    mapped = _map_ann_expr(ann.annotation)
    if mapped is not ann.annotation:
        return cst.Annotation(mapped)
    return ann


def _attr_decl_type(hints: list[str]) -> cst.BaseExpression:
    """Pick a declaration type for a harvested ``self.<attr>`` write set."""
    kinds = set(hints)
    kinds.discard("")
    if kinds == {"int"}:
        return _cy("longlong")
    if kinds == {"float"}:
        return _cy("double")
    if kinds == {"bool"}:
        return _cy("bint")
    if kinds == {"complex"}:
        return _cy("doublecomplex")
    if len(kinds) == 1 and kinds <= {
        "str", "bytes", "list", "dict", "set", "tuple", "frozenset",
        "bytearray",
    }:
        return cst.Name(kinds.pop())
    return cst.Name("object")


_DECL_TYPE_NAMES = {
    "object", "str", "bytes", "list", "dict", "set", "tuple", "frozenset",
    "bytearray",
}

_DECL_SKIP_HEADS = {"ClassVar", "Final", "ClassMethod", "StaticMethod"}


def _declare_type(ann: cst.BaseExpression) -> cst.BaseExpression:
    """Pick the ``cython.declare`` type argument for a class annotation.

    Scalar builtins keep native C types (``int`` → ``long long`` field,
    value-coerced so subclasses/enums pass).  Exact builtins
    (``dict``/``str``/``tuple``/…) degrade to ``object`` — ``declare(dict)``
    enforces ``CheckExact`` and would reject ``defaultdict`` that plain
    attributes accept.  Arbitrary class names likewise stay ``object``
    (a typed ``declare(SomeClass)`` adds a check plain attrs never had).
    """
    if isinstance(ann, cst.Name):
        if ann.value in _NATIVE:
            return _cy(_NATIVE[ann.value])
        return cst.Name("object")
    if (
        isinstance(ann, cst.Attribute)
        and isinstance(ann.value, cst.Name)
        and ann.value.value == "cython"
    ):
        return ann
    return cst.Name("object")


def _declare_convertible(ann: cst.BaseExpression) -> bool:
    """Whether a bare ``name: ann`` line may become an instance-attr declare.

    ``ClassVar``/``Final`` annotations describe class-level semantics, not
    instance attributes; converting them would invent attributes that do
    not exist under plain Python.
    """
    return _dotted_tail(ann) not in _DECL_SKIP_HEADS


def _attr_declare_stmt(name: str, ty: cst.BaseExpression) -> cst.SimpleStatementLine:
    """``name = cython.declare(ty, visibility="public")`` — a cclass instance
    attribute that stays Python-visible in both modes.

    Bare ``name: T`` annotations inside a cclass compile to *private* C
    attributes: any access that loses static type information (lists,
    dicts, cross-module getattr, plain callers) raises AttributeError.
    """
    return cst.SimpleStatementLine(
        body=[
            cst.Assign(
                targets=[cst.AssignTarget(cst.Name(name))],
                value=cst.Call(
                    func=_cy("declare"),
                    args=[
                        cst.Arg(ty),
                        cst.Arg(
                            cst.SimpleString('"public"'),
                            keyword=cst.Name("visibility"),
                        ),
                    ],
                ),
            )
        ]
    )


class _Scope:
    """Lexical scope frame for the transformer."""

    __slots__ = ("kind", "name", "cclass", "declared", "existing_fields", "del_names", "ann_names", "none_names", "bound_seen", "declare_names", "for_targets")

    def __init__(
        self,
        kind: str,
        name: str = "",
        cclass: bool = False,
    ) -> None:
        self.kind = kind  # 'class' | 'func'
        self.name = name
        self.cclass = cclass
        self.declared: set[str] = set()
        self.existing_fields: set[str] = set()
        self.del_names: set[str] = set()
        self.ann_names: set[str] = set()
        self.none_names: set[str] = set()
        # names bound so far (filled in post-order) — a later ``x: T``
        # annotation on any of them is a cython redeclaration.
        self.bound_seen: set[str] = set()
        # names bound via ``x = cython.declare(T, ...)`` — the declare is
        # the decl; a parallel ``x: object`` is a redeclaration.
        self.declare_names: set[str] = set()
        # ``for``-target names needing an ``x: object`` top decl — blocks
        # infer_types mistyping the loop var as the container type.
        self.for_targets: set[str] = set()


def mixin_demoted_class_names(modules: dict) -> dict[str, set[str]]:
    """Per-module class names that must stay plain Python classes.

    A class used as one of several bases in a multiple-inheritance class
    may not be an extension type: CPython raises ``multiple bases have
    instance lay-out conflict`` when more than one cdef-class base is
    present.  Demote every such base — the child class stays fully
    dynamic and inherits the ordinary Python layout as before.
    Cross-module base names resolve to every module defining a class of
    that name (over-demotion is safe: a dynamic class keeps semantics).
    """
    # map a class's bare name -> [(module, cclass-flag)] candidates
    defined: dict[str, list[tuple[str, bool]]] = {}
    for mod, rec in modules.items():
        for qual, c in rec.get("classes", {}).items():
            defined.setdefault(qual.rpartition(".")[-1], []).append(
                (mod, bool(c.get("cclass")))
            )

    def head(src: str) -> str:
        s = src.strip()
        for ch in ("[", "(", " "):
            s = s.split(ch)[0]
        return s.rsplit(".", 1)[-1]

    demoted: dict[str, set[str]] = {}
    for mod, rec in modules.items():
        own = {
            q.rpartition(".")[-1]: c for q, c in rec.get("classes", {}).items()
        }
        for c in rec.get("classes", {}).values():
            bases = c.get("bases", [])
            if len(bases) < 2:
                continue
            solid: list[tuple[str, str]] = []
            for b in bases:
                h = head(b)
                if not h:
                    continue
                if h in own:
                    if own[h].get("cclass"):
                        solid.append((h, mod))
                else:
                    solid.extend(
                        (h, m) for m, cc in defined.get(h, []) if cc
                    )
            # two or more extension-type bases in one class -> the MI
            # child cannot construct a layout; demote all of them.
            if len(solid) >= 2:
                for h, m in solid:
                    demoted.setdefault(m, set()).add(h)
    return demoted


def _cclass_override_conflicts(module_record: dict) -> set[tuple[str, str]]:
    """``(qualname, method)`` pairs that must not become cpdef callables.

    A cpdef method overriding a same-module cclass ancestor's cpdef must
    carry an identical signature — Cython reports ``Signature not
    compatible with previous declaration`` otherwise.  Stripping *both*
    defs keeps a clean Python override; dropping only the subclass's cpdef
    would leave the base vtable entry dispatching to the wrong impl.
    Cross-module ancestors are not resolvable here and are left to the
    compile-error repair loop.
    """
    classes = module_record.get("classes", {})

    def head(src: str) -> str:
        s = src.strip()
        for ch in ("[", "(", " "):
            s = s.split(ch)[0]
        return s.rsplit(".", 1)[-1]

    conflicts: set[tuple[str, str]] = set()
    for qual, c in classes.items():
        if not c.get("cclass"):
            continue
        members = set(c.get("member_names", ()))
        seen: set[str] = set()
        stack = [head(b) for b in c.get("bases", [])]
        while stack:
            b = stack.pop()
            if b in seen or b == qual or b not in classes:
                continue
            seen.add(b)
            anc = classes[b]
            if anc.get("cclass"):
                for m in members & set(anc.get("member_names", ())):
                    conflicts.add((qual, m))
                    conflicts.add((b, m))
            stack.extend(head(x) for x in anc.get("bases", []))
    return conflicts


class _OverloadScan(cst.CSTVisitor):
    """Count own-level def names per scope — duplicates forbid cpdef."""

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.counts: dict[tuple[str, str], int] = {}
        self._fn_depth = 0

    def visit_ClassDef(self, node: cst.ClassDef) -> bool:
        """Track class qualnames for per-scope name multiplicity."""
        self.stack.append(node.name.value)
        return True

    def leave_ClassDef(self, node: cst.ClassDef) -> None:
        """Pop class scope."""
        self.stack.pop()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        """Record the def name; never descend into nested functions.

        Depth must stay balanced with ``leave_FunctionDef`` — an early
        ``return False`` still gets a leave, so returning before
        incrementing would drive the counter negative and mask every
        later def in the module.
        """
        self._fn_depth += 1
        if self._fn_depth > 1:
            return False
        key = (".".join(self.stack), node.name.value)
        self.counts[key] = self.counts.get(key, 0) + 1
        return True

    def leave_FunctionDef(self, node: cst.FunctionDef) -> None:
        """Pop function depth marker."""
        self._fn_depth -= 1

    def duplicates(self) -> set[tuple[str, str]]:
        """``(scope_qualname, def_name)`` pairs defined more than once."""
        return {k for k, n in self.counts.items() if n > 1}


class _AnnotationNameScan(cst.CSTVisitor):
    """Collect bare ``Name`` tokens used in type positions.

    PEP-695 ``[T]`` parameters stripped in an earlier pass leave behind
    annotation usages (``Callable[[], T]``, ``cast(T, ...)``) with no
    binding — Cython then reports ``undeclared name``.  Recording every
    name used inside annotations (and ``cast``/``type`` first args) lets
    the module leave-injector synthesise ``T = typing.TypeVar("T")``.
    """

    _CAST_HEADS = {"cast", "typing.cast", "typing_extensions.cast"}

    def __init__(self) -> None:
        super().__init__()
        self.names: set[str] = set()

    def _collect(self, expr: cst.BaseExpression) -> None:
        """Collect bare ``Name`` binding refs from ``expr``."""
        self.names.update(_ref_names(expr))

    def visit_Annotation(self, node: cst.Annotation) -> bool:
        self._collect(node.annotation)
        return True

    def visit_Call(self, node: cst.Call) -> bool:
        head = _expr_dotted(node.func)
        if head in self._CAST_HEADS and node.args:
            self._collect(node.args[0].value)
        return True


def _expr_dotted(expr: cst.BaseExpression) -> str:
    """Dotted name of ``a.b.c`` expressions; '' otherwise."""
    parts: list[str] = []
    node = expr
    while isinstance(node, cst.Attribute):
        parts.append(node.attr.value)
        node = node.value
    if isinstance(node, cst.Name):
        parts.append(node.value)
        return ".".join(reversed(parts))
    return ""


def _dotted_tail(expr: cst.BaseExpression) -> str:
    """Last name of a possibly-subscripted dotted expr (``a.b.C[x]`` → ``C``)."""
    node = expr
    while isinstance(node, cst.Subscript):
        node = node.value
    last = ""
    while isinstance(node, cst.Attribute):
        last = node.attr.value
        node = node.value
    if not last and isinstance(node, cst.Name):
        last = node.value
    return last


def walk(expr):  # local helper — shallow CST descendant walk
    """Yield ``expr`` and all its CST descendants."""
    stack = [expr]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _ref_names(expr: cst.CSTNode) -> set[str]:
    """Bare ``Name`` binding references under ``expr``.

    Attribute member names are excluded: ``cython.bint`` binds ``cython``
    only, ``bint`` is not a binding reference — so it must not drive
    TypeVar injection or count as an alias-RHS requirement.
    """
    names: set[str] = set()
    stack: list[cst.CSTNode] = [expr]
    while stack:
        n = stack.pop()
        if isinstance(n, cst.Attribute):
            stack.append(n.value)
            continue
        if isinstance(n, cst.Name):
            names.add(n.value)
            continue
        stack.extend(n.children)
    return names


def _expand_star_literal(node: cst.BaseExpression) -> cst.BaseExpression | None:
    """``(a, *b, c)`` → ``(a,) + tuple(b) + (c,)``; same for lists/sets.

    Returns ``None`` when ``node`` is not a spread-containing literal.
    """
    if isinstance(node, cst.Tuple):
        lit, conv = cst.Tuple, "tuple"
        op: type[cst.BaseBinaryOp] = cst.Add
    elif isinstance(node, cst.List):
        lit, conv, op = cst.List, "list", cst.Add
    elif isinstance(node, cst.Set):
        lit, conv, op = cst.Set, "set", cst.BitOr
    else:
        return None
    els = node.elements
    if not any(isinstance(e, cst.StarredElement) for e in els):
        return None
    parts: list[cst.BaseExpression] = []
    pending: list[cst.Element] = []

    def flush() -> None:
        if pending:
            parts.append(lit(elements=list(pending)))
            pending.clear()

    for e in els:
        if isinstance(e, cst.StarredElement):
            flush()
            parts.append(cst.Call(func=cst.Name(conv), args=[cst.Arg(e.value)]))
        else:
            pending.append(e)
    flush()
    expr = parts[0]
    for part in parts[1:]:
        expr = cst.BinaryOperation(left=expr, operator=op(), right=part)
    return expr


def _top_level_bound_names(module: cst.Module) -> set[str]:
    """Names bound by module-level defs, classes and assignments."""
    names: set[str] = set()
    for stmt in module.body:
        if isinstance(stmt, (cst.FunctionDef, cst.ClassDef)):
            names.add(stmt.name.value)
        elif isinstance(stmt, cst.SimpleStatementLine):
            for el in stmt.body:
                if isinstance(el, cst.Assign):
                    for t in el.targets:
                        names.update(_target_names(t.target))
                elif isinstance(el, cst.AnnAssign):
                    names.update(_target_names(el.target))
                elif isinstance(el, cst.AugAssign):
                    names.update(_target_names(el.target))
                elif isinstance(el, cst.TypeAlias):
                    names.add(el.name.value)
    return names


def _target_names(target: cst.BaseExpression) -> set[str]:
    """Names bound by an assignment target expression."""
    if isinstance(target, cst.Name):
        return {target.value}
    if isinstance(target, (cst.Tuple, cst.List)):
        out: set[str] = set()
        for el in target.elements:
            out.update(_target_names(el.value))
        return out
    return set()


def _import_bound_names(line: cst.SimpleStatementLine) -> set[str]:
    """Names bound by ``import``/``from ... import`` on one simple line."""
    names: set[str] = set()
    for el in line.body:
        if isinstance(el, cst.Import):
            for a in el.names:
                if a.asname and isinstance(a.asname.name, cst.Name):
                    names.add(a.asname.name.value)
                else:
                    names.add(_module_str(a.name).split(".")[0])
        elif isinstance(el, cst.ImportFrom):
            if isinstance(el.names, cst.ImportStar):
                continue
            for a in el.names:
                if not isinstance(a, cst.ImportAlias):
                    continue
                if a.asname and isinstance(a.asname.name, cst.Name):
                    names.add(a.asname.name.value)
                elif isinstance(a.name, cst.Name):
                    names.add(a.name.value)
    return names


def _is_type_checking_test(expr: cst.BaseExpression) -> bool:
    """``TYPE_CHECKING`` / ``typing.TYPE_CHECKING`` guard test."""
    return _expr_dotted(expr) in {"TYPE_CHECKING", "typing.TYPE_CHECKING"}


class _LateAliasScan(cst.CSTVisitor):
    """Document-order indices of ``type`` aliases that need PEP-695 laziness.

    A module-exec-time alias whose RHS mentions a name bound only *later*
    (module level or enclosing class body) must keep the ``type`` statement;
    eager ``TypeAliasType`` evaluation would raise ``NameError`` at import.
    Aliases inside function bodies bind at call time and those under a
    ``TYPE_CHECKING`` guard never execute — both are never flagged.
    ``self.late`` holds indices into the document order of every
    ``TypeAlias`` node, matching ``leave_TypeAlias``'s counting order.
    """

    def __init__(self) -> None:
        super().__init__()
        import builtins

        self.exec_stack: list[set[str] | None] = [set(dir(builtins))]
        self.func_depth = 0
        self.static_stack: list[bool] = []
        self.late: set[int] = set()
        self.count = 0

    def _bind(self, names: set[str]) -> None:
        if self.func_depth == 0 and self.exec_stack[-1] is not None:
            self.exec_stack[-1].update(names)

    def visit_ClassDef(self, node: cst.ClassDef) -> bool:
        if self.func_depth == 0:
            self.exec_stack[-1].add(node.name.value)
            self.exec_stack.append(set())
        else:
            self.exec_stack.append(None)
        return True

    def leave_ClassDef(self, node: cst.ClassDef) -> None:
        self.exec_stack.pop()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        if self.func_depth == 0:
            self.exec_stack[-1].add(node.name.value)
        self.func_depth += 1
        return True

    def leave_FunctionDef(self, node: cst.FunctionDef) -> None:
        self.func_depth -= 1

    def visit_If(self, node: cst.If) -> bool:
        self.static_stack.append(
            bool(self.static_stack and self.static_stack[-1])
            or _is_type_checking_test(node.test)
        )
        return True

    def leave_If(self, node: cst.If) -> None:
        self.static_stack.pop()

    def visit_Assign(self, node: cst.Assign) -> bool:
        names: set[str] = set()
        for t in node.targets:
            names.update(_target_names(t.target))
        self._bind(names)
        return True

    def visit_AnnAssign(self, node: cst.AnnAssign) -> bool:
        self._bind(_target_names(node.target))
        return True

    def visit_AugAssign(self, node: cst.AugAssign) -> bool:
        self._bind(_target_names(node.target))
        return True

    def visit_Import(self, node: cst.Import) -> bool:
        names: set[str] = set()
        for a in node.names:
            if a.asname and isinstance(a.asname.name, cst.Name):
                names.add(a.asname.name.value)
            else:
                names.add(_module_str(a.name).split(".")[0])
        self._bind(names)
        return True

    def visit_ImportFrom(self, node: cst.ImportFrom) -> bool:
        if not isinstance(node.names, cst.ImportStar):
            names = {
                a.asname.name.value
                if a.asname and isinstance(a.asname.name, cst.Name)
                else a.name.value
                for a in node.names
                if isinstance(a, cst.ImportAlias) and isinstance(a.name, cst.Name)
            }
            self._bind(names)
        return True

    def visit_TypeAlias(self, node: cst.TypeAlias) -> bool:
        idx = self.count
        self.count += 1
        if self.func_depth or (
            self.static_stack and self.static_stack[-1]
        ):
            return True
        params = (
            {p.param.name.value for p in node.type_parameters.params}
            if node.type_parameters is not None
            else set()
        )
        visible: set[str] = set()
        for scope in self.exec_stack:
            if scope:
                visible |= scope
        refs = _ref_names(node.value)
        if refs - visible - params:
            self.late.add(idx)
        if self.exec_stack[-1] is not None:
            self.exec_stack[-1].add(node.name.value)
        return True


class Cythonizer(cst.CSTTransformer):
    """Rewrite one module according to its census record."""

    def __init__(self, module_record: dict, stats: dict,
                 overloaded: set[tuple[str, str]] | None = None,
                 annotation_names: set[str] | None = None,
                 late_aliases: set[int] | None = None) -> None:
        super().__init__()
        self.rec = module_record
        self.stats = stats
        self.scopes: list[_Scope] = []
        self.overloaded = overloaded or set()
        self.annotation_names = annotation_names or set()
        self.late_aliases = late_aliases or set()
        self._alias_count = 0
        self._pending_cclass_decls: dict[str, cst.BaseExpression] = {}
        self._swap_dataclass = False
        self._needs_dataclasses_import = False
        self._needs_typing_import = False
        self._typevars: dict[str, str] = {}  # name -> 'TypeVar'|'TypeVarTuple'|'ParamSpec'
        self._alias_names: set[str] = set()
        self._has_future_annotations = False
        # ``iter`` binding shadow tracking: while any enclosing function
        # (or the module top level) binds ``iter``, ``iter(...)`` calls would
        # resolve to the binding, not the builtin.
        self._iter_shadow: list[bool] = []
        self._operator_shadow: list[bool] = []
        self._builtins_shadow: list[bool] = []
        self._mod_iter_bound = False
        self._mod_operator_bound = False
        self._mod_builtins_bound = False
        self._mod_for_targets: set[str] = set()
        self._mod_none_names: set[str] = set()
        self._mod_ann_names: set[str] = set()
        self._mod_bound_seen: set[str] = set()
        self._needs_operator_import = False
        self._needs_builtins_import = False

    def _iter_ok(self) -> bool:
        """True when ``iter(EXPR)`` resolves to the builtin here."""
        return not self._mod_iter_bound and not any(self._iter_shadow)

    def _builtins_ok(self) -> bool:
        """True when ``builtins.iter`` resolves to the stdlib module here."""
        return not self._mod_builtins_bound and not any(self._builtins_shadow)

    def _wrap_for_iterable(self, expr: cst.BaseExpression) -> cst.BaseExpression:
        """Wrap a ``for`` iterable in ``iter()``.

        With ``infer_types`` Cython mistypes the loop target as the
        *container* type (``tuple``-typed iterable → ``tuple`` loop var),
        inserting a runtime ``Expected tuple, got X`` coercion that fires on
        ordinary elements.  ``iter(EXPR)`` is a semantic no-op — the for
        protocol already calls it — and returns ``object``, so the loop
        variable infers ``object`` and no check is emitted.
        """
        if not self._iter_ok():
            return expr
        # Convert an earlier genexpr wrap ``(_forit for _forit in X)`` to
        # the cheaper ``builtins.iter(X)`` — same object-typed iterator.
        if (
            isinstance(expr, cst.GeneratorExp)
            and isinstance(expr.elt, cst.Name)
            and expr.elt.value == "_forit"
            and isinstance(expr.for_in.target, cst.Name)
            and expr.for_in.target.value == "_forit"
            and not expr.for_in.ifs
            and expr.for_in.inner_for_in is None
            and expr.for_in.asynchronous is None
        ):
            expr = expr.for_in.iter  # falls through to the Call branch
        elif isinstance(expr, cst.GeneratorExp):
            return expr  # object-typed already; nothing to do
        # Peel an earlier ``iter(<call>)`` wrap: that spelling crashes
        # Cython's OptimizeBuiltinCalls, so the inner call gets re-wrapped
        # as ``builtins.iter(...)`` (or a genexpr) below instead.
        while (
            isinstance(expr, cst.Call)
            and isinstance(expr.func, cst.Name)
            and expr.func.value == "iter"
            and len(expr.args) == 1
            and isinstance(expr.args[0].value, cst.Call)
        ):
            expr = expr.args[0].value
            self._bump("for_iter_peeled")
        if (
            isinstance(expr, cst.Call)
            and isinstance(expr.func, cst.Name)
            and expr.func.value in {"iter", "range"}
        ):
            return expr  # already neutral; range keeps int-index inference
        if (
            isinstance(expr, cst.Call)
            and _expr_dotted(expr.func) == "builtins.iter"
        ):
            return expr  # our own wrap — idempotent
        if isinstance(expr, cst.Call):
            # ``iter(f(...))`` crashes Cython's OptimizeBuiltinCalls
            # (MethodDispatcherTransform unsliceable): the builtin-call
            # dispatcher mishandles a call in arg position.  ``builtins.iter``
            # is an attribute call — no builtin dispatch, still returns a
            # plain ``object`` iterator so the target infers ``object``.
            # A genexpr achieves the same erasure but hits a second Cython
            # bug (bad ``__pyx_opt_args`` codegen in functions with default
            # args), so it is only the fallback when ``builtins`` is bound.
            if self._builtins_ok():
                self._needs_builtins_import = True
                self._bump("for_iter_builtins")
                return cst.Call(
                    func=cst.Attribute(
                        value=cst.Name("builtins"), attr=cst.Name("iter")
                    ),
                    args=[cst.Arg(expr)],
                )
            self._bump("for_iter_genexpr")
            return cst.GeneratorExp(
                elt=cst.Name("_forit"),
                for_in=cst.CompFor(
                    target=cst.Name("_forit"),
                    iter=expr,
                ),
                lpar=[cst.LeftParen()],
                rpar=[cst.RightParen()],
            )
        self._bump("for_iter_wrapped")
        return cst.Call(func=cst.Name("iter"), args=[cst.Arg(expr)])

    def _unwrap_for_iterable(self, expr: cst.BaseExpression) -> cst.BaseExpression:
        """Undo wrap forms this transformer emitted — the decl path needs
        no iterable protection at all."""
        if (
            isinstance(expr, cst.GeneratorExp)
            and isinstance(expr.elt, cst.Name)
            and expr.elt.value == "_forit"
            and isinstance(expr.for_in.target, cst.Name)
            and expr.for_in.target.value == "_forit"
            and not expr.for_in.ifs
            and expr.for_in.inner_for_in is None
            and expr.for_in.asynchronous is None
        ):
            self._bump("for_iter_unwrapped")
            return expr.for_in.iter
        if (
            isinstance(expr, cst.Call)
            and _expr_dotted(expr.func) == "builtins.iter"
            and len(expr.args) == 1
        ):
            self._bump("for_iter_unwrapped")
            return expr.args[0].value
        if (
            isinstance(expr, cst.Call)
            and isinstance(expr.func, cst.Name)
            and expr.func.value == "iter"
            and len(expr.args) == 1
        ):
            # ``for x in iter(y)`` ≡ ``for x in y`` — the for protocol
            # calls ``iter`` itself; restoring the bare form is identical.
            self._bump("for_iter_unwrapped")
            return expr.args[0].value
        return expr

    def leave_For(self, original: cst.For, updated: cst.For) -> cst.For:
        """Guard the plain-loop iterable against container-type inference.

        Function/module scopes use ``x: object`` top decls (injected at
        scope leave); a ``for`` directly inside a class body has no decl
        owner, so it keeps the iterable wrap instead.
        """
        self._bound_here().update(_target_names(updated.target))
        if updated.asynchronous is not None:
            return updated
        if self._inside_function() or self._in_class() is None:
            # decl path: the target's ``x: object`` decl owns protection —
            # peel leftover wrap forms (genexpr wraps break codegen inside
            # functions that have optional args).
            return updated.with_changes(
                iter=self._unwrap_for_iterable(updated.iter)
            )
        return updated.with_changes(iter=self._wrap_for_iterable(updated.iter))

    def leave_CompFor(
        self, original: cst.CompFor, updated: cst.CompFor
    ) -> cst.CompFor:
        """Guard comprehension/genexpr ``for`` iterables the same way."""
        if updated.asynchronous is not None:
            return updated
        if (
            isinstance(updated.target, cst.Name)
            and updated.target.value == "_forit"
        ):
            return updated  # our generated genexpr — never re-wrap
        return updated.with_changes(iter=self._wrap_for_iterable(updated.iter))

    def _operator_ok(self) -> bool:
        """True when ``operator.eq(...)`` resolves to the stdlib module here."""
        return not self._mod_operator_bound and not any(self._operator_shadow)

    def _none_names_here(self) -> set[str]:
        """``None``-able names for the current lexical position."""
        scope = self.scopes[-1] if self.scopes else None
        if scope is None:
            return self._mod_none_names
        return scope.none_names if scope.kind == "func" else ()

    def leave_Comparison(
        self, original: cst.Comparison, updated: cst.Comparison
    ) -> cst.BaseExpression:
        """``a == b``/``a != b`` → ``operator.eq/ne`` when coercion may bite.

        When one side is C-typed (``longlong`` local/param, inferred) and
        the other an arbitrary object, Cython coerces the object to the C
        type — ``x == maybe_none`` raises ``TypeError`` where CPython
        answers ``False``.  ``operator.eq`` performs ``PyObject_RichCompare``
        on two boxed operands: exactly CPython ``==`` semantics.

        Only ``Eq``/``NotEq`` rewrite (ordering ops raise ``TypeError`` in
        CPython too).  Literal-paired compares are already safe: a literal
        is always a ``PyObject``.  ``a == b`` with two unmarked ``Name``s
        stays native — the fast path for scalar-scalar compares.
        """
        if len(updated.comparisons) != 1:
            return updated  # chained ``a == b == c`` cannot rewrite safely
        cmp = updated.comparisons[0]
        if isinstance(cmp.operator, cst.Equal):
            op_name = "eq"
        elif isinstance(cmp.operator, cst.NotEqual):
            op_name = "ne"
        else:
            return updated
        left, right = updated.left, cmp.comparator
        if _literalish(left) or _literalish(right):
            return updated
        none_names = self._none_names_here()

        def objectish(e: cst.BaseExpression) -> bool:
            """Operand produces/may-hold an arbitrary Python object."""
            return (
                isinstance(
                    e,
                    (
                        cst.Call, cst.Subscript, cst.Attribute,
                        cst.BinaryOperation, cst.UnaryOperation,
                        cst.BooleanOperation, cst.IfExp, cst.Await,
                        cst.NamedExpr, cst.GeneratorExp, cst.ListComp,
                        cst.SetComp, cst.DictComp,
                    ),
                )
                or (isinstance(e, cst.Name) and e.value in none_names)
            )

        if not (objectish(left) or objectish(right)):
            return updated
        if not self._operator_ok():
            return updated
        self._needs_operator_import = True
        self._bump("cmp_operator")
        return cst.Call(
            func=_attr(cst.Name("operator"), op_name),
            args=[cst.Arg(left), cst.Arg(right)],
        )

    def visit_Lambda(self, node: cst.Lambda) -> bool:
        """Lambdas have their own scope — track ``iter``/``operator`` params."""
        params = node.params
        pnames = {
            p.name.value
            for plist in (params.posonly_params, params.params, params.kwonly_params)
            for p in plist
            if isinstance(p.name, cst.Name)
        }
        self._iter_shadow.append("iter" in pnames)
        self._operator_shadow.append("operator" in pnames)
        self._builtins_shadow.append("builtins" in pnames)
        return True

    def leave_Lambda(
        self, original_node: cst.Lambda, updated_node: cst.Lambda
    ) -> cst.BaseExpression:
        """Pop the lambda's shadow flags."""
        self._iter_shadow.pop()
        self._operator_shadow.pop()
        self._builtins_shadow.pop()
        return updated_node

    # -- helpers ---------------------------------------------------------

    def _class_qualname(self, name: str) -> str:
        """Manifest qualname for the class being entered."""
        parts = [s.name for s in self.scopes if s.kind == "class"]
        return ".".join([*parts, name]) if parts else name

    def _class_record(self, qualname: str) -> dict:
        """Manifest record for a class qualname (empty dict if absent)."""
        return self.rec.get("classes", {}).get(qualname, {})

    def _in_class(self) -> _Scope | None:
        """Innermost enclosing class scope, if any."""
        for s in reversed(self.scopes):
            if s.kind == "class":
                return s
        return None

    def _inside_function(self) -> bool:
        """True when currently inside any function body."""
        return any(s.kind == "func" for s in self.scopes)

    def _bump(self, key: str, n: int = 1) -> None:
        """Count a transformation in the stats dict."""
        self.stats[key] = self.stats.get(key, 0) + n

    # -- module ----------------------------------------------------------

    def visit_Module(self, node: cst.Module) -> bool:
        """Record top-level ``iter`` bindings and ``None``-compared names."""
        self._mod_iter_bound = _module_binds(node, "iter")
        self._mod_operator_bound = _module_binds(node, "operator")
        self._mod_builtins_bound = _module_binds_nonimport(node, "builtins")
        self._mod_for_targets = _mod_for_targets(
            node,
            skip_known=not (
                _module_binds(node, "range") or _module_binds(node, "enumerate")
            ),
        )
        nv = _NoneCmpScan()
        node.visit(nv)
        self._mod_none_names = nv.names
        self._mod_ann_names = {
            s.body[0].target.value
            for s in node.body
            if isinstance(s, cst.SimpleStatementLine)
            and isinstance(s.body[0], cst.AnnAssign)
            and isinstance(s.body[0].target, cst.Name)
        }
        return True

    def leave_Module(
        self, original: cst.Module, updated: cst.Module
    ) -> cst.Module:
        """Inject the cython directive header and ``import cython``."""
        header_has_directive = any(
            line.comment and "cython:" in line.comment.value
            for line in updated.header
            if line.comment
        )
        if not header_has_directive:
            header = list(updated.header)
            header.append(cst.EmptyLine(comment=cst.Comment(DIRECTIVE)))
            updated = updated.with_changes(header=header)
            self._bump("directive")

        body = list(updated.body)

        # Relocate ``X = typing.TypeVar("X")``-shaped lines (self-named, one
        # bare string arg) to the fixed post-import injection point below.
        # Earlier runs could emit them ahead of ``import typing`` (a runtime
        # NameError under CPython); re-emitting at the anchor keeps the same
        # statement semantics with a safe ordering.
        _tv_kinds = {"TypeVar", "TypeVarTuple", "ParamSpec"}
        cleaned: list[cst.BaseStatement] = []
        relocated: dict[str, str] = {}
        for stmt in body:
            el = (
                stmt.body[0]
                if isinstance(stmt, cst.SimpleStatementLine)
                and len(stmt.body) == 1
                else None
            )
            name = ""
            if (
                isinstance(el, cst.Assign)
                and len(el.targets) == 1
                and isinstance(el.targets[0].target, cst.Name)
                and isinstance(el.value, cst.Call)
                and len(el.value.args) == 1
                and el.value.args[0].keyword is None
                and isinstance(el.value.args[0].value, cst.SimpleString)
            ):
                dotted = _expr_dotted(el.value.func)
                head, _, kind = dotted.rpartition(".")
                tname = el.targets[0].target.value
                arg = el.value.args[0].value.evaluated_value
                if head == "typing" and kind in _tv_kinds and arg == tname:
                    name = tname
            if name:
                relocated[name] = kind
                self._bump("typevar_relocated")
                continue
            cleaned.append(stmt)
        if len(cleaned) != len(body):
            body = cleaned
            updated = updated.with_changes(body=body)

        self._has_future_annotations = any(
            isinstance(stmt, cst.SimpleStatementLine)
            and any(
                isinstance(el, cst.ImportFrom)
                and el.module
                and _module_str(el.module) == "__future__"
                and _imports_name(el, "annotations")
                for el in stmt.body
            )
            for stmt in body
        )

        insert_at = 0
        # keep module docstring first
        if (
            body
            and isinstance(body[0], cst.SimpleStatementLine)
            and body[0].body
            and isinstance(body[0].body[0], cst.Expr)
            and isinstance(body[0].body[0].value, cst.SimpleString)
        ):
            insert_at = 1
        # after the leading run of top-level import statements — injected
        # ``X = typing.TypeVar(...)`` lines must follow ``import typing``
        # even when that import (or a stale injected var) already sits in
        # the header block from an earlier pass.
        for i in range(insert_at, len(body)):
            stmt = body[i]
            if not (
                isinstance(stmt, cst.SimpleStatementLine)
                and stmt.body
                and all(
                    isinstance(el, (cst.Import, cst.ImportFrom))
                    for el in stmt.body
                )
            ):
                break
            insert_at = i + 1

        imported = _top_level_imported_names(updated)
        injections: list[cst.SimpleStatementLine] = []
        # Trust the tree, not the manifest: a stale ``has_cython_import``
        # from an earlier pass must not starve a restored source.
        if "cython" not in imported:
            injections.append(
                cst.SimpleStatementLine(body=[cst.Import(names=[cst.ImportAlias(name=cst.Name("cython"))])])
            )
            self._bump("cython_import")
        if self._needs_dataclasses_import and "dataclasses" not in imported:
            injections.append(
                cst.SimpleStatementLine(body=[cst.Import(names=[cst.ImportAlias(name=cst.Name("dataclasses"))])])
            )
            self._bump("dataclasses_import")
        if self._needs_operator_import and "operator" not in imported:
            injections.append(
                cst.SimpleStatementLine(body=[cst.Import(names=[cst.ImportAlias(name=cst.Name("operator"))])])
            )
            self._bump("operator_import")
        if self._needs_builtins_import and "builtins" not in imported:
            injections.append(
                cst.SimpleStatementLine(body=[cst.Import(names=[cst.ImportAlias(name=cst.Name("builtins"))])])
            )
            self._bump("builtins_import")
        # TypeVars stripped via [T] plus every still-unbound name used in
        # annotation position (recovers typevars lost in earlier passes).
        bound = _top_level_bound_names(updated)
        import builtins as _bi
        builtins_names = set(dir(_bi))
        extra = {
            n for n in (
                self.annotation_names - imported - bound - builtins_names
                - {"self", "cls", "None", "True", "False", "cython", "typing"}
            )
            if not (n.startswith("__") and n.endswith("__"))
        }
        for name in extra:
            self._typevars.setdefault(name, "TypeVar")
        # Re-emit relocated ``X = typing.<kind>("X")`` lines only when the
        # name is still needed: recorded this pass (PEP-695 params), wanted
        # by annotations, or referenced anywhere else in the module.  A
        # stale artefact with no remaining use is dropped instead.
        if relocated:
            all_names = _ref_names(updated)
            for name, kind in relocated.items():
                if name in self._typevars or name in all_names:
                    self._typevars.setdefault(name, kind)
                else:
                    self._bump("typevar_dropped")
        if (self._typevars or self._needs_typing_import) and "typing" not in imported:
            injections.append(
                cst.SimpleStatementLine(body=[cst.Import(names=[cst.ImportAlias(name=cst.Name("typing"))])])
            )
            self._bump("typing_import")
        for name, kind in sorted(self._typevars.items()):
            if name in imported or name in bound:
                continue  # a real binding already owns this name
            rhs = cst.Call(
                func=_attr(cst.Name("typing"), kind),
                args=[cst.Arg(cst.SimpleString(f'"{name}"'))],
            )
            injections.append(
                cst.SimpleStatementLine(
                    body=[cst.Assign(
                        targets=[cst.AssignTarget(cst.Name(name))],
                        value=rhs,
                    )]
                )
            )
            self._bump("typevar_injected")
        # ``None``-able module-level names get an ``x: object`` decl ahead
        # of their first binding — same infer_types coercion hazard as
        # function locals.  Def/class-bound names are excluded (a decl
        # would clash with the def/class binding); names bound by plain
        # assignment still need — and can take — the decl, which the
        # header position guarantees precedes every binding.
        mod_defclass = {
            s.name.value
            for s in updated.body
            if isinstance(s, (cst.FunctionDef, cst.ClassDef))
        }
        mod_none = sorted(
            (self._mod_none_names | self._mod_for_targets)
            - self._mod_ann_names
            - imported
            - mod_defclass
            - _mod_declare_binds(updated)
        )
        if mod_none:
            injections.extend(
                cst.SimpleStatementLine(body=[
                    cst.AnnAssign(
                        target=cst.Name(n),
                        annotation=cst.Annotation(cst.Name("object")),
                        value=None,
                    )
                ])
                for n in mod_none
            )
            self._bump("mod_none_decl", len(mod_none))
        if injections:
            body[insert_at:insert_at] = injections
            updated = updated.with_changes(body=body)
        return updated

    # -- classes ---------------------------------------------------------

    def visit_ClassDef(self, node: cst.ClassDef) -> bool:
        """Enter class scope and record cclass eligibility."""
        self._bound_here().add(node.name.value)
        qual = self._class_qualname(node.name.value)
        rec = self._class_record(qual)
        # PEP-695 generics must stay plain Python classes: a cclass loses
        # ``__class_getitem__`` so ``C[T]`` subscription breaks at runtime,
        # and the stripped ``[T]`` is restored as a ``Generic[T]`` base
        # anyway (which the census would flag as a poison base).  The base
        # check also covers explicit ``Generic[...]`` inheritance on
        # re-runs where ``type_parameters`` is already gone.
        generic = node.type_parameters is not None or any(
            _dotted_tail(b.value) == "Generic"
            for b in node.bases
            if not b.star
        )
        # ``frozen=True`` dataclasses can never be cclasses: cython compiles
        # their fields as readonly C members, breaking the pervasive
        # ``object.__setattr__`` escape hatch (``__post_init__`` coercion,
        # ``T.__new__`` deep-clone in ``ir/native_copy_memo.py``).
        frozen = any(
            _deco_name(d) in _DATACLASS_DECO and _frozen_dataclass_dec(d)
            for d in node.decorators
        )
        cclass = (
            bool(rec.get("cclass"))
            and not generic
            and not frozen
            and node.name.value not in self.rec.get("mixin_demoted", ())
        )
        scope = _Scope("class", node.name.value, cclass)
        # collect names already declared at class level (annotations+assigns)
        for stmt in node.body.body:
            if isinstance(stmt, cst.SimpleStatementLine):
                for el in stmt.body:
                    tgt = None
                    if isinstance(el, cst.AnnAssign):
                        tgt = el.target
                    elif isinstance(el, cst.Assign):
                        tgt = el.targets[0].target if el.targets else None
                    if isinstance(tgt, cst.Name):
                        scope.existing_fields.add(tgt.value)
            elif isinstance(stmt, cst.FunctionDef):
                scope.existing_fields.add(stmt.name.value)
        self.scopes.append(scope)
        return True

    def leave_ClassDef(
        self, original: cst.ClassDef, updated: cst.ClassDef
    ) -> cst.ClassDef:
        """Apply ``@cython.cclass`` / dataclass swap / attr declarations."""
        scope = self.scopes.pop()
        rec = self._class_record(self._qual_from(original))
        if original.type_parameters is not None:
            # ``class C[T]`` carries ``__class_getitem__`` implicitly; the
            # stripped form needs an explicit ``Generic[T]`` base to keep
            # ``C[X]`` subscriptable under CPython and compiled Cython.
            updated = self._inject_generic_base(updated, original.type_parameters)
        updated = self._strip_type_params(updated)
        if not scope.cclass:
            self._bump("class_dynamic")
            return self._revert_class(updated)

        decorators = list(updated.decorators)
        swapped = False
        new_decos: list[cst.Decorator] = []
        for dec in decorators:
            if _deco_name(dec) in _DATACLASS_DECO:
                inner = dec.decorator
                if isinstance(inner, cst.Call):
                    # cython.dataclasses rejects slots= (cdef classes are
                    # inherently slotted); drop the kwarg when swapping.
                    args = [
                        a for a in inner.args
                        if not (a.keyword and a.keyword.value == "slots")
                    ]
                    inner = inner.with_changes(
                        func=_cy("dataclasses.dataclass"), args=args
                    )
                else:
                    inner = _cy("dataclasses.dataclass")
                new_decos.append(dec.with_changes(decorator=inner))
                swapped = True
                self._bump("dataclass_swapped")
            else:
                new_decos.append(dec)
        decorators = new_decos
        if not swapped:
            # collapse repeats from earlier runs, then add only when absent
            seen = False
            deduped: list[cst.Decorator] = []
            for dec in decorators:
                if _deco_name(dec) in {"cython.cclass", "cclass"}:
                    if seen:
                        self._bump("cclass_deduped")
                        continue
                    seen = True
                deduped.append(dec)
            decorators = deduped
            if not seen:
                decorators.insert(
                    0,
                    cst.Decorator(decorator=_cy("cclass")),
                )
                self._bump("cclass_added")
        updated = updated.with_changes(decorators=decorators)

        is_dataclass = swapped or any(
            _deco_name(d) in {"cython.dataclasses.dataclass", "dataclasses.dataclass"}
            for d in decorators
        )
        if not is_dataclass:
            # Bare ``name: T`` lines in a cclass compile to *private* C
            # attributes; Python-visible access needs a public declare.
            # Dataclass classes are exempt: there the annotation *is* the
            # (already public) field declaration.
            new_body: list[cst.BaseStatement] = []
            for stmt in updated.body.body:
                el = (
                    stmt.body[0]
                    if isinstance(stmt, cst.SimpleStatementLine)
                    and len(stmt.body) == 1
                    else None
                )
                if (
                    isinstance(el, cst.AnnAssign)
                    and el.value is None
                    and isinstance(el.target, cst.Name)
                    and _declare_convertible(el.annotation.annotation)
                ):
                    new_body.append(
                        _attr_declare_stmt(
                            el.target.value,
                            _declare_type(el.annotation.annotation),
                        )
                    )
                    self._bump("attr_decl_public")
                else:
                    new_body.append(stmt)
            updated = updated.with_changes(
                body=updated.body.with_changes(body=new_body)
            )

        # inject self.<attr> declarations after the class docstring
        decls: list[cst.BaseStatement] = []
        del_attrs = set(rec.get("del_self_attrs", ()))
        for attr, hints in sorted(rec.get("self_attrs", {}).items()):
            if attr in scope.existing_fields or not attr.isidentifier():
                continue
            ty = cst.Name("object") if attr in del_attrs else _attr_decl_type(hints)
            decls.append(_attr_declare_stmt(attr, ty))
            self._bump("attr_decl")
        if decls:
            body = list(updated.body.body)
            pos = 0
            if (
                body
                and isinstance(body[0], cst.SimpleStatementLine)
                and body[0].body
                and isinstance(body[0].body[0], cst.Expr)
                and isinstance(body[0].body[0].value, cst.SimpleString)
            ):
                pos = 1
            body[pos:pos] = decls
            updated = updated.with_changes(body=updated.body.with_changes(body=body))
        return updated

    def _revert_class(self, updated: cst.ClassDef) -> cst.ClassDef:
        """Undo prior cython class decorations on a now-dynamic class.

        Re-running the transform after eligibility changes must restore a
        compilable class: ``@cython.cclass`` is removed and a swapped
        ``cython.dataclasses.dataclass`` reverts to ``dataclasses.dataclass``.
        """
        new_decos: list[cst.Decorator] = []
        changed = False
        for dec in updated.decorators:
            name = _deco_name(dec)
            if name == "cython.cclass" or name == "cclass":
                changed = True
                self._bump("cclass_reverted")
                continue
            if name == "cython.dataclasses.dataclass":
                inner = dec.decorator
                if isinstance(inner, cst.Call):
                    args = [
                        a for a in inner.args
                        if not (a.keyword and a.keyword.value == "slots")
                    ]
                    inner = inner.with_changes(
                        func=_attr(cst.Name("dataclasses"), "dataclass"),
                        args=args,
                    )
                else:
                    inner = _attr(cst.Name("dataclasses"), "dataclass")
                new_decos.append(dec.with_changes(decorator=inner))
                self._needs_dataclasses_import = True
                changed = True
                self._bump("dataclass_reverted")
                continue
            new_decos.append(dec)
        if changed:
            updated = updated.with_changes(decorators=new_decos)
        # Public-attr declares belong to cclasses only; a demoted class gets
        # the plain ``name: T`` annotation form back.
        body_changed = False
        new_body: list[cst.BaseStatement] = []
        for stmt in updated.body.body:
            el = (
                stmt.body[0]
                if isinstance(stmt, cst.SimpleStatementLine)
                and len(stmt.body) == 1
                else None
            )
            if (
                isinstance(el, cst.Assign)
                and len(el.targets) == 1
                and isinstance(el.targets[0].target, cst.Name)
                and isinstance(el.value, cst.Call)
                and _expr_dotted(el.value.func) == "cython.declare"
                and el.value.args
            ):
                new_body.append(
                    stmt.with_changes(
                        body=[
                            cst.AnnAssign(
                                target=el.targets[0].target,
                                annotation=cst.Annotation(el.value.args[0].value),
                                value=None,
                            )
                        ]
                    )
                )
                body_changed = True
                self._bump("attr_decl_reverted")
            else:
                new_body.append(stmt)
        if body_changed:
            updated = updated.with_changes(
                body=updated.body.with_changes(body=new_body)
            )
        return updated

    def _strip_type_params(self, node):
        """Remove PEP-695 ``[T]`` parameters; remember names for TypeVar glue."""
        tps = getattr(node, "type_parameters", None)
        if tps is None:
            return node
        for tp in tps.params:
            p = tp.param
            kind = type(p).__name__  # TypeVar | TypeVarTuple | ParamSpec
            self._typevars[p.name.value] = kind
        self._bump("type_params_stripped")
        return node.with_changes(type_parameters=None)

    def _inject_generic_base(
        self, node: cst.ClassDef, tps: cst.TypeParameters
    ) -> cst.ClassDef:
        """Add ``typing.Generic[T, ...]`` to preserve PEP-695 genericity."""
        parts = []
        for tp in tps.params:
            name = tp.param.name.value
            if type(tp.param).__name__ == "TypeVarTuple":
                name = "*" + name
            parts.append(name)
        gen = cst.parse_expression(f"typing.Generic[{', '.join(parts)}]")
        self._needs_typing_import = True
        return node.with_changes(
            bases=[*node.bases, cst.Arg(value=gen)]
        )

    def _qual_from(self, node: cst.ClassDef) -> str:
        """Qualname as tracked when the (already left) class was entered."""
        parts = [s.name for s in self.scopes if s.kind == "class"]
        return ".".join([*parts, node.name.value]) if parts else node.name.value

    # -- functions --------------------------------------------------------

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        """Enter function scope; pre-scan ``del``-ed local names."""
        self._bound_here().add(node.name.value)
        scope = _Scope("func", node.name.value)
        scope.del_names = _del_targets(node)
        scope.bound_seen = {
            p.name.value
            for plist in (
                node.params.posonly_params,
                node.params.params,
                node.params.kwonly_params,
            )
            for p in plist
            if isinstance(p.name, cst.Name)
        }
        # ``infer_types`` C-types locals used in arithmetic; a var assigned a
        # ``None``-able value then compared to ``None`` must stay ``object``
        # or the coercion crashes *before* the guard runs.
        scope.none_names = _fn_none_checked(node)
        scope.declare_names = _fn_declare_binds(node)
        # ``for`` targets get ``x: object`` top decls instead of an
        # iterable wrap — the decl stops container-type inference without
        # touching the iterated expression at all.
        scope.for_targets = _fn_for_targets(
            node,
            skip_known=not (
                _fn_binds(node, "range") or _fn_binds(node, "enumerate")
            ),
        )
        # ``iter`` bound inside this function shadows the builtin for the
        # whole body — the for-iterable ``iter(...)`` wrap must stay off
        # here.  Same for ``operator`` (compare rewrites call ``operator.eq``).
        self._iter_shadow.append(_fn_binds(node, "iter"))
        self._operator_shadow.append(_fn_binds(node, "operator"))
        self._builtins_shadow.append(_fn_binds_nonimport(node, "builtins"))
        # params already declare the name — a matching ``x: T`` local would be
        # a cython redeclaration.
        for plist in (
            node.params.posonly_params,
            node.params.params,
            node.params.kwonly_params,
        ):
            for p in plist:
                if isinstance(p.name, cst.Name):
                    scope.ann_names.add(p.name.value)
        # ``@cython.locals(x=T, ...)`` already declares those locals —
        # a later ``x: T`` annotation would be a cython redeclaration.
        for dec in node.decorators:
            d = dec.decorator
            if not (
                isinstance(d, cst.Call)
                and _deco_name(dec) == "cython.locals"
            ):
                continue
            for arg in d.args:
                if arg.keyword is not None:
                    scope.ann_names.add(arg.keyword.value)
        self.scopes.append(scope)
        return True

    def leave_FunctionDef(
        self, original: cst.FunctionDef, updated: cst.FunctionDef
    ) -> cst.BaseStatement:
        """Remap signature annotations and maybe add ``@cython.ccall``."""
        scope = self.scopes.pop()
        self._iter_shadow.pop()
        self._operator_shadow.pop()
        self._builtins_shadow.pop()
        updated = self._strip_type_params(updated)
        name = updated.name.value
        is_dunder = name.startswith("__") and name.endswith("__")
        nested = self._inside_function()
        deco_names = {_deco_name(d) for d in updated.decorators}
        # any non-cython decorator (or unparseable '') blocks ccall — unknown
        # wrapper semantics; cython.* decorators compose with ccall.
        blocked = any(not n.startswith("cython") for n in deco_names)
        has_call_deco = bool(deco_names & _CALL_DECO)
        has_yield = _contains_yield(updated)
        has_closure = _has_closure_construct(updated)
        is_async = isinstance(updated, cst.FunctionDef) and updated.asynchronous is not None
        star_arg = updated.params.star_arg
        star_arg_name = (
            star_arg.name.value
            if isinstance(star_arg, cst.Param) and isinstance(star_arg.name, cst.Name)
            else ""
        )
        has_star = bool(star_arg_name) or updated.params.star_kwarg is not None
        del_names = scope.del_names

        # remap parameter annotations (posonly + regular + kwonly)
        params = updated.params
        for list_name in ("posonly_params", "params", "kwonly_params"):
            plist: list[cst.Param] = getattr(params, list_name)
            new_params: list[cst.Param] = []
            for p in plist:
                ann = p.annotation
                if p.name.value in {"self", "cls", "mcs"} or p.star in {"*", "**"}:
                    new_params.append(p)
                    continue
                if p.name.value in del_names:
                    new_params.append(p.with_changes(annotation=None))
                    self._bump("ann_kept_del")
                    continue
                if (
                    ann is not None
                    and p.default is not None
                    and isinstance(p.default, cst.Name)
                    and p.default.value == "None"
                ):
                    if _ann_has_exact(ann.annotation):
                        # ``x: dict = None``/``x: str | None = None`` still
                        # declares ``Optional[T]`` — CheckExact rejects the
                        # subclasses CPython accepts at the ccall boundary.
                        new_params.append(
                            p.with_changes(
                                annotation=cst.Annotation(cst.Name("object"))
                            )
                        )
                        self._bump("arg_ann_exact_demote")
                        continue
                    new_params.append(p)  # keep object typing for None defaults
                    self._bump("ann_kept_none_default")
                    continue
                if ann is not None and p.name.value in scope.none_names:
                    # ``if v is not None`` proves ``None`` reaches this
                    # param; scalar/checked annotations reject it at the
                    # ccall boundary — demote to ``object``.
                    new_params.append(
                        p.with_changes(annotation=cst.Annotation(cst.Name("object")))
                    )
                    self._bump("arg_ann_none_demote")
                    continue
                if ann is not None and _ann_has_exact(ann.annotation):
                    # ``x: dict``/``x: str | None`` enforce CheckExact —
                    # subclasses (``defaultdict``, ``str``-enums) that CPython
                    # accepts would raise at the boundary.  Demote to ``object``.
                    new_params.append(
                        p.with_changes(annotation=cst.Annotation(cst.Name("object")))
                    )
                    self._bump("arg_ann_exact_demote")
                    continue
                mapped = _map_annotation(ann)
                if mapped is not ann:
                    self._bump("arg_ann")
                new_params.append(p.with_changes(annotation=mapped))
            params = params.with_changes(**{list_name: new_params})
        # star_arg / star_kwarg untouched
        updated = updated.with_changes(params=params)

        # ``@cython.locals(x=T)`` declares local types — remap native
        # scalars in its keyword values just like ``x: T`` locals.
        new_decorators: list[cst.Decorator] = []
        dec_changed = False
        for dec in updated.decorators:
            d = dec.decorator
            if not (
                isinstance(d, cst.Call) and _deco_name(dec) == "cython.locals"
            ):
                new_decorators.append(dec)
                continue
            new_args: list[cst.Arg] = []
            for arg in d.args:
                v = arg.value
                if isinstance(v, cst.Name) and v.value in _NATIVE:
                    arg = arg.with_changes(value=_cy(_NATIVE[v.value]))
                    dec_changed = True
                new_args.append(arg)
            new_decorators.append(
                dec.with_changes(decorator=d.with_changes(args=new_args))
                if dec_changed
                else dec
            )
        if dec_changed:
            self._bump("locals_deco_args")
            updated = updated.with_changes(decorators=new_decorators)

        # remap return annotation (skip when the body can return None and the
        # annotation is a native numeric — returning None must stay legal).
        if updated.returns is not None:
            returns_none = _returns_none(updated)
            if returns_none and isinstance(
                updated.returns.annotation, cst.Name
            ) and updated.returns.annotation.value in _NATIVE:
                self._bump("ret_ann_kept_none")
            else:
                mapped = _map_annotation(updated.returns)
                if mapped is not updated.returns:
                    self._bump("ret_ann")
                    updated = updated.with_changes(returns=mapped)
            # ``-> tuple[T, …]`` fixed arity coerces returns to ctuple —
            # a literal ``return (*x, …)`` splice cannot coerce statically;
            # downgrade the annotation to a plain ``tuple`` instead.
            if _fixed_tuple_ann(updated.returns) and _has_starred_tuple_return(updated):
                self._bump("ret_ann_starred_tuple")
                updated = updated.with_changes(
                    returns=cst.Annotation(cst.Name("tuple"))
                )
            # ``-> dict``/``-> str`` enforce CheckExact on the return value —
            # subclass results that CPython allows would raise.  Demote
            # unless every own-level ``return`` provably yields the builtin.
            ret_head = _ann_head(updated.returns.annotation)
            if (
                ret_head in _EXACT_HEADS
                and not _returns_all_exact(original, ret_head)
            ) or (
                ret_head not in _EXACT_HEADS
                and _ann_has_exact(updated.returns.annotation)
            ):
                self._bump("ret_ann_exact_demote")
                updated = updated.with_changes(
                    returns=cst.Annotation(cst.Name("object"))
                )

        # decide ccall eligibility
        cls = self._in_class()
        # cpdef signatures require defaults for every parameter after the
        # first defaulted one (Python only enforces positional params, but
        # required kwonly params after a default break the C signature).
        seen_default = False
        bad_default_order = False
        for p in (*params.posonly_params, *params.params, *params.kwonly_params):
            if p.default is not None:
                seen_default = True
            elif seen_default:
                bad_default_order = True
        scope_qual = ".".join(s.name for s in self.scopes if s.kind == "class")
        is_overloaded = (scope_qual, name) in self.overloaded
        eligible = (
            not is_dunder
            and not nested
            and not has_yield
            and not has_closure
            and not is_async
            and not has_star
            and not bad_default_order
            and not is_overloaded
            and (cls is None or cls.cclass)
        )
        if not eligible:
            # an ineligible function cannot keep cdef/cpdef decorators —
            # strip any (revert support for changed eligibility rules).
            keep = [
                d for d in updated.decorators
                if _deco_name(d) not in _CALL_DECO
            ]
            if len(keep) != len(updated.decorators):
                self._bump("ccall_reverted")
                updated = updated.with_changes(decorators=keep)
        if eligible and not blocked and not has_call_deco:
            updated = updated.with_changes(
                decorators=[cst.Decorator(decorator=_cy("ccall")), *updated.decorators]
            )
            self._bump("ccall")
        else:
            reason = (
                "dunder" if is_dunder else
                "nested" if nested else
                "generator" if has_yield else
                "closure" if has_closure else
                "async" if is_async else
                "star_args" if has_star else
                "decorated" if blocked else
                "overloaded" if is_overloaded else
                "default_order" if bad_default_order else
                "method_in_dynamic_class"
            )
            self._bump(f"skip_ccall:{reason}")
        # inject ``x: object`` decls for ``None``-able names at function top —
        # a decl must precede all bindings to avoid ``redeclared`` errors, so
        # it goes right after the docstring rather than at each assign site.
        # ``& bound_seen`` restricts to names *bound in this scope*: a free
        # variable (closure read in a nested function) is only compared here,
        # and a local decl would unbind it (``referenced before assignment``).
        inject_names = sorted(
            ((scope.none_names | scope.for_targets) & scope.bound_seen)
            - scope.del_names
            - scope.ann_names
            - scope.declare_names
        )
        if inject_names:
            decls: list[cst.BaseStatement] = [
                cst.SimpleStatementLine(body=[
                    cst.AnnAssign(
                        target=cst.Name(n),
                        annotation=cst.Annotation(cst.Name("object")),
                        value=None,
                    )
                ])
                for n in inject_names
            ]
            stmts = list(updated.body.body)
            idx = 0
            if stmts and isinstance(stmts[0], cst.SimpleStatementLine):
                first = stmts[0].body[0]
                if isinstance(first, cst.Expr) and isinstance(
                    first.value, (cst.SimpleString, cst.ConcatenatedString)
                ):
                    idx = 1
            updated = updated.with_changes(
                body=updated.body.with_changes(
                    body=[*stmts[:idx], *decls, *stmts[idx:]]
                )
            )
            self._bump("none_decl", len(inject_names))
        return updated

    # -- type aliases -----------------------------------------------------

    def leave_TypeAlias(
        self, original: cst.TypeAlias, updated: cst.TypeAlias
    ) -> cst.BaseSmallStatement:
        """``type X = Y`` → ``X = typing.TypeAliasType("X", Y)``.

        Cython cannot parse the PEP-695 ``type`` statement.  An eagerly
        evaluated ``TypeAliasType`` preserves ``__value__``, ``__type_params__``
        and ``X[...]`` subscription semantics exactly — passing a lazy callable
        would leave ``__value__`` as the thunk.  Aliases that need PEP-695
        laziness (RHS names bound later in the module) are refused by
        ``_LateAliasScan`` in the driver and keep the ``type`` statement.
        ``[K, V]`` params are registered for ``typing.TypeVar``/``TypeVarTuple``/
        ``ParamSpec`` injection and passed via ``type_params=``.
        """
        idx = self._alias_count
        self._alias_count += 1
        if idx in self.late_aliases:
            self._bump("type_alias_kept_lazy")
            return updated
        name = updated.name.value
        args = [
            cst.Arg(cst.SimpleString(f'"{name}"')),
            cst.Arg(updated.value),
        ]
        if updated.type_parameters is not None:
            names: list[str] = []
            for tp in updated.type_parameters.params:
                p = tp.param
                self._typevars[p.name.value] = type(p).__name__
                names.append(p.name.value)
            tp_expr = cst.parse_expression(
                "(" + "".join(f"{n}, " for n in names) + ")"
            )
            args.append(
                cst.Arg(keyword=cst.Name("type_params"), value=tp_expr)
            )
        self._needs_typing_import = True
        self._alias_names.add(name)
        self._bump("type_alias")
        return cst.Assign(
            targets=[cst.AssignTarget(updated.name)],
            value=cst.Call(
                func=_attr(cst.Name("typing"), "TypeAliasType"), args=args
            ),
        )

    # -- calls ------------------------------------------------------------

    def _bound_here(self) -> set[str]:
        """The ``bound_seen`` set for the current position."""
        scope = self.scopes[-1] if self.scopes else None
        if scope is None:
            return self._mod_bound_seen
        return scope.bound_seen

    def leave_Assign(
        self, original: cst.Assign, updated: cst.Assign
    ) -> cst.BaseStatement:
        """``a, b = seq[i:j]`` → ``a, b = tuple(seq[i:j])``.

        Cython's MarkParallelAssignments crashes on tuple-unpacking a
        slice subscript inside cdef code; materialising the slice into a
        ``tuple()`` first preserves unpack semantics for every iterable
        while dodging the crash.
        """
        bound = self._bound_here()
        for t in updated.targets:
            bound.update(_target_names(t.target))
        # ``x = cython.declare(<scalar>, <None-able>)`` is a ``cdef scalar``
        # bound to a value that may be ``None`` — the coercion crashes
        # before the guard.  ``declare`` owns the decl (no ``x: object``
        # is injected for it), so the type arg itself must degrade.
        if (
            len(updated.targets) == 1
            and isinstance(updated.targets[0].target, cst.Name)
            and isinstance(updated.value, cst.Call)
            and _expr_dotted(updated.value.func) == "cython.declare"
            and updated.value.args
        ):
            name = updated.targets[0].target.value
            fn_scope = next(
                (s for s in reversed(self.scopes) if s.kind == "func"), None
            )
            none_names = (
                fn_scope.none_names - fn_scope.del_names
                if fn_scope is not None
                else self._mod_none_names
            )
            if name in none_names:
                first = updated.value.args[0]
                ty = first.value
                scalar = (
                    isinstance(ty, cst.Name) and ty.value in _NATIVE
                ) or (
                    isinstance(ty, cst.Attribute)
                    and isinstance(ty.value, cst.Name)
                    and ty.value.value == "cython"
                    and isinstance(ty.attr, cst.Name)
                    and ty.attr.value in _NATIVE_INV
                )
                if scalar:
                    self._bump("declare_scalar_demote")
                    return updated.with_changes(
                        value=updated.value.with_changes(
                            args=[
                                first.with_changes(value=cst.Name("object")),
                                *updated.value.args[1:],
                            ]
                        )
                    )
        if not any(isinstance(t.target, cst.Tuple) for t in updated.targets):
            return updated
        v = updated.value
        if not (
            isinstance(v, cst.Subscript)
            and any(
                isinstance(el.slice, cst.Slice) for el in v.slice
            )
        ):
            return updated
        wrapped = cst.Call(func=cst.Name("tuple"), args=[cst.Arg(v)])
        self._bump("slice_unpack_wrap")
        return updated.with_changes(value=wrapped)

    def leave_IfExp(
        self, original: cst.IfExp, updated: cst.IfExp
    ) -> cst.BaseExpression:
        """Different-arity tuple branches → ``tuple(...)`` each.

        ``(a, b, c) if cond else (d,)`` fails with ``Incompatible types
        in conditional expression`` once ``a``/``d`` infer as ctuples of
        different arity.  Coercing each branch to ``tuple`` makes both
        arms the same Python type with identical runtime semantics.
        """
        body, orelse = updated.body, updated.orelse
        if not (isinstance(body, cst.Tuple) and isinstance(orelse, cst.Tuple)):
            return updated
        if len(body.elements) == len(orelse.elements):
            return updated
        wrapped_body = cst.Call(func=cst.Name("tuple"), args=[cst.Arg(body)])
        wrapped_else = cst.Call(func=cst.Name("tuple"), args=[cst.Arg(orelse)])
        self._bump("ifexp_tuple_wrap")
        return updated.with_changes(body=wrapped_body, orelse=wrapped_else)

    def leave_Call(
        self, original: cst.Call, updated: cst.Call
    ) -> cst.BaseExpression:
        """``sorted(<untyped expr>)`` → ``sorted(tuple(<expr>))``.

        Cython 3.3's ``sorted`` builtin-call optimiser crashes when the
        argument's type is ``None`` (``getattr(...) or ()`` and similar).
        Wrapping the argument in ``tuple()`` gives it a concrete type and
        preserves semantics exactly.
        """
        updated = self._expand_star_literals(updated)
        head = _expr_dotted(updated.func)
        if head in _TYPED_CALL_HEADS and updated.args:
            first = updated.args[0]
            if isinstance(first.value, cst.Name) and first.value.value in _NATIVE:
                mapped = _cy(_NATIVE[first.value.value])
                self._bump("typed_call_arg")
                return updated.with_changes(
                    args=[first.with_changes(value=mapped), *updated.args[1:]]
                )
        elif head in _RUNTIME_CAST_HEADS and updated.args:
            # ``typing.cast`` args evaluate at runtime where ``import cython``
            # binds nothing under an extension build; restore the builtin so
            # ``cast(int, x)`` stays legal in both modes.
            first = updated.args[0]
            v = first.value
            if (
                isinstance(v, cst.Attribute)
                and isinstance(v.value, cst.Name)
                and v.value.value == "cython"
                and isinstance(v.attr, cst.Name)
                and v.attr.value in _NATIVE_INV
            ):
                self._bump("typed_call_arg_reverted")
                return updated.with_changes(
                    args=[
                        first.with_changes(value=cst.Name(_NATIVE_INV[v.attr.value])),
                        *updated.args[1:],
                    ]
                )
        if not (
            isinstance(updated.func, cst.Name)
            and updated.func.value == "sorted"
            and updated.args
        ):
            return updated
        first = updated.args[0]
        if first.star or first.keyword is not None:
            return updated
        v = first.value
        # Collapse ``tuple(tuple(...))`` layers left by earlier passes that
        # re-wrapped an already-materialized argument.
        collapsed = False
        while (
            isinstance(v, cst.Call)
            and isinstance(v.func, cst.Name)
            and v.func.value == "tuple"
            and len(v.args) == 1
            and not v.args[0].star
            and v.args[0].keyword is None
            and isinstance(v.args[0].value, cst.Call)
            and isinstance(v.args[0].value.func, cst.Name)
            and v.args[0].value.func.value == "tuple"
            and len(v.args[0].value.args) == 1
        ):
            v = v.args[0].value
            collapsed = True
        if collapsed:
            self._bump("sorted_wrap_collapsed")
            return updated.with_changes(
                args=[first.with_changes(value=v), *updated.args[1:]]
            )
        # ``tuple(...)`` args are already materialized (including wraps added
        # by earlier passes); re-wrapping stacks a no-op layer each run.
        already = (
            isinstance(v, cst.Call)
            and isinstance(v.func, cst.Name)
            and v.func.value == "tuple"
        )
        if not already and isinstance(v, (cst.BooleanOperation, cst.Call, cst.IfExp)):
            wrapped = cst.Call(func=cst.Name("tuple"), args=[cst.Arg(v)])
            self._bump("sorted_wrap")
            return updated.with_changes(
                args=[first.with_changes(value=wrapped), *updated.args[1:]]
            )
        return updated

    def _expand_star_literals(
        self, updated: cst.Call
    ) -> cst.Call:
        """Spread literals in call args → concatenated literals.

        ``f((a, *b))`` / ``f([a, *b])`` / ``f({a, *b})`` all hit
        ``starred expression is not allowed here`` inside cdef calls;
        ``(a,) + tuple(b)`` / ``[a] + list(b)`` / ``{a} | set(b)`` carry
        identical semantics and compile fine.
        """
        new_args: list[cst.Arg] = []
        changed = False
        for arg in updated.args:
            exp = _expand_star_literal(arg.value)
            if exp is None:
                new_args.append(arg)
            else:
                new_args.append(arg.with_changes(value=exp))
                changed = True
        if changed:
            self._bump("star_literal_expand")
            return updated.with_changes(args=new_args)
        return updated

    # -- annotations ------------------------------------------------------

    def leave_ExceptHandler(
        self, original: cst.ExceptHandler, updated: cst.ExceptHandler
    ) -> cst.ExceptHandler:
        """Parenthesise PEP-758 bare except tuples for Cython's parser.

        ``except A, B:`` is valid CPython 3.14+ but rejected by Cython;
        ``except (A, B):`` is identical under both.
        """
        t = updated.type
        if isinstance(updated.name, cst.AsName) and isinstance(updated.name.name, cst.Name):
            self._bound_here().add(updated.name.name.value)
        if isinstance(t, cst.Tuple) and not t.lpar:
            self._bump("except_paren")
            return updated.with_changes(
                type=t.with_changes(
                    lpar=[cst.LeftParen()], rpar=[cst.RightParen()]
                )
            )
        return updated

    def leave_WithItem(
        self, original: cst.WithItem, updated: cst.WithItem
    ) -> cst.WithItem:
        """``with x as v`` binds ``v`` in this scope."""
        if updated.asname is not None and isinstance(
            updated.asname.name, cst.Name
        ):
            self._bound_here().add(updated.asname.name.value)
        return updated

    def leave_NamedExpr(
        self, original: cst.NamedExpr, updated: cst.NamedExpr
    ) -> cst.BaseExpression:
        """``(v := e)`` binds ``v`` in this scope."""
        if isinstance(updated.target, cst.Name):
            self._bound_here().add(updated.target.value)
        return updated

    def leave_Del(self, original: cst.Del, updated: cst.Del) -> cst.Del:
        """``del v`` counts as a prior binding for redeclare purposes."""
        self._bound_here().update(_target_names(updated.target))
        return updated

    def leave_AnnAssign(
        self, original: cst.AnnAssign, updated: cst.AnnAssign
    ) -> cst.RemovalSentinel | cst.BaseStatement:
        """Remap native scalar annotations at every site to cython types.

        Function locals, class attributes (cclass or dynamic), and
        module-level annotated names all get the native spelling — under
        CPython the ``cython.*`` forms are inert annotation metadata.
        """
        cls = self._in_class()
        in_func = self._inside_function()

        fn_scope = next(
            (s for s in reversed(self.scopes) if s.kind == "func"), None
        )
        scope = fn_scope if fn_scope is not None else cls
        name = updated.target.value if isinstance(updated.target, cst.Name) else ""
        if name:
            if fn_scope is not None and name in fn_scope.del_names:
                # `del name` requires a Python-typed local — drop the
                # annotation so the binding stays a plain object.
                self._bump("ann_del_demote")
                if updated.value is None:
                    return cst.RemovalSentinel.REMOVE
                return cst.Assign(
                    targets=[cst.AssignTarget(updated.target)],
                    value=updated.value,
                )
            if scope is not None and name in scope.ann_names:
                # duplicate annotated binding in one scope — cython treats a
                # second declaration as a redeclared cdef var; demote it.
                self._bump("ann_dedup")
                if updated.value is None:
                    return cst.RemovalSentinel.REMOVE
                return cst.Assign(
                    targets=[cst.AssignTarget(updated.target)],
                    value=updated.value,
                )
            bound = self._bound_here()
            if name in bound:
                # any earlier binding (assign/for/with/except/param/import)
                # already declared ``name`` — a ``name: T`` here is a cython
                # redeclaration; strip the annotation, keep the assign.
                self._bump("ann_late_demote")
                if updated.value is None:
                    return cst.RemovalSentinel.REMOVE
                return cst.Assign(
                    targets=[cst.AssignTarget(updated.target)],
                    value=updated.value,
                )
            if fn_scope is not None:
                none_names = fn_scope.none_names - fn_scope.del_names
            elif cls is None:
                none_names = self._mod_none_names
            else:
                none_names = ()
            if name in none_names:
                # ``name`` may receive ``None`` — a scalar/exact annotation
                # would coerce the ``None``-assign before the guard.  The
                # scope-top ``name: object`` decl injected at leave owns the
                # declaration; strip the annotation here.  A value-less
                # ``x: T`` is a pure decl — it binds nothing, so it must not
                # enter ``bound_seen`` (else the leave pass re-injects it as
                # a top decl forever, and for a free/closure var that decl
                # is outright wrong).
                self._bump("ann_none_demote")
                if updated.value is None:
                    return cst.RemovalSentinel.REMOVE
                bound.add(name)
                return cst.Assign(
                    targets=[cst.AssignTarget(updated.target)],
                    value=updated.value,
                )
            bound.add(name)
            if scope is not None:
                scope.ann_names.add(name)

        # do not retype dataclass ClassVar/InitVar wrappers
        ann = updated.annotation
        head = _ann_head(ann.annotation)
        if head in {"ClassVar", "InitVar"}:
            return updated
        # ``x = cython.declare(T, v)`` already declares x — a parallel
        # ``x: T`` annotation is a cython redeclaration.
        if isinstance(updated.value, cst.Call) and _expr_dotted(
            updated.value.func
        ) == "cython.declare":
            self._bump("ann_kept_declare")
            return cst.Assign(
                targets=[cst.AssignTarget(updated.target)],
                value=updated.value,
            )
        # ``x: int = None`` must keep Python typing — None is not a long long.
        if updated.value is not None and isinstance(
            updated.value, cst.Name
        ) and updated.value.value == "None":
            # ``x: str | None = None`` is not free either — the union member
            # yields ``Optional[str]`` which CheckExacts every later assign
            # (``StrEnum`` values crash).  Demote exact-member unions.
            if _ann_has_exact(ann.annotation):
                self._bump("ann_exact_demote")
                return updated.with_changes(
                    annotation=cst.Annotation(cst.Name("object"))
                )
            return updated
        # ``x: tuple[T, …] = (*s, …)`` — a starred splice literal cannot
        # coerce into a fixed-arity ctuple; downgrade to plain ``tuple``.
        if _starred_tuple_literal(updated.value) and _fixed_tuple_ann(ann):
            self._bump("ann_starred_tuple")
            return updated.with_changes(
                annotation=cst.Annotation(cst.Name("tuple"))
            )
        # ``x: dict = defaultdict(…)``/``x: str = enum_val`` — exact-builtin
        # annotations enforce CheckExact on every assignment; subclasses
        # CPython accepts would raise.  Only a provably-exact value keeps
        # the builtin annotation; everything else demotes to ``object``.
        if (head in _EXACT_HEADS and not _value_exact(updated.value, head)) or (
            head not in _EXACT_HEADS and _ann_has_exact(ann.annotation)
        ):
            # A union member still CheckExacts (``str | None`` = Optional[str]);
            # the declared slot rejects subclasses on every later assign too,
            # so unions containing an exact builtin demote unconditionally.
            self._bump("ann_exact_demote")
            return updated.with_changes(
                annotation=cst.Annotation(cst.Name("object"))
            )
        mapped = _map_annotation(ann)
        if mapped is not ann:
            self._bump("local_ann")
            return updated.with_changes(annotation=mapped)
        return updated


def _imports_name(imp: cst.ImportFrom, name: str) -> bool:
    """True when ``imp`` imports ``name`` (handles star imports)."""
    if isinstance(imp.names, cst.ImportStar):
        return True
    return any(
        isinstance(a.name, cst.Name) and a.name.value == name
        for a in imp.names
        if isinstance(a, cst.ImportAlias)
    )


def _top_level_imported_names(module: cst.Module) -> set[str]:
    """Names bound by module-level ``import``/``from ... import`` statements."""
    names: set[str] = set()
    for stmt in module.body:
        if not isinstance(stmt, cst.SimpleStatementLine):
            continue
        for el in stmt.body:
            if isinstance(el, cst.Import):
                for a in el.names:
                    if a.asname and isinstance(a.asname.name, cst.Name):
                        names.add(a.asname.name.value)
                    else:
                        names.add(_module_str(a.name).split(".")[0])
            elif isinstance(el, cst.ImportFrom):
                if isinstance(el.names, cst.ImportStar):
                    continue
                for a in el.names:
                    if not isinstance(a, cst.ImportAlias):
                        continue
                    if a.asname and isinstance(a.asname.name, cst.Name):
                        names.add(a.asname.name.value)
                    elif isinstance(a.name, cst.Name):
                        names.add(a.name.value)
    return names


def _module_str(expr: cst.BaseExpression) -> str:
    """Dotted name string from an import module expression."""
    parts: list[str] = []
    node = expr
    while isinstance(node, cst.Attribute):
        parts.append(node.attr.value)
        node = node.value
    if isinstance(node, cst.Name):
        parts.append(node.value)
    return ".".join(reversed(parts))


def _ann_head(expr: cst.BaseExpression) -> str:
    """Head name of an annotation expression (``X`` of ``X[...]``/``a.X``)."""
    node = expr
    while isinstance(node, cst.Subscript):
        node = node.value
    while isinstance(node, cst.Attribute):
        node = node.value
    return node.value if isinstance(node, cst.Name) else ""


def _del_targets(fn: cst.FunctionDef) -> set[str]:
    """Names deleted via ``del name`` at the function's own level."""
    class _D(cst.CSTVisitor):
        names: set[str]

        def __init__(self) -> None:
            self.names = set()

        def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
            return False  # nested defs have their own scopes

        def visit_ClassDef(self, n: cst.ClassDef) -> bool:
            return False

        def visit_Del(self, n: cst.Del) -> None:
            t = n.target
            exprs = (
                [el.value for el in t.elements if isinstance(el, cst.Element)]
                if isinstance(t, cst.Tuple)
                else [t]
            )
            for v in exprs:
                if isinstance(v, cst.Name):
                    self.names.add(v.value)

    v = _D()
    fn.body.visit(v)
    return v.names


def _has_closure_construct(fn: cst.FunctionDef) -> bool:
    """True when the function body creates a closure scope at its own level.

    cpdef functions cannot contain nested ``def``/``lambda``/genexpr/class
    constructs (``closures inside cpdef functions not yet supported``);
    comprehensions compile inline and stay allowed.
    """
    class _C(cst.CSTVisitor):
        found: bool = False

        def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
            self.found = True
            return False  # async defs are FunctionDef too — covers both

        def visit_ClassDef(self, n: cst.ClassDef) -> bool:
            self.found = True
            return False

        def visit_Lambda(self, n: cst.Lambda) -> bool:
            self.found = True
            return False

        def visit_GeneratorExp(self, n: cst.GeneratorExp) -> bool:
            self.found = True
            return False

    v = _C()
    fn.body.visit(v)
    return v.found


class _BindScan(cst.CSTVisitor):
    """Detect a name bound at the scanned scope level (no nested descent)."""

    def __init__(self, target: str) -> None:
        super().__init__()
        self.target = target
        self.bound = False

    def _mark(self, names: set[str] | cst.BaseExpression | None) -> None:
        if isinstance(names, set):
            if self.target in names:
                self.bound = True
        elif isinstance(names, cst.Name):
            if names.value == self.target:
                self.bound = True
        elif isinstance(names, (cst.Tuple, cst.List)):
            for el in names.elements:
                self._mark(el.value)
        elif isinstance(names, cst.StarredElement):
            self._mark(names.value)

    # nested defs/classes bind only their *names* here; never descend —
    # inner bodies are separate scopes (comprehension ``for`` targets are
    # comprehension-scoped, but marking them is safely over-conservative).
    def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
        self._mark(n.name)
        return False

    def visit_ClassDef(self, n: cst.ClassDef) -> bool:
        self._mark(n.name)
        return False

    def visit_Lambda(self, n: cst.Lambda) -> bool:
        return False

    def visit_Param(self, n: cst.Param) -> None:
        self._mark(n.name)

    def visit_Assign(self, n: cst.Assign) -> None:
        for t in n.targets:
            self._mark(_target_names(t.target))

    def visit_AnnAssign(self, n: cst.AnnAssign) -> None:
        self._mark(_target_names(n.target))

    def visit_AugAssign(self, n: cst.AugAssign) -> None:
        self._mark(_target_names(n.target))

    def visit_For(self, n: cst.For) -> None:
        self._mark(n.target)

    def visit_CompFor(self, n: cst.CompFor) -> None:
        self._mark(n.target)

    def visit_NamedExpr(self, n: cst.NamedExpr) -> None:
        self._mark(n.target)

    def visit_WithItem(self, n: cst.WithItem) -> None:
        if n.asname is not None:
            self._mark(n.asname.name)

    def visit_ExceptHandler(self, n: cst.ExceptHandler) -> None:
        if n.name is not None:
            self._mark(n.name.name)

    def visit_Del(self, n: cst.Del) -> None:
        self._mark(n.target)

    def visit_Global(self, n: cst.Global) -> None:
        for i in n.names:
            self._mark(i.name)

    def visit_Nonlocal(self, n: cst.Nonlocal) -> None:
        for i in n.names:
            self._mark(i.name)

    def visit_Import(self, n: cst.Import) -> None:
        for a in n.names:
            if a.asname is not None:
                self._mark(a.asname.name)
            elif isinstance(a.name, cst.Name):
                self._mark({a.name.value})

    def visit_ImportFrom(self, n: cst.ImportFrom) -> None:
        if isinstance(n.names, cst.ImportStar):
            return
        for a in n.names:
            if not isinstance(a, cst.ImportAlias):
                continue
            if a.asname is not None:
                self._mark(a.asname.name)
            elif isinstance(a.name, cst.Name):
                self._mark(a.name)

    def visit_MatchAs(self, n: cst.MatchAs) -> None:
        if n.name is not None:
            self._mark(n.name)

    def visit_MatchStar(self, n: cst.MatchStar) -> None:
        self._mark(n.name)


class _ForTargetScan(cst.CSTVisitor):
    """``for``-target names bound at the scanned level (no nested descent).

    ``range``/``enumerate`` loops are skipped when those builtins are
    unshadowed: ``infer_types`` correctly int-types their induction vars
    and a forced ``object`` decl would lose that speed for no safety gain.
    """

    _SKIP_HEADS = {"range", "enumerate"}

    def __init__(self, skip_known: bool) -> None:
        super().__init__()
        self.skip_known = skip_known
        self.names: set[str] = set()

    def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
        return False

    def visit_ClassDef(self, n: cst.ClassDef) -> bool:
        return False

    def visit_Lambda(self, n: cst.Lambda) -> bool:
        return False

    def visit_For(self, n: cst.For) -> bool:
        if n.asynchronous is not None:
            return True
        it = n.iter
        if (
            self.skip_known
            and isinstance(it, cst.Call)
            and isinstance(it.func, cst.Name)
            and it.func.value in self._SKIP_HEADS
        ):
            return True  # keep int-inferred index vars
        self.names |= _target_names(n.target)
        return True


def _fn_for_targets(fn: cst.FunctionDef, skip_known: bool) -> set[str]:
    v = _ForTargetScan(skip_known)
    fn.body.visit(v)
    return v.names


def _mod_for_targets(module: cst.Module, skip_known: bool) -> set[str]:
    v = _ForTargetScan(skip_known)
    module.visit(v)
    return v.names


class _DeclareBindScan(cst.CSTVisitor):
    """Names bound via ``x = cython.declare(...)`` at the scanned level.

    The declare call *is* the Cython declaration — a parallel ``x: object``
    decl is a ``redeclared`` error, so ``none_decl`` injection must skip
    these names.
    """

    def __init__(self) -> None:
        super().__init__()
        self.names: set[str] = set()

    def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
        return False

    def visit_ClassDef(self, n: cst.ClassDef) -> bool:
        return False

    def visit_Lambda(self, n: cst.Lambda) -> bool:
        return False

    def _check(self, target: cst.BaseExpression, value: cst.BaseExpression | None) -> None:
        if (
            isinstance(value, cst.Call)
            and _expr_dotted(value.func) == "cython.declare"
        ):
            self.names |= _target_names(target)

    def visit_Assign(self, n: cst.Assign) -> None:
        for t in n.targets:
            self._check(t.target, n.value)

    def visit_AnnAssign(self, n: cst.AnnAssign) -> None:
        self._check(n.target, n.value)


def _fn_declare_binds(fn: cst.FunctionDef) -> set[str]:
    v = _DeclareBindScan()
    fn.body.visit(v)
    return v.names


def _mod_declare_binds(module: cst.Module) -> set[str]:
    names: set[str] = set()
    for stmt in module.body:
        if not isinstance(stmt, cst.SimpleStatementLine):
            continue
        for el in stmt.body:
            if isinstance(el, cst.Assign):
                for t in el.targets:
                    if (
                        isinstance(el.value, cst.Call)
                        and _expr_dotted(el.value.func) == "cython.declare"
                    ):
                        names |= _target_names(t.target)
            elif (
                isinstance(el, cst.AnnAssign)
                and isinstance(el.value, cst.Call)
                and _expr_dotted(el.value.func) == "cython.declare"
            ):
                names |= _target_names(el.target)
    return names


# Call forms whose results may be ``None`` even when the annotation looks
# scalar — assignments must stay ``object`` or ``infer_types`` can C-type the
# target and crash on ``None`` before any guard runs.
_NONEABLE_ATTR_HEADS = {
    "get", "pop", "match", "fullmatch", "search", "findall", "finditer",
}
_NONEABLE_NAME_HEADS = {"next", "getattr"}


def _noneable_call(expr: cst.BaseExpression) -> bool:
    """True when ``expr`` is a call form that may return ``None``."""
    if not isinstance(expr, cst.Call):
        return False
    f = expr.func
    if isinstance(f, cst.Attribute):
        if f.attr.value in _NONEABLE_ATTR_HEADS:
            return True
        return (
            f.attr.value == "group"
            and isinstance(f.value, cst.Call)
            and isinstance(f.value.func, cst.Attribute)
            and f.value.func.attr.value in {"match", "search", "fullmatch"}
        )
    return isinstance(f, cst.Name) and f.value in _NONEABLE_NAME_HEADS


class _NoneCmpScan(cst.CSTVisitor):
    """Names that may hold ``None`` at the scanned scope level.

    Two evidence forms: compared against ``None``
    (``is``/``is not``/``==``/``!=``) or assigned a maybe-``None`` call
    (``d.get``, ``d.pop``, ``re.match/search``, ``next``, ``getattr``).
    """

    def __init__(self) -> None:
        super().__init__()
        self.names: set[str] = set()

    # inner bodies are separate scopes; comprehension vars marked here are
    # merely over-conservative (pinning a non-None-able name is still safe).
    def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
        return False

    def visit_ClassDef(self, n: cst.ClassDef) -> bool:
        return False

    def visit_Lambda(self, n: cst.Lambda) -> bool:
        return False

    def visit_Comparison(self, n: cst.Comparison) -> None:
        operands = [n.left, *(c.comparator for c in n.comparisons)]
        if not any(isinstance(o, cst.Name) and o.value == "None" for o in operands):
            return
        for o in operands:
            if isinstance(o, cst.Name) and o.value != "None":
                self.names.add(o.value)

    def visit_Assign(self, n: cst.Assign) -> None:
        if _noneable_call(n.value):
            for t in n.targets:
                self.names |= _target_names(t.target)

    def visit_AnnAssign(self, n: cst.AnnAssign) -> None:
        if n.value is not None and _noneable_call(n.value):
            self.names |= _target_names(n.target)


class _GlbScan(cst.CSTVisitor):
    """``global``/``nonlocal`` names at the scanned level (no nesting)."""

    def __init__(self) -> None:
        super().__init__()
        self.names: set[str] = set()

    def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
        return False

    def visit_ClassDef(self, n: cst.ClassDef) -> bool:
        return False

    def visit_Lambda(self, n: cst.Lambda) -> bool:
        return False

    def visit_Global(self, n: cst.Global) -> None:
        for i in n.names:
            self.names.add(i.name.value)

    def visit_Nonlocal(self, n: cst.Nonlocal) -> None:
        for i in n.names:
            self.names.add(i.name.value)


def _fn_none_checked(fn: cst.FunctionDef) -> set[str]:
    """Names compared to ``None`` inside ``fn``'s own scope.

    ``global``/``nonlocal`` names are excluded — they cannot be retyped by
    a local annotation, and ``del``-ed names are filtered by the caller.
    """
    v = _NoneCmpScan()
    fn.body.visit(v)
    g = _GlbScan()
    fn.body.visit(g)
    return v.names - g.names


# Builtin annotation heads that Cython enforces with an *exact* type check —
# ``x: dict`` rejects ``defaultdict``, ``x: str`` rejects ``str``-enums —
# while CPython annotations never check at all.  Unless the value is
# provably the exact builtin, these demote to ``object``.
_EXACT_HEADS = {"str", "bytes", "bytearray", "dict", "list", "set", "tuple", "frozenset"}

_CONST_NAMES = {"None", "True", "False", "Ellipsis"}


def _ann_has_exact(expr: cst.BaseExpression) -> bool:
    """True when an annotation is or contains an exact-checked builtin.

    Cython enforces exact checks for ``str``/``dict``/… components anywhere
    in a union (``str | None`` → ``Optional[str]`` still ``CheckExact``s the
    non-``None`` branch), so a ``StrEnum`` or ``defaultdict`` value crashes
    at the boundary.  ``Union[...]``/``Optional[...]`` spellings count too.
    """
    if _ann_head(expr) in _EXACT_HEADS:
        return True
    if isinstance(expr, cst.BinaryOperation) and isinstance(expr.operator, cst.BitOr):
        return _ann_has_exact(expr.left) or _ann_has_exact(expr.right)
    if (
        isinstance(expr, cst.Subscript)
        and isinstance(expr.value, cst.Name)
        and expr.value.value in {"Union", "Optional"}
    ):
        return any(
            isinstance(s.slice, cst.Index) and _ann_has_exact(s.slice.value)
            for s in expr.slice
        )
    return False


def _literalish(e: cst.BaseExpression) -> bool:
    """Operand guaranteed to evaluate to a plain ``PyObject`` constant."""
    if isinstance(
        e,
        (
            cst.Integer, cst.Float, cst.Imaginary, cst.SimpleString,
            cst.ConcatenatedString, cst.FormattedString,
        ),
    ):
        return True
    if isinstance(e, cst.Name):
        return e.value in _CONST_NAMES
    if isinstance(e, (cst.Tuple, cst.List, cst.Set)):
        return all(_literalish(el.value) for el in e.elements)
    if isinstance(e, cst.UnaryOperation):
        return _literalish(e.expression)
    return False


def _call_head(e: cst.BaseExpression) -> str | None:
    """Bare name of a ``Name(...)`` call's callee."""
    if isinstance(e, cst.Call) and isinstance(e.func, cst.Name):
        return e.func.value
    return None


def _is_bytes_literal(e: cst.BaseExpression) -> bool:
    """True for ``b"..."`` literal strings."""
    if not isinstance(e, cst.SimpleString):
        return False
    raw = e.value.lower()
    prefix = raw.split("'", 1)[0].split('"', 1)[0]
    return "b" in prefix


def _value_exact(v: cst.BaseExpression | None, head: str) -> bool:
    """True when ``v`` provably evaluates to the exact builtin ``head``.

    Only literals and the matching builtin constructor qualify — anything
    else (calls, attributes, subscripts, names) may deliver a subclass.
    """
    if v is None:
        return False
    if head == "str":
        if isinstance(v, (cst.ConcatenatedString, cst.FormattedString)):
            return True
        if isinstance(v, cst.SimpleString):
            return not _is_bytes_literal(v)
        return _call_head(v) == "str" or (
            isinstance(v, cst.Call)
            and isinstance(v.func, cst.Attribute)
            and v.func.attr.value == "join"
        )
    if head == "bytes":
        return _is_bytes_literal(v) or _call_head(v) == "bytes"
    if head == "bytearray":
        return _call_head(v) == "bytearray"
    if head == "dict":
        return isinstance(v, (cst.Dict, cst.DictComp)) or _call_head(v) == "dict"
    if head == "list":
        return isinstance(v, (cst.List, cst.ListComp)) or _call_head(v) == "list"
    if head == "set":
        return isinstance(v, (cst.Set, cst.SetComp)) or _call_head(v) == "set"
    if head == "frozenset":
        return _call_head(v) == "frozenset"
    if head == "tuple":
        return isinstance(v, cst.Tuple) or _call_head(v) == "tuple"
    return False


class _ReturnScan(cst.CSTVisitor):
    """``return`` values at the scanned function's own level."""

    def __init__(self) -> None:
        super().__init__()
        self.vals: list[cst.BaseExpression | None] = []

    def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
        return False

    def visit_ClassDef(self, n: cst.ClassDef) -> bool:
        return False

    def visit_Lambda(self, n: cst.Lambda) -> bool:
        return False

    def visit_Return(self, n: cst.Return) -> None:
        self.vals.append(n.value)


def _returns_all_exact(fn: cst.FunctionDef, head: str) -> bool:
    """True when every own-level ``return`` yields the exact builtin.

    ``-> dict`` returning a bare ``return``/``return None`` still crashes
    under Cython's return coercion — the annotation only survives when all
    returns provably produce the exact type.
    """
    rs = _ReturnScan()
    fn.body.visit(rs)
    return bool(rs.vals) and all(
        v is not None and _value_exact(v, head) for v in rs.vals
    )


class _NonImportBindScan(_BindScan):
    """``_BindScan`` that ignores ``import <target>`` itself.

    ``import builtins`` *is* the binding that makes ``builtins.iter``
    resolve to stdlib — only non-import bindings (assigns, params,
    from-imports, ``import x as builtins``) actually shadow it.
    """

    def visit_Import(self, n: cst.Import) -> None:
        for a in n.names:
            if (
                a.asname is None
                and isinstance(a.name, cst.Name)
                and a.name.value == self.target
            ):
                continue  # plain ``import <target>`` — the desired binding
            if a.asname is not None:
                self._mark(a.asname.name)
            elif isinstance(a.name, cst.Name):
                self._mark({a.name.value})


def _fn_binds_nonimport(fn: cst.FunctionDef, name: str) -> bool:
    v = _NonImportBindScan(name)
    fn.params.visit(v)
    fn.body.visit(v)
    return v.bound


def _module_binds_nonimport(module: cst.Module, name: str) -> bool:
    v = _NonImportBindScan(name)
    module.visit(v)
    return v.bound


def _fn_binds(fn: cst.FunctionDef, name: str) -> bool:
    """True when ``fn``'s own scope binds ``name`` (builtin then shadowed)."""
    v = _BindScan(name)
    fn.params.visit(v)
    fn.body.visit(v)
    return v.bound


def _module_binds(module: cst.Module, name: str) -> bool:
    """True when module top level binds ``name``."""
    v = _BindScan(name)
    module.visit(v)
    return v.bound


def _contains_yield(fn: cst.FunctionDef) -> bool:
    """True when the function body yields at its own level (not nested)."""
    class _Y(cst.CSTVisitor):
        found: bool = False

        def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
            return False  # never descend into nested functions

        def visit_Yield(self, n: cst.Yield) -> None:
            self.found = True

    v = _Y()
    fn.body.visit(v)
    return v.found


def _fixed_tuple_ann(ann: cst.Annotation | None) -> bool:
    """True for fixed-arity ``tuple[T, U, ...]`` annotations (ctuple).

    Variadic ``tuple[T, ...]`` carries an Ellipsis element and does not
    force Cython's ctuple coercion.
    """
    if ann is None:
        return False
    node = ann.annotation
    if not (
        isinstance(node, cst.Subscript)
        and _expr_dotted(node.value) in {"tuple", "builtins.tuple"}
    ):
        return False
    return not any(
        isinstance(el.slice.value, cst.Ellipsis) for el in node.slice
    )


def _starred_tuple_literal(expr: cst.CSTNode | None) -> bool:
    """``(…, *x, …)`` — a tuple literal splicing a runtime sequence."""
    return isinstance(expr, cst.Tuple) and any(
        isinstance(el, cst.StarredElement) for el in expr.elements
    )


def _has_starred_tuple_return(fn: cst.FunctionDef) -> bool:
    """Any own-level ``return (…, *x, …)`` — a static ctuple coercion error."""
    class _S(cst.CSTVisitor):
        found: bool = False

        def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
            return False  # nested functions own their returns

        def visit_ClassDef(self, n: cst.ClassDef) -> bool:
            return False

        def visit_Return(self, n: cst.Return) -> None:
            if _starred_tuple_literal(n.value):
                self.found = True

    v = _S()
    fn.body.visit(v)
    return v.found


def _returns_none(fn: cst.FunctionDef) -> bool:
    """True when any own-level return yields ``None`` or is bare."""
    class _R(cst.CSTVisitor):
        found: bool = False

        def visit_FunctionDef(self, n: cst.FunctionDef) -> bool:
            return False  # never descend into nested functions

        def visit_Return(self, n: cst.Return) -> None:
            if n.value is None or (
                isinstance(n.value, cst.Name) and n.value.value == "None"
            ):
                self.found = True

    v = _R()
    fn.body.visit(v)
    return v.found


def transform_source(
    source: str, module_record: dict, stats: dict
) -> str:
    """Rewrite one module's source; returns transformed text."""
    tree = cst.parse_module(source)
    scan = _OverloadScan()
    tree.visit(scan)
    ann_scan = _AnnotationNameScan()
    tree.visit(ann_scan)
    late = _LateAliasScan()
    tree.visit(late)
    tx = Cythonizer(
        module_record, stats,
        overloaded=scan.duplicates() | _cclass_override_conflicts(module_record),
        annotation_names=ann_scan.names, late_aliases=late.late,
    )
    return tree.visit(tx).code

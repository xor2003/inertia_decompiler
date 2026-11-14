"""Layer: Tooling/cythonize.

Responsibility: whole-program census for the automated Cython pure-mode rewrite.

Scans every ``*.py`` under the target package and produces ``manifest.json``:

- ``classes`` — per-module class table: bases, decorators, risk flags,
  harvested ``self.<attr>`` write types (for ``cdef`` attribute injection),
  and the computed ``cclass`` verdict from the eligibility fixpoint.
- ``class_index`` — qualified-name registry mapping ``module.Class`` to the
  class entry so the transformer can recognise cclass-typed annotations.
- ``files`` — per-file facts needed by the transformer (existing ``import
  cython``, ``cython`` name collisions, dataclass import bindings).

Eligibility is computed program-wide: a class may become ``@cython.cclass``
only when every base resolves to ``object`` or to another eligible class.
"""

from __future__ import annotations

import ast
import json
import pathlib
import sys
from dataclasses import dataclass, field

# Bases that can never back a cdef class (keep the class fully dynamic).
POISON_BASE_NAMES: frozenset[str] = frozenset(
    {
        "Enum", "StrEnum", "IntEnum", "IntFlag", "Flag", "ReprEnum",
        "Protocol", "ABC", "ABCMeta", "TypedDict", "NamedTuple",
        "Exception", "BaseException", "RuntimeError", "ValueError",
        "TypeError", "KeyError", "IndexError", "AttributeError",
        "StopIteration", "StopAsyncIteration", "Warning", "Generic",
    }
)

import builtins as _builtins_mod

# Class members that shadow builtins break or miscompile Cython's
# generated dataclass fragments (the repr recursion guard calls
# ``set()``/``id()``/``len()`` at class scope where a member named
# ``set`` resolves to the method instead of the builtin — observed
# compile error ``Call with wrong number of arguments``). Any builtin
# name is a landmine here; flag the class, keep it dynamic.
BUILTIN_MEMBER_NAMES: frozenset[str] = frozenset(dir(_builtins_mod))

# C type keywords that are legal Python identifiers but break Cython's
# generated ``__init__`` fragment when used as cdef dataclass field or
# cdef attribute names (verified: ``Empty declarator`` errors).
C_FIELD_KEYWORDS: frozenset[str] = frozenset(
    {
        "int", "long", "short", "char", "float", "double", "void",
        "signed", "unsigned", "const", "volatile", "sizeof",
        "_Bool", "_Complex", "_Imaginary",
    }
)

# Decorators that are compatible with @cython.cclass stacking.
SAFE_CLASS_DECORATORS: frozenset[str] = frozenset(
    {
        "dataclass", "cclass", "final", "no_type_check",
        "frozen",
        "cython.cclass", "cython.dataclasses.dataclass",
        "cython.freelist", "cython.final",
        "dataclasses.dataclass", "typing.final",
    }
)


def _decorator_name(dec: ast.expr) -> str:
    """Return the dotted name of a decorator expression (``mod.attr.name``)."""
    node = dec.func if isinstance(dec, ast.Call) else dec
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _expr_head_name(expr: ast.expr) -> str:
    """Terminal name of ``mod.sub.Name`` or plain ``Name`` expressions."""
    node = expr
    while isinstance(node, ast.Attribute):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _ann_name(expr: ast.expr | None) -> str:
    """Simple annotation head name (``int`` of ``int``/``Optional[int]`` etc.)."""
    if expr is None:
        return ""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return _ann_name_from_source(expr.value)
    node = expr
    while isinstance(node, (ast.Subscript,)):
        node = node.value
    while isinstance(node, ast.Attribute):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _ann_name_from_source(text: str) -> str:
    """Head name parsed from a string annotation."""
    try:
        return _ann_name(ast.parse(text.strip(), mode="eval").body)
    except SyntaxError:
        return ""


_LITERAL_TYPE: dict[type, str] = {
    int: "int",
    float: "float",
    bool: "bool",
    str: "str",
    bytes: "bytes",
    list: "list",
    dict: "dict",
    set: "set",
    tuple: "tuple",
}


def _rhs_type_hint(node: ast.expr) -> str:
    """Cheap literal/call-based type guess for an assignment RHS."""
    if isinstance(node, ast.Constant):
        if node.value is None:
            return "None"
        return _LITERAL_TYPE.get(type(node.value), "")
    if isinstance(node, (ast.ListComp, ast.List)):
        return "list"
    if isinstance(node, (ast.DictComp, ast.Dict)):
        return "dict"
    if isinstance(node, (ast.SetComp, ast.Set)):
        return "set"
    if isinstance(node, ast.GeneratorExp):
        return ""
    if isinstance(node, ast.Tuple):
        return "tuple"
    if isinstance(node, ast.Call):
        return _expr_head_name(node.func)
    return ""


def _rhs_has_class_closure(value: ast.AST) -> bool:
    """True when a class-body attribute value needs a closure scope.

    Cython's CClassDef emitter cannot compile class-level attribute
    initialisers that create a nested scope: bare ``attr = lambda`` /
    genexpr assignments, generator expressions nested inside calls, and
    lambdas whose body contains a comprehension (the comprehension is
    itself a closure scope inside the lambda).
    """
    if isinstance(value, (ast.Lambda, ast.GeneratorExp)):
        return True
    for sub in ast.walk(value):
        if isinstance(sub, ast.GeneratorExp):
            return True
        if isinstance(sub, ast.Lambda) and any(
            isinstance(
                n, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Lambda)
            )
            for n in ast.walk(sub.body)
        ):
            return True
    return False


@dataclass
class ClassInfo:
    """Census record for one class definition."""

    module: str
    name: str
    qualname: str
    bases: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    self_attrs: dict[str, set[str]] = field(default_factory=dict)
    del_self_attrs: set[str] = field(default_factory=set)
    field_names: set[str] = field(default_factory=set)
    member_names: set[str] = field(default_factory=set)
    has_yield: bool = False
    risky: dict[str, bool] = field(default_factory=dict)
    cclass: bool = False
    skip_reason: str = ""

    def to_json(self) -> dict:
        """Serialise to the manifest shape."""
        return {
            "name": self.name,
            "qualname": self.qualname,
            "bases": self.bases,
            "decorators": self.decorators,
            "self_attrs": {k: sorted(v) for k, v in self.self_attrs.items()},
            "del_self_attrs": sorted(self.del_self_attrs),
            "field_names": sorted(self.field_names),
            "member_names": sorted(self.member_names),
            "risky": self.risky,
            "cclass": self.cclass,
            "skip_reason": self.skip_reason,
        }


class _ClassCensus(ast.NodeVisitor):
    """Collect ClassInfo for all classes in one module."""

    def __init__(self, module: str) -> None:
        self.module = module
        self.classes: dict[str, ClassInfo] = {}
        self._stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Record the class then descend into nested definitions."""
        qualname = ".".join([*self._stack, node.name]) if self._stack else node.name
        info = ClassInfo(
            module=self.module,
            name=node.name,
            qualname=qualname,
            bases=[ast.unparse(b) for b in node.bases],
            decorators=[_decorator_name(d) for d in node.decorator_list],
            risky={
                "metaclass": any(k.arg == "metaclass" for k in node.keywords),
                "multi_inherit": len(node.bases) > 1,
                "star_base": any(isinstance(b, ast.Starred) for b in node.bases),
                "dict": False,
                "getattr": False,
                "setattr": False,
                "getattribute": False,
                "slots": False,
                "weakref": False,
                "delattr": False,
                "dynamic_self": False,
            },
        )
        self.classes[qualname] = info
        self._stack.append(node.name)
        for child in node.body:
            self._scan_body_node(child, info)
        self._stack.pop()
        # Nested classes were recorded during _scan_body_node via visit.

    def _scan_body_node(self, node: ast.AST, info: ClassInfo) -> None:
        """Walk class body scanning for risk markers and self-attr writes."""
        if isinstance(node, ast.ClassDef):
            self.visit_ClassDef(node)
            return
        for sub in ast.walk(node):
            if isinstance(sub, ast.ClassDef) and sub is not node:
                # handled via visit in the parent loop for direct nesting only
                continue
            if isinstance(sub, ast.Name) and sub.id in {"__dict__", "weakref"}:
                info.risky["dict" if sub.id == "__dict__" else "weakref"] = True
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                if sub.value.id == "__dict__":
                    info.risky["dict"] = True
            if isinstance(sub, ast.Assign):
                self._scan_assign_targets(sub.targets, sub.value, info)
            elif isinstance(sub, ast.AnnAssign) and sub.value is not None:
                self._scan_assign_targets([sub.target], sub.value, info)
            elif isinstance(sub, ast.AugAssign):
                self._scan_assign_targets([sub.target], sub.value, info)
            elif isinstance(sub, ast.Name) and sub.id == "__slots__":
                info.risky["slots"] = True
            elif isinstance(sub, ast.Assign):
                pass
            if isinstance(sub, ast.Delete):
                for t in sub.targets:
                    if (
                        isinstance(t, ast.Attribute)
                        and isinstance(t.value, ast.Name)
                        and t.value.id == "self"
                    ):
                        info.del_self_attrs.add(t.attr)
            if (
                sub is node
                and isinstance(sub, (ast.Assign, ast.AnnAssign))
                and sub.value is not None
                and _rhs_has_class_closure(sub.value)
            ):
                # Class-level values whose subtree needs a closure scope
                # (bare lambda/genexpr RHS, genexpr inside a call, lambda
                # containing a comprehension) crash CClassDef compilation.
                # Plain lambdas like field(default_factory=lambda: 7) are
                # fine — only closure-creating ones are fatal.
                info.risky["class_lambda"] = True
            if sub is node and isinstance(sub, ast.Assign):
                for t in sub.targets:
                    if isinstance(t, ast.Name):
                        info.field_names.add(t.id)
            if sub is node and isinstance(sub, ast.AnnAssign):
                if isinstance(sub.target, ast.Name):
                    info.field_names.add(sub.target.id)
            if sub is node and isinstance(
                sub, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                info.member_names.add(sub.name)
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                if sub.func.id == "setattr" and sub.args and isinstance(
                    sub.args[0], (ast.Name, ast.Attribute)
                ):
                    head = sub.args[0]
                    if isinstance(head, ast.Name) and head.id in {"self", "cls"}:
                        info.risky["dynamic_self"] = True
                    elif isinstance(head, ast.Attribute) and isinstance(
                        head.value, ast.Name
                    ) and head.value.id in {"self", "cls"}:
                        info.risky["dynamic_self"] = True
                if sub.func.id == "delattr":
                    info.risky["delattr"] = True
                if sub.func.id in {"__setattr__", "__getattribute__", "__getattr__"}:
                    info.risky[sub.func.id.strip("_")] = True
        for sub in ast.walk(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if sub.name in {"__getattr__", "__setattr__", "__getattribute__"}:
                    info.risky[sub.name.strip("_").rstrip("_")] = True
                    key = {"__getattr__": "getattr", "__setattr__": "setattr",
                           "__getattribute__": "getattribute"}[sub.name]
                    info.risky[key] = True
                if sub.name == "__init_subclass__":
                    info.risky["init_subclass"] = True
                if sub.name == "__new__":
                    info.risky["custom_new"] = True

    def _scan_assign_targets(
        self, targets: list[ast.expr], value: ast.expr, info: ClassInfo
    ) -> None:
        """Harvest ``self.<name> = rhs`` attribute writes for cdef declarations."""
        hint = _rhs_type_hint(value)
        for target in targets:
            if isinstance(target, ast.Starred):
                target = target.value
            if isinstance(target, ast.Tuple):
                self._scan_assign_targets(list(target.elts), value, info)
                continue
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                info.self_attrs.setdefault(target.attr, set()).add(
                    hint or "object"
                )

    def generic_visit(self, node: ast.AST) -> None:  # noqa: D102
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                self.visit_ClassDef(child)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # functions nested at module level cannot contain class-level
                # ``self`` writes belonging to a class here; skip deeper walk
                for inner in ast.iter_child_nodes(child):
                    if isinstance(inner, ast.ClassDef):
                        self.visit_ClassDef(inner)


def _module_name(root: pathlib.Path, path: pathlib.Path) -> str:
    """Dotted module name for ``path`` under package ``root``."""
    rel = path.relative_to(root.parent)
    return ".".join(rel.with_suffix("").parts)


def build_manifest(root: pathlib.Path) -> dict:
    """Scan ``root`` and return the census manifest dict."""
    modules: dict[str, dict] = {}
    class_index: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*.py")):
        module = _module_name(root, path)
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except SyntaxError as exc:
            modules[module] = {"error": f"SyntaxError: {exc}"}
            continue
        census = _ClassCensus(module)
        for top in tree.body:
            if isinstance(top, ast.ClassDef):
                census.visit_ClassDef(top)
        src = path.read_text(errors="replace")
        modules[module] = {
            "path": str(path),
            "has_cython_import": "import cython" in src,
            "cython_name_collision": bool(
                [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "cython"]
            )
            and "import cython" not in src,
            "classes": {
                qual: info.to_json() for qual, info in census.classes.items()
            },
        }
        for qual, info in census.classes.items():
            class_index.setdefault(info.name, []).append(f"{module}.{qual}")

    # Eligibility fixpoint on the whole program.
    flat: dict[str, ClassInfo] = {}
    for module, mdata in modules.items():
        for qual, cdata in mdata.get("classes", {}).items():
            flat[f"{module}.{qual}"] = ClassInfo(
                module=module,
                name=cdata["name"],
                qualname=cdata["qualname"],
                bases=cdata["bases"],
                decorators=cdata["decorators"],
                self_attrs={
                    k: set(v) for k, v in cdata.get("self_attrs", {}).items()
                },
                field_names=set(cdata.get("field_names", [])),
                member_names=set(cdata.get("member_names", [])),
                risky=cdata["risky"],
            )

    def resolve_base(base_src: str, module: str) -> str | None:
        """Resolve a base to ``module.Class`` — same module only.

        cdef classes can only inherit from extension types visible at
        compile time; cross-module bases would need ``.pxd`` cimports, so
        only same-module bases keep a class eligible.
        """
        head = _ann_name_from_source(base_src) or _expr_head_from_source(base_src)
        if not head:
            return None
        for cand in class_index.get(head, ()):
            if cand.rpartition(".")[0] == module or cand.startswith(module + "."):
                return cand
        return None

    def _expr_head_from_source(text: str) -> str:
        try:
            return _expr_head_name(ast.parse(text.strip(), mode="eval").body)
        except SyntaxError:
            return ""

    def eligible(info: ClassInfo) -> tuple[bool, str]:
        """Single-step eligibility check ignoring base eligibility."""
        r = info.risky
        if r.get("metaclass"):
            return False, "metaclass"
        if r.get("multi_inherit"):
            return False, "multi_inherit"
        if r.get("star_base"):
            return False, "star_base"
        if r.get("dict"):
            return False, "__dict__"
        if r.get("getattr") or r.get("setattr") or r.get("getattribute"):
            return False, "dynamic_attribute"
        if r.get("slots"):
            return False, "__slots__"
        if r.get("weakref"):
            return False, "weakref"
        if r.get("dynamic_self"):
            return False, "setattr(self)"
        if r.get("class_lambda"):
            return False, "class_level_lambda"
        if r.get("init_subclass"):
            return False, "__init_subclass__"
        reserved = (set(info.self_attrs) | info.field_names) & C_FIELD_KEYWORDS
        if reserved:
            return False, f"c_keyword_field:{sorted(reserved)[0]}"
        shadow = (
            set(info.self_attrs) | info.field_names | info.member_names
        ) & BUILTIN_MEMBER_NAMES
        if shadow:
            return False, f"builtin_member:{sorted(shadow)[0]}"
        for dec in info.decorators:
            if dec not in SAFE_CLASS_DECORATORS:
                return False, f"decorator:{dec}"
        for base in info.bases:
            name = _ann_name_from_source(base)
            if name in POISON_BASE_NAMES:
                return False, f"base:{name}"
        return True, ""

    # Seed eligibility with intrinsic flags, then propagate base constraints.
    for key, info in flat.items():
        ok, reason = eligible(info)
        info.cclass = ok
        info.skip_reason = reason

    changed = True
    while changed:
        changed = False
        for key, info in flat.items():
            if not info.cclass:
                continue
            for base in info.bases:
                resolved = resolve_base(base, info.module)
                if resolved is None:
                    name = _ann_name_from_source(base)
                    if name and name not in {
                        "object", "Generic", "NamedTuple", "TypedDict",
                    } and not name.isupper() and name not in POISON_BASE_NAMES:
                        info.cclass = False
                        info.skip_reason = f"external_base:{base}"
                        changed = True
                        break
                    if name in POISON_BASE_NAMES:
                        info.cclass = False
                        info.skip_reason = f"base:{name}"
                        changed = True
                        break
                    continue
                if resolved in flat and not flat[resolved].cclass:
                    info.cclass = False
                    info.skip_reason = f"base_not_cclass:{base}"
                    changed = True
                    break

    # ``__post_init__`` effective-per-MRO: cython dataclass ``__init__`` only
    # calls a ``__post_init__`` defined on the class itself — an inherited
    # one silently never runs (``field(init=False)`` slots stay ``None``).
    post_init_mro: dict[str, bool] = {}
    changed = True
    while changed:
        changed = False
        for key, info in flat.items():
            has = "__post_init__" in info.member_names or any(
                post_init_mro.get(resolved, False)
                for base in info.bases
                if (resolved := resolve_base(base, info.module)) is not None
            )
            if has != post_init_mro.get(key, False):
                post_init_mro[key] = has
                changed = True
    for key, info in flat.items():
        if (
            info.cclass
            and post_init_mro.get(key)
            and "__post_init__" not in info.member_names
        ):
            info.cclass = False
            info.skip_reason = "inherited_post_init"

    cclass_names = {
        info.name for info in flat.values() if info.cclass
    } | {k for k, v in flat.items() if v.cclass}

    for module, mdata in modules.items():
        for qual, cdata in mdata.get("classes", {}).items():
            key = f"{module}.{qual}"
            info = flat[key]
            cdata["cclass"] = info.cclass
            cdata["skip_reason"] = info.skip_reason

    return {
        "root": str(root),
        "modules": modules,
        "cclass_names": sorted(cclass_names),
        "cclass_qualified": sorted(k for k, v in flat.items() if v.cclass),
        "stats": {
            "modules": len(modules),
            "classes": len(flat),
            "cclass": sum(1 for v in flat.values() if v.cclass),
        },
    }


def main() -> None:
    """CLI: ``census.py <package-root> <out.json>``."""
    root = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else None
    manifest = build_manifest(root)
    text = json.dumps(manifest, indent=1, sort_keys=True)
    if out:
        out.write_text(text + "\n")
        s = manifest["stats"]
        print(f"modules={s['modules']} classes={s['classes']} cclass={s['cclass']}")
    else:
        print(text)


if __name__ == "__main__":
    main()

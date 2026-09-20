"""Check that changed non-test Python modules and definitions have explicit contracts.

Layer: Tooling/gates.
Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

type LineTrackedNode = (
    ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Assign | ast.AnnAssign | ast.AugAssign
)

_DYNAMIC_ATTR_BOUNDARY_TERMS = frozenset(("third-party", "angr", "codegen", "plugin", "compatibility"))


def _is_test_path(path: Path) -> bool:
    """Return whether a path belongs to the test tree."""

    parts = set(path.parts)
    if "scripts" in parts:
        return False
    return path.name.startswith("test_") or "tests" in parts or path.match("angr_platforms/tests/*.py")


def _tracked_by_git(path: Path) -> bool:
    """Return whether a path is tracked in the current git repository."""

    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(path)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _changed_lines_for_tracked_path(path: Path) -> set[int]:
    """Return added or modified line numbers in the working-tree diff for one file."""

    result = subprocess.run(
        ["git", "diff", "--unified=0", "--", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git diff failed for {path}")
    changed: set[int] = set()
    for line in result.stdout.splitlines():
        if not line.startswith("@@"):
            continue
        marker = line.split("+", 1)[1].split(" ", 1)[0]
        start_text, _, count_text = marker.partition(",")
        start = int(start_text)
        count = int(count_text or "1")
        changed.update(range(start, start + count))
    return changed


def _changed_lines(path: Path) -> set[int]:
    """Return changed lines, treating untracked files as fully changed."""

    if not _tracked_by_git(path):
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        return set(range(1, line_count + 1))
    return _changed_lines_for_tracked_path(path)


def _arg_missing_annotation(arg: ast.arg) -> bool:
    """Return whether a function argument lacks an annotation."""

    if arg.arg in {"self", "cls"}:
        return False
    return arg.annotation is None


def _function_missing_annotations(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return missing annotation labels for a function definition."""

    missing: list[str] = []
    positional = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    for arg in positional:
        if _arg_missing_annotation(arg):
            missing.append(arg.arg)
    if node.args.vararg is not None and _arg_missing_annotation(node.args.vararg):
        missing.append(f"*{node.args.vararg.arg}")
    if node.args.kwarg is not None and _arg_missing_annotation(node.args.kwarg):
        missing.append(f"**{node.args.kwarg.arg}")
    if node.returns is None:
        missing.append("return")
    return missing


def _is_public_definition_name(name: str) -> bool:
    """Return whether a definition is part of the public owned contract."""

    return not name.startswith("_")


def _definition_touches_changed_lines(node: LineTrackedNode, changed: set[int]) -> bool:
    """Return whether a definition range intersects changed working-tree lines."""

    start = node.lineno
    end = node.end_lineno if node.end_lineno is not None else start
    return any(line in changed for line in range(start, end + 1))


def _line_range_touches_changed_lines(start: int, end: int | None, changed: set[int]) -> bool:
    """Return whether a source line range intersects changed working-tree lines."""

    last = end if end is not None else start
    return any(line in changed for line in range(start, last + 1))


def _changed_functions_missing_annotations(path: Path) -> list[str]:
    """Return diagnostics for changed functions without full annotations."""

    changed = _changed_lines(path)
    if not changed:
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    diagnostics: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _definition_touches_changed_lines(node, changed):
            continue
        missing = _function_missing_annotations(node)
        if missing:
            diagnostics.append(f"{path}:{node.lineno}: {node.name} missing annotations: {', '.join(missing)}")
    return diagnostics


def _changed_definitions_missing_docstrings(path: Path) -> list[str]:
    """Return diagnostics for changed public definitions without docstrings."""

    changed = _changed_lines(path)
    if not changed:
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    diagnostics: list[str] = []
    public_defs: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            public_defs.append(node)
        if isinstance(node, ast.ClassDef):
            public_defs.extend(
                stmt
                for stmt in node.body
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            )
    for node in public_defs:
        if _is_public_definition_name(node.name) and _definition_touches_changed_lines(node, changed):  # noqa: SIM102
            if not (ast.get_docstring(node) or "").strip():
                diagnostics.append(f"{path}:{node.lineno}: {node.name} missing docstring")
    return diagnostics


def _decorator_name(node: ast.AST) -> str | None:
    """Return the simple decorator name for class-contract checks."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


def _class_is_dataclass(node: ast.ClassDef) -> bool:
    """Return whether a class is decorated as a dataclass."""

    return any(_decorator_name(decorator) == "dataclass" for decorator in node.decorator_list)


def _class_is_enum(node: ast.ClassDef) -> bool:
    """Return whether a class inherits from an enum base."""

    return any(_decorator_name(base) in {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"} for base in node.bases)


def _class_is_string_status_enum(node: ast.ClassDef) -> bool:
    """Return whether an enum class should use stable string member values."""

    return any(_decorator_name(base) in {"Enum", "StrEnum"} for base in node.bases)


def _assignment_target_names(node: ast.Assign) -> tuple[str, ...]:
    """Return simple names assigned by one class-level assignment."""

    names: list[str] = []
    for target in node.targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            names.extend(item.id for item in target.elts if isinstance(item, ast.Name))
    return tuple(names)


def _changed_dataclass_fields_missing_annotations(path: Path) -> list[str]:
    """Return diagnostics for changed dataclass fields written without annotations."""

    changed = _changed_lines(path)
    if not changed:
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    diagnostics: list[str] = []
    for class_node in ast.walk(tree):
        if not isinstance(class_node, ast.ClassDef) or not _class_is_dataclass(class_node):
            continue
        for stmt in class_node.body:
            if not isinstance(stmt, ast.Assign) or not _definition_touches_changed_lines(stmt, changed):
                continue
            for field_name in _assignment_target_names(stmt):
                if _is_public_definition_name(field_name):
                    diagnostics.append(f"{path}:{stmt.lineno}: {class_node.name}.{field_name} missing annotation")
    return diagnostics


def _changed_enum_members_missing_string_values(path: Path) -> list[str]:
    """Return diagnostics for changed status enum members without string values."""

    changed = _changed_lines(path)
    if not changed:
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    diagnostics: list[str] = []
    for class_node in ast.walk(tree):
        if not isinstance(class_node, ast.ClassDef) or not _class_is_string_status_enum(class_node):
            continue
        for stmt in class_node.body:
            if not isinstance(stmt, ast.Assign) or not _definition_touches_changed_lines(stmt, changed):
                continue
            if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                continue
            for member_name in _assignment_target_names(stmt):
                if _is_public_definition_name(member_name):
                    diagnostics.append(
                        f"{path}:{stmt.lineno}: {class_node.name}.{member_name} must use an explicit string value"
                    )
    return diagnostics


def _changed_public_assignments_missing_annotations(path: Path) -> list[str]:
    """Return diagnostics for changed public module/class assignments without annotations."""

    changed = _changed_lines(path)
    if not changed:
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    diagnostics: list[str] = []
    scopes: list[tuple[str | None, list[ast.stmt]]] = [(None, tree.body)]
    scopes.extend(
        (class_node.name, class_node.body)
        for class_node in tree.body
        if isinstance(class_node, ast.ClassDef) and not _class_is_dataclass(class_node) and not _class_is_enum(class_node)
    )
    for scope_name, body in scopes:
        for stmt in body:
            if not isinstance(stmt, ast.Assign) or not _definition_touches_changed_lines(stmt, changed):
                continue
            for target_name in _assignment_target_names(stmt):
                if not _is_public_definition_name(target_name):
                    continue
                qualified_name = f"{scope_name}.{target_name}" if scope_name is not None else target_name
                diagnostics.append(f"{path}:{stmt.lineno}: {qualified_name} missing annotation")
    return diagnostics


def _literal_dunder_all_names(value: ast.AST | None) -> tuple[str, ...] | None:
    """Return literal __all__ names, or None when the assignment is computed."""

    if not isinstance(value, (ast.Tuple, ast.List)):
        return None
    names: list[str] = []
    for element in value.elts:
        if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
            return None
        names.append(element.value)
    return tuple(names)


def _changed_computed_dunder_all(path: Path) -> list[str]:
    """Return diagnostics for changed computed __all__ export contracts."""

    changed = _changed_lines(path)
    if not changed:
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    diagnostics: list[str] = []
    for stmt in tree.body:
        targets: Sequence[ast.expr]
        if isinstance(stmt, ast.Assign):
            targets = stmt.targets
            value: ast.AST | None = stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            targets = (stmt.target,)
            value = stmt.value
        elif isinstance(stmt, ast.AugAssign):
            targets = (stmt.target,)
            value = None
        else:
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
            continue
        if not _definition_touches_changed_lines(stmt, changed):
            continue
        if _literal_dunder_all_names(value) is None:
            diagnostics.append(f"{path}:{stmt.lineno}: __all__ must be a literal tuple/list of string exports")
    return diagnostics


def _dynamic_attr_access_has_reason(lines: list[str], line_no: int) -> bool:
    """Return whether an attached comment explains a dynamic attribute boundary."""

    nearby_comments: list[str] = []
    for line in lines[max(0, line_no - 2) : line_no]:
        _, separator, comment = line.partition("#")
        if separator:
            nearby_comments.append(comment.strip().lower())
    reason = " ".join(nearby_comments)
    return (
        "dynamic" in reason
        and "boundary" in reason
        and any(term in reason for term in _DYNAMIC_ATTR_BOUNDARY_TERMS)
    )


def _dynamic_attr_reason_in_text(text: str | None) -> bool:
    """Return whether owned documentation explains a dynamic attribute boundary."""

    reason = (text or "").lower()
    return (
        "dynamic" in reason
        and "boundary" in reason
        and any(term in reason for term in _DYNAMIC_ATTR_BOUNDARY_TERMS)
    )


def _enclosing_dynamic_attr_reason(tree: ast.Module, line_no: int) -> str | None:
    """Return the nearest enclosing docstring that explains dynamic attribute access."""

    owner: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        end = node.end_lineno if node.end_lineno is not None else node.lineno
        if not (node.lineno <= line_no <= end):
            continue
        if owner is None or node.lineno >= owner.lineno:
            owner = node
    if owner is not None:
        docstring = ast.get_docstring(owner)
        if _dynamic_attr_reason_in_text(docstring):
            return docstring
    module_docstring = ast.get_docstring(tree)
    if _dynamic_attr_reason_in_text(module_docstring):
        return module_docstring
    return None


def _head_source(path: Path) -> str | None:
    """Return a tracked file's HEAD source, or none when no baseline exists."""

    result = subprocess.run(
        ["git", "show", f"HEAD:{path.as_posix()}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def _static_setattr_key(node: ast.Call) -> tuple[str, str] | None:
    """Return a stable target/field key for fixed-name setattr calls."""

    if not (
        isinstance(node.func, ast.Name)
        and node.func.id == "setattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
        and node.args[1].value.isidentifier()
    ):
        return None
    return ast.unparse(node.args[0]), node.args[1].value


def _static_setattr_counts(source: str | None) -> Counter[tuple[str, str]]:
    """Count fixed-name setattr slots in source for debt-ratchet comparison."""

    if source is None:
        return Counter()
    tree = ast.parse(source)
    return Counter(
        key
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for key in (_static_setattr_key(node),)
        if key is not None
    )


def _changed_dynamic_attribute_access_missing_reason(path: Path) -> list[str]:
    """Return diagnostics for changed getattr/setattr calls without a dynamic-boundary reason."""

    changed = _changed_lines(path)
    if not changed:
        return []
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source, filename=str(path))
    diagnostics: list[str] = []
    baseline_static_setattrs = _static_setattr_counts(_head_source(path))
    current_static_setattrs = _static_setattr_counts(source)
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"getattr", "setattr"}
            and _line_range_touches_changed_lines(node.lineno, node.end_lineno, changed)
        ):
            continue
        static_key = _static_setattr_key(node)
        if static_key is not None:
            if current_static_setattrs[static_key] <= baseline_static_setattrs[static_key]:
                continue
            diagnostics.append(
                f"{path}:{node.lineno}: static setattr field {static_key[1]!r} must use dot access; "
                "dynamic-boundary exceptions require a runtime-computed field name"
            )
            continue
        if _dynamic_attr_access_has_reason(lines, node.lineno) or _enclosing_dynamic_attr_reason(tree, node.lineno):
            continue
        diagnostics.append(
            f"{path}:{node.lineno}: {node.func.id} requires nearby dynamic-boundary reason; "
            "use dot access for owned contracts"
        )
    return diagnostics


def _changed_module_missing_docstring(path: Path) -> list[str]:
    """Return diagnostics when a changed module lacks a module docstring."""

    if not _changed_lines(path):
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    if (ast.get_docstring(tree) or "").strip():
        return []
    return [f"{path}:1: module missing docstring"]


def _changed_module_docstring_missing_layer(path: Path) -> list[str]:
    """Return diagnostics when a changed module docstring lacks ownership."""

    if not _changed_lines(path):
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    docstring = ast.get_docstring(tree) or ""
    if not docstring.strip() or "Layer:" in docstring:
        return []
    return [f"{path}:1: module docstring missing Layer: ownership"]


def _changed_module_docstring_missing_responsibility(path: Path) -> list[str]:
    """Return diagnostics when a changed module docstring lacks responsibility."""

    if not _changed_lines(path):
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    docstring = ast.get_docstring(tree) or ""
    if not docstring.strip() or "Responsibility:" in docstring:
        return []
    return [f"{path}:1: module docstring missing Responsibility: ownership"]


def _module_has_future_annotations(tree: ast.Module) -> bool:
    """Return whether a module enables postponed annotation evaluation."""

    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )


def _changed_module_missing_future_annotations(path: Path) -> list[str]:
    """Return diagnostics when a changed module lacks postponed annotations."""

    if not _changed_lines(path):
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    if _module_has_future_annotations(tree):
        return []
    return [f"{path}:1: module missing 'from __future__ import annotations'"]


def main(argv: list[str] | None = None) -> int:
    """Run the changed-definition contract ratchet."""

    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv)
    diagnostics: list[str] = []
    for raw_path in args.files:
        path = Path(raw_path)
        if path.suffix != ".py" or _is_test_path(path) or not path.exists():
            continue
        diagnostics.extend(_changed_module_missing_docstring(path))
        diagnostics.extend(_changed_module_docstring_missing_layer(path))
        diagnostics.extend(_changed_module_docstring_missing_responsibility(path))
        diagnostics.extend(_changed_module_missing_future_annotations(path))
        diagnostics.extend(_changed_functions_missing_annotations(path))
        diagnostics.extend(_changed_definitions_missing_docstrings(path))
        diagnostics.extend(_changed_dataclass_fields_missing_annotations(path))
        diagnostics.extend(_changed_enum_members_missing_string_values(path))
        diagnostics.extend(_changed_public_assignments_missing_annotations(path))
        diagnostics.extend(_changed_computed_dunder_all(path))
        diagnostics.extend(_changed_dynamic_attribute_access_missing_reason(path))
    if diagnostics:
        print("changed non-test modules and definitions must be typed and documented:", file=sys.stderr)
        for diagnostic in diagnostics:
            print(diagnostic, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

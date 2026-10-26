"""Layer: Frontend/angr compatibility.

Responsibility: deterministic structured-codegen rendering for already-proven facts.
Forbidden: semantic recovery from rendered C, source, COD, or assembly text.
"""

from __future__ import annotations

import typing
from collections.abc import Iterable, Iterator
from copy import copy

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.knowledge_plugins.functions.function import Function
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimTemporaryVariable

from inertia.semantics.callee_name_normalization import normalize_callee_name_8616

__all__ = ["install_structured_codegen_sort_compat_8616", "repair_cfunctioncall_render_target_8616", "repair_cfunctioncall_render_targets_8616", "set_cfunctioncall_render_name_8616"]


def _stable_ident_key_8616(value: object | None) -> tuple[int, str, str]:
    if value is None:
        return (0, "", "")
    return (1, type(value).__name__, str(value))


def _stable_offset_key_8616(value: object | None) -> tuple[int, int | str]:
    if isinstance(value, int):
        return (0, value)
    return (1, str(value))


def install_structured_codegen_sort_compat_8616() -> bool:
    """Make angr C local-var sorting deterministic for mixed/None idents.

    x86-16 recovery can produce SimStackVariable instances that represent the
    same stack slot through different provenance paths, and angr's renderer
    sorts by ``(offset, ident)``. Python 3 rejects comparisons between
    ``None`` and ``str`` idents. The compatibility layer keeps angr's ordering
    categories and normalizes sort keys. Proven temporary declarations must
    also survive: upstream sorting otherwise silently omits that variable kind.
    Dynamic attribute boundary: this patches third-party angr renderer classes
    and reads optional third-party angr SimVariable identity fields.
    """
    cfunc_cls = getattr(structured_c, "CFunction", None)
    if cfunc_cls is None:
        return False
    current = getattr(cfunc_cls, "sort_local_vars", None)
    if getattr(current, "_inertia_x86_16_stable_sort", False):
        return False

    def _sort_local_vars(local_vars: Iterable[object]) -> list[object]:
        """Sort local variables across the dynamic third-party angr boundary."""
        reg_vars, stack_vars, mem_vars = [], [], []
        temporary_vars: list[SimTemporaryVariable] = []
        for var in local_vars:
            if isinstance(var, SimRegisterVariable):
                reg_vars.append(var)
            elif isinstance(var, SimStackVariable):
                stack_vars.append(var)
            elif isinstance(var, SimMemoryVariable):
                mem_vars.append(var)
            elif isinstance(var, SimTemporaryVariable):
                temporary_vars.append(var)

        reg_vars = sorted(reg_vars, key=lambda v: _stable_ident_key_8616(getattr(v, "ident", None)))
        stack_vars = sorted(
            stack_vars,
            key=lambda v: (
                _stable_offset_key_8616(getattr(v, "offset", None)),
                _stable_ident_key_8616(getattr(v, "ident", None)),
            ),
        )
        mem_vars = sorted(
            mem_vars,
            key=lambda v: (
                _stable_offset_key_8616(getattr(v, "addr", None)),
                _stable_ident_key_8616(getattr(v, "ident", None)),
            ),
        )
        temporary_vars.sort(key=lambda variable: variable.tmp_id)
        return reg_vars + stack_vars + mem_vars + temporary_vars

    dynamic_sort_local_vars = typing.cast(typing.Any, _sort_local_vars)
    dynamic_sort_local_vars._inertia_x86_16_stable_sort = True
    cfunc_cls.sort_local_vars = staticmethod(_sort_local_vars)
    return True


def _iter_c_nodes_8616(root: object) -> Iterator[object]:
    """Iterate C AST nodes across the dynamic third-party angr/codegen boundary."""
    stack = [root]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if node is None or not isinstance(node, structured_c.CConstruct):
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)
        yield node
        for attr in (
            "statements",
            "body",
            "else_node",
            "condition_and_nodes",
            "condition",
            "init",
            "iteration",
            "switch",
            "cases",
            "default",
            "retval",
            "lhs",
            "rhs",
            "expr",
            "operand",
            "args",
        ):
            value = getattr(node, attr, None)
            if value is None:
                continue
            if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
                for item in reversed(tuple(value)):
                    if isinstance(item, tuple):
                        stack.extend(reversed(item))
                    else:
                        stack.append(item)
            else:
                stack.append(value)


def _kb_function_for_addr_8616(project: object, addr: int) -> object | None:
    """Find an existing function without discovery or mutating the native KB."""
    # Dynamic boundary: angr/plugin projects and KBs are not owned Inertia contracts.
    kb_functions = getattr(getattr(project, "kb", None), "functions", None)
    if kb_functions is None:
        return None
    try:
        return typing.cast(object, kb_functions.function(addr=addr, create=False))
    except KeyError:
        return None


def _copy_function_render_context_8616(function: Function, context: Function) -> Function:
    """Keep a native declaration while restoring only foreign render back-references."""
    restored = copy(function)
    # Native Function serialization omits its project and manager. Retain all
    # selected semantic fields, with independent containers for mutable names
    # and the info object's native owner relationship.
    restored._project = context.project
    restored._function_manager = context._function_manager
    restored._info = function.info.copy(restored)
    restored.previous_names = list(function.previous_names)
    return restored


def _detached_native_callee_8616(call: structured_c.CFunctionCall) -> object | None:
    """Return the callee only when it is a detached native Function-like object.

    Dynamic boundary: ``CFunctionCall`` and its callee are third-party angr
    nodes; the callee may lack ``project`` or raise on attribute access, so
    detection probes the dynamic surface rather than owned fields.
    """
    callee: object | None = getattr(call, "callee_func", None)
    if callee is None:
        return None
    module = getattr(type(callee), "__module__", "")
    if not isinstance(module, str) or "knowledge_plugins.functions" not in module:
        return None
    try:
        callee_project = getattr(callee, "project", None)
    except AssertionError:
        callee_project = None
    except Exception:
        callee_project = None
    if callee_project is not None:
        return None
    return callee


def repair_cfunctioncall_render_target_8616(project: object | None, call: structured_c.CFunctionCall) -> bool:
    """Restore native render context while preserving the call's selected ABI.

    Native Function copies can lose their project. Replacing their declaration
    with the KB default changes the prototype and therefore the call's type.
    Copy the selected declaration instead, restoring only the native project's
    back-reference from an existing function in that same project. Without a
    resolvable project, retain all semantic metadata and disable name ambiguity
    rendering. This does not prove an unresolved target for any semantic owner.
    """
    callee = _detached_native_callee_8616(call)
    if callee is None:
        return False
    if isinstance(callee, Function) and project is not None:
        canonical = _kb_function_for_addr_8616(project, callee.addr)
        if isinstance(canonical, Function) and canonical.project is project:
            call.callee_func = _copy_function_render_context_8616(callee, canonical)
            return True
    replacement = normalize_callee_name_8616(getattr(callee, "name", None))
    if not isinstance(replacement, str) or not replacement:
        replacement = normalize_callee_name_8616(getattr(call, "callee_target", None))
    changed = False
    if isinstance(replacement, str) and replacement and getattr(call, "callee_target", None) != replacement:
        call.callee_target = replacement
        changed = True
    if getattr(call, "callee_func", None) is not None:
        call.callee_func = None
        changed = True
    return changed


def set_cfunctioncall_render_name_8616(
    project: object | None, call: structured_c.CFunctionCall, target_addr: int, identifier: str,
) -> bool | None:
    """Choose a C label for an existing native target without deleting its ABI.

    Return None when the existing declaration cannot be associated with this
    exact native address and project. Names supply no identity evidence. A
    renamed native copy retains the selected prototype and provenance; the
    source declaration and KB stay unchanged. Repeated formatting is stable.
    """
    function = call.callee_func
    if not isinstance(function, Function) or function.addr != target_addr or project is None:
        return None
    changed = repair_cfunctioncall_render_target_8616(project, call)
    function = call.callee_func
    if not isinstance(function, Function) or function.project is not project:
        return None
    if function.name != identifier:
        named = _copy_function_render_context_8616(function, function)
        named.name = identifier
        call.callee_func = named
        changed = True
    if call.callee_target != identifier:
        call.callee_target = identifier
        changed = True
    if call.show_demangled_name or call.show_disambiguated_name:
        call.show_demangled_name = False
        call.show_disambiguated_name = False
        changed = True
    return changed


def repair_cfunctioncall_render_targets_8616(codegen: object) -> int:
    """Repair copied call-target metadata before angr C rendering.

    angr's ``CFunctionCall`` renderer checks callee-name ambiguity through
    ``callee_func.binary``. Validation snapshots and copied ASTs may preserve
    the callee address/name but lose the ``Function.project`` back-reference.
    Restore its native project while retaining the chosen prototype and calling
    convention; otherwise disable only the renderer's disambiguated-name check.
    Dynamic attribute boundary: codegen, cfunc, and C AST nodes are third-party
    angr/codegen objects with optional renderer metadata.
    """
    project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return 0

    repaired = 0
    for node in _iter_c_nodes_8616(root):
        if not isinstance(node, structured_c.CFunctionCall):
            continue
        repaired += repair_cfunctioncall_render_target_8616(project, node)
    return repaired


install_structured_codegen_sort_compat_8616()

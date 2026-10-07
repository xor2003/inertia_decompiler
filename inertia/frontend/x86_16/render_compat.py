"""Layer: Frontend/angr compatibility.

Responsibility: deterministic structured-codegen rendering for already-proven facts.
Forbidden: semantic recovery from rendered C, source, COD, or assembly text.
"""

from __future__ import annotations

import typing
from collections.abc import Iterable, Iterator

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimTemporaryVariable

__all__ = ["install_structured_codegen_sort_compat_8616", "repair_cfunctioncall_render_targets_8616"]


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
    """Resolve functions across the dynamic third-party angr project boundary."""
    kb_functions = getattr(getattr(project, "kb", None), "functions", None)
    if kb_functions is None:
        return None
    for create in (False, True):
        try:
            return typing.cast(object, kb_functions.function(addr=addr, create=create))
        except Exception:
            continue
    return None


def repair_cfunctioncall_render_targets_8616(codegen: object) -> int:
    """Repair copied call-target metadata before angr C rendering.

    angr's ``CFunctionCall`` renderer checks callee-name ambiguity through
    ``callee_func.binary``. Validation snapshots and copied ASTs may preserve
    the callee address/name but lose the ``Function.project`` back-reference.
    Reattach the function from the current KB when possible; otherwise disable
    only the renderer's disambiguated-name check for that call.
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
        callee_func = getattr(node, "callee_func", None)
        if callee_func is None or getattr(callee_func, "project", None) is not None:
            continue
        addr = getattr(callee_func, "addr", None)
        if isinstance(addr, int) and project is not None:
            replacement = _kb_function_for_addr_8616(project, addr)
            if replacement is not None and getattr(replacement, "project", None) is not None:
                typing.cast(typing.Any, node).callee_func = replacement
                repaired += 1
                continue
        if getattr(node, "show_disambiguated_name", False):
            node.show_disambiguated_name = False
            repaired += 1
    return repaired


install_structured_codegen_sort_compat_8616()

"""Layer: Rewrite/Postprocess cleanup.

Responsibility: normalize already-proven decompiler output and attach inert metadata.
Allowed work: cleanup of typed AST output after earlier layers prove facts.
Forbidden work: semantic recovery from source, COD, assembly, or rendered C text.
Owning layer: cleanup only; proof belongs in IR, alias, widening, lowering, or structuring.
Dynamic attribute access here is a third-party angr C AST and codegen telemetry
boundary; owned Inertia state should stay typed before this cleanup bridge.
Void-return normalization must not delete call-result assignments: a void caller
can consume its callees' results in other scopes. Carrier DCE requires complete
owned liveness evidence, never synthetic names or a local statement-list scan.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import sys
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from dataclasses import dataclass
from enum import Enum
from types import SimpleNamespace
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CGoto,
    CIndexedVariable,
    CLabel,
    CReturn,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import (
    SimType,
    SimTypeBottom,
    SimTypeFunction,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from capstone.x86_const import X86_OP_MEM, X86_OP_REG

from .alias.alias_model import _stack_slot_identity_can_join, _stack_slot_identity_for_variable, _StackSlotIdentity
from .analysis_helpers import preferred_known_helper_signature_decl
from .annotations import (
    ANNOTATION_KEY,
    _parse_c_prototype_8616,
    annotate_function,
    stack_layout_annotation_specs_8616,
)
from .c_ast_utils import _replace_c_children_8616 as _replace_c_children_syntax_8616
from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _iter_c_nodes_deep_8616,
    _match_bp_stack_load_8616,
    _replace_c_children_8616,
    _structured_codegen_node_8616,
)
from .decompiler_return_compat import x86_16_msvc_x87_scalar_stack_args
from .lowering.authoritative_function_prototypes import authoritative_function_prototype_8616
from .lowering.return_type_evidence import (
    FunctionReturnClass8616,
    proven_function_return_class_8616,
)
from .lowering.stack_argument_identity import machine_bp_stack_identity_8616
from .lowering.stack_c_ast_matching import _stack_variable_read_offsets_8616
from .lowering.stack_lowering_from_facts import _stack_object_name
from .lowering.stack_prototype_materialization import align_pointer_flags_to_stack_argument_widths_8616
from .lowering.stack_variable_binding import (
    StackAnnotationSpec8616,
    StackVariableBinding,
    select_normalized_stack_argument_annotation_spec_8616,
    select_stack_annotation_spec_8616,
    stack_binding_inherits_containing_name_8616,
)
from .lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
)
from .lowering.stack_variable_display_names import publish_prototype_argument_projection_names_8616
from .pipeline.contracts import SemanticLaneState


def _source_annotation_lines_8616(func: object) -> tuple[str, ...]:
    return ()


def _merge_source_annotations_if_missing_8616(_target_func: object, _source_func: object) -> bool:
    return False


def _attach_project_cod_source_annotations_if_missing_8616(project: object, func_addr: int, func: object) -> bool:
    return False


def _metadata_function_for_codegen_addr_8616(project: Any, func_addr: int) -> Any | None:
    func = None
    with contextlib.suppress(Exception):
        func = project.kb.functions.function(addr=func_addr, create=False)
    has_metadata = False
    if func is not None:
        info = getattr(func, "info", None)
        has_metadata = getattr(func, "prototype", None) is not None or (
            isinstance(info, MutableMapping) and bool(info.get(ANNOTATION_KEY))
        )
    if has_metadata:
        _attach_project_cod_source_annotations_if_missing_8616(project, func_addr, func)
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(delta, int):
            with contextlib.suppress(Exception):
                rebased_func = project.kb.functions.function(addr=int(func_addr) + delta, create=False)
                _merge_source_annotations_if_missing_8616(func, rebased_func)
        original_project = getattr(project, "_inertia_original_project", None)
        if isinstance(delta, int) and original_project is not None and not _source_annotation_lines_8616(func):
            with contextlib.suppress(Exception):
                original_func = original_project.kb.functions.function(addr=int(func_addr) + delta, create=False)
                _merge_source_annotations_if_missing_8616(func, original_func)
        return func
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        with contextlib.suppress(Exception):
            rebased_func = project.kb.functions.function(addr=int(func_addr) + delta, create=False)
            if rebased_func is not None:
                info = getattr(rebased_func, "info", None)
                if getattr(rebased_func, "prototype", None) is not None or (
                    isinstance(info, MutableMapping) and bool(info.get(ANNOTATION_KEY))
                ):
                    return rebased_func
    original_project = getattr(project, "_inertia_original_project", None)
    if isinstance(delta, int) and original_project is not None:
        with contextlib.suppress(Exception):
            original_func = original_project.kb.functions.function(addr=int(func_addr) + delta, create=False)
            if original_func is not None:
                return original_func
    return func


def _strip_typed_suffix_8616(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    if name.endswith("}"):
        brace_pos = name.find("{")
        if brace_pos > 0:
            return name[:brace_pos]
    return name


def _function_complexity_8616(project: Any, function: Any) -> tuple[int, int]:
    block_addrs = sorted(getattr(function, "block_addrs_set", ()) or ())
    byte_count = 0
    for block_addr in block_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        byte_count += len(block.bytes)
    return len(block_addrs), byte_count


def _is_tiny_function_8616(project: Any, function: Any) -> bool:
    block_count, byte_count = _function_complexity_8616(project, function)
    return block_count <= 4 and byte_count <= 32


def _unwrap_synthetic_wide_return_8616(retval: object) -> object | None:
    if not isinstance(retval, CBinaryOp):
        return None

    candidates: list[tuple[object, object]] = []
    if retval.op == "Or":
        candidates.extend(((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)))
    elif retval.op == "Concat":
        candidates.extend(((retval.lhs, retval.rhs),))
    else:
        return None

    for maybe_wide, maybe_low in candidates:
        if isinstance(maybe_wide, CBinaryOp):
            if maybe_wide.op == "Shl" and _c_constant_value_8616(maybe_wide.rhs) == 16:
                return maybe_low
            if maybe_wide.op == "Concat":
                return maybe_low

    return None


def _normalize_arg_names_8616(
    arg_names: tuple[str | None, ...] | list[str | None] | None, count: int
) -> list[str]:
    normalized: list[str] = []
    used: set[str] = set()
    source = list(arg_names or ())
    for index in range(count):
        base_name = source[index] if index < len(source) else None
        if not isinstance(base_name, str) or not base_name:
            base_name = f"a{index}"
        candidate = base_name
        suffix_match = re.fullmatch(r"(?P<base>.+?)_(?P<suffix>\d+)", base_name)
        if suffix_match is not None:
            unsuffixed = suffix_match.group("base")
            if unsuffixed and unsuffixed not in used:
                candidate = unsuffixed
        suffix = 2
        while candidate in used:
            candidate = f"{base_name}_{suffix}"
            suffix += 1
        normalized.append(candidate)
        used.add(candidate)
    return normalized


def _known_helper_arg_names_8616(name: str | None) -> list[str] | None:
    if not isinstance(name, str) or not name:
        return None

    decl = preferred_known_helper_signature_decl(name)
    if decl is None:
        return None

    try:
        _, proto, _ = _parse_c_prototype_8616(decl)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "_parse_c_prototype_8616 failed for decl=%r: %s",
            decl,
            ex,
        )
        return None

    if proto is None:
        return None

    arg_names = [arg_name for arg_name in getattr(proto, "arg_names", ()) or () if isinstance(arg_name, str)]
    return arg_names or None


def _set_codegen_prototype_8616(codegen: Any, prototype: object) -> None:
    functy_ok = False
    proto_ok = False
    try:
        codegen.cfunc.functy = prototype
        functy_ok = True
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "setting cfunc.functy failed for %#x: %s",
            getattr(codegen.cfunc, "addr", 0),
            ex,
        )
    try:
        codegen.cfunc.prototype = prototype
        proto_ok = True
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "setting cfunc.prototype failed for %#x: %s",
            getattr(codegen.cfunc, "addr", 0),
            ex,
        )
    if not functy_ok and not proto_ok:
        logging.getLogger(__name__).warning(
            "codegen prototype set failed for %#x (neither functy nor prototype attribute)",
            getattr(codegen.cfunc, "addr", 0),
        )
    for attr in ("_function", "function", "func"):
        owner = getattr(codegen, attr, None)
        if owner is None:
            continue
        with contextlib.suppress(Exception):
            owner.prototype = prototype
            owner.is_prototype_guessed = False
    with contextlib.suppress(Exception):
        codegen._inertia_codegen_decl_refresh_required_8616 = True
        codegen._inertia_codegen_prototype_sync_count_8616 = (
            int(getattr(codegen, "_inertia_codegen_prototype_sync_count_8616", 0) or 0) + 1
        )


def _prototypes_equivalent_8616(left: object, right: object) -> bool:
    """Return true when two prototype objects describe the same function interface."""

    if left is right:
        return True
    if left is None or right is None:
        return False
    with contextlib.suppress(Exception):
        return bool(left == right)
    return False


def _types_equivalent_8616(left: object, right: object) -> bool:
    """Return true when two angr type objects describe the same C type."""

    if left is right:
        return True
    if left is None or right is None:
        return False
    with contextlib.suppress(Exception):
        return bool(left == right)
    return False


def _prune_return_address_stack_arguments_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    def _impl() -> bool:
        debug = os.environ.get("INERTIA_DEBUG_RETADDR_PRUNE") == "1"

        def _debug_stack_variable(container: str, variable: object) -> None:
            if not debug or not isinstance(variable, SimStackVariable):
                return
            identity = _stack_slot_identity_for_variable(variable)
            logging.getLogger(__name__).warning(
                "[retaddr-prune] %s name=%r offset=%r size=%r base=%r identity=%r",
                container,
                getattr(variable, "name", None),
                getattr(variable, "offset", None),
                getattr(variable, "size", None),
                getattr(variable, "base", None),
                identity,
            )

        def _return_address_stack_offset(variable: object) -> int | None:
            if not isinstance(variable, SimStackVariable):
                return None
            identity = _stack_slot_identity_for_variable(variable)
            if not isinstance(identity, _StackSlotIdentity) or identity.base != "bp":
                return None
            slot_offset = identity.offset
            return slot_offset if isinstance(slot_offset, int) else None

        def _should_drop_arg(variable: object, stack_specs: Mapping[object, object]) -> bool:
            slot_offset = _return_address_stack_offset(variable)
            if slot_offset != 0:  # noqa: SIM103
                return False
            # BP+2 is the near return IP, not a source-level argument. Metadata
            # can label object-file stack slots with a different bias, but it
            # must not override the architectural return-address exclusion.
            return True

        def _prune_return_address_variable_maps() -> bool:
            changed_maps = False
            cfunc = getattr(codegen, "cfunc", None)
            if cfunc is None:
                return False
            variables_in_use = getattr(cfunc, "variables_in_use", None)
            if isinstance(variables_in_use, dict):
                for variable in tuple(variables_in_use.keys()):
                    _debug_stack_variable("variables_in_use", variable)
                    if _return_address_stack_offset(variable) == 0:
                        del variables_in_use[variable]
                        changed_maps = True
            unified = getattr(cfunc, "unified_local_vars", None)
            if isinstance(unified, dict):
                for variable in tuple(unified.keys()):
                    _debug_stack_variable("unified_local_vars", variable)
                    if _return_address_stack_offset(variable) == 0:
                        del unified[variable]
                        changed_maps = True
            return changed_maps

        def _assignment_lhs_rhs(node: object) -> tuple[object | None, object | None]:
            lhs = getattr(node, "lhs", None)
            rhs = getattr(node, "rhs", None)
            if lhs is None and hasattr(node, "dst"):
                lhs = getattr(node, "dst", None)
                rhs = getattr(node, "src", None)
            return lhs, rhs

        def _top_level_assignment(stmt: object) -> Any | None:
            if isinstance(stmt, CAssignment) or stmt.__class__.__name__.endswith("Assignment"):
                return stmt
            nested = getattr(stmt, "statements", None)
            if isinstance(nested, (list, tuple)) and len(nested) == 1:
                child = nested[0]
                if isinstance(child, CAssignment) or child.__class__.__name__.endswith("Assignment"):
                    return child
            return None

        def _return_address_lvalue(lhs: object) -> bool:
            node = lhs
            while isinstance(node, CTypeCast):
                node = node.expr
            variable = getattr(node, "variable", None)
            return _return_address_stack_offset(variable) == 0

        def _rhs_has_side_effect(rhs: object) -> bool:
            for node in (rhs, *_iter_c_nodes_deep_8616(rhs)):
                if isinstance(node, CFunctionCall):
                    return True
                if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                    return True
            return False

        def _is_return_address_assignment_artifact(stmt: object) -> bool:
            assignment = _top_level_assignment(stmt)
            if assignment is None:
                return False
            lhs, rhs = _assignment_lhs_rhs(assignment)
            if lhs is None or rhs is None or not _return_address_lvalue(lhs):
                return False
            return not _rhs_has_side_effect(rhs)

        def _prune_return_address_body_assignments(owner: Any) -> bool:
            statements = getattr(owner, "statements", None)
            statements_owner = owner
            if isinstance(owner, CStatements):
                statements_owner = owner
                statements = owner.statements
            elif isinstance(statements, CStatements):
                statements_owner = statements
                statements = statements.statements
            changed_body = False
            if isinstance(statements, (list, tuple)):
                items = []
                for stmt in statements:
                    if _is_return_address_assignment_artifact(stmt):
                        changed_body = True
                        continue
                    changed_body = _prune_return_address_body_assignments(stmt) or changed_body
                    items.append(stmt)
                if changed_body:
                    statements_owner.statements = items if isinstance(statements, list) else tuple(items)
            for attr in ("body", "else_node"):
                child = getattr(owner, attr, None)
                if child is not None:
                    changed_body = _prune_return_address_body_assignments(child) or changed_body
            for pair in tuple(getattr(owner, "condition_and_nodes", ()) or ()):
                if isinstance(pair, tuple) and len(pair) == 2 and pair[1] is not None:
                    changed_body = _prune_return_address_body_assignments(pair[1]) or changed_body
            return changed_body

        def _arg_name_from_stack_spec(
            variable: object, stack_specs: Any
        ) -> str | None:
            arg_name = getattr(variable, "name", None)
            if not isinstance(variable, SimStackVariable):
                return arg_name
            offset = variable.offset
            if not (isinstance(offset, int) and offset > 0):
                return arg_name
            spec = stack_specs.get(offset - 2)
            if isinstance(spec, str):
                return spec
            if isinstance(spec, dict):
                spec_name = spec.get("name")
                if isinstance(spec_name, str) and spec_name:
                    return spec_name
            return arg_name

        def _sync_arg_name(arg: Any, variable: Any, arg_name: str | None) -> None:
            if arg_name is None:
                return
            with contextlib.suppress(Exception):
                arg.name = arg_name
            if variable is not None and getattr(variable, "name", None) != arg_name:
                variable.name = arg_name
            unified = getattr(arg, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != arg_name:
                unified.name = arg_name

        def _build_proto_args_and_names(
            kept_args: list[Any],
            proto_args: list[Any],
            stack_specs: object,
            *,
            prefer_proto_types: bool = False,
        ) -> tuple[list[Any], list[str | None]]:
            """Build a pruned prototype while preserving explicit argument types."""
            arg_types: list[Any] = []
            arg_names: list[str | None] = []
            for index, arg in enumerate(kept_args):
                arg_type = proto_args[index] if prefer_proto_types and index < len(proto_args) else None
                if arg_type is None:
                    arg_type = getattr(arg, "variable_type", None)
                if arg_type is None and index < len(proto_args):
                    arg_type = proto_args[index]
                arg_types.append(arg_type)
                variable = getattr(arg, "variable", None)
                arg_name = _arg_name_from_stack_spec(variable, stack_specs)
                _sync_arg_name(arg, variable, arg_name)
                arg_names.append(arg_name)
            return arg_types, arg_names

        if getattr(codegen, "cfunc", None) is None:
            return False
        if getattr(codegen, "_inertia_return_selector_materialized_8616", False):
            codegen._inertia_retaddr_prune_refused_selector_return_8616 = (
                int(getattr(codegen, "_inertia_retaddr_prune_refused_selector_return_8616", 0) or 0) + 1
            )
            return False

        func_addr = getattr(codegen.cfunc, "addr", None)
        if func_addr is None:
            return False

        func = _metadata_function_for_codegen_addr_8616(project, func_addr)
        if func is None:
            return False

        annotations = getattr(func, "info", {}).get(ANNOTATION_KEY, {})
        annotated_prototype = annotations.get("prototype") if isinstance(annotations, Mapping) else None
        prototype = (
            annotated_prototype
            if isinstance(annotated_prototype, SimTypeFunction)
            else getattr(func, "prototype", None)
        )
        stack_specs = stack_layout_annotation_specs_8616(annotations)
        arg_list = list(getattr(codegen.cfunc, "arg_list", ()) or ())
        if prototype is None or not arg_list:
            changed_body = _prune_return_address_body_assignments(codegen.cfunc)
            changed_maps = _prune_return_address_variable_maps()
            return changed_body or changed_maps

        kept_args = []
        args_changed = False
        for arg in arg_list:
            variable = getattr(arg, "variable", None)
            _debug_stack_variable("arg_list", variable)
            if _should_drop_arg(variable, stack_specs):
                args_changed = True
                continue
            kept_args.append(arg)

        changed_body = _prune_return_address_body_assignments(codegen.cfunc)
        changed_maps = _prune_return_address_variable_maps()
        changed = changed_body or changed_maps or args_changed
        if not changed:
            return False
        if not args_changed:
            return True
        codegen.cfunc.arg_list = kept_args
        proto_args = list(getattr(prototype, "args", ()) or ())
        arg_types, arg_names = _build_proto_args_and_names(
            kept_args,
            proto_args,
            stack_specs,
            prefer_proto_types=isinstance(annotated_prototype, SimTypeFunction),
        )

        new_proto = prototype.__class__(
            arg_types,
            prototype.returnty,
            arg_names=_normalize_arg_names_8616(arg_names, len(arg_types)),
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        func.prototype = new_proto
        func.is_prototype_guessed = False
        _set_codegen_prototype_8616(codegen, new_proto)
        return True

    return _impl()


def _normalize_function_prototype_arg_names_8616(project: Any, codegen: Any) -> bool:
    """Normalize generated argument names without losing stack coordinates."""
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    prototype = getattr(func, "prototype", None)
    if prototype is None:
        return False

    arg_names = getattr(prototype, "arg_names", None)
    if arg_names is None:
        return False

    normalized = _normalize_arg_names_8616(arg_names, len(getattr(prototype, "args", ()) or ()))
    if list(arg_names) == normalized:
        return False

    new_proto = prototype.__class__(
        list(getattr(prototype, "args", ()) or ()),
        prototype.returnty,
        arg_names=normalized,
        variadic=getattr(prototype, "variadic", False),
    ).with_arch(project.arch)
    publish_prototype_argument_projection_names_8616(codegen, normalized)
    func.prototype = new_proto
    _set_codegen_prototype_8616(codegen, new_proto)
    return True


def _collect_goto_label_names_8616(root: object) -> set[str]:
    names: set[str] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CLabel):
            label_name = node.name
            if isinstance(label_name, str) and label_name:
                names.add(label_name)
    return names


def _collect_mapped_goto_label_names_8616(cfunc: object) -> set[str]:
    mapping = getattr(cfunc, "map_addr_to_label", None)
    if not isinstance(mapping, dict):
        return set()
    names: set[str] = set()
    for value in mapping.values():
        if isinstance(value, CLabel):
            mapped_name = value.name
            if isinstance(mapped_name, str) and mapped_name:
                names.add(mapped_name)
    return names


def _repair_unresolved_function_exit_gotos_8616(project: Any, codegen: Any) -> bool:
    def _impl() -> bool:
        """Repair unresolved CGoto that are definitely function-exit candidates.

        This is a conservative pass: only jump targets proven to be out-of-procedure
        become ``return``. Any ambiguous in-procedure target remains unchanged.
        """
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False

        root = getattr(cfunc, "statements", None)
        if root is None:
            return False

        stats = getattr(codegen, "_inertia_unresolved_goto_exit_stats_8616", None)
        if not isinstance(stats, dict):
            stats = {
                "unresolved_goto_exit_candidates": 0,
                "unresolved_goto_exit_repaired": 0,
                "unresolved_goto_exit_refused": 0,
            }
            codegen._inertia_unresolved_goto_exit_stats_8616 = stats

        func_addr = getattr(cfunc, "addr", None)
        function = None
        if func_addr is not None and project is not None:
            try:
                function = project.kb.functions.function(addr=func_addr, create=False)
            except Exception:
                function = None

        block_addrs = tuple(sorted(getattr(function, "block_addrs_set", ()) or ()))
        min_block_addr = block_addrs[0] if block_addrs else None
        max_block_addr = block_addrs[-1] if block_addrs else None

        defined_labels = _collect_goto_label_names_8616(root)
        mapped_labels = _collect_mapped_goto_label_names_8616(cfunc)
        defined_all_labels = defined_labels | mapped_labels

        map_addr_to_label = getattr(cfunc, "map_addr_to_label", None)

        def _is_known_target(target: int, target_idx: int | None) -> bool:
            if not block_addrs:
                return False
            if target in block_addrs:
                return True
            if not isinstance(map_addr_to_label, dict):
                return False
            mapped_label = map_addr_to_label.get((target, target_idx))
            if mapped_label is None and target_idx is not None:
                mapped_label = map_addr_to_label.get((target, None))
            mapped_name = getattr(mapped_label, "name", None) if isinstance(mapped_label, CLabel) else None
            if isinstance(mapped_name, str):
                return mapped_name in defined_all_labels
            return False

        def _is_function_exit_target(target: int) -> bool:
            if not block_addrs:
                return False
            if target in block_addrs:
                return False
            if min_block_addr is None or max_block_addr is None:
                return False
            return bool(target < min_block_addr or target > max_block_addr)

        changed = False

        for goto in tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CGoto)):
            target = getattr(goto, "target", None)
            target_idx = getattr(goto, "target_idx", None)
            if not isinstance(target, int):
                stats["unresolved_goto_exit_refused"] = int(stats["unresolved_goto_exit_refused"]) + 1
                continue

            if _is_known_target(target, target_idx):
                continue

            stats["unresolved_goto_exit_candidates"] = int(stats["unresolved_goto_exit_candidates"]) + 1

            if _is_function_exit_target(target):
                candidate_return = CReturn(None, codegen=codegen)
                replaced = _replace_c_children_8616(
                    root,
                    lambda node: candidate_return if node is goto else node,  # noqa: B023
                )
                if replaced:
                    changed = True
                    stats["unresolved_goto_exit_repaired"] = int(stats["unresolved_goto_exit_repaired"]) + 1
                else:
                    stats["unresolved_goto_exit_refused"] = int(stats["unresolved_goto_exit_refused"]) + 1
                continue

            stats["unresolved_goto_exit_refused"] = int(stats["unresolved_goto_exit_refused"]) + 1

        return changed

    return _impl()


def _make_unique_identifier_8616(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _dedupe_codegen_variable_names_8616(codegen: Any) -> bool:
    # Name dedup is readability-only. If it perturbs canonicalized semantics it must
    # not run in the correctness pipeline by default.
    def _impl() -> bool:
        if os.environ.get("INERTIA_ENABLE_NAME_DEDUP", "").strip().lower() not in {"1", "true", "yes", "on"}:
            return False

        if getattr(codegen, "cfunc", None) is None:
            return False

        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if not isinstance(variables_in_use, dict) and not isinstance(unified_locals, dict):
            return False

        def is_generic_name(name: object) -> bool:
            normalized = _strip_typed_suffix_8616(name)
            if not isinstance(normalized, str):
                return False
            return re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", normalized) is not None

        def preferred_name(variable: object, cvar: object) -> str | None:
            candidates = [
                getattr(variable, "name", None),
                getattr(cvar, "name", None),
                getattr(getattr(cvar, "unified_variable", None), "name", None),
            ]
            for candidate in candidates:
                if isinstance(candidate, str) and candidate and not is_generic_name(candidate):
                    return candidate
            for candidate in candidates:
                if isinstance(candidate, str) and candidate:
                    return candidate
            return None

        def sort_key(item: tuple[object, object]) -> tuple[object, ...]:
            variable, cvar = item
            variable_name = getattr(variable, "name", None)
            cvar_name = getattr(cvar, "name", None)
            variable_name_key = variable_name if isinstance(variable_name, str) else ""
            cvar_name_key = cvar_name if isinstance(cvar_name, str) else ""
            if isinstance(variable, SimStackVariable):
                offset = variable.offset
                base_rank = 0 if isinstance(offset, int) and offset > 0 else 1
                return (
                    0,
                    base_rank,
                    offset if isinstance(offset, int) else 0,
                    variable.size if isinstance(variable.size, int) else 0,
                    variable_name_key,
                )
            if isinstance(variable, SimRegisterVariable):
                reg = variable.reg
                return (
                    1,
                    reg if isinstance(reg, int) else 0,
                    variable.size if isinstance(variable.size, int) else 0,
                    variable_name_key,
                )
            if isinstance(variable, SimMemoryVariable):
                addr = variable.addr
                return (
                    2,
                    addr if isinstance(addr, int) else 0,
                    variable.size if isinstance(variable.size, int) else 0,
                    variable_name_key,
                )
            return (3, variable_name_key, cvar_name_key)

        ordered_items = list(variables_in_use.items()) if isinstance(variables_in_use, dict) else []
        if isinstance(unified_locals, dict):
            for variable, cvars in unified_locals.items():
                if isinstance(variables_in_use, dict) and variable not in variables_in_use and cvars:
                    ordered_items.append((variable, next(iter(cvars))[0]))

        ordered_items.sort(key=sort_key)

        used_names: set[str] = set()
        seen_variables: set[int] = set()
        changed = False

        def apply_name(variable: Any, cvar: Any, new_name: str) -> None:
            nonlocal changed
            if getattr(variable, "name", None) != new_name:
                variable.name = new_name
                changed = True
            if getattr(cvar, "name", None) != new_name:
                try:
                    cvar.name = new_name
                except Exception:
                    pass
                else:
                    changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != new_name:
                unified.name = new_name
                changed = True

        for variable, cvar in ordered_items:
            if id(variable) in seen_variables:
                continue
            seen_variables.add(id(variable))
            name = preferred_name(variable, cvar)
            if name is None:
                continue
            if name in used_names:
                name = _make_unique_identifier_8616(name, used_names)
            else:
                used_names.add(name)
            apply_name(variable, cvar, name)

        return changed

    return _impl()


def _return_value_shape_8616(retval: object) -> str | None:
    def _impl() -> str | None:
        if retval is None:
            return None
        if isinstance(retval, CFunctionCall) and getattr(retval, "callee_target", None) == "MK_FP":
            return "wide_fp"
        if isinstance(retval, CBinaryOp):
            if retval.op in {"Or", "Concat"}:
                for maybe_wide, maybe_low in ((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)):
                    if _c_constant_value_8616(maybe_low) == 0:
                        return _return_value_shape_8616(maybe_wide) or "wide_fp"
                    if isinstance(maybe_wide, CBinaryOp):
                        if maybe_wide.op == "Shl" and _c_constant_value_8616(maybe_wide.rhs) == 16:
                            return "wide_fp"
                        if maybe_wide.op == "Concat":
                            return "wide_fp"
            return "scalar"
        if isinstance(retval, CConstant):
            return "scalar"
        if isinstance(retval, CVariable):
            return "scalar"
        if isinstance(retval, CTypeCast):
            return _return_value_shape_8616(retval.expr)
        if isinstance(retval, CUnaryOp):
            return "scalar" if retval.op in {"Neg", "Not", "Reference"} else None
        return "scalar"

    return _impl()


def _stack_arg_has_pointer_evidence_8616(codegen: object, variable: object) -> bool:
    if not isinstance(variable, SimStackVariable):
        return False
    identity = _stack_slot_identity_for_variable(variable)
    if identity is None:
        return False

    statements = getattr(getattr(codegen, "cfunc", None), "statements", None)
    for stmt in getattr(statements, "statements", ()) or ():
        for node in _iter_c_nodes_deep_8616(stmt):
            if not isinstance(node, CUnaryOp) or node.op != "Dereference":
                continue
            for operand_node in _iter_c_nodes_deep_8616(node.operand):
                if not isinstance(operand_node, CVariable):
                    continue
                operand_var = operand_node.variable
                if not isinstance(operand_var, SimStackVariable):
                    continue
                if _stack_slot_identity_for_variable(operand_var) == identity:
                    return True
    return False


def _positive_stack_specs_are_normalized_for_codegen_8616(
    stack_specs: Mapping[object, object], codegen: SimpleNamespace
) -> bool:
    positive_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
    if not positive_offsets or positive_offsets[0] != 2:
        return False
    # Dynamic angr/codegen compatibility boundary.
    cfunc = getattr(codegen, "cfunc", None)
    known_offsets: set[int] = set()
    arg_offsets: set[int] = set()
    # Dynamic angr/codegen compatibility boundary.
    for cvar in tuple(getattr(cfunc, "arg_list", ()) or ()):
        offset = _machine_bp_offset_for_cvariable_8616(codegen, cvar)
        if isinstance(offset, int):
            arg_offsets.add(offset)
            known_offsets.add(offset)
    if arg_offsets:
        shifted_offsets = {offset + 2 for offset in positive_offsets}
        if shifted_offsets <= arg_offsets:
            return True
        if set(positive_offsets) <= arg_offsets:
            return False
    # Dynamic angr/codegen compatibility boundary.
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in variables_in_use:
            if not isinstance(variable, SimStackVariable):
                continue
            identity = machine_bp_stack_identity_8616(codegen, variable)
            if identity is not None:
                known_offsets.add(identity.offset)
    if known_offsets:
        direct_offsets = set(positive_offsets)
        shifted_offsets = {offset + 2 for offset in positive_offsets}
        if direct_offsets <= known_offsets:
            return False
        if shifted_offsets <= known_offsets:
            return True
    # x86-16 near-call arguments start at BP+4. COD/sidecar aliases are stored
    # normalized around the return address in this project, so a first positive
    # alias at +2 must be materialized as BP+4 in codegen storage.
    return True


def _promote_stack_prototype_from_bp_loads_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    """Bridge legacy BP evidence only when typed Lowering owns no interface."""

    def _impl() -> bool:
        if getattr(codegen, "cfunc", None) is None:
            return False

        func_addr = getattr(codegen.cfunc, "addr", None)
        if func_addr is None:
            return False

        func = _metadata_function_for_codegen_addr_8616(project, func_addr)
        if func is None:
            return False

        if bool(getattr(codegen, "_inertia_authoritative_zero_arg_prototype_8616", False)):
            return False

        live_prototype = getattr(func, "prototype", None)
        if isinstance(live_prototype, SimTypeFunction) and authoritative_function_prototype_8616(
            project,
            func,
            argument_count=len(tuple(live_prototype.args or ())),
        ) is not None:
            return False

        positive_bp_changed = _promote_positive_bp_stack_slots_to_args_8616(project, codegen)
        info = getattr(func, "info", None)
        annotations = info.get(ANNOTATION_KEY) if isinstance(info, Mapping) else None
        annotated_prototype = annotations.get("prototype") if isinstance(annotations, Mapping) else None
        prototype = (
            annotated_prototype
            if isinstance(annotated_prototype, SimTypeFunction)
            else getattr(func, "prototype", None)
        )
        if prototype is None:
            return positive_bp_changed
        if not list(getattr(prototype, "args", ()) or ()):
            return positive_bp_changed
        current_proto = getattr(getattr(codegen, "cfunc", None), "functy", None) or prototype
        existing_args = list(getattr(codegen.cfunc, "arg_list", ()) or ())
        promote_near_pointers = True

        annotations, source_pointer_flags, _stack_specs, annotated_args = _collect_stack_promotion_inputs_8616(func)
        if not source_pointer_flags:
            source_pointer_flags = _prototype_pointer_flags_for_codegen_function_8616(project, func_addr)
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"promote_stack_proto func={func_addr!r} "
                f"source_pointer_flags={source_pointer_flags!r} "
                f"annotated_args={annotated_args!r}",
                file=sys.stderr,
                flush=True,
            )
        arg_names = [name for name in getattr(prototype, "arg_names", ()) or () if isinstance(name, str)]

        if _sync_arg_list_from_prototype_stack_layout_8616(
            project=project,
            codegen=codegen,
            func=func,
            prototype=prototype,
            arg_names=arg_names,
            source_pointer_flags=source_pointer_flags,
            annotated_args=annotated_args,
        ):
            return True

        if _promote_from_annotated_args_8616(
            project=project,
            codegen=codegen,
            func=func,
            prototype=prototype,
            arg_names=arg_names,
            existing_args=existing_args,
            annotated_args=annotated_args,
            source_pointer_flags=source_pointer_flags,
            promote_near_pointers=promote_near_pointers,
        ):
            return True

        if _promote_from_fallback_args_8616(
            project=project,
            codegen=codegen,
            func=func,
            current_proto=current_proto,
            existing_args=existing_args,
            source_pointer_flags=source_pointer_flags,
            promote_near_pointers=promote_near_pointers,
        ):
            return True

        return positive_bp_changed or _promote_from_legacy_arg_names_8616(
            project=project,
            codegen=codegen,
            func=func,
            prototype=prototype,
            arg_names=arg_names,
        )

    return _impl()


def _promote_positive_bp_stack_slots_to_args_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    """Promote proven positive BP stack slots into function arguments.

    The high-byte projection lane is a compatibility consumer for already
    discovered stack argument shape.  It may rewrite body uses of a contained
    high-byte stack slot into a projection of the owning word argument.  A
    high-byte slot that exists only in the function argument list is stale
    metadata, not a classified body fact, and must be pruned without tripping
    the closed-loop materialization contract.
    """

    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return False
    candidates: dict[int, tuple[SimStackVariable, CVariable]] = {}
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimStackVariable) or not isinstance(cvar, CVariable):
            continue
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int) or offset < 4:
            continue
        candidates.setdefault(offset, (variable, cvar))
    for node in _iter_c_nodes_deep_8616(getattr(cfunc, "statements", None)):
        if not isinstance(node, CVariable):
            continue
        variable = node.variable
        if not isinstance(variable, SimStackVariable):
            continue
        offset = variable.offset
        if not isinstance(offset, int) or offset < 4:
            continue
        candidates.setdefault(offset, (variable, node))
    for cvar in getattr(cfunc, "arg_list", ()) or ():
        if not isinstance(cvar, CVariable):
            continue
        variable = cvar.variable
        if not isinstance(variable, SimStackVariable):
            continue
        offset = variable.offset
        if not isinstance(offset, int) or offset < 4:
            continue
        candidates.setdefault(offset, (variable, cvar))
    if not candidates:
        return False
    source_arg_names_by_offset: dict[int, str] = {}
    source_arg_types_by_offset: dict[int, SimType] = {}
    # Dynamic angr/codegen compatibility boundary.
    func_addr = getattr(cfunc, "addr", None)
    func = None
    if isinstance(func_addr, int):
        with contextlib.suppress(Exception):
            func = project.kb.functions.function(addr=func_addr, create=False)
    # Dynamic angr/codegen compatibility boundary.
    annotations = getattr(func, "info", {}).get(ANNOTATION_KEY) if func is not None else None
    stack_specs = stack_layout_annotation_specs_8616(annotations)
    if isinstance(stack_specs, dict):
        positive_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
        positive_specs_are_normalized = bool(positive_offsets) and positive_offsets[0] == 2
        for offset, spec in sorted(stack_specs.items(), key=lambda item: item[0]):
            if not isinstance(offset, int) or offset <= 0:
                continue
            name = spec if isinstance(spec, str) else None
            if isinstance(spec, dict):
                spec_name = spec.get("name")
                if isinstance(spec_name, str):
                    name = spec_name
            if isinstance(name, str) and name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                source_arg_names_by_offset[offset + 2 if positive_specs_are_normalized else offset] = name
    # Dynamic angr/codegen compatibility boundary.
    annotated_prototype = annotations.get("prototype") if isinstance(annotations, dict) else None
    current_proto = (
        annotated_prototype
        if isinstance(annotated_prototype, SimTypeFunction)
        else getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    )
    if current_proto is None and func is not None:
        # Dynamic angr/codegen compatibility boundary.
        current_proto = getattr(func, "prototype", None)
    if isinstance(current_proto, SimTypeFunction):
        cursor = 4
        prototype_is_explicit = func is not None and not bool(getattr(func, "is_prototype_guessed", True))
        for arg_type, arg_name in zip(
            # Dynamic angr/codegen compatibility boundary.
            tuple(current_proto.args or ()),
            # Dynamic angr/codegen compatibility boundary.
            tuple(current_proto.arg_names or ()), strict=False,
        ):
            if isinstance(arg_name, str) and arg_name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", arg_name):
                source_arg_names_by_offset.setdefault(cursor, arg_name)
            if prototype_is_explicit and isinstance(arg_type, SimType):
                source_arg_types_by_offset[cursor] = arg_type
            cursor += max(2, _type_size_bytes_8616(arg_type))
    changed = False
    body_stack_offsets = {
        offset
        # Dynamic angr/codegen compatibility boundary.
        for node in _iter_c_nodes_deep_8616(getattr(cfunc, "statements", None))
        if isinstance(node, CVariable)
        # Dynamic angr/codegen compatibility boundary.
        for variable in (getattr(node, "variable", None),)
        # Dynamic angr/codegen compatibility boundary.
        for offset in (getattr(variable, "offset", None),)
        if isinstance(variable, SimStackVariable) and isinstance(offset, int)
    }
    body_stack_read_offsets = _stack_variable_read_offsets_8616(cfunc.statements)
    stale_contained_high_byte_args: dict[int, int] = {}
    contained_high_byte_args: dict[int, int] = {}
    for offset, (variable, _cvar) in candidates.items():
        size = int(getattr(variable, "size", 0) or 0)
        if size != 1 or offset <= 4 or offset % 2 == 0:
            continue
        base_offset = offset - 1
        base = candidates.get(base_offset)
        if base is None:
            continue
        base_size = int(getattr(base[0], "size", 0) or 0)
        if base_size >= 2:
            if offset in body_stack_read_offsets:
                contained_high_byte_args[offset] = base_offset
            elif offset not in body_stack_offsets:
                stale_contained_high_byte_args[offset] = base_offset
    high_byte_stats = StackArgHighByteProjectionStats8616(
        raw_fact_count=len(contained_high_byte_args),
        normalized_fact_count=len(contained_high_byte_args),
        classified_fact_count=len(contained_high_byte_args),
    )
    if contained_high_byte_args:
        codegen._inertia_stack_arg_high_byte_projection_candidates_8616 = int(
            getattr(codegen, "_inertia_stack_arg_high_byte_projection_candidates_8616", 0) or 0
        ) + len(contained_high_byte_args)
        base_cvars = {base_offset: candidates[base_offset][1] for base_offset in set(contained_high_byte_args.values())}
        projected_high_byte_offsets: set[int] = set()

        def _high_byte_projection(node: object) -> object:
            if not isinstance(node, CVariable):
                return node
            # Dynamic angr/codegen compatibility boundary.
            variable = node.variable
            if not isinstance(variable, SimStackVariable):
                return node
            # Dynamic angr/codegen compatibility boundary.
            offset = variable.offset
            if not isinstance(offset, int):
                return node
            base_offset = contained_high_byte_args.get(offset)
            if base_offset is None:
                return node
            base_cvar = base_cvars.get(base_offset)
            if base_cvar is None:
                return node
            projected_high_byte_offsets.add(offset)
            return CBinaryOp(
                "Shr",
                base_cvar,
                CConstant(8, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )

        def _should_rewrite_high_byte_child(parent: object, attr: str) -> bool:
            if attr == "variable":
                return False
            return not (isinstance(parent, CAssignment) and attr == "lhs")

        if _replace_c_children_syntax_8616(
            cfunc.statements,
            _high_byte_projection,
            should_process_child=_should_rewrite_high_byte_child,
        ):
            changed = True
            high_byte_stats.materialized_count = len(projected_high_byte_offsets)
            codegen._inertia_stack_arg_high_byte_projection_materialized_8616 = int(
                # Dynamic angr/codegen compatibility boundary.
                getattr(codegen, "_inertia_stack_arg_high_byte_projection_materialized_8616", 0) or 0
            ) + len(projected_high_byte_offsets)
        if high_byte_stats.classified_fact_count > 0 and high_byte_stats.materialized_count == 0:
            high_byte_stats.failure_count = 1
        _record_stack_arg_high_byte_projection_lane_8616(codegen, high_byte_stats)
        contained_high_byte_args = {
            offset: base_offset
            for offset, base_offset in contained_high_byte_args.items()
            if offset in projected_high_byte_offsets
        }
    contained_high_word_args: dict[int, int] = {}
    body_stack_variable_ids = {
        id(variable)
        # Dynamic angr/codegen compatibility boundary.
        for node in _iter_c_nodes_deep_8616(getattr(cfunc, "statements", None))
        if isinstance(node, CVariable)
        # Dynamic angr/codegen compatibility boundary.
        for variable in (getattr(node, "variable", None),)
        if isinstance(variable, SimStackVariable)
    }
    for offset, (variable, _cvar) in candidates.items():
        if offset <= 4 or offset % 2 != 0 or id(variable) in body_stack_variable_ids:
            continue
        base_offset = offset - 2
        base = candidates.get(base_offset)
        if base is None:
            continue
        base_variable, base_cvar = base
        # Dynamic angr/codegen compatibility boundary.
        base_size = int(getattr(base_variable, "size", 0) or 0)
        # Dynamic angr/codegen compatibility boundary.
        base_type_size = _type_size_bytes_8616(getattr(base_cvar, "variable_type", None))
        if max(base_size, base_type_size) >= 4:
            contained_high_word_args[offset] = base_offset
    desired_args = []
    arg_types = []
    arg_names = []
    for index, (offset, (variable, cvar)) in enumerate(sorted(candidates.items())):
        if offset in contained_high_byte_args or offset in stale_contained_high_byte_args or offset in contained_high_word_args:
            continue
        width = max(2, int(getattr(variable, "size", 0) or 2))
        if offset in set(contained_high_word_args.values()):
            width = max(width, 4)
        name = getattr(variable, "name", None)
        source_name = source_arg_names_by_offset.get(offset)
        if isinstance(source_name, str) and source_name and name != source_name:
            name = source_name
            variable.name = name
            with contextlib.suppress(Exception):
                cast(Any, cvar).name = name
            changed = True
        elif not isinstance(name, str) or not name or re.fullmatch(
            r"(?:s_[0-9a-fA-F]+|v\d+|vvar_\d+|local_\d+)", name
        ):
            name = f"arg_{offset:x}"
            variable.name = name
            with contextlib.suppress(Exception):
                cast(Any, cvar).name = name
            changed = True
        arg_type = getattr(cvar, "variable_type", None)
        source_type = source_arg_types_by_offset.get(offset)
        if source_type is not None and arg_type != source_type:
            arg_type = source_type
            cvar.variable_type = source_type
            changed = True
        if arg_type is None:
            arg_type = SimTypeShort(False)
            cvar.variable_type = arg_type
            changed = True
        if width > 2 and _type_size_bytes_8616(arg_type) <= 2:
            arg_type = SimTypeLong(False)
            cvar.variable_type = arg_type
            changed = True
        desired_args.append(cvar)
        arg_types.append(arg_type)
        arg_names.append(name if isinstance(name, str) and name else f"arg_{index}")
    existing_args = list(getattr(cfunc, "arg_list", ()) or ())
    if len(existing_args) != len(desired_args) or any(
        existing is not desired for existing, desired in zip(existing_args, desired_args, strict=False)
    ):
        cfunc.arg_list = desired_args
        changed = True
    current_proto = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    return_type = getattr(current_proto, "returnty", None) if current_proto is not None else SimTypeShort(False)
    if return_type is None or (
        isinstance(return_type, SimTypeBottom) and getattr(return_type, "label", None) != "void"
    ):
        return_type = SimTypeShort(False)
    prototype = SimTypeFunction(arg_types, return_type, arg_names=arg_names).with_arch(project.arch)
    if getattr(cfunc, "functy", None) is not prototype:
        _set_codegen_prototype_8616(codegen, prototype)
        changed = True
    if contained_high_byte_args or stale_contained_high_byte_args or contained_high_word_args:
        contained_offsets = set(contained_high_byte_args) | set(stale_contained_high_byte_args) | set(
            contained_high_word_args
        )
        for variable in tuple(variables_in_use):
            if isinstance(variable, SimStackVariable) and getattr(variable, "offset", None) in contained_offsets:
                del variables_in_use[variable]
                changed = True
        unified = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            for variable in tuple(unified):
                if isinstance(variable, SimStackVariable) and getattr(variable, "offset", None) in contained_offsets:
                    del unified[variable]
                    changed = True
    if changed:
        codegen._inertia_positive_bp_args_materialized_8616 = int(
            getattr(codegen, "_inertia_positive_bp_args_materialized_8616", 0) or 0
        ) + len(desired_args)
    return changed


def _type_size_bytes_8616(type_: object, *, default: int = 2) -> int:
    try:
        bits = getattr(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return default


def _sync_arg_list_from_prototype_stack_layout_8616(
    *,
    project: SimpleNamespace,
    codegen: SimpleNamespace,
    func: object,
    prototype: object,
    arg_names: list[str],
    source_pointer_flags: tuple[bool, ...] = (),
    annotated_args: list[tuple[int, str | None]] | tuple[tuple[int, str | None], ...] = (),
) -> bool:
    """Sync codegen argument variables from a structured stack prototype layout."""

    def _impl() -> bool:
        proto_args: list[Any] = list(getattr(prototype, "args", ()) or ())
        if not proto_args:
            return False
        if len(source_pointer_flags) != len(proto_args):
            return False
        prototype_is_explicit = not bool(getattr(func, "is_prototype_guessed", True))
        original_proto_args = list(proto_args)
        x87_scalar_arg_types = (
            {} if prototype_is_explicit else _x87_scalar_stack_arg_types_8616(project, func, codegen=codegen)
        )
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False
        if not callable(getattr(codegen, "next_idx", None)):
            return False
        func_addr = getattr(cfunc, "addr", None)
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if not isinstance(variables_in_use, dict):
            return False
        unified = getattr(cfunc, "unified_local_vars", None)
        stack_cvars_by_offset: dict[int, CVariable] = {}
        for variable, cvar in variables_in_use.items():
            if isinstance(variable, SimStackVariable) and isinstance(cvar, CVariable):
                offset_value = variable.offset
                if isinstance(offset_value, int):
                    stack_cvars_by_offset.setdefault(offset_value, cvar)
        # Dynamic angr/codegen compatibility boundary.
        for node in _iter_c_nodes_deep_8616(getattr(cfunc, "statements", None)):
            if not isinstance(node, CVariable):
                continue
            # Dynamic angr/codegen compatibility boundary.
            variable = node.variable
            if not isinstance(variable, SimStackVariable):
                continue
            # Dynamic angr/codegen compatibility boundary.
            var_offset = variable.offset
            if isinstance(var_offset, int) and var_offset > 0:
                stack_cvars_by_offset.setdefault(var_offset, node)

        desired_args = []
        expected_offsets: set[int] = set()
        offset = 4
        annotated_offsets: tuple[int, ...] = ()
        if len(annotated_args) == len(proto_args):
            candidate_offsets = tuple(
                offset for offset, _name in annotated_args if isinstance(offset, int) and offset > 0
            )
            if len(candidate_offsets) == len(proto_args) and tuple(sorted(candidate_offsets)) == candidate_offsets:
                annotated_offsets = candidate_offsets
        inferred_arg_widths = _annotation_arg_widths_from_stack_layout_8616(
            arg_offsets=list(annotated_offsets),
            known_positive_stack_offsets={
                offset for offset in stack_cvars_by_offset if isinstance(offset, int) and offset > 0
            },
        )
        changed = False
        for index, arg_type in enumerate(proto_args):
            if annotated_offsets:
                offset = annotated_offsets[index]
            scalar_type = x87_scalar_arg_types.get(offset)
            if scalar_type is not None:
                arg_type = scalar_type
                if proto_args[index] != scalar_type:
                    proto_args[index] = scalar_type
                    changed = True
            elif (
                index < len(source_pointer_flags)
                and source_pointer_flags[index] is False
                and isinstance(arg_type, SimTypePointer)
            ):
                arg_type = SimTypeShort(False).with_arch(project.arch)
                if proto_args[index] != arg_type:
                    proto_args[index] = arg_type
                    changed = True
            width = max(2, _type_size_bytes_8616(arg_type))
            if annotated_offsets and index + 1 < len(annotated_offsets):
                annotated_width = annotated_offsets[index + 1] - offset
                if annotated_width > 0:
                    width = annotated_width
            if annotated_offsets and not prototype_is_explicit:
                width = max(width, inferred_arg_widths.get(offset, 2))
            if not prototype_is_explicit and width > 2 and not isinstance(arg_type, SimTypePointer):
                wide_type = SimTypeLong(False).with_arch(project.arch)
                if _type_size_bytes_8616(arg_type) <= width or isinstance(arg_type, SimTypeLong):
                    arg_type = wide_type
                    if proto_args[index] != wide_type:
                        proto_args[index] = wide_type
                        changed = True
            expected_offsets.add(offset)
            name = arg_names[index] if index < len(arg_names) and isinstance(arg_names[index], str) else f"a{index}"
            cvar = stack_cvars_by_offset.get(offset)
            variable = getattr(cvar, "variable", None) if cvar is not None else None
            if not isinstance(variable, SimStackVariable) or getattr(variable, "size", None) != width:
                variable = SimStackVariable(offset, width, base="bp", name=name, region=func_addr)
                cvar = CVariable(variable, variable_type=arg_type, codegen=codegen)
                variables_in_use[variable] = cvar
                if isinstance(unified, dict):
                    unified[variable] = {(cvar, arg_type)}
                changed = True
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True
            if getattr(cvar, "name", None) != name:
                with contextlib.suppress(Exception):
                    cast(Any, cvar).name = name
                changed = True
            if getattr(cvar, "variable_type", None) != arg_type:
                cast(Any, cvar).variable_type = arg_type
                changed = True
            if variable not in variables_in_use:
                variables_in_use[variable] = cvar
                changed = True
            desired_args.append(cvar)
            if not annotated_offsets:
                offset += width

        first_arg_offset = min(expected_offsets) if expected_offsets else 4
        for variable in tuple(variables_in_use.keys()):
            if not isinstance(variable, SimStackVariable):
                continue
            var_offset = variable.offset
            if isinstance(var_offset, int) and 0 < var_offset < first_arg_offset:
                del variables_in_use[variable]
                changed = True
        if isinstance(unified, dict):
            for variable in tuple(unified.keys()):
                if not isinstance(variable, SimStackVariable):
                    continue
                var_offset = variable.offset
                if isinstance(var_offset, int) and 0 < var_offset < first_arg_offset:
                    del unified[variable]
                    changed = True
        changed = (
            _prune_unused_stack_slots_covered_by_annotation_args_8616(
                codegen=codegen,
                arg_offsets=set(annotated_offsets),
                arg_widths=inferred_arg_widths,
            )
            or changed
        )

        existing_args = list(getattr(cfunc, "arg_list", ()) or ())
        if len(existing_args) != len(desired_args) or any(
            existing is not desired for existing, desired in zip(existing_args, desired_args, strict=False)
        ):
            cfunc.arg_list = desired_args
            changed = True
        active_prototype = prototype
        if proto_args != original_proto_args:
            prototype_dynamic = cast(Any, prototype)
            return_type = prototype_dynamic.returnty
            # Dynamic angr/codegen compatibility boundary.
            if any(isinstance(arg_type, SimTypeLong) and not getattr(arg_type, "signed", True) for arg_type in proto_args):  # noqa: SIM102
                if isinstance(return_type, SimTypeLong):
                    return_type = SimTypeLong(False).with_arch(project.arch)
            active_prototype = prototype_dynamic.__class__(
                proto_args,
                return_type,
                arg_names=getattr(prototype, "arg_names", None),
                variadic=getattr(prototype, "variadic", False),
            ).with_arch(project.arch)
            cast(Any, func).prototype = active_prototype
            cast(Any, func).is_prototype_guessed = False
        if getattr(cfunc, "functy", None) is not active_prototype:
            _set_codegen_prototype_8616(codegen, active_prototype)
            changed = True
        return changed

    return _impl()


def _collect_stack_promotion_inputs_8616(
    func: object,
) -> tuple[dict[object, object], tuple[bool, ...], object, list[tuple[int, str | None]]]:
    def _impl() -> tuple[dict[object, object], tuple[bool, ...], object, list[tuple[int, str | None]]]:
        annotations = {}
        info = getattr(func, "info", None)
        if isinstance(info, MutableMapping):
            maybe_annotations = info.get(ANNOTATION_KEY)
            if isinstance(maybe_annotations, dict):
                annotations = maybe_annotations
        prototype_pointer_flags: tuple[bool, ...] = ()
        # Dynamic angr/codegen compatibility boundary.
        if getattr(func, "is_prototype_guessed", True) is False:
            prototype_pointer_flags = _prototype_pointer_flags_8616(getattr(func, "prototype", None))
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"collect_inputs func={getattr(func, 'addr', None)!r} "
                f"prototype_pointer_flags={prototype_pointer_flags!r}",
                file=sys.stderr,
                flush=True,
            )
        stack_specs = stack_layout_annotation_specs_8616(annotations)
        annotated_args: list[tuple[int, str | None]] = []
        if isinstance(stack_specs, dict):
            positive_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
            positive_specs_are_normalized = bool(positive_offsets) and positive_offsets[0] == 2
            for offset, spec in sorted(stack_specs.items(), key=lambda item: item[0]):
                if not isinstance(offset, int) or offset <= 0:
                    continue
                name = None
                if isinstance(spec, str):
                    name = spec
                elif isinstance(spec, dict):
                    spec_name = spec.get("name")
                    if isinstance(spec_name, str) and spec_name:
                        name = spec_name
                codegen_offset = offset + 2 if positive_specs_are_normalized else offset
                annotated_args.append((codegen_offset, name))
        return annotations, prototype_pointer_flags, stack_specs, annotated_args

    return _impl()


def _prototype_pointer_flags_8616(prototype: object) -> tuple[bool, ...]:
    if prototype is None:
        return ()
    args = cast(tuple[object, ...], tuple(getattr(prototype, "args", ()) or ()))
    if not args:
        return ()
    return tuple(isinstance(arg, SimTypePointer) for arg in args)


def _prototype_pointer_flags_for_codegen_function_8616(
    project: SimpleNamespace, func_addr: int | None
) -> tuple[bool, ...]:
    if not isinstance(func_addr, int):
        return ()
    for candidate in (func_addr,):
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=candidate, create=False)
            flags = _prototype_pointer_flags_8616(function.prototype) if function.is_prototype_guessed is False else ()
            if flags:
                return flags
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        for candidate in (func_addr + delta, func_addr - delta):
            if candidate < 0:
                continue
            with contextlib.suppress(Exception):
                function = project.kb.functions.function(addr=candidate, create=False)
                flags = _prototype_pointer_flags_8616(function.prototype) if function.is_prototype_guessed is False else ()
                if flags:
                    return flags
    return ()


def _pointer_type_for_codegen_8616(codegen: Any) -> SimTypePointer:
    """Bind a pointer view to the codegen architecture, retaining its type class."""
    pointer_type = SimTypePointer(SimTypeShort(False))
    arch = getattr(getattr(codegen, "project", None), "arch", None)
    if arch is not None:
        pointer_type = cast(SimTypePointer, pointer_type.with_arch(arch))
    return pointer_type


class PointerArgIndirectFactKind8616(Enum):
    """Classify proven indirect uses of pointer-like stack arguments."""

    LOAD_WORD = "load_word"
    STORE_WORD = "store_word"


@dataclass(frozen=True, slots=True)
class PointerArgIndirectFact8616:
    """Evidence that a register loaded from a stack argument is dereferenced."""

    kind: PointerArgIndirectFactKind8616
    insn_addr: int
    stack_offset: int
    base_reg: str


@dataclass(slots=True)
class PointerArgIndirectMaterializationStats8616:
    """Evidence counters for pointer-argument indirect load materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refused_count: int = 0


@dataclass(slots=True)
class StackArgHighByteProjectionStats8616:
    """Evidence counters for replacing high-byte stack args with base-word projections."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _record_semantic_lane_8616(
    codegen: SimpleNamespace,
    *,
    name: str,
    raw: int,
    normalized: int,
    classified: int,
    materialized: int,
    failures: int,
) -> SemanticLaneState:
    lane = SemanticLaneState(
        name=name,
        raw=raw,
        normalized=normalized,
        classified=classified,
        materialized=materialized,
        failures=failures,
    )
    # Dynamic angr/codegen compatibility boundary.
    lanes = tuple(getattr(codegen, "_inertia_semantic_lanes_8616", ()) or ())
    # Dynamic angr/codegen compatibility boundary.
    filtered = tuple(existing for existing in lanes if getattr(existing, "name", None) != lane.name)
    codegen._inertia_semantic_lanes_8616 = (*filtered, lane)
    return lane


def _record_pointer_arg_indirect_lane_8616(
    codegen: SimpleNamespace, stats: PointerArgIndirectMaterializationStats8616
) -> None:
    lane = _record_semantic_lane_8616(
        codegen,
        name="pointer_arg_indirect",
        raw=stats.raw_fact_count,
        normalized=stats.normalized_fact_count,
        classified=stats.classified_fact_count,
        materialized=stats.materialized_count,
        failures=stats.failure_count,
    )
    codegen._inertia_pointer_arg_indirect_lane_8616 = lane


def _record_stack_arg_high_byte_projection_lane_8616(
    codegen: SimpleNamespace, stats: StackArgHighByteProjectionStats8616
) -> None:
    lane = _record_semantic_lane_8616(
        codegen,
        name="stack_arg_high_byte_projection",
        raw=stats.raw_fact_count,
        normalized=stats.normalized_fact_count,
        classified=stats.classified_fact_count,
        materialized=stats.materialized_count,
        failures=stats.failure_count,
    )
    codegen._inertia_stack_arg_high_byte_projection_lane_8616 = lane


def _operand_reg_name_from_capstone_8616(insn: Any, operand: Any) -> str | None:
    reg = getattr(operand, "reg", None)
    if not isinstance(reg, int):
        return None
    reg_name = getattr(insn, "reg_name", None)
    if not callable(reg_name):
        return None
    with contextlib.suppress(Exception):
        name = reg_name(reg)
        if isinstance(name, str) and name:
            return name.lower()
    return None


def _operand_mem_base_name_from_capstone_8616(insn: Any, operand: Any) -> str | None:
    if getattr(operand, "type", None) != X86_OP_MEM:
        return None
    mem = getattr(operand, "mem", None)
    base_reg = getattr(mem, "base", None) if mem is not None else None
    if not isinstance(base_reg, int):
        return None
    return _operand_reg_name_from_capstone_8616(insn, SimpleNamespace(reg=base_reg))


def _bp_memory_displacement_from_capstone_8616(insn: Any, operand: Any) -> int | None:
    if getattr(operand, "type", None) != X86_OP_MEM:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    base = _operand_mem_base_name_from_capstone_8616(insn, operand)
    if base != "bp":
        return None
    index_reg = getattr(mem, "index", None)
    if isinstance(index_reg, int) and index_reg:
        return None
    disp = getattr(mem, "disp", None)
    return disp if isinstance(disp, int) else None


def _is_simple_reg_indirect_operand_8616(insn: Any, operand: Any, reg_name: str) -> bool:
    if getattr(operand, "type", None) != X86_OP_MEM:
        return False
    mem = getattr(operand, "mem", None)
    if mem is None:
        return False
    if _operand_mem_base_name_from_capstone_8616(insn, operand) != reg_name:
        return False
    index_reg = getattr(mem, "index", None)
    disp = getattr(mem, "disp", None)
    return not (isinstance(index_reg, int) and index_reg) and (disp is None or disp == 0)


def _collect_pointer_arg_indirect_facts_8616(
    project: Any, function: Any, pointer_arg_offsets: set[int]
) -> tuple[PointerArgIndirectFact8616, ...]:
    if project is None or function is None or not pointer_arg_offsets:
        return ()

    facts: list[PointerArgIndirectFact8616] = []
    seen: set[tuple[PointerArgIndirectFactKind8616, int, int]] = set()
    reg_points_to_arg_offset: dict[str, int] = {}

    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            block = project.factory.block(block_addr, opt_level=0)
            insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        except Exception:
            continue
        for wrapped_insn in insns:
            insn = getattr(wrapped_insn, "insn", wrapped_insn)
            mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
            operands: tuple[Any, ...] = tuple(getattr(insn, "operands", ()) or ())
            insn_addr = int(getattr(wrapped_insn, "address", getattr(insn, "address", 0)) or 0)
            if mnemonic != "mov" or len(operands) != 2:
                dst_reg = (
                    _operand_reg_name_from_capstone_8616(insn, operands[0])
                    if operands and getattr(operands[0], "type", None) == X86_OP_REG
                    else None
                )
                if dst_reg is not None:
                    reg_points_to_arg_offset.pop(dst_reg, None)
                continue

            dst, src = operands
            dst_reg = (
                _operand_reg_name_from_capstone_8616(insn, dst) if getattr(dst, "type", None) == X86_OP_REG else None
            )
            src_reg = (
                _operand_reg_name_from_capstone_8616(insn, src) if getattr(src, "type", None) == X86_OP_REG else None
            )

            if dst_reg is not None:
                src_bp_disp = _bp_memory_displacement_from_capstone_8616(insn, src)
                if src_bp_disp in pointer_arg_offsets:
                    reg_points_to_arg_offset[dst_reg] = int(src_bp_disp)
                    continue
                if src_reg is not None and src_reg in reg_points_to_arg_offset:
                    reg_points_to_arg_offset[dst_reg] = reg_points_to_arg_offset[src_reg]
                    continue

                for base_reg, stack_offset in tuple(reg_points_to_arg_offset.items()):
                    if _is_simple_reg_indirect_operand_8616(insn, src, base_reg):
                        key = (PointerArgIndirectFactKind8616.LOAD_WORD, insn_addr, stack_offset)
                        if key not in seen:
                            seen.add(key)
                            facts.append(
                                PointerArgIndirectFact8616(
                                    PointerArgIndirectFactKind8616.LOAD_WORD,
                                    insn_addr,
                                    stack_offset,
                                    base_reg,
                                )
                            )
                        break
                reg_points_to_arg_offset.pop(dst_reg, None)
                continue

            for base_reg, stack_offset in tuple(reg_points_to_arg_offset.items()):
                if _is_simple_reg_indirect_operand_8616(insn, dst, base_reg):
                    key = (PointerArgIndirectFactKind8616.STORE_WORD, insn_addr, stack_offset)
                    if key not in seen:
                        seen.add(key)
                        facts.append(
                            PointerArgIndirectFact8616(
                                PointerArgIndirectFactKind8616.STORE_WORD,
                                insn_addr,
                                stack_offset,
                                base_reg,
                            )
                        )
                    break

    return tuple(sorted(facts, key=lambda fact: fact.insn_addr))


def _make_zero_indexed_pointer_arg_8616(codegen: Any, cvar: CVariable) -> CIndexedVariable:
    index_type = SimTypeShort(False)
    arch = getattr(getattr(codegen, "project", None), "arch", None)
    if arch is not None and hasattr(index_type, "with_arch"):
        index_type = index_type.with_arch(arch)
    return CIndexedVariable(cvar, CConstant(0, index_type, codegen=codegen), codegen=codegen)


def _function_call_name_8616(expr: object) -> str | None:
    if not isinstance(expr, CFunctionCall):
        return None
    target = expr.callee_target
    if isinstance(target, str) and target:
        return target.lstrip("_")
    callee = expr.callee_func
    if callee is None:
        return None
    name = callee.name
    return name.lstrip("_") if isinstance(name, str) and name else None


def _offset_expr_stack_arg_offset_8616(expr: object) -> int | None:
    while isinstance(expr, CTypeCast):
        expr = expr.expr
    if isinstance(expr, CVariable):
        return _stack_offset_for_cvariable_8616(expr)
    if not isinstance(expr, CBinaryOp) or expr.op != "Add":
        return None
    lhs = expr.lhs
    rhs = expr.rhs
    if isinstance(lhs, CConstant) and isinstance(lhs.value, int) and lhs.value == 0:
        return _offset_expr_stack_arg_offset_8616(rhs)
    if isinstance(rhs, CConstant) and isinstance(rhs.value, int) and rhs.value == 0:
        return _offset_expr_stack_arg_offset_8616(lhs)
    return None


def _materialized_pointer_arg_helper_load_8616(
    rhs: object,
    pointer_args_by_offset: dict[int, CVariable],
    codegen: SimpleNamespace,
) -> tuple[int, CIndexedVariable] | None:
    if not isinstance(rhs, CFunctionCall):
        return None
    if _function_call_name_8616(rhs) not in {"SEG_U16", "MEM_U16"}:
        return None
    args = tuple(rhs.args or ())
    if len(args) == 2:
        offset_expr = args[1]
    elif len(args) == 1:
        offset_expr = args[0]
    else:
        return None
    offset = _offset_expr_stack_arg_offset_8616(offset_expr)
    if not isinstance(offset, int):
        return None
    pointer_arg = pointer_args_by_offset.get(offset)
    if pointer_arg is None:
        return None
    return offset, _make_zero_indexed_pointer_arg_8616(codegen, pointer_arg)


def _existing_pointer_arg_indexed_load_offset_8616(
    rhs: object,
    pointer_args_by_offset: dict[int, CVariable],
) -> int | None:
    if not isinstance(rhs, CIndexedVariable):
        return None
    offset = _stack_offset_for_cvariable_8616(rhs.variable)
    if offset not in pointer_args_by_offset:
        return None
    index_value = _c_constant_value_8616(rhs.index)
    if index_value != 0:
        return None
    return offset


def _assignment_lhs_accepts_pointer_load_value_8616(lhs: object) -> bool:
    while isinstance(lhs, CTypeCast):
        lhs = lhs.expr
    if isinstance(lhs, CIndexedVariable):
        return True
    if isinstance(lhs, CUnaryOp) and lhs.op == "Dereference":
        return True
    if isinstance(lhs, CVariable):
        return not isinstance(lhs.variable_type, SimTypePointer)
    return False


def _statement_children_for_pointer_arg_materialization_8616(stmt: object) -> tuple[object, ...]:
    children: list[object] = []
    for attr in ("initializer", "iterator", "body", "else_node", "statements"):
        child = getattr(stmt, attr, None)
        if child is not None:
            children.append(child)
    cond_pairs = getattr(stmt, "condition_and_nodes", ())
    if isinstance(cond_pairs, (list, tuple)):
        for _cond, body in cast(tuple[tuple[object, object], ...], tuple(cond_pairs)):
            if body is not None:
                children.append(body)
    cases = getattr(stmt, "cases", ())
    if isinstance(cases, (list, tuple)):
        for _case, body in cast(tuple[tuple[object, object], ...], tuple(cases)):
            if body is not None:
                children.append(body)
    return tuple(children)


def _iter_assignments_in_statement_order_8616(
    root: object, seen: set[int] | None = None
) -> Iterator[CAssignment]:
    if seen is None:
        seen = set()
    if root is None:
        return
    obj_id = id(root)
    if obj_id in seen:
        return
    seen.add(obj_id)
    if isinstance(root, CAssignment):
        yield root
        return
    if isinstance(root, CStatements):
        for stmt in tuple(root.statements or ()):
            yield from _iter_assignments_in_statement_order_8616(stmt, seen)
        return
    if isinstance(root, (list, tuple)):
        for item in root:
            yield from _iter_assignments_in_statement_order_8616(item, seen)
        return
    for child in _statement_children_for_pointer_arg_materialization_8616(root):
        yield from _iter_assignments_in_statement_order_8616(child, seen)


def _stack_offset_for_cvariable_8616(cvar: object) -> int | None:
    if not isinstance(cvar, CVariable):
        return None
    for variable in (cvar.variable, cvar.unified_variable):
        offset = getattr(variable, "offset", None)
        if isinstance(variable, SimStackVariable) and isinstance(offset, int):
            return offset
    return None


def _machine_bp_offset_for_cvariable_8616(
    codegen: object,
    cvar: object,
) -> int | None:
    """Return one structured variable's canonical machine-BP offset."""
    if not isinstance(cvar, CVariable):
        return None
    for variable in (cvar.variable, cvar.unified_variable):
        if not isinstance(variable, SimStackVariable):
            continue
        offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if isinstance(offset, int):
            return offset
    return None


def _machine_bp_stack_binding_identity_8616(
    codegen: object,
    variable: SimStackVariable,
    cvar: object,
) -> _StackSlotIdentity | None:
    """Prefer a declaration map's canonical C-variable identity over its key."""
    if isinstance(cvar, CVariable) and isinstance(
        cvar.variable,
        SimStackVariable,
    ):
        identity = machine_bp_stack_identity_8616(codegen, cvar.variable)
        if identity is not None:
            return identity
    return machine_bp_stack_identity_8616(codegen, variable)


def _pointer_arg_offsets_for_codegen_8616(codegen: SimpleNamespace) -> dict[int, CVariable]:
    offsets: dict[int, CVariable] = {}
    cfunc = codegen.cfunc
    if cfunc is None:
        return offsets
    # Dynamic angr/codegen compatibility boundary.
    prototype_args = tuple(getattr(cfunc.functy, "args", ()) or ())
    # Dynamic angr/codegen compatibility boundary.
    prototype_names = tuple(getattr(cfunc.functy, "arg_names", ()) or ())
    current_names = [
        # Dynamic angr/codegen compatibility boundary.
        getattr(getattr(cvar, "variable", None), "name", None)
        for cvar in tuple(cfunc.arg_list or ())
        if isinstance(cvar, CVariable)
    ]
    duplicate_names = {
        name for name in current_names if isinstance(name, str) and current_names.count(name) > 1
    }
    for index, cvar in enumerate(tuple(cfunc.arg_list or ())):
        if not isinstance(cvar, CVariable):
            continue
        cvar_type = cvar.variable_type
        proto_type = prototype_args[index] if index < len(prototype_args) else None
        if not isinstance(cvar_type, SimTypePointer) and not isinstance(proto_type, SimTypePointer):
            continue
        proto_name = prototype_names[index] if index < len(prototype_names) else None
        # Dynamic angr/codegen compatibility boundary.
        current_name = getattr(cvar.variable, "name", None)
        if (
            isinstance(proto_name, str)
            and proto_name
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", proto_name)
            and (
                current_name in duplicate_names
                or not isinstance(current_name, str)
                or re.fullmatch(r"(?:arg_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", current_name)
            )
        ):
            variable = cvar.variable
            # Dynamic angr/codegen compatibility boundary.
            if variable is not None and getattr(variable, "name", None) != proto_name:
                variable.name = proto_name
            # Dynamic angr/codegen compatibility boundary.
            if cvar.name != proto_name:
                with contextlib.suppress(Exception):
                    cvar.name = proto_name
        offset = _stack_offset_for_cvariable_8616(cvar)
        if isinstance(offset, int):
            offsets[offset] = cvar
    return offsets


def _candidate_functions_for_pointer_arg_fact_scan_8616(
    project: Any, codegen: Any, func: Any
) -> Iterator[tuple[Any, Any]]:
    yielded: set[tuple[int, int]] = set()

    def add(candidate_project: Any, candidate_func: Any) -> Iterator[tuple[Any, Any]]:
        if candidate_project is None or candidate_func is None:
            return
        key = (id(candidate_project), id(candidate_func))
        if key in yielded:
            return
        yielded.add(key)
        yield candidate_project, candidate_func

    yield from add(project, getattr(codegen, "_func", None))
    cfunc_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if isinstance(cfunc_addr, int):
        with contextlib.suppress(Exception):
            yield from add(project, project.kb.functions.function(addr=cfunc_addr, create=False))
    yield from add(project, func)

    delta = getattr(project, "_inertia_original_linear_delta", None)
    original_project = getattr(project, "_inertia_original_project", None)
    if isinstance(delta, int) and original_project is not None and isinstance(cfunc_addr, int):
        with contextlib.suppress(Exception):
            yield from add(
                original_project, original_project.kb.functions.function(addr=cfunc_addr + delta, create=False)
            )


def _materialize_pointer_arg_indirect_loads_8616(
    project: SimpleNamespace, codegen: SimpleNamespace, func: object
) -> bool:
    pointer_args_by_offset = _pointer_arg_offsets_for_codegen_8616(codegen)
    debug_pointer_indirect = os.environ.get("INERTIA_DEBUG_POINTER_ARG_INDIRECT") == "1"
    stats = PointerArgIndirectMaterializationStats8616()
    codegen._inertia_pointer_arg_indirect_stats_8616 = stats
    if not pointer_args_by_offset:
        codegen._inertia_pointer_arg_indirect_refused_8616 = 0
        _record_pointer_arg_indirect_lane_8616(codegen, stats)
        if debug_pointer_indirect:
            print("[dbg-pointer-indirect] no pointer args", file=sys.stderr, flush=True)
        return False

    facts: tuple[PointerArgIndirectFact8616, ...] = ()
    for scan_project, scan_func in _candidate_functions_for_pointer_arg_fact_scan_8616(project, codegen, func):
        facts = _collect_pointer_arg_indirect_facts_8616(scan_project, scan_func, set(pointer_args_by_offset))
        if debug_pointer_indirect:
            print(
                "[dbg-pointer-indirect] "
                f"scan_project={id(scan_project)} func={getattr(scan_func, 'addr', None)!r} "
                f"blocks={sorted(getattr(scan_func, 'block_addrs_set', ()) or ())} facts={facts!r}",
                file=sys.stderr,
                flush=True,
            )
        if facts:
            break

    load_facts = tuple(fact for fact in facts if fact.kind is PointerArgIndirectFactKind8616.LOAD_WORD)
    stats.raw_fact_count = len(facts)
    stats.normalized_fact_count = len(load_facts)
    stats.classified_fact_count = len(load_facts)
    codegen._inertia_pointer_arg_indirect_fact_count_8616 = len(facts)
    codegen._inertia_pointer_arg_indirect_load_fact_count_8616 = len(load_facts)
    if debug_pointer_indirect:
        pointer_debug = {
            offset: (
                # Dynamic angr/codegen compatibility boundary.
                getattr(cvar, "name", None),
                # Dynamic angr/codegen compatibility boundary.
                getattr(getattr(cvar, "variable", None), "name", None),
                # Dynamic angr/codegen compatibility boundary.
                getattr(getattr(cvar, "variable", None), "offset", None),
                id(cvar),
            )
            for offset, cvar in sorted(pointer_args_by_offset.items())
        }
        print(
            "[dbg-pointer-indirect] "
            f"pointer_offsets={sorted(pointer_args_by_offset)} pointer_map={pointer_debug!r} "
            f"load_facts={load_facts!r}",
            file=sys.stderr,
            flush=True,
        )
    if not load_facts:
        _record_pointer_arg_indirect_lane_8616(codegen, stats)
        return False

    changed = False
    fact_index = 0
    refused = 0
    materialized = 0
    for stmt in _iter_assignments_in_statement_order_8616(codegen.cfunc.statements):
        rhs = stmt.rhs
        if debug_pointer_indirect:
            rhs_var = getattr(rhs, "variable", None)
            rhs_unified = getattr(rhs, "unified_variable", None)
            print(
                "[dbg-pointer-indirect] assignment "
                f"lhs={type(getattr(stmt, 'lhs', None)).__name__} rhs={type(rhs).__name__} "
                f"lhs_name={getattr(getattr(getattr(stmt, 'lhs', None), 'variable', None), 'name', None)!r} "
                f"rhs_name={getattr(rhs_var, 'name', None)!r} "
                f"rhs_var={type(rhs_var).__name__} rhs_offset={getattr(rhs_var, 'offset', None)!r} "
                f"rhs_unified={type(rhs_unified).__name__} unified_offset={getattr(rhs_unified, 'offset', None)!r}",
                file=sys.stderr,
                flush=True,
            )
        helper_load = _materialized_pointer_arg_helper_load_8616(rhs, pointer_args_by_offset, codegen)
        if helper_load is not None:
            offset, indexed_pointer_arg = helper_load
            if fact_index >= len(load_facts) or load_facts[fact_index].stack_offset != offset:
                refused += 1
                if debug_pointer_indirect:
                    print(
                        "[dbg-pointer-indirect] refused helper order "
                        f"offset={offset} fact_index={fact_index} next_fact="
                        f"{load_facts[fact_index] if fact_index < len(load_facts) else None!r}",
                        file=sys.stderr,
                        flush=True,
                    )
                continue
            stmt.rhs = indexed_pointer_arg
            if debug_pointer_indirect:
                print(
                    f"[dbg-pointer-indirect] materialized helper offset={offset} fact={load_facts[fact_index]!r}",
                    file=sys.stderr,
                    flush=True,
                )
            fact_index += 1
            materialized += 1
            changed = True
            continue
        existing_indexed_offset = _existing_pointer_arg_indexed_load_offset_8616(rhs, pointer_args_by_offset)
        if isinstance(existing_indexed_offset, int):
            if fact_index >= len(load_facts) or load_facts[fact_index].stack_offset != existing_indexed_offset:
                refused += 1
                if debug_pointer_indirect:
                    print(
                        "[dbg-pointer-indirect] refused existing indexed order "
                        f"offset={existing_indexed_offset} fact_index={fact_index} next_fact="
                        f"{load_facts[fact_index] if fact_index < len(load_facts) else None!r}",
                        file=sys.stderr,
                        flush=True,
                    )
                continue
            if debug_pointer_indirect:
                print(
                    "[dbg-pointer-indirect] accepted existing indexed "
                    f"offset={existing_indexed_offset} fact={load_facts[fact_index]!r}",
                    file=sys.stderr,
                    flush=True,
                )
            fact_index += 1
            materialized += 1
            continue
        if not isinstance(rhs, CVariable):
            continue
        candidate_offset = _stack_offset_for_cvariable_8616(rhs)
        if not isinstance(candidate_offset, int):
            continue
        offset = candidate_offset
        if offset not in pointer_args_by_offset:
            continue
        if not _assignment_lhs_accepts_pointer_load_value_8616(stmt.lhs):
            refused += 1
            if debug_pointer_indirect:
                print(
                    "[dbg-pointer-indirect] refused lhs "
                    f"offset={offset} lhs={getattr(stmt, 'lhs', None)!r} rhs={rhs!r}",
                    file=sys.stderr,
                    flush=True,
                )
            continue
        if fact_index >= len(load_facts) or load_facts[fact_index].stack_offset != offset:
            refused += 1
            if debug_pointer_indirect:
                print(
                    "[dbg-pointer-indirect] refused order "
                    f"offset={offset} fact_index={fact_index} next_fact="
                    f"{load_facts[fact_index] if fact_index < len(load_facts) else None!r}",
                    file=sys.stderr,
                    flush=True,
                )
            continue
        stmt.rhs = _make_zero_indexed_pointer_arg_8616(codegen, pointer_args_by_offset[offset])
        if debug_pointer_indirect:
            print(
                f"[dbg-pointer-indirect] materialized offset={offset} fact={load_facts[fact_index]!r}",
                file=sys.stderr,
                flush=True,
            )
        fact_index += 1
        materialized += 1
        changed = True

    if fact_index < len(load_facts):
        refused += len(load_facts) - fact_index
    stats.materialized_count = materialized
    stats.refused_count = refused
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        stats.failure_count = 1
    _record_pointer_arg_indirect_lane_8616(codegen, stats)
    codegen._inertia_pointer_arg_indirect_load_materialized_8616 = materialized
    codegen._inertia_pointer_arg_indirect_refused_8616 = refused
    if changed:
        with contextlib.suppress(Exception):
            codegen._inertia_force_codegen_regeneration_8616 = True
        with contextlib.suppress(Exception):
            codegen._inertia_postprocess_changed = True
    return changed


def _x87_scalar_stack_arg_types_8616(
    project: Any, func: Any, *, codegen: Any | None = None
) -> dict[int, object]:
    candidates = [getattr(codegen, "_func", None) if codegen is not None else None, func]
    seen: set[int] = set()
    for candidate in candidates:
        if candidate is None or id(candidate) in seen:
            continue
        seen.add(id(candidate))
        try:
            result = x86_16_msvc_x87_scalar_stack_args(project, candidate)
        except Exception:
            logging.getLogger(__name__).debug(
                "x87 scalar stack evidence failed for %#x",
                getattr(candidate, "addr", 0),
                exc_info=True,
            )
            continue
        if result:
            if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
                print(
                    "[dbg-x87-proto] "
                    f"func={getattr(func, 'addr', None)!r} "
                    f"candidate={getattr(candidate, 'addr', None)!r} "
                    f"args={sorted(result)}",
                    file=sys.stderr,
                    flush=True,
                )
            result_dict: dict[int, object] = {int(key): value for key, value in result.items()}
            return result_dict
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"func={getattr(func, 'addr', None)!r} "
                f"candidate={getattr(candidate, 'addr', None)!r} "
                "args=[]",
                file=sys.stderr,
                flush=True,
            )
    return {}


def _apply_stack_arg_cvar_type_8616(codegen: object, cvar: object, variable_type: object) -> bool:
    """Apply a stack-argument C variable type when it structurally changes."""

    changed = False
    # Dynamic angr/codegen compatibility boundary.
    if not _types_equivalent_8616(getattr(cvar, "variable_type", None), variable_type):
        with contextlib.suppress(Exception):
            cast(Any, cvar).variable_type = variable_type
            changed = True
    variable = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
    variable_manager = getattr(getattr(codegen, "cfunc", None), "variable_manager", None)
    if variable_manager is not None and variable is not None:
        with contextlib.suppress(Exception):
            variable_manager.set_variable_type(variable, variable_type)
    return changed


def _promote_from_annotated_args_8616(
    *,
    project: SimpleNamespace,
    codegen: SimpleNamespace,
    func: object,
    prototype: object,
    arg_names: list[str],
    existing_args: list[Any],
    annotated_args: list[tuple[int, str | None]],
    source_pointer_flags: tuple[bool, ...],
    promote_near_pointers: bool,
) -> bool:
    """Sync annotated positive BP arguments into the active codegen prototype."""

    def _impl() -> bool:
        if not annotated_args:
            return False
        target_arg_count = len(annotated_args)
        new_args: list[Any] = list(getattr(prototype, "args", ()) or ())
        if len(new_args) < target_arg_count:
            new_args.extend(
                SimTypeShort(False).with_arch(project.arch) for _ in range(target_arg_count - len(new_args))
            )
        elif len(new_args) > target_arg_count:
            new_args = new_args[:target_arg_count]
        desired_names = []
        for index in range(target_arg_count):
            annotated_name = annotated_args[index][1] if index < len(annotated_args) else None
            existing_name = arg_names[index] if index < len(arg_names) else None
            desired_names.append(annotated_name or existing_name)
        normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)
        stack_cvars_by_offset: dict[int, object] = {}
        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if isinstance(variable, SimStackVariable):
                stack_cvars_by_offset.setdefault(variable.offset, cvar)
        annotated_offsets = [offset for offset, _name in annotated_args if isinstance(offset, int)]
        inferred_arg_widths = _annotation_arg_widths_from_stack_layout_8616(
            arg_offsets=annotated_offsets,
            known_positive_stack_offsets={
                offset for offset in stack_cvars_by_offset if isinstance(offset, int) and offset > 0
            },
        )
        pointer_promoted = False
        scalar_materialized = False
        resolved_args = []
        pointer_type = _pointer_type_for_codegen_8616(codegen)
        x87_scalar_arg_types = _x87_scalar_stack_arg_types_8616(project, func, codegen=codegen)
        for index in range(target_arg_count):
            annotated_offset = annotated_args[index][0] if index < len(annotated_args) else None
            if index < len(existing_args):
                resolved_arg = existing_args[index]
            elif isinstance(annotated_offset, int):
                resolved_arg = stack_cvars_by_offset.get(annotated_offset)
            else:
                resolved_arg = None
            resolved_args.append(resolved_arg)
            inferred_width = (
                inferred_arg_widths.get(annotated_offset, 2) if isinstance(annotated_offset, int) else 2
            )
            scalar_type = x87_scalar_arg_types.get(annotated_offset) if isinstance(annotated_offset, int) else None
            if scalar_type is not None:
                if resolved_arg is not None:
                    scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if inferred_width > 2 and not isinstance(new_args[index], SimTypePointer):
                wide_type = SimTypeLong(False).with_arch(project.arch)
                if _type_size_bytes_8616(new_args[index]) <= inferred_width or isinstance(new_args[index], SimTypeLong):
                    if resolved_arg is not None:
                        scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, wide_type)
                        # Dynamic angr/codegen compatibility boundary.
                        variable = getattr(resolved_arg, "variable", None)
                        # Dynamic angr/codegen compatibility boundary.
                        if isinstance(variable, SimStackVariable) and getattr(variable, "size", None) != inferred_width:
                            variable.size = inferred_width
                            scalar_materialized = True
                    if new_args[index] != wide_type:
                        new_args[index] = wide_type
                        scalar_materialized = True
            if (
                resolved_arg is not None
                and isinstance(new_args[index], SimTypePointer)
                and index < len(source_pointer_flags)
                and source_pointer_flags[index] is False
                and not _stack_arg_has_pointer_evidence_8616(codegen, getattr(resolved_arg, "variable", None))
            ):
                scalar_type = SimTypeShort(False).with_arch(project.arch)
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if resolved_arg is None or not promote_near_pointers:
                continue
            if index < len(source_pointer_flags) and source_pointer_flags[index] is False:
                continue
            if not _stack_arg_has_pointer_evidence_8616(codegen, getattr(resolved_arg, "variable", None)):
                continue
            if getattr(resolved_arg, "variable_type", None) != pointer_type:
                cast(Any, resolved_arg).variable_type = pointer_type
                pointer_promoted = True
            if new_args[index] != pointer_type:
                new_args[index] = pointer_type
                pointer_promoted = True
        if not (
            scalar_materialized
            or pointer_promoted
            or target_arg_count > len(getattr(prototype, "args", ()) or ())
            or list(arg_names) != normalized_names
        ):
            return False
        prototype_dynamic = cast(Any, prototype)
        new_proto = prototype_dynamic.__class__(
            new_args,
            prototype_dynamic.returnty,
            arg_names=normalized_names,
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        cast(Any, func).prototype = new_proto
        cast(Any, func).is_prototype_guessed = False
        _set_codegen_prototype_8616(codegen, new_proto)
        arg_list = getattr(codegen.cfunc, "arg_list", None)
        if isinstance(arg_list, list) and len(arg_list) > target_arg_count:
            codegen.cfunc.arg_list = arg_list[:target_arg_count]
        elif not arg_list and any(resolved_arg is not None for resolved_arg in resolved_args):
            codegen.cfunc.arg_list = [resolved_arg for resolved_arg in resolved_args if resolved_arg is not None]
        _prune_unused_stack_slots_covered_by_annotation_args_8616(
            codegen=codegen,
            arg_offsets=set(annotated_offsets),
            arg_widths=inferred_arg_widths,
        )
        return True

    return _impl()


def _promote_from_fallback_args_8616(
    *,
    project: Any,
    codegen: Any,
    func: Any,
    current_proto: Any,
    existing_args: list[Any],
    source_pointer_flags: tuple[bool, ...],
    promote_near_pointers: bool,
) -> bool:
    def _impl() -> bool:
        fallback_args: list[Any] = [
            arg for arg in existing_args if isinstance(getattr(arg, "variable", None), SimStackVariable)
        ]
        if not fallback_args:
            return False
        target_arg_count = len(fallback_args)
        new_args: list[Any] = list(getattr(current_proto, "args", ()) or ())
        if len(new_args) < target_arg_count:
            new_args.extend(
                SimTypeShort(False).with_arch(project.arch) for _ in range(target_arg_count - len(new_args))
            )
        elif len(new_args) > target_arg_count:
            new_args = new_args[:target_arg_count]
        pointer_promoted = False
        scalar_materialized = False
        pointer_type = _pointer_type_for_codegen_8616(codegen)
        x87_scalar_arg_types = _x87_scalar_stack_arg_types_8616(project, func, codegen=codegen)
        for index, resolved_arg in enumerate(fallback_args):
            variable = getattr(resolved_arg, "variable", None)
            var_offset = getattr(variable, "offset", None)
            scalar_type = x87_scalar_arg_types.get(var_offset) if isinstance(var_offset, int) else None
            if scalar_type is not None:
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if index < len(new_args) and new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if (
                index < len(source_pointer_flags)
                and source_pointer_flags[index] is False
                and index < len(new_args)
                and isinstance(new_args[index], SimTypePointer)
            ):
                scalar_type = SimTypeShort(False).with_arch(project.arch)
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if not promote_near_pointers:
                continue
            if index < len(source_pointer_flags) and source_pointer_flags[index] is False:
                continue
            if not _stack_arg_has_pointer_evidence_8616(codegen, getattr(resolved_arg, "variable", None)):
                continue
            if getattr(resolved_arg, "variable_type", None) != pointer_type:
                cast(Any, resolved_arg).variable_type = pointer_type
                pointer_promoted = True
            if index < len(new_args) and new_args[index] != pointer_type:
                new_args[index] = pointer_type
                pointer_promoted = True
        if not (scalar_materialized or pointer_promoted):
            return False
        desired_names: list[str | None] = []
        for index in range(target_arg_count):
            if index < len(fallback_args):
                desired_names.append(
                    getattr(getattr(fallback_args[index], "unified_variable", None), "name", None)
                    or fallback_args[index].name
                )
            elif index < len(getattr(current_proto, "arg_names", ()) or ()):
                desired_names.append(current_proto.arg_names[index])
            else:
                desired_names.append(None)
        normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)
        current_proto_dynamic = cast(Any, current_proto)
        new_proto = current_proto_dynamic.__class__(
            new_args,
            current_proto_dynamic.returnty,
            arg_names=normalized_names,
            variadic=getattr(current_proto, "variadic", False),
        )
        arch = getattr(getattr(codegen, "project", None), "arch", None)
        if arch is not None and hasattr(new_proto, "with_arch"):
            new_proto = new_proto.with_arch(arch)
        cast(Any, func).prototype = new_proto
        codegen.cfunc.functy = new_proto
        codegen.cfunc.arg_list = fallback_args
        return True

    return _impl()


def _legacy_arg_names_only_8616(arg_names: list[str]) -> bool:
    for name in arg_names:
        if name is None:
            continue
        if not (isinstance(name, str) and len(name) > 1 and name[0] == "a" and name[1:].isdigit()):
            return False
    return True


def _has_wide_return_pattern_8616(codegen: Any) -> bool:
    def _impl() -> bool:
        for stmt in getattr(codegen.cfunc.statements, "statements", ()) or ():
            if not isinstance(stmt, CReturn):
                continue
            retval = stmt.retval
            if not isinstance(retval, CBinaryOp) or retval.op != "Or":
                continue
            for maybe_shl, maybe_other in ((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)):
                if not isinstance(maybe_shl, CBinaryOp) or maybe_shl.op != "Shl":
                    continue
                if _c_constant_value_8616(maybe_shl.rhs) != 16:
                    continue
                if isinstance(maybe_other, CVariable):
                    return True
        return False

    return _impl()


def _c_variable_name_8616(expr: object) -> str | None:
    if not isinstance(expr, CVariable):
        return None
    for candidate in (
        # Dynamic angr/codegen compatibility boundary.
        expr.name,
        # Dynamic angr/codegen compatibility boundary.
        getattr(expr.variable, "name", None),
        # Dynamic angr/codegen compatibility boundary.
        getattr(getattr(expr.variable, "unified_variable", None), "name", None),
        # Dynamic angr/codegen compatibility boundary.
        getattr(expr, "reg", None),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate
    # Dynamic angr/codegen compatibility boundary.
    variable = expr.variable
    if isinstance(variable, SimRegisterVariable):
        # Dynamic angr/codegen compatibility boundary.
        reg = variable.reg
        if isinstance(reg, str) and reg:
            return reg
    return None


def _is_unresolved_synthetic_carrier_name_8616(name: str | None) -> bool:
    """Return true for generated temporary names that are not semantic variables."""
    return isinstance(name, str) and re.fullmatch(r"(?:vvar|v|ir|tmp)_?\d+", name) is not None


def _return_carrier_name_8616(expr: object) -> str | None:
    """Return the generated carrier name for C variables and dirty expressions."""
    variable_name = _c_variable_name_8616(expr)
    if variable_name is not None:
        return variable_name
    if type(expr).__name__ != "CDirtyExpression":
        return None
    # Dynamic angr/codegen compatibility boundary.
    dirty = getattr(expr, "dirty", None)
    synthetic_candidates = (
        # Dynamic angr/codegen compatibility boundary.
        getattr(expr, "name", None),
        # Dynamic angr/codegen compatibility boundary.
        getattr(dirty, "varid", None),
        # Dynamic angr/codegen compatibility boundary.
        getattr(dirty, "oident", None),
    )
    for candidate in synthetic_candidates:
        if isinstance(candidate, str) and _is_unresolved_synthetic_carrier_name_8616(candidate):
            return candidate
        if isinstance(candidate, int):
            return f"vvar_{candidate}"
    # Dynamic angr/codegen compatibility boundary.
    for candidate in (getattr(dirty, "name", None), getattr(expr, "reg", None)):
        if isinstance(candidate, str) and candidate in {"ax", "reg:ax"}:
            return candidate
        if isinstance(candidate, str) and _is_unresolved_synthetic_carrier_name_8616(candidate):
            return candidate
    # Dynamic angr/codegen compatibility boundary.
    expr_idx = getattr(expr, "idx", None)
    if isinstance(expr_idx, int):
        return f"vvar_{expr_idx}"
    return None


def _return_value_is_unresolved_synthetic_carrier_8616(retval: object) -> bool:
    """Return true when a return value is only an unresolved generated carrier."""
    carrier_name = _return_carrier_name_8616(retval)
    if _is_unresolved_synthetic_carrier_name_8616(carrier_name):
        return True
    if _is_generated_stack_local_carrier_name_8616(carrier_name):
        return True
    if _is_generated_stack_local_carrier_variable_8616(retval):
        return True
    if isinstance(retval, CConstant):
        return False
    if isinstance(retval, CVariable):
        return False
    if isinstance(retval, CBinaryOp):
        return (
            _return_value_is_unresolved_synthetic_carrier_component_8616(retval.lhs)
            and _return_value_is_unresolved_synthetic_carrier_component_8616(retval.rhs)
        )
    if isinstance(retval, CUnaryOp) and retval.op in {"Dereference", "Reference", "Neg", "BitwiseNeg"}:
        return _return_value_is_unresolved_synthetic_carrier_component_8616(retval.operand)
    if isinstance(retval, CTypeCast):
        return _return_value_is_unresolved_synthetic_carrier_component_8616(retval.expr)
    return False


def _return_value_is_unresolved_synthetic_carrier_component_8616(expr: object) -> bool:
    """Return true for constants or generated carriers inside a synthetic return expression."""
    if isinstance(expr, CConstant):
        return True
    if isinstance(expr, CVariable):
        name = _c_variable_name_8616(expr)
        return _is_unresolved_synthetic_carrier_name_8616(name) or (
            _is_generated_stack_local_carrier_name_8616(name)
            or _is_generated_stack_local_carrier_variable_8616(expr)
            or (isinstance(name, str)
            and re.fullmatch(r"ss|ds|es", name) is not None)
        )
    if isinstance(expr, CIndexedVariable):
        return _return_value_is_unresolved_synthetic_carrier_component_8616(
            # Dynamic angr/codegen compatibility boundary.
            expr.variable
        ) and _return_value_is_unresolved_synthetic_carrier_component_8616(
            # Dynamic angr/codegen compatibility boundary.
            expr.index
        )
    return _return_value_is_unresolved_synthetic_carrier_8616(expr)


def _is_generated_stack_local_carrier_name_8616(name: str | None) -> bool:
    """Return true for generated stack-local carrier names without semantic ownership."""
    return isinstance(name, str) and re.fullmatch(r"local_?\d+(?:_\d+)?", name) is not None


def _is_generated_stack_local_carrier_variable_8616(expr: object) -> bool:
    """Return true for unnamed generated stack-slot carriers."""
    if not isinstance(expr, CVariable):
        return False
    # Dynamic angr/codegen compatibility boundary.
    return isinstance(expr.variable, SimStackVariable)


def _node_references_c_variable_name_8616(node: object, name: str) -> bool:
    """Return true when a C AST node still reads the named generated variable."""
    for child in _iter_c_nodes_deep_8616(node):
        if child is node:
            continue
        if isinstance(child, CVariable) and _c_variable_name_8616(child) == name:
            return True
    return False


def _drop_codegen_variable_name_if_unreferenced_8616(codegen: SimpleNamespace, name: str) -> bool:
    """Remove a generated declaration entry once the final C AST no longer uses it."""
    # Dynamic angr/codegen compatibility boundary.
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is not None and _node_references_c_variable_name_8616(root, name):
        return False
    # Dynamic angr/codegen compatibility boundary.
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    changed = False
    for attr_name in ("variables_in_use", "unified_local_vars"):
        # Dynamic angr/codegen compatibility boundary.
        mapping = getattr(cfunc, attr_name, None)
        if not isinstance(mapping, MutableMapping):
            continue
        for variable, cvar in tuple(mapping.items()):
            # Dynamic angr/codegen compatibility boundary.
            variable_name = getattr(variable, "name", None)
            # Dynamic angr/codegen compatibility boundary.
            cvar_name = _c_variable_name_8616(cvar) if isinstance(cvar, CVariable) else getattr(cvar, "name", None)
            if name in {variable_name, cvar_name}:
                del mapping[variable]
                changed = True
    return changed


def _collapse_adjacent_unresolved_return_carrier_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    """Replace adjacent ``return vvar_*; return ax;`` with the concrete AX return."""
    del project
    # Dynamic angr/codegen compatibility boundary.
    if getattr(codegen, "cfunc", None) is None:
        return False
    # Dynamic angr/codegen compatibility boundary.
    root = getattr(codegen.cfunc, "statements", None)
    ax_return_expr = next(
        (
            node
            for node in _iter_c_nodes_deep_8616(root)
            if _return_carrier_name_8616(node) in {"ax", "reg:ax"}
        ),
        None,
    )
    changed = False
    for container in tuple(node for node in (root, *_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)):
        # Dynamic angr/codegen compatibility boundary.
        statements = list(getattr(container, "statements", ()) or ())
        if not statements:
            continue
        rewritten: list[object] = []
        index = 0
        local_changed = False
        while index < len(statements):
            current = statements[index]
            next_stmt = statements[index + 1] if index + 1 < len(statements) else None
            if isinstance(current, CReturn) and isinstance(next_stmt, CReturn):
                # Dynamic angr/codegen compatibility boundary.
                current_name = _return_carrier_name_8616(current.retval)
                # Dynamic angr/codegen compatibility boundary.
                next_name = _return_carrier_name_8616(next_stmt.retval)
                if (
                    isinstance(current_name, str)
                    and current_name.startswith("vvar_")
                    and next_name in {"ax", "reg:ax"}
                ):
                    # Dynamic angr/codegen compatibility boundary.
                    rewritten.append(CReturn(next_stmt.retval, codegen=current.codegen))
                    index += 2
                    local_changed = True
                    continue
            if isinstance(current, CReturn) and index == len(statements) - 1 and ax_return_expr is not None:
                # Dynamic angr/codegen compatibility boundary.
                current_name = _return_carrier_name_8616(current.retval)
                if isinstance(current_name, str) and current_name.startswith("vvar_"):
                    # Dynamic angr/codegen compatibility boundary.
                    rewritten.append(CReturn(ax_return_expr, codegen=current.codegen))
                    index += 1
                    local_changed = True
                    continue
            rewritten.append(current)
            index += 1
        if local_changed:
            container.statements = rewritten
            changed = True
    if changed:
        with contextlib.suppress(Exception):
            codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


def _promote_from_legacy_arg_names_8616(
    *, project: SimpleNamespace, codegen: SimpleNamespace, func: object, prototype: object, arg_names: list[str]
) -> bool:
    def _impl() -> bool:
        if not _legacy_arg_names_only_8616(arg_names):
            return False
        if not getattr(codegen, "cfunc", None):
            return False
        stack_slots_by_offset: dict[int, _StackSlotIdentity] = {}
        for variable in getattr(codegen.cfunc, "variables_in_use", {}):
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _stack_slot_identity_for_variable(variable)
            if identity is not None:
                offset_value = variable.offset
                if isinstance(offset_value, int):
                    stack_slots_by_offset[offset_value] = identity
        offsets: set[int] = set()
        slot_identities = set()
        for stmt in getattr(codegen.cfunc.statements, "statements", ()) or ():
            if not isinstance(stmt, CReturn):
                continue
            retval = stmt.retval
            if retval is None:
                continue
            for node in _iter_c_nodes_deep_8616(retval):
                offset = _match_bp_stack_load_8616(node, project)
                if offset is not None and offset > 2:
                    slot_identity = stack_slots_by_offset.get(offset)
                    if slot_identity is None:
                        continue
                    offsets.add(offset)
                    slot_identities.add(slot_identity)
        if len(slot_identities) > 1:
            return False
        existing_args: list[Any] = list(getattr(prototype, "args", ()) or ())
        if offsets:
            target_arg_count = max(len(existing_args), max(((offset - 2) // 2) for offset in offsets))
            if target_arg_count > len(existing_args):
                new_args: list[Any] = list(existing_args)
                new_args.extend(
                    SimTypeShort(False).with_arch(project.arch) for _ in range(target_arg_count - len(existing_args))
                )
            else:
                new_args = list(existing_args)
            normalized_names = _normalize_arg_names_8616(getattr(prototype, "arg_names", None), len(new_args))
            if target_arg_count > len(existing_args):
                prototype_dynamic = cast(Any, prototype)
                new_proto = prototype_dynamic.__class__(
                    new_args,
                    prototype_dynamic.returnty,
                    arg_names=normalized_names,
                    variadic=getattr(prototype, "variadic", False),
                ).with_arch(project.arch)
                cast(Any, func).prototype = new_proto
                cast(Any, func).is_prototype_guessed = False
                _set_codegen_prototype_8616(codegen, new_proto)
                return True
        prototype_dynamic = cast(Any, prototype)
        if not isinstance(prototype_dynamic.returnty, SimTypeLong) or not _has_wide_return_pattern_8616(codegen):
            return False
        wide_ty = SimTypeLong().with_arch(project.arch)
        new_proto = prototype_dynamic.__class__(
            [wide_ty],
            wide_ty,
            arg_names=_normalize_arg_names_8616(getattr(prototype, "arg_names", None), 1),
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        cast(Any, func).prototype = new_proto
        cast(Any, func).is_prototype_guessed = False
        _set_codegen_prototype_8616(codegen, new_proto)
        return True

    return _impl()


def _classify_return_shape_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    # Return-shape reclassification mutates function prototypes and can affect
    # observable memory/ABI behavior. Keep it opt-in until fully proven stable.
    def _impl() -> bool:
        func, prototype = _resolve_codegen_function_and_prototype_8616(project, codegen)
        if func is None or prototype is None:
            return False

        source_decl_is_void = _function_has_void_return_prototype_8616(func)
        function_addr = getattr(func, "addr", None)
        proven_value_return = (
            isinstance(function_addr, int)
            and proven_function_return_class_8616(project, function_addr) is FunctionReturnClass8616.VALUE
        )
        if (
            source_decl_is_void
            and proven_value_return
        ):
            source_decl_is_void = False
        existing_returnty = getattr(prototype, "returnty", None)
        if (
            not source_decl_is_void
            and func is not None
            and not bool(getattr(func, "is_prototype_guessed", True))
            and not (proven_value_return and _is_void_return_type_8616(existing_returnty))
        ):
            return False
        has_switch_loop_exit_void_evidence = bool(
            # Dynamic angr/codegen compatibility boundary.
            getattr(codegen, "_inertia_switch_loop_exit_return_materialized_8616", False)
        )
        if os.environ.get("INERTIA_DEBUG_RETURN_SHAPE", "").strip().lower() in {"1", "true", "yes", "on"}:
            print(
                "[return-shape] "
                # Dynamic angr/codegen compatibility boundary.
                f"func={getattr(func, 'name', None)!r} addr={getattr(func, 'addr', None)!r} "
                # Dynamic angr/codegen compatibility boundary.
                f"proto={prototype!r} guessed={getattr(func, 'is_prototype_guessed', None)!r} "
                f"source_void={source_decl_is_void} switch_void={has_switch_loop_exit_void_evidence} ",
                file=sys.stderr,
                flush=True,
            )
        if (
            os.environ.get("INERTIA_ENABLE_RETURN_SHAPE_CLASSIFY", "").strip().lower() not in {"1", "true", "yes", "on"}
            and not source_decl_is_void
            and not has_switch_loop_exit_void_evidence
            and not proven_value_return
        ):
            return False

        ignored_unreachable_returns = _switch_loop_exit_unreachable_tail_returns_8616(codegen)
        return_nodes = [
            node
            for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements)
            if isinstance(node, CReturn) and id(node) not in ignored_unreachable_returns
        ]
        if not return_nodes:
            source_shape = "scalar" if proven_value_return else None
            if (
                not source_decl_is_void
                and not has_switch_loop_exit_void_evidence
                and not proven_value_return
            ):
                return False
            return_nodes = []
        else:
            source_shape = "scalar" if proven_value_return else None

        tiny_function = _is_tiny_function_8616(project, func)
        changed = False
        value_returns = 0
        return_shapes: set[str] = set()

        for ret in return_nodes:
            retval = getattr(ret, "retval", None)
            if retval is None:
                continue
            value_returns += 1
            shape = _return_value_shape_8616(retval)
            replacement = _unwrap_synthetic_wide_return_8616(retval)
            if tiny_function and replacement is not None:
                ret.retval = None
                changed = True
                if shape is not None and shape != "wide_fp":
                    return_shapes.add(shape)
                continue
            if shape is not None:
                return_shapes.add(shape)

        has_value_return = any(getattr(ret, "retval", None) is not None for ret in return_nodes)
        if (
            not has_value_return
            and not return_nodes
            and source_shape is None
            and not source_decl_is_void
        ):
            return changed

        shape = "void" if not has_value_return and source_shape is None else "scalar_ax"

        info = getattr(func, "info", None)
        if isinstance(info, MutableMapping):
            return_info = info.setdefault("x86_16_return_shape", {})
            return_info["shape"] = shape
            return_info["tiny_function"] = tiny_function
            return_info["value_returns"] = value_returns
            return_info["ignored_unreachable_returns"] = len(ignored_unreachable_returns)

        new_returnty = _choose_return_type_for_shape_8616(
            shape=shape,
            return_shapes=return_shapes,
            source_shape=source_shape,
            existing_returnty=getattr(prototype, "returnty", None),
        )

        if new_returnty is None:
            return changed

        prototype_dynamic = cast(Any, prototype)
        new_proto = prototype_dynamic.__class__(
            list(getattr(prototype, "args", ()) or ()),
            new_returnty,
            arg_names=getattr(prototype, "arg_names", None),
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        try:
            codegen_prototype = codegen.cfunc.functy
        except AttributeError:
            codegen_prototype = None
        if isinstance(codegen_prototype, SimTypeFunction):
            codegen_prototype = codegen_prototype.__class__(
                list(codegen_prototype.args or ()),
                new_returnty,
                arg_names=codegen_prototype.arg_names,
                variadic=codegen_prototype.variadic,
            ).with_arch(project.arch)
        else:
            codegen_prototype = new_proto
        _set_codegen_prototype_8616(codegen, codegen_prototype)
        cast(Any, func).prototype = new_proto
        cast(Any, func).is_prototype_guessed = False
        return True

    return _impl()


def _resolve_codegen_function_and_prototype_8616(
    project: SimpleNamespace, codegen: SimpleNamespace
) -> tuple[object | None, object | None]:
    if getattr(codegen, "cfunc", None) is None:
        return None, None
    for candidate in (
        # Dynamic angr/codegen compatibility boundary.
        getattr(codegen, "_inertia_current_function_8616", None),
        # Dynamic angr/codegen compatibility boundary.
        getattr(codegen, "_func", None),
    ):
        # Dynamic angr/codegen compatibility boundary.
        prototype = getattr(candidate, "prototype", None)
        if candidate is not None and prototype is not None:
            return candidate, prototype
    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return None, None
    with contextlib.suppress(Exception):
        # Dynamic angr/codegen compatibility boundary.
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(delta, int):
            func = project.kb.functions.function(addr=func_addr + delta, create=False)
            # Dynamic angr/codegen compatibility boundary.
            prototype = getattr(func, "prototype", None) if func is not None else None
            if prototype is not None:
                return func, prototype
    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        # Dynamic angr/codegen compatibility boundary.
        prototype = getattr(codegen.cfunc, "functy", None) or getattr(codegen.cfunc, "prototype", None)
        return (SimpleNamespace(addr=func_addr, info={}), prototype) if prototype is not None else (None, None)
    prototype = getattr(func, "prototype", None)
    return func, prototype


def _switch_loop_exit_unreachable_tail_returns_8616(codegen: SimpleNamespace) -> set[int]:
    # Dynamic angr/codegen compatibility boundary.
    if not bool(getattr(codegen, "_inertia_switch_loop_exit_return_materialized_8616", False)):
        return set()
    # Dynamic angr/codegen compatibility boundary.
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if not isinstance(root, CStatements):
        return set()
    ignored: set[int] = set()
    for container in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(container, CStatements):
            continue
        # Dynamic angr/codegen compatibility boundary.
        statements = list(container.statements or ())
        for index, statement in enumerate(statements[:-1]):
            loop = _single_wrapped_while_loop_8616(statement)
            # Dynamic angr/codegen compatibility boundary.
            if loop is None or not _constant_true_8616(getattr(loop, "condition", None)):
                continue
            # Dynamic angr/codegen compatibility boundary.
            if _first_switch_8616(getattr(loop, "body", None)) is None:
                continue
            for tail_stmt in statements[index + 1 :]:
                for node in _iter_c_nodes_deep_8616(tail_stmt):
                    if isinstance(node, CReturn):
                        ignored.add(id(node))
    return ignored


def _single_wrapped_while_loop_8616(node: object) -> CWhileLoop | None:
    if isinstance(node, CWhileLoop):
        return node
    current = node
    for _depth in range(4):
        if not isinstance(current, CStatements):
            return None
        # Dynamic angr/codegen compatibility boundary.
        children = tuple(current.statements or ())
        if len(children) != 1:
            return None
        child = children[0]
        if isinstance(child, CWhileLoop):
            return child
        current = child
    return None


def _constant_true_8616(node: object) -> bool:
    return isinstance(node, CConstant) and isinstance(node.value, int) and node.value != 0


def _first_switch_8616(node: object) -> CSwitchCase | None:
    if isinstance(node, CSwitchCase):
        return node
    for child in _iter_c_nodes_deep_8616(node):
        if isinstance(child, CSwitchCase):
            return child
    return None


def _is_void_return_type_8616(return_type: object) -> bool:
    return isinstance(return_type, SimTypeBottom) and getattr(return_type, "label", None) == "void"


def _function_has_void_return_prototype_8616(func: object, project: object | None = None) -> bool:
    prototype = getattr(func, "prototype", None)
    # Dynamic angr/codegen compatibility boundary.
    return _is_void_return_type_8616(getattr(prototype, "returnty", None))


def _codegen_has_void_return_evidence_8616(_project: object, codegen: SimpleNamespace, func: object | None) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    for candidate in (
        getattr(cfunc, "prototype", None),
        getattr(cfunc, "functy", None),
        getattr(getattr(codegen, "_func", None), "prototype", None),
        getattr(getattr(codegen, "_inertia_current_function_8616", None), "prototype", None),
        getattr(func, "prototype", None) if func is not None else None,
    ):
        if _is_void_return_type_8616(getattr(candidate, "returnty", None)):
            return True
    for candidate_func in (
        getattr(codegen, "_inertia_current_function_8616", None),
        func,
    ):
        if candidate_func is not None and _function_has_void_return_prototype_8616(candidate_func):
            return True
    return False


def _choose_return_type_for_shape_8616(
    *,
    shape: str,
    return_shapes: set[str],
    source_shape: str | None,
    existing_returnty: object,
) -> SimType | None:
    """Choose a changed return type, or refuse an idempotent/no-proof update."""

    def _impl() -> SimType | None:
        if shape == "void":
            return None if _is_void_return_type_8616(existing_returnty) else SimTypeBottom(label="void")
        if shape == "scalar_ax" and ((return_shapes and return_shapes <= {"scalar"}) or source_shape == "scalar"):
            return None if isinstance(existing_returnty, SimTypeShort) else SimTypeShort(False)
        if (return_shapes and return_shapes <= {"wide_fp"}) or source_shape == "wide_fp":
            return None if isinstance(existing_returnty, SimTypeLong) else SimTypeLong()
        return None

    return _impl()


def _prune_void_function_return_values_8616(project: object, codegen: SimpleNamespace) -> bool:
    """Normalize proven-void returns, retaining all internal call-result bindings."""
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = getattr(codegen, "_inertia_current_function_8616", None)
    if func is None:
        with contextlib.suppress(Exception):
            func = cast(Any, project).kb.functions.function(addr=func_addr, create=False)

    if not _codegen_has_void_return_evidence_8616(project, codegen, func):
        return False

    changed = False
    root = getattr(codegen.cfunc, "statements", None)
    for container in tuple(node for node in (root, *_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)):
        if not isinstance(container, CStatements):
            continue
        statements = list(container.statements or ())
        if not statements:
            continue
        rewritten: list[object] = []
        local_changed = False
        for stmt in statements:
            if not isinstance(stmt, CReturn):
                rewritten.append(stmt)
                continue
            retval = stmt.retval
            if retval is None:
                rewritten.append(stmt)
                continue
            if isinstance(retval, CFunctionCall):
                rewritten.append(CExpressionStatement(retval, codegen=stmt.codegen))
                rewritten.append(CReturn(None, codegen=stmt.codegen))
                local_changed = True
                continue
            rewritten.append(CReturn(None, codegen=stmt.codegen))
            local_changed = True
        if local_changed:
            container.statements = rewritten
            changed = True
    if changed:
        with contextlib.suppress(Exception):
            codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


def _prevalidated_positive_stack_annotations_complete_8616(
    codegen: object,
    structured_prototype: object,
    annotations: object,
) -> bool:
    """Return true when lowering already consumed all positive stack annotations."""

    # Dynamic angr/codegen compatibility boundary.
    if not getattr(codegen, "_inertia_annotated_stack_prototype_materialized_8616", 0):
        return False
    if not isinstance(annotations, Mapping):
        return False
    global_specs = annotations.get("global_vars", {})
    if isinstance(global_specs, Mapping) and global_specs:
        return False
    stack_specs = stack_layout_annotation_specs_8616(annotations)
    if not isinstance(stack_specs, Mapping) or not stack_specs:
        return False
    positive_offsets = [offset for offset in stack_specs if isinstance(offset, int) and offset > 0]
    if len(positive_offsets) != len(stack_specs):
        return False
    # Dynamic angr/codegen compatibility boundary.
    cfunc = getattr(codegen, "cfunc", None)
    # Dynamic angr/codegen compatibility boundary.
    if not _prototypes_equivalent_8616(getattr(cfunc, "functy", None), structured_prototype):
        return False
    # Dynamic angr/codegen compatibility boundary.
    return len(tuple(getattr(cfunc, "arg_list", ()) or ())) >= len(positive_offsets)


def _apply_annotations_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    """Apply annotation names while preserving authoritative typed interfaces."""

    def _impl() -> bool:
        """Run the annotation bridge across the dynamic angr codegen surface."""
        if getattr(codegen, "cfunc", None) is None:
            return False

        func_addr = getattr(codegen.cfunc, "addr", None)
        if func_addr is None:
            return False

        func = _metadata_function_for_codegen_addr_8616(project, func_addr)
        if func is None:
            return False

        changed = False
        structured_proto_applied = False
        # Dynamic angr/codegen compatibility boundary.
        annotations = func.info.get(ANNOTATION_KEY) if isinstance(getattr(func, "info", None), Mapping) else None
        annotated_prototype = annotations.get("prototype") if isinstance(annotations, Mapping) else None
        argument_count = len(tuple(getattr(codegen.cfunc, "arg_list", ()) or ()))
        authoritative_prototype = authoritative_function_prototype_8616(
            project,
            func,
            argument_count=argument_count,
        )
        structured_prototype = (
            authoritative_prototype
            if authoritative_prototype is not None
            else annotated_prototype
            if isinstance(annotated_prototype, SimTypeFunction)
            else getattr(func, "prototype", None)
        )
        if _prevalidated_positive_stack_annotations_complete_8616(codegen, structured_prototype, annotations):
            return False
        if structured_prototype is not None:
            # Dynamic angr/codegen compatibility boundary.
            current_codegen_proto = getattr(codegen.cfunc, "functy", None)
            if not _prototypes_equivalent_8616(current_codegen_proto, structured_prototype):
                _set_codegen_prototype_8616(codegen, structured_prototype)
                changed = True
            # Dynamic angr/codegen compatibility boundary.
            for index, cvar in enumerate(getattr(codegen.cfunc, "arg_list", ()) or ()):
                # Dynamic angr/codegen compatibility boundary.
                if index >= len(getattr(structured_prototype, "args", ()) or ()):
                    break
                arg_type_changed = _apply_stack_arg_cvar_type_8616(codegen, cvar, structured_prototype.args[index])
                if arg_type_changed:
                    changed = True
            structured_proto_applied = True
            if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
                print(
                    "[dbg-x87-proto] "
                    f"structured_proto_applied func={func_addr!r} "
                    f"proto={structured_prototype!r}",
                    file=sys.stderr,
                    flush=True,
                )
        if not structured_proto_applied:
            changed_helper, func = _apply_helper_signature_annotation_8616(project, codegen, func_addr, func)
            changed |= changed_helper
            if func is None:
                return False
        changed |= _attach_project_cod_source_annotations_if_missing_8616(project, func_addr, func)
        if not annotations:
            return False

        stack_specs = stack_layout_annotation_specs_8616(annotations)
        global_specs = annotations.get("global_vars", {})
        promote_near_pointers = True
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"apply_annotations func={getattr(func, 'addr', None)!r} "
                f"cfunc={getattr(codegen.cfunc, 'addr', None)!r} "
                f"project_id={id(project)} "
                f"cod_map_keys={sorted(getattr(project, '_inertia_cod_metadata_by_func_addr_8616', {}) or {})} "
                f"stack_offsets={sorted(k for k in stack_specs if isinstance(k, int))}",
                file=sys.stderr,
                flush=True,
            )

        def global_spec_for(addr: int) -> tuple[str | None, object | None]:
            spec = global_specs.get(addr)
            if isinstance(spec, str):
                return spec, None
            if isinstance(spec, dict):
                name = spec.get("name")
                vartype = spec.get("type")
                if isinstance(name, str):
                    return name, vartype
            return None, None

        arg_slot_identities: set[_StackSlotIdentity] = set()
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ():
            arg_variable = getattr(arg, "variable", None)
            if isinstance(arg_variable, SimStackVariable):
                identity = machine_bp_stack_identity_8616(codegen, arg_variable)
                if identity is not None:
                    arg_slot_identities.add(identity)
        helper_arg_names = list(getattr(getattr(func, "prototype", None), "arg_names", ()) or ())
        helper_arg_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
        helper_arg_name_by_offset: dict[int, str] = {
            offset: helper_arg_names[index]
            for index, offset in enumerate(helper_arg_offsets)
            if index < len(helper_arg_names) and isinstance(helper_arg_names[index], str) and helper_arg_names[index]
        }
        stack_vars_by_offset = {}
        used_stack_names: set[str] = set()
        name_owner_offsets: dict[str, int] = {}
        exact_stack_candidates: dict[int, list[tuple[tuple[int, int, int, int, int], CVariable]]] = {}

        def _stack_name_is_generic(name: object) -> bool:
            normalized = _strip_typed_suffix_8616(name)
            if not isinstance(normalized, str):
                return False
            return (
                isinstance(normalized, str)
                and re.fullmatch(r"(?:arg_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", normalized) is not None
            )

        def _stack_candidate_score(
            variable: SimStackVariable, cvar: Any, *, exact: bool
        ) -> tuple[int, int, int, int, int]:
            identity = _machine_bp_stack_binding_identity_8616(
                codegen,
                variable,
                cvar,
            )
            if identity is None:
                return (-1, -1, -1, -1, -1)
            variable_name = getattr(variable, "name", None)
            cvar_name = getattr(cvar, "name", None)
            unified_name = getattr(getattr(cvar, "unified_variable", None), "name", None)
            preferred_name = next(
                (
                    name
                    for name in (variable_name, cvar_name, unified_name)
                    if isinstance(name, str) and name and not _stack_name_is_generic(name)
                ),
                None,
            )
            is_arg_slot = 1 if identity in arg_slot_identities else 0
            has_preferred_name = 1 if preferred_name is not None else 0
            size = getattr(variable, "size", None)
            size_rank = -size if isinstance(size, int) else 0
            exact_rank = 1 if exact else 0
            return (exact_rank, is_arg_slot, has_preferred_name, size_rank, -identity.offset)

        # Lowering owns the function interface.  Its canonical arguments may
        # intentionally be absent from angr's body-only declaration table.
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ():
            variable = getattr(arg, "variable", None)
            if not isinstance(arg, CVariable) or not isinstance(variable, SimStackVariable):
                continue
            identity = _machine_bp_stack_binding_identity_8616(codegen, variable, arg)
            if identity is not None:
                score = _stack_candidate_score(variable, arg, exact=True)
                exact_stack_candidates.setdefault(identity.offset, []).append((score, arg))

        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if isinstance(variable, SimStackVariable):
                identity = _machine_bp_stack_binding_identity_8616(
                    codegen,
                    variable,
                    cvar,
                )
                if identity is None:
                    continue
                score = _stack_candidate_score(variable, cvar, exact=True)
                exact_stack_candidates.setdefault(identity.offset, []).append((score, cvar))

        for offset, candidates in exact_stack_candidates.items():
            _best_score, best_cvar = max(candidates, key=lambda item: item[0])
            stack_vars_by_offset[offset] = best_cvar

        materialized_stack_cvars: dict[int, CVariable] = {}
        positive_stack_spec_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
        positive_specs_are_normalized = _positive_stack_specs_are_normalized_for_codegen_8616(
            stack_specs, codegen
        ) and (
            not stack_vars_by_offset
            or any((offset + 2) in stack_vars_by_offset for offset in positive_stack_spec_offsets)
        )
        annotation_stack_bindings = tuple(
            StackVariableBinding(
                bp_offset=identity.offset,
                size=variable.size,
                var_name=variable.name,
            )
            for variable, cvar in codegen.cfunc.variables_in_use.items()
            if isinstance(variable, SimStackVariable)
            and (
                identity := _machine_bp_stack_binding_identity_8616(
                    codegen,
                    variable,
                    cvar,
                )
            )
            is not None
            and isinstance(variable.size, int)
            and variable.size > 0
        )

        def _stack_spec_for_offset(offset: int, size: int) -> StackAnnotationSpec8616 | None:
            binding = StackVariableBinding(offset, size)
            if positive_specs_are_normalized and offset > 0:
                return select_normalized_stack_argument_annotation_spec_8616(
                    binding,
                    stack_specs=stack_specs,
                )
            candidate_offsets: tuple[int, ...]
            candidate_offsets = (offset, offset + 2, offset - 2) if offset < 0 else (offset,)
            return select_stack_annotation_spec_8616(
                binding,
                stack_specs=stack_specs,
                candidate_offsets=candidate_offsets,
                known_bindings=annotation_stack_bindings,
            )

        def _materialize_stack_cvar(offset: int, type_: object) -> object | None:
            existing = materialized_stack_cvars.get(offset)
            if existing is not None:
                return cast(object | None, existing)

            size = max((getattr(type_, "size", None) or 8) // 8, 1)
            spec = _stack_spec_for_offset(offset, size)
            if spec is None:
                return None

            if spec.name is None:
                return None

            stack_var = SimStackVariable(offset, size, base="bp", name=spec.name, region=func_addr)
            vartype = type_ if type_ is not None else spec.type_spec
            cvar = CVariable(stack_var, variable_type=vartype, codegen=codegen)
            materialized_stack_cvars[offset] = cvar

            variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
            if isinstance(variables_in_use, dict):
                variables_in_use[stack_var] = cvar

            unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
            if isinstance(unified_locals, dict):
                unified_locals[stack_var] = {
                    (cvar, vartype if vartype is not None else getattr(cvar, "variable_type", None))
                }

            stack_vars_by_offset[offset] = cvar
            return cast(object | None, cvar)

        def resolve_stack_cvar(offset: int) -> object | None:
            # A normalized positive stack map starts after the architectural
            # near return word.  BP+2 is therefore never a source variable;
            # do not let an angr declaration-only return carrier win an exact
            # stack binding lookup.
            if positive_specs_are_normalized and offset == 2:
                return None
            direct = stack_vars_by_offset.get(offset)
            if direct is not None:
                return cast(object | None, direct)

            # Positive stack slots are arguments in the x86-16 calling
            # convention model we use here. If we have no exact materialization
            # yet, synthesize the slot rather than aliasing it to a covering local
            # variable. That keeps argument storage distinct from locals and avoids
            # collapsing different stack objects onto the same C variable name.
            if offset > 0:
                return _materialize_stack_cvar(offset, None)

            best = None
            best_size: int | None = None
            for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
                if not isinstance(variable, SimStackVariable):
                    continue
                identity = _machine_bp_stack_binding_identity_8616(
                    codegen,
                    variable,
                    cvar,
                )
                if identity is None:
                    continue
                base_offset = identity.offset
                size = variable.size
                if not isinstance(size, int):
                    continue
                if base_offset <= offset < base_offset + size:  # noqa: SIM102
                    if best_size is None or size < best_size:
                        best = cvar
                        best_size = size
            if best is not None:
                return cast(object | None, best)
            return _materialize_stack_cvar(offset, None)

        rename_changed = _rename_stack_variables_from_specs_8616(
            codegen=codegen,
            stack_specs=stack_specs,
            helper_arg_name_by_offset=helper_arg_name_by_offset,
            used_stack_names=used_stack_names,
            name_owner_offsets=name_owner_offsets,
        )
        if rename_changed:
            changed = True

        rewrite_changed = _apply_annotation_rewrites_8616(
            project=project,
            codegen=codegen,
            stack_vars_by_offset=stack_vars_by_offset,
            global_spec_for=global_spec_for,
            resolve_stack_cvar=resolve_stack_cvar,
            materialize_stack_cvar=_materialize_stack_cvar,
            stack_candidate_score=_stack_candidate_score,
        )
        if rewrite_changed:
            changed = True

        arg_list_synced = _sync_arg_list_from_annotations_8616(
            codegen=codegen,
            func=func,
            stack_specs=stack_specs,
            resolve_stack_cvar=resolve_stack_cvar,
            promote_near_pointers=promote_near_pointers,
        )
        if arg_list_synced:
            changed = True
            rewrite_after_sync_changed = _apply_annotation_rewrites_8616(
                project=project,
                codegen=codegen,
                stack_vars_by_offset=stack_vars_by_offset,
                global_spec_for=global_spec_for,
                resolve_stack_cvar=resolve_stack_cvar,
                materialize_stack_cvar=_materialize_stack_cvar,
                stack_candidate_score=_stack_candidate_score,
            )
            if rewrite_after_sync_changed:
                changed = True

        return changed

    return _impl()


def _rename_stack_variables_from_specs_8616(
    *,
    codegen: SimpleNamespace,
    stack_specs: Mapping[object, object],
    helper_arg_name_by_offset: dict[int, str],
    used_stack_names: set[str],
    name_owner_offsets: dict[str, int],
) -> bool:
    """Apply inert stack names through the typed lowering storage contract."""

    def _impl() -> bool:
        positive_specs_are_normalized = _positive_stack_specs_are_normalized_for_codegen_8616(stack_specs, codegen)
        cfunc = codegen.cfunc
        variables_in_use = cfunc.variables_in_use
        stack_bindings = tuple(
            StackVariableBinding(
                bp_offset=identity.offset,
                size=variable.size,
                var_name=variable.name,
            )
            for variable, cvar in variables_in_use.items()
            if isinstance(variable, SimStackVariable)
            and (
                identity := _machine_bp_stack_binding_identity_8616(
                    codegen,
                    variable,
                    cvar,
                )
            )
            is not None
            and isinstance(variable.size, int)
            and variable.size > 0
        )

        def unique_stack_name(base_name: str | None) -> str | None:
            if not isinstance(base_name, str) or not base_name:
                return None
            candidate = base_name
            suffix = 2
            while candidate in used_stack_names:
                candidate = f"{base_name}_{suffix}"
                suffix += 1
            used_stack_names.add(candidate)
            return candidate

        def spec_name_for(
            variable: SimStackVariable,
            cvar: CVariable,
        ) -> tuple[str | None, object | None]:
            identity = _machine_bp_stack_binding_identity_8616(
                codegen,
                variable,
                cvar,
            )
            if identity is None:
                return None, None
            offset = identity.offset
            candidate_offsets: tuple[int, ...]
            if offset > 0:
                candidate_offsets = (offset - 2, offset) if positive_specs_are_normalized else (offset,)
                helper_name = helper_arg_name_by_offset.get(offset)
                if helper_name is not None:
                    return helper_name, None
            else:
                candidate_offsets = (offset, offset + 2, offset - 2)
            binding = StackVariableBinding(
                bp_offset=offset,
                size=variable.size,
                var_name=variable.name,
            )
            if positive_specs_are_normalized and offset > 0:
                selected = select_normalized_stack_argument_annotation_spec_8616(
                    binding,
                    stack_specs=stack_specs,
                )
            else:
                selected = select_stack_annotation_spec_8616(
                    binding,
                    stack_specs=stack_specs,
                    candidate_offsets=candidate_offsets,
                    known_bindings=stack_bindings,
                )
            if selected is None:
                if stack_binding_inherits_containing_name_8616(
                    binding,
                    current_name=variable.name,
                    known_bindings=stack_bindings,
                ):
                    return _stack_object_name(offset, codegen=codegen), None
                return None, None
            return selected.name, selected.type_spec

        changed = False
        stack_candidates: list[tuple[_StackSlotIdentity, SimStackVariable, CVariable]] = [
            (identity, variable, cvar)
            for variable, cvar in variables_in_use.items()
            if isinstance(variable, SimStackVariable)
            and (
                identity := _machine_bp_stack_binding_identity_8616(
                    codegen,
                    variable,
                    cvar,
                )
            )
            is not None
            and isinstance(variable.size, int)
            and isinstance(cvar, CVariable)
        ]
        stack_items = sorted(
            stack_candidates,
            key=lambda item: (
                0 if item[0].offset > 0 else 1,
                abs(item[0].offset),
                cast(int, item[1].size),
                item[1].name or "",
            ),
        )
        for identity, variable, cvar in stack_items:
            offset = identity.offset
            name, vartype = spec_name_for(variable, cvar)
            if name is None:
                current = variable.name
                if current and not current.startswith(("arg_", "s_", "v")):
                    name = current
            current_name = variable.name
            if isinstance(current_name, str) and current_name and current_name == name:
                owner_offset = name_owner_offsets.get(current_name)
                if current_name not in used_stack_names or owner_offset == offset:
                    used_stack_names.add(current_name)
                    name_owner_offsets[current_name] = offset
                    unified = cvar.unified_variable
                    if unified is not None and unified.name != current_name:
                        unified.name = current_name
                        changed = True
                    if vartype is not None and _apply_stack_arg_cvar_type_8616(codegen, cvar, vartype):
                        changed = True
                    continue
            if isinstance(name, str) and name in used_stack_names:
                owner_offset = name_owner_offsets.get(name)
                if owner_offset != offset:
                    name = unique_stack_name(name)
                    if name is not None:
                        name_owner_offsets[name] = offset
            else:
                name = unique_stack_name(name if isinstance(name, str) else None)
                if name is not None:
                    name_owner_offsets[name] = offset
            if name is not None:
                target = cvar.unified_variable or cvar.variable
                if target is not None and target.name != name:
                    target.name = name
                    changed = True
                if variable.name != name:
                    variable.name = name
                    changed = True
            if vartype is not None and _apply_stack_arg_cvar_type_8616(codegen, cvar, vartype):
                changed = True
        return changed

    return _impl()


def _sync_arg_list_from_annotations_8616(
    *,
    codegen: SimpleNamespace,
    func: object,
    stack_specs: Mapping[object, object],
    resolve_stack_cvar: Callable[[int], object],
    promote_near_pointers: bool,
) -> bool:
    """Synchronize annotated argument names without weakening owned types."""

    def _impl() -> bool:
        """Run the compatibility sync against dynamic C-AST arguments."""
        raw_arg_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
        specs_are_normalized = _positive_stack_specs_are_normalized_for_codegen_8616(stack_specs, codegen)
        arg_offsets = [offset + 2 if specs_are_normalized else offset for offset in raw_arg_offsets]
        arg_offsets_set = set(arg_offsets)
        raw_offset_by_codegen_offset = dict(zip(arg_offsets, raw_arg_offsets, strict=False))
        if not arg_offsets:
            return False
        known_positive_stack_offsets = {
            identity.offset
            # Dynamic angr/codegen compatibility boundary.
            for variable, cvar in getattr(
                codegen.cfunc,
                "variables_in_use",
                {},
            ).items()
            if isinstance(variable, SimStackVariable)
            if (
                identity := _machine_bp_stack_binding_identity_8616(
                    codegen,
                    variable,
                    cvar,
                )
            )
            is not None
            and identity.offset > 0
        }
        inferred_arg_widths = _annotation_arg_widths_from_stack_layout_8616(
            arg_offsets=arg_offsets,
            known_positive_stack_offsets=known_positive_stack_offsets,
        )
        resolved_args = []
        resolved_names: list[str | None] = []

        def _name_from_stack_spec(offset: int) -> str | None:
            spec = stack_specs.get(raw_offset_by_codegen_offset.get(offset, offset))
            if isinstance(spec, str):
                return spec
            if isinstance(spec, dict):
                name = spec.get("name")
                return name if isinstance(name, str) and name else None
            return None

        def _apply_arg_name(cvar: Any, name: str | None) -> bool:
            if not isinstance(name, str) or not name:
                return False
            local_changed = False
            variable = getattr(cvar, "variable", None)
            if variable is not None and getattr(variable, "name", None) != name:
                variable.name = name
                local_changed = True
            if getattr(cvar, "name", None) != name:
                try:
                    cvar.name = name
                except Exception:
                    pass
                else:
                    local_changed = True
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and getattr(unified, "name", None) != name:
                unified.name = name
                local_changed = True
            return local_changed

        name_changed = False
        for offset in arg_offsets:
            cvar = resolve_stack_cvar(offset)
            if isinstance(cvar, CVariable):
                resolved_args.append(cvar)
                spec_name = _name_from_stack_spec(offset)
                resolved_names.append(spec_name)
                name_changed = _apply_arg_name(cvar, spec_name) or name_changed
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                "[dbg-x87-proto] "
                f"sync_annotations func={getattr(func, 'addr', None)!r} "
                f"arg_offsets={arg_offsets} resolved={len(resolved_args)} names={resolved_names!r}",
                file=sys.stderr,
                flush=True,
            )
        if not resolved_args:
            return False
        current_proto = getattr(codegen.cfunc, "functy", None) or getattr(func, "prototype", None)
        if current_proto is None:
            return False
        existing_args = list(getattr(codegen.cfunc, "arg_list", ()) or ())
        target_arg_count = len(resolved_args)
        project = getattr(codegen, "project", None)
        authoritative_prototype = (
            authoritative_function_prototype_8616(
                project,
                func,
                argument_count=target_arg_count,
            )
            if project is not None
            else None
        )
        if authoritative_prototype is not None:
            authoritative_names = tuple(authoritative_prototype.arg_names or ())
            desired_names = [
                resolved_names[index]
                if index < len(resolved_names) and resolved_names[index]
                else authoritative_names[index]
                if index < len(authoritative_names)
                else None
                for index in range(target_arg_count)
            ]
            normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)
            interface_changed = len(existing_args) != target_arg_count or any(
                existing is not resolved
                for existing, resolved in zip(existing_args, resolved_args, strict=False)
            )
            if interface_changed:
                codegen.cfunc.arg_list = resolved_args
            current_names = tuple(getattr(current_proto, "arg_names", ()) or ())
            if current_names != tuple(normalized_names):
                named_prototype = SimTypeFunction(
                    list(authoritative_prototype.args or ()),
                    authoritative_prototype.returnty,
                    arg_names=normalized_names,
                    variadic=authoritative_prototype.variadic,
                )
                arch = getattr(project, "arch", None)
                if arch is not None:
                    named_prototype = named_prototype.with_arch(arch)
                cast(Any, func).prototype = named_prototype
                _set_codegen_prototype_8616(codegen, named_prototype)
                interface_changed = True
            return name_changed or interface_changed
        new_args: list[Any] = list(getattr(current_proto, "args", ()) or ())
        if len(new_args) < target_arg_count:
            new_args.extend(
                SimTypeShort(False).with_arch(getattr(getattr(codegen, "project", None), "arch", None))
                for _ in range(target_arg_count - len(new_args))
            )
        elif len(new_args) > target_arg_count:
            new_args = new_args[:target_arg_count]
        pointer_promoted = False
        scalar_materialized = False
        pointer_type = _pointer_type_for_codegen_8616(codegen)
        _, source_pointer_flags, _, _ = _collect_stack_promotion_inputs_8616(func)
        if not source_pointer_flags and project is not None:
            source_pointer_flags = _prototype_pointer_flags_for_codegen_function_8616(
                cast(SimpleNamespace, project),
                getattr(getattr(codegen, "cfunc", None), "addr", getattr(func, "addr", None)),
            )
        source_pointer_flags = align_pointer_flags_to_stack_argument_widths_8616(
            tuple(source_pointer_flags), tuple(arg_offsets), inferred_arg_widths
        )
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            print(
                f"[dbg-x87-proto] sync_annotations source_pointer_flags={source_pointer_flags!r}",
                file=sys.stderr,
                flush=True,
            )
        x87_scalar_arg_types = (
            _x87_scalar_stack_arg_types_8616(project, func, codegen=codegen) if project is not None else {}
        )
        for index, resolved_arg in enumerate(resolved_args):
            variable = getattr(resolved_arg, "variable", None)
            inferred_width = inferred_arg_widths.get(arg_offsets[index], 2) if index < len(arg_offsets) else 2
            variable_identity = (
                machine_bp_stack_identity_8616(codegen, variable)
                if isinstance(variable, SimStackVariable)
                else None
            )
            scalar_type = (
                x87_scalar_arg_types.get(variable_identity.offset)
                if variable_identity is not None
                else None
            )
            if scalar_type is not None:
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if index < len(new_args) and new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if (
                index < len(source_pointer_flags)
                and source_pointer_flags[index] is False
                and (
                    isinstance(new_args[index], SimTypePointer)
                    or isinstance(getattr(resolved_arg, "variable_type", None), SimTypePointer)
                )
            ):
                arch = getattr(project, "arch", None)
                scalar_type = SimTypeShort(False).with_arch(arch) if arch is not None else SimTypeShort(False)
                scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, scalar_type)
                if index < len(new_args) and new_args[index] != scalar_type:
                    new_args[index] = scalar_type
                    scalar_materialized = True
                continue
            if inferred_width > 2 and index < len(new_args) and not isinstance(new_args[index], SimTypePointer):
                # Dynamic angr/codegen compatibility boundary.
                arch = getattr(project, "arch", None)
                wide_type = SimTypeLong(False).with_arch(arch) if arch is not None else SimTypeLong(False)
                if _type_size_bytes_8616(new_args[index]) <= inferred_width or isinstance(new_args[index], SimTypeLong):
                    scalar_materialized |= _apply_stack_arg_cvar_type_8616(codegen, resolved_arg, wide_type)
                    if new_args[index] != wide_type:
                        new_args[index] = wide_type
                        scalar_materialized = True
                # Dynamic angr/codegen compatibility boundary.
                if isinstance(variable, SimStackVariable) and getattr(variable, "size", None) != inferred_width:
                    variable.size = inferred_width
                    scalar_materialized = True
            if not promote_near_pointers:
                continue
            aligned_pointer_evidence = (
                index < len(source_pointer_flags) and source_pointer_flags[index]
            )
            if not aligned_pointer_evidence and not _stack_arg_has_pointer_evidence_8616(codegen, variable):
                continue
            if getattr(resolved_arg, "variable_type", None) != pointer_type:
                cast(Any, resolved_arg).variable_type = pointer_type
                pointer_promoted = True
            if index < len(new_args) and new_args[index] != pointer_type:
                new_args[index] = pointer_type
                pointer_promoted = True
        desired_names = []
        for index in range(target_arg_count):
            if index < len(resolved_names) and isinstance(resolved_names[index], str) and resolved_names[index]:
                desired_names.append(resolved_names[index])
            elif index < len(resolved_args):
                desired_names.append(
                    getattr(getattr(resolved_args[index], "unified_variable", None), "name", None)
                    or resolved_args[index].name
                )
            elif index < len(getattr(current_proto, "arg_names", ()) or ()):
                desired_names.append(current_proto.arg_names[index])
            else:
                desired_names.append(None)
        normalized_names = _normalize_arg_names_8616(desired_names, target_arg_count)
        if (
            len(existing_args) == target_arg_count
            and len(getattr(current_proto, "args", ()) or ()) == target_arg_count
            and list(getattr(current_proto, "arg_names", ()) or ()) == normalized_names
            and all(existing is resolved for existing, resolved in zip(existing_args, resolved_args, strict=False))
            and not pointer_promoted
            and not scalar_materialized
            and not name_changed
        ):
            return False
        new_proto = current_proto.__class__(
            new_args,
            current_proto.returnty,
            arg_names=normalized_names,
            variadic=getattr(current_proto, "variadic", False),
        )
        arch = getattr(getattr(codegen, "project", None), "arch", None)
        if arch is not None and hasattr(new_proto, "with_arch"):
            new_proto = new_proto.with_arch(arch)
        cast(Any, func).prototype = new_proto
        _set_codegen_prototype_8616(codegen, new_proto)
        codegen.cfunc.arg_list = resolved_args
        scalar_materialized = (
            _prune_unused_stack_slots_covered_by_annotation_args_8616(
                codegen=codegen,
                arg_offsets=arg_offsets_set,
                arg_widths=inferred_arg_widths,
            )
            or scalar_materialized
        )
        with contextlib.suppress(Exception):
            codegen._inertia_codegen_decl_refresh_required_8616 = True
        return True

    return _impl()


def _annotation_arg_widths_from_stack_layout_8616(
    *,
    arg_offsets: list[int],
    known_positive_stack_offsets: set[int],
) -> dict[int, int]:
    """Infer annotation argument byte widths from neighboring stack slots."""
    widths: dict[int, int] = {}
    for index, offset in enumerate(arg_offsets):
        width = 2
        if index + 1 < len(arg_offsets):
            next_offset = arg_offsets[index + 1]
            if next_offset > offset:
                width = max(2, min(4, next_offset - offset))
        elif offset + 2 in known_positive_stack_offsets:
            width = 4
        widths[offset] = width
    return widths


def _prune_unused_stack_slots_covered_by_annotation_args_8616(
    *,
    codegen: object,
    arg_offsets: set[int],
    arg_widths: Mapping[int, int],
) -> bool:
    """Remove declaration-only high-word stack slots covered by wider arguments."""
    # Dynamic angr/codegen compatibility boundary.
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    covered_offsets = {
        covered
        for base_offset, width in arg_widths.items()
        if width > 2
        for covered in range(base_offset + 2, base_offset + width, 2)
        if covered not in arg_offsets
    }
    if not covered_offsets:
        return False
    body_variable_ids = {
        id(variable)
        # Dynamic angr/codegen compatibility boundary.
        for node in _iter_c_nodes_deep_8616(getattr(cfunc, "statements", None))
        if isinstance(node, CVariable)
        # Dynamic angr/codegen compatibility boundary.
        for variable in (getattr(node, "variable", None),)
        if isinstance(variable, SimStackVariable)
    }
    changed = False
    # Dynamic angr/codegen compatibility boundary.
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable, cvar in tuple(variables_in_use.items()):
            if not isinstance(variable, SimStackVariable):
                continue
            if id(variable) in body_variable_ids:
                continue
            identity = _machine_bp_stack_binding_identity_8616(
                codegen,
                variable,
                cvar,
            )
            if identity is not None and identity.offset in covered_offsets:
                del variables_in_use[variable]
                changed = True
    # Dynamic angr/codegen compatibility boundary.
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        for variable in tuple(unified):
            if not isinstance(variable, SimStackVariable):
                continue
            if id(variable) in body_variable_ids:
                continue
            identity = machine_bp_stack_identity_8616(codegen, variable)
            if identity is not None and identity.offset in covered_offsets:
                del unified[variable]
                changed = True
    return changed


def _apply_annotation_rewrites_8616(
    *,
    project: Any,
    codegen: Any,
    stack_vars_by_offset: dict[int, CVariable],
    global_spec_for: Callable[[int], tuple[str | None, object | None]],
    resolve_stack_cvar: Callable[[int], object | None],
    materialize_stack_cvar: Callable[[int, object | None], object | None],
    stack_candidate_score: Callable[..., tuple[int, int, int, int, int]],
) -> bool:
    def _impl() -> bool:
        changed = False
        preferred_stack_cvars_by_identity: dict[object, CVariable] = {}
        for cvar in getattr(codegen.cfunc, "arg_list", ()) or ():
            if not isinstance(cvar, CVariable):
                continue
            variable = cvar.variable
            if not isinstance(variable, SimStackVariable):
                continue
            identity = machine_bp_stack_identity_8616(codegen, variable)
            if identity is not None:
                preferred_stack_cvars_by_identity[identity] = cvar
        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _machine_bp_stack_binding_identity_8616(
                codegen,
                variable,
                cvar,
            )
            if identity is None:
                continue
            current_best = preferred_stack_cvars_by_identity.get(identity)
            if current_best is None:
                preferred_stack_cvars_by_identity[identity] = cvar
                continue
            current_best_var = getattr(current_best, "variable", None)
            if not isinstance(current_best_var, SimStackVariable):
                preferred_stack_cvars_by_identity[identity] = cvar
                continue
            current_score = stack_candidate_score(current_best_var, current_best, exact=True)
            new_score = stack_candidate_score(variable, cvar, exact=True)
            if new_score > current_score:
                preferred_stack_cvars_by_identity[identity] = cvar

        def transform_stack_aliases(node: object) -> object:
            if not isinstance(node, CVariable):
                return node
            variable = node.variable
            if not isinstance(variable, SimStackVariable):
                return node
            identity = machine_bp_stack_identity_8616(codegen, variable)
            if identity is None:
                return node
            preferred = preferred_stack_cvars_by_identity.get(identity)
            if preferred is None or preferred is node:
                return node
            return preferred

        if _replace_c_children_8616(codegen.cfunc.statements, transform_stack_aliases):
            changed = True

        for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
            if not isinstance(variable, SimMemoryVariable):
                continue
            variable_addr = variable.addr
            if not isinstance(variable_addr, int):
                continue
            name, vartype = global_spec_for(variable_addr)
            if not isinstance(name, str):
                continue
            current = variable.name
            if current and not current.startswith(("g_", "field_")) and current != name:
                continue
            target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
            if target is not None and getattr(target, "name", None) != name:
                target.name = name
                changed = True
            if variable.name != name:
                variable.name = name
                changed = True
            if vartype is not None and getattr(cvar, "variable_type", None) != vartype:
                cast(Any, cvar).variable_type = vartype
                changed = True

        def transform_globals(node: object) -> object:
            nonlocal changed
            if not isinstance(node, CVariable):
                return node
            variable = node.variable
            if not isinstance(variable, SimMemoryVariable):
                return node
            variable_addr = variable.addr
            if not isinstance(variable_addr, int):
                return node
            name, vartype = global_spec_for(variable_addr)
            if not isinstance(name, str):
                return node
            current = variable.name
            if current and not current.startswith(("g_", "field_")) and current != name:
                return node
            if variable.name != name:
                variable.name = name
                changed = True
            return CVariable(
                variable,
                variable_type=vartype if vartype is not None else node.variable_type,
                codegen=codegen,
            )

        if _replace_c_children_8616(codegen.cfunc.statements, transform_globals):
            changed = True

        def transform(node: object) -> object:
            if not _structured_codegen_node_8616(node):
                return node
            direct_offset = _match_bp_stack_load_8616(node, project)
            if direct_offset is not None:
                type_ = getattr(node, "type", None)
                stack_cvar = resolve_stack_cvar(direct_offset) or materialize_stack_cvar(direct_offset, type_)
                if stack_cvar is not None:
                    return stack_cvar
            if isinstance(node, CBinaryOp) and node.op in {"Or", "Add"}:
                for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                    low_offset = _match_bp_stack_load_8616(low_expr, project)
                    if low_offset is None:
                        continue
                    high_offset = _match_bp_stack_load_8616(high_expr, project)
                    if not isinstance(high_offset, int):
                        continue
                    if high_offset != low_offset + 1:
                        continue
                    low_cvar = stack_vars_by_offset.get(low_offset)
                    high_cvar = stack_vars_by_offset.get(high_offset)
                    if low_cvar is not None and high_cvar is not None:
                        low_var = getattr(low_cvar, "variable", None)
                        high_var = getattr(high_cvar, "variable", None)
                        if isinstance(low_var, SimStackVariable) and isinstance(high_var, SimStackVariable):  # noqa: SIM102
                            if not _stack_slot_identity_can_join(low_var, high_var):
                                continue
                    if low_cvar is not None:
                        return low_cvar
            return node

        if _replace_c_children_8616(codegen.cfunc.statements, transform):
            changed = True
        return changed

    return _impl()


def _apply_helper_signature_annotation_8616(
    project: Any, codegen: Any, func_addr: int, func: Any
) -> tuple[bool, object | None]:
    def _impl() -> tuple[bool, object | None]:
        nonlocal func
        changed = False
        func_name = getattr(func, "name", None)
        if isinstance(func_name, str) and func_name.startswith("_") and not func_name.startswith("__"):
            stripped_name = func_name.lstrip("_")
            if (
                isinstance(stripped_name, str)
                and stripped_name
                and preferred_known_helper_signature_decl(func_name) is not None
                and preferred_known_helper_signature_decl(stripped_name) is not None
                and getattr(func, "name", None) != stripped_name
            ):
                func.name = stripped_name
                if (
                    getattr(codegen, "cfunc", None) is not None
                    and getattr(codegen.cfunc, "name", None) != stripped_name
                ):
                    codegen.cfunc.name = stripped_name
                changed = True
                func_name = stripped_name
            stripped_decl = (
                preferred_known_helper_signature_decl(stripped_name) if isinstance(stripped_name, str) else None
            )
            if isinstance(stripped_decl, str) and stripped_decl:
                existing = tuple(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
                if stripped_decl not in existing:
                    codegen._inertia_callsite_prototype_decls = (*existing, stripped_decl)
                    changed = True
        helper_decl = preferred_known_helper_signature_decl(func_name) if isinstance(func_name, str) else None
        if helper_decl is None:
            return changed, func
        annotate_function(project, func_addr, name=func_name, c_decl=helper_decl)
        func = project.kb.functions.function(addr=func_addr, create=False)
        if func is None:
            return changed, None
        if getattr(codegen, "cfunc", None) is not None and getattr(func, "prototype", None) is not None:
            codegen.cfunc.functy = func.prototype
            prototype_arg_names = tuple(getattr(func.prototype, "arg_names", ()) or ())
            for index, cvar in enumerate(getattr(codegen.cfunc, "arg_list", ()) or ()):
                if index >= len(prototype_arg_names):
                    break
                arg_name = prototype_arg_names[index]
                if not isinstance(arg_name, str) or not arg_name:
                    continue
                variable = getattr(cvar, "variable", None)
                unified = getattr(cvar, "unified_variable", None)
                if variable is not None and getattr(variable, "name", None) != arg_name:
                    variable.name = arg_name
                if unified is not None and getattr(unified, "name", None) != arg_name:
                    unified.name = arg_name
                if getattr(cvar, "name", None) != arg_name:
                    cvar.name = arg_name
        return True, func

    return _impl()


def _prune_unused_unnamed_memory_declarations_8616(codegen: Any) -> bool:
    def _impl() -> bool:
        if getattr(codegen, "cfunc", None) is None:
            return False

        used_variables: set[int] = set()
        for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
            if not isinstance(node, CVariable):
                continue
            variable = node.variable
            if variable is not None:
                used_variables.add(id(variable))
            unified = node.unified_variable
            if unified is not None:
                used_variables.add(id(unified))

        changed = False
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable in list(variables_in_use):
                if not isinstance(variable, SimMemoryVariable):
                    continue
                name = variable.name
                if not isinstance(name, str) or not name.startswith("g_"):
                    continue
                if id(variable) in used_variables:
                    continue
                cvar = variables_in_use[variable]
                unified = getattr(cvar, "unified_variable", None)
                if unified is not None and id(unified) in used_variables:
                    continue
                del variables_in_use[variable]
                changed = True

        return changed

    return _impl()


def _prune_unused_flag_assignments_8616(project: Any, codegen: Any) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    used_registers: set[int] = set()
    used_variables: set[int] = set()

    def collect_reads(node: object, *, assignment_lhs: bool = False) -> None:
        if not _structured_codegen_node_8616(node):
            return
        if isinstance(node, CVariable) and not assignment_lhs:
            variable = node.variable
            if variable is not None:
                used_variables.add(id(variable))
                if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) is not None:
                    used_registers.add(variable.reg)
            unified = node.unified_variable
            if unified is not None:
                used_variables.add(id(unified))
                if isinstance(unified, SimRegisterVariable) and getattr(unified, "reg", None) is not None:
                    used_registers.add(unified.reg)
            return

        for attr in (
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "body",
            "iffalse",
            "iftrue",
            "callee_target",
            "else_node",
            "retval",
        ):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                collect_reads(child)
        lhs = getattr(node, "lhs", None)
        if _structured_codegen_node_8616(lhs):
            collect_reads(lhs, assignment_lhs=isinstance(node, CAssignment))
        for attr in ("args", "operands", "statements"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    collect_reads(item)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            collect_reads(subitem)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    collect_reads(cond)
                if _structured_codegen_node_8616(body):
                    collect_reads(body)

    collect_reads(codegen.cfunc.statements)

    changed = False

    def visit(node: object) -> None:
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            for stmt in node.statements:
                visit(stmt)
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if (
                        isinstance(variable, SimRegisterVariable)
                        and getattr(variable, "reg", None) == flags_offset
                        and id(variable) not in used_variables
                        and getattr(variable, "reg", None) not in used_registers
                    ):
                        changed = True
                        continue
                new_statements.append(stmt)
            node.statements = new_statements

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed


def _c_expr_uses_register_8616(node: object, reg_offset: int) -> bool:
    def _impl() -> bool:
        if not _structured_codegen_node_8616(node):
            return False
        if isinstance(node, CVariable):
            variable = node.variable
            return isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == reg_offset

        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "body",
            "iftrue",
            "iffalse",
            "callee_target",
            "else_node",
            "retval",
        ):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child) and _c_expr_uses_register_8616(child, reg_offset):
                return True

        for attr in ("args", "operands", "statements"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item) and _c_expr_uses_register_8616(item, reg_offset):
                    return True
                if isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem) and _c_expr_uses_register_8616(subitem, reg_offset):
                            return True

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
                    return True
                if _structured_codegen_node_8616(body) and _c_expr_uses_register_8616(body, reg_offset):
                    return True

        return False

    return _impl()


def _stmt_reads_reg_before_write_8616(stmt: object, reg_offset: int) -> tuple[bool, bool]:
    def _impl() -> tuple[bool, bool]:
        if not _structured_codegen_node_8616(stmt):
            return False, False

        if isinstance(stmt, CAssignment):
            lhs = stmt.lhs
            writes = (
                isinstance(lhs, CVariable)
                and isinstance(getattr(lhs, "variable", None), SimRegisterVariable)
                and getattr(lhs.variable, "reg", None) == reg_offset
            )
            reads = _c_expr_uses_register_8616(stmt.rhs, reg_offset)
            return reads, writes

        if isinstance(stmt, CStatements):
            for substmt in stmt.statements:
                reads, writes = _stmt_reads_reg_before_write_8616(substmt, reg_offset)
                if reads:
                    return True, writes
                if writes:
                    return False, True
            return False, False

        if type(stmt).__name__ == "CIfElse":
            cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
            for cond, body in cond_nodes:
                if _c_expr_uses_register_8616(cond, reg_offset):
                    return True, False
                reads, writes = _stmt_reads_reg_before_write_8616(body, reg_offset)
                if reads:
                    return True, writes
            else_node = getattr(stmt, "else_node", None)
            if else_node is not None:
                reads, writes = _stmt_reads_reg_before_write_8616(else_node, reg_offset)
                if reads:
                    return True, writes
            return False, False

        if type(stmt).__name__ == "CWhileLoop":
            cond = getattr(stmt, "condition", None)
            if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
                return True, False
            body = getattr(stmt, "body", None)
            if body is not None:
                return _stmt_reads_reg_before_write_8616(body, reg_offset)
            return False, False

        return _c_expr_uses_register_8616(stmt, reg_offset), False

    return _impl()


def _prune_overwritten_flag_assignments_8616(project: Any, codegen: Any) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    changed = False

    def visit(node: object) -> None:
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            statements = list(node.statements)
            for idx, stmt in enumerate(statements):
                remove = False
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == flags_offset:
                        remainder = CStatements(statements[idx + 1 :], codegen=codegen)
                        reads, _writes = _stmt_reads_reg_before_write_8616(remainder, flags_offset)
                        if not reads:
                            remove = True
                if not remove:
                    new_statements.append(stmt)
                    visit(stmt)
                else:
                    changed = True
            node.statements = new_statements
            return

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed

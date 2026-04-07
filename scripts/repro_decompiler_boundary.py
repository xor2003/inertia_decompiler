#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from inertia_decompiler import cli
from inertia_decompiler.project_loading import _build_project, _is_blob_only_input

UPSTREAM_DECOMPILER_PATH = (
    "/home/xor/vextest/.venv/lib/python3.14/site-packages/angr/analyses/decompiler/decompiler.py:293-443"
)


def _format_variables(variable_manager) -> list[str]:
    try:
        variables = list(variable_manager.get_variables())
    except Exception as ex:  # noqa: BLE001
        return [f"variable_manager.get_variables failed: {type(ex).__name__}: {ex}"]
    if not variables:
        return ["(none)"]

    def _sort_key(variable: object) -> tuple[int, int, str]:
        offset = getattr(variable, "offset", None)
        sortable_offset = offset if isinstance(offset, int) else 1 << 30
        return (
            sortable_offset,
            getattr(variable, "size", -1) if isinstance(getattr(variable, "size", None), int) else -1,
            type(variable).__name__,
        )

    rendered: list[str] = []
    for variable in sorted(variables, key=_sort_key):
        rendered.append(
            f"{type(variable).__name__} offset={getattr(variable, 'offset', None)!r} "
            f"size={getattr(variable, 'size', None)!r} "
            f"base={getattr(variable, 'base', None)!r} "
            f"name={getattr(variable, 'name', None)!r} "
            f"id={id(variable)}"
        )
    return rendered


def _stack_variables_by_offset(variable_manager) -> dict[int, object]:
    by_offset: dict[int, object] = {}
    for variable in variable_manager.get_variables():
        offset = getattr(variable, "offset", None)
        if isinstance(offset, int):
            by_offset[offset] = variable
    return by_offset


def _probe_decompiler(project, function, decompiler_options, *, generate_code: bool, regen_clinic: bool | None = None):
    with cli._guard_angr_peephole_expr_bitwidth_assertion():
        with cli._guard_angr_variable_recovery_binop_sub_size_mismatch():
            kwargs = {"cfg": None, "options": decompiler_options, "generate_code": generate_code}
            if regen_clinic is not None:
                kwargs["regen_clinic"] = regen_clinic
            return project.analyses.Decompiler(function, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproduce clinic/decompiler boundary state for one function.")
    parser.add_argument("binary", type=Path)
    parser.add_argument("--addr", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--window", type=lambda value: int(value, 0), default=0x80)
    parser.add_argument("--base-addr", type=lambda value: int(value, 0), default=0x1000)
    parser.add_argument("--entry-point", type=lambda value: int(value, 0), default=0x100)
    args = parser.parse_args()

    project = _build_project(
        args.binary,
        force_blob=_is_blob_only_input(args.binary),
        base_addr=args.base_addr,
        entry_point=args.entry_point,
    )
    region = cli._infer_x86_16_linear_region(project, args.addr, window=args.window)
    cfg, function = cli._pick_function(project, args.addr, regions=[region], data_references=True)
    cli._prepare_function_for_decompilation(project, function)

    print(f"binary={args.binary}")
    print(f"function={function.addr:#x} {function.name}")
    print(f"region={region[0]:#x}-{region[1]:#x}")

    try:
        project.analyses.Clinic(function)
    except Exception as ex:  # noqa: BLE001
        print(f"clinic_without_guards=error {type(ex).__name__}: {ex}")
    else:
        print("clinic_without_guards=ok")

    block_count, byte_count = cli._function_complexity(function)
    profile = cli._function_decompilation_profile(function, block_count, byte_count)
    decompiler_options = cli._preferred_decompiler_options(
        block_count,
        byte_count,
        wrapper_like=bool(profile.get("wrapper_like")),
        tiny_single_call_helper=bool(profile.get("tiny_single_call_helper")),
    )

    dec_generate_code_false = _probe_decompiler(project, function, decompiler_options, generate_code=False)
    dec_regen_clinic_false = _probe_decompiler(
        project,
        function,
        decompiler_options,
        generate_code=True,
        regen_clinic=False,
    )

    clinic_a = dec_generate_code_false.clinic
    clinic_b = dec_regen_clinic_false.clinic
    manager_a = clinic_a.variable_kb.variables.get_function_manager(function.addr) if clinic_a is not None else None
    manager_b = clinic_b.variable_kb.variables.get_function_manager(function.addr) if clinic_b is not None else None
    variables_a = _stack_variables_by_offset(manager_a) if manager_a is not None else {}
    variables_b = _stack_variables_by_offset(manager_b) if manager_b is not None else {}

    print(f"decompiler_generate_code_false.codegen_present={dec_generate_code_false.codegen is not None}")
    print(f"decompiler_generate_code_false.clinic_present={clinic_a is not None}")
    print(f"decompiler_regen_clinic_false.codegen_present={dec_regen_clinic_false.codegen is not None}")
    print(f"decompiler_regen_clinic_false.clinic_present={clinic_b is not None}")
    print(f"upstream_hook_path={UPSTREAM_DECOMPILER_PATH}")
    print("upstream_hook_note=no caller-visible callback exists between Clinic(...) and StructuredCodeGenerator(...)")
    print("cache_hook_note=Decompiler(generate_code=False) followed by Decompiler(regen_clinic=False) reuses the cached clinic")
    print(f"clinic_object_id.generate_code_false={id(clinic_a) if clinic_a is not None else None}")
    print(f"clinic_object_id.regen_clinic_false={id(clinic_b) if clinic_b is not None else None}")
    print(f"variable_manager_id.generate_code_false={id(manager_a) if manager_a is not None else None}")
    print(f"variable_manager_id.regen_clinic_false={id(manager_b) if manager_b is not None else None}")
    print(f"same_clinic_object={clinic_a is clinic_b}")
    print(f"same_variable_manager_object={manager_a is manager_b}")
    print("cached_clinic.generate_code_false.variables:")
    for line in _format_variables(manager_a):
        print(f"  {line}")
    print("cached_clinic.regen_clinic_false.variables:")
    for line in _format_variables(manager_b):
        print(f"  {line}")
    for offset in sorted(set(variables_a) | set(variables_b)):
        left = variables_a.get(offset)
        right = variables_b.get(offset)
        print(
            "stack_object_offset="
            f"{offset:+#x} "
            f"generate_code_false=size={getattr(left, 'size', None)!r} id={id(left) if left is not None else None} "
            f"regen_clinic_false=size={getattr(right, 'size', None)!r} id={id(right) if right is not None else None} "
            f"same_object={left is right and left is not None}"
        )
    print(
        "stack_object_0x1157c_preserved="
        f"{(variables_a.get(-2) is not None and variables_b.get(-2) is not None and variables_a.get(-2) is variables_b.get(-2))}"
    )
    print(
        "stack_object_0x1157c_widened="
        f"{(getattr(variables_b.get(-2), 'size', None) or 0) > (getattr(variables_a.get(-2), 'size', None) or 0)}"
    )
    codegen_text = dec_regen_clinic_false.codegen.text if dec_regen_clinic_false.codegen is not None else ""
    duplicate_call_count = codegen_text.count("sub_15d8(); /* do not return */")
    print(f"codegen_sub_15d8_call_count={duplicate_call_count}")
    print(f"codegen_keeps_ss_store_sequence={'+ (unsigned int)(&s_' in codegen_text}")
    boundary_fixpoint = "stable_pre_codegen_stack_object_widened"
    boundary_status = "stable_pre_codegen_stack_object_widened"
    if manager_b is not None and getattr(variables_b.get(-2), "size", None) == 1:
        boundary_fixpoint = "upstream_angr_cached_clinic_reuse_before_codegen"
        boundary_status = "blocked_pre_codegen_stack_object_remains_narrow"
    print(f"boundary_fixpoint={boundary_fixpoint}")
    print(f"boundary_status={boundary_status}")

    if dec_regen_clinic_false.codegen is not None:
        print("-- codegen --")
        print(dec_regen_clinic_false.codegen.text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

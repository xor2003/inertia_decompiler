from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c


def _simplify_nested_mk_fp_calls(
    codegen,
    *,
    unwrap_c_casts,
    c_constant_value,
    replace_c_children,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def _is_zero_offset_mk_fp(expr) -> bool:
        expr = unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CFunctionCall) or getattr(expr, "callee_target", None) != "MK_FP":
            return False
        args = list(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return False
        return c_constant_value(unwrap_c_casts(args[1])) == 0

    def transform(node):
        nonlocal changed
        if not isinstance(node, structured_c.CFunctionCall) or getattr(node, "callee_target", None) != "MK_FP":
            return node
        args = list(getattr(node, "args", ()) or ())
        if len(args) != 2:
            return node

        seg_expr = unwrap_c_casts(args[0])
        off_expr = unwrap_c_casts(args[1])
        if isinstance(seg_expr, structured_c.CFunctionCall) and getattr(seg_expr, "callee_target", None) == "MK_FP":
            inner_args = list(getattr(seg_expr, "args", ()) or ())
            if len(inner_args) == 2 and _is_zero_offset_mk_fp(off_expr):
                changed = True
                return structured_c.CFunctionCall(
                    "MK_FP",
                    None,
                    [unwrap_c_casts(inner_args[0]), unwrap_c_casts(inner_args[1])],
                    codegen=codegen,
                )
        if _is_zero_offset_mk_fp(off_expr):
            inner_args = list(getattr(off_expr, "args", ()) or ())
            if len(inner_args) == 2:
                changed = True
                return structured_c.CFunctionCall(
                    "MK_FP",
                    None,
                    [seg_expr, unwrap_c_casts(inner_args[0])],
                    codegen=codegen,
                )

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True

    return changed

"""Syntactic load matchers for legacy postprocess consumers.

Layer: Rewrite/Postprocess cleanup.
Responsibility: owns cleanup-only load shape queries over existing C AST nodes.

This module identifies rendered C shapes for global and segmented loads so late
cleanup passes can consume them. It is a temporary compatibility layer, not an
owner of memory semantics.

Allowed work here is limited to shape queries over existing C AST nodes. The
actual proof of a load's Address(space, offset, width) belongs in alias,
segmented memory lowering, object/global recovery, and typed lowering before
structuring.

Do not add new memory recovery, segment flattening, or byte/word inference here.
If a caller needs stronger facts, move that proof to the memory/lowering layer
and make this module unnecessary for that case.

Package ownership contract (canonical inertia/postprocess package):
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from
rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CTypeCast

from inertia.postprocess.decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _global_memory_addr_8616,
    _match_segmented_dereference_8616,
)

__all__ = [
    "_global_load_addr_8616",
    "_match_global_scaled_high_byte_8616",
    "_segmented_load_addr_8616",
]


def _global_load_addr_8616(node: object) -> int | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    return _global_memory_addr_8616(node)


def _segmented_load_addr_8616(node: object, project: object) -> tuple[str | None, int | None]:
    while isinstance(node, CTypeCast):
        node = node.expr
    seg_name, linear = _match_segmented_dereference_8616(node, project)
    if seg_name is None or not isinstance(linear, int):
        return None, None
    return seg_name, linear


def _match_global_scaled_high_byte_8616(node: object) -> int | None:
    if not isinstance(node, CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value_8616(maybe_scale) != 0x100:
                continue
            addr = _global_load_addr_8616(maybe_load)
            if addr is not None:
                return addr

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value_8616(maybe_scale) != 8:
                continue
            addr = _global_load_addr_8616(maybe_load)
            if addr is not None:
                return addr

    return None

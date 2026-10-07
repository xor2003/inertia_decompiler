"""Preserve exact callsite segment-address provenance on generated C nodes.

Layer: Types/Lowering.
Responsibility: carry typed callsite PUSH instruction addresses onto segmented
address helpers so local segment policy can consume exact IR state.
Consumes alias, widening, and typed facts by preserving an existing callsite
summary contract at the C-AST boundary.
Do not recover semantics from COD, source, assembly, or rendered C text.
This module transports existing evidence only; it does not infer argument
values, segment identity, object layout, or call signatures.
"""

from __future__ import annotations

from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

_SOURCE_ADDRS_TAG = "inertia_source_instruction_addrs"


class _TaggedAstNode8616(Protocol):
    """Dynamic angr C node surface carrying mutable provenance tags."""

    tags: dict[str, object]


def attach_callsite_segment_address_provenance_8616(
    args: tuple[object, ...],
    instruction_addrs: tuple[int, ...],
) -> None:
    """Attach exact PUSH sites to segmented address helpers in call arguments."""
    exact_addrs = tuple(sorted({addr for addr in instruction_addrs if isinstance(addr, int)}))
    if not exact_addrs:
        return
    seen: set[int] = set()
    for arg in args:
        for candidate in (arg, *_iter_c_nodes_deep_8616(arg)):
            if id(candidate) in seen or not isinstance(candidate, CFunctionCall):
                continue
            seen.add(id(candidate))
            if candidate.callee_target not in {"SEG_PTR", "MK_FP"}:
                continue
            boundary = cast(_TaggedAstNode8616, cast(Any, candidate))
            try:
                current_tags = boundary.tags
            except AttributeError:
                current_tags = {}
            tags = dict(current_tags) if isinstance(current_tags, dict) else {}
            prior = tags.get(_SOURCE_ADDRS_TAG, ())
            prior_addrs = tuple(addr for addr in prior if isinstance(addr, int)) if isinstance(prior, tuple) else ()
            tags[_SOURCE_ADDRS_TAG] = tuple(sorted({*prior_addrs, *exact_addrs}))
            boundary.tags = tags

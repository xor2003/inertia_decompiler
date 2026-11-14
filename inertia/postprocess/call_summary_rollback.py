# cython: language_level=3, infer_types=True
"""Layer: Rewrite/Postprocess.

Responsibility: transport call occurrence identities through exact rollback clones.
This transports existing evidence; it never discovers a target or matches names.
Layer: Rewrite/Postprocess cleanup
Consumes already-proven IR, alias, widening, typed, and structuring facts
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CStatements

from inertia.semantics.callsite_summary import CallsiteSummary8616
import dataclasses

_MARKER = "_rollback_call_binding_8616"
_RETAINED = "__rollback_call_binding_8616"


@dataclasses.dataclass(frozen=True)
class CallCloneBinding8616:
    """Exact original-to-clone occurrences retained by one rollback snapshot."""

    root: CStatements
    pairs: object


def retain_call_clone_binding_8616(
    root: object, originals: object, memo: object,
    live: object,
) -> None:
    """Attach temporary provenance to a detached rollback root only."""
    if not isinstance(root, CStatements):
        return
    live_ids = {id(call) for call in iter(live)}
    pairs = tuple((call, clone) for call in iter(originals)
                  if isinstance(clone := memo.get(id(call), call), CFunctionCall)
                  and id(clone) in live_ids)
    root.tags = dict(root.tags or {})
    root.tags[_MARKER] = CallCloneBinding8616(root, pairs)


@cython.ccall
def take_call_clone_binding_8616(codegen: object, root: object) -> None:
    """Remove temporary provenance before the restored AST becomes live."""
    binding: object
    # Dynamic angr codegen boundary; this field is not semantic Inertia metadata.
    vars(codegen).pop(_MARKER, None)
    if isinstance(root, CStatements):
        binding = root.tags.pop(_MARKER, None)
        if isinstance(binding, CallCloneBinding8616) and binding.root is root:
            vars(codegen)[_MARKER] = binding


@cython.ccall
def restore_call_clone_binding_8616(
    codegen: object, snapshot: object, root: object,
    live: object,
) -> None:
    """Rekey only memo-proven surviving occurrences, including repeated restores."""
    binding: object
    pending: object
    summaries: object
    # Dynamic angr codegen boundary. Retention belongs to this metadata snapshot.
    pending = vars(codegen).pop(_MARKER, None)
    if isinstance(pending, CallCloneBinding8616) and pending.root is root:
        snapshot[_RETAINED] = pending
    binding = snapshot.get(_RETAINED)
    if not isinstance(binding, CallCloneBinding8616) or binding.root is not root:
        return
    summaries = vars(codegen).get("_inertia_callsite_summaries")
    if not isinstance(summaries, dict):
        return
    live_ids = {id(call) for call in iter(live)}
    vars(codegen)["_inertia_callsite_summaries"] = {
        id(clone): summary for original, clone in iter(binding.pairs)
        if id(clone) in live_ids
        and isinstance(summary := summaries.get(id(original)), CallsiteSummary8616)
    }


@cython.ccall
def is_call_clone_snapshot_key_8616(name: object) -> cython.bint:
    """Keep rollback-only retained provenance out of restored codegen metadata."""
    return name == _RETAINED

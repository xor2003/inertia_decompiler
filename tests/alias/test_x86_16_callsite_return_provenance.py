from __future__ import annotations

from types import SimpleNamespace

from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction
from inertia.semantics.callsite_summary import _caller_has_explicit_void_return_8616


def _void_function(source: PrototypeSource | None) -> SimpleNamespace:
    """Build one caller with a void prototype at an optional provenance level."""
    fields: dict[str, object] = {
        "prototype": SimTypeFunction([], SimTypeBottom(label="void")),
    }
    if source is not None:
        fields["prototype_source"] = source
    return SimpleNamespace(**fields)


def test_callsite_accepts_legacy_void_without_provenance_as_explicit() -> None:
    assert _caller_has_explicit_void_return_8616(_void_function(None))


def test_callsite_accepts_signature_void_as_explicit() -> None:
    assert _caller_has_explicit_void_return_8616(
        _void_function(PrototypeSource.SIGNATURES)
    )


def test_callsite_rejects_inferred_void_as_machine_evidence_override() -> None:
    assert not _caller_has_explicit_void_return_8616(
        _void_function(PrototypeSource.CCA_DECOMPILER)
    )

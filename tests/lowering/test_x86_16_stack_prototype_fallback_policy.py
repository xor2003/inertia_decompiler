"""Tests for typed stack-prototype fallback orchestration.

Layer: Tests.
Responsibility: prove callers can avoid duplicate positive-BP materialization.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import inertia.lowering.positive_bp_arguments as positive_bp_arguments
from inertia.lowering.stack_prototype_materialization import (
    materialize_annotated_stack_prototype_8616,
)


def test_positive_bp_fallback_can_be_suppressed_without_changing_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def materialize(_project: object, _codegen: object) -> bool:
        nonlocal calls
        calls += 1
        return True

    monkeypatch.setattr(
        positive_bp_arguments,
        "materialize_positive_bp_arguments_8616",
        materialize,
    )
    function = SimpleNamespace(info={})
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function),
        ),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    assert not materialize_annotated_stack_prototype_8616(
        project,
        codegen,
        fallback_to_positive_bp=False,
    )
    assert calls == 0
    assert materialize_annotated_stack_prototype_8616(project, codegen)
    assert calls == 1

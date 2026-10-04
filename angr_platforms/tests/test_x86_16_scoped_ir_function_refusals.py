"""Parent controls for function-only refusal retention in scoped coverage.

Layer: tests.
Responsibility: reuse the labeled synthetic domain/native seam and reject
unrelated function-level refusals even when the block projection closes.
"""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
import test_x86_16_scoped_ir_coverage as fixture
from angr_platforms.X86_16.ir.core import IRRefusal
from test_x86_16_scoped_ir_coverage import world  # noqa: F401


@pytest.mark.parametrize('native_only', [False, True])
def test_function_only_refusal_cannot_disappear(
    world: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, native_only: bool,  # noqa: F811
) -> None:
    """Reject an unrelated refusal on retained or freshly imported evidence."""
    refusal = IRRefusal('unmodeled_function_effect', 'not a discharged jump', fixture.FUNC)
    if native_only:
        fixture._native_seam(monkeypatch, lambda: replace(world.source, refusals=(refusal,)))
    else:
        # Corrupt the frozen retained artifact in place so all independently
        # held source identities remain equal; identity alone must not pass.
        object.__setattr__(world.source, 'refusals', (refusal,))
    result = fixture._coverage(world.project, world.boundary, world.source, world.view)
    assert not result.complete_for(world.scope)


def test_mirrored_discharged_refusal_remains_eligible(world: SimpleNamespace) -> None:  # noqa: F811
    """An importer may mirror its block refusal in the function ledger."""
    object.__setattr__(world.source, 'refusals', tuple(
        refusal for block in world.source.blocks for refusal in block.refusals
    ))
    result = fixture._coverage(world.project, world.boundary, world.source, world.view)
    assert result.complete_for(world.scope)

from __future__ import annotations

from dataclasses import replace

import inertia.semantics.callsite_summary as callsite_summary
import inertia.lowering.direct_stack_replay as replay_generation
from inertia.pipeline.structured_ast_generation import (
    StructuredAstGeneration8616,
)


def _summary() -> callsite_summary.CallsiteSummary8616:
    """Return one complete direct-stack callsite fixture."""
    return callsite_summary.CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=0x2000,
        return_addr=0x1013,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        push_arg_instruction_addrs=(0x100E,),
        stack_cleanup_instruction_addr=0x1013,
    )


def test_direct_stack_generation_ignores_summary_identity_and_return_use(
    monkeypatch,
) -> None:
    """Value-equivalent summaries and unrelated return facts keep one generation."""
    inventory = {0x1010: _summary()}
    ast = StructuredAstGeneration8616("stable", 1)
    monkeypatch.setattr(
        replay_generation,
        "callsite_summary_inventory_8616",
        lambda _codegen: inventory,
    )
    monkeypatch.setattr(
        replay_generation,
        "structured_ast_generation_8616",
        lambda _codegen: ast,
    )

    first = replay_generation.direct_stack_replay_generation_8616(object(), None)
    inventory[0x1010] = replace(
        inventory[0x1010],
        return_register=None,
        return_used=False,
        return_use_kind=None,
    )
    second = replay_generation.direct_stack_replay_generation_8616(object(), None)

    assert first == second


def test_direct_stack_generation_tracks_consumed_cleanup_and_push_facts(
    monkeypatch,
) -> None:
    """Changing an exact direct-stack input invalidates the generation."""
    inventory = {0x1010: _summary()}
    ast = StructuredAstGeneration8616("stable", 1)
    monkeypatch.setattr(
        replay_generation,
        "callsite_summary_inventory_8616",
        lambda _codegen: inventory,
    )
    monkeypatch.setattr(
        replay_generation,
        "structured_ast_generation_8616",
        lambda _codegen: ast,
    )

    first = replay_generation.direct_stack_replay_generation_8616(object(), None)
    inventory[0x1010] = replace(
        inventory[0x1010],
        push_arg_instruction_addrs=(0x100C,),
        stack_cleanup_instruction_addr=0x1015,
    )
    second = replay_generation.direct_stack_replay_generation_8616(object(), None)

    assert first != second

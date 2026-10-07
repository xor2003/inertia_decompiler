from __future__ import annotations

import inertia.lowering.return_liveness_replay as return_liveness_replay
from inertia.lowering.register_local_declarations import (
    RegisterLocalDeclarationResult8616,
)


def test_return_liveness_replay_runs_only_bounded_consumers(monkeypatch) -> None:
    """Prune dead carriers before republishing surviving register locals."""
    codegen = object()
    events: list[str] = []
    declarations = RegisterLocalDeclarationResult8616(changed_count=1)
    monkeypatch.setattr(
        return_liveness_replay,
        "prune_unread_stack_lowered_register_carriers_8616",
        lambda observed: events.append("carrier-prune") or observed is codegen,
    )
    monkeypatch.setattr(
        return_liveness_replay,
        "materialize_typed_register_locals_8616",
        lambda observed: events.append("register-locals") or declarations,
    )

    result = return_liveness_replay.replay_return_liveness_lowering_8616(codegen)

    assert events == ["carrier-prune", "register-locals"]
    assert result.carrier_prune_changed
    assert result.register_locals is declarations
    assert result.changed

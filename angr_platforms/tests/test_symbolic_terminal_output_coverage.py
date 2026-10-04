"""Partial solver output coverage cannot establish a terminal comparison."""

from typing import Any

import pytest
from test_symbolic_terminal import compare_pe, exit_code

from tools.dosunit import symbolic_terminal as ST


@pytest.mark.parametrize('projection', ['omitted', 'skipped', 'duplicate'])
def test_terminal_comparison_requires_every_output(
    monkeypatch: pytest.MonkeyPatch, projection: str,
) -> None:
    """Reject incomplete projection even when its retained register is equal."""
    original = ST.S._z3_output_pairs

    def partial(*args: Any, **kwargs: Any) -> Any:
        pairs, skipped = original(*args, **kwargs)
        retained = [pair for pair in pairs if pair[0] == 'ebx']
        assert len(retained) == 1
        if projection == 'duplicate':
            return retained * len(pairs), skipped
        if projection == 'skipped':
            skipped = [*skipped, {'kind': 'parent_probe', 'reg': 'terminal_payload'}]
        return retained, skipped

    monkeypatch.setattr(ST.S, '_z3_output_pairs', partial)
    result = compare_pe(exit_code(7), exit_code(9))
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    assert result.counters.failure_count > 0

"""Parent controls: invalid reads must not prove a terminal transition."""


import pytest
import tools.dosunit.tests.test_symbolic_terminal as fixtures

import tools.dosunit.compare.symbolic_terminal as terminal


@pytest.mark.parametrize("prefix", ["a100000000", "a10000000031c0"])
def test_unmapped_pe_read_cannot_prove_terminal_equivalence(prefix: str) -> None:
    """A discarded read still faults; output liveness cannot erase it."""
    binary = fixtures.pe32_bytes(fixtures.exit_code(prefix=bytes.fromhex(prefix)))
    environment = fixtures.pe_environment()
    result = terminal.compare_symbolic_terminals(binary, environment, binary, environment)
    assert result.status is terminal.TerminalComparisonStatus.REFUSED, result.detail

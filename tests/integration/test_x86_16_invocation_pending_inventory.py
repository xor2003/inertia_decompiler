"""Parent boundary-budget and late-coverage checks for pending caller evidence."""

import tests.integration.test_x86_16_invocation_inventory_budgets as fixtures


def _inventory(monkeypatch):
    return fixtures._load_inventory()


def test_later_closed_census_accounts_for_pending_head(monkeypatch):
    """A pending head covered later moves buckets without double counting."""
    inv = _inventory(monkeypatch)
    project, table, calls = fixtures._world()
    table[0x100] = (
        (fixtures._Block(0x100, [fixtures._Insn(0x100, 0x200), fixtures._Insn(0x101, 0x180)]),),
        (0x100, 0x101),
    )
    table[0x180] = (
        (fixtures._Block(0x180, [fixtures._Insn(0x180), fixtures._Insn(0x200)]),),
        (0x180, 0x200),
    )
    fixtures._install_provider(inv, table, calls)
    result = inv.build_invocation_inventory_8616(project, 0x100, direct_target_resolver=fixtures._resolver)
    assert calls == [0x100, 0x200, 0x180]
    assert result.pending_targets == ()
    assert result.stats.closed, result.stats
    assert result.ready


def test_boundary_cap_precedes_next_decode(monkeypatch):
    """Exhaustion must not request another potentially expensive closure."""
    inv = _inventory(monkeypatch)
    project, table, calls = fixtures._world()
    table[0x100] = ((fixtures._Block(0x100, [fixtures._Insn(0x100, 0x200)]),), (0x100,))
    table[0x200] = fixtures._leaf_spec(0x200)
    fixtures._install_provider(inv, table, calls)
    result = inv.build_invocation_inventory_8616(
        project, 0x100,
        budget=inv.InvocationInventoryBudget8616(max_boundaries=1),
        direct_target_resolver=fixtures._resolver,
    )
    assert result.status is inv.InvocationInventoryStatus8616.BUDGET_BOUNDARIES
    assert calls == [0x100]

"""Internal exits cannot turn a one-iteration census into a complete proof."""

import tests.ir.test_x86_16_declared_resize_boundary as native
from inertia.ir.real16_invocation_domain import Real16InvocationFailure8616


def test_repeated_write_into_fetched_code_is_not_complete() -> None:
    """REP's first store is safe, but its second overwrites the code entry."""
    caller = bytes.fromhex("b80001 8ec0 bfff00 b90200 31c0 fc f3aa e80100 c3")
    boot = native._boot(caller)
    project, _, coverage = native._world(boot, len(caller))
    premise = native._resize_premise(
        project, coverage, native.MODULE_BASE + 16, boot, (),
    )
    assert not premise.complete
    assert premise.failure in (
        Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN,
        Real16InvocationFailure8616.CODE_WRITE_VIOLATION,
    )
    assert premise.failure_count > 0
    assert premise.classified_fact_count == premise.materialized_count + premise.failure_count

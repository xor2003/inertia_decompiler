from __future__ import annotations

from inertia.frontend.x86_16.decompiler_return_compat import (
    _dynamic_int_counter_8616,
    _increment_dynamic_int_counter_8616,
)


class _SlottedAngrFunction:
    __slots__ = ("info",)

    def __init__(self) -> None:
        self.info: dict[str, object] = {}


def test_return_compat_counter_uses_info_for_slotted_angr_function() -> None:
    function = _SlottedAngrFunction()

    _increment_dynamic_int_counter_8616(function, "materialized")
    _increment_dynamic_int_counter_8616(function, "materialized")

    assert function.info == {"materialized": 2}
    assert _dynamic_int_counter_8616(function, "materialized") == 2

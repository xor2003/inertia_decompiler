from __future__ import annotations

from types import SimpleNamespace

import pytest
import inertia.alias.terminal_pointer_outputs as terminal_pointer_outputs
from inertia.semantics.callsite_summary import CallsitePushSourceKind8616
from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)

from inertia.alias.register_reaching_source import (
    RegisterReachingSourceResult8616,
    RegisterReachingSourceVerdict8616,
)
from inertia.alias.terminal_pointer_output_contracts import (
    TerminalPointerAliasFailure8616,
)
from inertia.alias.terminal_pointer_outputs import (
    classify_terminal_pointer_output_aliases_8616,
)
from inertia.semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputDisposition8616,
    TerminalPointerOutputEvidence8616,
    TerminalPointerOutputFact8616,
    TerminalPointerOutputStats8616,
    TerminalPointerStoreSite8616,
)

BP_VALUE = CallsitePushSourceKind8616.BP_VALUE.value


def _output(*sites: int) -> TerminalPointerOutputFact8616:
    base = IRValue(MemSpace.REG, name="bx", size=2, version=3)
    address = IRAddress(
        MemSpace.DS,
        base=("bx",),
        offset=1,
        size=1,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(base,),
    )
    return TerminalPointerOutputFact8616(
        address,
        base,
        TerminalPointerOutputDisposition8616.MUST_WRITE,
        tuple(TerminalPointerStoreSite8616(0x1000, index, site) for index, site in enumerate(sites)),
        (0x1000,),
        (0x1000,),
    )


def _evidence(output: TerminalPointerOutputFact8616) -> TerminalPointerOutputEvidence8616:
    return TerminalPointerOutputEvidence8616(
        0x1000,
        (output,),
        None,
        TerminalPointerOutputStats8616(1, 1, 1, 1),
    )


def _source(identity: tuple[object, ...] | None) -> RegisterReachingSourceResult8616:
    proven = identity is not None
    return RegisterReachingSourceResult8616(
        RegisterReachingSourceVerdict8616.PROVEN
        if proven
        else RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE,
        identity,
        1,
        1,
        int(proven),
        int(proven),
        int(not proven),
    )


def test_every_store_site_binds_to_one_exact_positive_bp_parameter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[int, str]] = []

    def _recover(
        function: object,
        *,
        instruction_addr: int,
        register: str,
    ) -> RegisterReachingSourceResult8616:
        assert function is not None
        seen.append((instruction_addr, register))
        return _source((BP_VALUE, 6, 2))

    monkeypatch.setattr(
        terminal_pointer_outputs,
        "recover_register_source_before_instruction_8616",
        _recover,
    )

    result = classify_terminal_pointer_output_aliases_8616(
        SimpleNamespace(), _evidence(_output(0x1010, 0x1020))
    )

    assert result.complete
    assert seen == [(0x1010, "bx"), (0x1020, "bx")]
    assert result.facts[0].parameter_storage == IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=6,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


@pytest.mark.parametrize(
    ("source", "failure"),
    (
        (None, TerminalPointerAliasFailure8616.REACHING_SOURCE_REFUSED),
        (("global", 0x200, 2), TerminalPointerAliasFailure8616.PARAMETER_SOURCE_UNSUPPORTED),
        ((BP_VALUE, -2, 2), TerminalPointerAliasFailure8616.PARAMETER_SOURCE_UNSUPPORTED),
        ((BP_VALUE, 4, 1), TerminalPointerAliasFailure8616.PARAMETER_SOURCE_UNSUPPORTED),
    ),
)
def test_unknown_or_non_parameter_source_refuses_atomically(
    monkeypatch: pytest.MonkeyPatch,
    source: tuple[object, ...] | None,
    failure: TerminalPointerAliasFailure8616,
) -> None:
    monkeypatch.setattr(
        terminal_pointer_outputs,
        "recover_register_source_before_instruction_8616",
        lambda _function, *, instruction_addr, register: _source(source),
    )

    result = classify_terminal_pointer_output_aliases_8616(
        SimpleNamespace(), _evidence(_output(0x1010))
    )

    assert not result.complete
    assert result.facts == ()
    assert result.failure is failure


def test_competing_parameter_sources_refuse_without_partial_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = iter((_source((BP_VALUE, 4, 2)), _source((BP_VALUE, 6, 2))))
    monkeypatch.setattr(
        terminal_pointer_outputs,
        "recover_register_source_before_instruction_8616",
        lambda _function, *, instruction_addr, register: next(sources),
    )

    result = classify_terminal_pointer_output_aliases_8616(
        SimpleNamespace(), _evidence(_output(0x1010, 0x1020))
    )

    assert not result.complete
    assert result.facts == ()
    assert result.failure is TerminalPointerAliasFailure8616.PARAMETER_SOURCE_CONFLICT

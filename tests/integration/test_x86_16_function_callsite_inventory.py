from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CStatements
import inertia.postprocess.decompiler_postprocess_calls as decompiler_postprocess_calls
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.postprocess.decompiler_postprocess_calls import (
    _all_function_callsite_addrs_8616,
    _missing_calls_from_owned_inventory_8616,
)

from inertia.frontend.x86_16.frontend_block_inventory import (
    decoded_function_callsite_addresses_8616,
)


def _instruction(address: int, mnemonic: str) -> SimpleNamespace:
    return SimpleNamespace(address=address, mnemonic=mnemonic)


def test_function_callsite_inventory_includes_unresolved_indirect_calls() -> None:
    first_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _instruction(0x101A, "call"),
                _instruction(0x1000, "push"),
                _instruction(0x100E, "call"),
            )
        )
    )
    second_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _instruction(0x1020, "lcall"),
                _instruction(0x101A, "call"),
            )
        )
    )
    function = SimpleNamespace(blocks=(first_block, second_block))

    assert decoded_function_callsite_addresses_8616(function) == (
        0x100E,
        0x101A,
        0x1020,
    )


def test_callsite_summary_bridge_combines_cfg_and_decoded_call_evidence(monkeypatch) -> None:
    block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _instruction(0x1006, "call"),
                _instruction(0x100E, "call"),
                _instruction(0x101A, "call"),
            )
        )
    )
    function = SimpleNamespace(
        blocks=(block,),
        get_call_sites=lambda: (0x1006,),
    )
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    monkeypatch.setattr(
        decompiler_postprocess_calls,
        "collect_neighbor_call_targets",
        lambda _function: (),
    )

    assert _all_function_callsite_addrs_8616(project, function) == (
        0x1006,
        0x100E,
        0x101A,
    )


def test_missing_direct_call_bridge_ignores_unresolved_indirect_calls(monkeypatch) -> None:
    summary = CallsiteSummary8616(
        callsite_addr=0x100E,
        target_addr=None,
        return_addr=0x1011,
        kind="near-indirect",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        target_source=("bp", 4),
    )
    codegen = SimpleNamespace(
        _inertia_callsite_summary_inventory_8616={summary.callsite_addr: summary},
        next_ident=lambda name: name,
        next_node_idx=lambda: 1,
    )
    root = CStatements([], codegen=codegen)

    def _reject_direct_recovery(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("indirect call entered direct-call recovery")

    monkeypatch.setattr(
        decompiler_postprocess_calls,
        "_lookup_callee_function_8616",
        _reject_direct_recovery,
    )

    assert _missing_calls_from_owned_inventory_8616(SimpleNamespace(), codegen, root) == (
        [],
        {},
    )

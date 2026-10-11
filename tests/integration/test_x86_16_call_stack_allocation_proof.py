"""Exercise binary-backed allocation effects through the pre-Alias path.

Guarded STACK_PROBE pattern identity is labeling evidence only: the helper's
carry and DS-limit failure exits are reachable, so identity alone must resolve
as an explicit STACK_ALLOCATION_UNPROVEN refusal rather than a complete
unconditional allocation or a silent balanced zero-argument call.
"""

from types import SimpleNamespace

import pytest

import inertia.semantics.call_stack_effect_pipeline as pipeline
from inertia.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.semantics.call_stack_effect_contracts import CallStackEffectFailure8616
from inertia.semantics.callsite_summary import CallsiteSummary8616

PROBE = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")
FAR_PROBE = bytes.fromhex("59 5a 8b dc 2b d8 72 0b 3b 1e c6 00 72 05 8b e3 52 51 cb")
TARGET = 0x2000


def _write(register, source, address=0x1000, size=2):
    return IRInstr("MOV", IRValue(MemSpace.REG, name=register, size=size),
                   (source,), size=size, addr=address)


def _run(monkeypatch, *, code=PROBE, between=(), request=18, delta=0, marked_probe=True,
         kind="direct_near"):
    def load(address, size):
        if address != TARGET:
            raise KeyError(address)
        return code[:size]

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=load),
                               main_object=SimpleNamespace(linked_base=TARGET, max_addr=len(code) - 1)),
    )
    if delta:
        project = SimpleNamespace(
            arch=project.arch, loader=SimpleNamespace(memory=SimpleNamespace(load=load)),
            _inertia_original_project=project, _inertia_original_linear_delta=delta,
        )
    summary = CallsiteSummary8616(
        callsite_addr=0x1006, target_addr=0x2000,
        return_addr=0x100B if kind == "direct_far" else 0x1009,
        kind=kind, arg_count=0, arg_widths=(), stack_cleanup=0,
        return_register=None, return_used=False, stack_probe_helper=marked_probe,
        stack_probe_allocation_size=request,
    )
    monkeypatch.setattr(pipeline, "build_callsite_summary_inventory_with_program_evidence_8616",
                        lambda *_args: {0x1006: summary})
    artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, (
        _write("ax", IRValue(MemSpace.CONST, const=18, size=2)),
        *between,
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=TARGET - delta, size=2),), addr=0x1006),
    )),))
    effects, _outputs, _ssa = pipeline.build_semantic_function_ssa_8616(
        project, SimpleNamespace(addr=0x1000), ir_artifact=artifact,
    )
    return effects.facts[-1]


def _assert_allocation_unproven(fact):
    assert not fact.effect.complete
    assert fact.effect.net_stack_delta is None
    assert fact.failure is CallStackEffectFailure8616.STACK_ALLOCATION_UNPROVEN


@pytest.mark.parametrize("allocation_request", [None, 18])
def test_guarded_probe_identity_resolves_allocation_unproven(monkeypatch, allocation_request):
    """Pattern identity plus a reaching immediate is not allocation authority."""
    _assert_allocation_unproven(_run(monkeypatch, request=allocation_request))


@pytest.mark.parametrize("register", ["al", "ah", "ax", "eax"])
def test_partial_or_full_ax_clobber_refuses_allocation(monkeypatch, register):
    clobber = _write(register, IRValue(MemSpace.REG, name="dx", size=2), address=0x1003)
    _assert_allocation_unproven(_run(monkeypatch, between=(clobber,)))


def test_probe_name_without_binary_bytes_is_not_proof(monkeypatch):
    _assert_allocation_unproven(_run(monkeypatch, code=b"\xc3"))


def test_conflicting_allocation_request_is_not_ignored(monkeypatch):
    _assert_allocation_unproven(_run(monkeypatch, request=20))


def test_intervening_call_kills_the_reaching_allocation(monkeypatch):
    call = IRInstr("CALL", None, (), addr=0x1003)
    _assert_allocation_unproven(_run(monkeypatch, between=(call,)))


def test_relocated_slice_keeps_the_guarded_candidate_as_refusal(monkeypatch):
    """Sliced binary evidence must still refuse instead of silently vanishing."""
    _assert_allocation_unproven(_run(monkeypatch, delta=0x100))


@pytest.mark.parametrize("marked_probe", [False, True])
def test_unmarked_probe_summary_cannot_fall_through_to_balanced_abi(monkeypatch, marked_probe):
    """An unmarked guarded candidate still refuses rather than reporting zero."""
    _assert_allocation_unproven(
        _run(monkeypatch, request=None, marked_probe=marked_probe))


@pytest.mark.parametrize("marked_probe", [False, True])
def test_far_probe_identity_resolves_allocation_unproven(monkeypatch, marked_probe):
    fact = _run(monkeypatch, code=FAR_PROBE, kind="direct_far",
                request=None, marked_probe=marked_probe)

    _assert_allocation_unproven(fact)


@pytest.mark.parametrize("code,kind", [(PROBE, "direct_far"), (FAR_PROBE, "direct_near")])
@pytest.mark.parametrize("marked_probe", [False, True])
def test_call_frame_must_match_binary_allocation_return_frame(monkeypatch, code, kind, marked_probe):
    fact = _run(monkeypatch, code=code, kind=kind, marked_probe=marked_probe, request=None)

    _assert_allocation_unproven(fact)


def test_ordinary_zero_argument_call_remains_complete(monkeypatch):
    """A non-probe call with no allocation evidence keeps the balanced ABI."""
    fact = _run(monkeypatch, code=b"\xc3", marked_probe=False, request=None)

    assert fact.effect.complete
    assert fact.effect.net_stack_delta == 0
    assert fact.failure is None

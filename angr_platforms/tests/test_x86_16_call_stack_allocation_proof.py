"""Exercise binary-backed allocation effects through the pre-Alias path."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.semantics import call_stack_effect_pipeline as pipeline

PROBE = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")
FAR_PROBE = bytes.fromhex("59 5a 8b dc 2b d8 72 0b 3b 1e c6 00 72 05 8b e3 52 51 cb")
TARGET = 0x2000
ALLOCATION = 18


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


@pytest.mark.parametrize("allocation_request", [None, 18])
def test_binary_and_reaching_ir_value_prove_allocation(monkeypatch, allocation_request):
    fact = _run(monkeypatch, request=allocation_request)

    assert fact.effect.complete
    assert fact.effect.net_stack_delta == -ALLOCATION
    assert fact.failure is None
    assert fact.effect.bp_preserved


@pytest.mark.parametrize("register", ["al", "ah", "ax", "eax"])
def test_partial_or_full_ax_clobber_refuses_allocation(monkeypatch, register):
    clobber = _write(register, IRValue(MemSpace.REG, name="dx", size=2), address=0x1003)
    fact = _run(monkeypatch, between=(clobber,))

    assert not fact.effect.complete
    assert fact.effect.net_stack_delta is None


def test_probe_name_without_binary_bytes_is_not_proof(monkeypatch):
    assert not _run(monkeypatch, code=b"\xc3").effect.complete


def test_conflicting_allocation_request_is_not_ignored(monkeypatch):
    assert not _run(monkeypatch, request=20).effect.complete


def test_intervening_call_kills_the_reaching_allocation(monkeypatch):
    call = IRInstr("CALL", None, (), addr=0x1003)
    assert not _run(monkeypatch, between=(call,)).effect.complete


def test_relocated_slice_consumes_original_callee_binary_evidence(monkeypatch):
    fact = _run(monkeypatch, delta=0x100)

    assert fact.effect.complete
    assert fact.effect.net_stack_delta == -ALLOCATION


def test_binary_allocation_does_not_require_a_named_probe_summary(monkeypatch):
    fact = _run(monkeypatch, request=None, marked_probe=False)

    assert fact.effect.complete
    assert fact.effect.net_stack_delta == -ALLOCATION


@pytest.mark.parametrize("marked_probe", [False, True])
def test_far_binary_allocation_preserves_the_proven_frame(monkeypatch, marked_probe):
    fact = _run(monkeypatch, code=FAR_PROBE, kind="direct_far",
                request=None, marked_probe=marked_probe)

    assert fact.effect.complete
    assert fact.effect.net_stack_delta == -ALLOCATION
    assert fact.effect.bp_preserved
    assert fact.failure is None


@pytest.mark.parametrize("code,kind", [(PROBE, "direct_far"), (FAR_PROBE, "direct_near")])
@pytest.mark.parametrize("marked_probe", [False, True])
def test_call_frame_must_match_binary_allocation_return_frame(monkeypatch, code, kind, marked_probe):
    fact = _run(monkeypatch, code=code, kind=kind, marked_probe=marked_probe, request=None)

    assert not fact.effect.complete
    assert fact.effect.net_stack_delta is None

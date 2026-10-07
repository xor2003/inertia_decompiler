"""Actual-PE32 matched recursive component controls through the adapters.

Layer: tests.
Responsibility: drive the staged flat32 PE component builder, image-bound
access-domain proof and composed image-bound joint adapter on genuine
CLE-loaded PE images under each driver's 32-bit register model. Covers
equivalence, code deltas, metadata/edge corruption, frame, stack, code-scope
and stale-premise controls plus honest unsupported import/fault refusals.
"""
from __future__ import annotations

from dataclasses import replace

import pytest
from tools.dosunit.tests.recursive_proof_fixtures.call_continuation_inputs import swap_declared_continuations
from tools.dosunit.tests.recursive_proof_fixtures.flat32_pe_recursive_inputs import (
    BASE_CASE_FLIPPED,
    DATA_BASE,
    ENTRY,
    ENVIRONMENT_CALL,
    FAULT_CODE,
    PROGRESS_FLIPPED,
    STACK_HI,
    Flat32PeRecursiveInputs,
    make_flat32_pe_recursive_inputs,
)
from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.flat32_image_bound_domain import Flat32AccessDomain
from tools.dosunit.recursive_proofs.flat32_image_bound_joint_proof import (
    Flat32ModelRequirement,
    check_image_bound_flat32_joint,
)
from tools.dosunit.recursive_proofs.flat32_pe_component import (
    Flat32ProposalReason,
    Flat32ProposalRefusal,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason, JointStepKind

_DRIVERS: tuple[str, ...] = ("msc8", "bc5")
_INPUTS: dict[str, Flat32PeRecursiveInputs] = {}


def _inputs(driver: str, **kwargs: object) -> Flat32PeRecursiveInputs:
    """Build the actual-PE inputs once per driver register model."""
    key = driver if not kwargs else f"{driver}:{kwargs!r}"
    if key not in _INPUTS:
        with _driver_lane(driver) as lane, lane.adapter.installed(region=True):
            _INPUTS[key] = make_flat32_pe_recursive_inputs(**kwargs)  # type: ignore[arg-type]
    return _INPUTS[key]


def _prove(driver: str, inputs: Flat32PeRecursiveInputs,
           system: object = None, loads: object = None, initialized: object = None,
           access: object = None, timeout_ms: int = 120000) -> object:
    """Run the composed adapter inside this driver's flat32 register model."""
    with _driver_lane(driver) as lane, lane.adapter.installed(region=True):
        return check_image_bound_flat32_joint(
            system or inputs.system, loads or inputs.loads,  # type: ignore[arg-type]
            initialized or inputs.initialized, inputs.requests, inputs.bootstrap,  # type: ignore[arg-type]
            access or inputs.access, timeout_ms=timeout_ms)  # type: ignore[arg-type]


@pytest.mark.parametrize("driver", _DRIVERS)
def test_pe32_recursive_component_discharges_conditional_joint(driver: str) -> None:
    """Identical actual-PE images reach the conditional modeled theorem."""
    inputs = _inputs(driver)
    component = inputs.component
    steps = component.system.steps
    kinds = [step.kind for step in steps]
    assert kinds.count(JointStepKind.CALL) == 2
    assert JointStepKind.RETURN in kinds and JointStepKind.BRANCH in kinds
    assert len(steps) == len({step.node for step in steps}) >= 4
    assert component.system.control_field == "ip"
    assert all(component.system.initial_state == state for state in component.bootstrap)
    assert len(component.requests[0]) == len(component.requests[1]) == len(steps)
    proof = _prove(driver, inputs)
    assert proof.status is ProofStatus.CONDITIONAL and proof.reason is JointReason.CONDITIONAL_MODEL, proof
    assert proof.proof.counters.failure_count == 0
    assert proof.remaining == tuple(Flat32ModelRequirement)
    assert proof.domain is not None and proof.domain.status is ProofStatus.PROVED
    assert len(proof.sources) == 2
    assert all(source.status is ProofStatus.PROVED for source in proof.sources)
    assert proof.joint is not None and proof.joint.status is ProofStatus.CONDITIONAL
    assert proof.frames and all(frame.status is ProofStatus.PROVED for frame in proof.frames)
    assert not proof.binary_equivalence_proved


@pytest.mark.parametrize("driver", _DRIVERS)
@pytest.mark.parametrize("mutated", [BASE_CASE_FLIPPED, PROGRESS_FLIPPED],
                         ids=["changed-base", "changed-progress"])
def test_pe32_changed_code_never_discharges(driver: str, mutated: bytes) -> None:
    """A same-shape byte change must produce countermodel evidence, never a pass."""
    if mutated is BASE_CASE_FLIPPED:
        # VEX lifts jz as exit-to-taken and jnz as exit-to-fallthrough, so the
        # guarded-edge roles at 0x401002 genuinely differ: the matched
        # component cannot be built and admission refuses the proposal.
        with pytest.raises(Flat32ProposalRefusal) as caught:
            _inputs(driver, candidate_code=mutated)
        assert caught.value.reason is Flat32ProposalReason.MANIFEST
        return
    inputs = _inputs(driver, candidate_code=mutated)
    proof = _prove(driver, inputs)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.reason is JointReason.COUNTERMODEL, proof
    assert proof.proof.counters.failure_count > 0


def _first_call(system: object) -> int:
    """Locate the first CALL transition index inside the component manifest."""
    return next(index for index, step in enumerate(system.steps)
                if step.kind is JointStepKind.CALL)  # type: ignore[union-attr]


@pytest.mark.parametrize("driver", _DRIVERS)
def test_swapped_call_continuations_refuse(driver: str) -> None:
    """Admissible metadata swaps cannot reuse each other's saved-word proof."""
    inputs = _inputs(driver)
    corrupted = swap_declared_continuations(inputs.system)
    proof = _prove(driver, inputs, system=corrupted)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.reason in {JointReason.CALL_CONTINUATION, JointReason.COUNTERMODEL, JointReason.UNKNOWN}, proof
    assert proof.proof.counters.failure_count > 0


@pytest.mark.parametrize("driver", _DRIVERS)
@pytest.mark.parametrize("corruption", ["omitted-block", "omitted-edge"])
def test_manifest_corruption_refuses(driver: str, corruption: str) -> None:
    """Dropping a block or a declared edge cannot complete the manifest."""
    inputs = _inputs(driver)
    if corruption == "omitted-block":
        corrupted = replace(inputs.system, steps=inputs.system.steps[:-1])
    else:
        head = inputs.system.steps[0]
        corrupted = replace(inputs.system, steps=(
            replace(head, successors=head.successors[:-1]), *inputs.system.steps[1:]))
    proof = _prove(driver, inputs, system=corrupted)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.proof.counters.failure_count > 0


@pytest.mark.parametrize("driver", _DRIVERS)
@pytest.mark.parametrize("corruption", ["register", "memory"])
def test_hidden_state_corruption_refuses(driver: str, corruption: str) -> None:
    """A fabricated state can never match its byte-bound request hash.

    States are proposals; the independent byte-binding linkage requires every
    step's effect to equal the actual lift of the immutable image bytes, so
    corruption refuses at admission before any solver comparison runs.
    """
    inputs = _inputs(driver)
    step = inputs.system.steps[0]
    changed = dict(step.candidate)
    if corruption == "register":
        changed["ebx"] = {"op": "const", "width": 32, "value": "0x1234"}
    else:
        changed["memory"] = {"op": "storele", "width": 0, "args": [
            changed["memory"],
            {"op": "const", "width": 32, "value": "0x402ff0"},
            {"op": "const", "width": 8, "value": "0x0"},
        ]}
    corrupted = replace(inputs.system, steps=(
        replace(step, candidate=changed), *inputs.system.steps[1:]))
    proof = _prove(driver, inputs, system=corrupted)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.reason is JointReason.ADMISSION, proof
    assert proof.proof.counters.failure_count > 0


@pytest.mark.parametrize("driver", _DRIVERS)
def test_symmetrically_corrupt_frame_refuses(driver: str) -> None:
    """A same-on-both-sides wrong esp effect still fails byte-bound linkage.

    Fabricated frame evidence cannot reach the frame proof: states must equal
    the independently byte-derived effects, so a stationary-esp corruption is
    refused at source admission on both sides.
    """
    inputs = _inputs(driver)
    index = _first_call(inputs.system)
    step = inputs.system.steps[index]
    stationary = {"op": "input", "name": "esp", "width": 32}
    original = dict(step.original)
    candidate = dict(step.candidate)
    original["esp"] = stationary
    candidate["esp"] = stationary
    corrupted = replace(inputs.system, steps=(
        *inputs.system.steps[:index],
        replace(step, original=original, candidate=candidate),
        *inputs.system.steps[index + 1:]))
    proof = _prove(driver, inputs, system=corrupted)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.reason is JointReason.ADMISSION, proof
    assert proof.proof.counters.failure_count > 0


@pytest.mark.parametrize("driver", _DRIVERS)
@pytest.mark.parametrize("corruption", ["stack-window", "code-overlap"])
def test_domain_declaration_corruption_refuses(driver: str, corruption: str) -> None:
    """A stack window too small for the budget or covering code cannot pass."""
    inputs = _inputs(driver)
    if corruption == "stack-window":
        access = Flat32AccessDomain(DATA_BASE + 0xF80, STACK_HI, DATA_BASE + 0xF80, DATA_BASE + 0xFE0, 64)
    else:
        access = Flat32AccessDomain(ENTRY - 4, ENTRY + 8, ENTRY - 4, ENTRY, 4)
    proof = _prove(driver, inputs, access=access)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.proof.counters.failure_count > 0


@pytest.mark.parametrize("driver", _DRIVERS)
@pytest.mark.parametrize("corruption", ["bytes", "mappings"])
def test_stale_load_premises_refuse(driver: str, corruption: str) -> None:
    """Freshness revalidation rejects mutated immutable file bytes or mappings."""
    inputs = _inputs(driver)
    load = inputs.loads[0]
    if corruption == "bytes":
        stale = replace(load, file_bytes=load.file_bytes + b"\0")
    else:
        binding = replace(load.binding, mappings=tuple(
            replace(mapping, writable=False) for mapping in load.binding.mappings))
        stale = replace(load, binding=binding)
    proof = _prove(driver, inputs, loads=(stale, inputs.loads[1]))
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.reason is JointReason.ADMISSION, proof


@pytest.mark.parametrize("driver", _DRIVERS)
@pytest.mark.parametrize("corruption", ["model", "entry"])
def test_stale_model_and_entry_premises_refuse(driver: str, corruption: str) -> None:
    """A foreign model seal or contract hash cannot authorize the receipt."""
    inputs = _inputs(driver)
    if corruption == "model":
        proof = _prove(driver, inputs,
                       initialized=replace(inputs.initialized, model_hash="0" * 64))
    else:
        system = replace(inputs.system,
                         contract=replace(inputs.system.contract, original_hash="0" * 64))
        proof = _prove(driver, inputs, system=system)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.proof.counters.failure_count > 0


@pytest.mark.parametrize("driver", _DRIVERS)
@pytest.mark.parametrize("code,functions,label", [
    (ENVIRONMENT_CALL, {ENTRY: len(ENVIRONMENT_CALL)}, "call-outside-component"),
    (FAULT_CODE, {ENTRY: len(FAULT_CODE)}, "fault-signal-block"),
], ids=["import", "fault"])
def test_unsupported_environment_and_fault_refuse(driver: str, code: bytes,
                                                  functions: dict[int, int], label: str) -> None:
    """Undeclared call targets and signal blocks are honest intake refusals."""
    with (
        _driver_lane(driver) as lane,
        lane.adapter.installed(region=True),
        pytest.raises(Flat32ProposalRefusal) as caught,
    ):
        make_flat32_pe_recursive_inputs(original_code=code, functions=functions)
    assert caught.value.reason is Flat32ProposalReason.LIFT, label


@pytest.mark.parametrize("driver", _DRIVERS)
def test_combined_deadline_is_never_replenished(driver: str) -> None:
    """An exhausted shared budget leaves the composed report unproved."""
    inputs = _inputs(driver)
    proof = _prove(driver, inputs, timeout_ms=0)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.reason is JointReason.DEADLINE, proof

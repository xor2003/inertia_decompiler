"""Collect original-image instruction evidence for consumed call setup.

Layer: Recovery metadata.
Responsibility: bound and decode loaded caller/callee bytes, reject synthetic
targets, and delegate value-liveness proof to Semantics. Never lift new blocks
or mutate a project while final callsite materialization is in progress.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from angr import Project
from capstone import CS_ARCH_X86, CS_MODE_16, Cs, CsError

from inertia.frontend.x86_16.synthetic_call_stub_evidence import synthetic_call_stub_registry_8616
from inertia.semantics.register_entry_overwrite import (
    ConsumedStackAddressSetup8616,
    RegisterEntryOverwriteProof8616,
    RegisterEntryOverwriteReason8616,
    RegisterEntryOverwriteVerdict8616,
    prove_consumed_stack_address_setup_8616,
)


def collect_consumed_stack_address_setup_8616(
    project: Project, request: ConsumedStackAddressSetup8616,
) -> RegisterEntryOverwriteProof8616:
    """Read bounded image bytes without trusting analysis-only stub bodies."""
    refusal = RegisterEntryOverwriteProof8616(
        RegisterEntryOverwriteVerdict8616.UNKNOWN_REFUSE,
        RegisterEntryOverwriteReason8616.MISSING_EFFECTS, 0xFFFF, (),
    )
    registry = synthetic_call_stub_registry_8616(project)
    if registry is not None and (
        not registry.closes_evidence or request.target_address in registry.addresses
    ):
        return refusal
    image = project.loader.main_object
    if not (
        image.min_addr <= request.producer_address < request.push_address < request.call_address
        and request.call_address < image.max_addr
        and image.min_addr <= request.target_address <= image.max_addr
        and request.call_address - request.producer_address <= 256
    ):
        return refusal
    try:
        decoder = Cs(CS_ARCH_X86, CS_MODE_16)
        decoder.detail = True
        caller_bytes = bytes(project.loader.memory.load(
            request.producer_address,
            min(request.call_address + 15, image.max_addr + 1) - request.producer_address,
        ))
        caller = tuple(
            instruction for instruction in decoder.disasm(caller_bytes, request.producer_address)
            if instruction.address <= request.call_address
        )
        callee_bytes = bytes(project.loader.memory.load(
            request.target_address, min(128, image.max_addr + 1 - request.target_address),
        ))
        callee = tuple(decoder.disasm(callee_bytes, request.target_address))
    except (KeyError, ValueError, TypeError, CsError):
        return refusal
    return prove_consumed_stack_address_setup_8616(caller, callee, request)

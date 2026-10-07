"""Architectural domain invariants for real16 matched-loop cutpoints.

Layer: dosunit relational loop proofs.
Responsibility: establish a nonempty code-entry domain and prove that each
continuing transition preserves it before call summaries reuse that domain.
Retain the full loaded control destination and reject word-wrapped graph edges.
"""

from __future__ import annotations

from typing import Any

from tools.dosunit.compare.real16_call_contracts import (
    FunctionCtx,
    Real16CallRefusal,
    prove_terms_equal,
)
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.contracts.real16_entry_domain import Real16EntryDomain, code_entry_domain


def loop_entry_domain(ctx: FunctionCtx) -> Real16EntryDomain:
    """Require a nonvacuous selector relation at the function entry."""
    domain = code_entry_domain(ctx.entry_linear)
    if domain is None:
        raise Real16CallRefusal("code_entry_domain_unmapped", {"entry": ctx.entry_linear})
    return domain


def check_cutpoint_state(
    ctx: FunctionCtx, state: dict[str, dict[str, Any]], *,
    continuing: bool, timeout_ms: int,
) -> None:
    """Prove selector-domain preservation for every continuing loop step.

    Entry admits precisely the derived selector interval. Induction may reuse
    that assumption only after this preservation obligation is discharged.
    Exit states retain full control but need not reenter the loop domain.
    """
    control = state.get("control_ip")
    if not isinstance(control, dict) or control.get("width") != 32:
        raise Real16CallRefusal("full_control_unobserved", {"function": ctx.function_id})
    if not continuing:
        return
    selector = state.get("cs")
    if not isinstance(selector, dict):
        raise Real16CallRefusal("cutpoint_code_domain_unproved", {"function": ctx.function_id})
    domain = loop_entry_domain(ctx)
    proved = prove_terms_equal(
        domain.contains(selector), {"op": "const", "width": 1, "value": "0x1"},
        timeout_ms, input_constraints=domain.constraints(),
    )
    if proved is not ProofStatus.PROVED:
        raise Real16CallRefusal("cutpoint_code_domain_unproved", {"function": ctx.function_id})


def check_physical_successors(ctx: FunctionCtx, source: dict[str, Any]) -> None:
    """Reject a published successor that only matches after truncating to 16 bits."""
    declared_physical_successors(ctx, source)


def declared_physical_successors(ctx: FunctionCtx, source: dict[str, Any]) -> frozenset[int]:
    """Return only exact loaded successors belonging to the declared function.

    Acyclic composition and induction share this boundary. Metadata supplies
    candidates; the caller must still prove each actual control transition.
    """
    transfer = source.get("transfer")
    if not isinstance(transfer, dict):
        raise Real16CallRefusal("successor_outside_region", {"function": ctx.function_id})
    if transfer.get("kind") == "direct_call":
        destinations = [transfer.get("fallthrough")]
    elif transfer.get("kind") == "direct_successors":
        destinations = transfer.get("successors", [])
    else:
        raise Real16CallRefusal("successor_outside_region", {"function": ctx.function_id})
    admitted = {ctx.entry_linear + delta for delta in ctx.blocks}
    if not isinstance(destinations, list) or not destinations:
        raise Real16CallRefusal("successor_outside_region", {"function": ctx.function_id})
    resolved: set[int] = set()
    for destination in destinations:
        linear = _destination_linear(destination, ctx.function_id)
        if linear not in admitted:
            raise Real16CallRefusal("successor_outside_region", {"function": ctx.function_id, "linear": linear})
        resolved.add(linear)
    return frozenset(resolved)


def _destination_linear(destination: object, function: str) -> int:
    """Decode a published loaded address without truncation or guessed defaults."""
    if not isinstance(destination, dict):
        raise Real16CallRefusal("successor_outside_region", {"function": function})
    raw = destination.get("linear")
    if type(raw) is int:
        return raw
    if isinstance(raw, str):
        try:
            return int(raw, 0)
        except ValueError as error:
            raise Real16CallRefusal("successor_outside_region", {"function": function}) from error
    raise Real16CallRefusal("successor_outside_region", {"function": function})

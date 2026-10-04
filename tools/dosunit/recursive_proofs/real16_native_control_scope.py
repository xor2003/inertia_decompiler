"""Layer: dosunit native control-coordinate proof.

Responsibility: independently decode one exact near16 block and compare its
loaded control with WORD-wrapped architectural destinations. This local fact
grants neither reachability nor frame, dispatch, fault or binary equivalence.
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, cast

import capstone
import pyvex
import z3
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.control_coordinates import (
    ControlAddressDomain,
    ControlWidth,
    architectural_offset,
    linear_continuation,
)
from angr_platforms.X86_16.relative_control_edge import DecodedRelativeEdge, decode_relative_edge

from tools.dosunit import ssa_constant_terms
from tools.dosunit import straightline_ssa as S
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import initial_state, materialize_function
from tools.dosunit.recursive_proofs import recursive_static_control
from tools.dosunit.recursive_proofs.real16_entry_domain import Real16ScalarDomain, entry_domain_model_hash
from tools.dosunit.recursive_proofs.real16_native_effect_binding import native_binding_model_hash
from tools.dosunit.recursive_proofs.recursive_static_control import resolve_static_control
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import _state_exprs
from tools.dosunit.register_state_relations import MachineState


class ControlScopeObligation(StrEnum):
    """Fixed complete denominator of one local coordinate certificate."""

    SOURCE = "fresh_complete_near16_decode"
    DOMAIN = "nonempty_fixed_cs_entry_and_request_head"
    FORM = "complete_supported_terminal_control_form"
    CONTROL = "native_control_equals_architectural_target"
    MODEL = "stable_source_and_coordinate_model"


class ControlScopeReason(StrEnum):
    """Exact local completion or refusal boundary."""

    PROVED = "native_control_coordinates_discharged"
    SOURCE = "native_control_source_or_effect_incomplete"
    DOMAIN = "native_control_domain_or_entry_unproved"
    FORM = "native_control_terminal_form_unsupported"
    CONTROL = "native_control_coordinate_countermodel"
    OPAQUE = "native_control_target_term_opaque"
    DEADLINE = "native_control_original_deadline_exhausted"
    MODEL = "native_control_source_or_model_changed"


class ControlForm(StrEnum):
    """Decoded near transfer class, without branch-guard semantics."""

    JMP = "direct_near_jmp16"
    CONDITIONAL = "direct_near_conditional16"
    CALL = "direct_near_call16"
    RETURN = "near_ret16"


@dataclass(frozen=True, slots=True)
class ControlScopeFact:
    """One required attempted local fact and its typed outcome."""

    obligation: ControlScopeObligation
    status: ProofStatus
    detail: str = ""
    attempted: bool = True


@dataclass(frozen=True, slots=True)
class NativeControlScope:
    """A sealed, local source-bound coordinate result, never binary acceptance."""

    status: ProofStatus
    reason: ControlScopeReason
    source_sha256: str
    entry_sha256: str
    model_hash: str
    head: int
    size: int
    domain: Real16ScalarDomain | None
    fixed_cs: int | None
    form: ControlForm | None
    expected_targets: frozenset[int]
    native_targets: frozenset[int]
    facts: tuple[ControlScopeFact, ...]
    counters: FactCounters

    @property
    def complete(self) -> bool:
        """Require every exact positive fact and coherent accounting."""
        required = tuple(ControlScopeObligation)
        return (self.status is ProofStatus.PROVED and self.reason is ControlScopeReason.PROVED
                and tuple(row.obligation for row in self.facts) == required
                and all(row.status is ProofStatus.PROVED and row.attempted for row in self.facts)
                and self.counters == FactCounters(len(required), len(required), len(required), len(required), 0))

    @property
    def binary_equivalence_proved(self) -> bool:
        """A coordinate fact cannot close whole-binary obligations."""
        return False


class _Refusal(Exception):
    """Carry a bounded typed non-result without swallowing decoder defects."""

    def __init__(self, reason: ControlScopeReason, detail: str) -> None:
        """Retain the exact refusal boundary and cause."""
        self.reason = reason
        super().__init__(detail)


def native_control_model_hash() -> str:
    """Seal this owner and all consumed native/domain/projection owners."""
    import angr_platforms.X86_16.control_coordinates as coordinates

    digest = hashlib.sha256(Path(__file__).read_bytes())
    digest.update(native_binding_model_hash().encode("ascii"))
    digest.update(entry_domain_model_hash().encode("ascii"))
    for path in (Path(coordinates.__file__), Path(S.__file__), Path(ssa_constant_terms.__file__),
                 Path(recursive_static_control.__file__)):
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _time(deadline: float) -> int:
    """Charge every foreign decode and solver call to the original deadline."""
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise _Refusal(ControlScopeReason.DEADLINE, "original native control deadline exhausted")
    return remaining


def _constant_unneeded(value: object, width: object) -> NoReturn:
    """Refuse a symbolic coordinate at this fixed-CS concrete projection."""
    raise ValueError(f"fixed-CS projection unexpectedly requested symbolic constant {value!r}:{width!r}")


def _terminal_form(raw: bytes, head: int) -> tuple[ControlForm, int]:
    """Consume shared exact-byte edges while retaining this gate's near16 scope."""
    if raw and (raw[0], len(raw)) in {(0xC3, 1), (0xC2, 3)}:
        return ControlForm.RETURN, 0
    edge = decode_relative_edge(head, raw)
    if not isinstance(edge, DecodedRelativeEdge) or edge.width is not ControlWidth.WORD:
        raise _Refusal(ControlScopeReason.FORM, "terminal opcode/width is not admitted near16 control")
    form = ControlForm.CONDITIONAL if edge.is_conditional else ControlForm.CALL if edge.is_call else ControlForm.JMP
    return form, edge.displacement


def _decode(data: bytes, head: int, deadline: float) -> tuple[tuple[capstone.CsInsn, ...], ControlForm, int]:
    """Accept exact complete bytes and only one final supported near16 control."""
    _time(deadline)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instructions = tuple(decoder.disasm(data, head))
    if not instructions or sum(row.size for row in instructions) != len(data):
        raise _Refusal(ControlScopeReason.SOURCE, "Capstone did not cover the exact request")
    if len(instructions) > 256:
        raise _Refusal(ControlScopeReason.SOURCE, "native block exceeds bounded instruction intake")
    running_head = head
    for row in instructions:
        if row.address != running_head:
            raise _Refusal(ControlScopeReason.SOURCE, "decoded instruction heads are not contiguous")
        running_head += row.size
    if any(any(group in row.groups for group in (capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET))
           for row in instructions[:-1]):
        raise _Refusal(ControlScopeReason.FORM, "internal control transfer requires another request")
    terminal = instructions[-1]
    raw = bytes(terminal.bytes)
    if not raw or any(terminal.prefix):
        raise _Refusal(ControlScopeReason.FORM, "prefixed terminal control needs a separate width contract")
    form, displacement = _terminal_form(raw, terminal.address)
    _time(deadline)
    return instructions, form, displacement


def _expected(terminal: capstone.CsInsn, form: ControlForm, displacement: int,
              fixed_cs: int) -> frozenset[int]:
    """Use shared coordinate owners for fixed-CS WORD relative destinations."""
    next_linear = terminal.address + terminal.size
    offset = architectural_offset(next_linear, fixed_cs, ControlWidth.WORD, _constant_unneeded)
    if not isinstance(offset, int):
        raise ValueError("fixed selector must yield a concrete architectural next offset")
    target = linear_continuation(fixed_cs, (offset + displacement) & 0xFFFF,
                                 ControlWidth.WORD, _constant_unneeded)
    fallthrough = linear_continuation(fixed_cs, offset, ControlWidth.WORD, _constant_unneeded)
    if not isinstance(target, int) or not isinstance(fallthrough, int):
        raise ValueError("fixed selector must yield concrete loaded control")
    return frozenset({target, fallthrough} if form is ControlForm.CONDITIONAL else {target})


def _lift(data: bytes, head: int, entry: MachineState, deadline: float,
          ) -> tuple[pyvex.IRSB, MachineState, MachineState]:
    """Independently lift the full block and the straight-line RET prefix."""
    _time(deadline)
    arch = Arch86_16(control_address_domain=ControlAddressDomain.LOADER_LINEAR)
    irsb = pyvex.lift(data, head, arch, max_bytes=len(data), opt_level=0)
    if irsb.size != len(data) or irsb.jumpkind == "Ijk_NoDecode":
        raise _Refusal(ControlScopeReason.SOURCE, "full native lift is incomplete")
    lowered = S._lower_irsb(irsb, output_regs=tuple(S.INTERNAL_STATE_REGS),
                            max_assignments_per_function=4096)
    if isinstance(lowered, S.LowerFailure):
        raise _Refusal(ControlScopeReason.SOURCE, f"{lowered.reason}: {lowered.message}")
    post = S._compose_block_outputs(lowered, lowered["outputs"], entry,
                                    compose_stats={"deadline": deadline})
    control = post.get("control_ip")
    if set(post) != set(initial_state()) or not isinstance(control, dict) or control.get("width") != 32:
        raise _Refusal(ControlScopeReason.SOURCE, "complete DWORD native control effect is missing")
    _time(deadline)
    return irsb, post, entry


def _terms(entry: MachineState, pre: MachineState, post: MachineState,
           ) -> tuple[dict[str, z3.ExprRef], dict[str, z3.ExprRef], dict[str, z3.ExprRef]]:
    """Encode all three owned SSA projections with one shared native input map."""
    docs = tuple(materialize_function(name, state) for name, state in
                 (("control:entry", entry), ("control:pre", pre), ("control:post", post)))
    merged = {"inputs": [item for document in docs for item in document["inputs"]]}
    inputs = S._z3_inputs(merged, merged, z3)
    before = _state_exprs(entry, inputs)
    before_terminal = _state_exprs(pre, inputs)
    after = _state_exprs(post, inputs)
    return before, before_terminal, after


def _check(predicate: z3.BoolRef, deadline: float, *, witness: bool = False) -> ProofStatus:
    """Discharge or refute one native Boolean under the unchanged deadline."""
    solver = z3.Solver()
    solver.set(timeout=_time(deadline))
    solver.add(predicate if witness else z3.Not(predicate))
    outcome = solver.check()
    _time(deadline)
    if outcome == (z3.sat if witness else z3.unsat):
        return ProofStatus.PROVED
    return ProofStatus.COUNTEREXAMPLE if outcome == z3.sat and not witness else ProofStatus.UNKNOWN


def _ret_equation(pre: dict[str, z3.ExprRef], post: dict[str, z3.ExprRef]) -> z3.BoolRef:
    """Compare full control with the actual pre-RET SS:SP memory word."""
    ss, sp, cs = (cast(z3.BitVecRef, pre[name]) for name in ("ss", "sp", "cs"))
    memory = cast(z3.ArrayRef, pre["memory"])
    base = z3.ZeroExt(16, ss) << 4
    low = base + z3.ZeroExt(16, sp)
    high = low + z3.BitVecVal(1, 32)
    word = z3.Concat(z3.Select(memory, high), z3.Select(memory, low))
    expected = (z3.ZeroExt(16, cs) << 4) + z3.ZeroExt(16, word)
    return cast(z3.BoolRef, z3.And(z3.ULE(sp, z3.BitVecVal(0xFFFE, 16)),
                                    post["control_ip"] == expected))


def _validate_request(data: bytes, head: int, deadline: float) -> None:
    """Reject malformed or unbounded local requests before collecting facts."""
    if type(data) is not bytes or not data or len(data) > 4096:
        raise ValueError("control scope requires a bounded immutable block")
    if type(head) is not int or not 0 <= head < 0x100000 or head + len(data) > 0x100000:
        raise ValueError("control scope requires a normal loaded block head")
    if type(deadline) not in {float, int} or not math.isfinite(deadline):
        raise ValueError("control scope requires a finite absolute deadline")


def _source_effect(data: bytes, head: int, entry: MachineState, deadline: float,
                   ) -> tuple[tuple[capstone.CsInsn, ...], ControlForm, int, MachineState]:
    """Bind exact native decode, lift, jumpkind and complete SSA effect."""
    instructions, form, displacement = _decode(data, head, deadline)
    if set(entry) != set(initial_state()) or not isinstance(entry.get("control_ip"), dict):
        raise _Refusal(ControlScopeReason.DOMAIN, "entry lacks complete native state")
    irsb, post, _ = _lift(data, head, entry, deadline)
    expected_jumpkind = {ControlForm.JMP: "Ijk_Boring", ControlForm.CONDITIONAL: "Ijk_Boring",
                         ControlForm.CALL: "Ijk_Call", ControlForm.RETURN: "Ijk_Ret"}[form]
    if irsb.jumpkind != expected_jumpkind or irsb.instructions != len(instructions):
        raise _Refusal(ControlScopeReason.SOURCE, "native jumpkind or instruction count differs from decode")
    return instructions, form, displacement, post


def _fixed_cs(entry: MachineState, domain: Real16ScalarDomain | None) -> int:
    """Use the derived component CS or a genuine concrete bootstrap selector."""
    if domain is not None:
        selector: int = domain.cs
        return selector
    term = entry.get("cs")
    literal = ssa_constant_terms.constant_bitvector(term) if isinstance(term, dict) else None
    if literal is None or literal[1] != 16:
        raise _Refusal(ControlScopeReason.DOMAIN, "bootstrap requires an exact native16 entry CS constant")
    bootstrap_selector: int = literal[0]
    return bootstrap_selector


def _entry_cutpoint(entry: MachineState, post: MachineState, head: int, size: int,
                    domain: Real16ScalarDomain | None, deadline: float, facts: list[ControlScopeFact],
                    ) -> tuple[z3.BoolRef, dict[str, z3.ExprRef], int]:
    """Prove a nonempty supplied-head premise and fixed CS through the block."""
    fixed_cs = _fixed_cs(entry, domain)
    base = fixed_cs << 4
    if not (base <= head and head + size <= base + 0x10000):
        raise _Refusal(ControlScopeReason.DOMAIN, "request outside fixed CS window")
    before, _, after = _terms(entry, entry, post)
    scalar = domain.predicate(before) if domain is not None else before["cs"] == fixed_cs
    premise = cast(z3.BoolRef, z3.And(scalar, before["control_ip"] == head))
    witness = _check(premise, deadline, witness=True)
    facts.append(ControlScopeFact(ControlScopeObligation.DOMAIN, witness))
    if witness is not ProofStatus.PROVED:
        raise _Refusal(ControlScopeReason.DOMAIN, "scalar entry/head cutpoint domain is empty or unknown")
    preserved = _check(z3.Implies(premise, after["cs"] == before["cs"]), deadline)
    if preserved is not ProofStatus.PROVED:
        facts[-1] = ControlScopeFact(ControlScopeObligation.DOMAIN, preserved,
                                     "native block does not preserve the fixed code selector")
        raise _Refusal(ControlScopeReason.DOMAIN, "native block does not preserve the fixed code selector")
    return premise, before, fixed_cs


def _control_target(data: bytes, head: int, entry: MachineState, post: MachineState,
                    instructions: tuple[capstone.CsInsn, ...], form: ControlForm, displacement: int,
                    fixed_cs: int, premise: z3.BoolRef,
                    before: dict[str, z3.ExprRef], deadline: float, facts: list[ControlScopeFact],
                    ) -> tuple[frozenset[int], frozenset[int], ProofStatus]:
    """Check the complete direct target set or actual pre-RET stack word."""
    if form is ControlForm.RETURN:
        prefix = data[:-instructions[-1].size]
        pre = _lift(prefix, head, entry, deadline)[1] if prefix else entry
        _, before_ret, after = _terms(entry, pre, post)
        preserved = _check(z3.Implies(premise, before_ret["cs"] == before["cs"]), deadline)
        if preserved is not ProofStatus.PROVED:
            facts[-1] = ControlScopeFact(ControlScopeObligation.FORM, preserved,
                                         "RET prefix changes the fixed code selector")
            raise _Refusal(ControlScopeReason.FORM, "RET prefix changes the fixed code selector")
        return frozenset(), frozenset(), _check(z3.Implies(premise, _ret_equation(before_ret, after)), deadline)
    expected = _expected(instructions[-1], form, displacement, fixed_cs)
    resolved = resolve_static_control(post["control_ip"], deadline=deadline)
    if not resolved.complete:
        if resolved.reason is recursive_static_control.StaticControlReason.OPAQUE and len(expected) == 1:
            # A CS-relative direct edge can remain symbolic in the native
            # state even after the entry cutpoint establishes its selector.
            # Prove its entire DWORD value under that already-discharged
            # premise; never replace it from decoded metadata alone.
            _, _, after = _terms(entry, entry, post)
            target = next(iter(expected))
            status = _check(z3.Implies(premise,
                                      after["control_ip"] == z3.BitVecVal(target, 32)), deadline)
            native = expected if status is ProofStatus.PROVED else frozenset()
            return expected, native, status
        raise _Refusal(ControlScopeReason.OPAQUE, f"native target: {resolved.reason.value}")
    native = resolved.targets
    status = ProofStatus.PROVED if native == expected else ProofStatus.COUNTEREXAMPLE
    return expected, native, status


def prove_native_control_scope(data: bytes, head: int, entry: MachineState,
                               domain: Real16ScalarDomain | None, *, deadline: float) -> NativeControlScope:
    """Check one near16 exit, assuming a nonempty execution cutpoint at head."""
    _validate_request(data, head, deadline)
    required = tuple(ControlScopeObligation)
    facts: list[ControlScopeFact] = []
    source = hashlib.sha256(data).hexdigest()
    entry_hash = hashlib.sha256(canonical_json_bytes(entry)).hexdigest()
    model = ""
    form: ControlForm | None = None
    fixed_cs: int | None = None
    expected = frozenset[int]()
    native = frozenset[int]()
    reason = ControlScopeReason.PROVED
    try:
        _time(deadline)
        model = native_control_model_hash()
        instructions, form, displacement, post = _source_effect(data, head, entry, deadline)
        facts.append(ControlScopeFact(ControlScopeObligation.SOURCE, ProofStatus.PROVED))
        # Reachability supplies this cutpoint head relation. Root initiation
        # and edge/frame closure must be consumed by the parent component.
        premise, before, fixed_cs = _entry_cutpoint(entry, post, head, len(data), domain, deadline, facts)
        facts.append(ControlScopeFact(ControlScopeObligation.FORM, ProofStatus.PROVED))
        expected, native, status = _control_target(data, head, entry, post, instructions, form,
                                                    displacement, fixed_cs, premise, before, deadline, facts)
        facts.append(ControlScopeFact(ControlScopeObligation.CONTROL, status))
        if status is not ProofStatus.PROVED:
            raise _Refusal(ControlScopeReason.CONTROL, "native loaded target differs from architectural WORD target")
        stable = source == hashlib.sha256(data).hexdigest() and model == native_control_model_hash()
        facts.append(ControlScopeFact(ControlScopeObligation.MODEL, ProofStatus.PROVED if stable else ProofStatus.UNKNOWN))
        if not stable:
            raise _Refusal(ControlScopeReason.MODEL, "source or coordinate model changed")
        _time(deadline)
    except _Refusal as refusal:
        reason = refusal.reason
        if len(facts) < len(required) and facts and facts[-1].status is not ProofStatus.PROVED:
            pass
        elif len(facts) < len(required):
            facts.append(ControlScopeFact(required[len(facts)], ProofStatus.UNKNOWN, str(refusal)))
    except S.LowerFailure as refusal:
        reason = ControlScopeReason.SOURCE
        if len(facts) < len(required):
            facts.append(ControlScopeFact(required[len(facts)], ProofStatus.UNKNOWN,
                                          f"{refusal.reason}: {refusal.message}"))
    facts.extend(ControlScopeFact(item, ProofStatus.UNKNOWN, "not attempted after prior refusal", False)
                 for item in required[len(facts):])
    failed = sum(row.status is not ProofStatus.PROVED for row in facts)
    status = (ProofStatus.PROVED if reason is ControlScopeReason.PROVED and failed == 0 else
              ProofStatus.COUNTEREXAMPLE if any(row.status is ProofStatus.COUNTEREXAMPLE for row in facts) else
              ProofStatus.UNKNOWN)
    return NativeControlScope(status, reason, source, entry_hash, model, head, len(data), domain, fixed_cs,
                              form, expected, native,
                              tuple(facts), FactCounters(len(required), len(required), len(required),
                                                        sum(row.attempted for row in facts), failed))

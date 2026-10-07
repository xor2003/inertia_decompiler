"""Synthetic contract tests for the declared ordered-I/O environment model.

No loaded executable or solver state is required. The tests exercise typed
contracts, event retention, and public premise binding using synthetic data.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
import pyvex

if TYPE_CHECKING:
    from tools.dosunit.contracts.proof_contracts import ObligationEvidence

from tools.dosunit.contracts.binary_environment import (
    EnvironmentEffect,
    active_ordered_io,
    decoded_io_events,
    decoded_machine_state,
    installed_ordered_io,
    part_io_events,
    requires_environment_contract,
    scoped_ordered_io,
)
from tools.dosunit.contracts.ordered_io_environment import (
    ORDERED_IO_MODEL,
    ORDERED_IO_MODEL_IDENTITY,
    ORDERED_IO_PREMISE_NAME,
    ORDERED_IO_VERSION,
    OrderedIoContract,
    declared_ordered_io,
    parse_ordered_io_identity,
    premise_identity,
)
from tools.dosunit.contracts.proof_contracts import Architecture

IN_AL_DX = bytes.fromhex("ec")
IN_AX_DX = bytes.fromhex("ed")
OUT_DX_AL = bytes.fromhex("ee")
INSB = bytes.fromhex("6c")
XOR_RET = bytes.fromhex("31c0c3")
CALLEE = bytes.fromhex("ec31c0c3")
CALLEE_EXTRA = bytes.fromhex("ecec31c0c3")
CALLEE_DIR = bytes.fromhex("ee31c0c3")
CALLEE_NOREAD = bytes.fromhex("31c0c3")


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": hex(value), "width": 16}


def _io_in(index: int, width: int = 8, port: int = 0x60) -> dict[str, object]:
    return {
        "op": "summary_io_in",
        "args": [
            {"op": "mem_input", "name": "io"},
            _const(index),
            _const(port),
            _const(width),
        ],
    }


def _io_out(index: int, width: int = 8, port: int = 0x60) -> dict[str, object]:
    return {
        "op": "summary_io_out",
        "args": [
            {"op": "mem_input", "name": "io"},
            _const(index),
            _const(port),
            {"op": "input", "name": "al"},
            _const(width),
        ],
    }


def _io_state(event: dict[str, object]) -> dict[str, object]:
    """Actual lowering state transition for one read or write term."""
    if event["op"] == "summary_io_out":
        return event
    return {"op": "summary_io_in_state", "args": [*event["args"], event]}


def _part(
    assignments: list[dict[str, object]],
    outputs: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build native-shaped ordered state unless outputs are explicitly supplied."""
    if outputs is not None:
        return {"id": "p0", "assignments": assignments, "outputs": outputs}
    current = {"op": "mem_input", "name": "io"}
    retained = []
    seen = []
    for event in assignments:
        if not isinstance(event, dict) or event.get("op") not in {"summary_io_in", "summary_io_out"}:
            retained.append(event)
            continue
        if event in seen:
            continue
        seen.append(event)
        linked = {**event, "args": [current, *event["args"][1:]]}
        retained.append(linked)
        current = _io_state(linked)
    return {"id": "p0", "assignments": retained, "outputs": {"io": current}}


# --- typed contract ----------------------------------------------------------


def test_contract_serialization_is_deterministic() -> None:
    """The contract serializes and digests deterministically."""
    model = declared_ordered_io(Architecture.REAL16)
    assert model.to_document() == declared_ordered_io(Architecture.REAL16).to_document()
    assert model.identity_digest() == declared_ordered_io(Architecture.REAL16).identity_digest()
    document = model.to_document()
    assert document["identity"] == ORDERED_IO_MODEL_IDENTITY
    assert document["model"] == ORDERED_IO_MODEL
    assert document["version"] == ORDERED_IO_VERSION
    assert document["architecture"] == Architecture.REAL16.value
    assert document["relation"] == "ordered_io_events"
    assert 8 in document["widths"]


def test_contract_architecture_content_is_bound() -> None:
    """Contract identity is bound to its declared architecture."""
    real = declared_ordered_io(Architecture.REAL16)
    flat = declared_ordered_io(Architecture.FLAT32)
    assert real.identity_digest() != flat.identity_digest()
    assert real.architecture is Architecture.REAL16
    real.validate_for(Architecture.REAL16)
    with pytest.raises(ValueError):
        real.validate_for(Architecture.FLAT32)


@pytest.mark.parametrize("field,value", [
    ("model", "other_model"),
    ("version", "v2"),
    ("widths", frozenset({64})),
    ("widths", frozenset()),
    ("effects", frozenset()),
    ("effects", frozenset({"summary_io_in"})),
    ("scalar_instruction_ids", frozenset({0x7FFFFFFF})),
    ("dirty_helpers", frozenset({"x86g_dirtyhelper_CLI"})),
])
def test_contract_rejects_malformed_content(field: str, value: object) -> None:
    """Malformed contract fields fail closed with ``ValueError``."""
    base = declared_ordered_io(Architecture.REAL16)
    fields = {
        "architecture": base.architecture,
        "model": base.model,
        "version": base.version,
        "widths": base.widths,
        "effects": base.effects,
        "scalar_instruction_ids": base.scalar_instruction_ids,
        "dirty_helpers": base.dirty_helpers,
    }
    fields[field] = value
    with pytest.raises(ValueError):
        OrderedIoContract(**fields)  # type: ignore[arg-type]


def test_identity_binding_is_exact() -> None:
    """Only the exact identity string parses; anything else refuses."""
    bound = parse_ordered_io_identity(ORDERED_IO_MODEL_IDENTITY, Architecture.FLAT32)
    assert bound.architecture is Architecture.FLAT32
    with pytest.raises(ValueError):
        parse_ordered_io_identity("dosunit.ordered_io.v0", Architecture.FLAT32)
    with pytest.raises(ValueError):
        parse_ordered_io_identity({"model": "ordered_scalar_port_io"}, Architecture.FLAT32)
    with pytest.raises(ValueError):
        parse_ordered_io_identity(None, Architecture.FLAT32)


def test_premise_is_explicit_and_unproved() -> None:
    """The environment premise is explicit and never claims proof."""
    model = declared_ordered_io(Architecture.REAL16)
    premise = model.premise_document()
    assert premise["kind"] == "declared_ordered_io_environment"
    assert premise["proved"] is False
    assert premise["model"] == model.to_document()
    assert premise_identity(premise) == model.identity_digest()
    assert premise_identity({}) is None
    assert premise_identity("text") is None


def test_event_and_helper_coverage() -> None:
    """Scalar IN/OUT and their helpers are covered; other forms are not."""
    from capstone.x86_const import X86_INS_IN, X86_INS_INSB, X86_INS_OUT

    model = declared_ordered_io(Architecture.REAL16)
    assert model.covers_event(EnvironmentEffect.PORT_READ, X86_INS_IN, 8)
    assert model.covers_event(EnvironmentEffect.PORT_WRITE, X86_INS_OUT, 16)
    assert not model.covers_event(EnvironmentEffect.PORT_READ, X86_INS_IN, None)
    assert not model.covers_event(EnvironmentEffect.PORT_READ, X86_INS_IN, 64)
    assert not model.covers_event(EnvironmentEffect.PORT_READ, X86_INS_INSB, 8)
    # Direction is bound to the instruction: set membership alone cannot alias
    # an IN for a write or an OUT for a read.
    assert not model.covers_event(EnvironmentEffect.PORT_WRITE, X86_INS_IN, 8)
    assert not model.covers_event(EnvironmentEffect.PORT_READ, X86_INS_OUT, 8)
    # A raw string cannot alias the typed effect enum (StrEnum equality).
    assert not model.covers_event("summary_io_in", X86_INS_IN, 8)  # type: ignore[arg-type]
    assert model.covers_helper("x86g_dirtyhelper_IN")
    assert model.covers_helper("x86g_dirtyhelper_OUT")
    assert not model.covers_helper("x86g_dirtyhelper_CLI")


# --- decoded ordered events ---------------------------------------------------


def test_decoded_events_preserve_order_and_direction() -> None:
    """Decoded events retain order, direction and width."""
    single = decoded_io_events(CALLEE, 0x100, mode_bits=16)
    assert single is not None and len(single) == 1
    event = single[0]
    assert event.effect is EnvironmentEffect.PORT_READ
    assert event.width_bits == 8
    assert event.address == 0x100
    double = decoded_io_events(CALLEE_EXTRA, 0x100, mode_bits=16)
    assert double is not None and len(double) == 2
    assert [e.effect for e in double] == [EnvironmentEffect.PORT_READ] * 2
    assert [e.address for e in double] == [0x100, 0x101]
    direction = decoded_io_events(CALLEE_DIR, 0x100, mode_bits=16)
    assert direction is not None and direction[0].effect is EnvironmentEffect.PORT_WRITE
    assert decoded_io_events(CALLEE_NOREAD, 0x100, mode_bits=16) == ()
    assert decoded_io_events(CALLEE, 0x100, mode_bits=32)[0].width_bits == 8
    wide = decoded_io_events(IN_AX_DX + b"\xc3", 0x100, mode_bits=16)
    assert wide is not None and wide[0].width_bits == 16


def test_changed_callee_sequences_differ() -> None:
    """Equivalent idioms match; added/removed/redirected events differ."""
    base = decoded_io_events(CALLEE, 0x100, mode_bits=16)
    equivalent = decoded_io_events(bytes.fromhex("ec33c0c3"), 0x100, mode_bits=16)
    assert base == equivalent  # xor vs xor-zero idiom is identical io semantics
    for variant in (CALLEE_EXTRA, CALLEE_DIR, CALLEE_NOREAD):
        assert decoded_io_events(variant, 0x100, mode_bits=16) != base


def test_string_io_is_decoded_but_never_covered() -> None:
    """String I/O is decoded as an effect but outside the scalar model."""
    events = decoded_io_events(INSB + b"\xc3", 0x100, mode_bits=16)
    assert events is not None and len(events) == 1
    assert events[0].effect is EnvironmentEffect.PORT_READ
    assert events[0].width_bits is None
    assert not declared_ordered_io(Architecture.REAL16).covers_event(
        events[0].effect, events[0].instruction_id, events[0].width_bits
    )


def test_decoding_fails_closed() -> None:
    """Empty input or bad mode refuses instead of guessing."""
    assert decoded_io_events(b"", 0x100, mode_bits=16) is None
    assert decoded_io_events(CALLEE, 0x100, mode_bits=13) is None


def test_machine_state_instructions_are_flagged() -> None:
    """Unmodeled machine-state instructions are reported by address."""
    # HLT + two HLTs separated by a nop: every flagged address is retained.
    assert decoded_machine_state(bytes.fromhex("f490f4c3"), 0x100, mode_bits=16) == (0x100, 0x102)
    assert decoded_machine_state(CALLEE, 0x100, mode_bits=16) == ()
    assert decoded_machine_state(b"", 0x100, mode_bits=16) is None


# --- SSA event extraction -----------------------------------------------------


def test_part_io_events_ordered_sequence() -> None:
    """SSA parts yield ordered ``(index, effect, width)`` event records."""
    part = _part([_io_in(0), _io_out(1)])
    assert part_io_events(part) == (
        (0, EnvironmentEffect.PORT_READ, 8),
        (1, EnvironmentEffect.PORT_WRITE, 8),
    )


def test_part_io_events_empty_without_io() -> None:
    """Parts without I/O terms produce an empty sequence."""
    assert part_io_events(_part([{"op": "add", "args": []}])) == ()
    assert part_io_events({"id": "p0"}) == ()


def test_part_io_events_rejects_dropped_or_duplicated_index() -> None:
    """Skipped indices or conflicting same-index terms refuse."""
    assert part_io_events(_part([_io_in(1)])) is None
    # The same index on a *different* term is corruption; a byte-identical
    # duplicate is the same materialized term seen twice and dedupes.
    assert part_io_events(_part([_io_in(0, port=0x60), _io_in(0, port=0x61)])) is None
    assert part_io_events(_part([_io_in(0), _io_in(0)])) == (
        (0, EnvironmentEffect.PORT_READ, 8),
    )
    assert part_io_events(_part([_io_in(0), _io_out(2)])) is None


def test_part_io_events_rejects_malformed_terms() -> None:
    """Malformed structure or non-constant index/width refuses."""
    bad_index = _io_in(0)
    bad_index["args"][1] = {"op": "input", "name": "x"}
    assert part_io_events(_part([bad_index])) is None
    bad_width = _io_in(0)
    bad_width["args"][3] = {"op": "input", "name": "x"}
    assert part_io_events(_part([bad_width])) is None
    assert part_io_events(_part(["oops"])) is None
    conflicting = _part([_io_in(0)], outputs={"io": _io_out(0)})
    assert part_io_events(conflicting) is None


def test_part_io_events_outputs_must_be_native_mapping() -> None:
    """Native SSA ``outputs`` is a name→term mapping; a list is malformed."""
    assert part_io_events({"assignments": [], "outputs": [_io_in(0)]}) is None
    # A sampled value is not the ordered state transition retaining that read.
    assert part_io_events(_part([], outputs={"io": _io_in(0)})) is None
    assert part_io_events(_part([], outputs={"io": _io_state(_io_in(0))})) == (
        (0, EnvironmentEffect.PORT_READ, 8),
    )


def test_part_io_events_finds_output_embedded_terms() -> None:
    """Event terms nested inside output mapping values are discovered."""
    part = _part([], outputs={"io": {"op": "wrap", "args": [_io_in(0)]}})
    assert part_io_events(part) is None


def test_part_io_events_dedupes_assignment_and_output_aliases() -> None:
    """An event materialized as an assignment and again in outputs dedupes.

    Byte-identical alias terms are the same event seen twice; a different
    term claiming the same index is corruption and still refuses.
    """
    event = _io_in(0)
    part = _part([dict(event)], outputs={"io": _io_state(dict(event))})
    assert part_io_events(part) == ((0, EnvironmentEffect.PORT_READ, 8),)
    conflict = _part([dict(event)], outputs={"io": _io_in(0, port=0x61)})
    assert part_io_events(conflict) is None


def test_part_io_events_nested_chain_retains_every_read() -> None:
    """An inline ``io`` chain retains predecessor events, incl. dead reads.

    ``summary_io_in_state`` wraps the read term and the prior chain; an
    event term must still descend into its own ``io`` operand or nested
    predecessors would be silently dropped.
    """
    read = _io_in(0)
    state = {"op": "summary_io_in_state", "args": [*read["args"], read]}
    write = _io_out(1)
    write["args"][0] = state
    part = _part([], outputs={"io": write})
    assert part_io_events(part) == (
        (0, EnvironmentEffect.PORT_READ, 8),
        (1, EnvironmentEffect.PORT_WRITE, 8),
    )


# --- ambient binding -----------------------------------------------------------


def test_installed_binding_scope_and_release() -> None:
    """Ambient bindings scope correctly and always release."""
    model = declared_ordered_io(Architecture.REAL16)
    assert active_ordered_io() is None
    with installed_ordered_io(model):
        assert active_ordered_io() is model
        with scoped_ordered_io(model):
            assert active_ordered_io() is model
        other_lane = declared_ordered_io(Architecture.FLAT32)
        with pytest.raises(ValueError), scoped_ordered_io(other_lane):
            pass
        with pytest.raises(ValueError), installed_ordered_io(model):
            pass
    assert active_ordered_io() is None
    with scoped_ordered_io(model):
        assert active_ordered_io() is model
    assert active_ordered_io() is None
    with pytest.raises(ValueError), installed_ordered_io("not-a-contract"):
        pass


def test_binding_is_context_local_across_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    """An independent thread never observes another comparison's binding."""
    import threading

    class FakeDirty:
        pass

    monkeypatch.setattr(pyvex.stmt, "Dirty", FakeDirty)
    dirty = FakeDirty()
    dirty.cee = SimpleNamespace(name="x86g_dirtyhelper_IN")
    irsb = SimpleNamespace(statements=[dirty])
    observed: list[object] = []
    refused: list[bool] = []

    def probe() -> None:
        observed.append(active_ordered_io())
        refused.append(requires_environment_contract(irsb))

    model = declared_ordered_io(Architecture.REAL16)
    with installed_ordered_io(model):
        worker = threading.Thread(target=probe)
        worker.start()
        worker.join()
        assert active_ordered_io() is model
        assert not requires_environment_contract(irsb)
    assert observed == [None]
    assert refused == [True]
    assert active_ordered_io() is None


def test_dirty_helper_gate_requires_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    """I/O dirty helpers need a covering ambient binding to admit."""
    class FakeDirty:
        pass

    monkeypatch.setattr(pyvex.stmt, "Dirty", FakeDirty)
    dirty = FakeDirty()
    dirty.cee = SimpleNamespace(name="x86g_dirtyhelper_IN")
    unknown = FakeDirty()
    unknown.cee = SimpleNamespace(name="x86g_dirtyhelper_CLI")
    irsb = SimpleNamespace(statements=[dirty])
    assert requires_environment_contract(irsb)
    model = declared_ordered_io(Architecture.REAL16)
    with installed_ordered_io(model):
        assert not requires_environment_contract(irsb)
        mixed = SimpleNamespace(statements=[dirty, unknown])
        assert requires_environment_contract(mixed)
    assert requires_environment_contract(irsb)


# --- conditional premise marking -------------------------------------------------


def _evidence_row(status: object) -> ObligationEvidence:
    """Minimal proved/unknown evidence row for premise-binding tests."""
    from tools.dosunit.contracts.proof_contracts import (
        ContractIdentity,
        FactCounters,
        ObligationEvidence,
        ObligationId,
    )

    return ObligationEvidence(
        id=ObligationId("function", "caller"),
        contract=ContractIdentity(Architecture.REAL16, "a" * 8, "b" * 8, "c" * 8, "d" * 8, "e" * 8),
        status=status,
        reason="leaf",
        counters=FactCounters(1, 1, 1, 1, 0),
    )


def test_bind_io_premise_marks_consumed_row_conditional() -> None:
    """A PROVED row consuming I/O becomes CONDITIONAL."""
    from tools.dosunit.contracts.proof_contracts import ProofStatus
    from tools.dosunit.compare.real16_binary_compare import _bind_io_premise

    model = declared_ordered_io(Architecture.REAL16)
    document = {"functions": [
        {**_part([_io_in(0)]), "function": {"id": "caller", "name": "caller"}},
    ]}
    row = _bind_io_premise(_evidence_row(ProofStatus.PROVED), "caller", model, document, None)
    assert row.status is ProofStatus.CONDITIONAL
    assert row.reason == "ordered_io_environment_premise"
    assert ORDERED_IO_PREMISE_NAME in row.assumptions


def test_bind_io_premise_marks_backend_consumed_row() -> None:
    """Backend-recorded premise consumption is marked too."""
    from tools.dosunit.contracts.proof_contracts import ProofStatus
    from tools.dosunit.compare.real16_binary_compare import _bind_io_premise

    model = declared_ordered_io(Architecture.REAL16)
    document = {"functions": []}
    backend = {"environment": {"premise": model.premise_document()}}
    row = _bind_io_premise(_evidence_row(ProofStatus.PROVED), "caller", model, document, backend)
    assert row.status is ProofStatus.CONDITIONAL
    assert ORDERED_IO_PREMISE_NAME in row.assumptions


def test_bind_io_premise_keeps_unconsumed_proved() -> None:
    """Rows without I/O consumption stay unchanged."""
    from tools.dosunit.contracts.proof_contracts import ProofStatus
    from tools.dosunit.compare.real16_binary_compare import _bind_io_premise

    model = declared_ordered_io(Architecture.REAL16)
    document = {"functions": [
        {**_part([{"op": "add", "args": []}]), "function": {"id": "caller"}},
    ]}
    row = _bind_io_premise(_evidence_row(ProofStatus.PROVED), "caller", model, document, {})
    assert row.status is ProofStatus.PROVED
    assert ORDERED_IO_PREMISE_NAME not in row.assumptions
    unbound = _bind_io_premise(row, "caller", None, document, {})
    assert unbound.status is ProofStatus.PROVED
    refused = _bind_io_premise(_evidence_row(ProofStatus.UNKNOWN), "caller", model, document, {})
    assert refused.status is ProofStatus.UNKNOWN


def test_conditional_io_verdict_records_premise() -> None:
    """The flat32 retry seam converts passed verdicts to conditional."""
    from tools.dosunit.compare.flat32_proof_retry import _conditional_io_verdict

    model = declared_ordered_io(Architecture.FLAT32)
    verdict = _conditional_io_verdict({"status": "passed", "reason": "equal"}, model)
    assert verdict["status"] == "conditional"
    assert verdict["backend_status"] == "passed"
    assert verdict["reason"] == "ordered_io_environment_premise"
    assert verdict["environment_premise"]["relation_identity"] == model.identity_digest()
    assert verdict["assumptions"][ORDERED_IO_PREMISE_NAME]["proved"] is False


def test_public_domain_binds_io_premise() -> None:
    """The public domain document records the ordered-I/O premise."""
    from tools.dosunit.reporting.proof_public_domain import OutputDeclarationSource, flat32_public_domain

    model = declared_ordered_io(Architecture.FLAT32)
    bound = flat32_public_domain(
        outputs=("eax",), register_source=OutputDeclarationSource.CALLER_DECLARED,
        ordered_io=model,
    )
    plain = flat32_public_domain(
        outputs=("eax",), register_source=OutputDeclarationSource.CALLER_DECLARED,
    )
    assert bound.to_document() != plain.to_document()
    env = bound.to_document()["environment"]
    assert env["external_effects"] == "compared"
    assert any(
        premise_identity(item) == model.identity_digest() for item in env["premise"]
    )
    assert plain.to_document()["environment"]["external_effects"] == "refused"


# --- retained SSA receipts at the flat32 coverage seam ------------------------


def _fake_project(blocks: dict[int, bytes]) -> object:
    """Minimal project seam: real pyvex lift over recorded bytes, no angr."""
    import archinfo

    class _Factory:
        def block(self, address: int, size: int | None = None, opt_level: int = 0) -> object:
            code = blocks[address] if size is None else blocks[address][:size]
            return SimpleNamespace(
                vex=pyvex.IRSB(data=code, mem_addr=address, arch=archinfo.ArchX86()),
                bytes=code,
            )

    return SimpleNamespace(arch=SimpleNamespace(name="x86", bits=32), factory=_Factory())


def _coverage_record(
    address: int, code: bytes, receipt: dict[str, object] | None = None
) -> dict[str, object]:
    record: dict[str, object] = {
        "entry": {"linear": hex(address)},
        "source": {"machine_code_size": len(code)},
    }
    if receipt is not None:
        record.update(receipt)
    return record


def _read_receipt(index: int = 0, width: int = 8, op: str = "in") -> dict[str, object]:
    event = _io_in(index, width=width) if op == "in" else _io_out(index, width=width)
    part = _part([event])
    return {"assignments": part["assignments"], "outputs": part["outputs"]}


def test_scan_lowered_parts_accepts_retained_events() -> None:
    """A retained SSA receipt matching the decoded sequence passes."""
    from tools.dosunit.contracts.binary_environment import scan_lowered_parts

    model = declared_ordered_io(Architecture.FLAT32)
    project = _fake_project({0x100: CALLEE})
    part = _coverage_record(0x100, CALLEE, receipt=_read_receipt())
    scan = scan_lowered_parts(project, [part], io_model=model)
    assert scan.complete and not scan.requires_contract
    assert not scan.mismatched
    assert [event.effect for event in scan.events] == [EnvironmentEffect.PORT_READ]


def test_scan_lowered_parts_multiple_events_in_order() -> None:
    """Repeated reads (including a dead read) must all survive in order."""
    from tools.dosunit.contracts.binary_environment import scan_lowered_parts

    model = declared_ordered_io(Architecture.FLAT32)
    project = _fake_project({0x100: CALLEE_EXTRA})
    receipt = _part([_io_in(0), _io_in(1)])
    scan = scan_lowered_parts(project, [_coverage_record(0x100, CALLEE_EXTRA, receipt)], io_model=model)
    assert scan.complete and not scan.requires_contract and not scan.mismatched
    dropped = {"assignments": [dict(_io_in(0))], "outputs": {}}
    scan = scan_lowered_parts(
        project, [_coverage_record(0x100, CALLEE_EXTRA, dropped)], io_model=model
    )
    assert scan.requires_contract and scan.mismatched == ("0x100",)


def test_scan_lowered_parts_refuses_dropped_event() -> None:
    """A removed SSA event refuses even with identical bytes and range."""
    from tools.dosunit.contracts.binary_environment import scan_lowered_parts

    model = declared_ordered_io(Architecture.FLAT32)
    project = _fake_project({0x100: CALLEE})
    dropped = _coverage_record(0x100, CALLEE, receipt={"assignments": [], "outputs": {}})
    scan = scan_lowered_parts(project, [dropped], io_model=model)
    assert scan.requires_contract and scan.mismatched == ("0x100",)


def test_scan_lowered_parts_refuses_wrong_width_and_direction() -> None:
    """Retained events with wrong width or direction refuse."""
    from tools.dosunit.contracts.binary_environment import scan_lowered_parts

    model = declared_ordered_io(Architecture.FLAT32)
    project = _fake_project({0x100: CALLEE})
    for receipt in (_read_receipt(width=16), _read_receipt(op="out")):
        scan = scan_lowered_parts(
            project, [_coverage_record(0x100, CALLEE, receipt)], io_model=model
        )
        assert scan.requires_contract and scan.mismatched == ("0x100",)


def test_scan_lowered_parts_refuses_missing_or_invalid_receipt() -> None:
    """Byte ranges alone, misbound or malformed receipts refuse under model."""
    from tools.dosunit.contracts.binary_environment import scan_lowered_parts

    model = declared_ordered_io(Architecture.FLAT32)
    project = _fake_project({0x100: CALLEE})
    bare = _coverage_record(0x100, CALLEE)
    scan = scan_lowered_parts(project, [bare], io_model=model)
    assert scan.requires_contract and scan.mismatched == ("0x100",)
    malformed = _coverage_record(0x100, CALLEE, receipt={"assignments": [_io_in(1)]})
    scan = scan_lowered_parts(project, [malformed], io_model=model)
    assert scan.requires_contract and scan.mismatched == ("0x100",)
    misbound = {**_coverage_record(0x100, CALLEE), "receipt_bound": False}
    scan = scan_lowered_parts(project, [misbound], io_model=model)
    assert scan.requires_contract and scan.mismatched == ("0x100",)
    wrong_shape = _coverage_record(0x100, CALLEE, receipt={"outputs": [_io_in(0)]})
    scan = scan_lowered_parts(project, [wrong_shape], io_model=model)
    assert scan.requires_contract and scan.mismatched == ("0x100",)


def test_scan_lowered_parts_no_io_part_needs_no_receipt() -> None:
    """A byte-range-only part whose bytes decode no events passes vacuously."""
    from tools.dosunit.contracts.binary_environment import scan_lowered_parts

    model = declared_ordered_io(Architecture.FLAT32)
    project = _fake_project({0x100: XOR_RET})
    bare = _coverage_record(0x100, XOR_RET)
    scan = scan_lowered_parts(project, [bare], io_model=model)
    assert scan.complete and not scan.requires_contract and not scan.mismatched
    empty_receipt = _coverage_record(0x100, XOR_RET, receipt={"assignments": [], "outputs": {}})
    scan = scan_lowered_parts(project, [empty_receipt], io_model=model)
    assert scan.complete and not scan.requires_contract


def test_scan_lowered_parts_no_contract_behavior_unchanged() -> None:
    """Without a binding, any decoded port event still requires a contract."""
    from tools.dosunit.contracts.binary_environment import scan_lowered_parts

    project = _fake_project({0x100: CALLEE, 0x200: XOR_RET})
    with_receipt = _coverage_record(0x100, CALLEE, receipt=_read_receipt())
    scan = scan_lowered_parts(project, [with_receipt])
    assert scan.complete and scan.requires_contract
    bare = _coverage_record(0x100, CALLEE)
    assert scan_lowered_parts(project, [bare]).requires_contract
    assert not scan_lowered_parts(project, [_coverage_record(0x200, XOR_RET)]).requires_contract


def test_environment_parts_retains_source_bound_receipt() -> None:
    """Composed-call coverage carries the block's lowered SSA receipt."""
    from tools.dosunit.compare.flat32_call_contracts import _LiftedBlock
    from tools.dosunit.compare.flat32_environment_coverage import environment_parts

    receipt_part = {
        "entry": {"linear": hex(0x100)},
        "source": {"machine_code_size": 4},
        "assignments": [_io_in(0)],
        "outputs": {"io": _io_in(0)},
    }
    block = _LiftedBlock(0x100, SimpleNamespace(size=4), receipt_part, "Ijk_Ret", (), None, None)
    (record,) = environment_parts({0x100: block})
    assert record["assignments"] == [_io_in(0)]
    assert record["outputs"] == {"io": _io_in(0)}
    plain = SimpleNamespace(irsb=SimpleNamespace(size=4))
    (bare,) = environment_parts({0x100: plain})
    assert set(bare) == {"entry", "source"}
    foreign = _LiftedBlock(
        0x100, SimpleNamespace(size=4),
        {**receipt_part, "entry": {"linear": hex(0x200)}},
        "Ijk_Ret", (), None, None,
    )
    (bad,) = environment_parts({0x100: foreign})
    assert bad["receipt_bound"] is False and "assignments" not in bad
    nonmapping = _LiftedBlock(0x100, SimpleNamespace(size=4), "corrupt", "Ijk_Ret", (), None, None)
    (bad2,) = environment_parts({0x100: nonmapping})
    assert bad2["receipt_bound"] is False
    spoof = SimpleNamespace(irsb=SimpleNamespace(size=4), part=receipt_part)
    (unowned,) = environment_parts({0x100: spoof})
    assert set(unowned) == {"entry", "source"}


def test_checked_environment_verdict_gates_on_retained_receipt() -> None:
    """The composed-call coverage gate refuses a silently dropped event."""
    from tools.dosunit.compare.flat32_proof_retry import checked_environment_verdict

    model = declared_ordered_io(Architecture.FLAT32)
    project = _fake_project({0x100: CALLEE})
    good = _coverage_record(0x100, CALLEE, receipt=_read_receipt())
    context = (project, project, {}, {})
    verdict = {"status": "passed",
               "environment_coverage": {"oracle": [good], "candidate": [dict(good)]}}
    out = checked_environment_verdict(dict(verdict), context, [], [], io_model=model)
    assert out["status"] == "conditional"
    assert out["reason"] == "ordered_io_environment_premise"
    dropped = _coverage_record(0x100, CALLEE, receipt={"assignments": [], "outputs": {}})
    refused = checked_environment_verdict(
        {"status": "passed",
         "environment_coverage": {"oracle": [good], "candidate": [dropped]}},
        context, [], [], io_model=model,
    )
    assert refused == {"status": "refused", "reason": "external_environment_contract_required"}
    bare = _coverage_record(0x100, CALLEE)
    refused_bare = checked_environment_verdict(
        {"status": "passed",
         "environment_coverage": {"oracle": [bare], "candidate": [bare]}},
        context, [], [], io_model=model,
    )
    assert refused_bare["status"] == "refused"


@pytest.mark.parametrize("entrypoint", ["compare", "summarize", "lookup", "groups"])
def test_low_level_real16_rejects_flat32_contract_before_work(entrypoint: str) -> None:
    """Wrong-lane declarations reject before even reading malformed documents."""
    from tools.dosunit.compare.real16_call_composition import compare_real16_with_calls
    from tools.dosunit.compare.real16_call_contracts import Real16CallLimits
    from tools.dosunit.compare.real16_call_evidence import group_functions, group_lookup
    from tools.dosunit.compare.real16_call_execution import summarize

    wrong = declared_ordered_io(Architecture.FLAT32)
    with pytest.raises(ValueError, match="does not match lane"):
        if entrypoint == "compare":
            compare_real16_with_calls(None, None, "f", io_model=wrong)
        elif entrypoint == "summarize":
            summarize(None, "f", limits=Real16CallLimits(), timeout_ms=1, io_model=wrong)
        elif entrypoint == "lookup":
            group_lookup(None, "f", io_model=wrong)
        else:
            group_functions(None, io_model=wrong)


@pytest.mark.parametrize("entrypoint", ["environment", "retry"])
def test_low_level_flat32_rejects_real16_contract_before_work(entrypoint: str) -> None:
    """Wrong-lane bindings reject before touching verdicts or proof context."""
    from tools.dosunit.compare.flat32_proof_retry import checked_environment_verdict, retry_function_proof

    wrong = declared_ordered_io(Architecture.REAL16)
    with pytest.raises(ValueError, match="does not match lane"):
        if entrypoint == "environment":
            checked_environment_verdict(None, None, [], [], io_model=wrong)
        else:
            retry_function_proof("f", None, None, (), 1, io_model=wrong)


@pytest.mark.parametrize("binding_kind", ["absent", "different", "matching"])
def test_public_flat32_binding_cannot_silently_inherit(
    binding_kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public declarations must equal ambient premises before any source work."""
    from argparse import Namespace
    from dataclasses import replace
    from pathlib import Path

    import tools.dosunit.reporting.flat32_proof_report as flat32_proof_report

    model = declared_ordered_io(Architecture.FLAT32)
    binding = None if binding_kind == "absent" else model
    if binding_kind == "different":
        binding = replace(model, widths=frozenset({8}))
    args = Namespace(entry_esp_range=None, ordered_io_environment=binding)

    def source_work(_driver: Path) -> dict:
        raise RuntimeError("source_work_reached")

    monkeypatch.setattr(flat32_proof_report, "_semantic_sources", source_work)
    error = RuntimeError if binding_kind == "matching" else ValueError
    message = "source_work_reached" if binding_kind == "matching" else "conflicts with ambient binding"
    with installed_ordered_io(model), pytest.raises(error, match=message):
        flat32_proof_report.run_bound_comparison(lambda _args: {}, args, Path("unused"))
    assert active_ordered_io() is None


@pytest.mark.parametrize("binding_kind", ["absent", "different", "matching"])
def test_public_real16_binding_cannot_silently_inherit(
    binding_kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real16 execution and sealing share the explicitly declared premise."""
    from dataclasses import replace
    from pathlib import Path

    import tools.dosunit.compare.real16_binary_compare as real16_binary_compare
    from tools.dosunit.contracts.model import DosUnitError

    model = declared_ordered_io(Architecture.REAL16)
    binding = None if binding_kind == "absent" else model
    if binding_kind == "different":
        binding = replace(model, widths=frozenset({8}))

    def source_work(*args: object, **kwargs: object) -> dict:
        assert active_ordered_io() == model
        raise RuntimeError("source_work_reached")

    monkeypatch.setattr(real16_binary_compare, "_compare_binary16", source_work)
    error = RuntimeError if binding_kind == "matching" else DosUnitError
    message = "source_work_reached" if binding_kind == "matching" else "conflicts with ambient binding"
    with installed_ordered_io(model), pytest.raises(error, match=message):
        real16_binary_compare.compare_binary16(
            Path("unused"), Path("unused"), {}, {}, ordered_io_environment=binding,
        )
    assert active_ordered_io() is None


@pytest.mark.parametrize("lane", [Architecture.REAL16, Architecture.FLAT32])
def test_public_domain_rejects_wrong_ordered_io_architecture(lane: Architecture) -> None:
    """Domain serialization cannot publish a premise belonging to another ISA."""
    from tools.dosunit.reporting.proof_public_domain import (
        OutputDeclarationSource,
        flat32_public_domain,
        real16_public_domain,
    )

    wrong_lane = Architecture.FLAT32 if lane is Architecture.REAL16 else Architecture.REAL16
    model = declared_ordered_io(wrong_lane)
    with pytest.raises(ValueError, match="does not match lane"):
        if lane is Architecture.REAL16:
            real16_public_domain(registers=(), ordered_io=model)
        else:
            flat32_public_domain(
                outputs=(), register_source=OutputDeclarationSource.CALLER_DECLARED,
                ordered_io=model,
            )


def _materialized_reads(count: int) -> dict:
    """Use the owned SSA materializer to produce real ref-linked I/O receipts."""
    import tools.dosunit.compare.straightline_ssa as S

    state = S.SsaExpr("mem_input", 0, name="io")
    for index in range(count):
        args = (state, S.SsaExpr("const", 16, value=index),
                S.SsaExpr("input", 16, name="dx"), S.SsaExpr("const", 16, value=8))
        read = S.SsaExpr("summary_io_in", 8, args)
        state = S.SsaExpr("summary_io_in_state", 0, (*args, read))
    assignments = []
    output = S._materialize(state, assignments=assignments, memo={}, object_memo={},
                            max_assignments_per_function=128)
    return {"assignments": assignments, "outputs": {"io": output}}


@pytest.mark.parametrize("count", [1, 2])
def test_materialized_dead_reads_reach_final_io_state(count: int) -> None:
    """Shared ref-linked state retains each read even without a sampled-value output."""
    part = _materialized_reads(count)
    assert part_io_events(part) == tuple((i, EnvironmentEffect.PORT_READ, 8) for i in range(count))


@pytest.mark.parametrize("damage", ["reset", "removed_predecessor", "hidden_value", "missing_ref", "cycle"])
def test_materialized_trace_loss_refuses(damage: str) -> None:
    """Assignment inventory cannot stand in for the final compared I/O chain."""
    from tools.dosunit.contracts.binary_environment import scan_lowered_parts

    part = _materialized_reads(2)
    initial = {"op": "mem_input", "name": "io"}
    reads = [a for a in part["assignments"] if a.get("op") == "summary_io_in"]
    states = [a for a in part["assignments"] if a.get("op") == "summary_io_in_state"]
    if damage == "reset":
        part["outputs"]["io"] = initial
    elif damage == "hidden_value":
        part["outputs"]["eax"] = {"ref": reads[-1]["id"]}
        part["outputs"]["io"] = initial
    elif damage == "removed_predecessor":
        states[-1]["args"][0] = initial
        reads[-1]["args"][0] = initial
    elif damage == "missing_ref":
        part["outputs"]["io"] = {"ref": "missing"}
    else:
        states[-1]["args"][0] = {"ref": states[-1]["id"]}
        reads[-1]["args"][0] = {"ref": states[-1]["id"]}
    assert part_io_events(part) is None
    scan = scan_lowered_parts(
        _fake_project({0x100: CALLEE_EXTRA}),
        [_coverage_record(0x100, CALLEE_EXTRA, part)],
        io_model=declared_ordered_io(Architecture.FLAT32),
    )
    assert scan.complete and scan.requires_contract and scan.mismatched == ("0x100",)

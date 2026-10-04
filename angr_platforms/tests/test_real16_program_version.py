"""Actual initialized MZ DOS-version-query controls; agreement is concrete only."""

from dataclasses import replace

import pytest
from test_real16_program_replay import environment, mz

from tools.dosunit.real16_program_boot import ProgramEnvironment, program_from_mz_bytes
from tools.dosunit.real16_program_manifest import parse_program_manifest
from tools.dosunit.real16_program_model import (
    ProgramAgreement,
    ProgramEvent,
    ProgramEventKind,
    ProgramObservation,
    ProgramStatus,
    compare_programs,
)
from tools.dosunit.real16_program_replay import replay_program
from tools.dosunit.real16_program_version import (
    VERSION_EVENT_BYTES,
    VersionAnswered,
    VersionPolicy,
    VersionRefusal,
    VersionRefused,
    parse_version_policy,
    program_version_query,
    version_event_data,
    version_policy_document,
)
from tools.dosunit.real16_replay_model import LinearRange

# mov eax,0x12345678; mov ebx,0x9ABCDEF0; mov ecx,0x01234567;
# xor al,al; mov ah,0x30; stc; int 0x21; mov al,7; mov ah,0x4c; int 0x21
QUERY_EXIT = "66b87856341266bbf0debc9a66b96745230132c0b430f9cd21b007b44ccd21"
QUERY_ADDRESS = 0x10117  # linear address of the first int 0x21 in QUERY_EXIT
DECLARED = {"major": 3, "minor": 30, "oem": 0x42, "serial24": 0x123456}
# answered response: AX=(minor<<8)|major=0x1E03, BX=(oem<<8)|serial_hi=0x4212, CX=serial_lo=0x3456
EXPECTED_EVENT = "213000031e42563412"  # int21, ah30, al00 + major/minor/oem + serial little-endian


def version_environment(**overrides):
    fields = dict(DECLARED)
    fields.update(overrides)
    base = environment()
    return parse_program_manifest({
        "schema": "dosunit.real16_program_environment.v1",
        "environment": {"psp_segment": base.psp_segment,
                        "allocation_hex": base.allocation.hex(),
                        "registers": dict(base.registers), "fs": 0, "gs": 0,
                        "dos_version": fields},
    }).environment


def sentinel_environment(*, version=True):
    arena = bytearray(b"\xA5" * 0x10100)
    arena[:2] = b"\xCD\x20"
    arena[2:4] = (0x1200).to_bytes(2, "little")
    # eax's low half is the declared selector AX=0x3000 so AH30/AL00 routes in.
    values = (("eax", 0x12343000), ("ebx", 0x9ABCDEF0), ("ecx", 0x01234567), ("edx", 0xDEADBEEF),
              ("esi", 0), ("edi", 0), ("ebp", 0), ("esp", 0), ("eflags", 2))
    return ProgramEnvironment(0x1000, bytes(arena), values, 0, 0,
                              version_policy=VersionPolicy(DECLARED["major"], DECLARED["minor"],
                                                           DECLARED["oem"], DECLARED["serial24"])
                              if version else None)


def execute(code, *, env=None, entry_ip=0, limit=200):
    if isinstance(code, str):
        code = bytes.fromhex(code)
    boot = program_from_mz_bytes(mz(code, entry_ip=entry_ip), version_environment() if env is None else env)
    return replay_program(boot, observations=(ProgramObservation("buffer", LinearRange(0x10200, 4)),),
                          instruction_limit=limit)


def test_declared_version_query_answers_and_preserves_all_unowned_state():
    result = execute(QUERY_EXIT)
    assert result.status is ProgramStatus.TERMINATED
    assert result.exit_code == 7
    assert result.instructions == 10
    regs = dict(result.registers)
    # Documented low halves: AX=(minor<<8)|major, BX=(oem<<8)|serial_hi, CX=serial_lo;
    # then exit sets AL=7/AH=0x4C. Every upper half is preserved untouched.
    assert regs["eax"] == 0x12344C07
    assert regs["ebx"] == 0x9ABC4212
    assert regs["ecx"] == 0x01233456
    assert regs["edx"] == 0
    # stc + xor results survive the query: the service writes no flag.
    assert regs["eflags"] == 0x47
    assert (regs["cs"], regs["ss"], regs["ds"], regs["es"]) == (0x1010, 0x1010, 0x1000, 0x1000)
    # Response writes no buffer; executed interrupts retain architectural frames.
    assert result.writes == ((0x110FA, bytes.fromhex("1f0010104700")),)
    assert result.observations == (("buffer", b"\x03\xa5\xa5\xa5"),)  # arena[0x200]=3 declared byte
    query, exit_event = result.events
    assert query.kind is ProgramEventKind.DOS_VERSION
    assert query.address == QUERY_ADDRESS
    assert query.data.hex() == EXPECTED_EVENT
    assert exit_event.kind is ProgramEventKind.DOS_EXIT
    assert compare_programs(result, result) is ProgramAgreement.AGREED


def test_policy_absent_version_query_still_refuses():
    result = execute(QUERY_EXIT, env=environment())
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.instructions == 7
    event = result.events[0]
    assert event.kind is ProgramEventKind.UNSUPPORTED_INSTRUCTION
    assert event.address == QUERY_ADDRESS
    assert event.data == b"\xcd\x21"
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


@pytest.mark.parametrize("ax", [0x3001, 0x30FF])
def test_other_al_selectors_are_explicit_typed_refusals(ax):
    result = execute(f"b8{ax & 0xFF:02x}{ax >> 8:02x}cd21b007b44ccd21")
    assert result.status is ProgramStatus.UNSUPPORTED
    event = result.events[0]
    assert event.kind is ProgramEventKind.UNSUPPORTED_INSTRUCTION
    assert event.data == VersionRefusal.UNSUPPORTED_SELECTOR.value.encode()
    # No partial mutation: the query answer registers are never written.
    assert dict(result.registers)["ax"] == ax
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


@pytest.mark.parametrize("ax", [0x0900, 0x3100, 0x1900, 0x6200])
def test_other_int21_services_refuse_unchanged(ax):
    result = execute(f"b8{ax & 0xFF:02x}{ax >> 8:02x}cd21b007b44ccd21")
    assert result.status is ProgramStatus.UNSUPPORTED
    event = result.events[0]
    assert event.kind is ProgramEventKind.UNSUPPORTED_INSTRUCTION
    assert event.data == b"\xcd\x21"


@pytest.mark.parametrize("values", [
    (True, 30, 0, 0), (1, 30, 0, 0), (256, 30, 0, 0), (-1, 30, 0, 0), (3.0, 30, 0, 0), ("3", 30, 0, 0),
    (3, True, 0, 0), (3, -1, 0, 0), (3, 256, 0, 0),
    (3, 30, True, 0), (3, 30, -1, 0), (3, 30, 256, 0),
    (3, 30, 0, True), (3, 30, 0, -1), (3, 30, 0, 0x1000000),
])
def test_version_policy_rejects_malformed_field_domains(values):
    with pytest.raises(ValueError):
        VersionPolicy(*values)


@pytest.mark.parametrize("declaration", [
    {"major": 3, "minor": 30, "oem": 0},
    {"major": 3, "minor": 30, "oem": 0, "serial24": 0, "vendor": "ms"},
    {"major": True, "minor": 30, "oem": 0, "serial24": 0},
    {"major": 1, "minor": 30, "oem": 0, "serial24": 0},
    {"major": 3, "minor": 30, "oem": 0, "serial24": 0x1000000},
    {"major": "major", "minor": 30, "oem": 0, "serial24": 0},
    5, "dos", ["major"],
])
def test_malformed_dos_version_declaration_rejects_before_execution(declaration):
    base = environment()
    document = {
        "schema": "dosunit.real16_program_environment.v1",
        "environment": {"psp_segment": base.psp_segment,
                        "allocation_hex": base.allocation.hex(),
                        "registers": dict(base.registers), "fs": 0, "gs": 0,
                        "dos_version": declaration},
    }
    with pytest.raises(ValueError):
        parse_program_manifest(document)


def test_null_and_absent_dos_version_keep_the_service_refused():
    base = environment()
    for extra in ({}, {"dos_version": None}):
        declared = {"psp_segment": base.psp_segment, "allocation_hex": base.allocation.hex(),
                    "registers": dict(base.registers), "fs": 0, "gs": 0}
        declared.update(extra)
        manifest = parse_program_manifest({
            "schema": "dosunit.real16_program_environment.v1", "environment": declared})
        assert manifest.environment.version_policy is None
        result = execute(QUERY_EXIT, env=manifest.environment)
        assert result.status is ProgramStatus.UNSUPPORTED


@pytest.mark.parametrize("field,delta", [("major", 4), ("minor", 10), ("oem", 1), ("serial24", 0x654321)])
def test_each_declared_field_changes_boot_and_environment_identities(field, delta):
    oracle = execute(QUERY_EXIT)
    changed = execute(QUERY_EXIT, env=version_environment(**{field: delta}))
    assert oracle.boot_identity != changed.boot_identity
    assert oracle.environment_identity != changed.environment_identity
    assert compare_programs(oracle, changed) is ProgramAgreement.INCOMPLETE


def test_mutated_version_environment_fails_the_stale_boot_recheck():
    boot = program_from_mz_bytes(mz(bytes.fromhex(QUERY_EXIT)), version_environment())
    replay_program(boot, instruction_limit=200)  # baseline executes
    for mutated in (version_environment(major=5), replace(boot.environment, version_policy=None),
                    replace(boot.environment, version_policy=VersionPolicy(3, 30, 0x42, 0x654321))):
        object.__setattr__(boot, "environment", mutated)
        with pytest.raises(ValueError, match="stale"):
            replay_program(boot, instruction_limit=200)


def test_fallthrough_wrap_refuses_before_any_mutation():
    # The query sits at the last two bytes of the segment; fallthrough wraps.
    code = b"\x90" * 0xFFFE + b"\xcd\x21"
    boot = program_from_mz_bytes(mz(code, entry_ip=0xFFFE), sentinel_environment())
    result = replay_program(boot, instruction_limit=10)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.instructions == 1
    (event,) = result.events
    assert event.kind is ProgramEventKind.CONTROL_ESCAPE
    assert event.data == b"service_fallthrough_wrap"
    regs = dict(result.registers)
    assert (regs["eax"], regs["ebx"], regs["ecx"], regs["edx"]) == (
        0x12343000, 0x9ABCDEF0, 0x01234567, 0xDEADBEEF)
    assert regs["eflags"] == 2
    assert result.writes == ()


def test_version_receipts_are_compared_not_silently_dropped():
    once = execute(QUERY_EXIT)
    # Query twice: after the first answer AH holds minor, so re-clear AL and
    # re-set AH before the second int 0x21.
    twice = execute("32c0b430cd21" "32c0b430cd21" "b007b44ccd21")
    assert twice.status is ProgramStatus.TERMINATED
    assert twice.exit_code == 7
    assert [event.kind for event in twice.events] == [
        ProgramEventKind.DOS_VERSION, ProgramEventKind.DOS_VERSION, ProgramEventKind.DOS_EXIT]
    assert compare_programs(once, twice) is ProgramAgreement.MISMATCHED


def test_fabricated_or_dropped_version_events_never_agree():
    base = execute(QUERY_EXIT)
    exit_event = base.events[-1]
    altered = replace(base, events=(
        ProgramEvent(ProgramEventKind.DOS_VERSION, base.events[0].address, b"\x00" * 9), exit_event))
    assert compare_programs(base, altered) is ProgramAgreement.INCOMPLETE
    dropped = replace(base, events=(exit_event,))
    assert compare_programs(base, dropped) is ProgramAgreement.MISMATCHED
    short = replace(base, events=(
        ProgramEvent(ProgramEventKind.DOS_VERSION, base.events[0].address, b"\x00"), exit_event))
    assert compare_programs(base, short) is ProgramAgreement.INCOMPLETE


def test_identical_version_runs_are_deterministic_and_agree():
    first = execute(QUERY_EXIT)
    second = execute(QUERY_EXIT)
    assert first == second
    assert compare_programs(first, second) is ProgramAgreement.AGREED


def test_version_query_function_enforces_the_typed_contract():
    policy = VersionPolicy(3, 30, 0x42, 0x123456)
    assert program_version_query(policy, selector=0) == VersionAnswered(0x1E03, 0x4212, 0x3456)
    for selector in (1, 2, 0xFF):
        assert program_version_query(policy, selector=selector) == (
            VersionRefused(selector, VersionRefusal.UNSUPPORTED_SELECTOR))
    for bad_selector in (True, -1, 0x100, "0", None):
        with pytest.raises(ValueError):
            program_version_query(policy, selector=bad_selector)
    for bad_policy in (None, "dos", 5):
        with pytest.raises(ValueError):
            program_version_query(bad_policy, selector=0)


def test_version_records_and_documents_validate_their_domains():
    with pytest.raises(ValueError):
        VersionAnswered(0x10000, 0, 0)
    with pytest.raises(ValueError):
        VersionAnswered(True, 0, 0)
    with pytest.raises(ValueError):
        VersionRefused(True, VersionRefusal.UNSUPPORTED_SELECTOR)
    with pytest.raises(ValueError):
        VersionRefused(0, "unsupported_version_selector")
    policy = VersionPolicy(3, 30, 0x42, 0x123456)
    assert version_policy_document(None) is None
    document = version_policy_document(policy)
    assert (document["major"], document["minor"], document["oem"], document["serial24"]) == (
        3, 30, 0x42, 0x123456)
    data = version_event_data(policy)
    assert data == bytes.fromhex(EXPECTED_EVENT)
    assert len(data) == VERSION_EVENT_BYTES
    with pytest.raises(ValueError):
        version_event_data(None)
    with pytest.raises(ValueError):
        version_policy_document("dos")
    assert parse_version_policy(None) is None


def test_environment_schema_declares_and_bounds_dos_version():
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator

    schemas = Path(__file__).resolve().parents[2] / "tools/dosunit/schemas"
    validator = Draft202012Validator(
        json.loads((schemas / "dosunit.real16_program_environment.v1.schema.json").read_text()))
    base = environment()
    document = {
        "schema": "dosunit.real16_program_environment.v1",
        "environment": {"psp_segment": base.psp_segment,
                        "allocation_hex": base.allocation.hex(),
                        "registers": dict(base.registers), "fs": 0, "gs": 0,
                        "dos_version": dict(DECLARED)},
    }
    validator.validate(document)
    for bad in ({"major": 1, "minor": 30, "oem": 0, "serial24": 0},
                {"major": 3, "minor": 30, "oem": 0, "serial24": 0x1000000},
                {"major": 3, "minor": 30, "oem": 0, "serial24": 0, "extra": 1},
                {"major": 3, "minor": 30, "oem": 0},
                "dos", 5):
        document["environment"]["dos_version"] = bad
        import jsonschema
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(document)


@pytest.mark.parametrize("payload", [bytes(9), bytes.fromhex("2131000616ff000000"),
                                    bytes.fromhex("2130010616ff000000"),
                                    bytes.fromhex("2130000116ff000000")])
def test_malformed_matching_version_receipts_cannot_establish_agreement(payload):
    base = execute(QUERY_EXIT)
    malformed = replace(base, events=(replace(base.events[0], data=payload), base.events[-1]))
    assert compare_programs(malformed, malformed) is ProgramAgreement.INCOMPLETE


def test_public_version_report_declares_policy_and_validates_schema(tmp_path):
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator
    from test_real16_program_cli import arguments, document

    from tools.dosunit.real16_program_cli import cmd_replay_program16

    args = arguments(tmp_path)
    image = mz(bytes.fromhex(QUERY_EXIT))
    args.oracle_exe.write_bytes(image)
    args.candidate_exe.write_bytes(image)
    env = document()
    env["environment"]["dos_version"] = dict(DECLARED)
    args.environment.write_text(json.dumps(env))
    assert cmd_replay_program16(args) == 0
    result = json.loads(args.out.read_text())
    assert result["contract"]["services"]["dos_version"] == version_policy_document(
        VersionPolicy(3, 30, 0x42, 0x123456))
    assert result["oracle"]["events"][0]["kind"] == "dos_version"
    schema_path = Path(__file__).resolve().parents[2] / "tools/dosunit/schemas/dosunit.real16_program_replay.v1.schema.json"
    Draft202012Validator(json.loads(schema_path.read_text())).validate(result)

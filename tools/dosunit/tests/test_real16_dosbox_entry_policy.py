"""Declared DOSBox entry policy identity, parsing and concrete effect controls."""
from dataclasses import replace

import pytest

from inertia.frontend.real16_dosbox_entry_policy import (
    DosBoxInt21EntryPolicy8616,
    dosbox_entry_policy_document,
    parse_dosbox_entry_policy,
)
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_program_model import ProgramObservation, ProgramStatus
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_program_version import VersionPolicy
from tools.dosunit.runtime.real16_replay_model import LinearRange
from tools.dosunit.tests.test_real16_program_replay import environment, mz

pytestmark = pytest.mark.dosunit


def test_policy_roundtrip_is_explicit_and_none_stays_none():
    policy = DosBoxInt21EntryPolicy8616(0x1000)
    assert parse_dosbox_entry_policy(dosbox_entry_policy_document(policy)) == policy
    assert parse_dosbox_entry_policy(None) is None


@pytest.mark.parametrize("document", [{}, {"kind": "dosbox_int21_register_save_v1", "psp_segment": True},
                                       {"kind": "inferred", "psp_segment": 0x1000}])
def test_malformed_profile_refuses(document):
    with pytest.raises(ValueError):
        parse_dosbox_entry_policy(document)


def test_environment_refuses_foreign_psp():
    with pytest.raises(ValueError, match="exact environment PSP"):
        replace(environment(), dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(0x1001))


def test_concrete_saved_words_and_pointer_are_reported_and_identity_bound():
    base = replace(environment(), version_policy=VersionPolicy(5, 0, 0, 0))
    env = replace(base, dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(base.psp_segment))
    code = bytes.fromhex("b80030bb3412cd21b8004ccd21")
    boot = program_from_mz_bytes(mz(code), env)
    plain = program_from_mz_bytes(mz(code), base)
    assert boot.boot_sha256 != plain.boot_sha256
    observations = (ProgramObservation("pointer", LinearRange(0x1002E, 4)),
                    ProgramObservation("saved", LinearRange(0x110E8, 18)))
    result = replay_program(boot, observations=observations)
    assert result.status is ProgramStatus.TERMINATED
    assert dict(result.observations)["pointer"] == bytes.fromhex("e80f1010")
    assert dict(result.observations)["saved"] == bytes.fromhex("003034120000000000000000000000100010")
    assert any(address == 0x1002E for address, _ in result.writes)
    plain_result = replay_program(plain, observations=observations)
    assert result.environment_identity != plain_result.environment_identity
    assert dict(plain_result.observations)["pointer"] == b"\xa5" * 4

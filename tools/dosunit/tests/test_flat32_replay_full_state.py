"""Native and public replay controls for complete default machine observation."""
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from tools.dosunit.tests.test_flat32_concrete_replay import _image, _vector
from tools.dosunit.tests.test_flat32_replay_cli import _elf32

from tools.dosunit.dosunit import main
from tools.dosunit.runtime.flat32_replay import ReplayAgreement, ReplayStatus, compare_replays, replay


@pytest.mark.parametrize("original,candidate", [
    ("b900000000c3", "b901000000c3"),
    ("f8c3", "f9c3"),
], ids=["ecx", "carry_flag"])
def test_default_native_replay_rejects_volatile_register_and_flag_mutations(
    original: str, candidate: str,
) -> None:
    """Real instructions differ solely in a previously omitted observation."""
    left = replay(_image(bytes.fromhex(original)), 0x10000, _vector(), instruction_limit=10)
    right = replay(_image(bytes.fromhex(candidate)), 0x10000, _vector(), instruction_limit=10)
    assert left.status is right.status is ReplayStatus.RETURNED
    assert compare_replays(left, right) is ReplayAgreement.MISMATCHED


@pytest.mark.parametrize("register", ["ecx", "eflags", "eip", "cs", "ss", "ds", "es", "fs", "gs"])
def test_complete_returned_evidence_cannot_drop_control_or_segment_fields(register: str) -> None:
    """A changed captured field must survive the default observation projection."""
    original = replay(_image(bytes.fromhex("c3")), 0x10000, _vector(), instruction_limit=10)
    values = dict(original.registers)
    values[register] = values.get(register, 0) ^ 1
    changed = replace(original, registers=tuple(sorted(values.items())))
    assert compare_replays(original, changed) is ReplayAgreement.MISMATCHED


@pytest.mark.parametrize("corruption", ["missing_ecx", "duplicate_eax"])
def test_ambiguous_or_incomplete_returned_evidence_cannot_agree(corruption: str) -> None:
    """Missing and duplicate register records remain incomplete evidence."""
    original = replay(_image(bytes.fromhex("c3")), 0x10000, _vector(), instruction_limit=10)
    if corruption == "missing_ecx":
        registers = tuple(row for row in original.registers if row[0] != "ecx")
    else:
        registers = (*original.registers, ("eax", dict(original.registers)["eax"]))
    assert compare_replays(original, replace(original, registers=registers)) is ReplayAgreement.INCOMPLETE


@pytest.mark.parametrize("code", ["660f76c0c3", "d9e8c3"], ids=["xmm_return", "x87_return"])
def test_unobserved_vector_and_floating_state_refuses_instead_of_agreeing(code: str) -> None:
    """The declared integer backend cannot hide output in an unmodeled register file."""
    result = replay(_image(bytes.fromhex(code)), 0x10000, _vector(), instruction_limit=10)
    assert result.status is ReplayStatus.UNSUPPORTED
    assert compare_replays(result, result) is ReplayAgreement.INCOMPLETE


@pytest.mark.parametrize("code", ["0f31", "0fa2", "0fc7f0", "0fc7f8", "0f01f9", "0f01d0"],
                         ids=["clock", "cpu_features", "random", "seed", "serialized_clock", "extended_control"])
def test_undeclared_machine_inputs_refuse_in_function_and_program_replay(code: str) -> None:
    """Clock, CPU identity and random sources require explicit environment state."""
    from tools.dosunit.tests.test_pe32_program_replay import execute, exit_code

    from tools.dosunit.runtime.real16_program_model import ProgramAgreement, ProgramStatus, compare_programs

    result = replay(_image(bytes.fromhex(code + "c3")), 0x10000, _vector(), instruction_limit=10)
    assert result.status is ReplayStatus.UNSUPPORTED
    assert compare_replays(result, result) is ReplayAgreement.INCOMPLETE
    program = execute(exit_code(prefix=bytes.fromhex(code)))
    assert program.status is ProgramStatus.UNSUPPORTED
    assert compare_programs(program, program) is ProgramAgreement.INCOMPLETE


def test_repeated_fresh_guests_fit_the_execution_address_space_budget() -> None:
    """Native guest resources must be reclaimed between independent vectors."""
    script = """
import resource
resource.setrlimit(resource.RLIMIT_AS, (4 << 30, 4 << 30))
from tools.dosunit.runtime.flat32_replay import MemoryRange, ReplayImage, ReplayStatus, ReplayVector, replay
image = ReplayImage(((0x10000, bytes.fromhex('c3')),), (MemoryRange(0x10000, 1),))
vector = ReplayVector((('esp', 0x28000),))
for index in range(16):
    assert replay(image, 0x10000, vector, instruction_limit=10).status is ReplayStatus.RETURNED
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("original,candidate", [
    ("b900000000c3", "b901000000c3"),
    ("f8c3", "f9c3"),
], ids=["ecx", "carry_flag"])
def test_public_replay_retains_full_observation_contract(
    tmp_path: Path, original: str, candidate: str,
) -> None:
    """The linked-image CLI rejects the mutation and reports the compared fields."""
    left, right = tmp_path / "left.elf", tmp_path / "right.elf"
    left.write_bytes(_elf32(bytes.fromhex(original)))
    right.write_bytes(_elf32(bytes.fromhex(candidate)))
    vectors, output = tmp_path / "vectors.json", tmp_path / "result.json"
    vectors.write_text(json.dumps({"vectors": [{"id": "state", "oracle_entry": "0x10000",
                                               "candidate_entry": "0x10000", "registers": {"esp": "0x28000"}}]}))
    assert main(["replay-flat32", "--oracle-exe", str(left), "--candidate-exe", str(right),
                 "--vectors", str(vectors), "--out", str(output)]) == 1
    result = json.loads(output.read_text())
    assert result["summary"]["mismatched"] == 1
    assert result["proof_status"] == "not_established_by_execution"
    assert set(result["observables"]) == {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                                          "eflags", "eip", "cs", "ss", "ds", "es", "fs", "gs"}

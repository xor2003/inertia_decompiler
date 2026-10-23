"""Concrete refutations retain function, input and observation boundaries."""

import pytest

from tools.dosunit.compare.flat32_concrete_witness import ConcreteFunction, compare_concrete_witness
from tools.dosunit.runtime.flat32_memory_permissions import DeclaredAccess, DeclaredRegion, MappingOrigin
from tools.dosunit.runtime.flat32_replay_model import MemoryRange, ReplayVector

pytestmark = [pytest.mark.ssa_z3, pytest.mark.runtime]


def _function(code: str) -> ConcreteFunction:
    return ConcreteFunction(0x10000, bytes.fromhex(code))


def _vector() -> ReplayVector:
    return ReplayVector((('esp', 0x28000),))


def test_concrete_mismatch_and_agreement_have_asymmetric_admission() -> None:
    left, right = _function('b807000000c3'), _function('b808000000c3')
    result = compare_concrete_witness(left, right, _vector())
    assert result['status'] == 'failed'
    assert result['proof_scope'] == 'complete_function'
    assert result['mismatches'] == [{'reg': 'eax', 'oracle_value': '0x7', 'candidate_value': '0x8'}]
    assert all(row['returned_via_ret'] for row in result['execution'].values())
    assert compare_concrete_witness(left, left, _vector())['reason'] == 'concrete_agreement_is_not_proof'


@pytest.mark.parametrize('code', [
    'ebfe',  # instruction budget
    'b80000ffffff e0',  # JMP EAX to the return trap, not a RET
    'a100000100c3',  # guest read from execute-only code
    '9fc3',  # LAHF could consume undefined AF from arithmetic
    'cd80c3',  # external service
    'd9e8c3',  # unmodeled x87 state
    'e9fbff0000',  # jump outside declared function
])
def test_incomplete_or_out_of_contract_execution_never_refutes(code: str) -> None:
    result = compare_concrete_witness(_function(code), _function('b808000000c3'), _vector(),
                                      instruction_limit=20)
    assert result['status'] == 'refused', result
    assert result['reason'] == 'concrete_execution_incomplete'


def test_only_requested_register_differences_refute() -> None:
    result = compare_concrete_witness(_function('b907000000c3'), _function('b908000000c3'), _vector())
    assert result['reason'] == 'concrete_agreement_is_not_proof'


def test_seeded_code_cannot_be_a_shared_input_patch() -> None:
    vector = ReplayVector((('esp', 0x28000),), ((0x10000, b'\x90'),))
    with pytest.raises(ValueError, match='executable'):
        compare_concrete_witness(_function('b807000000c3'), _function('b808000000c3'), vector)


@pytest.mark.parametrize('outputs', [(), ('eax', 'eax'), ('eflags',), ('st0',)])
def test_unsupported_observations_are_rejected(outputs: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match='register outputs'):
        compare_concrete_witness(_function('c3'), _function('c3'), _vector(), outputs=outputs)


def test_equal_return_with_different_output_buffer_refutes() -> None:
    vector = ReplayVector((('esp', 0x28000),), observations=(MemoryRange(0x60000, 4),),
                          mappings=(DeclaredRegion(0x60000, 4096, DeclaredAccess.READ | DeclaredAccess.WRITE,
                                                   MappingOrigin.VECTOR),))
    left = _function('c705000006000700000031c0c3')
    right = _function('c705000006000800000031c0c3')
    result = compare_concrete_witness(left, right, vector)
    assert result['reason'] == 'concrete_memory_counterexample'
    assert result['status'] == 'failed'
    assert result['mismatches'] == [{'memory_address': '0x60000', 'size': 4,
                                     'oracle_bytes': '07000000', 'candidate_bytes': '08000000'}]
    assert compare_concrete_witness(left, left, vector)['reason'] == 'concrete_agreement_is_not_proof'


@pytest.mark.parametrize('address', [0x10000, 0x70000, 0x28000])
def test_non_vector_memory_never_creates_a_counterexample(address: int) -> None:
    vector = ReplayVector((('esp', 0x28000),), observations=(MemoryRange(address, 1),))
    # The code differs but both functions return the same EAX; image bytes are
    # unequal programs, not unequal results from identical shared data.
    result = compare_concrete_witness(_function('31c0c3'), _function('33c0c3'), vector)
    assert result['status'] == 'refused'
    assert result['reason'] == 'concrete_memory_observation_not_admitted'


@pytest.mark.parametrize('prefix', [
    '6bc9027400',  # IMUL leaves ZF undefined.
    '6bc9027a00',  # IMUL leaves PF undefined.
    '6bc9027c00',  # JL reads undefined SF even though OF is defined.
    'c1f81f7000',  # Multi-bit SAR leaves OF undefined.
    '6bc902c1f8207400',  # A masked-zero shift preserves undefined ZF.
    'c0f808407200',  # Narrow overshift then INC cannot repair CF.
    '66c1f8107200',  # Conservatively exclude CF after a word overshift.
    'd3f8',  # Variable-count shifts remain outside this immediate-count owner.
])
def test_undefined_flag_paths_cannot_refute(prefix: str) -> None:
    result = compare_concrete_witness(_function(prefix + 'b807000000c3'),
                                      _function('b808000000c3'), _vector())
    assert result['reason'] == 'concrete_execution_incomplete'
    assert result['execution']['oracle']['detail'] in {
        'undefined_integer_flag_consumed', 'integer_flag_effect_not_admitted'}


@pytest.mark.parametrize('prefix', [
    '6bc9027200',  # IMUL defines CF.
    '6bc90283f9007400',  # CMP replaces the undefined arithmetic flags.
    '6bc902407400',  # INC defines ZF while preserving CF.
    'd1f87000',  # A one-bit SAR defines OF.
    'c1f81f7400',  # Multi-bit SAR still defines ZF.
    'c1f8207000',  # Masked-zero count preserves defined entry flags.
    'c0f80831c07000',  # XOR overwrites the overshift flags.
])
def test_defined_flag_paths_admit_integer_counterexamples(prefix: str) -> None:
    result = compare_concrete_witness(_function(prefix + 'b807000000c3'),
                                      _function('b808000000c3'), _vector())
    assert result['reason'] == 'concrete_register_counterexample', result

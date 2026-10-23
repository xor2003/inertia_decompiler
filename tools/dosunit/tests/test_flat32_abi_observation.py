"""Native root-return ABI observation preserves aliases and observable effects."""

import json
import sys

import angr
import pytest

from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation
from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _driver_lane

pytestmark = pytest.mark.ssa_z3


def _compare(original: str, candidate: str, contract: Flat32AbiObservation | None):
    left, right = bytes.fromhex(original), bytes.fromhex(candidate)
    with _driver_lane("msc8") as lane, lane.adapter.installed(region=True):
        return compare_functions_with_calls(
            angr.load_shellcode(left, arch="x86", load_address=BASE),
            angr.load_shellcode(right, arch="x86", load_address=BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: len(left)}, candidate_functions={BASE: len(right)},
            outputs=lane.adapter.OUTPUT_REGS, timeout_ms=10000, abi_observation=contract,
        )


def test_private_stack_differs_strictly_but_agrees_at_abi_return() -> None:
    original, candidate = "b807000000 c3", "52 5a b807000000 c3"
    assert _compare(original, candidate, None)["status"] == "failed"
    checked = _compare(original, candidate, Flat32AbiObservation(32, 16))
    assert checked["status"] == "conditional", checked
    assert checked["abi_observation"]["excluded_stack_byte_offsets"] == [-4, -3, -2, -1]


@pytest.mark.parametrize("return_bits,expected", [(32, "conditional"), (64, "failed")])
def test_edx_is_observable_only_for_wide_scalar_return(return_bits: int, expected: str) -> None:
    result = _compare("ba01000000 b807000000 c3", "ba02000000 b807000000 c3",
                      Flat32AbiObservation(return_bits))
    assert result["status"] == expected, result


@pytest.mark.parametrize("changed", ["b808000000 c3", "bb01000000 b807000000 c3", "c60602 b807000000 c3",
                                     "fd b807000000 c3", "c644240401 b807000000 c3"])
def test_abi_keeps_return_preserved_registers_and_public_memory(changed: str) -> None:
    result = _compare("b807000000 c3", changed, Flat32AbiObservation(32, 16))
    assert result["status"] == "failed", result


def test_private_stack_alias_read_remains_observable() -> None:
    result = _compare("6a01 8b06 59 c3", "6a02 8b06 59 c3", Flat32AbiObservation(32, 16))
    assert result["status"] == "failed", result


@pytest.mark.parametrize("extent", [0, 2])
def test_stack_bytes_outside_declared_extent_remain_observable(extent: int) -> None:
    result = _compare("6a01 59 b807000000 c3", "6a02 59 b807000000 c3", Flat32AbiObservation(32, extent))
    assert result["status"] == "failed", result


@pytest.mark.parametrize("width,expected", [(8, "conditional"), (16, "failed"), (32, "failed")])
def test_return_width_does_not_hide_declared_result_bits(width: int, expected: str) -> None:
    result = _compare("b801000000 c3", "b801010000 c3", Flat32AbiObservation(width))
    assert result["status"] == expected, result


def test_public_cli_retains_strict_result_and_binds_catalog(tmp_path, monkeypatch) -> None:
    """Real PE inputs exercise the new CLI option and source-bound premise."""
    from tools.comparator.msc8_cli import main
    from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

    for side, code in (("oracle", "ba01000000 b807000000 c3"), ("candidate", "ba02000000 b807000000 c3")):
        (tmp_path / (side + ".exe")).write_bytes(pe32_bytes(bytes.fromhex(code)))
        (tmp_path / (side + ".lst")).write_text(
            ".text:00401000 sub_401000 proc near\n.text:0040100A sub_401000 endp\n")
    catalog = tmp_path / "abi.json"
    catalog.write_text(json.dumps({"schema": "dosunit.flat32_abi_observation.v1", "functions": {
        "sub_401000": {"return_bits": 32, "private_stack_bytes": 0}}}))
    monkeypatch.setattr(sys, "argv", ["z3cmp32", "--oracle-exe", str(tmp_path / "oracle.exe"),
        "--oracle-lst", str(tmp_path / "oracle.lst"), "--candidate-exe", str(tmp_path / "candidate.exe"),
        "--candidate-lst", str(tmp_path / "candidate.lst"), "--functions", "sub_401000",
        "--mode", "matched-cfg", "--abi-observation-catalog", str(catalog), "--out-dir", str(tmp_path / "out")])
    main()
    report = json.loads((tmp_path / "out/compare.json").read_text())
    row = report["results"][0]
    assert row["status"] == "conditional", row
    assert row["strict_cfg_result"]["status"] == "refused", row
    assert row["strict_cfg_result"]["reason"] == "matched_cfg_induction", row
    assert row["abi_observation"]["return_bits"] == 32
    assert report["auxiliary_inputs"]["abi_observation_catalog"]["path"] == str(catalog)


@pytest.mark.parametrize("mutation,bits,expected", [
    ("none", 32, "conditional"), ("inc", 32, "conditional"),
    ("none", 64, "refused"), ("strict", 32, "refused"),
    ("return", 32, "refused"), ("memory", 32, "refused"), ("stack", 32, "refused"),
])
def test_loop_return_observation_keeps_internal_effects(mutation: str, bits: int, expected: str) -> None:
    """Only a declared root return may discard scratch EDX across a real loop."""
    from tools.dosunit.compare.flat32_proof_retry import retry_function_proof

    original = "8b44240485c074034875fd31c0c20400"
    candidate = "8b44240485c07408ba010000004875f831c031d2c20400"
    if mutation == "inc":
        candidate = "8b44240485c07404424875fc31c031d2c20400"
    elif mutation == "return":
        candidate = candidate.replace("31c0", "b801000000")
    elif mutation == "memory":
        candidate = candidate.replace("31d2", "31d28910")
    elif mutation == "stack":
        candidate = candidate.replace("c20400", "c20800")
    left, right = bytes.fromhex(original), bytes.fromhex(candidate)
    with _driver_lane("msc8") as lane, lane.adapter.installed(region=True):
        context = (angr.load_shellcode(left, arch="x86", load_address=BASE),
                   angr.load_shellcode(right, arch="x86", load_address=BASE),
                   {"f": (BASE, len(left))}, {"f": (BASE, len(right))})
        checked = retry_function_proof(
            "f", {"status": "refused", "reason": "cfg_not_bijective"},
            context, lane.adapter.OUTPUT_REGS, 20000,
            abi_observation=None if mutation == "strict" else Flat32AbiObservation(bits),
        )
    assert checked["status"] == expected, checked
    if expected == "conditional":
        assert checked["assumptions"]["abi_observation"]["return_bits"] == 32
        assert checked["additional_proof_attempts"]["call_loop"]["status"] == "refused"
        assert checked["environment_coverage"]["oracle"]


@pytest.mark.parametrize("bits,extent", [(8, 0), (16, 0), (32, 4)])
def test_loop_observation_rejects_unimplemented_projections(bits: int, extent: int) -> None:
    """Unsupported premises must not silently weaken loop or memory checks."""
    from tools.dosunit.compare.flat32_loop_observation import compare_observed_loop

    def unexpected_check(outputs):
        raise AssertionError("unsupported observation reached the proof engine")

    result = compare_observed_loop(unexpected_check, Flat32AbiObservation(bits, extent))
    assert result["status"] == "refused"
    assert result["reason"] == "loop_abi_observation_unsupported"


@pytest.mark.parametrize("scope", [None, "complete_function"])
def test_loop_observation_requires_inductive_scope(scope) -> None:
    """A projected scalar equality is insufficient without closed transitions."""
    from tools.dosunit.compare.flat32_loop_observation import compare_observed_loop

    result = compare_observed_loop(
        lambda outputs: {"status": "passed", "proof_scope": scope}, Flat32AbiObservation(32),
    )
    assert result["status"] == "refused"
    assert result["reason"] == "loop_abi_observation_incomplete_scope"


@pytest.mark.parametrize("mutation", ["none", "return", "memory", "stack"])
def test_normalized_loop_retains_explicit_abi_and_all_observed_effects(mutation) -> None:
    """Relocation and ABI observations compose without losing either premise."""
    from tools.dosunit.compare.flat32_proof_retry import retry_function_proof

    original = "8b44240485c074034875fd31c0c20400"
    candidate = "8b44240485c07408ba010000004875f831c031d2c20400"
    if mutation == "return":
        candidate = candidate.replace("31c0", "b801000000")
    elif mutation == "memory":
        candidate = candidate.replace("31d2", "31d28910")
    elif mutation == "stack":
        candidate = candidate.replace("c20400", "c20800")
    left, right = bytes.fromhex(original), bytes.fromhex(candidate)
    with _driver_lane("msc8") as lane, lane.adapter.installed(region=True):
        context = (angr.load_shellcode(left, arch="x86", load_address=BASE),
                   angr.load_shellcode(right, arch="x86", load_address=BASE),
                   {"f": (BASE, len(left))}, {"f": (BASE, len(right))})
        result = retry_function_proof(
            "f", {"status": "refused", "reason": "cfg_not_bijective"},
            context, lane.adapter.OUTPUT_REGS, 20000,
            abi_observation=Flat32AbiObservation(32), candidate_normalization={0x3000: 0x2000},
        )
    assert result["status"] == ("conditional" if mutation == "none" else "refused"), result
    if mutation == "none":
        assert result["normalization_assumptions"]["constant_map"] == {"0x3000": "0x2000"}
        assert result["assumptions"]["abi_observation"]["return_bits"] == 32
        assert result["proof_scope"] == "cutpoint_simulation"

"""Behavior regressions for full-state flat32 region composition."""

from argparse import Namespace
from pathlib import Path

import angr
import pytest

from tools.comparator import bc5_cli as z3cmp32
from tools.comparator.bc5_catalog import Symbol


@pytest.mark.parametrize("left_hex,right_hex", [
    ("b901000000 eb00 89c8 c3", "b902000000 eb00 89c8 c3"),
    ("83f900 eb00 7406 b801000000 c3 b802000000 c3", "83f901 eb00 7406 b801000000 c3 b802000000 c3"),
])
def test_driver_observes_state_written_before_a_block_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, left_hex: str, right_hex: str,
) -> None:
    """Scratch registers and lazy flags can carry live values into later blocks."""
    left = bytes.fromhex(left_hex)
    right = bytes.fromhex(right_hex)
    oracle_path, candidate_path = tmp_path / "o.bin", tmp_path / "c.bin"
    oracle_path.write_bytes(left)
    candidate_path.write_bytes(right)
    original = angr.Project(str(oracle_path), auto_load_libs=False,
                            main_opts={"backend": "blob", "arch": "x86", "base_addr": 0x401000, "entry_point": 0x401000})
    candidate = angr.Project(str(candidate_path), auto_load_libs=False,
                             main_opts={"backend": "blob", "arch": "x86", "base_addr": 0x501000, "entry_point": 0x501000})
    monkeypatch.setattr(z3cmp32, "load32_verified", lambda path, _cache: original if path == oracle_path else candidate)
    monkeypatch.setattr(z3cmp32, "cached_lst_functions", lambda _path, _cache: {"f": (0x401000, 0x401000 + len(left) - 1)})
    monkeypatch.setattr(z3cmp32, "nm_symbols", lambda _path: {"f": Symbol(0x501000, len(right), "T")})
    args = Namespace(
        oracle_exe=oracle_path, candidate_exe=candidate_path, oracle_lst=tmp_path / "o.lst",
        candidate_lst=None, candidate_syms=None, cache_dir=tmp_path / "cache",
        functions="f", mode="region", output_regs="eax,esp", scan_limit=256,
        timeout_ms=10000, region_max_blocks=128, normalize_globals=False,
        assume_paired_calls=False, out_dir=tmp_path,
    )
    result = z3cmp32.compare(args)
    assert result["results"][0]["status"] == "failed", result
    assert any(item.get("reg") == "eax" for item in result["results"][0]["mismatches"])


@pytest.mark.parametrize('candidate_value,expected', [(7, 'passed'), (8, 'failed')])
def test_driver_proves_caller_through_unselected_callee(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, candidate_value: int, expected: str,
) -> None:
    """A requested caller consumes the whole binary callee, even outside selection."""
    images = []
    paths = [tmp_path / 'original.bin', tmp_path / 'candidate.bin']
    base = 0x401000
    for path, value in zip(paths, [7, candidate_value], strict=True):
        image = bytearray(0x26)
        image[:6] = bytes.fromhex('e81b000000c3')
        image[0x20:0x26] = b'\xb8' + value.to_bytes(4, 'little') + b'\xc3'
        path.write_bytes(image)
        images.append(angr.Project(str(path), auto_load_libs=False,
                                  main_opts={'backend': 'blob', 'arch': 'x86', 'base_addr': base, 'entry_point': base}))
    monkeypatch.setattr(z3cmp32, 'load32_verified', lambda path, _cache: images[paths.index(path)])
    monkeypatch.setattr(z3cmp32, 'cached_lst_functions', lambda _path, _cache: {
        'f': (base, base + 5), 'callee': (base + 0x20, base + 0x25),
    })
    monkeypatch.setattr(z3cmp32, 'nm_symbols', lambda _path: {
        'f': Symbol(base, 6, 'T'), 'callee': Symbol(base + 0x20, 6, 'T'),
    })
    args = Namespace(
        oracle_exe=paths[0], candidate_exe=paths[1], oracle_lst=tmp_path / 'o.lst',
        candidate_lst=None, candidate_syms=None, cache_dir=tmp_path / 'cache',
        functions='f', mode='region', output_regs='eax,esp', scan_limit=256,
        timeout_ms=10000, region_max_blocks=128, normalize_globals=False,
        assume_paired_calls=False, out_dir=tmp_path,
    )
    result = z3cmp32.compare(args)
    row = result['results'][0]
    assert row['status'] == expected, result
    assert row['proof_method'] == 'checked_direct_call_composition'
    assert row['return_targets_proved'] == 2
    assert result['summary']['total'] == 1
    assert result['loaded_images']['oracle']['sha256']

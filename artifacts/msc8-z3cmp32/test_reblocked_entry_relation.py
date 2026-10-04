"""A loop entry cannot be moved behind its backedge predecessor."""

import sys
from pathlib import Path

import angr
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from flat32_cfg import compare_cfg

from tools.dosunit.flat32_cfg_regions import compare_reblocked_cfg


def test_pretest_and_posttest_loops_do_not_become_equal_after_chain_collapse(tmp_path: Path) -> None:
    """The initial header test distinguishes zero iterations from one iteration."""
    projects = []
    codes = ['85c974044049ebf8c3', '404985c97402ebf8c3']
    base = 0x401000
    for index, code in enumerate(codes):
        path = tmp_path / f'{index}.bin'
        path.write_bytes(bytes.fromhex(code))
        projects.append(angr.Project(str(path), auto_load_libs=False,
                                     main_opts={'backend': 'blob', 'arch': 'x86', 'base_addr': base, 'entry_point': base}))
    result = compare_reblocked_cfg(tuple(projects), (base, len(bytes.fromhex(codes[0]))),
                                  (base, len(bytes.fromhex(codes[1]))), ('eax', 'esp', 'eip'), 10000)
    assert result['status'] != 'passed', result


@pytest.mark.parametrize('reblocked', [False, True])
def test_narrow_return_projection_keeps_stack_cleanup_observable(reblocked: bool) -> None:
    """ABI stack and return effects survive a caller's narrow return-value choice."""
    original = angr.load_shellcode(bytes.fromhex('c3'), arch='x86', load_address=0x401000)
    candidate = angr.load_shellcode(bytes.fromhex('c20400'), arch='x86', load_address=0x501000)
    if reblocked:
        result = compare_reblocked_cfg((original, candidate), (0x401000, 1), (0x501000, 3), ('eax',), 10000)
    else:
        result = compare_cfg(original, candidate, name='f', oracle_range=(0x401000, 1),
                             candidate_range=(0x501000, 3), outputs=('eax',), timeout_ms=10000)
    # A failed cutpoint obligation is not promoted to a whole-function verdict.
    # Its strict stack observation and modeled counterexample must still survive.
    assert result['status'] == 'refused', result
    assert result['proof_scope'] == 'cutpoint_simulation', result
    assert result['block_compare']['summary']['failed'] == 1, result
    assert result['block_compare']['results'][0]['status'] == 'failed', result
    mismatches = [mismatch for row in result['block_compare']['results']
                  for mismatch in row['mismatches']]
    assert any(item['reg'] == 'esp' and item['oracle_value'] == '0x4'
               and item['candidate_value'] == '0x8' for item in mismatches), result
    assert _guest_return_stack(bytes.fromhex('c3')) == (0x800004, 0x600000)
    assert _guest_return_stack(bytes.fromhex('c20400')) == (0x800008, 0x600000)


def _guest_return_stack(code: bytes) -> tuple[int, int]:
    """Replay a realizable shared frame independently of symbolic induction."""
    from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
    from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

    guest = Uc(UC_ARCH_X86, UC_MODE_32)
    for address in (0x401000, 0x600000, 0x800000):
        guest.mem_map(address, 0x1000)
    guest.mem_write(0x401000, code)
    guest.mem_write(0x800000, (0x600000).to_bytes(4, 'little'))
    guest.reg_write(UC_X86_REG_ESP, 0x800000)
    guest.emu_start(0x401000, 0x600000, count=2)
    return guest.reg_read(UC_X86_REG_ESP), guest.reg_read(UC_X86_REG_EIP)

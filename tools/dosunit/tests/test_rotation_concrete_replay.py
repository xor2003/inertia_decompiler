"""Independent guest evidence for rotated loops and divergent mutants."""
import pytest
from tools.dosunit.tests.test_dosunit_tool import _mz_exe

from tools.dosunit.runtime.flat32_replay import (
    MemoryRange,
    ReplayAgreement,
    ReplayImage,
    ReplayStatus,
    ReplayVector,
    compare_replays,
)
from tools.dosunit.runtime.flat32_replay import (
    replay as replay32,
)
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.runtime.real16_replay import compare_executions
from tools.dosunit.runtime.real16_replay import replay as replay16
from tools.dosunit.runtime.real16_replay_model import (
    CallerFrame,
    FrameKind,
    Real16Agreement,
    Real16ReplayStatus,
    Real16Vector,
    SegOffset,
)


@pytest.mark.parametrize('count', [0, 1, 2, 255])
@pytest.mark.parametrize('width', [16, 32])
def test_rotated_guest_execution(width, count):
    codes = (['e3098d5f01678d49ffebf5c3', 'eb078d5f01678d49ffe302ebf5c3',
              'eb078d5f02678d49ffe302ebf5c3', 'ebfe'] if width == 16 else
             ['e3088d5b018d49ffebf6c3', 'eb068d5b018d49ffe302ebf6c3',
              'eb068d5b028d49ffe302ebf6c3', 'ebfe'])
    if width == 16:
        images = [image_from_mz_bytes(_mz_exe(bytes(0x200) + bytes.fromhex(code))) for code in codes]
        entry = SegOffset(images[0].load_segment, 0x200)
        vector = Real16Vector(registers=(('cx', count), ('bx', 0xfffe), ('sp', 0x1000), ('flags', 0x887)),
                              segments=(('ss', 0x7000), ('ds', entry.segment), ('es', entry.segment)),
                              frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)),
                              high_halves=(('ebx', 0xabcf), ('ecx', 0x9876)))
        results = [replay16(image, entry, vector, instruction_limit=2000) for image in images]
        assert compare_executions(results[0], results[1]).agreement is Real16Agreement.AGREED
        if count:
            assert compare_executions(results[0], results[2]).agreement is Real16Agreement.MISMATCHED
        assert results[3].status is Real16ReplayStatus.BUDGET_EXHAUSTED
        assert compare_executions(results[0], results[3]).agreement is Real16Agreement.INCOMPLETE
    else:
        images = [ReplayImage(((0x1000, bytes.fromhex(code)),),
                              (MemoryRange(0x1000, len(bytes.fromhex(code))),)) for code in codes]
        vector = ReplayVector((('ecx', count), ('ebx', 0xfffffffe), ('esp', 0x8000), ('eflags', 0x887)))
        results = [replay32(image, 0x1000, vector, instruction_limit=2000) for image in images]
        observed = ('eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'ebp', 'esp', 'eflags')
        assert compare_replays(results[0], results[1], observables=observed) is ReplayAgreement.AGREED
        if count:
            assert compare_replays(results[0], results[2], observables=observed) is ReplayAgreement.MISMATCHED
        assert results[3].status is ReplayStatus.BUDGET_EXHAUSTED
        assert compare_replays(results[0], results[3], observables=observed) is ReplayAgreement.INCOMPLETE

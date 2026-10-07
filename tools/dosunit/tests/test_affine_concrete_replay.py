"""Independent 16/32-bit execution of additive loop fixtures and corruptions."""
import pytest
from tools.dosunit.tests.test_dosunit_tool import _mz_exe

from tools.dosunit.runtime.flat32_replay import (
    MemoryRange,
    ReplayAgreement,
    ReplayImage,
    ReplayVector,
    compare_replays,
)
from tools.dosunit.runtime.flat32_replay import (
    replay as replay32,
)
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.runtime.real16_replay import compare_executions
from tools.dosunit.runtime.real16_replay import replay as replay16
from tools.dosunit.runtime.real16_replay_model import CallerFrame, FrameKind, Real16Agreement, Real16Vector, SegOffset


@pytest.mark.parametrize('count',[0,1,2,255])
@pytest.mark.parametrize('width',[16,32])
def test_additive_guest_relation(width,count):
    # Width-specific addressing modes use different LEA ModRM base encodings.
    codes16=['e3058d5f01e2fbc3','8d5f07e3058d5f01e2fb8d5ff9c3',
             '8d5f07e3058d5f01e2fb8d5ff8c3','8d5f07e3058d5f01e1fb8d5ff9c3']
    codes32=[code.replace('8d5f','8d5b') for code in codes16]
    # ZF=0 exposes LOOPE-vs-LOOP; other defined flags remain independently set.
    if width==16:
        images=[image_from_mz_bytes(_mz_exe(bytes(0x200)+bytes.fromhex(code))) for code in codes16]
        entry=SegOffset(images[0].load_segment,0x200)
        vector=Real16Vector(registers=(('cx',count),('bx',0xfffe),('sp',0x1000),('flags',0x887)),
            segments=(('ss',0x7000),('ds',entry.segment),('es',entry.segment)),
            frame=CallerFrame(FrameKind.NEAR16,SegOffset(entry.segment,0x8000)))
        results=[replay16(image,entry,vector,instruction_limit=2000) for image in images]
        assert compare_executions(results[0],results[1]).agreement is Real16Agreement.AGREED
        assert compare_executions(results[0],results[2]).agreement is Real16Agreement.MISMATCHED
        if count>1:
            assert compare_executions(results[0],results[3]).agreement is Real16Agreement.MISMATCHED
    else:
        images=[ReplayImage(((0x1000,bytes.fromhex(code)),),(MemoryRange(0x1000,len(bytes.fromhex(code))),))
                for code in codes32]
        vector=ReplayVector((('ecx',count),('ebx',0xfffffffe),('esp',0x8000),('eflags',0x887)))
        results=[replay32(image,0x1000,vector,instruction_limit=2000) for image in images]
        observed=('eax','ecx','edx','ebx','esi','edi','ebp','esp','eflags')
        assert compare_replays(results[0],results[1],observables=observed) is ReplayAgreement.AGREED
        assert compare_replays(results[0],results[2],observables=observed) is ReplayAgreement.MISMATCHED
        if count>1:
            assert compare_replays(results[0],results[3],observables=observed) is ReplayAgreement.MISMATCHED


@pytest.mark.parametrize('count', [0, 1, 2, 255])
@pytest.mark.parametrize('width', [16, 32])
def test_scaled_guest_relation(width, count):
    codes16 = ['53e3058d5f01e2fb5bc3', '53678d5c5b07e3058d5f03e2fb5bc3',
               '53678d5c5b07e3058d5f03e2fb5ac3', '53678d5c5b07e3058d5f03e1fb5bc3']
    codes32 = ['53e3058d5b01e2fb5bc3', '538d5c5b07e3058d5b03e2fb5bc3',
               '538d5c5b07e3058d5b03e2fb5ac3', '538d5c5b07e3058d5b03e1fb5bc3']
    if width == 16:
        images = [image_from_mz_bytes(_mz_exe(bytes(0x200) + bytes.fromhex(code))) for code in codes16]
        entry = SegOffset(images[0].load_segment, 0x200)
        vector = Real16Vector(registers=(('cx', count), ('bx', 0xfffe), ('dx', 0x1234),
                                        ('sp', 0x1000), ('flags', 0x887)),
            segments=(('ss', 0x7000), ('ds', entry.segment), ('es', entry.segment)),
            frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)),
            high_halves=(('ebx', 0xabcf),))
        results = [replay16(image, entry, vector, instruction_limit=2000) for image in images]
        assert compare_executions(results[0], results[1]).agreement is Real16Agreement.AGREED
        assert compare_executions(results[0], results[2]).agreement is Real16Agreement.MISMATCHED
        if count > 1:
            assert compare_executions(results[0], results[3]).agreement is Real16Agreement.MISMATCHED
    else:
        images = [ReplayImage(((0x1000, bytes.fromhex(code)),),
                              (MemoryRange(0x1000, len(bytes.fromhex(code))),)) for code in codes32]
        vector = ReplayVector((('ecx', count), ('ebx', 0xfffffffe), ('edx', 0x1234),
                               ('esp', 0x8000), ('eflags', 0x887)))
        results = [replay32(image, 0x1000, vector, instruction_limit=2000) for image in images]
        observed = ('eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'ebp', 'esp', 'eflags')
        assert compare_replays(results[0], results[1], observables=observed) is ReplayAgreement.AGREED
        assert compare_replays(results[0], results[2], observables=observed) is ReplayAgreement.MISMATCHED
        if count > 1:
            assert compare_replays(results[0], results[3], observables=observed) is ReplayAgreement.MISMATCHED

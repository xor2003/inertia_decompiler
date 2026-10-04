"""Independent guest evidence for binary register-correspondence controls."""
import pytest

from tools.dosunit.flat32_replay import (
    MemoryRange,
    ReplayAgreement,
    ReplayImage,
    ReplayVector,
    compare_replays,
    replay,
)


@pytest.mark.parametrize('value', [0,1,2])
def test_register_loop_guest(value):
    codes=['85c074034875fdc3','9185c974034975fd91c3','9185c974034975fdc3',
           '9185db74034975fd91c3','9185c974034975fd91c20400']
    vector=ReplayVector((('eax',value),('ecx',0x12345678),('ebx',0),('esp',0x8000),('eflags',2)),
                        observations=(MemoryRange(0x8000,8),))
    results=[]
    for code in codes:
        data=bytes.fromhex(code)
        image=ReplayImage(((0x1000,data),),(MemoryRange(0x1000,len(data)),))
        results.append(replay(image,0x1000,vector,instruction_limit=200000))
    observed=('eax','ecx','edx','ebx','esi','edi','ebp','esp','eflags')
    assert compare_replays(results[0],results[1],observables=observed) is ReplayAgreement.AGREED
    assert compare_replays(results[0],results[2],observables=observed) is ReplayAgreement.MISMATCHED
    assert compare_replays(results[0],results[4],observables=observed) is ReplayAgreement.MISMATCHED
    if value:
        assert compare_replays(results[0],results[3],observables=observed) is ReplayAgreement.MISMATCHED

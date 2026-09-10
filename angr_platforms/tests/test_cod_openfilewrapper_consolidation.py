"""The consolidated slow regression retains all three original obligations."""

from subprocess import CompletedProcess

import pytest
import test_x86_16_cod_regressions as regressions


@pytest.mark.parametrize("damage", ["function: 0x1000 _openFileWrapper", "path", "mode",
                                    "Decompilation empty", "<missing-type>",
                                    "s_2 = &", "s_4 = mode", "s_6 = path"])
def test_consolidated_openfilewrapper_rejects_lost_obligations(monkeypatch, damage):
    output = "function: 0x1000 _openFileWrapper\npath\nmode"
    output = output.replace(damage, "") if damage in output else output + damage
    calls = []

    def run(path, proc):
        calls.append((path, proc))
        return CompletedProcess([], 0, output, "")

    monkeypatch.setattr(regressions, "_run_cod_proc", run)
    with pytest.raises(AssertionError):
        regressions.test_cod_openfilewrapper_direct_forwarding()
    assert calls == [(regressions.COD_DIR / "EGAME2.COD", "_openFileWrapper")]

"""Layer: Tests.

Responsibility: execute SetGear's COD-evidenced decisions, byte writes and calls.
Message offsets belong to this relocated COD fixture, never production recovery.
"""

import subprocess
from pathlib import Path

_RUNTIME = r"""
unsigned short Alt, ejected, Knots, MinAlt;
unsigned char Status, Damaged;
static unsigned int calls, wanted_message, expected_status;
static void check(int condition, const char *description) {
    if (!condition) { fputs(description, stderr); exit(1); }
}
unsigned short Message(int message, int kind) {
    check(Status == expected_status, "Message preceded the status write");
    check((unsigned int)message == wanted_message && kind == 2, "wrong Message arguments");
    ++calls;
    return 0;
}
int main(void) {
    const unsigned short commands[] = {0, 1, 2, 65535};
    const unsigned short speeds[] = {0, 350, 351, 32767, 32768, 65535};
    const unsigned char states[] = {0, 1, 254, 255};
    const unsigned char damages[] = {0, 4, 255};
    for (unsigned int g = 0; g < 4; ++g)
    for (unsigned int e = 0; e < 2; ++e)
    for (unsigned int k = 0; k < 6; ++k)
    for (unsigned int s = 0; s < 4; ++s)
    for (unsigned int d = 0; d < 3; ++d)
    for (unsigned int a = 0; a < 2; ++a)
    for (unsigned int m = 0; m < 2; ++m) {
        ejected = e;
        Knots = speeds[k];
        Status = states[s];
        Damaged = damages[d];
        Alt = a ? 65535 : 0;
        MinAlt = m ? 65535 : 0;
        calls = wanted_message = 0;
        expected_status = Status;
        int signed_speed = Knots < 32768 ? (int)Knots : (int)Knots - 65536;
        if (!ejected && commands[g] == 1 && (Status & 1) && signed_speed <= 350) {
            expected_status = Status & 254;
            wanted_message = 28678;
        }
        if (!ejected && commands[g] == 0 && !(Status & 1) && Alt != MinAlt && !(Damaged & 4)) {
            expected_status = Status | 1;
            wanted_message = 28686;
        }
        _SetGear(commands[g]);
        check(Status == expected_status, "wrong Status result");
        check(calls == (wanted_message != 0), "wrong Message count");
        check(ejected == e && Knots == speeds[k] && Damaged == damages[d], "input global changed");
        check(Alt == (a ? 65535 : 0) && MinAlt == (m ? 65535 : 0), "altitude changed");
    }
    return 0;
}
"""


def assert_setgear_behavior(generated_c: str, tmp_path: Path) -> None:
    """Compile unchanged generated C and check 2,304 decision/state combinations."""
    source = (
        "#include <stdio.h>\n#include <stdlib.h>\n"
        "extern unsigned short Alt, ejected, Knots, MinAlt;\n"
        "extern unsigned char Status, Damaged;\n"
        "unsigned short Message(int message, int kind);\n"
        + generated_c + _RUNTIME
    )
    executable = tmp_path / "setgear-behavior"
    compiled = subprocess.run(
        ["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O2", "-x", "c", "-", "-o", str(executable)],
        input=source, capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, f"SetGear compilation failed: {compiled.stderr}"
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=5)
    assert executed.returncode == 0, f"SetGear behavior failed: {executed.stderr}"

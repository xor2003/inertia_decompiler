"""Generate the explicit native-debugger entry snapshot command.

Layer: compiler tooling.
Responsibility: read live full-width DOSBox state before the first instruction.
"""

from __future__ import annotations

import json
from pathlib import Path


def debugger_script(target: str, output: Path, identities: dict[str, str]) -> str:
    """Build GDB Python breakpoints without parsing printed machine state.

    This is an explicit third-party debug ABI: missing fields or symbols fail
    rather than substituting register values. No DOS services are declared.
    """
    settings = json.dumps({"target": target, "output": str(output.resolve()), "identities": identities})
    return f'''set pagination off
set confirm off
python
import gdb, hashlib, json, pathlib
settings = json.loads({settings!r})
def number(expression):
    return int(gdb.parse_and_eval(expression))
class Entry(gdb.Breakpoint):
    def __init__(self, coordinates):
        super().__init__("core_normal.cpp:280", internal=False)
        self.coordinates = coordinates
        self.condition = ("core.cseip == %d && Segs.val[1] == %d && cpu_regs.ip.dword[0] == %d" %
                          ((coordinates["cs"] << 4) + coordinates["ip"], coordinates["cs"], coordinates["ip"]))
    def stop(self):
        coordinates = self.coordinates
        expected_linear = (coordinates["cs"] << 4) + coordinates["ip"]
        if (number("core.cseip") != expected_linear or
                number("Segs.val[1]") != coordinates["cs"] or
                number("cpu_regs.ip.dword[0]") != coordinates["ip"]):
            return False
        output = pathlib.Path(settings["output"])
        memory = bytes(gdb.selected_inferior().read_memory(number("MemBase"), 0x100000))
        registers = {{name: number("cpu_regs.regs[%d].dword[0]" % index)
                     for index, name in enumerate(("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"))}}
        registers["eflags"] = number("cpu_regs.flags")
        segments = {{name: number("Segs.val[%d]" % index)
                    for index, name in enumerate(("es", "cs", "ss", "ds", "fs", "gs"))}}
        record = {{"schema": "inertia.real16_entry_capture.v1", "identities": settings["identities"],
                  "memory_sha256": hashlib.sha256(memory).hexdigest(), "registers": registers,
                  "segments": segments, "eip": number("cpu_regs.ip.dword[0]"),
                  "lazy_flags_type": number("lflags.type"), "loader": self.coordinates}}
        (output / "memory.bin").write_bytes(memory)
        (output / "capture.json").write_text(json.dumps(record, indent=2) + "\\n")
        gdb.execute("quit")
        return True
class Loader(gdb.Breakpoint):
    def stop(self):
        name = gdb.parse_and_eval("name").string()
        if name != settings["target"]:
            return False
        coordinates = {{name: number(expression) for name, expression in
                       (("load_segment", "loadseg"), ("cs", "init_cs"), ("ip", "init_ip"),
                        ("ss", "init_ss"), ("sp", "init_sp"))}}
        self.enabled = False
        Entry(coordinates)
        return False
Loader("custom_init_entrypoint", internal=False)
end
run
'''

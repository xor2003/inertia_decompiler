import logging
import re

import angr
import claripy
import keystone as ks
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa
from angr_platforms.X86_16.simos_86_16 import SimCC8616MSC  # noqa
from archinfo import ArchX86

logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel("ERROR")
logging.getLogger("pyvex.expr").setLevel("DEBUG")
logging.getLogger("angr_platforms.X86_16.parse").setLevel("DEBUG")

FLAGS = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "DF": 10, "OF": 11}
_ARCH_COMPARE_REGS = {
    "ax",
    "bx",
    "cx",
    "dx",
    "sp",
    "bp",
    "si",
    "di",
    "ip",
    "cs",
    "ds",
    "es",
    "fs",
    "gs",
    "ss",
}


def assembler(lines, bitness=0) -> bytes:
    if bitness == 16 and lines == "cwd":
        return b"\x99"
    ks_ = ks.Ks(ks.KS_ARCH_X86, {16: ks.KS_MODE_16, 32: ks.KS_MODE_32}[bitness])
    data, _ = ks_.asm(lines, as_bytes=True)
    return data


def _instruction_for_bitness(instruction: str, bitness: int) -> str:
    instruction = instruction.strip()
    if instruction == "cdq":
        return "cwd"
    if bitness == 32 and instruction == "ret":
        return f"data16 {instruction}"
    return instruction


def step(simgr, insn_bytes):
    simgr.step(num_inst=1, insn_bytes=insn_bytes)
    return simgr.active


def _state_ip16(state):
    for reg_name in ("ip", "eip"):
        try:
            return state.solver.eval(getattr(state.regs, reg_name)) & 0xFFFF
        except Exception:
            continue
    return 0


def _is_control_flow_instruction(instruction: str) -> bool:
    instruction = instruction.strip()
    return instruction.startswith(("j", "l", "ret"))


def prepare(arch, data):
    addr = 0x100
    project = angr.load_shellcode(
        data, arch=arch, start_offset=addr, load_address=addr, selfmodifying_code=False, rebase_granularity=0x1000
    )
    state = project.factory.blank_state()
    return project.factory.simgr(state)


def compare_states(instruction, state32_, state16_, fallthrough32=None, fallthrough16=None):
    differencies = []
    control_flow = _is_control_flow_instruction(instruction)
    state32_ = sorted(state32_, key=_state_ip16)
    state16_ = sorted(state16_, key=_state_ip16)
    for state32, state16 in zip(state32_, state16_, strict=False):
        state16.regs.eip &= 0xFFFF
        differencies.extend(_compare_state_registers(state32, state16, control_flow, fallthrough32, fallthrough16))
        differencies.extend(_compare_state_flags(state32, state16))
    return differencies


def _report_state_diff(kind, name, val32_ast, val16_ast):
    val32 = filter_symbolic(repr(val32_ast))
    val16 = filter_symbolic(repr(val16_ast))
    print(f"{kind} {name} differs: state32={val32}\n                 state16={val16}")
    return (name, val32, val16)


def _compare_state_registers(state32, state16, control_flow, fallthrough32, fallthrough16):
    differencies = []
    skip_regs = {"eflags", "flags", "d"}
    if not control_flow:
        skip_regs.add("eip")
        skip_regs.add("ip")
    # Compare registers
    for reg in state16.arch.register_list:
        reg_name = reg.name
        if reg_name in skip_regs:
            continue
        if reg_name not in _ARCH_COMPARE_REGS:
            continue
        if getattr(reg, "artificial", False) or getattr(reg, "floating_point", False):
            continue
        val32_ast = claripy.simplify(getattr(state32.regs, reg_name))
        try:
            diff = _register_state_diff(state32, state16, reg_name, val32_ast, control_flow, fallthrough32, fallthrough16)
        except KeyError:
            continue
        if diff is not None:
            differencies.append(diff)
    return differencies


def _register_state_diff(state32, state16, reg_name, val32_ast, control_flow, fallthrough32, fallthrough16):
    val16_ast = claripy.simplify(getattr(state16.regs, reg_name))
    if (
        control_flow
        and reg_name in {"ip", "eip"}
        and fallthrough32 is not None
        and fallthrough16 is not None
    ):
        ip32 = state32.solver.eval(val32_ast) & 0xFFFF
        ip16 = state16.solver.eval(val16_ast) & 0xFFFF
        is_fallthrough32 = ip32 == (fallthrough32 & 0xFFFF)
        is_fallthrough16 = ip16 == (fallthrough16 & 0xFFFF)
        if is_fallthrough32 == is_fallthrough16 and (is_fallthrough32 or ip32 == ip16):
            return None
        return _report_state_diff("Register", reg_name, val32_ast, val16_ast)
    if getattr(val32_ast, "size", lambda: None)() != getattr(val16_ast, "size", lambda: None)():
        val32_ast = val32_ast[val16_ast.size() - 1 : 0]
    if not state32.solver.satisfiable(extra_constraints=[val32_ast != val16_ast]):
        return None
    return _report_state_diff("Register", reg_name, val32_ast, val16_ast)


def _compare_state_flags(state32, state16):
    differencies = []
    # To handle lazy flag calculation, print individual flags
    flags32 = {key: state32.regs.flags[bit] for key, bit in FLAGS.items()}
    flags16 = {key: state16.regs.flags[bit] for key, bit in FLAGS.items()}
    for flag in flags32:
        if flag not in {"CF", "ZF", "SF", "OF"}:
            continue
        value32_ast = claripy.simplify(flags32[flag])
        value16_ast = claripy.simplify(flags16[flag])

        if state32.solver.satisfiable(extra_constraints=[value32_ast != value16_ast]):
            differencies.append(_report_state_diff("Flag", flag, value32_ast, value16_ast))
    return differencies


def filter_symbolic(value32):
    value32 = value32.replace("{UNINITIALIZED}", "").replace("reg_", "")
    value32 = re.sub(r"_\d_32", "", value32)
    value32 = re.sub(r"\[(\d+):\1]", r"[\g<1>]", value32)
    return value32


def compare_instructions_impact(instruction: str):
    instruction = instruction.strip()
    arch_16 = Arch86_16()  # get architecture
    arch_32 = ArchX86()  # get architecture
    bytes32 = assembler(_instruction_for_bitness(instruction, 32), 32)
    simgr32 = prepare(arch_32, bytes32)
    bytes16 = assembler(_instruction_for_bitness(instruction, 16), 16)
    simgr16 = prepare(arch_16, bytes16)
    current_state32 = simgr32.active[0]
    current_state16 = simgr16.active[0]
    current_state16.regs.d = current_state16.regs.eflags[10]
    for reg in current_state16.arch.register_list:
        val16 = getattr(current_state16.regs, reg.name)
        try:
            setattr(current_state32.regs, reg.name, val16)
        except Exception as ex:
            print(f"Register {reg.name} failed to set %s", ex)
    current_state32.regs.eip = 0x100
    # Conditional-jump equivalence requires the same concrete starting flags;
    # x86 otherwise retains independent lazy flag state behind eflags.
    current_state16.regs.flags = 0
    current_state16.regs.d = 0
    current_state32.regs.eflags = 0
    expected_return_sp = None
    if instruction == "ret":
        return_stack = b"\x80\x01\x00\x00"
        current_state16.regs.ss = 0
        current_state32.regs.ss = 0
        current_state16.memory.store(current_state16.regs.sp, return_stack)
        current_state32.memory.store(current_state32.regs.sp, return_stack)
        expected_return_sp = (current_state16.solver.eval(current_state16.regs.sp) + 2) & 0xFFFF
    stage32 = step(simgr32, bytes32)
    stage16 = step(simgr16, bytes16)
    if expected_return_sp is not None:
        if not stage32 or not stage16:
            return [("successor-count", str(len(stage32)), str(len(stage16)))]
        # VEX's 32-bit reference lift ignores the return operand-size prefix.
        for state32 in stage32:
            state32.regs.sp = expected_return_sp
    fallthrough32 = current_state32.addr + len(bytes32)
    fallthrough16 = current_state16.addr + len(bytes16)
    return compare_states(instruction, stage32, stage16, fallthrough32=fallthrough32, fallthrough16=fallthrough16)


TODO = """
imul si,si,0x3 ; TODO cf, of
imul si,si,0x1234 ; TODO cf, of
jmp 0x1ea  # working. assember issue
jmp -35  # working
jmp 0xffffff35  # working
shl dx,1  # flags correct
shl dx,0  # TODO flags
shl ax,1  # cf, of
imul ax,ax,0x6  # TODO cf, of
jno 0x106  # assembler
jo 0x106
jns 0x106
js 0x106
jnc 0x106
jc 0x106
jna 0x106
ja 0x106
jnl 0x106
jl 0x106
jng 0x106
jg 0x106  # assembler
shl bx,cl  # disagree
shl si,cl  # disagree
shr di,cl  # disagree

call 0x17a # assembler
call 0xfd92 # assembler
callf [0x2e0:0xb38] # assembler

pop bp  # ??
pop di
push ax
push cs
push si

rol si,cl # TODO
ror si,cl # TODO
rcl si,cl # TODO
rcr si,cl # TODO
mul bx
div cx
div cl
mul bl
movsw # TODO
idiv cx  # TODO
in al,dx
"""

LIST = """
and ax,cx
or ax,cx
xor ax,cx
cmp ax,cx
sub ax,cx
xchg ax,cx
add ax,cx

and al,cl
or al,cl
xor al,cl
cmp al,cl
sub al,cl
xchg al,cl
add al,cl

std
sti

int 0x21
add bx,0x10
add bx,dx
add cx,2
add sp,2
and al,3
and ax,0xf
and bx,0xfff0
cdq 
cld
cli
cmp bp,di
cmp al,1
cmp ax,0x15
cmp ax,8
cmp cx,ax
cmp di,0x200
dec cx
mov bx,0x1234
inc bx
je 0x25
jnz 6
jcxz 0x7b
jge 0x2e
jl 0x11
jle 5
jmp 5
mov ah,0x0
mov ax,0x1a
mov ax,0x2500
mov ax,di
mov bp,sp
mov bx,0x0
mov bx,ax
mov bx,si
mov ch,al
mov cl,0x4
mov cl,4
mov cx,0x7fff
mov cx,0x96
mov cx,ax
mov di,0x200
mov di,ax
mov ds,dx
mov dx,0x171
mov dx,bx
mov dx,cs
mov dx,di
mov dx,ss
mov es,ax
mov es,di
mov si,0x452e
mov si,ax
mov sp,bp
mov sp,di
mov ss,dx
jno 6
jo 6
jns 6
js 6
jnc 6
jc 6
jna 6
ja 6
jnl 6
jl 6
jng 6
jg 6
neg cx
nop
or al,al
or ax,ax
or ch,0x80
not cx
ret
sti
sub ah,ah
sub al,0x4a
sub ax,ax
sub bp,dx
sub cl,cl
sub sp,0x34
xchg bx,ax
xor ah,ah
xor bp,bp

out dx,al
"""


def test_instructions():
    for line in filter(None, LIST.splitlines()):
        result = compare_instructions_impact(line)
        assert not result, f"instruction={line!r} mismatches={result!r}"
    print("Success!")


if __name__ == "__main__":
    test_instructions()

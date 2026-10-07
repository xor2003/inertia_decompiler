"""Legacy VEX lifting experiment kept outside the decompiler pipeline.

Layer: Tooling/gates.
Responsibility: preserve the existing oldmain tool behavior.
"""

import re
from copy import copy, deepcopy

import angr
import jsonpickle
import pyvex

# pip install keystone-engine
# from capstone import *
from archinfo import arch
from archinfo.arch_x86 import ArchX86
from cffi import FFI as ffi
from pyvex import IRSB, IRTypeEnv
from pyvex.const import U1, U8, U16, U32
from pyvex.expr import *  # noqa: F403
from pyvex.lifting import LibVEXLifter, lifters
from pyvex.stmt import *  # noqa: F403
from reprmixin import ReprMixin

arch = ArchX86()  # noqa: F811
# Serialization
IMark.__repr__ = lambda self: "IMark(addr=self.v.addr, length=self.v._size, delta=0)"  # noqa: F405
WrTmp.__repr__ = lambda self: f"WrTmp(t{self.tmp},{self.data!r})"  # noqa: F405
RdTmp.__repr__ = lambda self: "RdTmp(t%d)" % self.tmp  # noqa: F405, UP031
Binop.__repr__ = lambda self: f"Binop({self.op!r},{self.args!r})"  # noqa: F405
Const.__repr__ = lambda self: f"Const({self._con!r})"  # noqa: F405
U1.__repr__ = lambda self: "U1(%d)" % self.value  # noqa: UP031
U8.__repr__ = lambda self: "U8(%d)" % self.value  # noqa: UP031
U16.__repr__ = lambda self: "U16(%d)" % self.value  # noqa: UP031
U32.__repr__ = lambda self: "U32(%d)" % self.value  # noqa: UP031
IRTypeEnv.__repr__ = lambda self: f"IRTypeEnv(self.arch, types={self.types})"
Get.__repr__ = lambda self: f"self.get('{arch.translate_register_name(self.offset)}')"  # noqa: F405
Put.__repr__ = lambda self: f"self.put('{arch.translate_register_name(self.offset)}',{self.data!r})"  # noqa: F405
IRSB.__repr__ = lambda self: (
    f"IRSB(None, {self.addr!r}, self.arch)\nv.statements={self.statements!r}\nv.next={self.next!r}\n"
    + f"v.jumpkind={self.jumpkind!r}\nv.default_exit_target={self.default_exit_target!r}\n"
    + f"v.data_refs={self.data_refs!r}\nv._tyenv={self._tyenv!r}\n"
    + f"v._instructions={self._instructions!r}\n"
    + f"v._instruction_addresses={self._instruction_addresses!r}"
)
for Class in [
    Unop,  # noqa: F405
    IRExpr,  # noqa: F405
    Binder,  # noqa: F405
    VECRET,  # noqa: F405
    GSPTR,  # noqa: F405
    GetI,  # noqa: F405
    Qop,  # noqa: F405
    Triop,  # noqa: F405
    Load,  # noqa: F405
    ITE,  # noqa: F405
    CCall,  # noqa: F405
    IRStmt,  # noqa: F405
    NoOp,  # noqa: F405
    IMark,  # noqa: F405
    AbiHint,  # noqa: F405
    Put,  # noqa: F405
    PutI,  # noqa: F405
    Store,  # noqa: F405
    CAS,  # noqa: F405
    LLSC,  # noqa: F405
    MBE,  # noqa: F405
    Dirty,  # noqa: F405
    Exit,  # noqa: F405
    LoadG,  # noqa: F405
    StoreG,  # noqa: F405
]:
    Class.__bases__ += (ReprMixin,)


def disasm(CODE: bytes, bitness=0, addr: int = 0) -> str:  # noqa: ANN001, D103
    import capstone as cs

    md = cs.Cs(cs.CS_ARCH_X86, {16: cs.CS_MODE_16, 32: cs.CS_MODE_32}[bitness])
    yield from md.disasm(CODE, addr)
    # "0x%x:\t%s\t%s" % (instr.address, instr.mnemonic, instr.op_str))


def asm32(line) -> bytes:  # noqa: ANN001, D103
    import keystone as ks

    if line:
        ks_ = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        data, count = ks_.asm(line, as_bytes=True)
        if count == 0:
            raise Exception(f"Could not assemble {line}")
        # if count != 1:
        #    raise Exception(f"Could not assemble {line}")
        return data


def assembler(lines, bitness=0) -> bytes:  # noqa: ANN001, D103
    import keystone as ks

    ks_ = ks.Ks(ks.KS_ARCH_X86, {16: ks.KS_MODE_16, 32: ks.KS_MODE_32}[bitness])
    data, _count = ks_.asm(lines, as_bytes=True)
    return data


data = b""
sizes_16bit = []
sizes_32bit = []


class Lifter16(LibVEXLifter):  # noqa: D101
    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003, D107
        super().__init__(*args, **kwargs)
        """
        self.arch_16 = ArchX86()  # get architecture
        # arch_16.bits=16
        self.arch_16.reg_blacklist = ('gdt', 'ldt')  # make cs,ds valid
        self.arch_16.ks_mode = _keystone.KS_MODE_16 + _keystone.KS_MODE_LITTLE_ENDIAN
        self.arch_16.keystone  # init keystone assembler
        self.arch_16._ks.sym_resolver = resolver  # set resolver
        self.arch_16._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax
        """

    def lift(  # noqa: ANN201, D102
        self,
        data,  # noqa: ANN001
        bytes_offset=None,  # noqa: ANN001
        max_bytes=None,  # noqa: ANN001
        max_inst=None,  # noqa: ANN001
        opt_level=1,  # noqa: ANN001
        traceflags=None,  # noqa: ANN001
        allow_arch_optimizations=None,  # noqa: ANN001
        strict_block_end=None,  # noqa: ANN001
        skip_stmts=False,  # noqa: ANN001
        collect_data_refs=False,  # noqa: ANN001
        cross_insn_opt=True,  # noqa: ANN001
        load_from_ro_regions=False,  # noqa: ANN001
    ):
        print(f"Input: {locals()}")
        collect_data_refs = False

        # asm = asm32()
        # next(asm)

        addr16bit = 0
        addr32bit = 0
        i = 0
        try:
            bytes16 = ffi().unpack(data, len(data))
            # raise Exception()
        except:  # noqa: E722
            vex = super().lift(
                data,
                bytes_offset=bytes_offset,
                max_bytes=max_bytes,
                max_inst=max_inst,
                opt_level=opt_level,
                traceflags=traceflags,
                allow_arch_optimizations=allow_arch_optimizations,
                strict_block_end=strict_block_end,
                skip_stmts=skip_stmts,
                collect_data_refs=collect_data_refs,
                cross_insn_opt=cross_insn_opt,
                load_from_ro_regions=load_from_ro_regions,
            )
            print(f"As is: {vex}")
            # self.render_vex_to_json(vex)
            return vex

        print("Trying to convert:")
        print(f"bytes: {bytes16}")

        vex = None
        first = True
        for instr16 in disasm(bytes16, addr=addr16bit, bitness=16):
            print(f"intr16: {instr16.size} {instr16.mnemonic} {instr16.op_str}")
            instr16_size = instr16.size

            bytes32 = asm32(f"{instr16.mnemonic} {instr16.op_str}")
            instr32_size = len(bytes32)

            d = disasm(bytes32, addr=addr32bit, bitness=32)
            instr32 = next(d)
            print(f"intr32: {instr32.size} {instr32.mnemonic} {instr32.op_str}")

            try:
                instr32_cdata = ffi().from_buffer(bytearray(bytes32))
                vex_current = super().lift(
                    instr32_cdata,
                    bytes_offset=bytes_offset,
                    max_bytes=max_bytes,  # instr32_size,
                    max_inst=1,
                    opt_level=opt_level,
                    traceflags=traceflags,
                    allow_arch_optimizations=allow_arch_optimizations,
                    strict_block_end=strict_block_end,
                    skip_stmts=False,
                    collect_data_refs=collect_data_refs,
                    cross_insn_opt=cross_insn_opt,
                    load_from_ro_regions=load_from_ro_regions,
                )
            except Exception as ex:
                print(ex)
                raise
            assert vex_current.statements
            print(f"""
            Before:
            {vex_current}
            """)
            # self.render_vex_to_json(vex)

            # print(vex)
            # self.render_vex_to_json(vex)
            vex_current = self.change_instr_size(vex_current, addr16bit, instr16_size)

            addr16bit += instr16_size
            addr32bit += instr32_size

            print(repr(vex_current))
            print(f"""After:
            {vex_current}
            """)
            # {Lifter16.render_vex_to_json(vex_current)}

            if first:
                vex = vex_current
                # v = MyVex()
                # vex = v.mov()
                first = False
            else:
                # vex = merge_vexes(vex, vex_current)
                vex.extend(vex_current)

        print(f"Output: {vex}")
        return vex

    def change_instr_size(self, vex_current, addr16bit, instr16_size):  # noqa: ANN001, ANN201, D102
        vex_current._instruction_addresses = (addr16bit,)
        assert isinstance(vex_current.statements[0], IMark)  # noqa: F405
        vex_current.statements[0].addr = addr16bit
        vex_current.statements[0].len = instr16_size
        if isinstance(vex_current.next, Const):  # noqa: F405
            vex_current.next = pyvex.expr.Const(pyvex.const.U32(addr16bit + instr16_size))
        vex_current.default_exit_target = addr16bit + instr16_size
        return vex_current

    @staticmethod
    def render_vex_to_json(vex):  # noqa: ANN001, ANN205, D102
        vexx = copy(vex)
        vexx.arch = None
        json = jsonpickle.encode(vexx, indent=2)
        return json


lifters["X86"] = [Lifter16]

# from archinfo.arch_x86 import ArchX86
from angr.analyses import (  # noqa: E402
    CallingConventionAnalysis,
    CFGFast,
    Decompiler,
    VariableRecoveryFast,
)


class MyVex(IRSB):  # noqa: D101
    def __init__(self, addr=0) -> None:  # noqa: ANN001, D107
        self.addr = addr
        self.arch = ArchX86()
        self.v = IRSB(None, self.addr, self.arch)
        self.v._tyenv = IRTypeEnv(self.arch)

    def add_tmp(self, size):  # noqa: ANN001, ANN201, D102
        return self.v._tyenv.add(pyvex.expr.int_type_for_size(size))

    def get(self, register):  # noqa: ANN001, ANN201, D102
        ty = pyvex.expr.int_type_for_size(8 * self.v.arch.registers[register][1])
        # ty_int = pyvex.enums.get_int_from_enum(ty)
        return Get(self.v.arch.get_register_offset(register), ty)  # noqa: F405

    def conv16Uto32(self, source):  # noqa: ANN001, ANN201, D102
        return Unop("Iop_16Uto32", [source])  # noqa: F405

    def put(self, register, source):  # noqa: ANN001, ANN201, D102
        return Put(source, self.v.arch.get_register_offset(register))  # noqa: F405

    def load_byte(self, addr):  # noqa: ANN001, ANN201, D102
        return Load("Iend_LE", "Ity_I8", addr)  # noqa: F405

    def load_word(self, addr):  # noqa: ANN001, ANN201, D102
        return Load("Iend_LE", "Ity_I16", addr)  # noqa: F405

    def load_dword(self, addr):  # noqa: ANN001, ANN201, D102
        return Load("Iend_LE", "Ity_I32", addr)  # noqa: F405

    def add(self, size, *args):  # noqa: ANN001, ANN002, ANN201, D102
        if size not in [8, 16, 32]:
            raise ValueError("Invalid op size %d" % size)  # noqa: UP031
        if len(args) == 1:
            return Unop("Iop_Add%d" % size, args)  # noqa: F405, UP031
        elif len(args) == 2:
            return Binop("Iop_Add%d" % size, args)  # noqa: F405, UP031
        elif len(args) == 3:
            return Triop("Iop_Add%d" % size, args)  # noqa: F405, UP031
        else:
            raise ValueError(f"Invalid number of args {args}")

    def mov(self):  # noqa: ANN201, D102
        self.v._size = 5
        """
        self.v.statements = [
            IMark(self.addr, self.v._size, 0),
            WrTmp(t2, self.get('esp')),
            WrTmp(t1, self.add(32, RdTmp(t2), Const(U32(4)))),
            WrTmp(t4, self.load_word(RdTmp(t1))),
            WrTmp(t3, self.conv16Uto32(RdTmp(t4))),
            self.put('eax', RdTmp(t3))
        ]
        """
        # self.v=IRSB(None, 0, self.arch)
        t0 = self.add_tmp(32)
        t1 = self.add_tmp(32)
        t2 = self.add_tmp(16)
        t3 = self.add_tmp(32)
        t4 = self.add_tmp(32)  # movzx     eax, word ptr [esp + 4]
        t5 = self.add_tmp(16)  # movzx     eax, word ptr [esp + 4]
        self.v.statements = [
            IMark(addr=self.v.addr, length=self.v._size, delta=0),  # noqa: F405
            WrTmp(t2, self.get("es")),  # noqa: F405
            WrTmp(t3, Unop(op="Iop_16Uto32", args=[RdTmp(t2)])),  # noqa: F405
            WrTmp(t4, Binop("Iop_Shl32", [RdTmp(t3), Const(U8(4))])),  # noqa: F405
            WrTmp(t1, Binop("Iop_Add32", [RdTmp(t4), Const(U32(0x2000))])),  # noqa: F405
            WrTmp(t5, Load(end="Iend_LE", ty="Ity_I16", addr=RdTmp(t1))),  # noqa: F405
            WrTmp(t0, Unop(op="Iop_16Uto32", args=[RdTmp(t5)])),  # noqa: F405
            self.put("eax", RdTmp(t0)),  # noqa: F405
        ]

        self.v.next = Const(U32(self.v.addr + self.v._size))  # noqa: F405
        self.v.jumpkind = "Ijk_Boring"
        self.v._instructions = 1
        self.v.default_exit_target = self.v.addr + self.v._size
        self.v._instruction_addresses = (self.v.addr,)
        # self.v.data_refs = [DataRef(4, 0, 36864, 2, 0)]

        print(self.v)
        print(repr(self.v))
        # print(Lifter16.render_vex_to_json(self.v))
        return self.v

    def make_temp(self) -> None:  # noqa: D102
        pass


# from keystone import Ks


def resolver(symbol, value) -> bool:  # noqa: ANN001, D103
    if symbol == b"abcd":
        value.contents.value = 0x42
        return True
    return False


def vexer(instruction):  # noqa: ANN001, ANN201, D103
    global arch_32
    arch_16 = ArchX86()  # get architecture
    # arch_16.bits=16
    arch_16.reg_blacklist = ("gdt", "ldt")  # make cs,ds valid
    arch_16.ks_mode = _keystone.KS_MODE_16 + _keystone.KS_MODE_LITTLE_ENDIAN
    arch_16.keystone  # init keystone assembler  # noqa: B018
    arch_16._ks.sym_resolver = resolver  # set resolver
    arch_16._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax
    _16bit_length = len(arch_16.asm(instruction))

    arch_32 = ArchX86()  # get architecture
    # a.bits=16
    # arch_32.reg_blacklist = ('gdt', 'ldt')  # make cs,ds valid
    arch_32.keystone  # init keystone assembler  # noqa: B018
    arch_32._ks.sym_resolver = resolver  # set resolver
    # a._ks_x86_syntax = 'masm'
    # a._configure_keystone()
    arch_32._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax
    addr = 1
    instruction = re.sub(r"\b[cdefgs]s:", "", instruction)
    bytes = arch_32.asm(instruction)
    vex = pyvex.lift(bytes, addr, arch_32)
    assert vex.statements
    vex._size = _16bit_length
    vex.statements[0].len = _16bit_length

    vex.default_exit_target = addr + _16bit_length
    vex.next = pyvex.expr.Const(pyvex.const.U32(addr + _16bit_length))
    return vex


def get_instructions_sizes(CODE):  # noqa: ANN001, ANN201, D103
    from keystone import KS_ARCH_X86, KS_MODE_16, KS_MODE_32, Ks, KsError

    sizes16 = []
    sizes32 = []
    for line in CODE.splitlines():
        if line:
            try:
                ks16 = Ks(KS_ARCH_X86, KS_MODE_16)
                # ks16.syntax = KS_OPT_SYNTAX_MASM
                data16, count16 = ks16.asm(line, as_bytes=True)
                if not data16:
                    continue
                assert count16 == 1
                data16_size = len(data16)

                ks32 = Ks(KS_ARCH_X86, KS_MODE_32)
                # ks32.syntax = KS_OPT_SYNTAX_MASM
                data32, count32 = ks32.asm(line, as_bytes=True)
                assert data32
                assert count32 == 1
                data32_size = len(data32)

                if data16_size == 0:
                    continue
                print(f"{CODE} = {data16} (number of statements: {count16})")
                sizes16.append(data16_size)
                sizes32.append(data32_size)
            except KsError as e:
                print(f"ERROR: {e}")
                exit(1)
    return sizes16, sizes32


class myContext:  # noqa: D101
    def __init__(  # noqa: D107
        self,
    ) -> None:
        self.results = []


class myRdTmp:  # noqa: D101
    @staticmethod
    def get_temp(obj, context) -> None:  # noqa: ANN001, D102
        context.results.append(obj._tmp)

    @staticmethod
    def set_temp(obj, context) -> None:  # noqa: ANN001, D102
        if len(context.results) == 0:
            raise Exception
        obj._tmp = context.results.pop(0)


class myWrTmp:  # noqa: D101
    @staticmethod
    def get_temp(obj, context) -> None:  # noqa: ANN001, D102
        context.results.append(obj.tmp)

    @staticmethod
    def set_temp(obj, context) -> None:  # noqa: ANN001, D102
        obj.tmp = context.results.pop(0)


def arg_walker(args: IRSB, op, context: myContext) -> None:  # noqa: ANN001, D103
    if isinstance(args, RdTmp):  # noqa: F405
        getattr(myRdTmp, op)(args, context)
    elif isinstance(args, Load):  # noqa: F405
        arg_walker(args.addr, op, context)
    elif isinstance(args, (Unop, Binop, Triop)):  # noqa: F405
        for arg in args.args:
            arg_walker(arg, op, context)


def statement_walker(vex: IRSB, op, context: myContext) -> None:  # noqa: ANN001, D103
    for stmt in vex.statements:
        if isinstance(stmt, WrTmp):  # noqa: F405
            getattr(myWrTmp, op)(stmt, context)
            arg_walker(stmt.data, op, context)
        elif isinstance(stmt, Put):  # noqa: F405
            arg_walker(stmt.data, op, context)
    arg_walker(vex.next, op, context)


def merge_vexes(vex1, vex2_):  # noqa: ANN001, ANN201, D103
    vex2 = deepcopy(vex2_)
    # Get temporary variables indexes for instr 1
    max_temp = len(vex1._tyenv.types)  # max(c1.results)

    # Get temporary variables indexes for instr 2
    c2 = myContext()
    statement_walker(vex2, "get_temp", c2)
    # print(c2.results)

    # Shift second instruciton indexes
    for i in range(len(c2.results)):
        c2.results[i] += max_temp

    # Add PUT(eip) = x
    # vex1.statements.append(Put(copy(vex1.next), 68))
    # Fix temporaries indexes
    statement_walker(vex2, "set_temp", c2)

    # Fix addr inside IMark
    # assert isinstance(vex2.statements[0], IMark)
    # vex2.statements[0].addr += vex1._size

    # Merge instructions
    vex2.statements = vex1.statements + vex2.statements
    # Fix temporaries indexes
    ##c1.results += c2.results
    ##statement_walker(vex1, 'set_temp', c1)

    # Merge types
    vex2._tyenv.types = vex1._tyenv.types + vex2._tyenv.types

    # Sum number of instructions
    vex2._instructions = vex1._instructions + vex2._instructions
    # Update default_exit_target
    ##vex1.default_exit_target = vex2.default_exit_target
    # Add instruction addresses
    vex2._instruction_addresses = tuple(
        list(vex1._instruction_addresses) + [vex1._size + ins_addr for ins_addr in vex2._instruction_addresses]
    )
    # Increase size
    vex2._size = vex1._size + vex2._size
    # Fix next
    ##vex1.next = copy(vex2.next)  #pyvex.expr.Const(pyvex.const.U32(vex1._size))
    ##vex1.jumpkind = vex2.jumpkind

    return vex2


if __name__ == "__main__":
    try:
        import capstone as _capstone
    except ImportError:
        _capstone = None

    try:
        import keystone as _keystone
    except ImportError:
        _keystone = None

    # angr.block.DEFAULT_VEX_ENGINE = Lifter16(None)

    # print(pyvex.lift(a.asm('je 3'), 0, a).pp())
    # print(pyvex.lift(a.asm('adc ax,5\nmul ax'), 0, a).pp())
    # print(pyvex.lift(a.asm('adc ax,abcd'), 0, a).pp())
    instruction = "add ax,abcd"
    # instruction = 'mov word ptr es:[di],0x42'
    # instruction = 'inc eax'

    #########
    # vex = vexer(instruction)
    # print(vex.pp())
    #########
    # exit(0)

    # print(pyvex.lift(a.asm('jp abcd'), 0, a).pp())
    # print(pyvex.lift(a.asm('clc')+a.asm('add ax,3')+a.asm('adc ax,5')+a.asm('mul ax')+a.asm('clc'), 0, a).pp())
    arch_32 = ArchX86()  # get architecture

    """
    print(1)
    vex1 = pyvex.lift(arch_32.asm('add     eax, dword ptr [esp + 4]'), 0, arch_32)
    #vex1 = pyvex.lift(arch_32.asm('jmp 4'), 0, arch_32)
    print(vex1.pp())

    # print(Lifter16.render_vex_to_json(vex))

    # with open("1.txt", "w") as text_file:
    #    text_file.write(Lifter16.render_vex_to_json(vex))

    print(2)
    vex2 = pyvex.lift(arch_32.asm('sub     ebx, dword ptr [esp + 0xc]'), 0, arch_32)
    #vex2 = pyvex.lift(arch_32.asm('jmp 8'), 0, arch_32)
    print(vex2.pp())
    #print(Lifter16.render_vex_to_json(vex2))
    # with open("2.txt", "w") as text_file:
    #    text_file.write(Lifter16.render_vex_to_json(vex))

    vex = merge_vexes(vex1, vex2)
    '''
    c.results = []
    statement_walker(vex, 'get_temp', c)
    print(c.results)
    '''
    print(vex.pp())

    #exit(0)

    print(12)
    vex = pyvex.lift(arch_32.asm('''add     eax, dword ptr [esp + 4]
            sub     ebx, dword ptr [esp + 0xc]'''), 0, arch_32)
    #vex = pyvex.lift(arch_32.asm('''  mov al,1
    #        jmp 80    '''), 0, arch_32)
    print(vex.pp())
    #print(Lifter16.render_vex_to_json(vex))
    # with open("12.txt", "w") as text_file:
    #    text_file.write(Lifter16.render_vex_to_json(vex))
    exit(0)
    """

    # Lifter16.render_vex_to_json(vex)
    # a.bits=32

    # bytes = a.asm('push ebp')+a.asm('mov ebp,esp')+a.asm('mov eax,[ebp+8]')+a.asm('mov ebx,[ebp+0xc]')+a.asm('add ax,bx')+a.asm('pop ebp')+a.asm('ret')
    # ;push     ebp
    # ;mov     ebp, esp

    arch_32 = ArchX86()  # get architecture
    # arch_32.reg_blacklist = ('gdt', 'ldt')  # make cs,ds valid
    arch_32.keystone  # init keystone assembler  # noqa: B018
    arch_32._ks.sym_resolver = resolver  # set resolver
    arch_32._ks._syntax = _keystone.KS_OPT_SYNTAX_MASM  # set syntax

    """
    bytes = arch_32.asm('''

            mov     eax, dword ptr [esp + 4]
            mov     ebx, dword ptr [esp + 0xc]
            mov     ecx, dword ptr [esp + 8]
            sub ax,abcd
            ja second
            sub ax,cx
        second:
            movzx eax,ax
            ret
    ''')

    bytes = arch_32.asm('''
            mov     eax, dword ptr [esp + 4]
            mov     ecx, dword ptr [esp + 8]
            shl     ecx, 4
            mov     eax, dword ptr [eax + ecx]
            ret
    ''')

    bytes = arch_32.asm('''

            mov     eax, dword ptr [esp + 4]
            mov     ebx, dword ptr [esp + 0xc]
            mov     ecx, dword ptr [esp + 8]
            sub ax,abcd
            sub ax,cx
            movzx eax,ax
            ret
    ''')
    """

    CODE = """
        movzx     eax, word ptr [esp + 4]
        movzx     ecx, word ptr [esp + 8]
        shl     ecx, 4
        movzx  ecx,cx
        mov     ax, word ptr [eax + ecx]
        movzx eax,ax
        ret
        """
    CODE = """
            imul bx
            movzx     eax, word ptr [esp + 4]
            movzx     ecx, word ptr [esp + 8]
            sub ax,42
            sub ax,cx
            movzx eax,ax
            ret
    """

    # sizes_16bit, sizes_32bit = get_instructions_sizes(CODE)
    bytes_ = assembler(CODE, 16)

    print(bytes_)

    project = angr.load_shellcode(bytes_, arch_32, start_offset=0, load_address=0, selfmodifying_code=False)
    cfg = project.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions[0]

    _ = project.analyses[VariableRecoveryFast].prep()(func)
    cca = project.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
    func.calling_convention = cca.cc
    func.prototype = cca.prototype

    dec = project.analyses[Decompiler].prep()(func, cfg=cfg.model)
    assert dec.codegen is not None, f"Failed to decompile function {func!r}."
    print(f"Decompiled function {func!r}\n{dec.codegen.text}")

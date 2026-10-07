import logging

import networkx as nx
import numpy as np
from capstone import CS_ARCH_X86, CS_MODE_16, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from tools.ada_script.utils import handle_error, logger  # Assume utils.py exists or inline


class EmulationAnalyzer:
    def __init__(self, binary, db, full=False, classify=False, xrefs=False):
        self.binary = binary
        self.db = db
        self.full = full
        self.classify = classify
        self.compute_xrefs = xrefs
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)
        self.md.detail = True
        self.functions = {}
        self.instructions = []
        self.xrefs = []
        self.cfg = nx.DiGraph()

    def disassemble_segments(self):
        try:
            self.instructions = []
            self.cfg.clear()
            # Query segments from DB
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT start_addr, end_addr FROM segments WHERE executable = 1")
            segments = cursor.fetchall()
            total_disasm_bytes = 0
            for start, end in segments:
                end = min(end, len(self.binary))
                if start >= end:
                    continue
                code = self.binary[start:end]
                for i in self.md.disasm(code, start):
                    ops = []
                    for op in i.operands:
                        if op.type == X86_OP_IMM:
                            ops.append({'type': 'imm', 'value': op.imm})
                        elif op.type == X86_OP_MEM:
                            ops.append({'type': 'mem', 'base': op.mem.base, 'index': op.mem.index, 'scale': op.mem.scale, 'disp': op.mem.disp})
                        elif op.type == X86_OP_REG:
                            ops.append({'type': 'reg', 'value': op.reg})
                    inst = {
                        'addr': i.address,
                        'size': i.size,
                        'mnem': i.mnemonic,
                        'op_str': i.op_str,
                        'operands': ops,
                        'classified': False
                    }
                    self.instructions.append(inst)
                    # Add to CFG
                    self.cfg.add_node(i.address)
                    # Branches/calls for edges
                    if i.mnemonic in ['call', 'jmp', 'je', 'jne', 'ja', 'jb', 'loop']:
                        if any(op['type'] == 'imm' for op in ops):
                            target = next(op['value'] for op in ops if op['type'] == 'imm')
                            self.cfg.add_edge(i.address, target)
                total_disasm_bytes += (end - start)
            # Insert instructions to DB
            for inst in self.instructions:
                self.db.execute("INSERT OR IGNORE INTO instructions (addr, size, mnem, op_str, type) VALUES (?, ?, ?, ?, ?)",
                                (inst['addr'], inst['size'], inst['mnem'], inst['op_str'], 'code'))
            total_size = sum(end - start for start, end in segments)
            coverage = (total_disasm_bytes / total_size * 100) if total_size > 0 else 0
            logger.info(f"Disassembled {len(self.instructions)} instructions across {len(segments)} segments, coverage: {coverage:.1f}%")
        except CsError as e:
            handle_error(f"Disasm error: {e}", e)
            self.instructions = []

    def classify_regions(self):
        if not self.classify:
            logger.info("Skipping classification (--classify not set)")
            return
        try:
            for inst in self.instructions:
                addr = inst['addr']
                window_start = max(0, addr - 32)
                window_end = min(len(self.binary), addr + 32)
                window = self.binary[window_start:window_end]
                entropy = self._calc_entropy(window)
                is_data = entropy < 3.0 or self._is_data_signature(inst)
                inst['classified'] = 'data' if is_data else 'code'
                self.db.execute("UPDATE OR IGNORE instructions SET type=? WHERE addr=?", ('data' if is_data else 'code', addr))
            logger.info("Classification complete")
        except Exception as e:
            logger.warning(f"Classification failed: {e} - using default 'code'")
            for inst in self.instructions:
                inst['classified'] = 'code'

    def _calc_entropy(self, data):
        if not data:
            return 0
        hist, _ = np.histogram(list(data), bins=256, density=True)
        hist = hist[hist > 0]
        if len(hist) == 0:
            return 0
        entropy = 0.0
        for p in hist.tolist():
            entropy -= float(p) * float(np.log2(p))
        return entropy

    def _is_data_signature(self, inst):
        if 'mov' in inst['mnem'] and any(op['type'] == 'imm' and 0 <= op['value'] <= 63 for op in inst['operands']):
            return True
        return False

    def detect_functions(self):
        if not self.full:
            logger.info("Skipping full function detection (--full not set)")
            return
        self.functions = {}
        # Use CFG for better detection
        for component in nx.weakly_connected_components(self.cfg):
            if len(component) < 3:  # Skip small components
                continue
            # Find potential start: node with no in-edges or prologue
            starts = [node for node in component if self.cfg.in_degree(node) == 0]
            if not starts:
                starts = list(component)[:1]  # Fallback
            for start in starts:
                inst = next((i for i in self.instructions if i['addr'] == start), None)
                if inst and self._is_prologue(inst):
                    func_end = self._find_epilogue(start)
                    name = f"sub_{start:X}"
                    # Check symbols from IDC for better names
                    cursor = self.db.conn.cursor()
                    cursor.execute("SELECT name FROM symbols WHERE addr = ?", (start,))
                    sym = cursor.fetchone()
                    if sym:
                        name = sym[0]
                    self.functions[start] = {
                        'name': name,
                        'start': start,
                        'end': func_end,
                        'calls': list(self.cfg.successors(start))
                    }
                    self.db.execute("INSERT OR REPLACE INTO functions (start, end, name) VALUES (?, ?, ?)",
                                    (start, func_end, name))
        logger.info(f"Detected {len(self.functions)} functions using CFG")

    def _is_prologue(self, inst):
        prologue_patterns = [
            (inst['mnem'] == 'push' and 'bp' in inst['op_str']),
            (inst['mnem'] == 'mov' and 'bp,sp' in inst['op_str']),
            (inst['mnem'] == 'xor' and 'bp,bp' in inst['op_str']),
            (inst['mnem'] == 'enter' and len(inst['operands']) >= 1),
            # DOS/16-bit specifics
            (inst['mnem'] == 'mov' and 'sp,0xFFFE' in inst['op_str']),  # Common DOS stack init
            (inst['mnem'] == 'push' and 'ax' in inst['op_str'] and inst['addr'] == self.db.get_entry()),  # Entry push
        ]
        return any(pattern for pattern in prologue_patterns)

    def _find_epilogue(self, start):
        for i in self.instructions:
            if i['addr'] >= start and i['mnem'] in ['ret', 'retn', 'retf']:
                return i['addr'] + i['size']
        return len(self.binary)

    def detect_xrefs(self):
        if not self.compute_xrefs:
            logger.info("Skipping xref computation (--xrefs not set)")
            return
        try:
            self.xrefs = []
            # From CFG edges
            for fr, to in self.cfg.edges:
                inst = next((i for i in self.instructions if i['addr'] == fr), None)
                if inst:
                    mnem = inst['mnem']
                    xtype = 'call' if mnem.startswith('call') else 'jmp' if mnem == 'jmp' else 'branch'
                    self.xrefs.append((fr, to, xtype, mnem))
            # Data xrefs: imm in non-control flow insts
            for inst in self.instructions:
                if inst['mnem'] not in ['call', 'jmp', 'je', 'jne', 'ja', 'jb', 'loop']:
                    for op in inst['operands']:
                        if op['type'] == 'imm' and op['value'] > 0:
                            target = op['value']
                            self.xrefs.append((inst['addr'], target, 'data', inst['mnem']))
            # Insert to DB (assume add_xref or use execute)
            for fr, to, typ, instr in self.xrefs:
                self.db.execute("INSERT OR IGNORE INTO xrefs (from_addr, to_addr, type, instruction) VALUES (?, ?, ?, ?)",
                                (fr, to, typ, instr))
            logger.info(f"Detected {len(self.xrefs)} xrefs")
        except Exception as e:
            handle_error(f"Xref detection failed: {e}", e)

    def analyze(self):
        self.disassemble_segments()
        if self.classify:
            self.classify_regions()
        if self.full:
            self.detect_functions()
        if self.compute_xrefs:
            self.detect_xrefs()
        # Compute overall coverage
        total_code_bytes = sum(inst['size'] for inst in self.instructions if inst.get('classified', 'code') != 'data')
        total_size = len(self.binary)
        coverage = (total_code_bytes / total_size * 100) if total_size > 0 else 0
        self.db.execute("INSERT OR REPLACE INTO stats (key, value) VALUES ('code_coverage', ?)", (coverage,))
        logging.debug(f"Coverage calc: {total_code_bytes} code bytes / {total_size} total = {coverage:.1f}%")
        logger.info(f"Analysis complete: {len(self.instructions)} insts, {len(self.functions)} funcs, {coverage:.1f}% coverage")

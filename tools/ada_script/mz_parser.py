import struct
from collections import Counter

from tools.ada_script.database import Database
from tools.ada_script.utils import handle_error

# Linear base address at which IDA loads an MZ load module (1000h:0000).
LOAD_BASE = 0x10000


class MZParser:
    """Parses an MZ/EXE header and seeds the analysis database.

    Address model used across the whole project: every address is a *linear*
    address where the first byte of the load image is mapped at 0x10000.
    file_offset(addr) = header_size + (addr - LOAD_BASE).
    """

    def __init__(self, binary):
        self.binary = binary
        self.header = {}
        self.image_size = 0
        self.header_size = 0
        self.entry_addr = 0
        self.relocs = []  # list of (linear_addr_of_word, pointed_seg_base_linear)

    def parse(self):
        try:
            if len(self.binary) < 28 or self.binary[:2] != b'MZ':
                raise ValueError("Invalid MZ/EXE signature or file too short")

            b = self.binary
            h = self.header
            h['last_page_bytes'] = struct.unpack('<H', b[2:4])[0]   # e_cp
            h['pages'] = struct.unpack('<H', b[4:6])[0]              # e_cpage
            h['num_relocs'] = struct.unpack('<H', b[6:8])[0]         # e_crlc
            h['header_paras'] = struct.unpack('<H', b[8:10])[0]      # e_cparhdr
            h['min_paras'] = struct.unpack('<H', b[10:12])[0]
            h['max_paras'] = struct.unpack('<H', b[12:14])[0]
            h['ss'] = struct.unpack('<H', b[14:16])[0]
            h['sp'] = struct.unpack('<H', b[16:18])[0]
            h['csum'] = struct.unpack('<H', b[18:20])[0]
            h['ip'] = struct.unpack('<H', b[20:22])[0]
            h['cs'] = struct.unpack('<H', b[22:24])[0]
            h['reloc_offset'] = struct.unpack('<H', b[24:26])[0]
            h['overlay_num'] = struct.unpack('<H', b[26:28])[0]

            self.header_size = h['header_paras'] * 16
            last = h['last_page_bytes'] or 512
            self.image_size = (h['pages'] - 1) * 512 + last - self.header_size
            if self.image_size <= 0:
                self.image_size = len(b) - self.header_size
            # image may not extend past EOF
            self.image_size = min(self.image_size, len(b) - self.header_size)
            image_end = LOAD_BASE + self.image_size

            self.entry_addr = LOAD_BASE + (h['cs'] << 4) + h['ip']

            db = Database('analysis.db', fresh=True)
            db.image_base = LOAD_BASE
            db.header_size = self.header_size
            db.image_size = self.image_size

            for key, val in (
                ('load_base', LOAD_BASE), ('header_size', self.header_size),
                ('image_size', self.image_size), ('image_end', image_end),
                ('entry_addr', self.entry_addr),
                ('ss', h['ss']), ('sp', h['sp']), ('cs', h['cs']), ('ip', h['ip']),
            ):
                db.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                           (key, str(val)))

            # Relocation table: each entry is a far pointer (off:seg) to a word
            # inside the image holding a segment value relative to image start.
            reloc_start = h['reloc_offset']
            relocs = []
            for i in range(h['num_relocs']):
                off = reloc_start + i * 4
                if off + 4 > len(b):
                    break
                roff, rseg = struct.unpack('<HH', b[off:off + 4])
                loc = LOAD_BASE + (rseg << 4) + roff
                fo = loc - LOAD_BASE + self.header_size
                pointed = None
                if 0 <= fo + 2 <= len(b):
                    pointed = LOAD_BASE + (struct.unpack('<H', b[fo:fo + 2])[0] << 4)
                relocs.append((loc, pointed))
                db.execute("INSERT INTO relocations (addr, offset) VALUES (?, ?)",
                           (loc, pointed if pointed is not None else 0))
            self.relocs = relocs

            # Default segments (IDC may delete and recreate them).
            # CODE: whole load image.  STACK: from ss:sp.
            db.execute(
                "INSERT INTO segments (start_addr, end_addr, base, class, type, executable, name) "
                "VALUES (?, ?, ?, 'CODE', 'code', 1, 'seg000')",
                (LOAD_BASE, image_end, LOAD_BASE >> 4))
            stack_start = LOAD_BASE + (h['ss'] << 4)
            stack_end = stack_start + (h['sp'] or 0x1000)
            db.execute(
                "INSERT INTO segments (start_addr, end_addr, base, class, type, executable, name) "
                "VALUES (?, ?, ?, 'STACK', 'stack', 0, 'seg_stack')",
                (stack_start, stack_end, (h['ss'] + 0x1000) & 0xFFFF))

            # Guess the default data segment from relocation targets: the most
            # common segment paragraph pointed to by relocations is the DGROUP.
            seg_votes = Counter(p for _, p in relocs if p)
            if seg_votes:
                dseg_base, _cnt = seg_votes.most_common(1)[0]
                db.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('default_ds', ?)",
                           (str(dseg_base >> 4),))
                if dseg_base > LOAD_BASE and dseg_base < stack_start:
                    db.execute(
                        "INSERT INTO segments (start_addr, end_addr, base, class, type, executable, name) "
                        "VALUES (?, ?, ?, 'DATA', 'data', 0, 'dseg')",
                        (dseg_base, stack_start, dseg_base >> 4))
                    if dseg_base < image_end:
                        db.execute("UPDATE segments SET end_addr=? WHERE start_addr=? AND type='code'",
                                   (dseg_base, LOAD_BASE))

            db.execute("INSERT OR REPLACE INTO symbols (addr, name) VALUES (?, ?)",
                       (self.entry_addr, 'start'))

            print(f"MZ parsing complete: entry at {self.entry_addr:#x}, "
                  f"{h['num_relocs']} relocs, image {self.image_size:#x} bytes")
            return db

        except struct.error as e:
            handle_error(f"MZ unpack error (invalid binary format): {e}", e)
            raise ValueError("Failed to parse MZ header - possibly corrupted or non-MZ file")
        except Exception as e:
            handle_error(f"MZ parse error: {e}", e)
            raise

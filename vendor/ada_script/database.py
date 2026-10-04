import sqlite3

from utils import handle_error, logger  # Assume utils.py with logging


class Database:
    TABLES = (
        'instructions', 'functions', 'symbols', 'xrefs', 'segments',
        'relocations', 'comments', 'extra_comments', 'data_items',
        'code_seeds', 'op_overrides', 'enums', 'enum_members', 'strucs',
        'struc_members', 'sregs', 'sreg_ranges', 'frame_vars', 'frames',
        'stats', 'config',
    )

    def __init__(self, path='analysis.db', fresh=False):
        """Open (or create) the analysis database.

        Opening is non-destructive: existing rows survive.  Pass fresh=True
        only when a new analysis run intentionally resets all tables --
        a casual ``Database('analysis.db')`` must never wipe real data.
        """
        try:
            self.conn = sqlite3.connect(path)
            self.binary = b""
            self.image_base = 0x10000
            self.header_size = 0
            self.image_size = 0
            if fresh:
                self._drop_tables()
            self._create_tables()
            logger.info(f"DB initialized: {path}")
        except sqlite3.Error as e:
            handle_error(f"DB init failed: {e}", e, fatal=True)
            raise

    def _drop_tables(self):
        cur = self.conn.cursor()
        for t in self.TABLES:
            cur.execute(f"DROP TABLE IF EXISTS {t}")
        self.conn.commit()

    def _create_tables(self):
        try:
            cur = self.conn.cursor()
            # Instructions table. db_bytes: hex string of original bytes to
            # emit verbatim in .asm when uasm cannot reproduce the encoding
            cur.execute("""
                CREATE TABLE IF NOT EXISTS instructions (
                    addr INTEGER PRIMARY KEY,
                    size INTEGER,
                    mnem TEXT,
                    op_str TEXT,
                    asm_str TEXT,
                    type TEXT DEFAULT 'code',
                    db_bytes TEXT
                )
            """)
            cols = {r[1] for r in cur.execute(
                "PRAGMA table_info(instructions)")}
            if 'db_bytes' not in cols:
                cur.execute(
                    "ALTER TABLE instructions ADD COLUMN db_bytes TEXT")
            # Functions table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS functions (
                    start INTEGER PRIMARY KEY,
                    end INTEGER,
                    name TEXT,
                    flags INTEGER DEFAULT 0
                )
            """)
            # Symbols table: explicit names (auto=0) and auto-generated labels
            # (auto=1). kind: 'name','loc','sub','data','str','seg'
            cur.execute("""
                CREATE TABLE IF NOT EXISTS symbols (
                    addr INTEGER PRIMARY KEY,
                    name TEXT,
                    auto INTEGER DEFAULT 0,
                    kind TEXT DEFAULT 'name'
                )
            """)
            # Xrefs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS xrefs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_addr INTEGER NOT NULL,
                    to_addr INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    instruction TEXT,
                    UNIQUE(from_addr, to_addr, type)
                )
            """)
            # Segments table (enhanced)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS segments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_addr INTEGER NOT NULL,
                    end_addr INTEGER NOT NULL,
                    base INTEGER DEFAULT 0,
                    class TEXT DEFAULT 'UNKNOWN',
                    type TEXT DEFAULT 'code',
                    executable INTEGER DEFAULT 0,
                    entropy REAL DEFAULT 0.0,
                    align INTEGER DEFAULT 1,
                    comb INTEGER DEFAULT 2,
                    name TEXT
                )
            """)

            # Relocations table: addr = linear address of relocated word,
            # offset = linear segment base the word points at
            cur.execute("""
                CREATE TABLE IF NOT EXISTS relocations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    addr INTEGER NOT NULL,
                    offset INTEGER NOT NULL
                )
            """)

            # Comments table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    addr INTEGER PRIMARY KEY,
                    comment TEXT NOT NULL,
                    repeatable INTEGER DEFAULT 0
                )
            """)

            # Anterior/posterior comment lines (update_extra_cmt)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS extra_comments (
                    addr INTEGER NOT NULL,
                    line INTEGER NOT NULL,
                    comment TEXT,
                    PRIMARY KEY (addr, line)
                )
            """)

            # Defined data items (create_byte/word/dword, make_array, strlit)
            # kind: 'byte','word','dword','str'; count = array elements
            cur.execute("""
                CREATE TABLE IF NOT EXISTS data_items (
                    addr INTEGER PRIMARY KEY,
                    size INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    count INTEGER DEFAULT 1
                )
            """)

            # create_insn() markers: addresses that must be decoded as code
            cur.execute("""
                CREATE TABLE IF NOT EXISTS code_seeds (
                    addr INTEGER PRIMARY KEY
                )
            """)

            # Operand formatting overrides (op_hex/op_enum/op_seg/...)
            # kind: 'hex','dec','enum','offset','seg','stkvar','char','struct'
            cur.execute("""
                CREATE TABLE IF NOT EXISTS op_overrides (
                    addr INTEGER NOT NULL,
                    opnum INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    arg INTEGER DEFAULT 0,
                    arg2 INTEGER DEFAULT 0,
                    PRIMARY KEY (addr, opnum)
                )
            """)

            # Enums
            cur.execute("""
                CREATE TABLE IF NOT EXISTS enums (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS enum_members (
                    enum_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    value INTEGER NOT NULL,
                    PRIMARY KEY (enum_id, value)
                )
            """)

            # Structures (add_struc / add_struc_member)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS strucs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS struc_members (
                    struc_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    offset INTEGER NOT NULL,
                    size INTEGER DEFAULT 1,
                    PRIMARY KEY (struc_id, offset)
                )
            """)

            # Default segment register values per segment (SegDefReg) and
            # explicit split_sreg_range() ranges.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sregs (
                    seg_start INTEGER NOT NULL,
                    reg TEXT NOT NULL,
                    value INTEGER NOT NULL,
                    PRIMARY KEY (seg_start, reg)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sreg_ranges (
                    start_addr INTEGER NOT NULL,
                    end_addr INTEGER NOT NULL,
                    reg TEXT NOT NULL,
                    value INTEGER NOT NULL,
                    PRIMARY KEY (start_addr, reg)
                )
            """)

            # Stack frame variables (define_local_var): offset is bp-relative
            cur.execute("""
                CREATE TABLE IF NOT EXISTS frame_vars (
                    func_start INTEGER NOT NULL,
                    offset INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    size INTEGER DEFAULT 0,
                    PRIMARY KEY (func_start, offset)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS frames (
                    func_start INTEGER PRIMARY KEY,
                    frsize INTEGER DEFAULT 0,
                    frregs INTEGER DEFAULT 0,
                    argsize INTEGER DEFAULT 0
                )
            """)

            # Stats table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS stats (
                    key TEXT PRIMARY KEY,
                    value REAL
                )
            """)

            # Processor config
            cur.execute("""
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            self.conn.commit()
            logger.debug("Tables created/verified")
        except sqlite3.Error as e:
            handle_error(f"Table creation failed: {e}", e)
            raise

    def execute(self, query, params=()):
        try:
            cur = self.conn.cursor()
            cur.execute(query, params)
            self.conn.commit()
            return cur
        except sqlite3.Error as e:
            logger.error(f"DB query failed: {query[:50]}... - {e}")
            if 'CREATE' in query:
                logger.info("Retrying table creation...")
                self._create_tables()
                # Retry once
                try:
                    cur = self.conn.cursor()
                    cur.execute(query, params)
                    self.conn.commit()
                    return cur
                except sqlite3.Error:
                    pass
            raise

    def add_xref(self, from_addr, to_addr, xtype, instruction=''):
        try:
            self.execute("""
                INSERT OR IGNORE INTO xrefs (from_addr, to_addr, type, instruction)
                VALUES (?, ?, ?, ?)
            """, (from_addr, to_addr, xtype, instruction))
        except Exception as e:
            logger.warning(f"Xref add failed {from_addr}->{to_addr}: {e}")

    def get_xrefs_to(self, addr):
        try:
            return self.execute("SELECT * FROM xrefs WHERE to_addr=?", (addr,)).fetchall()
        except Exception as e:
            logger.warning(f"Xref query failed for {hex(addr)}: {e}")
            return []

    def file_offset(self, addr):
        """Linear address -> file offset (None if outside the image)."""
        fo = self.header_size + (addr - self.image_base)
        if fo < 0 or fo >= len(self.binary):
            return None
        return fo

    def read_bytes(self, addr, size):
        fo = self.file_offset(addr)
        if fo is None:
            return None
        return self.binary[fo:fo + size]

    def close(self):
        try:
            self.conn.close()
            logger.debug("DB closed")
        except Exception as e:
            logger.warning(f"DB close failed: {e}")

"""Rizin-assisted analysis backend.

Rizin's built-in analysis ('aaa'/'af') does not handle 16-bit MZ code, so this
backend uses Rizin for what it is good at — fast linear 'pdj' decoding with
type/jump metadata — to *discover procedures* (call targets) inside the
executable segments stored in the database.

The actual labeled disassembly is produced by the capstone Analyzer, which
consumes the discovered functions from the DB.
"""
from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path

from analysis_backend import AnalysisOptions

logger = logging.getLogger(__name__)


def _require_rizin():
    try:
        import rzpipe  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "Rizin backend requires 'rzpipe'. Install it in the active venv."
        ) from exc
    if shutil.which("rizin") is None:
        raise RuntimeError("Rizin backend requires 'rizin' executable in PATH.")


def _open_mapped(rzpipe, path, image_base, header_size):
    """Open the file in rizin with the load image mapped at image_base.

    The MZ bin plugin produces useless maps, so we open raw, drop the bin
    maps and create our own: file offset X -> vaddr X + (base - hdrsize).
    """
    rz = rzpipe.open(str(path), flags=["-q", "-m", "0"])  # no io maps initially
    rz.cmd("e asm.arch=x86")
    rz.cmd("e asm.bits=16")
    rz.cmd("e io.cache=true")
    vaddr = image_base - header_size
    rz.cmd(f"om {path} {vaddr} 0x{path.stat().st_size:x} r-x")
    return rz


def discover_functions(binary: bytes, db) -> int:
    """Scan executable segments with rizin and record call targets as
    functions in the DB. Returns the number of procedures discovered."""
    _require_rizin()
    import rzpipe

    segs = db.conn.execute(
        "SELECT start_addr, end_addr FROM segments WHERE executable = 1 "
        "ORDER BY start_addr").fetchall()
    if not segs:
        return 0

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(binary)
        tmp_path = Path(tmp.name)

    known = {r[0] for r in db.conn.execute("SELECT start FROM functions")}
    found = 0
    rz = None
    try:
        rz = _open_mapped(rzpipe, tmp_path, db.image_base, db.header_size)
        for start, end in segs:
            cur = start
            while cur < end:
                span = min(0x4000, end - cur)
                ops = rz.cmdj(f"pdj {span} @ 0x{cur:x}") or []
                for op in ops:
                    a = op.get("offset")
                    typ = op.get("type")
                    if not isinstance(a, int) or a < cur or a >= cur + span:
                        continue
                    if typ == "call":
                        tgt = op.get("jump")
                        # accept near call targets inside an exec segment
                        if isinstance(tgt, int) and any(
                                s <= tgt < e for s, e in segs) and tgt not in known:
                            db.execute(
                                "INSERT OR IGNORE INTO functions "
                                "(start, end, name, flags) VALUES (?, ?, NULL, 0)",
                                (tgt, tgt))
                            known.add(tgt)
                            found += 1
                n = len(ops)
                cur += span if n == 0 else max(span, 1)
        # rizin's own analysis may still find something; merge if so
        try:
            rz.cmd("e anal.in=io.maps.x")
            rz.cmd("aac")
            for fn in rz.cmdj("aflj") or []:
                off, size, name = fn.get("offset"), fn.get("size"), fn.get("name")
                if isinstance(off, int) and off not in known and \
                        any(s <= off < e for s, e in segs):
                    db.execute(
                        "INSERT OR IGNORE INTO functions "
                        "(start, end, name, flags) VALUES (?, ?, ?, 0)",
                        (off, off + (size or 0), name))
                    known.add(off)
                    found += 1
        except Exception as exc:
            logger.debug(f"rizin aac pass skipped: {exc}")
    finally:
        if rz is not None:
            try:
                rz.quit()
            except Exception:
                pass
        tmp_path.unlink(missing_ok=True)
    logger.info(f"Rizin discovery: {found} procedures")
    return found


class RizinBackend:
    """Rizin discovers procedures; the capstone Analyzer renders labels."""

    def __init__(self, binary: bytes, db, options: AnalysisOptions):
        self.binary = binary
        self.db = db
        self.options = options

    def analyze(self) -> None:
        discover_functions(self.binary, self.db)
        from analyzer import Analyzer
        Analyzer(self.binary, self.db,
                 full=self.options.full,
                 classify=self.options.classify,
                 xrefs=self.options.xrefs).analyze()

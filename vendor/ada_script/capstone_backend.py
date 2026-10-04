from __future__ import annotations

from analysis_backend import AnalysisOptions
from analyzer import Analyzer


class CapstoneBackend:
    """Capstone-based analyzer producing IDA-style labeled disassembly.

    Disassembles executable regions (IDC-defined or discovered), resolves
    jump/call/data references into labels, applies operand overrides and
    stores the rendered instructions into the database.
    """

    def __init__(self, binary: bytes, db, options: AnalysisOptions):
        self._analyzer = Analyzer(
            binary,
            db,
            full=options.full,
            classify=options.classify,
            xrefs=options.xrefs,
        )

    def analyze(self) -> None:
        self._analyzer.analyze()

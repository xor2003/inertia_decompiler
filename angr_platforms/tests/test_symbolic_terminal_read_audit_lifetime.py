"""Parent memory-effect controls for partial stores and transient SSA terms."""



from tools.dosunit import straightline_ssa as ssa
from tools.dosunit.terminal_memory_effects import MemoryReadAuditor


def test_partial_store_keeps_unwritten_initial_read_lanes() -> None:
    """One overwritten byte cannot discharge the other three initial bytes."""
    memory = ssa.SsaExpr('mem_input', 0, name='mem')
    address = ssa.SsaExpr('const', 32, value=0x1000)
    stored = ssa.SsaExpr('storele', 0, (
        memory, address, ssa.SsaExpr('const', 8, value=0x41)))
    auditor = MemoryReadAuditor(admit=lambda address, size: None,
                                initial_bytes=lambda address, size: b'X' * size)
    auditor.audit_term(ssa.SsaExpr('loadle', 32, (stored, address)))
    covered = {byte for site in auditor.initial_sites()
               for byte in range(site.address, site.address + site.size)}
    assert {0x1001, 0x1002, 0x1003} <= covered


def test_discarded_terms_do_not_hide_new_read_effects() -> None:
    """Temporary object lifetime cannot suppress later native read admission."""
    memory = ssa.SsaExpr('mem_input', 0, name='mem')
    seen = []
    auditor = MemoryReadAuditor(admit=lambda address, size: seen.append(address),
                                initial_bytes=lambda address, size: b'X' * size)
    for offset in range(128):
        auditor.audit_term(ssa.SsaExpr('loadle', 8, (
            memory, ssa.SsaExpr('const', 32, value=0x1000 + offset))))
    assert seen == list(range(0x1000, 0x1080))


def test_multiple_stores_fully_cover_initial_read() -> None:
    """Disjoint writes covering every lane need no initial-byte assumption."""
    memory = ssa.SsaExpr('mem_input', 0, name='mem')
    for offset in (0, 2):
        memory = ssa.SsaExpr('storele', 0, (
            memory, ssa.SsaExpr('const', 32, value=0x1000 + offset),
            ssa.SsaExpr('const', 16, value=0x4141)))
    auditor = MemoryReadAuditor(admit=lambda address, size: None,
                                initial_bytes=lambda address, size: b'X' * size)
    auditor.audit_term(ssa.SsaExpr('loadle', 32, (
        memory, ssa.SsaExpr('const', 32, value=0x1000))))
    assert auditor.initial_sites() == ()


def test_middle_store_retains_both_initial_fragments() -> None:
    """A middle overwrite leaves two separate live initial-data intervals."""
    memory = ssa.SsaExpr('storele', 0, (
        ssa.SsaExpr('mem_input', 0, name='mem'),
        ssa.SsaExpr('const', 32, value=0x1001),
        ssa.SsaExpr('const', 16, value=0x4141)))
    auditor = MemoryReadAuditor(admit=lambda address, size: None,
                                initial_bytes=lambda address, size: b'X' * size)
    auditor.audit_term(ssa.SsaExpr('loadle', 32, (
        memory, ssa.SsaExpr('const', 32, value=0x1000))))
    assert [(site.address, site.size) for site in auditor.initial_sites()] == [
        (0x1000, 1), (0x1003, 1)]

# COD Literal Identity Repair

## Scope And Root Cause

September 20: follow-up to the eight-function stability checkpoint.
`DOSFUNC.COD::_dos_resize` passed whole-tail validation but failed C compilation.
Comparing its generated C with listing instructions exposed a separate wrong
argument: `OFFSET __iob+16` became the adjacent assertion string.

The synthetic allocation inventory distinguishes the objects: `SG446` is at
28694 and `iob` at 28698 with an 18-byte span. The literal-evidence collector in
Types/Lowering filtered references to strings, then accepted a unique reference
within eight instruction bytes. Thus an unrelated MOV immediate could inherit
a nearby string even though its storage identity was different. Neither the
shared opcode nor proximity proves identity.

The collector now requires the exact rebased instruction address. If optional
listing alignment is not exact, literal substitution is refused; the underlying
address is retained. No call argument is repaired in Rewrite or CLI.

## Evidence And Acceptance

- The existing collector regression now checks exact rebasing, rejects a
  two-byte mismatch, and includes a distinct pointer load eight bytes away.
  Both parameter cases failed before the fix; all 181 tests in the owning
  segmented-global module pass afterward (8.37 seconds).
- A production CLI rerun produces `fprintf(&iob[0 + 8], ...)` and
  `fflush((struct FILE *)&iob[8])`, rather than assertion-string arguments.
  Artifacts: `.cache/dos-resize-exact-literal.{c,log}`.
- Focused mypy and the mandatory non-test types/docs check pass. Ruff reports
  69 legacy findings across the two touched large files; none are suppressed.
- The routine pipeline passed all three lanes: 6,128 main-lane tests in
  313.66 seconds, QuickC fixtures in 33.41 seconds, and all eight MS C tiny
  examples in 107.665 seconds. This is not the entire repository test suite.
  Evidence: `.cache/cod-literal-pipeline.log` and the pipeline summary JSON.
  `quality-fast` remains blocked by lint debt; its 39-module compiled import
  smoke passes. Full quality log: `.cache/cod-literal-quality.log`.

DoD for this sub-repair: exact-match positive and nearby negative controls pass;
the stream pointer survives the real reproducer; existing routine behavior gates
do not regress; remaining function failures remain visible. Failure: proximity
alone authorizes a literal, pointer identity is changed, or compilation is made
green by deleting calls or suppressing diagnostics.

This is not function-fix acceptance. `_dos_resize` still exits 4: `FILE` is
undeclared, the `ERROR` format argument has incompatible pointer type, and the
generated function still lacks its return. Whole-tail stability alone therefore
does not establish original-source equivalence. Its missing return and fixture
qualification remain separate investigations. Symbol-reference matching still
has proximity-based legacy behavior and needs an evidence-backed audit.

Graph tools were unavailable; exact source and saved artifacts were inspected.
The COD input is an object-listing fixture, not a verified linked executable.

# OMF Relocation Signature Repair

## Cause

The OMF FIXUPP LOCAT field places control bits in its first byte and the low
offset bits in its second byte. It is not a little-endian integer, despite the
byte order of ordinary Intel words. See the
[TIS OMF specification, FIXUP Subrecord](https://openwatcom.org/ftp/devel/docs/omf.pdf).

`omf_pat._parse_fixupp_refs` decoded LOCAT as little-endian. It consequently
masked incorrect byte locations or discarded fixups as out of range. Runtime
signatures then retained addresses that the linker relocates. A synthetic LIDATA
fixture repeated the parser's wrong encoding and did not expose the defect.

The repair is in the optional-signature parser, not decompiler cleanup or call
recovery. It decodes LOCAT control-byte-first and corrects the synthetic fixture.
New tests cover offsets 0, 2, 0x80, 0x102 and 0x3fe. Six regression cases failed
before the repair; all 17 focused OMF tests pass afterward.

## Corpus Evidence

The fixed-seed Csmith program has 69 listed procedures: 67 header-runtime
helpers and two application functions. A separately compiled header-only object
contains no application function. Linking this probe deliberately fails for
missing main; only its successfully compiled OMF object is used for signatures.

On the original linked EXE, pattern hits covered 62 of the 67 runtime procedure
ranges before the fix and all 67 afterward. Neither catalog had hits inside
`func_1` or `main`. This is bounded signature evidence for this binary, not a
claim of universal signature uniqueness or successful decompilation.

Local evidence lives in `.cache/compiler-coverage/csmith-runtime-probe/`:

- `CSMRT.OBJ`: separately compiled runtime object.
- `runtime.pat` and `runtime-fixed.pat`: before/after catalogs.
- `address-audit.json` and `address-audit-fixed.json`: address-range checks using
  the existing OMF matcher and DOSUnit COD parser, not rendered-C matching.
- `build.log`: compilation diagnostics and expected missing-main link error.

The original DOS program exits 0 and prints `checksum = 637A4628`. Rebuilt-program
equivalence is still unverified. Catalog integration must retain ordinary
compiler-library signatures and preserve runtime-call ABI/effects.

## Verification Limits

The new regression is enrolled in `scripts/test_pipeline.py`. The pipeline's
268-test contract preflight passed. The main suite reported 6,370 passed and one
28-second decompilation timeout in the DOS loadProgram regression (458.47 seconds
total). All eight tiny MS C round trips and the QuickC lane passed. The failing
test then passed alone: 22.09 seconds in its call, 46.85 seconds total with xdist
startup. This suggests load-sensitive timing, but the full run remains failed;
no timeout was increased and no test was skipped.

Logs: `.cache/compiler-coverage-fixupp-pipeline.log` and
`.cache/compiler-coverage-loadprogram-isolated.log`.

Whole-file Ruff reports 11 findings and MyPy reports 22 errors outside the edited
parser; this is not a clean whole-file gate.
The edited parser retains complete annotations and has a responsibility docstring.
`quality-fast` also remains red on global linter findings; its retained log is
`.cache/compiler-coverage-fixupp-quality-fast.log`.

# Required Byte-Cast Signedness

## Defect And Owner

`SimTypeChar(False)` carries unsigned byte semantics, but angr's unnamed
`c_repr()` returns `char`, even with an `unsigned char` label. Likewise the
signed variant returns plain `char`. C's default char signedness is not a
portable replacement for either explicit conversion.

`lowering/semantic_cast.py::CSemanticCast8616` owns emission of casts already
required by typed lowering. It now emits `unsigned char` or `signed char` from
the existing boolean type field. Other types and unknown signedness retain
their native representation. This introduces no source/assembly inference,
no AST traversal, no function-body repair, and no Rewrite-stage semantics.

## Evidence (2026-09-09)

- The new compiled regression checks all 256 byte values for both signedness
  contracts under GCC `-fsigned-char` and `-funsigned-char`, with cosmetic casts
  disabled. Before: **2 failed, 9 passed**, 8.21s. Unsigned conversion fails
  under signed-default char; signed conversion fails under unsigned-default.
- After: **25 passed**, seven dependency warnings, 8.77s, including adjacent
  stack-byte-write and assignment-lvalue tests. Scoped Ruff (`--fix`), MyPy
  and Pyright pass. The full semantic-cast test module is now admitted to the
  routine pytest and Ruff lists; compiler-dependent tests remain explicit
  skips if GCC is unavailable, not weakened assertions.
- Fresh `TYPES.EXE --proc byteops_unsigned --no-alternate-source-c --timeout 60
  -q` exits 0, reports `validation=passed`, and has clean whole-tail validation.
  Its byte casts are now explicitly unsigned. Both old and new standalone C
  return the expected `0xC000` under both GCC char defaults when supplied the
  declared EBP variable. Thus the example's fixed-input oracle does not expose
  this defect; the exhaustive conversion regression does.

Logs: `/tmp/inertia-semantic-byte-cast-{before,after,mypy,pyright}.log`.
Fresh function artifacts: `/tmp/inertia-byteops-semantic-cast.{c,log}`.
`quality-fast` exits 0: **3,069 tests pass**, seven warnings, 137.24s, and all
three executable guards pass. Default pipeline exits 2: its unit lane passes
3,069 tests in 123.04s, QuickC passes, and five of seven MSC6 constructs rebuild
and execute with exit 255. The same two failures remain: `scalar_types_io`
cannot compile the undeclared EBP reference; `function_pointers` cannot link
ESP/EBP references. Gate logs:
`/tmp/inertia-semantic-byte-cast-{quality-fast,test-pipeline}.log`.
Default lane wall times are 123.471s, 46.989s and 65.593s; completion was
verified by 16:49:13 CEST. These are measured command durations, not an estimate
of total active engineering time. No full repository or hard pre-commit gate
was run for this follow-up, and no commit/push was made.
Do not count this as whole-function or whole-goal acceptance.

## Acceptance Boundary

Reason: required width/signedness conversion must survive C emission, regardless
of a compiler's plain-char default. DoD: exhaustive compiled byte-value cases,
adjacent cast consumers, tail validation and routine gates preserve their
contracts. Definition of failure: emitting target-dependent plain char for a
known signedness, hiding the cast with cosmetic settings, weakening numeric
oracles, or adding semantic inference to rendering.

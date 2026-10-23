# x87 upstream semantics and test evidence

## Pinned sources

Investigated on 2026-10-12. Downloaded originals and licenses are retained under
`.cache/ssa-capability-audit/emulators/`; `sources.json` records individual file
SHA256 values, and `build-sources/archives.json` records archive provenance.

| Project | Commit | Use |
| --- | --- | --- |
| dosbox-staging/dosbox-staging | 5426d72fa2cdf08cf94598053dcdbab1cbb8ab4d | Instruction behavior and stack test |
| bochs-emu/Bochs | 5c357adef5bc62e1ddf7f43a8488e84d48316c44 | Explicit x87 state transitions and floatx80 arithmetic |
| ucb-bar/berkeley-softfloat-3 | a0c6494cdc11865811dec815d5c0049fba9d82a8 | Concrete extended precision numerical reference |
| ucb-bar/berkeley-testfloat-3 | a9c849f1b0eb0264b626d9686ffae167d996e3be | SlowFloat differential tests and vectors |

DOSBox's portable `src/fpu/fpu_instructions.h` uses double internally; do not
adopt it as an exact 80-bit arithmetic model. Its `tests/files/fpu_test.asm`
pushes/pops eight values and uses self-modifying code to exercise synchronization
between execution cores. The stack vector can inform instruction tests; the
whole test is outside the current static-code comparator contract.

Bochs `bochs/cpu/fpu/fpu.cc` explicitly handles pending exceptions and FLDCW
reserved bits: `(word & ~0xe0c0) | 0x0040`. This matches the recorded host probe,
but the intended target CPU policy still needs to be declared. Its handlers
are useful state-transition references, not a directly usable symbolic lifter.

Preserve original licenses when adapting code: examined DOSBox headers are
GPL-2.0-or-later; Bochs fpu.cc is LGPL-2.0-or-later; Berkeley SoftFloat/TestFloat
carry their own BSD-style COPYING terms. No upstream production code was
vendored by this audit.

## Executed numerical checks

Built both Berkeley projects with `make -j2`, using their Linux-x86_64-GCC
build directories and default SoftFloat 8086-SSE specialization. Logs are
`softfloat-build.log` and `testfloat-build.log` under the evidence directory.

`testsoftfloat` compares SoftFloat with separate SlowFloat routines and checks
exception flags. Executed seed 1, level 1, tininess-after-rounding:

- add, sub, mul, div, sqrt at precisions 32, 64, 80;
- conversion to f32, f64, i32 at precision 80;
- each with near-even, toward-zero, down, and up rounding.

Result: **72 configurations, 2,255,808 cases, no reported errors**.
`testsoftfloat-results.json` records exact arguments, executable hash, per-run
log hashes, counts and exit codes. These are finite upstream tests, not an
exhaustive proof or tests of the repository's SSA lifter.

Generated 46,464 extF80_add vectors with seed 1, precision 80, near-even.
`testfloat_ver -checkAll` accepts the unchanged vectors (exit 0); toggling one
result significand bit produces exactly one detected error (exit 1).
See `vector-check-results.json`, `extF80-add-vectors*.txt`, and
`verifier-{valid,corrupt}.log`. Generator/verifier share SoftFloat; this is a
transport and negative-control check, not independent arithmetic evidence.
The generator rejects a requested 1,000-case batch: this configuration has a
46,464-case minimum.

## Integrated management and stack slice (2026-10-12)

The native flat32 call and CFG owners now represent full CW/SW, TOP, tag word,
eight physical 80-bit registers and last-instruction/data environment. Admitted
forms include FNSTCW/FNSTSW, FLDCW, FNCLEX, FNINIT, FNOP, standalone FWAIT,
FLD ST(i)/m80/constants, FST/FSTP ST(i), FSTP m80, FXCH, FFREE, FINCSTP/FDECSTP,
FCHS and FABS. Unsupported operand forms still fail admission. Constants honor
RC independently of PC. Memory forms record SS for EBP/ESP bases and DS for
other bases; an EBP SIB index does not choose SS. Explicit segment prefixes
are not admitted by this slice.

Checking instructions bind a no-pending-unmasked-exception predicate at their
actual entry state. Calls, reused callee summaries, branches and loop transitions
carry those predicates to the shared solver. The solver constrains countermodels
and checks that the domain is nonempty. CPU-policy and pending-exception premises
remain visible; successful comparisons relying on them are conditional. Trapping
continuations have not been implemented. The leaf-only VEX lane rejects x87 rather
than using erased or narrowed VEX effects; native call/CFG owners perform the work.

Independent parent review corrected stack-fault responses, RC-dependent constants,
FNOP identity admission and the default data selector. The saved 180-case hardware
stack matrix matches the corrected stack/constants slice. Production focused
regression:381 passed; scoped MyPy:7 modules clean. Broad lint still reports the
unchanged pre-existing complexity violation in `_lower_repeat_string_summary`;
other changed files pass. This is not a completed full-pipeline acceptance.

Frozen native integration probes for CL/sub_1DA00 and C1XX3216/sub_7CC10 now reach
observable mismatches instead of the composition limit. These are literal-state
symbolic counterexamples with explicit x87 premises, not independent concrete
replays. Full CL coverage is being measured separately and must not be inferred
from these two functions or from unit-test counts.

## Integration still required

1. Implement and independently validate symbolic arithmetic and rounded loads/
   stores, integer/BCD conversions, comparisons and condition flags. Preserve
   all 80 bits, NaN payloads, noncanonical encodings, exception flags and rounding
   behavior. The private Devin numerical engine is unfinished and is not in the
   production comparator. Single-round arithmetic must pass adversarial cases;
   64-bit intermediate rounding followed by PC24/53 rounding is incorrect.
2. Implement environment save/restore, transcendental/remainder/scale operations
   and remaining operand forms. Specify CPU-dependent approximations. FPREM and
   FPREM1 require distinct quotient rules and partial-reduction/C2 behavior.
3. Cover exception delivery rather than only non-trapping continuations, and
   expand shared native semantics to the leaf route. Keep undefined condition
   codes and CPU-specific policies explicit.
4. Extend attributed emulator/TestFloat and independent hardware tests across
   all implemented families, including corrupted operand, pop count, rounding,
   result bit and exception-flag controls. Finite execution is a test oracle,
   not universal symbolic proof.
5. Complete production gates and all original-versus-rebuilt PE corpus runs on
   frozen sources. Report unconditional and conditional proofs separately with
   their actual denominators. This slice does not establish >=90% coverage.

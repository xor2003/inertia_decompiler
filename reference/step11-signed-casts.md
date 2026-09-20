# Step 11: Proven Signed Conversions

Status: this slice is complete; all required correctness gates pass.
This is the first readability slice, not completion of all Steps 11/12/10.
Started September 19, 2026 at approximately 23:11 +02:00.
Final pipeline finished at 23:45:44 +02:00: an observed window of about 35
minutes including investigation and test waits, not 35 minutes of active coding.

## Change And Ownership

IR's `condition_value_extensions.py` proves the exact existing signed-extension
identity: masked source, matching sign-bit XOR/subtraction, valid source and
destination widths, and matching intermediate/constant widths. Near-matches
refuse. No opcode, function name, source listing or rendered-C pattern is used.

Types/Lowering's `condition_value_casts.py` consumes that proof and projects the
unchanged source once into required signed-source and destination casts.
Structuring only invokes the consumer. Memory access widths, storage identity,
calls and control flow are not recovered or changed in Rewrite.

The first live run exposed a genuine validation projection mismatch: a byte
mask inserted during global lowering remained inside an already narrowing
signed-byte cast. IR's owned fingerprint normalizer now recognizes precisely
that identity, preserving the cast and both type views. It refuses incomplete
masks, widening conversions, noninteger/unknown types and other operators.
This is structured fingerprint normalization, not parsing generated C.

## Observable Result

InsertionSort at `0x10808` changes:

```c
/* Before */
(short)(((field & 0xff & 0xff) ^ 128) - 128)
/* After */
(short)(signed char)(field & 0xff)
```

QuickSort at `0x10ce0` changes two equivalent ordering operands to
`(short)(signed char)field`. Its unused `xff` extern declaration also disappears.
Other 18 exported function files are byte-identical to the Step 9 exports.
Calls, writes, returns and branches survive; all 20 functions validate.

## Acceptance

DoD: exact typed conversions, single evaluation, unchanged load widths and
refusal controls; improved emitted C; clean function/whole-tail validation,
recompilation, compiled behavior, focused and default pipeline gates.
Failure: guessed signedness, widened loads, lost effects, accepted near-matches,
fingerprint waivers, or a new regression anywhere in the exercised pipeline.

- Four new cast/mask normalization cases fail before the identity is added.
  Corrected conversion tests also deliberately disable cast materialization and
  prove their readability oracle rejects the legacy arithmetic representation.
- Focused extension/mask/condition-lowering tests: 56 passed in 21.85s.
  Earlier fixture API mistakes were corrected; they are not regression evidence.
- Live InsertionSort: baseline 1 passed in 37.06s; after 1 passed in 53.95s,
  including compiled signed-byte behavior and corrupted controls. Runs had
  different overlapping check loads, so these are not a performance comparison.
- Whole SORTD: selected/queued/attempted/decompiled and all evidence counters
  are 20; zero empty functions, failures, timeouts, tracebacks or violations.
- Explicit combined-C compilation: 20 functions, zero errors, zero warnings.
- Generated behavior: 19 functions, compilation and execution passed.
- Scoped Ruff/MyPy/type/doc checks pass, as do project-wide MyPy, architecture
  and test ownership. `quality-fast` remains red on existing global Ruff debt.
- Final default pipeline: 268 prerequisite tests pass in 13.73s; 5,885 routine
  tests pass in 227.61s; both external compiler lanes pass. Selected/passed 3,
  failed/skipped/timed_out 0. QuickC takes 2.136s; MS C tiny takes 34.590s.
  This repeat benefits from warm caches and is not a measured code speedup.
- The first pipeline run had 5,884 passes and one `_SetGear` subprocess timeout
  at the unchanged 45-second limit, with both external lanes passing. Host load
  was high, but causation was not isolated. An unchanged focused rerun passes
  (15.59s test body, 33.77s total), followed by the green complete default
  repeat above. No timeout, test selection or semantic threshold was relaxed.

## Evidence

Production manifest: 1,052 files, digest
`b974ea6f81f862ade40f56d02c06fd6890ad19d602bf37c834f64fca7cfe32bf`.
Combined generated C SHA256:
`07021e52ce9dffc81b632292a1bf1dc6333344e7b62d6f7737cb8c7575cd7db5`.
Frozen SORTD MZ image is unchanged from the Step 9 closure.

Local reports: `.cache/step11-sortd.{txt,json,log}`,
`.cache/step11-sortd-functions/`, `.cache/step11-combined.c`,
`.cache/step11-compilation.json`, `.cache/step11-behavior/`,
`.cache/step11-{focused,insertion-before,insertion-after,mask-before,mypy,quality-fast,pipeline}.log`.
Final pipeline evidence: `.cache/step11-pipeline-repeat.log` and
`angr_platforms/.cache/test_pipeline/summary.json`; the earlier failure is
retained in `.cache/step11-pipeline-initial-summary.json` and its original log.
Slowest routine test on the repeat: the SORTD indexed-address inventory, 38.91s.
Use the Step 9 reproduction commands with these Step 11 output paths.
All Python commands use `PYTHON_JIT=1`; CLI uses `PYTHONHASHSEED=0`; pytest uses
`-n 7`. The routine pipeline already owns both extended test modules.
Codebase-memory MCP transport was unavailable; exact-source fallback was used.

Step 9's saved artifact remains the historical accepted baseline. No full-suite,
all-path linked DOS equivalence, or performance improvement claim is made here.

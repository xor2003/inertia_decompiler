# Linked Selector/Offset Read Probe

Status: failing diagnostic, not an accepted decompiler repair. Added September
20 while isolating the DOSFUNC segmented-load failure. This does not enlarge
the frozen three-function stack-restore acceptance cohort.

## Reproducer

`examples/stability/segcopy.c` is a 29-line MS C fixture with two application
functions. It reads two initialized stack words through explicit selector and
offset arguments. It avoids DOS environment contents and unresolved object
relocations. MS C 6 produces `mov es,cx; mov ax,es:[bx]` in `read_far`.

```sh
PYTHON_JIT=1 PYTHONHASHSEED=0 .venv/bin/python scripts/build_msc6_examples.py \
  --examples-dir examples/stability --only-constructs segcopy \
  --out-dir .cache/segcopy-msc6 \
  --kvikdos /home/xor/kvikdos/kvikdos \
  --msc6-root '/home/xor/inertia_player/dos_compilers/Microsoft C v6ax' \
  --decompile-mode functions --decompile-max-functions 0 \
  --decompile-timeout 30 --decompile-run-timeout 120

PYTHON_JIT=1 PYTHONHASHSEED=0 .venv/bin/python decompile.py \
  .cache/segcopy-msc6/SEGCOPY.EXE --addr 0x10010 \
  --ignore-local-sidecar-hints --no-alternate-source-c --timeout 30
```

The address is a diagnostic coordinate in this particular linked artifact,
not a production special case. Recheck its MAP after changing the fixture or
toolchain. Original compiler output, MAP, COD, executable and structured report
are under `.cache/segcopy-msc6/`. This explicit diagnostic directory is outside
the routine construct inventory; a failed case must not be counted as passing.

## Observed Results

- Original MS C 6 compilation and kvikdos execution pass; exit code 255 after
  checking both 0x1234 and 0xabcd.
- Full two-function decompilation takes 33.39 seconds, without timeouts. Main
  reports validation passed; `read_far` is rejected. No rebuilt execution passes.
- The rejected linked helper returns `(unsigned short)offset`, losing the
  required memory load. Validation blocks it with a parameter-class mismatch
  at BP+6. The slice fallback additionally reports an uninitialized BX carrier.
- The direct sidecar-free helper probe also exits 4 and returns its offset
  argument in the rejected C. The problem is not dependent on original C or
  COD/debug hints. Logs: `.cache/segcopy-raw-helper.{c,log}`.
- A worker-local read-only hook confirms that the first observed postprocess
  pass, `_apply_word_global_types_8616`, already receives the wrong return.
  This is a boundary observation, not proof of which earlier transformation
  removed the load. Do not blame the later cleanup named by the final guard.
  Evidence: `.cache/segcopy-pass-probe.log`.
- The existing IR segmented-load carrier test module passes 11 tests under
  `pytest -n 7`, in 9.43 seconds. It does not cover this complete linked failure.

## Next Repair And Acceptance

Priority: correctness blocker after the current frozen repair. Trace the load
through AIL, typed object/argument lowering and C generation before editing.
Keep selector and offset as separate value parameters unless typed evidence
justifies another representation; do not silence the parameter guard or repair
the body/signature in Rewrite or CLI. The current guard catches this example,
but that does not prove general coverage of lost memory loads.

DoD: both application functions validate and compile, required memory reads
survive, and original/rebuilt executions both return 255. Add a focused
regression at the identified owner and negative controls rejecting an offset
return or a stale selector. Then enroll the passing full round trip in the
routine lane. Definition of failure: missing load, changed argument semantics,
validation failure, skipped helper, or compile-only success counted as behavior.

Graph indexing and coverage calls failed with `Transport closed`. Investigation
used exact source and live worker observations; no exhaustive graph claim.

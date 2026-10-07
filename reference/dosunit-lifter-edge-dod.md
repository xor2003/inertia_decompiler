# DOS Unit Lifter-Backed Edge Solver DoD

## Goal

Replace edge discovery's hand decoder with a lifter-backed adapter while
keeping the compact solver slice. The adapter may still recognize only a small
set of branch predicates at first, but the source of instruction decode and
basic block boundaries must be the repository's x86-16 lifter.

## Required Architecture

```text
original EXE + function catalog
  -> angr/x86-16 project loading
  -> project.factory.block(...).vex
  -> lifter-backed branch/predicate candidate extraction
  -> compact ConditionIR
  -> solver_slice.py
  -> concrete vector + original coverage metadata
  -> KVM oracle recording
  -> rebuilt function-boundary replay through mapping
```

## Definition Of Done

1. `gen-vectors --strategy edge` has a lifter-backed discovery path.
   - The path calls the x86-16 lifter through `project.factory.block`.
   - It records in generation metadata whether each vector came from
     `lifter_vex` or the fallback byte decoder.

2. The byte decoder is fallback only.
   - It remains available for fixtures or loader failures.
   - Fallback use is visible in counters/diagnostics.
   - Silent fallback is not allowed.

3. Compact solver slice stays compact.
   - Raw VEX is not sent directly to Z3.
   - Only branch-relevant `ConditionIR` reaches `solver_slice.py`.
   - Lazy flag semantics remain: materialize only consumed branch flags.

4. Supported lifter-backed branch shapes match current fixtures.
   - `cmp ax, imm; je/jne`
   - `cmp bx, cx; jne`
   - `test ax, ax; jz`
   - `or ax, ax; jz`
   - `test ax, imm; jnz`
   - `cmp al, imm; je`

5. Unsupported effects are typed refusals.
   - memory predicates -> `unbounded_memory`
   - indirect jumps -> `unbounded_indirect_control`
   - calls/interrupts needed for a predicate -> `call_unmodeled` or
     `dos_interrupt_unmodeled`
   - unknown lifted condition forms -> `unsupported_ir`

6. Rebuilt comparison remains function-boundary only.
   - No rebuilt CFG or block alignment is introduced.
   - Existing mapping-based replay tests still pass.

7. Tests prove lifter use.
   - At least one test monkeypatches or instruments the adapter to show
     `project.factory.block` was called.
   - Existing byte-level edge fixtures still emit equivalent vectors.
   - A KVM fixture with different rebuilt function address still passes through
     mapping.

8. Real corpus smoke still passes.
   - F-15 edge generation emits vectors with `source.coverage`.
   - A selected generated subset records oracle on
     `/home/xor/tmp/f15se2-re/bin/egame.exe`.
   - The same vectors replay on
     `/home/xor/tmp/f15se2-re/build/egame.exe` via mapping with
     `--ignore-field sregs`.

## Gates

Run these before treating edge-generation changes as done:

```bash
rtk pytest -q tools/dosunit/tests/test_dosunit_tool.py \
  -k 'edge_vectors or tiny_example or byte_decoder_fallback'
```

The focused gate must prove:

- normal edge fixtures emit `source.coverage.discovery_source = lifter_vex`
- normal edge generation reports `counters.edge_sources.lifter_vex > 0`
- normal edge generation reports `counters.lifter_blocks_lifted > 0`
- forced lifter failure emits `source.coverage.discovery_source = byte_decoder`
- forced fallback reports `counters.edge_fallback_diagnostics > 0`

## Non-Goals

- Full raw VEX to Z3 translation.
- All x86 instructions in the solver.
- Rebuilt branch coverage measurement.
- Symbolic broad memory arrays.

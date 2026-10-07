# DOS Unit Region Effect DoD

## Goal

Check instruction arguments and observable effects for straight-line parts of a
function. Edge vectors remain useful for state generation, but the primary
static correctness gate is now region operand/effect equivalence.

## Required Architecture

```text
original EXE + function catalog
  -> lifter-backed regions through project.factory.block(...).vex
  -> per-instruction operand/effect summaries
  -> aggregate region read/write/flag/memory effects
  -> candidate region summary
  -> structured region comparison
  -> KVM function/region replay for concrete vectors
```

## Region Artifact

`dosunit.regions.v1` records:

- function id/name
- region entry/end `CS:IP` and linear addresses
- instruction mnemonic, operands, widths, and access mode
- register reads/writes
- flag reads/writes
- segmented memory reads/writes with `space`, `base`, `index`, `scale`, and
  signed displacement
- control exits and successors

## Definition Of Done

1. `dosunit regions` emits lifter-backed region summaries.
   - It calls `project.factory.block(...).vex`.
   - It records structured operands, not parsed `op_str` text.
   - Memory remains segmented (`DS:[si+4]`, `SS:[bp-2]`, etc.).

2. `dosunit compare-regions` detects argument/effect drift.
   - Register operand changes are reported.
   - Memory base/index/displacement/segment changes are reported.
   - Width changes are reported.
   - Flag read/write changes are reported.
   - Control target immediates are normalized as control targets, not raw
     candidate addresses.

3. `dosunit report-failures` renders failures visibly.
   - Region failures show function name, region ordinal, mismatch kind, and
     compact oracle/candidate operand/effect values.
   - Instruction mismatches show region entry, instruction `CS:IP`, linear
     address, and disassembly for both oracle and candidate.
   - Runtime vector failures show changed fields and diagnostics.
   - Data compare failures show byte offsets and oracle/candidate bytes.

4. Runtime comparison remains function-boundary unless a safe region trap is
   declared.
   - Rebuilt C still uses mapped function-entry replay.
   - Rebuilt ASM can later add region traps where labels are known.

5. Unsupported effects are explicit.
   - Missing region mapping -> `mapping_missing`.
   - Lifter failure -> `unsupported_ir`.
   - Unknown broad memory effects remain visible in effects/refusals, not
     silently dropped.

## Gates

Run these before treating region/effect work as done:

```bash
rtk pytest -q tools/dosunit/tests/test_dosunit_tool.py \
  -k 'region_effects or region_compare or cli_regions'
```

The focused gate must prove:

- `DS:[si+4]` reads are captured with width/access
- `DS:[di-2]` writes are captured with width/access
- changing `[di-2]` to `[bp-2]` fails comparison
- the failure includes the segment change from `DS` to `SS`
- CLI `regions` and `compare-regions` work through JSON files
- `report-failures` emits a visible Markdown report for the failed comparison

## Non-Goals

- Single-instruction-only unit tests as the primary strategy.
- Full arbitrary C internal block mapping.
- Broad symbolic memory arrays.
- Treating edge coverage as semantic proof.

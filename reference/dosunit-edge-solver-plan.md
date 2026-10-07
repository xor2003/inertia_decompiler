# DOS Unit Original-Side Edge Solver Plan

## Goal

Generate branch/edge-oriented concrete vectors from the original binary only,
then replay those vectors on rebuilt binaries at function boundaries through the
existing mapping flow.

The rebuilt binary does not need block or branch correspondence. Edge metadata
is coverage evidence for original-side vector generation; comparison remains:

```text
same concrete pre-state -> original oracle -> rebuilt function entry -> observable comparison
```

## Architecture

```text
original EXE + function catalog
  -> lifter-backed branch candidate discovery
  -> compact solver slice with lazy condition lowering
  -> concrete vector pre-state + original coverage metadata
  -> record-oracle through libkvikdos
  -> compare rebuilt through function mapping
```

## Implementation Steps

1. Add `tools/dosunit/architectures/ir_edges.py`
   - Discover original-side `BranchTarget` records through
     `project.factory.block(...).vex` and the x86-16 lifter-backed block
     decode.
   - Keep the old byte decoder as a fallback only when the lifter project
     cannot be loaded; fallback use must be visible in counters and vector
     metadata.
   - Implement bounded direct x86 patterns:
     - `cmp r16, imm16/imm8; je/jne/jb/jae/ja/jbe`
     - `cmp r16, r16; je/jne/jb/jae/ja/jbe`
     - `cmp r8, imm8; je/jne`
     - `test r16, r16; jz/jnz`
     - `test r16, imm16; jz/jnz`
     - `test r8, imm8; jz/jnz`
     - `or r16, r16; jz/jnz` as a zero-test idiom
   - Emit typed refusals for unsupported memory predicates, indirect jumps, and
     missing concrete function entries.

2. Add `tools/dosunit/catalog/solver_slice.py`
   - Solve only the selected branch predicate.
   - Materialize only the condition needed by the edge:
     - equality
     - non-equality
     - unsigned less-than / greater-or-equal
     - unsigned greater-than / less-or-equal
     - zero / non-zero
   - Use Z3 bitvectors when available.
   - Fill unconstrained inputs deterministically only at vector materialization.

3. Extend `gen-vectors --strategy edge`
   - Replace the old `cmp ax, imm; je/jne` special case with the branch-target
     discovery and solver-slice path.
   - Keep compare semantics unchanged.
   - Add CLI limits:
     - `--max-branches`
     - `--max-blocks` reserved for future CFG walking
     - `--max-loop-unroll` reserved for future bounded paths
     - `--solver-timeout-ms`

4. Extend vector metadata
   - Add original-side coverage under `source.coverage`:

```json
{
  "binary": "oracle",
  "kind": "edge",
  "function_id": "demo.exe:branch",
  "from": {"cs": "0x0000", "ip": "0x0203"},
  "to": {"cs": "0x0000", "ip": "0x0206"},
  "predicate": "ax == 0x1234",
  "label": "taken",
  "discovery_source": "lifter_vex"
}
```

5. Tests
   - `cmp ax, imm; je`: taken and fallthrough.
   - `cmp bx, cx; jne`: register/register branch constraints.
   - `test ax, ax; jz`: zero/non-zero branch constraints.
   - `or ax, ax; jz`: zero-test idiom.
   - `test ax, imm; jnz`: bit-mask branch constraints.
   - `cmp al, imm; je`: partial-register branch constraints.
   - unsupported indirect jump refusal.
   - rebuilt comparison fixture with different candidate function address,
     proving rebuilt block correspondence is not required.

## Tiny Examples Used To Drive Improvements

```text
3d 34 12 74 01 c3        cmp ax, 1234h; je target; ret
39 cb 75 01 c3           cmp bx, cx; jne target; ret
85 c0 74 01 c3           test ax, ax; jz target; ret
09 c0 74 01 c3           or ax, ax; jz target; ret
a9 08 00 75 01 c3 c3     test ax, 8; jnz target; ret; ret
3c 12 74 01 c3           cmp al, 12h; je target; ret
```

The examples intentionally stay tiny so each solver improvement has a closed
evidence loop: a byte pattern, a compact condition, concrete pre-state, and a
fixture replay through the same public `gen-vectors` path used for F-15.

## Definition Of Done

- `gen-vectors --strategy edge` emits vectors with `source.coverage` metadata.
- Normal edge fixtures report `source.coverage.discovery_source = lifter_vex`,
  `counters.edge_sources.lifter_vex > 0`, and
  `counters.lifter_blocks_lifted > 0`.
- Byte-decoder fallback is exercised only by an explicit failure test and
  reports `source.coverage.discovery_source = byte_decoder` plus
  `counters.edge_fallback_diagnostics > 0`.
- At least three branch fixtures produce taken/fallthrough vectors.
- Unsupported branch shapes produce typed refusals instead of guessed vectors.
- Existing KVM-backed function-boundary compare still passes.
- F-15 original/rebuilt flow still works for the known smoke subset.

## Non-Goals For This Step

- Full VEX/AIL path solving.
- Rebuilt CFG alignment.
- Loop unrolling beyond local direct branch predicates.
- Broad symbolic memory arrays.

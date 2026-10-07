# BASELINE: Inertia Decompiler Core Test Suite

**Purpose**: Establish a fixed baseline command that gates all roadmap changes. Before and after each GLOBAL_PLAN4 step, this baseline must pass.

**Last baseline run**: 2026-04-05
**Status**: 30 tests passing in ~7.5 seconds

## Baseline Command

```bash
cd /home/xor/vextest
source .venv/bin/activate
python -m pytest \
  tests/cli/test_x86_16_corpus_scan.py \
  tests/cli/test_x86_16_recompilable_subset.py \
  -v --tb=short
```

## Current Results (2026-04-05)

```
tests/cli/test_x86_16_corpus_scan.py — 28 tests
  ✅ All PASSED

tests/cli/test_x86_16_recompilable_subset.py — 2 tests
  ✅ test_x86_16_recompilable_subset_description_is_stable PASSED
  ✅ test_x86_16_recompilable_subset_syntax_checks_pass PASSED

Total: 30 PASSED in 7.54s
```

## Baseline Metrics (Per Step)

Track these metrics before and after each GLOBAL_PLAN4 step:

| Metric | Baseline | Gate |
|--------|----------|------|
| **Corpus scan tests** | 28 PASSED | Must stay ≥28 |
| **Recompilable syntax tests** | 2 PASSED | Must stay ≥2 |
| **Total runtime** | 7.54s | Must stay <30s |
| **No timeouts** | ✅ | Must stay true |
| **No crashes** | ✅ | Must stay true |

## Regression Detection Rules

**STOP work on a step if ANY of these trigger:**

1. **Corpus scan tests drop** below 28 PASSED
   - Root cause: Check if corpus-scan logic was affected
   - Action: Revert change, debug why scan tests broke

2. **Recompilable tests drop** below 2 PASSED
   - Root cause: Check if recompilable subset was changed
   - Action: Revert change, restore recompilable snapshot

3. **Baseline runtime exceeds 30s**
   - Root cause: Check for new expensive operations in baseline tests
   - Action: Profile and optimize; revert if necessary

4. **Any baseline test times out** (>10s per test)
   - Root cause: Check for infinite loops or O(n²) operations
   - Action: Add iteration bounds, revert if not fixable

## GLOBAL_PLAN4 Step Gates

Each roadmap step below must verify:

- [ ] Step 1: Freeze baseline
- [ ] Step 2: Connect structuring to real codegen
- [ ] Step 3: Replace acyclic structuring stubs
- [ ] Step 4: Finish cyclic structuring
- [ ] Step 5: Add bounded switch/jump-table recovery
- [ ] Step 6: Port post-structuring cleanup
- [ ] Step 7: Turn segmented-memory reasoning into consumer
- [ ] Step 8: Replace placeholder type-equivalence analysis
- [ ] Step 9: Make array recovery evidence-driven
- [ ] Step 10: Upgrade structure and union recovery
- [ ] Step 11: Add union-alternative selection
- [ ] Step 12: Harden helper/prototype/recompilation
- [ ] Step 13: Add MartyPC-backed semantic oracle
- [ ] Step 14: Make scan-safe performance explicit
- [ ] Step 15: Declare dream-decompiler milestone

---

**Rule**: Before committing any change from a GLOBAL_PLAN4 step, run the baseline command and verify all tests PASS. If any fail, that change does not land.

---

**Last updated**: 2026-04-05  
**By**: Inertia team (baseline freeze)  
**Status**: ✅ GREEN baseline established

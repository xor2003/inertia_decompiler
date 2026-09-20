## Context efficiency

- Do not read large files unless necessary.
- Prefer grep/search followed by reading only relevant sections.
- Do not repeatedly read files that have not changed.
- Do not paste large test/build logs into context.
- For failures, inspect only the relevant error and surrounding lines.
- Keep plans and progress summaries concise.
- After completing a logical milestone, update PROGRESS.md.

# Project Instructions

## Instruction order

1. [AGENTS.md](AGENTS.md) — read at startup. Canonical architecture,
   layer-ownership, and acceptance contract. On any conflict, it wins.
2. [reference/agent-execution.md](reference/agent-execution.md) — mandatory
   supplemental regression-test, performance, delegation, output, and
   progress rules owned by AGENTS.md.
3. This file — context-efficiency working rules only. They supplement and
   never override the files above.


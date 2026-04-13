1. Typed-IR execution slice complete.
Why now: block-local typed IR, segment evidence import, typed condition lifting, and one CFG-level merge consumer are all implemented and green under focused and broad checks.
Edit targets: none until a new bounded residue is chosen.
Required edits: none.
Required tests: none.
Verification commands: `/home/xor/vextest/.venv/bin/python /home/xor/vextest/scripts/run_plan3_checks.py --no-py-compile`
Definition of done: preserve the current green baseline until the next bounded typed-IR task is added.

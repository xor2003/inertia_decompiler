# Comparator performance checkpoint (2026-09-28)

The BC5 `z3cmp32.py` driver compares 15 selected `BCC.EXE` / `BCC32n.exe`
functions in `--mode auto --normalize-globals --assume-paired-calls` with a warm
VEX cache and a 5-second per-function timeout. The command returns status 2
because 13 functions refuse and 2 are conditional; this is expected for this
sample. All runs produced identical oracle and candidate SSA documents and the
same status and reason for every function. Solver-time fields varied.

| Loader/listing state | Wall time | User + system CPU | Peak RSS |
| --- | ---: | ---: | ---: |
| Normal PE loader, cold listing cache | 75.18 s | 19.45 s | 290 MB |
| Normal PE loader, warm listing cache | 64.13 s | 15.18 s | 290 MB |
| Verified PE loader, warm image certificate | 10.42-13.64 s | 6.83-7.58 s | 251 MB |

The machine was contended, so the wall-time ratios are indicative, not a
controlled throughput guarantee. Isolated PE loading was more decisive:
normal loading took 6.18 and 3.96 seconds for the two images; unrelocated
loading took 0.09 and 0.02 seconds. Their executable-section bytes matched.
The first verified load records any changed non-executable section bytes (up
to a 1 MiB cap); later loads restore those bytes and check hashes of *all*
mapped sections. Direct checks on both BC5 images found every mapped section
identical to the normal CLE load after restoration. The cache falls back to
the normal loader if the binary, section layout, code bytes, data patch,
loader versions, or final image hash do not match. ELF loading follows its
original path.

The 25 MB oracle `.lst` yielded 2,515 function bounds and 7,144 data labels.
Parsing both maps took 19.06 seconds cold and 0.45-0.56 seconds from the
content-keyed listing cache. The cache uses a file lock and atomic replacement
for parallel shards, rejects damaged entries, and refuses a listing that
changes during parsing.

For the 16-bit path, five `SORTDEMO.EXE` functions lifted 80 VEX blocks in
62.90 seconds with a cold cache. A second run hit all 80 blocks and lowered
in 3.13 seconds. This is the existing dosunit VEX cache; its regression now
checks that warm and cold SSA functions and refusals are identical. The cold
path is dominated by the Python real-mode lifter, so Cython was not added
without a controlled end-to-end gain.

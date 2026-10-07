# Borrowed Real-Mode Full-Value Failure Report

Initial exhaustive audit of defined, in-scope `borrow/80286` and `borrow/80386` cases.

## Summary

- Hardware-required failures: **86,402**
- 80286 failures: **66,433**
- 80386 failures: **19,969**
- Failing opcode files: **902**

Undefined outcomes, x87, control/debug/test registers, synthetic non-divide fault stress, and known oracle defects are accounted separately and are not failures.

## Opcode Groups

| CPU | Opcode | Failed | Hardware-required | First retained evidence |
|---|---:|---:|---:|---|
| 80286 | `D1.6` | 3124 | 4967 | reg:flags |
| 80286 | `D0.6` | 2627 | 5000 | reg:ip, mem:0xd6c8 |
| 80286 | `C0.6` | 2495 | 5000 | reg:bx, reg:ip, reg:flags |
| 80286 | `C1.4` | 2470 | 4968 | reg:flags |
| 80286 | `CF` | 2468 | 5000 | reg:flags |
| 80286 | `C0.4` | 2466 | 5000 | reg:flags |
| 80286 | `D2.2` | 2459 | 5000 | reg:flags |
| 80286 | `D2.6` | 2421 | 5000 | reg:flags |
| 80286 | `D3.6` | 2420 | 4967 | reg:flags |
| 80286 | `D2.3` | 2414 | 5000 | reg:flags |
| 80286 | `C0.2` | 2401 | 5000 | reg:flags |
| 80286 | `C0.3` | 2335 | 5000 | reg:flags |
| 80286 | `C0.5` | 2289 | 5000 | reg:flags |
| 80286 | `D2.5` | 2285 | 5000 | reg:flags |
| 80286 | `D2.4` | 2273 | 5000 | reg:flags |
| 80286 | `C1.5` | 2268 | 4967 | reg:flags |
| 80386 | `66C8` | 2053 | 2372 | mem:0xbdc6, mem:0xbdc7, mem:0xbdc8, mem:0xbdc9 |
| 80286 | `D1.4` | 1334 | 4967 | reg:ip, reg:flags |
| 80286 | `A0` | 784 | 5000 | reg:ax |
| 80286 | `A1` | 781 | 5000 | reg:ax |
| 80386 | `67F7.6` | 651 | 2280 | Register DIV fault did not match the hardware vector-0 witness |
| 80386 | `F7.6` | 631 | 2496 | Register DIV fault did not match the hardware vector-0 witness |
| 80386 | `66F7.6` | 588 | 2495 | Register DIV fault did not match the hardware vector-0 witness |
| 80386 | `D1.4` | 570 | 2421 | reg:eflags |
| 80386 | `D1.6` | 570 | 2421 | reg:eflags |
| 80386 | `6766F7.6` | 560 | 2284 | Register DIV fault did not match the hardware vector-0 witness |
| 80286 | `C0.0` | 473 | 5000 | reg:ip, reg:flags |
| 80286 | `D2.0` | 468 | 5000 | reg:flags |
| 80286 | `C0.1` | 460 | 5000 | reg:ip, reg:flags |
| 80286 | `D2.1` | 453 | 5000 | reg:flags |
| 80286 | `C1.6` | 448 | 4967 | reg:ip, reg:flags, mem:0x4fcce, mem:0x4fccf |
| 80286 | `8B` | 393 | 4966 | reg:bp |
| 80286 | `39` | 371 | 4960 | reg:ip, reg:flags |
| 80286 | `3B` | 367 | 4960 | reg:ip, reg:flags |
| 80286 | `8A` | 354 | 5000 | reg:dx, reg:ip |
| 80386 | `A6` | 346 | 2433 | reg:ecx, reg:esi, reg:edi, reg:eflags |
| 80386 | `A1` | 343 | 2444 | reg:eax |
| 80386 | `A0` | 338 | 2438 | reg:eax |
| 80286 | `38` | 331 | 5000 | reg:ip, reg:flags |
| 80386 | `67A6` | 297 | 2428 | reg:ecx, reg:esi, reg:edi, reg:eflags |
| 80386 | `67A7` | 271 | 2429 | reg:ecx, reg:esi, reg:edi, reg:eflags |
| 80386 | `A7` | 268 | 2226 | reg:ecx, reg:esi, reg:edi, reg:eflags |
| 80286 | `FF.6` | 260 | 4967 | RuntimeError: Unable to decode first instruction for case 1: lock push word [ds:bx+di] |
| 80286 | `FF.2` | 252 | 4967 | RuntimeError: Unable to decode first instruction for case 5: lock call word [ds:bx+di] |
| 80286 | `FF.4` | 223 | 4967 | RuntimeError: Unable to decode first instruction for case 3: lock jmp word [ds:bx+di] |
| 80286 | `83.7` | 210 | 4966 | reg:ip, reg:flags |
| 80286 | `81.7` | 204 | 4948 | reg:ip, reg:flags |
| 80286 | `89` | 190 | 4966 | reg:bx, reg:ip |
| 80286 | `FF.3` | 187 | 3710 | RuntimeError: Unable to decode first instruction for case 4: lock call far [ds:bx+di] |
| 80286 | `C8` | 180 | 4983 | mem:0x1d000 |
| 80286 | `31` | 178 | 4960 | reg:flags |
| 80286 | `29` | 177 | 4959 | reg:flags |
| 80286 | `01` | 175 | 4960 | reg:flags |
| 80286 | `80.7` | 175 | 5000 | reg:ip, reg:flags |
| 80286 | `82.7` | 175 | 5000 | reg:ip, reg:flags |
| 80286 | `21` | 174 | 4959 | reg:flags |
| 80286 | `81.0` | 172 | 4948 | reg:flags |
| 80286 | `81.4` | 172 | 4948 | reg:flags |
| 80286 | `81.6` | 172 | 4948 | reg:flags |
| 80286 | `83.5` | 172 | 4966 | reg:ax, reg:ip, reg:flags |
| 80286 | `09` | 171 | 4960 | reg:flags |
| 80286 | `81.5` | 171 | 4948 | reg:flags |
| 80286 | `83.1` | 171 | 4966 | reg:ax, reg:ip, reg:flags |
| 80286 | `83.4` | 171 | 4966 | reg:ax, reg:ip, reg:flags |
| 80286 | `83.6` | 171 | 4966 | reg:ax, reg:ip, reg:flags |
| 80286 | `81.1` | 170 | 4948 | reg:flags |
| 80286 | `3A` | 169 | 5000 | reg:ip, reg:flags |
| 80286 | `83.0` | 168 | 4966 | reg:ax, reg:ip, reg:flags |
| 80386 | `6687` | 166 | 994 | mem:0x35938, mem:0x35939, mem:0x3593a, mem:0x3593b |
| 80386 | `C0.3` | 164 | 2433 | reg:eflags |
| 80286 | `A3` | 161 | 5000 | reg:ip, mem:0x2e667, mem:0x2e668 |
| 80286 | `C0.7` | 160 | 5000 | reg:bx, reg:ip, reg:flags |
| 80286 | `C1.0` | 160 | 4967 | reg:ip, reg:flags, mem:0x4fcce, mem:0x4fccf |
| 80286 | `C1.1` | 160 | 4967 | reg:ip, reg:flags |
| 80286 | `C1.2` | 160 | 4967 | reg:ip |
| 80286 | `C1.3` | 160 | 4967 | reg:ip, mem:0x4fcce, mem:0x4fccf |
| 80286 | `C1.7` | 160 | 4967 | reg:ip, reg:flags, mem:0x4fcce, mem:0x4fccf |
| 80286 | `C7` | 160 | 4758 | reg:ip, mem:0x101719, mem:0x10171a |
| 80286 | `D0.0` | 160 | 5000 | reg:ip, mem:0xd6c8 |
| 80286 | `D0.2` | 160 | 5000 | reg:ip, reg:flags, mem:0xd6c8 |
| 80286 | `D0.3` | 160 | 5000 | reg:ip, mem:0xd6c8 |
| 80286 | `D0.4` | 160 | 5000 | reg:ip, reg:flags, mem:0xd6c8 |
| 80286 | `D0.5` | 160 | 5000 | reg:ip, reg:flags, mem:0xd6c8 |
| 80286 | `D1.0` | 160 | 4967 | reg:ip, reg:flags, mem:0xd6c8, mem:0xd6c9 |
| 80286 | `D1.1` | 160 | 4967 | reg:ip, reg:flags, mem:0xd6c8, mem:0xd6c9 |
| 80286 | `D1.2` | 160 | 4967 | reg:ip, mem:0xd6c8, mem:0xd6c9 |
| 80286 | `D1.5` | 160 | 4967 | reg:ip, reg:flags, mem:0xd6c8, mem:0xd6c9 |
| 80286 | `D1.7` | 160 | 4967 | reg:ip, reg:flags, mem:0xd6c8, mem:0xd6c9 |
| 80286 | `D2.7` | 160 | 5000 | reg:ip, reg:flags, mem:0xd6c8 |
| 80286 | `D3.7` | 160 | 4967 | reg:ip, reg:flags, mem:0xd6c8, mem:0xd6c9 |
| 80286 | `D8` | 160 | 4967 | reg:ip |
| 80286 | `A2` | 159 | 5000 | reg:ip, mem:0x2e667 |
| 80286 | `84` | 158 | 5000 | reg:ip, reg:flags |
| 80286 | `88` | 158 | 5000 | reg:bx, reg:ip |
| 80286 | `C9` | 156 | 4759 | reg:sp, reg:bp, reg:ip |
| 80286 | `F6.0` | 156 | 5000 | reg:ip, reg:flags |
| 80286 | `F6.1` | 156 | 5000 | reg:ip, reg:flags |
| 80286 | `E8` | 155 | 5000 | reg:sp, reg:ip, mem:0x54056, mem:0x54057 |
| 80286 | `F6.4` | 155 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `F6.5` | 155 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `F7.0` | 155 | 4948 | reg:ip, reg:flags |
| 80286 | `F7.1` | 155 | 4948 | reg:ip, reg:flags |
| 80286 | `E7` | 154 | 5000 | reg:ip |
| 80286 | `E9` | 154 | 5000 | reg:ip |
| 80286 | `EC` | 154 | 5000 | reg:ax, reg:ip |
| 80286 | `F7.4` | 154 | 4967 | reg:ax, reg:dx, reg:ip, reg:flags |
| 80286 | `1B` | 153 | 4961 | reg:bx, reg:ip, reg:flags |
| 80286 | `9C` | 153 | 5000 | reg:sp, reg:ip, mem:0x8aa46 |
| 80286 | `C3` | 153 | 4974 | reg:sp, reg:ip |
| 80286 | `E4` | 153 | 5000 | reg:ax, reg:ip |
| 80286 | `E6` | 153 | 5000 | reg:ip |
| 80286 | `EE` | 153 | 5000 | reg:ip |
| 80286 | `EF` | 153 | 5000 | reg:ip |
| 80286 | `6B` | 152 | 4958 | reg:sp, reg:ip |
| 80286 | `C2` | 151 | 4974 | AngrExitError: Cannot execute following jumpkind Ijk_SigILL |
| 80286 | `9D` | 150 | 5000 | reg:sp, reg:ip, reg:flags |
| 80286 | `1E` | 148 | 5000 | reg:sp, reg:ip, mem:0xf17b6, mem:0xf17b7 |
| 80286 | `69` | 148 | 4938 | reg:sp, reg:ip |
| 80286 | `ED` | 148 | 5000 | reg:ax, reg:ip |
| 80286 | `06` | 147 | 5000 | reg:sp, reg:ip, mem:0x564ec, mem:0x564ed |
| 80286 | `0E` | 147 | 5000 | reg:sp, reg:ip, mem:0x1ce7e, mem:0x1ce7f |
| 80286 | `16` | 147 | 5000 | reg:sp, reg:ip, mem:0xf17b6, mem:0xf17b7 |
| 80286 | `E5` | 147 | 5000 | reg:ax, reg:ip |
| 80286 | `60` | 146 | 4999 | reg:sp, reg:ip, mem:0xead4, mem:0xead5 |
| 80286 | `68` | 146 | 5000 | reg:sp, reg:ip, mem:0xeae2, mem:0xeae3 |
| 80286 | `6A` | 146 | 5000 | reg:sp, reg:ip, mem:0xeae2 |
| 80286 | `1F` | 145 | 4977 | reg:ds, reg:sp, reg:ip |
| 80286 | `55` | 145 | 5000 | reg:sp, reg:ip, mem:0xcf606, mem:0xcf607 |
| 80286 | `61` | 145 | 4976 | reg:ax, reg:bx, reg:cx, reg:dx |
| 80286 | `07` | 144 | 4977 | reg:es, reg:sp, reg:ip |
| 80286 | `51` | 144 | 5000 | reg:sp, reg:ip, mem:0xcf606, mem:0xcf607 |
| 80286 | `53` | 144 | 5000 | reg:sp, reg:ip, mem:0xcf606, mem:0xcf607 |
| 80286 | `17` | 143 | 4977 | reg:ss, reg:sp, reg:ip |
| 80286 | `50` | 143 | 5000 | reg:sp, reg:ip, mem:0xe3ade, mem:0xe3adf |
| 80286 | `52` | 143 | 5000 | reg:sp, reg:ip |
| 80286 | `54` | 143 | 5000 | reg:sp, reg:ip, mem:0xe3ade, mem:0xe3adf |
| 80286 | `56` | 143 | 5000 | reg:sp, reg:ip, mem:0xe3ade |
| 80286 | `57` | 143 | 5000 | reg:sp, reg:ip, mem:0xcf606, mem:0xcf607 |
| 80286 | `5B` | 142 | 5000 | reg:bx, reg:sp, reg:ip |
| 80286 | `5E` | 142 | 5000 | reg:sp, reg:si, reg:ip |
| 80386 | `C0.2` | 142 | 2433 | reg:eflags |
| 80286 | `58` | 141 | 5000 | reg:ax, reg:sp, reg:ip |
| 80286 | `59` | 141 | 5000 | reg:cx, reg:sp, reg:ip |
| 80286 | `5F` | 141 | 5000 | reg:sp, reg:di, reg:ip |
| 80286 | `5C` | 140 | 5000 | reg:sp, reg:ip |
| 80286 | `5D` | 140 | 5000 | reg:sp, reg:bp, reg:ip |
| 80386 | `67C0.3` | 140 | 2085 | reg:eflags |
| 80286 | `5A` | 139 | 5000 | reg:dx, reg:sp, reg:ip |
| 80386 | `67C0.2` | 135 | 2085 | reg:eflags |
| 80386 | `67D2.2` | 130 | 2085 | reg:eflags |
| 80286 | `8C` | 129 | 4846 | reg:ip, mem:0xe8cd, mem:0xe8ce |
| 80286 | `8F` | 127 | 4769 | reg:sp, reg:ip, mem:0x84b56, mem:0x84b57 |
| 80286 | `C6` | 126 | 4804 | reg:ip, mem:0x101719 |
| 80386 | `67D2.3` | 124 | 2085 | reg:eflags |
| 80386 | `67C0.0` | 123 | 2085 | reg:eflags |
| 80386 | `D2.2` | 123 | 2434 | reg:eflags |
| 80386 | `D2.3` | 122 | 2434 | reg:eflags |
| 80386 | `67F7.7` | 119 | 2184 | RuntimeError: Execution produced no active or deadended state |
| 80386 | `67F6.7` | 118 | 2201 | RuntimeError: Execution produced no active or deadended state |
| 80386 | `C0.0` | 118 | 2433 | reg:eflags |
| 80286 | `8D` | 116 | 3720 | reg:bp, reg:ip |
| 80286 | `C5` | 116 | 3713 | reg:ds, reg:bp, reg:ip |
| 80286 | `FF.5` | 116 | 3706 | RuntimeError: Unable to decode first instruction for case 2: lock jmp far [ds:bx+di] |
| 80386 | `67C0.1` | 116 | 2085 | reg:eflags |
| 80286 | `C4` | 115 | 3707 | reg:dx, reg:es, reg:ip |
| 80286 | `FF.0` | 114 | 4967 | reg:cs, reg:ip, reg:flags, mem:0xc5246 |
| 80286 | `FF.1` | 114 | 4967 | reg:cs, reg:ip, reg:flags, mem:0xc5246 |
| 80386 | `67D2.0` | 110 | 2085 | reg:eflags |
| 80386 | `F6.7` | 109 | 2499 | RuntimeError: Execution produced no active or deadended state |
| 80386 | `6766F7.7` | 107 | 2234 | RuntimeError: Execution produced no active or deadended state |
| 80386 | `676687` | 106 | 822 | reg:eip, mem:0x6b4ed, mem:0x6b4ee, mem:0x6b4ef |
| 80386 | `D2.0` | 106 | 2434 | reg:eflags |
| 80386 | `67F6.6` | 105 | 2285 | RuntimeError: Execution produced no active or deadended state |
| 80386 | `F7.7` | 105 | 2494 | RuntimeError: Execution produced no active or deadended state |
| 80386 | `66F7.7` | 103 | 2492 | RuntimeError: Execution produced no active or deadended state |
| 80386 | `C0.1` | 103 | 2433 | reg:eflags |
| 80286 | `8E` | 98 | 3611 | reg:ds, reg:ip |
| 80286 | `A5` | 98 | 4475 | reg:si, reg:di, reg:ip, mem:0xb930c |
| 80286 | `A7` | 98 | 4478 | reg:si, reg:di, reg:ip, reg:flags |
| 80386 | `67D2.1` | 95 | 2085 | reg:eflags |
| 80386 | `D2.1` | 95 | 2434 | reg:eflags |
| 80386 | `39` | 92 | 2423 | reg:eflags |
| 80386 | `3B` | 91 | 2423 | reg:eflags |
| 80286 | `2B` | 86 | 4959 | reg:bp, reg:ip, reg:flags |
| 80386 | `F6.6` | 78 | 2499 | RuntimeError: Execution produced no active or deadended state |
| 80286 | `32` | 77 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `CE` | 77 | 2528 | reg:ip |
| 80386 | `67660FBB` | 75 | 2030 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80286 | `F7.6` | 74 | 4967 | reg:ax, reg:dx, reg:ip |
| 80386 | `67660FAB` | 73 | 2030 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `01` | 72 | 2478 | reg:eflags |
| 80386 | `09` | 72 | 2478 | reg:eflags |
| 80386 | `29` | 72 | 2478 | reg:eflags |
| 80386 | `21` | 71 | 2478 | reg:eflags |
| 80286 | `F6.6` | 70 | 5000 | reg:ax, reg:ip |
| 80386 | `31` | 70 | 2478 | reg:eflags, mem:0xcedbf, mem:0xcedc0 |
| 80386 | `38` | 70 | 2432 | reg:eflags |
| 80386 | `670FAB` | 68 | 2053 | reg:eflags |
| 80386 | `81.1` | 68 | 2480 | reg:eflags |
| 80386 | `670FBB` | 67 | 2056 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `81.0` | 67 | 2480 | reg:eflags |
| 80386 | `83.1` | 66 | 2480 | reg:eflags |
| 80386 | `83.4` | 66 | 2480 | reg:eflags |
| 80386 | `83.6` | 66 | 2480 | reg:eflags |
| 80386 | `81.5` | 65 | 2480 | reg:eflags |
| 80386 | `81.6` | 65 | 2480 | reg:eflags |
| 80386 | `83.0` | 65 | 2480 | reg:eflags |
| 80386 | `81.4` | 64 | 2480 | reg:eflags |
| 80386 | `83.5` | 63 | 2480 | reg:eflags |
| 80386 | `67660FB3` | 61 | 2030 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80286 | `F6.7` | 57 | 5000 | reg:ax, reg:ip |
| 80286 | `F7.7` | 57 | 4967 | reg:ax, reg:dx, reg:ip |
| 80386 | `670FB3` | 57 | 2055 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `67C1.2` | 55 | 2063 | reg:eflags |
| 80386 | `670FBA.7` | 54 | 2096 | reg:eflags, mem:0xbe569 |
| 80386 | `67660FBA.7` | 52 | 2095 | reg:eflags, mem:0xbe56b |
| 80386 | `67660FBA.5` | 50 | 2095 | reg:eflags |
| 80386 | `8B` | 50 | 974 | reg:ebp |
| 80386 | `670FBA.5` | 48 | 2096 | mem:0xbe569 |
| 80386 | `67C1.3` | 47 | 2063 | reg:eflags |
| 80386 | `67D3.2` | 47 | 2063 | reg:eflags |
| 80286 | `6E` | 46 | 2000 | reg:si, reg:ip |
| 80286 | `6C` | 45 | 2000 | reg:di, reg:ip, mem:0x100470 |
| 80286 | `6D` | 44 | 1891 | reg:di, reg:ip, mem:0x100470, mem:0x100471 |
| 80286 | `F6.2` | 43 | 5000 | reg:bx, reg:ip |
| 80386 | `67D3.3` | 43 | 2063 | reg:eflags |
| 80386 | `C1.3` | 43 | 2421 | reg:eflags |
| 80286 | `80.0` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `80.1` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `80.2` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `80.3` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `80.4` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `80.5` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `80.6` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `81.2` | 42 | 4948 | reg:ax, reg:ip, reg:flags |
| 80286 | `81.3` | 42 | 4948 | reg:ax, reg:ip, reg:flags |
| 80286 | `82.0` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `82.1` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `82.2` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `82.3` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `82.4` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `82.5` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `82.6` | 42 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `F6.3` | 42 | 5000 | reg:bx, reg:ip, reg:flags |
| 80286 | `FE.0` | 42 | 5000 | reg:bx, reg:ip, reg:flags |
| 80286 | `FE.1` | 42 | 5000 | reg:bx, reg:ip, reg:flags |
| 80286 | `6F` | 41 | 1891 | reg:si, reg:ip |
| 80286 | `83.2` | 41 | 4966 | reg:ax, reg:ip, reg:flags |
| 80286 | `86` | 41 | 5000 | reg:ax, reg:cx, reg:ip |
| 80386 | `0FBB` | 41 | 2486 | reg:eflags |
| 80386 | `660FAB` | 40 | 2486 | reg:eflags |
| 80386 | `67660FA3` | 40 | 1985 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `8A` | 40 | 974 | reg:ecx |
| 80286 | `00` | 39 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `02` | 39 | 5000 | reg:cx, reg:ip, reg:flags |
| 80286 | `03` | 39 | 4959 | reg:bp, reg:ip, reg:flags |
| 80286 | `08` | 39 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `0A` | 39 | 5000 | reg:ip, reg:flags |
| 80286 | `10` | 39 | 5000 | reg:cx, reg:ip, reg:flags |
| 80286 | `11` | 39 | 4960 | reg:cx, reg:ip, reg:flags |
| 80286 | `12` | 39 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `13` | 39 | 4960 | reg:sp, reg:ip, reg:flags |
| 80286 | `18` | 39 | 5000 | reg:cx, reg:ip, reg:flags |
| 80286 | `30` | 39 | 5000 | reg:cx, reg:ip, reg:flags |
| 80286 | `33` | 39 | 4960 | reg:sp, reg:ip, reg:flags |
| 80386 | `660FBB` | 39 | 2486 | reg:eflags |
| 80386 | `6766C4` | 39 | 1956 | reg:edi, reg:es |
| 80386 | `6766C5` | 39 | 1957 | reg:edi, reg:ds |
| 80386 | `C1.2` | 39 | 2421 | reg:eflags |
| 80286 | `0B` | 38 | 4960 | reg:bp, reg:ip, reg:flags |
| 80286 | `19` | 38 | 4961 | reg:cx, reg:ip, reg:flags |
| 80286 | `20` | 38 | 5000 | reg:ip, reg:flags |
| 80286 | `22` | 38 | 5000 | reg:cx, reg:ip, reg:flags |
| 80286 | `28` | 38 | 5000 | reg:ax, reg:ip, reg:flags |
| 80286 | `2A` | 38 | 5000 | reg:cx, reg:ip, reg:flags |
| 80386 | `660FB3` | 38 | 2486 | reg:eflags |
| 80386 | `670FBA.6` | 38 | 2096 | reg:eflags, mem:0xbe569 |
| 80386 | `0FAB` | 37 | 2486 | reg:eflags |
| 80386 | `0FB3` | 37 | 2486 | reg:eflags |
| 80386 | `67660FB5` | 37 | 1922 | reg:ebp, reg:gs |
| 80386 | `67660FBA.6` | 37 | 2095 | reg:eflags, mem:0xbe56b |
| 80386 | `67C4` | 37 | 1956 | reg:edi, reg:es |
| 80386 | `67C5` | 37 | 1957 | reg:edi, reg:ds |
| 80286 | `23` | 36 | 4959 | reg:bp, reg:ip, reg:flags |
| 80386 | `670FB5` | 36 | 1924 | reg:ebp, reg:gs |
| 80386 | `67660FB2` | 36 | 1921 | reg:edi, reg:ss |
| 80386 | `D3.3` | 36 | 2422 | reg:eflags |
| 80386 | `670FB2` | 35 | 1923 | reg:edi, reg:ss |
| 80386 | `670FA3` | 34 | 2011 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `66A5` | 33 | 2212 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `67660FB4` | 33 | 1921 | reg:ebp, reg:fs |
| 80286 | `87` | 32 | 4966 | reg:dx, reg:bp, reg:ip |
| 80286 | `D6` | 32 | 1000 | reg:ax, reg:ip |
| 80286 | `F4` | 32 | 1000 | reg:ip |
| 80386 | `660FBA.5` | 32 | 2471 | reg:eflags |
| 80386 | `660FBA.6` | 32 | 2471 | reg:eflags |
| 80386 | `670FB4` | 32 | 1923 | reg:ebp, reg:fs |
| 80386 | `67660FBD` | 32 | 2055 | reg:edi, reg:eflags |
| 80386 | `83.7` | 32 | 2421 | reg:eflags |
| 80386 | `670FBC` | 31 | 2056 | reg:edi, reg:eflags |
| 80386 | `670FBD` | 31 | 2056 | reg:edi, reg:eflags |
| 80386 | `670FBE` | 31 | 2076 | reg:edi |
| 80386 | `676609` | 31 | 2080 | reg:eflags, mem:0x486c, mem:0x486d, mem:0x486e |
| 80386 | `67660FBC` | 31 | 2055 | reg:edi, reg:eflags |
| 80386 | `67660FBE` | 31 | 2076 | reg:edi |
| 80386 | `676619` | 31 | 2079 | reg:eflags, mem:0x5a5ae, mem:0x5a5af, mem:0x5a5b0 |
| 80386 | `81.7` | 31 | 2421 | reg:eflags |
| 80386 | `660FBA.7` | 30 | 2471 | reg:eflags |
| 80386 | `670FB7` | 30 | 2054 | reg:edi |
| 80386 | `6719` | 30 | 2081 | reg:eflags, mem:0x5a5ae, mem:0x5a5af |
| 80386 | `676603` | 30 | 2046 | reg:ebx, reg:eflags |
| 80386 | `67660FA4` | 30 | 2050 | mem:0xf3ce4, mem:0xf3ce5, mem:0xf3ce6, mem:0xf3ce7 |
| 80386 | `67660FB7` | 30 | 2054 | reg:edi |
| 80386 | `676611` | 30 | 2077 | mem:0x5a5ae, mem:0x5a5af, mem:0x5a5b0, mem:0x5a5b1 |
| 80386 | `676629` | 30 | 2077 | reg:eflags, mem:0xcc464, mem:0xcc465, mem:0xcc466 |
| 80386 | `67662B` | 30 | 2044 | reg:esi, reg:eflags |
| 80386 | `676631` | 30 | 2074 | reg:eflags, mem:0xa7d1, mem:0xa7d2, mem:0xa7d3 |
| 80386 | `0FBA.5` | 29 | 2473 | reg:eflags |
| 80386 | `6700` | 29 | 2103 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `6702` | 29 | 2071 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `6709` | 29 | 2082 | reg:eflags, mem:0x486c, mem:0x486d |
| 80386 | `670FBF` | 29 | 2056 | reg:edi |
| 80386 | `6710` | 29 | 2099 | reg:eflags, mem:0x5a5ae |
| 80386 | `6711` | 29 | 2080 | reg:eflags, mem:0x5a5ae, mem:0x5a5af |
| 80386 | `6718` | 29 | 2103 | reg:eflags, mem:0x5a5ae |
| 80386 | `671A` | 29 | 2069 | reg:ebx, reg:eflags |
| 80386 | `6728` | 29 | 2099 | reg:eflags, mem:0xcc464 |
| 80386 | `6729` | 29 | 2080 | reg:eflags, mem:0xcc464, mem:0xcc465 |
| 80386 | `672A` | 29 | 2070 | reg:edx, reg:eflags |
| 80386 | `672B` | 29 | 2047 | reg:esi, reg:eflags |
| 80386 | `6730` | 29 | 2099 | reg:eflags, mem:0xa7d1 |
| 80386 | `6731` | 29 | 2078 | reg:eflags, mem:0xa7d1, mem:0xa7d2 |
| 80386 | `676601` | 29 | 2078 | reg:eflags, mem:0x486c, mem:0x486d, mem:0x486e |
| 80386 | `67660FA5` | 29 | 2050 | reg:eflags, mem:0xf3ce4, mem:0xf3ce5, mem:0xf3ce6 |
| 80386 | `67660FAC` | 29 | 2052 | mem:0x60da9, mem:0x60daa, mem:0x60dab, mem:0x60dac |
| 80386 | `67660FBF` | 29 | 2056 | reg:edi |
| 80386 | `676613` | 29 | 2048 | reg:edi, reg:eflags |
| 80386 | `67661B` | 29 | 2049 | reg:edi, reg:eflags |
| 80386 | `676621` | 29 | 2077 | reg:eflags, mem:0xc80a, mem:0xc80b, mem:0xc80d |
| 80386 | `D3.2` | 29 | 2422 | reg:eflags |
| 80386 | `6701` | 28 | 2081 | reg:eflags, mem:0x486c, mem:0x486d |
| 80386 | `6703` | 28 | 2049 | reg:ebx, reg:eflags |
| 80386 | `670FB6` | 28 | 2073 | reg:edi |
| 80386 | `6712` | 28 | 2070 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `6713` | 28 | 2051 | reg:edi, reg:eflags |
| 80386 | `671B` | 28 | 2051 | reg:edi, reg:eflags |
| 80386 | `6721` | 28 | 2080 | reg:eflags, mem:0xc80a, mem:0xc80b |
| 80386 | `6732` | 28 | 2066 | reg:eax, reg:eflags |
| 80386 | `67660FB6` | 28 | 2073 | reg:edi |
| 80386 | `6766A5` | 28 | 2408 | mem:0xa52d, mem:0xa52e |
| 80386 | `0FBA.6` | 27 | 2473 | reg:eflags |
| 80386 | `6708` | 27 | 2104 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `67660FAD` | 27 | 2052 | reg:eflags, mem:0x60da9, mem:0x60daa, mem:0x60dab |
| 80386 | `6720` | 26 | 2100 | reg:eflags, mem:0xc80a |
| 80386 | `67660FAF` | 26 | 2054 | reg:eax, reg:eflags |
| 80386 | `676639` | 26 | 2043 | reg:eflags |
| 80386 | `676681.0` | 26 | 2089 | reg:eflags, mem:0x69c85, mem:0x69c86, mem:0x69c87 |
| 80386 | `676681.1` | 26 | 2089 | mem:0x69c85, mem:0x69c87, mem:0x69c88 |
| 80386 | `676681.2` | 26 | 2089 | reg:eflags, mem:0x69c85, mem:0x69c86, mem:0x69c87 |
| 80386 | `676681.3` | 26 | 2089 | mem:0x69c85, mem:0x69c86, mem:0x69c87, mem:0x69c88 |
| 80386 | `676681.5` | 26 | 2089 | reg:eflags, mem:0x69c85, mem:0x69c86, mem:0x69c87 |
| 80386 | `676681.6` | 26 | 2089 | reg:eflags, mem:0x69c85, mem:0x69c86, mem:0x69c87 |
| 80386 | `676683.0` | 26 | 2084 | reg:eflags, mem:0x69c85 |
| 80386 | `676683.2` | 26 | 2085 | reg:eflags, mem:0x69c85 |
| 80386 | `67668D` | 26 | 1830 | reg:ecx |
| 80386 | `678D` | 26 | 1829 | reg:ecx |
| 80386 | `67C1.4` | 26 | 2063 | mem:0xf881a, mem:0xf881b |
| 80386 | `67C1.6` | 26 | 2063 | mem:0xf881a, mem:0xf881b |
| 80386 | `670A` | 25 | 2072 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `670FAF` | 25 | 2056 | reg:eax, reg:eflags |
| 80386 | `6733` | 25 | 2046 | reg:ecx, reg:eflags |
| 80386 | `6738` | 25 | 2064 | reg:eflags |
| 80386 | `6739` | 25 | 2044 | reg:eflags |
| 80386 | `673B` | 25 | 2044 | reg:eflags |
| 80386 | `67660B` | 25 | 2048 | reg:ebx, reg:eflags |
| 80386 | `676623` | 25 | 2045 | reg:eax, reg:eflags |
| 80386 | `676633` | 25 | 2042 | reg:ecx |
| 80386 | `67663B` | 25 | 2042 | reg:eflags |
| 80386 | `676681.4` | 25 | 2089 | reg:eflags, mem:0x69c85, mem:0x69c86, mem:0x69c87 |
| 80386 | `676683.1` | 25 | 2084 | reg:eflags |
| 80386 | `676683.5` | 25 | 2083 | reg:eflags, mem:0x69c85 |
| 80386 | `676683.6` | 25 | 2082 | mem:0x69c85 |
| 80386 | `6766C7` | 25 | 2005 | mem:0x28815, mem:0x28816, mem:0x28817, mem:0x28818 |
| 80386 | `67C7` | 25 | 2002 | mem:0x28815, mem:0x28816 |
| 80386 | `0FBA.7` | 24 | 2473 | reg:eflags |
| 80386 | `676669` | 24 | 2070 | reg:esp, reg:eflags |
| 80386 | `676681.7` | 24 | 2050 | reg:eflags |
| 80386 | `6780.0` | 24 | 2107 | reg:eflags, mem:0x69c85 |
| 80386 | `6780.2` | 24 | 2107 | reg:eflags, mem:0x69c85 |
| 80386 | `6780.3` | 24 | 2107 | reg:eflags, mem:0x69c85 |
| 80386 | `6780.5` | 24 | 2105 | reg:eflags, mem:0x69c85 |
| 80386 | `6780.6` | 24 | 2105 | mem:0x69c85 |
| 80386 | `6781.0` | 24 | 2086 | reg:eflags, mem:0x69c85, mem:0x69c86 |
| 80386 | `6781.2` | 24 | 2086 | reg:eflags, mem:0x69c85, mem:0x69c86 |
| 80386 | `6781.3` | 24 | 2086 | reg:eflags, mem:0x69c85, mem:0x69c86 |
| 80386 | `6781.5` | 24 | 2086 | reg:eflags, mem:0x69c85, mem:0x69c86 |
| 80386 | `6781.6` | 24 | 2086 | reg:eflags, mem:0x69c85, mem:0x69c86 |
| 80386 | `6782.0` | 24 | 2107 | reg:eflags, mem:0x69c85 |
| 80386 | `6782.1` | 24 | 2107 | mem:0x69c85 |
| 80386 | `6782.2` | 24 | 2107 | reg:eflags, mem:0x69c85 |
| 80386 | `6782.3` | 24 | 2108 | reg:eflags, mem:0x69c85 |
| 80386 | `6782.5` | 24 | 2105 | reg:eflags, mem:0x69c85 |
| 80386 | `6782.6` | 24 | 2105 | reg:eflags, mem:0x69c85 |
| 80386 | `6783.0` | 24 | 2087 | reg:eflags, mem:0x69c85 |
| 80386 | `6783.1` | 24 | 2088 | reg:eflags |
| 80386 | `6783.2` | 24 | 2087 | reg:eflags, mem:0x69c85 |
| 80386 | `6783.5` | 24 | 2085 | reg:eflags, mem:0x69c85 |
| 80386 | `6783.6` | 24 | 2085 | reg:eflags, mem:0x69c85 |
| 80386 | `67C6` | 24 | 2023 | mem:0x28815 |
| 80386 | `C7` | 24 | 2338 | mem:0x23083, mem:0x23084 |
| 80386 | `2B` | 23 | 2424 | reg:edi, reg:eflags |
| 80386 | `670B` | 23 | 2050 | reg:ebx, reg:eflags |
| 80386 | `673A` | 23 | 2064 | reg:eflags |
| 80386 | `67666B` | 23 | 2064 | reg:esp, reg:eflags |
| 80386 | `676683.4` | 23 | 2082 | reg:eflags, mem:0x69c85, mem:0x69c86, mem:0x69c87 |
| 80386 | `676685` | 23 | 2046 | reg:eflags |
| 80386 | `6766D1.2` | 23 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D1.5` | 23 | 2059 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D1.6` | 23 | 2059 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6769` | 23 | 2067 | reg:esp, reg:eflags |
| 80386 | `676B` | 23 | 2067 | reg:esp |
| 80386 | `6780.1` | 23 | 2107 | reg:eflags, mem:0x69c85 |
| 80386 | `6780.4` | 23 | 2105 | reg:eflags, mem:0x69c85 |
| 80386 | `6781.4` | 23 | 2086 | reg:eflags, mem:0x69c85, mem:0x69c86 |
| 80386 | `6781.7` | 23 | 2049 | reg:eflags |
| 80386 | `6782.4` | 23 | 2105 | reg:eflags, mem:0x69c85 |
| 80386 | `67D0.0` | 23 | 2086 | mem:0xf881a |
| 80386 | `67D0.2` | 23 | 2086 | mem:0xf881a |
| 80386 | `67D0.4` | 23 | 2085 | reg:eflags, mem:0xf881a |
| 80386 | `67D0.5` | 23 | 2085 | reg:eflags, mem:0xf881a |
| 80386 | `67D1.2` | 23 | 2063 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67D1.5` | 23 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67D1.6` | 23 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67F6.2` | 23 | 2122 | mem:0x3f9f8 |
| 80386 | `67F6.3` | 23 | 2122 | reg:eflags, mem:0x3f9f8 |
| 80386 | `FF.2` | 23 | 2420 | reg:eip |
| 80386 | `6723` | 22 | 2048 | reg:eax, reg:eflags |
| 80386 | `6766C1.1` | 22 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766C1.2` | 22 | 2061 | mem:0xf881a, mem:0xf881b, mem:0xf881c, mem:0xf881d |
| 80386 | `6766C1.3` | 22 | 2061 | mem:0xf881a, mem:0xf881b, mem:0xf881c, mem:0xf881d |
| 80386 | `6766C1.4` | 22 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766C1.6` | 22 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D1.4` | 22 | 2059 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766F7.0` | 22 | 2069 | reg:eflags |
| 80386 | `6780.7` | 22 | 2068 | reg:eflags |
| 80386 | `6781.1` | 22 | 2086 | mem:0x69c85 |
| 80386 | `6783.7` | 22 | 2048 | reg:eflags |
| 80386 | `6785` | 22 | 2049 | reg:eflags |
| 80386 | `67C0.6` | 22 | 2086 | mem:0xf881a |
| 80386 | `67D0.1` | 22 | 2086 | reg:eflags, mem:0xf881a |
| 80386 | `67D0.3` | 22 | 2086 | mem:0xf881a |
| 80386 | `67D0.6` | 22 | 2085 | reg:eflags, mem:0xf881a |
| 80386 | `67D0.7` | 22 | 2085 | reg:eflags, mem:0xf881a |
| 80386 | `67D1.4` | 22 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `676662` | 21 | 795 | reg:eip |
| 80386 | `6766C1.5` | 21 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881c, mem:0xf881d |
| 80386 | `6766D1.1` | 21 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D1.3` | 21 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D1.7` | 21 | 2059 | reg:eflags |
| 80386 | `6766D3.1` | 21 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D3.4` | 21 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D3.6` | 21 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D3.7` | 21 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766F7.1` | 21 | 2069 | reg:eflags |
| 80386 | `6766F7.2` | 21 | 2095 | mem:0x3f9f8, mem:0x3f9f9, mem:0x3f9fa, mem:0x3f9fb |
| 80386 | `6766F7.3` | 21 | 2095 | reg:eflags, mem:0x3f9f8, mem:0x3f9f9, mem:0x3f9fa |
| 80386 | `6783.4` | 21 | 2085 | reg:eflags, mem:0x69c85, mem:0x69c86 |
| 80386 | `67C0.4` | 21 | 2086 | mem:0xf881a |
| 80386 | `67C0.5` | 21 | 2086 | mem:0xf881a |
| 80386 | `67C0.7` | 21 | 2086 | reg:eflags, mem:0xbc86c |
| 80386 | `67C1.1` | 21 | 2063 | mem:0xf881a, mem:0xf881b |
| 80386 | `67C1.5` | 21 | 2063 | mem:0xf881a, mem:0xf881b |
| 80386 | `67D1.1` | 21 | 2063 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67D1.3` | 21 | 2063 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67D1.7` | 21 | 2061 | reg:eflags |
| 80386 | `67D2.5` | 21 | 2084 | reg:eflags, mem:0xf881a |
| 80386 | `67D3.1` | 21 | 2063 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67D3.4` | 21 | 2063 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67D3.6` | 21 | 2063 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67D3.7` | 21 | 2063 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67F7.0` | 21 | 2063 | reg:eflags |
| 80386 | `67F7.2` | 21 | 2097 | mem:0x3f9f8, mem:0x3f9f9 |
| 80386 | `67F7.3` | 21 | 2097 | reg:eflags, mem:0x3f9f8, mem:0x3f9f9 |
| 80386 | `676683.7` | 20 | 2045 | reg:eflags |
| 80386 | `6766C1.0` | 20 | 2061 | mem:0xf881a, mem:0xf881b, mem:0xf881c, mem:0xf881d |
| 80386 | `6766C1.7` | 20 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D3.2` | 20 | 2061 | mem:0xf881a, mem:0xf881b, mem:0xf881c, mem:0xf881d |
| 80386 | `6766D3.5` | 20 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766F7.4` | 20 | 2064 | reg:eax, reg:edx, reg:eflags |
| 80386 | `6766F7.5` | 20 | 2064 | reg:eax, reg:edx, reg:eflags |
| 80386 | `67C1.7` | 20 | 2063 | mem:0xf881a, mem:0xf881b |
| 80386 | `67D2.7` | 20 | 2084 | reg:eflags, mem:0xf881a |
| 80386 | `67D3.5` | 20 | 2063 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67F6.1` | 20 | 2088 | reg:eflags |
| 80386 | `67F7.1` | 20 | 2063 | reg:eflags |
| 80386 | `670FBA.4` | 19 | 2056 | reg:eflags |
| 80386 | `6722` | 19 | 2068 | reg:edx, reg:eflags |
| 80386 | `6766D3.0` | 19 | 2061 | reg:eflags, mem:0xf881a, mem:0xf881b, mem:0xf881c |
| 80386 | `6766D3.3` | 19 | 2061 | mem:0xf881a, mem:0xf881b, mem:0xf881c, mem:0xf881d |
| 80386 | `67C1.0` | 19 | 2063 | mem:0xf881a, mem:0xf881b |
| 80386 | `67D3.0` | 19 | 2063 | reg:eflags, mem:0xf881a, mem:0xf881b |
| 80386 | `67F7.4` | 19 | 2066 | reg:eax, reg:edx, reg:eflags |
| 80386 | `67F7.5` | 19 | 2066 | reg:eax, reg:edx, reg:eflags |
| 80386 | `FF.6` | 19 | 2425 | mem:0x15d6c, mem:0x15d6d |
| 80386 | `6782.7` | 18 | 2070 | reg:eflags |
| 80386 | `67D2.4` | 18 | 2084 | reg:eflags, mem:0xf881a |
| 80386 | `67D2.6` | 18 | 2084 | reg:eflags, mem:0xf881a |
| 80386 | `67F6.0` | 18 | 2088 | reg:eflags |
| 80386 | `67F6.4` | 18 | 2086 | reg:eax, reg:eflags |
| 80286 | `62` | 17 | 649 | reg:ip |
| 80386 | `32` | 17 | 2431 | reg:eax, reg:eflags |
| 80386 | `670FA5` | 17 | 1100 | reg:eflags, mem:0xf3ce4, mem:0xf3ce5 |
| 80386 | `67660FBA.4` | 17 | 2055 | reg:eflags |
| 80386 | `6784` | 17 | 2070 | reg:eflags |
| 80386 | `6661` | 16 | 2318 | reg:edx |
| 80386 | `670FAD` | 16 | 1109 | reg:eflags, mem:0x60da9, mem:0x60daa |
| 80386 | `67F6.5` | 16 | 2086 | reg:eax, reg:eflags |
| 80386 | `660FA3` | 15 | 2433 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `66AB` | 15 | 2319 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `670FA4` | 15 | 1134 | mem:0x14e40, mem:0x14e41 |
| 80386 | `0FA3` | 13 | 2433 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `670FAC` | 13 | 1129 | mem:0x14e40, mem:0x14e41 |
| 80386 | `D4` | 13 | 2436 | SimZeroDivisionException: divide by zero! |
| 80386 | `66A7` | 12 | 2218 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `676689` | 12 | 804 | mem:0x69c85, mem:0x69c86, mem:0x69c87, mem:0x69c88 |
| 80386 | `6786` | 12 | 833 | reg:ecx, mem:0xff70e |
| 80386 | `6788` | 12 | 812 | mem:0x69c85 |
| 80386 | `678A` | 12 | 813 | reg:eax |
| 80386 | `80.7` | 12 | 2430 | reg:eflags |
| 80386 | `82.7` | 12 | 2430 | reg:eflags |
| 80386 | `6762` | 11 | 718 | reg:eip |
| 80386 | `67668B` | 11 | 803 | reg:eax |
| 80386 | `6787` | 11 | 822 | reg:ebp, mem:0xff70e, mem:0xff70f |
| 80386 | `6789` | 11 | 804 | mem:0x69c85, mem:0x69c86 |
| 80386 | `678B` | 11 | 803 | reg:eax |
| 80386 | `A5` | 11 | 2221 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `3A` | 10 | 2431 | reg:eflags |
| 80386 | `670F9E` | 10 | 422 | mem:0xc5a98 |
| 80386 | `6766AB` | 10 | 2314 | mem:0x85000 |
| 80386 | `670F95` | 9 | 417 | mem:0xc5a98 |
| 80386 | `670F90` | 8 | 419 | mem:0x9913a |
| 80386 | `670F93` | 8 | 420 | mem:0x6fecc |
| 80386 | `670F9C` | 8 | 420 | mem:0xc5a98 |
| 80386 | `67668E` | 8 | 809 | reg:fs |
| 80386 | `6766A7` | 8 | 2428 | reg:eflags |
| 80386 | `678E` | 8 | 809 | reg:fs |
| 80386 | `89` | 8 | 974 | mem:0xd2162, mem:0xd2163 |
| 80386 | `6660` | 7 | 2427 | reg:esp, reg:eip, mem:0xb8fd, mem:0xb8fe |
| 80386 | `666D` | 7 | 930 | mem:0x56000, mem:0x56001, mem:0x56002 |
| 80386 | `66AF` | 7 | 2320 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `670F97` | 7 | 418 | mem:0xc5a98 |
| 80386 | `670F99` | 7 | 418 | mem:0xfaa19 |
| 80386 | `670F9A` | 7 | 420 | mem:0xc5a98 |
| 80386 | `67668C` | 7 | 828 | mem:0x106f38 |
| 80386 | `678C` | 7 | 828 | mem:0x106f38 |
| 80386 | `66AD` | 6 | 2324 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `670F96` | 6 | 418 | mem:0x6fecc |
| 80386 | `670F98` | 6 | 418 | mem:0xc5a98 |
| 80386 | `670F9B` | 6 | 419 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `AB` | 6 | 2325 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `AD` | 6 | 2327 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `AF` | 6 | 2326 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `C1.4` | 6 | 2421 | reg:eflags |
| 80386 | `C1.6` | 6 | 2421 | reg:eflags |
| 80386 | `C8` | 6 | 2393 | mem:0xe90fa |
| 80386 | `666B` | 5 | 2424 | reg:ebp, reg:eflags |
| 80386 | `66C1.0` | 5 | 2418 | reg:eflags, mem:0x102fff, mem:0x103000, mem:0x103001 |
| 80386 | `66C1.2` | 5 | 2418 | reg:eflags, mem:0x102fff, mem:0x103000, mem:0x103001 |
| 80386 | `66C1.3` | 5 | 2418 | mem:0x102fff, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66C1.4` | 5 | 2418 | reg:eflags, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66C1.6` | 5 | 2418 | mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66C1.7` | 5 | 2418 | mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66D1.0` | 5 | 2419 | reg:eflags, mem:0x102fff, mem:0x103000, mem:0x103001 |
| 80386 | `66D1.1` | 5 | 2419 | mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66D1.3` | 5 | 2419 | mem:0x102fff, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66D1.4` | 5 | 2418 | reg:eflags, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66D3.0` | 5 | 2419 | reg:eflags, mem:0x102fff, mem:0x103000, mem:0x103001 |
| 80386 | `66D3.1` | 5 | 2419 | reg:eflags, mem:0x102fff, mem:0x103000, mem:0x103001 |
| 80386 | `66D3.2` | 5 | 2419 | mem:0x102fff, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66D3.3` | 5 | 2419 | reg:eflags, mem:0x102fff, mem:0x103000, mem:0x103001 |
| 80386 | `66D3.4` | 5 | 2419 | mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66D3.5` | 5 | 2419 | reg:eflags, mem:0x102fff, mem:0x103000, mem:0x103001 |
| 80386 | `66E5` | 5 | 500 | reg:eax |
| 80386 | `66F7.2` | 5 | 2473 | mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66F7.3` | 5 | 2473 | mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66F7.4` | 5 | 2421 | reg:eax, reg:edx |
| 80386 | `66F7.5` | 5 | 2421 | reg:eax, reg:edx, reg:eflags |
| 80386 | `670F91` | 5 | 418 | mem:0x6fecc |
| 80386 | `67668F` | 5 | 771 | mem:0x100b6c, mem:0x100b6d, mem:0x100b6e, mem:0x100b6f |
| 80386 | `6766AD` | 5 | 2311 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `67AD` | 5 | 2315 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `6603` | 4 | 2422 | reg:edi, reg:eflags |
| 80386 | `6609` | 4 | 2475 | reg:eflags |
| 80386 | `660B` | 4 | 2420 | reg:edi |
| 80386 | `6613` | 4 | 2423 | reg:edi |
| 80386 | `6619` | 4 | 2477 | reg:eflags, mem:0x1b000 |
| 80386 | `661B` | 4 | 2424 | reg:edi, reg:eflags |
| 80386 | `6621` | 4 | 2475 | mem:0x100000, mem:0x100001 |
| 80386 | `6629` | 4 | 2475 | reg:eflags |
| 80386 | `662B` | 4 | 2421 | reg:esp |
| 80386 | `6631` | 4 | 2475 | reg:eflags |
| 80386 | `6633` | 4 | 2419 | reg:esp, reg:eflags |
| 80386 | `6669` | 4 | 2423 | reg:ebx, reg:eip, reg:eflags |
| 80386 | `66A1` | 4 | 2446 | reg:eax |
| 80386 | `66A3` | 4 | 2441 | mem:0x7e000, mem:0x7e001 |
| 80386 | `66C1.1` | 4 | 2418 | mem:0x102fff, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66C1.5` | 4 | 2418 | mem:0x102fff, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66C9` | 4 | 2339 | reg:ebp |
| 80386 | `66D1.5` | 4 | 2418 | mem:0xa4fff, mem:0xa5000, mem:0xa5001 |
| 80386 | `66D1.6` | 4 | 2418 | reg:eflags, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66D1.7` | 4 | 2418 | reg:eflags, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66D3.6` | 4 | 2419 | reg:eflags, mem:0x103000, mem:0x103001, mem:0x103002 |
| 80386 | `66D3.7` | 4 | 2419 | reg:eflags, mem:0x102fff |
| 80386 | `670F92` | 4 | 420 | mem:0x5e835 |
| 80386 | `670F94` | 4 | 417 | mem:0x6fecc |
| 80386 | `670F9D` | 4 | 421 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `67666D` | 4 | 933 | mem:0x56000, mem:0x56001, mem:0x56002 |
| 80386 | `6766AF` | 4 | 2320 | reg:eflags |
| 80386 | `678F` | 4 | 801 | mem:0x100b6c, mem:0x100b6d |
| 80286 | `70` | 3 | 5000 | reg:ip |
| 80286 | `73` | 3 | 5000 | reg:ip |
| 80286 | `75` | 3 | 5000 | reg:ip |
| 80286 | `77` | 3 | 5000 | reg:ip |
| 80286 | `78` | 3 | 5000 | reg:ip |
| 80286 | `7B` | 3 | 5000 | reg:ip |
| 80286 | `7D` | 3 | 5000 | reg:ip |
| 80286 | `7F` | 3 | 5000 | reg:ip |
| 80386 | `6601` | 3 | 2475 | reg:eflags, mem:0x100000, mem:0x100001 |
| 80386 | `660FA4` | 3 | 2418 | reg:eflags, mem:0x57000 |
| 80386 | `660FA5` | 3 | 2418 | mem:0x57000 |
| 80386 | `660FAC` | 3 | 2417 | mem:0x56fff, mem:0x57000 |
| 80386 | `660FAD` | 3 | 2416 | mem:0x56ffd, mem:0x57000 |
| 80386 | `660FAF` | 3 | 2417 | reg:edi |
| 80386 | `660FBD` | 3 | 2417 | reg:edi |
| 80386 | `6681.0` | 3 | 2476 | reg:eflags, mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `6681.1` | 3 | 2476 | mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `6681.2` | 3 | 2476 | reg:eflags, mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `6681.3` | 3 | 2476 | reg:eflags, mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `6681.4` | 3 | 2476 | reg:eflags, mem:0x31001, mem:0x31002 |
| 80386 | `6681.5` | 3 | 2476 | mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `6681.6` | 3 | 2476 | reg:eflags, mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `6683.5` | 3 | 2477 | reg:eflags |
| 80386 | `6683.6` | 3 | 2477 | reg:eflags, mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `66D1.2` | 3 | 2419 | reg:eflags, mem:0xa5000, mem:0xa5001 |
| 80386 | `66F7.1` | 3 | 2419 | reg:eflags |
| 80386 | `670F9F` | 3 | 420 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `6766A1` | 3 | 2479 | reg:eax |
| 80386 | `6766A3` | 3 | 2467 | mem:0x10e000, mem:0x10e001, mem:0x10e002 |
| 80386 | `67AB` | 3 | 2317 | reg:ecx, reg:edi, reg:eip |
| 80386 | `67AF` | 3 | 2323 | reg:ecx, reg:edi, reg:eip, reg:eflags |
| 80386 | `C2` | 3 | 2419 | reg:esp, reg:eip |
| 80386 | `E8` | 3 | 2500 | reg:eip |
| 80386 | `E9` | 3 | 2500 | reg:eip |
| 80286 | `71` | 2 | 5000 | reg:ip |
| 80286 | `72` | 2 | 5000 | reg:ip |
| 80286 | `74` | 2 | 5000 | reg:ip |
| 80286 | `76` | 2 | 5000 | reg:ip |
| 80286 | `79` | 2 | 5000 | reg:ip |
| 80286 | `7A` | 2 | 5000 | reg:ip |
| 80286 | `7C` | 2 | 5000 | reg:ip |
| 80286 | `7E` | 2 | 5000 | reg:ip |
| 80386 | `6611` | 2 | 2478 | mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `663B` | 2 | 2421 | reg:eflags |
| 80386 | `6662` | 2 | 1552 | reg:eip |
| 80386 | `666F` | 2 | 924 | reg:ecx, reg:esi, reg:eip |
| 80386 | `6681.7` | 2 | 2417 | reg:eflags |
| 80386 | `6683.0` | 2 | 2477 | mem:0x1b000, mem:0x1b001, mem:0x1b002 |
| 80386 | `6683.1` | 2 | 2477 | mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `6683.3` | 2 | 2477 | mem:0x31000 |
| 80386 | `6683.4` | 2 | 2477 | reg:eflags |
| 80386 | `6683.7` | 2 | 2418 | reg:eflags |
| 80386 | `66C2` | 2 | 2196 | reg:esp, reg:eip |
| 80386 | `66F7.0` | 2 | 2419 | reg:eflags |
| 80386 | `67A0` | 2 | 2447 | reg:eax, reg:eip |
| 80386 | `67A1` | 2 | 2453 | reg:eax, reg:eip |
| 80386 | `67A2` | 2 | 2452 | reg:eip |
| 80386 | `67A3` | 2 | 2447 | reg:eip |
| 80386 | `67A4` | 2 | 2412 | reg:ecx, reg:esi, reg:edi, reg:eip |
| 80386 | `67A5` | 2 | 2411 | reg:ecx, reg:esi, reg:edi, reg:eip |
| 80386 | `67AA` | 2 | 2416 | reg:ecx, reg:edi, reg:eip |
| 80386 | `67AC` | 2 | 2404 | reg:ecx, reg:esi, reg:eip |
| 80386 | `67AE` | 2 | 2428 | reg:ecx, reg:edi, reg:eip, reg:eflags |
| 80386 | `6D` | 2 | 931 | reg:ecx, reg:edi, reg:eip, mem:0xd353c |
| 80386 | `6F` | 2 | 927 | reg:ecx, reg:esi, reg:eip |
| 80386 | `A2` | 2 | 2440 | reg:eip |
| 80386 | `A3` | 2 | 2439 | reg:eip |
| 80386 | `A4` | 2 | 2432 | reg:ecx, reg:esi, reg:edi, reg:eip |
| 80386 | `A8` | 2 | 2500 | reg:eip, reg:eflags |
| 80386 | `A9` | 2 | 2500 | reg:eip, reg:eflags |
| 80386 | `AA` | 2 | 2434 | reg:ecx, reg:edi, reg:eip |
| 80386 | `AC` | 2 | 2434 | reg:ecx, reg:esi, reg:eip |
| 80386 | `AE` | 2 | 2434 | reg:ecx, reg:edi, reg:eip, reg:eflags |
| 80386 | `C9` | 2 | 2343 | reg:ebp |
| 80386 | `FF.3` | 2 | 2405 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `FF.5` | 2 | 2405 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80286 | `9A` | 1 | 4989 | mem:0x1d000 |
| 80286 | `CB` | 1 | 4974 | reg:ip |
| 80386 | `00` | 1 | 2487 | reg:edx, reg:eip, reg:eflags |
| 80386 | `02` | 1 | 2434 | reg:eax, reg:eip, reg:eflags |
| 80386 | `03` | 1 | 2425 | reg:eip, reg:eflags |
| 80386 | `04` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `05` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `08` | 1 | 2487 | reg:edx, reg:eip, reg:eflags |
| 80386 | `0A` | 1 | 2432 | reg:eax, reg:eip, reg:eflags |
| 80386 | `0B` | 1 | 2423 | reg:eip, reg:eflags |
| 80386 | `0C` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `0D` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `10` | 1 | 2489 | reg:edx, reg:eip, reg:eflags |
| 80386 | `11` | 1 | 2481 | reg:esi, reg:eip, reg:eflags |
| 80386 | `12` | 1 | 2433 | reg:eax, reg:eip, reg:eflags |
| 80386 | `13` | 1 | 2426 | reg:eip, reg:eflags |
| 80386 | `14` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `15` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `18` | 1 | 2488 | reg:edx, reg:eip, reg:eflags |
| 80386 | `19` | 1 | 2480 | reg:esi, reg:eip, reg:eflags |
| 80386 | `1A` | 1 | 2436 | reg:eax, reg:eip, reg:eflags |
| 80386 | `1B` | 1 | 2427 | reg:eip, reg:eflags |
| 80386 | `1C` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `1D` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `20` | 1 | 2487 | reg:edx, reg:eip, reg:eflags |
| 80386 | `22` | 1 | 2432 | reg:eax, reg:eip, reg:eflags |
| 80386 | `23` | 1 | 2423 | reg:esp, reg:eip, reg:eflags |
| 80386 | `24` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `25` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `27` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `28` | 1 | 2487 | reg:edx, reg:eip, reg:eflags |
| 80386 | `2A` | 1 | 2433 | reg:eax, reg:eip, reg:eflags |
| 80386 | `2C` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `2D` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `2F` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `30` | 1 | 2487 | reg:edx, reg:eip, reg:eflags |
| 80386 | `33` | 1 | 2422 | reg:eip, reg:eflags |
| 80386 | `34` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `35` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `37` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `40` | 1 | 500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `41` | 1 | 500 | reg:ecx, reg:eip, reg:eflags |
| 80386 | `42` | 1 | 500 | reg:edx, reg:eip, reg:eflags |
| 80386 | `43` | 1 | 500 | reg:ebx, reg:eip, reg:eflags |
| 80386 | `44` | 1 | 500 | reg:esp, reg:eip, reg:eflags |
| 80386 | `45` | 1 | 500 | reg:ebp, reg:eip, reg:eflags |
| 80386 | `46` | 1 | 500 | reg:esi, reg:eip, reg:eflags |
| 80386 | `47` | 1 | 500 | reg:edi, reg:eip, reg:eflags |
| 80386 | `48` | 1 | 500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `49` | 1 | 500 | reg:ecx, reg:eip, reg:eflags |
| 80386 | `4C` | 1 | 500 | reg:esp, reg:eip, reg:eflags |
| 80386 | `4D` | 1 | 500 | reg:ebp, reg:eip, reg:eflags |
| 80386 | `4E` | 1 | 500 | reg:esi, reg:eip, reg:eflags |
| 80386 | `4F` | 1 | 500 | reg:edi, reg:eip, reg:eflags |
| 80386 | `58` | 1 | 965 | reg:eax |
| 80386 | `59` | 1 | 965 | reg:ecx |
| 80386 | `5A` | 1 | 964 | reg:edx |
| 80386 | `5B` | 1 | 964 | reg:ebx |
| 80386 | `5C` | 1 | 963 | reg:esp |
| 80386 | `5D` | 1 | 965 | reg:ebp |
| 80386 | `5E` | 1 | 965 | reg:esi |
| 80386 | `5F` | 1 | 965 | reg:edi |
| 80386 | `60` | 1 | 2435 | reg:esp, reg:eip, mem:0xb90d, mem:0xb90e |
| 80386 | `61` | 1 | 2415 | reg:eax, reg:ebx, reg:ecx, reg:edx |
| 80386 | `62` | 1 | 1527 | Real-mode segment-limit fault did not match the hardware vector-13 witness |
| 80386 | `6605` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `6607` | 1 | 963 | reg:es |
| 80386 | `660D` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `660F80` | 1 | 500 | reg:eip |
| 80386 | `660F82` | 1 | 500 | reg:eip |
| 80386 | `660F84` | 1 | 500 | reg:eip |
| 80386 | `660F86` | 1 | 500 | reg:eip |
| 80386 | `660F88` | 1 | 500 | reg:eip |
| 80386 | `660F8A` | 1 | 500 | reg:eip |
| 80386 | `660F8D` | 1 | 500 | reg:eip |
| 80386 | `660F8E` | 1 | 500 | reg:eip |
| 80386 | `660FB2` | 1 | 2394 | reg:ebx |
| 80386 | `660FB4` | 1 | 2393 | reg:ebx |
| 80386 | `660FB5` | 1 | 2393 | reg:ebx |
| 80386 | `6615` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `6617` | 1 | 964 | reg:ss |
| 80386 | `661D` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `661F` | 1 | 964 | reg:ds |
| 80386 | `6623` | 1 | 2420 | reg:esp, reg:eip, reg:eflags |
| 80386 | `6625` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `662D` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `6635` | 1 | 2500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `6640` | 1 | 500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `6641` | 1 | 500 | reg:ecx, reg:eip, reg:eflags |
| 80386 | `6642` | 1 | 500 | reg:edx, reg:eip, reg:eflags |
| 80386 | `6643` | 1 | 500 | reg:ebx, reg:eip, reg:eflags |
| 80386 | `6644` | 1 | 500 | reg:esp, reg:eip, reg:eflags |
| 80386 | `6645` | 1 | 500 | reg:ebp, reg:eip, reg:eflags |
| 80386 | `6646` | 1 | 500 | reg:esi, reg:eip, reg:eflags |
| 80386 | `6647` | 1 | 500 | reg:edi, reg:eip, reg:eflags |
| 80386 | `6648` | 1 | 500 | reg:eax, reg:eip, reg:eflags |
| 80386 | `6649` | 1 | 500 | reg:ecx, reg:eip, reg:eflags |
| 80386 | `664C` | 1 | 500 | reg:esp, reg:eip, reg:eflags |
| 80386 | `664D` | 1 | 500 | reg:ebp, reg:eip, reg:eflags |
| 80386 | `664E` | 1 | 500 | reg:esi, reg:eip, reg:eflags |
| 80386 | `664F` | 1 | 500 | reg:edi, reg:eip, reg:eflags |
| 80386 | `6658` | 1 | 930 | reg:eax |
| 80386 | `6659` | 1 | 929 | reg:ecx |
| 80386 | `665A` | 1 | 930 | reg:edx |
| 80386 | `665B` | 1 | 930 | reg:ebx |
| 80386 | `665C` | 1 | 927 | reg:esp |
| 80386 | `665D` | 1 | 928 | reg:ebp |
| 80386 | `665E` | 1 | 929 | reg:esi |
| 80386 | `665F` | 1 | 929 | reg:edi |
| 80386 | `6668` | 1 | 966 | reg:esp, reg:eip, mem:0xb919, mem:0xb91a |
| 80386 | `666A` | 1 | 966 | reg:esp, reg:eip, mem:0xb919 |
| 80386 | `6670` | 1 | 500 | reg:eip |
| 80386 | `6672` | 1 | 500 | reg:eip |
| 80386 | `6675` | 1 | 500 | reg:eip |
| 80386 | `6676` | 1 | 500 | reg:eip |
| 80386 | `6678` | 1 | 500 | reg:eip |
| 80386 | `667B` | 1 | 500 | reg:eip |
| 80386 | `667D` | 1 | 500 | reg:eip |
| 80386 | `6683.2` | 1 | 2477 | reg:eflags, mem:0x31000 |
| 80386 | `6689` | 1 | 972 | mem:0x31000, mem:0x31001, mem:0x31002 |
| 80386 | `668B` | 1 | 973 | reg:esi |
| 80386 | `668F` | 1 | 894 | reg:esi |
| 80386 | `669A` | 1 | 2432 | mem:0x34a4, mem:0x34a5 |
| 80386 | `66C3` | 1 | 2201 | reg:esp, reg:eip |
| 80386 | `66C4` | 1 | 2420 | reg:esp, reg:es, reg:eip |
| 80386 | `66C5` | 1 | 2420 | reg:esp, reg:ds, reg:eip |
| 80386 | `66C7` | 1 | 2336 | reg:eip, mem:0xf5cd3, mem:0xf5cd4, mem:0xf5cd5 |
| 80386 | `66CA` | 1 | 2221 | reg:esp, reg:cs, reg:eip |
| 80386 | `66CB` | 1 | 2207 | reg:esp, reg:cs, reg:eip |
| 80386 | `66CF` | 1 | 2291 | reg:esp, reg:cs, reg:eip, reg:eflags |
| 80386 | `66E8` | 1 | 2500 | reg:esp, reg:eip, mem:0xb919, mem:0xb91a |
| 80386 | `66E9` | 1 | 2500 | reg:eip |
| 80386 | `66EA` | 1 | 2499 | reg:cs, reg:eip |
| 80386 | `66EB` | 1 | 2500 | reg:eip |
| 80386 | `67666F` | 1 | 929 | reg:ecx, reg:esi, reg:eip |
| 80386 | `676C` | 1 | 970 | reg:ecx, reg:edi, reg:eip, mem:0xd353c |
| 80386 | `676D` | 1 | 933 | reg:ecx, reg:edi, reg:eip, mem:0xd353c |
| 80386 | `676E` | 1 | 970 | reg:ecx, reg:esi, reg:eip |
| 80386 | `676F` | 1 | 930 | reg:ecx, reg:esi, reg:eip |
| 80386 | `67D7` | 1 | 2444 | reg:eax, reg:eip |
| 80386 | `68` | 1 | 966 | reg:esp, reg:eip, mem:0xb91b, mem:0xb91c |
| 80386 | `69` | 1 | 2426 | reg:ebx, reg:eip, reg:eflags |
| 80386 | `6A` | 1 | 966 | reg:esp, reg:eip, mem:0xb91b |
| 80386 | `6B` | 1 | 2426 | reg:ebx, reg:eip, reg:eflags |
| 80386 | `6C` | 1 | 972 | reg:ecx, reg:edi, reg:eip, mem:0xd353c |
| 80386 | `6E` | 1 | 972 | reg:ecx, reg:esi, reg:eip |
| 80386 | `C0.4` | 1 | 2433 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `C0.5` | 1 | 2433 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `C0.6` | 1 | 2433 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `C0.7` | 1 | 2433 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `C1.0` | 1 | 2421 | reg:eip, mem:0xbe81, mem:0xbe82 |
| 80386 | `C1.1` | 1 | 2421 | reg:eip |
| 80386 | `C1.5` | 1 | 2421 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `C1.7` | 1 | 2421 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `C3` | 1 | 2419 | reg:esp, reg:eip |
| 80386 | `C4` | 1 | 2421 | reg:esp, reg:es, reg:eip |
| 80386 | `C5` | 1 | 2421 | reg:esp, reg:ds, reg:eip |
| 80386 | `C6` | 1 | 2351 | reg:eip, mem:0xf5cd3 |
| 80386 | `CA` | 1 | 2420 | reg:esp, reg:cs, reg:eip |
| 80386 | `CB` | 1 | 2420 | reg:esp, reg:cs, reg:eip |
| 80386 | `CF` | 1 | 2436 | reg:esp, reg:cs, reg:eip, reg:eflags |
| 80386 | `D0.0` | 1 | 2433 | reg:eip, mem:0xbe81 |
| 80386 | `D0.1` | 1 | 2433 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `D0.2` | 1 | 2433 | reg:eip, mem:0xbe81 |
| 80386 | `D0.3` | 1 | 2433 | reg:eip, mem:0xbe81 |
| 80386 | `D0.4` | 1 | 2434 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `D0.5` | 1 | 2434 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `D0.6` | 1 | 2434 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `D0.7` | 1 | 2434 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `D1.0` | 1 | 2422 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `D1.1` | 1 | 2422 | reg:eip, mem:0xbe81, mem:0xbe82 |
| 80386 | `D1.2` | 1 | 2422 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `D1.3` | 1 | 2422 | reg:eip, reg:eflags, mem:0xbe82 |
| 80386 | `D1.5` | 1 | 2421 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `D1.7` | 1 | 2421 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `D2.4` | 1 | 2434 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `D2.5` | 1 | 2434 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `D2.6` | 1 | 2434 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `D2.7` | 1 | 2434 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `D3.0` | 1 | 2422 | reg:eip, mem:0xbe81, mem:0xbe82 |
| 80386 | `D3.1` | 1 | 2422 | reg:eip, mem:0xbe81, mem:0xbe82 |
| 80386 | `D3.4` | 1 | 2422 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `D3.5` | 1 | 2422 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `D3.6` | 1 | 2422 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `D3.7` | 1 | 2422 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `D5` | 1 | 2436 | reg:eip, reg:eflags |
| 80386 | `D7` | 1 | 2435 | reg:eax, reg:eip |
| 80386 | `E5` | 1 | 500 | reg:eax |
| 80386 | `EA` | 1 | 2499 | reg:cs, reg:eip |
| 80386 | `EB` | 1 | 2500 | reg:eip |
| 80386 | `F6.0` | 1 | 2433 | reg:eip, reg:eflags |
| 80386 | `F6.1` | 1 | 2433 | reg:eip, reg:eflags |
| 80386 | `F6.2` | 1 | 2486 | reg:eip, mem:0xbe81 |
| 80386 | `F6.3` | 1 | 2486 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `F6.4` | 1 | 2432 | reg:eip, reg:eflags |
| 80386 | `F6.5` | 1 | 2432 | reg:eip, reg:eflags |
| 80386 | `F7.0` | 1 | 2422 | reg:eip, reg:eflags |
| 80386 | `F7.1` | 1 | 2422 | reg:eip, reg:eflags |
| 80386 | `F7.2` | 1 | 2475 | reg:eip, mem:0xbe81, mem:0xbe82 |
| 80386 | `F7.3` | 1 | 2475 | reg:eip, reg:eflags, mem:0xbe81, mem:0xbe82 |
| 80386 | `F7.4` | 1 | 2423 | reg:edx, reg:eip, reg:eflags |
| 80386 | `F7.5` | 1 | 2423 | reg:edx, reg:eip, reg:eflags |
| 80386 | `FE.0` | 1 | 2485 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `FE.1` | 1 | 2485 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `FF.0` | 1 | 2473 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `FF.1` | 1 | 2473 | reg:eip, reg:eflags, mem:0xbe81 |
| 80386 | `FF.4` | 1 | 2420 | reg:eip |

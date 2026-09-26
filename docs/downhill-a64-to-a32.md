# rearm downhill — A64 → A32/T32 design notes

Status: **design / planning**. The uphill direction (A32/T32 → A64) is the
complete, verified pipeline; this document is the honest architectural
assessment of the reverse ("downhill") direction before any code is written.

## TL;DR

Downhill translation is **not** the uphill pipeline run backwards. Almost
every mapping that makes uphill cheap inverts into a lossy or unsound
translation going down. It is buildable, but as a *recompiler with a runtime*
(register-file + addressing emulation), not as 1:1 static codegen. The staged
plan below gets there in testable increments, reusing all existing machinery.

## 1. What inverts cleanly (do these first)

| A64 | A32/T32 | Notes |
|---|---|---|
| `MOV Wd, Wn` arith on 32-bit values | identical | X regs' **lower halves** map to R0-R14; w-ops translate almost 1:1 |
| `ADD/SUB/AND/ORR/EOR/BIC` (W) | same ops | flags variants map (`ADDS`→`ADDS`) |
| shifts (`LSL/LSR/ASR/ROR`), `MUL`, `SDIV/UDIV` | same | T32 has all of them |
| `CBZ/CBNZ` | `CBZ/CBNZ` (T1, T32) | range limits differ — out-of-range needs trampolines |
| conditional compare/select (`CSEL/CSINC…`) | `IT` blocks + `MOV` | or branch; both sound |
| `B/BL/BR/BLR` (+`LR`) | `B/BL/BX` | PC-range: A32 ±16MB vs A64 ±128MB → trampolines |
| NEON/FP (`ADD Vd.4S, …`, `FADD`, loads/stores) | NEON/VFP regs are the **same 32×128-bit register file** (`Q0-Q31` ↔ `V0-V31`) | the one genuinely symmetric subsystem |
| `LDXR/STXR/W` (32-bit exclusives) | `LDREX/STREX` | success=0 convention identical |
| `DMB/DSB/ISB` | identical encodings, 1:1 | |

## 2. What does NOT invert — the real problems

### 2.1 The register file (31×64 → 15×32 usable)

A64 has X0-X30 + SP; A32 has R0-R12 usable (R13=SP, R14=LR, R15=PC, some
usable with care). Two honest strategies:

* **Pair-mapping (correct, slow):** X0-X14 → register pairs; every 64-bit
  op becomes carry-chained 32-bit ops (`ADDS` + `ADC` for ADD; the SUB
  borrow chain; `UMULL`-based 64-bit mul; shifts via funnel-shift
  emulation). Costs ~3-6× instruction count and clobbers flags state
  (A64 NZCV must be *shadowed*, see 2.4).
* **Memory-backed file (simple, slower):** spilled X-state lives in a
  per-thread block at a fixed offset (like rearm's low-arena); hot regs
  cached in R-regs around basic blocks. This is what real
  64→32 dynamic emulators do; it composes better with the runtime we
  already ship.

Recommendation: start with memory-backed (correctness first — the project
motto), then add pair-mapping peepholes for the patterns that dominate
real code (32-bit-only data flow — which is most of it, see 2.2).

### 2.2 64-bit values and addressing

* A64 pointers are 64-bit. If the guest binary only ever holds addresses
  in the low 4 GiB (true for essentially all Android arm32-era .so inputs
  and for our own translated images — rearm's code window/bridges are
  already 32-bit), pointers fit W registers and 2.1 degrades gracefully.
* Code that *does* compute in X-width (hashes, `__int64` counters, CRC,
  crypto) must go through the pair path or helper calls.
* Loading/storing at `X`-computed addresses: truncate to 32 bits after a
  (debug-mode) check.

### 2.3 Atomics — the asymmetry that bit us uphill, in reverse

* `LDXR/STXR` 8-byte exclusives → `LDREXD/STREXD` (pairs) — fine.
* `LDXP/STXP` **128-bit** pair exclusives: **no A32 equivalent exists**.
  Emulate with a global lock + retry loop; note this serializes 128-bit
  atomics but preserves the API (the alternative — software LL/SC over
  two words — cannot be made atomic vs native 32-bit atomic agents).
* LSE (`LDADD/CAS/SWP`, ARMv8.1): lower to `LDREX/STREX` loops
  (u-cycle: the same loops we emit uphill).
* The outlined-atomics family we now ship (runtime/atomics_rt.o) is
  *uphill-only* — downhill never references it (no 64-bit caller exists
  in the guest), but the downhill *runtime* will need its own lock table.

### 2.4 NZCV and PSTATE

A64 NZCV ≈ A32 APSR (N/Z/C/V same positions, same meaning for the common
ops — verified uphill already). Differences:

* `MRS/MSR` of DAIF, etc. → runtime calls (no user-mode equivalent on
  AArch32 either).
* A64 has no `GE` flags; A32's SIMD-GE are unused by translated code
  (uphill preserves them in x20-x23; downhill can simply never set them
  except for `SEL`-style ops the guest won't contain).

### 2.5 No-A32- equivalent instructions

* `PAC*/AUT*/BTI` (ARMv8.3+): strip — safe iff pointers are 32-bit (PAC
  uses the upper bits; truncation is the identity here).
* `LDAR/STLR` → `LDREX/STXR` + `DMB` (acquire/release via barrier).
* `REV64`, `SXTL2`-style widening — expand as op sequences.

## 3. Pipeline shape (reuse, reuse, reuse)

```
ELF64 AArch64 .so
   │  objread64 (new: ELF64 dynamic reader — mirror of the ELF32 one)
   ▼
a64::decode (NEW — the big one; a64/decode.rs is a stub today)
   │  same Ins-style IR as a32/t32 today (ir.rs shared)
   ▼
translate/a64_to_a32.rs  (NEW)
   │  w-ops: near 1:1 (T32)          X-ops: pair/carry or runtime spill
   │  exclusives: LDXR→LDREX etc.; LDXP 16B → lock-table helper
   ▼
A32/T32 machine code (existing encoder!) ── embed in ELF32 .so emitter
   │  (mirror of soemit; runtime = downhill loader: 64-bit spill frames,
   │   lock table, trampolines for ±16MB branch range)
   ▼
ELF32 ARM .so
```

Everything right of `a64::decode` reuses existing, corpus-tested machinery
(encoders, Z3 differential harness, golden-corpus tooling, the .so emitter
pattern, the post-link symbol guard pattern we just added).

## 4. Staged milestones (each independently testable)

1. **A64 golden corpora** — extend tools/tcorpus.py to generate A64
   corpora (it already knows how to drive llvm-mc/llvm-objdump; the
   a64-misc corpus generator exists from Task 3's groundwork). Target
   ~2K instructions across integer/branch/ldst/SIMD.
2. **a64::decode complete** — 100% round-trip against the corpora with
   the existing encoder (decode∘encode == identity). This alone is a
   deliverable: a Rust A64 disassembler with Z3 hooks.
3. **a64_to_a32 lifter for the 32-bit subset** (W-ops, W-exclusives,
   branches, CBZ) + Z3 differential proofs — the "what inverts cleanly"
   table above. Verified against qemu-arm via the existing harness
   pattern (runtime/harness.rs, q*.log methodology).
4. **Runtime spill file + X-op helpers** (64-bit arithmetic callouts,
   LDXP/STXP lock table, LDAR/STLR lowering).
5. **objread64 + ELF32 emitter + trampoline range fixups.**
6. **End-to-end differential**: open-source A64 .so (built from source
   for aarch64) → rearm downhill → run both under qemu-user, compare.

## 5. Non-goals / honesty section

* No speculation of performance parity: expect 5-15× slowdown vs native
  A64 on X-heavy code; near 1× on the 32-bit subset.
* A64 → *T32-only* (Thumb) output is the default (density); A32 output
  mode kept for debugging, exactly like the encoder's dual mode today.
* SVE, SME, MTE, pointer-auth-in-data: rejected at decode with a clear
  error (they cannot appear in arm32-era Android workloads anyway).

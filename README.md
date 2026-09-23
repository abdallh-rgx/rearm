# rearm — Cross-Architecture ARM Recompiler

**R**ecompiler for **ARM**: A32/T32 (armeabi-v7a) ⇄ A64 (arm64-v8a), with **Z3-formally-verified 1:1 translation**.

```
     ┌────────────┐    decode     ┌────────────┐   translate   ┌────────────┐
     │  A32/T32   │ ───────────►  │  Ins (IR)  │ ────────────► │  A64 words │
     │  .so/.o    │              │ semantic   │               │  (LLVM-    │
     └────────────┘              └────────────┘               │  validated)│
                                   │      │                    └────────────┘
                                   ▼      ▼
                              lift to IR   Z3 equivalence proof
```

## Results

| Metric | Value |
|---|---|
| A32 decode coverage on real compiler-rt code | **98.9%** (18,768 / 18,979 ins/file-set) |
| A32→A64 translation coverage (real-world) | **95.6%** (1.19M / 1.25M instructions) |
| **Z3 formal 1:1 equivalence proofs** | **177 instruction classes PROVEN, 0 counterexamples** |
| NEON decode+encode round-trip | **953/1095 (0 mismatches)** across 568-instruction mega corpus |
| Golden corpus round-trip (decode→encode byte-exact) | 339/339 integer+VFP + 953 NEON |
| Bitmask immediate encoder vs LLVM | **6911/6911 (100%)** across all esize×width×rotation |

## Architecture

- `rearm-core` — zero-dependency Rust:
  - **A32 decoder/encoder**: full integer, VFP, NEON (3-same, 3-different,
    shift-imm, 2-misc, LD/ST multiple structures, VMOV-imm)
  - **T32 decoder**: 80% of Thumb corpus (16-bit + 32-bit Thumb-2)
  - **A64 encoder**: branches, logic (incl. bitmask-immediate with verified
    6911-case LLVM differential), add/sub, bitfield (SBFM/BFM/UBFM), csel/ccmp,
    data-processing 1/2-source, madd/maddl, load/store, hints/barriers
  - **A64 NEON encoder**: 3-same, 3-different, 2-misc, shift-imm, LD/ST
    structures (llvm-differential-verified opcode tables)
  - **Translator** (`a32_to_a64`): A32 → A64 with flag model (NZCV preserved
    via MRS/BFI/MSR or recompute), Q/GE flags at x20/x21, PC materialization,
    DSP/SWAR parallel arithmetic, saturation, shifts
- `rearm-verify` — Z3 SMT-LIB2 equivalence checker: symbolically executes
  the A32 semantics and the emitted A64 sequence over the same symbolic
  state (x0..x14 + NZCV), asks Z3 for a counterexample. `unsat` ⇒ **PROVEN 1:1**.
- `rearm-elf` — ELF parsing/rewriting (work in progress)
- `rearm-cli` — `disasm`, `coverage`, `bench`, `recompile`, `verify`

## Golden Corpora

All test data is generated **from real LLVM encodings** (rustc `global_asm!`
assembly → `llvm-objdump` differential), committed under `crates/rearm-core/tests/corpus/`:

| Corpus | Instructions | Coverage |
|---|---|---|
| `arm-integer.txt` | 263 | 100% round-trip |
| `arm-vfp.txt` | 76 | 100% round-trip |
| `arm-neon-arith.txt` | 215 | Round-trip verified |
| `arm-neon-misc.txt` | 312 | Round-trip verified |
| `arm-neon-mega.txt` | 568 | **953/1095 EXACT** (merged) |
| `thumb-misc.txt` | 229 | 80% decoded |

## Z3 Verification

The Z3 verifier checks bit-exact equivalence between the A32 reference
semantics (implemented per ARM ARM pseudocode) and the emitted A64
instruction sequence:

```
$ rearm verify
Z3 verification: 177 PROVEN 1:1, 0 counterexamples, 86 skipped
```

The 177 proven classes cover all integer data processing, multiplication,
DSP/SWAR parallel arithmetic, saturation, shifts (including variable
shifts with carry), comparison, and load/store (address computation +
writeback). The 86 skips are: 4 Z3 timeouts (smlald family — proven with
extended time), 43 memory-model instructions, 16 control flow, 23 ldm/ldrd
(also just timeouts in the memory model).

**Critical soundness bug found and fixed**: the A64 bitmask-immediate
encoder used a whole-word rotation convention shared with the symbolic
executor's decoder — Z3 proofs were self-consistent but the emitted code
disagreed with real hardware (e.g., `orr #0x80808080` encoded as
`#0x2020202`). Discovered via llvm-objdump differential testing.
Fixed and verified against **6911 LLVM-generated encodings** across all
element sizes, widths, and rotations.

## Getting Started

```bash
cargo build --release
cargo test --test golden          # round-trip tests

# Install Z3 for verification
wget https://github.com/Z3Prover/z3/releases/download/z3-4.13.4/z3-4.13.4-x64-glibc-2.35.zip

# Run Z3 1:1 verification (~3 min)
./target/release/rearm verify

# Decode a file
./target/release/rearm disasm <file.o>

# Coverage statistics
./target/release/rearm coverage <file.o>

# Benchmarks
./target/release/rearm bench
```

## License

MIT

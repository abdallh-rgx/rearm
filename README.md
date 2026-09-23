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
| A32 decode coverage on real compiler-rt code | **99.39%** (69,792 / 70,221 instrs) |
| A32→A64 translation coverage | **94.9%** (24,519 / 25,844) |
| **Z3 formal 1:1 equivalence proofs** | **45 instruction classes PROVEN, 0 counterexamples** |
| Decode throughput (release) | **313.9 MB/s (78.2 M ins/s)** |
| Golden corpus round-trip (decode→encode byte-exact) | 339/339 integer+VFP |

## Design

- `rearm-core` — zero-dependency Rust: A32 decoder/encoder, semantic `Ins` model, A64 encoder, translator
- `rearm-verify` — Z3 SMT-LIB2 equivalence checker: symbolically executes the A32 semantics and the emitted A64 sequence over the same symbolic state (x0..x14 + NZCV), asks Z3 for a counterexample. `unsat` ⇒ **PROVEN 1:1**.
- `rearm-cli` — `disasm`, `coverage`, `bench`, `recompile`, `verify`
- Golden corpora generated **from real LLVM encodings** (rustc `global_asm!` + `llvm-objdump`), committed under `crates/rearm-core/tests/corpus/`.

## Usage

```sh
cargo run -p rearm-cli --release -- coverage  libfoo.so     # decode coverage
cargo run -p rearm-cli --release -- bench     libfoo.so     # MB/s
cargo run -p rearm-cli --release -- recompile libfoo.so out # A32 → A64
cargo run -p rearm-cli --release -- verify                   # Z3 1:1 proofs
```

## Verified translation invariants

- Register mapping r0..r14 → x0..x14 (W-register ops zero-extend, matching A32 32-bit semantics exactly)
- NZCV semantics: ADD/SUB/CMP/CMN flags map 1:1; logic-with-S flag reconstruction uses `mrs`/`bfi` sequences to restore A32's shifter-carry + V-preservation — each pattern Z3-proven
- SMULL/UMULL/SMLAL/UMLAL split via 64-bit products and re-extraction — proven
- SXT/UXT accumulate forms materialize through scratch — proven

## License

MIT OR Apache-2.0. No GPL/QEMU code — clean-room implementation from the ARM Architecture Reference Manual, with encodings validated empirically against LLVM.

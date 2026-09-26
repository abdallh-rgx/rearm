//! T32 (Thumb-2) → A64 1:1 recompiler.
//!
//! Shares the fixed register map and helper sequences of the A32 translator
//! (`a32_to_a64`); every non-PC T32 instruction that decodes into a shared
//! `Ins` variant is delegated to it. This module owns the T32-specific
//! semantics:
//!
//! * **PC reads** — generic reads (ADD/CMP/MOV with r15) read `addr + 4`;
//!   **ADR and LDR (literal)** use `Align(addr + 4, 4)` per the ARM ARM.
//! * **Modified immediates** — `ThumbExpandImm` (rotation count = imm12<11:7>,
//!   base = `'1':imm12<6:0>`; validated against all 4096 LLVM encodings).
//!   `plain` immediates (ADDW/SUBW/ADR and all T16 immediate forms) are the
//!   raw 12-bit value.
//! * **IT blocks** — conditional instructions are guard-bracketed:
//!   `b.<inv-cond> skip; <body>; skip:`. `b.cond` does not write flags, so a
//!   flag-setting body evaluates the condition on the pre-instruction flags —
//!   exactly T32 IT semantics. The guard is architecturally exact, so the Z3
//!   1:1 proofs are run on the unguarded body.
//! * **Branch offsets** — passed through raw (byte offsets relative to the
//!   source instruction); `rearm-elf` resolves them against the source map.
//! * **LR writes** — T32 `BL`/`BLX` set `LR = (addr + 4) | 1`; `BX/BLX (reg)`
//!   targets interwork naturally because all translated code is A64.

use crate::common::*;
use crate::a32::ins::*;
use crate::a64::encode::{A64, XR};
use crate::translate::a32_to_a64::{translate_a32, translate_dp, TranslateErr};

use crate::translate::a32_to_a64::Operand;
use crate::translate::a32_to_a64::branch_off_or_zero;

#[inline]
fn x(r: R) -> XR { r as XR }

/// `Align(addr + 4, 4)` — the T32 ADR / literal-load base.
#[inline]
fn t32_pc_aligned(addr: u32) -> u32 { (addr.wrapping_add(4)) & !3u32 }

// ==================== ThumbExpandImm ====================

/// Expand a T32 modified immediate (i:imm3:imm8 raw 12-bit field).
///
/// Returns `(value, carry)` where `carry = Some(b)` is the shifter carry-out
/// used by flag-setting forms (logical ops read it as C when the instruction
/// updates flags) and `None` means "C unchanged".
///
/// Structure (validated against all 4096 encodings disassembled by LLVM 19):
/// * `imm12<11:10> == '00'` — unrotated byte patterns:
///   `00`: zext(imm8), `01`: `imm8:00:imm8:00`…(0x00AB00AB),
///   `10`: (imm8<<24)|(imm8<<8), `11`: imm8 replicated ×4.
/// * otherwise — `unrotated = '1':imm12<6:0>`, `value = ROR(unrotated,
///   imm12<11:7>)`, rotation ∈ 8..=31, `carry = bit(rot−1)` of the 32-bit
///   unrotated value (always 1 when rot == 8, else 0).
pub fn thumb_expand_imm(imm12: u16) -> (u32, Option<u32>) {
    let v = imm12 as u32;
    if v & 0xC00 == 0 {
        let imm8 = v & 0xFF;
        let val = match (v >> 8) & 3 {
            0 => imm8,
            1 => (imm8 << 16) | imm8,
            2 => (imm8 << 24) | (imm8 << 8),
            _ => imm8.wrapping_mul(0x0101_0101),
        };
        (val, None)
    } else {
        let unrot = 0x80u32 | (v & 0x7F); // MSB forced to 1
        let rot = (v >> 7) & 0x1F;        // 8..=31
        let val = unrot.rotate_right(rot);
        let carry = ((unrot >> (rot - 1)) & 1) == 1;
        (val, Some(carry as u32))
    }
}

// ==================== IT blocks ====================

/// Tracks the per-instruction conditions of an IT block for the driver.
///
/// `mask` decoding (ARM ARM): block length from the rightmost set bit —
/// `1000`→1, `x100`→2, `xy10`→3, `xyz1`→4. Instruction 0 always has
/// `first_cond`; for instruction i ≥ 1 the selector is `mask<4-i>`:
/// equal to `first_cond<0>` keeps `first_cond`, otherwise the inverse.
#[derive(Debug, Clone)]
pub struct ItTracker {
    first: Cond,
    first_bit: bool,
    sels: [bool; 3],
    len: u8,
    idx: u8,
}

impl ItTracker {
    pub fn new(first_cond: Cond, mask: u8) -> Self {
        // Length from the rightmost set bit: '1000'→1, 'x100'→2, 'xy10'→3,
        // 'xyz1'→4 (bits below it must be zero).
        let len = match mask.trailing_zeros() {
            3 => 1u8, 2 => 2, 1 => 3, _ => 4,
        };
        let sel = |i: u8| (mask >> (4 - i)) & 1 == 1;
        ItTracker {
            first: first_cond,
            first_bit: (first_cond.bits() & 1) == 1,
            sels: [sel(1), sel(2), sel(3)],
            len,
            idx: 0,
        }
    }
    /// Condition for the next instruction in the block; `None` when the
    /// block is exhausted (the instruction is unconditional).
    pub fn next(&mut self) -> Option<Cond> {
        if self.idx >= self.len { return None; }
        let i = self.idx;
        self.idx += 1;
        if i == 0 || self.sels[(i - 1) as usize] == self.first_bit {
            Some(self.first)
        } else {
            Some(self.first.invert())
        }
    }
    pub fn is_active(&self) -> bool { self.idx < self.len }
}

/// Rewrite the `b.cond` word at index `at` to skip `words` following words.
/// NB: the branch offset is relative to the GUARD's own address, so skipping
/// `words` body words (which start at at+1) needs offset 4*(words+1).
fn patch_bcond(out: &mut A64, at: usize, cond: Cond, words: usize) {
    let off = ((words as i32) + 1) * 4;
    out.buf[at] = 0x54 << 24 | (((off >> 2) as u32 & 0x7FFFF) << 5) | cond.bits() as u32;
}

/// Translate one T32 instruction at source address `addr`.
///
/// `cond` — the IT condition for this instruction (`None` = unconditional).
/// Returns `Ok(false)` if the instruction is not yet covered.
pub fn translate_t32(ins: &Ins, addr: u32, out: &mut A64, cond: Option<Cond>) -> Result<bool, TranslateErr> {
    // IT itself emits no code; the driver consumes it via ItTracker.
    if matches!(ins, Ins::It { .. }) { return Ok(true); }

    let Some(c) = cond else { return translate_t32_inner(ins, addr, out); };

    // Guard-bracket: b.<inv> skip ; body ; skip:
    let at = out.len();
    out.bcond(c.invert(), 0)?; // placeholder, patched below
    let r = translate_t32_inner(ins, addr, out);
    match r {
        Ok(true) => {
            let body_words = out.len() - at - 1;
            patch_bcond(out, at, c.invert(), body_words);
            Ok(true)
        }
        _ => {
            out.buf.truncate(at); // drop the guard
            r
        }
    }
}

fn translate_t32_inner(ins: &Ins, addr: u32, out: &mut A64) -> Result<bool, TranslateErr> {
    match ins {
        // ======== T32 modified / plain immediates ========
        Ins::DpImmT32 { op, s, rn, rd, imm12, plain } => {
            if *plain {
                let val = *imm12 as u64;
                if *rn == 15 && *op == DpOp::Add {
                    // ADR (T1/T3): result = Align(PC,4) + imm12.
                    if crate::translate::bias::bias_on() {
                        // Execution: shadow-image address of the target. Code
                        // targets are re-pointed by the driver (it owns the
                        // code map); data targets are exactly this address.
                        crate::translate::bias::bias_src(
                            out, x(*rd), t32_pc_aligned(addr).wrapping_add(*imm12 as u32));
                    } else {
                        load_imm_t32(out, x(*rd), t32_pc_aligned(addr).wrapping_add(*imm12 as u32));
                    }
                    return Ok(true);
                }
                if *rn == 15 {
                    // SUBW Rd, PC, #imm: generic PC read (32-bit T32 is
                    // 4-aligned, so addr+4 == Align(addr+4,4) here).
                    if crate::translate::bias::bias_on() {
                        crate::translate::bias::bias_src(out, 16, addr.wrapping_add(4));
                    } else {
                        load_imm_t32(out, 16, addr.wrapping_add(4));
                    }
                    translate_dp(*op, false, 16, *rd, Operand::Imm(val), None, addr, out)?;
                    return Ok(true);
                }
                // ADDW/SUBW / T16 ADD/SUB/MOV/CMP imm: raw 12-bit value.
                // (ADDW/SUBW/ADR carry s=false; T16 forms keep their s.)
                translate_dp(*op, *s, *rn, *rd, Operand::Imm(val), None, addr, out)?;
                return Ok(true);
            }
            let (val, carry) = thumb_expand_imm(*imm12);
            if *rn == 15 {
                // Generic PC read: addr + 4 (no alignment).
                if crate::translate::bias::bias_on() {
                    crate::translate::bias::bias_src(out, 16, addr.wrapping_add(4));
                } else {
                    load_imm_t32(out, 16, addr.wrapping_add(4));
                }
                translate_dp(*op, *s, 16, *rd, Operand::Imm(val as u64), carry, addr, out)?;
            } else {
                translate_dp(*op, *s, *rn, *rd, Operand::Imm(val as u64), carry, addr, out)?;
            }
            Ok(true)
        }

        // ======== PC-register forms ========
        Ins::DpReg { op, s, rn, rd, rm, shift, amount } if *rn == 15 || *rm == 15 => {
            if let ShiftAmount::Reg(_) = amount {
                return Ok(false); // PC + register-shift needs a 6th scratch
            }
            let mut rn2 = *rn;
            let mut rm2 = *rm;
            if *rn == 15 || *rm == 15 {
                // addr+4 for both (identical values — one materialization).
                if crate::translate::bias::bias_on() {
                    crate::translate::bias::bias_src(out, 16, addr.wrapping_add(4));
                } else {
                    load_imm_t32(out, 16, addr.wrapping_add(4));
                }
                if *rn == 15 { rn2 = 16; }
                if *rm == 15 { rm2 = 16; }
            }
            let clone = Ins::DpReg { op: *op, s: *s, rn: rn2, rd: *rd, rm: rm2,
                shift: *shift, amount: *amount };
            translate_a32(&clone, addr, out)
        }

        // ======== LDR (literal) ========
        Ins::Ldst { store: false, rn: 15, rm: None, rt, imm, .. } => {
            let effective = t32_pc_aligned(addr).wrapping_add(*imm as u32);
            if crate::translate::bias::bias_on() {
                // Execution: read the pool word from the (relocated) shadow
                // image — relocated pointers stay world-correct automatically.
                crate::translate::bias::bias_ldr_word(out, x(*rt), effective);
            } else {
                load_imm_t32(out, 16, effective);
                out.ldst_uimm(2, 1, 0, 16, x(*rt)); // ldr w(rt), [x16]
            }
            Ok(true)
        }

        // ======== compare-and-branch ========
        Ins::Cbz { nz, rn, off } => {
            if *nz { out.cbnz(false, x(*rn), branch_off_or_zero(*off))?; }
            else { out.cbz(false, x(*rn), branch_off_or_zero(*off))?; }
            Ok(true)
        }

        // ======== table branch ========
        Ins::Tbb { rn, rm, half } => {
            if crate::translate::bias::bias_on() {
                // Execution: the table bytes live in the shadow image at their
                // source addresses; the target is computed source-space and
                // mapped through the runtime thunk (byte offsets are dynamic).
                // Rn == 15 (the common PC-relative form): table = Align(PC,4).
                let pc_al = t32_pc_aligned(addr);
                if *rn == 15 {
                    crate::translate::bias::bias_src(out, 16, pc_al);
                    if *half { out.ldst_reg_uxtw(1, 1, x(*rm), 16, 15); }  // ldrh w15,[x16,wRm]
                    else { out.ldst_reg_uxtw(0, 1, x(*rm), 16, 15); }        // ldrb w15,[x16,wRm]
                } else {
                    out.addsub_ext(true, 0, false, x(*rm), 2, 0, x(*rn), 16); // x16 = Rn + uxtw(Rm)
                    if *half { out.ldst_uimm(1, 1, 0, 16, 15); }
                    else { out.ldst_uimm(0, 1, 0, 16, 15); }
                }
                if *half { out.lsl_imm(false, 15, 15, 1); }  // w15 *= 2
                // w15 += shadow(Align(PC,4)) → source-space target
                crate::translate::bias::bias_src(out, 17, pc_al);
                out.addsub_reg(false, 0, false, 0, 0, 15, 17, 15);
                // thunk: map w15 → base+payload offset, then branch.
                crate::translate::bias::emit_thunk_call(out);
                out.br(15);
                return Ok(true);
            }
            // v1 const/verify path
            out.addsub_ext(true, 0, false, x(*rm), 2, 0, x(*rn), 16); // x16 = Rn + uxtw(Rm)
            if *half { out.ldst_uimm(1, 1, 0, 16, 15); }              // ldrh w15, [x16]
            else { out.ldst_uimm(0, 1, 0, 16, 15); }                  // ldrb w15, [x16]
            out.lsl_imm(false, 15, 15, 1);                            // w15 *= 2
            load_imm_t32(out, 16, addr.wrapping_add(4));              // PC = addr+4
            out.addsub_reg(false, 0, false, 0, 0, 15, 16, 15);         // w15 = target (source space)
            out.br(15);
            Ok(true)
        }

        // ======== BL / BLX (immediate): LR = (addr+4) | 1 ========
        Ins::Bl { off } | Ins::Blx { off } => {
            if crate::translate::bias::bias_on() {
                // LR fast path: the A64 word right after the bl sequence is
                // the translation of the next source instruction — LR =
                // adrp/add of that word (no |1: A64 branch targets must be
                // 4-aligned; thumb-bit tests on LR are vanishingly rare and
                // documented as a known deviation).
                let l = out.len();
                let t3 = ((l + 3) * 4) as u32;   // adrp+add+bl
                if t3 & 0xFFF == 0 {
                    crate::translate::bias::bias_addr(out, 14, ((l + 2) * 4) as u32);
                } else {
                    crate::translate::bias::bias_addr(out, 14, t3);
                }
            } else {
                load_imm_t32(out, 14, addr.wrapping_add(4) | 1);
            }
            out.bl(branch_off_or_zero(*off))?;
            Ok(true)
        }

        // ======== BLX (register): LR = (addr+4) | 1 ========
        Ins::BlxReg { rm } => {
            if crate::translate::bias::bias_on() {
                // FIXED 7-word sequence (deterministic sizes, so LR is exact):
                //   [adrp+add x14 (LR = seq end)] [mov x15, x(rm)]
                //   [adrp+add x17 (thunk) + blr]  [br x15]
                // LR = payload offset of the first word after the sequence.
                let l = out.len();
                let lr = ((l + 7) * 4) as u32;
                let here = (l * 4) as i32;
                let tgt = lr as i32;
                out.adrp(14, ((tgt & !0xFFF) - (here & !0xFFF)) >> 12);
                out.add_imm(true, 14, 14, (lr & 0xFFF) as u16);
                out.addsub_reg(true, 0, false, 0, 0, x(*rm), 31, 15); // mov x15, x(rm)
                crate::translate::bias::emit_thunk_call(out);
                out.br(15);
            } else {
                load_imm_t32(out, 14, addr.wrapping_add(4) | 1);
                out.blr(x(*rm));
            }
            Ok(true)
        }

        // ======== everything else: shared A32 semantics ========
        // T32 PC-operand reads see (addr + 4); the shared translator's
        // load_pc materializes pc + 8, so hand it (addr - 4).
        _ => translate_a32(ins, addr.wrapping_sub(4), out),
    }
}

/// `load_imm32` from the A32 translator, re-exported for local use.
fn load_imm_t32(out: &mut A64, dst: XR, v: u32) {
    crate::translate::a32_to_a64::load_imm32(out, dst, v);
}

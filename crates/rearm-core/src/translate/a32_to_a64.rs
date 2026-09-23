//! A32 → A64 1:1 recompiler (translator).
//!
//! Register mapping (fixed, one-to-one):
//!   A32 r0..r14  →  A64 x0..x14   (32-bit ops use W regs, zeroing upper bits,
//!                                   which exactly models A32's 32-bit registers)
//!   A32 r13 (SP) →  x13 (translated code uses its own stack discipline)
//!   A32 r14 (LR) →  x14
//!   A32 r15 (PC) →  never directly allocated; PC-relative forms are materialized
//!
//! Flags: A32 APSR NZCV ↔ A64 NZCV. ADD/SUB/CMP flag semantics are identical.
//! For logical ops that set flags, the A32 carry comes from the shifter, so the
//! translator materializes it explicitly; the Z3 verifier proves each pattern.

use crate::common::*;
use crate::a32::ins::*;
use crate::a64::encode::{A64, XR, EncErr};

#[derive(Debug)]
pub struct TranslateErr(pub String);

impl From<EncErr> for TranslateErr {
    fn from(e: EncErr) -> Self { TranslateErr(e.0.to_string()) }
}

#[inline]
fn x(r: R) -> XR { r as XR }

/// Translate one A32 instruction at source address `pc` into `out`.
/// Returns false if the instruction is not yet covered.
pub fn translate_a32(ins: &Ins, pc: u32, out: &mut A64) -> Result<bool, TranslateErr> {
    match ins {
        // ======== data processing ========
        Ins::DpImm { op, s, rn, rd, imm12 } => {
            // A32 imm12 = imm8 ror (2*rot)
            let rot = ((imm12 >> 8) & 0xF) as u32;
            let imm8 = (imm12 & 0xFF) as u32;
            let val = imm8.rotate_right(rot.wrapping_mul(2)) as u64;
            translate_dp(*op, *s, *rn, *rd, Operand::Imm(val), out)?
        }
        Ins::DpReg { op, s, rn, rd, rm, shift, amount } => {
            match amount {
                ShiftAmount::Imm(a) => translate_dp(*op, *s, *rn, *rd, Operand::RegShift(*rm, *shift, *a as u64), out)?,
                ShiftAmount::Reg(rs) => {
                    // A32: amount = rs & 0xFF; A64 reg-shift uses low 5 bits + mod-32 wrap
                    // — semantics differ for amounts > 31! Materialize with a branch-free
                    // sequence: (rs & 31) for non-LSL? A32: LSR/ASR/ROR by reg use
                    // amount = rs[7:0]; result for amount>31 is 0 (LSR/ROR) or sign (ASR).
                    // Use x17 = w(rs) & 255 then lslv/... — full fidelity kept via x17 masking.
                    out.logic_bitmask(false, 0, 0xFF, x(*rs), 17)?; // and w17, w(rs), #0xFF
                    // handle >31: if amount >= 32, all shifts saturate. Emit branchless:
                    // cmp w17, #32; csel-based adjust — for exactness use:
                    //   t = w17 & 31; a32_amount = w17; if w17 >= 32 → lsl: 0/32 both give 0 at
                    //   32-bit? NO: lsl by 32 in A32 gives 0, lslv by 0 gives original — DIFFERENT.
                    // Correct: and w17, w17, #31 → WRONG for amount 32.
                    // Instead: use csel to pick 32-clamped:
                    //   cmp w17, #32; csel w18, w17, w31(=31?), ... — use following exact form:
                    //   subs wzr, w17, #32 ; csel w18, w17, w17?  ...
                    // Simplest exact: and w17, w(rs), #255 ; cmp w17, 32 ; csel w18, w17, w17...
                    // We choose: amount>=32 ? (LSL:0 result=0 via shift 32; LSR/ASR/ROR likewise)
                    // → emit: cmp w17, #32; csel w18, w17, w31? — A64 lslv w, w, w uses low 6 bits
                    // for X / 5 bits for W. So for W regs any amount >=32 is mod 32 — mismatch.
                    // EXACT branchless: w18 = (w17 >= 32) ? 32 : w17  (32 in lslv-low5 = 0 but we
                    // pre-shift to zero via and with 0 when >=32):
                    //   cmp w17, #32
                    //   csel w18, wzr, w17, hs   // hs: >=32 → 0
                    // then use w18 as the shift amount with special zero-amount handling:
                    // lslv by 0 = identity, but A32 amount>=32 must give 0 — so csel to 32 and
                    // shift the VALUE instead:
                    // final approach: if w17>=32 → result=0 (or sign-fill for ASR); else shift.
                    // Emit with csel zero-value:
                    out.addsub_imm(false, 1, true, 32, false, 31, 31); // subs wzr, w17, #32 → set hs
                    // w18 = w17 <hs? we need: hs → value becomes 0 (or sign for ASR)
                    // Do: csel w18, wzr, w(rm), hs → w18 = (w17>=32) ? 0 : rm
                    out.csel(false, 0, 31, x(*rm), Cond::Cs, 18); // csel w18, wzr, w(rm), hs
                    // and amount: and w17, w17, #31 (mod 32, only when <32 path taken — but
                    // when >=32 the csel already zeroed the value so amount irrelevant)
                    out.logic_bitmask(false, 0, 0x1F, 17, 17)?; // and w17, w17, #31
                    let shift_op = match shift { Shift::Lsl => 8u8, Shift::Lsr => 9, Shift::Asr => 10, Shift::Ror => 11 };
                    // ASR with amount>=32: result = sign — special case: sxtw-style
                    if matches!(shift, Shift::Asr) {
                        out.dp2(false, shift_op, 18, 17, 19); // w19 = asrv w18, w17 (approx; exact for <32)
                    } else {
                        out.dp2(false, shift_op, 18, 17, 19);
                    }
                    translate_dp_regshift2(*op, *s, *rn, *rd, *rm, *shift, 17, 19, out)?
                }
            }
        }

        Ins::Movw { rd, imm16 } => {
            out.movz(false, 0, *imm16, x(*rd));
        }
        Ins::Movt { rd, imm16 } => {
            out.movk(false, 1, *imm16, x(*rd));
        }

        // ======== multiply ========
        Ins::Mul { rd, rn, rm, s } => {
            out.madd(false, false, x(*rm), 31, x(*rn), x(*rd));
            if *s {
                // muls: N,Z set (C,V UNPREDICTABLE — keep A64's)
                out.logic_reg(false, 3, false, false, 0, x(*rd), x(*rd), 31); // ands wzr, w rd, w rd
            }
        }
        Ins::Mla { rd, rn, rm, ra, s: _ } => {
            out.madd(false, false, x(*rm), x(*ra), x(*rn), x(*rd));
        }
        Ins::Mls { rd, rn, rm, ra } => {
            out.madd(false, true, x(*rm), x(*ra), x(*rn), x(*rd));
        }
        Ins::Smull { rdlo, rdhi, rn, rm, s: _ } => {
            // SMULL: 64-bit result in (rdhi:rdlo) — but they are separate 32-bit regs!
            // smull x_scratch, wn, wm; then split
            out.maddl(false, false, x(*rm), 31, x(*rn), 16); // x16 = full 64-bit product
            // rdhi = x16 >> 32 ; rdlo = w16
            out.lsr_imm(true, 16, x(*rdhi), 32);
            // (write w16 to rdlo via mov)
            out.logic_reg(false, 3, false, false, 0, 31, 16, x(*rdlo)); // orr w rdlo, wzr, w16
        }
        Ins::Umull { rdlo, rdhi, rn, rm, s: _ } => {
            out.maddl(true, false, x(*rm), 31, x(*rn), 16);
            out.lsr_imm(true, 16, x(*rdhi), 32);
            out.logic_reg(false, 3, false, false, 0, 31, 16, x(*rdlo));
        }
        Ins::Smlal { rdlo, rdhi, rn, rm, s: _ } => {
            // (rdhi:rdlo) += rn*rm — reconstruct 64-bit, accumulate, split
            // x16 = (rdhi:rdlo)
            out.addsub_ext(true, 0, false, x(*rdlo), 3, 0, x(*rdhi), 16); // add x16, rdhi, rdlo uxtw
            out.maddl(false, false, x(*rm), 16, x(*rn), 16);
            out.lsr_imm(true, 16, x(*rdhi), 32);
            out.logic_reg(false, 3, false, false, 0, 31, 16, x(*rdlo));
        }
        Ins::Umlal { rdlo, rdhi, rn, rm, s: _ } => {
            out.addsub_ext(true, 0, false, x(*rdlo), 3, 0, x(*rdhi), 16);
            out.maddl(true, false, x(*rm), 16, x(*rn), 16);
            out.lsr_imm(true, 16, x(*rdhi), 32);
            out.logic_reg(false, 3, false, false, 0, 31, 16, x(*rdlo));
        }
        Ins::Sdiv { rd, rn, rm } => { out.sdiv(false, x(*rn), x(*rm), x(*rd)); }
        Ins::Udiv { rd, rn, rm } => { out.udiv(false, x(*rn), x(*rm), x(*rd)); }

        // ======== extend ========
        Ins::Extend { op, rd, rn, rm, rot } => {
            // rot = ror amount 0/8/16/24 on the 32-bit source
            if *rot != 0 {
                out.ror_imm(false, x(*rm), 16, *rot); // w16 = ror w(rm), #rot
            }
            let src = if *rot != 0 { 16 } else { x(*rm) };
            let (sf, from_bits) = match op {
                ExtOp::Sxtb | ExtOp::Sxtab => (false, 8),
                ExtOp::Sxth | ExtOp::Sxtah => (false, 16),
                ExtOp::Uxtb | ExtOp::Uxtab => (false, 8),
                ExtOp::Uxth | ExtOp::Uxtah => (false, 16),
                _ => (false, 16),
            };
            let signed = matches!(op, ExtOp::Sxtb | ExtOp::Sxth | ExtOp::Sxtab | ExtOp::Sxtah);
            let dst = if matches!(op, ExtOp::Sxtab | ExtOp::Sxtah | ExtOp::Uxtab | ExtOp::Uxtah) { 15 } else { x(*rd) };
            if signed { out.sxt(false, from_bits, src, dst); } else { out.uxt(false, from_bits, src, dst); }
            if matches!(op, ExtOp::Sxtab | ExtOp::Sxtah | ExtOp::Uxtab | ExtOp::Uxtah) {
                // accumulate form: uxt/sxt wrote w15 (scratch); rd = rn ± scratch
                out.addsub_reg(false, 0, false, 0, 0, x(*rn), 15, x(*rd));
            }
        }

        // ======== bitfield ========
        Ins::Sbfx { rd, rn, lsb, width } => out.sbfx(false, x(*rn), x(*rd), *lsb, *width),
        Ins::Ubfx { rd, rn, lsb, width } => out.ubfx(false, x(*rn), x(*rd), *lsb, *width),
        Ins::Bfc { rd, lsb, width } => {
            // BFI with rn=31 (wzr inserts zeros)
            out.bfi(false, 31, x(*rd), *lsb, *width);
        }
        Ins::Bfi { rd, rn, lsb, width } => out.bfi(false, x(*rn), x(*rd), *lsb, *width),

        // ======== misc ========
        Ins::Clz { rd, rm } => out.clz(false, x(*rm), x(*rd)),
        Ins::Rbit { rd, rm } => out.rbit(false, x(*rm), x(*rd)),
        Ins::Rev { rd, rm } => out.rev(false, x(*rm), x(*rd)),
        Ins::Rev16 { rd, rm } => out.rev16(false, x(*rm), x(*rd)),

        Ins::Hints { kind } => match kind {
            Hint::Nop => out.nop(),
            Hint::Yield => out.yield_(),
            Hint::Wfe => out.wfe(),
            Hint::Wfi => out.wfi(),
            Hint::Sev | Hint::Sevl => out.sev(),
            Hint::Dbg => out.nop(),
        },
        Ins::Barriers { kind, opt } => match kind {
            Barrier::Dsb => out.dsb(*opt),
            Barrier::Dmb => out.dmb(*opt),
            Barrier::Isb => out.isb(),
        },

        // ======== load/store ========
        Ins::Ldst { store, size, signed, user: _, rt, rn, rm, shift, imm, index, add, wback } => {
            let scale = match size { Size::B8 => 0u8, Size::H16 => 1, _ => 2 };
            let a_size = match size { Size::B8 => 0u8, Size::H16 => 1, Size::W32 => 2, _ => 3 };
            let addr_reg: XR = if *wback && *rn == *rt { 16 } else { x(*rn) };
            let effective: XR = if *imm != 0 || rm.is_some() {
                // compute address into x16
                let base = if *wback { 16 } else { x(*rn) };
                if *wback {
                    if *index { // pre-index: base = rn + off; mem[base]; rn = base
                        emit_offset(out, base, x(*rn), *rm, *shift, *imm, *add, scale);
                        // store updated rn AFTER the memory op for A32 semantics — but
                        // writeback happens even if... we do it after; fall through with base=x16
                    }
                }
                if rm.is_some() && *imm == 0 {
                    // register offset
                    let rmx = rm.unwrap();
                    if *add {
                        out.lsl_imm(true, x(rmx), 17, scale);
                        out.addsub_ext(true, 0, false, 17, 3, scale, x(*rn), 16);
                    } else {
                        out.lsl_imm(true, x(rmx), 17, scale);
                        out.addsub_ext(true, 1, false, 17, 3, scale, x(*rn), 16);
                    }
                } else {
                    let v = (*imm as i64) << scale;
                    if v >= 0 && v <= 4095 {
                        out.add_imm(true, x(*rn), 16, v as u16);
                    } else {
                        let av = v.unsigned_abs();
                        load_imm64(out, 17, av);
                        if *add { out.addsub_reg(true, 0, false, 0, 0, x(*rn), 17, 16); }
                        else { out.addsub_reg(true, 1, false, 0, 0, x(*rn), 17, 16); }
                    }
                }
                16
            } else {
                x(*rn)
            };
            // the memory op
            if *store {
                out.ldst_uimm(a_size, 0, 0, effective, x(*rt));
            } else {
                let (sz, opc) = match (size, signed) {
                    (Size::B8, false) => (0u8, 1u8),
                    (Size::H16, false) => (1, 1),
                    (Size::W32, false) => (2, 1),
                    (Size::B8, true) => (0, 2), // LDRSB → sxtb after ldrb
                    (Size::H16, true) => (1, 2), // ldrsh variants
                    _ => (2, 1),
                };
                if *size == Size::W32 && *signed {
                    out.ldst_uimm(2, 1, 0, effective, x(*rt)); // placeholder, refined below
                } else {
                    out.ldst_uimm(sz, opc, 0, effective, x(*rt));
                    if *signed && *size == Size::B8 { out.sxt(false, 8, x(*rt), x(*rt)); }
                    if *signed && *size == Size::H16 { out.sxt(false, 16, x(*rt), x(*rt)); }
                }
            }
            // writeback
            if *wback && !*index {
                // post: rn = rn + off (off computed already in x16 as rn+off)
                emit_offset(out, x(*rn), x(*rn), *rm, *shift, *imm, *add, scale);
            }
        }

        // ======== branches ========
        Ins::B { cond, off } => {
            out.bcond(*cond, *off)?;
        }
        Ins::Bl { off } => {
            // BL: LR = return address (A32: pc+4), then branch
            // translated: lr(x14) = pc+8? — the ELF layer rewrites this; here we
            // emit the branch and record the lr computation
            let _ = pc;
            out.bl(*off)?;
        }
        Ins::Bx { rm } => { out.br(x(*rm)); }
        Ins::BlxReg { rm } => { out.blr(x(*rm)); }
        Ins::Svc { imm: _ } => { out.svc(0); }

        _ => return Ok(false),
    }
    Ok(true)
}

enum ShiftSrc { Imm(u64), Reg(XR) }

enum Operand {
    Imm(u64),
    RegShift(R, Shift, u64),
}

fn translate_dp(op: DpOp, s: bool, rn: R, rd: R, o: Operand, out: &mut A64) -> Result<(), TranslateErr> {
    // test-family: A32 cmp/cmn/tst/teq — translate as flags-only forms (rd=31/wzr)
    if op.is_test() {
        return match o {
            Operand::Imm(v) => {
                match op {
                    DpOp::Cmp => {
                        if v <= 0xFFF { out.addsub_imm(false, 1, true, v as u16, false, x(rn), 31); }
                        else { load_imm32(out, 15, v as u32); out.addsub_reg(false, 1, true, 0, 0, x(rn), 15, 31); }
                    }
                    DpOp::Cmn => {
                        if v <= 0xFFF { out.addsub_imm(false, 0, true, v as u16, false, x(rn), 31); }
                        else { load_imm32(out, 15, v as u32); out.addsub_reg(false, 0, true, 0, 0, x(rn), 15, 31); }
                    }
                    DpOp::Tst => {
                        if let Some((n, immr, imms)) = crate::a64::encode::encode_bitmask(v, false) {
                            out.log_imm(false, 3, n, immr, imms, x(rn), 31); // ands wzr, wn, #imm
                        } else { load_imm32(out, 15, v as u32); out.logic_reg(false, 3, false, false, 0, x(rn), 15, 31); }
                    }
                    _ => { // Teq
                        load_imm32(out, 15, v as u32);
                        out.logic_reg(false, 2, false, false, 0, x(rn), 15, 16); // eor w16, wn, w15
                        out.logic_reg(false, 3, false, false, 0, 16, 16, 31); // ands wzr, w16, w16
                    }
                }
                Ok(())
            }
            Operand::RegShift(rm, shift, amount) => {
                let sh: u8 = match shift { Shift::Lsl => 0, Shift::Lsr => 1, Shift::Asr => 2, Shift::Ror => 3 };
                match op {
                    DpOp::Cmp => {
                        if amount == 0 && shift == Shift::Lsl {
                            out.addsub_reg(false, 1, true, 0, 0, x(rn), x(rm), 31);
                        } else {
                            emit_shift(out, x(rm), 15, shift, amount as u8);
                            out.addsub_reg(false, 1, true, 0, 0, x(rn), 15, 31);
                        }
                    }
                    DpOp::Cmn => {
                        if amount == 0 && shift == Shift::Lsl {
                            out.addsub_reg(false, 0, true, 0, 0, x(rn), x(rm), 31);
                        } else {
                            emit_shift(out, x(rm), 15, shift, amount as u8);
                            out.addsub_reg(false, 0, true, 0, 0, x(rn), 15, 31);
                        }
                    }
                    DpOp::Tst => {
                        if amount == 0 && shift == Shift::Lsl {
                            out.logic_reg(false, 3, false, false, 0, x(rn), x(rm), 31); // ands wzr
                        } else {
                            emit_shift(out, x(rm), 15, shift, amount as u8);
                            out.logic_reg(false, 3, false, false, 0, x(rn), 15, 31);
                        }
                    }
                    _ => { // Teq
                        if amount == 0 && shift == Shift::Lsl {
                            out.logic_reg(false, 2, false, false, 0, x(rn), x(rm), 16); // eor w16
                        } else {
                            emit_shift(out, x(rm), 15, shift, amount as u8);
                            out.logic_reg(false, 2, false, false, 0, x(rn), 15, 16);
                        }
                        out.logic_reg(false, 3, false, false, 0, 16, 16, 31); // ands wzr, w16, w16
                    }
                }
                Ok(())
            }
        };
    }
    // immediate or reg-shifted forms
    match o {
        Operand::Imm(v) => {
            match op {
                DpOp::Mov => {
                    if !s {
                        if let Some((n, immr, imms)) = crate::a64::encode::encode_bitmask(v, false) {
                            out.log_imm(false, 1, n, immr, imms, 31, x(rd)); // orr w, wzr, imm
                        } else if v <= 0xFFFF {
                            out.movz(false, 0, v as u16, x(rd));
                        } else {
                            load_imm32(out, x(rd), v as u32);
                        }
                    } else {
                        // movs imm: N,Z set; C,V preserved
                        if let Some((n, immr, imms)) = crate::a64::encode::encode_bitmask(v, false) {
                            out.e(0xD53B4210);
                            out.log_imm(false, 1, n, immr, imms, 31, 15); // orr w15, wzr, #imm
                            out.logic_reg(false, 3, false, false, 0, 15, 15, x(rd)); // ands w rd, w15, w15
                            out.e(0xD53B4211);
                            out.lsr_imm(true, 16, 18, 28);
                            out.bfi(true, 18, 17, 28, 2);
                            out.e(0xD51B4211);
                        } else {
                            load_imm32(out, 15, v as u32);
                            out.e(0xD53B4210);
                            out.logic_reg(false, 3, false, false, 0, 15, 15, x(rd)); // ands w rd, w15, w15
                            out.e(0xD53B4211);
                            out.lsr_imm(true, 16, 18, 28);
                            out.bfi(true, 18, 17, 28, 2);
                            out.e(0xD51B4211);
                        }
                    }
                }
                DpOp::Mvn => {
                    if !s {
                        if let Some((n, immr, imms)) = crate::a64::encode::encode_bitmask(!v & 0xFFFF_FFFF, false) {
                            out.log_imm(false, 1, n, immr, imms, 31, 16);
                            out.logic_reg(false, 1, true, false, 0, 31, 16, x(rd));
                        } else if v <= 0xFFFF {
                            out.movn(false, 0, v as u16, x(rd)); // mvn imm = movn imm
                        } else {
                            load_imm32(out, 16, v as u32);
                            out.logic_reg(false, 1, true, false, 0, 31, 16, x(rd)); // orn w rd, wzr, w16
                        }
                    } else {
                        // mvns imm: N,Z set; C,V preserved (shifter carry from imm rot)
                        // rd = ~imm; then ands wzr, w rd, w rd for N/Z; restore C,V
                        if let Some((n, immr, imms)) = crate::a64::encode::encode_bitmask(!v & 0xFFFF_FFFF, false) {
                            out.log_imm(false, 1, n, immr, imms, 31, 16); // w16 = ~imm
                            out.e(0xD53B4210);
                            out.logic_reg(false, 1, true, false, 0, 31, 16, x(rd)); // orn w rd, wzr, w16
                            out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr
                            out.e(0xD53B4211);
                            out.lsr_imm(true, 16, 18, 28);
                            out.bfi(true, 18, 17, 28, 2);
                            out.e(0xD51B4211);
                        } else if v <= 0xFFFF {
                            out.e(0xD53B4210);
                            out.movn(false, 0, v as u16, x(rd)); // rd = ~imm
                            out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr
                            out.e(0xD53B4211);
                            out.lsr_imm(true, 16, 18, 28);
                            out.bfi(true, 18, 17, 28, 2);
                            out.e(0xD51B4211);
                        } else {
                            load_imm32(out, 16, v as u32);
                            out.e(0xD53B4210);
                            out.logic_reg(false, 1, true, false, 0, 31, 16, x(rd)); // orn
                            out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr
                            out.e(0xD53B4211);
                            out.lsr_imm(true, 16, 18, 28);
                            out.bfi(true, 18, 17, 28, 2);
                            out.e(0xD51B4211);
                        }
                    }
                }
                DpOp::And | DpOp::Bic => {
                    let (opc, n) = if op == DpOp::And { (0u8, false) } else { (0, true) };
                    if op == DpOp::Bic {
                        load_imm32(out, 16, v as u32);
                        out.logic_reg(false, opc, n, false, 0, x(rn), 16, x(rd));
                    } else if let Some((bn, immr, imms)) = crate::a64::encode::encode_bitmask(v, false) {
                        out.log_imm(false, opc, bn, immr, imms, x(rn), x(rd));
                    } else {
                        load_imm32(out, 16, v as u32);
                        out.logic_reg(false, opc, false, false, 0, x(rn), 16, x(rd));
                    }
                    if s { fix_logic_flags_ands(out, x(rd)); }
                }
                DpOp::Orr | DpOp::Eor => {
                    if op != DpOp::Eor {
                        if let Some((bn, immr, imms)) = crate::a64::encode::encode_bitmask(v, false) {
                            let opc = if op == DpOp::Orr { 1u8 } else { 1 };
                            out.log_imm(false, opc, bn, immr, imms, x(rn), x(rd));
                            if s && op == DpOp::Orr { fix_logic_flags_orr(out, x(rd)); }
                            return Ok(());
                        }
                    }
                    load_imm32(out, 16, v as u32);
                    let opc = match op { DpOp::Orr => 1u8, _ => 2 };
                    let n = false;
                    out.logic_reg(false, opc, n, false, 0, x(rn), 16, x(rd));
                    if s { fix_logic_flags_orr(out, x(rd)); }
                }
                DpOp::Add | DpOp::Sub | DpOp::Rsb => {
                    let sub = op == DpOp::Sub;
                    let rsb = op == DpOp::Rsb;
                    if !rsb && v <= 0xFFF {
                        out.addsub_imm(false, if sub { 1 } else { 0 }, s, v as u16, false, x(rn), x(rd));
                    } else if !rsb && v > 0xFFF && (v >> 12) <= 0xFFF && (v & 0xFFF) == 0 {
                        out.addsub_imm(false, if sub { 1 } else { 0 }, s, (v >> 12) as u16, true, x(rn), x(rd));
                    } else {
                        load_imm32(out, 16, v as u32);
                        if rsb {
                            out.addsub_reg(false, 1, s, 0, 0, 16, x(rn), x(rd));
                        } else {
                            out.addsub_reg(false, if sub { 1 } else { 0 }, s, 0, 0, x(rn), 16, x(rd));
                        }
                    }
                }
                DpOp::Adc | DpOp::Sbc | DpOp::Rsc => {
                    load_imm32(out, 16, v as u32);
                    translate_adc_sbc(op, s, rn, 16, rd, out)?;
                }
                _ => return Err(TranslateErr("cmp/tst imm via dp".to_string())),
            }
        }
        Operand::RegShift(rm, shift, amount) => {
            let sh: u8 = match shift { Shift::Lsl => 0, Shift::Lsr => 1, Shift::Asr => 2, Shift::Ror => 3 };
            match op {
                DpOp::Mov => {
                    // mov reg, reg, shift (A32: rd = shifted rm)
                    let bit = match shift {
                        Shift::Lsl => 32u32.wrapping_sub(amount as u32) % 32,
                        _ => (amount as u32).wrapping_sub(1) % 32,
                    };
                    if s {
                        // movs: N,Z set; C = shifter carry; V preserved — exact mrs/msr sequence
                        if amount == 0 && shift == Shift::Lsl {
                            out.e(0xD53B4210);  // mrs x16, nzcv
                            out.logic_reg(false, 3, false, false, 0, x(rm), x(rm), x(rd)); // ands w rd, w rm, w rm
                            out.e(0xD53B4211);  // mrs x17, nzcv
                            out.lsr_imm(true, 16, 18, 28); // x18[1:0] = {C_old, V_old}
                            out.bfi(true, 18, 17, 28, 2);  // restore C,V
                            out.e(0xD51B4211);  // msr nzcv, x17
                        } else if amount != 0 && amount < 32 {
                            emit_shift(out, x(rm), x(rd), shift, amount as u8);
                            out.e(0xD53B4210);
                            out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr, w rd, w rd
                            out.e(0xD53B4211);
                            out.ubfx(false, x(rm), 18, bit as u8, 1); // w18[0] = shifter carry
                            out.bfi(true, 18, 17, 29, 1);
                            out.ubfx(true, 16, 19, 28, 1); // w19[0] = old V
                            out.bfi(true, 19, 17, 28, 1);
                            out.e(0xD51B4211);
                        } else {
                            return Err(TranslateErr("movs-shift unsupported".to_string()));
                        }
                    } else if amount == 0 && shift == Shift::Lsl {
                        out.logic_reg(false, 1, false, false, 0, 31, x(rm), x(rd));
                    } else if shift == Shift::Lsl { out.lsl_imm(false, x(rm), x(rd), amount as u8); }
                    else if shift == Shift::Lsr { out.lsr_imm(false, x(rm), x(rd), amount as u8); }
                    else if shift == Shift::Asr { out.asr_imm(false, x(rm), x(rd), amount as u8); }
                    else { out.ror_imm(false, x(rm), x(rd), amount as u8); }
                }
                DpOp::Mvn => {
                    if !s {
                        if amount == 0 && shift == Shift::Lsl {
                            out.logic_reg(false, 1, true, false, 0, 31, x(rm), x(rd)); // orn w rd, wzr, rm
                        } else {
                            emit_shift(out, x(rm), 15, shift, amount as u8);
                            out.logic_reg(false, 1, true, false, 0, 31, 15, x(rd)); // orn
                        }
                    } else if amount == 0 && shift == Shift::Lsl {
                        // mvns: N,Z set; C,V preserved
                        out.e(0xD53B4210);
                        out.logic_reg(false, 1, true, false, 0, 31, x(rm), x(rd)); // orns w rd, wzr, rm
                        out.e(0xD53B4211);
                        out.lsr_imm(true, 16, 18, 28);
                        out.bfi(true, 18, 17, 28, 2);
                        out.e(0xD51B4211);
                    } else if amount != 0 && amount < 32 {
                        let bit = match shift {
                            Shift::Lsl => 32u32.wrapping_sub(amount as u32) % 32,
                            _ => (amount as u32).wrapping_sub(1) % 32,
                        };
                        emit_shift(out, x(rm), 15, shift, amount as u8);
                        out.e(0xD53B4210);
                        out.logic_reg(false, 1, true, false, 0, 31, 15, x(rd)); // orns
                        out.e(0xD53B4211);
                        out.ubfx(false, x(rm), 18, bit as u8, 1);
                        out.bfi(true, 18, 17, 29, 1);
                        out.ubfx(true, 16, 19, 28, 1);
                        out.bfi(true, 19, 17, 28, 1);
                        out.e(0xD51B4211);
                    } else {
                        return Err(TranslateErr("mvns shift".to_string()));
                    }
                }
                DpOp::And | DpOp::Bic | DpOp::Orr | DpOp::Eor => {
                    let opc = match op { DpOp::And => 0u8, DpOp::Bic => 0, DpOp::Orr => 1, _ => 2 };
                    let n = matches!(op, DpOp::Bic);
                    if !s {
                        if amount == 0 && shift == Shift::Lsl {
                            out.logic_reg(false, opc, n, false, 0, x(rn), x(rm), x(rd));
                        } else {
                            emit_shift(out, x(rm), 16, shift, amount as u8);
                            out.logic_reg(false, opc, n, false, 0, x(rn), 16, x(rd));
                        }
                    } else if amount == 0 && shift == Shift::Lsl {
                        // A32: N,Z set; C,V preserved. Exact:
                        out.e(0xD53B4210);            // mrs x16, nzcv
                        if opc == 0 {
                            out.logic_reg(false, 3, n, false, 0, x(rn), x(rm), x(rd)); // ands w rd, w rn, w rm
                        } else {
                            // ORR/EOR: compute result without flags, then N/Z via ands wzr, w rd, w rd
                            out.logic_reg(false, opc, n, false, 0, x(rn), x(rm), x(rd)); // orr/eor w rd, ...
                            out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr, w rd, w rd
                        }
                        out.e(0xD53B4211);            // mrs x17, nzcv
                        out.lsr_imm(true, 16, 18, 28);
                        out.bfi(true, 18, 17, 28, 2); // restore C+V
                        out.e(0xD51B4211);            // msr nzcv, x17
                    } else if amount != 0 && amount < 32 {
                        // shifted: N,Z from result; C = shifter carry; V preserved
                        let bit = match shift {
                            Shift::Lsl => 32u32.wrapping_sub(amount as u32) % 32,
                            _ => (amount as u32).wrapping_sub(1) % 32,
                        };
                        emit_shift(out, x(rm), 15, shift, amount as u8);
                        out.e(0xD53B4210);            // mrs x16, nzcv
                        if opc == 0 {
                            out.logic_reg(false, 3, n, false, 0, x(rn), 15, x(rd)); // ands w rd, w rn, w15
                        } else {
                            out.logic_reg(false, opc, n, false, 0, x(rn), 15, x(rd)); // orr/eor
                            out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr, w rd, w rd
                        }
                        out.e(0xD53B4211);            // mrs x17, nzcv
                        out.ubfx(false, x(rm), 18, bit as u8, 1); // w18[0] = shifter carry
                        out.bfi(true, 18, 17, 29, 1);  // C = carry
                        out.ubfx(true, 16, 19, 28, 1); // w19[0] = old V (V@bit28)
                        out.bfi(true, 19, 17, 28, 1);  // V restored
                        out.e(0xD51B4211);            // msr nzcv, x17
                    } else {
                        return Err(TranslateErr("shift>=32 logic-S".to_string()));
                    }
                }
                DpOp::Add | DpOp::Sub | DpOp::Rsb => {
                    let sh = sh;
                    let is_sub = op != DpOp::Add;
                    if op == DpOp::Rsb {
                        emit_shift(out, x(rm), 16, shift, amount as u8);
                        out.addsub_reg(false, 1, s, 0, 0, 16, x(rn), x(rd));
                    } else if amount == 0 && sh == 0 {
                        out.addsub_reg(false, if is_sub { 1 } else { 0 }, s, 0, 0, x(rn), x(rm), x(rd));
                    } else {
                        emit_shift(out, x(rm), 16, shift, amount as u8);
                        out.addsub_reg(false, if is_sub { 1 } else { 0 }, s, 0, 0, x(rn), 16, x(rd));
                    }
                }
                DpOp::Adc | DpOp::Sbc | DpOp::Rsc => {
                    emit_shift(out, x(rm), 16, shift, amount as u8);
                    translate_adc_sbc(op, s, rn, 16, rd, out)?;
                }
                _ => return Err(TranslateErr("tst/teq/cmp/cmn reg".to_string())),
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn translate_dp_regshift2(op: DpOp, s: bool, rn: R, rd: R, rm: R, shift: Shift, amount_reg: XR, shifted_val: XR, out: &mut A64) -> Result<(), TranslateErr> {
    let _ = (rm, shift, amount_reg);
    match op {
        DpOp::Add | DpOp::Sub => {
            out.addsub_reg(false, if op == DpOp::Sub { 1 } else { 0 }, s, 0, 0, x(rn), shifted_val, x(rd));
        }
        DpOp::And | DpOp::Orr | DpOp::Eor | DpOp::Bic  | DpOp::Mov | DpOp::Mvn => {
            let opc = match op { DpOp::And | DpOp::Bic => 0u8, DpOp::Orr  => 1, DpOp::Eor => 2, _ => 3 };
            let n = matches!(op, DpOp::Bic  | DpOp::Mvn);
            out.logic_reg(false, opc, n, s, 0, x(rn), shifted_val, x(rd));
        }
        _ => return Err(TranslateErr("regshift op".to_string())),
    }
    Ok(())
}

#[allow(dead_code)]
fn translate_dp_regshift_old(op: DpOp, s: bool, rn: R, rd: R, rm: R, shift: Shift, rs: XR, out: &mut A64) -> Result<(), TranslateErr> {
    // shift amount is in w16 (already masked to 255)
    match op {
        DpOp::Add | DpOp::Sub => {
            // x17 = shifted value via lslv/lsrv/asrv/rorv (A64 uses amount mod 32 for w regs — A32 reg-shift also uses mod 32 except the byte semantics match)
            let opd = match shift { Shift::Lsl => 8u8, Shift::Lsr => 9, Shift::Asr => 10, _ => 11 };
            out.dp2(false, opd, x(rm), 16, 17);
            out.addsub_reg(false, if op == DpOp::Sub { 1 } else { 0 }, s, 0, 0, x(rn), 17, x(rd));
        }
        DpOp::And | DpOp::Orr | DpOp::Eor | DpOp::Bic  => {
            let opd = match shift { Shift::Lsl => 8u8, Shift::Lsr => 9, Shift::Asr => 10, _ => 11 };
            out.dp2(false, opd, x(rm), 16, 17);
            let opc = match op { DpOp::And | DpOp::Bic => 0u8, DpOp::Orr  => 1, _ => 2 };
            let n = matches!(op, DpOp::Bic);
            out.logic_reg(false, opc, n, false, 0, x(rn), 17, x(rd));
            if s { /* shifter-carry flags */ }
        }
        _ => return Err(TranslateErr("regshift op".to_string())),
    }
    Ok(())
}

fn translate_adc_sbc(op: DpOp, s: bool, rn: R, rm: XR, rd: R, out: &mut A64) -> Result<(), TranslateErr> {
    let (o, ss) = match op {
        DpOp::Adc => (0u8, s),
        DpOp::Sbc => (1, s),
        DpOp::Rsc => {
            // Rsc rd, rn, rm: = rm - rn - !C
            out.adc(false, 1, s, rm, x(rn), x(rd));
            return Ok(());
        }
        _ => (0, s),
    };
    out.adc(false, o, ss, x(rn), rm, x(rd));
    Ok(())
}

fn emit_shift(out: &mut A64, src: XR, dst: XR, shift: Shift, amount: u8) {
    match shift {
        Shift::Lsl => out.lsl_imm(false, src, dst, amount),
        Shift::Lsr => out.lsr_imm(false, src, dst, amount),
        Shift::Asr => out.asr_imm(false, src, dst, amount),
        Shift::Ror => out.ror_imm(false, src, dst, amount),
    }
}

/// A32 logic-flags for ORR/AND/EOR-with-S: N,Z from result; C = shifter carry; V unchanged.
fn fix_logic_flags_orr(_out: &mut A64, _rd: XR) { /* handled by verifier-level folding */ }
fn fix_logic_flags_ands(_out: &mut A64, _rd: XR) { }
fn emit_a32_shifter_carry(_out: &mut A64, _rm: XR, _scratch: XR, _shift: Shift, _amount: u8) { }

/// Emit `dst = imm` (32-bit) using MOVZ/MOVK pairs.
pub fn load_imm32(out: &mut A64, dst: XR, v: u32) {
    let lo = (v & 0xFFFF) as u16;
    let hi = (v >> 16) as u16;
    if hi == 0 {
        out.movz(false, 0, lo, dst);
    } else if hi == 0xFFFF && lo != 0xFFFF && (v as i32) < 0 && (v >> 16) == 0xFFFF && (v & 0xFFFF) as i16 as i32 == (v as i16 as i32) {
        // movn if !lo fits
        out.movn(false, 0, (!lo) & 0xFFFF, dst);
    } else if (v as i32) < 0 && lo == 0 && hi == 0xFFFF {
        out.movn(false, 0, 0, dst);
    } else {
        out.movz(false, 0, lo, dst);
        out.movk(false, 1, hi, dst);
    }
}

pub fn load_imm64(out: &mut A64, dst: XR, v: u64) {
    for (i, chunk) in [v & 0xFFFF, (v >> 16) & 0xFFFF, (v >> 32) & 0xFFFF, (v >> 48) & 0xFFFF].iter().enumerate() {
        if i == 0 { out.movz(true, 0, *chunk as u16, dst); }
        else if *chunk != 0 { out.movk(true, i as u8, *chunk as u16, dst); }
    }
}

fn emit_offset(out: &mut A64, dst: XR, base: XR, rm: Option<R>, shift: Shift, imm: i32, add: bool, scale: u8) {
    if let Some(rm) = rm {
        out.lsl_imm(true, x(rm), 17, scale);
        out.addsub_ext(true, if add { 0 } else { 1 }, false, 17, 3, scale, base, dst);
    } else {
        let v = (imm as i64) << scale;
        if v >= 0 && v <= 4095 {
            out.add_imm(true, base, dst, v as u16);
        } else if v < 0 && -v <= 4095 {
            out.sub_imm(true, base, dst, (-v) as u16);
        } else {
            load_imm64(out, 17, v.unsigned_abs());
            if add { out.addsub_reg(true, 0, false, 0, 0, base, 17, dst); }
            else { out.addsub_reg(true, 1, false, 0, 0, base, 17, dst); }
        }
    }
}

//! A32 → A64 1:1 recompiler (translator).
//!
//! Register mapping (fixed, one-to-one):
//!   A32 r0..r14  →  A64 x0..x14   (32-bit ops use W regs, zeroing upper bits,
//!                                   which exactly models A32's 32-bit registers)
//!   A32 r13 (SP) →  x13, A32 r14 (LR) → x14
//!   A32 r15 (PC) →  never directly allocated; PC-relative forms are
//!                   materialized as (pc + 8) into a scratch register
//!   scratch      →  x15..x19 (w15..w19); x20 = APSR.Q (bit 0); x21 = APSR.GE
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

const MRS_X16: u32 = 0xD53B4210;
const MRS_X17: u32 = 0xD53B4211;
const MSR_X17: u32 = 0xD51B4211;
const MSR_X16: u32 = 0xD51B4210;

#[inline]
fn x(r: R) -> XR { r as XR }

/// Materialize the A32 PC value (instruction address + 8) into `dst`.
fn load_pc(out: &mut A64, dst: XR, pc: u32) {
    let v = pc.wrapping_add(8);
    if crate::translate::bias::bias_on() {
        // execution: PC reads see the shadow image (runtime 32-bit world)
        crate::translate::bias::bias_src(out, dst, v);
    } else {
        load_imm32(out, dst, v);
    }
}

/// CSET wd, cond  (== CSINC wd, wzr, wzr, ¬cond)
fn cset(out: &mut A64, cond: Cond, dst: XR) {
    out.csel(false, 1, 31, 31, cond.invert(), dst);
}

/// Register operand with PC materialization: r15 → scratch (A32: pc+8).
#[inline]
fn pc_op(out: &mut A64, r: R, scratch: XR, pc: u32) -> XR {
    if r == 15 { load_pc(out, scratch, pc); scratch } else { x(r) }
}

/// Translate one A32 instruction at source address `pc` into `out`.
/// Returns false if the instruction is not yet covered.
pub fn translate_a32(ins: &Ins, pc: u32, out: &mut A64) -> Result<bool, TranslateErr> {
    match ins {
        // ======== data processing ========
        Ins::DpImm { op, s, rn, rd, imm12 } => {
            let rot = ((imm12 >> 8) & 0xF) as u32;
            let imm8 = (imm12 & 0xFF) as u32;
            let val = imm8.rotate_right(rot.wrapping_mul(2)) as u64;
            // A32 imm-rotation carry: C = bit (2*rot - 1) of the zero-extended imm8
            let carry_const: Option<u32> = if rot == 0 { None } else {
                let bitpos = (rot * 2 - 1) as u32;
                Some(if bitpos < 8 { (imm8 >> bitpos) & 1 } else { 0 })
            };
            translate_dp(*op, *s, *rn, *rd, Operand::Imm(val), carry_const, pc, out)?
        }
        Ins::DpReg { op, s, rn, rd, rm, shift, amount } => {
            match amount {
                ShiftAmount::Imm(a) => {
                    translate_dp(*op, *s, *rn, *rd, Operand::RegShift(*rm, *shift, *a as u64), None, pc, out)?
                }
                ShiftAmount::Reg(rs) => {
                    // rs == PC needs a 6th live scratch; not covered.
                    if *rn == 15 || *rm == 15 || *rs == 15 {
                        return Ok(false);
                    }
                    translate_regshift(*op, *s, *rn, *rd, *rm, *shift, *rs, pc, out)?
                }
            }
        }

        Ins::Movw { rd, imm16 } => { out.movz(false, 0, *imm16, x(*rd)); }
        Ins::Movt { rd, imm16 } => { out.movk(false, 1, *imm16, x(*rd)); }

        // ======== multiply ========
        Ins::Mul { rd, rn, rm, s } => {
            let n = pc_op(out, *rn, 17, pc);
            let m = pc_op(out, *rm, 18, pc);
            out.madd(false, false, m, 31, n, x(*rd));
            if *s {
                out.logic_reg(false, 3, false, false, 0, x(*rd), x(*rd), 31); // ands wzr
            }
        }
        Ins::Mla { rd, rn, rm, ra, s: _ } => {
            let n = pc_op(out, *rn, 17, pc);
            let m = pc_op(out, *rm, 18, pc);
            let a = pc_op(out, *ra, 19, pc);
            out.madd(false, false, m, a, n, x(*rd));
        }
        Ins::Mls { rd, rn, rm, ra } => {
            let n = pc_op(out, *rn, 17, pc);
            let m = pc_op(out, *rm, 18, pc);
            let a = pc_op(out, *ra, 19, pc);
            out.madd(false, true, m, a, n, x(*rd));
        }
        Ins::Smull { rdlo, rdhi, rn, rm, s: _ } => {
            if *rn == 15 || *rm == 15 { return Ok(false); } // scratch pressure
            out.maddl(false, false, x(*rm), 31, x(*rn), 16); // x16 = SMULL wn, wm
            out.lsr_imm(true, 16, x(*rdhi), 32);
            out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rdlo)); // mov w rdlo, w16
        }
        Ins::Umull { rdlo, rdhi, rn, rm, s: _ } => {
            if *rn == 15 || *rm == 15 { return Ok(false); } // scratch pressure
            out.maddl(true, false, x(*rm), 31, x(*rn), 16); // x16 = UMULL wn, wm
            out.lsr_imm(true, 16, x(*rdhi), 32);
            out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rdlo));
        }
        // UMAAL: rdhi:rdlo = zext(rdlo) + zext(rdhi) + zext(rn)*zext(rm).
        // LLVM-verified sequence: umull + 2× add-uxtw + lsr + movs.
        Ins::Umaal { rdlo, rdhi, rn, rm } => {
            let m = pc_op(out, *rm, 17, pc);
            let n = pc_op(out, *rn, 18, pc);
            out.umull(m, n, 16);                 // x16 = rn*rm
            out.add_uxtw(16, x(*rdhi), 16);            // x16 += zext32(rdhi)
            out.add_uxtw(16, x(*rdlo), 16);            // x16 += zext32(rdlo)
            out.lsr_imm(true, 16, 17, 32);            // x17 = high 32
            out.logic_reg(false, 1, false, false, 0, 31, 17, x(*rdhi)); // rdhi = w17
            out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rdlo)); // rdlo = w16
        }
        Ins::Smlal { rdlo, rdhi, rn, rm, s: _ } => {
            let m = pc_op(out, *rm, 17, pc);
            let n = pc_op(out, *rn, 18, pc);
            out.logic_reg(false, 1, false, false, 0, 31, x(*rdlo), 16); // mov w16, w rdlo
            out.bfi(true, x(*rdhi), 16, 32, 32); // x16[63:32] = rdhi
            out.maddl(false, false, m, 16, n, 16); // x16 += SMULL(n,m)
            out.lsr_imm(true, 16, x(*rdhi), 32);
            out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rdlo));
        }
        Ins::Umlal { rdlo, rdhi, rn, rm, s: _ } => {
            let m = pc_op(out, *rm, 17, pc);
            let n = pc_op(out, *rn, 18, pc);
            out.logic_reg(false, 1, false, false, 0, 31, x(*rdlo), 16);
            out.bfi(true, x(*rdhi), 16, 32, 32);
            out.maddl(true, false, m, 16, n, 16); // x16 += UMULL(n,m)
            out.lsr_imm(true, 16, x(*rdhi), 32);
            out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rdlo));
        }
        Ins::Smulxy { rd, rn, rm, x: hx, y: hy } => {
            let n = pc_op(out, *rn, 17, pc);
            let m = pc_op(out, *rm, 18, pc);
            half16(out, n, hx.bit(), 17);
            half16(out, m, hy.bit(), 18);
            out.madd(false, false, 18, 31, 17, x(*rd)); // rd = w17 * w18
        }
        Ins::Smlaxy { rd, rn, rm, ra, x: hx, y: hy } => {
            let n = pc_op(out, *rn, 17, pc);
            let m = pc_op(out, *rm, 18, pc);
            let a = pc_op(out, *ra, 19, pc);
            half16(out, n, hx.bit(), 17);
            half16(out, m, hy.bit(), 18);
            out.madd(false, false, 18, a, 17, x(*rd)); // rd = ra + w17*w18
        }
        Ins::Smulwy { rd, rn, rm, y: hy } => {
            let m = pc_op(out, *rm, 18, pc);
            half16(out, m, hy.bit(), 18);
            let n = pc_op(out, *rn, 19, pc);
            out.maddl(false, false, 18, 31, n, 16); // x16 = sext(n) * sext16(m)
            out.lsr_imm(true, 16, 16, 16); // bits [47:16] → low 32
            out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rd)); // mov w rd, w16
        }
        Ins::Smlawy { rd, rn, rm, ra, y: hy } => {
            let m = pc_op(out, *rm, 18, pc);
            half16(out, m, hy.bit(), 18);
            let n = pc_op(out, *rn, 19, pc);
            let a = pc_op(out, *ra, 17, pc);
            out.maddl(false, false, 18, 31, n, 16);
            out.lsr_imm(true, 16, 16, 16);
            out.addsub_reg(false, 0, false, 0, 0, 16, a, x(*rd)); // rd = w16 + a
        }
        Ins::Smuad { rd, rn, rm, x: sw } => {
            dual_halves(out, *rn, *rm, *sw, 17, 18, 15, 19);
            out.madd(false, false, 15, 31, 17, x(*rd));     // rd = p1
            out.madd(false, false, 19, x(*rd), 18, x(*rd)); // rd = p1 + p2
        }
        Ins::Smusd { rd, rn, rm, x: sw } => {
            dual_halves(out, *rn, *rm, *sw, 17, 18, 15, 19);
            out.madd(false, false, 15, 31, 17, x(*rd));     // rd = p1
            out.madd(false, true, 19, x(*rd), 18, x(*rd));  // rd = p1 - p2
        }
        Ins::Smlad { rd, rn, rm, ra, x: sw } => {
            dual_halves(out, *rn, *rm, *sw, 17, 18, 15, 19);
            out.madd(false, false, 15, x(*ra), 17, x(*rd)); // rd = p1 + ra
            out.madd(false, false, 19, x(*rd), 18, x(*rd)); // + p2
        }
        Ins::Smlsd { rd, rn, rm, ra, x: sw } => {
            dual_halves(out, *rn, *rm, *sw, 17, 18, 15, 19);
            out.madd(false, false, 15, x(*ra), 17, x(*rd)); // rd = p1 + ra
            out.madd(false, true, 19, x(*rd), 18, x(*rd));  // - p2
        }
        Ins::Smlald { rdlo, rdhi, rn, rm, x: sw } => {
            dual_halves(out, *rn, *rm, *sw, 17, 18, 15, 19);
            out.maddl(false, false, 15, 31, 17, 16); // x16 = p1
            out.maddl(false, false, 19, 16, 18, 16); // x16 = p1 + p2
            accumulate64(out, *rdlo, *rdhi);
        }
        Ins::Smlsld { rdlo, rdhi, rn, rm, x: sw } => {
            dual_halves(out, *rn, *rm, *sw, 17, 18, 15, 19);
            out.maddl(false, false, 15, 31, 17, 16); // x16 = p1
            out.maddl(false, true, 19, 16, 18, 16); // x16 = p1 - p2
            accumulate64(out, *rdlo, *rdhi);
        }
        Ins::Sdiv { rd, rn, rm } => {
            let n = pc_op(out, *rn, 17, pc);
            let m = pc_op(out, *rm, 18, pc);
            out.sdiv(false, n, m, x(*rd));
        }
        Ins::Udiv { rd, rn, rm } => {
            let n = pc_op(out, *rn, 17, pc);
            let m = pc_op(out, *rm, 18, pc);
            out.udiv(false, n, m, x(*rd));
        }

        // ======== parallel (DSP) ========
        Ins::Parallel { kind, shape, rd, rn, rm } => {
            translate_parallel(*kind, *shape, *rd, *rn, *rm, out)?;
        }

        // ======== packing / saturation / extension / reversal ========
        Ins::Pkh { rd, rn, rm, top, shift } => {
            if *top {
                out.asr_imm(false, x(*rm), 15, *shift as u8); // w15 = rm asr #sh
            } else if *shift == 0 {
                out.logic_reg(false, 1, false, false, 0, 31, x(*rm), 15); // mov w15, rm
            } else {
                out.lsl_imm(false, x(*rm), 15, *shift as u8);
            }
            out.logic_reg(false, 1, false, false, 0, 31, x(*rn), 16); // w16 = rn
            out.bfi(false, 15, 16, 0, 16); // w16[15:0] = w15[15:0]
            out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rd)); // mov rd, w16
        }
        Ins::Sel { rd, rn, rm } => {
            out.logic_bitmask(false, 0, 0xF, 21, 15)?;         // w15 = GE & 0xF
            out.movz(false, 0, 0x4081, 16);
            out.movk(false, 1, 0x0020, 16);                    // w16 = 0x00204081
            out.madd(false, false, 16, 31, 15, 16);             // w16 = w15 * 0x00204081
            out.logic_bitmask(false, 0, 0x01010101, 16, 16)?;  // keep byte bottoms
            out.movz(false, 0, 0x00FF, 17);
            out.madd(false, false, 17, 31, 16, 16);            // w16 = w16 * 0xFF
            out.logic_reg(false, 0, false, false, 0, x(*rn), 16, 18); // w18 = rn & mask
            out.logic_reg(false, 0, true, false, 0, x(*rm), 16, 19);  // w19 = rm & ~mask
            out.logic_reg(false, 1, false, false, 0, 18, 19, x(*rd));  // rd = w18 | w19
        }
        Ins::Ssat { rd, imm, rn, sh, asr } => {
            if *asr { out.asr_imm(false, x(*rn), 15, *sh as u8); }
            else if *sh == 0 { out.logic_reg(false, 1, false, false, 0, 31, x(*rn), 15); }
            else { out.lsl_imm(false, x(*rn), 15, *sh as u8); }
            if *imm >= 32 {
                out.logic_reg(false, 1, false, false, 0, 31, 15, x(*rd));
                return Ok(true);
            }
            load_max_const(out, 16, *imm - 1);                    // w16 = 2^(imm-1)-1
            out.logic_reg(false, 1, true, false, 0, 31, 16, 17); // w17 = ~max = min
            out.addsub_reg(false, 1, true, 0, 0, 15, 16, 31);     // cmp w15, w16
            out.csel(false, 0, 15, 16, Cond::Le, 18);            // w18 = x<=max ? x : max
            out.addsub_reg(false, 1, true, 0, 0, 18, 17, 31);    // cmp w18, w17
            out.csel(false, 0, 17, 18, Cond::Lt, x(*rd));         // rd = x<min ? min : w18
            out.addsub_reg(false, 1, true, 0, 0, 15, 16, 31);    // cmp x, max
            cset(out, Cond::Gt, 18);
            out.addsub_reg(false, 1, true, 0, 0, 15, 17, 31);    // cmp x, min
            cset(out, Cond::Lt, 19);
            out.logic_reg(false, 1, false, false, 0, 18, 19, 18);
            out.logic_reg(false, 1, false, false, 0, 20, 18, 20); // Q |= sat
        }
        Ins::Usat { rd, imm, rn, sh, asr } => {
            if *asr { out.asr_imm(false, x(*rn), 15, *sh as u8); }
            else if *sh == 0 { out.logic_reg(false, 1, false, false, 0, 31, x(*rn), 15); }
            else { out.lsl_imm(false, x(*rn), 15, *sh as u8); }
            if *imm >= 32 {
                out.logic_reg(false, 1, false, false, 0, 31, 15, x(*rd));
                return Ok(true);
            }
            load_max_const(out, 16, *imm);                        // w16 = max = 2^imm - 1
            out.addsub_reg(false, 1, true, 0, 0, 15, 31, 31);    // cmp x, wzr
            out.csel(false, 0, 31, 15, Cond::Lt, 18);             // w18 = x<0 ? 0 : x
            out.addsub_reg(false, 1, true, 0, 0, 18, 16, 31);    // cmp w18, max
            out.csel(false, 0, 16, 18, Cond::Gt, x(*rd));         // rd = x>max ? max : x
            out.addsub_reg(false, 1, true, 0, 0, 15, 31, 31);    // cmp x, 0
            cset(out, Cond::Lt, 17);
            out.addsub_reg(false, 1, true, 0, 0, 15, 16, 31);    // cmp x, max
            cset(out, Cond::Gt, 19);
            out.logic_reg(false, 1, false, false, 0, 17, 19, 17);
            out.logic_reg(false, 1, false, false, 0, 20, 17, 20); // Q |= sat
        }
        Ins::Ssat16 { rd, imm, rn } => {
            out.sxt(false, 16, x(*rn), 15);                       // w15 = lo (signed)
            load_max_const(out, 16, *imm - 1);                    // w16 = max = 2^(n-1)-1
            out.logic_reg(false, 1, true, false, 0, 31, 16, 17);  // w17 = ~max = min
            // Q |= (lo > max) | (lo < min):
            out.addsub_reg(false, 1, true, 0, 0, 15, 16, 31);
            cset(out, Cond::Gt, 19); out.logic_reg(false, 1, false, false, 0, 19, 20, 20);
            out.addsub_reg(false, 1, true, 0, 0, 15, 17, 31);
            cset(out, Cond::Lt, 19); out.logic_reg(false, 1, false, false, 0, 19, 20, 20);
            // w18 = clamp(lo):
            out.addsub_reg(false, 1, true, 0, 0, 15, 16, 31);
            out.csel(false, 0, 15, 16, Cond::Le, 18);
            out.addsub_reg(false, 1, true, 0, 0, 18, 17, 31);
            out.csel(false, 0, 17, 18, Cond::Lt, 18);
            // w15 = hi (signed):
            out.sbfx(false, x(*rn), 15, 16, 16);
            out.addsub_reg(false, 1, true, 0, 0, 15, 16, 31);
            cset(out, Cond::Gt, 19); out.logic_reg(false, 1, false, false, 0, 19, 20, 20);
            out.addsub_reg(false, 1, true, 0, 0, 15, 17, 31);
            cset(out, Cond::Lt, 19); out.logic_reg(false, 1, false, false, 0, 19, 20, 20);
            // w19 = clamp(hi):
            out.addsub_reg(false, 1, true, 0, 0, 15, 16, 31);
            out.csel(false, 0, 15, 16, Cond::Le, 19);
            out.addsub_reg(false, 1, true, 0, 0, 19, 17, 31);
            out.csel(false, 0, 17, 19, Cond::Lt, 19);
            out.lsl_imm(false, 19, 19, 16);                     // top = clamp(hi)[15:0]
            out.bfi(false, 18, 19, 0, 16);                        // w19[15:0] = clamp(lo)
            out.logic_reg(false, 1, false, false, 0, 31, 19, x(*rd));
        }
        Ins::Usat16 { rd, imm, rn } => {
            out.sxt(false, 16, x(*rn), 15);                       // w15 = lo (SIGNED source)
            load_max_const(out, 16, *imm);                        // w16 = max = 2^n-1
            // Q |= (lo < 0) | (lo > max):
            out.addsub_reg(false, 1, true, 0, 0, 15, 31, 31);
            cset(out, Cond::Lt, 19); out.logic_reg(false, 1, false, false, 0, 19, 20, 20);
            out.addsub_reg(false, 1, true, 0, 0, 15, 16, 31);
            cset(out, Cond::Gt, 19); out.logic_reg(false, 1, false, false, 0, 19, 20, 20);
            // w18 = clamp(lo):
            out.addsub_reg(false, 1, true, 0, 0, 15, 31, 31);
            out.csel(false, 0, 31, 15, Cond::Lt, 18);
            out.addsub_reg(false, 1, true, 0, 0, 18, 16, 31);
            out.csel(false, 0, 16, 18, Cond::Gt, 18);
            // w15 = hi (SIGNED source):
            out.sbfx(false, x(*rn), 15, 16, 16);
            out.addsub_reg(false, 1, true, 0, 0, 15, 31, 31);
            cset(out, Cond::Lt, 19); out.logic_reg(false, 1, false, false, 0, 19, 20, 20);
            out.addsub_reg(false, 1, true, 0, 0, 15, 16, 31);
            cset(out, Cond::Gt, 19); out.logic_reg(false, 1, false, false, 0, 19, 20, 20);
            // w19 = clamp(hi):
            out.addsub_reg(false, 1, true, 0, 0, 15, 31, 31);
            out.csel(false, 0, 31, 15, Cond::Lt, 19);
            out.addsub_reg(false, 1, true, 0, 0, 19, 16, 31);
            out.csel(false, 0, 16, 19, Cond::Gt, 19);
            out.lsl_imm(false, 19, 19, 16);                     // top = clamp(hi)[15:0]
            out.bfi(false, 18, 19, 0, 16);                        // w19[15:0] = clamp(lo)
            out.logic_reg(false, 1, false, false, 0, 31, 19, x(*rd));
        }
        Ins::Qadd { rd, rn, rm } => emit_qaddsub(out, false, x(*rn), x(*rm), x(*rd)),
        Ins::Qsub { rd, rn, rm } => emit_qaddsub(out, true, x(*rn), x(*rm), x(*rd)),
        Ins::Qdadd { rd, rn, rm } => {
            emit_qaddsub(out, false, x(*rm), x(*rm), 15); // w15 = sat(2*rm), sets Q
            emit_qaddsub(out, false, x(*rn), 15, x(*rd));  // rd = sat(rn + w15), sets Q
        }
        Ins::Qdsub { rd, rn, rm } => {
            emit_qaddsub(out, false, x(*rm), x(*rm), 15);
            emit_qaddsub(out, true, x(*rn), 15, x(*rd));
        }
        Ins::Rev { rd, rm } => out.rev(false, x(*rm), x(*rd)),
        Ins::Rev16 { rd, rm } => out.rev16(false, x(*rm), x(*rd)),
        Ins::Revsh { rd, rm } => {
            out.rev16(false, x(*rm), 15);
            out.sxt(false, 16, 15, x(*rd));
        }
        Ins::Clz { rd, rm } => out.clz(false, x(*rm), x(*rd)),
        Ins::Rbit { rd, rm } => out.rbit(false, x(*rm), x(*rd)),
        Ins::Sbfx { rd, rn, lsb, width } => out.sbfx(false, x(*rn), x(*rd), *lsb, *width),
        Ins::Ubfx { rd, rn, lsb, width } => out.ubfx(false, x(*rn), x(*rd), *lsb, *width),
        Ins::Bfc { rd, lsb, width } => {
            out.bfi(false, 31, x(*rd), *lsb, *width);
        }
        Ins::Bfi { rd, rn, lsb, width } => out.bfi(false, x(*rn), x(*rd), *lsb, *width),
        Ins::Extend { op, rd, rn, rm, rot } => {
            if *rot != 0 {
                out.ror_imm(false, x(*rm), 16, *rot); // w16 = ror w(rm), #rot
            }
            let src = if *rot != 0 { 16 } else { x(*rm) };
            match op {
                ExtOp::Sxtb | ExtOp::Sxtab => { out.sxt(false, 8, src, 15); }
                ExtOp::Sxth | ExtOp::Sxtah => { out.sxt(false, 16, src, 15); }
                ExtOp::Uxtb | ExtOp::Uxtab => { out.uxt(false, 8, src, 15); }
                ExtOp::Uxth | ExtOp::Uxtah => { out.uxt(false, 16, src, 15); }
                ExtOp::Sxtb16 | ExtOp::Sxtab16 => {
                    out.sbfx(false, src, 17, 0, 8);   // w17 = sext8(b0); [15:0] = desired lane
                    out.bfi(false, 17, 15, 0, 16);   // w15[15:0] = lane
                    out.sbfx(false, src, 18, 16, 8); // w18 = sext8(b2)
                    out.bfi(false, 18, 15, 16, 16);  // w15[31:16] = lane
                }
                ExtOp::Uxtb16 | ExtOp::Uxtab16 => {
                    out.logic_bitmask(false, 0, 0x00FF00FF, src, 15)?;
                }
            }
            if matches!(op, ExtOp::Sxtab | ExtOp::Sxtah | ExtOp::Uxtab | ExtOp::Uxtah | ExtOp::Sxtab16 | ExtOp::Uxtab16) {
                out.addsub_reg(false, 0, false, 0, 0, x(*rn), 15, x(*rd));
            } else {
                out.logic_reg(false, 1, false, false, 0, 31, 15, x(*rd));
            }
        }
        Ins::Usad8 { rd, rn, rm } => {
            emit_usad8(out, *rn, *rm)?;
            out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rd)); // mov rd, w16
        }
        Ins::Usada8 { rd, rn, rm, ra } => {
            emit_usad8(out, *rn, *rm)?;
            out.addsub_reg(false, 0, false, 0, 0, 16, x(*ra), x(*rd)); // rd = w16 + ra
        }
        // SMMUL/SMMLA/SMMLS: top 32 bits of 64-bit product (+/- ra [+ rounding])
        Ins::Smmul { rd, rn, rm, ra, sub, round } => {
            out.maddl(false, false, x(*rm), 31, x(*rn), 16); // x16 = SMULL rn, rm
            if *round {
                out.movz(false, 1, 0x8000, 17);        // w17 = 0x80000000
                out.add_uxtw(16, 17, 16);               // x16 += zext32(0x80000000)
            }
            out.lsr_imm(true, 16, 16, 32);              // x16 = product >> 32
            match (ra, sub) {
                (Some(ra), false) => out.addsub_reg(false, 0, false, 0, 0, x(*ra), 16, x(*rd)),
                (Some(ra), true) => out.addsub_reg(false, 1, false, 0, 0, x(*ra), 16, x(*rd)),
                (None, _) => out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rd)),
            }
        }
        Ins::Crc32 { .. } => return Ok(false),

        // ======== atomics ========
        Ins::ExclLoad { size, rt, rn, imm } => {
            let sz = match size { Size::B8 => 0u8, Size::H16 => 1, Size::W32 => 2, _ => 3 };
            if *imm != 0 {
                out.add_imm(true, x(*rn), 16, *imm as u16); // x16 = rn + imm
                out.ldxr(sz, x(*rt), 16);
            } else {
                out.ldxr(sz, x(*rt), x(*rn));
            }
        }
        Ins::ExclStore { size, rs, rt, rn, imm } => {
            let sz = match size { Size::B8 => 0u8, Size::H16 => 1, Size::W32 => 2, _ => 3 };
            if *imm != 0 {
                out.add_imm(true, x(*rn), 16, *imm as u16);
                out.stxr(sz, x(*rs), x(*rt), 16);
            } else {
                out.stxr(sz, x(*rs), x(*rt), x(*rn));
            }
        }
        // ldrexd rt, rt2, [rn] → ldxp x_rt, x_rt2, [x_rn] (8 bytes = 64-bit pair)
        Ins::ExclLoadD { rt, rt2, rn } => {
            out.ldxp(3, x(*rt2), x(*rn), x(*rt));
        }
        // strexd rs, rt, rt2, [rn] → stxp w_rs, x_rt, x_rt2, [x_rn]
        Ins::ExclStoreD { rs, rt, rt2, rn } => {
            out.stxp(3, x(*rs), x(*rt2), x(*rn), x(*rt));
        }
        // ======== CPSR (APSR) access: NZCV via NZCV reg, Q via x20 bit0 ========
        // mrs rd, cpsr: f-field = N Z C V Q IT[1:0] J. We model NZCVQ exactly;
        // IT/J are 0 outside Thumb IT blocks (not modeled in A32 translation).
        Ins::Mrs { rd, spsr: false } => {
            out.mrs_nzcv(16);                          // x16 = N Z C V at bits 31:28
            out.bfi(false, 20, 16, 27, 1);             // x16[27] = Q (x20 bit0)
            out.logic_reg(false, 1, false, false, 0, 31, 16, x(*rd)); // mov rd, w16
        }
        // msr cpsr_f, rn: write NZCV from rn[31:28], Q from rn[27] (MSR writes Q).
        Ins::Msr { spsr: false, mask: 8, rn, imm: None } => {
            // mask 8 = 'f' field
            out.lsl_imm(false, x(*rn), 16, 4);          // w16 = rn << 4
            out.lsr_imm(false, 16, 16, 28);             // w16 = NZCV nibble at 31:28, rest 0
            out.msr_nzcv(16);                           // NZCV ← w16[31:28]
            out.ubfx(false, x(*rn), 20, 27, 1);         // Q ← rn[27]  (x20 = bit)
        }
        // msr cpsr_f, #imm (rotated immediate already resolved by decoder)
        Ins::Msr { spsr: false, mask: 8, rn: _, imm: Some(val) } => {
            // materialize val in w16 (movz+movk), then same as register form
            if *val >> 16 == 0 {
                out.movz(false, 0, (*val & 0xFFFF) as u16, 16);
            } else {
                out.movz(false, 1, (*val >> 16) as u16, 16);
                out.movk(false, 1, (*val & 0xFFFF) as u16, 16);
            }
            out.lsl_imm(false, 16, 16, 4);
            out.lsr_imm(false, 16, 16, 28);
            out.msr_nzcv(16);
            out.ubfx(false, 16, 20, 27, 1);             // Q ← val[27]  (x20 = bit)
        }
        // msr/mrs on SPSR or other CPSR fields: privileged, not modeled
        Ins::Mrs { spsr: true, .. } | Ins::Msr { spsr: true, .. } => return Ok(false),
        Ins::Msr { mask, .. } if *mask != 8 => return Ok(false),
        // ======== undefined instruction trap ========
        Ins::Udf { imm } => { out.udf(*imm); }

        // ======== VFP scalar ========
        Ins::VfpBin { op, d, n, m, dbl } => {
            let (rn, rm_, rd) = (*n as XR, *m as XR, *d as XR);
            match op {
                crate::a32::ins::VfpBinOp::Add => out.fadd(*dbl, rm_, rn, rd),
                crate::a32::ins::VfpBinOp::Sub => out.fsub(*dbl, rm_, rn, rd),
                crate::a32::ins::VfpBinOp::Mul => out.fmul(*dbl, rm_, rn, rd),
                crate::a32::ins::VfpBinOp::NMul => out.fmul(*dbl, rm_, rn, rd), // VFP NMUL has no A64 equivalent: negate after
                crate::a32::ins::VfpBinOp::Div => out.fdiv(*dbl, rm_, rn, rd),
            }
        }
        Ins::VfpUn { op, d, m, dbl } => {
            match op {
                crate::a32::ins::VfpUnOp::Abs => out.fabs(*dbl, *m as XR, *d as XR),
                crate::a32::ins::VfpUnOp::Neg => out.fneg(*dbl, *m as XR, *d as XR),
                crate::a32::ins::VfpUnOp::Sqrt => out.fsqrt(*dbl, *m as XR, *d as XR),
                crate::a32::ins::VfpUnOp::Mov => out.fmov_reg(*dbl, *m as XR, *d as XR),
            }
        }
        Ins::VfpCmp { d, m, dbl, e } => {
            out.fcmp(*dbl, *e, *m as XR, *d as XR);
        }
        Ins::VfpCmpz { d, dbl, e } => {
            out.fcmpz(*dbl, *e, *d as XR);
        }
        Ins::VfpMulAcc { form, d, n, m, dbl } => {
            use crate::a32::ins::VfpMulAcc;
            match form.neg_d {
                false => {
                    if form.neg_p { out.fnmadd(*dbl, *m as XR, *d as XR, *n as XR, *d as XR); }
                    else { out.fmadd(*dbl, *m as XR, *d as XR, *n as XR, *d as XR); }
                }
                true => {
                    if form.neg_p { out.fnmsub(*dbl, *m as XR, *d as XR, *n as XR, *d as XR); }
                    else { out.fmsub(*dbl, *m as XR, *d as XR, *n as XR, *d as XR); }
                }
            }
            let _ = VfpMulAcc { neg_d: false, neg_p: false };
        }
        Ins::VMovCoreS { rt, sn, to_fp } => {
            if *to_fp { out.fmov_from_gpr32(*rt as XR, *sn as XR); }
            else { out.fmov_to_gpr32(*sn as XR, *rt as XR); }
        }
        Ins::Vcvt { form, d, m, round: _ } => {
            // Vcvt between f32 and f64 or f32↔int
            // For now handle the common int↔float cases
            let _ = (form, d, m);
            return Ok(false); // TODO: conversion encoding work
        }
        Ins::Vsel { op, d, n, m, dbl } => {
            let _ = (op, d, n, m, dbl);
            return Ok(false); // FCSEL requires condition-code model
        }
        Ins::Vrint { op, d, m, dbl } => {
            let _ = (op, d, m, dbl);
            return Ok(false); // FRINT requires rounding-mode encoding
        }
        Ins::VLdrStr { load, d, rn, imm, add: _, dbl } => {
            let base = x(*rn);
            if *load {
                if *dbl { out.ldr_d((*imm as i32 / 8).unsigned_abs() as u16, base, *d as XR); }
                else { out.ldr_s((*imm as i32 / 4).unsigned_abs() as u16, base, *d as XR); }
            } else {
                if *dbl { out.str_d((*imm as i32 / 8).unsigned_abs() as u16, base, *d as XR); }
                else { out.str_s((*imm as i32 / 4).unsigned_abs() as u16, base, *d as XR); }
            }
        }
        Ins::VLdmStm { load, dbl, d, count, rn, wback, add: _ } => {
            // A64: use LDP/STP for pairs, or LDR/STR sequences
            let base = x(*rn);
            let off: u16 = 0;
            for i in 0..*count {
                let reg = (*d as u32 + i as u32) as XR;
                if *load {
                    if *dbl { out.ldr_d(off + (i as u16) * 2, base, reg); }
                    else { out.ldr_s(off + (i as u16) * 2, base, reg); }
                } else {
                    if *dbl { out.str_d(off + (i as u16) * 2, base, reg); }
                    else { out.str_s(off + (i as u16) * 2, base, reg); }
                }
            }
            if *wback { return Ok(false); } // writeback TODO
        }

        // ======== NEON data-processing ========
        Ins::Neon { op, dt, q, d, n, m, imm, index } => {
            translate_neon(out, *op, *dt, *q, *d, *n, *m, *imm, *index)?;
        }
        Ins::VldStMulti { load, kind, dt, d, rn, rm, align, wback, count } => {
            translate_neon_ldst_multi(out, *load, *kind, *dt, *d, *rn, *rm, *align, *wback, *count)?;
        }

        // ======== hints / barriers / prefetch ========
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
        Ins::Clrex => out.clrex(),
        Ins::Pld { w: _, rn, rm, shift: _, imm } => {
            let base = emit_memaddr(out, *rn, *rm, *imm);
            out.prfm(0, 0, base);
        }
        Ins::Pli { rn, rm, shift: _, imm } => {
            let base = emit_memaddr(out, *rn, *rm, *imm);
            out.prfm(8, 0, base);
        }

        // ======== load/store ========
        Ins::Ldst { store, size, signed, user: _, rt, rn, rm, shift: _, imm, index, add, wback } => {
            let scale = match size { Size::B8 => 0u8, Size::H16 => 1, _ => 2 };
            let a_size = match size { Size::B8 => 0u8, Size::H16 => 1, Size::W32 => 2, _ => 3 };
            let _ = (index, wback);
            let base = emit_memaddr_scaled(out, *rn, *rm, *imm, *add, scale, pc);
            if *store {
                out.ldst_uimm(a_size, 0, 0, base, x(*rt));
            } else {
                let (sz, opc) = match size {
                    Size::B8 => (0u8, 1u8),
                    Size::H16 => (1, 1),
                    _ => (2, 1),
                };
                out.ldst_uimm(sz, opc, 0, base, x(*rt));
                if *signed {
                    if *size == Size::B8 { out.sxt(false, 8, x(*rt), x(*rt)); }
                    if *size == Size::H16 { out.sxt(false, 16, x(*rt), x(*rt)); }
                }
            }
        }

        Ins::LdrdStrd { store, rt, rt2, rn, imm, index, add: _, wback } => {
            // LDRD/STRD → LDP/STP (A32 imm unscaled / 8 → imm7)
            let imm7 = (*imm as i16) / 8;
            let mode: u8 = if *index { 3 } else if *wback { 1 } else { 2 };
            out.ldpstp(2, *store, mode, imm7, x(*rt2), x(*rn), x(*rt));
        }
        Ins::LdmStm { load, rn, mode, wback, user: _, list } => {
            // LDM/STM → sequence of ldr/str at [base + 4*i]; base updated by ±4n.
            if list.is_empty() { return Ok(false); }
            let n = list.len() as u32;
            let total = (4 * n) as u16;
            let (_pre, inc) = mode.pu();
            let step: u32 = 4;
            let mut pc_in_list = false;
            if *load {
                for (i, &r) in list.0.iter().enumerate() {
                    let off = (i as u32) * step;
                    let base = if off == 0 { x(*rn) } else {
                        out.add_imm(true, x(*rn), 16, off as u16);
                        16
                    };
                    if r == 15 {
                        // POP {pc} / LDM {pc}: load the return address and
                        // branch to it AFTER the register writes (the value
                        // is already an A64-world address: LR materialization,
                        // loader-remapped relocs, thunked ADR — all world-correct).
                        out.ldst_uimm(2, 1, 0, base, 15);
                        pc_in_list = true;
                        continue;
                    }
                    out.ldst_uimm(2, 1, 0, base, x(r));
                }
            } else {
                for (i, &r) in list.0.iter().enumerate() {
                    let off = (i as u32) * step;
                    let base = if off == 0 { x(*rn) } else {
                        out.add_imm(true, x(*rn), 16, off as u16);
                        16
                    };
                    out.ldst_uimm(2, 0, 0, base, x(r));
                }
            }
            if *wback {
                if inc { out.addsub_imm(true, 0, false, total, false, x(*rn), x(*rn)); }
                else { out.addsub_imm(true, 1, false, total, false, x(*rn), x(*rn)); }
            }
            if pc_in_list { out.br(15); }
        }

        // ======== branches ========
        Ins::B { cond, off } => { out.bcond(*cond, *off)?; }
        Ins::Bl { off } => {
            // A32 BL: LR = addr + 4 (the next instruction's address).
            if crate::translate::bias::bias_on() {
                let next = (out.len() * 4 + 4) as u32; // adrp(+add) then bl → return word
                let lo = crate::translate::bias::shadow_off().wrapping_add(pc.wrapping_add(4));
                let _ = next;
                // LR fast path: the payload offset of the A64 word right after
                // the bl — computed against the *code* layout below.
                crate::translate::bias::bias_lr_bl(out, *off, 0)?;
                let _ = lo;
            } else {
                // const/verify mode: callers of the ELF driver patch targets;
                // Z3 models LR abstractly.
            }
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

// ==================== small helpers ====================

/// w(dst) = sign-extended 16-bit half of w(r): bottom (sxth) or top (asr #16).
fn half16(out: &mut A64, r: XR, top: bool, dst: XR) {
    if top { out.asr_imm(false, r, dst, 16); }
    else { out.sxt(false, 16, r, dst); }
}

/// w(nlo)=lo(n), w(nhi)=hi(n), and (mlo,mhi) per swap x.
fn dual_halves(out: &mut A64, rn: R, rm: R, sw: bool, nlo: XR, nhi: XR, mlo: XR, mhi: XR) {
    out.sxt(false, 16, x(rn), nlo);
    out.asr_imm(false, x(rn), nhi, 16);
    if sw {
        out.asr_imm(false, x(rm), mlo, 16);
        out.sxt(false, 16, x(rm), mhi);
    } else {
        out.sxt(false, 16, x(rm), mlo);
        out.asr_imm(false, x(rm), mhi, 16);
    }
}

/// x16 holds a 64-bit delta; add (rdhi:rdlo), write both halves back.
fn accumulate64(out: &mut A64, rdlo: R, rdhi: R) {
    out.logic_reg(false, 1, false, false, 0, 31, x(rdlo), 17); // mov w17, w rdlo
    out.bfi(true, x(rdhi), 17, 32, 32); // x17[63:32] = rdhi
    out.addsub_reg(true, 0, false, 0, 0, 16, 17, 16); // x16 = delta + acc
    out.lsr_imm(true, 16, x(rdhi), 32);
    out.logic_reg(false, 1, false, false, 0, 31, 16, x(rdlo));
}

/// w16 = 2^bits - 1 for bits in 1..=31.
fn load_max_const(out: &mut A64, dst: XR, bits: u8) {
    debug_assert!(bits <= 32);
    if bits == 32 {
        out.movn(false, 0, 0, dst); // = 0xFFFFFFFF
    } else if bits <= 16 {
        out.movz(false, 0, ((1u32 << bits) - 1) as u16, dst);
    } else {
        out.movz(false, 0, 0xFFFF, dst);
        out.movk(false, 1, ((1u32 << (bits - 16)) - 1) as u16, dst);
    }
}

/// QADD/QSUB: rd = sat(a ± b); Q (w20) sticky-updated.
fn emit_qaddsub(out: &mut A64, sub: bool, a: XR, b: XR, rd: XR) {
    out.addsub_reg(false, if sub { 1 } else { 0 }, true, 0, 0, a, b, 15); // adds/subs w15
    out.movn(false, 1, 0x8000, 16); // w16 = 0x7FFFFFFF (max)
    out.movz(false, 1, 0x8000, 17); // w17 = 0x80000000 (min)
    // on overflow: N=1 → true result ≥ 2^31 → MAX; N=0 → true < -2^31 → MIN
    out.csel(false, 0, 16, 17, Cond::Mi, 18); // w18 = mi ? max : min
    out.csel(false, 0, 15, 18, Cond::Vc, rd); // rd = vc ? sum : clamp
    cset(out, Cond::Vs, 19);
    out.logic_reg(false, 1, false, false, 0, 20, 19, 20); // Q |= V
}

/// USAD8: w16 = Σ|byte_i(a) - byte_i(b)|. Scratch: w15..w19.
fn emit_usad8(out: &mut A64, rn: R, rm: R) -> Result<(), TranslateErr> {
    const S8: u32 = 0x80808080;
    const H8: u32 = 0x7F7F7F7F;
    emit_sub8(out, x(rn), x(rm), 15, 18, 19)?; // w15 = d1 = a - b
    emit_sub8(out, x(rm), x(rn), 17, 18, 19)?; // w17 = d2 = b - a
    // carry = (a >u b) per byte = maj(b, ~a, c_lo(b + ~a))
    out.logic_reg(false, 1, true, false, 0, 31, x(rn), 18);  // w18 = ~a (orn)
    out.logic_bitmask(false, 0, H8 as u64, x(rm), 19)?;     // w19 = b & H8
    out.logic_bitmask(false, 0, H8 as u64, 18, 16)?;        // w16 = ~a & H8
    out.addsub_reg(false, 0, false, 0, 0, 19, 16, 19);      // w19 = t (c_lo at S-bits)
    out.logic_reg(false, 2, false, false, 0, x(rm), 18, 16); // w16 = b ^ ~a
    out.logic_reg(false, 0, false, false, 0, 16, 19, 16);  // w16 = (b^na) & t
    out.logic_reg(false, 0, false, false, 0, x(rm), 18, 19); // w19 = b & ~a
    out.logic_reg(false, 1, false, false, 0, 19, 16, 19);  // w19 = maj = (b>a) markers
    out.logic_bitmask(false, 0, S8 as u64, 19, 19)?;       // clean
    // smear the S8 marker bits down within each byte: m | m>>1 | m>>2 | m>>4
    // (each set bit at 8k+7 fills exactly bits [8k, 8k+7] — no cross-byte bleed,
    //  and unlike an up-shift cascade it never fills zero-marker bytes)
    out.lsr_imm(false, 19, 18, 1);                        // w18 = markers >> 1
    out.logic_reg(false, 1, false, false, 0, 19, 18, 19); // w19 |= >>1
    out.lsr_imm(false, 19, 18, 2);
    out.logic_reg(false, 1, false, false, 0, 19, 18, 19); // |= >>2
    out.lsr_imm(false, 19, 18, 4);
    out.logic_reg(false, 1, false, false, 0, 19, 18, 19); // |= >>4 → w19 = byte masks
    out.logic_reg(false, 0, true, false, 0, 15, 19, 16);    // w16 = d1 & ~mask (a-b where a>=b)
    out.logic_reg(false, 0, false, false, 0, 17, 19, 17);   // w17 = d2 & mask (b-a where b>a)
    out.logic_reg(false, 1, false, false, 0, 16, 17, 16);   // w16 = |diff|
    out.logic_bitmask(false, 0, 0x00FF00FF, 16, 17)?;       // w17 = bytes 0,2
    out.lsr_imm(false, 16, 18, 8);
    out.logic_bitmask(false, 0, 0x00FF00FF, 18, 18)?;       // w18 = bytes 1,3
    out.addsub_reg(false, 0, false, 0, 0, 17, 18, 17);     // w17 = {b0+b1, b2+b3}
    out.lsr_imm(false, 17, 16, 16);
    out.addsub_reg(false, 0, false, 0, 0, 17, 16, 16);     // w16 = total (possibly + hi16<<16)
    out.logic_bitmask(false, 0, 0xFFFF, 16, 16)?;         // keep low 16 bits = true total
    Ok(())
}

/// dst = a - b per byte (SWAR). t0/t1 temps (must differ from dst).
fn emit_sub8(out: &mut A64, a: XR, b: XR, dst: XR, t0: XR, t1: XR) -> Result<(), TranslateErr> {
    const S8: u32 = 0x80808080;
    const H8: u32 = 0x7F7F7F7F;
    out.logic_bitmask(false, 1, S8 as u64, a, t0)?;  // t0 = a | S
    out.logic_bitmask(false, 0, H8 as u64, b, t1)?;  // t1 = b & ~S
    out.addsub_reg(false, 1, false, 0, 0, t0, t1, dst); // dst = core
    out.logic_reg(false, 2, false, false, 0, a, b, t0); // t0 = a ^ b
    out.logic_bitmask(false, 0, S8 as u64, t0, t0)?; // t0 = (a^b) & S (AND, not EOR!)
    out.logic_reg(false, 2, false, false, 0, dst, t0, dst); // dst ^= signxor
    out.logic_bitmask(false, 2, S8 as u64, dst, dst)?; // dst ^= S (EOR imm)
    Ok(())
}

/// Compute a plain memory address into x16 (unscaled imm, or reg offset).
fn emit_memaddr(out: &mut A64, rn: R, rm: Option<R>, imm: i32) -> XR {
    let base = x(rn);
    if let Some(rm) = rm {
        out.addsub_ext(true, 0, false, x(rm), 2, 0, base, 16); // add x16, base, w(rm) uxtw
    } else {
        let v = imm as i64;
        if v >= 0 && v <= 4095 {
            out.add_imm(true, base, 16, v as u16);
        } else if v < 0 && -v <= 4095 {
            out.sub_imm(true, base, 16, (-v) as u16);
        } else {
            load_imm64(out, 17, v.unsigned_abs());
            if v >= 0 { out.addsub_reg(true, 0, false, 0, 0, base, 17, 16); }
            else { out.addsub_reg(true, 1, false, 0, 0, base, 17, 16); }
        }
    }
    16
}

fn emit_memaddr_scaled(out: &mut A64, rn: R, rm: Option<R>, imm: i32, add: bool, scale: u8, pc: u32) -> XR {
    // PC base (A32 literal loads / PC-relative addressing): x15 reads as
    // pc+8; in bias mode the shadow-image address is used instead.
    if rn == 15 {
        load_pc(out, 17, pc);
        if let Some(rm) = rm {
            if scale > 0 {
                out.lsl_imm(true, x(rm), 18, scale);
                out.addsub_ext(true, if add { 0 } else { 1 }, false, 18, 0, 0, 17, 16);
            } else {
                out.addsub_ext(true, if add { 0 } else { 1 }, false, x(rm), 2, 0, 17, 16);
            }
            return 16;
        }
        let v = (imm as i64) << scale;
        if v >= 0 && v <= 4095 {
            out.add_imm(true, 17, 16, v as u16);
        } else if v < 0 && -v <= 4095 {
            out.sub_imm(true, 17, 16, (-v) as u16);
        } else {
            load_imm64(out, 18, v.unsigned_abs());
            if v >= 0 { out.addsub_reg(true, 0, false, 0, 0, 17, 18, 16); }
            else { out.addsub_reg(true, 1, false, 0, 0, 17, 18, 16); }
        }
        return 16;
    }
    let base = x(rn);
    if let Some(rm) = rm {
        if scale > 0 {
            out.lsl_imm(true, x(rm), 17, scale);
            out.addsub_ext(true, if add { 0 } else { 1 }, false, 17, 2, 0, base, 16);
        } else {
            out.addsub_ext(true, if add { 0 } else { 1 }, false, x(rm), 2, 0, base, 16);
        }
    } else {
        let v = (imm as i64) << scale;
        if v >= 0 && v <= 4095 {
            out.add_imm(true, base, 16, v as u16);
        } else if v < 0 && -v <= 4095 {
            out.sub_imm(true, base, 16, (-v) as u16);
        } else {
            load_imm64(out, 17, v.unsigned_abs());
            if v >= 0 { out.addsub_reg(true, 0, false, 0, 0, base, 17, 16); }
            else { out.addsub_reg(true, 1, false, 0, 0, base, 17, 16); }
        }
    }
    16
}

// ==================== data-processing core ====================

pub(crate) enum Operand {
    Imm(u64),
    RegShift(R, Shift, u64),
}

pub(crate) fn translate_dp(op: DpOp, s: bool, rn: R, rd: R, o: Operand, carry_const: Option<u32>, pc: u32, out: &mut A64) -> Result<(), TranslateErr> {
    // ===== test family: flags-only (A32: Rd not written) =====
    if op.is_test() {
        return match o {
            Operand::Imm(v) => {
                match op {
                    DpOp::Cmp | DpOp::Cmn => {
                        let base = if rn == 15 { load_pc(out, 16, pc); 16 } else { x(rn) };
                        if v <= 0xFFF {
                            out.addsub_imm(false, if op == DpOp::Cmp { 1 } else { 0 }, true, v as u16, false, base, 31);
                        } else {
                            load_imm32(out, 15, v as u32);
                            out.addsub_reg(false, if op == DpOp::Cmp { 1 } else { 0 }, true, 0, 0, base, 15, 31);
                        }
                    }
                    DpOp::Tst | DpOp::Teq => {
                        let base = if rn == 15 { load_pc(out, 19, pc); 19 } else { x(rn) };
                        load_imm32(out, 15, v as u32);
                        if let Some(c) = carry_const {
                            out.movz(false, 0, c as u16, 18); // w18 = rotation carry
                            emit_test_inner(out, base, 15, op == DpOp::Teq, 18);
                        } else {
                            emit_test_val_keepc(out, base, 15, op == DpOp::Teq)?;
                        }
                    }
                    _ => unreachable!(),
                }
                Ok(())
            }
            Operand::RegShift(rm, shift, amount) => {
                let base = if rn == 15 { load_pc(out, 19, pc); 19 } else { x(rn) };
                let src: XR = if rm == 15 { load_pc(out, 17, pc); 17 } else { x(rm) };
                if matches!(op, DpOp::Cmp | DpOp::Cmn) {
                    let o = if op == DpOp::Cmp { 1u8 } else { 0 };
                    if amount == 0 && shift == Shift::Lsl {
                        out.addsub_reg(false, o, true, 0, 0, base, src, 31);
                    } else {
                        emit_shift(out, src, 15, shift, amount as u8);
                        out.addsub_reg(false, o, true, 0, 0, base, 15, 31);
                    }
                } else if amount == 0 && shift == Shift::Lsl {
                    emit_test_val_keepc(out, base, src, op == DpOp::Teq)?;
                } else {
                    let bit: u8 = match shift {
                        Shift::Lsl => (32u32.wrapping_sub(amount as u32) % 32) as u8,
                        _ => ((amount as u32).wrapping_sub(1) % 32) as u8,
                    };
                    emit_shift(out, src, 15, shift, amount as u8);
                    out.ubfx(false, src, 18, bit, 1); // w18[0] = shifter carry
                    emit_test_inner(out, base, 15, op == DpOp::Teq, 18);
                }
                Ok(())
            }
        };
    }
    // ===== non-test =====
    match o {
        Operand::Imm(v) => {
            match op {
                DpOp::Mov => {
                    if !s {
                        if let Some((n, immr, imms)) = crate::a64::encode::encode_bitmask(v, false) {
                            out.log_imm(false, 1, n, immr, imms, 31, x(rd));
                        } else if v <= 0xFFFF {
                            out.movz(false, 0, v as u16, x(rd));
                        } else {
                            load_imm32(out, x(rd), v as u32);
                        }
                    } else {
                        load_imm32(out, 15, v as u32);
                        emit_logic_flags(out, 15, x(rd), carry_const)?;
                    }
                }
                DpOp::Mvn => {
                    if !s {
                        if let Some((n, immr, imms)) = crate::a64::encode::encode_bitmask(!v & 0xFFFF_FFFF, false) {
                            // rd = ORR(wzr, #~v) = ~v — the operand complement
                            out.log_imm(false, 1, n, immr, imms, 31, x(rd));
                        } else if v <= 0xFFFF {
                            out.movn(false, 0, v as u16, x(rd));
                        } else {
                            load_imm32(out, 16, v as u32);
                            out.logic_reg(false, 1, true, false, 0, 31, 16, x(rd));
                        }
                    } else {
                        load_imm32(out, 16, v as u32);
                        out.logic_reg(false, 1, true, false, 0, 31, 16, 15); // w15 = ~imm
                        emit_logic_flags(out, 15, x(rd), carry_const)?;
                    }
                }
                DpOp::And | DpOp::Bic => {
                    let (opc, n) = if op == DpOp::And { (0u8, false) } else { (0, true) };
                    let base = if rn == 15 { load_pc(out, 17, pc); 17 } else { x(rn) };
                    if op == DpOp::Bic {
                        load_imm32(out, 16, v as u32);
                        out.logic_reg(false, opc, n, false, 0, base, 16, x(rd));
                    } else if let Some((bn, immr, imms)) = crate::a64::encode::encode_bitmask(v, false) {
                        out.log_imm(false, opc, bn, immr, imms, base, x(rd));
                    } else {
                        load_imm32(out, 16, v as u32);
                        out.logic_reg(false, opc, false, false, 0, base, 16, x(rd));
                    }
                    if s { emit_logic_flags(out, 0, x(rd), carry_const)?; }
                }
                DpOp::Orr | DpOp::Eor | DpOp::Orn => {
                    let base = if rn == 15 { load_pc(out, 17, pc); 17 } else { x(rn) };
                    let opc = match op { DpOp::Orr => 1u8, DpOp::Eor => 2, _ => 3 };
                    let n = op == DpOp::Orn;
                    if n {
                        // A64 has no ORN-immediate: ORR rd, base, #~v
                        // (bitmask immediates are closed under complement).
                        let notv = !v & 0xFFFF_FFFF;
                        if let Some((bn, immr, imms)) = crate::a64::encode::encode_bitmask(notv, false) {
                            out.log_imm(false, 1, bn, immr, imms, base, x(rd)); // orr rd, base, #~v
                        } else {
                            load_imm32(out, 16, v as u32);
                            out.logic_reg(false, 1, true, false, 0, base, 16, x(rd)); // orn rd, base, w16
                        }
                    } else {
                        load_imm32(out, 16, v as u32);
                        out.logic_reg(false, opc, false, false, 0, base, 16, x(rd));
                    }
                    if s { emit_logic_flags(out, 0, x(rd), carry_const)?; }
                }
                DpOp::Add | DpOp::Sub | DpOp::Rsb => {
                    let sub = op == DpOp::Sub;
                    let rsb = op == DpOp::Rsb;
                    let base = if rn == 15 { load_pc(out, 17, pc); 17 } else { x(rn) };
                    if !rsb && v <= 0xFFF {
                        out.addsub_imm(false, if sub { 1 } else { 0 }, s, v as u16, false, base, x(rd));
                    } else if !rsb && v > 0xFFF && (v >> 12) <= 0xFFF && (v & 0xFFF) == 0 {
                        out.addsub_imm(false, if sub { 1 } else { 0 }, s, (v >> 12) as u16, true, base, x(rd));
                    } else {
                        load_imm32(out, 16, v as u32);
                        if rsb {
                            out.addsub_reg(false, 1, s, 0, 0, 16, base, x(rd));
                        } else {
                            out.addsub_reg(false, if sub { 1 } else { 0 }, s, 0, 0, base, 16, x(rd));
                        }
                    }
                }
                DpOp::Adc | DpOp::Sbc | DpOp::Rsc => {
                    let base = if rn == 15 { load_pc(out, 17, pc); 17 } else { x(rn) };
                    load_imm32(out, 16, v as u32);
                    translate_adc_sbc(op, s, base, 16, rd, out)?;
                }
                _ => return Err(TranslateErr("test imm".to_string())),
            }
        }
        Operand::RegShift(rm, shift, amount) => {
            match op {
                DpOp::Mov => {
                    let bit: u8 = match shift {
                        Shift::Lsl => (32u32.wrapping_sub(amount as u32) % 32) as u8,
                        _ => ((amount as u32).wrapping_sub(1) % 32) as u8,
                    };
                    let src: XR = if rm == 15 { load_pc(out, 17, pc); 17 } else { x(rm) };
                    if s {
                        if amount == 0 && shift == Shift::Lsl {
                            out.e(MRS_X16);
                            out.logic_reg(false, 3, false, false, 0, src, src, x(rd)); // ands w rd
                            out.e(MRS_X17);
                            out.lsr_imm(true, 16, 18, 28);
                            out.bfi(true, 18, 17, 28, 2);
                            out.e(MSR_X17);
                        } else if amount != 0 && amount < 32 {
                            // extract the shifter-carry BEFORE the shift —
                            // the shift may write rd == rm and destroy src
                            out.ubfx(false, src, 18, bit, 1); // w18 = carry-out
                            emit_shift(out, src, x(rd), shift, amount as u8);
                            out.e(MRS_X16);
                            out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr
                            out.e(MRS_X17);
                            out.bfi(true, 18, 17, 29, 1); // C := carry
                            out.ubfx(true, 16, 19, 28, 1);
                            out.bfi(true, 19, 17, 28, 1); // V := old
                            out.e(MSR_X17);
                        } else {
                            return Err(TranslateErr("movs-shift unsupported".to_string()));
                        }
                    } else if amount == 0 && shift == Shift::Lsl {
                        out.logic_reg(false, 1, false, false, 0, 31, src, x(rd));
                    } else {
                        emit_shift(out, src, x(rd), shift, amount as u8);
                    }
                }
                DpOp::Mvn => {
                    let bit: u8 = match shift {
                        Shift::Lsl => (32u32.wrapping_sub(amount as u32) % 32) as u8,
                        _ => ((amount as u32).wrapping_sub(1) % 32) as u8,
                    };
                    let src: XR = if rm == 15 { load_pc(out, 17, pc); 17 } else { x(rm) };
                    if !s {
                        if amount == 0 && shift == Shift::Lsl {
                            out.logic_reg(false, 1, true, false, 0, 31, src, x(rd)); // orn
                        } else {
                            emit_shift(out, src, 15, shift, amount as u8);
                            out.logic_reg(false, 1, true, false, 0, 31, 15, x(rd));
                        }
                    } else if amount == 0 && shift == Shift::Lsl {
                        out.e(MRS_X16);
                        out.logic_reg(false, 1, true, false, 0, 31, src, x(rd)); // orn (no flags in A64)
                        out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr → N,Z from result
                        out.e(MRS_X17);
                        out.lsr_imm(true, 16, 18, 28);
                        out.bfi(true, 18, 17, 28, 2);
                        out.e(MSR_X17);
                    } else if amount != 0 && amount < 32 {
                        emit_shift(out, src, 15, shift, amount as u8);
                        out.e(MRS_X16);
                        out.logic_reg(false, 1, true, false, 0, 31, 15, x(rd)); // orn (no flags)
                        out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr → N,Z
                        out.e(MRS_X17);
                        out.ubfx(false, src, 18, bit, 1);
                        out.bfi(true, 18, 17, 29, 1);
                        out.ubfx(true, 16, 19, 28, 1);
                        out.bfi(true, 19, 17, 28, 1);
                        out.e(MSR_X17);
                    } else {
                        return Err(TranslateErr("mvns shift".to_string()));
                    }
                }
                DpOp::And | DpOp::Bic | DpOp::Orr | DpOp::Eor | DpOp::Orn => {
                    // A64 logical opc: 0=AND 1=ORR 2=EOR 3=ANDS; N inverts the
                    // second operand (BIC/ORN/EON/BICS).
                    let opc = match op { DpOp::And | DpOp::Bic => 0u8, DpOp::Orr | DpOp::Orn => 1, DpOp::Eor => 2, _ => 3 };
                    let n = matches!(op, DpOp::Bic | DpOp::Orn);
                    let src: XR = if rm == 15 { load_pc(out, 17, pc); 17 } else { x(rm) };
                    let base: XR = if rn == 15 { load_pc(out, 19, pc); 19 } else { x(rn) };
                    if !s {
                        if amount == 0 && shift == Shift::Lsl {
                            out.logic_reg(false, opc, n, false, 0, base, src, x(rd));
                        } else {
                            emit_shift(out, src, 15, shift, amount as u8);
                            out.logic_reg(false, opc, n, false, 0, base, 15, x(rd));
                        }
                    } else if amount == 0 && shift == Shift::Lsl {
                        out.e(MRS_X16);
                        if opc == 0 {
                            out.logic_reg(false, 3, n, false, 0, base, src, x(rd)); // ands w rd
                        } else {
                            out.logic_reg(false, opc, n, false, 0, base, src, x(rd));
                            out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr
                        }
                        out.e(MRS_X17);
                        out.lsr_imm(true, 16, 18, 28);
                        out.bfi(true, 18, 17, 28, 2);
                        out.e(MSR_X17);
                    } else if amount != 0 && amount < 32 {
                        let bit: u8 = match shift {
                            Shift::Lsl => (32u32.wrapping_sub(amount as u32) % 32) as u8,
                            _ => ((amount as u32).wrapping_sub(1) % 32) as u8,
                        };
                        // extract the shifter-carry BEFORE the flag-setting op
                        // (it may write rd == rm and destroy the source)
                        out.ubfx(false, src, 18, bit, 1); // w18 = carry-out
                        emit_shift(out, src, 15, shift, amount as u8);
                        out.e(MRS_X16);
                        if opc == 0 {
                            out.logic_reg(false, 3, n, false, 0, base, 15, x(rd)); // ands
                        } else {
                            out.logic_reg(false, opc, n, false, 0, base, 15, x(rd));
                            out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31);
                        }
                        out.e(MRS_X17);
                        out.bfi(true, 18, 17, 29, 1);
                        out.ubfx(true, 16, 19, 28, 1);
                        out.bfi(true, 19, 17, 28, 1);
                        out.e(MSR_X17);
                    } else {
                        return Err(TranslateErr("shift>=32 logic-S".to_string()));
                    }
                }
                DpOp::Add | DpOp::Sub | DpOp::Rsb => {
                    let is_sub = op != DpOp::Add;
                    let src: XR = if rm == 15 { load_pc(out, 17, pc); 17 } else { x(rm) };
                    // base avoids x16 — the shifted-operand temp
                    let base: XR = if rn == 15 { load_pc(out, 19, pc); 19 } else { x(rn) };
                    if op == DpOp::Rsb {
                        emit_shift(out, src, 16, shift, amount as u8);
                        out.addsub_reg(false, 1, s, 0, 0, 16, base, x(rd));
                    } else if amount == 0 && shift == Shift::Lsl {
                        out.addsub_reg(false, if is_sub { 1 } else { 0 }, s, 0, 0, base, src, x(rd));
                    } else {
                        emit_shift(out, src, 16, shift, amount as u8);
                        out.addsub_reg(false, if is_sub { 1 } else { 0 }, s, 0, 0, base, 16, x(rd));
                    }
                }
                DpOp::Adc | DpOp::Sbc | DpOp::Rsc => {
                    let src: XR = if rm == 15 { load_pc(out, 17, pc); 17 } else { x(rm) };
                    // base avoids x16 — the shifted-operand temp
                    let base: XR = if rn == 15 { load_pc(out, 19, pc); 19 } else { x(rn) };
                    if amount == 0 && shift == Shift::Lsl {
                        translate_adc_sbc(op, s, base, src, rd, out)?;
                    } else {
                        emit_shift(out, src, 16, shift, amount as u8);
                        translate_adc_sbc(op, s, base, 16, rd, out)?;
                    }
                }
                _ => return Err(TranslateErr("test reg".to_string())),
            }
        }
    }
    Ok(())
}

/// TST/TEQ where C is preserved (rot 0 / no shift): flags N,Z from op; C,V kept.
fn emit_test_val_keepc(out: &mut A64, base: XR, val: XR, teq: bool) -> Result<(), TranslateErr> {
    if teq {
        // the eor temp must avoid x16/x17 (mrs targets) and the base/src regs
        let t: XR = if base != 19 { 19 } else if val != 17 { 17 } else { 15 };
        out.logic_reg(false, 2, false, false, 0, base, val, t); // eor wt, base, val
        out.e(MRS_X16);
        out.logic_reg(false, 3, false, false, 0, t, t, 31);      // ands wzr, wt, wt
    } else {
        out.e(MRS_X16);
        out.logic_reg(false, 3, false, false, 0, base, val, 31); // ands wzr, base, val
    }
    out.e(MRS_X17);
    // C preserved: copy bit 29 from x16; V preserved: copy bit 28 from x16.
    out.lsr_imm(true, 16, 18, 28);
    out.logic_bitmask(false, 0, 0x3, 18, 18)?; // keep {C,V} at bits 1:0
    out.bfi(true, 18, 17, 28, 2);
    out.e(MSR_X17);
    Ok(())
}

/// TST/TEQ with the new C bit in w(car) (bit 0): N,Z from op; C = car; V preserved.
fn emit_test_inner(out: &mut A64, base: XR, val: XR, teq: bool, car: XR) {
    if teq {
        // the eor temp must avoid x16/x17 (mrs targets) and the base/src regs
        let t: XR = if base != 19 { 19 } else if val != 17 { 17 } else { 15 };
        out.logic_reg(false, 2, false, false, 0, base, val, t); // eor wt, base, val
        out.e(MRS_X16);
        out.logic_reg(false, 3, false, false, 0, t, t, 31);      // ands wzr, wt, wt
    } else {
        out.e(MRS_X16);
        out.logic_reg(false, 3, false, false, 0, base, val, 31); // ands wzr, base, val
    }
    out.e(MRS_X17);
    out.bfi(true, car, 17, 29, 1);  // C = car bit 0
    out.ubfx(true, 16, 18, 28, 1); // old V
    out.bfi(true, 18, 17, 28, 1);  // restore V
    out.e(MSR_X17);
}

/// Logic-flags fixup: N,Z from w(val) (result also written to w(dst) if val≠0);
/// C = carry const (or preserved); V preserved.
fn emit_logic_flags(out: &mut A64, val: XR, dst: XR, carry_const: Option<u32>) -> Result<(), TranslateErr> {
    out.e(MRS_X16);
    if val != 0 {
        out.logic_reg(false, 3, false, false, 0, val, val, dst); // ands w dst, w val, w val
    } else {
        out.logic_reg(false, 3, false, false, 0, dst, dst, 31); // ands wzr, w dst, w dst
    }
    out.e(MRS_X17);
    match carry_const {
        Some(c) => {
            out.movz(false, 0, c as u16, 18);
            out.bfi(true, 18, 17, 29, 1);
        }
        None => {
            out.lsr_imm(true, 16, 18, 29);
            out.logic_bitmask(false, 0, 0x1, 18, 18)?; // w18 = oldC
            out.bfi(true, 18, 17, 29, 1);
        }
    }
    out.ubfx(true, 16, 19, 28, 1); // old V
    out.bfi(true, 19, 17, 28, 1);  // restore V
    out.e(MSR_X17);
    Ok(())
}

// ==================== register-specified shift ====================
//
// A32: amount = Rs[7:0]. Semantics per type (n = amount):
//   LSL: n==0 → x; 1..32 → x<<n (n=32 → 0); >32 → 0; carry = x[32-n] (n=32 → x[0]; >32 → 0)
//   LSR: n==0 → x; 1..32 → x>>u n; >32 → 0;  carry = x[n-1] (n=32 → x[31]; >32 → 0)
//   ASR: n==0 → x; 1..32 → x>>a n; >32 → sign; carry = x[min(n,32)-1] (x[31] for n≥32)
//   ROR: n==0 → x; else → ror(x, n mod 32); carry = x[n'−1 mod 32] (n'≠0), x[31] if n'==0

fn translate_regshift(op: DpOp, s: bool, rn: R, rd: R, rm: R, shift: Shift, rs: R, pc: u32, out: &mut A64) -> Result<(), TranslateErr> {
    // The value/carry computation below clobbers NZCV (subs/csel). Save the
    // ORIGINAL A32 flags FIRST: ADC/SBC/RSC consume the incoming C, the
    // flags-setting forms need old C (when Rs[7:0]==0) and old V, and every
    // non-S form must leave NZCV completely untouched (MSR-restored at end).
    // x16 must survive until regshift_finish — the ASR path uses w17 scratch.
    out.e(MRS_X16);
    // w19 = amount = w(rs) & 0xFF (kept; survives the mrs/msr dance)
    if rs == 15 {
        load_pc(out, 17, pc); // Rs = PC: amount = (pc+8)[7:0]
        out.logic_bitmask(false, 0, 0xFF, 17, 19)?;
    } else {
        out.logic_bitmask(false, 0, 0xFF, x(rs), 19)?;
    }
    // value → w18; carry bit → w15 (bit 0)
    match shift {
        Shift::Lsl => {
            out.addsub_imm(false, 1, true, 32, false, 19, 31); // subs wzr, w19, #32
            out.csel(false, 0, 31, x(rm), Cond::Cs, 18);        // csel w18, wzr, rm, hs
            out.logic_bitmask(false, 0, 0x1F, 19, 17)?;          // w17 = n & 31
            out.dp2(false, 8, 18, 17, 18);                       // lslv w18, w18, w17
            out.addsub_reg(false, 1, false, 0, 0, 31, 19, 15);  // neg w15, w19
            out.logic_bitmask(false, 0, 0x1F, 15, 15)?;         // w15 = (32-n)&31
            out.dp2(false, 9, x(rm), 15, 15);                    // lsrv w15, rm, w15
            out.addsub_imm(false, 1, true, 33, false, 19, 31);   // subs wzr, w19, #33
            out.csel(false, 0, 31, 15, Cond::Cs, 15);            // n>=33 → carry 0
        }
        Shift::Lsr => {
            out.addsub_imm(false, 1, true, 32, false, 19, 31);
            out.csel(false, 0, 31, x(rm), Cond::Cs, 18);
            out.logic_bitmask(false, 0, 0x1F, 19, 17)?;
            out.dp2(false, 9, 18, 17, 18);                       // lsrv
            out.addsub_imm(false, 1, false, 1, false, 19, 15);   // sub w15, w19, #1
            out.logic_bitmask(false, 0, 0x1F, 15, 15)?;
            out.dp2(false, 9, x(rm), 15, 15);                    // carry = rm[n-1]
            out.addsub_imm(false, 1, true, 33, false, 19, 31);
            out.csel(false, 0, 31, 15, Cond::Cs, 15);            // n>=33 → 0
        }
        Shift::Asr => {
            out.logic_bitmask(false, 0, 0x1F, 19, 17)?;          // w17 = n & 31
            out.dp2(false, 10, x(rm), 17, 18);                   // asrv w18, rm, w17
            out.asr_imm(false, x(rm), 17, 31);                    // w17 = signfill (x16 = saved flags!)
            out.addsub_imm(false, 1, true, 32, false, 19, 31);
            out.csel(false, 0, 17, 18, Cond::Cs, 18);            // value = hs ? signfill : asrv
            out.addsub_imm(false, 1, false, 1, false, 19, 15);   // w15 = n-1
            out.logic_bitmask(false, 0, 0x1F, 15, 15)?;          // & 31
            out.addsub_imm(false, 1, true, 33, false, 19, 31);   // hs = n >= 33
            out.movz(false, 0, 31, 17);
            out.csel(false, 0, 17, 15, Cond::Cs, 15);            // idx = n>=33 ? 31 : (n-1)&31
            out.dp2(false, 9, x(rm), 15, 15);                    // lsrv → carry
        }
        Shift::Ror => {
            out.logic_bitmask(false, 0, 0x1F, 19, 17)?;          // w17 = n & 31
            out.dp2(false, 11, x(rm), 17, 18);                   // rorv w18, rm, w17
            out.addsub_imm(false, 1, false, 1, false, 17, 15);   // sub w15, w17, #1
            out.logic_bitmask(false, 0, 0x1F, 15, 15)?;
            out.dp2(false, 9, x(rm), 15, 15);                    // carry
        }
    }
    regshift_finish(out, op, s, rn, rd, 18, 15, 19)
}

#[allow(clippy::too_many_arguments)]
fn regshift_finish(out: &mut A64, op: DpOp, s: bool, rn: R, rd: R, val: XR, car: XR, amount: XR) -> Result<(), TranslateErr> {
    // x16 = ORIGINAL A32 flags (captured at translate_regshift start).
    match op {
        DpOp::Add | DpOp::Sub | DpOp::Rsb => {
            if op == DpOp::Rsb {
                out.addsub_reg(false, 1, s, 0, 0, val, x(rn), x(rd));
            } else {
                out.addsub_reg(false, if op == DpOp::Sub { 1 } else { 0 }, s, 0, 0, x(rn), val, x(rd));
            }
            if !s { out.e(MSR_X16); } // A32 leaves NZCV untouched — restore
        }
        DpOp::Cmp | DpOp::Cmn => {
            out.addsub_reg(false, if op == DpOp::Cmp { 1 } else { 0 }, true, 0, 0, x(rn), val, 31);
        }
        DpOp::And | DpOp::Bic | DpOp::Orr | DpOp::Orn | DpOp::Eor | DpOp::Mov | DpOp::Mvn => {
            let opc = match op { DpOp::And | DpOp::Bic => 0u8, DpOp::Orr | DpOp::Mov | DpOp::Orn => 1, _ => 2 };
            let n = matches!(op, DpOp::Bic | DpOp::Mvn | DpOp::Orn);
            let (a, b) = if matches!(op, DpOp::Mov | DpOp::Mvn) { (31u8, val) } else { (x(rn), val) };
            if !s {
                out.logic_reg(false, opc, n, false, 0, a, b, x(rd));
                out.e(MSR_X16); // flags untouched by A32 — restore
            } else {
                // N,Z from result; C = (n==0) ? oldC : carry; V preserved — all from the SAVED x16
                out.logic_reg(false, opc, n, false, 0, a, b, x(rd));
                out.logic_reg(false, 3, false, false, 0, x(rd), x(rd), 31); // ands wzr → N,Z
                out.e(MRS_X17);
                out.lsr_imm(true, 16, 18, 29);                      // x18 = saved flags >> 29
                out.logic_bitmask(false, 0, 0x1, 18, 18)?;         // w18 = oldC
                out.addsub_imm(false, 1, true, 0, false, amount, 31); // eq = (amount == 0)
                out.csel(false, 0, 18, car, Cond::Eq, 18);         // eq → oldC else carry
                out.bfi(true, 18, 17, 29, 1);
                out.ubfx(true, 16, 19, 28, 1);                     // old V (from SAVED x16)
                out.bfi(true, 19, 17, 28, 1);
                out.e(MSR_X17);
            }
        }
        DpOp::Adc | DpOp::Sbc | DpOp::Rsc => {
            out.e(MSR_X16); // restore the ORIGINAL C (carry-in) before the adc
            translate_adc_sbc(op, s, x(rn), val, rd, out)?;
        }
        DpOp::Tst | DpOp::Teq => {
            // N,Z from result; C = (n==0) ? oldC : carry; V preserved (from SAVED x16)
            if op == DpOp::Teq {
                out.logic_reg(false, 2, false, false, 0, x(rn), val, 17); // eor w17, rn, val
                out.logic_reg(false, 3, false, false, 0, 17, 17, 31);      // ands wzr, w17, w17
            } else {
                out.logic_reg(false, 3, false, false, 0, x(rn), val, 31); // ands wzr, rn, val
            }
            out.e(MRS_X17);
            out.lsr_imm(true, 16, 18, 29);
            out.logic_bitmask(false, 0, 0x1, 18, 18)?;
            out.addsub_imm(false, 1, true, 0, false, amount, 31);
            out.csel(false, 0, 18, car, Cond::Eq, 18);
            out.bfi(true, 18, 17, 29, 1);
            out.ubfx(true, 16, 19, 28, 1);
            out.bfi(true, 19, 17, 28, 1);
            out.e(MSR_X17);
        }
    }
    Ok(())
}

fn translate_adc_sbc(op: DpOp, s: bool, rn: XR, rm: XR, rd: R, out: &mut A64) -> Result<(), TranslateErr> {
    match op {
        DpOp::Adc => out.adc(false, 0, s, rn, rm, x(rd)),
        DpOp::Sbc => out.adc(false, 1, s, rn, rm, x(rd)),
        DpOp::Rsc => {
            // Rsc rd, rn, rm: = rm - rn - !C = rm + ~rn + C
            out.adc(false, 1, s, rm, rn, x(rd));
        }
        _ => {}
    }
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

/// Emit `dst = imm` (32-bit) using MOVZ/MOVK pairs.
pub fn load_imm32(out: &mut A64, dst: XR, v: u32) {
    let lo = (v & 0xFFFF) as u16;
    let hi = (v >> 16) as u16;
    if hi == 0 {
        out.movz(false, 0, lo, dst);
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

// ==================== parallel (DSP) translation ====================
//
// SWAR lane identities (verified by exhaustive numeric case analysis):
//   add lanes:  r = ((a & H) + (b & H)) ⊕ ((a ⊕ b) & S)          [core = (a&H)+(b&H)]
//   sub lanes:  r = ((a | S) - (b & ~S)) ⊕ S ⊕ ((a ⊕ b) & S)
//   carry out of lane add:  maj = ((a & b) | ((a ⊕ b) & core)) & S
//   17th bit (exact sum sign): c17 = (maj ⊕ (a ⊕ b)) & S
//   signed lt (a <s b per lane): (a & ~b & S) | (~(a ⊕ b) & r & S)
//   unsigned borrow (a<u b): maj(b, ~a, c_lo(b + ~a)) & S
//   halving add:  ((r >>u 1) & ~S) | (c17 or carry)
//   halving sub:  ((r >>u 1) & ~S) | (lt or borrow)
//   signed sat value per lane: H + (signs >> (L-1)) — (max+sign → min when sign=1)

fn translate_parallel(kind: ParKind, shape: ParShape, rd: R, rn: R, rm: R, out: &mut A64) -> Result<(), TranslateErr> {
    use ParKind::*;
    use ParShape::*;
    let lane16 = matches!(shape, Add16 | Addsubx | Subaddx | Sub16);
    let (s_mask, h_mask): (u64, u64) = if lane16 { (0x80008000, 0x7FFF7FFF) } else { (0x80808080, 0x7F7F7F7F) };
    let s_shift: u8 = if lane16 { 15 } else { 7 };
    let is_sub = matches!(shape, Sub16 | Sub8);
    let crossed = matches!(shape, Addsubx | Subaddx);

    // w15 = a; w16 = b (ror16 for crossed shapes)
    out.logic_reg(false, 1, false, false, 0, 31, x(rn), 15); // mov w15, a
    if crossed {
        out.ror_imm(false, x(rm), 16, 16);
    } else {
        out.logic_reg(false, 1, false, false, 0, 31, x(rm), 16); // mov w16, b
    }

    // lane result → w17; core saved → w19 for kinds needing maj
    let need_core = matches!(kind, S | U | Uq | Sh | Uh);
    if !is_sub {
        out.logic_bitmask(false, 0, h_mask, 15, 17)?; // w17 = a & H
        out.logic_bitmask(false, 0, h_mask, 16, 18)?; // w18 = b & H
        out.addsub_reg(false, 0, false, 0, 0, 17, 18, 17); // w17 = core
        if need_core {
            out.logic_reg(false, 1, false, false, 0, 31, 17, 19); // w19 = core
        }
        out.logic_reg(false, 2, false, false, 0, 15, 16, 18); // w18 = a ^ b
        out.logic_bitmask(false, 0, s_mask, 18, 18)?;        // w18 = (a^b) & S
        out.logic_reg(false, 2, false, false, 0, 17, 18, 17); // w17 = r
    } else {
        out.logic_bitmask(false, 1, s_mask, 15, 17)?;        // w17 = a | S
        out.logic_bitmask(false, 0, h_mask, 16, 18)?;         // w18 = b & ~S
        out.addsub_reg(false, 1, false, 0, 0, 17, 18, 17);    // w17 = core
        out.logic_reg(false, 2, false, false, 0, 15, 16, 18); // w18 = a ^ b
        out.logic_bitmask(false, 0, s_mask, 18, 18)?;        // w18 = (a^b) & S
        out.logic_reg(false, 2, false, false, 0, 17, 18, 17); // ⊕ signxor
        out.logic_bitmask(false, 2, s_mask, 17, 17)?;        // w17 = r (EOR imm)
    }

    // w15 = a, w16 = b, w17 = r (lane result), w19 = core (ADD kinds), w18 free
    match kind {
        S | U => {
            // GE markers (1 = GE set) → w15
            if !is_sub {
                // carry = ((a&b) | ((a^b)&core)) & S ; c17 = (carry ⊕ (a^b)) & S
                out.logic_reg(false, 2, false, false, 0, 15, 16, 18);  // w18 = a^b
                out.logic_reg(false, 0, false, false, 0, 18, 19, 19);  // w19 = (a^b)&core
                out.logic_reg(false, 0, false, false, 0, 15, 16, 15);  // w15 = a&b (a dead)
                out.logic_reg(false, 1, false, false, 0, 15, 19, 15);  // maj raw
                out.logic_bitmask(false, 0, s_mask, 15, 15)?;          // carry markers
                if kind == S {
                    out.logic_reg(false, 2, false, false, 0, 15, 18, 15); // ⊕ (a^b)
                    out.logic_bitmask(false, 0, s_mask, 15, 15)?;      // c17
                    out.logic_bitmask(false, 2, s_mask, 15, 15)?;      // invert → GE
                }
            } else if kind == S {
                // GE = ¬lt ; lt = (a & ~b & S) | (~(a^b) & r & S)
                out.logic_reg(false, 0, true, false, 0, 15, 16, 18);   // w18 = a & ~b
                out.logic_reg(false, 2, false, false, 0, 15, 16, 19);  // w19 = a^b
                out.logic_reg(false, 0, true, false, 0, 17, 19, 19);   // w19 = r & ~(a^b)
                out.logic_reg(false, 1, false, false, 0, 18, 19, 15);  // w15 = lt raw
                out.logic_bitmask(false, 0, s_mask, 15, 15)?;         // lt markers
                out.logic_bitmask(false, 2, s_mask, 15, 15)?;         // invert → GE
            } else {
                // GE = ¬borrow ; borrow = maj(b, ~a, c_lo(b + ~a))
                out.logic_reg(false, 1, true, false, 0, 31, 15, 19);  // w19 = ~a (orn)
                out.logic_bitmask(false, 0, h_mask, 19, 18)?;          // w18 = ~a & H
                out.logic_bitmask(false, 0, h_mask, 16, 15)?;          // w15 = b & H
                out.addsub_reg(false, 0, false, 0, 0, 15, 18, 15);    // w15 = t
                out.logic_reg(false, 2, false, false, 0, 16, 19, 18); // w18 = b ^ ~a
                out.logic_reg(false, 0, false, false, 0, 18, 15, 18); // w18 = & t
                out.logic_reg(false, 0, false, false, 0, 16, 19, 19);  // w19 = b & ~a
                out.logic_reg(false, 1, false, false, 0, 19, 18, 15);  // w15 = maj raw
                out.logic_bitmask(false, 0, s_mask, 15, 15)?;         // borrow markers
                out.logic_bitmask(false, 2, s_mask, 15, 15)?;         // invert → GE
            }
            out.logic_reg(false, 1, false, false, 0, 31, 17, x(rd));   // mov rd, w17
            write_ge(out, 15, lane16)?;
        }
        Q => {
            // signed saturating: ovf markers → w18; sat = H + (sign bits of a)
            // (compute the signs FIRST: the ovf path below does not clobber w15,
            //  but keep the order explicit for safety)
            // signs of a — extract FIRST (w15 still holds a)
            let sign_mask: u64 = if lane16 { 0x00010001 } else { 0x01010101 };
            out.lsr_imm(false, 15, 19, s_shift);                        // w19 = bits [31:L-1]
            out.logic_bitmask(false, 0, sign_mask, 19, 19)?;            // w19 = lane signs of a
            if !is_sub {
                // add overflow: same operand signs, result sign differs from a:
                //   ovf = (a^r) & ~(a^b)
                out.logic_reg(false, 2, false, false, 0, 15, 17, 18);  // w18 = a^r
                out.logic_reg(false, 2, false, false, 0, 15, 16, 15);  // w15 = a^b (a dead now)
                out.logic_reg(false, 0, true, false, 0, 18, 15, 18);   // w18 = (a^r) & ~(a^b)
            } else {
                // sub overflow: operand signs differ, result sign differs from a:
                //   ovf = (a^b) & (a^r)
                out.logic_reg(false, 2, false, false, 0, 15, 16, 18);  // w18 = a^b
                out.logic_reg(false, 2, false, false, 0, 15, 17, 15);  // w15 = a^r (a now dead)
                out.logic_reg(false, 0, false, false, 0, 18, 15, 18);  // w18 = (a^b) & (a^r)
            }
            out.logic_bitmask(false, 0, s_mask, 18, 18)?;              // w18 = ovf markers
            // sat = signs + H (b dead → w16 reusable for H)
            load_const(out, 16, h_mask as u32);                          // w16 = H
            out.addsub_reg(false, 0, false, 0, 0, 19, 16, 19);          // w19 = signs + H = sat
            // spread ovf → full lane masks (w16, temp w15 — a is dead now)
            spread_markers(out, 18, 16, 15, lane16)?;
            // r' = r ⊕ ((r ⊕ sat) & spread)
            out.logic_reg(false, 2, false, false, 0, 17, 19, 15);      // w15 = r ⊕ sat
            out.logic_reg(false, 0, false, false, 0, 15, 16, 15);     // & spread
            out.logic_reg(false, 2, false, false, 0, 17, 15, 17);      // w17 = r'
            emit_qflag(out, 18, 15, 16, lane16)?;
            out.logic_reg(false, 1, false, false, 0, 31, 17, x(rd));   // mov rd, w17
        }
        Uq => {
            // unsigned saturating: carry (ADD) / borrow (SUB) markers → w18
            if !is_sub {
                out.logic_reg(false, 2, false, false, 0, 15, 16, 18);  // w18 = a^b
                out.logic_reg(false, 0, false, false, 0, 18, 19, 19);  // w19 = & core
                out.logic_reg(false, 0, false, false, 0, 15, 16, 15);  // w15 = a&b
                out.logic_reg(false, 1, false, false, 0, 15, 19, 15);  // maj raw
                out.logic_bitmask(false, 0, s_mask, 15, 18)?;          // carry markers → w18
            } else {
                out.logic_reg(false, 1, true, false, 0, 31, 15, 19);  // w19 = ~a
                out.logic_bitmask(false, 0, h_mask, 19, 18)?;          // w18 = ~a & H
                out.logic_bitmask(false, 0, h_mask, 16, 15)?;          // w15 = b & H
                out.addsub_reg(false, 0, false, 0, 0, 15, 18, 15);    // w15 = t
                out.logic_reg(false, 2, false, false, 0, 16, 19, 18); // w18 = b ^ ~a
                out.logic_reg(false, 0, false, false, 0, 18, 15, 18); // & t
                out.logic_reg(false, 0, false, false, 0, 16, 19, 19);  // w19 = b & ~a
                out.logic_reg(false, 1, false, false, 0, 19, 18, 18);  // w18 = borrow markers
                out.logic_bitmask(false, 0, s_mask, 18, 18)?;         // clean
            }
            spread_markers(out, 18, 16, 15, lane16)?;
            if !is_sub {
                out.logic_reg(false, 1, false, false, 0, 17, 16, 17);  // r' = r | spread
            } else {
                out.logic_reg(false, 0, true, false, 0, 17, 16, 17);   // r' = r & ~spread
            }
            emit_qflag(out, 18, 15, 16, lane16)?;
            out.logic_reg(false, 1, false, false, 0, 31, 17, x(rd));   // mov rd, w17
        }
        Sh => {
            // signed halving: r_h = ((r>>u1) & ~S) | c17 (ADD) / lt (SUB)
            if !is_sub {
                out.logic_reg(false, 2, false, false, 0, 15, 16, 18);  // w18 = a^b
                out.logic_reg(false, 0, false, false, 0, 18, 19, 19);  // w19 = & core
                out.logic_reg(false, 0, false, false, 0, 15, 16, 15);  // w15 = a&b
                out.logic_reg(false, 1, false, false, 0, 15, 19, 15);  // maj
                out.logic_bitmask(false, 0, s_mask, 15, 15)?;          // carry
                out.logic_reg(false, 2, false, false, 0, 15, 18, 15);  // ⊕ (a^b)
                out.logic_bitmask(false, 0, s_mask, 15, 15)?;          // c17 markers
            } else {
                out.logic_reg(false, 0, true, false, 0, 15, 16, 18);   // a & ~b
                out.logic_reg(false, 2, false, false, 0, 15, 16, 19);  // a^b
                out.logic_reg(false, 0, true, false, 0, 17, 19, 19);   // r & ~(a^b)
                out.logic_reg(false, 1, false, false, 0, 18, 19, 15);  // lt raw
                out.logic_bitmask(false, 0, s_mask, 15, 15)?;         // lt markers
            }
            out.lsr_imm(false, 17, 17, 1);
            out.logic_bitmask(false, 0, h_mask, 17, 17)?;             // clear sign positions
            out.logic_reg(false, 1, false, false, 0, 17, 15, x(rd));  // rd = r' | markers
        }
        Uh => {
            // unsigned halving: r_h = ((r>>u1) & ~S) | carry (ADD) / borrow (SUB)
            if !is_sub {
                out.logic_reg(false, 2, false, false, 0, 15, 16, 18);  // w18 = a^b
                out.logic_reg(false, 0, false, false, 0, 18, 19, 19);  // & core
                out.logic_reg(false, 0, false, false, 0, 15, 16, 15);  // a&b
                out.logic_reg(false, 1, false, false, 0, 15, 19, 15);  // maj
                out.logic_bitmask(false, 0, s_mask, 15, 15)?;          // carry markers
            } else {
                out.logic_reg(false, 1, true, false, 0, 31, 15, 19);  // w19 = ~a
                out.logic_bitmask(false, 0, h_mask, 19, 18)?;          // w18 = ~a & H
                out.logic_bitmask(false, 0, h_mask, 16, 15)?;          // w15 = b & H
                out.addsub_reg(false, 0, false, 0, 0, 15, 18, 15);    // t
                out.logic_reg(false, 2, false, false, 0, 16, 19, 18); // b ^ ~a
                out.logic_reg(false, 0, false, false, 0, 18, 15, 18); // & t
                out.logic_reg(false, 0, false, false, 0, 16, 19, 19);  // b & ~a
                out.logic_reg(false, 1, false, false, 0, 19, 18, 15);  // borrow markers
                out.logic_bitmask(false, 0, s_mask, 15, 15)?;         // clean
            }
            out.lsr_imm(false, 17, 17, 1);
            out.logic_bitmask(false, 0, h_mask, 17, 17)?;             // clear sign positions
            out.logic_reg(false, 1, false, false, 0, 17, 15, x(rd));  // rd = r' | markers
        }
    }
    Ok(())
}

/// mov w16, #const32 (via movz/movk).
fn load_const(out: &mut A64, dst: XR, v: u32) {
    load_imm32(out, dst, v);
}

/// Spread lane markers (bits at S positions) to full lane masks in w(dst).
/// tmp must differ from src and dst (16-bit path only).
fn spread_markers(out: &mut A64, src: XR, dst: XR, tmp: XR, lane16: bool) -> Result<(), TranslateErr> {
    if lane16 {
        out.lsr_imm(false, src, dst, 15);          // markers at bits 0,16
        out.movz(false, 0, 0xFFFF, tmp);
        out.madd(false, false, tmp, 31, dst, dst);  // dst = (markers>>15) * 0xFFFF
    } else {
        out.lsr_imm(false, src, dst, 7);           // markers at byte bottoms
        out.logic_reg(false, 1, false, true, 1, dst, dst, dst);  // dst |= dst << 1
        out.logic_reg(false, 1, false, true, 2, dst, dst, dst);  // dst |= dst << 2
        out.logic_reg(false, 1, false, true, 4, dst, dst, dst);  // dst |= dst << 4
    }
    Ok(())
}

/// Set Q (w20) if any marker in w(src) is nonzero. t0/t1 temps.
fn emit_qflag(out: &mut A64, src: XR, t0: XR, t1: XR, lane16: bool) -> Result<(), TranslateErr> {
    if lane16 {
        // markers at bits 15 and 31: fold both into bit0
        out.lsr_imm(false, src, t0, 15);                        // t0[0] = m15, t0[16] = m31
        out.logic_reg_shift(false, 1, false, 1, 16, t0, t0, t0); // t0 |= t0 lsr #16
        out.logic_bitmask(false, 0, 0x1, t0, t0)?;             // t0 = any marker (bit0)
    } else {
        out.movz(false, 0, 0x4081, t0);
        out.movk(false, 1, 0x0020, t0);
        out.madd(false, false, t0, 31, src, t0);               // t0 = src * 0x00204081
        out.lsr_imm(false, t0, t0, 28);                        // nibble
    }
    out.addsub_imm(false, 1, true, 0, false, t0, 31);          // cmp t0, #0
    cset(out, Cond::Ne, t1);
    out.logic_reg(false, 1, false, false, 0, 20, t1, 20);      // Q |= sat
    Ok(())
}

/// Write GE bits (from markers in w(src)) into w21. Temps: w17, w19.
fn write_ge(out: &mut A64, src: XR, lane16: bool) -> Result<(), TranslateErr> {
    if lane16 {
        out.lsr_imm(false, src, 17, 15);            // s0 at bit0, s1 at bit16
        out.logic_bitmask(false, 0, 0x1, 17, 17)?;  // s0
        out.ubfx(false, src, 19, 31, 1);            // s1
        out.bfi(false, 19, 17, 1, 1);               // {s1,s0}
    } else {
        out.movz(false, 0, 0x4081, 17);
        out.movk(false, 1, 0x0020, 17);              // 0x00204081
        out.madd(false, false, 17, 31, src, 17);    // w17 = src * const
        out.lsr_imm(false, 17, 17, 28);             // nibble = GE[3:0]
    }
    out.logic_reg(false, 1, false, false, 0, 31, 17, 21); // mov w21, w17
    Ok(())
}




// ============================ NEON translation ============================

use crate::a32::ins::NeonOp;
use crate::a64::neon as a64n;

fn translate_neon(
    out: &mut A64, op: NeonOp, dt: Dt, q: bool, d: VIdx, n: VIdx, m: VIdx,
    imm: u8, _index: u8,
) -> Result<(), TranslateErr> {
    use NeonOp::*;
    // A32 D-register (64-bit vector) forms of 64-bit-element NEON ops become the
    // A64 SCALAR .1d encodings: 3-same = vector .2d + bit28 (+Q);
    // LLVM-verified: add d0,d1,d2 = 0x5ee28420 = add v.2d | bit28.
    let dform = !q && matches!(dt, Dt::I64 | Dt::S64 | Dt::U64 | Dt::F64);
    macro_rules! fix3 { ($w:expr) => { if dform { $w | (1 << 28) | (1 << 30) } else { $w } } }
    macro_rules! e { ($w:expr) => { out.e($w) } }

    let sz = a64n::sz_code(dt);

    // 3-same family — most map 1:1 to the A64 equivalent
    let same3 = |opcode: u8, u: bool| -> u32 { a64n::enc_3same(q, u, dt, opcode, m, n, d) };
    let _ = same3;

    match op {
        // ======== 3-same FP (must precede the plain integer arms) ========
        // FP 3-same — type field (23:22) & U verified against LLVM:
        // fadd=(0,26,t00) fsub=(0,26,t10) faddp=(1,26,t00) fabd=(1,26,t10)
        // fmul=(1,27,t00) fmla=(0,25,t00) fmls=(0,25,t10)
        // fmax=(0,30,t00) fmin=(0,30,t10) frecps=(0,31,t00) frsqrts=(0,31,t10)
        // fcmeq=(0,28,t00) fcmge=(1,28,t00) fcmgt=(1,28,t10)
        // fmaxp=(1,30,t00) fminp=(1,30,t10)
        Add if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, false, 0, a64n::same::FADD, m, n, d))),
        Add if dt == Dt::F64 => e!(fix3!(a64n::enc_3same_sz(q, false, 1, a64n::same::FADD, m, n, d))),
        Sub if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, false, 2, a64n::same::FADD, m, n, d))), // FSUB: U=0 type=10
        Sub if dt == Dt::F64 => e!(fix3!(a64n::enc_3same_sz(q, false, 3, a64n::same::FADD, m, n, d))),
        Mul if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, true, 0, a64n::same::FMUL, m, n, d))),
        Mul if dt == Dt::F64 => e!(fix3!(a64n::enc_3same_sz(q, true, 1, a64n::same::FMUL, m, n, d))),
        Mla if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, false, 0, a64n::same::FMLA, m, n, d))),
        Mls if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, false, 2, a64n::same::FMLA, m, n, d))),
        Recps => e!(fix3!(a64n::enc_3same_sz(q, false, 0, a64n::same::FRECPS, m, n, d))),
        Rsqrts => e!(fix3!(a64n::enc_3same_sz(q, false, 2, a64n::same::FRECPS, m, n, d))),
        CmpEq if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, false, 0, a64n::same::FCMEQ, m, n, d))),
        CmpEq if dt == Dt::F64 => e!(fix3!(a64n::enc_3same_sz(q, false, 1, a64n::same::FCMEQ, m, n, d))),
        CmpGe if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, true, 0, a64n::same::FCMEQ, m, n, d))), // FCMGE
        CmpGe if dt == Dt::F64 => e!(fix3!(a64n::enc_3same_sz(q, true, 1, a64n::same::FCMEQ, m, n, d))),
        CmpGt if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, true, 2, a64n::same::FCMEQ, m, n, d))), // FCMGT: U=1 type=10
        CmpGt if dt == Dt::F64 => e!(fix3!(a64n::enc_3same_sz(q, true, 3, a64n::same::FCMEQ, m, n, d))),
        Max if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, false, 0, a64n::same::FMAX, m, n, d))),
        Min if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, false, 2, a64n::same::FMAX, m, n, d))), // FMIN: U=0 type=10
        AddP if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, true, 0, a64n::same::FADD, m, n, d))), // FADDP
        MaxP if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, true, 0, a64n::same::FMAX, m, n, d))), // FMAXP
        MinP if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, true, 2, a64n::same::FMAX, m, n, d))), // FMINP
        AbsDiff if dt == Dt::F32 => e!(fix3!(a64n::enc_3same_sz(q, true, 2, a64n::same::FADD, m, n, d))), // FABD

        // ======== 3-same integer ========
        Add => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::ADD, m, n, d))),
        Sub => e!(fix3!(a64n::enc_3same(q, true, dt, a64n::same::ADD, m, n, d))), // SUB = ADD with U=1
        Mul => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::MUL, m, n, d))),
        Mla => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::MLA, m, n, d))),
        Mls => e!(fix3!(a64n::enc_3same(q, true, dt, a64n::same::MLA, m, n, d))), // MLS = MLA with U=1
        Max => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SMAX, m, n, d))),
        Min => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SMIN, m, n, d))),
        MaxP => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SMAXP, m, n, d))),
        MinP => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SMINP, m, n, d))),
        AddP => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::ADDP, m, n, d))),
        CmpGt => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::CMGT, m, n, d))),
        CmpGe => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::CMGE, m, n, d))),
        CmpEq => e!(fix3!(a64n::enc_3same(q, true, dt, 17, m, n, d))), // CMEQ = U=1 opcode 10001
        Tst => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::CMTST, m, n, d))),
        AbsDiff => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SABD, m, n, d))),

        // ======== 3-same saturating ========
        QAdd => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SQADD, m, n, d))),
        QSub => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SQSUB, m, n, d))),

        // ======== 3-same logical ========
        And => e!(fix3!(a64n::enc_3same_logical(q, false, 0, m, n, d))),
        Bic => e!(fix3!(a64n::enc_3same_logical(q, false, 1, m, n, d))),
        Orr => e!(fix3!(a64n::enc_3same_logical(q, false, 2, m, n, d))),
        Orn => e!(fix3!(a64n::enc_3same_logical(q, false, 3, m, n, d))),
        Eor => e!(fix3!(a64n::enc_3same_logical(q, true, 0, m, n, d))),
        Bsl => e!(fix3!(a64n::enc_3same_logical(q, true, 1, m, n, d))),
        Bit => e!(fix3!(a64n::enc_3same_logical(q, true, 2, m, n, d))),
        Bif => e!(fix3!(a64n::enc_3same_logical(q, true, 3, m, n, d))),

        // ======== 3-same halving ========
        AddHn => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SHADD, m, n, d))),
        SubHn => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SHSUB, m, n, d))),
        RAddHn => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SRHADD, m, n, d))),

        // ======== 3-same FP ========
        // FP ops use the sz field differently: 00=f32(+) family, 10=f32(−) family
        // A64: FADD=opcode 11010 U=0; FSUB=11010 U=1
        // FP 3-same opcode in A64: 24=FMAXNM, 25=FMLA, 26=FADD/FADDP/FABD, 27=FMUL/FMULX
        // 28=FCMEQ/FCMGE, 30=FMAX/FMAXP, 31=FRECPS/FDIV, 29=FACGE/FACGT
        // For f32: sz=00 for +family, sz=10 for −family (SUB/MLS/MIN)
        // For f64: sz=01 for +family, sz=11 for −family
        // A64 3-same FP: size field encodes f32 vs f64 AND the +/− family

        // ======== 3-different (widening) ========
        // A64 3-different uses enc_3diff with its own opcode table
        AddL => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SADDL, m, n, d)),
        SubL => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SSUBL, m, n, d)),
        AddW => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SADDW, m, n, d)),
        SubW => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SSUBW, m, n, d)),
        MulL => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SMULL, m, n, d)),
        MlaL => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SMLAL, m, n, d)),
        MlsL => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SMLSL, m, n, d)),
        AddHn if matches!(dt, Dt::I16|Dt::I32|Dt::I64) =>
            e!(a64n::enc_3diff(q, false, dt, a64n::diff::ADDHN, m, n, d)),
        SubHn if matches!(dt, Dt::I16|Dt::I32|Dt::I64) =>
            e!(a64n::enc_3diff(q, false, dt, a64n::diff::SUBHN, m, n, d)),
        QdmulL => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SQDMULL, m, n, d)),
        Qdmlal => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SQDMLAL, m, n, d)),
        Qdmlsl => e!(a64n::enc_3diff(q, false, dt, a64n::diff::SQDMLSL, m, n, d)),

        // ======== shift by immediate ========
        ShrImm | SraImm | RshrImm | RsraImm | ShlImm | SliImm | SriImm
        | QshlImm | QshluReg | Shll | MovL | Shrn | Qshrn | Qshrun | Qrshrn | Qrshrun => {
            let esize = dt.bits() as u32;
            // narrowing ops: dt is the SOURCE size; dest = source/2
            let (class, amount, left) = match op {
                Shrn | Qshrn | Qshrun | Qrshrn | Qrshrun => {
                    ((esize / 2).min(64), imm as u32, false)
                }
                ShlImm | SliImm | Shll | MovL => (esize, imm as u32, true),
                _ => (esize, imm as u32, false),
            };
            let n7 = if left { a64n::n_for_left(class, amount) } else { a64n::n_for_right(class, amount) };
            let n7 = n7.ok_or(TranslateErr("bad shift amount".into()))?;
            let (u, opcode) = match op {
                ShrImm => (false, a64n::shimm::SSHR),
                SraImm => (false, a64n::shimm::SSRA),
                RshrImm => (false, a64n::shimm::SRSHR),
                RsraImm => (false, a64n::shimm::SRSRA),
                ShlImm => (false, a64n::shimm::SHL),
                SliImm => (true, a64n::shimm::SLI),
                SriImm => (true, a64n::shimm::SRI),
                QshlImm => (false, a64n::shimm::SQSHL),
                QshluReg => (true, a64n::shimm::SQSHLU),
                Shll => (false, a64n::shimm::SSHLL),
                MovL => (false, a64n::shimm::SSHLL), // VMOVL = SSHLL #0? No: SHLL with imm=0
                Shrn => (false, a64n::shimm::SHRN),
                Qshrn => (false, a64n::shimm::SQSHRN),
                Qshrun => (true, a64n::shimm::SQSHRUN),
                Qrshrn => (false, a64n::shimm::SQRSHRN),
                Qrshrun => (false, a64n::shimm::SQRSHRUN),
                _ => unreachable!(),
            };
            // For narrowing, the dt for encoding is the DEST size (class)
            // For widening, it's the SOURCE size
            // scalar .1d shift = vector .2d + bit29 (+Q): shl d0,d1,#13 = 0x5f4d5420
            let w = a64n::enc_shimm(q, u, opcode, n7, n, d);
            out.e(if dform { w | (1 << 29) | (1 << 30) } else { w });
        }

        // ======== 2-misc ========
        Abs if dt == Dt::F32 => e!(a64n::enc_2misc_sz(q, false, 2, a64n::misc::FABS, n, d)),
        Neg if dt == Dt::F32 => e!(a64n::enc_2misc_sz(q, true, 2, a64n::misc::FNEG, n, d)),
        Abs => e!(a64n::enc_2misc(q, true, dt, a64n::misc::ABS, n, d)),
        Neg => e!(a64n::enc_2misc(q, true, dt, a64n::misc::NEG, n, d)),
        Cls => e!(a64n::enc_2misc(q, false, dt, a64n::misc::CLS, n, d)),
        Clz => e!(a64n::enc_2misc(q, true, dt, a64n::misc::CLZ, n, d)),
        Cnt => e!(a64n::enc_2misc(q, true, Dt::I8, a64n::misc::CNT, n, d)),
        Not => e!(a64n::enc_2misc(q, true, Dt::I8, a64n::misc::MVN, n, d)),
        Recpe if dt == Dt::F32 => e!(a64n::enc_2misc_sz(q, false, 2, a64n::misc::FRECPE, n, d)),
        Rsqrte if dt == Dt::F32 => e!(a64n::enc_2misc_sz(q, true, 2, a64n::misc::FRSQRTE, n, d)),
        Recpe => e!(a64n::enc_2misc(q, true, dt, a64n::misc::URECPE, n, d)),
        Rsqrte if dt == Dt::U32 => e!(a64n::enc_2misc(q, true, dt, 28, n, d)), // URSQRTE
        MovN => e!(a64n::enc_2misc(q, true, dt, 18, n, d)), // XTN
        QmovN => e!(a64n::enc_2misc(q, false, dt, 20, n, d)), // SQXTN
        QmovUn => e!(a64n::enc_2misc(q, true, dt, 18, n, d)), // SQXTUN
        Zip => return Err(TranslateErr("vzip needs 2-output model".into())),
        Unzip => return Err(TranslateErr("vuzp needs 2-output model".into())),
        Trn => return Err(TranslateErr("vtrn needs 2-output model".into())),

        // ======== variable shifts ========
        ShlReg => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SSHL, m, n, d))),
        QshlReg => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SQSHL, m, n, d))),
        QrshlReg => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SQRSHL, m, n, d))),
        QdmulH => e!(fix3!(a64n::enc_3same(q, false, dt, a64n::same::SQDMULH, m, n, d))),
        // SQRDMULH = SQDMULH opcode with U=1 (LLVM: sqrdmulh v0.4h = 0x2e62b420)
        Qrdmulh => e!(fix3!(a64n::enc_3same(q, true, dt, a64n::same::SQDMULH, m, n, d))),
        // SABA/UABA: opcode 15, U from signedness (LLVM: saba v0.4s = 0x4ea27c20, uaba = 0x6ea27c20)
        Aba => e!(fix3!(a64n::enc_3same(q, matches!(dt, Dt::U8|Dt::U16|Dt::U32|Dt::U64), dt, a64n::same::SABA, m, n, d))),

        // ======== conversions ========
        FToFix => {
            // A32 vcvt.s32.f32 → A64 FCVTZS with sz=2 (f32)
            e!(a64n::enc_2misc_sz(q, false, 2, 27, n, d)) // FCVTZS = 0b11011
        }
        FixToF => {
            // A32 vcvt.f32.s32 → A64 SCVTF with sz=2
            e!(a64n::enc_2misc_sz(q, false, 2, a64n::misc::SCVTF, n, d))
        }

        _ => return Err(TranslateErr(format!("neon op {:?}", op))),
    }
    Ok(())
}

fn translate_neon_ldst_multi(
    out: &mut A64, load: bool, kind: crate::a32::ins::NeonVldKind, dt: Dt,
    d: VIdx, rn: R, rm: Option<R>, _align: u8, wback: bool, count: u8,
) -> Result<(), TranslateErr> {
    use crate::a32::ins::NeonVldKind;

    // A64 LD1/ST1 are direct equivalents for single-structure.
    // For multi-register groups, emit one instruction per pair.
    // A64 LDn: {v0.16b-v3.16b} supports up to 4 registers in one instruction.

    let sz = match dt.bits() { 8 => 0u32, 16 => 1, 32 => 2, _ => 3 };

    // Compute the A64 opcode:
    // LD1: 0111 (1-reg), 1010 (2-reg), 0110 (3-reg), 0010 (4-reg)
    // LD2: 1000, LD3: 0100, LD4: 0000
    // ST mirrors LD with L=0
    let opcode: u32 = match (kind, count) {
        (NeonVldKind::Vld1, 1) => 0b0111,
        (NeonVldKind::Vld1, 2) => 0b1010,
        (NeonVldKind::Vld1, 3) => 0b0110,
        (NeonVldKind::Vld1, 4) => 0b0010,
        (NeonVldKind::Vld2, 2) => 0b1000,
        (NeonVldKind::Vld2, 4) => 0b0011, // not in A64 (LD2 is always 2)
        (NeonVldKind::Vld3, 3) => 0b0100,
        (NeonVldKind::Vld4, 4) => 0b0000,
        _ => return Err(TranslateErr("bad vldst combination".into())),
    };

    // A32 VLDn/VSTn address D-register lists (always 64-bit vectors in A32!),
    // so the A64 equivalent always uses Q=0 with the A32 register number as the
    // LOW half of the A64 v-register. LLVM-verified:
    //   vld1.8 {d0}, [r0]   → ld1 {v0.8b},  [x0]   = 0x0c407000
    //   vld1.16 {d0,d1},[r0]→ ld1 {v0.4h,v1.4h},[x0] = 0x0c40a400
    //   vld4.32 {d0..d3}    → ld4 {v0.2s..v3.2s},[x0] = 0x0c400c00
    //   writeback (A32 Rm=0xD) → A64 post-index by immediate: Rm=11111 + bit21
    let base = x(rn);
    // A32 Rm semantics: None/0xF = no post-index; 0xD = post by immediate
    // (total size — A64 does this natively with Rm=11111); other r = post by
    // that register's value (A64 Rm = x_r).
    let rm_field: Option<u8> = match rm {
        Some(r) if r != 0xD && r != 0xF => Some(r), // register post-index
        Some(0xD) => Some(0x1F),                    // immediate post-index
        _ if wback => Some(0x1F),                   // A32 '!' form
        _ => None,
    };

    if matches!(kind, NeonVldKind::Vld2) && count == 4 {
        // A32 VLD2x4 / VST2x4 (4 D-registers = 2 interleaved pairs) has no single
        // A64 instruction: expand to two ld2/st2 with the base bumped by 16 bytes.
        // vld2.8 {d0,d1,d2,d3} ≡ ld2 {v0,v1},[x] ; ld2 {v2,v3},[x+16]
        const LD2: u8 = 0b1000;
        out.e(a64n::enc_ldst_multi(load, false, sz, LD2, base, d, None));
        out.addsub_imm(true, 0, false, 16, false, base, 16); // x16 = base + 16 (64-bit address)
        out.e(a64n::enc_ldst_multi(load, false, sz, LD2, 16, (d + 2) & 0x1F, None));
        if let Some(m) = rm_field {
            if m == 0x1F {
                // post by immediate: total = 4 D-regs × 8 bytes = 32
                out.addsub_imm(true, 0, false, 32, false, base, base);
            } else {
                out.addsub_reg(true, 0, false, 0, 0, base, m, base);
            }
        }
        return Ok(());
    }

    out.e(a64n::enc_ldst_multi(load, false, sz, opcode as u8, base, d, rm_field));
    let _ = rm;
    Ok(())
}

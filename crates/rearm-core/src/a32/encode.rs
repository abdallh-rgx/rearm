//! A32 encoder: `Ins` -> 32-bit instruction words.
//! Inverse of `decode.rs`; round-trip is validated by golden corpus tests.

use crate::common::*;
use crate::a32::ins::*;

pub fn encode_a32(ins: &Ins) -> Result<u32, EncodeErr> {
    Ok(match ins {
        Ins::DpImm { op, s, rn, rd, imm12 } => {
            let o = dp_opc(*op);
            if (0b1000..=0b1011).contains(&o) && !*s {
                return Err(EncodeErr("TST/TEQ/CMP/CMN require S=1"));
            }
            (Cond::Al.bits() as u32) << 28
                | (0b001 << 25)
                | (o << 21)
                | ((*s as u32) << 20)
                | ((*rn as u32) << 16)
                | ((*rd as u32) << 12)
                | *imm12 as u32
        }
        Ins::DpReg { op, s, rn, rd, rm, shift, amount } => {
            let o = dp_opc(*op);
            if (0b1000..=0b1011).contains(&o) && !*s {
                return Err(EncodeErr("TST/TEQ/CMP/CMN require S=1"));
            }
            let base = (Cond::Al.bits() as u32) << 28 | (0b000 << 25) | (o << 21) | ((*s as u32) << 20)
                | ((*rn as u32) << 16) | ((*rd as u32) << 12);
            match amount {
                ShiftAmount::Imm(a) => base | ((*a as u32) << 7) | ((shift.bits() as u32) << 5) | *rm as u32,
                ShiftAmount::Reg(rs) => {
                    base | ((*rs as u32) << 8) | ((shift.bits() as u32) << 5) | (1 << 4) | *rm as u32
                }
            }
        }
        Ins::Movw { rd, imm16 } => {
            (Cond::Al.bits() as u32) << 28 | (0b00110 << 23) | 0 << 20
                | (((imm16 >> 12) as u32) << 16) | ((*rd as u32) << 12) | (imm16 & 0xfff) as u32
        }
        Ins::Movt { rd, imm16 } => {
            (Cond::Al.bits() as u32) << 28 | (0b00110 << 23) | (1 << 22)
                | (((imm16 >> 12) as u32) << 16) | ((*rd as u32) << 12) | (imm16 & 0xfff) as u32
        }
        Ins::Mul { rd, rn, rm, s } => {
            (Cond::Al.bits() as u32) << 28 | ((*s as u32) << 20)
                | ((*rd as u32) << 16) | ((*rm as u32) << 8) | (0b1001 << 4) | *rn as u32
        }
        Ins::Mla { rd, rn, rm, ra, s } => {
            (Cond::Al.bits() as u32) << 28 | (1 << 21) | ((*s as u32) << 20)
                | ((*rd as u32) << 16) | ((*ra as u32) << 12) | ((*rm as u32) << 8) | (0b1001 << 4) | *rn as u32
        }
        Ins::Mls { rd, rn, rm, ra } => {
            (Cond::Al.bits() as u32) << 28 | (0b011 << 21)
                | ((*rd as u32) << 16) | ((*ra as u32) << 12) | ((*rm as u32) << 8) | (0b1001 << 4) | *rn as u32
        }
        Ins::Umull { rdlo, rdhi, rn, rm, s }
        | Ins::Smull { rdlo, rdhi, rn, rm, s }
        | Ins::Umlal { rdlo, rdhi, rn, rm, s }
        | Ins::Smlal { rdlo, rdhi, rn, rm, s } => {
            let sel = match ins {
                Ins::Umull { .. } => 0b100u32,
                Ins::Umlal { .. } => 0b101,
                Ins::Smull { .. } => 0b110,
                _ => 0b111,
            };
            (Cond::Al.bits() as u32) << 28 | (sel << 21) | ((*s as u32) << 20)
                | ((*rdhi as u32) << 16) | ((*rdlo as u32) << 12) | ((*rm as u32) << 8) | (0b1001 << 4) | *rn as u32
        }
        Ins::Smulxy { rd, rn, rm, x, y } => {
            (Cond::Al.bits() as u32) << 28 | (0b10110 << 20)
                | ((*rd as u32) << 12) | ((*rm as u32) << 8)
                | ((0b1000 | (y.bit() as u32) << 2 | (x.bit() as u32) << 1) << 4) | *rn as u32
        }
        Ins::Smlaxy { rd, rn, rm, ra, x, y } => {
            (Cond::Al.bits() as u32) << 28 | (0b10000 << 20)
                | ((*rd as u32) << 16) | ((*ra as u32) << 12) | ((*rm as u32) << 8)
                | ((0b1000 | (y.bit() as u32) << 2 | (x.bit() as u32) << 1) << 4) | *rn as u32
        }
        Ins::Smulwy { rd, rn, rm, y } => {
            (Cond::Al.bits() as u32) << 28 | (0b10010 << 20)
                | ((*rd as u32) << 12) | ((*rm as u32) << 8)
                | ((0b1010 | (y.bit() as u32) << 2) << 4) | *rn as u32
        }
        Ins::Smlawy { rd, rn, rm, ra, y } => {
            (Cond::Al.bits() as u32) << 28 | (0b10010 << 20)
                | ((*rd as u32) << 16) | ((*ra as u32) << 12) | ((*rm as u32) << 8)
                | ((0b1000 | (y.bit() as u32) << 2) << 4) | *rn as u32
        }
        Ins::Smuad { rd, rn, rm, x } => smuad_family(0b10000, 0b0001 | (*x as u32) << 1, *rd, 0xF, *rm, *rn),
        Ins::Smlad { rd, rn, rm, ra, x } => smuad_family(0b10000, 0b0001 | (*x as u32) << 1, *rd, *ra, *rm, *rn),
        Ins::Smusd { rd, rn, rm, x } => smuad_family(0b10000, 0b0101 | (*x as u32) << 1, *rd, 0xF, *rm, *rn),
        Ins::Smlsd { rd, rn, rm, ra, x } => smuad_family(0b10000, 0b0101 | (*x as u32) << 1, *rd, *ra, *rm, *rn),
        Ins::Smlald { rdlo, rdhi, rn, rm, x } => smuad_family(0b10100, 0b0001 | (*x as u32) << 1, *rdhi, *rdlo, *rm, *rn),
        Ins::Smlsld { rdlo, rdhi, rn, rm, x } => smuad_family(0b10100, 0b0101 | (*x as u32) << 1, *rdhi, *rdlo, *rm, *rn),
        Ins::Sdiv { rd, rn, rm } => smuad_family(0b10001, 0b0001, *rd, 0xF, *rm, *rn),
        Ins::Udiv { rd, rn, rm } => smuad_family(0b10011, 0b0001, *rd, 0xF, *rm, *rn),
        Ins::Usad8 { rd, rn, rm } => smuad_family(0b11000, 0b0001, *rd, 0xF, *rm, *rn),
        Ins::Usada8 { rd, rn, rm, ra } => smuad_family(0b11000, 0b0001, *rd, *ra, *rm, *rn),
        Ins::Qadd { rd, rn, rm } => qfam(0b1000, *rd, *rn, *rm),
        Ins::Qsub { rd, rn, rm } => qfam(0b1001, *rd, *rn, *rm),
        Ins::Qdadd { rd, rn, rm } => qfam(0b1010, *rd, *rn, *rm),
        Ins::Qdsub { rd, rn, rm } => qfam(0b1011, *rd, *rn, *rm),
        Ins::Bx { rm } => 0xE12F_FF10 | *rm as u32,
        Ins::Bxj { rm } => 0xE12F_FF20 | *rm as u32,
        Ins::BlxReg { rm } => 0xE12F_FF30 | *rm as u32,
        Ins::B { cond, off } => {
            check_branchoff(*off)?;
            ((cond.bits() as u32) << 28) | (0b101 << 25) | to_u24(*off)
        }
        Ins::Bl { off } => {
            check_branchoff(*off)?;
            (Cond::Al.bits() as u32) << 28 | (0b101 << 25) | (1 << 24) | to_u24(*off)
        }
        Ins::Blx { off } => {
            check_branchoff_h(*off)?;
            let h = ((*off as u32) >> 1) & 1;
            0xF000_0000 | (0b101 << 25) | (h << 24) | ((to_u24(*off)) & 0x00FF_FFFF)
        }
        Ins::Svc { imm } => (Cond::Al.bits() as u32) << 28 | (0b1111 << 24) | (*imm & 0x00FF_FFFF),
        Ins::Neon { .. } | Ins::Vswp { .. } | Ins::VdupScalar { .. } | Ins::VdupCore { .. } => {
            if let Some(w) = crate::a32::encode_neon::encode_neon(ins) { return Ok(w); }
            return Err(EncodeErr("neon encode"));
        }
        Ins::Hints { kind } => {
            let i = match kind {
                Hint::Nop => 0, Hint::Yield => 1, Hint::Wfe => 2, Hint::Wfi => 3,
                Hint::Sev => 4, Hint::Sevl => 5, Hint::Dbg => 0xF0,
            };
            (Cond::Al.bits() as u32) << 28 | (0b0011_0010 << 20) | (0xF << 12) | i
        }
        Ins::Barriers { kind, opt } => {
            let op = match kind { Barrier::Dsb => 4, Barrier::Dmb => 5, Barrier::Isb => 6 };
            0xF57F_F000 | (op << 4) | (*opt & 0xF) as u32
        }
        Ins::Setend { big } => 0xF101_0000 | ((*big as u32) << 9),
        Ins::Bkpt { imm } => (Cond::Al.bits() as u32) << 28 | (0b0001_0010 << 20) | ((imm >> 4) as u32) << 8 | (0b0111 << 4) | (imm & 0xF) as u32,
        Ins::Ldst { store, size, signed, user: _, rt, rn, rm, shift, imm, index, add, wback } => {
            ldst_a32(*store, *size, *signed, *rt, *rn, *rm, *shift, *imm, *index, *add, *wback)?
        }
        Ins::LdrdStrd { store, rt, rt2: _, rn, imm, index, add, wback } => {
            let (p, u, w) = pwu(*index, *add, *wback);
            let imm8 = (*imm).unsigned_abs() as u32;
            (Cond::Al.bits() as u32) << 28 | ((p as u32) << 24) | ((u as u32) << 23) | (1 << 22) | ((w as u32) << 21)
                | ((*rn as u32) << 16) | ((*rt as u32) << 12)
                | ((imm8 >> 4) << 8) | (if *store { 0b1111 } else { 0b1101 } << 4) | (imm8 & 0xF)
        }
        Ins::LdmStm { load, rn, mode, wback, user, list } => {
            let (p, u) = mode.pu();
            (Cond::Al.bits() as u32) << 28 | (0b100 << 25)
                | ((p as u32) << 24) | ((u as u32) << 23) | ((*user as u32) << 22)
                | ((*wback as u32) << 21) | ((*load as u32) << 20)
                | ((*rn as u32) << 16) | list.bitmap() as u32
        }
        Ins::ExclLoad { size, rt, rn } => {
            let op = match size { Size::B8 => 0b110, Size::H16 => 0b111, _ => 0b100 };
            (Cond::Al.bits() as u32) << 28 | (1 << 24) | ((op as u32) << 21) | (1 << 20)
                | ((*rn as u32) << 16) | ((*rt as u32) << 12) | (0xF << 8) | (0b1001 << 4) | 0xF
        }
        Ins::ExclStore { size, rs, rt, rn } => {
            let op = match size { Size::B8 => 0b110, Size::H16 => 0b111, _ => 0b100 };
            (Cond::Al.bits() as u32) << 28 | (1 << 24) | ((op as u32) << 21)
                | ((*rn as u32) << 16) | ((*rs as u32) << 12) | (0xF << 8) | (0b1001 << 4) | *rt as u32
        }
        Ins::ExclLoadD { rt, rt2, rn } => {
            (Cond::Al.bits() as u32) << 28 | (1 << 24) | (0b101 << 21) | (1 << 20)
                | ((*rn as u32) << 16) | ((*rt as u32) << 12) | (0xF << 8) | (0b1001 << 4) | *rt2 as u32
        }
        Ins::ExclStoreD { rs, rt, rt2, rn } => {
            (Cond::Al.bits() as u32) << 28 | (1 << 24) | (0b101 << 21)
                | ((*rn as u32) << 16) | ((*rs as u32) << 12) | (0xF << 8) | (0b1001 << 4) | *rt as u32
        }
        Ins::Mrs { rd, spsr } => {
            (Cond::Al.bits() as u32) << 28 | (1 << 24) | ((*spsr as u32) << 22)
                | (0xF << 16) | ((*rd as u32) << 12)
        }
        Ins::Msr { spsr, mask, rn, imm } => {
            let base_reg = (Cond::Al.bits() as u32) << 28 | (1 << 24) | ((*spsr as u32) << 22) | (1 << 21);
            match imm {
                Some(v) => {
                    let (imm8, rot) = a32_imm8(*v)?;
                    let base_imm = (Cond::Al.bits() as u32) << 28 | (0b001 << 25) | (1 << 24) | ((*spsr as u32) << 22) | (1 << 21);
                    base_imm | ((*mask as u32) << 16) | (0xF << 12) | (rot as u32) << 8 | imm8 as u32
                }
                None => base_reg | ((*mask as u32) << 16) | (0xF << 12) | *rn as u32,
            }
        }
        Ins::Parallel { kind, shape, rd, rn, rm } => {
            let k = match kind {
                ParKind::S => 0b00001u32, ParKind::Q => 0b00010, ParKind::Sh => 0b00011,
                ParKind::U => 0b00101, ParKind::Uq => 0b00110, ParKind::Uh => 0b00111,
            };
            let sh = match shape {
                ParShape::Add16 => 0b0001u32, ParShape::Addsubx => 0b0011, ParShape::Subaddx => 0b0101,
                ParShape::Sub16 => 0b0111, ParShape::Add8 => 0b1001, ParShape::Sub8 => 0b1111,
            };
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (k << 20)
                | ((*rn as u32) << 16) | ((*rd as u32) << 12) | (0xF << 8) | (sh << 4) | *rm as u32
        }
        Ins::Pkh { rd, rn, rm, top, shift } => {
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b01000 << 20)
                | ((*rn as u32) << 16) | ((*rd as u32) << 12) | ((*shift as u32) << 7)
                | ((if *top { 1u32 } else { 0 }) << 6) | (0b0001 << 4) | *rm as u32
        }
        Ins::Sel { rd, rn, rm } => {
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b01000 << 20)
                | ((*rn as u32) << 16) | ((*rd as u32) << 12) | (0xF << 8) | (0b1011 << 4) | *rm as u32
        }
        Ins::Ssat { rd, imm, rn, sh, asr } => {
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b0101 << 21)
                | (((*imm as u32) - 1) << 16) | ((*rd as u32) << 12) | ((*sh as u32) << 7)
                | ((*asr as u32) << 6) | (0b0001 << 4) | *rn as u32
        }
        Ins::Usat { rd, imm, rn, sh, asr } => {
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b0111 << 21)
                | ((*imm as u32) << 16) | ((*rd as u32) << 12) | ((*sh as u32) << 7)
                | ((*asr as u32) << 6) | (0b0001 << 4) | *rn as u32
        }
        Ins::Ssat16 { rd, imm, rn } => {
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b0101 << 21)
                | (((*imm as u32) - 1) << 16) | ((*rd as u32) << 12) | (0xF << 8) | (0b0011 << 4) | *rn as u32
        }
        Ins::Usat16 { rd, imm, rn } => {
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b0111 << 21)
                | ((*imm as u32) << 16) | ((*rd as u32) << 12) | (0xF << 8) | (0b0011 << 4) | *rn as u32
        }
        Ins::Rev { rd, rm } => (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b01011 << 20) | (0xF << 16) | ((*rd as u32) << 12) | (0xF << 8) | (0b0011 << 4) | *rm as u32,
        Ins::Rev16 { rd, rm } => (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b01011 << 20) | (0xF << 16) | ((*rd as u32) << 12) | (0xF << 8) | (0b1011 << 4) | *rm as u32,
        Ins::Revsh { rd, rm } => (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b01111 << 20) | (0xF << 16) | ((*rd as u32) << 12) | (0xF << 8) | (0b1011 << 4) | *rm as u32,
        Ins::Clz { rd, rm } => (Cond::Al.bits() as u32) << 28 | (0b10110 << 20) | (0xF << 16) | ((*rd as u32) << 12) | (0xF << 8) | (0b0001 << 4) | *rm as u32,
        Ins::Rbit { rd, rm } => (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b01111 << 20) | (0xF << 16) | ((*rd as u32) << 12) | (0xF << 8) | (0b0011 << 4) | *rm as u32,
        Ins::Sbfx { rd, rn, lsb, width } => {
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b11010 << 20)
                | (((*width - 1) as u32) << 16) | ((*rd as u32) << 12) | ((*lsb as u32) << 7) | (0b0101 << 4) | *rn as u32
        }
        Ins::Ubfx { rd, rn, lsb, width } => {
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b11110 << 20)
                | (((*width - 1) as u32) << 16) | ((*rd as u32) << 12) | ((*lsb as u32) << 7) | (0b0101 << 4) | *rn as u32
        }
        Ins::Bfc { rd, lsb, width } => {
            let msb = *lsb + *width - 1;
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b11100 << 20)
                | (msb as u32) << 16 | ((*rd as u32) << 12) | ((*lsb as u32) << 7) | (0b0001 << 4) | 0xF
        }
        Ins::Bfi { rd, rn, lsb, width } => {
            let msb = *lsb + *width - 1;
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (0b11100 << 20)
                | (msb as u32) << 16 | ((*rd as u32) << 12) | ((*lsb as u32) << 7) | (0b0001 << 4) | *rn as u32
        }
        Ins::Extend { op, rd, rn, rm, rot } => {
            let (op1, add) = match op {
                ExtOp::Sxtb16 => (0b01000u32, false), ExtOp::Sxtb => (0b01010, false), ExtOp::Sxth => (0b01011, false),
                ExtOp::Uxtb16 => (0b01100, false), ExtOp::Uxtb => (0b01110, false), ExtOp::Uxth => (0b01111, false),
                ExtOp::Sxtab16 => (0b01000, true), ExtOp::Sxtab => (0b01010, true), ExtOp::Sxtah => (0b01011, true),
                ExtOp::Uxtab16 => (0b01100, true), ExtOp::Uxtab => (0b01110, true), ExtOp::Uxtah => (0b01111, true),
            };
            let (r16, r12) = if add { (*rn as u32, *rd as u32) } else { (0xF, *rd as u32) };
            (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (op1 << 20) | (r16 << 16) | (r12 << 12)
                | ((*rot as u32) << 7) | (0b0111 << 4) | *rm as u32
        }
        Ins::Pld { w, rn, rm, shift, imm } => {
            match rm {
                Some(rm) => {
                    0xF7D0_0000u32
                        | ((*rn as u32) << 16) | (0xF << 12) | ((imm.unsigned_abs() as u32) << 7)
                        | ((shift_bits(*shift) as u32) << 5) | *rm as u32
                }
                None => {
                    0xF5D0_0000 | ((*rn as u32) << 16) | (0xF << 12) | (imm.unsigned_abs() as u32)
                }
            }
        }
        Ins::Pli { rn, rm, shift, imm } => {
            match rm {
                Some(rm) => {
                    0xF6D0_0000u32 | ((*rn as u32) << 16) | (0xF << 12) | ((imm.unsigned_abs() as u32) << 7)
                        | ((shift_bits(*shift) as u32) << 5) | *rm as u32
                }
                None => {
                    0xF4D0_0000 | ((*rn as u32) << 16) | (0xF << 12) | (imm.unsigned_abs() as u32)
                }
            }
        }
        Ins::VLdrStr { .. } | Ins::VLdmStm { .. } | Ins::VMovCoreD { .. } => {
            return crate::a32::decode_vfp::encode_vfp_ldst(ins);
        }
        Ins::VfpBin { op, d, n, m, dbl } => {
            let (opc1, opbit) = match op {
                VfpBinOp::Add => (0b0011u32, 0u32),
                VfpBinOp::Sub => (0b0011, 1),
                VfpBinOp::Mul => (0b0010, 0),
                VfpBinOp::NMul => (0b0010, 1),
                VfpBinOp::Div => (0b1000, 0),
            };
            let cp = if *dbl { 0b1011u32 } else { 0b1010 };
            let (d_f, dbit, n_f, nbit, m_f, mbit) = vfp_split(*d, *n, *m, *dbl);
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (opc1 << 20)
                | (dbit << 22) | (n_f << 16) | (d_f << 12) | (cp << 8)
                | (nbit << 7) | (opbit << 6) | (mbit << 5) | m_f)
        }
        Ins::VfpMulAcc { form, d, n, m, dbl } => {
            let (opc1, opbit) = match (form.neg_d, form.neg_p) {
                (false, false) => (0b0000u32, 0u32), // vmla
                (false, true) => (0b0000, 1),       // vmls
                (true, false) => (0b0001, 1),       // vnmla
                (true, true) => (0b0001, 0),        // vnmls
            };
            let cp = if *dbl { 0b1011u32 } else { 0b1010 };
            let (d_f, dbit, n_f, nbit, m_f, mbit) = vfp_split(*d, *n, *m, *dbl);
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (opc1 << 20)
                | (dbit << 22) | (n_f << 16) | (d_f << 12) | (cp << 8)
                | (nbit << 7) | (opbit << 6) | (mbit << 5) | m_f)
        }
        Ins::VfpUn { op, d, m, dbl } => {
            let (n_f, opbit, nbit) = match op {
                VfpUnOp::Abs => (0b0000u32, 1u32, 1u32),
                VfpUnOp::Mov => (0b0000, 1, 0),
                VfpUnOp::Sqrt => (0b0001, 1, 1),
                VfpUnOp::Neg => (0b0001, 1, 0),
            };
            let cp = if *dbl { 0b1011u32 } else { 0b1010 };
            let (d_f, dbit, _n_f, _nbit, m_f, mbit) = vfp_split(*d, 0, *m, *dbl);
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (0b1011 << 20)
                | (dbit << 22) | (n_f << 16) | (d_f << 12) | (cp << 8)
                | (nbit << 7) | (opbit << 6) | (mbit << 5) | m_f)
        }
        Ins::VfpCmp { d, m, dbl, e } => {
            let cp = if *dbl { 0b1011u32 } else { 0b1010 };
            let (d_f, dbit, _a, _b, m_f, mbit) = vfp_split(*d, 0, *m, *dbl);
            let ebit = *e as u32;
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (0b1011 << 20)
                | (dbit << 22) | (0b0100 << 16) | (d_f << 12) | (cp << 8)
                | (ebit << 7) | (1 << 6) | (mbit << 5) | m_f)
        }
        Ins::VfpCmpz { d, dbl, e } => {
            let cp = if *dbl { 0b1011u32 } else { 0b1010 };
            let (d_f, dbit, _a, _b, _m_f, _mbit) = vfp_split(*d, 0, 0, *dbl);
            let ebit = *e as u32;
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (0b1011 << 20)
                | (dbit << 22) | (0b0101 << 16) | (d_f << 12) | (cp << 8)
                | (ebit << 7) | (1 << 6) | (0 << 5) | 0)
        }
        Ins::VmovImm { kind, imm, q, d } => {
            if matches!(kind, NeonImmKind::I8 | NeonImmKind::I16 | NeonImmKind::I32 | NeonImmKind::F32N) {
                if let Some(w) = crate::a32::encode_neon::encode_neon(ins) { return Ok(w); }
            }
            let dbl = *kind == NeonImmKind::F64;
            let cp = if dbl { 0b1011u32 } else { 0b1010 };
            let (d_f, dbit, _a, _b, _c, _e) = vfp_split(*d, 0, 0, dbl);
            let imm4h = ((*imm >> 4) & 0xF) as u32;
            let imm4l = (*imm & 0xF) as u32;
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (0b1011 << 20)
                | (dbit << 22) | (imm4h << 16) | (d_f << 12) | (cp << 8)
                | (0 << 7) | (0 << 6) | (0 << 4) | imm4l)
        }
        Ins::VMrs { rt, to_apsr, sys: _ } => {
            let rt_f = if *to_apsr { 0xFu32 } else { rt.unwrap_or(0) as u32 };
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (0b1111 << 20)
                | (0x1 << 16) | (rt_f << 12) | (0b1010 << 8) | (0 << 7) | (0 << 6) | (1 << 4))
        }
        Ins::Vmsr { sys: _, rt } => {
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (0b1110 << 20)
                | (0x1 << 16) | ((*rt as u32) << 12) | (0b1010 << 8) | (0 << 7) | (0 << 6) | (1 << 4))
        }
        Ins::VMovCoreS { rt, sn, to_fp } => {
            let cp = 0b1010u32;
            let (n_f, nbit) = (*sn >> 1, (*sn & 1) as u32);
            let l = !*to_fp as u32;
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (l << 20)
                | ((n_f as u32) << 16) | ((*rt as u32) << 12) | (cp << 8) | (nbit << 7) | (0 << 6) | (1 << 4))
        }
        Ins::VMovLane { dt, to_fp, rt, d, index } => {
            let (n_f, nbit) = (*d & 0xF, *d >> 4);
            let (opc1, b7_4) = match dt {
                Dt::U32 | Dt::S32 => {
                    if *to_fp { ((*index as u32) * 2, 1u32) } else { (1 + (*index as u32) * 2, 1u32) }
                }
                Dt::U16 | Dt::S16 => {
                    let u = matches!(dt, Dt::U16);
                    let o = if *to_fp { ((*index as u32) >> 1) * 2 }
                            else { 1 + ((*index as u32) >> 1) * 2 + (u as u32) * 8 };
                    (o, 3 + (*index & 1) as u32 * 4)
                }
                _ => {
                    let u = matches!(dt, Dt::U8);
                    let o = if *to_fp { 4 + ((*index as u32) >> 2) * 2 }
                            else { 5 + ((*index as u32) >> 2) * 2 + (u as u32) * 8 };
                    (o, 1 + (*index & 3) as u32 * 2)
                }
            };
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (opc1 << 20)
                | ((n_f as u32) << 16) | ((*rt as u32) << 12) | (0b1011 << 8)
                | ((nbit as u32) << 7) | (b7_4 << 4))
        }
        Ins::Vcvt { form, d, m, round } => {
            let (n_f, opbit, nbit, dbl_dest, dbl_src) = match form {
                VcvtForm::FromS32 { dst } => (0b1000u32, 1u32, 1u32, *dst == 64, false),
                VcvtForm::FromU32 { dst } => (0b1000, 1, 0, *dst == 64, false),
                VcvtForm::ToS32 { src } => (0b1101, 1, 1, false, *src == 64),
                VcvtForm::ToU32 { src } => (0b1100, 1, 1, false, *src == 64),
                VcvtForm::F32F64 => (0b0111, 1, 1, false, true),
                VcvtForm::F64F32 => (0b0111, 1, 1, true, false),
                VcvtForm::F16F32 | VcvtForm::F32F16 => return Err(EncodeErr("f16 conversions unsupported in A32 encoder yet")),
            };
            // Vd per dest precision; Vm per source precision; cp per source precision.
            let to_float = matches!(form, VcvtForm::FromS32 { .. } | VcvtForm::FromU32 { .. });
            let cp = if (to_float && dbl_dest) || (!to_float && dbl_src) { 0b1011u32 } else { 0b1010 };
            let (d_f, dbit): (u8, u8) = if dbl_dest { (*d & 0xF, *d >> 4) } else { (*d >> 1, *d & 1) };
            let (m_f, mbit): (u8, u8) = if dbl_src { (*m & 0xF, *m >> 4) } else { (*m >> 1, *m & 1) };
            let rz = match round { Some(4) => 0u32, Some(_) => 1, None => 1 };
            let nbit = match form {
                VcvtForm::ToS32 { .. } | VcvtForm::ToU32 { .. } => rz,
                _ => nbit,
            };
            return Ok((Cond::Al.bits() as u32) << 28 | (0b1110 << 24) | (0b1011 << 20)
                | ((dbit as u32) << 22) | (n_f << 16) | ((d_f as u32) << 12) | (cp << 8)
                | ((nbit as u32) << 7) | (opbit << 6) | ((mbit as u32) << 5) | m_f as u32)
        }
        Ins::Unsupported { group } => return Err(EncodeErr(*group)),
        _ => return Err(EncodeErr("not yet encodable")),
    })
}

/// VFP register field split (matches decode_vfp::regs inverse).
fn vfp_split(d: u8, n: u8, m: u8, dbl: bool) -> (u32, u32, u32, u32, u32, u32) {
    if dbl {
        ((d & 0xF) as u32, (d >> 4) as u32, (n & 0xF) as u32, (n >> 4) as u32, (m & 0xF) as u32, (m >> 4) as u32)
    } else {
        ((d >> 1) as u32, (d & 1) as u32, (n >> 1) as u32, (n & 1) as u32, (m >> 1) as u32, (m & 1) as u32)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EncodeErr(pub &'static str);

impl core::fmt::Display for EncodeErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot encode: {}", self.0)
    }
}

const fn dp_opc(op: DpOp) -> u32 {
    match op {
        DpOp::And => 0b0000, DpOp::Eor => 0b0001, DpOp::Sub => 0b0010, DpOp::Rsb => 0b0011,
        DpOp::Add => 0b0100, DpOp::Adc => 0b0101, DpOp::Sbc => 0b0110, DpOp::Rsc => 0b0111,
        DpOp::Tst => 0b1000, DpOp::Teq => 0b1001, DpOp::Cmp => 0b1010, DpOp::Cmn => 0b1011,
        DpOp::Orr => 0b1100, DpOp::Mov => 0b1101, DpOp::Bic => 0b1110, DpOp::Mvn => 0b1111,
    }
}

const fn shift_bits(s: Shift) -> u8 {
    match s { Shift::Lsl => 0, Shift::Lsr => 1, Shift::Asr => 2, Shift::Ror => 3 }
}

fn smuad_family(op1: u32, op2: u32, rd: R, ra: R, rm: R, rn: R) -> u32 {
    (Cond::Al.bits() as u32) << 28 | (0b011 << 25) | (op1 << 20)
        | ((rd as u32) << 16) | ((ra as u32) << 12) | ((rm as u32) << 8) | (op2 << 4) | rn as u32
}

fn qfam(op2421: u32, rd: R, rn: R, rm: R) -> u32 {
    (Cond::Al.bits() as u32) << 28 | (op2421 << 21)
        | ((rn as u32) << 16) | ((rd as u32) << 12) | (0b0101 << 4) | rm as u32
}

fn check_branchoff(off: i32) -> Result<(), EncodeErr> {
    if off % 4 != 0 || !(-33_554_432..=33_554_428).contains(&off) {
        return Err(EncodeErr("branch offset out of range"));
    }
    Ok(())
}

fn check_branchoff_h(off: i32) -> Result<(), EncodeErr> {
    if off % 2 != 0 || !(-33_554_432..=33_554_428).contains(&off) {
        return Err(EncodeErr("blx offset must be halfword aligned"));
    }
    Ok(())
}

const fn to_u24(off: i32) -> u32 {
    ((off >> 2) as u32) & 0x00FF_FFFF
}

/// Try to encode a 32-bit value as imm8r (imm8 + rotation). Returns (imm8, rotation).
fn a32_imm8(v: u32) -> Result<(u32, u32), EncodeErr> {
    if v == 0 { return Ok((0, 0)); }
    for i in 0..16u32 {
        let r = i * 2;
        let imm8 = v.rotate_left(r);
        if imm8 <= 0xFF {
            return Ok((imm8, i));
        }
    }
    Err(EncodeErr("immediate not encodable as imm8r"))
}

fn pwu(index: bool, add: bool, wback: bool) -> (bool, bool, bool) {
    let p = index;
    let u = add;
    let w = wback && index;
    (p, u, w)
}

fn ldst_a32(
    store: bool, size: Size, signed: bool, rt: R, rn: R, rm: Option<R>, shift: Shift,
    imm: i32, index: bool, add: bool, wback: bool,
) -> Result<u32, EncodeErr> {
    // halfword/signed-byte extra forms
    if size == Size::H16 || signed {
        let op2 = match (size, signed, store) {
            (Size::H16, false, false) => 0b1011u32,
            (Size::H16, false, true) => 0b1011,
            (Size::B8, true, false) => 0b1101,
            (Size::H16, true, false) => 0b1111,
            _ => return Err(EncodeErr("bad ldst combo")),
        };
        let l = !store;
        let (p, u, w) = pwu(index, add, wback);
        let imm_flag = if rm.is_some() { 0u32 } else { 1 << 22 };
        return Ok((Cond::Al.bits() as u32) << 28 | (1 << 24) | ((p as u32) << 24) | ((u as u32) << 23)
            | imm_flag
            | ((w as u32) << 21) | ((l as u32) << 20)
            | ((rn as u32) << 16) | ((rt as u32) << 12)
            | match rm {
                Some(rm) => ((shift_bits(shift) as u32) << 5) | rm as u32,
                None => (((imm.unsigned_abs() as u32) >> 4) << 8) | ((imm.unsigned_abs() as u32) & 0xF),
            }
            | (op2 << 4));
    }
    // word/byte standard forms
    let b = size == Size::B8;
    let l = !store;
    let (p, u, w) = pwu(index, add, wback);
    match rm {
        Some(rm) => Ok((Cond::Al.bits() as u32) << 28 | (0b011 << 25) | ((p as u32) << 24) | ((u as u32) << 23)
            | ((b as u32) << 22) | ((w as u32) << 21) | ((l as u32) << 20)
            | ((rn as u32) << 16) | ((rt as u32) << 12)
            | ((imm.unsigned_abs() as u32) << 7) | ((shift_bits(shift) as u32) << 5) | rm as u32),
        None => Ok((Cond::Al.bits() as u32) << 28 | (0b010 << 25) | ((p as u32) << 24) | ((u as u32) << 23)
            | ((b as u32) << 22) | ((w as u32) << 21) | ((l as u32) << 20)
            | ((rn as u32) << 16) | ((rt as u32) << 12)
            | (imm.unsigned_abs() as u32)),
    }
}

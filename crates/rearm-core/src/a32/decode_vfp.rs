//! VFP (coprocessor 10/11) decoders/encoders for A32.
//!
//! Register model (validated byte-by-byte against LLVM-assembled corpus):
//!   single: Sx = 2*field + ext_bit  (Sd: field=bits(15:12), ext=bit22;
//!           Sn: field=bits(19:16), ext=bit7; Sm: field=bits(3:0), ext=bit5)
//!   double: Dx = field + 16*ext_bit
//!   VCVT mixed forms: Vd per destination precision, Vm per source precision (cp).
//!
//! Bit layout of bits(7:4) for data ops: [N=bit7][op=bit6][M=bit5][b4=bit4].

use crate::common::*;
use crate::a32::ins::*;
use crate::a32::decode::DecodeErr;
use crate::a32::encode::EncodeErr;

#[inline]
fn sreg(field: u32, ext: bool) -> u8 { ((field << 1) | ext as u32) as u8 }
#[inline]
fn dreg(field: u32, ext: bool) -> u8 { (field | ((ext as u32) << 4)) as u8 }

/// VFP loads/stores in the 110 coproc space: VLDR/VSTR/VLDM/VSTM + VMOV core-pair.
pub fn decode_vfp_ldst(word: u32) -> Result<Ins, DecodeErr> {
    let p = bit(word, 24);
    let u = bit(word, 23);
    let d = bit(word, 22);
    let w = bit(word, 21);
    let l = bit(word, 20);
    let rn = bits(word, 19, 16) as u8;
    let rd_field = bits(word, 15, 12);
    let cp = bits(word, 11, 8);
    let imm8 = bits(word, 7, 0);
    let dbl = cp & 1 == 1;

    // VMOV core-pair: bits(27:24)=1100, bit22=1, bits(7:4)=0001
    if bits(word, 27, 24) == 0b1100 && bit(word, 22) && bits(word, 7, 4) == 0b0001 {
        let dm = dreg(bits(word, 3, 0), bit(word, 5));
        return Ok(Ins::VMovCoreD {
            rt: rd_field as u8, rt2: bits(word, 19, 16) as u8, dm, to_fp: !l,
        });
    }
    if w || !p {
        // VLDM/VSTM: imm8 = number of single regs, or 2 * number of double regs
        let count = if dbl { imm8 / 2 } else { imm8 };
        let reg = if dbl { dreg(rd_field, d) } else { rd_field as u8 };
        return Ok(Ins::VLdmStm { load: l, dbl, d: reg, count: count as u8, rn, wback: w, add: u });
    }
    // VLDR/VSTR
    let imm = if u { (imm8 as i32) * 4 } else { -((imm8 as i32) * 4) };
    let reg = if dbl { dreg(rd_field, d) } else { sreg(rd_field, d) };
    Ok(Ins::VLdrStr { load: l, d: reg, rn, imm, add: u, dbl })
}

/// VFP data operations in the 1110 coproc space.
pub fn decode_vfp_data(word: u32) -> Result<Ins, DecodeErr> {
    let opc1 = bits(word, 23, 20);
    let l = bit(word, 20);
    let cp = bits(word, 11, 8);
    let dbl = cp & 1 == 1;
    let nbit = bit(word, 7);
    let op = bit(word, 6);
    let mbit = bit(word, 5);
    let b4 = bit(word, 4);

    let vd = if dbl { dreg(bits(word, 15, 12), bit(word, 22)) } else { sreg(bits(word, 15, 12), bit(word, 22)) };
    let vn = if dbl { dreg(bits(word, 19, 16), nbit) } else { sreg(bits(word, 19, 16), nbit) };
    let vm = if dbl { dreg(bits(word, 3, 0), mbit) } else { sreg(bits(word, 3, 0), mbit) };

    // VMRS/VMSR: opc1=1111 (VMRS) / 1110 (VMSR), bits(19:16)=0001, b4=1
    if (opc1 == 0b1111 || opc1 == 0b1110) && bits(word, 19, 16) == 0b0001 && b4 && !dbl {
        let rt = bits(word, 15, 12) as u8;
        return Ok(if l {
            if rt == 15 { Ins::VMrs { rt: None, to_apsr: true, sys: VfpSys::Fpscr } }
            else { Ins::VMrs { rt: Some(rt), to_apsr: false, sys: VfpSys::Fpscr } }
        } else {
            Ins::Vmsr { sys: VfpSys::Fpscr, rt }
        });
    }
    // VMOV core <-> single: opc1=0000/0001, b4=1, cp=1010; Sn = 2*bits(19:16) + N(bit7)
    if (opc1 == 0b0000 || opc1 == 0b0001) && b4 && !dbl {
        let sn = sreg(bits(word, 19, 16), nbit);
        return Ok(Ins::VMovCoreS { rt: bits(word, 15, 12) as u8, sn, to_fp: !l });
    }
    // VMOV core <-> lane: L=bit20; Dd = bits(19:16) + N(bit7)<<4; rt = bits(15:12); cp=1011
    // Index/size model (empirically validated against LLVM):
    //   to-fp:   .32: opc1=idx*2, b7_4=1 | .16: opc1=(idx>>1)*2, b7_4=3+(idx&1)*4
    //            | .8: opc1=4+(idx>>2)*2, b7_4=1+(idx&3)*2
    //   to-core: .32: opc1=1+idx*2 | .16: opc1=1+(idx>>1)*2+U*8 | .8: opc1=5+(idx>>2)*2+U*8
    if bits(word, 11, 8) == 0b1011 && b4 {
        let dnum = dreg(bits(word, 19, 16), nbit);
        let rt = bits(word, 15, 12) as u8;
        let b7_4 = bits(word, 7, 4);
        let (dt, index, to_fp) = if !l {
            match (opc1, b7_4) {
                (0, 1) | (2, 1) => (Dt::U32, (opc1 / 2) as u8, true),
                (0, 3) | (0, 7) => (Dt::U16, ((b7_4 >> 2) & 1) as u8, true),
                (2, 3) | (2, 7) => (Dt::U16, (2 + ((b7_4 >> 2) & 1)) as u8, true),
                (4, x) if x & 1 == 1 => (Dt::U8, (((b7_4 >> 1) & 3) as u8), true),
                (6, x) if x & 1 == 1 => (Dt::U8, (4 + ((b7_4 >> 1) & 3)) as u8, true),
                _ => return Ok(Ins::Unsupported { group: "vmov-lane" }),
            }
        } else {
            match (opc1, b7_4) {
                (1, 1) | (3, 1) => (Dt::U32, ((opc1 - 1) / 2) as u8, false),
                (1, 3) | (1, 7) => (Dt::S16, ((b7_4 >> 2) & 1) as u8, false),
                (3, 3) | (3, 7) => (Dt::S16, (2 + ((b7_4 >> 2) & 1)) as u8, false),
                (9, 3) | (9, 7) => (Dt::U16, ((b7_4 >> 2) & 1) as u8, false),
                (0xB, 3) | (0xB, 7) => (Dt::U16, (2 + ((b7_4 >> 2) & 1)) as u8, false),
                (5, x) if x & 1 == 1 => (Dt::S8, ((b7_4 >> 1) & 3) as u8, false),
                (7, x) if x & 1 == 1 => (Dt::S8, (4 + ((b7_4 >> 1) & 3)) as u8, false),
                (0xD, x) if x & 1 == 1 => (Dt::U8, ((b7_4 >> 1) & 3) as u8, false),
                (0xF, x) if x & 1 == 1 => (Dt::U8, (4 + ((b7_4 >> 1) & 3)) as u8, false),
                _ => return Ok(Ins::Unsupported { group: "vmov-lane" }),
            }
        };
        return Ok(Ins::VMovLane { dt, to_fp, rt, d: dnum, index });
    }

    match (opc1, op) {
        (0b0011, false) => return Ok(Ins::VfpBin { op: VfpBinOp::Add, d: vd, n: vn, m: vm, dbl }),
        (0b0011, true) => return Ok(Ins::VfpBin { op: VfpBinOp::Sub, d: vd, n: vn, m: vm, dbl }),
        (0b0010, false) => return Ok(Ins::VfpBin { op: VfpBinOp::Mul, d: vd, n: vn, m: vm, dbl }),
        (0b0010, true) => return Ok(Ins::VfpBin { op: VfpBinOp::NMul, d: vd, n: vn, m: vm, dbl }),
        (0b1000, _) => return Ok(Ins::VfpBin { op: VfpBinOp::Div, d: vd, n: vn, m: vm, dbl }),
        (0b0000, false) => return Ok(Ins::VfpMulAcc { form: VfpMulAcc { neg_d: false, neg_p: false }, d: vd, n: vn, m: vm, dbl }),
        (0b0000, true) => return Ok(Ins::VfpMulAcc { form: VfpMulAcc { neg_d: false, neg_p: true }, d: vd, n: vn, m: vm, dbl }),
        (0b0001, true) => return Ok(Ins::VfpMulAcc { form: VfpMulAcc { neg_d: true, neg_p: false }, d: vd, n: vn, m: vm, dbl }),
        (0b0001, false) => return Ok(Ins::VfpMulAcc { form: VfpMulAcc { neg_d: true, neg_p: true }, d: vd, n: vn, m: vm, dbl }),
        (0b1011, _) => return decode_vfp_unary(word, dbl, vd, vm),
        _ => {}
    }
    Ok(Ins::Unsupported { group: "vfp-data" })
}

/// opc1=1011 space. `vd`/`vm` computed with the cp model; for mixed VCVT we recompute.
fn decode_vfp_unary(word: u32, dbl: bool, _vd: u8, _vm: u8) -> Result<Ins, DecodeErr> {
    let n_f = bits(word, 19, 16);
    let nbit = bit(word, 7);
    let op = bit(word, 6);
    let mbit = bit(word, 5);
    let b4 = bit(word, 4);
    let d_field = bits(word, 15, 12);
    let dbit = bit(word, 22);
    let m_field = bits(word, 3, 0);

    match (n_f, op, nbit) {
        // VABS: n_f=0, op=1, N=1
        (0b0000, true, true) => return Ok(Ins::VfpUn { op: VfpUnOp::Abs,
            d: if dbl { dreg(d_field, dbit) } else { sreg(d_field, dbit) },
            m: if dbl { dreg(m_field, mbit) } else { sreg(m_field, mbit) }, dbl }),
        // VMOV (fp): n_f=0, op=1, N=0
        (0b0000, true, false) => return Ok(Ins::VfpUn { op: VfpUnOp::Mov,
            d: if dbl { dreg(d_field, dbit) } else { sreg(d_field, dbit) },
            m: if dbl { dreg(m_field, mbit) } else { sreg(m_field, mbit) }, dbl }),
        // VSQRT: n_f=1, op=1, N=1
        (0b0001, true, true) => return Ok(Ins::VfpUn { op: VfpUnOp::Sqrt,
            d: if dbl { dreg(d_field, dbit) } else { sreg(d_field, dbit) },
            m: if dbl { dreg(m_field, mbit) } else { sreg(m_field, mbit) }, dbl }),
        // VNEG: n_f=1, op=1, N=0
        (0b0001, true, false) => return Ok(Ins::VfpUn { op: VfpUnOp::Neg,
            d: if dbl { dreg(d_field, dbit) } else { sreg(d_field, dbit) },
            m: if dbl { dreg(m_field, mbit) } else { sreg(m_field, mbit) }, dbl }),
        // VCMP: n_f=4, op=1, E=N
        (0b0100, true, e) => return Ok(Ins::VfpCmp {
            d: if dbl { dreg(d_field, dbit) } else { sreg(d_field, dbit) },
            m: if dbl { dreg(m_field, mbit) } else { sreg(m_field, mbit) }, dbl, e }),
        // VCMPZ: n_f=5, op=1, E=N
        (0b0101, true, e) => return Ok(Ins::VfpCmpz {
            d: if dbl { dreg(d_field, dbit) } else { sreg(d_field, dbit) }, dbl, e }),
        // to-float from int: n_f=8, op=1: N=1 signed, N=0 unsigned.
        // cp selects destination precision; Vm (int source) always single model.
        (0b1000, true, signed) => return Ok(Ins::Vcvt {
            form: if dbl { if signed { VcvtForm::FromS32 { dst: 64 } } else { VcvtForm::FromU32 { dst: 64 } } }
                  else { if signed { VcvtForm::FromS32 { dst: 32 } } else { VcvtForm::FromU32 { dst: 32 } } },
            d: if dbl { dreg(d_field, dbit) } else { sreg(d_field, dbit) },
            m: sreg(m_field, mbit), round: None }),
        // to-int from float: n_f=D (s32) / C (u32): N=1 round-zero, N=0 FPSCR (VCVTR)
        (0b1101, true, rz) => return Ok(Ins::Vcvt { form: VcvtForm::ToS32 { src: if dbl { 64 } else { 32 } },
            d: sreg(d_field, dbit),
            m: if dbl { dreg(m_field, mbit) } else { sreg(m_field, mbit) },
            round: Some(if rz { 0 } else { 4 }) }), // 0 = RZ, 4 = "FPSCR"
        (0b1100, true, rz) => return Ok(Ins::Vcvt { form: VcvtForm::ToU32 { src: if dbl { 64 } else { 32 } },
            d: sreg(d_field, dbit),
            m: if dbl { dreg(m_field, mbit) } else { sreg(m_field, mbit) },
            round: Some(if rz { 0 } else { 4 }) }),
        // f32 <-> f64: n_f=7, op=1: cp=1011 → f32<-f64; cp=1010 → f64<-f32
        (0b0111, true, _) => {
            return if dbl {
                Ok(Ins::Vcvt { form: VcvtForm::F32F64, d: sreg(d_field, dbit), m: dreg(m_field, mbit), round: None })
            } else {
                Ok(Ins::Vcvt { form: VcvtForm::F64F32, d: dreg(d_field, dbit), m: sreg(m_field, mbit), round: None })
            };
        }
        _ => {}
    }
    // VMOV imm: op=0, b4=0: imm8 = n_f : m_field
    if !op && !b4 && !nbit && !mbit && n_f <= 0xF {
        let imm64 = ((n_f as u64) << 4) | m_field as u64;
        return Ok(Ins::VmovImm {
            kind: if dbl { NeonImmKind::F64 } else { NeonImmKind::F32 },
            imm: imm64, q: false,
            d: if dbl { dreg(d_field, dbit) } else { sreg(d_field, dbit) },
        });
    }
    Ok(Ins::Unsupported { group: "vfp-unary" })
}

// ============================== encoders ==============================

pub fn encode_vfp_ldst(ins: &Ins) -> Result<u32, EncodeErr> {
    match ins {
        Ins::VLdrStr { load, d, rn, imm, add, dbl } => {
            let cp = if *dbl { 0b1011u32 } else { 0b1010 };
            let (d_f, dbit) = if *dbl { (*d & 0xF, *d >> 4) } else { (*d >> 1, *d & 1) };
            let imm8 = (imm.unsigned_abs() / 4) as u32;
            Ok((Cond::Al.bits() as u32) << 28 | (0b110 << 25) | (1 << 24)
                | ((*add as u32) << 23) | ((dbit as u32) << 22)
                | ((*load as u32) << 20)
                | ((*rn as u32) << 16) | ((d_f as u32) << 12) | (cp << 8) | (imm8 & 0xFF))
        }
        Ins::VLdmStm { load, dbl, d, count, rn, wback, add } => {
            let cp = if *dbl { 0b1011u32 } else { 0b1010 };
            let (d_f, dbit): (u32, u32) = if *dbl { ((*d & 0xF) as u32, (*d >> 4) as u32) } else { (*d as u32, 0u32) };
            let imm8 = if *dbl { (*count as u32) * 2 } else { *count as u32 };
            let p = !*add as u32; // IA: P=0; DB: P=1
            Ok((Cond::Al.bits() as u32) << 28 | (0b110 << 25)
                | (p << 24) | ((*add as u32) << 23) | (dbit << 22)
                | ((*wback as u32) << 21) | ((*load as u32) << 20)
                | ((*rn as u32) << 16) | (d_f << 12) | (cp << 8) | (imm8 & 0xFF))
        }
        Ins::VMovCoreD { rt, rt2, dm, to_fp } => {
            let l = (!*to_fp) as u32;
            let (dm_f, mbit) = (*dm & 0xF, *dm >> 4);
            Ok((Cond::Al.bits() as u32) << 28 | (0b1100 << 24) | (1 << 22) | (l << 20)
                | ((*rt2 as u32) << 16) | ((*rt as u32) << 12) | (0b1011 << 8)
                | ((mbit as u32) << 5) | (1 << 4) | dm_f as u32)
        }
        _ => Err(EncodeErr("not a vfp-ldst")),
    }
}

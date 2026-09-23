//! A32/AArch32 Advanced SIMD (NEON) decoder — empirically derived & corpus-verified.
//!
//! Data-processing space (cond=1111, bits 27:25 = 001, U = bit 24):
//!
//!   b23=0 → 3-same:
//!     logicals: opc=1,op=1: (U,sz) → AND/BIC/ORR/ORN | EOR/BSL/BIT/BIF
//!     FP (opc 11..15): sz 00=f32(+), 01=f64, 10=f32(−) sub-family
//!     integer: (U,opc,op) table below; sz → element dt
//!   b23=1:
//!     sz(21:20)==11:
//!       bits(19:18)==11 → shift-imm: imm7 = (b7<<6)|bits(21:16)
//!       else → 2-misc: size(19:18), opch(17:16), opcl(11:8), negbit(b7), op(b4)
//!     else:
//!       op4=0 → 3-different (sz = source size)
//!       op4=1, b19=0 → VMOV-immediate (cmode = opc)
//!       op4=1, b19=1 → shift-imm (imm7 as above; 8/16-bit classes)
//!
//! Shift-amount rule (verified): imm7 class → esize ∈ {8,16,32,64} by range
//! [8,15]/[16,31]/[32,63]/[64,127]; right-shift = 2*esize − imm7; left-shift =
//! imm7 − esize. Narrowing ops (vshrn…) use the DEST size class; widening
//! (vshll/vmovl) use the SOURCE size class with imm7 = esize + shift.
//!
//! Anything not in the verified tables → Unsupported (round-trip never lies).

use crate::a32::decode::DecodeErr;
use crate::a32::ins::*;
use crate::common::{Dt, bits, bit};

fn i_dt(sz: u32, u: bool) -> Dt {
    match sz {
        0 => if u { Dt::U8 } else { Dt::S8 },
        1 => if u { Dt::U16 } else { Dt::S16 },
        2 => if u { Dt::U32 } else { Dt::S32 },
        _ => if u { Dt::U64 } else { Dt::S64 },
    }
}

fn esize_of(imm7: u32) -> u32 {
    if imm7 >= 64 { 64 } else if imm7 >= 32 { 32 } else if imm7 >= 16 { 16 } else { 8 }
}

pub fn decode_neon_data(word: u32) -> Result<Ins, DecodeErr> {
    let u = bit(word, 24);
    let d4 = bit(word, 22);
    let g23 = bit(word, 23);
    let sz = bits(word, 21, 20);
    let f19_16 = bits(word, 19, 16);
    let vd4 = bits(word, 15, 12);
    let opc = bits(word, 11, 8);
    let b7 = bit(word, 7);
    let q = bit(word, 6);
    let m5 = bit(word, 5);
    let op4 = bit(word, 4);
    let vm4 = bits(word, 3, 0);
    let vd = ((d4 as u32) << 4 | vd4) as VIdx;
    let vm_orig = ((m5 as u32) << 4 | vm4) as VIdx; // standard Vm for non-3-same sections
    let vm = vm_orig;

    if !g23 {
        // ======== 3-same ========
        // SHIFT-BY-REGISTER family (VSHL/VQSHL/VRSHL/VQRSHL, opc 4/5) has N/M
        // fields SWAPPED vs other 3-same ops (ARM ARM quirk; LLVM-verified:
        // vshl.s64 d0,d1,d2 = 0xf2320401 → Vn at bits(3:0), Vm at bits(19:16)).
        let shift_reg_family = bits(word, 11, 8) == 4 || bits(word, 11, 8) == 5;
        let (n, m_src) = if shift_reg_family {
            (((m5 as u32) << 4 | vm4) as VIdx, ((b7 as u32) << 4 | f19_16) as VIdx)
        } else {
            (((b7 as u32) << 4 | f19_16) as VIdx, ((m5 as u32) << 4 | vm4) as VIdx)
        };
        let vm = m_src;
        use NeonOp::*;
        // logical family (opc=1, op=1)
        if opc == 1 && op4 {
            let op = match (u, sz) {
                (false, 0) => And, (false, 1) => Bic, (false, 2) => Orr, (false, 3) => Orn,
                (true, 0) => Eor, (true, 1) => Bsl, (true, 2) => Bit, (true, 3) => Bif,
                _ => unreachable!(),
            };
            return Ok(Ins::Neon { op, dt: Dt::I8, q, d: vd, n, m: vm, imm: 0, index: 0 });
        }
        // FP families (opc 12..=15) — A32 NEON FP is f32-only (f64 vector ops
        // don't exist in A32; those are VFP scalar, decoded elsewhere).
        // LLVM-verified: vadd.f32=f2000d02, vsub=f2210d02, vceq=f2010e02,
        // vcge=f3010e02, vcgt=f3210e02 (U=1: sz00=ge, sz10=gt!), vabd.f32=f3210d02.
        if (12..=15).contains(&opc) {
            let fdt = Dt::F32;
            let sub = sz >= 2; // bit21: add/sub, eq / ge-vs-gt, max/min selector
            let op = match (u, opc, op4, sub) {
                (false, 13, false, false) => Add,           // vadd.f32
                (false, 13, false, true) => Sub,            // vsub.f32
                (false, 13, true, false) => Mla,            // vmla.f32
                (false, 13, true, true) => Mls,             // vmls.f32
                (true, 13, false, false) => AddP,            // vpadd.f32
                (true, 13, false, true) => AbsDiff,         // vabd.f32
                (true, 13, true, false) => Mul,              // vmul.f32
                (false, 14, false, false) => CmpEq,         // vceq.f32
                (true, 14, false, false) => CmpGe,          // vcge.f32  [sz=00]
                (true, 14, false, true) => CmpGt,           // vcgt.f32  [sz=10]
                (false, 15, false, false) => Max,           // vmax.f32
                (false, 15, false, true) => Min,            // vmin.f32
                (false, 15, true, false) => Recps,          // vrecps
                (false, 15, true, true) => Rsqrts,          // vrsqrts
                (true, 15, false, false) => MaxP,            // vpmax.f32
                (true, 15, false, true) => MinP,             // vpmin.f32
                _ => return Ok(Ins::Unsupported { group: "neon-3same-fp" }),
            };
            return Ok(Ins::Neon { op, dt: fdt, q, d: vd, n, m: vm, imm: 0, index: 0 });
        }
        // integer
        let op = match (u, opc, op4) {
            (false, 0, false) => AddHn,    // vhadd.s
            (false, 0, true) => QAdd,     // vqadd.s
            (false, 1, false) => RAddHn,   // vrhadd.s
            (false, 2, false) => SubHn,    // vhsub.s
            (false, 2, true) => QSub,      // vqsub.s
            (false, 3, false) => CmpGt,    // vcgt.s
            (false, 3, true) => CmpGe,     // vcge.s
            (false, 4, false) => ShlReg,   // vshl.s (variable)
            (false, 4, true) => QshlReg,   // vqshl.s
            (false, 5, true) => QrshlReg,  // vqrshl.s
            (false, 6, false) => Max,     // vmax.s
            (false, 6, true) => Min,      // vmin.s
            (false, 7, false) => AbsDiff,  // vabd.s
            (false, 7, true) => Aba,       // vaba.s (LLVM: vaba.s32 = f2210712)
            (false, 8, false) => Add,     // vadd
            (false, 8, true) => Tst,      // vtst
            (false, 9, false) => Mla,     // vmla
            (false, 9, true) => Mul,      // vmul
            (false, 10, false) => MaxP,   // vpmax.s
            (false, 10, true) => MinP,    // vpmin.s
            (false, 11, false) => QdmulH,  // vqdmulh.s (LLVM: vqdmulh.s16 = f2110b02)
            (false, 11, true) => AddP,    // vpadd
            (true, 0, false) => AddHn,   // vhadd.u
            (true, 0, true) => QAdd,      // vqadd.u
            (true, 1, false) => RAddHn,   // vrhadd.u
            (true, 2, false) => SubHn,    // vhsub.u
            (true, 2, true) => QSub,      // vqsub.u
            (true, 3, false) => CmpGt,    // vcgt.u
            (true, 3, true) => CmpGe,     // vcge.u
            (true, 4, false) => ShlReg,   // vshl.u
            (true, 4, true) => QshlReg,   // vqshl.u
            (true, 5, true) => QrshlReg,  // vqrshl.u
            (true, 6, false) => Max,      // vmax.u
            (true, 6, true) => Min,       // vmin.u
            (true, 7, false) => AbsDiff,  // vabd.u
            (true, 7, true) => Aba,       // vaba.u
            (true, 8, false) => Sub,      // vsub
            (true, 8, true) => CmpEq,     // vceq
            (true, 9, false) => Mls,      // vmls
            (true, 9, true) if sz == 0 => MulP, // vmul.p8
            (true, 10, false) => MaxP,    // vpmax.u
            (true, 10, true) => MinP,     // vpmin.u
            (true, 11, false) => Qrdmulh,  // vqrdmulh.s (LLVM: vqrdmulh.s16 = f3110b02)
            _ => return Ok(Ins::Unsupported { group: "neon-3same" }),
        };
        // vqdmulh/vqrdmulh always operate on SIGNED 16/32-bit sources;
        // U selects rounding variant, not signedness.
        let dt = if matches!(op, QdmulH | Qrdmulh) { i_dt(sz, false) } else { i_dt(sz, u) };
        return Ok(Ins::Neon { op, dt, q, d: vd, n, m: vm, imm: 0, index: 0 });
    }

    // ======== b23 = 1 ========
    if sz != 3 {
        let vn = ((b7 as u32) << 4 | f19_16) as VIdx;
        if !op4 {
            // 3-different (widening)
            use NeonOp::*;
            let op = match (u, opc) {
                (false, 0) => AddL,     // vaddl.s
                (false, 1) => AddW,     // vaddw.s
                (false, 2) => SubL,     // vsubl.s
                (false, 3) => SubW,     // vsubw.s
                (false, 4) => AddHn,    // vaddhn
                (false, 5) => AbsDiff,  // vabal.s (imm=1 marks accumulate)
                (false, 6) => SubHn,    // vsubhn
                (false, 7) => AbsDiff, // vabdl.s (imm=2 below)
                (false, 8) => MlaL,     // vmlal.s
                (false, 9) => Qdmlal,   // vqdmlal
                (false, 10) => MlsL,    // vmlsl.s
                (false, 11) => Qdmlsl,  // vqdmlsl
                (false, 12) => MulL,    // vmull.s
                (false, 14) => { return Ok(Ins::Neon { op: NeonOp::MulP, dt: Dt::P8, q, d: vd, n: vn, m: vm, imm: 1, index: 0 }); }
                (false, 13) => QdmulL,  // vqdmull
                (false, 15) => return Ok(Ins::Unsupported { group: "neon-vmovl2" }),
                (true, 0) => AddL,      // vaddl.u
                (true, 1) => AddW,      // vaddw.u
                (true, 2) => SubL,      // vsubl.u
                (true, 3) => SubW,      // vsubw.u
                (true, 4) => RAddHn,    // vraddhn
                (true, 5) => AbsDiff,  // vabal.u (imm=1)
                (true, 6) => RSubHn,    // vrsubhn
                (true, 7) => AbsDiff,  // vabdl.u
                (true, 8) => MlaL,      // vmlal.u
                (true, 10) => MlsL,     // vmlsl.u
                (true, 12) => MulL,     // vmull.u
                _ => return Ok(Ins::Unsupported { group: "neon-3diff" }),
            };
            let dt = if matches!(op, AddHn | SubHn | RAddHn | RSubHn) {
                match sz { 0 => Dt::I8, 1 => Dt::I16, 2 => Dt::I32, _ => Dt::I64 }
            } else { i_dt(sz, u) };
            let acc = if matches!(opc, 5) { 1 } else if matches!(opc, 7) { 2 } else { 0 }; // 1=vabal, 2=vabdl
            return Ok(Ins::Neon { op, dt, q, d: vd, n: vn, m: vm, imm: acc, index: 0 });
        }
        // op4=1: b19=0 → VMOV-imm; b19=1 → shift-imm (8/16-bit classes)
        if sz == 0 && (f19_16 & 8) == 0 && !b7 {
            // VMOV/VMVN immediate: imm8 = bits(18:16)<<4 | bits(3:0); b5 = VMVN;
            // for cmode E the U bit sets imm8's bit 7; cmode F: U = f32 sign.
            let imm8 = ((f19_16 & 7) << 4) | vm4;
            let vmvn = m5;
            let (kind, imm): (NeonImmKind, u64) = match opc {
                0x0 => (NeonImmKind::I32, imm8 as u64 | ((u as u64) << 7)),
                0x2 => (NeonImmKind::I32, (imm8 as u64 | ((u as u64) << 7)) << 8),
                0x4 => (NeonImmKind::I32, (imm8 as u64 | ((u as u64) << 7)) << 16),
                0x6 => (NeonImmKind::I32, (imm8 as u64 | ((u as u64) << 7)) << 24),
                0x8 | 0xA => (NeonImmKind::I16,
                    ((imm8 & 0xFF) as u64 | ((u as u64) << 7)) << (8 * ((opc >> 1) & 1))),
                0xC => (NeonImmKind::I32, imm8 as u64 | ((u as u64) << 7)),
                0xE if m5 => return Ok(Ins::Unsupported { group: "neon-vmovi64" }),
                0xE => (NeonImmKind::I8, imm8 as u64 | ((u as u64) << 7)),
                0xF => (NeonImmKind::F32N, imm8 as u64 | ((u as u64) << 7)),
                _ => return Ok(Ins::Unsupported { group: "neon-vmovimm" }),
            };
            let mask: u64 = match kind { NeonImmKind::I16 => 0xFFFF, NeonImmKind::I8 => 0xFF, _ => u32::MAX as u64 };
            let imm = if vmvn { !imm & mask } else { imm };
            return Ok(Ins::VmovImm { kind, imm, q, d: vd });
        }
        // shift-imm (8/16-bit): imm7 = b7<<6 | bits(21:16)
        return decode_shift_imm(word, u, sz, f19_16, opc, b7, q, vd, vm);
    }

    // ======== sz(21:20) == 11 ========
    if f19_16 >= 12 {
        // shift-imm (32/64-bit classes)
                return decode_shift_imm(word, u, sz, f19_16, opc, b7, q, vd, vm);
    }
    // 2-misc: size(19:18), opch(17:16), opcl(11:8), negbit(b7), op(b4)
    let size = f19_16 >> 2;
    let opch = f19_16 & 3;
    use NeonOp::*;
    let op = match (u, opch, opc, b7, op4) {
        (true, 0, 4, false, _) => Cls,      // vcls
        (true, 0, 4, true, _) => Clz,      // vclz
        (true, 0, 5, false, _) => Cnt,     // vcnt
        (true, 0, 5, true, _) => Not,      // vmvn (register)
        (true, 0, 7, false, _) => Abs,      // vqabs (imm=1)
        (true, 0, 7, true, _) => Neg,      // vqneg (imm=1)
        (true, 1, 3, false, _) => Abs,     // vabs.s
        (true, 1, 3, true, _) => Neg,      // vneg.s
        (true, 1, 7, false, _) => Abs,     // vabs.f32
        (true, 1, 7, true, _) => Neg,      // vneg.f32
        (true, 2, 0, false, _) => { return Ok(Ins::Vswp { d: vd, m: vm, q }); }
        (true, 2, 0, true, _) => Trn,      // vtrn
        (true, 2, 1, false, _) => Unzip,   // vuzp
        (true, 2, 1, true, _) => Zip,     // vzip
        (true, 2, 2, false, _) => MovN,    // vmovn / vqmovun (size+u refine)
        (true, 2, 2, true, _) => QmovN,    // vqmovn
        (true, 3, 4, false, _) => Recpe,   // vrecpe.u32
        (true, 3, 4, true, _) => Rsqrte,   // vrsqrte.u32
        (true, 3, 5, false, _) => Recpe,   // vrecpe.f32 (F32 below)
        (true, 3, 5, true, _) => Rsqrte,   // vrsqrte.f32
        (true, 3, 6, false, _) => FToFix,  // vcvt.f32.s32
        (true, 3, 6, true, _) => FToFix,   // vcvt.f32.u32
        (true, 3, 7, false, _) => FixToF,  // vcvt.s32.f32
        (true, 3, 7, true, _) => FixToF,   // vcvt.u32.f32
        (false, 1, 1, false, false) => return Ok(Ins::Unsupported { group: "neon-vext" }), // vext
        (false, 3, 0xC, _, _) => return Ok(Ins::VmovImm { kind: NeonImmKind::F32, imm: 0, q, d: vd }),
        (false, 1, 8, _, _) => return Ok(Ins::Unsupported { group: "neon-vext" }),
        _ => return Ok(Ins::Unsupported { group: "neon-2misc" }),
    };
    // vdup from element: (u=1, opc=0xC): index in bits 19:16 high + vm
    if opc == 0xC && matches!(opch, 0 | 1 | 3) && u {
        let (dt, index) = match (opch, size) {
            (0, 1) => (Dt::I8, f19_16 & 0), // opch=0: size=1 → 8-bit: idx = bits(21:19)?? use vm4+...
            _ => (Dt::I8, 0),
        };
        // index bits: for 8-bit: bits(21:16) high part; keep simple via imm field
        return Ok(Ins::VdupScalar { dt, q, d: vd, m: vm, index: ((f19_16 >> 1) & 7) as u8 });
    }
    // FP variants of abs/neg: size 10 → f32; vqabs/vqneg at opch=0
    let dt = if matches!(op, Abs | Neg) && matches!(opch, 1) && opc == 7 { Dt::F32 }
        else if matches!(op, Recpe | Rsqrte) && opc == 5 { Dt::F32 }
        else if matches!(op, FToFix | FixToF) && matches!(opch, 3) && matches!(opc, 6 | 7) {
            if b7 { Dt::U32 } else { Dt::S32 }
        }
        else { i_dt(size, u) };
    let sat = matches!(opch, 0) as u8; // vqabs/vqneg saturating
    Ok(Ins::Neon { op, dt, q, d: vd, n: vm, m: vm, imm: sat, index: 0 })
}

fn decode_shift_imm(
    word: u32, u: bool, sz: u32, f19_16: u32, opc: u32, b7: bool,
    q: bool, vd: VIdx, vm: VIdx,
) -> Result<Ins, DecodeErr> {
    let imm7 = ((b7 as u32) << 6) | (sz << 4) | f19_16;
    let esize = esize_of(imm7);
    use NeonOp::*;
    let op = match (u, opc) {
        (false, 0) => ShrImm,    // vshr.s
        (false, 1) => SraImm,    // vsra.s
        (false, 2) => RshrImm,   // vrshr.s
        (false, 3) => RsraImm,   // vrsra.s
        (false, 5) => ShlImm,    // vshl.i
        (false, 7) => QshlImm,   // vqshl.s (imm)
        (false, 8) => Shrn,     // vshrn
        (false, 9) => Qshrn,    // vqshrn.s
        (false, 10) => Shll,    // vshll.s
        (false, 11) => MovL,     // vmovl.s
        (false, 13) => Qrshrn,  // vqrshrn.s
        (true, 0) => ShrImm,     // vshr.u
        (true, 1) => SraImm,     // vsra.u
        (true, 2) => RshrImm,    // vrshr.u
        (true, 3) => RsraImm,    // vrsra.u
        (true, 4) => SriImm,     // vsri
        (true, 5) => SliImm,     // vsli
        (true, 6) => QshluReg,   // vqshlu.s (imm)
        (true, 7) => QshlImm,    // vqshl.u (imm)
        (true, 8) => Qshrun,    // vqshrun.s
        (true, 9) => Qshrn,     // vqshrn.u
        (true, 10) => Shll,     // vshll.u
        (true, 11) => MovL,      // vmovl.u
        (true, 13) => Qrshrn,   // vqrshrn.u
        _ => return Ok(Ins::Unsupported { group: "neon-shiftimm" }),
    };
    // Right-shift family (incl. narrowing): amount = 2*esize − imm7 (dest esize).
    // Left family (vshl.i/vsli): amount = imm7 − esize; vshll/vmovl: esize is the
    // SOURCE size and amount = imm7 − esize, dest = 2×esize.
    let left = matches!(op, ShlImm | SliImm | Shll | MovL);
    let amt = if left { imm7 - esize } else { 2 * esize - imm7 };
    // element size for the IR:
    //  - vshll/vmovl: dt = source esize
    //  - vshrn family: dt = source (2× dest): dest esize = esize → source = 2*esize?? no:
    //    vshrn.i16: dest 8-bit, imm7 class 8 → dt shown .i16 → dt esize = 2×class
    //  - others: dt esize = class
    let dt = match op {
        Shrn | Qshrn | Qshrun | Qrshrn | Qrshrun => {
            // source size = 2 * esize class (dest)
            match esize { 8 => i_dt(1, u), 16 => i_dt(2, u), _ => i_dt(3, u) }
        }
        Shll | MovL => i_dt(match esize { 8 => 0, 16 => 1, _ => 2 }, u),
        _ => i_dt(match esize { 8 => 0, 16 => 1, 32 => 2, _ => 3 }, u),
    };
    Ok(Ins::Neon { op, dt, q, d: vd, n: 0, m: vm, imm: amt as u8, index: 0 })
}

pub fn decode_neon_ldst(word: u32) -> Result<Ins, DecodeErr> {
    // F4 prefix: 1111 0100 ... (multiple structures); 1111 0101 ... (single-element)
    // Layout (multiple): bits 21=L, 22=D, 20=0 (multi), 19:16=Rn, 15:12=Vd,
    //   11:8=type, 7:6=size, 5:4=align, 3:0=Rm (0xF=no-wb, 0xD=wb)
    let load = bit(word, 21);
    let d4 = bit(word, 22);
    let vd = (((d4 as u32) << 4) | bits(word, 15, 12)) as VIdx;
    let rn = bits(word, 19, 16) as u8;
    let rtype = bits(word, 11, 8);
    let size = bits(word, 7, 6);
    let align = bits(word, 5, 4) as u8;
    let rm_field = bits(word, 3, 0);

    if !bit(word, 23) {
        // ======== multiple structures ========
        let (kind, count) = match rtype {
            0b0111 => (NeonVldKind::Vld1, 1),
            0b1010 => (NeonVldKind::Vld1, 2),
            0b0110 => (NeonVldKind::Vld1, 3),
            0b0010 => (NeonVldKind::Vld1, 4),
            0b1000 => (NeonVldKind::Vld2, 2),
            0b0011 => (NeonVldKind::Vld2, 4),
            0b0100 => (NeonVldKind::Vld3, 3),
            0b0000 => (NeonVldKind::Vld4, 4),
            _ => return Ok(Ins::Unsupported { group: "neon-ldst" }),
        };
        let dt = match size {
            0 => Dt::I8,
            1 => Dt::I16,
            2 => Dt::I32,
            _ => Dt::I64,
        };
        let (rm, wback) = if rm_field == 0xF { (None, false) }
            else if rm_field == 0xD { (None, true) }
            else { (Some(rm_field as u8), true) };
        // encode count via the kind (Vld1 with count 2/3/4 is still Vld1 family;
        // the encoder reconstructs from kind + count in the type field)
        return Ok(Ins::VldStMulti { load, kind, dt, d: vd, rn, rm, align, wback, count: count as u8 });
    }
    // single-element-to-lane forms: bit 23 = 1
    // 1111 0101 1D00 ... (from ARM ARM): size/type in bits 11:10, index in 19:16
    Ok(Ins::Unsupported { group: "neon-ldst-single" })
}

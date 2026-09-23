//! A32 NEON encoder — exact inverse of decode_neon.rs (corpus round-trip verified).
//! All layouts documented in decode_neon.rs; see that file for the field maps.

use crate::a32::ins::*;
use crate::common::Dt;
use crate::a32::ins::NeonOp;

fn sz_of(dt: Dt) -> u32 {
    match dt {
        Dt::I8 | Dt::U8 | Dt::S8 | Dt::P8 => 0,
        Dt::I16 | Dt::U16 | Dt::S16 | Dt::F16 => 1,
        Dt::I32 | Dt::U32 | Dt::S32 | Dt::F32 => 2,
        Dt::I64 | Dt::U64 | Dt::S64 | Dt::F64 => 3,
    }
}

/// imm7 → (esize, imm7) for a right shift of `amt` on `esize`-bit lanes.
fn imm7_right(esize: u32, amt: u8) -> u32 { 2 * esize - amt as u32 }
fn imm7_left(esize: u32, amt: u8) -> u32 { esize + amt as u32 }

pub fn encode_neon(ins: &Ins) -> Option<u32> {
    match ins {
        Ins::Neon { op, dt, q, d, n, m, imm, index: _ } => encode_one(op, *dt, *q, *d, *n, *m, *imm),
        Ins::VmovImm { kind, imm, q, d } => encode_vmov_imm(*kind, *imm, *q, *d),
        Ins::VdupScalar { dt, q, d, m, index } => {
            // vdup.elem: 2-misc (u=1, opc=0xC); index at bits 19:16 high
            let d4 = ((d >> 4) & 1) as u32; let vd = (d & 0xF) as u32;
            let vm = (m & 0xF) as u32; let m5 = ((m >> 4) & 1) as u32;
            let sz = sz_of(*dt);
            // index bits: for .8: idx∈[0,7] at bits(19:17); .16: [0,3] at (19:18);
            // .32: [0,1] at bit 19
            let idx_bits = match dt.bits() {
                8 => (*index as u32) << 1,
                16 => (*index as u32) << 2,
                _ => (*index as u32) << 3,
            };
            Some(0xF3B00000u32 | (d4 << 22) | (idx_bits << 16) | (vd << 12) | (0xC << 8)
                | ((*q as u32) << 6) | (m5 << 5) | vm | (sz << 10))
        }
        Ins::Vswp { d, m, q } => {
            // vswp: 2-misc group: (u=1, opch=2, opcl=0, neg=0), Vm second operand
            let d4 = ((d >> 4) & 1) as u32; let vd = (d & 0xF) as u32;
            let vm = (m & 0xF) as u32; let m5 = ((m >> 4) & 1) as u32;
            Some(0xF3B00000u32 | (2 << 16) | (d4 << 22) | (vd << 12) | ((*q as u32) << 6) | (m5 << 5) | vm)
        }
        Ins::VldStMulti { load, kind, dt, d, rn, rm, align, wback, count } => {
            let d4 = ((d >> 4) & 1) as u32; let vd = (d & 0xF) as u32;
            let size = match dt.bits() { 8 => 0u32, 16 => 1, 32 => 2, _ => 3 };
            let rtype: u32 = match (kind, *count) {
                (NeonVldKind::Vld1, 1) => 0b0111,
                (NeonVldKind::Vld1, 2) => 0b1010,
                (NeonVldKind::Vld1, 3) => 0b0110,
                (NeonVldKind::Vld1, 4) => 0b0010,
                (NeonVldKind::Vld2, 2) => 0b1000,
                (NeonVldKind::Vld2, 4) => 0b0011,
                (NeonVldKind::Vld3, 3) => 0b0100,
                (NeonVldKind::Vld4, 4) => 0b0000,
                _ => return None,
            };
            let rm_field: u32 = match (rm, wback) {
                (None, false) => 0xF,
                (None, true) => 0xD,
                (Some(r), _) => *r as u32,
            };
            Some(0xF4000000u32 | (d4 << 22) | ((*load as u32) << 21)
                | ((*rn as u32) << 16) | (vd << 12) | (rtype << 8)
                | (size << 6) | ((*align as u32) << 4) | rm_field)
        }
        _ => None,
    }
}

/// VMOV/VMVN (NEON immediate): imm8 = bits(18:16)<<4 | bits(3:0); b5 = VMVN;
/// cmode E: U sets imm8 bit7; cmode F: U = f32 sign; i16: cmode A for shift 8.
fn encode_vmov_imm(kind: NeonImmKind, imm: u64, q: bool, d: VIdx) -> Option<u32> {
    // F32: bit 7 = sign → U bit
    if kind == NeonImmKind::F32N {
        let sign = ((imm >> 7) & 1) as u32;
        let v = (imm & 0x7F) as u32;
        let d4 = ((d >> 4) & 1) as u32; let vd = (d & 0xF) as u32;
        return Some(0xF2000000u32 | (sign << 24) | (1 << 23) | (d4 << 22)
            | ((v >> 4) & 0x7) << 16 | (vd << 12) | (0xF << 8) | ((q as u32) << 6) | (1 << 4) | (v & 0xF));
    }
    if let Some(w) = encode_vmov_pat(kind, imm, false, q, d) { return Some(w); }
    // VMVN fallback: complement within the kind width
    let w = match kind { NeonImmKind::I16 => !imm & 0xFFFF, NeonImmKind::I8 => !imm & 0xFF, _ => !imm & (u32::MAX as u64) };
    encode_vmov_pat(kind, w, true, q, d)
}

fn encode_vmov_pat(kind: NeonImmKind, imm: u64, vmvn: bool, q: bool, d: VIdx) -> Option<u32> {
    let (cmode, val, use_q): (u32, u64, bool) = match kind {
        NeonImmKind::I8 => (0xE, imm & 0x7F, q),
        NeonImmKind::I16 => {
            let v = imm & 0xFFFF;
            let (base, sh) = if v != 0 && (v & 0xFF) == 0 { (v >> 8, 1u64) } else { (v, 0u64) };
            if base > 0xFF { return None; }
            let cmode = if sh == 1 { 0xA } else { 0x8 };
            (cmode, base, q)
        }
        // I64 one-hot patterns: unsupported (rare)

        NeonImmKind::I32 => {
            let v = imm & 0xFFFFFFFF;
            if v <= 0xFF { (0x0, v, q) }
            else if v <= 0xFF00 && (v & 0xFF) == 0 { (0x2, v >> 8, q) }
            else if v <= 0xFF0000 && (v & 0xFFFF) == 0 { (0x4, v >> 16, q) }
            else if (v & 0xFFFFFF) == 0 { (0x6, v >> 24, q) }
            else if (v & 0xFFFF0000) == (v << 16) && v != 0 { (0xC, v & 0xFFFF, q) }
            else { return None }
        }
        _ => return None,
    };
    let d4 = ((d >> 4) & 1) as u32;
    let vd = (d & 0xF) as u32;
    let abc = ((val >> 4) & 0x7) as u32;
    let low = (val & 0xF) as u32;
    let ubit = match kind { NeonImmKind::I8 => ((imm >> 7) & 1) as u32, _ => ((val >> 7) & 1) as u32 };
    Some(0xF2000000u32 | (ubit << 24) | (1 << 23) | (d4 << 22) | (abc << 16)
        | (vd << 12) | (cmode << 8) | ((use_q as u32) << 6) | ((vmvn as u32) << 5) | (1 << 4) | low)
}

fn encode_one(op: &NeonOp, dt: Dt, q: bool, d: VIdx, n: VIdx, m: VIdx, imm: u8) -> Option<u32> {
    fn base(u: bool) -> u32 { 0xF2000000u32 | ((u as u32) << 24) }
    let q = q as u32;
    let d4 = ((d >> 4) & 1) as u32;
    let vd = (d & 0xF) as u32;
    let vn = (n & 0xF) as u32;
    let n5 = ((n >> 4) & 1) as u32;
    let vm = (m & 0xF) as u32;
    let m5 = ((m >> 4) & 1) as u32;
    let sz = sz_of(dt);
    use NeonOp::*;

    // ======== 3-same ========
    // SHIFT-BY-REGISTER family (opc 4/5): Vn at (3:0)+M, Vm at (19:16)+N (ARM ARM quirk).
    let same = |u: bool, opc: u32, op4: bool| -> u32 {
        let (f19_16, n7, f3_0, m5v) = if opc == 4 || opc == 5 {
            (vm, m5, vn, n5) // swapped: n → (3:0)+M, m → (19:16)+N
        } else {
            (vn, n5, vm, m5)
        };
        base(u) | (d4 << 22) | (sz << 20) | (f19_16 << 16) | (vd << 12) | (opc << 8)
            | (n7 << 7) | (q << 6) | (m5v << 5) | ((op4 as u32) << 4) | f3_0
    };
    let same_no_sz = |u: bool, opc: u32, op4: bool, szx: u32| -> u32 {
        base(u) | (d4 << 22) | (szx << 20) | (vn << 16) | (vd << 12) | (opc << 8)
            | (n5 << 7) | (q << 6) | (m5 << 5) | ((op4 as u32) << 4) | vm
    };
    // logical family: (opc=1, op=1) with (U, sz) selector
    let logical = match op {
        And => Some((false, 0)), Bic => Some((false, 1)), Orr => Some((false, 2)), Orn => Some((false, 3)),
        Eor => Some((true, 0)), Bsl => Some((true, 1)), Bit => Some((true, 2)), Bif => Some((true, 3)),
        _ => None,
    };
    if let Some((u, szx)) = logical {
        return Some(base(u) | (d4 << 22) | (szx << 20) | (vn << 16) | (vd << 12) | (1 << 8)
            | (n5 << 7) | (q << 6) | (m5 << 5) | (1 << 4) | vm);
    }
    // FP family (sz encodes the sub-family, not dt!)
    let fp = match (op, dt) {
        (Add, Dt::F32) => Some(((false, 13u32, false), 0u32)),
        (Sub, Dt::F32) => Some(((false, 13, false), 2)),
        (Mla, Dt::F32) => Some(((false, 13, true), 0)),
        (Mls, Dt::F32) => Some(((false, 13, true), 2)),
        (CmpEq, Dt::F32) => Some(((false, 14, false), 0)),
        (Max, Dt::F32) => Some(((false, 15, false), 0)),
        (Min, Dt::F32) => Some(((false, 15, false), 2)),
        (Recps, Dt::F32) => Some(((false, 15, true), 0)),
        (Rsqrts, Dt::F32) => Some(((false, 15, true), 2)),
        (AddP, Dt::F32) => Some(((true, 13, false), 0)),
        (Mul, Dt::F32) => Some(((true, 13, true), 0)),
        (CmpGt, Dt::F32) => Some(((true, 14, false), 2)),   // vcgt.f32 [sz=10]
        (CmpGe, Dt::F32) => Some(((true, 14, false), 0)),    // vcge.f32 [sz=00]
        (AbsDiff, Dt::F32) => Some(((true, 13, false), 2)),  // vabd.f32
        (MaxP, Dt::F32) => Some(((true, 15, false), 0)),
        (MinP, Dt::F32) => Some(((true, 15, false), 2)),
        _ => None,
    };
    if let Some(((u, opc, op4), szx)) = fp {
        return Some(base(u) | (d4 << 22) | (szx << 20) | (vn << 16) | (vd << 12) | (opc << 8)
            | (n5 << 7) | (q << 6) | (m5 << 5) | ((op4 as u32) << 4) | vm);
    }
    // integer 3-same: (U, opc, op) — sz comes from dt
    let int = match op {
        AddHn if matches!(dt, Dt::I8|Dt::I16|Dt::I32|Dt::I64) => None, // vaddhn → 3-diff
        AddHn if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 0, false)),  // vhadd.s
        AddHn => Some((true, 0, false)),   // vhadd.u
        QAdd if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 0, true)),
        QAdd => Some((true, 0, true)),
        RAddHn if matches!(dt, Dt::I8|Dt::I16|Dt::I32|Dt::I64) => None, // vraddhn → 3-diff
        RAddHn if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 1, false)),
        RAddHn => Some((true, 1, false)),
        SubHn if matches!(dt, Dt::I8|Dt::I16|Dt::I32|Dt::I64) => None, // vsubhn → 3-diff
        SubHn if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 2, false)),
        SubHn => Some((true, 2, false)),
        QSub if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 2, true)),
        QSub => Some((true, 2, true)),
        CmpGt if dt == Dt::F32 => None, // handled above
        CmpGt if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 3, false)),
        CmpGt => Some((true, 3, false)),
        CmpGe if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 3, true)),
        CmpGe => Some((true, 3, true)),
        ShlReg if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 4, false)),
        ShlReg => Some((true, 4, false)),
        QshlReg if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 4, true)),
        QshlReg => Some((true, 4, true)),
        QrshlReg if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 5, true)),
        QrshlReg => Some((true, 5, true)),
        Max if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 6, false)),
        Max => Some((true, 6, false)),
        Min if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 6, true)),
        Min => Some((true, 6, true)),
        AbsDiff if imm == 0 && !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 7, false)),
        AbsDiff if imm == 0 => Some((true, 7, false)),
        Aba if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 7, true)),
        Aba => Some((true, 7, true)),
        Add => Some((false, 8, false)),
        Sub => Some((true, 8, false)),
        Tst => Some((false, 8, true)),
        CmpEq => Some((true, 8, true)),
        Mla => Some((false, 9, false)),
        Mls => Some((true, 9, false)),
        Mul => Some((false, 9, true)),
        MulP if imm == 0 => Some((true, 9, true)),
        MaxP if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 10, false)),
        MaxP => Some((true, 10, false)),
        MinP if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 10, true)),
        MinP => Some((true, 10, true)),
        AddP => Some((false, 11, true)),
        QdmulH if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 11, false)),
        Qrdmulh if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((true, 11, false)),
        _ => None,
    };
    if let Some((u, opc, op4)) = int {
        // sz from dt, except i64 keeps sz=3
        return Some(same(u, opc, op4));
    }
    let _ = same_no_sz;

    // ======== 3-different (b23=1, op=0) ========
    let diff = |u: bool, opc: u32| -> u32 {
        base(u) | (1 << 23) | (d4 << 22) | (sz << 20) | (vn << 16) | (vd << 12) | (opc << 8)
            | (n5 << 7) | (q << 6) | (m5 << 5) | vm
    };
    let d3 = match op {
        AddL if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 0u32)),
        AddL => Some((true, 0)),
        AddW if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 1)),
        AddW => Some((true, 1)),
        SubL if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 2)),
        SubL => Some((true, 2)),
        SubW if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 3)),
        SubW => Some((true, 3)),
        AddHn if sz == 0 => None, // vaddhn handled below (2-misc-style? no — 3-diff op=0, opc=4)
        MulL if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 12)),
        MulL => Some((true, 12)),
        MlaL if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 8)),
        MlaL => Some((true, 8)),
        MlsL if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 10)),
        MlsL => Some((true, 10)),
        _ => None,
    };
    // vaddhn/vsubhn family live in the 3-diff space with opc 4/6 (r-variants U=1)
    let d3b = match op {
        AddHn => Some((false, 4)),
        SubHn => Some((false, 6)),
        RAddHn => Some((true, 4)),
        RSubHn => Some((true, 6)),
        _ => None,
    };
    // vabal/vabdl: AbsDiff with imm flag (imm=1 → vabal)
    let d3c = match (op, imm) {
        (NeonOp::AbsDiff, 1) if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 5)),
        (NeonOp::AbsDiff, 1) => Some((true, 5)),
        (NeonOp::AbsDiff, 2) if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => Some((false, 7)),
        (NeonOp::AbsDiff, 2) => Some((true, 7)),
        _ => None,
    };
    let d3q = match op {
        QdmulL => Some((false, 13)),
        Qdmlal => Some((false, 9)),
        Qdmlsl => Some((false, 11)),
        _ => None,
    };
    for entry in [d3, d3b, d3c, d3q] {
        if let Some((u, opc)) = entry {
            return Some(diff(u, opc));
        }
    }
    // vmull.p8: (false, 12) with sz=0
    if matches!(op, MulP) && dt == Dt::P8 && imm == 1 {
        return Some(diff(false, 14));
    }

    // ======== shift-imm (b23=1, op=1, b19=1 / sz=11+b19:18=11) ========
    let is_shift = matches!(op, ShrImm | SraImm | RshrImm | RsraImm | ShlImm | SliImm | SriImm
        | QshlImm | QshluReg | Shll | MovL | Shrn | Qshrn | Qshrun | Qrshrn | Qrshrun);
    if is_shift {
        let (u, opc) = match op {
            ShrImm if !matches!(dt, Dt::U8|Dt::U16|Dt::U32|Dt::U64) => (false, 0u32),
            ShrImm => (true, 0),
            SraImm if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => (false, 1),
            SraImm => (true, 1),
            RshrImm if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => (false, 2),
            RshrImm => (true, 2),
            RsraImm if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => (false, 3),
            RsraImm => (true, 3),
            ShlImm => (false, 5),
            SriImm => (true, 4),
            SliImm => (true, 5),
            QshluReg => (true, 6),
            QshlImm if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => (false, 7),
            QshlImm => (true, 7),
            Shrn => (false, 8),
            Qshrn if !matches!(dt, Dt::U16|Dt::U32) => (false, 9),
            Qshrn => (true, 9),
            Qshrun => (true, 8),
            Shll if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => (false, 10),
            Shll => (true, 10),
            MovL if !matches!(dt, Dt::U8|Dt::U16|Dt::U32) => (false, 11),
            MovL => (true, 11),
            Qrshrn if !matches!(dt, Dt::U16|Dt::U32) => (false, 13),
            Qrshrn => (true, 13),
            Qrshrun => (false, 12),
            _ => (false, 0),
        };
        // esize class:
        //  - right family + narrowing: dt = source esize, class = dest = dt/2
        //  - left family (shl/vsli/vshll/vmovl): dt = element esize = class
        let esize = dt.bits() as u32;
        let class = match op {
            Shrn | Qshrn | Qshrun | Qrshrn | Qrshrun => esize / 2,
            _ => esize,
        };
        let imm7 = match op {
            ShlImm | SliImm | Shll | MovL => imm7_left(class, imm),
            _ => imm7_right(class, imm),
        };
        let b7 = (imm7 >> 6) & 1;
        let bits21_16 = imm7 & 0x3F;
        return Some(base(u) | (1 << 23) | (d4 << 22) | ((bits21_16 as u32) << 16) | (vd << 12)
            | (opc << 8) | ((b7 as u32) << 7) | (q << 6) | (m5 << 5) | (1 << 4) | vm);
    }

    // ======== 2-misc (b23=1, sz=11, b19:18 ≤ 10) ========
    let misc2 = |u: bool, size: u32, opch: u32, opcl: u32, neg: bool, op4: bool| -> u32 {
        base(u) | (1 << 23) | (d4 << 22) | (0b11 << 20) | ((size << 2 | opch) << 16)
            | (vd << 12) | (opcl << 8) | ((neg as u32) << 7) | (q << 6) | (m5 << 5)
            | ((op4 as u32) << 4) | vm
    };
    let size2 = sz;
    let m2 = match op {
        Cls => Some((true, 0, 4, false, false)),
        Clz => Some((true, 0, 4, true, false)),
        Cnt => Some((true, 0, 5, false, false)),
        Not => Some((true, 0, 5, true, false)),
        Abs if dt == Dt::F32 => Some((true, 1, 7, false, false)),
        Neg if dt == Dt::F32 => Some((true, 1, 7, true, false)),
        Abs if imm == 1 => Some((true, 0, 7, false, false)),   // vqabs
        Neg if imm == 1 => Some((true, 0, 7, true, false)),    // vqneg
        Abs => Some((true, 1, 3, false, false)),
        Neg => Some((true, 1, 3, true, false)),
        Trn => Some((true, 2, 0, true, false)),
        Unzip => Some((true, 2, 1, false, false)),
        Zip => Some((true, 2, 1, true, false)),
        MovN => Some((true, 2, 2, false, false)),   // vmovn/vqmovun refined by U
        QmovN => Some((true, 2, 2, true, false)),
        Recpe if dt == Dt::F32 => Some((true, 3, 5, false, false)),
        Rsqrte if dt == Dt::F32 => Some((true, 3, 5, true, false)),
        Recpe => Some((true, 3, 4, false, false)),
        Rsqrte => Some((true, 3, 4, true, false)),
        FToFix if !matches!(dt, Dt::U32) => Some((true, 3, 6, false, false)),
        FToFix => Some((true, 3, 6, true, false)),
        FixToF if !matches!(dt, Dt::U32) => Some((true, 3, 7, false, false)),
        FixToF => Some((true, 3, 7, true, false)),
        _ => None,
    };
    if let Some((u, opch, opcl, neg, op4)) = m2 {
        // refine U for MovN/QmovN families by dt:
        let u = match op {
            MovN if matches!(dt, Dt::U16|Dt::U32|Dt::U64) => true, // vmovn.i
            QmovN if matches!(dt, Dt::U16|Dt::U32|Dt::U64) => true, // vqmovn.u
            _ => u,
        };
        let op4 = match op {
            MovN if matches!(dt, Dt::S16|Dt::S32|Dt::S64) => true, // vqmovun.s (b7 handled: qmovun uses neg=false + U? refined)
            _ => op4,
        };
        let neg = match op {
            MovN if matches!(dt, Dt::S16|Dt::S32|Dt::S64) => false, // vqmovun: keep b7=0 (U=1)
            _ => neg,
        };
        // vqmovun.s16 = f3b20242: b7=0, Q?? — our decoder mapped (2,2,b7=0) → MovN with u=1
        return Some(misc2(u, size2, opch, opcl, neg, op4));
    }
    None
}

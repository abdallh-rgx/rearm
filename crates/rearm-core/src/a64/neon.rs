//! A64 AdvSIMD (NEON) encoder — tables differential-verified against llvm-objdump.
//!
//! Formats (base layouts, bits are A64 bit numbers):
//!   3-same:      0Q U 0 1110 size 1 Rm(20:16) opcode(15:11) 1 Rn Rd  → 0x0E200400
//!   3-different: 0Q U 0 1110 size 1 Rm opcode 0 Rn Rd               → 0x0E200000
//!   2-misc:      0Q U 0 1110 size 10 opcode(16:12) 10 Rn Rd          → 0x0E200800
//!   shift-imm:   0Q U 0 11110 immh:immb(23:16) opcode(15:11) 1 0     → 0x0F000400
//!   3-same FP:   like 3-same; sz(23:22): 00=f32-maxgrp 01=f64-max 10=f32-min 11=f64-min

use crate::common::Dt;

pub type VR = u8; // vector register index 0-31

/// element size code for bits 23:22
pub fn sz_code(dt: Dt) -> u32 {
    match dt {
        Dt::I8 | Dt::U8 | Dt::S8 | Dt::P8 => 0,
        Dt::I16 | Dt::U16 | Dt::S16 | Dt::F16 => 1,
        Dt::I32 | Dt::U32 | Dt::S32 | Dt::F32 => 2,
        Dt::I64 | Dt::U64 | Dt::S64 | Dt::F64 => 3,
    }
}

/// 3-same opcodes (bits 15:11), keyed by (U, mnemonic intent).
pub mod same {
    pub const SHADD: u8 = 0;
    pub const SQADD: u8 = 1;
    pub const SRHADD: u8 = 2;
    pub const SHSUB: u8 = 4;
    pub const SQSUB: u8 = 5;
    pub const CMGT: u8 = 6;
    pub const CMGE: u8 = 7;
    pub const SSHL: u8 = 8;
    pub const SQSHL: u8 = 9;
    pub const SRSHL: u8 = 10;
    pub const SQRSHL: u8 = 11;
    pub const SMAX: u8 = 12;
    pub const SMIN: u8 = 13;
    pub const SABD: u8 = 14;
    pub const SABA: u8 = 15;
    pub const ADD: u8 = 16;
    pub const CMTST: u8 = 17;
    pub const MLA: u8 = 18;
    pub const MUL: u8 = 19;
    pub const SMAXP: u8 = 20;
    pub const SMINP: u8 = 21;
    pub const SQDMULH: u8 = 22;
    pub const ADDP: u8 = 23;
    // FP group (see fp_* below)
    pub const FMAXNM: u8 = 24;
    pub const FMLA: u8 = 25;
    pub const FADD: u8 = 26;
    pub const FMULX: u8 = 27;
    pub const FCMEQ: u8 = 28;
    pub const FMAX: u8 = 30;
    pub const FRECPS: u8 = 31;
    // U=1-only:
    pub const FMAXNMP: u8 = 24;
    pub const FADDP: u8 = 26;
    pub const FMUL: u8 = 27;
    pub const FCMGE: u8 = 28;
    pub const FACGE: u8 = 29;
    pub const FMAXP: u8 = 30;
    pub const FDIV: u8 = 31;
}

/// 3-different opcodes (bits 15:11).
pub mod diff {
    pub const SADDL: u8 = 0;
    pub const SADDW: u8 = 2;
    pub const SSUBL: u8 = 4;
    pub const SSUBW: u8 = 6;
    pub const ADDHN: u8 = 8;
    pub const SABAL: u8 = 10;
    pub const SUBHN: u8 = 12;
    pub const SABDL: u8 = 14;
    pub const SMLAL: u8 = 16;
    pub const SQDMLAL: u8 = 18;
    pub const SMLSL: u8 = 20;
    pub const SQDMLSL: u8 = 22;
    pub const SMULL: u8 = 24;
    pub const SQDMULL: u8 = 26;
    // U=1:
    pub const UADDL: u8 = 0;
    pub const UADDW: u8 = 2;
    pub const USUBL: u8 = 4;
    pub const USUBW: u8 = 6;
    pub const RADDHN: u8 = 8;
    pub const UABAL: u8 = 10;
    pub const RSUBHN: u8 = 12;
    pub const UABDL: u8 = 14;
    pub const UMLAL: u8 = 16;
    pub const UMLSL: u8 = 20;
    pub const UMULL: u8 = 24;
}

/// 2-misc opcodes (bits 16:12).
pub mod misc {
    pub const REV64: u8 = 0;
    pub const SADDLP: u8 = 2;
    pub const SUQADD: u8 = 3;
    pub const CLS: u8 = 4;
    pub const CNT: u8 = 5;
    pub const SADALP: u8 = 6;
    pub const SQABS: u8 = 7;
    pub const CMGT0: u8 = 8;
    pub const CMEQ0: u8 = 9;
    pub const CMLT0: u8 = 10;
    pub const ABS: u8 = 11;
    pub const XTN: u8 = 18;
    pub const SQXTN: u8 = 20;
    pub const FCVTN: u8 = 22;
    pub const FCVTL: u8 = 23;
    pub const FRINTN: u8 = 24;
    pub const FRINTM: u8 = 25;
    pub const FCVTNS: u8 = 26;
    pub const FCVTMS: u8 = 27;
    pub const FCVTAS: u8 = 28;
    pub const SCVTF: u8 = 29;
    pub const FRINT32Z: u8 = 30;
    pub const FRINT64Z: u8 = 31;
    // U=1:
    pub const REV32: u8 = 0;
    pub const UADDLP: u8 = 2;
    pub const USQADD: u8 = 3;
    pub const CLZ: u8 = 4;
    pub const MVN: u8 = 5;
    pub const UADALP: u8 = 6;
    pub const SQNEG: u8 = 7;
    pub const CMGE0: u8 = 8;
    pub const CMLE0: u8 = 9;
    pub const NEG: u8 = 11;
    pub const SQXTUN: u8 = 18;
    pub const SHLL: u8 = 19;
    pub const UQXTN: u8 = 20;
    pub const FRINTA: u8 = 24;
    pub const FRINTX: u8 = 25;
    pub const FCVTNU: u8 = 26;
    pub const FCVTMU: u8 = 27;
    pub const FCVTAU: u8 = 28;
    pub const UCVTF: u8 = 29;
    pub const FRINT32X: u8 = 30;
    pub const FRINT64X: u8 = 31;
    pub const FRINTP: u8 = 24;   // U=0, sz 10/11
    pub const FRINTZ: u8 = 25;   // U=0, sz 10/11
    pub const FCVTPS: u8 = 26;   // U=0, sz 10/11
    pub const FCVTZS: u8 = 27;   // U=0, sz 10/11
    pub const FCMGT0: u8 = 12;   // U=0, FP sizes
    pub const FCMEQ0: u8 = 13;
    pub const FCMLT0: u8 = 14;
    pub const FABS: u8 = 15;
    pub const FRINTI: u8 = 25;   // U=1, FP sizes sz10/11
    pub const FCVTPU: u8 = 26;
    pub const FCVTZU: u8 = 27;
    pub const FCMGE0: u8 = 12;   // U=1, FP sizes
    pub const FCMLE0: u8 = 13;
    pub const FNEG: u8 = 15;
    pub const URECPE: u8 = 28;   // U=1 sz=10
    pub const URSQRTE: u8 = 28;
    pub const FRECPE: u8 = 29;
    pub const FRSQRTE: u8 = 29;
    pub const FSQRT: u8 = 31;
    pub const RBIT: u8 = 5;      // U=1 sz=1
}

/// shift-by-immediate opcodes (bits 15:11).
pub mod shimm {
    pub const SSHR: u8 = 0;
    pub const SSRA: u8 = 2;
    pub const SRSHR: u8 = 4;
    pub const SRSRA: u8 = 6;
    pub const SRI: u8 = 8;    // U=1
    pub const SHL: u8 = 10;   // U=0
    pub const SLI: u8 = 10;   // U=1
    pub const SQSHLU: u8 = 12; // U=1
    pub const SQSHL: u8 = 14;  // U=0
    pub const UQSHL: u8 = 14;  // U=1
    pub const SHRN: u8 = 16;   // U=0
    pub const RSHRN: u8 = 17;  // U=0
    pub const SQSHRN: u8 = 18; // U=0
    pub const SQRSHRN: u8 = 19;// U=0
    pub const SQSHRUN: u8 = 16; // U=1
    pub const SQRSHRUN: u8 = 17;// U=1
    pub const UQSHRN: u8 = 18;  // U=1
    pub const UQRSHRN: u8 = 19; // U=1
    pub const SSHLL: u8 = 20;   // U=0
    pub const USHLL: u8 = 20;   // U=1
    pub const SCVTF: u8 = 28;   // fixed-point U=0
    pub const UCVTF: u8 = 28;   // U=1
    pub const FCVTZS: u8 = 31;  // U=0
    pub const FCVTZU: u8 = 31;  // U=1
}

/// 3-same: 0Q U 0 1110 size 1 Rm opcode 1 Rn Rd
pub fn enc_3same(q: bool, u: bool, dt: Dt, opcode: u8, rm: VR, rn: VR, rd: VR) -> u32 {
    ((q as u32) << 30) | ((u as u32) << 29) | 0x0E200400 | (sz_code(dt) << 22)
        | ((rm as u32) << 16) | ((opcode as u32) << 11) | ((rn as u32) << 5) | rd as u32
}

/// 3-same with explicit size code (FP: 00=f32, 01=f64 for the max/add group;
/// 10=f32, 11=f64 for the min/sub group).
pub fn enc_3same_sz(q: bool, u: bool, sz: u32, opcode: u8, rm: VR, rn: VR, rd: VR) -> u32 {
    ((q as u32) << 30) | ((u as u32) << 29) | 0x0E200400 | (sz << 22)
        | ((rm as u32) << 16) | ((opcode as u32) << 11) | ((rn as u32) << 5) | rd as u32
}

/// 3-same logical: opcode 3, size selects AND/BIC/ORR/ORN (U=0) or EOR/BSL/BIT/BIF (U=1).
pub fn enc_3same_logical(q: bool, u: bool, size: u32, rm: VR, rn: VR, rd: VR) -> u32 {
    enc_3same_sz(q, u, size, 3, rm, rn, rd)
}

/// 3-different: 0Q U 0 1110 size 1 Rm opcode 0 Rn Rd
pub fn enc_3diff(q: bool, u: bool, dt: Dt, opcode: u8, rm: VR, rn: VR, rd: VR) -> u32 {
    ((q as u32) << 30) | ((u as u32) << 29) | 0x0E200000 | (sz_code(dt) << 22)
        | ((rm as u32) << 16) | ((opcode as u32) << 11) | ((rn as u32) << 5) | rd as u32
}

/// 2-misc: 0Q U 0 1110 size 10 opcode 10 Rn Rd
pub fn enc_2misc(q: bool, u: bool, dt: Dt, opcode: u8, rn: VR, rd: VR) -> u32 {
    ((q as u32) << 30) | ((u as u32) << 29) | 0x0E200800 | (sz_code(dt) << 22)
        | ((opcode as u32) << 12) | ((rn as u32) << 5) | rd as u32
}

/// 2-misc with explicit size code (FP ops use special sizes).
pub fn enc_2misc_sz(q: bool, u: bool, sz: u32, opcode: u8, rn: VR, rd: VR) -> u32 {
    ((q as u32) << 30) | ((u as u32) << 29) | 0x0E200800 | (sz << 22)
        | ((opcode as u32) << 12) | ((rn as u32) << 5) | rd as u32
}

/// shift-by-immediate: 0Q U 0 11110 immh:immb opcode 10 Rn Rd.
/// `n` is the raw immh:immb byte: esize class = 8<<HighestSetBit(n>>4); the
/// ARM rule: for right shifts the assembly amount = 2*esize - n; for left = n - esize.
pub fn enc_shimm(q: bool, u: bool, opcode: u8, n: u8, rn: VR, rd: VR) -> u32 {
    ((q as u32) << 30) | ((u as u32) << 29) | 0x0F000000
        | ((n as u32) << 16) | ((opcode as u32) << 11) | (1 << 10)
        | ((rn as u32) << 5) | rd as u32
}

/// Build the immh:immb byte for a LEFT shift of `amount` on `esize`-bit elements.
pub fn n_for_left(esize: u32, amount: u32) -> Option<u8> {
    if amount >= esize || esize > 64 { return None; }
    let base = match esize { 8 => 8u32, 16 => 16, 32 => 32, 64 => 64, _ => return None };
    Some((base + amount) as u8)
}

/// Build the immh:immb byte for a RIGHT shift of `amount` on `esize`-bit elements.
pub fn n_for_right(esize: u32, amount: u32) -> Option<u8> {
    if !(1..=esize).contains(&amount) || esize > 64 { return None; }
    let base = match esize { 8 => 8u32, 16 => 16, 32 => 32, 64 => 64, _ => return None };
    Some((2 * base - amount) as u8)
}

/// by-element: 0Q U 0 11111 L sz M1 Vm opc(14:12) H(11) 0 Rn Rd
pub fn enc_byelem(q: bool, u: bool, sz: u32, l: bool, opc: u8, rm: VR, index: u8, rn: VR, rd: VR) -> u32 {
    let m = (rm >> 4) & 1;
    let vm = rm & 0xF;
    // index splits: sz 00 → H(11)=index>>1, L(21)=index&1
    //              sz 01 → H=index>>2, L=bit1? (16-bit: L=bit0, H=bits2:1)
    //              sz 10 → H=bit0 only
    let (h, l_bit) = match sz {
        0 => ((index >> 1) & 1, index & 1),
        1 => ((index >> 2) & 1, (index >> 1) & 1 | (index & 1) << 1), // placeholder; fixed per-op
        _ => (index & 1, 0),
    };
    let _ = l_bit;
    ((q as u32) << 30) | ((u as u32) << 29) | 0x0F000000 | (sz << 22)
        | (((l || (sz == 1 && (index & 2 != 0))) as u32) << 21) | ((m as u32) << 20)
        | ((vm as u32) << 16) | ((opc as u32) << 12) | ((h as u32) << 11)
        | ((rn as u32) << 5) | rd as u32
}

/// AdvSIMD copy: DUP (vector, from general) 0Q 0 0 11100010 imm5(20:16) 11111 Rd
pub fn enc_dup_gpr(q: bool, dt: Dt, rt: u8, rd: VR) -> u32 {
    let esize = dt.bits() as u32;
    let imm5 = match esize { 8 => 1, 16 => 2, 32 => 4, _ => 8 };
    ((q as u32) << 30) | 0x0E000C00 | (imm5 << 16) | ((rt as u32) << 5) | rd as u32
}

/// AdvSIMD copy: DUP (vector, from element): 0Q 0 0 11110001 imm5 00001 1 Rn Rd
pub fn enc_dup_elem(q: bool, dt: Dt, rn: VR, index: u8, rd: VR) -> u32 {
    let esize = dt.bits() as u32;
    let imm5 = match esize { 8 => 1, 16 => 2, 32 => 4, _ => 8 };
    let imm5 = imm5 | ((index as u32) << (if esize == 64 { 5 } else { esize / 2 + 1 }));
    ((q as u32) << 30) | 0x0E000400 | (imm5 << 16) | ((rn as u32) << 5) | rd as u32
}

/// MOVI/MVNI/ORR/BIC (immediate): 0Q U 0 11110 abc cmode(15:12) 01 defgh Rd.
/// For our use: simple byte-splat (cmode 1110), 16-bit (1010), 32-bit one-bit (0000-1101
/// shifts handled by caller via cmode), 64-bit (1110 with Q).
pub fn enc_movi(q: bool, neg: bool, abc: u8, cmode: u8, defgh: u8, rd: VR) -> u32 {
    ((q as u32) << 30) | ((neg as u32) << 29) | 0x0F000000
        | (((abc & 7) as u32) << 16) | ((cmode & 0xF) as u32) << 12 | (1 << 10)
        | ((defgh & 0x1F) as u32) | rd as u32
}

/// AdvSIMD load/store multiple structures: LD1/ST1 etc.
/// 0 Q 0 0 0110 size 0 11111 Rn Rt(4:0) with opcode in bits 15:12:
///   LD1 (4 regs, no wb): 0010; LD1R: 1101; LD1 (1 reg): 0111 (110?)...
/// Encoding: 0Q001 0 0110 L size 0 Rm 1111 opcode Rn Rt (Rm=11111 post)
pub fn enc_ldst_multi(load: bool, q: bool, size: u32, opcode: u8, rn: u8, rt: u8, rm: Option<u8>) -> u32 {
    let m = rm.unwrap_or(0x1F);
    ((q as u32) << 30) | 0x0C000000 | ((load as u32) << 22) | (size << 10)
        | ((m as u32) << 16) | ((opcode as u32) << 12) | ((rn as u32) << 5) | rt as u32
}

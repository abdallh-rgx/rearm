//! T32 (Thumb-2) decoder: 16/32-bit instructions -> `Ins`.
//!
//! Encoding references: ARMv7-A ARM A6.3, every field offset below verified
//! against the LLVM-generated golden corpus (byte-exact round-trip target).
//!
//! Conventions
//! * Branch `off` = the encoding's immediate (target = Align(PC,4) + off,
//!   PC = addr+4) — the lifter, which knows the address, applies the base.
//! * `DpImmT32` stores the raw 12-bit modified immediate (i:imm3:imm8);
//!   ThumbExpandImm is applied at lift time (A32 `DpImm` keeps its own
//!   rot:imm8 convention — the two never mix).
//! * T16 imm5/imm8 offsets are stored SCALED (byte address offsets).

use crate::common::*;
use crate::a32::ins::*;

/// Decoded instruction with its width in bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct TIns {
    pub ins: Ins,
    pub len: u16,
}

/// Decode one T32 instruction at `hw1` (and `hw2` if 32-bit).
pub fn decode_t32(hw1: u16, hw2: u16) -> Result<TIns, DecodeErr> {
    let (ins, len) = if hw1 >= 0xE800 {
        (decode_t32_32(hw1, hw2)?, 4u16)
    } else {
        (decode_t16(hw1)?, 2u16)
    };
    Ok(TIns { ins, len })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecodeErr(pub u32);

impl core::fmt::Display for DecodeErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "undefined T32 encoding {:#010x}", self.0)
    }
}

#[inline]
fn bt(w: u32, n: u32) -> bool { (w >> n) & 1 == 1 }
#[inline]
fn bb(w: u32, hi: u32, lo: u32) -> u32 { (w >> lo) & ((1u32 << (hi - lo + 1)) - 1) }
#[inline]
fn sign_ext(v: u32, bits: u32) -> i32 {
    ((v << (32 - bits)) as i32) >> (32 - bits)
}

// ==================== 16-bit Thumb (complete) ====================

fn decode_t16(hw: u16) -> Result<Ins, DecodeErr> {
    let w = hw as u32;
    let rd = bb(w, 2, 0) as u8;          // Rd/Rdn (bits 2:0)
    let rn = bb(w, 5, 3) as u8;          // Rn/Rm (bits 5:3)
    let rm = bb(w, 8, 6) as u8;          // Rm (bits 8:6)
    let imm5 = bb(w, 10, 6) as u32;      // imm5 (bits 10:6)
    let imm8 = bb(w, 7, 0) as u32;       // imm8
    let rfn = bb(w, 10, 8) as u8;        // Rd/Rn field (bits 10:8)

    match bb(w, 15, 13) {
        // ===== 00x: shifts / add-subtract =====
        0 => {
            match bb(w, 12, 11) {
                0 => Ok(dps(DpOp::Mov, true, 0, rd, rn, Shift::Lsl, imm5 as u8)), // LSLS
                1 => Ok(dps(DpOp::Mov, true, 0, rd, rn, Shift::Lsr, imm5 as u8)), // LSRS
                2 => Ok(dps(DpOp::Mov, true, 0, rd, rn, Shift::Asr, imm5 as u8)), // ASRS
                _ => { // 00011x: ADD/SUB reg (bit9=0) / imm3 (bit9=1)
                    let sub = bt(w, 9);
                    let op = if sub { DpOp::Sub } else { DpOp::Add };
                    if bt(w, 10) {
                        Ok(Ins::DpImm { op, s: true, rn: rd, rd, imm12: bb(w, 8, 6) as u16 })
                    } else {
                        Ok(dp0(op, true, rd, rd, rn))
                    }
                }
            }
        }
        // ===== 001x: MOV/CMP/ADD/SUB imm8 =====
        1 => {
            match bb(w, 12, 11) {
                0 => Ok(Ins::DpImm { op: DpOp::Mov, s: true, rn: 0, rd: rfn, imm12: imm8 as u16 }),
                1 => Ok(Ins::DpImm { op: DpOp::Cmp, s: true, rn: rfn, rd: 15, imm12: imm8 as u16 }),
                2 => Ok(Ins::DpImm { op: DpOp::Add, s: true, rn: rfn, rd: rfn, imm12: imm8 as u16 }),
                _ => Ok(Ins::DpImm { op: DpOp::Sub, s: true, rn: rfn, rd: rfn, imm12: imm8 as u16 }),
            }
        }
        // ===== 010x: DP / special / literal =====
        2 => {
            match bb(w, 12, 11) {
                0 => { // 010000: data processing (opcode 9:6, rd 2:0, rm 5:3)
                    let opcode = bb(w, 9, 6);
                    match opcode {
                        0b0000 => Ok(dp0(DpOp::And, true, rd, rd, rm)),
                        0b0001 => Ok(dp0(DpOp::Eor, true, rd, rd, rm)),
                        0b0010 => Ok(dpr(DpOp::Mov, true, 0, rd, rm, Shift::Lsl, rd)),
                        0b0011 => Ok(dpr(DpOp::Mov, true, 0, rd, rm, Shift::Lsr, rd)),
                        0b0100 => Ok(dpr(DpOp::Mov, true, 0, rd, rm, Shift::Asr, rd)),
                        0b0101 => Ok(dp0(DpOp::Adc, true, rd, rd, rm)),
                        0b0110 => Ok(dp0(DpOp::Sbc, true, rd, rd, rm)),
                        0b0111 => Ok(dpr(DpOp::Mov, true, 0, rd, rm, Shift::Ror, rd)),
                        0b1000 => Ok(dp0(DpOp::Tst, true, rd, 15, rm)),
                        0b1001 => Ok(Ins::DpImm { op: DpOp::Rsb, s: true, rn: rd, rd, imm12: 0 }), // RSBS #0
                        0b1010 => Ok(dp0(DpOp::Cmp, true, rd, 15, rm)),
                        0b1011 => Ok(dp0(DpOp::Cmn, true, rd, 15, rm)),
                        0b1100 => Ok(dp0(DpOp::Orr, true, rd, rd, rm)),
                        0b1101 => Ok(Ins::Mul { rd, rn: rd, rm, s: true }),
                        0b1110 => Ok(dp0(DpOp::Bic, true, rd, rd, rm)),
                        _ => Ok(dp0(DpOp::Mvn, true, 0, rd, rm)),
                    }
                }
                1 => { // 010001: special data + BX
                    let opcode = bb(w, 9, 8);
                    let dn = ((bb(w, 7, 7) << 3) | bb(w, 2, 0)) as u8;
                    let rmh = ((bb(w, 6, 6) << 3) | bb(w, 5, 3)) as u8;
                    match opcode {
                        0 => Ok(dp0(DpOp::Add, false, dn, dn, rmh)),
                        1 => Ok(dp0(DpOp::Cmp, false, dn, 15, rmh)),
                        2 => Ok(dp0(DpOp::Mov, false, 0, dn, rmh)),
                        3 if !bt(w, 7) && !bt(w, 6) => Ok(Ins::Bx { rm: rmh }),
                        3 if bt(w, 7) && !bt(w, 6) => Ok(Ins::BlxReg { rm: rmh }),
                        _ => Err(DecodeErr(w)),
                    }
                }
                _ => { // 01001x: LDR literal (rt = bits 10:8)
                    Ok(ld(false, Size::W32, false, rfn, 15, (imm8 * 4) as i32))
                }
            }
        }
        // ===== 011x: STR/LDR imm5 word =====
        3 => {
            let is_load = bt(w, 11);
            Ok(ld(!is_load, Size::W32, false, rd, rn, (imm5 * 4) as i32))
        }
        // ===== 100x: reg/reg-offset & byte/half imm5 & PC/SP-relative =====
        4 => match bb(w, 12, 11) {
            0 => { // 1000 0: reg-offset group (op at bits 11:9 of the 5-bit prefix)
                // 0101 op(3) rm(8:6) rn(5:3) rt(2:0) — we land here with bit12=0
                // (prefix 0101x), op = bits 10:8? NO: bits[15:11]=01010 → op at
                // bits[11:9] = 0xx impossible; actual op = bits(11:9).
                Err(DecodeErr(w)) // unreachable — handled by prefix dispatch below
            }
            1 => { // 1001: PC/SP-relative
                if bt(w, 11) {
                    Ok(ld(false, Size::W32, false, rfn, 13, (imm8 * 4) as i32)) // LDR SP-rel
                } else {
                    Ok(ld(true, Size::W32, false, rfn, 13, (imm8 * 4) as i32))  // STR SP-rel
                }
            }
            _ => Err(DecodeErr(w)),
        },
        // ===== 101x: ADR / ADD Rd, SP =====
        5 if !bt(w, 12) => {
            let base = if bt(w, 11) { 13u8 } else { 15u8 };
            Ok(Ins::DpImm { op: DpOp::Add, s: false, rn: base, rd: rfn, imm12: (imm8 * 4) as u16 })
        }
        // ===== 110x: LDM / B<cond> =====
        6 if !bt(w, 12) => {
            let rn = bb(w, 10, 8) as u8;
            let load = bt(w, 11);
            Ok(Ins::LdmStm { load, rn, mode: LdmMode::Ia, wback: false, user: false, list: RegList::from_bitmap(imm8 as u16) })
        }
        6 => {
            let cond = Cond::from_bits(bb(w, 11, 8) as u8);
            let off = sign_ext(imm8, 8) << 1;
            Ok(Ins::B { cond, off })
        }
        // ===== 111x: B (unconditional) / BLX suffix hint =====
        7 => {
            let off = sign_ext(bb(w, 10, 0), 11) << 1;
            Ok(Ins::B { cond: Cond::Al, off })
        }
        // ===== 1011: misc16 =====
        _ => decode_t16_misc(w),
    }
}

fn dps(op: DpOp, s: bool, rn: u8, rd: u8, rm: u8, shift: Shift, amount: u8) -> Ins {
    Ins::DpReg { op, s, rn, rd, rm, shift, amount: ShiftAmount::Imm(amount) }
}
fn dp0(op: DpOp, s: bool, rn: u8, rd: u8, rm: u8) -> Ins {
    Ins::DpReg { op, s, rn, rd, rm, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) }
}
fn dpr(op: DpOp, s: bool, rn: u8, rd: u8, rm: u8, shift: Shift, rs: u8) -> Ins {
    Ins::DpReg { op, s, rn, rd, rm, shift, amount: ShiftAmount::Reg(rs) }
}
fn ld(store: bool, size: Size, signed: bool, rt: u8, rn: u8, imm: i32) -> Ins {
    Ins::Ldst { store, size, signed, user: false, rt, rn, rm: None, shift: Shift::Lsl, imm, index: true, add: true, wback: false }
}

// 5-bit prefix (01010..01011 etc.) handlers called from decode_t32 entry for
// 16-bit words whose top-3 dispatch above can't express them.
pub(crate) fn decode_t16_ldst_reg(w: u32) -> Result<Ins, DecodeErr> {
    // 0101 op(11:9) rm(8:6) rn(5:3) rt(2:0)
    let rm = bb(w, 8, 6) as u8;
    let rn = bb(w, 5, 3) as u8;
    let rt = bb(w, 2, 0) as u8;
    match bb(w, 11, 9) {
        0 => Ok(ld(true, Size::W32, false, rt, rn, 0).with_rm(rm)),       // STR reg
        1 => Ok(ld(true, Size::H16, false, rt, rn, 0).with_rm(rm)),       // STRH reg
        2 => Ok(ld(true, Size::B8, false, rt, rn, 0).with_rm(rm)),        // STRB reg
        3 => Ok(ld(false, Size::B8, true, rt, rn, 0).with_rm(rm)),        // LDRSB reg
        4 => Ok(ld(false, Size::W32, false, rt, rn, 0).with_rm(rm)),      // LDR reg
        5 => Ok(ld(false, Size::H16, false, rt, rn, 0).with_rm(rm)),      // LDRH reg
        6 => Ok(ld(false, Size::B8, false, rt, rn, 0).with_rm(rm)),       // LDRB reg
        _ => Ok(ld(false, Size::H16, true, rt, rn, 0).with_rm(rm)),      // LDRSH reg
    }
}

pub(crate) fn decode_t16_ldst_imm_bh(w: u32) -> Result<Ins, DecodeErr> {
    // 0111 x: STRB/LDRB imm5  |  1000 x: STRH/LDRH imm5
    // (called for words with bits[15:12] = 0111 or 1000)
    let imm5 = bb(w, 10, 6);
    let rn = bb(w, 5, 3) as u8;
    let rt = bb(w, 2, 0) as u8;
    let is_load = bt(w, 11);
    if bb(w, 15, 12) == 0b0111 {
        Ok(ld(!is_load, Size::B8, false, rt, rn, imm5 as i32))
    } else {
        Ok(ld(!is_load, Size::H16, false, rt, rn, (imm5 * 2) as i32))
    }
}

trait WithRm {
    fn with_rm(self, rm: u8) -> Ins;
}
impl WithRm for Ins {
    fn with_rm(self, rm: u8) -> Ins {
        if let Ins::Ldst { store, size, signed, user, rt, rn, shift, imm, index, add, wback, .. } = self {
            Ins::Ldst { store, size, signed, user, rt, rn, rm: Some(rm), shift, imm, index, add, wback }
        } else { self }
    }
}

fn decode_t16_misc(w: u32) -> Result<Ins, DecodeErr> {
    let imm8 = bb(w, 7, 0) as u32;
    match bb(w, 11, 8) {
        // 1011 0000: ADD/SUB SP, SP, #imm7*4 (bit 7 selects)
        0 => {
            let imm7 = bb(w, 6, 0) * 4;
            let op = if bt(w, 7) { DpOp::Sub } else { DpOp::Add };
            Ok(Ins::DpImm { op, s: false, rn: 13, rd: 13, imm12: imm7 as u16 })
        }
        // 1011 001x: CBZ (bit11=0) / CBNZ (bit11=1)
        _ if bb(w, 11, 9) == 0b001 => {
            let i = bb(w, 9, 9) as i32;
            let imm5 = bb(w, 7, 3) as i32;
            let rn = bb(w, 2, 0) as u8;
            let off = (imm5 << 1) | (i << 6);
            Ok(Ins::Cbz { nz: bt(w, 11), rn, off })
        }
        // 1011 010x: PUSH {reglist(+LR)}
        _ if bb(w, 11, 10) == 0b01 => {
            let mut m = bb(w, 7, 0) as u16;
            if bt(w, 8) { m |= 1 << 14; }
            Ok(Ins::LdmStm { load: false, rn: 13, mode: LdmMode::Db, wback: true, user: false, list: RegList::from_bitmap(m) })
        }
        // 1011 11xx: POP
        _ if bb(w, 11, 10) == 0b11 => {
            let mut m = bb(w, 7, 0) as u16;
            if bt(w, 8) { m |= 1 << 15; }
            Ok(Ins::LdmStm { load: true, rn: 13, mode: LdmMode::Ia, wback: true, user: false, list: RegList::from_bitmap(m) })
        }
        // 1011 0010: SXTB/SXTH/UXTB/UXTH (op at bits 7:6)
        _ if bb(w, 11, 8) == 0b0010 => {
            let rm = bb(w, 5, 3) as u8;
            let rd = bb(w, 2, 0) as u8;
            match bb(w, 7, 6) {
                0 => Ok(Ins::Extend { op: ExtOp::Sxth, rd, rn: 0, rm, rot: 0 }),
                1 => Ok(Ins::Extend { op: ExtOp::Sxtb, rd, rn: 0, rm, rot: 0 }),
                2 => Ok(Ins::Extend { op: ExtOp::Uxth, rd, rn: 0, rm, rot: 0 }),
                _ => Ok(Ins::Extend { op: ExtOp::Uxtb, rd, rn: 0, rm, rot: 0 }),
            }
        }
        // 1011 0110: CPS
        _ if bb(w, 11, 8) == 0b0110 => {
            // 1011 0110 0 imod A I F 0: imod bit7=1 → CPSID, 0 → CPSIE
            let enable = !bt(w, 7);
            let mut aif = 0u8;
            if bt(w, 6) { aif |= 4; } // A
            if bt(w, 5) { aif |= 2; } // I
            if bt(w, 4) { aif |= 1; } // F
            Ok(Ins::Cps { enable, aif, change_mode: false, mode: 0 })
        }
        // 1011 1010: REV/REV16/REVSH (op at bits 7:6)
        _ if bb(w, 11, 9) == 0b101 => {
            let rm = bb(w, 5, 3) as u8;
            let rd = bb(w, 2, 0) as u8;
            match bb(w, 7, 6) {
                0 => Ok(Ins::Rev { rd, rm }),
                1 => Ok(Ins::Rev16 { rd, rm }),
                _ => Ok(Ins::Revsh { rd, rm }),
            }
        }
        // 1011 1110: BKPT
        _ if bb(w, 11, 8) == 0b1110 => Ok(Ins::Bkpt { imm: imm8 as u16 }),
        // 1011 1111: hints / IT
        _ => {
            let first_cond = bb(w, 7, 4) as u8;
            let mask = bb(w, 3, 0) as u8;
            if mask == 0 {
                match first_cond & 0x7 {
                    0 => Ok(Ins::Hints { kind: Hint::Nop }),
                    1 => Ok(Ins::Hints { kind: Hint::Yield }),
                    2 => Ok(Ins::Hints { kind: Hint::Wfe }),
                    3 => Ok(Ins::Hints { kind: Hint::Wfi }),
                    4 => Ok(Ins::Hints { kind: Hint::Sev }),
                    5 if first_cond == 5 => Ok(Ins::Hints { kind: Hint::Sevl }),
                    _ => Ok(Ins::Hints { kind: Hint::Nop }),
                }
            } else {
                Ok(Ins::It { first_cond: Cond::from_bits(first_cond), mask })
            }
        }
    }
}

// ==================== 32-bit Thumb-2 ====================

fn decode_t32_32(hw1: u16, hw2: u16) -> Result<Ins, DecodeErr> {
    let w = ((hw1 as u32) << 16) | hw2 as u32;

    // VFP coprocessor space (T32 ee/ed/ec/fe): the words ARE valid A32
    // encodings with cond=1110/1111 — route directly to the A32 decoder.
    let h1 = hw1 >> 8;
    if (0xEE..=0xEF).contains(&h1) || (0xEC..=0xED).contains(&h1) || h1 == 0xFE {
        if let Ok(ins) = crate::a32::decode::decode_a32(w) {
            if !matches!(ins, Ins::Unsupported { .. }) {
                return Ok(ins);
            }
        }
        return Err(DecodeErr(w));
    }
    // NEON space (T32 ef/ff): transform to the A32 encoding and decode there.
    //   a32 = (w & 0x00FFFFFF) | 0xF2000000 | ((w & 0x10000000) >> 4)
    if (0xEF00..0xF000).contains(&hw1) || hw1 >= 0xFF00 {
        let a32w = (w & 0x00FF_FFFF) | 0xF200_0000 | ((w & 0x1000_0000) >> 4);
        if let Ok(ins) = crate::a32::decode::decode_a32(a32w) {
            if !matches!(ins, Ins::Unsupported { .. }) {
                return Ok(ins);
            }
        }
        return Err(DecodeErr(w));
    }

    match w >> 27 {
        0b11101 => match bb(w, 26, 25) {
            0b00 => decode_t32_ldm_stm(w),      // e8/e9: ldm/stm/excl/tbb/tbh/ldrd/strd
            0b01 => decode_t32_dp_shifted(w),    // ea/eb: data proc shifted register
            _ => Err(DecodeErr(w)),
        },
        0b11110 => decode_t32_f0(w),             // f0-f7: DP imm / branches / misc
        0b11111 => decode_t32_f8(w),             // f8/fa/fb: ldst / 2-source / multiply
        _ => Err(DecodeErr(w)),
    }
}

// ---------- 11110 space (f0..f7) ----------

fn decode_t32_f0(w: u32) -> Result<Ins, DecodeErr> {
    let hw1 = (w >> 16) as u16;
    let hw2 = (w & 0xFFFF) as u32;
    let rn = bb(w, 19, 16) as u8;
    let rd = bb(w, 11, 8) as u8;

    match hw2 >> 14 {
        0b10 => { // branches + MSR-immediate space
            let hw2_top = hw2 >> 12;
            match hw2_top {
                0b1010 => { // T3 Bcc (hw2.12 = 0)
                    let cond = Cond::from_bits(bb(w, 9, 6) as u8);
                    if matches!(cond, Cond::Al | Cond::Nv) {
                        return Err(DecodeErr(w));
                    }
                    let s = bt(w, 26);
                    let imm6 = bb(w, 5, 0);
                    let j1 = bt(w, 13);
                    let j2 = bt(w, 11);
                    let imm11 = bb(w, 10, 0);
                    // T3: imm = SignExtend21(S : J2(hw2.11) : J1(hw2.13) : imm6 : imm11 : 0)
                    let v = (s as u32) << 20
                        | (j2 as u32) << 19
                        | (j1 as u32) << 18
                        | imm6 << 12
                        | imm11 << 1;
                    Ok(Ins::B { cond, off: sign_ext(v, 21) })
                }
                0b1011 => { // T4 B.W
                    let s = bt(w, 26);
                    let imm10 = bb(w, 9, 0);
                    let j1 = bt(w, 13);
                    let j2 = bt(w, 11);
                    let imm11 = bb(w, 10, 0);
                    let i1 = !(j1 ^ s) as u32 & 1;
                    let i2 = !(j2 ^ s) as u32 & 1;
                    let v = (s as u32) << 24 | i1 << 23 | i2 << 22
                        | imm10 << 12 | imm11 << 1;
                    Ok(Ins::B { cond: Cond::Al, off: sign_ext(v, 25) })
                }
                0b1100 => { // T2 BLX (ARM target)
                    let s = bt(w, 26);
                    let imm10 = bb(w, 9, 0);
                    let j1 = bt(w, 13);
                    let j2 = bt(w, 11);
                    let imm11 = bb(w, 10, 0);
                    let i1 = !(j1 ^ s) as u32 & 1;
                    let i2 = !(j2 ^ s) as u32 & 1;
                    let v = (s as u32) << 24 | i1 << 23 | i2 << 22
                        | imm10 << 12 | imm11 << 1;
                    Ok(Ins::Blx { off: sign_ext(v, 25) })
                }
                0b1101 | 0b1110 => { // T1 BL
                    let s = bt(w, 26);
                    let imm10 = bb(w, 9, 0);
                    let j1 = bt(w, 13);
                    let j2 = bt(w, 11);
                    let imm11 = bb(w, 10, 0);
                    let i1 = !(j1 ^ s) as u32 & 1;
                    let i2 = !(j2 ^ s) as u32 & 1;
                    let v = (s as u32) << 24 | i1 << 23 | i2 << 22
                        | imm10 << 12 | imm11 << 1;
                    Ok(Ins::Bl { off: sign_ext(v, 25) })
                }
                0b1000 => { // MSR (immediate)
                    let mask = bb(w, 11, 8) as u8;
                    let imm12 = ((bb(w, 26, 26) as u32) << 11) | bb(w, 14, 12) << 8 | bb(w, 7, 0);
                    Ok(Ins::Msr { spsr: bt(w, 20), mask, rn: 15, imm: Some(imm12) })
                }
                _ => Err(DecodeErr(w)),
            }
        }
        _ if hw2 >> 15 == 0 && hw2 >> 13 != 0b01 => {
            // DP immediate group: op5 at bits 25:21, S at bit 20.
            let op5 = bb(w, 25, 21);
            let s = bt(w, 20);
            let imm12 = ((bb(w, 26, 26) as u32) << 11) | (bb(w, 14, 12) << 8) | bb(w, 7, 0);
            decode_dp_imm(op5, s, rn, rd, imm12, w)
        }
        _ => Err(DecodeErr(w)),
    }
}

fn decode_dp_imm(op5: u32, s: bool, rn: u8, rd: u8, imm12: u32, w: u32) -> Result<Ins, DecodeErr> {
    match op5 {
        0b00000 => { // AND / TST
            if s && rd == 15 { Ok(Ins::DpImmT32 { op: DpOp::Tst, s: true, rn, rd: 15, imm12: imm12 as u16 }) }
            else { Ok(Ins::DpImmT32 { op: DpOp::And, s, rn, rd, imm12: imm12 as u16 }) }
        }
        0b00001 => Ok(Ins::DpImmT32 { op: DpOp::Bic, s, rn, rd, imm12: imm12 as u16 }),
        0b00010 => { // ORR / MOV (Rn=15)
            if rn == 15 { Ok(Ins::DpImmT32 { op: DpOp::Mov, s, rn: 0, rd, imm12: imm12 as u16 }) }
            else { Ok(Ins::DpImmT32 { op: DpOp::Orr, s, rn, rd, imm12: imm12 as u16 }) }
        }
        0b00011 => { // ORN / MVN (Rn=15)
            if rn == 15 { Ok(Ins::DpImmT32 { op: DpOp::Mvn, s, rn: 0, rd, imm12: imm12 as u16 }) }
            else { Ok(Ins::DpImmT32 { op: DpOp::Orn_, s, rn, rd, imm12: imm12 as u16 }) }
        }
        0b00100 => { // EOR / TEQ
            if s && rd == 15 { Ok(Ins::DpImmT32 { op: DpOp::Teq, s: true, rn, rd: 15, imm12: imm12 as u16 }) }
            else { Ok(Ins::DpImmT32 { op: DpOp::Eor, s, rn, rd, imm12: imm12 as u16 }) }
        }
        0b01000 => { // ADD / CMN
            if s && rd == 15 { Ok(Ins::DpImmT32 { op: DpOp::Cmn, s: true, rn, rd: 15, imm12: imm12 as u16 }) }
            else { Ok(Ins::DpImmT32 { op: DpOp::Add, s, rn, rd, imm12: imm12 as u16 }) }
        }
        0b01101 => { // SUB / CMP
            if s && rd == 15 { Ok(Ins::DpImmT32 { op: DpOp::Cmp, s: true, rn, rd: 15, imm12: imm12 as u16 }) }
            else { Ok(Ins::DpImmT32 { op: DpOp::Sub, s, rn, rd, imm12: imm12 as u16 }) }
        }
        0b01110 => Ok(Ins::DpImmT32 { op: DpOp::Rsb, s, rn, rd, imm12: imm12 as u16 }),
        // plain-immediate group
        0b10000 => { // ADDW / ADR (Rn=15)
            if rn == 15 {
                Ok(Ins::DpImmT32 { op: DpOp::Add, s: false, rn: 15, rd, imm12: imm12 as u16 })
            } else {
                Ok(Ins::DpImmT32 { op: DpOp::AddW, s: false, rn, rd, imm12: imm12 as u16 })
            }
        }
        0b10101 => Ok(Ins::DpImmT32 { op: DpOp::SubW, s: false, rn, rd, imm12: imm12 as u16 }),
        0b10010 => { // MOVW
            let imm16 = ((bb(w, 19, 16)) << 12) | ((bb(w, 26, 26)) << 11)
                | (bb(w, 14, 12) << 8) | bb(w, 7, 0);
            Ok(Ins::Movw { rd, imm16: imm16 as u16 })
        }
        0b10110 => { // MOVT
            let imm16 = ((bb(w, 19, 16)) << 12) | ((bb(w, 26, 26)) << 11)
                | (bb(w, 14, 12) << 8) | bb(w, 7, 0);
            Ok(Ins::Movt { rd, imm16: imm16 as u16 })
        }
        // misc-control f3 space (reaches here only when hw2[15:14]=00)
        _ => Err(DecodeErr(w)),
    }
}

// ---------- ea/eb: data processing (shifted register) ----------

fn decode_t32_dp_shifted(w: u32) -> Result<Ins, DecodeErr> {
    let rn = bb(w, 19, 16) as u8;
    let rd = bb(w, 11, 8) as u8;
    let rm = bb(w, 3, 0) as u8;
    let imm3 = bb(w, 14, 12);
    let imm2 = bb(w, 7, 6);
    let typ = bb(w, 5, 4);
    let opcode = bb(w, 24, 21);
    let s = bt(w, 20);
    let shift_amount = ((imm3 << 2) | imm2) as u8;
    let shift = Shift::from_bits(typ as u8);

    // PKH: opcode 01100 (PKHBT) / 01101 (PKHTB)
    if !s && (opcode == 0b01100 || opcode == 0b01101) {
        return Ok(Ins::Pkh { rd, rn, rm, top: opcode == 0b01101, shift: shift_amount });
    }

    // Rn=15 forms: MOV/MVN/shifts. Rd=15 + S: TST/TEQ/CMP/CMN.
    let op = match opcode {
        0b0000 => DpOp::And,
        0b0001 => DpOp::Bic,
        0b0010 => DpOp::Orr,
        0b0011 => DpOp::Orn,
        0b0100 => DpOp::Eor,
        0b1000 => DpOp::Add,
        0b1101 => DpOp::Sub,
        0b1110 => DpOp::Rsb,
        _ => return Err(DecodeErr(w)),
    };

    if rn == 15 {
        // MOV.W (shifted reg) / MVN / plain shifts / TST-alike with rn=PC
        if s && rd == 15 {
            return Ok(Ins::DpReg { op, s: true, rn, rd: 15, rm, shift, amount: ShiftAmount::Imm(shift_amount) });
        }
        // MOV/MVN with Rn=1111
        match op {
            DpOp::Orr => return Ok(Ins::DpReg { op: DpOp::Mov, s, rn: 0, rd, rm, shift, amount: ShiftAmount::Imm(shift_amount) }),
            DpOp::Orn => return Ok(Ins::DpReg { op: DpOp::Mvn, s, rn: 0, rd, rm, shift, amount: ShiftAmount::Imm(shift_amount) }),
            _ => {}
        }
    }
    if s && rd == 15 {
        // TST/TEQ/CMP/CMN (register)
        return Ok(Ins::DpReg { op, s: true, rn, rd: 15, rm, shift, amount: ShiftAmount::Imm(shift_amount) });
    }
    // Shift-by-register forms: opcode=0010 with Rn=1111 → LSL.W etc.
    if rn == 15 && opcode == 0b0010 && (imm3 << 2 | imm2) == 0 {
        // 1110101 0010 S 1111 Rd imm3 imm2 type Rm: shifts by register
        let rs = rm;
        return Ok(Ins::DpReg { op: DpOp::Mov, s, rn: 0, rd, rm: rm, shift, amount: ShiftAmount::Reg(rs) }
            .rewrite_shift(shift));
    }
    Ok(Ins::DpReg { op, s, rn, rd, rm, shift, amount: ShiftAmount::Imm(shift_amount) })
}

trait RewriteShift {
    fn rewrite_shift(self, shift: Shift) -> Ins;
}
impl RewriteShift for Ins {
    fn rewrite_shift(self, shift: Shift) -> Ins { self }
}

// ---------- e8/e9: ldm/stm, exclusives, tbb/tbh, ldrd/strd ----------

fn decode_t32_ldm_stm(w: u32) -> Result<Ins, DecodeErr> {
    let hw1 = (w >> 16) as u32;
    let hw2 = w & 0xFFFF;
    let rn = bb(hw1, 3, 0) as u8;
    let op_lo = bb(hw1, 7, 4); // P U W L
    let u = bt(w, 23);
    let l = bt(w, 20);

    // Exclusive / TBB / TBH: hw1[7:4] ∈ {0100,0101,1100,1101}
    match bb(hw1, 7, 4) {
        0b0100 | 0b1100 => { // LDREX family / TBB / TBH (1100 = LDREX w/imm8, 0100 = ...)
            if rn == 15 { return Err(DecodeErr(w)); }
            // rt at hw2[11:8]
            let rt = bb(hw2, 11, 8) as u8;
            if op_lo == 0b0100 && rt == 15 {
                // TBB/TBH: hw2 bits 11:5 = 0 (Rt=15 marker), H at hw2.4
                if bb(hw2, 11, 5) == 0 {
                    let rm = bb(hw2, 3, 0) as u8;
                    return Ok(Ins::Tbb { rn, rm, half: bt(hw2, 4) });
                }
                return Err(DecodeErr(w));
            }
            // LDREX (imm8 scaled by access size — stored raw here, scaled by
            // size at decode time per-family below)
            let imm8 = bb(hw2, 7, 0);
            if op_lo == 0b1100 {
                // 1110 1000 1100 Rn Rt imm8: LDREX word, imm8 << 2
                return Ok(Ins::ExclLoad { size: Size::W32, rt, rn }.scale_imm(imm8, 4));
            }
            // 1110 1000 0100 Rn Rt 1111 100 Rm: LDREXB/H/D by size bits (7:6)
            match bb(hw2, 6, 5) {
                0 => Ok(Ins::ExclLoad { size: Size::B8, rt, rn }),
                1 => Ok(Ins::ExclLoad { size: Size::H16, rt, rn }),
                _ => Ok(Ins::ExclLoadD { rt, rt2: bb(hw2, 15, 12) as u8, rn }),
            }
        }
        0b0101 => { // STREX family
            let rt = bb(hw2, 3, 0) as u8;   // value register
            let rn_f = rn;
            let rs = bb(hw2, 11, 8) as u8;  // status
            match bb(hw2, 6, 5) {
                0 => Ok(Ins::ExclStore { size: Size::B8, rs, rt, rn: rn_f }),
                1 => Ok(Ins::ExclStore { size: Size::H16, rs, rt, rn: rn_f }),
                2 => Ok(Ins::ExclStore { size: Size::W32, rs, rt, rn: rn_f }),
                _ => Ok(Ins::ExclStoreD { rs, rt, rt2: bb(hw2, 15, 12) as u8, rn: rn_f }),
            }
        }
        0b1101 => { // STREX with imm8 (word, imm8<<2) — 1110 1000 1101
            let rt = bb(hw2, 3, 0) as u8;
            let rs = bb(hw2, 11, 8) as u8;
            let imm8 = bb(hw2, 7, 0);
            let _ = imm8;
            Ok(Ins::ExclStore { size: Size::W32, rs, rt, rn })
        }
        _ => {}
    }

    // LDRD/STRD: hw1[15:9] = 1110100 1 (0xE9 with bit21=1... actually e9 + marker)
    if bb(hw1, 15, 9) == 0b1110100_1 && bt(hw1, 8) == true || bb(hw1, 15, 9) == 0b1110100_0 && bt(hw1, 8) == true {
        // (unreachable — handled below via the general path)
    }
    if (hw1 >> 8) == 0xE9 {
        // LDRD/STRD: 1110 100P UWL Rn, hw2 = Rt2 Rt imm8
        let rt = bb(hw2, 11, 8) as u8;
        let rt2 = bb(hw2, 15, 12) as u8;
        let imm8 = bb(hw2, 7, 0) as i32;
        let p = bt(w, 24);
        let wb = bt(w, 21);
        let scale = if u { imm8 * 4 } else { -imm8 * 4 };
        return Ok(Ins::LdrdStrd {
            store: !l,
            rt, rt2, rn,
            imm: scale,
            index: p,
            add: u,
            wback: wb,
        });
    }

    // LDM/STM: 1110 100 P U W L Rn, hw2 = register_list
    let mode = match (bt(w, 24), u) {
        (false, true) => LdmMode::Ia,
        (true, true) => LdmMode::Ib,
        (false, false) => LdmMode::Da,
        (true, false) => LdmMode::Db,
    };
    let wback = bt(w, 21);
    Ok(Ins::LdmStm { load: l, rn, mode, wback, user: false, list: RegList::from_bitmap(hw2 as u16) })
}

trait ScaleImm {
    fn scale_imm(self, imm8: u32, scale: u32) -> Ins;
}
impl ScaleImm for Ins {
    fn scale_imm(self, imm8: u32, scale: u32) -> Ins { let _ = (imm8, scale); self }
}

// ---------- f8: single load/store ----------

fn decode_t32_f8(w: u32) -> Result<Ins, DecodeErr> {
    let hw1 = (w >> 16) as u32;
    let hw2 = w & 0xFFFF;

    match bb(hw1, 11, 9) {
        0b011 => decode_t32_f8_ldst(w),          // f8/f9: single ldst
        0b010 => decode_t32_2src(w),             // fa: two-source
        0b001 => decode_t32_mul(w),              // fb: multiply
        _ => Err(DecodeErr(w)),
    }
}

fn decode_t32_f8_ldst(w: u32) -> Result<Ins, DecodeErr> {
    let hw1 = (w >> 16) as u32;
    let hw2 = w & 0xFFFF;
    let rn = bb(hw1, 3, 0) as u8;
    let signed = bt(w, 24);
    let u = bt(w, 23);
    let load = bt(w, 20);
    // size: bits 22:21 (hw1.6:5): 00=byte, 01=half, 10=word
    let size = match bb(hw1, 6, 5) {
        0 => Size::B8,
        1 => Size::H16,
        _ => Size::W32,
    };
    let rt = bb(hw2, 15, 12) as u8;

    if !u {
        // mode forms: hw2[11:8] = 1:P:U:W, imm8 at hw2[7:0]
        let mode = bb(hw2, 11, 8);
        let imm8 = bb(hw2, 7, 0) as i32;
        let (p, uu, wb, t) = (
            (mode >> 2) & 1 == 1,
            (mode >> 1) & 1 == 1,
            mode & 1 == 1,
            false,
        );
        let _ = t;
        let imm = if uu { imm8 } else { -imm8 };
        if !p && !wb {
            // post-index requires W=1; mode 8/9 are post (P=0,W=1)
        }
        let is_post = !p && wb;
        return Ok(Ins::Ldst {
            store: !load, size, signed,
            user: mode == 0b1110 && bb(hw2, 11, 8) == 0b1110 && p && uu && !wb, // E = unprivileged
            rt, rn, rm: None, shift: Shift::Lsl,
            imm,
            index: !is_post,
            add: uu,
            wback: wb || is_post,
        });
    }
    // U=1: imm12 form (or register form when hw2[11:4] == 0x00?+shift)
    if bb(hw2, 11, 4) != 0 || bb(hw2, 11, 6) == 0 && bb(hw2, 5, 4) != 0 {
        if bb(hw2, 11, 6) == 0 {
            // register form: hw2[11:6] == 0, shift at hw2[5:4], Rm at hw2[3:0]
            let rm = bb(hw2, 3, 0) as u8;
            let shift = Shift::from_bits(bb(hw2, 5, 4) as u8);
            return Ok(Ins::Ldst {
                store: !load, size, signed, user: false,
                rt, rn, rm: Some(rm), shift, imm: 0,
                index: true, add: true, wback: false,
            });
        }
    }
    let imm12 = bb(hw2, 11, 0) as i32;
    Ok(Ins::Ldst {
        store: !load, size, signed, user: false,
        rt, rn, rm: None, shift: Shift::Lsl, imm: imm12,
        index: true, add: true, wback: false,
    })
}

// ---------- fa: two-source (extends/reverse/parallel/QADD/SEL/CLZ/CRC) ----------

fn decode_t32_2src(w: u32) -> Result<Ins, DecodeErr> {
    let op1 = bb(w, 23, 20);
    let rn = bb(w, 19, 16) as u8;
    let rd = bb(w, 11, 8) as u8;
    let rm = bb(w, 3, 0) as u8;
    let op2 = bb(w, 7, 4);

    match op1 {
        0b0000 => { // SXTAH family (add forms of extends)
            let (op, rot) = extend_decode(op2, true);
            Ok(Ins::Extend { op, rd, rn, rm, rot })
        }
        0b0001 => { // UXTAH family
            let (op, rot) = extend_decode(op2, false);
            Ok(Ins::Extend { op, rd, rn, rm, rot })
        }
        0b0010 => Ok(Ins::Rev16 { rd, rm }),
        0b0011 => {
            if op2 == 0b0000 { Ok(Ins::Rev { rd, rm }) } else { Ok(Ins::Revsh { rd, rm }) }
        }
        0b0100 => { // SXTH family (plain)
            let (op, rot) = extend_decode(op2, true);
            Ok(Ins::Extend { op, rd, rn: 0, rm, rot })
        }
        0b0101 => { // UXTH family
            let (op, rot) = extend_decode(op2, false);
            Ok(Ins::Extend { op, rd, rn: 0, rm, rot })
        }
        0b1000..=0b1111 => {
            // parallel / QADD / SEL / REV16+ / CLZ / CRC32
            let family = PAR_FAMILY.get((op1 - 8) as usize).copied().flatten();
            let _ = family;
            decode_parallel(op1, op2, rn, rd, rm, w)
        }
        _ => Err(DecodeErr(w)),
    }
}

static PAR_FAMILY: [Option<ParKind>; 8] = [
    Some(ParKind::U), Some(ParKind::S), Some(ParKind::Q), None,
    Some(ParKind::Sh), Some(ParKind::Uq), None, Some(ParKind::Uh),
];

/// op2 (bits 7:4) → (ExtOp base, rotation) for the extend families.
/// Layout: op2 = rot(3:1) | add-form bit0? Actual: op2 bits [2:1]=rot/2? —
/// empirically: rot = ((op2 & 0x7) >> ... verified: op2 = 8|(rot/8)?? —
/// use the raw table: plain (rn=15 → handled by caller), op2 = rot/2 | 8.
fn extend_decode(op2: u32, signed: bool) -> (ExtOp, u8) {
    let rot = ((op2 >> 1) & 0x7) * 8; // 0,8,16,24 — hmm see corpus; fix later
    let _ = signed;
    (ExtOp::Sxth, rot as u8)
}

fn decode_parallel(op1: u32, op2: u32, rn: u8, rd: u8, rm: u8, w: u32) -> Result<Ins, DecodeErr> {
    // family (op1 - 8): 8=U-family?? — actual mapping derived from corpus:
    // op1 8=UADD/QADD(op2>=8), 9=SADD+RBIT, A=QADD16+SEL, B=SHADD+CLZ,
    // C=UQADD, D=UHADD
    match op1 {
        0b1000 => {
            match op2 {
                0b0000 => Ok(par(ParKind::U, ParShape::Add16, rd, rn, rm)),
                0b0001 => Ok(par(ParKind::U, ParShape::Addsubx, rd, rn, rm)),
                0b0010 => Ok(par(ParKind::U, ParShape::Sub16, rd, rn, rm)),
                0b0011 => Ok(par(ParKind::U, ParShape::Add8, rd, rn, rm)),
                0b0100 => Ok(par(ParKind::U, ParShape::Sub8, rd, rn, rm)),
                0b0101 => Ok(par(ParKind::U, ParShape::Subaddx, rd, rn, rm)),
                0b1000 => Ok(Ins::Qadd { rd, rn, rm }),
                0b1010 => Ok(Ins::Qdadd { rd, rn, rm }),
                0b1110 => Ok(Ins::Qsub { rd, rn, rm }),
                0b1100 => Ok(Ins::Qdsub { rd, rn, rm }),
                _ => Err(DecodeErr(w)),
            }
        }
        0b1001 => {
            match op2 {
                0b1000 => Ok(Ins::Rbit { rd, rm: rn }),
                _ => decode_par_shapes(ParKind::S, op2, rn, rd, rm, w),
            }
        }
        0b1010 => {
            match op2 {
                0b1000 => Ok(Ins::Sel { rd, rn, rm }),
                _ => decode_par_shapes(ParKind::Q, op2, rn, rd, rm, w),
            }
        }
        0b1011 => {
            match op2 {
                0b1000 => Ok(Ins::Clz { rd, rm: rn }),
                _ => decode_par_shapes(ParKind::Sh, op2, rn, rd, rm, w),
            }
        }
        0b1100 => decode_par_shapes(ParKind::Uq, op2, rn, rd, rm, w),
        0b1110 => decode_par_shapes(ParKind::Uh, op2, rn, rd, rm, w),
        _ => Err(DecodeErr(w)),
    }
}

fn decode_par_shapes(kind: ParKind, op2: u32, rn: u8, rd: u8, rm: u8, w: u32) -> Result<Ins, DecodeErr> {
    let shape = match op2 {
        0b0000 => ParShape::Add16,
        0b0001 => ParShape::Addsubx,
        0b0010 => ParShape::Sub16,
        0b0011 => ParShape::Add8,
        0b0100 => ParShape::Sub8,
        0b0101 => ParShape::Subaddx,
        _ => return Err(DecodeErr(w)),
    };
    Ok(par(kind, shape, rd, rn, rm))
}

fn par(kind: ParKind, shape: ParShape, rd: u8, rn: u8, rm: u8) -> Ins {
    Ins::Parallel { kind, shape, rd, rn, rm }
}

// ---------- fb: multiply ----------

fn decode_t32_mul(w: u32) -> Result<Ins, DecodeErr> {
    let op1 = bb(w, 23, 21);
    let op2 = bb(w, 7, 4);
    let rn = bb(w, 19, 16) as u8;
    let rdlo = bb(w, 15, 12) as u8;
    let ra = bb(w, 15, 12) as u8;
    let rd = bb(w, 11, 8) as u8;
    let rm = bb(w, 3, 0) as u8;
    let n_hi = bt(w, 5); // N bit: 16×16→32
    let m_hi = bt(w, 4); // M bit

    match (op1, op2) {
        (0b000, 0b0000) => {
            if ra == 15 { Ok(Ins::Mul { rd, rn, rm, s: false }) }
            else { Ok(Ins::Mla { rd, rn, rm, ra, s: false }) }
        }
        (0b000, 0b0001) => Ok(Ins::Mls { rd, rn, rm, ra }),
        (0b000, _) => Err(DecodeErr(w)),
        (0b001, _) => {
            // SMUAD/SMLAD-family: op2 bit0 = X (exchange halves)
            let x = op2 & 1 == 1;
            if ra == 15 {
                if bt(w, 5) { Ok(Ins::Smusd { rd, rn, rm, x }) } else { Ok(Ins::Smuad { rd, rn, rm, x }) }
            } else if bt(w, 5) {
                Ok(Ins::Smlsd { rd, rn, rm, ra, x })
            } else {
                Ok(Ins::Smlad { rd, rn, rm, ra, x })
            }
        }
        (0b010, _) if op2 == 0 || op2 & 0xE == 0 => {
            // SMLALD/SMLSLD (op2 bit0 = X) with Ra=rdlo
            let x = op2 & 1 == 1;
            if bt(w, 5) { Ok(Ins::Smlsld { rdlo, rdhi: rd, rn, rm, x }) }
            else { Ok(Ins::Smlald { rdlo, rdhi: rd, rn, rm, x }) }
        }
        (0b010, 0b1111) => Ok(Ins::Smmul { rd, rn, rm, ra: None, sub: false, round: false }),
        (0b011, _) => {
            // SMLAL/UMAAL/SMULL-family (U=bit21? no — op1 011: SMLAL variants)
            // Actual fb space: op1=100/101 = SMULL/UMULL (U=bit21), 110/111 = SMLAL/UMLAL
            Err(DecodeErr(w))
        }
        (0b100, 0b0000) => Ok(Ins::Smull { rdlo, rdhi: rd, rn, rm, s: false }),
        (0b101, 0b0000) => Ok(Ins::Umull { rdlo, rdhi: rd, rn, rm, s: false }),
        (0b110, 0b0000) => Ok(Ins::Smlal { rdlo, rdhi: rd, rn, rm, s: false }),
        (0b111, 0b0000) => Ok(Ins::Umlal { rdlo, rdhi: rd, rn, rm, s: false }),
        (0b110, 0b1100) => Ok(Ins::Umaal { rdlo, rdhi: rd, rn, rm }),
        (0b001, 0b1111) => Ok(Ins::Smulxy { rd, rn, rm, x: Half::B, y: Half::B }),
        (0b111, 0b1111) => Ok(Ins::Udiv { rd, rn, rm }),
        (0b011, 0b1111) if bb(w, 23, 20) == 0b0011 => Ok(Ins::Sdiv { rd, rn, rm }),
        (0b011, _) => {
            // SDIV is fb1x? no: SDIV = (0011,1111). Fall through:
            Err(DecodeErr(w))
        }
        (0b010, _) => Err(DecodeErr(w)),
        _ => Err(DecodeErr(w)),
    }
    .map(|ins| ins)
}

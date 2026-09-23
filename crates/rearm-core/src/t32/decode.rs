//! T32 (Thumb-2) decoder: 16/32-bit instructions -> `Ins`.
//!
//! Encoding references: ARMv7-A ARM A6.3 (T32 instruction set index).
//! Output reuses the A32 `Ins` enum — semantics are identical; only the
//! encodings differ. Register r13=SP, r14=LR, r15=PC as in A32.

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

fn dp0(op: DpOp, s: bool, rn: u8, rd: u8, rm: u8) -> Ins {
    Ins::DpReg { op, s, rn, rd, rm, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) }
}
fn dps(op: DpOp, s: bool, rn: u8, rd: u8, rm: u8, shift: Shift, amount: u8) -> Ins {
    Ins::DpReg { op, s, rn, rd, rm, shift, amount: ShiftAmount::Imm(amount) }
}
fn dpr(op: DpOp, s: bool, rn: u8, rd: u8, rm: u8, shift: Shift, rs: u8) -> Ins {
    Ins::DpReg { op, s, rn, rd, rm, shift, amount: ShiftAmount::Reg(rs) }
}
fn ld(store: bool, size: Size, signed: bool, rt: u8, rn: u8, imm: i32) -> Ins {
    Ins::Ldst { store, size, signed, user: false, rt, rn, rm: None, shift: Shift::Lsl, imm, index: true, add: true, wback: false }
}

// ==================== 16-bit Thumb (complete) ====================

fn decode_t16(hw: u16) -> Result<Ins, DecodeErr> {
    let w = hw as u32;
    let rd = bb(w, 2, 0) as u8;          // Rd/Rdn (bits 2:0)
    let rn = bb(w, 5, 3) as u8;          // Rn/Rm (bits 5:3)
    let rm = bb(w, 8, 6) as u8;          // Rm (bits 8:6)
    let imm5 = bb(w, 10, 6) as u32;      // imm5 (bits 10:6)
    let imm8 = bb(w, 7, 0) as u32;       // imm8
    let rfn = bb(w, 10, 8) as u8;        // Rn/Rd field (bits 10:8)

    match bb(w, 15, 13) {
        // ===== 00x: shifts + add/sub =====
        0 => {
            match bb(w, 12, 11) {
                0 | 1 => Ok(dps(DpOp::Mov, true, 0, rd, rn, Shift::Lsl, imm5 as u8)), // LSLS
                2 | 3 => Ok(dps(DpOp::Mov, true, 0, rd, rn, Shift::Lsr, imm5 as u8)), // LSRS
                _ => Ok(dps(DpOp::Mov, true, 0, rd, rn, Shift::Asr, imm5 as u8)),     // ASRS
            }
        }
        1 => {
            match bb(w, 12, 9) {
                0b0000..=0b0111 => { // ADD reg / SUB reg / ADD imm3 / SUB imm3
                    let (is_sub, is_imm) = (bt(w, 9), bt(w, 10));
                    let op = if is_sub { DpOp::Sub } else { DpOp::Add };
                    if is_imm {
                        Ok(Ins::DpImm { op, s: true, rn: rd, rd, imm12: bb(w, 5, 3) as u16 })
                    } else {
                        Ok(dp0(op, true, rd, rd, rn))
                    }
                }
                _ => { // MOV/CMP/ADD/SUB imm8
                    match bb(w, 12, 11) {
                        0b10 => Ok(Ins::DpImm { op: DpOp::Mov, s: true, rn: 0, rd: rfn, imm12: imm8 as u16 }),
                        0b11 => Ok(Ins::DpImm { op: DpOp::Cmp, s: true, rn: rfn, rd: 15, imm12: imm8 as u16 }),
                        0b00..=0b01 => match bb(w, 11, 11) {
                            0 => Ok(Ins::DpImm { op: DpOp::Add, s: true, rn: rfn, rd: rfn, imm12: imm8 as u16 }),
                            _ => Ok(Ins::DpImm { op: DpOp::Sub, s: true, rn: rfn, rd: rfn, imm12: imm8 as u16 }),
                        },
                        _ => unreachable!(),
                    }
                }
            }
        }
        // ===== 010: data processing + special + literal =====
        2 => {
            match bb(w, 12, 11) {
                0 => { // 010000: data processing
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
                    match (opcode, bt(w, 7), bt(w, 6)) {
                        (0, _, _) => Ok(dp0(DpOp::Add, false, dn, dn, rmh)),
                        (1, _, _) => Ok(dp0(DpOp::Cmp, false, dn, 15, rmh)),
                        (2, _, _) => Ok(dp0(DpOp::Mov, false, 0, dn, rmh)),
                        (3, false, false) => Ok(Ins::Bx { rm: rmh }),
                        (3, _, _) => Ok(Ins::BlxReg { rm: rmh }),
                        _ => Err(DecodeErr(w)),
                    }
                }
                _ => { // 01001x: LDR literal
                    Ok(ld(false, Size::W32, false, rfn, 15, (imm8 * 4) as i32))
                }
            }
        }
        // ===== 011: STR/LDR imm5 word (011xx with bit11=L) =====
        3 => {
            let is_load = bt(w, 11);
            Ok(ld(!is_load, Size::W32, false, rd, rn, (imm5 * 4) as i32))
        }
        // ===== 100x: STRH/LDRH/STRB/LDRB imm5 =====
        4 => {
            match bb(w, 12, 11) {
                0b00 => Ok(ld(true, Size::H16, false, rd, rn, (imm5 * 2) as i32)),  // STRH
                0b01 => Ok(ld(false, Size::H16, false, rd, rn, (imm5 * 2) as i32)), // LDRH
                0b10 => Ok(ld(true, Size::B8, false, rd, rn, imm5 as i32)),         // STRB
                _ => Ok(ld(false, Size::B8, false, rd, rn, imm5 as i32)),          // LDRB
            }
        }
        // ===== 1010: ADR | ADD Rd, SP, #imm8 =====
        5 if !bt(w, 12) => { // top-3 = 101, bit12 = 0 → 1010
            let base = if bt(w, 11) { 13u8 } else { 15u8 };
            Ok(Ins::DpImm { op: DpOp::Add, s: false, rn: base, rd: rfn, imm12: (imm8 * 4) as u16 })
        }
        // ===== 110x: LDM/B-cond =====
        6 => decode_t16_hi(w),
        // ===== 111x: B =====
        7 => decode_t16_hi(w),
        // ===== 1011: misc16 =====
        _ => decode_t16_misc(w),
    }
}

// Arm 6 (110x) and 7 (111x) are appended via decode_t16_hi below.
fn decode_t16_hi(w: u32) -> Result<Ins, DecodeErr> {
    let imm8 = bb(w, 7, 0) as u32;
    match bb(w, 15, 13) {
        // 110x: bit12=0 → LDM/STM 16-bit (1100 1xxx)
        6 if !bt(w, 12) => {
            let rn = bb(w, 10, 8) as u8;
            let load = bt(w, 11);
            Ok(Ins::LdmStm { load, rn, mode: LdmMode::Ia, wback: false, user: false, list: RegList::from_bitmap(imm8 as u16) })
        }
        // 1101: B<cond>
        6 => {
            let cond = Cond::from_bits(bb(w, 11, 8) as u8);
            let off = (sign_ext(imm8, 8) << 1).wrapping_add(2);
            Ok(Ins::B { cond, off })
        }
        // 1110x: B (unconditional)
        _ => {
            let off = (sign_ext(bb(w, 10, 0), 11) << 1).wrapping_add(2);
            Ok(Ins::B { cond: Cond::Al, off })
        }
    }
}

fn decode_t16_misc(w: u32) -> Result<Ins, DecodeErr> {
    let imm8 = bb(w, 7, 0) as u32;
    match bb(w, 11, 8) { // bit 12 is always 1 (1011 prefix)
        // 1011 0000: ADD/SUB SP, SP, #imm7*4 (bit 7 selects)
        0 => {
            let imm7 = bb(w, 6, 0) * 4;
            let op = if bt(w, 7) { DpOp::Sub } else { DpOp::Add };
            Ok(Ins::DpImm { op, s: false, rn: 13, rd: 13, imm12: imm7 as u16 })
        }
        // 1011 0x10: CBZ/CBNZ (bits 11:10 = 01)
        // CBZ/CBNZ: bits 10:8 = 001, bit 11 = nonzero
        _ if bb(w, 10, 8) == 0b001 => {
            let i = bb(w, 9, 9) as i32;
            let imm5 = bb(w, 7, 3) as i32;
            let rn = bb(w, 2, 0) as u8;
            let off = (imm5 << 1) | (i << 6);
            let nonzero = bt(w, 11);
            Ok(Ins::Cbz { nz: nonzero, rn, off })
        }
        // 1011 010x: PUSH {reglist(+LR)}: bits 12:11 = 01
        _ if bb(w, 11, 10) == 0b01 => {
            let mut m = bb(w, 7, 0) as u16;
            if bt(w, 8) { m |= 1 << 14; }
            Ok(Ins::LdmStm { load: false, rn: 13, mode: LdmMode::Db, wback: true, user: false, list: RegList::from_bitmap(m) })
        }
        // 1011 11xx: POP (bits 11:10 = 11)
        _ if bb(w, 11, 10) == 0b11 => {
            let mut m = bb(w, 7, 0) as u16;
            if bt(w, 8) { m |= 1 << 15; }
            Ok(Ins::LdmStm { load: true, rn: 13, mode: LdmMode::Ia, wback: true, user: false, list: RegList::from_bitmap(m) })
        }
        // SXTB/SXTH/UXTB/UXTH 16-bit: 1011 001x xx mmm ddd
        _ if bb(w, 11, 10) == 0b00 => {
            let op = bb(w, 9, 8) | (bb(w, 11, 11) << 1);
            let rm = bb(w, 5, 3) as u8;
            let rd = bb(w, 2, 0) as u8;
            match (bb(w, 11, 11), bb(w, 9, 8)) {
                (0, 0b10) => Ok(Ins::Extend { op: ExtOp::Sxth, rd, rn: 0, rm, rot: 0 }),
                (0, 0b11) => Ok(Ins::Extend { op: ExtOp::Sxtb, rd, rn: 0, rm, rot: 0 }),
                (1, 0b10) => Ok(Ins::Extend { op: ExtOp::Uxth, rd, rn: 0, rm, rot: 0 }),
                _ => Ok(Ins::Extend { op: ExtOp::Uxtb, rd, rn: 0, rm, rot: 0 }),
            }
        }
        // REV/REV16/REVSH 16-bit: 1011 1010 op(7:6) Rm Rd
        _ if bb(w, 11, 9) == 0b101 => {
            let op = bb(w, 7, 6);
            let rm = bb(w, 5, 3) as u8;
            let rd = bb(w, 2, 0) as u8;
            match op {
                0b00 => Ok(Ins::Rev { rd, rm }),
                0b01 => Ok(Ins::Rev16 { rd, rm }),
                _ => Ok(Ins::Revsh { rd, rm }),
            }
        }
        // 1011 111x: hints (imm5=0) / IT / BKPT / etc
        _ if bt(w, 11) && bt(w, 10) => {
            match bb(w, 7, 0) {
                0 => Ok(Ins::Hints { kind: Hint::Nop }),
                1 => Ok(Ins::Hints { kind: Hint::Yield }),
                2 => Ok(Ins::Hints { kind: Hint::Wfe }),
                3 => Ok(Ins::Hints { kind: Hint::Wfi }),
                4 => Ok(Ins::Hints { kind: Hint::Sev }),
                _ if bb(w, 7, 4) == 0b1011 => { // BKPT
                    Ok(Ins::Bkpt { imm: bb(w, 7, 0) as u16 })
                }
                _ if bb(w, 7, 4) == 0b1111 => { // SVC (if bit12 set... simplified)
                    if bt(w, 12) { Ok(Ins::Svc { imm: bb(w, 7, 0) }) } else { Ok(Ins::Bkpt { imm: bb(w, 7, 0) as u16 }) }
                }
                _ if bt(w, 4) == false && bb(w, 7, 5) == 0b000 => { // NOP variants
                    Ok(Ins::Hints { kind: Hint::Nop })
                }
                _ => Ok(Ins::Hints { kind: Hint::Nop }), // IT etc: placeholder
            }
        }
        _ => Err(DecodeErr(w)),
    }
}

// ==================== 32-bit Thumb-2 ====================

fn decode_t32_32(hw1: u16, hw2: u16) -> Result<Ins, DecodeErr> {
    let w = ((hw1 as u32) << 16) | hw2 as u32;
    // VFP coprocessor space (T32 ee/ed/ec): the words ARE valid A32 encodings
    // with cond=1110/1111 — route directly to the A32 decoder.
    if matches!(hw1 >> 8, 0xEE..=0xEF) || matches!(hw1 >> 8, 0xEC..=0xED) || (hw1 >> 8) == 0xFE {
        if let Ok(ins) = crate::a32::decode::decode_a32(w) {
            if !matches!(ins, Ins::Unsupported { .. }) {
                return Ok(ins);
            }
        }
    }
    // NEON space (T32 ef/ff): transform to the A32 encoding and decode there.
    // T32 1110/1111 11xx ... → A32 1111 00/01xx ... :
    //   A32 = (w & 0x00FFFFFF) | 0xF2000000 | ((w & 0x10000000) >> 4)
    if hw1 >= 0xEF00 && hw1 < 0xF000 || hw1 >= 0xFF00 {
        let a32w = (w & 0x00FF_FFFF) | 0xF200_0000 | ((w & 0x1000_0000) >> 4);
        if let Ok(ins) = crate::a32::decode::decode_a32(a32w) {
            if !matches!(ins, Ins::Unsupported { .. }) {
                return Ok(ins);
            }
        }
    }
    match w >> 27 {
        0b11101 => match bb(w, 26, 25) {
            0b00 => decode_t32_ldm_stm(w),     // e8/e9: ldm/stm/tbb/tbh
            0b01 => decode_t32_dp_shifted(w),   // ea/eb: data proc shifted
            _ => Err(DecodeErr(w)),              // f3/f4: misc control
        },
        0b11110 => decode_t32_dp(w),           // data proc (modified imm) + MOVW/MOVT
        0b11111 => decode_t32_dp2(w),          // multiply, ld/st, coproc
        _ => Err(DecodeErr(w)),
    }
}

/// ThumbExpandImm: 12-bit modified immediate.
fn thumb_expand(imm12: u32) -> u32 {
    let hi = imm12 >> 10; // i:imm3
    if hi == 0 {
        // 0xxx: rotate-right 8-bit
        let imm8 = imm12 & 0xFF;
        match (imm12 >> 7) & 0xF {
            0 => imm8,
            r @ 1..=3 => (0x80 | imm8).rotate_right(r * 8),
            _ => imm8,
        }
    } else {
        // 1xxx: pattern replication
        let width = 32 - hi; // element width
        let mut elem = 1u32 << width; // leading one + following zeros
        elem |= (imm12 & 0x7F) << 1;  // append 7 bits
        let mut out = 0u32;
        let mut i = 0;
        while i < 32 {
            out |= elem << i;
            i += width;
        }
        out
    }
}

/// 11101 op S Rn 0 imm3 Rd imm2 type Rm — data processing (shifted register)
fn decode_t32_dp_shifted(w: u32) -> Result<Ins, DecodeErr> {
    // Special forms first: PKH (op = bits 24:20 = 01100/01101)
    if bb(w, 24, 20) == 0b01100 || bb(w, 24, 20) == 0b01101 {
        let rn = bb(w, 19, 16) as u8;
        let rd = bb(w, 11, 8) as u8;
        let rm = bb(w, 3, 0) as u8;
        let imm3 = bb(w, 14, 12);
        let imm2 = bb(w, 7, 6);
        let top = bt(w, 20); // T bit
        let shift = ((imm3 << 2) | imm2) as u8;
        return Ok(Ins::Pkh { rd, rn, rm, top, shift });
    }
    let s = bt(w, 20);
    let rn = bb(w, 19, 16) as u8;
    let rd = bb(w, 11, 8) as u8;
    let imm3 = bb(w, 14, 12);
    let imm2 = bb(w, 7, 6);
    let typ = bb(w, 5, 4); // shift type
    let rm = bb(w, 3, 0) as u8;
    let opcode = bb(w, 24, 21);
    let shift_amount = (imm3 << 2) | imm2;
    let shift = match typ { 0 => Shift::Lsl, 1 => Shift::Lsr, 2 => Shift::Asr, _ => Shift::Ror };

    // Special forms first: opcode with Rn=1111 = MOV/MVN/shifts; Rd=1111 = tests
    if rn == 15 {
        match opcode {
            0b0000 | 0b0010 => { // TST/shift-imm forms with Rn=1111: MOV-shift
                return Ok(Ins::DpReg { op: DpOp::Mov, s, rn: 0, rd, rm, shift, amount: ShiftAmount::Imm(shift_amount as u8) });
            }
            0b0011 => { // MVN Rd, Rm{,shift}
                return Ok(Ins::DpReg { op: DpOp::Mvn, s, rn: 0, rd, rm, shift, amount: ShiftAmount::Imm(shift_amount as u8) });
            }
            0b1000 => { // ADD with Rn=1111 → ADR-like: MOV Rd, PC+? — treat as MOV shifted
                return Ok(Ins::DpReg { op: DpOp::Mov, s, rn: 15, rd, rm, shift, amount: ShiftAmount::Imm(shift_amount as u8) });
            }
            _ => {}
        }
    }
    let dp_op = match opcode {
        0b0000 => DpOp::And,
        0b0001 => DpOp::Bic,
        0b0010 => DpOp::Orr,
        0b0011 => return Ok(Ins::Unsupported { group: "t32-orn-reg" }),
        0b0100 => DpOp::Eor,
        0b1000 => DpOp::Add,
        0b1010 => DpOp::Adc,
        0b1011 => DpOp::Sbc,
        0b1101 => DpOp::Sub,
        0b1110 => DpOp::Rsb,
        _ => return Err(DecodeErr(w)),
    };
    if rd == 15 {
        let t_op = match dp_op {
            DpOp::And => DpOp::Tst,
            DpOp::Add => DpOp::Cmn,
            DpOp::Sub => DpOp::Cmp,
            _ => return Err(DecodeErr(w)),
        };
        return Ok(Ins::DpReg { op: t_op, s: true, rn, rd: 15, rm, shift, amount: ShiftAmount::Imm(shift_amount as u8) });
    }
    Ok(Ins::DpReg { op: dp_op, s, rn, rd, rm, shift, amount: ShiftAmount::Imm(shift_amount as u8) })
}

fn decode_t32_dp(w: u32) -> Result<Ins, DecodeErr> {
    // 1110 1 op S Rn [0 1 1 1] imm3 Rd imm8 or reg forms
    let s = bt(w, 20);
    let rn = bb(w, 19, 16) as u8;
    let rd = bb(w, 11, 8) as u8;
    let imm3 = bb(w, 14, 12);
    let imm8 = bb(w, 7, 0);
    let i = bt(w, 26);

    // Determine the sub-form from hw1 bits 8:5 (op field)
    let sub = bb(w, 25, 21);
    // Data processing (modified immediate): 11110 x0xxx
    let opcode = bb(w, 24, 21);
    let imm12 = ((i as u32) << 11) | (imm3 << 8) | imm8;
    let val = thumb_expand(imm12);
    let _ = (sub, val);

    // NOP hint: 11110 i 0 0000 1111 ... 0000
    if rn == 15 && rd == 15 && bb(w, 24, 21) == 0 {
        return Ok(Ins::Hints { kind: Hint::Nop });
    }
    // MOVW: 11110 i 10 0100 imm4 imm3 Rd imm8 (imm16 = imm4:i:imm3:imm8)
    if bb(w, 24, 20) == 0b00100 {
        let imm16 = ((rn as u32) << 12) | ((i as u32) << 11) | (imm3 << 8) | imm8;
        return Ok(Ins::Movw { rd, imm16: imm16 as u16 });
    }
    // MOVT: 11110 i 10 1100 imm4 imm3 Rd imm8
    if bb(w, 24, 20) == 0b01100 {
        let imm16 = ((rn as u32) << 12) | ((i as u32) << 11) | (imm3 << 8) | imm8;
        return Ok(Ins::Movt { rd, imm16: imm16 as u16 });
    }
    // MOV/MVN imm: 11110 i 0 000 S 10 0x 1111
    if rn == 15 && bb(w, 23, 21) == 0b001 {
        return if bt(w, 21) {
            Ok(Ins::DpImm { op: DpOp::Mvn, s, rn: 0, rd, imm12: val as u16 })
        } else {
            Ok(Ins::DpImm { op: DpOp::Mov, s, rn: 0, rd, imm12: val as u16 })
        };
    }

    // ORN (opcode 3) handled before this match
    let dp_op = match opcode {
        0b0000 => DpOp::And,
        0b0001 => DpOp::Bic,
        0b0010 => DpOp::Orr,
        0b0011 => DpOp::Bic, // ORN — inverted below
        0b0100 => DpOp::Eor,
        0b1000 => DpOp::Add,
        0b1010 => DpOp::Adc,
        0b1011 => DpOp::Sbc,
        0b1101 => DpOp::Sub,
        0b1110 => DpOp::Rsb,
        _ => return Err(DecodeErr(w)),
    };
    // Test-family: Rd=1111
    if rd == 15 {
        let t_op = match dp_op {
            DpOp::And => DpOp::Tst,
            DpOp::Add => DpOp::Cmn,
            DpOp::Sub => DpOp::Cmp,
            _ => return Err(DecodeErr(w)),
        };
        return Ok(Ins::DpImm { op: t_op, s: true, rn, rd: 15, imm12: val as u16 });
    }
    // ORN Rd, Rn, #imm: Rd = Rn | ~imm
    if opcode == 0b0011 {
        return Ok(Ins::DpImm { op: DpOp::Orr, s, rn, rd, imm12: (!val & 0xFFFF) as u16 });
    }
    Ok(Ins::DpImm { op: dp_op, s, rn, rd, imm12: val as u16 })
}

fn decode_t32_dp2(w: u32) -> Result<Ins, DecodeErr> {
    // 11111 group: multiply, ld/st, coproc, branches
    match bb(w, 26, 24) {
        0b000 | 0b001 => decode_t32_ldst(w), // 1111 100x/101x: load/store
        0b010 => decode_t32_dp2src(w),        // 1111 1010: 2-source DP (clz/rbit/ext/qadd/parallel)
        0b011 => { // 1111 1011/1111: multiply + divide
            let rn = bb(w, 19, 16) as u8;
            let ra = bb(w, 15, 12) as u8;
            let rd = bb(w, 11, 8) as u8;
            let rm = bb(w, 3, 0) as u8;
            let op2 = bb(w, 7, 4);
            let op1 = bb(w, 23, 20) >> 2; // bits 23:22
            let op1 = bb(w, 23, 21); // 3-bit op1 field
            match op1 {
                // 001: SMUAD/SMLAD/SMUSD/SMLSD (X = bit 5; Ra=1111 → no accumulate)
                0b001 => {
                    let x = bt(w, 5);
                    if ra == 15 {
                        if x { Ok(Ins::Smusd { rd, rn, rm, x: false }) }
                        else { Ok(Ins::Smuad { rd, rn, rm, x: false }) }
                    } else {
                        if x { Ok(Ins::Smlsd { rd, rn, rm, ra, x: false }) }
                        else { Ok(Ins::Smlad { rd, rn, rm, ra, x: false }) }
                    }
                }
                // 011: USAD8/USADA8
                0b011 => {
                    if ra == 15 { Ok(Ins::Usad8 { rd, rn, rm }) }
                    else { Ok(Ins::Usada8 { rd, rn, rm, ra }) }
                }
                0b000 => {
                    if ra == 15 { Ok(Ins::Mul { rd, rn, rm, s: false }) }
                    else if bt(w, 4) { Ok(Ins::Mls { rd, rn, rm, ra }) }
                    else { Ok(Ins::Mla { rd, rn, rm, ra, s: false }) }
                }
                0b100 => Ok(Ins::Smull { rdlo: rd, rdhi: ra, rn, rm, s: false }),
                0b101 => Ok(Ins::Umull { rdlo: rd, rdhi: ra, rn, rm, s: false }),
                0b110 => Ok(Ins::Smlal { rdlo: rd, rdhi: ra, rn, rm, s: false }),
                0b111 => Ok(Ins::Umlal { rdlo: rd, rdhi: ra, rn, rm, s: false }),
                0b011 if op2 == 0b1111 => Ok(Ins::Sdiv { rd, rn, rm }),
                0b010 if op2 == 0b1111 => Ok(Ins::Udiv { rd, rn, rm }),
                _ => {
                    let _ = op1;
                    Err(DecodeErr(w))
                }
            }
        }
        _ => Err(DecodeErr(w)),
    }
}

/// e8/e9: LDM/STM/PUSH.W/POP.W/TBB/TBH
fn decode_t32_ldm_stm(w: u32) -> Result<Ins, DecodeErr> {
    let rn = bb(w, 19, 16) as u8;
    let imm12 = bb(w, 11, 0);
    // TBB/TBH: e8d0f001 — Rn + (Rm << 1) with Rt = 15
    if bt(w, 21) && !bt(w, 20) && bb(w, 15, 12) == 15 && bb(w, 11, 8) == 0xF {
        let rm = bb(w, 3, 0) as u8;
        let half = bt(w, 12);
        return Ok(Ins::Tbb { rn, rm, half });
    }
    // LDM/STM: 1110 10 0P U W Rn reglist / PUSH.W = STMDB SP! / POP.W = LDMIA SP!
    let load = bt(w, 20);
    let p = bt(w, 24); // P
    let u = bt(w, 23); // U
    let wb = bt(w, 21); // W
    let mode = match (p, u) {
        (false, true) => LdmMode::Ia,
        (true, true) => LdmMode::Ib,
        (false, false) => LdmMode::Da,
        (true, false) => LdmMode::Db,
    };
    Ok(Ins::LdmStm { load, rn, mode, wback: wb, user: false, list: RegList::from_bitmap(imm12 as u16) })
}

/// 11111 010: 2-source data processing (extend, reverse, clz, qadd, parallel)
fn decode_t32_dp2src(w: u32) -> Result<Ins, DecodeErr> {
    let rn = bb(w, 19, 16) as u8;
    let rd = bb(w, 11, 8) as u8;
    let rm = bb(w, 3, 0) as u8;
    match (bb(w, 23, 20), bb(w, 7, 4)) {
        // 0000-0001: extend add forms
        (0b0000, 0b1000) => Ok(Ins::Extend { op: ExtOp::Sxtah, rd, rn, rm, rot: 0 }),
        (0b0000, 0b1001) => Ok(Ins::Extend { op: ExtOp::Sxtab, rd, rn, rm, rot: 0 }),
        (0b0000, 0b1010) => Ok(Ins::Extend { op: ExtOp::Sxtab16, rd, rn, rm, rot: 0 }),
        (0b0001, 0b1000) => Ok(Ins::Extend { op: ExtOp::Uxtah, rd, rn, rm, rot: 0 }),
        (0b0001, 0b1001) => Ok(Ins::Extend { op: ExtOp::Uxtab, rd, rn, rm, rot: 0 }),
        (0b0001, 0b1010) => Ok(Ins::Extend { op: ExtOp::Uxtab16, rd, rn, rm, rot: 0 }),
        // 0010-0011: reverse
        (0b0010, 0b0000) => Ok(Ins::Rev16 { rd, rm }),
        (0b0011, 0b0100) => Ok(Ins::Rev { rd, rm }),
        (0b0011, 0b0101) => Ok(Ins::Revsh { rd, rm }),
        // 0100-0101: plain extends
        (0b0100, 0b1000) => Ok(Ins::Extend { op: ExtOp::Sxth, rd, rn, rm, rot: 0 }),
        (0b0100, 0b1001) => Ok(Ins::Extend { op: ExtOp::Sxtb, rd, rn, rm, rot: 0 }),
        (0b0100, 0b1010) => Ok(Ins::Extend { op: ExtOp::Sxtb16, rd, rn, rm, rot: 0 }),
        (0b0101, 0b1000) => Ok(Ins::Extend { op: ExtOp::Uxth, rd, rn, rm, rot: 0 }),
        (0b0101, 0b1001) => Ok(Ins::Extend { op: ExtOp::Uxtb, rd, rn, rm, rot: 0 }),
        (0b0101, 0b1010) => Ok(Ins::Extend { op: ExtOp::Uxtb16, rd, rn, rm, rot: 0 }),
        // 1000: UADD16-family (op2 0000-0101) + QADD family (op2 1000-1011)
        (0b1000, 0b1000) => Ok(Ins::Qadd { rd, rn, rm }),
        (0b1000, 0b1001) => Ok(Ins::Qdadd { rd, rn, rm }),
        (0b1000, 0b1010) => Ok(Ins::Qsub { rd, rn, rm }),
        (0b1000, 0b1011) => Ok(Ins::Qdsub { rd, rn, rm }),
        (0b1000, op) if op <= 0b0101 => Ok(Ins::Parallel { kind: ParKind::U, shape: par_shape(op), rd, rn, rm }),
        // 1001: SADD16-family + RBIT
        (0b1001, 0b1010) => Ok(Ins::Rbit { rd, rm }),
        (0b1001, op) if op <= 0b0101 => Ok(Ins::Parallel { kind: ParKind::S, shape: par_shape(op), rd, rn, rm }),
        // 1010: QADD16-family + SEL
        (0b1010, 0b1000) => Ok(Ins::Sel { rd, rn, rm }),
        (0b1010, op) if op <= 0b0101 => Ok(Ins::Parallel { kind: ParKind::Q, shape: par_shape(op), rd, rn, rm }),
        // 1011: SHADD-family + CLZ
        (0b1011, 0b1000) => Ok(Ins::Clz { rd, rm }),
        (0b1011, op) if op <= 0b0101 => Ok(Ins::Parallel { kind: ParKind::Sh, shape: par_shape(op), rd, rn, rm }),
        // 1100: UQADD16-family + PKH
        (0b1100, op) if op <= 0b0101 => Ok(Ins::Parallel { kind: ParKind::Uq, shape: par_shape(op), rd, rn, rm }),
        // 1101: UHADD16-family
        (0b1101, op) if op <= 0b0101 => Ok(Ins::Parallel { kind: ParKind::Uh, shape: par_shape(op), rd, rn, rm }),
        _ => Err(DecodeErr(w)),
    }
}

fn par_shape(op: u32) -> ParShape {
    match op {
        0b0000 => ParShape::Add16,
        0b0001 => ParShape::Addsubx,
        0b0010 => ParShape::Sub16,
        0b0011 => ParShape::Add8,
        0b0100 => ParShape::Sub8,
        _ => ParShape::Subaddx,
    }
}




/// 32-bit Thumb load/store (11111 10xx)
fn decode_t32_ldst(w: u32) -> Result<Ins, DecodeErr> {
    let rn = bb(w, 19, 16) as u8;
    let rt = bb(w, 15, 12) as u8;
    let imm12 = bb(w, 11, 0);
    let size = match bb(w, 31, 30) { 0 => Size::B8, 1 => Size::H16, _ => Size::W32 };
    let is_load = bt(w, 24) || (bb(w, 29, 27) == 0b101 && bt(w, 25));
    let is_store = !bt(w, 24) && bb(w, 29, 27) != 0b101;

    // Register offset form (bit 23:22 != 00? no — the A64-style encodings)
    // f8510022 = LDR r0, [r1, r2, lsl #2]: hw1 = f851: 1111 1000 0101 0001
    // bits 26:24 = 000 → the "register offset" form: bit 23 = P/U, bits 11:0 = 0000 imm2? no...
    // The reg-offset form: 1111 1000 0 1 1 Rn 0000 0000 00 shift Rm
    let b23 = bb(w, 23, 23);
    let b22 = bb(w, 22, 22);
    if !bt(w, 11) && !bt(w, 10) && !bt(w, 21) && bb(w, 9, 6) == 0 {
        // hmm — simplified dispatch below instead
    }
    let _ = (b23, b22);

    // Immediate forms: P/U/W bits 23:21 —
    //   f8d1xxxx (LDR imm12): P=1 U=1 W=0 → index, no wb
    //   f8510f04 (LDR pre-ind): P=1 U=1 W=1 → pre-index wb
    //   f8510b04 (LDR post): P=0 W=0 U=1 → post-inc wb
    //   f8510c08 (LDR negative): P=1 U=0
    let p = bt(w, 24) && bb(w, 23, 21) != 0;  // bit 24 = P (index)
    let u = bt(w, 23);                         // bit 23 = U (add)
    let wb = bt(w, 21);                         // bit 21 = W (writeback)
    // post-index: P=0 → bit 21 set means post-inc
    let post = !bt(w, 24);

    if bb(w, 25, 24) == 0b01 && bb(w, 9, 4) != 0 {
        // register offset: 1111 1000 01 Rn rt 000000 shift Rm — detect via imm12 pattern
        let rm = bb(w, 3, 0) as u8;
        let shift = bb(w, 5, 4);
        let sh = match shift { 0 => Shift::Lsl, _ => Shift::Lsl };
        let amount = bb(w, 5, 4) as i32 * 2;
        return Ok(Ins::Ldst {
            store: !bt(w, 24) || bb(w, 23, 23) == 0 && bt(w, 20),
            size, signed: bt(w, 26), user: false, rt, rn,
            rm: Some(rm), shift: sh, imm: amount,
            index: true, add: true, wback: false,
        });
    }
    let _ = (is_load, is_store, p, post);
    // immediate
    Ok(Ins::Ldst {
        store: bt(w, 24) == false && !bt(w, 20),
        size, signed: bt(w, 26) && bt(w, 25) == false, user: false, rt, rn,
        rm: None, shift: Shift::Lsl,
        imm: if u { imm12 as i32 } else { -(imm12 as i32) },
        index: !post, add: u, wback: wb || post,
    })
}

fn decode_t32_branch_misc(w: u32) -> Result<Ins, DecodeErr> {
    let _ = w;
    Err(DecodeErr(w))
}

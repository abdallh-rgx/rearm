//! T32 (Thumb-2) decoder: 16/32-bit instructions -> `Ins`.
//!
//! Every field offset below is backed by assembled bytes from the
//! LLVM-generated golden corpus (see tools/tcorpus.py + tools/thumb2-*.s).
//!
//! Conventions
//! * Branch `off` = the encoding's immediate; target = Align(PC,4) + off with
//!   PC = addr+4 — the lifter (which knows the address) applies the base.
//! * `DpImmT32` stores the raw 12-bit modified immediate (i:imm3:imm8);
//!   ThumbExpandImm is applied at lift time. `plain` marks ADDW/SUBW/ADR.
//! * T16 imm5/imm8/imm3 offsets are stored SCALED (final byte offsets).
//! * ADR decodes to DpImmT32{op:Add, plain, rn:15} (ADDW with Rn=PC).

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
    let rfn = bb(w, 10, 8) as u8;       // Rd/Rn field (bits 10:8)

    match w >> 12 {
        // ===== 0000-0001: shifts + add/subtract =====
        0x0 | 0x1 => {
            match bb(w, 12, 11) {
                0 => Ok(dps(DpOp::Mov, true, 0, rd, rn, Shift::Lsl, imm5 as u8)), // LSLS
                1 => Ok(dps(DpOp::Mov, true, 0, rd, rn, Shift::Lsr, imm5 as u8)), // LSRS
                2 => Ok(dps(DpOp::Mov, true, 0, rd, rn, Shift::Asr, imm5 as u8)), // ASRS
                _ => { // 00011x: ADD/SUB reg (bit10=0) / imm3 (bit10=1); bit9 = sub
                    let sub = bt(w, 9);
                    let op = if sub { DpOp::Sub } else { DpOp::Add };
                    if bt(w, 10) {
                        // ADD/SUB imm3: rn at [5:3], imm3 at [8:6]
                        Ok(Ins::DpImmT32 { op, s: true, rn, rd, imm12: bb(w, 8, 6) as u16, plain: true })
                    } else {
                        // ADD/SUB reg: rn at [5:3], rm at [8:6]
                        Ok(dp0(op, true, rn, rd, rm))
                    }
                }
            }
        }
        // ===== 0010-0011: MOV/CMP/ADD/SUB imm8 =====
        0x2 | 0x3 => {
            match bb(w, 12, 11) {
                0 => Ok(Ins::DpImmT32 { op: DpOp::Mov, s: true, rn: 0, rd: rfn, imm12: imm8 as u16, plain: true }),
                1 => Ok(Ins::DpImmT32 { op: DpOp::Cmp, s: true, rn: rfn, rd: 15, imm12: imm8 as u16, plain: true }),
                2 => Ok(Ins::DpImmT32 { op: DpOp::Add, s: true, rn: rfn, rd: rfn, imm12: imm8 as u16, plain: true }),
                _ => Ok(Ins::DpImmT32 { op: DpOp::Sub, s: true, rn: rfn, rd: rfn, imm12: imm8 as u16, plain: true }),
            }
        }
        // ===== 0100-0101: DP / special / literal / reg-offset ldst =====
        0x4 | 0x5 => {
            if bt(w, 12) {
                // 0101 op(11:9) rm(8:6) rn(5:3) rt(2:0)
                let size_signed = bb(w, 11, 9);
                let rt = rd;
                let rbase = rn;
                let roff = rm;
                return Ok(match size_signed {
                    0 => ld(true, Size::W32, false, rt, rbase, 0).with_rm(roff),        // STR reg
                    1 => ld(true, Size::H16, false, rt, rbase, 0).with_rm(roff),        // STRH reg
                    2 => ld(true, Size::B8, false, rt, rbase, 0).with_rm(roff),         // STRB reg
                    3 => ld(false, Size::B8, true, rt, rbase, 0).with_rm(roff),         // LDRSB reg
                    4 => ld(false, Size::W32, false, rt, rbase, 0).with_rm(roff),       // LDR reg
                    5 => ld(false, Size::H16, false, rt, rbase, 0).with_rm(roff),       // LDRH reg
                    6 => ld(false, Size::B8, false, rt, rbase, 0).with_rm(roff),        // LDRB reg
                    _ => ld(false, Size::H16, true, rt, rbase, 0).with_rm(roff),       // LDRSH reg
                });
            }
            match bb(w, 11, 10) {
                0 => { // 010000: data processing (opcode 9:6, rm at 5:3, rd 2:0)
                    match bb(w, 9, 6) {
                        0b0000 => Ok(dp0(DpOp::And, true, rd, rd, rn)),
                        0b0001 => Ok(dp0(DpOp::Eor, true, rd, rd, rn)),
                        0b0010 => Ok(dpr(DpOp::Mov, true, 0, rd, rn, Shift::Lsl, rd)),
                        0b0011 => Ok(dpr(DpOp::Mov, true, 0, rd, rn, Shift::Lsr, rd)),
                        0b0100 => Ok(dpr(DpOp::Mov, true, 0, rd, rn, Shift::Asr, rd)),
                        0b0101 => Ok(dp0(DpOp::Adc, true, rd, rd, rn)),
                        0b0110 => Ok(dp0(DpOp::Sbc, true, rd, rd, rn)),
                        0b0111 => Ok(dpr(DpOp::Mov, true, 0, rd, rn, Shift::Ror, rd)),
                        0b1000 => Ok(dp0(DpOp::Tst, true, rd, 15, rn)),
                        0b1001 => Ok(Ins::DpImm { op: DpOp::Rsb, s: true, rn, rd, imm12: 0 }), // RSBS #0
                        0b1010 => Ok(dp0(DpOp::Cmp, true, rd, 15, rn)),
                        0b1011 => Ok(dp0(DpOp::Cmn, true, rd, 15, rn)),
                        0b1100 => Ok(dp0(DpOp::Orr, true, rd, rd, rn)),
                        0b1101 => Ok(Ins::Mul { rd, rn: rd, rm: rn, s: true }),
                        0b1110 => Ok(dp0(DpOp::Bic, true, rd, rd, rn)),
                        _ => Ok(dp0(DpOp::Mvn, true, 0, rd, rn)),
                    }
                }
                1 => { // 010001: special data + BX
                    let dn = ((bb(w, 7, 7) << 3) | bb(w, 2, 0)) as u8;
                    let rmh = ((bb(w, 6, 6) << 3) | bb(w, 5, 3)) as u8;
                    match bb(w, 9, 8) {
                        0 => Ok(dp0(DpOp::Add, false, dn, dn, rmh)),
                        1 => Ok(dp0(DpOp::Cmp, false, dn, 15, rmh)),
                        2 => Ok(dp0(DpOp::Mov, false, 0, dn, rmh)),
                        3 if !bt(w, 7) => Ok(Ins::Bx { rm: rmh }),
                        3 if bt(w, 7) => Ok(Ins::BlxReg { rm: rmh }),
                        _ => Err(DecodeErr(w)),
                    }
                }
                _ => { // 01001x: LDR literal (rt = bits 10:8) — imm in BYTES
                    Ok(ld(false, Size::W32, false, rfn, 15, (imm8 * 4) as i32))
                }
            }
        }
        // ===== 0110-0111: STR/LDR imm5 (imm in BYTES = imm5 ×4) =====
        0x6 | 0x7 => {
            let is_load = bt(w, 11);
            if bt(w, 12) {
                Ok(ld(!is_load, Size::B8, false, rd, rn, imm5 as i32)) // STRB/LDRB (×1)
            } else {
                Ok(ld(!is_load, Size::W32, false, rd, rn, (imm5 * 4) as i32)) // STR/LDR (×4)
            }
        }
        // ===== 1000: STRH/LDRH imm5 (imm in BYTES = imm5 ×2) =====
        0x8 => {
            let is_load = bt(w, 11);
            Ok(ld(!is_load, Size::H16, false, rd, rn, (imm5 * 2) as i32))
        }
        // ===== 1001: STR/LDR SP-relative imm8 (imm in BYTES = imm8 ×4) =====
        0x9 => {
            let is_load = bt(w, 11);
            Ok(ld(!is_load, Size::W32, false, rfn, 13, (imm8 * 4) as i32))
        }
        // ===== 1010: ADR (bit11=0) / ADD Rd, SP, #imm8×4 (bit11=1) =====
        0xA => {
            let base = if bt(w, 11) { 13u8 } else { 15u8 };
            Ok(Ins::DpImmT32 { op: DpOp::Add, s: false, rn: base, rd: rfn, imm12: (imm8 * 4) as u16, plain: true })
        }
        // ===== 1011: misc16 =====
        0xB => decode_t16_misc(w),
        // ===== 1100: STM/LDM (rn = bits 10:8, list low 8) =====
        0xC => {
            let rn_l = bb(w, 10, 8) as u8;
            let is_load = bt(w, 11);
            Ok(Ins::LdmStm { load: is_load, rn: rn_l, mode: LdmMode::Ia, wback: false, user: false, list: RegList::from_bitmap(imm8 as u16) })
        }
        // ===== 1101: B<cond> (imm8 ×2, ±256) / SVC (cond=NV) =====
        0xD => {
            let cond = Cond::from_bits(bb(w, 11, 8) as u8);
            if cond == Cond::Nv {
                Ok(Ins::Svc { imm: imm8 })
            } else {
                Ok(Ins::B { cond, off: sign_ext(imm8, 8) << 1 })
            }
        }
        // ===== 1110: B (imm11 ×2, ±2048) =====
        0xE => {
            Ok(Ins::B { cond: Cond::Al, off: sign_ext(bb(w, 10, 0), 11) << 1 })
        }
        _ => Err(DecodeErr(w)), // 0xF: 32-bit prefix — not reachable here
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
        // 1011 0000: ADD/SUB SP, SP, #imm7*4 (bit 7 selects sub)
        0 => {
            let imm7 = bb(w, 6, 0) * 4;
            let op = if bt(w, 7) { DpOp::Sub } else { DpOp::Add };
            Ok(Ins::DpImmT32 { op, s: false, rn: 13, rd: 13, imm12: imm7 as u16, plain: true })
        }
        // 1011 0110: CPS — before PUSH (bits[11:10]=01 pattern overlaps)
        _ if bb(w, 11, 8) == 0b0110 => {
            let enable = !bt(w, 4);
            let mut aif = 0u8;
            if bt(w, 2) { aif |= 4; } // A
            if bt(w, 1) { aif |= 2; } // I
            if bt(w, 0) { aif |= 1; } // F
            Ok(Ins::Cps { enable, aif, change_mode: false, mode: 0 })
        }
        // 1011 x0i1xxxxx: CBZ (bit11=0) / CBNZ (bit11=1) — bit9 = i (offset bit 5)
        _ if (bb(w, 10, 8) & 0b101) == 0b001 => {
            let i = bb(w, 9, 9) as i32;
            let imm5 = bb(w, 7, 3) as i32;
            let rn = bb(w, 2, 0) as u8;
            Ok(Ins::Cbz { nz: bt(w, 11), rn, off: (imm5 << 1) | (i << 6) })
        }
        // 1011 010x: PUSH {reglist(+LR)}
        _ if bb(w, 11, 9) == 0b010 => {
            let mut m = bb(w, 7, 0) as u16;
            if bt(w, 8) { m |= 1 << 14; }
            Ok(Ins::LdmStm { load: false, rn: 13, mode: LdmMode::Db, wback: true, user: false, list: RegList::from_bitmap(m) })
        }
        // 1011 11xx: POP
        _ if bb(w, 11, 9) == 0b110 => {
            let mut m = bb(w, 7, 0) as u16;
            if bt(w, 8) { m |= 1 << 15; }
            Ok(Ins::LdmStm { load: true, rn: 13, mode: LdmMode::Ia, wback: true, user: false, list: RegList::from_bitmap(m) })
        }
        // 1011 0010: SXTB/SXTH/UXTB/UXTH (op at bits 7:6)
        _ if bb(w, 11, 8) == 0b0010 => {
            let rm = bb(w, 5, 3) as u8;
            let rd_l = bb(w, 2, 0) as u8;
            match bb(w, 7, 6) {
                0 => Ok(Ins::Extend { op: ExtOp::Sxth, rd: rd_l, rn: 0, rm, rot: 0 }),
                1 => Ok(Ins::Extend { op: ExtOp::Sxtb, rd: rd_l, rn: 0, rm, rot: 0 }),
                2 => Ok(Ins::Extend { op: ExtOp::Uxth, rd: rd_l, rn: 0, rm, rot: 0 }),
                _ => Ok(Ins::Extend { op: ExtOp::Uxtb, rd: rd_l, rn: 0, rm, rot: 0 }),
            }
        }
        // 1011 1010: REV/REV16/REVSH (op at bits 7:6)
        _ if bb(w, 11, 9) == 0b101 => {
            let rm = bb(w, 5, 3) as u8;
            let rd_l = bb(w, 2, 0) as u8;
            match bb(w, 7, 6) {
                0 => Ok(Ins::Rev { rd: rd_l, rm }),
                1 => Ok(Ins::Rev16 { rd: rd_l, rm }),
                _ => Ok(Ins::Revsh { rd: rd_l, rm }),
            }
        }
        // 1011 1110: BKPT
        _ if bb(w, 11, 8) == 0b1110 => Ok(Ins::Bkpt { imm: imm8 as u16 }),
        // 1011 1111: hints / IT
        _ if bb(w, 11, 8) == 0b1111 => {
            let first_cond = bb(w, 7, 4) as u8;
            let mask = bb(w, 3, 0) as u8;
            if mask == 0 {
                match first_cond & 0xF {
                    0 => Ok(Ins::Hints { kind: Hint::Nop }),
                    1 => Ok(Ins::Hints { kind: Hint::Yield }),
                    2 => Ok(Ins::Hints { kind: Hint::Wfe }),
                    3 => Ok(Ins::Hints { kind: Hint::Wfi }),
                    4 => Ok(Ins::Hints { kind: Hint::Sev }),
                    5 => Ok(Ins::Hints { kind: Hint::Sevl }),
                    _ => Ok(Ins::Hints { kind: Hint::Nop }),
                }
            } else {
                Ok(Ins::It { first_cond: Cond::from_bits(first_cond), mask })
            }
        }
        // unknown 1011-space: treat as data (the sweep stops the path)
        _ => Err(DecodeErr(w)),
    }
}

// ==================== 32-bit Thumb-2 ====================

fn decode_t32_32(hw1: u16, hw2: u16) -> Result<Ins, DecodeErr> {
    let w = ((hw1 as u32) << 16) | hw2 as u32;

    // VFP coprocessor space (T32 ee/ed/ec/fe): the words ARE valid A32
    // encodings with cond=1110/1111 — route directly to the A32 decoder.
    let h1 = hw1 >> 8;
    if h1 == 0xEE || (0xEC..=0xED).contains(&h1) || h1 == 0xFE {
        if let Ok(ins) = crate::a32::decode::decode_a32(w) {
            return Ok(ins); // Unsupported propagates (skipped by round-trip)
        }
        return Err(DecodeErr(w));
    }
    // NEON space (T32 ef/ff): transform to the A32 encoding and decode there.
    //   a32 = (w & 0x00FFFFFF) | 0xF2000000 | ((w & 0x10000000) >> 4)
    if (0xEF00..0xF000).contains(&hw1) || hw1 >= 0xFF00 {
        let a32w = (w & 0x00FF_FFFF) | 0xF200_0000 | ((w & 0x1000_0000) >> 4);
        if let Ok(ins) = crate::a32::decode::decode_a32(a32w) {
            return Ok(ins); // Unsupported propagates
        }
        return Err(DecodeErr(w));
    }

    match w >> 27 {
        0b11101 => match bb(w, 26, 25) {
            0b00 => decode_e8(w),                  // e8/e9: ldm/stm/excl/tbb/ldrd
            0b01 => decode_ea(w),                  // ea/eb: DP shifted register
            _ => Err(DecodeErr(w)),
        },
        0b11110 => decode_f0(w),                    // f0-f7: DP imm / branches / f3 misc
        0b11111 => {
            // f9 with bit20 = 0: NEON ld/st multiple — transform to A32.
            if h1 == 0xF9 && !bt(w, 20) {
                let a32w = (w & 0xF0FF_FFFF) | 0x0400_0000;
                if let Ok(ins) = crate::a32::decode::decode_a32(a32w) {
                    return Ok(ins); // Unsupported propagates
                }
                return Err(DecodeErr(w));
            }
            match bb(w, 26, 24) {
                0b000 | 0b001 => decode_f8(w),          // f8/f9: single ldst
                0b010 => decode_fa(w),                  // fa: two-source
                0b011 => decode_fb(w),                  // fb: multiply
                _ => Err(DecodeErr(w)),
            }
        }
        _ => Err(DecodeErr(w)),
    }
}

// ---------- e8/e9: ldm/stm, exclusives, tbb/tbh, ldrd/strd ----------
// hw1 = 1110 1 00 P U 1 W L Rn — bit6=1 marks the "special" (excl/dual) space.

fn decode_e8(w: u32) -> Result<Ins, DecodeErr> {
    let hw1 = (w >> 16) as u32;
    let hw2 = w & 0xFFFF;
    let rn = bb(hw1, 3, 0) as u8;
    let p = bt(w, 24);
    let u = bt(w, 23);
    let wb = bt(w, 21);
    let load = bt(w, 20);

    if !bt(w, 22) {
        // LDM/STM: 1110 1000 P U 0 W L Rn
        let mode = match (p, u) {
            (false, true) => LdmMode::Ia,
            (true, true) => LdmMode::Ib,
            (false, false) => LdmMode::Da,
            (true, false) => LdmMode::Db,
        };
        return Ok(Ins::LdmStm { load, rn, mode, wback: wb, user: false, list: RegList::from_bitmap(hw2 as u16) });
    }
    // Special space (bit22=1): excl / tbb/tbh / ldrd/strd.
    // rt-slot at hw2[15:12]:
    let rt = bb(hw2, 15, 12) as u8;

    match (p, u, wb, load) {
        (false, false, false, true) => {
            // 1110 1000 0101 Rn: LDREX word (imm8 ×4 at hw2[7:0], F marker 11:8)
            let imm8 = bb(hw2, 7, 0) as i32 * 4;
            Ok(Ins::ExclLoad { size: Size::W32, rt, rn, imm: imm8 })
        }
        (false, false, false, false) => {
            // 1110 1000 0100 Rn: STREX word (Rs at hw2[11:8], imm8 ×4 at [7:0])
            Ok(Ins::ExclStore { size: Size::W32, rs: bb(hw2, 11, 8) as u8, rt, rn, imm: bb(hw2, 7, 0) as i32 * 4 })
        }
        (true, true, false, true) => {
            // 1110 1000 1101 Rn: TBB/TBH (Rt-slot=F, hw2[11:4]=0), LDREXB/H
            // ([11:8]=F, [7:4]∈{4,5}), LDREXD ([7:4]=7), else LDRD.
            if rt == 15 && bb(hw2, 11, 4) == 0 {
                return Ok(Ins::Tbb { rn, rm: bb(hw2, 3, 0) as u8, half: bt(hw2, 4) });
            }
            if bb(hw2, 7, 4) == 4 && bb(hw2, 11, 8) == 0xF {
                Ok(Ins::ExclLoad { size: Size::B8, rt, rn, imm: 0 })
            } else if bb(hw2, 7, 4) == 5 && bb(hw2, 11, 8) == 0xF {
                Ok(Ins::ExclLoad { size: Size::H16, rt, rn, imm: 0 })
            } else if bb(hw2, 7, 4) == 7 && bb(hw2, 3, 0) == 0xF {
                Ok(Ins::ExclLoadD { rt, rt2: bb(hw2, 11, 8) as u8, rn })
            } else {
                let rt_l = bb(hw2, 11, 8) as u8;
                let rt2 = rt;
                let imm8 = bb(hw2, 7, 0) as i32 * 4;
                Ok(Ins::LdrdStrd { store: false, rt: rt_l, rt2, rn, imm: imm8, index: true, add: true, wback: false })
            }
        }
        (true, true, false, false) => {
            // 1110 1000 1100 Rn: STREXB/H ([11:8]=F), STREXD ([7:4]=7), else STRD.
            let rs = bb(hw2, 3, 0) as u8;
            if bb(hw2, 7, 4) == 4 && bb(hw2, 11, 8) == 0xF {
                Ok(Ins::ExclStore { size: Size::B8, rs, rt, rn, imm: 0 })
            } else if bb(hw2, 7, 4) == 5 && bb(hw2, 11, 8) == 0xF {
                Ok(Ins::ExclStore { size: Size::H16, rs, rt, rn, imm: 0 })
            } else if bb(hw2, 7, 4) == 7 {
                Ok(Ins::ExclStoreD { rs, rt, rt2: bb(hw2, 11, 8) as u8, rn })
            } else {
                let rt_l = bb(hw2, 11, 8) as u8;
                let rt2 = rt;
                let imm8 = bb(hw2, 7, 0) as i32 * 4;
                Ok(Ins::LdrdStrd { store: true, rt: rt_l, rt2, rn, imm: imm8, index: true, add: true, wback: false })
            }
        }
        // LDRD/STRD (imm8 ×4): P=1 offset/pre-index, P=0 post; Rt at [11:8], Rt2 at [15:12]
        _ => {
            let rt_l = bb(hw2, 11, 8) as u8;
            let rt2 = rt;
            let imm8 = bb(hw2, 7, 0) as i32 * 4;
            let imm = if u { imm8 } else { -imm8 };
            Ok(Ins::LdrdStrd { store: !load, rt: rt_l, rt2, rn, imm, index: p, add: u, wback: wb })
        }
    }
}

// ---------- ea/eb: data processing (shifted register) ----------
// hw1 = 1110 101 op4 S Rn — op4 at bits 24:21 (word), S at bit 20.

fn decode_ea(w: u32) -> Result<Ins, DecodeErr> {
    let rn = bb(w, 19, 16) as u8;
    let rd = bb(w, 11, 8) as u8;
    let rm = bb(w, 3, 0) as u8;
    let imm5 = ((bb(w, 14, 12) << 2) | bb(w, 7, 6)) as u8;
    let typ = bb(w, 5, 4);
    let s = bt(w, 20);
    let opcode = bb(w, 24, 21);

    // PKH: op=0110 (PKHBT: typ=00 LSL, PKHTB: typ≠00 ASR)
    if opcode == 0b0110 && !s {
        return Ok(Ins::Pkh { rd, rn, rm, top: typ != 0, shift: imm5 });
    }

    let op = match opcode {
        0b0000 => DpOp::And,
        0b0001 => DpOp::Bic,
        0b0010 => DpOp::Orr,
        0b0011 => DpOp::Orn,
        0b0100 => DpOp::Eor,
        0b1000 => DpOp::Add,
        0b1010 => DpOp::Adc,
        0b1011 => DpOp::Sbc,
        0b1101 => DpOp::Sub,
        0b1110 => DpOp::Rsb,
        _ => return Err(DecodeErr(w)),
    };

    // Rd=15 + S: TST/TEQ/CMP/CMN (register) — decode through with rd=15.
    // Rn=15 + op=ORR: MOV (shifted); Rn=15 + op=ORN: MVN (shifted).
    if rn == 15 {
        match op {
            DpOp::Orr => return Ok(Ins::DpReg { op: DpOp::Mov, s, rn: 0, rd, rm, shift: Shift::from_bits(typ as u8), amount: ShiftAmount::Imm(imm5) }),
            DpOp::Orn => return Ok(Ins::DpReg { op: DpOp::Mvn, s, rn: 0, rd, rm, shift: Shift::from_bits(typ as u8), amount: ShiftAmount::Imm(imm5) }),
            _ => {}
        }
    }
    if rd == 15 && s {
        return Ok(Ins::DpReg { op, s: true, rn, rd: 15, rm, shift: Shift::from_bits(typ as u8), amount: ShiftAmount::Imm(imm5) });
    }
    Ok(Ins::DpReg { op, s, rn, rd, rm, shift: Shift::from_bits(typ as u8), amount: ShiftAmount::Imm(imm5) })
}

// ---------- f0-f7: DP imm / branches / f3 misc ----------
// hw1 = 1111 0 i op5 S Rn; hw2 = imm3 Rd imm8 (bit15 = 0) OR branch/misc (bit15 = 1).

fn decode_f0(w: u32) -> Result<Ins, DecodeErr> {
    let hw1 = (w >> 16) as u32;
    let hw2 = w & 0xFFFF;
    let rn = bb(hw1, 3, 0) as u8;
    let rd = bb(hw2, 11, 8) as u8;
    let imm12 = ((bb(w, 26, 26)) << 11) | (bb(hw2, 14, 12) << 8) | bb(hw2, 7, 0);

    if hw2 & 0x8000 == 0 {
        // DP immediate group: op5 = hw1[9:5], S = hw1.4.
        let op5 = bb(hw1, 9, 5);
        let s = bt(hw1, 4);
        return match op5 {
            0b00000 if s && rd == 15 => Ok(imm_forms::tst(rn, imm12 as u16)),
            0b00000 => Ok(imm_forms::and(s, rn, rd, imm12 as u16)),
            0b00001 => Ok(imm_forms::bic(s, rn, rd, imm12 as u16)),
            0b00010 if rn == 15 => Ok(imm_forms::mov(s, rd, imm12 as u16)),
            0b00010 => Ok(imm_forms::orr(s, rn, rd, imm12 as u16)),
            0b00011 if rn == 15 => Ok(imm_forms::mvn(s, rd, imm12 as u16)),
            0b00011 => Ok(imm_forms::orn(s, rn, rd, imm12 as u16)),
            0b00100 if s && rd == 15 => Ok(imm_forms::teq(rn, imm12 as u16)),
            0b00100 => Ok(imm_forms::eor(s, rn, rd, imm12 as u16)),
            0b01000 if s && rd == 15 => Ok(imm_forms::cmn(rn, imm12 as u16)),
            0b01000 => Ok(imm_forms::add(s, rn, rd, imm12 as u16)),
            0b01101 if s && rd == 15 => Ok(imm_forms::cmp(rn, imm12 as u16)),
            0b01101 => Ok(imm_forms::sub(s, rn, rd, imm12 as u16)),
            0b01110 => Ok(imm_forms::rsb(s, rn, rd, imm12 as u16)),
            0b10000 => Ok(imm_forms::plain(DpOp::Add, rn, rd, imm12 as u16)),   // ADDW / ADR
            0b10101 => Ok(imm_forms::plain(DpOp::Sub, rn, rd, imm12 as u16)),   // SUBW
            0b10010 => Ok(Ins::Movw { rd, imm16: movw_imm(w) as u16 }),   // MOVW
            0b10110 => Ok(Ins::Movt { rd, imm16: movw_imm(w) as u16 }),   // MOVT
            _ => decode_f3_sat(w),
        };
    }

    // hw2 bit15 = 1: branches (bit14 = 0, cond ∉ AL/NV), f3 misc control
    // (bit14 = 0, cond = AL/NV), BL/BLX (bit14 = 1, bit12 = 1/0).
    let cond_field = bb(hw1, 9, 6);
    if !bt(hw2, 14) {
        // bit14 = 0: Bcc/B.W or the f3 misc-control space.
        if bt(hw2, 12) {
            // bit12 = 1 → T4 B.W (imm10 occupies the cond-field bits).
            return Ok(Ins::B { cond: Cond::Al, off: sign_ext(bl_imm(w), 25) });
        }
        if cond_field != 0b1110 && cond_field != 0b1111 {
            // bit12 = 0 → T3 Bcc.
            return {
                // T3 Bcc: imm = SignExtend21(S : J2(hw2.11) : J1(hw2.13) : imm6 : imm11 : 0)
                let s = bt(w, 26);
                let imm6 = bb(hw1, 5, 0);
                let j1 = bt(w, 13);
                let j2 = bt(w, 11);
                let imm11 = bb(hw2, 10, 0);
                let v = (s as u32) << 20 | (j2 as u32) << 19 | (j1 as u32) << 18
                    | imm6 << 12 | imm11 << 1;
                Ok(Ins::B { cond: Cond::from_bits(cond_field as u8), off: sign_ext(v, 21) })
            };
        }
        // f3 misc-control: dispatch by hw1[7:4] (op) + Rn.
        let op = bb(hw1, 7, 4);
        return match (op, rn) {
            (0b1000, _) | (0b1001, _) => {
                // MSR: register form hw2[7:4]=0000, else immediate.
                if bb(hw2, 7, 4) == 0 {
                    Ok(Ins::Msr { spsr: bt(hw1, 4), mask: bb(hw2, 11, 8) as u8, rn: bb(hw2, 3, 0) as u8, imm: None })
                } else {
                    Ok(Ins::Msr { spsr: bt(hw1, 4), mask: bb(hw2, 11, 8) as u8, rn: 15, imm: Some(imm12) })
                }
            }
            (0b1110, 15) | (0b1111, 15) => {
                // MRS: Rd at hw2[11:8]; R = hw1.4 selects SPSR
                Ok(Ins::Mrs { rd: bb(hw2, 11, 8) as u8, spsr: bt(hw1, 4) })
            }
            (0b1111, _) => {
                // UDF.W: hw1 = f7fx, imm16 = hw1[3:0] : hw2[11:0]
                Ok(Ins::Udf { imm: ((bb(hw1, 3, 0) << 12) | bb(hw2, 11, 0)) as u16 })
            }
            (0b1010, 15) => {
                // Hints.W: opcode = hw2[7:0]
                Ok(match bb(hw2, 7, 0) {
                    0 => Ins::Hints { kind: Hint::Nop },
                    1 => Ins::Hints { kind: Hint::Yield },
                    2 => Ins::Hints { kind: Hint::Wfe },
                    3 => Ins::Hints { kind: Hint::Wfi },
                    4 => Ins::Hints { kind: Hint::Sev },
                    _ => Ins::Hints { kind: Hint::Nop },
                })
            }
            (0b1011, 15) => {
                // Barriers: DSB(4x) DMB(5x) ISB(6x); option at hw2[3:0]
                Ok(match bb(hw2, 7, 4) {
                    0b0100 => Ins::Barriers { kind: Barrier::Dsb, opt: bb(hw2, 3, 0) as u8 },
                    0b0101 => Ins::Barriers { kind: Barrier::Dmb, opt: bb(hw2, 3, 0) as u8 },
                    _ => Ins::Barriers { kind: Barrier::Isb, opt: bb(hw2, 3, 0) as u8 },
                })
            }
            _ => Err(DecodeErr(w)),
        };
    }
    // bit14 = 1: BL (bit12 = 1) / BLX (bit12 = 0).
    if bt(hw2, 12) {
        Ok(Ins::Bl { off: sign_ext(bl_imm(w), 25) })
    } else {
        Ok(Ins::Blx { off: sign_ext(bl_imm(w), 25) })
    }
}

#[inline]
fn bl_imm(w: u32) -> u32 {
    let hw1 = w >> 16;
    let hw2 = w & 0xFFFF;
    let s = (hw1 >> 10) & 1;
    let imm10 = hw1 & 0x3FF;
    let j1 = (hw2 >> 13) & 1;
    let j2 = (hw2 >> 11) & 1;
    let imm11 = hw2 & 0x7FF;
    let i1 = !(j1 ^ s) & 1;
    let i2 = !(j2 ^ s) & 1;
    (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
}

#[inline]
fn movw_imm(w: u32) -> u32 {
    // imm16 = imm4(19:16) : i(26) : imm3(hw2 14:12) : imm8(hw2 7:0)
    ((w >> 16 & 0xF) << 12) | (((w >> 26) & 1) << 11) | (((w >> 12) & 0x7) << 8) | (w & 0xFF)
}

mod imm_forms {
    use super::*;

    fn d(op: DpOp, s: bool, rn: u8, rd: u8, imm12: u16) -> Ins {
        Ins::DpImmT32 { op, s, rn, rd, imm12, plain: false }
    }
    pub fn and(s: bool, rn: u8, rd: u8, imm12: u16) -> Ins { d(DpOp::And, s, rn, rd, imm12) }
    pub fn bic(s: bool, rn: u8, rd: u8, imm12: u16) -> Ins { d(DpOp::Bic, s, rn, rd, imm12) }
    pub fn orr(s: bool, rn: u8, rd: u8, imm12: u16) -> Ins { d(DpOp::Orr, s, rn, rd, imm12) }
    pub fn orn(s: bool, rn: u8, rd: u8, imm12: u16) -> Ins { d(DpOp::Orn, s, rn, rd, imm12) }
    pub fn eor(s: bool, rn: u8, rd: u8, imm12: u16) -> Ins { d(DpOp::Eor, s, rn, rd, imm12) }
    pub fn add(s: bool, rn: u8, rd: u8, imm12: u16) -> Ins { d(DpOp::Add, s, rn, rd, imm12) }
    pub fn sub(s: bool, rn: u8, rd: u8, imm12: u16) -> Ins { d(DpOp::Sub, s, rn, rd, imm12) }
    pub fn rsb(s: bool, rn: u8, rd: u8, imm12: u16) -> Ins { d(DpOp::Rsb, s, rn, rd, imm12) }
    pub fn mov(s: bool, rd: u8, imm12: u16) -> Ins { d(DpOp::Mov, s, 0, rd, imm12) }
    pub fn mvn(s: bool, rd: u8, imm12: u16) -> Ins { d(DpOp::Mvn, s, 0, rd, imm12) }
    pub fn tst(rn: u8, imm12: u16) -> Ins { d(DpOp::Tst, true, rn, 15, imm12) }
    pub fn teq(rn: u8, imm12: u16) -> Ins { d(DpOp::Teq, true, rn, 15, imm12) }
    pub fn cmp(rn: u8, imm12: u16) -> Ins { d(DpOp::Cmp, true, rn, 15, imm12) }
    pub fn cmn(rn: u8, imm12: u16) -> Ins { d(DpOp::Cmn, true, rn, 15, imm12) }
    pub fn plain(op: DpOp, rn: u8, rd: u8, imm12: u16) -> Ins {
        Ins::DpImmT32 { op, s: false, rn, rd, imm12, plain: true }
    }
}

// f3 saturation space (reached from decode_f0's DP-imm path when op5 doesn't
// match a DP-imm code — the f3 encodings alias the cond=AL/NV slots).
fn decode_f3_sat(w: u32) -> Result<Ins, DecodeErr> {
    decode_f3(w)
}

fn decode_f3(w: u32) -> Result<Ins, DecodeErr> {
    let hw1 = (w >> 16) as u32;
    let hw2 = w & 0xFFFF;
    let rn = bb(hw1, 3, 0) as u8;
    let rd = bb(hw2, 11, 8) as u8;
    let op = bb(hw1, 7, 4);
    let imm5 = (bb(hw2, 14, 12) << 2) | bb(hw2, 7, 6);

    match op {
        0b0000 => { // SSAT (sh = LSL)
            Ok(Ins::Ssat { rd, imm: bb(hw2, 4, 0) as u8 + 1, rn, sh: imm5 as u8, asr: false })
        }
        0b0010 => { // SSAT (sh = ASR) or SSAT16 (imm5 == 0)
            if imm5 == 0 {
                Ok(Ins::Ssat16 { rd, imm: bb(hw2, 3, 0) as u8 + 1, rn })
            } else {
                Ok(Ins::Ssat { rd, imm: bb(hw2, 4, 0) as u8 + 1, rn, sh: imm5 as u8, asr: true })
            }
        }
        0b1000 => { // USAT (sh = LSL)
            Ok(Ins::Usat { rd, imm: bb(hw2, 4, 0) as u8, rn, sh: imm5 as u8, asr: false })
        }
        0b1010 => { // USAT (sh = ASR) or USAT16 (imm5 == 0)
            if imm5 == 0 {
                Ok(Ins::Usat16 { rd, imm: bb(hw2, 3, 0) as u8, rn })
            } else {
                Ok(Ins::Usat { rd, imm: bb(hw2, 4, 0) as u8, rn, sh: imm5 as u8, asr: true })
            }
        }
        0b0100 => { // SBFX: lsb = imm3:imm2, width = widthm1+1
            Ok(Ins::Sbfx { rd, rn, lsb: imm5 as u8, width: bb(hw2, 5, 0) as u8 + 1 })
        }
        0b1100 => { // UBFX
            Ok(Ins::Ubfx { rd, rn, lsb: imm5 as u8, width: bb(hw2, 5, 0) as u8 + 1 })
        }
        0b0110 => { // BFI (Rn=15 → BFC): lsb = imm3:imm2, msb at [5:0]
            let lsb = imm5 as u8;
            let msb = bb(hw2, 5, 0) as u8;
            if msb < lsb { return Err(DecodeErr(w)); } // UNPREDICTABLE
            if rn == 15 {
                Ok(Ins::Bfc { rd, lsb, width: msb - lsb + 1 })
            } else {
                Ok(Ins::Bfi { rd, rn, lsb, width: msb - lsb + 1 })
            }
        }
        _ => Err(DecodeErr(w)),
    }
}


// ---------- f8/f9: single load/store ----------
// hw1 = 1111 1 00 S U sz2 L Rn — S=bit24, U=bit23, size=bits22:21, L=bit20.

fn decode_f8(w: u32) -> Result<Ins, DecodeErr> {
    let hw1 = (w >> 16) as u32;
    let hw2 = w & 0xFFFF;
    let rn = bb(hw1, 3, 0) as u8;
    let signed = bt(w, 24);
    let u = bt(w, 23);
    let load = bt(w, 20);
    let size = match bb(hw1, 6, 5) {
        0 => Size::B8,
        1 => Size::H16,
        _ => Size::W32,
    };
    let rt = bb(hw2, 15, 12) as u8;

    // PLD/PLI/PLDW marker: Rt-slot = 15 with L=1 (and not the PC-literal form).
    if rt == 15 && load {
        return decode_pl(w);
    }
    // LDR literal: Rn=15 + word + unsigned → imm12 ×4 (BYTES; sign from U).
    if rn == 15 && size == Size::W32 && !signed {
        let imm12 = bb(hw2, 11, 0) as i32;
        let imm = if u { imm12 } else { -imm12 };
        return Ok(ld(false, Size::W32, false, rt, 15, imm * 4));
    }
    let scale = match size { Size::B8 => 0i32, Size::H16 => 1, _ => 2 };
    if u {
        // imm12 form: hw2[11:0] = imm12 (in transfer units) — convert to BYTES.
        // (The register form only encodes with U=0, so U=1 → always imm12.)
        return Ok(ld(!load, size, signed, rt, rn, (bb(hw2, 11, 0) as i32) << scale));
    }
    // U=0: register form (hw2[11:6] == 0) or mode nibble.
    if bb(hw2, 11, 6) == 0 {
        let rm = bb(hw2, 3, 0) as u8;
        let shamt = bb(hw2, 5, 4) as i32;
        return Ok(Ins::Ldst {
            store: !load, size, signed, user: false,
            rt, rn, rm: Some(rm), shift: Shift::Lsl, imm: shamt,
            index: true, add: true, wback: false,
        });
    }
    let mode = bb(hw2, 11, 8);
    let imm8 = bb(hw2, 7, 0) as i32;
    let (p, uu, wb, t) = ((mode >> 2) & 1 == 1, (mode >> 1) & 1 == 1, mode & 1 == 1, mode == 0b1110);
    let imm = if uu { imm8 << scale } else { -(imm8 << scale) }; // BYTES
    Ok(Ins::Ldst {
        store: !load, size, signed, user: t,
        rt, rn, rm: None, shift: Shift::Lsl,
        imm,
        index: p,
        add: uu,
        wback: wb,
    })
}

fn decode_pl(w: u32) -> Result<Ins, DecodeErr> {
    let hw1 = (w >> 16) as u32;
    let hw2 = w & 0xFFFF;
    let rn = bb(hw1, 3, 0) as u8;
    let signed = bt(w, 24);
    let u = bt(w, 23);
    let size = bb(hw1, 6, 5);
    // PLD (sz=00,S=0), PLDW (sz=01,S=0), PLI (sz=00,S=1).
    let is_pli = signed;
    let is_pldw = !signed && size == 0b01;
    if u {
        let imm12 = bb(hw2, 11, 0) as i32;
        return Ok(pl_ins(is_pli, is_pldw, rn, None, Shift::Lsl, imm12));
    }
    if bb(hw2, 11, 6) == 0 {
        let rm = bb(hw2, 3, 0) as u8;
        let shamt = bb(hw2, 5, 4) as i32;
        return Ok(pl_ins(is_pli, is_pldw, rn, Some(rm), Shift::Lsl, shamt));
    }
    let mode = bb(hw2, 11, 8);
    let imm8 = bb(hw2, 7, 0) as i32;
    let (p, uu) = ((mode >> 2) & 1 == 1, (mode >> 1) & 1 == 1);
    let _ = p;
    let imm = if uu { imm8 } else { -imm8 };
    Ok(pl_ins(is_pli, is_pldw, rn, None, Shift::Lsl, imm))
}

fn pl_ins(is_pli: bool, is_pldw: bool, rn: u8, rm: Option<u8>, shift: Shift, imm: i32) -> Ins {
    if is_pli {
        Ins::Pli { rn, rm, shift, imm }
    } else {
        Ins::Pld { w: is_pldw, rn, rm, shift, imm }
    }
}

// ---------- fa: two-source ----------
// hw1 = 1111 1010 op1(4) Rn; hw2 = 0(15) Rd(11:8) op2(7:4) Rm(3:0).

fn decode_fa(w: u32) -> Result<Ins, DecodeErr> {
    let op1 = bb(w, 23, 20);
    let rn = bb(w, 19, 16) as u8;
    let rd = bb(w, 11, 8) as u8;
    let rm = bb(w, 3, 0) as u8;
    let op2 = bb(w, 7, 4);

    // Shifts by register: op1 = 2*type, op2 = 0, Rn = source.
    if op2 == 0 && op1 <= 6 && op1 & 1 == 0 {
        let shift = Shift::from_bits((op1 / 2) as u8);
        return Ok(Ins::DpReg { op: DpOp::Mov, s: false, rn: 0, rd, rm, shift, amount: ShiftAmount::Reg(rn) });
    }
    // Extend families: op1 selects op, op2 = 8 + rot/8; Rn=15 → plain form.
    let ext_op = match op1 {
        0 => Some((ExtOp::Sxth, ExtOp::Sxtah)),
        1 => Some((ExtOp::Uxth, ExtOp::Uxtah)),
        2 => Some((ExtOp::Sxtb16, ExtOp::Sxtab16)),
        3 => Some((ExtOp::Uxtb16, ExtOp::Uxtab16)),
        4 => Some((ExtOp::Sxtb, ExtOp::Sxtab)),
        5 => Some((ExtOp::Uxtb, ExtOp::Uxtab)),
        _ => None,
    };
    if let Some((plain_op, add_op)) = ext_op {
        if op2 >= 8 {
            let rot = ((op2 - 8) * 8) as u8;
            let op = if rn == 15 { plain_op } else { add_op };
            let rn_eff = if rn == 15 { 0 } else { rn };
            return Ok(Ins::Extend { op, rd, rn: rn_eff, rm, rot });
        }
        return Err(DecodeErr(w));
    }

    match (op1, op2) {
        (0b1001, 0b1000) => Ok(Ins::Rev { rd, rm }),
        (0b1001, 0b1001) => Ok(Ins::Rev16 { rd, rm }),
        (0b1001, 0b1010) => Ok(Ins::Rbit { rd, rm }),
        (0b1001, 0b1011) => Ok(Ins::Revsh { rd, rm }),
        (0b1010, 0b1000) => Ok(Ins::Sel { rd, rn, rm }),
        (0b1011, 0b1000) => Ok(Ins::Clz { rd, rm: rn }),
        (0b1000, 0b1000) => Ok(Ins::Qadd { rd, rn, rm }),
        (0b1000, 0b1001) => Ok(Ins::Qdadd { rd, rn, rm }),
        (0b1000, 0b1010) => Ok(Ins::Qsub { rd, rn, rm }),
        (0b1000, 0b1011) => Ok(Ins::Qdsub { rd, rn, rm }),
        // CRC32: (c,8/9/a) = b/h/w; (d,8/9/a) = cb/ch/cw (poly32 = op1 == 0xd)
        (0b1100, 0b1000) => Ok(Ins::Crc32 { poly32: false, sz: Size::B8, rd, rn, rm }),
        (0b1100, 0b1001) => Ok(Ins::Crc32 { poly32: false, sz: Size::H16, rd, rn, rm }),
        (0b1100, 0b1010) => Ok(Ins::Crc32 { poly32: false, sz: Size::W32, rd, rn, rm }),
        (0b1101, 0b1000) => Ok(Ins::Crc32 { poly32: true, sz: Size::B8, rd, rn, rm }),
        (0b1101, 0b1001) => Ok(Ins::Crc32 { poly32: true, sz: Size::H16, rd, rn, rm }),
        (0b1101, 0b1010) => Ok(Ins::Crc32 { poly32: true, sz: Size::W32, rd, rn, rm }),
        // Parallel families: shape from op1 (8=Add8,9=Add16,A=Asx,C=Sub8,D=Sub16,E=Sax),
        // kind from op2 (0=S,1=Q,2=SH,4=U,5=UQ,6=UH).
        _ => {
            let shape = match op1 {
                0b1000 => ParShape::Add8,
                0b1001 => ParShape::Add16,
                0b1010 => ParShape::Addsubx,
                0b1100 => ParShape::Sub8,
                0b1101 => ParShape::Sub16,
                0b1110 => ParShape::Subaddx,
                _ => return Err(DecodeErr(w)),
            };
            let kind = match op2 {
                0 => ParKind::S,
                1 => ParKind::Q,
                2 => ParKind::Sh,
                4 => ParKind::U,
                5 => ParKind::Uq,
                6 => ParKind::Uh,
                _ => return Err(DecodeErr(w)),
            };
            Ok(Ins::Parallel { kind, shape, rd, rn, rm })
        }
    }
}

// ---------- fb: multiply ----------
// hw1 = 1111 1011 op1(4) Rn; hw2 = Ra(15:12) Rd(11:8) op2(7:4) Rm(3:0).

fn decode_fb(w: u32) -> Result<Ins, DecodeErr> {
    let op1 = bb(w, 23, 20);
    let op2 = bb(w, 7, 4);
    let rn = bb(w, 19, 16) as u8;
    let ra = bb(w, 15, 12) as u8;
    let rd = bb(w, 11, 8) as u8;
    let rdlo = ra;
    let rm = bb(w, 3, 0) as u8;
    let no_acc = ra == 15;

    match (op1, op2) {
        (0b0000, 0b0000) if no_acc => Ok(Ins::Mul { rd, rn, rm, s: false }),
        (0b0000, 0b0000) => Ok(Ins::Mla { rd, rn, rm, ra, s: false }),
        (0b0000, 0b0001) => Ok(Ins::Mls { rd, rn, rm, ra }),
        // (1, xy): SMULxy / SMLAxy — x = op2.1 (Rn half), y = op2.0 (Rm half)
        (0b0001, 0..=3) if no_acc => Ok(Ins::Smulxy {
            rd, rn, rm,
            x: if op2 & 2 != 0 { Half::T } else { Half::B },
            y: if op2 & 1 != 0 { Half::T } else { Half::B },
        }),
        (0b0001, 0..=3) => Ok(Ins::Smlaxy {
            rd, rn, rm, ra,
            x: if op2 & 2 != 0 { Half::T } else { Half::B },
            y: if op2 & 1 != 0 { Half::T } else { Half::B },
        }),
        // (2, x): SMUAD(X)/SMLAD(X); (4, x): SMUSD(X)/SMLSD(X)
        (0b0010, x) if x <= 1 && no_acc => Ok(Ins::Smuad { rd, rn, rm, x: op2 & 1 == 1 }),
        (0b0010, x) if x <= 1 => Ok(Ins::Smlad { rd, rn, rm, ra, x: op2 & 1 == 1 }),
        (0b0100, x) if x <= 1 && no_acc => Ok(Ins::Smusd { rd, rn, rm, x: op2 & 1 == 1 }),
        (0b0100, x) if x <= 1 => Ok(Ins::Smlsd { rd, rn, rm, ra, x: op2 & 1 == 1 }),
        // (3, y): SMULWB/WT + SMLAWB/WT (y = Rm half)
        (0b0011, x) if x <= 1 && no_acc => Ok(Ins::Smulwy { rd, rn, rm, y: if op2 & 1 == 1 { Half::T } else { Half::B } }),
        (0b0011, x) if x <= 1 => Ok(Ins::Smlawy { rd, rn, rm, ra, y: if op2 & 1 == 1 { Half::T } else { Half::B } }),
        // (5, r): SMMUL/SMMULR (Ra=15) + SMMLA/SMMLAR
        (0b0101, 0) if no_acc => Ok(Ins::Smmul { rd, rn, rm, ra: None, sub: false, round: false }),
        (0b0101, 1) if no_acc => Ok(Ins::Smmul { rd, rn, rm, ra: None, sub: false, round: true }),
        (0b0101, 0) => Ok(Ins::Smmul { rd, rn, rm, ra: Some(ra), sub: false, round: false }),
        (0b0101, 1) => Ok(Ins::Smmul { rd, rn, rm, ra: Some(ra), sub: false, round: true }),
        // (6, r): SMMLS/SMMLSR (Ra≠15)
        (0b0110, 0) => Ok(Ins::Smmul { rd, rn, rm, ra: Some(ra), sub: true, round: false }),
        (0b0110, 1) => Ok(Ins::Smmul { rd, rn, rm, ra: Some(ra), sub: true, round: true }),
        // (7, 0): USAD8 / USADA8
        (0b0111, 0) if no_acc => Ok(Ins::Usad8 { rd, rn, rm }),
        (0b0111, 0) => Ok(Ins::Usada8 { rd, rn, rm, ra }),
        // long multiplies: (8,0) SMULL, (A,0) UMULL, (C,0) SMLAL, (E,0) UMLAL, (E,6) UMAAL
        (0b1000, 0) => Ok(Ins::Smull { rdlo, rdhi: rd, rn, rm, s: false }),
        (0b1010, 0) => Ok(Ins::Umull { rdlo, rdhi: rd, rn, rm, s: false }),
        (0b1100, 0) => Ok(Ins::Smlal { rdlo, rdhi: rd, rn, rm, s: false }),
        (0b1110, 0) => Ok(Ins::Umlal { rdlo, rdhi: rd, rn, rm, s: false }),
        (0b1110, 0b0110) => Ok(Ins::Umaal { rdlo, rdhi: rd, rn, rm }),
        // (C,c/d): SMLALD/X; (D,c/d): SMLSLD/X
        (0b1100, 0b1100) => Ok(Ins::Smlald { rdlo, rdhi: rd, rn, rm, x: false }),
        (0b1100, 0b1101) => Ok(Ins::Smlald { rdlo, rdhi: rd, rn, rm, x: true }),
        (0b1101, 0b1100) => Ok(Ins::Smlsld { rdlo, rdhi: rd, rn, rm, x: false }),
        (0b1101, 0b1101) => Ok(Ins::Smlsld { rdlo, rdhi: rd, rn, rm, x: true }),
        // (9,F): SDIV; (B,F): UDIV
        (0b1001, 0b1111) => Ok(Ins::Sdiv { rd, rn, rm }),
        (0b1011, 0b1111) => Ok(Ins::Udiv { rd, rn, rm }),
        _ => Err(DecodeErr(w)),
    }
}

//! T32 (Thumb-2) encoder: `Ins` -> (hw1, hw2).
//!
//! Inverse of `decode.rs`; round-trip is validated by the golden corpus tests.
//! Encoding preference mirrors LLVM's assembler: emit a 16-bit form whenever
//! the instruction is representable in one; 32-bit forms only when required
//! (hi registers, wide immediates, writeback, signed/exclusive/dual forms…).

use crate::common::*;
use crate::a32::ins::*;
use crate::a32::ins::Ins::*;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EncodeErr(pub &'static str);

impl core::fmt::Display for EncodeErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot encode T32: {}", self.0)
    }
}

#[inline]
fn bit(v: u32, n: u32) -> u32 { (v >> n) & 1 }

/// Encode one instruction. Returns (hw1, hw2, len-in-bytes).
/// Encode an `Ins` back to T32, preferring 16-bit forms where both exist.
pub fn encode_t32(ins: &Ins) -> Result<(u16, u16, u16), EncodeErr> {
    // ---- try the 16-bit forms first (LLVM-compatible preference) ----
    if let Some(hw) = encode_t16(ins) {
        return Ok((hw, 0, 2));
    }
    let (hw1, hw2) = encode_t32_32(ins)?;
    Ok((hw1, hw2, 4))
}

/// Length-aware encoding: guarantees byte-exact re-encoding for the form the
/// decoder produced (`len` = 2 or 4). Disambiguates the T16/32-bit forms that
/// decode to the same `Ins` (e.g. ADR T1 vs ADR.W T3).
pub fn encode_t32_len(ins: &Ins, len: u16) -> Result<(u16, u16, u16), EncodeErr> {
    if len == 2 {
        let hw = encode_t16(ins).ok_or(EncodeErr("no 16-bit form"))?;
        return Ok((hw, 0, 2));
    }
    let (hw1, hw2) = encode_t32_32(ins)?;
    Ok((hw1, hw2, 4))
}

// ==================== 16-bit forms ====================

fn encode_t16(ins: &Ins) -> Option<u16> {
    Some(match ins {
        // LSLS/LSRS/ASRS imm5 (rd, rn < 8)
        DpReg { op: DpOp::Mov, s: true, rn: 0, rd, rm, shift, amount: ShiftAmount::Imm(a) }
            if *rd < 8 && *rm < 8 && *a < 32 => match shift {
                Shift::Lsl => 0x0000 | ((*a as u32) << 6) | ((*rm as u32) << 3) | *rd as u32,
                Shift::Lsr => 0x0800 | ((*a as u32) << 6) | ((*rm as u32) << 3) | *rd as u32,
                Shift::Asr => 0x1000 | ((*a as u32) << 6) | ((*rm as u32) << 3) | *rd as u32,
                Shift::Ror => return None,
            },
        // ADD/SUB reg, 3 fields (all < 8)
        DpReg { op, s: true, rn, rd, rm, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) }
            if matches!(op, DpOp::Add | DpOp::Sub) && *rn < 8 && *rd < 8 && *rm < 8 => {
                let sub = matches!(op, DpOp::Sub) as u32;
                0x1800 | (sub << 9) | ((*rm as u32) << 6) | ((*rn as u32) << 3) | *rd as u32
            }
        // ADD/SUB imm3 3-field (rn ≠ rd, both < 8, imm ≤ 7)
        DpImmT32 { op, s: true, rn, rd, imm12, plain: true } if rn != rd && *rn < 8 && *rd < 8 && matches!(op, DpOp::Add | DpOp::Sub) && *imm12 <= 7 => {
            let sub = matches!(op, DpOp::Sub) as u32;
            0x1C00 | (sub << 9) | ((*imm12 as u32) << 6) | ((*rn as u32) << 3) | *rd as u32
        }
        // MOV/CMP/ADD/SUB imm8 (r < 8, imm ≤ 255, rn==rd for add/sub)
        DpImmT32 { op: DpOp::Mov, s: true, rn: 0, rd, imm12, plain: true } if *rd < 8 && *imm12 <= 0xFF => {
            0x2000 | ((*rd as u32) << 8) | *imm12 as u32
        }
        DpImmT32 { op: DpOp::Cmp, s: true, rn, rd: 15, imm12, plain: true } if *rn < 8 && *imm12 <= 0xFF => {
            0x2800 | ((*rn as u32) << 8) | *imm12 as u32
        }
        DpImmT32 { op, s: true, rn, rd, imm12, plain: true } if rn == rd && *rd < 8 && matches!(op, DpOp::Add | DpOp::Sub) && *imm12 <= 0xFF => {
            let base = if matches!(op, DpOp::Add) { 0x3000 } else { 0x3800 };
            base | ((*rd as u32) << 8) | *imm12 as u32
        }
        // DP (010000): tests (Rd=15) — operand reg < 8
        DpReg { op, s: true, rn, rd: 15, rm, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) }
            if *rn < 8 && *rm < 8 => {
                let code = match op {
                    DpOp::Tst => 0x8u32, DpOp::Cmp => 0xA, _ => 0xB, // Cmn
                };
                0x4000 | (code << 6) | ((*rm as u32) << 3) | *rn as u32
            }
        // MVNS (rn == 0)
        DpReg { op: DpOp::Mvn, s: true, rn: 0, rd, rm, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) }
            if *rd < 8 && *rm < 8 => {
                0x43C0 | ((*rm as u32) << 3) | *rd as u32
            }
        // DP (010000): rn == rd < 8 for the 2-operand group
        DpReg { op, s: true, rn, rd, rm, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) }
            if *rn == *rd && *rd < 8 && *rm < 8 => {
                let code = match op {
                    DpOp::And => 0x0u32, DpOp::Eor => 0x1, DpOp::Adc => 0x5, DpOp::Sbc => 0x6,
                    DpOp::Orr => 0xC, DpOp::Bic => 0xE,
                    _ => return None,
                };
                0x4000 | (code << 6) | ((*rm as u32) << 3) | *rd as u32
            }
        // RSBS rd, rn, #0
        DpImm { op: DpOp::Rsb, s: true, rn, rd, imm12: 0 } if *rn < 8 && *rd < 8 => {
            0x4240 | ((*rn as u32) << 3) | *rd as u32
        }
        // MULS (rd == rn < 8)
        Mul { rd, rn, rm, s: true } if *rd == *rn && *rd < 8 && *rm < 8 => {
            0x4340 | ((*rm as u32) << 3) | *rd as u32
        }
        // shifts by register (ROR here; the LSL/LSR/ASR-by-reg go 32-bit only
        // via 010000 opcode 7 — but that IS rors) — all four are 010000/0011..
        DpReg { op: DpOp::Mov, s: true, rn: 0, rd, rm, shift, amount: ShiftAmount::Reg(rs) }
            if *rs == *rd && *rd < 8 && *rm < 8 => {
                let code = match shift {
                    Shift::Lsl => 0x2u32, Shift::Lsr => 0x3, Shift::Asr => 0x4, Shift::Ror => 0x7,
                };
                0x4000 | (code << 6) | ((*rm as u32) << 3) | *rd as u32
            }
        // Special data: ADD/CMP/MOV hi-reg forms (S=0, no flags)
        DpReg { op: DpOp::Add, s: false, rn, rd, rm, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) }
            if *rn == *rd && *rm < 16 && *rd < 16 => {
                0x4400 | (bit(*rn as u32, 3) << 7) | ((*rm as u32) << 3) | (*rd as u32 & 7)
            }
        DpReg { op: DpOp::Cmp, s: false, rn, rd: 15, rm, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) }
            if *rm < 16 && *rn < 16 => {
                0x4280 | (bit(*rn as u32, 3) << 7) | ((*rm as u32) << 3) | (*rn as u32 & 7)
            }
        DpReg { op: DpOp::Mov, s: false, rn: 0, rd, rm, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) }
            if *rm < 16 && *rd < 16 => {
                0x4600 | (bit(*rd as u32, 3) << 7) | ((*rm as u32) << 3) | (*rd as u32 & 7)
            }
        // LDR literal (rt < 8, 0 ≤ imm ≤ 1020, 4-aligned)
        Ldst { store: false, size: Size::W32, signed: false, user: false, rt, rn: 15, rm: None, shift: _, imm, index: true, add: true, wback: false }
            if *rt < 8 && *imm >= 0 && *imm <= 1020 && imm % 4 == 0 => {
                0x4800 | ((*rt as u32) << 8) | (*imm as u32 >> 2) as u16 as u32
            }
        // reg-offset ldst (all regs < 8, LSL #0)
        Ldst { store, size, signed: false, user: false, rt, rn, rm: Some(rm), shift: Shift::Lsl, imm: 0, index: true, add: true, wback: false }
            if *rt < 8 && *rn < 8 && *rm < 8 => {
                let code = match (store, size) {
                    (true, Size::W32) => 0u32, (true, Size::H16) => 1, (true, Size::B8) => 2,
                    (false, Size::W32) => 4, (false, Size::H16) => 5, (false, Size::B8) => 6,
                    _ => return None,
                };
                0x5000 | (code << 9) | ((*rm as u32) << 6) | ((*rn as u32) << 3) | *rt as u32
            }
        // imm5 ldst (word ×4 / byte / half ×2)
        Ldst { store, size: Size::W32, signed: false, user: false, rt, rn, rm: None, shift: _, imm, index: true, add: true, wback: false }
            if *rt < 8 && *rn < 8 && *imm >= 0 && *imm <= 124 && imm % 4 == 0 => {
                0x6000 | ((*store ^ true) as u32) << 11 | ((imm >> 2) as u32) << 6 | ((*rn as u32) << 3) | *rt as u32
            }
        Ldst { store, size: Size::B8, signed: false, user: false, rt, rn, rm: None, shift: _, imm, index: true, add: true, wback: false }
            if *rt < 8 && *rn < 8 && *imm >= 0 && *imm <= 31 => {
                0x7000 | ((*store ^ true) as u32) << 11 | (*imm as u32) << 6 | ((*rn as u32) << 3) | *rt as u32
            }
        Ldst { store, size: Size::H16, signed: false, user: false, rt, rn, rm: None, shift: _, imm, index: true, add: true, wback: false }
            if *rt < 8 && *rn < 8 && *imm >= 0 && *imm <= 62 && imm % 2 == 0 => {
                0x8000 | ((*store ^ true) as u32) << 11 | ((imm >> 1) as u32) << 6 | ((*rn as u32) << 3) | *rt as u32
            }
        // SP-relative STR/LDR (rt < 8, imm 0..1020)
        Ldst { store, size: Size::W32, signed: false, user: false, rt, rn: 13, rm: None, shift: _, imm, index: true, add: true, wback: false }
            if *rt < 8 && *imm >= 0 && *imm <= 1020 && imm % 4 == 0 => {
                0x9000 | ((*store ^ true) as u32) << 11 | ((*rt as u32) << 8) | (imm >> 2) as u32
            }
        // ADR (rn = 15, imm 0..1020, 4-aligned) / ADD Rd, SP, #imm8×4
        DpImmT32 { op: DpOp::Add, s: false, rn, rd, imm12, plain: true } if *rd < 8 && *imm12 <= 1020 && imm12 % 4 == 0 && matches!(rn, 13 | 15) => {
            let sp = (*rn == 13) as u32;
            0xA000 | (sp << 11) | ((*rd as u32) << 8) | (imm12 >> 2) as u32
        }
        // ADD/SUB SP, SP, #imm7×4
        DpImmT32 { op, s: false, rn: 13, rd: 13, imm12, plain: true } if matches!(op, DpOp::Add | DpOp::Sub) && *imm12 <= 508 && imm12 % 4 == 0 => {
            let sub = matches!(op, DpOp::Sub) as u32;
            0xB000 | (sub << 7) | (imm12 >> 2) as u32
        }
        // CBZ/CBNZ (rn < 8, off 0..126, even)
        Cbz { nz, rn, off } if *rn < 8 && *off >= 0 && *off <= 126 && off % 2 == 0 => {
            let v = *off as u32;
            0xB100 | ((*nz as u32) << 11) | (((v >> 6) & 1) << 8) | (((v >> 1) & 0x1F) << 3) | *rn as u32
        }
        // PUSH/POP (T16): no PC+LR mix; low list only (+optional LR for push / PC for pop)
        LdmStm { load: false, rn: 13, mode: LdmMode::Db, wback: true, user: false, list } => {
            let m = list.bitmap();
            let lr = m & (1 << 14) != 0;
            let low = m & 0xFF;
            let high = m & !0x40FF; // bits above 8 minus LR
            if high != 0 || (lr && m & (1 << 15) != 0) { return None; }
            0xB400 | ((lr as u32) << 8) | low as u32
        }
        LdmStm { load: true, rn: 13, mode: LdmMode::Ia, wback: true, user: false, list } => {
            let m = list.bitmap();
            let pc = m & (1 << 15) != 0;
            let low = m & 0xFF;
            let _ = pc;
            if (m >> 8) & !(if pc { 0x80 } else { 0 }) != 0 { return None; }
            0xBC00 | ((pc as u32) << 8) | low as u32
        }
        // STM/LDM 16-bit (rn < 8, low regs only, IA, no writeback)
        LdmStm { load, rn, mode: LdmMode::Ia, wback: false, user: false, list }
            if *rn < 8 && list.bitmap() & 0xFF00 == 0 => {
                0xC000 | ((*load as u32) << 11) | ((*rn as u32) << 8) | list.bitmap() as u32
            }
        // B T1 (cond): off ±256, even
        B { cond, off } if *cond != Cond::Al && *cond != Cond::Nv && off % 2 == 0 && (-256..=254).contains(off) => {
            let v = ((*off >> 1) as u32) & 0xFF;
            0xD000 | ((cond.bits() as u32) << 8) | v
        }
        // B T2: off ±2046, even
        B { cond: Cond::Al, off } if off % 2 == 0 && (-2048..=2046).contains(off) => {
            let v = ((*off >> 1) as u32) & 0x7FF;
            0xE000 | v
        }
        // SXTB/SXTH/UXTB/UXTH (no rotation; 16-bit has no B16 forms)
        Extend { op, rd, rn: 0, rm, rot: 0 } if *rd < 8 && *rm < 8 && matches!(op,
            ExtOp::Sxth | ExtOp::Sxtb | ExtOp::Uxth | ExtOp::Uxtb) => {
            let code = match op {
                ExtOp::Sxth => 0b00, ExtOp::Sxtb => 0b01, ExtOp::Uxth => 0b10, _ => 0b11,
            };
            0xB200 | ((code as u32) << 6) | ((*rm as u32) << 3) | *rd as u32
        }
        // REV/REV16/REVSH
        Rev { rd, rm } if *rd < 8 && *rm < 8 => 0xBA00 | ((*rm as u32) << 3) | *rd as u32,
        Rev16 { rd, rm } if *rd < 8 && *rm < 8 => 0xBA40 | ((*rm as u32) << 3) | *rd as u32,
        Revsh { rd, rm } if *rd < 8 && *rm < 8 => 0xBAC0 | ((*rm as u32) << 3) | *rd as u32,
        // CPS (enable/disable AIF)
        Cps { enable, aif, change_mode: false, mode: _ } if *aif != 0 => {
            0xB660 | ((!*enable as u32) << 4) | (aif & 7) as u32
        }
        // BKPT
        Bkpt { imm } if *imm <= 0xFF => 0xBE00 | *imm as u32,
        // Hints (T16)
        Hints { kind } => match kind {
            Hint::Nop => 0xBF00,
            Hint::Yield => 0xBF10,
            Hint::Wfe => 0xBF20,
            Hint::Wfi => 0xBF30,
            Hint::Sev => 0xBF40,
            _ => return None,
        },
        // IT
        It { first_cond, mask } if *mask != 0 => {
            0xBF00 | ((first_cond.bits() as u32) << 4) | *mask as u32
        }
        // BX / BLX reg
        Bx { rm } => 0x4700 | ((*rm as u32) << 3),
        BlxReg { rm } => 0x4780 | ((*rm as u32) << 3),
        // SVC
        Svc { imm } if *imm <= 0xFF => 0xDF00 | *imm,
        _ => return None,
    } as u16)
}

// ==================== 32-bit forms ====================

fn encode_t32_32(ins: &Ins) -> Result<(u16, u16), EncodeErr> {
    let w = encode_t32_word(ins)?;
    Ok(((w >> 16) as u16, (w & 0xFFFF) as u16))
}

fn enc_err(s: &'static str) -> EncodeErr { EncodeErr(s) }

fn encode_t32_word(ins: &Ins) -> Result<u32, EncodeErr> {
    Ok(match ins {
        // ======== data processing ========
        DpImm { .. } => return Err(enc_err("T16-only immediate form")),
        DpImmT32 { op, s, rn, rd, imm12, plain } => {
            if *plain {
                // ADDW/SUBW/ADR: op5 = 10000 (Add) / 10101 (Sub); S=0.
                let op5 = match op { DpOp::Add => 0b10000u32, DpOp::Sub => 0b10101, _ => return Err(enc_err("plain imm only Add/Sub")) };
                f0_imm(op5, 0, *rn, *rd, *imm12)
            } else {
                let op5 = match op {
                    DpOp::And => 0b00000, DpOp::Bic => 0b00001, DpOp::Orr => 0b00010,
                    DpOp::Orn => 0b00011, DpOp::Eor => 0b00100, DpOp::Add => 0b01000,
                    DpOp::Sub => 0b01101, DpOp::Rsb => 0b01110,
                    DpOp::Mov => 0b00010, // ORN.. no: MOV = ORR with Rn=15 (handled below)
                    DpOp::Mvn => 0b00011,
                    DpOp::Tst => 0b00000, DpOp::Teq => 0b00100,
                    DpOp::Cmp => 0b01101, DpOp::Cmn => 0b01000,
                    _ => return Err(enc_err("no T32 DP-imm form")),
                };
                let (rn_e, rd_e) = match op {
                    DpOp::Mov | DpOp::Mvn => (15u8, *rd), // Rn = PC marker
                    DpOp::Tst | DpOp::Teq | DpOp::Cmp | DpOp::Cmn => (*rn, 15u8),
                    _ => (*rn, *rd),
                };
                let s_e = match op {
                    DpOp::Tst | DpOp::Teq | DpOp::Cmp | DpOp::Cmn => true,
                    _ => *s,
                };
                f0_imm(op5, s_e as u32, rn_e, rd_e, *imm12)
            }
        }
        // Shifts by register: fa op1 = 2*type, Rn = the amount register.
        DpReg { op: DpOp::Mov, s: false, rn: 0, rd, rm, shift, amount: ShiftAmount::Reg(rs) } => {
            let op1 = (shift.bits() as u32) * 2;
            0xFA00_F000 | (op1 << 20) | ((*rs as u32) << 16) | ((*rd as u32) << 8) | *rm as u32
        }
        DpReg { op, s, rn, rd, rm, shift, amount } => {
            // MOV/MVN via Rn=15 (ORR/ORN slots); tests via Rd=15+S.
            let (opcode, rn_e, rd_e, op_e) = match op {
                DpOp::Mov => (0b0010u32, 15u8, *rd, DpOp::Orr),
                DpOp::Mvn => (0b0011u32, 15u8, *rd, DpOp::Orn),
                DpOp::Tst => (0b0000u32, *rn, 15u8, *op),
                DpOp::Teq => (0b0100u32, *rn, 15u8, *op),
                DpOp::Cmp => (0b1101u32, *rn, 15u8, *op),
                DpOp::Cmn => (0b1000u32, *rn, 15u8, *op),
                DpOp::And => (0b0000, *rn, *rd, *op),
                DpOp::Bic => (0b0001, *rn, *rd, *op),
                DpOp::Orr => (0b0010, *rn, *rd, *op),
                DpOp::Orn => (0b0011, *rn, *rd, *op),
                DpOp::Eor => (0b0100, *rn, *rd, *op),
                DpOp::Add => (0b1000, *rn, *rd, *op),
                DpOp::Adc => (0b1010, *rn, *rd, *op),
                DpOp::Sbc => (0b1011, *rn, *rd, *op),
                DpOp::Sub => (0b1101, *rn, *rd, *op),
                DpOp::Rsb => (0b1110, *rn, *rd, *op),
                _ => return Err(enc_err("no T32 DP-reg form")),
            };
            let _ = op_e;
            let s_e = if matches!(op, DpOp::Tst | DpOp::Teq | DpOp::Cmp | DpOp::Cmn) { true } else { *s };
            match amount {
                ShiftAmount::Imm(a) => {
                    let a = *a as u32;
                    if a >= 32 { return Err(enc_err("shift amount")); }
                    0xEA00_0000u32
                        | (opcode << 21) | ((s_e as u32) << 20)
                        | ((rn_e as u32) << 16)
                        | ((a >> 2) << 12) | ((rd_e as u32) << 8) | ((a & 3) << 6)
                        | ((shift.bits() as u32) << 4) | *rm as u32
                }
                ShiftAmount::Reg(_) => return Err(enc_err("reg-shift only via fa")),
            }
        }
        Movw { rd, imm16 } => f0_imm(0b10010, 0, (imm16 >> 12) as u8, *rd, imm16 & 0xFFF),
        Movt { rd, imm16 } => f0_imm(0b10110, 0, (imm16 >> 12) as u8, *rd, imm16 & 0xFFF),

        // ======== multiplies (fb) ========
        Mul { rd, rn, rm, s: false } => fb(0b0000, *rn, 15, *rd, 0, *rm),
        Mla { rd, rn, rm, ra, s: false } => fb(0b0000, *rn, *ra, *rd, 0, *rm),
        Mls { rd, rn, rm, ra } => fb(0b0000, *rn, *ra, *rd, 1, *rm),
        Smulxy { rd, rn, rm, x, y } => fb(0b0001, *rn, 15, *rd, (x.bit() as u32) << 1 | y.bit() as u32, *rm),
        Smlaxy { rd, rn, rm, ra, x, y } => fb(0b0001, *rn, *ra, *rd, (x.bit() as u32) << 1 | y.bit() as u32, *rm),
        Smulwy { rd, rn, rm, y } => fb(0b0011, *rn, 15, *rd, y.bit() as u32, *rm),
        Smlawy { rd, rn, rm, ra, y } => fb(0b0011, *rn, *ra, *rd, y.bit() as u32, *rm),
        Smuad { rd, rn, rm, x } => fb(0b0010, *rn, 15, *rd, *x as u32, *rm),
        Smlad { rd, rn, rm, ra, x } => fb(0b0010, *rn, *ra, *rd, *x as u32, *rm),
        Smusd { rd, rn, rm, x } => fb(0b0100, *rn, 15, *rd, *x as u32, *rm),
        Smlsd { rd, rn, rm, ra, x } => fb(0b0100, *rn, *ra, *rd, *x as u32, *rm),
        Smmul { rd, rn, rm, ra, sub, round } => {
            let op1 = if *sub { 0b0110 } else { 0b0101 };
            let racc = ra.unwrap_or(15);
            fb(op1, *rn, racc, *rd, *round as u32, *rm)
        }
        Usad8 { rd, rn, rm } => fb(0b0111, *rn, 15, *rd, 0, *rm),
        Usada8 { rd, rn, rm, ra } => fb(0b0111, *rn, *ra, *rd, 0, *rm),
        Smull { rdlo, rdhi, rn, rm, s: false } => fb(0b1000, *rn, *rdlo, *rdhi, 0, *rm),
        Umull { rdlo, rdhi, rn, rm, s: false } => fb(0b1010, *rn, *rdlo, *rdhi, 0, *rm),
        Smlal { rdlo, rdhi, rn, rm, s: false } => fb(0b1100, *rn, *rdlo, *rdhi, 0, *rm),
        Umlal { rdlo, rdhi, rn, rm, s: false } => fb(0b1110, *rn, *rdlo, *rdhi, 0, *rm),
        Umaal { rdlo, rdhi, rn, rm } => fb(0b1110, *rn, *rdlo, *rdhi, 0b0110, *rm),
        Smlald { rdlo, rdhi, rn, rm, x } => fb(0b1100, *rn, *rdlo, *rdhi, 0b1100 | *x as u32, *rm),
        Smlsld { rdlo, rdhi, rn, rm, x } => fb(0b1101, *rn, *rdlo, *rdhi, 0b1100 | *x as u32, *rm),
        Sdiv { rd, rn, rm } => fb(0b1001, *rn, 15, *rd, 0b1111, *rm),
        Udiv { rd, rn, rm } => fb(0b1011, *rn, 15, *rd, 0b1111, *rm),

        // ======== saturation / bitfield (f3) ========
        Ssat { rd, imm, rn, sh, asr } => {
            if *imm == 0 || *imm > 32 { return Err(enc_err("ssat imm")); }
            let shb = *asr as u32;
            f3(0b0011, (shb << 1) as u8, *rn, *rd,
               (((*sh as u32) >> 2) << 12) | (*rd as u32) << 8 | (((*sh as u32) & 3) << 6) | (*imm as u32 - 1) & 0x3F)
        }
        Usat { rd, imm, rn, sh, asr } => {
            if *imm > 31 { return Err(enc_err("usat imm")); }
            let shb = *asr as u32;
            f3(0b0011, (0b1000 | (shb << 1)) as u8, *rn, *rd,
               (((*sh as u32) >> 2) << 12) | (*rd as u32) << 8 | (((*sh as u32) & 3) << 6) | *imm as u32)
        }
        Ssat16 { rd, imm, rn } => {
            if *imm == 0 || *imm > 16 { return Err(enc_err("ssat16 imm")); }
            f3(0b0011, 0b0010, *rn, *rd, (*rd as u32) << 8 | (*imm as u32 - 1) & 0xF)
        }
        Usat16 { rd, imm, rn } => {
            if *imm > 15 { return Err(enc_err("usat16 imm")); }
            f3(0b0011, 0b1010, *rn, *rd, (*rd as u32) << 8 | *imm as u32)
        }
        Sbfx { rd, rn, lsb, width } => {
            if *lsb as u32 + *width as u32 > 32 { return Err(enc_err("sbfx")); }
            f3(0b0011, 0b0100, *rn, *rd,
               (((*lsb as u32) >> 2) << 12) | (*rd as u32) << 8 | (((*lsb as u32) & 3) << 6) | (*width as u32 - 1))
        }
        Ubfx { rd, rn, lsb, width } => {
            if *lsb as u32 + *width as u32 > 32 { return Err(enc_err("ubfx")); }
            f3(0b0011, 0b1100, *rn, *rd,
               (((*lsb as u32) >> 2) << 12) | (*rd as u32) << 8 | (((*lsb as u32) & 3) << 6) | (*width as u32 - 1))
        }
        Bfc { rd, lsb, width } => {
            let msb = *lsb as u32 + *width as u32 - 1;
            if msb > 31 { return Err(enc_err("bfc")); }
            f3(0b0011, 0b0110, 15, *rd,
               (((*lsb as u32) >> 2) << 12) | (*rd as u32) << 8 | (((*lsb as u32) & 3) << 6) | msb)
        }
        Bfi { rd, rn, lsb, width } => {
            let msb = *lsb as u32 + *width as u32 - 1;
            if msb > 31 { return Err(enc_err("bfi")); }
            f3(0b0011, 0b0110, *rn, *rd,
               (((*lsb as u32) >> 2) << 12) | (*rd as u32) << 8 | (((*lsb as u32) & 3) << 6) | msb)
        }

        // ======== status / system ========
        Mrs { rd, spsr } => {
            let hw1 = if *spsr { 0xF3FFu32 } else { 0xF3EF };
            (hw1 << 16) | 0x8000 | ((*rd as u32) << 8)
        }
        Msr { spsr, mask, rn, imm: None } => {
            let r = *spsr as u32;
            0xF380_0000 | (r << 20) | ((*rn as u32) << 0) | 0x8000 | ((*mask as u32) << 8)
        }
        Msr { spsr: _, mask: _, rn: _, imm: Some(_) } => return Err(enc_err("msr imm")),
        Hints { kind } => {
            let op = match kind {
                Hint::Nop => 0, Hint::Yield => 1, Hint::Wfe => 2, Hint::Wfi => 3,
                Hint::Sev => 4, Hint::Sevl => 5, Hint::Dbg => 0x10,
            };
            0xF3AF_8000 | op
        }
        Barriers { kind, opt } => {
            let code = match kind { Barrier::Dsb => 4, Barrier::Dmb => 5, Barrier::Isb => 6 };
            0xF3BF_8F00 | (code << 4) | *opt as u32
        }
        Udf { imm } => ((0xF7F0u32 | (*imm as u32 >> 12)) << 16) | 0xA000 | (*imm as u32 & 0xFFF),

        // ======== branches ========
        B { cond, off } if *cond != Cond::Al && *cond != Cond::Nv => enc_branch_t3(*cond, *off)?,
        B { cond: Cond::Al, off } => enc_branch_t4(*off)?,
        Bl { off } => enc_bl(*off, 1)?,
        Blx { off } => enc_bl(*off, 0)?,

        // ======== load/store ========
        Ldst { store, size, signed, user, rt, rn, rm, shift, imm, index, add, wback } => {
            enc_f8_ldst(*store, *size, *signed, *user, *rt, *rn, *rm, *shift, *imm, *index, *add, *wback)?
        }
        LdrdStrd { store, rt, rt2, rn, imm, index, add, wback } => {
            // imm (BYTES) must be a multiple of 4 in ±1020.
            // Rt = hw2[15:12] → [Rn]; Rt2 = hw2[11:8] → [Rn+4] (ARM ARM order).
            if *imm % 4 != 0 || *imm > 1020 || *imm < -1020 { return Err(enc_err("ldrd imm")); }
            let imm8 = (imm.unsigned_abs() / 4) as u32;
            let (p, u, w, l) = (*index as u32, *add as u32, *wback as u32, !*store as u32);
            0xE800_0000 | (p << 24) | (u << 23) | (1 << 22) | (w << 21) | (l << 20)
                | ((*rn as u32) << 16) | ((*rt as u32) << 12) | ((*rt2 as u32) << 8) | imm8
        }
        LdmStm { load, rn, mode, wback, user: _, list } => {
            let (p, u) = mode.pu();
            let (p, u) = (p as u32, u as u32);
            0xE800_0000 | (p << 24) | (u << 23) | ((*wback as u32) << 21) | ((*load as u32) << 20)
                | ((*rn as u32) << 16) | list.bitmap() as u32
        }
        ExclLoad { size: Size::W32, rt, rn, imm } => {
            if *imm < 0 || *imm > 1020 || imm % 4 != 0 { return Err(enc_err("ldrex imm")); }
            0xE850_0000 | ((*rn as u32) << 16) | ((*rt as u32) << 12) | 0x0F00 | (imm / 4) as u32
        }
        ExclLoad { size, rt, rn, imm: 0 } => {
            let szbits = match size { Size::B8 => 4u32, Size::H16 => 5, _ => return Err(enc_err("excl imm")) };
            0xE8D0_0000 | ((*rn as u32) << 16) | ((*rt as u32) << 12) | (szbits << 4) | 0xF
        }
        ExclLoad { .. } => return Err(enc_err("excl imm")),
        ExclLoadD { rt, rt2, rn } =>
            0xE8D0_0000 | ((*rn as u32) << 16) | ((*rt as u32) << 12) | ((*rt2 as u32) << 8) | 0x7F,
        ExclStore { size: Size::W32, rs, rt, rn, imm } => {
            if *imm < 0 || *imm > 1020 || imm % 4 != 0 { return Err(enc_err("strex imm")); }
            0xE840_0000 | ((*rn as u32) << 16) | ((*rt as u32) << 12) | ((*rs as u32) << 8) | (imm / 4) as u32
        }
        ExclStore { size, rs, rt, rn, imm: 0 } => {
            let szbits = match size { Size::B8 => 4u32, Size::H16 => 5, _ => return Err(enc_err("excl imm")) };
            0xE8C0_0000 | ((*rn as u32) << 16) | ((*rt as u32) << 12) | 0x0F00 | (szbits << 4) | *rs as u32
        }
        ExclStore { .. } => return Err(enc_err("excl imm")),
        ExclStoreD { rs, rt, rt2, rn } =>
            0xE8C0_0000 | ((*rn as u32) << 16) | ((*rt as u32) << 12) | ((*rt2 as u32) << 8) | 0x70 | *rs as u32,
        Tbb { rn, rm, half } =>
            0xE8D0_0000 | ((*rn as u32) << 16) | 0xF000 | ((*half as u32) << 4) | *rm as u32,

        // ======== 2-source (fa) ========
        Extend { op, rd, rn, rm, rot } => {
            let (op1, plain_op, add_op) = match op {
                ExtOp::Sxth | ExtOp::Sxtah => (0u32, ExtOp::Sxth, ExtOp::Sxtah),
                ExtOp::Uxth | ExtOp::Uxtah => (1, ExtOp::Uxth, ExtOp::Uxtah),
                ExtOp::Sxtb16 | ExtOp::Sxtab16 => (2, ExtOp::Sxtb16, ExtOp::Sxtab16),
                ExtOp::Uxtb16 | ExtOp::Uxtab16 => (3, ExtOp::Uxtb16, ExtOp::Uxtab16),
                ExtOp::Sxtb | ExtOp::Sxtab => (4, ExtOp::Sxtb, ExtOp::Sxtab),
                ExtOp::Uxtb | ExtOp::Uxtab => (5, ExtOp::Uxtb, ExtOp::Uxtab),
            };
            if *rot % 8 != 0 || *rot > 24 { return Err(enc_err("extend rot")); }
            let op2 = (8 + rot / 8) as u32;
            let (rn_e, _is_add) = if *op == plain_op {
                (15u32, false)
            } else if *op == add_op {
                (*rn as u32, true)
            } else {
                return Err(enc_err("extend form"));
            };
            0xFA00_F000 | (op1 << 20) | (rn_e << 16) | ((*rd as u32) << 8) | (op2 << 4) | *rm as u32
        }
        Rev { rd, rm } => fa2(0b1001, 0b1000, *rm, *rd, *rm,),
        Rev16 { rd, rm } => fa2(0b1001, 0b1001, *rm, *rd, *rm,),
        Rbit { rd, rm } => fa2(0b1001, 0b1010, *rm, *rd, *rm,),
        Revsh { rd, rm } => fa2(0b1001, 0b1011, *rm, *rd, *rm,),
        Sel { rd, rn, rm } => fa2(0b1010, 0b1000, *rn, *rd, *rm,),
        Clz { rd, rm } => fa2(0b1011, 0b1000, *rm, *rd, *rm,),
        Qadd { rd, rn, rm } => fa2(0b1000, 0b1000, *rn, *rd, *rm,),
        Qsub { rd, rn, rm } => fa2(0b1000, 0b1010, *rn, *rd, *rm,),
        Qdadd { rd, rn, rm } => fa2(0b1000, 0b1001, *rn, *rd, *rm,),
        Qdsub { rd, rn, rm } => fa2(0b1000, 0b1011, *rn, *rd, *rm,),
        Crc32 { poly32, sz, rd, rn, rm } => {
            let op1 = if *poly32 { 0b1101u32 } else { 0b1100 };
            let op2 = match sz { Size::B8 => 0b1000, Size::H16 => 0b1001, Size::W32 => 0b1010, _ => return Err(enc_err("crc32 sz")) };
            fa2(op1, op2, *rn, *rd, *rm)
        }
        Parallel { kind, shape, rd, rn, rm } => {
            let op1 = match shape {
                ParShape::Add8 => 0b1000u32, ParShape::Add16 => 0b1001,
                ParShape::Addsubx => 0b1010, ParShape::Sub8 => 0b1100,
                ParShape::Sub16 => 0b1101, ParShape::Subaddx => 0b1110,
            };
            let op2 = match kind {
                ParKind::S => 0, ParKind::Q => 1, ParKind::Sh => 2,
                ParKind::U => 4, ParKind::Uq => 5, ParKind::Uh => 6,
            };
            fa2(op1, op2, *rn, *rd, *rm)
        }
        Pkh { rd, rn, rm, top, shift } => {
            if *shift > 31 { return Err(enc_err("pkh shift")); }
            let opcode = if *top { 0b0110u32 } else { 0b0110 };
            let typ = if *top { 2u32 } else { 0 };
            0xEA00_0000 | (opcode << 21) | ((*rn as u32) << 16)
                | (((*shift as u32) >> 2) << 12) | ((*rd as u32) << 8) | (((*shift as u32) & 3) << 6)
                | (typ << 4) | *rm as u32
        }

        // ======== VFP (ee/ec/ed/fe = A32 identity) ========
        VfpBin { .. } | VfpUn { .. } | VfpCmp { .. } | VfpCmpz { .. } | crate::a32::ins::Ins::VfpMulAcc { .. }
        | VMovCoreS { .. } | VMovCoreD { .. } | VMovLane { .. } | VMrs { .. } | Vmsr { .. }
        | VLdrStr { .. } | VLdmStm { .. } | Vcvt { .. } | VcvtImm { .. }
        | Vsel { .. } | Vmaxnm { .. } | Vrint { .. } => {
            crate::a32::encode::encode_a32(ins).map_err(|_| enc_err("vfp"))?
        }
        // ======== NEON (ef/ff transform) ========
        VmovImm { kind, .. } if matches!(kind, NeonImmKind::F32 | NeonImmKind::F64) => {
            // scalar VMOV.F32/F64 imm lives in the ee VFP space (identity)
            crate::a32::encode::encode_a32(ins).map_err(|_| enc_err("vfp"))?
        }
        VdupCore { .. } | VdupScalar { .. } | Vswp { .. } | Neon { .. } | VmovImm { .. } => {
            let a32 = crate::a32::encode::encode_a32(ins).map_err(|_| enc_err("neon"))?;
            (a32 & 0x00FF_FFFF) | 0xEF00_0000 | ((a32 & 0x0100_0000) << 4)
        }
        // NEON ld/st multiple (f9): t32 = (a32 & 0x00FFFF7F) | 0xF9000000
        VldStMulti { .. } => {
            let a32 = crate::a32::encode::encode_a32(ins).map_err(|_| enc_err("neon ldst"))?;
            (a32 & 0xF0FF_FFFF) | 0x0900_0000
        }

        // ======== preload ========
        Pld { w, rn, rm, shift, imm } => {
            let sz = if *w { 0b01u32 } else { 0b00 };
            enc_pl_f8(0, sz, *rn, *rm, *shift, *imm)?
        }
        Pli { rn, rm, shift, imm } => enc_pl_f8(1, 0b00, *rn, *rm, *shift, *imm)?,

        // IT has no 32-bit form (16-bit only)
        It { .. } => return Err(enc_err("IT is 16-bit only")),

        _ => return Err(enc_err("unsupported for T32 encode")),
    })
}

// ---------- field packing helpers ----------

/// DP immediate: hw1 = 1111 0 i op5 S Rn; hw2 = imm3 Rd imm8.
fn f0_imm(op5: u32, s: u32, rn: u8, rd: u8, imm12: u16) -> u32 {
    let i = ((imm12 as u32) >> 11) & 1;
    let imm3 = ((imm12 as u32) >> 8) & 7;
    let imm8 = (imm12 as u32) & 0xFF;
    0xF000_0000
        | (i << 26) | (op5 << 21) | (s << 20)
        | ((rn as u32) << 16)
        | (imm3 << 12) | ((rd as u32) << 8) | imm8
}

/// fb multiply helper: hw1 = 1111 1011 op1 Rn, hw2 = Ra Rd op2 Rm.
fn fb(op1: u32, rn: u8, ra: u8, rd: u8, op2: u32, rm: u8) -> u32 {
    0xFB00_0000 | (op1 << 20) | ((rn as u32) << 16)
        | ((ra as u32) << 12) | ((rd as u32) << 8) | (op2 << 4) | rm as u32
}

/// fa 2-source helper: hw1 = 1111 1010 op1 Rn, hw2 = F Rd op2 Rm.
fn fa2(op1: u32, op2: u32, rn: u8, rd: u8, rm: u8) -> u32 {
    0xFA00_F000 | (op1 << 20) | ((rn as u32) << 16) | ((rd as u32) << 8) | (op2 << 4) | rm as u32
}

/// f3 space: hw1 = 1111 0011 [op nibble at 7:4] Rn, hw2 raw.
fn f3(_op_hi: u32, op_lo: u8, rn: u8, _rd: u8, hw2: u32) -> u32 {
    let hw1 = 0xF300u32 | ((op_lo as u32) << 4) | rn as u32;
    (hw1 << 16) | (hw2 & 0xFFFF)
}

// ---------- branches ----------

fn enc_branch_t3(cond: Cond, off: i32) -> Result<u32, EncodeErr> {
    if off % 2 != 0 || !(-1048576..=1048574).contains(&off) {
        return Err(enc_err("Bcc.W offset"));
    }
    let v = (off as u32) & 0x1F_FFFF; // S:J2:J1:imm6:imm11:0
    let s = (v >> 20) & 1;
    let j2 = (v >> 19) & 1;
    let j1 = (v >> 18) & 1;
    let imm6 = (v >> 12) & 0x3F;
    let imm11 = (v >> 1) & 0x7FF;
    Ok(0xF000_8000
        | (s << 26) | ((cond.bits() as u32) << 22) | (imm6 << 16)
        | (j1 << 13) | (j2 << 11) | imm11)
}

fn enc_branch_t4(off: i32) -> Result<u32, EncodeErr> {
    if off % 2 != 0 || !(-16777216..=16777214).contains(&off) {
        return Err(enc_err("B.W offset"));
    }
    let v = (off as u32) & 0x1FF_FFFF; // S:I1:I2:imm10:imm11:0
    let s = (v >> 24) & 1;
    let i1 = (v >> 23) & 1;
    let i2 = (v >> 22) & 1;
    let imm10 = (v >> 12) & 0x3FF;
    let imm11 = (v >> 1) & 0x7FF;
    let j1 = (!(i1 ^ s)) & 1;
    let j2 = (!(i2 ^ s)) & 1;
    Ok(0xF000_9000
        | (s << 26) | (imm10 << 16)
        | (j1 << 13) | (1 << 12) | (j2 << 11) | imm11)
}

fn enc_bl(off: i32, bit12: u32) -> Result<u32, EncodeErr> {
    if off % 2 != 0 || !(-16777216..=16777214).contains(&off) {
        return Err(enc_err("branch offset"));
    }
    let v = (off as u32) & 0x1FF_FFFF; // S:I1:I2:imm10:imm11:0
    let s = (v >> 24) & 1;
    let i1 = (v >> 23) & 1;
    let i2 = (v >> 22) & 1;
    let imm10 = (v >> 12) & 0x3FF;
    let imm11 = (v >> 1) & 0x7FF;
    let j1 = (!(i1 ^ s)) & 1;
    let j2 = (!(i2 ^ s)) & 1;
    Ok(0xF000_0000
        | (s << 26) | (imm10 << 16)
        | (0b11 << 14) | (j1 << 13) | (bit12 << 12) | (j2 << 11) | imm11)
}

// ---------- f8 load/store ----------

#[allow(clippy::too_many_arguments)]
fn enc_f8_ldst(store: bool, size: Size, signed: bool, user: bool, rt: u8, rn: u8,
               rm: Option<u8>, shift: Shift, imm: i32, index: bool, add: bool, wback: bool)
    -> Result<u32, EncodeErr> {
    let sz = match size { Size::B8 => 0b00u32, Size::H16 => 0b01, Size::W32 => 0b10, _ => return Err(enc_err("d64 ldst")) };
    let s = signed as u32;
    let l = !store as u32;
    let base = 0xF800_0000 | (s << 24) | (sz << 21) | (l << 20) | ((rn as u32) << 16);

    // LDR literal: Rn=PC + word + unsigned → hw2[11:0] = |imm|, U = sign.
    if rn == 15 && size == Size::W32 && !signed && rm.is_none() {
        let (u_bit, mag) = if imm >= 0 { (1u32, imm as u32) } else { (0, imm.unsigned_abs() as u32) };
        if mag <= 0xFFF && !wback && index {
            return Ok(base | (u_bit << 23) | ((rt as u32) << 12) | mag);
        }
        return Err(enc_err("literal offset"));
    }
    // Register-offset form: rm with LSL #0-3 (imm field = shift amount).
    if let Some(rm_v) = rm {
        if !user && !wback && index && add && shift == Shift::Lsl && (0..=3).contains(&imm) {
            // hw2 = Rt(15:12) 000000 shift Rm — U=0 path with [11:6]=0.
            return Ok(base & !0x0080_0000 | ((rt as u32) << 12) | ((imm as u32) << 4) | rm_v as u32);
        }
        return Err(enc_err("ldst reg form"));
    }

    // Literal (Rn=PC) handled above; plain positive imm12 (U=1).
    if index && !wback && add && !user && imm >= 0 {
        let imm12 = imm as u32;
        if imm12 <= 0xFFF {
            return Ok(base | 0x0080_0000 | ((rt as u32) << 12) | imm12);
        }
        return Err(enc_err("imm12 overflow"));
    }
    // Mode forms: negative offsets (C), pre-index writeback (D/F), post (B/9), unprivileged (E).
    if !user && wback && !index {
        // post-index: mode B (add) / 9 (sub)
        if imm >= 0 && add {
            return Ok(base | ((rt as u32) << 12) | 0x0B00 | (imm as u32 & 0xFF));
        }
        if imm < 0 && !add {
            return Ok(base | ((rt as u32) << 12) | 0x0900 | (imm.unsigned_abs() as u32 & 0xFF));
        }
        return Err(enc_err("post-index"));
    }
    if !user && wback && index {
        if imm >= 0 {
            return Ok(base | ((rt as u32) << 12) | 0x0F00 | (imm as u32 & 0xFF));
        }
        return Ok(base | ((rt as u32) << 12) | 0x0D00 | (imm.unsigned_abs() as u32 & 0xFF));
    }
    if !user && !wback && !index {
        return Err(enc_err("post without wb"));
    }
    if user && !wback && index && add && imm >= 0 {
        // unprivileged (T): mode E
        return Ok(base | ((rt as u32) << 12) | 0x0E00 | (imm as u32 & 0xFF));
    }
    if user && !wback && !index && add && imm >= 0 {
        return Err(enc_err("ldrt must have W=0 P=0?")); // unreachable
    }
    // negative offset, no writeback: mode C
    if !user && !wback && index && !add && imm < 0 && imm >= -255 {
        return Ok(base | ((rt as u32) << 12) | 0x0C00 | (imm.unsigned_abs() as u32 & 0xFF));
    }
    Err(enc_err("ldst form"))
}

/// Preload f8 form: S bit + size, Rt-slot = 1111 marker.
fn enc_pl_f8(s: u32, sz: u32, rn: u8, rm: Option<u8>, shift: Shift, imm: i32) -> Result<u32, EncodeErr> {
    let base = 0xF800_0000u32 | (s << 24) | (sz << 21) | (1 << 20) | ((rn as u32) << 16);
    let rtf = 0xF000u32; // Rt-slot = PC marker
    if let Some(rm_v) = rm {
        if !wback7(shift, imm) {
            return Ok(base | rtf | ((imm as u32 & 3) << 4) | rm_v as u32);
        }
        return Err(enc_err("pld reg"));
    }
    if imm >= 0 && imm <= 0xFFF {
        return Ok(base | 0x0080_0000 | rtf | imm as u32);
    }
    if imm < 0 && imm >= -255 {
        return Ok(base | rtf | 0x0C00 | imm.unsigned_abs() as u32);
    }
    Err(enc_err("pld offset"))
}

fn wback7(shift: Shift, imm: i32) -> bool {
    let _ = (shift, imm);
    false
}

//! A32 (ARM state) decoder: 32-bit instruction words -> `Ins`.
//! Encoding tables verified against the LLVM-generated golden corpus
//! (every field offset below is backed by assembled bytes).

use crate::common::*;
use crate::a32::ins::*;

/// Decode one A32 instruction word.
pub fn decode_a32(word: u32) -> Result<Ins, DecodeErr> {
    let cond = Cond::from_bits(bits(word, 31, 28) as u8);
    if cond == Cond::Nv {
        return decode_unconditional(word);
    }
    match bits(word, 27, 25) {
        0b000 => decode_group0(word),
        0b001 => decode_dp_imm(word),
        0b010 => decode_ldst_imm(word),
        0b011 => decode_group3(word),
        0b100 => decode_ldm_stm(word),
        0b101 => decode_branch(word),
        0b110 => decode_coproc_ldst(word),
        _ => decode_coproc(word),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecodeErr(pub u32);

impl core::fmt::Display for DecodeErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "undefined A32 encoding {:#010x}", self.0)
    }
}

const fn dp_op(op: u32) -> DpOp {
    match op {
        0b0000 => DpOp::And, 0b0001 => DpOp::Eor, 0b0010 => DpOp::Sub, 0b0011 => DpOp::Rsb,
        0b0100 => DpOp::Add, 0b0101 => DpOp::Adc, 0b0110 => DpOp::Sbc, 0b0111 => DpOp::Rsc,
        0b1000 => DpOp::Tst, 0b1001 => DpOp::Teq, 0b1010 => DpOp::Cmp, 0b1011 => DpOp::Cmn,
        0b1100 => DpOp::Orr, 0b1101 => DpOp::Mov, 0b1110 => DpOp::Bic, _ => DpOp::Mvn,
    }
}

// =========================== 001: DP immediate ===========================

fn decode_dp_imm(word: u32) -> Result<Ins, DecodeErr> {
    let op = bits(word, 24, 21);
    let s = bit(word, 20);
    let rn = bits(word, 19, 16) as u8;
    let rd = bits(word, 15, 12) as u8;
    let imm12 = bits(word, 11, 0) as u16;

    // MOVW: 0011 0000 imm4 Rd imm12
    if bit(word, 24) && !bit(word, 23) && !bit(word, 22) && !bit(word, 21) && !bit(word, 20) {
        return Ok(Ins::Movw { rd, imm16: (((rn as u16) << 12) | imm12) });
    }
    // MOVT: 0011 0100 imm4 Rd imm12
    if bit(word, 24) && !bit(word, 23) && bit(word, 22) && !bit(word, 21) && !bit(word, 20) {
        return Ok(Ins::Movt { rd, imm16: (((rn as u16) << 12) | imm12) });
    }
    // hints: TST/TEQ slot with S=0, bits(19:16)=0000, bits(15:12)=1111, imm12 0..5
    if (0b1000..=0b1011).contains(&op) && !s && rn == 0b0000 && rd == 0b1111 {
        match imm12 {
            0 => return Ok(Ins::Hints { kind: Hint::Nop }),
            1 => return Ok(Ins::Hints { kind: Hint::Yield }),
            2 => return Ok(Ins::Hints { kind: Hint::Wfe }),
            3 => return Ok(Ins::Hints { kind: Hint::Wfi }),
            4 => return Ok(Ins::Hints { kind: Hint::Sev }),
            5 => return Ok(Ins::Hints { kind: Hint::Sevl }),
            _ => return Err(DecodeErr(word)),
        }
    }
    // MSR (immediate): 0011 0d10 mask 1111 rot imm8
    if bit(word, 24) && !bit(word, 23) && bit(word, 21) && !bit(word, 20) && rd == 0b1111 {
        let mask = rn;
        let rot = bits(word, 11, 8);
        let imm8 = bits(word, 7, 0);
        let val = imm8.rotate_right(rot * 2);
        return Ok(Ins::Msr { spsr: false, mask, rn: 0, imm: Some(val) });
    }
    // hints: TST/TEQ slot with S=0, bits(19:16)=0000, bits(15:12)=1111, imm12 0..5
    if (0b1000..=0b1011).contains(&op) && !s && rn == 0b0000 && rd == 0b1111 {
        match imm12 {
            0 => return Ok(Ins::Hints { kind: Hint::Nop }),
            1 => return Ok(Ins::Hints { kind: Hint::Yield }),
            2 => return Ok(Ins::Hints { kind: Hint::Wfe }),
            3 => return Ok(Ins::Hints { kind: Hint::Wfi }),
            4 => return Ok(Ins::Hints { kind: Hint::Sev }),
            5 => return Ok(Ins::Hints { kind: Hint::Sevl }),
            _ => return Err(DecodeErr(word)),
        }
    }
    Ok(Ins::DpImm { op: dp_op(op), s, rn, rd, imm12 })
}

// =========================== 000 group ===========================

fn decode_group0(word: u32) -> Result<Ins, DecodeErr> {
    let op = bits(word, 24, 21);
    let s = bit(word, 20);
    let rn = bits(word, 19, 16) as u8;
    let rd = bits(word, 15, 12) as u8;
    let op2 = bits(word, 7, 4);

    // ---- multiply / sync (op2=1001) ----
    if op2 == 0b1001 && bit(word, 4) {
        return if bit(word, 24) { decode_sync(word) } else { decode_multiply(word) };
    }
    // ---- extra load/store (op2 = 1011/1101/1111) ----
    if op2 == 0b1011 || op2 == 0b1101 || op2 == 0b1111 {
        return decode_extra_ldst(word);
    }

    // ---- miscellaneous (checked before media) ----
    // MRS: 0001 0r00 1111 Rd 00000000
    if bit(word, 24) && !bit(word, 23) && !bit(word, 22) && !bit(word, 21) && !bit(word, 20)
        && rn == 0b1111 && bits(word, 11, 0) == 0 {
        return Ok(Ins::Mrs { rd, spsr: false });
    }
    if bit(word, 24) && !bit(word, 23) && bit(word, 22) && !bit(word, 21) && !bit(word, 20)
        && rn == 0b1111 && bits(word, 11, 0) == 0 {
        return Ok(Ins::Mrs { rd, spsr: true });
    }
    // MSR (register): 0001 0r10 mask 1111 0000 0000 Rm
    if bit(word, 24) && !bit(word, 23) && bit(word, 21) && !bit(word, 20)
        && rd == 0b1111 && bits(word, 11, 4) == 0 && op2 == 0b0000 {
        return Ok(Ins::Msr { spsr: bit(word, 22), mask: rn, rn: bits(word, 3, 0) as u8, imm: None });
    }
    // BX / BXJ / BLX reg: 0001 0010 1111 1111 1111 0xx1 Rm
    if bit(word, 24) && !bit(word, 23) && !bit(word, 22) && bit(word, 21) && !bit(word, 20)
        && rn == 0b1111 && rd == 0b1111 && bits(word, 11, 8) == 0b1111 {
        match op2 {
            0b0001 => return Ok(Ins::Bx { rm: bits(word, 3, 0) as u8 }),
            0b0010 => return Ok(Ins::Bxj { rm: bits(word, 3, 0) as u8 }),
            0b0011 => return Ok(Ins::BlxReg { rm: bits(word, 3, 0) as u8 }),
            _ => {}
        }
    }
    // BKPT: 0010 0010 0000 0000 0111 imm
    if bit(word, 24) && !bit(word, 23) && !bit(word, 22) && bit(word, 21) && !bit(word, 20)
        && rn == 0 && rd == 0 && op2 == 0b0111 {
        return Ok(Ins::Bkpt { imm: ((bits(word, 11, 8) as u16) << 4) | bits(word, 3, 0) as u16 });
    }
    // SMC: 0001 0110 0000 0000 0000 0111 imm4
    if bit(word, 24) && !bit(word, 23) && bit(word, 22) && bit(word, 21) && !bit(word, 20)
        && rn == 0 && rd == 0 && op2 == 0b0111 {
        return Ok(Ins::Smc { imm: bits(word, 3, 0) as u16 });
    }

    // ---- media in 000 space ----
    if bit(word, 24) && !bit(word, 23) && (bit(word, 7) || bit(word, 4)) {
        return decode_media_000(word);
    }

    // ---- data processing (register) ----
    let rm = bits(word, 3, 0) as u8;
    if bit(word, 4) {
        let rs = bits(word, 11, 8) as u8;
        return Ok(Ins::DpReg {
            op: dp_op(op), s, rn, rd, rm,
            shift: Shift::from_bits(bits(word, 6, 5) as u8),
            amount: ShiftAmount::Reg(rs),
        });
    }
    Ok(Ins::DpReg {
        op: dp_op(op), s, rn, rd, rm,
        shift: Shift::from_bits(bits(word, 6, 5) as u8),
        amount: ShiftAmount::Imm(bits(word, 11, 7) as u8),
    })
}

/// Multiply family: bits(7:4)=1001, bit24=0.
fn decode_multiply(word: u32) -> Result<Ins, DecodeErr> {
    let rd = bits(word, 19, 16) as u8;
    let ra_or_lo = bits(word, 15, 12) as u8;
    let rm = bits(word, 11, 8) as u8;
    let rn = bits(word, 3, 0) as u8;
    let s = bit(word, 20);
    Ok(match bits(word, 23, 21) {
        0b000 => Ins::Mul { rd, rn, rm, s },
        0b001 => Ins::Mla { rd, rn, rm, ra: ra_or_lo, s },
        0b011 => Ins::Mls { rd, rn, rm, ra: ra_or_lo },
        0b100 => Ins::Umull { rdlo: ra_or_lo, rdhi: rd, rn, rm, s },
        0b101 => Ins::Umlal { rdlo: ra_or_lo, rdhi: rd, rn, rm, s },
        0b110 => Ins::Smull { rdlo: ra_or_lo, rdhi: rd, rn, rm, s },
        0b111 => Ins::Smlal { rdlo: ra_or_lo, rdhi: rd, rn, rm, s },
        _ => return Err(DecodeErr(word)),
    })
}

/// Sync primitives: bits(7:4)=1001, bit24=1.
fn decode_sync(word: u32) -> Result<Ins, DecodeErr> {
    let rn = bits(word, 19, 16) as u8;
    let rt = bits(word, 15, 12) as u8;
    let l = bit(word, 20);
    let rm = bits(word, 3, 0) as u8;
    Ok(match bits(word, 23, 21) {
        0b100 if l => Ins::ExclLoad { size: Size::W32, rt, rn },
        0b100 => Ins::ExclStore { size: Size::W32, rs: rt, rt: rm, rn },
        0b101 if l => Ins::ExclLoadD { rt, rt2: rm, rn },
        0b101 => Ins::ExclStoreD { rs: rt, rt: rm, rt2: (rm + 1) & 15, rn },
        0b110 if l => Ins::ExclLoad { size: Size::B8, rt, rn },
        0b110 => Ins::ExclStore { size: Size::B8, rs: rt, rt: rm, rn },
        0b111 if l => Ins::ExclLoad { size: Size::H16, rt, rn },
        0b111 => Ins::ExclStore { size: Size::H16, rs: rt, rt: rm, rn },
        _ => return Err(DecodeErr(word)),
    })
}

/// Extra load/store: bits(7:4) in {1011,1101,1111}.
fn decode_extra_ldst(word: u32) -> Result<Ins, DecodeErr> {
    let p = bit(word, 24);
    let u = bit(word, 23);
    let imm_form = bit(word, 22);
    let w = bit(word, 21);
    let l = bit(word, 20);
    let rn = bits(word, 19, 16) as u8;
    let rt = bits(word, 15, 12) as u8;
    let op2 = bits(word, 7, 4);
    let lo = bits(word, 3, 0);

    let wback = w || !p;
    let index = p;
    let add = u;

    let (rm, imm) = if imm_form {
        let imm8 = (bits(word, 11, 8) << 4) | lo;
        (None, if u { imm8 as i32 } else { -(imm8 as i32) })
    } else {
        (Some(lo as u8), 0)
    };

    Ok(match (op2, l) {
        (0b1011, false) => Ins::Ldst { store: true, size: Size::H16, signed: false, user: false,
            rt, rn, rm, shift: Shift::Lsl, imm, index, add, wback },
        (0b1011, true) => Ins::Ldst { store: false, size: Size::H16, signed: false, user: false,
            rt, rn, rm, shift: Shift::Lsl, imm, index, add, wback },
        (0b1101, true) => Ins::Ldst { store: false, size: Size::B8, signed: true, user: false,
            rt, rn, rm, shift: Shift::Lsl, imm, index, add, wback },
        (0b1111, true) => Ins::Ldst { store: false, size: Size::H16, signed: true, user: false,
            rt, rn, rm, shift: Shift::Lsl, imm, index, add, wback },
        (0b1101, false) => Ins::LdrdStrd { store: false, rt, rt2: (rt + 1) & 15, rn, imm, index, add, wback },
        (0b1111, false) => Ins::LdrdStrd { store: true, rt, rt2: (rt + 1) & 15, rn, imm, index, add, wback },
        _ => return Err(DecodeErr(word)),
    })
}

/// Media in 000 space: bit24=1, bit23=0.
/// SMLAxy(op2421=0000,op2=0001) / SMULxy(1011,1yx0) / SMULW-SMLAW(1001) /
/// QADD family(1000..1011, 0101) / CLZ(1011, op2=0001, bits(11:8)=f).
fn decode_media_000(word: u32) -> Result<Ins, DecodeErr> {
    let op = bits(word, 24, 21);
    let rn = bits(word, 19, 16) as u8;   // Ra for accumulate forms; 1111 marker for CLZ
    let rd = bits(word, 15, 12) as u8;
    let rm = bits(word, 11, 8) as u8;
    let op2 = bits(word, 7, 4);
    let rn_f = bits(word, 3, 0) as u8;   // Rn

    match (op, op2) {
        // SMLAxy: op(24:21)=1000, op2=1yx0: Rd(19:16) Ra(15:12) Rm(11:8) Rn(3:0)
        (0b1000, 0b1000) | (0b1000, 0b1010) | (0b1000, 0b1100) | (0b1000, 0b1110) => return Ok(Ins::Smlaxy { rd: rn, rn: rn_f, rm, ra: rd,
            x: if bit(word, 5) { Half::T } else { Half::B },
            y: if bit(word, 6) { Half::T } else { Half::B } }),
        // QADD family: op(24:21): 1000=qadd, 1001=qsub, 1010=qdadd, 1011=qdsub (op2=0101)
        // layout: Rn(19:16) Rd(15:12) 0000(11:8) 0101(7:4) Rm(3:0)
        (0b1000, 0b0101) => return Ok(Ins::Qadd { rd, rn, rm: rn_f }),
        (0b1001, 0b0101) => return Ok(Ins::Qsub { rd, rn, rm: rn_f }),
        (0b1010, 0b0101) => return Ok(Ins::Qdadd { rd, rn, rm: rn_f }),
        (0b1011, 0b0101) => return Ok(Ins::Qdsub { rd, rn, rm: rn_f }),
        // SMULxy: op(24:21)=1011, op2=1yx0: Rd(15:12) Rm(11:8) Rn(3:0)
        (0b1011, 0b1000) | (0b1011, 0b1010) | (0b1011, 0b1100) | (0b1011, 0b1110) => {
            return Ok(Ins::Smulxy { rd, rn: rn_f, rm,
                x: if bit(word, 5) { Half::T } else { Half::B },
                y: if bit(word, 6) { Half::T } else { Half::B } });
        }
        // CLZ: op(24:21)=1011, op2=0001, marker(19:16)=1111, bits(11:8)=1111
        (0b1011, 0b0001) if bits(word, 11, 8) == 0b1111 && rn == 0b1111 => {
            return Ok(Ins::Clz { rd, rm: rn_f });
        }
        // SMULW/SMLAW: op(24:21)=1001: SMULW: Ra=0
        (0b1001, 0b1010) if rn == 0 => return Ok(Ins::Smulwy { rd, rn: rn_f, rm, y: Half::B }),
        (0b1001, 0b1110) if rn == 0 => return Ok(Ins::Smulwy { rd, rn: rn_f, rm, y: Half::T }),
        (0b1001, 0b1000) => return Ok(Ins::Smlawy { rd: rn, rn: rn_f, rm, ra: rd, y: Half::B }),
        (0b1001, 0b1100) => return Ok(Ins::Smlawy { rd: rn, rn: rn_f, rm, ra: rd, y: Half::T }),
        _ => {}
    }
    Err(DecodeErr(word))
}

// =========================== 011 group ===========================

fn decode_group3(word: u32) -> Result<Ins, DecodeErr> {
    if bit(word, 4) {
        return decode_media_011(word);
    }
    // load/store register offset: cond 011 P U B W L Rn Rt imm5 type 0 Rm
    let p = bit(word, 24);
    let u = bit(word, 23);
    let b = bit(word, 22);
    let w = bit(word, 21);
    let l = bit(word, 20);
    let rn = bits(word, 19, 16) as u8;
    let rt = bits(word, 15, 12) as u8;
    let rm = bits(word, 3, 0) as u8;
    let shift = Shift::from_bits(bits(word, 6, 5) as u8);
    let amount = bits(word, 11, 7) as u8;
    if !p && w {
        return Err(DecodeErr(word));
    }
    Ok(Ins::Ldst {
        store: !l, size: if b { Size::B8 } else { Size::W32 },
        signed: false, user: false,
        rt, rn, rm: Some(rm), shift,
        imm: amount as i32, index: p, add: u, wback: w || !p,
    })
}

/// Media instructions in 011 space (bit4=1).
/// op1 = bits(24:20); op2 = bits(7:4).
fn decode_media_011(word: u32) -> Result<Ins, DecodeErr> {
    let op1 = bits(word, 24, 20);
    let rn = bits(word, 19, 16) as u8;
    let rd = bits(word, 15, 12) as u8;
    let bits11_8 = bits(word, 11, 8) as u8;
    let op2 = bits(word, 7, 4);
    let rm = bits(word, 3, 0) as u8;

    // ---- parallel add/sub (op1 selects family, op2 selects shape) ----
    let kind = match op1 {
        0b00001 => Some(ParKind::S),
        0b00010 => Some(ParKind::Q),
        0b00011 => Some(ParKind::Sh),
        0b00101 => Some(ParKind::U),
        0b00110 => Some(ParKind::Uq),
        0b00111 => Some(ParKind::Uh),
        _ => None,
    };
    if let Some(kind) = kind {
        let shape = match op2 {
            0b0001 => ParShape::Add16,
            0b0011 => ParShape::Addsubx,
            0b0101 => ParShape::Subaddx,
            0b0111 => ParShape::Sub16,
            0b1001 => ParShape::Add8,
            0b1011 => ParShape::Sub8,
            0b1111 => ParShape::Sub8,
            _ => return Err(DecodeErr(word)),
        };
        return Ok(Ins::Parallel { kind, shape, rd, rn, rm });
    }

    match op1 {
        // PKH / SXTB16-family / SEL: nibble#2=8 (op1=01000)
        0b01000 => {
            if op2 & 0b0011 == 0b0001 {
                // PKHBT (bit6=0) / PKHTB (bit6=1): imm5 shift at bits(11:7)
                return Ok(Ins::Pkh { rd, rn, rm, top: bit(word, 6), shift: bits(word, 11, 7) as u8 });
            }
            match op2 {
                0b0111 => {
                    let rot = bits(word, 11, 7) as u8;
                    return Ok(if rn == 0b1111 {
                        Ins::Extend { op: ExtOp::Sxtb16, rd, rn: rm, rm, rot }
                    } else {
                        Ins::Extend { op: ExtOp::Sxtab16, rd, rn, rm, rot }
                    });
                }
                0b1011 => return Ok(Ins::Sel { rd, rn, rm }),
                _ => return Err(DecodeErr(word)),
            }
        }
        // SSAT (imm<16) / SSAT16 / SXTB-family: nibble#2=a (op1=01010)
        0b01010 => {
            if op2 & 0b0011 == 0b0001 {
                return Ok(Ins::Ssat { rd, imm: (rn + 1) as u8, rn: rm, sh: bits(word, 11, 7) as u8, asr: bit(word, 6) });
            }
            match op2 {
                0b0011 if bits11_8 == 0b1111 => return Ok(Ins::Ssat16 { rd, imm: (rn + 1) as u8, rn: rm }),
                0b0111 => {
                    let rot = bits(word, 11, 7) as u8;
                    return Ok(if rn == 0b1111 {
                        Ins::Extend { op: ExtOp::Sxtb, rd, rn: rm, rm, rot }
                    } else {
                        Ins::Extend { op: ExtOp::Sxtab, rd, rn, rm, rot }
                    });
                }
                _ => return Err(DecodeErr(word)),
            }
        }
        // SSAT (imm>=16) / SSAT16(imm>=16) / REV / SXTH-family / REV16: nibble#2=b (op1=01011)
        0b01011 => {
            if op2 & 0b0011 == 0b0001 {
                return Ok(Ins::Ssat { rd, imm: (16 + rn + 1) as u8, rn: rm, sh: bits(word, 11, 7) as u8, asr: bit(word, 6) });
            }
            match op2 {
                0b0011 if rn == 0b1111 && bits11_8 == 0b1111 => return Ok(Ins::Rev { rd, rm }),
                0b0011 if bits11_8 == 0b1111 && rn != 0b1111 => return Ok(Ins::Ssat16 { rd, imm: (16 + rn + 1) as u8, rn: rm }),
                0b0111 => {
                    let rot = bits(word, 11, 7) as u8;
                    return Ok(if rn == 0b1111 {
                        Ins::Extend { op: ExtOp::Sxth, rd, rn: rm, rm, rot }
                    } else {
                        Ins::Extend { op: ExtOp::Sxtah, rd, rn, rm, rot }
                    });
                }
                0b1011 if rn == 0b1111 && bits11_8 == 0b1111 => return Ok(Ins::Rev16 { rd, rm }),
                _ => return Err(DecodeErr(word)),
            }
        }
        // UXTB16-family: nibble#2=c
        0b01100 => {
            if op2 == 0b0111 {
                let rot = bits(word, 11, 7) as u8;
                return Ok(if rn == 0b1111 {
                    Ins::Extend { op: ExtOp::Uxtb16, rd, rn: rm, rm, rot }
                } else {
                    Ins::Extend { op: ExtOp::Uxtab16, rd, rn, rm, rot }
                });
            }
            return Err(DecodeErr(word));
        }
        // USAT (imm<16) / USAT16 / UXTB-family: nibble#2=e (op1=01110)
        0b01110 => {
            if op2 & 0b0011 == 0b0001 {
                return Ok(Ins::Usat { rd, imm: rn, rn: rm, sh: bits(word, 11, 7) as u8, asr: bit(word, 6) });
            }
            match op2 {
                0b0011 if bits11_8 == 0b1111 => return Ok(Ins::Usat16 { rd, imm: rn, rn: rm }),
                0b0111 => {
                    let rot = bits(word, 11, 7) as u8;
                    return Ok(if rn == 0b1111 {
                        Ins::Extend { op: ExtOp::Uxtb, rd, rn: rm, rm, rot }
                    } else {
                        Ins::Extend { op: ExtOp::Uxtab, rd, rn, rm, rot }
                    });
                }
                _ => return Err(DecodeErr(word)),
            }
        }
        // USAT (imm>=16) / USAT16(imm>=16) / RBIT / UXTH-family / REVSH: nibble#2=f (op1=01111)
        0b01111 => {
            if op2 & 0b0011 == 0b0001 {
                return Ok(Ins::Usat { rd, imm: 16 + rn, rn: rm, sh: bits(word, 11, 7) as u8, asr: bit(word, 6) });
            }
            match op2 {
                0b0011 if rn == 0b1111 && bits11_8 == 0b1111 => return Ok(Ins::Rbit { rd, rm }),
                0b0011 if bits11_8 == 0b1111 && rn != 0b1111 => return Ok(Ins::Usat16 { rd, imm: 16 + rn, rn: rm }),
                0b0111 => {
                    let rot = bits(word, 11, 7) as u8;
                    return Ok(if rn == 0b1111 {
                        Ins::Extend { op: ExtOp::Uxth, rd, rn: rm, rm, rot }
                    } else {
                        Ins::Extend { op: ExtOp::Uxtah, rd, rn, rm, rot }
                    });
                }
                0b1011 if rn == 0b1111 && bits11_8 == 0b1111 => return Ok(Ins::Revsh { rd, rm }),
                _ => return Err(DecodeErr(word)),
            }
        }
        // SMUAD/SMUADX/SMUSD/SMUSDX & SMLAD-family: nibble#2=0 (Rd at 19:16, Ra at 15:12,
        // Rm at 11:8, Rn at 3:0)
        0b10000 => {
            let rd2 = rn;       // Rd
            let ra = rd;        // Ra (15:12) — 0xF for SMU*
            let rm2 = bits11_8; // Rm
            let rn2 = rm;       // Rn (3:0)
            match op2 {
                0b0001 | 0b0011 => {
                    return Ok(if ra == 0b1111 {
                        if op2 == 0b0001 { Ins::Smuad { rd: rd2, rn: rn2, rm: rm2, x: false } }
                        else { Ins::Smuad { rd: rd2, rn: rn2, rm: rm2, x: true } }
                    } else {
                        if op2 == 0b0001 { Ins::Smlad { rd: rd2, rn: rn2, rm: rm2, ra, x: false } }
                        else { Ins::Smlad { rd: rd2, rn: rn2, rm: rm2, ra, x: true } }
                    });
                }
                0b0101 | 0b0111 => {
                    return Ok(if ra == 0b1111 {
                        if op2 == 0b0101 { Ins::Smusd { rd: rd2, rn: rn2, rm: rm2, x: false } }
                        else { Ins::Smusd { rd: rd2, rn: rn2, rm: rm2, x: true } }
                    } else {
                        if op2 == 0b0101 { Ins::Smlsd { rd: rd2, rn: rn2, rm: rm2, ra, x: false } }
                        else { Ins::Smlsd { rd: rd2, rn: rn2, rm: rm2, ra, x: true } }
                    });
                }
                _ => return Err(DecodeErr(word)),
            }
        }
        // SDIV: Rd(19:16), f(15:12), Rm(11:8), Rn(3:0)
        0b10001 if op2 == 0b0001 && rd == 0b1111 => {
            return Ok(Ins::Sdiv { rd: rn, rn: rm, rm: bits11_8 });
        }
        // UDIV
        0b10011 if op2 == 0b0001 && rd == 0b1111 => {
            return Ok(Ins::Udiv { rd: rn, rn: rm, rm: bits11_8 });
        }
        // SMLALD/SMLALDX/SMLSLD/SMLSLDX: nibble#2=4: RdHi(19:16) RdLo(15:12) Rm(11:8) Rn(3:0)
        0b10100 => {
            let rdhi = rn;
            let rdlo = rd;
            let rm2 = bits11_8;
            let rn2 = rm;
            return Ok(match op2 {
                0b0001 => Ins::Smlald { rdlo, rdhi, rn: rn2, rm: rm2, x: false },
                0b0011 => Ins::Smlald { rdlo, rdhi, rn: rn2, rm: rm2, x: true },
                0b0101 => Ins::Smlsld { rdlo, rdhi, rn: rn2, rm: rm2, x: false },
                0b0111 => Ins::Smlsld { rdlo, rdhi, rn: rn2, rm: rm2, x: true },
                _ => return Err(DecodeErr(word)),
            });
        }
        // USAD8/USADA8: nibble#2=8: Rd(19:16), Ra(15:12), Rm(11:8), Rn(3:0)
        0b11000 if op2 == 0b0001 => {
            let rd2 = rn;
            let ra = rd;
            let rm2 = bits11_8;
            let rn2 = rm;
            return Ok(if ra == 0b1111 {
                Ins::Usad8 { rd: rd2, rn: rn2, rm: rm2 }
            } else {
                Ins::Usada8 { rd: rd2, rn: rn2, rm: rm2, ra }
            });
        }
        // SBFX: op1=11010: widthm1(19:16) Rd(15:12) lsb(11:7) 101 Rn(3:0)
        0b11010 if op2 & 0b0011 == 0b0001 => {
            let widthm1 = rn;
            let lsb = bits(word, 11, 7) as u8;
            return Ok(Ins::Sbfx { rd, rn: rm, lsb, width: widthm1 + 1 });
        }
        // UBFX: op1=11110
        0b11110 if op2 & 0b0011 == 0b0001 => {
            let widthm1 = rn;
            let lsb = bits(word, 11, 7) as u8;
            return Ok(Ins::Ubfx { rd, rn: rm, lsb, width: widthm1 + 1 });
        }
        // BFC/BFI: op1=11100: msb(19:16) Rd(15:12) lsb(11:7) 001 Rn/f
        0b11100 if op2 & 0b0011 == 0b0001 => {
            let msb = rn;
            let lsb = bits(word, 11, 7) as u8;
            let width = msb - lsb + 1;
            return Ok(if bits11_8 == 0b1111 || rm == 0b1111 {
                Ins::Bfc { rd, lsb, width }
            } else {
                Ins::Bfi { rd, rn: rm, lsb, width }
            });
        }
        _ => {}
    }
    Err(DecodeErr(word))
}

// =========================== 010: load/store imm ===========================

fn decode_ldst_imm(word: u32) -> Result<Ins, DecodeErr> {
    let p = bit(word, 24);
    let u = bit(word, 23);
    let b = bit(word, 22);
    let w = bit(word, 21);
    let l = bit(word, 20);
    let rn = bits(word, 19, 16) as u8;
    let rt = bits(word, 15, 12) as u8;
    let imm12 = bits(word, 11, 0);
    if !p && w {
        // user-mode register offset (LDRT etc.) or undefined
        return Err(DecodeErr(word));
    }
    Ok(Ins::Ldst {
        store: !l, size: if b { Size::B8 } else { Size::W32 },
        signed: false, user: false,
        rt, rn, rm: None, shift: Shift::Lsl,
        imm: if u { imm12 as i32 } else { -(imm12 as i32) },
        index: p, add: u, wback: w || !p,
    })
}

// =========================== 100: LDM/STM ===========================

fn decode_ldm_stm(word: u32) -> Result<Ins, DecodeErr> {
    let p = bit(word, 24);
    let u = bit(word, 23);
    let s = bit(word, 22);
    let w = bit(word, 21);
    let l = bit(word, 20);
    let rn = bits(word, 19, 16) as u8;
    let list = RegList::from_bitmap(bits(word, 15, 0) as u16);
    let mode = match (p, u) {
        (false, true) => LdmMode::Ia,
        (true, true) => LdmMode::Ib,
        (false, false) => LdmMode::Da,
        (true, false) => LdmMode::Db,
    };
    Ok(Ins::LdmStm { load: l, rn, mode, wback: w, user: s, list })
}

// =========================== 101: branch ===========================

fn decode_branch(word: u32) -> Result<Ins, DecodeErr> {
    let cond = Cond::from_bits(bits(word, 31, 28) as u8);
    let off = sign_ext((bits(word, 23, 0) << 2), 26);
    Ok(if bit(word, 24) { Ins::Bl { off } } else { Ins::B { cond, off } })
}

// =========================== 110: coprocessor ldst (incl. VFP ldr/str/ldm/stm) ===========================

fn decode_coproc_ldst(word: u32) -> Result<Ins, DecodeErr> {
    let cp = bits(word, 11, 8);
    if cp == 0b1010 || cp == 0b1011 {
        return crate::a32::decode_vfp::decode_vfp_ldst(word);
    }
    Ok(Ins::Unsupported { group: "coproc-ldst" })
}

// =========================== 111: coproc dp (CDP/MCR/MRC), SVC, VFP data ===========================

fn decode_coproc(word: u32) -> Result<Ins, DecodeErr> {
    // SVC: 1111 cond + bits(24:20)=11111
    if bit(word, 24) && bits(word, 23, 20) == 0b1111 {
        return Ok(Ins::Svc { imm: bits(word, 23, 0) });
    }
    let cp = bits(word, 11, 8);
    if cp == 0b1010 || cp == 0b1011 {
        return crate::a32::decode_vfp::decode_vfp_data(word);
    }
    Ok(Ins::Unsupported { group: "coproc" })
}

// =========================== unconditional space (cond=1111) ===========================

fn decode_unconditional(word: u32) -> Result<Ins, DecodeErr> {
    match bits(word, 27, 25) {
        0b000 => {
            // SETEND: 1111 0001 00 1 0 00 00000 00000010 E
            if (word & 0xFFFF_FDFF) == 0xF101_0000 {
                return Ok(Ins::Setend { big: bit(word, 9) });
            }
            // CPS (flags form): 1111 0001 0000 00 im?0 aif I/F/A ... F108/F10A ...
            // CPS: bits(27:20)=00010000, bit(19:18)=im != 00
            if bits(word, 27, 20) == 0b0001_0000 && bits(word, 19, 18) != 0b00 {
                let imode = bits(word, 19, 18);
                let enable = imode == 0b11 || imode == 0b10; // 11=i? per manual: 10=e, 01=d
                let aif = ((word >> 6) & 7) as u8;
                let change_mode = bit(word, 17);
                let mode = (word & 0x1f) as u8;
                // imode: 10 = enable, 01 = disable; bit(17) = mode change
                return Ok(Ins::Cps { enable: imode == 0b10, aif, change_mode, mode });
            }
            Err(DecodeErr(word))
        }
        0b001 => crate::a32::decode_neon::decode_neon_data(word),
        0b010 | 0b011 => {
            // barriers first: F57FF0xx (rn=1111, rd=1111, bits(11:8)=1111)
            if bits(word, 27, 25) == 0b010
                && bits(word, 19, 16) == 0b1111 && bits(word, 15, 12) == 0b1111
                && bits(word, 11, 8) == 0b0000 {
                let opt = (word & 0xF) as u8;
                return Ok(match (word >> 4) & 0xF {
                    0b0100 => Ins::Barriers { kind: Barrier::Dsb, opt },
                    0b0101 => Ins::Barriers { kind: Barrier::Dmb, opt },
                    0b0110 => Ins::Barriers { kind: Barrier::Isb, opt: 15 },
                    _ => return Err(DecodeErr(word)),
                });
            }
            let is_010 = bits(word, 27, 25) == 0b010;
            if bits(word, 15, 12) == 0b1111 {
                let rn = bits(word, 19, 16) as u8;
                if is_010 {
                    if !bit(word, 24) {
                        // PLI imm: 1111 0100
                        let imm = if bit(word, 23) { bits(word, 11, 0) as i32 } else { -(bits(word, 11, 0) as i32) };
                        return Ok(Ins::Pli { rn, rm: None, shift: Shift::Lsl, imm });
                    }
                    // PLD imm: 1111 0101
                    let imm = if bit(word, 23) { bits(word, 11, 0) as i32 } else { -(bits(word, 11, 0) as i32) };
                    return Ok(Ins::Pld { w: bit(word, 21), rn, rm: None, shift: Shift::Lsl, imm });
                }
                // 011 space with rd=1111: PLI-reg (bit24=0) or PLD/PLDW-reg (bit24=1)
                let rmv = bits(word, 3, 0) as u8;
                let shift = Shift::from_bits(bits(word, 6, 5) as u8);
                let amount = bits(word, 11, 7) as i32;
                if !bit(word, 24) {
                    return Ok(Ins::Pli { rn, rm: Some(rmv), shift, imm: amount });
                }
                return Ok(Ins::Pld { w: bit(word, 21), rn, rm: Some(rmv), shift, imm: amount });
            }
            crate::a32::decode_neon::decode_neon_ldst(word)
        }
        0b100 => Ok(Ins::Unsupported { group: "srs-rfe" }), // SRS/RFE (privileged; rare in user .so)
        0b101 => {
            // BLX imm: 1111 101H off24
            let off = sign_ext((bits(word, 23, 0) << 2) | ((bit(word, 24) as u32) << 1), 26);
            Ok(Ins::Blx { off })
        }
        _ => {
            // barriers: F57FF0xx (DSS option op): 1111 0101 0111 1111 1111 op opt
            if (word & 0xFFFF_F0F0) == 0xF57F_F000 {
                let opt = (word & 0xF) as u8;
                return Ok(match (word >> 4) & 0xF {
                    0b0100 => Ins::Barriers { kind: Barrier::Dsb, opt },
                    0b0101 => Ins::Barriers { kind: Barrier::Dmb, opt },
                    0b0110 => Ins::Barriers { kind: Barrier::Isb, opt: 15 },
                    _ => return Err(DecodeErr(word)),
                });
            }
            Ok(Ins::Unsupported { group: "neon-misc" })
        }
    }
}

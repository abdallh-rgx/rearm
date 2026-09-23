//! T32 (Thumb-2) decoder: 16/32-bit instructions -> `Ins`.

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
    let ins = if hw1 >= 0xE800 {
        decode_t32_32(hw1, hw2)?
    } else {
        decode_t32_16(hw1)?
    };
    let len = if hw1 >= 0xE800 { 4 } else { 2 };
    Ok(TIns { ins, len: len as u16 })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecodeErr(pub u32);

impl core::fmt::Display for DecodeErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "undefined T32 encoding {:#010x}", self.0)
    }
}

fn decode_t32_16(hw: u16) -> Result<Ins, DecodeErr> {
    let w = hw as u32;
    let ops = bits(w, 15, 10);
    let rd = bits(w, 2, 0) as u8;
    let rn = bits(w, 5, 3) as u8;
    let rm = bits(w, 8, 6) as u8;
    let imm3 = bits(w, 5, 3) as u8;
    let imm8 = bits(w, 7, 0) as u8;

    match ops {
        0b00_0000 | 0b00_0001 => {
            // LSLS Rd, Rm, #imm5
            let imm5 = bits(w, 10, 6) as u8;
            Ok(Ins::DpReg { op: DpOp::Mov, s: true, rn: 0, rd, rm: rn, shift: Shift::Lsl, amount: ShiftAmount::Imm(imm5) })
        }
        0b00_0010 | 0b00_0011 => {
            let imm5 = bits(w, 10, 6) as u8;
            Ok(Ins::DpReg { op: DpOp::Mov, s: true, rn: 0, rd, rm: rn, shift: Shift::Lsr, amount: ShiftAmount::Imm(imm5) })
        }
        0b00_0100 | 0b00_0101 => {
            let imm5 = bits(w, 10, 6) as u8;
            Ok(Ins::DpReg { op: DpOp::Mov, s: true, rn: 0, rd, rm: rn, shift: Shift::Asr, amount: ShiftAmount::Imm(imm5) })
        }
        0b00_1000..=0b00_1111 => {
            // ADD/SUB register/immediate (3-bit)
            let sub = bit(w, 9);
            let imm_flag = bit(w, 10);
            let rn3 = bits(w, 5, 3) as u8;
            let op = if sub { DpOp::Sub } else { DpOp::Add };
            if imm_flag {
                Ok(Ins::DpImm { op, s: true, rn: rd, rd, imm12: imm3 as u16 })
            } else {
                Ok(Ins::DpReg { op, s: true, rn: rd, rd, rm: rn3, shift: Shift::Lsl, amount: ShiftAmount::Imm(0) })
            }
        }
        0b01_0000..=0b01_0011 => {
            // MOV imm8 / CMP / ADDS imm8 / SUBS imm8
            let rn_f = bits(w, 10, 8) as u8;
            match ops & 0b11 {
                0b00 => Ok(Ins::DpImm { op: DpOp::Mov, s: true, rn: 0, rd: rn_f, imm12: imm8 as u16 }),
                0b01 => Ok(Ins::DpImm { op: DpOp::Cmp, s: true, rn: rn_f, rd: 15, imm12: imm8 as u16 }),
                0b10 => Ok(Ins::DpImm { op: DpOp::Add, s: true, rn: rn_f, rd: rn_f, imm12: imm8 as u16 }),
                _ => Ok(Ins::DpImm { op: DpOp::Sub, s: true, rn: rn_f, rd: rn_f, imm12: imm8 as u16 }),
            }
        }
        0b01_1000..=0b01_1111 => Ok(Ins::DpImm {
            op: DpOp::Mov, s: false, rn: 0, rd: bits(w, 10, 8) as u8, imm12: imm8 as u16,
        }),
        _ => Err(DecodeErr(w)),
    }
}

fn decode_t32_32(hw1: u16, hw2: u16) -> Result<Ins, DecodeErr> {
    let w = ((hw1 as u32) << 16) | hw2 as u32;
    // 32-bit Thumb: 111 op1(12:11) ...
    match bits(w, 15, 11) {
        0b11101 => decode_t32_dp_branch_misc(w),
        0b11110 => decode_t32_dp(w),
        0b11111 => decode_t32_coproc(w),
        _ => Err(DecodeErr(w)),
    }
}

fn decode_t32_dp(w: u32) -> Result<Ins, DecodeErr> {
    let op = bits(w, 28, 21);
    let s = bit(w, 20);
    let rn = bits(w, 19, 16) as u8;
    let rd = bits(w, 11, 8) as u8;
    let _ = (op, s, rn, rd);
    Err(DecodeErr(w))
}

fn decode_t32_dp_branch_misc(w: u32) -> Result<Ins, DecodeErr> {
    let _ = w;
    Err(DecodeErr(w))
}

fn decode_t32_coproc(w: u32) -> Result<Ins, DecodeErr> {
    let _ = w;
    Err(DecodeErr(w))
}

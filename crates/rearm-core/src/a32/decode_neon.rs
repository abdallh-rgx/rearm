//! NEON (Advanced SIMD) decoders for A32 (unconditional space).

use crate::a32::ins::*;
use crate::a32::decode::DecodeErr;

pub fn decode_neon_data(word: u32) -> Result<Ins, DecodeErr> {
    let _ = word;
    Ok(Ins::Unsupported { group: "neon-data" })
}

pub fn decode_neon_ldst(word: u32) -> Result<Ins, DecodeErr> {
    let _ = word;
    Ok(Ins::Unsupported { group: "neon-ldst" })
}

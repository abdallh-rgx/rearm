//! Common types shared by A32/T32/A64 layers of `rearm`.

/// ARM general-purpose register (A32/T32 view): r0..r15 with aliased names.
/// r13 = SP, r14 = LR, r15 = PC.
pub type R = u8;

pub const SP: R = 13;
pub const LR: R = 14;
pub const PC: R = 15;

/// AArch64 general purpose register index 0..=30, 31 = SP/ZR depending on context.
pub type XR = u8;

/// A64 register file size (x0..x30)
pub const A64_GPR_COUNT: u8 = 31;

/// Condition codes shared by A32/T32 and A64 (identical encodings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Cond {
    Eq, Ne, Cs, Cc,
    Mi, Pl, Vs, Vc,
    Hi, Ls, Ge, Lt,
    Gt, Le, Al, Nv,
}

impl Cond {
    #[inline]
    pub const fn from_bits(v: u8) -> Cond {
        match v & 0xF {
            0 => Cond::Eq, 1 => Cond::Ne, 2 => Cond::Cs, 3 => Cond::Cc,
            4 => Cond::Mi, 5 => Cond::Pl, 6 => Cond::Vs, 7 => Cond::Vc,
            8 => Cond::Hi, 9 => Cond::Ls, 10 => Cond::Ge, 11 => Cond::Lt,
            12 => Cond::Gt, 13 => Cond::Le, 14 => Cond::Al, _ => Cond::Nv,
        }
    }
    #[inline]
    pub const fn bits(self) -> u8 { self as u8 }
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Cond::Eq => "eq", Cond::Ne => "ne", Cond::Cs => "cs", Cond::Cc => "cc",
            Cond::Mi => "mi", Cond::Pl => "pl", Cond::Vs => "vs", Cond::Vc => "vc",
            Cond::Hi => "hi", Cond::Ls => "ls", Cond::Ge => "ge", Cond::Lt => "lt",
            Cond::Gt => "gt", Cond::Le => "le", Cond::Al => "", Cond::Nv => "nv",
        }
    }
    /// Inverse condition (used by IT blocks, cbz-else, ...).
    #[inline]
    pub const fn invert(self) -> Cond {
        Cond::from_bits(self.bits() ^ 1)
    }
}

/// Shift/rotate kinds (shared A32/T32/A64 semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

impl Shift {
    #[inline]
    pub const fn from_bits(v: u8) -> Shift {
        match v & 3 {
            0 => Shift::Lsl, 1 => Shift::Lsr, 2 => Shift::Asr, _ => Shift::Ror,
        }
    }
    #[inline]
    pub const fn bits(self) -> u8 { self as u8 }
    pub const fn name(self) -> &'static str {
        match self { Shift::Lsl => "lsl", Shift::Lsr => "lsr", Shift::Asr => "asr", Shift::Ror => "ror" }
    }
}

/// A register-shifted operand: either a fixed amount or a register amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftAmount {
    Imm(u8),
    Reg(R),
}

/// Operand2-style flexible operand (immediate with rotation, or reg + shift).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlexOp {
    /// A32 immediate: value rotated right by `rot` * 2.
    RorImm { imm: u8, rot: u8 },
    Reg { rm: R, shift: Shift, amount: ShiftAmount },
}

/// Integer sizes for memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Size {
    B8,
    H16,
    W32,
    D64,
    Q128,
}

impl Size {
    pub const fn bytes(self) -> u32 {
        match self {
            Size::B8 => 1, Size::H16 => 2, Size::W32 => 4, Size::D64 => 8, Size::Q128 => 16,
        }
    }
    pub const fn bits(self) -> u32 { self.bytes() * 8 }
    pub const fn from_bytes(b: u32) -> Option<Size> {
        match b { 1 => Some(Size::B8), 2 => Some(Size::H16), 4 => Some(Size::W32), 8 => Some(Size::D64), 16 => Some(Size::Q128), _ => None }
    }
    pub const fn name(self) -> &'static str {
        match self { Size::B8 => "b", Size::H16 => "h", Size::W32 => "w", Size::D64 => "d", Size::Q128 => "q" }
    }
}

/// Vector/FP element types (NEON dt specifiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dt {
    I8, I16, I32, I64,
    U8, U16, U32, U64,
    S8, S16, S32, S64,
    F16, F32, F64,
    P8,
}

impl Dt {
    pub const fn bits(self) -> u8 {
        match self {
            Dt::I8 | Dt::U8 | Dt::S8 | Dt::P8 => 8,
            Dt::I16 | Dt::U16 | Dt::S16 | Dt::F16 => 16,
            Dt::I32 | Dt::U32 | Dt::S32 | Dt::F32 => 32,
            Dt::I64 | Dt::U64 | Dt::S64 | Dt::F64 => 64,
        }
    }
    pub const fn is_float(self) -> bool { matches!(self, Dt::F16 | Dt::F32 | Dt::F64) }
    pub const fn is_signed(self) -> bool {
        matches!(self, Dt::I8 | Dt::I16 | Dt::I32 | Dt::I64 | Dt::S8 | Dt::S16 | Dt::S32 | Dt::S64)
    }
    /// NEON dt letter code used in A32 encodings (U:I:size)
    pub const fn from_code(u: bool, size: u8, f: bool) -> Option<Dt> {
        Some(match (u, size & 3, f) {
            (false, 0, false) => Dt::S8, (false, 1, false) => Dt::S16, (false, 2, false) => Dt::S32, (false, 3, false) => Dt::S64,
            (true, 0, false) => Dt::U8, (true, 1, false) => Dt::U16, (true, 2, false) => Dt::U32, (true, 3, false) => Dt::U64,
            (false, 0, true) => Dt::F16, (false, 1, true) => Dt::F32, (false, 3, true) => Dt::F64,
            (true, 1, true) => Dt::F16, (true, 3, true) => Dt::F64,
            _ => return None,
        })
    }
    pub const fn name(self) -> &'static str {
        match self {
            Dt::I8 => "i8", Dt::I16 => "i16", Dt::I32 => "i32", Dt::I64 => "i64",
            Dt::U8 => "u8", Dt::U16 => "u16", Dt::U32 => "u32", Dt::U64 => "u64",
            Dt::S8 => "s8", Dt::S16 => "s16", Dt::S32 => "s32", Dt::S64 => "s64",
            Dt::F16 => "f16", Dt::F32 => "f32", Dt::F64 => "f64",
            Dt::P8 => "p8",
        }
    }
}

/// A32 VFP/NEON register indices.
pub type SReg = u8; // s0..s31
pub type DReg = u8; // d0..d31
pub type QReg = u8; // q0..q15

/// A64 FP/vector register (v0..v31) with an access width.
pub const A64_VREG_COUNT: u8 = 32;

#[inline]
pub const fn d_of_q(q: QReg, hi: bool) -> DReg { q * 2 + hi as u8 }
#[inline]
pub const fn s_of_d(d: DReg, hi: bool) -> SReg { d * 2 + hi as u8 }
#[inline]
pub const fn q_of_d(d: DReg) -> QReg { d / 2 }

/// Bit manipulation helpers.
#[inline]
pub const fn bits(v: u32, hi: u32, lo: u32) -> u32 {
    debug_assert!(hi >= lo);
    (v >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}
#[inline]
pub const fn bit(v: u32, n: u32) -> bool { (v >> n) & 1 != 0 }
#[inline]
pub const fn sign_ext(v: u32, bits: u32) -> i32 {
    if bits >= 32 { v as i32 } else if bit(v, bits - 1) { (v as i32) | (!0i32 << bits) } else { v as i32 & ((1i32 << bits) - 1) }
}
/// Sign-extend an n-bit value to i64.
#[inline]
pub const fn sext64(v: u64, bits: u32) -> i64 {
    if bits >= 64 || bits == 0 { return v as i64; }
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift)
}
/// Zero-extend an n-bit value.
#[inline]
pub const fn zext64(v: u64, bits: u32) -> u64 {
    if bits >= 64 { v } else { v & ((1u64 << bits) - 1) }
}

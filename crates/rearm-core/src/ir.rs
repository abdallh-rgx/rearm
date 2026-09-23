//! Intermediate representation (IR) used for **semantic lifting** of A32/T32/A64
//! instructions and for Z3-based equivalence verification.
//!
//! State model:
//! * `Loc::Gpr(i)` — general purpose registers (width depends on lifted ISA:
//!   32-bit for A32/T32, 64-bit for A64)
//! * `Loc::V(i)` — FP/NEON registers as full 128-bit slots v0..v31.
//!   A32 views: `dN` = `V(n)[63:0]`, `qN` = `V(2N+1):V(2N)` (pair mapping),
//!   `sN` = `V(n/2)[31:0]` of d-view.
//! * `Loc::Flag(f)` — N/Z/C/V flags
//! * `Loc::Q`, `Loc::Ge` — A32 sticky saturation and GE bits
//! * `Loc::FpCtl` — FP control (rounding mode, etc.)
//! * `Loc::Excl` — local exclusive monitor
//! * memory — byte-granular array over a shared 64-bit address space

use crate::common::Dt;

/// Architectural state location that IR can read/write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Loc {
    Gpr(u8),
    V(u8),
    Flag(Flag),
    Q,
    Ge,
    FpCtl,
    Excl,
}

/// Condition flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    N,
    Z,
    C,
    V,
}

/// Type-checked bit width for IR expressions.
pub type Width = u8;

/// A pure IR expression tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Constant, zero-extended into `bits` width.
    Const { bits: Width, val: u128 },
    /// Read of an architectural location at the current program point.
    Read(Loc),
    /// Wildcard / non-deterministic value (architecturally UNPREDICTABLE).
    Wild { bits: Width, tag: u16 },

    // ---- 1-bit results ----
    Eq(Box<Expr>, Box<Expr>),
    Ne(Box<Expr>, Box<Expr>),
    Ult(Box<Expr>, Box<Expr>),
    Ule(Box<Expr>, Box<Expr>),
    Slt(Box<Expr>, Box<Expr>),
    Sle(Box<Expr>, Box<Expr>),
    /// carry out of a + b + cin
    CarryOutAdd { bits: Width, a: Box<Expr>, b: Box<Expr>, cin: Box<Expr> },
    /// carry (NOT borrow) out of a - b - !cin == a + ~b + cin
    CarryOutSub { bits: Width, a: Box<Expr>, b: Box<Expr>, cin: Box<Expr> },
    /// signed overflow of a + b + cin
    OverAdd { bits: Width, a: Box<Expr>, b: Box<Expr>, cin: Box<Expr> },
    /// signed overflow of a - b - !cin
    OverSub { bits: Width, a: Box<Expr>, b: Box<Expr>, cin: Box<Expr> },

    // ---- bitwise (same-width operands) ----
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),

    // ---- arithmetic ----
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    UDiv(Box<Expr>, Box<Expr>),
    SDiv(Box<Expr>, Box<Expr>),
    URem(Box<Expr>, Box<Expr>),
    SRem(Box<Expr>, Box<Expr>),

    // ---- shifts (rhs is an 8-bit amount) ----
    Shl(Box<Expr>, Box<Expr>),
    Lshr(Box<Expr>, Box<Expr>),
    Ashr(Box<Expr>, Box<Expr>),
    /// rotate left (A32 setend-ish / A64 rol)
    Rol(Box<Expr>, Box<Expr>),
    /// rotate right
    Ror(Box<Expr>, Box<Expr>),
    /// RRX: value = (C:operand) >> 1 — modeled by lifters via Concat, kept for clarity

    // ---- width manipulation ----
    ZExt { to: Width, v: Box<Expr> },
    SExt { to: Width, v: Box<Expr> },
    Trunc { to: Width, v: Box<Expr> },
    Extract { hi: Width, lo: Width, v: Box<Expr> },
    Concat { hi: Box<Expr>, lo: Box<Expr> },

    // ---- selects ----
    /// select on a 1-bit cond; `bits` sets result width
    Ite { bits: Width, c: Box<Expr>, t: Box<Expr>, f: Box<Expr> },
    /// 1-bit to 1-bit select
    Ite1 { c: Box<Expr>, t: Box<Expr>, f: Box<Expr> },

    // ---- memory ----
    /// little-endian load of `bits` width (8/16/32/64/128)
    Load { bits: Width, addr: Box<Expr> },

    // ---- misc integer ----
    Clz { bits: Width, a: Box<Expr> },
    Cls { bits: Width, a: Box<Expr> },
    Rbit { a: Box<Expr> },
    Rev16 { a: Box<Expr> },
    /// reverse 32-bit endianness of each 32-bit word in a
    Rev32 { a: Box<Expr> },
    /// saturate `a` (of some width) into `to`-bit signed/unsigned result
    Sat { to: Width, signed: bool, a: Box<Expr> },
    /// 1-bit: did saturation occur
    SatHappened { to: Width, signed: bool, a: Box<Expr> },
    /// round-half-up shift used for VCVT fix (RNE-encoded directly in lifters)
    RoundShiftRne { shift: Width, a: Box<Expr> },

    // ---- floating point (IEEE-754 semantics) ----
    FAdd { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FSub { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FMul { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FDiv { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FSqrt { bits: Width, a: Box<Expr> },
    FAbs { bits: Width, a: Box<Expr> },
    FNeg { bits: Width, a: Box<Expr> },
    FMax { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FMin { bits: Width, a: Box<Expr>, b: Box<Expr> },
    /// A32 VMAXNM/VMINNM semantics (NaN → other operand)
    FMaxNum { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FMinNum { bits: Width, a: Box<Expr>, b: Box<Expr> },
    /// FMulX: multiply, but inf * 0 = 0 (NEON)
    FMulX { bits: Width, a: Box<Expr>, b: Box<Expr> },
    /// reciprocal estimate / step / rsqrt estimate / step
    FRecpe { bits: Width, a: Box<Expr> },
    FRsqrte { bits: Width, a: Box<Expr> },
    FRecps { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FRsqrts { bits: Width, a: Box<Expr>, b: Box<Expr> },
    /// FP compare results (1-bit each)
    FCmpLT { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FCmpGT { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FCmpEQ { bits: Width, a: Box<Expr>, b: Box<Expr> },
    FCmpUn { bits: Width, a: Box<Expr>, b: Box<Expr> },
    /// conversions; `round` is a 2-bit rounding-mode expression (0=RN,1=RZ,2=RP,3=RM)
    FpToSInt { from: Width, to: Width, round: Box<Expr>, a: Box<Expr> },
    FpToUInt { from: Width, to: Width, round: Box<Expr>, a: Box<Expr> },
    SIntToFp { from: Width, to: Width, a: Box<Expr> },
    UIntToFp { from: Width, to: Width, a: Box<Expr> },
    FpConv { from: Width, to: Width, round: Box<Expr>, a: Box<Expr> },

    // ---- vector (NEON) element-wise ops on 64/128-bit packed values ----
    VecBin { op: VecBinOp, dt: Dt, q: bool, a: Box<Expr>, b: Box<Expr> },
    VecUn { op: VecUnOp, dt: Dt, q: bool, a: Box<Expr> },
    VecCmp { op: VecCmpOp, dt: Dt, q: bool, a: Box<Expr>, b: Box<Expr> },
    /// horizontal reductions (vpadd/vpaddl/vpadal/vmax horizontal)
    VecAcross { op: VecAcrossOp, dt: Dt, q: bool, a: Box<Expr>, b: Box<Expr> },
    /// duplicate element `index` of `a` into all lanes
    Dup { dt: Dt, q: bool, a: Box<Expr>, index: u8 },
    /// insert `v` into lane `index` of `a`
    InsLane { dt: Dt, q: bool, a: Box<Expr>, v: Box<Expr>, index: u8 },
    /// read element `index`
    ExtractLane { dt: Dt, a: Box<Expr>, index: u8 },
    /// interleave/de-interleave (vzip/vuzp/vtrn T2 2-reg forms)
    Interleave { op: InterOp, dt: Dt, a: Box<Expr>, b: Box<Expr>, q: bool },
    /// table lookup (vtbl/vtbx) over `len` consecutive d regs
    Tbl { a: Box<Expr>, indices: Box<Expr>, len: u8, is_tbx: bool },
    /// polynomial multiply (vmulp)
    PolyMul { dt: Dt, a: Box<Expr>, b: Box<Expr>, q: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecBinOp {
    Add, Sub, Mul,
    And, Or, Xor, Bic, Orn,
    Max, Min, MaxNum, MinNum,
    AbsDiff,
    QAdd, QSub,          // saturating (NEON: no Q flag)
    QDMulH, QRDMulH,     // doubling saturating multiply high
    MulLong, MulLong2,   // widening multiply from low/high halves (vmull)
    AddLong, SubLong,    // widening add/sub from low/high halves (vaddl)
    AddWide, SubWide,    // vaddw
    Shl, ShrS, ShrU, RshrS, RshrU, // shifts by per-lane amounts (b)
    SqShl, SqRshl, UqShl, UqRshl,  // saturating shifts
    RecpStep, RsqrtStep, // vrecps/vrsqrts
    FAdd, FSub, FMul, FDiv, FMax, FMin, FMaxNum, FMinNum, FMulX, FAbsDiff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecUnOp {
    Abs, Neg, Not, Clz, Cls, Cnt,
    FRecpe, FRsqrte, FAbs, FNeg,
    CntP, // vcnt on p8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecCmpOp { Eq, Ge, Gt, Hi, Hs }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecAcrossOp {
    AddP,   // pairwise add
    AddL,   // pairwise long add (vpaddl)
    AddAL,  // pairwise accumulate long (vpadal)
    MaxAcross, MinAcross, AddAcross,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterOp { Zip1, Zip2, Uzp1, Uzp2, Trn1, Trn2 }

/// A side-effecting IR statement.
#[derive(Debug, Clone, PartialEq)]
pub enum IrStmt {
    /// write a state location
    Write(Loc, Expr),
    /// store `val` (`bits` wide) to memory at `addr`
    StoreMem { addr: Expr, bits: Width, val: Expr },
    /// exclusive load: writes `loc`, sets monitor
    LoadExcl { addr: Expr, bits: Width, loc: Loc },
    /// exclusive store: returns success (0 ok) into `loc`
    StoreExcl { addr: Expr, bits: Width, val: Expr, loc: Loc },
    /// control flow inside a translated region
    Label(u32),
    Branch { cond: Option<Expr>, target: u32 },
    /// terminator: computed branch out of the region (`target` = A32 address expr)
    IndirectExit { target: Expr },
    /// no-op / hint (yield, nop, dmb...)
    Hint,
}

/// A lifted block: statements plus metadata.
#[derive(Debug, Clone, Default)]
pub struct IrBlock {
    pub stmts: Vec<IrStmt>,
    /// bits set for flags that the source architecture marks UNPREDICTABLE
    /// after some point — verification may ignore them.
    pub unpredicted_flags: u8,
}

impl IrBlock {
    pub fn new() -> Self { Self { stmts: Vec::new(), unpredicted_flags: 0 } }
    pub fn push(&mut self, s: IrStmt) { self.stmts.push(s); }
    pub fn write(&mut self, l: Loc, e: Expr) { self.stmts.push(IrStmt::Write(l, e)); }
}

// ---------- builder helpers ----------

impl Expr {
    pub fn c32(v: u32) -> Expr { Expr::Const { bits: 32, val: v as u128 } }
    pub fn c64(v: u64) -> Expr { Expr::Const { bits: 64, val: v as u128 } }
    pub fn c8(v: u8) -> Expr { Expr::Const { bits: 8, val: v as u128 } }
    pub fn c1(v: bool) -> Expr { Expr::Const { bits: 1, val: v as u128 } }
    pub fn r(l: Loc) -> Expr { Expr::Read(l) }
    #[inline]
    pub fn b(e: Expr) -> Box<Expr> { Box::new(e) }
}

pub fn loc_gpr(i: u8) -> Loc { Loc::Gpr(i) }
pub fn loc_flag(f: Flag) -> Loc { Loc::Flag(f) }
pub fn loc_v(i: u8) -> Loc { Loc::V(i) }

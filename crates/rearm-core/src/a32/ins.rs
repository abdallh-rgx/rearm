//! Semantic instruction model for A32 (ARM state) and T32 (Thumb-2).
//! One enum covers both encodings; decoders map bits -> `Ins`.

use crate::common::{Cond, Dt, R, Shift, ShiftAmount, Size};

/// Data-processing opcode shared between forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpOp {
    And, Eor, Sub, Rsb, Add, Adc, Sbc, Rsc,
    Tst, Teq, Cmp, Cmn,
    Orr, Mov, Bic, Mvn,
}

impl DpOp {
    pub const fn name(self) -> &'static str {
        use DpOp::*;
        match self {
            And => "and", Eor => "eor", Sub => "sub", Rsb => "rsb",
            Add => "add", Adc => "adc", Sbc => "sbc", Rsc => "rsc",
            Tst => "tst", Teq => "teq", Cmp => "cmp", Cmn => "cmn",
            Orr => "orr", Mov => "mov", Bic => "bic", Mvn => "mvn",
        }
    }
    pub const fn is_test(self) -> bool {
        use DpOp::*;
        matches!(self, Tst | Teq | Cmp | Cmn)
    }
    pub const fn uses_rn(self) -> bool {
        use DpOp::*;
        !matches!(self, Mov | Mvn)
    }
}

/// Parallel (DSP) add/sub families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParKind { S, Q, Sh, U, Uq, Uh }
impl ParKind {
    pub const fn name(self) -> &'static str {
        match self {
            ParKind::S => "", ParKind::Q => "q", ParKind::Sh => "sh",
            ParKind::U => "u", ParKind::Uq => "uq", ParKind::Uh => "uh",
        }
    }
}

/// Parallel add/sub shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParShape { Add16, Addsubx, Subaddx, Sub16, Add8, Sub8 }
impl ParShape {
    pub const fn name(self) -> &'static str {
        use ParShape::*;
        match self {
            Add16 => "add16", Addsubx => "addsubx", Subaddx => "subaddx",
            Sub16 => "sub16", Add8 => "add8", Sub8 => "sub8",
        }
    }
}

/// Half-selector for SMULxy etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Half { B, T }
impl Half {
    pub const fn name(self) -> &'static str { if let Half::B = self { "b" } else { "t" } }
    pub const fn bit(self) -> bool { matches!(self, Half::T) }
}

/// Extension ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtOp {
    Sxtb, Sxth, Sxtb16, Uxtb, Uxth, Uxtb16,
    Sxtab, Sxtah, Sxtab16, Uxtab, Uxtah, Uxtab16,
}
impl ExtOp {
    pub const fn name(self) -> &'static str {
        use ExtOp::*;
        match self {
            Sxtb => "sxtb", Sxth => "sxth", Sxtb16 => "sxtb16",
            Uxtb => "uxtb", Uxth => "uxth", Uxtb16 => "uxtb16",
            Sxtab => "sxtab", Sxtah => "sxtah", Sxtab16 => "sxtab16",
            Uxtab => "uxtab", Uxtah => "uxtah", Uxtab16 => "uxtab16",
        }
    }
    pub const fn is_add_form(self) -> bool {
        use ExtOp::*;
        matches!(self, Sxtab | Sxtah | Sxtab16 | Uxtab | Uxtah | Uxtab16)
    }
}

/// LDM/STM addressing variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdmMode { Ia, Ib, Da, Db }
impl LdmMode {
    pub const fn name(self) -> &'static str {
        match self {
            LdmMode::Ia => "ia", LdmMode::Ib => "ib", LdmMode::Da => "da", LdmMode::Db => "db",
        }
    }
    /// (pre_index, increment)
    pub const fn pu(self) -> (bool, bool) {
        match self {
            LdmMode::Ia => (false, true),
            LdmMode::Ib => (true, true),
            LdmMode::Da => (false, false),
            LdmMode::Db => (true, false),
        }
    }
}

/// Register list for LDM/STM/PUSH/POP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegList(pub Vec<R>);

impl RegList {
    pub fn bitmap(&self) -> u16 {
        let mut m = 0u16;
        for &r in &self.0 { m |= 1 << r; }
        m
    }
    pub fn from_bitmap(m: u16) -> RegList {
        let mut v = Vec::new();
        for i in 0..16u8 { if m & (1 << i) != 0 { v.push(i); } }
        RegList(v)
    }
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
    pub fn contains(&self, r: R) -> bool { self.0.contains(&r) }
}

/// VFP/NEON register operand as raw index; interpretation (s/d/q) is per instruction.
pub type VIdx = u8;

/// FP scalar ops (VFP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfpBinOp { Add, Sub, Mul, NMul, Div }

/// VFP multiply-accumulate forms: d = ±d ±(n*m).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VfpMulAcc { pub neg_d: bool, pub neg_p: bool }

/// FP unary ops (VFP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfpUnOp { Abs, Neg, Sqrt, Mov }

/// VFP system registers reachable via VMRS/VMSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfpSys { Fpscr, Fpexc, Fpsid, Mvfr0, Mvfr1 }

/// VFP conversion forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcvtForm {
    /// s32 <- f32 or f64 (src width 32/64)
    ToS32 { src: u8 },
    ToU32 { src: u8 },
    FromS32 { dst: u8 },
    FromU32 { dst: u8 },
    F32F64, // f32 <- f64
    F64F32, // f64 <- f32
    F16F32, // f32 <- f16 (scalar VFPv4 / NEON)
    F32F16, // f16 <- f32
}

/// NEON immediate kinds (cmode-decoded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonImmKind { I8, I16, I32, I64, F32, F64, F32N }

/// NEON operation classes covered by the generic vector form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonOp {
    And, Bic, Orr, Orn, Eor, Bsl, Bit, Bif,
    Add, Sub, Mul, MulP,
    AddL, SubL, AddW, SubW, AddHn, SubHn, RAddHn, RSubHn,
    QAdd, QSub,
    MulL, QdmulL, QdmulH, Qrdmulh,
    Mla, Mls, MlaL, MlsL, Qdmlal, Qdmlsl,
    Fma, Fms, Fnma, Fnms,
    Abs, Neg, AbsDiff,
    Max, Min, MaxNm, MinNm,
    CmpEq, CmpGe, CmpGt, Tst,
    MaxP, MinP, AddP, AddLp, AddALp, MaxAcross, MinAcross,
    ShlReg, ShlImm, ShrImm, SraImm, RshrImm, RsraImm, SliImm, SriImm,
    Shll, Shrn, Rshrn, QshlReg, QshluReg, QrshlReg,
    QshlImm, QshluImm, QrshlImm,
    Qshrn, Qrshrn, Qshrun, Qrshrun,
    Recpe, Rsqrte, Recps, Rsqrts,
    MovN, QmovN, QmovUn, MovL,
    Ext, Zip, Unzip, Trn,
    Cnt, Clz, Cls, Not,
    FToFix, FixToF, FCvtF16F32, FCvtF32F16, FRint,
}

/// NEON load/store multi-element kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonVldKind { Vld1, Vld2, Vld3, Vld4 }

/// Hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint { Nop, Yield, Wfe, Wfi, Sev, Sevl, Dbg }

/// Memory barriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Barrier { Dmb, Dsb, Isb }

/// VSEL conditions (v8 A32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VselOp { Ge, Gt, Eq, Vs }

/// VRINT modes (v8 A32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrintOp { RintN, RintP, RintM, RintZ, RintA }

/// The A32/T32 semantic instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum Ins {
    // ======== data processing ========
    DpImm { op: DpOp, s: bool, rn: R, rd: R, imm12: u16 },
    DpReg { op: DpOp, s: bool, rn: R, rd: R, rm: R, shift: Shift, amount: ShiftAmount },
    Movw { rd: R, imm16: u16 },
    Movt { rd: R, imm16: u16 },

    // ======== multiplies ========
    Mul { rd: R, rn: R, rm: R, s: bool },
    Mla { rd: R, rn: R, rm: R, ra: R, s: bool },
    Mls { rd: R, rn: R, rm: R, ra: R },
    Smull { rdlo: R, rdhi: R, rn: R, rm: R, s: bool },
    Umull { rdlo: R, rdhi: R, rn: R, rm: R, s: bool },
    Smlal { rdlo: R, rdhi: R, rn: R, rm: R, s: bool },
    Umlal { rdlo: R, rdhi: R, rn: R, rm: R, s: bool },
    Smulxy { rd: R, rn: R, rm: R, x: Half, y: Half },
    Smlaxy { rd: R, rn: R, rm: R, ra: R, x: Half, y: Half },
    Smulwy { rd: R, rn: R, rm: R, y: Half },
    Smlawy { rd: R, rn: R, rm: R, ra: R, y: Half },
    Smuad { rd: R, rn: R, rm: R, x: bool },
    Smusd { rd: R, rn: R, rm: R, x: bool },
    Smlad { rd: R, rn: R, rm: R, ra: R, x: bool },
    Smlsd { rd: R, rn: R, rm: R, ra: R, x: bool },
    Smlald { rdlo: R, rdhi: R, rn: R, rm: R, x: bool },
    Smlsld { rdlo: R, rdhi: R, rn: R, rm: R, x: bool },

    // ======== parallel (DSP) ========
    Parallel { kind: ParKind, shape: ParShape, rd: R, rn: R, rm: R },

    // ======== packing / saturation / extension / reversal ========
    Pkh { rd: R, rn: R, rm: R, top: bool, shift: u8 },
    Sel { rd: R, rn: R, rm: R },
    Ssat { rd: R, imm: u8, rn: R, sh: u8, asr: bool },
    Usat { rd: R, imm: u8, rn: R, sh: u8, asr: bool },
    Ssat16 { rd: R, imm: u8, rn: R },
    Usat16 { rd: R, imm: u8, rn: R },
    Qadd { rd: R, rn: R, rm: R },
    Qsub { rd: R, rn: R, rm: R },
    Qdadd { rd: R, rn: R, rm: R },
    Qdsub { rd: R, rn: R, rm: R },
    Rev { rd: R, rm: R },
    Rev16 { rd: R, rm: R },
    Revsh { rd: R, rm: R },
    Clz { rd: R, rm: R },
    Rbit { rd: R, rm: R },
    Sbfx { rd: R, rn: R, lsb: u8, width: u8 },
    Ubfx { rd: R, rn: R, lsb: u8, width: u8 },
    Bfc { rd: R, lsb: u8, width: u8 },
    Bfi { rd: R, rn: R, lsb: u8, width: u8 },
    Extend { op: ExtOp, rd: R, rn: R, rm: R, rot: u8 },
    Usad8 { rd: R, rn: R, rm: R },
    Usada8 { rd: R, rn: R, rm: R, ra: R },
    Crc32 { poly32: bool, sz: Size, rd: R, rn: R, rm: R },

    // ======== division ========
    Sdiv { rd: R, rn: R, rm: R },
    Udiv { rd: R, rn: R, rm: R },

    // ======== load/store ========
    Ldst {
        store: bool, size: Size, signed: bool, user: bool,
        rt: R, rn: R, rm: Option<R>, shift: Shift,
        imm: i32, index: bool, add: bool, wback: bool,
    },
    LdrdStrd { store: bool, rt: R, rt2: R, rn: R, imm: i32, index: bool, add: bool, wback: bool },
    LdmStm { load: bool, rn: R, mode: LdmMode, wback: bool, user: bool, list: RegList },
    ExclLoad { size: Size, rt: R, rn: R },
    ExclLoadD { rt: R, rt2: R, rn: R },
    // stores keep Rt(value) at bits(3:0)
    ExclStore { size: Size, rs: R, rt: R, rn: R },
    ExclStoreD { rs: R, rt: R, rt2: R, rn: R },
    LdaStl { load: bool, size: Size, rt: R, rn: R },
    LdaexD { rt: R, rt2: R, rn: R },
    StlexD { rs: R, rs2: R, rn: R },

    // ======== branches ========
    B { cond: Cond, off: i32 },
    Bl { off: i32 },
    Blx { off: i32 },
    Bx { rm: R },
    BlxReg { rm: R },
    Bxj { rm: R },
    Cbz { nz: bool, rn: R, off: i32 },
    Tbb { rn: R, rm: R, half: bool },

    // ======== status / system ========
    Mrs { rd: R, spsr: bool },
    Msr { spsr: bool, mask: u8, rn: R, imm: Option<u32> },
    Hints { kind: Hint },
    Barriers { kind: Barrier, opt: u8 },
    Bkpt { imm: u16 },
    Svc { imm: u32 },
    Udf { imm: u16 },
    Setend { big: bool },
    Cps { enable: bool, aif: u8, change_mode: bool, mode: u8 },
    Pld { w: bool, rn: R, rm: Option<R>, shift: Shift, imm: i32 },
    Pli { rn: R, rm: Option<R>, shift: Shift, imm: i32 },
    Srs { mode: LdmMode, wback: bool, user: bool, bank: u8 },
    Rfe { mode: LdmMode, wback: bool, rn: R },
    Eret,
    Hvc { imm: u16 },
    Smc { imm: u16 },

    // ======== VFP ========
    VfpBin { op: VfpBinOp, d: VIdx, n: VIdx, m: VIdx, dbl: bool },
    VfpMulAcc { form: VfpMulAcc, d: VIdx, n: VIdx, m: VIdx, dbl: bool },
    VfpUn { op: VfpUnOp, d: VIdx, m: VIdx, dbl: bool },
    VfpCmp { d: VIdx, m: VIdx, dbl: bool, e: bool },
    VfpCmpz { d: VIdx, dbl: bool, e: bool },
    VMovCoreS { rt: R, sn: VIdx, to_fp: bool },
    VMovCoreD { rt: R, rt2: R, dm: VIdx, to_fp: bool },
    VMovLane { dt: Dt, to_fp: bool, rt: R, d: VIdx, index: u8 },
    VMrs { rt: Option<R>, to_apsr: bool, sys: VfpSys },
    Vmsr { sys: VfpSys, rt: R },
    VLdrStr { load: bool, d: VIdx, rn: R, imm: i32, add: bool, dbl: bool },
    VLdmStm { load: bool, dbl: bool, d: VIdx, count: u8, rn: R, wback: bool, add: bool },
    Vcvt { form: VcvtForm, d: VIdx, m: VIdx, round: Option<u8> },
    VcvtImm { to_fp: bool, unsigned: bool, dbl: bool, fbits: u8, d: VIdx, m: VIdx },
    Vsel { op: VselOp, d: VIdx, n: VIdx, m: VIdx, dbl: bool },
    Vmaxnm { min: bool, d: VIdx, n: VIdx, m: VIdx, dbl: bool },
    Vrint { op: VrintOp, d: VIdx, m: VIdx, dbl: bool },

    // ======== NEON ========
    VmovImm { kind: NeonImmKind, imm: u64, q: bool, d: VIdx },
    VdupCore { dt: Dt, q: bool, d: VIdx, rt: R },
    VdupScalar { dt: Dt, q: bool, d: VIdx, m: VIdx, index: u8 },
    Vswp { d: VIdx, m: VIdx, q: bool },
    Neon {
        op: NeonOp, dt: Dt, q: bool,
        d: VIdx, n: VIdx, m: VIdx,
        imm: u8, index: u8,
    },
    VldStMulti { load: bool, kind: NeonVldKind, dt: Dt, d: VIdx, rn: R, rm: Option<R>, align: u8, wback: bool },
    VldStSingle { load: bool, kind: NeonVldKind, dt: Dt, d: VIdx, index: u8, rn: R, rm: Option<R>, align: u8, wback: bool, replicate: bool },

    /// Decoded but not semantically lifted yet (exotics: coprocessor etc).
    Unsupported { group: &'static str },
}

impl Ins {
    /// Short mnemonic for reporting / coverage statistics.
    pub fn mnemonic(&self) -> &'static str {
        use Ins::*;
        match self {
            DpImm { op, .. } | DpReg { op, .. } => op.name(),
            Movw { .. } => "movw",
            Movt { .. } => "movt",
            Mul { .. } => "mul", Mla { .. } => "mla", Mls { .. } => "mls",
            Smull { .. } => "smull", Umull { .. } => "umull",
            Smlal { .. } => "smlal", Umlal { .. } => "umlal",
            Smulxy { x, y, .. } => "smulxy",
            Smlaxy { .. } => "smlaxy", Smulwy { .. } => "smulwy", Smlawy { .. } => "smlawy",
            Smuad { .. } => "smuad", Smusd { .. } => "smusd",
            Smlad { .. } => "smlad", Smlsd { .. } => "smlsd",
            Smlald { .. } => "smlald", Smlsld { .. } => "smlsld",
            Parallel { kind, shape, .. } => "par",
            Pkh { .. } => "pkh", Sel { .. } => "sel",
            Ssat { .. } => "ssat", Usat { .. } => "usat",
            Ssat16 { .. } => "ssat16", Usat16 { .. } => "usat16",
            Qadd { .. } => "qadd", Qsub { .. } => "qsub",
            Qdadd { .. } => "qdadd", Qdsub { .. } => "qdsub",
            Rev { .. } => "rev", Rev16 { .. } => "rev16", Revsh { .. } => "revsh",
            Clz { .. } => "clz", Rbit { .. } => "rbit",
            Sbfx { .. } => "sbfx", Ubfx { .. } => "ubfx",
            Bfc { .. } => "bfc", Bfi { .. } => "bfi",
            Extend { op, .. } => op.name(),
            Usad8 { .. } => "usad8", Usada8 { .. } => "usada8",
            Crc32 { .. } => "crc32",
            Sdiv { .. } => "sdiv", Udiv { .. } => "udiv",
            Ldst { store, size, .. } => if *store { "str" } else { "ldr" },
            LdrdStrd { .. } => "ldrd",
            LdmStm { load, .. } => if *load { "ldm" } else { "stm" },
            ExclLoad { .. } => "ldrex", ExclLoadD { .. } => "ldrexd",
            ExclStore { .. } => "strex", ExclStoreD { .. } => "strexd",
            LdaStl { .. } => "lda/stl",
            LdaexD { .. } => "ldaexd", StlexD { .. } => "stlexd",
            B { .. } => "b", Bl { .. } => "bl", Blx { .. } => "blx",
            Bx { .. } => "bx", BlxReg { .. } => "blx", Bxj { .. } => "bxj",
            Cbz { .. } => "cbz", Tbb { .. } => "tbb",
            Mrs { .. } => "mrs", Msr { .. } => "msr",
            Hints { .. } => "hint", Barriers { .. } => "barrier",
            Bkpt { .. } => "bkpt", Svc { .. } => "svc", Udf { .. } => "udf",
            Setend { .. } => "setend", Cps { .. } => "cps",
            Pld { .. } => "pld", Pli { .. } => "pli",
            Srs { .. } => "srs", Rfe { .. } => "rfe", Eret => "eret",
            Hvc { .. } => "hvc", Smc { .. } => "smc",
            VfpBin { .. } => "vfp", VfpMulAcc { .. } => "vfp",
            VfpUn { .. } => "vfp", VfpCmp { .. } => "vcmp", VfpCmpz { .. } => "vcmp",
            VMovCoreS { .. } | VMovCoreD { .. } | VMovLane { .. } => "vmov",
            VMrs { .. } => "vmrs", Vmsr { .. } => "vmsr",
            VLdrStr { .. } => "vldr/vstr", VLdmStm { .. } => "vldm/vstm",
            Vcvt { .. } | VcvtImm { .. } => "vcvt",
            Vsel { .. } => "vsel", Vmaxnm { .. } => "vmaxnm",
            Vrint { .. } => "vrint",
            VmovImm { .. } => "vmov.i", VdupCore { .. } => "vdup", VdupScalar { .. } => "vdup",
            Vswp { .. } => "vswp", Neon { .. } => "neon",
            VldStMulti { .. } => "vldm", VldStSingle { .. } => "vld",
            Unsupported { group } => group,
        }
    }
}

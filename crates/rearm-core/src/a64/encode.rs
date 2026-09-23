//! A64 (arm64-v8a) encoder — the recompiler output target.
//! Encodings byte-verified against the LLVM golden corpus (a64-misc.json).

use crate::common::Cond;

pub type XR = u8;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EncErr(pub &'static str);

impl core::fmt::Display for EncErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "a64 encode: {}", self.0)
    }
}

/// Assembled A64 code (little-endian 32-bit words).
#[derive(Default, Clone)]
pub struct A64 {
    pub buf: Vec<u32>,
}

impl A64 {
    pub fn new() -> Self { A64 { buf: Vec::with_capacity(1024) } }
    pub fn len(&self) -> usize { self.buf.len() }
    pub fn is_empty(&self) -> bool { self.buf.is_empty() }
    pub fn words(&self) -> &[u32] { &self.buf }
    pub fn clear(&mut self) { self.buf.clear() }
    pub fn bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.buf.len() * 4);
        for w in &self.buf { v.extend_from_slice(&w.to_le_bytes()); }
        v
    }
    #[inline]
    pub fn e(&mut self, w: u32) { self.buf.push(w); }
    /// byte offset of the next emitted instruction
    pub fn pc(&self) -> i32 { (self.buf.len() * 4) as i32 }

    // ==================== branches ====================
    pub fn b(&mut self, off: i32) -> Result<(), EncErr> {
        if off & 3 != 0 || !(-134_217_728..=134_217_724).contains(&off) {
            return Err(EncErr("b range"));
        }
        self.e(0b000101 << 26 | ((off >> 2) as u32 & 0x03FF_FFFF));
        Ok(())
    }
    pub fn bl(&mut self, off: i32) -> Result<(), EncErr> {
        if off & 3 != 0 || !(-134_217_728..=134_217_724).contains(&off) {
            return Err(EncErr("bl range"));
        }
        self.e(0b100101 << 26 | ((off >> 2) as u32 & 0x03FF_FFFF));
        Ok(())
    }
    pub fn bcond(&mut self, cond: Cond, off: i32) -> Result<(), EncErr> {
        if off & 3 != 0 || !(-1_048_576..=1_048_572).contains(&off) {
            return Err(EncErr("b.cond range"));
        }
        self.e(0x54 << 24 | (((off >> 2) as u32 & 0x7FFFF) << 5) | cond.bits() as u32);
        Ok(())
    }
    pub fn cbz(&mut self, sf: bool, rt: XR, off: i32) -> Result<(), EncErr> {
        if off & 3 != 0 { return Err(EncErr("cbz align")); }
        self.e(((sf as u32) << 31) | (0x34 << 24) | (((off >> 2) as u32 & 0x1F_FFFF) << 5) | rt as u32);
        Ok(())
    }
    pub fn cbnz(&mut self, sf: bool, rt: XR, off: i32) -> Result<(), EncErr> {
        if off & 3 != 0 { return Err(EncErr("cbnz align")); }
        self.e(((sf as u32) << 31) | (0x35 << 24) | (((off >> 2) as u32 & 0x1F_FFFF) << 5) | rt as u32);
        Ok(())
    }
    pub fn tbz(&mut self, rt: XR, bit: u8, off: i32) -> Result<(), EncErr> {
        if off & 3 != 0 || bit > 63 { return Err(EncErr("tbz")); }
        self.e((((bit >> 5) as u32) << 31) | (0x36 << 24)
            | (((off >> 2) as u32 & 0x3FFF) << 5) | (((bit & 0x1F) as u32) << 19) | rt as u32);
        Ok(())
    }
    pub fn tbnz(&mut self, rt: XR, bit: u8, off: i32) -> Result<(), EncErr> {
        if off & 3 != 0 || bit > 63 { return Err(EncErr("tbnz")); }
        self.e((((bit >> 5) as u32) << 31) | (0x37 << 24)
            | (((off >> 2) as u32 & 0x3FFF) << 5) | (((bit & 0x1F) as u32) << 19) | rt as u32);
        Ok(())
    }
    pub fn br(&mut self, xn: XR) { self.e(0xD61F_0000 | (xn as u32) << 5); }
    pub fn blr(&mut self, xn: XR) { self.e(0xD63F_0000 | (xn as u32) << 5); }
    pub fn ret(&mut self, xn: Option<XR>) {
        self.e(0xD65F_0000 | (xn.unwrap_or(30) as u32) << 5);
    }

    // ==================== data-proc immediate ====================
    pub fn movz(&mut self, sf: bool, hw: u8, imm16: u16, rd: XR) {
        self.e(wide(sf, 0b10, hw, imm16, rd));
    }
    pub fn movn(&mut self, sf: bool, hw: u8, imm16: u16, rd: XR) {
        self.e(wide(sf, 0b00, hw, imm16, rd));
    }
    pub fn movk(&mut self, sf: bool, hw: u8, imm16: u16, rd: XR) {
        self.e(wide(sf, 0b11, hw, imm16, rd));
    }
    /// logical bitmask immediate (raw fields)
    pub fn log_imm(&mut self, sf: bool, opc: u8, n: bool, immr: u8, imms: u8, rn: XR, rd: XR) {
        self.e(((sf as u32) << 31) | ((opc as u32) << 29) | (0x24 << 23)
            | ((n as u32) << 22) | ((immr as u32) << 16) | ((imms as u32) << 10)
            | (rn as u32) << 5 | rd as u32);
    }
    /// AND/ORR/EOR/ANDS with a bitmask immediate (opc: 0=AND 1=ORR 2=EOR 3=ANDS)
    pub fn logic_bitmask(&mut self, sf: bool, opc: u8, val: u64, rn: XR, rd: XR) -> Result<(), EncErr> {
        let (n, immr, imms) = encode_bitmask(val, sf).ok_or(EncErr("bad bitmask"))?;
        self.log_imm(sf, opc, n, immr, imms, rn, rd);
        Ok(())
    }
    /// add/sub immediate
    pub fn addsub_imm(&mut self, sf: bool, op: u8, s: bool, imm12: u16, shift12: bool, rn: XR, rd: XR) {
        self.e(((sf as u32) << 31) | ((op as u32) << 30) | ((s as u32) << 29)
            | (0x11 << 24) | ((shift12 as u32) << 22) | ((imm12 as u32) << 10)
            | (rn as u32) << 5 | rd as u32);
    }
    pub fn add_imm(&mut self, sf: bool, rn: XR, rd: XR, imm: u16) { self.addsub_imm(sf, 0, false, imm, false, rn, rd); }
    pub fn sub_imm(&mut self, sf: bool, rn: XR, rd: XR, imm: u16) { self.addsub_imm(sf, 1, false, imm, false, rn, rd); }
    pub fn adds_imm(&mut self, sf: bool, rn: XR, rd: XR, imm: u16) { self.addsub_imm(sf, 0, true, imm, false, rn, rd); }
    pub fn subs_imm(&mut self, sf: bool, rn: XR, rd: XR, imm: u16) { self.addsub_imm(sf, 1, true, imm, false, rn, rd); }

    // ==================== bitfield ====================
    /// SBFM/UBFM/BFM common: opc 10=SBFM 00=BFM(UBFM shares opc 00 with N=0? no: UBFM opc=10?)
    /// UBFM: sf opc=10? — per corpus: asr x0,x1,#7 = 9347fc20 (SBFM), lsr = d347fc20 (UBFM), lsl = d379e020 (UBFM)
    pub fn bfm(&mut self, sf: bool, opc: u8, immr: u8, imms: u8, rn: XR, rd: XR) {
        // N bit (bit22) must equal sf — LLVM-verified: lsr x17,x16,#32 = 0xd360fe11.
        self.e(((sf as u32) << 31) | ((opc as u32) << 29) | (0x26 << 23) | ((sf as u32) << 22)
            | ((immr as u32) << 16) | ((imms as u32) << 10) | (rn as u32) << 5 | rd as u32);
    }
    pub fn lsl_imm(&mut self, sf: bool, rn: XR, rd: XR, amount: u8) {
        let bits: u8 = if sf { 63 } else { 31 };
        self.bfm(sf, 0b10, (bits + 1 - amount) & bits, bits - amount, rn, rd);
    }
    pub fn lsr_imm(&mut self, sf: bool, rn: XR, rd: XR, amount: u8) {
        let bits: u8 = if sf { 63 } else { 31 };
        self.bfm(sf, 0b10, amount, bits, rn, rd);
    }
    pub fn asr_imm(&mut self, sf: bool, rn: XR, rd: XR, amount: u8) {
        let bits: u8 = if sf { 63 } else { 31 };
        self.bfm(sf, 0b00, amount, bits, rn, rd); // SBFM: opc=00 (corpus: asr x0,x1,#7 = 9347fc20)
    }
    pub fn bfi(&mut self, sf: bool, rn: XR, rd: XR, lsb: u8, width: u8) {
        let bits: u8 = if sf { 63 } else { 31 };
        self.bfm(sf, 0b01, (bits + 1 - lsb) & bits, width - 1, rn, rd); // BFM
    }
    pub fn bfxil(&mut self, sf: bool, rn: XR, rd: XR, lsb: u8, width: u8) {
        self.bfm(sf, 0b01, lsb, lsb + width - 1, rn, rd);
    }
    pub fn sbfx(&mut self, sf: bool, rn: XR, rd: XR, lsb: u8, width: u8) {
        // LLVM-verified: sbfx w0,w1,#4,#8 = SBFM #4, #11 (imms = lsb+width-1)
        self.bfm(sf, 0b00, lsb, lsb + width - 1, rn, rd);
    }
    pub fn ubfx(&mut self, sf: bool, rn: XR, rd: XR, lsb: u8, width: u8) {
        self.bfm(sf, 0b10, lsb, lsb + width - 1, rn, rd);
    }
    pub fn sxt(&mut self, sf: bool, from_bits: u8, rn: XR, rd: XR) {
        self.bfm(sf, 0b00, 0, from_bits - 1, rn, rd); // SBFM (sxtb w0,w1 = 13001c20)
    }
    pub fn uxt(&mut self, sf: bool, from_bits: u8, rn: XR, rd: XR) {
        self.bfm(sf, 0b10, 0, from_bits - 1, rn, rd);
    }
    pub fn extr(&mut self, sf: bool, o0: bool, rm: XR, lsb: u8, rn: XR, rd: XR) {
        self.e(((sf as u32) << 31) | (0x27 << 23) | ((o0 as u32) << 21)
            | ((rm as u32) << 16) | ((lsb as u32) << 10) | (rn as u32) << 5 | rd as u32);
    }
    pub fn ror_imm(&mut self, sf: bool, rn: XR, rd: XR, amount: u8) {
        self.extr(sf, false, rn, amount, rn, rd);
    }

    // ==================== data-proc register ====================
    /// ADD/SUB shifted register: shift: 0=LSL 1=LSR 2=ASR; op 0=ADD 1=SUB
    pub fn addsub_reg(&mut self, sf: bool, op: u8, s: bool, shift: u8, amount: u8, rn: XR, rm: XR, rd: XR) {
        self.e(((sf as u32) << 31) | ((op as u32) << 30) | ((s as u32) << 29)
            | (0x0B << 24) | ((shift as u32) << 22) | ((rm as u32) << 16) | ((amount as u32) << 10)
            | (rn as u32) << 5 | rd as u32);
    }
    /// ADD/SUB extended register: ext 0..7 = UXTB,UXTH,UXTW,UXTX,SXTB,SXTH,SXTW,SXTX; amount 0..4
    pub fn addsub_ext(&mut self, sf: bool, op: u8, s: bool, rm: XR, ext: u8, amount: u8, rn: XR, rd: XR) {
        self.e(((sf as u32) << 31) | ((op as u32) << 30) | ((s as u32) << 29)
            | (0x0B << 24) | (1 << 21)
            | ((rm as u32) << 16) | ((ext as u32) << 13) | ((amount as u32) << 10)
            | (rn as u32) << 5 | rd as u32);
    }
    /// ADC/SBC: op 0=ADC 1=SBC
    pub fn adc(&mut self, sf: bool, op: u8, s: bool, rn: XR, rm: XR, rd: XR) {
        self.e(((sf as u32) << 31) | ((op as u32) << 30) | ((s as u32) << 29)
            | (0x1A << 24) | ((rm as u32) << 16) | (rn as u32) << 5 | rd as u32);
    }
    /// Logic register: opc 0=AND 1=ORR 2=EOR 3=ANDS; N inverts Rm.
    /// Legacy bool overload: shift=true means "LSL #amount" (shift_type 0).
    pub fn logic_reg(&mut self, sf: bool, opc: u8, n: bool, shift: bool, amount: u8, rn: XR, rm: XR, rd: XR) {
        let amt = if shift { amount } else { 0 };
        self.logic_reg_shift(sf, opc, n, 0, amt, rn, rm, rd);
    }
    pub fn logic_reg_shift(&mut self, sf: bool, opc: u8, n: bool, shift_type: u32, amount: u8, rn: XR, rm: XR, rd: XR) {
        self.e(((sf as u32) << 31) | ((opc as u32) << 29)
            | (0x0A << 24) | (shift_type << 22) | ((n as u32) << 21)
            | ((rm as u32) << 16) | ((amount as u32) << 10) | (rn as u32) << 5 | rd as u32);
    }
    /// CSEL family: op 0=CSEL 1=CSINC 2=CSINV 3=CSNEG
    /// Encoding (LLVM-verified): sf 0? 11010 100 Rm cond op2 Rn Rd;
    /// bit30 = op>>1 (inv/neg group), op2(bits11:10) = op&1 (inc/neg).
    pub fn csel(&mut self, sf: bool, op: u8, rn: XR, rm: XR, cond: Cond, rd: XR) {
        self.e(((sf as u32) << 31) | (((op >> 1) as u32) << 30) | (0x1A << 24)
            | (4u32 << 21) | ((rm as u32) << 16) | ((cond.bits() as u32) << 12)
            | (((op & 1) as u32) << 10) | (rn as u32) << 5 | rd as u32);
    }
    /// CCMP/CCMN register: op 0=CCMN 1=CCMP
    pub fn ccmp(&mut self, sf: bool, op: u8, rm: XR, nzcv: u8, cond: Cond, rn: XR) {
        self.e(((sf as u32) << 31) | ((op as u32) << 30) | (1 << 29) | (0x1A << 24) | (2 << 21)
            | ((rm as u32) << 16) | ((cond.bits() as u32) << 12) | (rn as u32) << 5
            | (nzcv as u32 & 0xF));
    }
    /// Data-proc 1-source: opcode rbit=0 rev16=1 rev32=2 rev=3 clz=4 cls=5
    pub fn dp1(&mut self, sf: bool, opcode: u8, rn: XR, rd: XR) {
        // LLVM-verified: rbit w0,w1 = 0x5ac00020 (bits 23:22 = 11)
        self.e(((sf as u32) << 31) | (1 << 30) | (0x1A << 24) | (3 << 22)
            | ((opcode as u32) << 10) | (rn as u32) << 5 | rd as u32);
    }
    pub fn rbit(&mut self, sf: bool, rn: XR, rd: XR) { self.dp1(sf, 0, rn, rd); }
    pub fn rev16(&mut self, sf: bool, rn: XR, rd: XR) { self.dp1(sf, 1, rn, rd); }
    pub fn rev32(&mut self, sf: bool, rn: XR, rd: XR) { self.dp1(sf, 3, rn, rd); }
    pub fn rev(&mut self, sf: bool, rn: XR, rd: XR) { self.dp1(sf, 2, rn, rd); }
    pub fn clz(&mut self, sf: bool, rn: XR, rd: XR) { self.dp1(sf, 4, rn, rd); }
    pub fn cls(&mut self, sf: bool, rn: XR, rd: XR) { self.dp1(sf, 5, rn, rd); }
    /// Data-proc 2-source: opcode udiv=2 sdiv=3 lslv=8 lsrv=9 asrv=10 rorv=11
    pub fn dp2(&mut self, sf: bool, opcode: u8, rn: XR, rm: XR, rd: XR) {
        self.e(((sf as u32) << 31) | (0x1A << 24) | (6 << 21)
            | ((rm as u32) << 16) | ((opcode as u32) << 10) | (rn as u32) << 5 | rd as u32);
    }
    pub fn sdiv(&mut self, sf: bool, rn: XR, rm: XR, rd: XR) { self.dp2(sf, 3, rn, rm, rd); }
    pub fn udiv(&mut self, sf: bool, rn: XR, rm: XR, rd: XR) { self.dp2(sf, 2, rn, rm, rd); }
    pub fn lslv(&mut self, sf: bool, rn: XR, rm: XR, rd: XR) { self.dp2(sf, 8, rn, rm, rd); }
    pub fn lsrv(&mut self, sf: bool, rn: XR, rm: XR, rd: XR) { self.dp2(sf, 9, rn, rm, rd); }
    pub fn asrv(&mut self, sf: bool, rn: XR, rm: XR, rd: XR) { self.dp2(sf, 10, rn, rm, rd); }
    pub fn rorv(&mut self, sf: bool, rn: XR, rm: XR, rd: XR) { self.dp2(sf, 11, rn, rm, rd); }
    /// MADD/MSUB (LLVM-verified: madd w0,w1,w2,w3 = 0x1b020c20; o0 = bit15!)
    pub fn madd(&mut self, sf: bool, o0: bool, rm: XR, ra: XR, rn: XR, rd: XR) {
        self.e(((sf as u32) << 31) | (0x1B << 24)
            | ((rm as u32) << 16) | ((o0 as u32) << 15) | ((ra as u32) << 10)
            | (rn as u32) << 5 | rd as u32);
    }
    /// SMADDL/SMSUBL/UMADDL/UMSUBL (LLVM-verified: smaddl = 0x9b220c20:
    /// bit21=1 marks long forms, u = bit23, o0 = bit15)
    pub fn maddl(&mut self, u: bool, o0: bool, rm: XR, ra: XR, rn: XR, rd: XR) {
        self.e((1u32 << 31) | ((u as u32) << 23) | (0x1B << 24) | (1u32 << 21)
            | ((rm as u32) << 16) | ((o0 as u32) << 15) | ((ra as u32) << 10)
            | (rn as u32) << 5 | rd as u32);
    }
    /// SMULH/UMULH (LLVM-verified: smulh x0,x1,x2 = 0x9b427c20:
    /// bit22=1, u = bit23, Ra = xzr)
    pub fn mulh(&mut self, u: bool, rm: XR, rn: XR, rd: XR) {
        self.e((1u32 << 31) | ((u as u32) << 23) | (0x1B << 24) | (1u32 << 22)
            | ((rm as u32) << 16) | (31u32 << 10) | (rn as u32) << 5 | rd as u32);
    }
    /// ADD (extended register, 64-bit dest): add Xd, Xn, Wm, uxtw.
    /// LLVM-verified: add x1, x2, w3, uxtw = 0x8b234041 (bit21 set; option=010 at 15:13).
    pub fn add_uxtw(&mut self, rn: XR, rm: XR, rd: XR) {
        self.e(0x8B00_0000 | (1 << 21) | ((rm as u32) << 16) | (0b010 << 13) | ((rn as u32) << 5) | rd as u32);
    }
    /// UMULL: Xd = Wa * Wb. LLVM-verified: umull x16,w14,w10 = 0x9baa7dd0
    /// (= UMADDL with Ra = xzr; u=bit23, bit21 long-form, markers 11111 at 14:10).
    pub fn umull(&mut self, rm: XR, rn: XR, rd: XR) {
        self.maddl(true, false, rm, 31, rn, rd);
    }

    // ==================== loads/stores ====================
    /// LDR/STR unsigned imm: size 00=8b 01=16b 10=32b 11=64b; opc 00=store 01=load
    pub fn ldst_uimm(&mut self, size: u8, opc: u8, imm12: u16, rn: XR, rt: XR) {
        self.e(((size as u32) << 30) | (0x39 << 24) | ((opc as u32) << 22)
            | ((imm12 as u32) << 10) | (rn as u32) << 5 | rt as u32);
    }
    /// LDR/STR imm9: mode 0=unscaled 1=post-idx 2=pre-idx
    pub fn ldst_imm9(&mut self, size: u8, opc: u8, imm9: i16, mode: u8, rn: XR, rt: XR) {
        self.e(((size as u32) << 30) | (0x38 << 24) | ((opc as u32) << 22)
            | (((imm9 as u32) & 0x1FF) << 12) | ((mode as u32) << 10)
            | (rn as u32) << 5 | rt as u32);
    }
    /// LDR/STR register offset (LSL #size)
    pub fn ldst_reg(&mut self, size: u8, opc: u8, rm: XR, rn: XR, rt: XR) {
        self.e(((size as u32) << 30) | (0x38 << 24) | ((opc as u32) << 22) | (1 << 21)
            | ((rm as u32) << 16) | (6 << 13) | (1 << 11)
            | (rn as u32) << 5 | rt as u32);
    }
    /// LDP/STP: opc 00=32 10=64; L 0=store 1=load; mode 2=post 1=signed-off 3=pre
    pub fn ldpstp(&mut self, opc: u8, l: bool, mode: u8, imm7: i16, rt2: XR, rn: XR, rt: XR) {
        self.e(((opc as u32) << 30) | (0x29 << 24) | ((l as u32) << 22)
            | ((mode as u32) << 23) | (((imm7 as u32) & 0x7F) << 15)
            | ((rt2 as u32) << 10) | (rn as u32) << 5 | rt as u32);
    }
    pub fn ldxr(&mut self, size: u8, rt: XR, rn: XR) {
        self.e(((size as u32) << 30) | (0x08 << 24) | (1 << 22) | (0x1F << 16) | (0x1F << 10)
            | (rn as u32) << 5 | rt as u32);
    }
    pub fn stxr(&mut self, size: u8, rs: XR, rt: XR, rn: XR) {
        self.e(((size as u32) << 30) | (0x08 << 24)
            | ((rs as u32) << 16) | (0x1F << 10) | (rn as u32) << 5 | rt as u32);
    }
    /// LLVM-verified: ldxp w1,w2,[x3] = 0x887f0861; ldxp x1,x2 = 0xc87f0861.
    /// Bit22 = L (load), bit21 = pair; Rs-marker 11111 at (20:16).
    pub fn ldxp(&mut self, size: u8, rt2: XR, rn: XR, rt: XR) {
        self.e(((size as u32) << 30) | (0x08 << 24) | (1 << 22) | (1 << 21) | (0x1F << 16)
            | ((rt2 as u32) << 10) | (rn as u32) << 5 | rt as u32);
    }
    /// LLVM-verified: stxp w0,w1,w2,[x3] = 0x88200861; stxp x-form 0xc8...
    pub fn stxp(&mut self, size: u8, rs: XR, rt2: XR, rn: XR, rt: XR) {
        self.e(((size as u32) << 30) | (0x08 << 24) | (1 << 21)
            | ((rs as u32) << 16) | ((rt2 as u32) << 10) | (rn as u32) << 5 | rt as u32);
    }

    // ==================== misc ====================
    pub fn nop(&mut self) { self.e(0xD503_201F); }
    pub fn yield_(&mut self) { self.e(0xD503_203F); }
    pub fn wfe(&mut self) { self.e(0xD503_205F); }
    pub fn wfi(&mut self) { self.e(0xD503_207F); }

    // ==================== scalar FP (data-proc 1 source) ====================
    // Encoding: 0001 1110 type(2) opcode(5) 10000 Rn Rd
    pub fn fp1(&mut self, dbl: bool, opcode: u32, rn: XR, rd: XR) {
        // LLVM-verified layout: opcode is 2 bits at (16:15):
        // fmov=00 fabs=01 fneg=10 fsqrt=11 (fabs d0,d1 = 0x1e60c020).
        let ty = if dbl { 1u32 } else { 0 };
        self.e(0x1E204000 | (ty << 22) | ((opcode & 3) << 15)
            | ((rn as u32) << 5) | rd as u32);
    }
    /// FMOV (register): fp1 opcode 00
    pub fn fmov_reg(&mut self, dbl: bool, rn: XR, rd: XR) { self.fp1(dbl, 0x0, rn, rd); }
    /// FABS: fp1 opcode 01 (fabs d0,d1 = 0x1e60c020)
    pub fn fabs(&mut self, dbl: bool, rn: XR, rd: XR) { self.fp1(dbl, 0x1, rn, rd); }
    /// FNEG: fp1 opcode 10 (fneg d0,d1 = 0x1e614020)
    pub fn fneg(&mut self, dbl: bool, rn: XR, rd: XR) { self.fp1(dbl, 0x2, rn, rd); }
    /// FSQRT: fp1 opcode 11 (fsqrt d0,d1 = 0x1e61c020)
    pub fn fsqrt(&mut self, dbl: bool, rn: XR, rd: XR) { self.fp1(dbl, 0x3, rn, rd); }

    // ==================== scalar FP (data-proc 2 source) ====================
    // Encoding: 0001 1110 type(2) 1 Rm opcode(4) 10 Rn Rd
    pub fn fp2(&mut self, dbl: bool, opcode: u8, rm: XR, rn: XR, rd: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        self.e(0x1E200800 | (ty << 22) | ((rm as u32) << 16)
            | ((opcode as u32) << 12) | ((rn as u32) << 5) | rd as u32);
    }
    /// FMUL: fp2 opcode 0000 (no U)
    pub fn fmul(&mut self, dbl: bool, rm: XR, rn: XR, rd: XR) { self.fp2(dbl, 0x0, rm, rn, rd); }
    /// FDIV: fp2 opcode 0001
    pub fn fdiv(&mut self, dbl: bool, rm: XR, rn: XR, rd: XR) { self.fp2(dbl, 0x1, rm, rn, rd); }
    /// FADD: fp2 opcode 0010
    pub fn fadd(&mut self, dbl: bool, rm: XR, rn: XR, rd: XR) { self.fp2(dbl, 0x2, rm, rn, rd); }
    /// FSUB: fp2 opcode 0011
    pub fn fsub(&mut self, dbl: bool, rm: XR, rn: XR, rd: XR) { self.fp2(dbl, 0x3, rm, rn, rd); }
    /// FCMP/FCMPE: LLVM-verified fcmp d1,d2 = 0x1e622020; E is bit4 (fcmpe = 0x1e622030).
    pub fn fcmp(&mut self, dbl: bool, e: bool, rm: XR, rn: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        self.e(0x1E202000 | (ty << 22) | ((rm as u32) << 16) | ((e as u32) << 4)
            | ((rn as u32) << 5));
    }
    /// FCMP with zero: LLVM-verified fcmp d1,#0.0 = 0x1e602028; fcmpe = 0x1e602038 (E=bit4).
    pub fn fcmpz(&mut self, dbl: bool, e: bool, rn: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        self.e(0x1E202000 | (ty << 22) | ((e as u32) << 4) | ((rn as u32) << 5) | 0x8);
    }

    /// FMADD family — LLVM-verified: fmadd=0x1f420c20; fmsub=|bit15; fnmadd=|bit21;
    /// fnmsub=both (NOT the reverse!).
    pub fn fmadd(&mut self, dbl: bool, rm: XR, ra: XR, rn: XR, rd: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        self.e(0x1F000000 | (ty << 22) | ((rm as u32) << 16) | ((ra as u32) << 10)
            | ((rn as u32) << 5) | rd as u32);
    }
    pub fn fmsub(&mut self, dbl: bool, rm: XR, ra: XR, rn: XR, rd: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        self.e(0x1F000000 | (1 << 15) | (ty << 22) | ((rm as u32) << 16) | ((ra as u32) << 10)
            | ((rn as u32) << 5) | rd as u32);
    }
    pub fn fnmadd(&mut self, dbl: bool, rm: XR, ra: XR, rn: XR, rd: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        self.e(0x1F000000 | (1 << 21) | (ty << 22) | ((rm as u32) << 16) | ((ra as u32) << 10)
            | ((rn as u32) << 5) | rd as u32);
    }
    pub fn fnmsub(&mut self, dbl: bool, rm: XR, ra: XR, rn: XR, rd: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        self.e(0x1F000000 | (1 << 21) | (1 << 15) | (ty << 22) | ((rm as u32) << 16) | ((ra as u32) << 10)
            | ((rn as u32) << 5) | rd as u32);
    }

    // ==================== scalar FP ↔ integer conversions ====================
    // LLVM-verified: scvtf s0,w1 = 0x1e220020; scvtf d0,x1 = 0x9e620020;
    // fcvtzs w0,s1 = 0x1e380020; fcvtzs x0,d1 = 0x9e780020. sf at bit31, ty at b22.
    pub fn scvtf(&mut self, dbl: bool, sf: bool, rn: XR, rd: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        let sf = sf as u32;
        self.e(0x1E220000 | (ty << 22) | (sf << 31) | ((rn as u32) << 5) | rd as u32);
    }
    pub fn ucvtf(&mut self, dbl: bool, sf: bool, rn: XR, rd: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        let sf = sf as u32;
        self.e(0x1E230000 | (ty << 22) | (sf << 31) | ((rn as u32) << 5) | rd as u32);
    }
    pub fn fcvtzs(&mut self, dbl: bool, sf: bool, rn: XR, rd: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        let sf = sf as u32;
        self.e(0x1E380000 | (ty << 22) | (sf << 31) | ((rn as u32) << 5) | rd as u32);
    }
    pub fn fcvtzu(&mut self, dbl: bool, sf: bool, rn: XR, rd: XR) {
        let ty = if dbl { 1u32 } else { 0 };
        let sf = sf as u32;
        self.e(0x1E390000 | (ty << 22) | (sf << 31) | ((rn as u32) << 5) | rd as u32);
    }

    // ==================== FMOV (GPR ↔ FP) ====================
    // LLVM-verified: fmov w0,s1 = 0x1e260020; fmov x0,d1 = 0x9e660020;
    // fmov s0,w1 = 0x1e270020; fmov d0,x1 = 0x9e670020.
    // to-gpr base 0x1E260000, from-gpr base 0x1E270000; ty at b22, sf at b31.
    pub fn fmov_to_gpr32(&mut self, vn: XR, rd: XR) {
        self.e(0x1E260000 | ((vn as u32) << 5) | rd as u32);
    }
    pub fn fmov_from_gpr32(&mut self, rn: XR, rd: XR) {
        self.e(0x1E270000 | ((rn as u32) << 5) | rd as u32);
    }
    pub fn fmov_to_gpr64(&mut self, vn: XR, rd: XR) {
        self.e(0x9E660000 | ((vn as u32) << 5) | rd as u32);
    }
    pub fn fmov_from_gpr64(&mut self, rn: XR, rd: XR) {
        self.e(0x9E670000 | ((rn as u32) << 5) | rd as u32);
    }

    // ==================== scalar FP load/store ====================
    /// LDR/STR Dn, [Xn, #imm12*8]: 11 111 0 01 00 imm12 Rn Rt
    pub fn ldr_d(&mut self, imm12: u16, rn: XR, rt: XR) {
        self.e(0xFD400000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | rt as u32);
    }
    pub fn str_d(&mut self, imm12: u16, rn: XR, rt: XR) {
        self.e(0xFD000000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | rt as u32);
    }
    /// LDR/STR Sn, [Xn, #imm12*4]: 11 111 0 01 00 imm12 Rn Rt (smaller offset scale)
    pub fn ldr_s(&mut self, imm12: u16, rn: XR, rt: XR) {
        self.e(0xBD400000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | rt as u32);
    }
    pub fn str_s(&mut self, imm12: u16, rn: XR, rt: XR) {
        self.e(0xBD000000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | rt as u32);
    }

    // ==================== FMOV (immediate) ====================
    /// FMOV Sn, #imm8: 0001 1110 00 01 0001 00000 imm8 Rd
    pub fn fmov_f32_imm(&mut self, imm8: u8, rd: XR) {
        self.e(0x1E201000 | ((imm8 as u32) << 13) | ((rd as u32) << 0));
    }
    /// FMOV Dn, #imm8: 0001 1110 01 01 0001 00000 imm8 Rd
    pub fn fmov_f64_imm(&mut self, imm8: u8, rd: XR) {
        self.e(0x1E601000 | ((imm8 as u32) << 13) | ((rd as u32) << 0));
    }

    pub fn sev(&mut self) { self.e(0xD503_209F); }
    pub fn dsb(&mut self, opt: u8) { self.e(0xD503_309F | ((opt as u32 & 0xF) << 8)); }
    pub fn dmb(&mut self, opt: u8) { self.e(0xD503_30BF | ((opt as u32 & 0xF) << 8)); }
    pub fn isb(&mut self) { self.e(0xD503_3FDF); }
    /// LLVM-verified: clrex = 0xd5033f5f.
    pub fn clrex(&mut self) { self.e(0xD503_3F5F); }
    pub fn svc(&mut self, imm16: u16) { self.e(0xD400_0001 | ((imm16 as u32) << 5)); }
    pub fn brk(&mut self, imm16: u16) { self.e(0xD420_0000 | ((imm16 as u32) << 5)); }
    /// A64 UDF #imm16 — LLVM-verified: udf #0x1234 = 0x00001234 (imm at bits 15:0).
    pub fn udf(&mut self, imm16: u16) { self.e(imm16 as u32); }
    /// MRS Xt, NZCV — LLVM-verified: mrs x0,nzcv = 0xd53b4200; mrs x16 = 0xd53b4210.
    /// Rt at bits(4:0).
    pub fn mrs_nzcv(&mut self, rt: XR) { self.e(0xD53B_4200 | rt as u32); }
    /// MSR NZCV, Xt — LLVM-verified: msr nzcv,x16 = 0xd51b4210. Rt at bits(4:0).
    pub fn msr_nzcv(&mut self, rt: XR) { self.e(0xD51B_4200 | rt as u32); }
    /// PRFM (immediate): prfop 0=PLDL1KEEP 8=PLIL1KEEP; imm12 scaled by 8.
    /// LLVM-verified: prfm pldl1keep,[x1] = 0xf9800020; plil1keep,[x1,#8] = 0xf9800428.
    pub fn prfm(&mut self, prfop: u8, imm12: u16, rn: XR) {
        self.e(0xF980_0000 | ((imm12 as u32) << 10) | (rn as u32) << 5 | prfop as u32);
    }
    /// CRC32/CRC32C: sz 0=B 1=H 2=W 3=X. LLVM-verified field layout:
    /// crc32b w0,w1,w2 = 0x1ac24020 (sz at bits 11:10, C at bit 30, sf for X).
    pub fn crc32(&mut self, c: bool, sz: u8, rn: XR, rm: XR, rd: XR) {
        self.e((((sz == 3) as u32) << 31) | ((c as u32) << 30) | (0x1A << 24)
            | (2 << 21) | ((rm as u32) << 16) | ((sz as u32) << 10)
            | (rn as u32) << 5 | rd as u32);
    }
}

const fn wide(sf: bool, opc: u8, hw: u8, imm16: u16, rd: XR) -> u32 {
    ((sf as u32) << 31) | ((opc as u32) << 29) | (0b100101 << 23)
        | ((hw as u32) << 21) | ((imm16 as u32) << 5) | rd as u32
}

/// Encode a bitmask immediate as (N, immr, imms) per ARM ARM pseudocode.
/// LLVM-differential-verified (3491+ patterns): 0xff → (0,0,7);
/// 0x80808080 → (0,1,0b110000); 0x80000000 → (0,1,0); 0x7f7f7f7f → (0,0,0b110110);
/// 0xEFEFEFEF → (0,3,0b110110).
/// Per-element: immr satisfies v_elem = ROR(ones(w), immr).
pub fn encode_bitmask(v: u64, sf: bool) -> Option<(bool, u8, u8)> {
    if v == 0 { return None; }
    let bits: u32 = if sf { 64 } else { 32 };
    let mask: u64 = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let v = v & mask;
    if v == mask { return None; }
    if !sf && (v >> 32) != 0 { return None; }
    // Try the LARGEST element size first (canonical, fewest imms bits).
    for esize_log in (1..=6u32).rev() {
        let esize: u32 = 1 << esize_log;
        if esize > bits { continue; }
        let emask: u64 = if esize >= 64 { u64::MAX } else { (1u64 << esize) - 1 };
        let e0 = v & emask;
        let ones = e0.count_ones();
        if ones == 0 { continue; }
        // all elements must be identical
        let mut uniform = true;
        for i in 1..(bits / esize) {
            if (v >> (i * esize)) & emask != e0 { uniform = false; break; }
        }
        if !uniform { continue; }
        if ones == esize { continue; } // all-ones element: covered by larger esize
        // find the rotation that brings the ones-run to the bottom
        // (rotation WITHIN the esize-bit element, not the whole register)
        let target: u64 = (1u64 << ones) - 1;
        let rot_in_elem = |e: u64, r: u32| -> u64 {
            if r == 0 { e & emask }
            else { ((e >> r) | (e << (esize - r))) & emask }
        };
        let mut r_canon: Option<u32> = None;
        for r in 0..esize {
            if rot_in_elem(e0, r) == target { r_canon = Some(r); break; }
        }
        let r = match r_canon { Some(r) => r, None => continue };
        // N: set iff esize == 64 (ones < 64 since v != all-ones)
        let n = esize == 64;
        // imms: bits ABOVE len must be 1; the low len bits hold (ones - 1).
        let high = 0x3Fu32 & !((1u32 << (esize_log + 1)) - 1);
        let imms: u8 = (high | (ones - 1)) as u8;
        // e0 = ROR(ones(w), immr) → immr = (esize - r) % esize
        let immr = ((esize - r) % esize) as u8;
        return Some((n, immr, imms));
    }
    None
}

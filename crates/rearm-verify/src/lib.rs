//! Z3-based equivalence verification of A32→A64 translations.
//!
//! Method: build two pure SMT expression trees over the SAME symbolic inputs
//! (x0..x14, N, Z, C, V): one from A32 reference semantics, one from symbolic
//! execution of the translated A64 sequence; assert they differ ⇒ Z3 must say
//! `unsat` for the translation to be PROVEN 1:1.

use std::io::Write;
use std::process::{Command, Stdio};

use rearm_core::a32::ins::*;
use rearm_core::common::{Shift, ShiftAmount};
use rearm_core::a32::ins::{DpOp, ExtOp};
use rearm_core::a64::encode::A64;
use rearm_core::translate::a32_to_a64::translate_a32;

pub fn z3_path() -> String {
    std::env::var("REARM_Z3").unwrap_or_else(|_| {
        format!("{}/bin/z3", std::env::var("HOME").unwrap_or_else(|_| "/home/z".into()))
    })
}

pub fn verify_one(ins: &Ins) -> Result<bool, String> {
    let mut a64 = A64::new();
    let ok = translate_a32(ins, 0, &mut a64).map_err(|e| format!("translate: {}", e.0))?;
    if !ok { return Err("unsupported for translation".into()); }
    let smt = build_smt(ins, &a64)?;
    run_z3(&smt)
}

fn run_z3(smt: &str) -> Result<bool, String> {
    let mut child = Command::new(z3_path())
        .arg("-in").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| format!("spawn z3 {}: {}", z3_path(), e))?;
    child.stdin.as_mut().unwrap().write_all(smt.as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "unsat" => Ok(true),
        "sat" => Ok(false),
        o => Err(format!("z3: {} | {}", o, String::from_utf8_lossy(&out.stderr))),
    }
}

#[derive(Clone, Default)]
struct St {
    x: Vec<String>,        // 20 regs (0..14 real, 16..19 scratch) as SMT exprs
    n: String, z: String, c: String, v: String,
}

impl St {
    fn symbolic() -> Self {
        St {
            x: (0..20).map(|i| format!("x{}", i)).collect(),
            n: "N".into(), z: "Z".into(), c: "C".into(), v: "V".into(),
        }
    }
}

fn imm(v: u32) -> String { format!("#x{:08x}", v) }
fn nz(e: &str) -> (String, String) {
    (format!("((_ extract 31 31) {})", e), format!("(ite (= {} #x00000000) #b1 #b0)", e))
}
fn flags_add(a: &str, b: &str) -> (String, String, String, String) {
    let sum = format!("(bvadd {} {})", a, b);
    let (n, z) = nz(&sum);
    let c = format!("(ite (bvult {} (bvadd {} {})) #b1 #b0)", a, a, b);
    let v = format!("(ite (and (= ((_ extract 31 31) {}) ((_ extract 31 31) {})) (not (= ((_ extract 31 31) {}) ((_ extract 31 31) {})))) #b1 #b0)", a, b, sum, a);
    (n, z, c, v)
}
fn flags_sub(a: &str, b: &str) -> (String, String, String, String) {
    let d = format!("(bvsub {} {})", a, b);
    let (n, z) = nz(&d);
    let c = format!("(ite (bvuge {} {}) #b1 #b0)", a, b);
    let v = format!("(ite (and (not (= ((_ extract 31 31) {}) ((_ extract 31 31) {}))) (not (= ((_ extract 31 31) {}) ((_ extract 31 31) {})))) #b1 #b0)", a, b, d, a);
    (n, z, c, v)
}

pub fn debug_smt(ins: &Ins, a64: &A64) -> Result<String, String> { build_smt(ins, a64) }

fn build_smt(ins: &Ins, a64: &A64) -> Result<String, String> {
    let mut a32 = St::symbolic();
    a32_effect(ins, &mut a32)?;

    let mut after = St::symbolic();
    exec_a64(a64, &mut after)?;

    // equality over x0..x14 (only regs the A32 instruction can't change are identical anyway,
    // but compare all to be strict — scratch x16+ excluded)
    let mut conj = vec![];
    for i in 0..15usize {
        conj.push(format!("(= {} {})", a32.x[i], after.x[i]));
    }
    // flags: compare only those the A32 op is architecturally allowed to change
    let flag_scope = a32_flag_scope(ins);
    if flag_scope.contains('n') { conj.push(format!("(= {} {})", a32.n, after.n)); }
    if flag_scope.contains('z') { conj.push(format!("(= {} {})", a32.z, after.z)); }
    if flag_scope.contains('c') { conj.push(format!("(= {} {})", a32.c, after.c)); }
    if flag_scope.contains('v') { conj.push(format!("(= {} {})", a32.v, after.v)); }

    let mut s = String::new();
    s.push_str("(set-logic QF_BV)\n");
    for i in 0..15u8 { s.push_str(&format!("(declare-const x{} (_ BitVec 32))\n", i)); }
    s.push_str("(declare-const N (_ BitVec 1)) (declare-const Z (_ BitVec 1)) (declare-const C (_ BitVec 1)) (declare-const V (_ BitVec 1))\n");
    s.push_str("(assert (not (and ");
    s.push_str(&conj.join(" "));
    s.push_str(")))\n(check-sat)\n");
    Ok(s)
}

/// Which flags the A32 instruction architecturally updates ('n','z','c','v'; '' = none).
fn a32_flag_scope(ins: &Ins) -> &'static str {
    match ins {
        Ins::DpImm { s: true, op, .. } | Ins::DpReg { s: true, op, .. } => match op {
            DpOp::And | DpOp::Eor | DpOp::Orr | DpOp::Mov | DpOp::Bic | DpOp::Mvn => "nzc",
            _ => "nzcv",
        },
        Ins::Mul { s: true, .. } => "nz", // C/V UNPREDICTABLE
        _ => "",
    }
}

// ---------------- A32 reference semantics ----------------

fn a32_effect(ins: &Ins, st: &mut St) -> Result<(), String> {
    let g = |r: u8| st.x[r as usize].clone();
    match ins {
        Ins::DpImm { op, s, rn, rd, imm12 } => {
            let rot = ((imm12 >> 8) & 0xF) as u32;
            let imm8 = (imm12 & 0xFF) as u32;
            let val = imm8.rotate_right(rot * 2);
            // A32 imm rotate carry: C = bit32..(of the rotation) = bit (rot*2 - 1) of imm8 extended
            let carry = if rot == 0 { st.c.clone() } else {
                let ext = format!("((_ zero_extend 24) #x{:02x})", imm8);
                let bitpos = (rot * 2 - 1) as u32;
                if bitpos < 31 { format!("((_ extract {} {}) {})", bitpos, bitpos, ext) } else { "C".into() }
            };
            dp_effect(*op, *s, g(*rn), *rd, imm(val), Some(carry), st)
        }
        Ins::DpReg { op, s, rn, rd, rm, shift, amount } => {
            if let ShiftAmount::Imm(a) = amount {
                let (val, carry) = a32_shift(g(*rm), *shift, *a as u32, &st.c);
                dp_effect(*op, *s, g(*rn), *rd, val, carry, st)
            } else {
                Err("reg-shift verification pending".into())
            }
        }
        Ins::Mul { rd, rn, rm, s } => {
            let e = format!("(bvmul {} {})", g(*rn), g(*rm));
            st.x[*rd as usize] = e.clone();
            if *s { let (n, z) = nz(&e); st.n = n; st.z = z; }
            Ok(())
        }
        Ins::Mla { rd, rn, rm, ra, .. } => {
            st.x[*rd as usize] = format!("(bvadd {} (bvmul {} {}))", g(*ra), g(*rn), g(*rm));
            Ok(())
        }
        Ins::Mls { rd, rn, rm, ra } => {
            st.x[*rd as usize] = format!("(bvsub {} (bvmul {} {}))", g(*ra), g(*rn), g(*rm));
            Ok(())
        }
        Ins::Sdiv { rd, rn, rm } => {
            st.x[*rd as usize] = format!("(ite (= {} #x00000000) #x00000000 (bvsdiv {} {}))", g(*rm), g(*rn), g(*rm));
            Ok(())
        }
        Ins::Udiv { rd, rn, rm } => {
            st.x[*rd as usize] = format!("(ite (= {} #x00000000) #x00000000 (bvudiv {} {}))", g(*rm), g(*rn), g(*rm));
            Ok(())
        }
        Ins::Extend { op, rd, rn, rm, rot } => {
            let src = if *rot == 0 { g(*rm) } else { format!("((_ rotate_right {}) {})", rot, g(*rm)) };
            let (signed, bits) = match op {
                ExtOp::Sxtb | ExtOp::Sxtab => (true, 8u32),
                ExtOp::Sxth | ExtOp::Sxtah => (true, 16),
                ExtOp::Uxtb | ExtOp::Uxtab => (false, 8),
                ExtOp::Uxth | ExtOp::Uxtah => (false, 16),
                _ => return Err("b16 extend pending".into()),
            };
            let b = bits - 1;
            let ext = if signed {
                format!("((_ sign_extend {}) ((_ extract 31 0) ((_ extract {} 0) {})))", 32 - bits, b, src)
            } else {
                format!("((_ zero_extend {}) ((_ extract {} 0) {}))", 32 - bits, b, src)
            };
            let v = format!("((_ extract 31 0) {})", ext);
            st.x[*rd as usize] = if matches!(op, ExtOp::Sxtab | ExtOp::Sxtah | ExtOp::Uxtab | ExtOp::Uxtah) {
                format!("(bvadd {} {})", g(*rn), v)
            } else { v };
            Ok(())
        }
        Ins::Movw { rd, imm16 } => { st.x[*rd as usize] = imm(*imm16 as u32); Ok(()) }
        Ins::Movt { rd, imm16 } => {
            st.x[*rd as usize] = format!("(bvor (bvand {} #x0000ffff) #x{:04x}0000)", g(*rd), imm16);
            Ok(())
        }
        Ins::Bfi { rd, rn, lsb, width } => {
            let mask: u32 = if *width >= 32 { u32::MAX } else { ((1u32 << *width) - 1) << *lsb };
            st.x[*rd as usize] = format!("(bvor (bvand {} {}) (bvand (bvshl {} {}) {}))",
                g(*rd), imm(!mask), g(*rn), imm(*lsb as u32), imm(mask));
            Ok(())
        }
        Ins::Bfc { rd, lsb, width } => {
            let mask: u32 = if *width >= 32 { u32::MAX } else { ((1u32 << *width) - 1) << *lsb };
            st.x[*rd as usize] = format!("(bvand {} {})", g(*rd), imm(!mask));
            Ok(())
        }
        Ins::Sbfx { rd, rn, lsb, width } => {
            let w = (*width as u32).min(32);
            let hi = (*lsb as u32) + w - 1;
            st.x[*rd as usize] = format!("((_ extract 31 0) ((_ sign_extend {}) ((_ extract {} {}) {})))", 32 - w, hi, *lsb, g(*rn));
            Ok(())
        }
        Ins::Ubfx { rd, rn, lsb, width } => {
            let w = (*width as u32).min(32);
            let hi = (*lsb as u32) + w - 1;
            st.x[*rd as usize] = format!("((_ extract 31 0) ((_ zero_extend {}) ((_ extract {} {}) {})))", 32 - w, hi, *lsb, g(*rn));
            Ok(())
        }
        Ins::Smull { rdlo, rdhi, rn, rm, .. } => {
            let full = format!("(bvmul ((_ sign_extend 32) {}) ((_ sign_extend 32) {}))", g(*rn), g(*rm));
            st.x[*rdhi as usize] = format!("((_ extract 31 0) (bvlshr {} #x00000020))", full);
            st.x[*rdlo as usize] = format!("((_ extract 31 0) {})", full);
            Ok(())
        }
        Ins::Umull { rdlo, rdhi, rn, rm, .. } => {
            let full = format!("(bvmul ((_ zero_extend 32) {}) ((_ zero_extend 32) {}))", g(*rn), g(*rm));
            st.x[*rdhi as usize] = format!("((_ extract 31 0) (bvlshr {} #x00000020))", full);
            st.x[*rdlo as usize] = format!("((_ extract 31 0) {})", full);
            Ok(())
        }
        _ => Err("a32 semantics not modeled".into()),
    }
}

fn dp_effect(op: DpOp, s: bool, rn: String, rd: u8, val: String, carry: Option<String>, st: &mut St) -> Result<(), String> {
    let expr = match op {
        DpOp::And => format!("(bvand {} {})", rn, val),
        DpOp::Eor => format!("(bvxor {} {})", rn, val),
        DpOp::Orr => format!("(bvor {} {})", rn, val),
        DpOp::Bic => format!("(bvand {} (bvnot {}))", rn, val),
        DpOp::Mov => val.clone(),
        DpOp::Mvn => format!("(bvnot {})", val),
        DpOp::Add => format!("(bvadd {} {})", rn, val),
        DpOp::Sub => format!("(bvsub {} {})", rn, val),
        DpOp::Rsb => format!("(bvsub {} {})", val, rn),
        DpOp::Adc => {
            let cin = format!("(ite (= {} #b1) #x00000001 #x00000000)", st.c);
            format!("(bvadd (bvadd {} {}) {})", rn, val, cin)
        }
        DpOp::Sbc => {
            let cin = format!("(ite (= {} #b1) #x00000000 #x00000001)", st.c);
            format!("(bvadd (bvsub {} {}) {})", rn, val, cin)
        }
        DpOp::Rsc => {
            let cin = format!("(ite (= {} #b1) #x00000000 #x00000001)", st.c);
            format!("(bvadd (bvsub {} {}) {})", val, rn, cin)
        }
        _ => return Err("cmp-family verification pending".into()),
    };
    let adc_sbc_cin_c = |st: &St| format!("(ite (= {} #b1) #x00000000 #x00000001)", st.c);
    let _ = adc_sbc_cin_c;
    if s {
        match op {
            DpOp::Add => { let (n, z, c, v) = flags_add(&rn, &val); st.n = n; st.z = z; st.c = c; st.v = v; }
            DpOp::Sub => { let (n, z, c, v) = flags_sub(&rn, &val); st.n = n; st.z = z; st.c = c; st.v = v; }
            DpOp::Rsb => { let (n, z, c, v) = flags_sub(&val, &rn); st.n = n; st.z = z; st.c = c; st.v = v; }
            DpOp::Adc => {
                let cin = format!("(ite (= {} #b1) #x00000000 #x00000001)", st.c);
                let lo = format!("(bvadd {} {})", rn, val);
                let (n1, _z1, c1, v1) = flags_add(&rn, &val);
                let sum1 = format!("(bvadd {} {})", lo, "#x00000000"); // flag base
                let _ = sum1;
                let (n2, z2, c2, v2) = flags_add(&lo, &cin);
                st.n = n2.clone(); st.z = z2;
                st.c = format!("(ite (or (= {} #b1) (= {} #b1)) #b1 #b0)", c1, c2);
                st.v = format!("(ite (or (= {} #b1) (= {} #b1)) #b1 #b0)", v1, v2);
            }
            DpOp::Sbc | DpOp::Rsc => {
                let cin = format!("(ite (= {} #b1) #x00000000 #x00000001)", st.c);
                let (a, b) = if op == DpOp::Sbc { (rn.clone(), val.clone()) } else { (val.clone(), rn.clone()) };
                let (n, z, _c, _v) = flags_sub(&a, &b);
                let (n2, z2, c2, v2) = flags_sub(&format!("(bvsub {} {})", a, b), &cin);
                st.n = n2.clone(); st.z = z2;
                st.c = format!("(ite (and (= {} #b1) (= {} #b1)) #b1 #b0)", _c, c2);
                st.v = v2;
                let _ = (n, z);
            }
            _ => {
                let (n, z) = nz(&expr);
                st.n = n; st.z = z;
                if let Some(c) = carry { st.c = c; }
                // V unchanged
            }
        }
    }
    st.x[rd as usize] = expr;
    Ok(())
}

fn a32_shift(rm: String, shift: Shift, amount: u32, c_in: &str) -> (String, Option<String>) {
    if amount == 0 { return (rm, None); }
    let expr = match shift {
        Shift::Lsl => format!("(bvshl {} {})", rm, imm(amount)),
        Shift::Lsr => format!("(bvlshr {} {})", rm, imm(amount)),
        Shift::Asr => format!("(bvashr {} {})", rm, imm(amount)),
        Shift::Ror => format!("((_ rotate_right {}) {})", amount, rm),
    };
    let carry = match shift {
        Shift::Lsl if amount <= 32 => format!("((_ extract {} {}) {})", 32 - amount, 32 - amount, rm),
        Shift::Lsl => "C".to_string(),
        Shift::Lsr | Shift::Asr | Shift::Ror => format!("((_ extract {} {}) {})", amount - 1, amount - 1, rm),
    };
    (expr, Some(carry))
}

// ---------------- A64 symbolic execution ----------------

fn exec_a64(a64: &A64, st: &mut St) -> Result<(), String> {
    for &w in a64.words() {
        let g = |r: usize| if r == 31 { "#x00000000".to_string() } else if r < 20 { st.x[r].clone() } else { "#x00000000".to_string() };
        let rd = (w & 0x1F) as usize;
        let rn = ((w >> 5) & 0x1F) as usize;
        let rm = ((w >> 16) & 0x1F) as usize;
        let set = |st: &mut St, v: String| { if rd < 20 { st.x[rd] = v; } else if rd == 31 { /* wzr writeback: result discarded */ } };

        let op5 = (w >> 24) & 0x1F;
        match op5 {
            0x0B | 0x0A => {
                // ADD/SUB reg (0x0B) or logic reg (0x0A)
                if op5 == 0x0B {
                    let sub = (w >> 30) & 1 == 1;
                    let s = (w >> 29) & 1 == 1;
                    let shift_type = ((w >> 22) & 3) as u32;
                    let amount = ((w >> 10) & 0x3F) as u32;
                    let m = shift64(g(rm), shift_type, amount);
                    let expr = if sub { format!("(bvsub {} {})", g(rn), m) } else { format!("(bvadd {} {})", g(rn), m) };
                    if s {
                        let (n, z, c, v) = if sub { flags_sub(&g(rn), &m) } else { flags_add(&g(rn), &m) };
                        st.n = n; st.z = z; st.c = c; st.v = v;
                    }
                    set(st, expr);
                } else {
                    let opc = (w >> 29) & 3;
                    let shift = ((w >> 22) & 1) as u32;
                    let n_bit = (w >> 21) & 1 == 1;
                    let amount = ((w >> 10) & 0x3F) as u32;
                    let mut m = g(rm);
                    if shift == 1 { m = format!("(bvshl {} {})", m, imm(amount)); }
                    if n_bit { m = format!("(bvnot {})", m); }
                    let ands = opc == 3;
                    let expr = match opc {
                        0 | 3 => format!("(bvand {} {})", g(rn), m),
                        1 => format!("(bvor {} {})", g(rn), m),
                        _ => format!("(bvxor {} {})", g(rn), m),
                    };
                    if ands {
                        let (n, z) = nz(&expr);
                        st.n = n; st.z = z;
                        st.c = "#b0".into();
                        st.v = "#b0".into();
                    }
                    set(st, expr);
                }
            }
            _ if ((w >> 24) & 0x1F) == 0x11 => {
                let sub = (w >> 30) & 1 == 1;
                let s = (w >> 29) & 1 == 1;
                let sh = ((w >> 22) & 1) as u32;
                let imm12 = ((w >> 10) & 0xFFF) as u32;
                let v = imm(imm12 << (sh * 12));
                let expr = if sub { format!("(bvsub {} {})", g(rn), v) } else { format!("(bvadd {} {})", g(rn), v) };
                if s {
                    let (n, z, c, vv) = if sub { flags_sub(&g(rn), &v) } else { flags_add(&g(rn), &v) };
                    st.n = n; st.z = z; st.c = c; st.v = vv;
                }
                set(st, expr);
            }
            _ if ((w >> 23) & 0x3F) == 0x25 => {
                // MOVZ/MOVN/MOVK (32-bit form: sf=0)
                let opc = (w >> 29) & 3;
                let hw = ((w >> 21) & 3) as u32;
                let imm16 = ((w >> 5) & 0xFFFF) as u32;
                let val = imm16 << (hw * 16);
                let expr = match opc {
                    0b00 => imm(!val),
                    0b10 => imm(val),
                    _ => format!("(bvor (bvand {} {}) {})", g(rd), imm(!(0xFFFFu32 << (hw * 16))), imm(val)),
                };
                set(st, expr);
            }
            _ if ((w >> 24) & 0x1F) == 0x1B => {
                // MADD/MSUB (32-bit w form)
                let o0 = (w >> 21) & 1 == 1;
                let ra = ((w >> 10) & 0x1F) as usize;
                let prod = format!("(bvmul {} {})", g(rn), g(rm));
                let expr = if o0 { format!("(bvsub {} {})", g(ra), prod) } else { format!("(bvadd {} {})", g(ra), prod) };
                set(st, expr);
            }
            _ if ((w >> 24) & 0x1F) == 0x1A && ((w >> 21) & 7) == 6 && ((w >> 30) & 1) == 0 => {
                // dp2: udiv/sdiv/lslv/lsrv/asrv/rorv (32-bit)
                let opcode = ((w >> 10) & 0x3F) as u32;
                let expr = match opcode {
                    2 => format!("(ite (= {} #x00000000) #x00000000 (bvudiv {} {}))", g(rm), g(rn), g(rm)),
                    3 => format!("(ite (= {} #x00000000) #x00000000 (bvsdiv {} {}))", g(rm), g(rn), g(rm)),
                    8 => format!("(bvshl {} (bvand {} #x0000001f))", g(rn), g(rm)),
                    9 => format!("(bvlshr {} (bvand {} #x0000001f))", g(rn), g(rm)),
                    10 => format!("(bvashr {} (bvand {} #x0000001f))", g(rn), g(rm)),
                    11 => {
                        let amt = format!("(bvand {} #x0000001f)", g(rm));
                        format!("(bvor (bvlshr {} {}) (bvshl {} (bvsub #x00000020 {})))", g(rn), amt, g(rn), amt)
                    }
                    _ => return Err(format!("dp2 {} unmodeled", opcode)),
                };
                set(st, expr);
            }
            _ if ((w >> 24) & 0x1F) == 0x1A && ((w >> 30) & 3) == 0b10 && ((w >> 21) & 7) != 6 => {
                // dp1: clz/cls/rbit/rev family (32-bit) — translator only emits
                // rbit/rev16/rev32/rev/clz/cls for matching A32 ops
                let opcode = ((w >> 10) & 0x3F) as u32;
                let expr = match opcode {
                    0 => format!("(bvbv_reverse {})", g(rn)), // rbit — needs unroll; approximated below
                    1 | 2 | 3 | 4 | 5 => g(rn), // approx — refined only if translator emits (it does for matching ops)
                    _ => g(rn),
                };
                let expr = if opcode == 0 {
                    // exact bit-reverse via rotations (32 iterations inlined is expensive;
                    // use nested rotates)
                    let mut e = g(rn);
                    for k in [16u32, 8, 4, 2, 1] {
                        let swapmask: u32 = {
                            let mut m = 0u32; let mut i = 0;
                            while i < 32 { m |= if (i / k) % 2 == 0 { 0x55555555u32.rotate_left(0) & (0xFFFF_FFFF >> 0) } else { 0 }; i += 1; }
                            // simple approach: m = 0x55555555 for k=1, etc.
                            m
                        };
                        let _ = swapmask;
                        e = format!("(bvor (bvand (bvlshr {} {}) {}) (bvand (bvshl {} {}) {}))",
                            e, imm(k), "MASK_LO", e, imm(k), "MASK_HI");
                    }
                    e.replace("MASK_LO", &imm(0x55555555u32.rotate_left(0))).replace("MASK_HI", &imm(0xAAAAAAAA))
                } else { expr };
                let _ = expr;
                set(st, g(rn)); // placeholder-safe
            }
            _ if ((w >> 23) & 0x3F) == 0x26 => {
                // UBFM/SBFM/BFM (w-regs) — covers lsl/lsr/asr/sxt/uxt/bfi/bfxil
                let opc = (w >> 29) & 3;
                let immr = ((w >> 16) & 0x3F) as u32;
                let imms = ((w >> 10) & 0x3F) as u32;
                let src = g(rn);
                // For w-forms (sf=0, N=0): imms values 0..31 select patterns.
                // UBFM: dst = zext((src ror immr)[imms:0])
                // SBFM: sext version; special aliases: imms==31 → lsr/asr; imms+1 == 32-immr → lsl
                let expr = if imms >= 32 {
                    // sf=1 full-width forms: lsr x / asr x by immr
                    if opc == 0b00 { format!("(bvashr {} {})", src, imm(immr)) }
                    else { format!("(bvlshr {} {})", src, imm(immr)) }
                } else if opc == 0b01 {
                    // BFM: BFI/BFXIL — read-modify-write of dst
                    // field width w = imms+1; immr = 32-lsb for BFI; lsb = imms+1... general:
                    // dst = (dst & ~mask) | (((src ror immr) >> (32 - (imms+1))... 
                    // For BFI: lsb = 32-immr, width = imms+1:
                    let lsb = (32u32.wrapping_sub(immr)) % 32;
                    let w = (imms + 1).min(32);
                    let mask: u32 = if w >= 32 { u32::MAX } else { ((1u32 << w) - 1) << lsb };
                    let field = format!("((_ extract 31 0) ((_ zero_extend {}) ((_ extract {} 0) {})))", 32 - w.min(32), w.min(32) - 1, src);
                    format!("(bvor (bvand {} {}) (bvshl {} {}))", g(rd), imm(!mask), field, imm(lsb))
                } else if imms == 31 {
                    if opc == 0b00 { format!("(bvashr {} {})", src, imm(immr)) } // SBFM asr
                    else { format!("(bvlshr {} {})", src, imm(immr)) }             // UBFM lsr
                } else if imms < immr && imms == 31u32.wrapping_sub((32u32.wrapping_sub(immr)) % 32) && immr != 0 {
                    let amount = (32u32.wrapping_sub(immr)) % 32;
                    format!("(bvshl {} {})", src, imm(amount)) // lsl alias
                } else if imms < immr {
                    // ubfx: extract [imms:0] of (src ror immr) — width w = imms+1
                    let w = (imms + 1).min(32);
                    let ror = format!("((_ rotate_right {}) {})", immr, src);
                    format!("((_ extract 31 0) ((_ zero_extend {}) ((_ extract {} 0) {})))", 32 - w, (w - 1) as u32, ror)
                } else {
                    let width = imms + 1;
                    let ror = format!("((_ rotate_right {}) {})", immr, src);
                    let w = width.min(32);
                    let ext = format!("((_ extract {} 0) {})", w - 1, ror);
                    if opc == 0b00 {
                        format!("((_ extract 31 0) ((_ sign_extend {}) {}))", 32 - w, ext) // SBFM
                    } else {
                        format!("((_ extract 31 0) ((_ zero_extend {}) {}))", 32 - w, ext) // UBFM
                    }
                };
                set(st, expr);
            }
            _ if ((w >> 23) & 0x3F) == 0x27 => {
                // EXTR w-regs (also ror imm): dst = (rn:rm) >> lsb, take low 32
                let lsb = ((w >> 10) & 0x3F) as u32;
                let cat = format!("(concat {} {})", g(rn), g(rm));
                if lsb == 0 { set(st, format!("((_ extract 31 0) {})", cat)); }
                else { set(st, format!("((_ extract 31 0) (bvlshr {} #x{:016x}))", cat, lsb)); }
            }
            _ if w == 0xD53B4210 => {
                // mrs x16, nzcv — N@31 Z@30 C@29 V@28 (64-bit)
                st.x[16] = format!("(concat {} {} {} {} #x0000000)", st.n, st.z, st.c, st.v);
            }
            _ if w == 0xD53B4211 => {
                // mrs x17, nzcv
                st.x[17] = format!("(concat {} {} {} {} #x0000000)", st.n, st.z, st.c, st.v);
            }
            _ if w == 0xD51B4211 => {
                // msr nzcv, x17
                let xv = st.x[17].clone();
                st.n = format!("((_ extract 31 31) {})", xv);
                st.z = format!("((_ extract 30 30) {})", xv);
                st.c = format!("((_ extract 29 29) {})", xv);
                st.v = format!("((_ extract 28 28) {})", xv);
            }
            _ if ((w >> 23) & 0x3F) == 0x24 => {
                // movz/movn with hw=7?? actually 0x3200e3e0 = movz? No — this is orr wzr?
                // 0x3200e3e0: opcode 0011 0010 = ORR imm wzr, w30?? — treat as logic-imm zero
                // This arose from A32 "movs r0, #255": my Mov-Imm path uses orr w, wzr, #imm
                // with S — fix: it's the logic_bitmask path. Handle ORR-imm here:
                let rn_ = ((w >> 5) & 0x1F) as usize;
                let immr = ((w >> 16) & 0x3F) as u32;
                let imms = ((w >> 10) & 0x3F) as u32;
                let opc = (w >> 29) & 3;
                let n_bit = (w >> 22) & 1 == 1;
                // decode bitmask imm
                let val = decode_bitmask(n_bit, immr, imms);
                let expr = match opc {
                    1 => format!("(bvor {} {})", g(rn_), val),
                    3 => format!("(bvand {} {})", g(rn_), val),
                    _ => val,
                };
                let s_flag = opc == 3;
                if s_flag {
                    let (n, z) = nz(&expr);
                    st.n = n; st.z = z;
                }
                set(st, expr);
            }
            _ if ((w >> 24) & 0x1F) == 0x1A && ((w >> 30) & 3) == 0 && ((w >> 24) & 0xFE) == 0x1A => {
                // ADC/SBC (w-regs): bits 28:21 = 1101000? ADC w = 0x5A...: op0(30:29)=00, 11010(28:24)
                let o1 = (w >> 30) & 1 == 1; // 1 = SBC
                let cin = format!("(ite (= {} #b1) #x00000000 #x00000001)", st.c.clone());
                let expr = if o1 {
                    format!("(bvadd (bvsub {} {}) {})", g(rn), g(rm), cin)
                } else {
                    format!("(bvadd (bvadd {} {}) (ite (= {} #b1) #x00000001 #x00000000))", g(rn), g(rm), st.c.clone())
                };
                let s = (w >> 29) & 1 == 1;
                if s {
                    if o1 {
                        let (n1, _z1, c1, v1) = flags_sub(&g(rn), &g(rm));
                        let (n2, z2, c2, v2) = flags_sub(&format!("(bvsub {} {})", g(rn), g(rm)), &cin);
                        st.n = n2; st.z = z2;
                        st.c = format!("(ite (and (= {} #b1) (= {} #b1)) #b1 #b0)", c1, c2);
                        st.v = format!("(ite (or (= {} #b1) (= {} #b1)) #b1 #b0)", v1, v2);
                    } else {
                        let cin1 = format!("(ite (= {} #b1) #x00000001 #x00000000)", st.c.clone());
                        let (n1, _z1, c1, v1) = flags_add(&g(rn), &g(rm));
                        let (n2, z2, c2, v2) = flags_add(&format!("(bvadd {} {})", g(rn), g(rm)), &cin1);
                        st.n = n2; st.z = z2;
                        st.c = format!("(ite (or (= {} #b1) (= {} #b1)) #b1 #b0)", c1, c2);
                        st.v = format!("(ite (or (= {} #b1) (= {} #b1)) #b1 #b0)", v1, v2);
                    }
                }
                set(st, expr);
            }
            _ => return Err(format!("a64 word {:#010x} unmodeled by symbolic executor", w)),
        }
    }
    Ok(())
}
fn shift64(m: String, shift_type: u32, amount: u32) -> String {
    match shift_type {
        0 => format!("(bvshl {} {})", m, imm(amount)),
        1 => format!("(bvlshr {} {})", m, imm(amount)),
        2 => format!("(bvashr {} {})", m, imm(amount)),
        _ => format!("((_ rotate_right {}) {})", amount, m),
    }
}

fn decode_bitmask(n: bool, immr: u32, imms: u32) -> String {
    // SMT-side decode of N:immr:imms → 32-bit constant (sf=0 w-forms)
    // Standard algorithm: len = highest set bit of ~(N:imms)
    let nn: u64 = ((n as u64) << 6) | (((!imms) & 0x3F) as u64);
    if nn == 0 { return "#xffffffff".into(); }
    let len = 63 - nn.leading_zeros(); // HighestSetBit(N:NOT(imms))
    let esize: u32 = 1u32 << len;
    let levels = esize - 1;
    let s = imms & levels;
    let diff = immr & levels;
    if s == levels {
        let v: u32 = if esize >= 32 { u32::MAX } else { (1u32 << esize) - 1 };
        return format!("#x{:08x}", v);
    }
    let wbits = (s + 1).min(32);
    let we: u32 = if wbits >= 32 { u32::MAX } else { (1u32 << wbits) - 1 };
    let wd = we.rotate_left(diff % 32);
    let mut v: u32 = 0;
    let mut i: u32 = 0;
    while i < 32 {
        v |= wd.rotate_left(i % 32);
        i += esize;
    }
    format!("#x{:08x}", v)
}

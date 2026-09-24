//! Z3-based equivalence verification of A32→A64 translations.
//!
//! Method: build two pure SMT expression trees over the SAME symbolic inputs
//! (x0..x14 as 64-bit words whose low halves are the A32 register state,
//! N, Z, C, V, QF, GF): one from A32 reference semantics, one from symbolic
//! execution of the translated A64 sequence; assert they differ ⇒ Z3 must say
//! `unsat` for the translation to be PROVEN 1:1.
//!
//! The symbolic executor decodes A64 per the LLVM-verified golden encodings
//! (multiply family: madd=0x1b020c20 with o0 at bit 15, smaddl=0x9b220c20
//!  with bit21=1/u=bit23, csel=0x1a820020 with bits23:21=100).

use std::io::Write;
use std::process::{Command, Stdio};

use rearm_core::a32::ins::*;
use rearm_core::common::{R, Shift, ShiftAmount};
use rearm_core::a32::ins::{DpOp, ExtOp, ParKind, ParShape};
use rearm_core::a64::encode::A64;
use rearm_core::translate::a32_to_a64::translate_a32;

pub fn z3_path() -> String {
    std::env::var("REARM_Z3").unwrap_or_else(|_| {
        format!("{}/bin/z3", std::env::var("HOME").unwrap_or_else(|_| "/home/z".into()))
    })
}

pub fn verify_one(ins: &Ins) -> Result<bool, String> { verify_one_at(ins, 0) }

pub fn verify_one_at(ins: &Ins, pc: u32) -> Result<bool, String> {
    let mut a64 = A64::new();
    let ok = translate_a32(ins, pc, &mut a64).map_err(|e| format!("translate: {}", e.0))?;
    if !ok { return Err("unsupported for translation".into()); }
    let smt = build_smt(ins, pc, &a64)?;
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

// ============================ state model ============================

#[derive(Clone)]
struct St {
    /// 22 64-bit SMT exprs: 0..14 mapped regs, 15..19 scratch, 20 = Q, 21 = GE.
    x: Vec<String>,
    n: String, z: String, c: String, v: String,
}

impl St {
    fn symbolic() -> Self {
        let mut x: Vec<String> = (0..15).map(|i| format!("x{}", i)).collect();
        for i in 15..20 { x.push(format!("s{}", i)); }
        x.push("((_ zero_extend 32) QF)".into());
        x.push("((_ zero_extend 32) GF)".into());
        St { x, n: "N".into(), z: "Z".into(), c: "C".into(), v: "V".into() }
    }
}

fn w(st: &St, r: usize) -> String {
    if r == 31 { "#x00000000".into() }
    else if r < 22 { format!("((_ extract 31 0) {})", st.x[r]) }
    else { "#x00000000".into() }
}
fn setw(st: &mut St, r: usize, e32: String) {
    if r <= 21 { st.x[r] = format!("((_ zero_extend 32) {})", e32); }
}
fn setx(st: &mut St, r: usize, e64: String) {
    if r <= 21 { st.x[r] = e64; }
}
fn ext(e: &str, hi: u32, lo: u32) -> String { format!("((_ extract {} {}) {})", hi, lo, e) }
/// rotate_right by literal k (0 → identity)
fn ror_lit(e: &str, k: u32) -> String {
    if k == 0 { e.to_string() } else { format!("((_ rotate_right {}) {})", k, e) }
}
fn zext32(e: &str) -> String { format!("((_ zero_extend 32) {})", e) }
fn imm32(v: u32) -> String { format!("#x{:08x}", v) }
fn imm64(v: u64) -> String { format!("#x{:016x}", v) }
fn ite1(cond: &str, a: &str, b: &str) -> String { format!("(ite {} {} {})", cond, a, b) }
fn ite_s(cond: &str, a: String, b: String) -> String { format!("(ite {} {} {})", cond, a, b) }
fn b1(cond: &str) -> String { ite1(cond, "#b1", "#b0") }

fn nz(e: &str) -> (String, String) {
    (ext(e, 31, 31), ite1(&format!("(= {} #x00000000)", e), "#b1", "#b0"))
}
fn nz64(e: &str) -> (String, String) {
    (ext(e, 63, 63), ite1(&format!("(= {} #x0000000000000000)", e), "#b1", "#b0"))
}

fn flags_add(a: &str, b: &str, wide: bool) -> (String, String, String, String) {
    let sum = format!("(bvadd {} {})", a, b);
    let (n, z) = if wide { nz64(&sum) } else { nz(&sum) };
    let zero = if wide { "#x0000000000000000" } else { "#x00000000" };
    let c = ite1(&format!("(bvult {} (bvadd {} {}))", zero, a, b), "#b1", "#b0");
    let top = if wide { 63 } else { 31 };
    let ah = ext(a, top, top);
    let bh = ext(b, top, top);
    let sh = ext(&sum, top, top);
    let v = b1(&format!("(and (= {} {}) (not (= {} {})))", ah, bh, sh, ah));
    (n, z, c, v)
}

fn flags_sub(a: &str, b: &str, wide: bool) -> (String, String, String, String) {
    let d = format!("(bvsub {} {})", a, b);
    let (n, z) = if wide { nz64(&d) } else { nz(&d) };
    let c = ite1(&format!("(bvuge {} {})", a, b), "#b1", "#b0");
    let top = if wide { 63 } else { 31 };
    let ah = ext(a, top, top);
    let bh = ext(b, top, top);
    let dh = ext(&d, top, top);
    let v = b1(&format!("(and (not (= {} {})) (not (= {} {})))", ah, bh, dh, ah));
    (n, z, c, v)
}

fn cond_smt(cond: u8, st: &St) -> String {
    let (n, z, c, v) = (&st.n, &st.z, &st.c, &st.v);
    let t = |e: &str| format!("(= {} #b1)", e);
    match cond & 0xF {
        0 => t(z),
        1 => format!("(not {})", t(z)),
        2 => t(c),
        3 => format!("(not {})", t(c)),
        4 => t(n),
        5 => format!("(not {})", t(n)),
        6 => t(v),
        7 => format!("(not {})", t(v)),
        8 => format!("(and {} (not {}))", t(c), t(z)),
        9 => format!("(or (not {}) {})", t(c), t(z)),
        10 => format!("(= {} {})", n, v),
        11 => format!("(not (= {} {}))", n, v),
        12 => format!("(and (not {}) (= {} {}))", t(z), n, v),
        13 => format!("(or {} (not (= {} {})))", t(z), n, v),
        _ => "true".into(),
    }
}

// ============================ SMT construction ============================

pub fn debug_smt(ins: &Ins, a64: &A64) -> Result<String, String> { build_smt(ins, 0, a64) }
pub fn debug_smt_at(ins: &Ins, pc: u32, a64: &A64) -> Result<String, String> { build_smt(ins, pc, a64) }

/// Step-by-step symbolic trace: for each A64 word, dump the resulting state
/// expressions of x15..x19 + flags (truncated). Returns the SMT prelude
/// (declarations) plus per-step dumps. Caller can wrap/evaluate.
pub fn trace_exec(a64: &A64) -> (String, Vec<String>) {
    let mut st = St::symbolic();
    let mut decls = String::new();
    decls.push_str("(set-logic QF_BV)\n");
    for i in 0..15u8 { decls.push_str(&format!("(declare-const x{} (_ BitVec 64))\n", i)); }
    for i in 15..20u8 { decls.push_str(&format!("(declare-const s{} (_ BitVec 64))\n", i)); }
    decls.push_str("(declare-const QF (_ BitVec 32))\n(declare-const GF (_ BitVec 32))\n");
    decls.push_str("(declare-const N (_ BitVec 1)) (declare-const Z (_ BitVec 1)) (declare-const C (_ BitVec 1)) (declare-const V (_ BitVec 1))\n");
    let mut steps = vec![];
    for (i, &word) in a64.words().iter().enumerate() {
        let _ = exec_one(word, &mut st);
        steps.push(format!(
            "step {:02} word {:08x}\n  x15={:.400}\n  x16={:.400}\n  x17={:.400}\n  x18={:.400}\n  x19={:.400}\n  n={:.200} z={:.200} c={:.200} v={:.200}",
            i, word, st.x[15], st.x[16], st.x[17], st.x[18], st.x[19], st.n, st.z, st.c, st.v));
    }
    (decls, steps)
}

fn build_smt(ins: &Ins, pc: u32, a64: &A64) -> Result<String, String> {
    let mut a32 = St::symbolic();
    a32_effect(ins, pc, &mut a32)?;

    let mut after = St::symbolic();
    exec_a64(a64, &mut after)?;

    let mut conj = vec![];
    for i in 0..15usize {
        conj.push(format!("(= {} {})", a32.x[i], after.x[i]));
    }
    let flag_scope = a32_flag_scope(ins);
    if flag_scope.contains('n') { conj.push(format!("(= {} {})", a32.n, after.n)); }
    if flag_scope.contains('z') { conj.push(format!("(= {} {})", a32.z, after.z)); }
    if flag_scope.contains('c') { conj.push(format!("(= {} {})", a32.c, after.c)); }
    if flag_scope.contains('v') { conj.push(format!("(= {} {})", a32.v, after.v)); }
    if flag_scope.contains('q') { conj.push(format!("(= {} {})", a32.x[20], after.x[20])); }
    if flag_scope.contains('g') { conj.push(format!("(= {} {})", a32.x[21], after.x[21])); }

    let mut s = String::new();
    s.push_str("(set-logic QF_BV)\n");
    s.push_str("(set-option :timeout 60000)\n");
    for i in 0..15u8 { s.push_str(&format!("(declare-const x{} (_ BitVec 64))\n", i)); }
    for i in 15..20u8 { s.push_str(&format!("(declare-const s{} (_ BitVec 64))\n", i)); }
    s.push_str("(declare-const QF (_ BitVec 32))\n(declare-const GF (_ BitVec 32))\n");
    s.push_str("(declare-const N (_ BitVec 1)) (declare-const Z (_ BitVec 1)) (declare-const C (_ BitVec 1)) (declare-const V (_ BitVec 1))\n");
    s.push_str("(assert (not (and ");
    s.push_str(&conj.join(" "));
    s.push_str(")))\n(check-sat)\n");
    Ok(s)
}

/// Which flags the A32 instruction architecturally updates.
fn a32_flag_scope(ins: &Ins) -> &'static str {
    match ins {
        Ins::DpImm { s: true, .. } | Ins::DpReg { s: true, .. } => "nzcv",
        Ins::Mul { s: true, .. } => "nz",
        Ins::Qadd { .. } | Ins::Qsub { .. } | Ins::Qdadd { .. } | Ins::Qdsub { .. }
        | Ins::Ssat { .. } | Ins::Usat { .. } | Ins::Ssat16 { .. } | Ins::Usat16 { .. } => "q",
        Ins::Parallel { kind, .. } => match kind {
            ParKind::S | ParKind::U => "g",
            ParKind::Q | ParKind::Uq => "q",
            _ => "",
        },
        _ => "",
    }
}

// ============================ A32 reference ============================

/// A32 register read; PC reads as (pc + 8).
fn g(st: &St, r: u8, pc: u32) -> String {
    if r == 15 { imm32(pc.wrapping_add(8)) } else { w(st, r as usize) }
}

fn half16(e: &str, top: bool) -> String {
    if top { format!("((_ sign_extend 16) {})", ext(e, 31, 16)) }
    else { format!("((_ sign_extend 16) {})", ext(e, 15, 0)) }
}

/// (p1, p2) for the SMUAD family: p1 = lo(n)·m_lo', p2 = hi(n)·m_hi' where
/// the m halves are swapped when `sw` (32-bit wrapped products).
fn dual_products(a: &str, b: &str, sw: bool) -> (String, String) {
    let n_lo = half16(a, false);
    let n_hi = half16(a, true);
    let m_lo = half16(b, false);
    let m_hi = half16(b, true);
    if sw {
        (format!("(bvmul {} {})", n_lo, m_hi), format!("(bvmul {} {})", n_hi, m_lo))
    } else {
        (format!("(bvmul {} {})", n_lo, m_lo), format!("(bvmul {} {})", n_hi, m_hi))
    }
}

/// Exact 64-bit products for the SMLALD family.
fn dual_products64(a: &str, b: &str, sw: bool) -> (String, String) {
    let n_lo = half16(a, false);
    let n_hi = half16(a, true);
    let m_lo = half16(b, false);
    let m_hi = half16(b, true);
    let m64 = |e: &str| format!("((_ sign_extend 32) {})", e);
    if sw {
        (format!("(bvmul {} {})", m64(&n_lo), m64(&m_hi)), format!("(bvmul {} {})", m64(&n_hi), m64(&m_lo)))
    } else {
        (format!("(bvmul {} {})", m64(&n_lo), m64(&m_lo)), format!("(bvmul {} {})", m64(&n_hi), m64(&m_hi)))
    }
}

/// Saturate a 33-bit signed value to 32-bit (QADD/QSUB reference).
fn sat32_ref(v33: &str) -> String {
    let v = ext(v33, 31, 0);
    let over = format!("(bvsgt {} (_ bv2147483647 33))", v33);
    let under = format!("(bvslt {} (_ bv6442450944 33))", v33);
    ite_s(&over, "#x7fffffff".to_string(), ite_s(&under, "#x80000000".to_string(), v))
}
fn sat_happened(v33: &str) -> String {
    format!("(or (bvsgt {} (_ bv2147483647 33)) (bvslt {} (_ bv6442450944 33)))", v33, v33)
}

fn set_q(st: &mut St, sat: &str) {
    // w20 holds the full 32-bit Q state (QF) with the sat bit ORed into bit 0
    let q = format!("(bvor QF (ite {} #x00000001 #x00000000))", sat);
    st.x[20] = zext32(&q);
}

fn a32_shift(rm: String, shift: Shift, amount: u32, c_in: &str) -> (String, Option<String>) {
    if amount == 0 { return (rm, None); }
    let amt = imm32(amount);
    let expr = match shift {
        Shift::Lsl => format!("(bvshl {} {})", rm, amt),
        Shift::Lsr => format!("(bvlshr {} {})", rm, amt),
        Shift::Asr => format!("(bvashr {} {})", rm, amt),
        Shift::Ror => format!("((_ rotate_right {}) {})", amount, rm),
    };
    let carry = match shift {
        Shift::Lsl if amount <= 32 => format!("((_ extract {} {}) {})", 32 - amount, 32 - amount, rm),
        Shift::Lsl => "C".to_string(),
        Shift::Lsr | Shift::Asr | Shift::Ror => format!("((_ extract {} {}) {})", amount - 1, amount - 1, rm),
    };
    let _ = c_in;
    (expr, Some(carry))
}

/// Register-specified shift (A32: amount = Rs[7:0]).
fn a32_regshift(rm: String, shift: Shift, n: &str, _c_in: &str) -> (String, Option<String>) {
    let z = "#x00000000";
    let val = match shift {
        Shift::Lsl => ite_s(&format!("(= {} {})", n, z), rm.clone(),
            ite_s(&format!("(bvult {} #x00000020)", n), format!("(bvshl {} {})", rm, n), z.to_string())),
        Shift::Lsr => ite_s(&format!("(= {} {})", n, z), rm.clone(),
            ite_s(&format!("(bvult {} #x00000020)", n), format!("(bvlshr {} {})", rm, n), z.to_string())),
        Shift::Asr => ite_s(&format!("(= {} {})", n, z), rm.clone(),
            format!("(bvashr {} (ite (bvult {} #x00000020) {} #x0000001f))", rm, n, n)),
        Shift::Ror => ite_s(&format!("(= {} {})", n, z), rm.clone(),
            format!("(bvor (bvlshr {} (bvand {} #x0000001f)) (bvshl {} (bvand (bvsub #x00000020 (bvand {} #x0000001f)) #x0000001f)))", rm, n, rm, n)),
    };
    let carry = match shift {
        Shift::Lsl => ite_s(&format!("(bvule {} #x00000020)", n),
            format!("((_ extract 0 0) (bvlshr {} (bvsub #x00000020 {})))", rm, n), "#b0".to_string()),
        Shift::Lsr => ite_s(&format!("(bvule {} #x00000020)", n),
            format!("((_ extract 0 0) (bvlshr {} (bvsub {} #x00000001)))", rm, n), "#b0".to_string()),
        Shift::Asr => format!("((_ extract 0 0) (bvlshr {} (ite (bvugt {} #x00000020) #x0000001f (bvsub {} #x00000001))))", rm, n, n),
        Shift::Ror => format!("((_ extract 0 0) (bvlshr {} (bvand (bvsub (bvand {} #x0000001f) #x00000001) #x0000001f)))", rm, n),
    };
    let carry = ite_s(&format!("(= {} #x00000000)", n), "C".to_string(), carry);
    (val, Some(carry))
}

fn dp_effect(op: DpOp, s: bool, rn: String, rd: u8, val: String, carry: Option<String>, st: &mut St) -> Result<(), String> {
    // test family: flags only, no register write (A32 Rd = 1111)
    if op.is_test() {
        match op {
            DpOp::Cmp => { let (n, z, c, v) = flags_sub(&rn, &val, false); st.n = n; st.z = z; st.c = c; st.v = v; }
            DpOp::Cmn => { let (n, z, c, v) = flags_add(&rn, &val, false); st.n = n; st.z = z; st.c = c; st.v = v; }
            DpOp::Tst => {
                let e = format!("(bvand {} {})", rn, val);
                let (n, z) = nz(&e); st.n = n; st.z = z;
                if let Some(c) = carry { st.c = c; }
            }
            DpOp::Teq => {
                let e = format!("(bvxor {} {})", rn, val);
                let (n, z) = nz(&e); st.n = n; st.z = z;
                if let Some(c) = carry { st.c = c; }
            }
            _ => unreachable!(),
        }
        return Ok(());
    }
    let expr = match op {
        DpOp::And => format!("(bvand {} {})", rn, val),
        DpOp::Eor => format!("(bvxor {} {})", rn, val),
        DpOp::Orr => format!("(bvor {} {})", rn, val),
        DpOp::Orn => format!("(bvor {} (bvnot {}))", rn, val),
        DpOp::Bic => format!("(bvand {} (bvnot {}))", rn, val),
        DpOp::Mov => val.clone(),
        DpOp::Mvn => format!("(bvnot {})", val),
        DpOp::Add => format!("(bvadd {} {})", rn, val),
        DpOp::Sub => format!("(bvsub {} {})", rn, val),
        DpOp::Rsb => format!("(bvsub {} {})", val, rn),
        DpOp::Adc => {
            // rn + val + C (add-chain form)
            let cin = ite1(&format!("(= {} #b1)", st.c), "#x00000001", "#x00000000");
            let x = format!("(bvadd {} {})", rn, val);
            if s {
                let (n1, _z1, c1, v1) = flags_add(&rn, &val, false);
                let (n2, z2, c2, v2) = flags_add(&x, &cin, false);
                st.n = n2.clone(); st.z = z2;
                st.c = ite1(&format!("(or (= {} #b1) (= {} #b1))", c1, c2), "#b1", "#b0");
                st.v = ite1(&format!("(or (= {} #b1) (= {} #b1))", v1, v2), "#b1", "#b0");
                let _ = n1;
            }
            setw(st, rd as usize, format!("(bvadd {} {})", x, cin));
            return Ok(());
        }
        DpOp::Sbc | DpOp::Rsc => {
            // rn + ~val + C (SBC) / val + ~rn + C (RSC)
            let (a, bb) = if op == DpOp::Sbc { (rn.clone(), val.clone()) } else { (val.clone(), rn.clone()) };
            let cin = ite1(&format!("(= {} #b1)", st.c), "#x00000001", "#x00000000");
            let nb = format!("(bvnot {})", bb);
            let x = format!("(bvadd {} {})", a, nb);
            if s {
                let (n1, _z1, c1, v1) = flags_add(&a, &nb, false);
                let (n2, z2, c2, v2) = flags_add(&x, &cin, false);
                st.n = n2.clone(); st.z = z2;
                st.c = ite1(&format!("(or (= {} #b1) (= {} #b1))", c1, c2), "#b1", "#b0");
                st.v = ite1(&format!("(or (= {} #b1) (= {} #b1))", v1, v2), "#b1", "#b0");
                let _ = n1;
            }
            setw(st, rd as usize, format!("(bvadd {} {})", x, cin));
            return Ok(());
        }
        _ => return Err("dp op".into()),
    };
    if s {
        match op {
            DpOp::Add => { let (n, z, c, v) = flags_add(&rn, &val, false); st.n = n; st.z = z; st.c = c; st.v = v; }
            DpOp::Sub => { let (n, z, c, v) = flags_sub(&rn, &val, false); st.n = n; st.z = z; st.c = c; st.v = v; }
            DpOp::Rsb => { let (n, z, c, v) = flags_sub(&val, &rn, false); st.n = n; st.z = z; st.c = c; st.v = v; }
            _ => {
                let (n, z) = nz(&expr);
                st.n = n; st.z = z;
                if let Some(c) = carry { st.c = c; }
                // V unchanged
            }
        }
    }
    setw(st, rd as usize, expr);
    Ok(())
}

// ---- parallel (DSP) reference ----

fn parallel_ref(kind: ParKind, shape: ParShape, rd: R, rn: R, rm: R, st: &mut St) -> Result<(), String> {
    let lane16 = matches!(shape, ParShape::Add16 | ParShape::Addsubx | ParShape::Subaddx | ParShape::Sub16);
    let lw: u32 = if lane16 { 16 } else { 8 };
    let lanes: u32 = if lane16 { 2 } else { 4 };
    let is_sub = matches!(shape, ParShape::Sub16 | ParShape::Sub8);
    let crossed = matches!(shape, ParShape::Addsubx | ParShape::Subaddx);
    // crossed: ADDSUBX = add16(a, ror16(b)) — i.e. the m halves swapped
    let a = w(st, rn as usize);
    let bm = w(st, rm as usize);
    let b = if crossed {
        format!("(concat {} {})", ext(&bm, 15, 0), ext(&bm, 31, 16))
    } else { bm };

    let lane_of = |e: &str, i: u32| ext(e, i * lw + lw - 1, i * lw);
    let s_lane = |e: &str, i: u32| format!("((_ sign_extend {}) {})", 32 - lw, lane_of(e, i));
    let u_lane = |e: &str, i: u32| format!("((_ zero_extend {}) {})", 32 - lw, lane_of(e, i));
    // exact (w+1)-bit sum/diff
    let ext1 = |e: &str| format!("((_ sign_extend 1) {})", e);
    let zext1 = |e: &str| format!("((_ zero_extend 1) {})", e);

    let mut res_lanes: Vec<String> = vec![];
    let mut ge_bits: Vec<String> = vec![];
    let mut q_any = "false".to_string();
    let mut halv_carry: Vec<String> = vec![];

    for i in 0..lanes {
        let sa = s_lane(&a, i);
        let sb = s_lane(&b, i);
        let ua = u_lane(&a, i);
        let ub = u_lane(&b, i);
        match kind {
            ParKind::S => {
                let (wrapped, ge, cbit): (String, String, Option<String>) = if is_sub {
                    let d = format!("(bvsub {} {})", sa, sb);
                    let dd = format!("(bvsub {} {})", ext1(&sa), ext1(&sb));
                    (d, ite1(&format!("(= ((_ extract 32 32) {}) #b0)", dd), "#b1", "#b0"), None)
                } else {
                    let s = format!("(bvadd {} {})", sa, sb);
                    let ss = format!("(bvadd {} {})", ext1(&sa), ext1(&sb));
                    (s, ite1(&format!("(= ((_ extract 32 32) {}) #b0)", ss), "#b1", "#b0"), None)
                };
                res_lanes.push(ext(&wrapped, lw - 1, 0));
                ge_bits.push(ge);
                let _ = cbit;
            }
            ParKind::U => {
                let (wrapped, ge) = if is_sub {
                    let d = format!("(bvsub {} {})", ua, ub);
                    (d, ite1(&format!("(bvuge {} {})", ua, ub), "#b1", "#b0"))
                } else {
                    let s = format!("(bvadd {} {})", ua, ub);
                    let ss = format!("(bvadd {} {})", zext1(&ua), zext1(&ub));
                    (s, ext(&ss, lw, lw))
                };
                res_lanes.push(ext(&wrapped, lw - 1, 0));
                ge_bits.push(ge);
            }
            ParKind::Q => {
                let exact = if is_sub {
                    format!("(bvsub {} {})", ext1(&sa), ext1(&sb))
                } else {
                    format!("(bvadd {} {})", ext1(&sa), ext1(&sb))
                };
                // 33-bit saturating bounds (value-as-integer syntax; hex
                // literals only exist in 4-bit multiples)
                let max = format!("(_ bv{} 33)", (1u32 << (lw - 1)) - 1);
                let min = format!("(_ bv{} 33)", (1i64 << 33) - ((1u32 << (lw - 1)) as i64));
                let over = format!("(bvsgt {} {})", exact, max);
                let under = format!("(bvslt {} {})", exact, min);
                let max_lane = format!("(_ bv{} {})", (1u32 << (lw - 1)) - 1, lw);
                let min_lane = format!("(_ bv{} {})", (1i64 << lw) - ((1u32 << (lw - 1)) as i64), lw);
                res_lanes.push(ite1(&over, &max_lane, &ite1(&under, &min_lane, &ext(&exact, lw - 1, 0))));
                q_any = format!("(or {} {} {})", q_any, over, under);
            }
            ParKind::Uq => {
                let exact = if is_sub {
                    format!("(bvsub {} {})", zext1(&ua), zext1(&ub))
                } else {
                    format!("(bvadd {} {})", zext1(&ua), zext1(&ub))
                };
                let max = format!("(_ bv{} 33)", (1u32 << lw) - 1);
                let over = if is_sub {
                    format!("(bvult {} {})", ua, ub) // borrow → 0 (lane compare)
                } else {
                    format!("(bvugt {} {})", exact, max)
                };
                if is_sub {
                    res_lanes.push(ite1(&over, &format!("(_ bv0 {})", lw), &ext(&exact, lw - 1, 0)));
                } else {
                    res_lanes.push(ite1(&over, &ext(&max, lw - 1, 0), &ext(&exact, lw - 1, 0)));
                }
                q_any = format!("(or {} {})", q_any, over);
            }
            ParKind::Sh => {
                let exact = if is_sub {
                    format!("(bvsub {} {})", ext1(&sa), ext1(&sb))
                } else {
                    format!("(bvadd {} {})", ext1(&sa), ext1(&sb))
                };
                // floor(exact / 2) as lw-bit: (exact >> 1)[lw-1:0] (arithmetic on exact)
                res_lanes.push(ext(&format!("(bvashr {} (_ bv1 33))", exact), lw - 1, 0));
            }
            ParKind::Uh => {
                let exact = if is_sub {
                    format!("(bvsub {} {})", zext1(&ua), zext1(&ub))
                } else {
                    format!("(bvadd {} {})", zext1(&ua), zext1(&ub))
                };
                res_lanes.push(ext(&format!("(bvlshr {} (_ bv1 33))", exact), lw - 1, 0));
            }
        }
        let _ = &mut halv_carry;
    }

    // assemble result (lanes in reverse for concat)
    let mut r = res_lanes[lanes as usize - 1].clone();
    for i in (0..lanes as usize - 1).rev() {
        r = format!("(concat {} {})", r, res_lanes[i]);
    }
    setw(st, rd as usize, r);

    if matches!(kind, ParKind::S | ParKind::U) {
        // GE: lanes 0..n-1 at bits 0..n-1, remaining bits zero
        let mut ge = ge_bits[lanes as usize - 1].clone();
        for i in (0..lanes as usize - 1).rev() {
            ge = format!("(concat {} {})", ge, ge_bits[i]);
        }
        let zbits = 4 - lanes;
        if zbits > 0 {
            let mut g4 = ge;
            for _ in 0..zbits { g4 = format!("(concat #b0 {})", g4); }
            ge = g4;
        }
        st.x[21] = format!("((_ zero_extend 60) {})", ge);
    }
    if matches!(kind, ParKind::Q | ParKind::Uq) {
        set_q(st, &q_any);
    }
    Ok(())
}

// ---- misc reference helpers ----

fn clz_ref(e: &str) -> String {
    // nested ite: if bit(31-i) == 1 → i else next
    let mut acc = imm32(31); // all zeros
    for i in 0..32u32 {
        let bit_is_one = format!("(= ((_ extract {} {}) {}) #b1)", 31 - i, 31 - i, e);
        // if bit31-i is 1, clz = i
        acc = ite1(&bit_is_one, &imm32(i), &acc);
    }
    acc
}

fn rev_ref(e: &str) -> String {
    format!("(concat {} {} {} {})", ext(e, 7, 0), ext(e, 15, 8), ext(e, 23, 16), ext(e, 31, 24))
}
fn rev16_ref(e: &str) -> String {
    format!("(concat {} {} {} {})", ext(e, 23, 16), ext(e, 31, 24), ext(e, 7, 0), ext(e, 15, 8))
}
fn rbit_ref(e: &str) -> String {
    let mut parts = vec![];
    for i in 0..32u32 { parts.push(ext(e, i, i)); }
    format!("(concat {})", parts.join(" "))
}

// ============================ full A32 effect ============================

fn a32_effect(ins: &Ins, pc: u32, st: &mut St) -> Result<(), String> {
    match ins {
        Ins::DpImm { op, s, rn, rd, imm12 } => {
            let rot = ((imm12 >> 8) & 0xF) as u32;
            let imm8 = (imm12 & 0xFF) as u32;
            let val = imm32(imm8.rotate_right(rot * 2));
            let carry = if rot == 0 { None } else {
                let bitpos = (rot * 2 - 1) as u32;
                let bit = if bitpos < 8 { (imm8 >> bitpos) & 1 } else { 0 };
                Some(if bit == 1 { "#b1".to_string() } else { "#b0".to_string() })
            };
            dp_effect(*op, *s, g(st, *rn, pc), *rd, val, carry, st)
        }
        Ins::DpReg { op, s, rn, rd, rm, shift, amount } => {
            match amount {
                ShiftAmount::Imm(a) => {
                    let (val, carry) = a32_shift(g(st, *rm, pc), *shift, *a as u32, &st.c);
                    dp_effect(*op, *s, g(st, *rn, pc), *rd, val, carry, st)
                }
                ShiftAmount::Reg(rs) => {
                    let n = format!("((_ zero_extend 24) ((_ extract 7 0) {}))", w(st, *rs as usize));
                    let (val, carry) = a32_regshift(g(st, *rm, pc), *shift, &n, &st.c);
                    dp_effect(*op, *s, g(st, *rn, pc), *rd, val, carry, st)
                }
            }
        }
        Ins::Movw { rd, imm16 } => { setw(st, *rd as usize, imm32(*imm16 as u32)); Ok(()) }
        Ins::Movt { rd, imm16 } => {
            let old = w(st, *rd as usize);
            setw(st, *rd as usize, format!("(bvor (bvand {} #x0000ffff) #x{:04x}0000)", old, imm16));
            Ok(())
        }
        Ins::Mul { rd, rn, rm, s } => {
            let e = format!("(bvmul {} {})", g(st, *rn, pc), g(st, *rm, pc));
            setw(st, *rd as usize, e.clone());
            if *s { let (n, z) = nz(&e); st.n = n; st.z = z; }
            Ok(())
        }
        Ins::Mla { rd, rn, rm, ra, .. } => {
            setw(st, *rd as usize, format!("(bvadd {} (bvmul {} {}))", g(st, *ra, pc), g(st, *rn, pc), g(st, *rm, pc)));
            Ok(())
        }
        Ins::Mls { rd, rn, rm, ra } => {
            setw(st, *rd as usize, format!("(bvsub {} (bvmul {} {}))", g(st, *ra, pc), g(st, *rn, pc), g(st, *rm, pc)));
            Ok(())
        }
        Ins::Smull { rdlo, rdhi, rn, rm, .. } => {
            let full = format!("(bvmul ((_ sign_extend 32) {}) ((_ sign_extend 32) {}))", g(st, *rn, pc), g(st, *rm, pc));
            setx(st, *rdhi as usize, zext32(&ext(&full, 63, 32)));
            setw(st, *rdlo as usize, ext(&full, 31, 0));
            Ok(())
        }
        Ins::Umull { rdlo, rdhi, rn, rm, .. } => {
            let full = format!("(bvmul ((_ zero_extend 32) {}) ((_ zero_extend 32) {}))", g(st, *rn, pc), g(st, *rm, pc));
            setx(st, *rdhi as usize, zext32(&ext(&full, 63, 32)));
            setw(st, *rdlo as usize, ext(&full, 31, 0));
            Ok(())
        }
        Ins::Smlal { rdlo, rdhi, rn, rm, .. } => {
            let acc = format!("(concat {} {})", w(st, *rdhi as usize), w(st, *rdlo as usize));
            let full = format!("(bvmul ((_ sign_extend 32) {}) ((_ sign_extend 32) {}))", g(st, *rn, pc), g(st, *rm, pc));
            let sum = format!("(bvadd {} {})", acc, full);
            setx(st, *rdhi as usize, zext32(&ext(&sum, 63, 32)));
            setw(st, *rdlo as usize, ext(&sum, 31, 0));
            Ok(())
        }
        Ins::Umlal { rdlo, rdhi, rn, rm, .. } => {
            let acc = format!("(concat {} {})", w(st, *rdhi as usize), w(st, *rdlo as usize));
            let full = format!("(bvmul ((_ zero_extend 32) {}) ((_ zero_extend 32) {}))", g(st, *rn, pc), g(st, *rm, pc));
            let sum = format!("(bvadd {} {})", acc, full);
            setx(st, *rdhi as usize, zext32(&ext(&sum, 63, 32)));
            setw(st, *rdlo as usize, ext(&sum, 31, 0));
            Ok(())
        }
        Ins::Umaal { rdlo, rdhi, rn, rm } => {
            // ARM ARM: sum = R[n]*R[m] (unsigned 64-bit) + R[dHi] + R[dLo]
            // (the two accumulator halves are added as SEPARATE zero-extended
            // 32-bit values — unlike UMLAL which accumulates the 64-bit pair)
            let prod = format!("(bvmul ((_ zero_extend 32) {}) ((_ zero_extend 32) {}))", g(st, *rn, pc), g(st, *rm, pc));
            let sum = format!("(bvadd (bvadd {} ((_ zero_extend 32) {})) ((_ zero_extend 32) {}))",
                prod, w(st, *rdhi as usize), w(st, *rdlo as usize));
            setx(st, *rdhi as usize, zext32(&ext(&sum, 63, 32)));
            setw(st, *rdlo as usize, ext(&sum, 31, 0));
            Ok(())
        }
        Ins::Smmul { rd, rn, rm, ra, sub, round } => {
            // SMMUL/SMMULR: Rd = (Rn*Rm)[63:32] (signed), optional +0x80000000
            // SMMLA/SMMLAR/SMMLS/SMMLS R: Rd = Ra ± (Rn*Rm)[63:32]
            let mut full = format!("(bvmul ((_ sign_extend 32) {}) ((_ sign_extend 32) {}))", g(st, *rn, pc), g(st, *rm, pc));
            if *round { full = format!("(bvadd {} #x0000000080000000)", full); }
            let hi = ext(&full, 63, 32);
            let v = match ra {
                None => hi,
                Some(ra) if *sub => format!("(bvsub {} {})", g(st, *ra, pc), hi),
                Some(ra) => format!("(bvadd {} {})", g(st, *ra, pc), hi),
            };
            setw(st, *rd as usize, v);
            Ok(())
        }
        Ins::Smulxy { rd, rn, rm, x: hx, y: hy } => {
            let n = half16(&g(st, *rn, pc), hx.bit());
            let m = half16(&g(st, *rm, pc), hy.bit());
            setw(st, *rd as usize, format!("(bvmul {} {})", n, m));
            Ok(())
        }
        Ins::Smlaxy { rd, rn, rm, ra, x: hx, y: hy } => {
            let n = half16(&g(st, *rn, pc), hx.bit());
            let m = half16(&g(st, *rm, pc), hy.bit());
            setw(st, *rd as usize, format!("(bvadd {} (bvmul {} {}))", g(st, *ra, pc), n, m));
            Ok(())
        }
        Ins::Smulwy { rd, rn, rm, y: hy } => {
            let m = half16(&g(st, *rm, pc), hy.bit());
            let full = format!("(bvmul ((_ sign_extend 32) {}) ((_ sign_extend 32) {}))", g(st, *rn, pc), m);
            setw(st, *rd as usize, ext(&format!("(bvlshr {} #x0000000000000010)", full), 31, 0));
            Ok(())
        }
        Ins::Smlawy { rd, rn, rm, ra, y: hy } => {
            let m = half16(&g(st, *rm, pc), hy.bit());
            let full = format!("(bvmul ((_ sign_extend 32) {}) ((_ sign_extend 32) {}))", g(st, *rn, pc), m);
            let top = ext(&format!("(bvlshr {} #x0000000000000010)", full), 31, 0);
            setw(st, *rd as usize, format!("(bvadd {} {})", top, g(st, *ra, pc)));
            Ok(())
        }
        Ins::Smuad { rd, rn, rm, x: sw } => {
            let (p1, p2) = dual_products(&g(st, *rn, pc), &g(st, *rm, pc), *sw);
            setw(st, *rd as usize, format!("(bvadd {} {})", p1, p2));
            Ok(())
        }
        Ins::Smusd { rd, rn, rm, x: sw } => {
            let (p1, p2) = dual_products(&g(st, *rn, pc), &g(st, *rm, pc), *sw);
            setw(st, *rd as usize, format!("(bvsub {} {})", p1, p2));
            Ok(())
        }
        Ins::Smlad { rd, rn, rm, ra, x: sw } => {
            let (p1, p2) = dual_products(&g(st, *rn, pc), &g(st, *rm, pc), *sw);
            setw(st, *rd as usize, format!("(bvadd (bvadd {} {}) {})", g(st, *ra, pc), p1, p2));
            Ok(())
        }
        Ins::Smlsd { rd, rn, rm, ra, x: sw } => {
            let (p1, p2) = dual_products(&g(st, *rn, pc), &g(st, *rm, pc), *sw);
            setw(st, *rd as usize, format!("(bvsub (bvadd {} {}) {})", g(st, *ra, pc), p1, p2));
            Ok(())
        }
        Ins::Smlald { rdlo, rdhi, rn, rm, x: sw } => {
            let (p1, p2) = dual_products64(&g(st, *rn, pc), &g(st, *rm, pc), *sw);
            let acc = format!("(concat {} {})", w(st, *rdhi as usize), w(st, *rdlo as usize));
            let sum = format!("(bvadd (bvadd {} {}) {})", acc, p1, p2);
            setx(st, *rdhi as usize, zext32(&ext(&sum, 63, 32)));
            setw(st, *rdlo as usize, ext(&sum, 31, 0));
            Ok(())
        }
        Ins::Smlsld { rdlo, rdhi, rn, rm, x: sw } => {
            let (p1, p2) = dual_products64(&g(st, *rn, pc), &g(st, *rm, pc), *sw);
            let acc = format!("(concat {} {})", w(st, *rdhi as usize), w(st, *rdlo as usize));
            let sum = format!("(bvsub (bvadd {} {}) {})", acc, p1, p2);
            setx(st, *rdhi as usize, zext32(&ext(&sum, 63, 32)));
            setw(st, *rdlo as usize, ext(&sum, 31, 0));
            Ok(())
        }
        Ins::Sdiv { rd, rn, rm } => {
            let rnv = g(st, *rn, pc); let rmv = g(st, *rm, pc);
            setw(st, *rd as usize, format!("(ite (= {} #x00000000) #x00000000 (bvsdiv {} {}))", rmv, rnv, rmv));
            Ok(())
        }
        Ins::Udiv { rd, rn, rm } => {
            let rnv = g(st, *rn, pc); let rmv = g(st, *rm, pc);
            setw(st, *rd as usize, format!("(ite (= {} #x00000000) #x00000000 (bvudiv {} {}))", rmv, rnv, rmv));
            Ok(())
        }
        Ins::Parallel { kind, shape, rd, rn, rm } => parallel_ref(*kind, *shape, *rd, *rn, *rm, st),
        Ins::Pkh { rd, rn, rm, top, shift } => {
            let sh = imm32(*shift as u32);
            let bot = if *top {
                ext(&format!("(bvashr {} {})", g(st, *rm, pc), sh), 15, 0)
            } else {
                ext(&format!("(bvshl {} {})", g(st, *rm, pc), sh), 15, 0)
            };
            setw(st, *rd as usize, format!("(concat {} {})", ext(&g(st, *rn, pc), 31, 16), bot));
            Ok(())
        }
        Ins::Sel { rd, rn, rm } => {
            let a = g(st, *rn, pc); let b = g(st, *rm, pc);
            let mut lanes = vec![];
            for i in (0..4u32).rev() {
                let ge = format!("(= ((_ extract {} {}) GF) #b1)", i, i);
                lanes.push(ite1(&ge, &ext(&a, i * 8 + 7, i * 8), &ext(&b, i * 8 + 7, i * 8)));
            }
            setw(st, *rd as usize, format!("(concat {})", lanes.join(" ")));
            Ok(())
        }
        Ins::Ssat { rd, imm, rn, sh, asr } => {
            let shv = imm32(*sh as u32);
            let x = if *asr { format!("(bvashr {} {})", g(st, *rn, pc), shv) }
                    else { format!("(bvshl {} {})", g(st, *rn, pc), shv) };
            let n = *imm as u32;
            let max = imm32((1u32 << (n - 1)) - 1);
            let min = imm32((0u32).wrapping_sub(1u32 << (n - 1)));
            let over = format!("(bvsgt {} {})", x, max);
            let under = format!("(bvslt {} {})", x, min);
            setw(st, *rd as usize, ite1(&over, &max, &ite1(&under, &min, &x)));
            set_q(st, &format!("(or {} {})", over, under));
            Ok(())
        }
        Ins::Usat { rd, imm, rn, sh, asr } => {
            let shv = imm32(*sh as u32);
            let x = if *asr { format!("(bvashr {} {})", g(st, *rn, pc), shv) }
                    else { format!("(bvshl {} {})", g(st, *rn, pc), shv) };
            let n = *imm as u32;
            let max = imm32((1u32 << n) - 1);
            let over = format!("(bvsgt {} {})", x, max);
            let under = format!("(bvslt {} #x00000000)", x);
            setw(st, *rd as usize, ite1(&under, "#x00000000", &ite1(&over, &max, &x)));
            set_q(st, &format!("(or {} {})", over, under));
            Ok(())
        }
        Ins::Ssat16 { rd, imm, rn } => {
            let src = g(st, *rn, pc);
            let n = *imm as u32;
            let max = imm32((1u32 << (n - 1)) - 1);
            let min = imm32((0u32).wrapping_sub(1u32 << (n - 1)));
            let lo = format!("((_ sign_extend 16) {})", ext(&src, 15, 0));
            let hi = format!("((_ sign_extend 16) {})", ext(&src, 31, 16));
            let over = format!("(or (bvsgt {} {}) (bvslt {} {}) (bvsgt {} {}) (bvslt {} {}))",
                lo, max, lo, min, hi, max, hi, min);
            let cl = ite_s(&format!("(bvsgt {} {})", lo, max), max.clone(),
                     ite_s(&format!("(bvslt {} {})", lo, min), min.clone(), lo));
            let ch = ite_s(&format!("(bvsgt {} {})", hi, max), max.clone(),
                     ite_s(&format!("(bvslt {} {})", hi, min), min.clone(), hi));
            setw(st, *rd as usize, format!("(concat ((_ extract 15 0) {}) ((_ extract 15 0) {}))", ch, cl));
            set_q(st, &over);
            Ok(())
        }
        Ins::Usat16 { rd, imm, rn } => {
            let src = g(st, *rn, pc);
            let n = *imm as u32;
            let max = imm32((1u32 << n) - 1);
            let lo = format!("((_ sign_extend 16) {})", ext(&src, 15, 0));
            let hi = format!("((_ sign_extend 16) {})", ext(&src, 31, 16));
            let over = format!("(or (bvslt {} #x00000000) (bvsgt {} {}) (bvslt {} #x00000000) (bvsgt {} {}))",
                lo, lo, max, hi, hi, max);
            let cl = ite_s(&format!("(bvslt {} #x00000000)", lo), "#x00000000".to_string(),
                     ite_s(&format!("(bvsgt {} {})", lo, max), max.clone(), lo));
            let ch = ite_s(&format!("(bvslt {} #x00000000)", hi), "#x00000000".to_string(),
                     ite_s(&format!("(bvsgt {} {})", hi, max), max.clone(), hi));
            setw(st, *rd as usize, format!("(concat ((_ extract 15 0) {}) ((_ extract 15 0) {}))", ch, cl));
            set_q(st, &over);
            Ok(())
        }
        Ins::Qadd { rd, rn, rm } => {
            let s33 = format!("(bvadd ((_ sign_extend 1) {}) ((_ sign_extend 1) {}))", g(st, *rn, pc), g(st, *rm, pc));
            setw(st, *rd as usize, sat32_ref(&s33));
            set_q(st, &sat_happened(&s33));
            Ok(())
        }
        Ins::Qsub { rd, rn, rm } => {
            let d33 = format!("(bvsub ((_ sign_extend 1) {}) ((_ sign_extend 1) {}))", g(st, *rn, pc), g(st, *rm, pc));
            setw(st, *rd as usize, sat32_ref(&d33));
            set_q(st, &sat_happened(&d33));
            Ok(())
        }
        Ins::Qdadd { rd, rn, rm } => {
            let dbl = format!("(bvadd ((_ sign_extend 1) {}) ((_ sign_extend 1) {}))", g(st, *rm, pc), g(st, *rm, pc));
            let inner_sat = sat_happened(&dbl);
            let inner = sat32_ref(&dbl);
            let s33 = format!("(bvadd ((_ sign_extend 1) {}) ((_ sign_extend 1) {}))", g(st, *rn, pc), inner);
            setw(st, *rd as usize, sat32_ref(&s33));
            set_q(st, &format!("(or {} {})", inner_sat, sat_happened(&s33)));
            Ok(())
        }
        Ins::Qdsub { rd, rn, rm } => {
            let dbl = format!("(bvadd ((_ sign_extend 1) {}) ((_ sign_extend 1) {}))", g(st, *rm, pc), g(st, *rm, pc));
            let inner_sat = sat_happened(&dbl);
            let inner = sat32_ref(&dbl);
            let d33 = format!("(bvsub ((_ sign_extend 1) {}) ((_ sign_extend 1) {}))", g(st, *rn, pc), inner);
            setw(st, *rd as usize, sat32_ref(&d33));
            set_q(st, &format!("(or {} {})", inner_sat, sat_happened(&d33)));
            Ok(())
        }
        Ins::Rev { rd, rm } => { setw(st, *rd as usize, rev_ref(&g(st, *rm, pc))); Ok(()) }
        Ins::Rev16 { rd, rm } => { setw(st, *rd as usize, rev16_ref(&g(st, *rm, pc))); Ok(()) }
        Ins::Revsh { rd, rm } => {
            let r16 = rev16_ref(&g(st, *rm, pc));
            setw(st, *rd as usize, format!("((_ sign_extend 16) {})", ext(&r16, 15, 0)));
            Ok(())
        }
        Ins::Clz { rd, rm } => { setw(st, *rd as usize, clz_ref(&g(st, *rm, pc))); Ok(()) }
        Ins::Rbit { rd, rm } => { setw(st, *rd as usize, rbit_ref(&g(st, *rm, pc))); Ok(()) }
        Ins::Sbfx { rd, rn, lsb, width } => {
            let wv = (*width as u32).min(32);
            let hi = (*lsb as u32) + wv - 1;
            setw(st, *rd as usize, format!("((_ extract 31 0) ((_ sign_extend {}) ((_ extract {} {}) {})))", 32 - wv, hi, *lsb, g(st, *rn, pc)));
            Ok(())
        }
        Ins::Ubfx { rd, rn, lsb, width } => {
            let wv = (*width as u32).min(32);
            let hi = (*lsb as u32) + wv - 1;
            setw(st, *rd as usize, format!("((_ extract 31 0) ((_ zero_extend {}) ((_ extract {} {}) {})))", 32 - wv, hi, *lsb, g(st, *rn, pc)));
            Ok(())
        }
        Ins::Bfc { rd, lsb, width } => {
            let mask: u32 = if *width >= 32 { u32::MAX } else { ((1u32 << *width) - 1) << *lsb };
            setw(st, *rd as usize, format!("(bvand {} {})", w(st, *rd as usize), imm32(!mask)));
            Ok(())
        }
        Ins::Bfi { rd, rn, lsb, width } => {
            let mask: u32 = if *width >= 32 { u32::MAX } else { ((1u32 << *width) - 1) << *lsb };
            setw(st, *rd as usize, format!("(bvor (bvand {} {}) (bvand (bvshl {} {}) {}))",
                w(st, *rd as usize), imm32(!mask), g(st, *rn, pc), imm32(*lsb as u32), imm32(mask)));
            Ok(())
        }
        Ins::Extend { op, rd, rn, rm, rot } => {
            let src = if *rot == 0 { g(st, *rm, pc) } else { format!("((_ rotate_right {}) {})", rot, g(st, *rm, pc)) };
            let (signed, bits, dual) = match op {
                ExtOp::Sxtb | ExtOp::Sxtab => (true, 8u32, false),
                ExtOp::Sxth | ExtOp::Sxtah => (true, 16, false),
                ExtOp::Uxtb | ExtOp::Uxtab => (false, 8, false),
                ExtOp::Uxth | ExtOp::Uxtah => (false, 16, false),
                ExtOp::Sxtb16 | ExtOp::Sxtab16 => (true, 8, true),
                ExtOp::Uxtb16 | ExtOp::Uxtab16 => (false, 8, true),
            };
            let v = if dual {
                // two 8→16 lanes
                let b0 = ext(&src, 7, 0);
                let b2 = ext(&src, 23, 16);
                if signed {
                    format!("(concat ((_ sign_extend 8) {}) ((_ sign_extend 8) {}))", b2, b0)
                } else {
                    format!("(concat ((_ zero_extend 8) {}) ((_ zero_extend 8) {}))", b2, b0)
                }
            } else {
                let b = ext(&src, bits - 1, 0);
                if signed { format!("((_ sign_extend {}) {})", 32 - bits, b) }
                else { format!("((_ zero_extend {}) {})", 32 - bits, b) }
            };
            let v = if op.is_add_form() { format!("(bvadd {} {})", g(st, *rn, pc), v) } else { v };
            setw(st, *rd as usize, v);
            Ok(())
        }
        Ins::Usad8 { rd, rn, rm } => {
            let a = g(st, *rn, pc); let b = g(st, *rm, pc);
            let mut total = "#x00000000".to_string();
            for i in 0..4u32 {
                let ua = format!("((_ zero_extend 24) {})", ext(&a, i * 8 + 7, i * 8));
                let ub = format!("((_ zero_extend 24) {})", ext(&b, i * 8 + 7, i * 8));
                total = format!("(bvadd {} (ite (bvuge {} {}) (bvsub {} {}) (bvsub {} {})))",
                    total, ua, ub, ua, ub, ub, ua);
            }
            setw(st, *rd as usize, total);
            Ok(())
        }
        Ins::Usada8 { rd, rn, rm, ra } => {
            let a = g(st, *rn, pc); let b = g(st, *rm, pc);
            let mut total = "#x00000000".to_string();
            for i in 0..4u32 {
                let ua = format!("((_ zero_extend 24) {})", ext(&a, i * 8 + 7, i * 8));
                let ub = format!("((_ zero_extend 24) {})", ext(&b, i * 8 + 7, i * 8));
                total = format!("(bvadd {} (ite (bvuge {} {}) (bvsub {} {}) (bvsub {} {})))",
                    total, ua, ub, ua, ub, ub, ua);
            }
            setw(st, *rd as usize, format!("(bvadd {} {})", total, g(st, *ra, pc)));
            Ok(())
        }
        Ins::Hints { .. } | Ins::Barriers { .. } | Ins::Pld { .. } | Ins::Pli { .. } => Ok(()),
        Ins::Ldst { .. } | Ins::LdrdStrd { .. } | Ins::LdmStm { .. } | Ins::ExclLoad { .. }
        | Ins::ExclStore { .. } | Ins::ExclLoadD { .. } | Ins::ExclStoreD { .. } => {
            Err("memory op: no memory model".into())
        }
        Ins::B { .. } | Ins::Bl { .. } | Ins::Blx { .. } | Ins::Bx { .. } | Ins::BlxReg { .. } => {
            Err("control flow not modeled".into())
        }
        Ins::Svc { .. } => Err("svc not modeled".into()),
        _ => Err("a32 semantics not modeled".into()),
    }
}

// ============================ A64 symbolic executor ============================

fn shift_str64(m: String, shift_type: u32, amount: u32) -> String {
    match shift_type {
        0 => format!("(bvshl {} {})", m, imm64(amount as u64)),
        1 => format!("(bvlshr {} {})", m, imm64(amount as u64)),
        2 => format!("(bvashr {} {})", m, imm64(amount as u64)),
        _ => format!("((_ rotate_right {}) {})", amount, m),
    }
}

fn shift_str(m: String, shift_type: u32, amount: u32) -> String {
    match shift_type {
        0 => format!("(bvshl {} {})", m, imm32(amount)),
        1 => format!("(bvlshr {} {})", m, imm32(amount)),
        2 => format!("(bvashr {} {})", m, imm32(amount)),
        _ => format!("((_ rotate_right {}) {})", amount, m),
    }
}

fn decode_bitmask_n(n: bool, immr: u32, imms: u32, sf: bool) -> String {
    let v = decode_bitmask_raw(n, immr, imms);
    if sf { format!("#x{:016x}", v) } else { format!("#x{:08x}", v as u32) }
}

fn decode_bitmask_raw(n: bool, immr: u32, imms: u32) -> u64 {
    let bits: u32 = if n { 64 } else { 32 };
    let nn: u64 = ((n as u64) << 6) | (((!imms) & 0x3F) as u64);
    if nn == 0 { return u64::MAX; }
    let len = 63 - nn.leading_zeros();
    let esize: u32 = 1u32 << len;
    let levels = esize - 1;
    let s = imms & levels;
    let diff = immr & levels;
    if s == levels {
        return if esize >= 64 { u64::MAX } else { (1u64 << esize) - 1 };
    }
    let wbits = (s + 1).min(bits);
    let we: u64 = if wbits >= 64 { u64::MAX } else { (1u64 << wbits) - 1 };
    // ARM ARM: element = ROR(ones(w), immr) within esize, then replicate.
    // (LLVM-differential-verified; NOT a whole-word rotate.)
    let emask: u64 = if esize >= 64 { u64::MAX } else { (1u64 << esize) - 1 };
    let wd: u64 = if diff == 0 { we & emask }
        else { ((we >> diff) | (we << (esize - diff))) & emask };
    let mut v: u64 = 0;
    let mut i: u32 = 0;
    while i < bits {
        v |= wd << i;
        i += esize;
    }
    v
}

fn exec_a64(a64: &A64, st: &mut St) -> Result<(), String> {
    for &word in a64.words() {
        exec_one(word, st)?;
    }
    Ok(())
}

fn exec_one(word: u32, st: &mut St) -> Result<(), String> {
    if std::env::var("REARM_TRACE").is_ok() {
        eprintln!("word {:08x}: z={:.50} n={:.30}", word, st.z, st.n);
    }
    let rd = (word & 0x1F) as usize;
    let rn = ((word >> 5) & 0x1F) as usize;
    let rm = ((word >> 16) & 0x1F) as usize;
    let sf = (word >> 31) & 1 == 1;
    let wide = sf;

    // ---- exact mrs/msr forms ----
    if word == 0xD53B4210 {
        st.x[16] = format!("((_ zero_extend 32) (concat {} {} {} {} #x0000000))", st.n, st.z, st.c, st.v);
        return Ok(());
    }
    if word == 0xD53B4211 {
        st.x[17] = format!("((_ zero_extend 32) (concat {} {} {} {} #x0000000))", st.n, st.z, st.c, st.v);
        return Ok(());
    }
    if word == 0xD51B4211 {
        let xv = st.x[17].clone();
        st.n = ext(&xv, 31, 31);
        st.z = ext(&xv, 30, 30);
        st.c = ext(&xv, 29, 29);
        st.v = ext(&xv, 28, 28);
        return Ok(());
    }
    if word == 0xD51B4210 {
        let xv = st.x[16].clone();
        st.n = ext(&xv, 31, 31);
        st.z = ext(&xv, 30, 30);
        st.c = ext(&xv, 29, 29);
        st.v = ext(&xv, 28, 28);
        return Ok(());
    }

    // ---- hints/barriers (0xD503xxxx): no state change ----
    if (word >> 23) == 0x1AA { return Ok(()); }

    // ---- prfm: no state change ----
    if (word & 0xFFC00000) == 0xF9800000 { return Ok(()); }

    // ---- branches / exceptions: not modeled ----
    if (word >> 26) == 0x05 || (word >> 24) == 0x54 || ((word >> 24) & 0xFE) == 0x34 || ((word >> 24) & 0xFE) == 0x36 {
        return Err("control flow not modeled".into());
    }
    if (word >> 16) == 0xD61F || (word >> 16) == 0xD63F || (word >> 16) == 0xD65F {
        return Err("control flow not modeled".into());
    }
    if (word >> 21) == 0x6A0 {
        return Err("exception not modeled".into());
    }

    // ---- loads/stores ----
    if ((word >> 24) & 0x3F) == 0x39 || ((word >> 24) & 0x3F) == 0x38 || ((word >> 24) & 0x3F) == 0x29
        || ((word >> 24) & 0x3F) == 0x28 || ((word >> 24) & 0x3F) == 0x08 {
        return Err("load/store: no memory model".into());
    }

    let op5 = (word >> 24) & 0x1F;

    // ---- multiply family (madd/msub/maddl/mulh) ----
    if op5 == 0x1B {
        let o0 = (word >> 15) & 1 == 1;
        let ra = ((word >> 10) & 0x1F) as usize;
        if !sf {
            // MADD/MSUB (w): bits23:21 == 000
            let prod = format!("(bvmul {} {})", w(st, rn), w(st, rm));
            let expr = if o0 { format!("(bvsub {} {})", w(st, ra), prod) } else { format!("(bvadd {} {})", w(st, ra), prod) };
            setw(st, rd, expr);
            return Ok(());
        }
        let group = (word >> 21) & 7; // bits23:21
        match group {
            0 => { // MADD/MSUB x (64-bit operands)
                let prod = format!("(bvmul {} {})", st.x[rn].clone(), st.x[rm].clone());
                let ra_v = if ra == 31 { "#x0000000000000000".to_string() } else { st.x[ra].clone() };
                let expr = if o0 { format!("(bvsub {} {})", ra_v, prod) } else { format!("(bvadd {} {})", ra_v, prod) };
                setx(st, rd, expr);
            }
            1 | 5 => { // SMADDL / UMADDL (+ sub variants)
                let u = group == 5;
                let a = if u { format!("((_ zero_extend 32) {})", w(st, rn)) } else { format!("((_ sign_extend 32) {})", w(st, rn)) };
                let b = if u { format!("((_ zero_extend 32) {})", w(st, rm)) } else { format!("((_ sign_extend 32) {})", w(st, rm)) };
                let prod = format!("(bvmul {} {})", a, b);
                let ra_v = if ra == 31 { "#x0000000000000000".to_string() } else { st.x[ra].clone() };
                let expr = if o0 { format!("(bvsub {} {})", ra_v, prod) } else { format!("(bvadd {} {})", ra_v, prod) };
                setx(st, rd, expr);
            }
            2 | 6 => { // SMULH / UMULH
                let u = group == 6;
                let a = if u { format!("((_ zero_extend 32) {})", w(st, rn)) } else { format!("((_ sign_extend 32) {})", w(st, rn)) };
                let b = if u { format!("((_ zero_extend 32) {})", w(st, rm)) } else { format!("((_ sign_extend 32) {})", w(st, rm)) };
                let prod = format!("(bvmul {} {})", a, b);
                setx(st, rd, ext(&prod, 63, 32));
            }
            _ => return Err(format!("a64 word {:#010x} unmodeled (mul group {})", word, group)),
        }
        return Ok(());
    }

    if op5 == 0x1A {
        let sub21 = (word >> 21) & 7; // bits23:21
        // ---- CSEL family: bits28:21 = 0xD4 ----
        if ((word >> 21) & 0xFF) == 0xD4 {
            let op = ((word >> 30) & 2) | ((word >> 10) & 1); // 0=CSEL 1=CSINC 2=CSINV 3=CSNEG
            let cond = ((word >> 12) & 0xF) as u8;
            let c = cond_smt(cond, st);
            let a = w(st, rn);
            let b = w(st, rm);
            let b2 = match op {
                1 => format!("(bvadd {} #x00000001)", b),
                2 => format!("(bvnot {})", b),
                3 => format!("(bvneg {})", b),
                _ => b,
            };
            let expr = ite1(&c, &a, &b2);
            setw(st, rd, expr);
            return Ok(());
        }
        // ---- dp1/dp2 (both bits28:21 = 0xD6; bit30 distinguishes: 1=dp1, 0=dp2) ----
        if ((word >> 21) & 0xFF) == 0xD6 && (word >> 30) & 1 == 0 {
            let opcode = (word >> 10) & 0x3F;
            let n = w(st, rn);
            let m = w(st, rm);
            let m31 = format!("(bvand {} #x0000001f)", m);
            let expr = match opcode {
                2 => format!("(ite (= {} #x00000000) #x00000000 (bvudiv {} {}))", m, n, m),
                3 => format!("(ite (= {} #x00000000) #x00000000 (bvsdiv {} {}))", m, n, m),
                8 => format!("(bvshl {} {})", n, m31),
                9 => format!("(bvlshr {} {})", n, m31),
                10 => format!("(bvashr {} {})", n, m31),
                11 => format!("(bvor (bvlshr {} {}) (bvshl {} (bvsub #x00000020 {})))", n, m31, n, m31),
                _ => return Err(format!("dp2 {} unmodeled", opcode)),
            };
            setw(st, rd, expr);
            return Ok(());
        }
        // ---- dp1: rbit/rev16/rev/rev32/clz/cls ----
        if ((word >> 21) & 0xFF) == 0xD6 && (word >> 30) & 1 == 1 {
            let opcode = (word >> 10) & 0x3F;
            let n = w(st, rn);
            let expr = match opcode {
                0 => rbit_ref(&n),
                1 => rev16_ref(&n),
                2 => rev_ref(&n),
                4 => clz_ref(&n),
                _ => return Err(format!("dp1 {} unmodeled", opcode)),
            };
            setw(st, rd, expr);
            return Ok(());
        }
        // ---- ADC/SBC (unshifted): bits28:21 = 0xD0 ----
        if ((word >> 21) & 0xFF) == 0xD0 {
            let o1 = (word >> 30) & 1 == 1; // SBC
            let s = (word >> 29) & 1 == 1;
            let a = w(st, rn);
            let bv = w(st, rm);
            let y = if o1 { format!("(bvnot {})", bv) } else { bv };
            let cin = ite1(&format!("(= {} #b1)", st.c), "#x00000001", "#x00000000");
            let x = format!("(bvadd {} {})", a, y);
            if s {
                let (n1, _z1, c1, v1) = flags_add(&a, &y, false);
                let (n2, z2, c2, v2) = flags_add(&x, &cin, false);
                st.n = n2.clone(); st.z = z2;
                st.c = ite1(&format!("(or (= {} #b1) (= {} #b1))", c1, c2), "#b1", "#b0");
                st.v = ite1(&format!("(or (= {} #b1) (= {} #b1))", v1, v2), "#b1", "#b0");
                let _ = n1;
            }
            setw(st, rd, format!("(bvadd {} {})", x, cin));
            return Ok(());
        }
        return Err(format!("a64 word {:#010x} unmodeled (op5 0x1A sub {})", word, sub21));
    }

    // ---- add/sub register (shifted or extended) ----
    if op5 == 0x0B {
        let sub_op = (word >> 30) & 1 == 1;
        let s = (word >> 29) & 1 == 1;
        let ext_form = (word >> 21) & 1 == 1;
        let a_op = if sf { st.x[rn].clone() } else { w(st, rn) };
        let m = if ext_form {
            let extk = ((word >> 13) & 7) as u32;
            let amount = ((word >> 10) & 7) as u32;
            let wm = w(st, rm);
            let e = match extk {
                0 => format!("((_ zero_extend 24) {})", ext(&wm, 7, 0)),
                1 => format!("((_ zero_extend 16) {})", ext(&wm, 15, 0)),
                2 => format!("((_ zero_extend 32) {})", wm),
                3 => format!("((_ extract 31 0) {})", st.x[rm].clone()),
                4 => format!("((_ sign_extend 24) {})", ext(&wm, 7, 0)),
                5 => format!("((_ sign_extend 16) {})", ext(&wm, 15, 0)),
                6 => format!("((_ sign_extend 32) {})", wm),
                _ => format!("((_ extract 31 0) {})", st.x[rm].clone()),
            };
            if amount == 0 { e } else { format!("(bvshl {} {})", e, imm64(amount as u64)) }
        } else {
            let shift_type = ((word >> 22) & 3) as u32;
            let amount = ((word >> 10) & 0x3F) as u32;
            if sf { shift_str64(st.x[rm].clone(), shift_type, amount) } else { shift_str(w(st, rm), shift_type, amount) }
        };
        let expr = if sub_op { format!("(bvsub {} {})", a_op, m) } else { format!("(bvadd {} {})", a_op, m) };
        if s {
            let (n, z, c, v) = if sub_op { flags_sub(&a_op, &m, sf) } else { flags_add(&a_op, &m, sf) };
            st.n = n; st.z = z; st.c = c; st.v = v;
        }
        if sf { setx(st, rd, expr); } else { setw(st, rd, expr); }
        return Ok(());
    }

    // ---- logic register ----
    if op5 == 0x0A {
        let opc = (word >> 29) & 3;
        let shift_type = ((word >> 22) & 3) as u32;
        let n_bit = (word >> 21) & 1 == 1;
        let amount = ((word >> 10) & 0x3F) as u32;
        let mut m = w(st, rm);
        if amount != 0 {
            m = shift_str(m, shift_type, amount);
        }
        if n_bit { m = format!("(bvnot {})", m); }
        let expr = match opc {
            0 | 3 => format!("(bvand {} {})", w(st, rn), m),
            1 => format!("(bvor {} {})", w(st, rn), m),
            _ => format!("(bvxor {} {})", w(st, rn), m),
        };
        if opc == 3 {
            let (n, z) = nz(&expr);
            st.n = n; st.z = z;
            st.c = "#b0".into();
            st.v = "#b0".into();
        }
        setw(st, rd, expr);
        return Ok(());
    }

    // ---- add/sub immediate ----
    if op5 == 0x11 {
        let sub_op = (word >> 30) & 1 == 1;
        let s = (word >> 29) & 1 == 1;
        let sh = ((word >> 22) & 1) as u32;
        let imm12 = ((word >> 10) & 0xFFF) as u32;
        let val = (imm12 as u64) << (sh * 12);
        let a = if sf { st.x[rn].clone() } else { w(st, rn) };
        let v = if sf { imm64(val) } else { imm32(val as u32) };
        let expr = if sub_op { format!("(bvsub {} {})", a, v) } else { format!("(bvadd {} {})", a, v) };
        if s {
            let (n, z, c, vv) = if sub_op { flags_sub(&a, &v, sf) } else { flags_add(&a, &v, sf) };
            st.n = n; st.z = z; st.c = c; st.v = vv;
        }
        if sf { setx(st, rd, expr); } else { setw(st, rd, expr); }
        return Ok(());
    }

    // ---- logic immediate (bitmask) ----
    if (word >> 23) & 0x3F == 0x24 {
        let opc = (word >> 29) & 3;
        let n_bit = (word >> 22) & 1 == 1;
        let immr = ((word >> 16) & 0x3F) as u32;
        let imms = ((word >> 10) & 0x3F) as u32;
        let val = decode_bitmask_n(n_bit, immr, imms, sf);
        let expr = match opc {
            0 => format!("(bvand {} {})", w(st, rn), val),
            1 => format!("(bvor {} {})", w(st, rn), val),
            2 => format!("(bvxor {} {})", w(st, rn), val),
            _ => format!("(bvand {} {})", w(st, rn), val), // 3 = ANDS
        };
        if opc == 3 {
            let (n, z) = nz(&expr);
            st.n = n; st.z = z;
        }
        // write back (dst is the full 64-bit reg for x forms)
        if sf { setx(st, rd, expr); } else { setw(st, rd, expr); }
        return Ok(());
    }

    // ---- MOVZ/MOVN/MOVK ----
    if (word >> 23) & 0x3F == 0x25 {
        let opc = (word >> 29) & 3;
        let hw = ((word >> 21) & 3) as u32;
        let imm16 = ((word >> 5) & 0xFFFF) as u32;
        let shift = hw * 16;
        let bits = if sf { 64 } else { 32 };
        let val = (imm16 as u64) << shift;
        let expr = match opc {
            0b00 => { // MOVN
                if !sf { imm32(!(val as u32)) } else { imm64(!val) }
            }
            0b10 => { // MOVZ
                if !sf { imm32(val as u32) } else { imm64(val) }
            }
            _ => { // MOVK: keep other bits of dst
                let old = if sf { st.x[rd].clone() } else { w(st, rd) };
                let mask: u64 = 0xFFFFu64 << shift;
                format!("(bvor (bvand {} {}) {})", old,
                    if !sf { imm32(!(mask as u32)) } else { imm64(!mask) },
                    if !sf { imm32(val as u32) } else { imm64(val) })
            }
        };
        if sf { setx(st, rd, expr); } else { setw(st, rd, expr); }
        return Ok(());
    }

    // ---- BFM/SBFM/UBFM (sf-aware pattern decode) ----
    if (word >> 23) & 0x3F == 0x26 {
        let opc = (word >> 29) & 3; // 0=SBFM 1=BFM 2=UBFM
        let immr = ((word >> 16) & 0x3F) as u32;
        let imms = ((word >> 10) & 0x3F) as u32;
        let bits: u32 = if sf { 64 } else { 32 };
        let src = if sf { st.x[rn].clone() } else { w(st, rn) };
        let rot = ror_lit(&src, immr % bits);
        if imms >= immr {
            // extract mode: field = R[imms-immr : 0]
            let wdt = (imms - immr + 1).min(bits);
            let field = if wdt == bits { rot.clone() } else { ext(&rot, wdt - 1, 0) };
            let expr = match opc {
                0 => { // SBFM: sign-extend
                    if wdt == bits { field } else { format!("((_ extract {} 0) ((_ sign_extend {}) {}))", bits - 1, bits - wdt, field) }
                }
                2 => { // UBFM: zero-extend
                    if wdt == bits { field } else { format!("((_ extract {} 0) ((_ zero_extend {}) {}))", bits - 1, bits - wdt, field) }
                }
                _ => { // BFM extract (bfxil): dst[wdt-1:0] = field
                    let old = if sf { st.x[rd].clone() } else { w(st, rd) };
                    let mask: u64 = if wdt >= 64 { u64::MAX } else { ((1u64 << wdt) - 1) };
                    let field_full = if wdt == bits { field } else {
                        format!("((_ zero_extend {}) {})", bits - wdt, field)
                    };
                    format!("(bvor (bvand {} {}) {})", old,
                        if !sf { imm32(!(mask as u32)) } else { imm64(!mask) }, field_full)
                }
            };
            let expr = if bits == 32 { expr } else { expr };
            if sf { setx(st, rd, expr); } else { setw(st, rd, expr); }
        } else {
            // insert mode: w = imms+1
            let wdt = imms + 1;
            match opc {
                1 => { // BFM insert (bfi): dst[lsb+w-1:lsb] = src[w-1:0], lsb = bits-immr
                    let lsb = bits - immr;
                    let field = if wdt == bits { src.clone() } else { ext(&src, wdt - 1, 0) };
                    let old = if sf { st.x[rd].clone() } else { w(st, rd) };
                    let mask: u64 = if wdt >= 64 { u64::MAX } else { ((1u64 << wdt) - 1) << lsb };
                    let field_full = if wdt == bits { field } else {
                        format!("((_ zero_extend {}) {})", bits - wdt, field)
                    };
                    let shifted = if lsb == 0 { field_full } else { format!("(bvshl {} {})", field_full, if !sf { imm32(lsb) } else { imm64(lsb as u64) }) };
                    let expr = format!("(bvor (bvand {} {}) {})", old,
                        if !sf { imm32(!(mask as u32)) } else { imm64(!mask) }, shifted);
                    if sf { setx(st, rd, expr); } else { setw(st, rd, expr); }
                }
                _ => { // SBFM/UBFM with imms < immr (lsl alias):
                       // field = src[imms:0] (UNROTATED), placed at offset = bits-immr
                    let wdt = imms + 1;
                    let field = if wdt == bits { src.clone() } else { ext(&src, wdt - 1, 0) };
                    let field_full = if wdt == bits { field } else {
                        format!("((_ zero_extend {}) {})", bits - wdt, field)
                    };
                    let offset = bits - immr;
                    let expr = if offset == 0 { field_full } else {
                        format!("(bvshl {} {})", field_full, if !sf { imm32(offset) } else { imm64(offset as u64) })
                    };
                    if sf { setx(st, rd, expr); } else { setw(st, rd, expr); }
                }
            }
        }
        return Ok(());
    }

    // ---- EXTR / ROR imm ----
    if (word >> 23) & 0x3F == 0x27 {
        let lsb = ((word >> 10) & 0x3F) as u32;
        let bits: u32 = if sf { 64 } else { 32 };
        let rn_v = if sf { st.x[rn].clone() } else { w(st, rn) };
        let rm_v = if sf { st.x[rm].clone() } else { w(st, rm) };
        if rn == rm && lsb != 0 {
            // ROR imm
            let expr = format!("((_ rotate_right {}) {})", lsb % bits, rn_v);
            if sf { setx(st, rd, expr); } else { setw(st, rd, expr); }
        } else {
            let cat = format!("(concat {} {})", rn_v, rm_v);
            let e = if lsb == 0 { ext(&cat, bits - 1, 0) } else { ext(&format!("(bvlshr {} {})", cat, if !sf { imm32(lsb) } else { imm64(lsb as u64) }), bits - 1, 0) };
            if sf { setx(st, rd, e); } else { setw(st, rd, e); }
        }
        return Ok(());
    }

    Err(format!("a64 word {:#010x} unmodeled by symbolic executor", word))
}

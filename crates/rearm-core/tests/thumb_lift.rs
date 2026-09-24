//! T32 → A64 translation tests:
//! * ThumbExpandImm against ALL 4096 LLVM-disassembled encodings
//! * IT-block condition tracking
//! * corpus-wide translation coverage (decode → translate_t32)
//! * PC-semantics structural checks (ADR at a 2-mod-4 address, BL LR value)

use rearm_core::a32::ins::{DpOp, Ins};
use rearm_core::a64::encode::A64;
use rearm_core::t32::decode::decode_t32;
use rearm_core::translate::t32_to_a64::{thumb_expand_imm, translate_t32, ItTracker};
use rearm_core::common::{Cond, Shift, ShiftAmount, Size};

// ==================== ThumbExpandImm golden ====================

#[test]
fn thumb_expand_imm_matches_llvm() {
    let path = format!("{}/tests/corpus/thumb-imm12.txt", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read_to_string(&path).expect("thumb-imm12.txt");
    let mut n = 0usize;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let (hex, val_hex) = line.split_once(' ').unwrap();
        let imm12 = u16::from_str_radix(hex, 16).unwrap();
        let expect = u32::from_str_radix(val_hex, 16).unwrap();
        let (val, _carry) = thumb_expand_imm(imm12);
        assert_eq!(val, expect, "imm12 {:#05x} expanded to {:#010x}, LLVM says {:#010x}", imm12, val, expect);
        n += 1;
    }
    assert_eq!(n, 4096, "all encodings covered");
}

#[test]
fn thumb_expand_imm_carry_rule() {
    // unrotated forms leave C alone
    for imm12 in [0x0FFu16, 0x1AB, 0x2CD, 0x3EF] {
        let (_, c) = thumb_expand_imm(imm12);
        assert!(c.is_none(), "imm12 {:#05x}", imm12);
    }
    // rotated forms: C = bit(rot-1) of the 32-bit unrotated ('1':imm12<6:0>)
    for imm12 in [0x400u16, 0x47F, 0x580, 0xFFF] {
        let (_, c) = thumb_expand_imm(imm12);
        let rot = ((imm12 >> 7) & 0x1F) as u32;
        let unrot = 0x80u32 | (imm12 as u32 & 0x7F);
        assert_eq!(c, Some(((unrot >> (rot - 1)) & 1)), "imm12 {:#05x}", imm12);
    }
}

// ==================== IT tracking ====================

#[test]
fn it_tracker_masks() {
    let cases: Vec<(Cond, u8, Vec<Cond>)> = vec![
        // IT EQ
        (Cond::Eq, 0b1000, vec![Cond::Eq]),
        // ITT EQ (mask 0100)
        (Cond::Eq, 0b0100, vec![Cond::Eq, Cond::Eq]),
        // ITE EQ (mask 1100)
        (Cond::Eq, 0b1100, vec![Cond::Eq, Cond::Ne]),
        // ITTT EQ (mask 0010)
        (Cond::Eq, 0b0010, vec![Cond::Eq, Cond::Eq, Cond::Eq]),
        // ITET EQ (mask 1010)
        (Cond::Eq, 0b1010, vec![Cond::Eq, Cond::Ne, Cond::Eq]),
        // ITTTT EQ (mask 0001): all selectors equal EQ<0> → all EQ
        (Cond::Eq, 0b0001, vec![Cond::Eq, Cond::Eq, Cond::Eq, Cond::Eq]),
        // ITTEE EQ (mask 0011): x=0, y=0, z=1 → EQ, EQ, EQ, NE
        (Cond::Eq, 0b0011, vec![Cond::Eq, Cond::Eq, Cond::Eq, Cond::Ne]),
        // ITET NE (mask 1010, firstcond NE): x=1==NE<0> → NE, y=0 → EQ
        (Cond::Ne, 0b1010, vec![Cond::Ne, Cond::Ne, Cond::Eq]),
        // ITE GT (GT=1100, low bit 0 → T matches, E differs)
        (Cond::Gt, 0b0100, vec![Cond::Gt, Cond::Gt]),
        (Cond::Gt, 0b1100, vec![Cond::Gt, Cond::Le]),
    ];
    for (first, mask, expect) in cases {
        let mut it = ItTracker::new(first, mask);
        for want in expect {
            assert_eq!(it.next(), Some(want), "IT {}/{:04b}", first.name(), mask);
        }
        assert_eq!(it.next(), None, "block must end");
        assert!(!it.is_active());
    }
}

#[test]
fn it_guard_bracketing() {
    // IT EQ; ADDS r0, r1, r2 — the ADDS must be guard-bracketed and the
    // patched b.ne must jump over exactly the body.
    let mut out = A64::new();
    let ins = Ins::DpReg {
        op: DpOp::Add, s: true, rn: 1, rd: 0, rm: 2,
        shift: Shift::Lsl, amount: ShiftAmount::Imm(0),
    };
    let ok = translate_t32(&ins, 0x1000, &mut out, Some(Cond::Eq)).unwrap();
    assert!(ok);
    assert!(out.len() >= 2);
    let first = out.words()[0];
    // b.ne (cond 0001) with a positive, word-aligned offset skipping the body
    let cond = (first & 0xF) as u8;
    let off_words = (first >> 5) & 0x7FFFF; // imm19 = byte off / 4
    assert_eq!(cond, Cond::Ne.bits(), "guard must branch on inverted cond");
    assert_eq!(off_words as usize, out.len() - 1, "guard must skip exactly the body (in words)");
    // unguarded: no leading branch
    let mut out2 = A64::new();
    translate_t32(&ins, 0x1000, &mut out2, None).unwrap();
    assert_eq!(out2.len(), out.len() - 1, "unguarded == guarded minus the b.cond");
}

// ==================== corpus translation ====================

fn load_corpus(name: &str) -> Vec<(u32, String)> {
    let path = format!("{}/tests/corpus/{}", env!("CARGO_MANIFEST_DIR"), name);
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => { eprintln!("corpus {} not found, skipping", name); return Vec::new(); }
    };
    data.lines().filter_map(|l| {
        let l = l.trim();
        if l.is_empty() { return None; }
        let (hex, text) = l.split_once(' ')?;
        Some((u32::from_str_radix(hex, 16).unwrap(), text.to_string()))
    }).collect()
}

fn translate_corpus(name: &str, min_pct: f64) {
    let entries = load_corpus(name);
    if entries.is_empty() { return; }
    let mut translated = 0usize;
    let mut unsupported = 0usize;
    let mut errors = 0usize;
    let mut it: Option<ItTracker> = None;
    for (word, _text) in &entries {
        let (hw1, hw2) = if *word > 0xFFFF { ((*word >> 16) as u16, (*word & 0xFFFF) as u16) }
                         else { (*word as u16, 0) };
        let tins = match decode_t32(hw1, hw2) { Ok(t) => t, Err(_) => continue };
        if matches!(tins.ins, Ins::Unsupported { .. }) { unsupported += 1; continue; }
        let cond = if let Ins::It { first_cond, mask } = &tins.ins {
            it = Some(ItTracker::new(*first_cond, *mask));
            continue;
        } else {
            match &mut it { Some(tr) => tr.next(), None => None }
        };
        let mut out = A64::new();
        match translate_t32(&tins.ins, 0x1000, &mut out, cond) {
            Ok(true) => translated += 1,
            Ok(false) => unsupported += 1,
            Err(e) => { errors += 1; eprintln!("{}: {:#010x} -> {}", name, word, e.0); }
        }
    }
    let total = translated + unsupported + errors;
    let pct = 100.0 * translated as f64 / total as f64;
    eprintln!("corpus {}: {} translated, {} unsupported, {} errors ({:.1}%)",
        name, translated, unsupported, errors, pct);
    assert!(pct >= min_pct, "corpus {} coverage {:.1}% < {:.1}%", name, pct, min_pct);
}

#[test]
fn translate_thumb2_dp() { translate_corpus("thumb2-dp.txt", 93.0); }

#[test]
fn translate_thumb2_mem() { translate_corpus("thumb2-mem.txt", 90.0); }

#[test]
fn translate_thumb2_mul() { translate_corpus("thumb2-mul.txt", 95.0); }

#[test]
fn translate_thumb2_branch() { translate_corpus("thumb2-branch.txt", 0.0); }

#[test]
fn translate_thumb_misc() { translate_corpus("thumb-misc.txt", 60.0); }

// ==================== PC semantics ====================

/// movz w(rd), #imm16 encoding helper for assertions.
fn movz_w(rd: u8, imm16: u16) -> u32 { 0x5280_0000 | ((imm16 as u32) << 5) | rd as u32 }

#[test]
fn t32_adr_at_2mod4_address() {
    // adr.w r0, #0x40 at 0x1002: Align(0x1002+4, 4) = 0x1004, +0x40 = 0x1044
    let ins = Ins::DpImmT32 { op: DpOp::Add, s: false, rn: 15, rd: 0, imm12: 0x40, plain: true };
    let mut out = A64::new();
    assert!(translate_t32(&ins, 0x1002, &mut out, None).unwrap());
    assert_eq!(out.words(), &[movz_w(0, 0x1044)]);
}

#[test]
fn t32_bl_sets_lr_with_thumb_bit() {
    // bl +0x100 at 0x2000: LR = 0x2004 | 1 = 0x2005, then bl
    let ins = Ins::Bl { off: 0x100 };
    let mut out = A64::new();
    assert!(translate_t32(&ins, 0x2000, &mut out, None).unwrap());
    assert_eq!(out.words()[0], movz_w(14, 0x2005), "LR = (addr+4)|1");
    assert_eq!(out.words()[1] >> 26, 0b100101, "second word must be bl");
}

#[test]
fn t32_ldr_literal_at_2mod4() {
    // ldr r0, [pc, #0x10] at 0x1002: base = Align(0x1006,4)=0x1004 → 0x1014
    let ins = Ins::Ldst {
        store: false, size: Size::W32, signed: false, user: false,
        rt: 0, rn: 15, rm: None, shift: Shift::Lsl,
        imm: 0x10, index: true, add: true, wback: false,
    };
    let mut out = A64::new();
    assert!(translate_t32(&ins, 0x1002, &mut out, None).unwrap());
    assert_eq!(out.words()[0], movz_w(16, 0x1014), "aligned literal base materialized");
    assert_eq!(out.words()[1], 0xB940_0200, "ldr w0, [x16]");
}

#[test]
fn t32_cbz_emits_cbz() {
    let ins = Ins::Cbz { nz: false, rn: 3, off: 0x20 };
    let mut out = A64::new();
    assert!(translate_t32(&ins, 0x1000, &mut out, None).unwrap());
    // cbz w3, +0x20: 0x34 << 24 | (off>>2) << 5 | rt
    assert_eq!(out.words(), &[0x3400_0103]);
}

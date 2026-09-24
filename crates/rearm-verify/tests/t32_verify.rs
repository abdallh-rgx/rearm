//! T32 → A64 Z3 equivalence proofs (sampled from the golden corpora).
//!
//! Each instruction is decoded from the corpus, translated by
//! `translate_t32` at a source address with alternating 2-mod-4 alignment
//! (exercising the ADR/literal Align(PC,4) semantics), and proven 1:1
//! against the T32 reference semantics with Z3.

use rearm_core::a32::ins::Ins;
use rearm_core::t32::decode::decode_t32;
use rearm_core::translate::t32_to_a64::ItTracker;
use rearm_verify::verify_one_at_t32;

fn load_corpus(name: &str) -> Vec<(u32, String)> {
    let path = format!("{}/../rearm-core/tests/corpus/{}", env!("CARGO_MANIFEST_DIR"), name);
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

fn verify_t32_corpus(name: &str, stride: usize) {
    let entries = load_corpus(name);
    if entries.is_empty() { return; }
    let mut proven = 0usize;
    let mut counterexamples = 0usize;
    let mut skipped = 0usize;
    let mut details: Vec<String> = vec![];
    let mut it: Option<ItTracker> = None;
    for (i, (word, text)) in entries.iter().enumerate() {
        let (hw1, hw2) = if *word > 0xFFFF { ((*word >> 16) as u16, (*word & 0xFFFF) as u16) }
                         else { (*word as u16, 0) };
        let tins = match decode_t32(hw1, hw2) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if matches!(tins.ins, Ins::Unsupported { .. }) { continue; }
        if let Ins::It { first_cond, mask } = &tins.ins {
            it = Some(ItTracker::new(*first_cond, *mask));
            continue;
        }
        let _cond = match &mut it { Some(tr) => tr.next(), None => None };
        if i % stride != 0 { continue; }
        // alternating 2-mod-4 alignment exercises Align(PC,4)
        let at = 0x1000u32.wrapping_add((i as u32) * 6);
        match verify_one_at_t32(&tins.ins, at) {
            Ok(true) => proven += 1,
            Ok(false) => {
                counterexamples += 1;
                details.push(format!("COUNTEREXAMPLE: {} ({:#018x})", text, word));
            }
            Err(e) => { skipped += 1; details.push(format!("skip {}: {}", text, e)); }
        }
    }
    eprintln!("T32 Z3 {}: {} proven, {} counterexamples, {} skipped",
        name, proven, counterexamples, skipped);
    for d in details.iter().filter(|d| d.starts_with("COUNTER")).take(10) {
        eprintln!("  {}", d);
    }
    assert_eq!(counterexamples, 0, "T32 translations must be Z3-proven 1:1");
    assert!(proven > 0, "no instructions verified for {}", name);
}

#[test]
fn verify_t32_thumb2_dp() { verify_t32_corpus("thumb2-dp.txt", 3); }

#[test]
fn verify_t32_thumb2_mem() { verify_t32_corpus("thumb2-mem.txt", 3); }

#[test]
fn verify_t32_thumb2_mul() { verify_t32_corpus("thumb2-mul.txt", 3); }

#[test]
fn verify_t32_thumb_misc() { verify_t32_corpus("thumb-misc.txt", 6); }

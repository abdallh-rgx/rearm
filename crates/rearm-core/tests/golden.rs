//! Golden-corpus round-trip tests: decode(bytes) then re-encode must
//! reproduce the exact bytes. Corpus generated from real LLVM encodings.

use rearm_core::a32::{decode::decode_a32, encode::encode_a32};
use rearm_core::a32::ins::Ins;

fn load_corpus(name: &str) -> Vec<(u32, String)> {
    let path = format!("{}/tests/corpus/{}", env!("CARGO_MANIFEST_DIR"), name);
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("corpus {} not found, skipping", name);
            return Vec::new();
        }
    };
    data.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() { return None; }
            let (hex, text) = l.split_once(' ')?;
            Some((u32::from_str_radix(hex, 16).unwrap(), text.to_string()))
        })
        .collect()
}

fn run_corpus(name: &str) {
    let entries = load_corpus(name);
    if entries.is_empty() { return; }

    let mut failures = Vec::new();
    let mut unsupported = 0usize;
    for (word, text) in &entries {
        match decode_a32(*word) {
            Ok(ins) => {
                if matches!(ins, Ins::Unsupported { .. }) {
                    unsupported += 1;
                    continue;
                }
                match encode_a32(&ins) {
                    Ok(w2) => {
                        if w2 != *word {
                            failures.push(format!("{:#010x} {} -> re-encoded {:#010x} ({:?})", word, text, w2, ins));
                        }
                    }
                    Err(e) => failures.push(format!("{:#010x} {} -> encode failed: {} ({:?})", word, text, e, ins)),
                }
            }
            Err(e) => {
                failures.push(format!("{:#010x} {} -> decode failed: {}", word, text, e));
            }
        }
    }
    let total = entries.len();
    eprintln!("corpus {}: {} entries, {} failures, {} unsupported", name, total, failures.len(), unsupported);
    if !failures.is_empty() {
        panic!("round-trip failures:\n{}", failures.iter().take(60).cloned().collect::<Vec<_>>().join("\n"));
    }
}

#[test]
fn arm_integer_roundtrip() { run_corpus("arm-integer.txt"); }

#[test]
fn arm_vfp_roundtrip() { run_corpus("arm-vfp.txt"); }

#[test]
fn arm_neon_arith_roundtrip() { run_corpus("arm-neon-arith.txt"); }

#[test]
fn arm_neon_misc_roundtrip() { run_corpus("arm-neon-misc.txt"); }

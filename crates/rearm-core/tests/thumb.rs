//! T32 golden-corpus round-trip test: decode(hw1, hw2) then re-encode must
//! reproduce the exact halfwords. Corpus lines: 4 hex digits = 16-bit
//! instruction, 8 hex digits = 32-bit (hw1 then hw2, memory order).

use rearm_core::t32::decode::decode_t32;
use rearm_core::t32::encode::encode_t32_len;
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
        let (hw1, hw2) = if *word > 0xFFFF {
            ((*word >> 16) as u16, (*word & 0xFFFF) as u16)
        } else {
            // 16-bit instruction: the single halfword sits at hw1
            (*word as u16, 0)
        };
        match decode_t32(hw1, hw2) {
            Ok(tins) => {
                if matches!(tins.ins, Ins::Unsupported { .. }) {
                    unsupported += 1;
                    continue;
                }
                match encode_t32_len(&tins.ins, tins.len) {
                    Ok((eh1, eh2, len)) => {
                        if eh1 != hw1 || eh2 != hw2 || len != tins.len {
                            failures.push(format!(
                                "{:#06x}/{:#06x} {} -> re-encoded {:#06x}/{:#06x} (len {} vs {}) [{:?}]",
                                hw1, hw2, text, eh1, eh2, len, tins.len, tins.ins
                            ));
                        }
                    }
                    Err(e) => failures.push(format!("{:#06x}/{:#06x} {} -> encode failed: {} [{:?}]", hw1, hw2, text, e, tins.ins)),
                }
            }
            Err(e) => failures.push(format!("{:#06x}/{:#06x} {} -> decode failed: {}", hw1, hw2, text, e)),
        }
    }
    let total = entries.len();
    eprintln!(
        "corpus {}: {} entries, {} failures, {} unsupported",
        name, total, failures.len(), unsupported
    );
    if !failures.is_empty() {
        panic!(
            "T32 round-trip failures ({}):\n{}",
            failures.len(),
            failures.iter().take(80).cloned().collect::<Vec<_>>().join("\n")
        );
    }
}

#[test]
fn thumb2_dp_roundtrip() { run_corpus("thumb2-dp.txt"); }

#[test]
fn thumb2_mem_roundtrip() { run_corpus("thumb2-mem.txt"); }

#[test]
fn thumb2_mul_roundtrip() { run_corpus("thumb2-mul.txt"); }

#[test]
fn thumb2_branch_roundtrip() { run_corpus("thumb2-branch.txt"); }

#[test]
fn thumb_misc_roundtrip() { run_corpus("thumb-misc.txt"); }

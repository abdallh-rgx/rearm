// quick coverage probe (example)
use rearm_core::a32::decode::decode_a32;
fn main() {
    let mut total = 0; let mut ok = 0; let mut unsup = 0;
    let mut fail = 0;
    let mut by_group = std::collections::HashMap::new();
    for line in std::fs::read_to_string("crates/rearm-core/tests/corpus/arm-neon-mega.txt").unwrap().lines() {
        let hex = line.split_whitespace().next().unwrap();
        let word = u32::from_str_radix(hex, 16).unwrap();
        total += 1;
        match decode_a32(word) {
            Ok(ins) => {
                if let rearm_core::a32::ins::Ins::Unsupported { group } = &ins {
                    *by_group.entry(*group).or_insert(0) += 1;
                    unsup += 1;
                } else { ok += 1; }
            }
            Err(_) => fail += 1,
        }
    }
    println!("mega corpus: {total} total, {ok} decoded, {unsup} unsupported, {fail} err");
    let mut v: Vec<_> = by_group.iter().collect();
    v.sort_by_key(|(_, c)| -**c);
    for (g, c) in v { println!("  {g}: {c}"); }
}

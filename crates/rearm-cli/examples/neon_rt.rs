use rearm_core::a32::decode::decode_a32;
use rearm_core::a32::encode::encode_a32;
fn main() {
    let mut total = 0; let mut ok = 0; let mut unsup = 0; let mut mismatch = 0;
    let mut enc_fail = 0;
    let mut bad: Vec<String> = vec![];
    let files = [
        "crates/rearm-core/tests/corpus/arm-neon-arith.txt",
        "crates/rearm-core/tests/corpus/arm-neon-misc.txt",
        "crates/rearm-core/tests/corpus/arm-neon-mega.txt",
    ];
    for f in files {
        for line in std::fs::read_to_string(f).unwrap().lines() {
            let hex = match line.split_whitespace().next() { Some(h) if h.len() == 8 => h, _ => continue };
            let word = u32::from_str_radix(hex, 16).unwrap();
            let text = line.trim();
            total += 1;
            match decode_a32(word) {
                Ok(ins) => {
                    if matches!(ins, rearm_core::a32::ins::Ins::Unsupported { .. }) { unsup += 1; continue; }
                    match encode_a32(&ins) {
                        Ok(w2) if w2 == word => ok += 1,
                        Ok(w2) => { mismatch += 1; bad.push(format!("{} → {:08x} | {}", text, w2, w2)); }
                        Err(_) => { enc_fail += 1; bad.push(format!("{} → encode-fail", text)); }
                    }
                }
                Err(_) => { unsup += 1; }
            }
        }
    }
    println!("NEON round-trip: {total} total, {ok} EXACT, {mismatch} mismatched, {enc_fail} enc-fail, {unsup} unsupported");
    for b in bad.iter().take(25) { println!("  {}", b); }
}

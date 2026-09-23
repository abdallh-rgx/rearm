// T32 decoder coverage against the thumb corpus
use rearm_core::t32::decode::decode_t32;
fn main() {
    let corpus = format!("{}/../rearm-core/tests/corpus/thumb-misc.txt", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read_to_string(&corpus).unwrap();
    let mut ok = 0usize; let mut fail = 0usize;
    let mut fails: Vec<String> = vec![];
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let (hex, text) = match line.split_once(' ') { Some(x) => x, None => continue };
        if text.starts_with("<unknown>") { continue; }
        let v = u32::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);
        let hw1 = (v >> 16) as u16;
        let hw2 = v as u16;
        // thumb hex in corpus is the halfword LE — v is (hw1<<16)|hw2 for 32-bit,
        // or just the 16-bit hw for 16-bit forms. Detect: if hw1 == 0 → 16-bit.
        if v <= 0xFFFF {
            match decode_t32(v as u16, 0) {
                Ok(_) => ok += 1,
                Err(_) => { fail += 1; fails.push(format!("{}", text)); }
            }
        } else {
            match decode_t32(hw1, hw2) {
                Ok(_) => ok += 1,
                Err(_) => { fail += 1; fails.push(format!("{} ({})", text, hex)); }
            }
        }
    }
    println!("T32 corpus: {} decoded, {} failed ({:.0}%)", ok, fail, 100.0 * ok as f64 / (ok + fail) as f64);
    for f in fails.iter().take(25) { println!("  miss: {}", f); }
}

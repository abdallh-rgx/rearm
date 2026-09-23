use rearm_core::a32::decode::decode_a32;
use rearm_verify::verify_one;
fn main() {
    let corpus = format!("{}/../rearm-core/tests/corpus/arm-integer.txt", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read_to_string(&corpus).unwrap();
    let mut m: std::collections::BTreeMap<String, usize> = Default::default();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let (hex, text) = match line.split_once(' ') { Some(x) => x, None => continue };
        let w = u32::from_str_radix(hex, 16).unwrap_or(0);
        let ins = match decode_a32(w) { Ok(i) => i, Err(_) => continue };
        if let Err(e) = verify_one(&ins) {
            if e.starts_with("z3:") {
                *m.entry(ins.mnemonic().to_string()).or_insert(0) += 1;
                let _ = text;
            }
        }
    }
    let v: Vec<_> = m.into_iter().collect();
    for (k, c) in v { println!("{:3}x {}", c, k); }
}

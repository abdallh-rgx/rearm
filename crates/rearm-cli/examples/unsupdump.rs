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
        match verify_one(&ins) {
            Ok(true) => {}
            Ok(false) => {}
            Err(e) => {
                if e.contains("unsupported for translation") {
                    *m.entry(format!("{:24} # {}", ins.mnemonic(), text)).or_insert(0) += 1;
                } else if e.contains("a32 semantics not modeled") {
                    *m.entry(format!("REFMISS {:18} # {}", ins.mnemonic(), text)).or_insert(0) += 1;
                }
            }
        }
    }
    let mut v: Vec<_> = m.into_iter().collect();
    v.sort();
    for (k, c) in v { println!("{:2}x {}", c, k); }
}

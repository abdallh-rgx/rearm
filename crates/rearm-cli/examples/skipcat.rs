use rearm_core::a32::decode::decode_a32;
use rearm_verify::verify_one;
use std::collections::BTreeMap;

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let data = std::fs::read_to_string(&path).unwrap();
    let mut reasons: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let (hex, text) = line.split_once(' ').unwrap();
        let w = u32::from_str_radix(hex, 16).unwrap_or(0);
        let ins = match decode_a32(w) { Ok(i) => i, Err(_) => continue };
        match verify_one(&ins) {
            Ok(true) => {}
            Ok(false) => reasons.entry("COUNTEREXAMPLE".into()).or_default().push(text.into()),
            Err(e) => reasons.entry(e).or_default().push(text.into()),
        }
    }
    for (r, v) in reasons {
        println!("### {} ({}):", r, v.len());
        for t in v.iter().take(8) { println!("   {}", t); }
        if v.len() > 8 { println!("   ..."); }
    }
}

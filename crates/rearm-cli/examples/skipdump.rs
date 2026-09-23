use rearm_core::a32::decode::decode_a32;
use rearm_verify::verify_one;

fn main() {
    let corpus = format!("{}/../rearm-core/tests/corpus/arm-integer.txt", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read_to_string(&corpus).unwrap();
    let mut reasons: std::collections::BTreeMap<String, usize> = Default::default();
    let mut samples: std::collections::BTreeMap<String, String> = Default::default();
    let mut total = 0;
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
                total += 1;
                // normalize reason: take first sentence
                let key = e.split(':').next().unwrap_or("?").trim().to_string();
                *reasons.entry(key.clone()).or_insert(0) += 1;
                samples.entry(key).or_insert_with(|| format!("{} ({})", text, hex));
            }
        }
    }
    println!("total skipped: {}", total);
    let mut v: Vec<_> = reasons.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, c) in v { println!("{:4}  {:60}  e.g. {}", c, k, samples.get(&k).map(|s| s.as_str()).unwrap_or("")); }
}

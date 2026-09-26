// probe2: per-block key recovery + pattern analysis
// For each 1KB block, brute-force a *small* key set: keys derived from
// XORing the most frequent cipher word against common ARM plains, plus
// shifts of the master key family. Report the key sequence.
use rearm_elf::Elf32;

fn valid(w: u32) -> bool {
    use rearm_core::a32::decode::decode_a32;
    use rearm_core::a32::ins::Ins;
    matches!(decode_a32(w), Ok(i) if !matches!(i, Ins::Unsupported { .. }))
}

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let data = std::fs::read(&path).unwrap();
    let elf = Elf32::parse(data).unwrap();
    let mut text_off = 0usize; let mut text_size = 0usize;
    for sec in elf.sections.iter() {
        if sec.name == ".text" { text_off = sec.off; text_size = sec.size as usize; }
    }
    let words: Vec<u32> = elf.data[text_off..text_off+text_size]
        .chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();

    let plains: Vec<u32> = vec![
        0xE1A00000, 0xE1A00001, 0xE12FFF1E, 0xE1500000, 0xE1501000,
        0xE3500000, 0xE92D4008, 0xE8BD8008, 0xE59F0000, 0xE3A00000,
        0xE1A03000, 0xE0810002, 0xE92D4800, 0xE8BD8010, 0xE28DD00C,
        0xE5900000, 0xE5800000, 0xE5901000, 0xE1A0000A, 0xE1A00009,
    ];

    let block = 256usize; // words per block (1KB)
    let mut keys: Vec<(usize, u32, f64)> = Vec::new();
    for (bi, chunk) in words.chunks(block).enumerate() {
        // frequency top words
        let mut freq = std::collections::HashMap::new();
        for &w in chunk.iter() { *freq.entry(w).or_insert(0u32) += 1; }
        let mut top: Vec<(u32, u32)> = freq.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        let mut cands: Vec<u32> = Vec::new();
        for &(cw, _) in top.iter().take(6) {
            for &p in plains.iter() { cands.push(cw ^ p); }
        }
        // also try previous key (keys persist across blocks)
        if let Some(&(_, pk, _)) = keys.last() { cands.push(pk); }
        let mut best_key = 0u32; let mut best_score = -1f64;
        for &k in cands.iter() {
            let score = chunk.iter().filter(|&&w| valid(w ^ k)).count() as f64;
            if score > best_score { best_score = score; best_key = k; }
        }
        let frac = best_score / chunk.len() as f64;
        keys.push((bi, best_key, frac));
    }
    // print the key transition sequence
    let mut prev: Option<u32> = None;
    for &(bi, k, f) in keys.iter() {
        if prev != Some(k) {
            println!("block {:5} @ {:#010x}: key={:08x}  ({:.0}%)", bi, text_off + bi*block*4, k, 100.0*f);
            prev = Some(k);
        }
    }
    let good = keys.iter().filter(|&&(_,_,f)| f > 0.85).count();
    println!("\nblocks >85%: {}/{}", good, keys.len());
}

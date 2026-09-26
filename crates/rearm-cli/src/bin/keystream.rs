// keystream: decrypt .text with dominant key; at failure points, find local
// keys; assemble the full key stream and look for structure.
use rearm_elf::Elf32;

fn valid(w: u32) -> bool {
    use rearm_core::a32::decode::decode_a32;
    use rearm_core::a32::ins::Ins;
    matches!(decode_a32(w), Ok(i) if !matches!(i, Ins::Unsupported { .. }))
}

fn main() {
    let data = std::fs::read("pubg-apk/lib/armeabi-v7a/libUE4.so").unwrap();
    let elf = Elf32::parse(data).unwrap();
    let mut to = 0usize; let mut ts = 0usize;
    for sec in elf.sections.iter() {
        if sec.name == ".text" { to = sec.off; ts = sec.size as usize; }
    }
    let words: Vec<u32> = elf.data[to..to+ts].chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0],c[1],c[2],c[3]])).collect();

    const K0: u32 = 0xDEDEDEDE;
    // scan: runs of validity with K0
    let mut run = 0usize;
    let mut transitions: Vec<(usize, bool)> = Vec::new(); // (word idx, valid?)
    let mut in_valid = valid(words[0] ^ K0);
    transitions.push((0, in_valid));
    for (i, &w) in words.iter().enumerate() {
        let v = valid(w ^ K0);
        if v != in_valid { transitions.push((i, v)); in_valid = v; }
    }
    // measure valid/invalid density with K0
    let mut ok = 0; let mut bad = 0;
    for &w in words.iter() { if valid(w ^ K0) { ok += 1 } else { bad += 1 } }
    println!("with K0=dededede: {} valid ({:.1}%), {} invalid", ok, 100.0*ok as f64/words.len() as f64, bad);

    // classify invalid regions: find local keys at invalid stretches
    let mut local_keys: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    let mut analyzed = 0;
    let mut i = 0usize;
    while i < words.len() {
        if valid(words[i] ^ K0) { i += 1; continue; }
        // start of invalid stretch: find local key from cribs over next 32 words
        let cribs: [u32; 8] = [0xE92D4800, 0xE1A0C00D, 0xE52DE004, 0xE59F0000, 0xE3A00000, 0xE1A00000, 0xE24DD004, 0xE92D4008];
        let mut found = false;
        'outer: for &cr in cribs.iter() {
            let k = words[i] ^ cr;
            if k == K0 { continue; }
            let mut okc = 0;
            for j in 0..32 { if i+j < words.len() && valid(words[i+j] ^ k) { okc += 1 } }
            if okc >= 28 { *local_keys.entry(k).or_insert(0) += 1; found = true; analyzed += 1; break 'outer; }
        }
        // skip the invalid stretch (up to next valid-with-K0 run of 4)
        let mut j = i + 1;
        while j < words.len() && !valid(words[j] ^ K0) { j += 1; }
        // back off to include some context
        i = j;
    }
    let mut v: Vec<(u32, usize)> = local_keys.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    println!("local keys found at {} invalid stretches (top 20):", analyzed);
    for (k, c) in v.iter().take(20) { println!("  {:08x}: {}", k, c); }
}

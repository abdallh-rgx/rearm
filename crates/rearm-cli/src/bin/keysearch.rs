// probe: windowed XOR-key recovery for TP-encrypted .text
// Strategy: for each window, try candidate keys derived from common ARM
// plaintexts; score by rearm A32 decoder validity (decoder full coverage).
use rearm_elf::Elf32;

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let data = std::fs::read(&path).unwrap();
    let elf = Elf32::parse(data).unwrap();

    // find .text section info
    let mut text_off = 0usize; let mut text_size = 0usize;
    for (i, sec) in elf.sections.iter().enumerate() {
        if sec.name == ".text" { text_off = sec.off; text_size = sec.size as usize; }
    }
    let d = &elf.data[..];
    let words: Vec<u32> = d[text_off..text_off+text_size]
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    // plaintext candidates (most common ARM instructions)
    let plains: [u32; 12] = [
        0xE1A00000, // mov r0,r0 (nop)
        0xE1A00001, // mov r0,r1
        0xE12FFF1E, // bx lr
        0xE1500000, // cmp r0,r0
        0xE1501000, // cmp r0,r1
        0xE3500000, // cmp r0,#0
        0xE92D4008, // push {r4,lr}
        0xE8BD8008, // pop {r3,pc}
        0xE59F0000, // ldr r0,[pc]
        0xE3A00000, // mov r0,#0
        0xE1A03000, // mov r3,r0
        0xE0810002, // add r0,r1,r2
    ];

    let valid = |w: u32| -> bool {
        use rearm_core::a32::decode::decode_a32;
        use rearm_core::a32::ins::Ins;
        matches!(decode_a32(w), Ok(i) if !matches!(i, Ins::Unsupported { .. }))
    };

    let win = 0x10000 / 4; // 64KB in words
    let mut n_ok_windows = 0;
    let mut total = 0usize;
    for (wi, chunk) in words.chunks(win).enumerate() {
        // top-3 most frequent words in window
        let mut freq = std::collections::HashMap::new();
        for &w in chunk.iter().step_by(3) { *freq.entry(w).or_insert(0u32) += 1; }
        let mut top: Vec<(u32, u32)> = freq.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        let mut best_key = 0u32; let mut best_score = 0f64;
        for &(cw, _) in top.iter().take(4) {
            for &p in plains.iter() {
                let k = cw ^ p;
                let score = chunk.iter().step_by(7)
                    .filter(|&&w| valid(w ^ k)).count() as f64;
                if score > best_score { best_score = score; best_key = k; }
            }
        }
        let frac = best_score / (chunk.len() as f64 / 7.0);
        if frac > 0.8 { n_ok_windows += 1; }
        total += 1;
        if wi % 40 == 0 || frac > 0.8 {
            println!("win {:4} @ {:#09x}: key={:08x} valid={:.1}%",
                wi, text_off + wi*win*4, best_key, 100.0*frac);
        }
    }
    println!("\nwindows with >80% decode: {}/{}", n_ok_windows, total);
}

// fine-grained key transition analysis on first 128KB
use rearm_elf::Elf32;
fn valid(w: u32) -> bool {
    use rearm_core::a32::decode::decode_a32;
    use rearm_core::a32::ins::Ins;
    matches!(decode_a32(w), Ok(i) if !matches!(i, Ins::Unsupported { .. }))
}
fn main() {
    let data = std::fs::read("pubg-apk/lib/armeabi-v7a/libUE4.so").unwrap();
    let elf = Elf32::parse(data).unwrap();
    let mut to = 0; let mut ts = 0;
    for sec in elf.sections.iter() { if sec.name == ".text" { to = sec.off; ts = sec.size as usize; } }
    let words: Vec<u32> = elf.data[to..to+ts].chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0],c[1],c[2],c[3]])).collect();
    let plains: Vec<u32> = vec![0xE1A00000,0xE1A00001,0xE12FFF1E,0xE1500000,0xE1501000,
        0xE3500000,0xE92D4008,0xE8BD8008,0xE59F0000,0xE3A00000,0xE1A03000,0xE0810002,
        0xE92D4800,0xE8BD8010,0xE5900000,0xE5800000];
    let block = 64usize; // 256-byte blocks
    let mut prev = 0xDEDEDEDEu32;
    let mut last_key = None;
    for (bi, chunk) in words[..8192].chunks(block).enumerate() {
        let mut freq = std::collections::HashMap::new();
        for &w in chunk.iter() { *freq.entry(w).or_insert(0u32) += 1; }
        let mut top: Vec<(u32,u32)> = freq.into_iter().collect();
        top.sort_by(|a,b| b.1.cmp(&a.1));
        let mut cands: Vec<u32> = vec![prev, 0xDEDEDEDE, 0xDEDEFEDE, 0x09E35ED6, 0x3FCA8336, 0x390506CA, 0x017024EB, 0xD892A4DE, 0xD17F24CE];
        for &(cw,_) in top.iter().take(4) { for &p in plains.iter() { cands.push(cw^p); } }
        let mut bk = 0; let mut bs = -1f64;
        for &k in cands.iter() {
            let s = chunk.iter().filter(|&&w| valid(w^k)).count() as f64;
            if s > bs { bs = s; bk = k; }
        }
        if last_key != Some(bk) {
            println!("{:#09x}: key={:08x} ({:.0}%)", to + bi*block*4, bk, 100.0*bs/block as f64);
            last_key = Some(bk);
        }
        prev = bk;
    }
}

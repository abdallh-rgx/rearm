// blcheck: DEFINITIVE proof — decrypt with 0xDEDEDEDE and verify that
// BL/B instruction targets land exactly on .ARM.exidx function starts.
use rearm_elf::Elf32;

fn main() {
    let data = std::fs::read("pubg-apk/lib/armeabi-v7a/libUE4.so").unwrap();
    let elf = Elf32::parse(data).unwrap();
    let mut to = 0usize; let mut ts = 0usize;
    let mut exidx_off = 0usize; let mut exidx_size = 0usize; let mut exidx_addr = 0u32;
    let mut text_addr = 0u32;
    for (i, sec) in elf.sections.iter().enumerate() {
        match sec.name.as_str() {
            ".text" => { to = sec.off; ts = sec.size as usize; text_addr = elf.vbases()[i]; }
            ".ARM.exidx" => { exidx_off = sec.off; exidx_size = sec.size as usize; exidx_addr = elf.vbases()[i]; }
            _ => {}
        }
    }
    let words: Vec<u32> = elf.data[to..to+ts].chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0],c[1],c[2],c[3]])).collect();

    let mut funcs: Vec<u32> = Vec::new();
    for i in 0..exidx_size/8 {
        let w0 = u32::from_le_bytes(elf.data[exidx_off+i*8..exidx_off+i*8+4].try_into().unwrap());
        let rel = (w0 << 1) as i32 >> 1;
        funcs.push((exidx_addr as i64 + 8*i as i64 + rel as i64) as u32 & !1);
    }
    funcs.sort_unstable();
    funcs.dedup();

    const K: u32 = 0xDEDEDEDE;
    let mut n_bl = 0usize; let mut hit = 0usize; let mut miss_near = 0usize;
    let mut misses: Vec<(u32, u32)> = Vec::new();
    for (i, &cw) in words.iter().enumerate() {
        let w = cw ^ K;
        let cond = w >> 28;
        // BL: cond!=1111, bits 27:25 = 101, bit24=1
        if cond != 0xF && (w >> 25) & 0x7 == 0x5 && (w >> 24) & 1 == 1 {
            let off = ((w & 0xFFFFFF) << 2) as i32;
            let target = (text_addr as i64 + 8 + 4*i as i64 + off as i64) as u32;
            n_bl += 1;
            if funcs.binary_search(&target).is_ok() { hit += 1; }
            else {
                miss_near += 1;
                if misses.len() < 10 { misses.push((4*i as u32 + text_addr, target)); }
            }
        }
    }
    println!("decrypted BL count: {}", n_bl);
    println!("  targets landing exactly on exidx function starts: {} ({:.1}%)", hit, 100.0*hit as f64/n_bl as f64);
    println!("  misses: {} (first few: {:?})", miss_near, &misses[..misses.len().min(5)]);

    // also count classic prologues at function starts
    let mut push_ok = 0;
    let mut fcount = 0;
    for &f in funcs.iter() {
        if f < text_addr || f as usize >= to + ts { continue; }
        let w = words[((f - text_addr)/4) as usize] ^ K;
        fcount += 1;
        if (w >> 24) == 0xE9 && (w >> 20) & 0xF == 0x2 { push_ok += 1 } // STMDB (push)
        else if (w >> 24) == 0xE1 && (w & 0x0FFF0FF0) == 0x01A00000 { push_ok += 1 } // MOV
        else if (w >> 24) == 0xE5 { push_ok += 1 } // LDR
        else if (w >> 24) == 0xE3 { push_ok += 1 } // MOV imm
        else if (w >> 24) == 0xE2 { push_ok += 1 } // ADD/SUB imm
    }
    println!("function starts beginning with classic prologue: {}/{} ({:.1}%)", push_ok, fcount, 100.0*push_ok as f64/fcount as f64);
}

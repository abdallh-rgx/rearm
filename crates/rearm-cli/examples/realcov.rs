// Translation coverage over the 403 real rustc ARM objects.
use rearm_core::a32::decode::decode_a32;
use rearm_core::translate::a32_to_a64::translate_a32;
use rearm_core::a64::encode::A64;

fn exec_sections(data: &[u8]) -> Vec<(String, usize, usize)> {
    // REL objects: scan SECTION headers for SHF_EXECINSTR + .text-like
    if data.len() < 52 || &data[0..4] != b"\x7fELF" { return vec![]; }
    let is64 = data[4] == 2;
    let mut out = vec![];
    if !is64 {
        let shoff = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;
        let shentsize = u16::from_le_bytes([data[46], data[47]]) as usize;
        let shnum = u16::from_le_bytes([data[48], data[49]]) as usize;
        for i in 0..shnum {
            let p = shoff + i * shentsize;
            if p + 40 > data.len() { break; }
            let flags = u32::from_le_bytes([data[p+8], data[p+9], data[p+10], data[p+11]]);
            let off = u32::from_le_bytes([data[p+16], data[p+17], data[p+18], data[p+19]]) as usize;
            let fsz = u32::from_le_bytes([data[p+20], data[p+21], data[p+22], data[p+23]]) as usize;
            if flags & 0x4 != 0 && fsz > 0 {
                out.push((format!(".sec{}", i), off, fsz));
            }
        }
        if out.is_empty() {
            // fall back to program headers (EXEC files)
            let phoff = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as usize;
            let phentsize = u16::from_le_bytes([data[42], data[43]]) as usize;
            let phnum = u16::from_le_bytes([data[44], data[45]]) as usize;
            for i in 0..phnum {
                let p = phoff + i * phentsize;
                if p + 36 > data.len() { break; }
                let ptype = u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]);
                let flags = u32::from_le_bytes([data[p+24], data[p+25], data[p+26], data[p+27]]);
                let off = u32::from_le_bytes([data[p+4], data[p+5], data[p+6], data[p+7]]) as usize;
                let fsz = u32::from_le_bytes([data[p+16], data[p+17], data[p+18], data[p+19]]) as usize;
                if ptype == 1 && flags & 1 != 0 && fsz > 0 {
                    out.push((format!(".load{}", i), off, fsz));
                }
            }
        }
    } else {
        let phoff = u64::from_le_bytes([data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39]]) as usize;
        let phentsize = u16::from_le_bytes([data[54], data[55]]) as usize;
        let phnum = u16::from_le_bytes([data[56], data[57]]) as usize;
        for i in 0..phnum {
            let p = phoff + i * phentsize;
            if p + 56 > data.len() { break; }
            let ptype = u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]);
            let flags = u32::from_le_bytes([data[p+4], data[p+5], data[p+6], data[p+7]]);
            let off = u64::from_le_bytes([data[p+8], data[p+9], data[p+10], data[p+11], data[p+12], data[p+13], data[p+14], data[p+15]]) as usize;
            let fsz = u64::from_le_bytes([data[p+32], data[p+33], data[p+34], data[p+35], data[p+36], data[p+37], data[p+38], data[p+39]]) as usize;
            if ptype == 1 && flags & 1 != 0 && fsz > 0 {
                out.push((format!(".load{}", i), off, fsz));
            }
        }
    }
    out
}

fn main() {
    let dir = std::path::Path::new("/home/z/rearm/test-data/rustlib/ex");
    let mut total = 0usize; let mut translated = 0usize; let mut decode_fail = 0usize;
    let mut transl_fail: std::collections::BTreeMap<&'static str, usize> = Default::default();
    let mut files = vec![];
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        files.push(e.path());
    }
    files.sort();
    for f in files {
        let data = std::fs::read(&f).unwrap();
        for (_, off, size) in exec_sections(&data) {
            if off + size > data.len() { continue; }
            let code = &data[off..off + size];
            for c in code.chunks_exact(4) {
                let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
                total += 1;
                match decode_a32(w) {
                    Ok(ins) => {
                        let mut a64 = A64::new();
                        match translate_a32(&ins, 0, &mut a64) {
                            Ok(true) => translated += 1,
                            Ok(false) => { *transl_fail.entry(ins.mnemonic()).or_insert(0) += 1; }
                            Err(_) => { *transl_fail.entry(ins.mnemonic()).or_insert(0) += 1; }
                        }
                    }
                    Err(_) => decode_fail += 1,
                }
            }
        }
    }
    println!("real-world ARM objects: {} instructions", total);
    println!("  translated : {} ({:.1}%)", translated, 100.0 * translated as f64 / total as f64);
    println!("  decode fail: {}", decode_fail);
    let mut v: Vec<_> = transl_fail.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, c) in v.iter().take(12) { println!("  miss {:3}x {}", c, k); }
}

// example: dump untranslated A32 instructions from objects
use rearm_core::a32::decode::decode_a32;
use rearm_core::a64::encode::A64;
use rearm_core::translate::a32_to_a64::translate_a32;
use std::collections::HashMap;

fn exec_sections(b: &[u8]) -> Vec<(usize, usize)> {
    if !(b.len() > 20 && &b[0..4] == b"\x7fELF" && b[4] == 1) { return vec![]; }
    let rd16 = |o: usize| u16::from_le_bytes([b[o], b[o+1]]) as usize;
    let rd32 = |o: usize| u32::from_le_bytes([b[o], b[o+1], b[o+2], b[o+3]]) as usize;
    let e_shoff = rd32(0x20); let e_shentsize = rd16(0x2E); let e_shnum = rd16(0x30);
    let mut out = vec![];
    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        let sh_flags = rd32(sh + 8); let sh_offset = rd32(sh + 0x10); let sh_size = rd32(sh + 0x14);
        if sh_flags & 0x4 != 0 && sh_size > 0 { out.push((sh_offset, sh_size)); }
    }
    out
}

fn main() {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut examples: HashMap<String, (u32, String)> = HashMap::new();
    let mut dir = std::fs::read_dir("test-data/rustlib/ex").unwrap();
    let mut files: Vec<_> = dir.by_ref().map(|e| e.unwrap().path()).collect();
    files.sort();
    for path in files {
        let data = std::fs::read(&path).unwrap();
        for (off, size) in exec_sections(&data) {
            for c in data[off..off+size].chunks_exact(4) {
                let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
                let ins = match decode_a32(w) { Ok(i) => i, Err(_) => {
                    *counts.entry("UNDECODABLE".into()).or_default() += 1;
                    examples.entry("UNDECODABLE".into()).or_insert((w, path.file_name().unwrap().to_string_lossy().into_owned()));
                    continue;
                }};
                let mut out = A64::new();
                match translate_a32(&ins, 0, &mut out) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        let key = format!("{:?}", ins);
                        *counts.entry(key.clone()).or_default() += 1;
                        examples.entry(key).or_insert((w, path.file_name().unwrap().to_string_lossy().into_owned()));
                    }
                }
            }
        }
    }
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, n) in v { let (w, f) = examples[&k].clone(); println!("{n:5}  {k}   [{w:08x} {f}]"); }
}

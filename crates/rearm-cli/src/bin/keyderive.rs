// keyderive: extract exact (function_start, key) pairs from .ARM.exidx
// boundaries + prologue cribs, then analyze the derivation rule.
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
    let mut exidx_off = 0usize; let mut exidx_size = 0usize; let mut exidx_addr = 0u32;
    for (i, sec) in elf.sections.iter().enumerate() {
        match sec.name.as_str() {
            ".text" => { to = sec.off; ts = sec.size as usize; }
            ".ARM.exidx" => { exidx_off = sec.off; exidx_size = sec.size as usize; exidx_addr = elf.vbases()[i]; }
            _ => {}
        }
    }
    let words: Vec<u32> = elf.data[to..to+ts].chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0],c[1],c[2],c[3]])).collect();

    // exidx entries: pairs (word0 = func_off<<2 | 1 if prel31 to func, word1 = handler)
    let mut funcs: Vec<u32> = Vec::new();
    for i in 0..exidx_size/8 {
        let w0 = u32::from_le_bytes(elf.data[exidx_off+i*8..exidx_off+i*8+4].try_into().unwrap());
        let rel = (w0 << 1) as i32 >> 1; // prel31 sign-extend
        funcs.push((exidx_addr as i64 + 8*i as i64 + rel as i64) as u32);
    }
    funcs.sort_unstable();
    funcs.dedup();
    println!("exidx functions: {}", funcs.len());

    // cribs: typical ARM function prologues (first instruction)
    let cribs: [u32; 10] = [
        0xE92D4800, // push {r7, lr}
        0xE92D4008, // push {r4, lr}
        0xE92D4FF0, // push many
        0xE1A0C00D, // mov ip, sp
        0xE24DD004, // sub sp, #4
        0xE52DE004, // push {lr}
        0xE59F0000, // ldr r0, [pc]
        0xE3A00000, // mov r0, #0
        0xE1A00000, // mov r0, r0
        0xE59FC000, // ldr ip, [pc]
    ];

    let idx = |a: u32| ((a as usize) - to) / 4;

    let mut pairs: Vec<(u32, u32)> = Vec::new();
    'f: for &f in funcs.iter() {
        if f < to as u32 || f as usize >= to + ts || f & 3 != 0 { continue; }
        let i = idx(f);
        let c0 = words[i];
        for &cr in cribs.iter() {
            let k = c0 ^ cr;
            // verify: next 24 words decode validly
            let mut ok = 0;
            for j in 1..24.min(words.len()-i) {
                if valid(words[i+j] ^ k) { ok += 1; }
            }
            if ok >= 21 { pairs.push((f, k)); continue 'f; }
        }
    }
    println!("recovered pairs: {}", pairs.len());
    for (a, k) in pairs.iter().take(30) {
        // try to spot the rule: print k ^ a, k - a, etc.
        println!("f={:#010x} k={:08x}  k^a={:08x} k-a={:08x}", a, k, k ^ a, k.wrapping_sub(*a));
    }
    // check simple rules
    let mut rule1 = std::collections::HashMap::new();
    for (a, k) in pairs.iter() { *rule1.entry(k ^ a).or_insert(0usize) += 1; }
    let mut v: Vec<_> = rule1.into_iter().collect();
    v.sort_by(|x, y| y.1.cmp(&x.1));
    println!("top k^a constants: {:?}", &v[..v.len().min(5)]);
}

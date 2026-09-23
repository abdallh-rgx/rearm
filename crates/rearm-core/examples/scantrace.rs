// Trace: for each corpus word, translate and record (a32, [a64 words]) so bad
// A64 emissions can be traced back to their source.
use rearm_core::a32::decode::decode_a32;
use rearm_core::a64::encode::A64;
use rearm_core::translate::a32_to_a64::translate_a32;

fn main() {
    let corpora = ["arm-integer.txt", "arm-bitfield.txt", "arm-vfp.txt", "arm-neon-arith.txt", "arm-neon-misc.txt", "arm-neon-mega.txt"];
    let mut blob: Vec<u32> = vec![];
    let mut tags: Vec<(usize, String)> = vec![]; // (start index in words, tag)
    for c in corpora {
        let path = format!("{}/tests/corpus/{}", env!("CARGO_MANIFEST_DIR"), c);
        let data = std::fs::read_to_string(&path).unwrap_or_default();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            let (hex, text) = match line.split_once(' ') { Some(x) => x, None => continue };
            let w = u32::from_str_radix(hex, 16).unwrap_or(0);
            let ins = match decode_a32(w) { Ok(i) => i, Err(_) => continue };
            let mut out = A64::new();
            if matches!(translate_a32(&ins, 0, &mut out), Ok(true)) {
                let start = blob.len();
                blob.extend(out.bytes().chunks_exact(4).map(|c| u32::from_le_bytes([c[0],c[1],c[2],c[3]])));
                tags.push((start, format!("{} | {}", hex, text.trim())));
            }
        }
    }
    use std::io::Write;
    let mut s = std::fs::File::create("/tmp/trace-a64.s").unwrap();
    for w in &blob { writeln!(s, ".inst 0x{:08x}", w).unwrap(); }
    let mut t = std::fs::File::create("/tmp/trace-tags.txt").unwrap();
    for (i, tag) in &tags { writeln!(t, "{}\t{}", i, tag).unwrap(); }
    eprintln!("{} words, {} tags", blob.len(), tags.len());
}

// Full differential: translate every corpus A32 instruction to A64; dump the
// combined A64 stream for llvm-objdump validity checking (any unallocated word
// disassembles as `udf` in LLVM → encoder bug).
use rearm_core::a32::decode::decode_a32;
use rearm_core::a64::encode::A64;
use rearm_core::translate::a32_to_a64::translate_a32;

fn main() {
    let corpora = ["arm-integer.txt", "arm-bitfield.txt", "arm-vfp.txt", "arm-neon-arith.txt", "arm-neon-misc.txt", "arm-neon-mega.txt"];
    let mut n_ok = 0; let mut n_skip = 0; let mut n_fail = 0;
    let mut blob: Vec<u32> = vec![];
    for c in corpora {
        let path = format!("{}/tests/corpus/{}", env!("CARGO_MANIFEST_DIR"), c);
        let data = std::fs::read_to_string(&path).unwrap_or_default();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            let (hex, _) = match line.split_once(' ') { Some(x) => x, None => continue };
            let w = u32::from_str_radix(hex, 16).unwrap_or(0);
            let ins = match decode_a32(w) { Ok(i) => i, Err(_) => { n_fail += 1; continue; } };
            let mut out = A64::new();
            match translate_a32(&ins, 0, &mut out) {
                Ok(true) => { n_ok += 1; blob.extend(out.bytes().chunks_exact(4).map(|c| u32::from_le_bytes([c[0],c[1],c[2],c[3]]))); }
                _ => n_skip += 1,
            }
        }
    }
    eprintln!("translated {} instr ({} skipped, {} undecodable), {} A64 words", n_ok, n_skip, n_fail, blob.len());
    use std::io::Write;
    let mut f = std::fs::File::create("/tmp/full-a64.bin").unwrap();
    for w in &blob { f.write_all(&w.to_le_bytes()).unwrap(); }
    let mut s = std::fs::File::create("/tmp/full-a64.s").unwrap();
    for w in &blob { writeln!(s, ".inst 0x{:08x}", w).unwrap(); }
}

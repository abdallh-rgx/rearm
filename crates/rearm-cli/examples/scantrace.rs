// Differential scan: translate every corpus A32 instruction, emit ALL resulting
// A64 words to a flat binary, then (externally) disassemble with llvm-objdump
// and flag any <unknown> words. Usage: scantrace [corpus...] > /tmp/a64.bin
use rearm_core::a32::decode::decode_a32;
use rearm_core::translate::a32_to_a64::translate_a32;
use rearm_core::a64::encode::A64;
use std::io::Write;

fn main() {
    let mut corps: Vec<String> = std::env::args().skip(1).collect();
    if corps.is_empty() {
        for f in ["arm-integer", "arm-bitfield", "arm-multiply", "arm-vfp",
                  "arm-neon-arith", "arm-neon-misc", "arm-neon-mega"] {
            corps.push(format!("crates/rearm-core/tests/corpus/{}.txt", f));
        }
    }
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut n_words = 0usize;
    let mut n_ins = 0usize;
    for c in corps {
        let data = match std::fs::read_to_string(&c) { Ok(d) => d, Err(e) => { eprintln!("skip {}: {}", c, e); continue; } };
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            let (hex, _text) = match line.split_once(' ') { Some(x) => x, None => continue };
            let w = u32::from_str_radix(hex, 16).unwrap_or(0);
            let ins = match decode_a32(w) { Ok(i) => i, Err(_) => continue };
            let mut a64 = A64::new();
            match translate_a32(&ins, 0, &mut a64) {
                Ok(true) => {
                    n_ins += 1;
                    for word in a64.words() {
                        out.write_all(&word.to_le_bytes()).unwrap();
                        n_words += 1;
                    }
                }
                _ => {}
            }
        }
    }
    eprintln!("{} instructions → {} A64 words", n_ins, n_words);
}

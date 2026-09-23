use rearm_core::a32::decode::decode_a32;
use rearm_core::a64::encode::A64;
use rearm_core::translate::a32_to_a64::translate_a32;
fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "test-data/rustlib/ex".into());
    let mut total = 0; let mut translated = 0;
    let mut by_mn: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir).unwrap()
        .filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        let data = match std::fs::read(&path) { Ok(d) => d, Err(_) => continue };
        // .text section = bytes 0x54.. (simplified: scan for ARM code at offset 0x54)
        let text_off = 0x54;
        if data.len() < text_off + 4 { continue; }
        let mut i = text_off;
        while i + 4 <= data.len() {
            let w = u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
            if w == 0 || w == 0xFFFFFFFF { i += 4; continue; }
            // check if this looks like an instruction (not data)
            if let Ok(ins) = decode_a32(w) {
                if matches!(ins, rearm_core::a32::ins::Ins::Unsupported { .. }) { i += 4; continue; }
                total += 1;
                let mut a64 = A64::new();
                match translate_a32(&ins, 0, &mut a64) {
                    Ok(true) => {
                        translated += 1;
                        let e = by_mn.entry(ins.mnemonic().to_string()).or_insert((0, 0));
                        e.1 += 1;
                    }
                    _ => {
                        let e = by_mn.entry(ins.mnemonic().to_string()).or_insert((0, 0));
                        e.0 += 1;
                    }
                }
            }
            i += 4;
        }
    }
    println!("Real-world translation: {}/{} = {:.1}%", translated, total, translated as f64 / total as f64 * 100.0);
    let mut v: Vec<_> = by_mn.iter().collect();
    v.sort_by_key(|(_, (f, _))| std::cmp::Reverse(*f));
    for (mn, (fail, ok)) in v.iter().take(12) {
        println!("  {} {mn}: {fail} fail / {ok} ok", if *fail > 0 { "✗" } else { " " });
    }
}

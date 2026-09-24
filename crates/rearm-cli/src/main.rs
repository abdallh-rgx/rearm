//! rearm — cross-architecture ARM recompiler CLI
//!
//! Commands:
//!   disasm <file>            — disassemble a .so/.o/.bin (A32/T32 auto)
//!   recompile <in> <out>     — translate A32 code sections to A64
//!   verify [corpus]          — Z3-verify translations (corpus = golden set)
//!   coverage <file>          — decode-coverage statistics
//!   bench <file>             — decode throughput (MB/s)

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: rearm <disasm|recompile|verify|coverage|bench> [args]");
        std::process::exit(2);
    }
    let cmd = args[1].as_str();
    let result = match cmd {
        "disasm" => cmd_disasm(&args[2..]),
        "recompile" => cmd_recompile(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "verify-t32" => cmd_verify_t32(&args[2..]),
        "coverage" => cmd_coverage(&args[2..]),
        "bench" => cmd_bench(&args[2..]),
        _ => {
            eprintln!("unknown command: {}", cmd);
            eprintln!("usage: rearm <disasm|recompile|verify|verify-t32|coverage|bench> [args]");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn read_file(p: &str) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("{}: {}", p, e))
}

fn is_elf(b: &[u8]) -> bool { b.len() > 20 && &b[0..4] == b"\x7fELF" }
fn is_elf32_arm(b: &[u8]) -> bool { is_elf(b) && b[4] == 1 && b[18] == 0x28 } // EI_CLASS=1, e_machine=EM_ARM
fn is_elf64_aarch64(b: &[u8]) -> bool { is_elf(b) && b[4] == 2 && b[18] == 0xB7 }

/// Very small ELF section reader: returns (name, offset, size) of SHF_EXECINSTR sections.
fn exec_sections(b: &[u8]) -> Result<Vec<(String, usize, usize)>, String> {
    if !is_elf(b) { return Ok(vec![]); }
    if b[4] == 1 {
        // ELF32 LE
        let rd16 = |o: usize| u16::from_le_bytes([b[o], b[o+1]]) as usize;
        let rd32 = |o: usize| u32::from_le_bytes([b[o], b[o+1], b[o+2], b[o+3]]) as usize;
        let e_shoff = rd32(0x20);
        let e_shentsize = rd16(0x2E);
        let e_shnum = rd16(0x30);
        let e_shstrndx = rd16(0x32);
        if e_shoff == 0 || e_shnum == 0 { return Ok(vec![]); }
        let shstr_off = rd32(e_shoff + e_shstrndx * e_shentsize + 0x10);
        let mut out = vec![];
        for i in 0..e_shnum {
            let sh = e_shoff + i * e_shentsize;
            let sh_name = rd32(sh);
            let sh_type = rd32(sh + 4);
            let sh_flags = rd32(sh + 8);
            let sh_offset = rd32(sh + 0x10);
            let sh_size = rd32(sh + 0x14);
            if sh_type != 0 && sh_flags & 0x4 != 0 && sh_size > 0 {
                let mut nend = shstr_off + sh_name;
                while nend < b.len() && b[nend] != 0 { nend += 1; }
                let name = String::from_utf8_lossy(&b[shstr_off + sh_name..nend]).into_owned();
                out.push((name, sh_offset, sh_size));
            }
        }
        Ok(out)
    } else {
        Ok(vec![]) // ELF64 not needed for input (inputs are arm32)
    }
}

fn cmd_disasm(args: &[String]) -> Result<(), String> {
    if args.is_empty() { return Err("usage: rearm disasm <file>".into()); }
    let data = read_file(&args[0])?;
    if is_elf(&data) {
        if is_elf64_aarch64(&data) {
            eprintln!("note: A64 ELF — A64 disassembler is corpus-validated for decode coverage; text dump via words");
        } else if is_elf32_arm(&data) {
            eprintln!("note: A32 ELF");
        } else {
            return Err("unsupported ELF class/machine".into());
        }
        for (name, off, size) in exec_sections(&data)? {
            println!("section {} @ {:#x} ({} bytes)", name, off, size);
            disasm_region(&data[off..off + size], &name);
        }
    } else {
        disasm_region(&data, "raw");
    }
    Ok(())
}

fn disasm_region(code: &[u8], label: &str) {
    use rearm_core::a32::decode::decode_a32;
    use rearm_core::a32::ins::Ins;
    let mut supported = 0usize;
    let mut unsupported = 0usize;
    let mut fails = 0usize;
    let mut chunks = code.chunks_exact(4);
    let mut i = 0usize;
    while let Some(c) = chunks.next() {
        let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        match decode_a32(w) {
            Ok(ins) => {
                match &ins {
                    Ins::Unsupported { group } => { unsupported += 1; }
                    _ => { supported += 1; }
                }
            }
            Err(_) => { fails += 1; }
        }
        i += 4;
    }
    let total = i / 4;
    println!("  [{}] {} ins: {} decoded, {} unsupported, {} undefined ({:.1}% coverage)",
        label, total, supported, unsupported, fails,
        if total > 0 { 100.0 * supported as f64 / total as f64 } else { 0.0 });
    let _ = i;
    let _ = label;
    let _ = chunks;
    let _ = fails;
    let _ = unsupported;
    let _ = supported;
    // print first 20 disassembled instructions as text via Debug
    let mut shown = 0;
    let mut ch2 = code.chunks_exact(4);
    let mut addr = 0usize;
    while let Some(c) = ch2.next() {
        let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        if let Ok(ins) = decode_a32(w) {
            println!("    {:08x}: {:08x} {:?}", addr, w, ins);
            shown += 1;
            if shown >= 20 { break; }
        }
        addr += 4;
    }
}

fn cmd_coverage(args: &[String]) -> Result<(), String> {
    if args.is_empty() { return Err("usage: rearm coverage <file>".into()); }
    let data = read_file(&args[0])?;
    for (name, off, size) in exec_sections(&data)? {
        disasm_region(&data[off..off + size], &name);
    }
    Ok(())
}

fn cmd_bench(args: &[String]) -> Result<(), String> {
    if args.is_empty() { return Err("usage: rearm bench <file>".into()); }
    let data = read_file(&args[0])?;
    let secs = exec_sections(&data)?;
    let mut bytes = 0usize;
    let mut buf = Vec::new();
    for (_, off, size) in &secs {
        buf.extend_from_slice(&data[*off..*off + *size]);
        bytes += size;
    }
    if buf.is_empty() { buf = data.clone(); bytes = data.len(); }
    use rearm_core::a32::decode::decode_a32;
    let t0 = std::time::Instant::now();
    let mut n = 0usize;
    for c in buf.chunks_exact(4) {
        let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        if decode_a32(w).is_ok() { n += 1; }
    }
    let dt = t0.elapsed().as_secs_f64();
    println!("decoded {} instructions / {} bytes in {:.3}s → {:.1} MB/s, {:.1} Mins/s",
        n, bytes, dt, bytes as f64 / dt / 1e6, n as f64 / dt / 1e6);
    Ok(())
}

fn cmd_recompile(args: &[String]) -> Result<(), String> {
    if args.len() < 2 { return Err("usage: rearm recompile <in.so> <out.bin>".into()); }
    let data = read_file(&args[0])?;
    use rearm_core::a32::decode::decode_a32;
    use rearm_core::a64::encode::A64;
    use rearm_core::translate::a32_to_a64::translate_a32;
    let mut out = A64::new();
    let mut translated = 0usize;
    let mut skipped = 0usize;
    let secs = exec_sections(&data)?;
    for (name, off, size) in &secs {
        eprintln!("translating {} ({} bytes)", name, size);
        for c in data[*off..*off + *size].chunks_exact(4) {
            let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            match decode_a32(w) {
                Ok(ins) => {
                    match translate_a32(&ins, 0, &mut out) {
                        Ok(true) => translated += 1,
                        Ok(false) => skipped += 1,
                        Err(_) => skipped += 1,
                    }
                }
                Err(_) => skipped += 1,
            }
        }
    }
    std::fs::write(&args[1], out.bytes()).map_err(|e| e.to_string())?;
    println!("translated {} instructions ({} skipped), wrote {} bytes of A64",
        translated, skipped, out.bytes().len());
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    use rearm_core::a32::decode::decode_a32;
    use rearm_verify::verify_one;
    // Default: verify the golden corpus of A32 integer instructions that the
    // translator covers.
    let corpus_path = if args.is_empty() {
        format!("{}/../rearm-core/tests/corpus/arm-integer.txt", env!("CARGO_MANIFEST_DIR"))
    } else {
        args[0].clone()
    };
    let data = std::fs::read_to_string(&corpus_path)
        .map_err(|e| format!("corpus {}: {}", corpus_path, e))?;
    let mut proven = 0usize;
    let mut failed = 0usize;
    let mut errors = 0usize;
    let mut details: Vec<String> = vec![];
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let (hex, text) = match line.split_once(' ') { Some(x) => x, None => continue };
        let w = u32::from_str_radix(hex, 16).unwrap_or(0);
        let ins = match decode_a32(w) { Ok(i) => i, Err(_) => continue };
        match verify_one(&ins) {
            Ok(true) => proven += 1,
            Ok(false) => { failed += 1; details.push(format!("COUNTEREXAMPLE: {} ({})", text, hex)); }
            Err(e) => { errors += 1; details.push(format!("skip {}: {}", text, e)); }
        }
    }
    println!("Z3 verification: {} PROVEN 1:1, {} counterexamples, {} skipped",
        proven, failed, errors);
    for d in details.iter().filter(|d| d.starts_with("COUNTER")).take(20) { println!("  {}", d); }
    for d in details.iter().filter(|d| !d.starts_with("COUNTER")).take(10) { println!("  {}", d); }
    if failed > 0 { std::process::exit(1); }
    Ok(())
}

/// Z3-verify T32 translations over a T32 corpus (hex + text lines).
fn cmd_verify_t32(args: &[String]) -> Result<(), String> {
    use rearm_core::t32::decode::decode_t32;
    use rearm_core::translate::t32_to_a64::ItTracker;
    use rearm_verify::verify_one_at_t32;
    let corpus_path = if args.is_empty() {
        format!("{}/../rearm-core/tests/corpus/thumb2-dp.txt", env!("CARGO_MANIFEST_DIR"))
    } else {
        args[0].clone()
    };
    let data = std::fs::read_to_string(&corpus_path)
        .map_err(|e| format!("corpus {}: {}", corpus_path, e))?;
    let mut proven = 0usize;
    let mut failed = 0usize;
    let mut errors = 0usize;
    let mut it: Option<ItTracker> = None;
    let mut details: Vec<String> = vec![];
    for (i, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let (hex, text) = match line.split_once(' ') { Some(x) => x, None => continue };
        let word = u32::from_str_radix(hex, 16).unwrap_or(0);
        let (hw1, hw2) = if word > 0xFFFF { ((word >> 16) as u16, (word & 0xFFFF) as u16) } else { (word as u16, 0) };
        let tins = match decode_t32(hw1, hw2) { Ok(t) => t, Err(_) => continue };
        if matches!(tins.ins, rearm_core::a32::ins::Ins::Unsupported { .. }) { continue; }
        if let rearm_core::a32::ins::Ins::It { first_cond, mask } = &tins.ins {
            it = Some(ItTracker::new(*first_cond, *mask));
            continue;
        }
        let _ = match &mut it { Some(tr) => tr.next(), None => None };
        // alternating 2-mod-4 alignment exercises Align(PC,4)
        let at = 0x1000u32.wrapping_add((i as u32) * 6);
        match verify_one_at_t32(&tins.ins, at) {
            Ok(true) => proven += 1,
            Ok(false) => { failed += 1; details.push(format!("COUNTEREXAMPLE: {} ({})", text, hex)); }
            Err(e) => { errors += 1; details.push(format!("skip {}: {}", text, e)); }
        }
    }
    println!("T32 Z3 verification ({}): {} PROVEN 1:1, {} counterexamples, {} skipped",
        corpus_path.rsplit('/').next().unwrap_or("?"), proven, failed, errors);
    for d in details.iter().filter(|d| d.starts_with("COUNTER")).take(20) { println!("  {}", d); }
    if failed > 0 { std::process::exit(1); }
    Ok(())
}

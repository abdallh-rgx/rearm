//! `rearm so` / `rearm verify-so` — ARM32 .so/.o → AArch64 rewriting.

use rearm_elf::Elf32;

pub fn cmd_so(args: &[String]) -> Result<(), String> {
    if args.len() < 2 { return Err("usage: rearm so <in.so|in.o> <out.o>".into()); }
    let data = std::fs::read(&args[0]).map_err(|e| format!("{}: {}", args[0], e))?;
    let elf = Elf32::parse(data)?;
    let (out, _map, st) = rearm_elf::translate_so(&elf)?;
    let elf64 = rearm_elf::emit_elf64(&out, &_map, &elf);
    std::fs::write(&args[1], &elf64).map_err(|e| format!("{}: {}", args[1], e))?;
    println!("rearm so: {} -> {} ({} bytes)", args[0], args[1], elf64.len());
    println!("{:#?}", st);
    Ok(())
}

pub fn cmd_verify_so(args: &[String]) -> Result<(), String> {
    if args.is_empty() { return Err("usage: rearm verify-so <in.so|in.o> [sample_n]".into()); }
    let sample_n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(64);
    let data = std::fs::read(&args[0]).map_err(|e| format!("{}: {}", args[0], e))?;
    let elf = Elf32::parse(data)?;
    let (_out, map, st) = rearm_elf::translate_so(&elf)?;
    println!("decode: {} T32 + {} A32 ins ({} unsupported, {} undefined encodings); {} translated; {} A64 words",
        st.t32_ins, st.a32_ins, st.unsupported, st.undefined_enc, st.translated, st.a64_words);
    println!("branches: {} resolved / {} unresolved; literal folds: {}",
        st.branches_resolved, st.branches_unresolved, st.literal_folds);

    // Z3-sample: verify translated instructions against the T32/A32 reference
    // matching the mode at each address. Deterministic stride over the map.
    use rearm_verify::{verify_one_at, verify_one_at_t32};

    // Pre-compute sorted mode markers ($t/$a + STT_FUNC thumb bits).
    let mut mode_marks: Vec<(u32, bool)> = Vec::new();
    for (symtab, strtab) in [(".dynsym", ".dynstr"), (".symtab", ".strtab")] {
        if let Ok(syms) = elf.symbols(symtab, strtab) {
            for s in syms.iter() {
                let name = elf.sym_name(s);
                let a = s.value & !1u32;
                let m = if name == "$t" { Some(true) }
                    else if name == "$a" { Some(false) }
                    else if s.info & 0xF == 2 && s.size > 0 { Some(s.value & 1 == 1) }
                    else { None };
                if let Some(m) = m { mode_marks.push((a, m)); }
            }
        }
    }
    mode_marks.sort_unstable();
    mode_marks.dedup_by_key(|(a, _)| *a);

    let step = (map.len() / sample_n.max(1)).max(1);
    let mut proven = 0usize;
    let mut counterexamples = 0usize;
    let mut skipped = 0usize;
    for (i, &(addr, _)) in map.iter().enumerate().step_by(step) {
        if i >= map.len() || counterexamples >= 8 { break; }
        // mode: nearest preceding marker wins (default T32)
        let mut is_t32 = true;
        match mode_marks.binary_search_by_key(&addr, |(a, _)| *a) {
            Ok(idx) => is_t32 = mode_marks[idx].1,
            Err(idx) => { if idx > 0 { is_t32 = mode_marks[idx - 1].1; } }
        }
        // re-decode at that address
        let Some(sec) = elf.section_at(addr) else { continue; };
        let vbases = elf.vbases();
        let vbase = vbases[elf.sections.iter().position(|s| std::ptr::eq(s, sec)).unwrap_or(0)];
        let ro = (addr - vbase) as usize;
        if ro + 2 > sec.size { continue; }
        if is_t32 {
            let hw1 = u16::from_le_bytes([elf.data[sec.off + ro], elf.data[sec.off + ro + 1]]);
            let hw2 = if ro + 4 <= sec.size {
                u16::from_le_bytes([elf.data[sec.off + ro + 2], elf.data[sec.off + ro + 3]])
            } else { 0 };
            let Ok(tins) = rearm_core::t32::decode::decode_t32(hw1, hw2) else { continue; };
            if matches!(tins.ins, rearm_core::a32::ins::Ins::Unsupported { .. }) { continue; }
            if matches!(tins.ins, rearm_core::a32::ins::Ins::It { .. }) { continue; }
            match verify_one_at_t32(&tins.ins, addr) {
                Ok(true) => proven += 1,
                Ok(false) => {
                    counterexamples += 1;
                    println!("COUNTEREXAMPLE at {:#010x}: {:?}", addr, tins.ins);
                }
                Err(_) => skipped += 1,
            }
        } else {
            if ro + 4 > sec.size { continue; }
            let w = u32::from_le_bytes([
                elf.data[sec.off + ro], elf.data[sec.off + ro + 1],
                elf.data[sec.off + ro + 2], elf.data[sec.off + ro + 3]]);
            let Ok(ins) = rearm_core::a32::decode::decode_a32(w) else { continue; };
            if matches!(ins, rearm_core::a32::ins::Ins::Unsupported { .. }) { continue; }
            match verify_one_at(&ins, addr) {
                Ok(true) => proven += 1,
                Ok(false) => {
                    counterexamples += 1;
                    println!("COUNTEREXAMPLE (A32) at {:#010x}: {:?}", addr, ins);
                }
                Err(_) => skipped += 1,
            }
        }
    }
    println!("Z3 sample ({} of {} entries): {} PROVEN 1:1, {} counterexamples, {} skipped",
        (map.len() / step).min(sample_n), map.len(), proven, counterexamples, skipped);
    if counterexamples > 0 { std::process::exit(1); }
    Ok(())
}

// verify-vfp: targeted Z3 verification of the newly-implemented VFP
// translations (VMrs/Vcvt/VcvtImm/VmovImm/VMovCoreD) over real PUBG code.
use rearm_elf::Elf32;
use rearm_core::a32::decode::decode_a32;
use rearm_core::a32::ins::Ins;

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let max: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(80);
    let data = std::fs::read(&path).unwrap();
    let elf = Elf32::parse(data).unwrap();

    // collect distinct new-VFP instruction shapes from .text
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut cases: Vec<(u32, Ins)> = Vec::new();
    for sec in elf.sections.iter() {
        if sec.flags & 0x4 == 0 || sec.size == 0 { continue; }
        let vbase = elf.vbases()[elf.sections.iter().position(|s| std::ptr::eq(s, sec)).unwrap()];
        let mut ro = 0usize;
        while ro + 4 <= sec.size as usize {
            let w = u32::from_le_bytes([elf.data[sec.off+ro], elf.data[sec.off+ro+1],
                elf.data[sec.off+ro+2], elf.data[sec.off+ro+3]]);
            if let Ok(ins) = decode_a32(w) {
                let key = match &ins {
                    Ins::VMrs { .. } => Some(format!("VMrs")),
                    Ins::Vmsr { .. } => Some(format!("Vmsr")),
                    Ins::VMovCoreD { to_fp, .. } => Some(format!("VMovCoreD-to_fp{}", to_fp)),
                    Ins::Vcvt { form, round, .. } => Some(format!("Vcvt-{:?}-{:?}", form, round)),
                    Ins::VcvtImm { to_fp, unsigned, dbl, fbits, .. } =>
                        Some(format!("VcvtImm-t{}u{}d{}b{}", to_fp, unsigned, dbl, fbits)),
                    Ins::VmovImm { kind, q, .. } => Some(format!("VmovImm-{:?}-q{}", kind, q)),
                    _ => None,
                };
                if let Some(k) = key {
                    if seen.insert(k) {
                        cases.push((vbase + ro as u32, ins));
                    }
                }
            }
            ro += 4;
        }
    }
    println!("distinct new-VFP shapes found: {}", cases.len());

    use rearm_verify::{verify_one_at};
    let mut proven = 0; let mut failed = 0; let mut skipped = 0;
    for (addr, ins) in cases.iter().take(max) {
        let k = match ins {
            Ins::VMrs { .. } => "VMrs",
            Ins::Vmsr { .. } => "Vmsr",
            Ins::VMovCoreD { .. } => "VMovCoreD",
            Ins::Vcvt { .. } => "Vcvt",
            Ins::VcvtImm { .. } => "VcvtImm",
            Ins::VmovImm { .. } => "VmovImm",
            _ => "?",
        };
        match verify_one_at(ins, *addr) {
            Ok(true) => { proven += 1; println!("  PROVEN  {:?} @ {:#x}", k, addr); }
            Ok(false) => { failed += 1; println!("  ***COUNTEREXAMPLE*** {:?} @ {:#x}: {:?}", k, addr, ins); }
            Err(e) => { skipped += 1; if std::env::var_os("REARM_V").is_some() { println!("  skip     {} @ {:#x}: {}", k, addr, e); } }
        }
    }
    println!("\nnew-VFP Z3: {} PROVEN, {} counterexamples, {} skipped (of {} tested)",
        proven, failed, skipped, cases.iter().take(max).count());
    if failed > 0 { std::process::exit(1); }
}

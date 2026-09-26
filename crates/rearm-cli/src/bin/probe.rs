// temporary probe: count raw decode outcomes over all exec sections
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let data = std::fs::read(&path).unwrap();
    let elf = rearm_elf::Elf32::parse(data).unwrap();
    let mut hist = std::collections::BTreeMap::new();
    let mut err = 0u64;
    let mut ok = 0u64;
    let mut unsup = std::collections::BTreeMap::new();
    for (i, sec) in elf.sections.iter().enumerate() {
        if sec.flags & 0x4 == 0 || sec.size == 0 || sec.typ == 0 { continue; }
        let vbase = elf.vbases()[i];
        let end = sec.size as usize;
        let mut ro = 0usize;
        while ro + 4 <= end {
            let w = u32::from_le_bytes([elf.data[sec.off+ro], elf.data[sec.off+ro+1], elf.data[sec.off+ro+2], elf.data[sec.off+ro+3]]);
            match rearm_core::a32::decode::decode_a32(w) {
                Ok(rearm_core::a32::ins::Ins::Unsupported { group }) => { *unsup.entry(group).or_insert(0u64) += 1; },
                Ok(_) => ok += 1,
                Err(_) => *hist.entry("DECODE-ERR").or_insert(0u64) += 1,
            }
            err += 0;
            ro += 4;
        }
    }
    println!("ok={} decode_err={:?} groups={:?}", ok, hist, unsup);
}

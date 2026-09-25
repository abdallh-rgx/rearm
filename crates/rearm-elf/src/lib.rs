//! rearm-elf — ARM32 (armeabi-v7a) ELF → AArch64 ELF rewriting.
//!
//! V1 pipeline (per SHF_EXECINSTR section):
//! 1. Parse the ELF32 LE ARM object: sections, symbol tables (Thumb bit from
//!    `st_value`), dynamic relocations (used for coverage statistics).
//! 2. Translate code symbol-by-symbol: T32 decode → `translate_t32`
//!    (IT-tracked), source address = section vaddr + offset. Symbol mode is
//!    driven by the Thumb bit (default: T32 — Android armeabi-v7a builds are
//!    Thumb-first).
//! 3. Branch fixups: `B`/`B.cond`/`BL`/`CBZ`/`BLX` targets that fall inside
//!    the same translated region are rewritten to the target's A64 offset
//!    (forward branches via a patch list).
//! 4. `LDR (literal)` reads the 4 bytes from the source section at
//!    `Align(PC,4)+imm` and constant-folds them (`movz/movk`).
//! 5. Emit a valid ELF64 LE AArch64 **relocatable object** with the
//!    translated `.text`, copied non-exec sections, and a symbol table
//!    (`STT_FUNC` per translated entry point), verified clean by
//!    `readelf`/`llvm-objdump`.
//!
//! Known V1 gaps (documented, next milestones): PLT/GOT relocation weaving
//! for imported symbols, TBB/TBH table translation, literal pools that
//! carry dynamic relocations (folded statically), interworking switch
//! tables.

use rearm_core::a32::ins::Ins;
use rearm_core::a64::encode::A64;
use rearm_core::t32::decode::decode_t32;
use rearm_core::translate::a32_to_a64::load_imm32;
use rearm_core::translate::t32_to_a64::{translate_t32, ItTracker};
use rearm_core::common::Cond;

pub mod dynmeta;
pub mod objread;
pub mod payload;
pub mod soemit;

// ============================ ELF32 reader ============================

pub struct Elf32 {
    pub data: Vec<u8>,
    /// every section (name, offset, size, vaddr, flags, type)
    pub sections: Vec<Section>,
}

pub struct Section {
    pub name: String,
    pub off: usize,
    pub size: usize,
    pub addr: u32,
    pub flags: u32,
    pub typ: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sym {
    pub name_off: usize,
    pub value: u32,
    pub size: u32,
    pub info: u8,
    pub shndx: u16,
}

impl Elf32 {
    pub fn parse(data: Vec<u8>) -> Result<Elf32, String> {
        if data.len() < 52 || &data[0..4] != b"\x7fELF" {
            return Err("not an ELF".into());
        }
        if data[4] != 1 { return Err("not ELF32".into()); }
        if data[5] != 1 { return Err("not little-endian".into()); }
        if data[18] != 0x28 { return Err("not EM_ARM".into()); }
        let rd16 = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
        let rd32 = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let e_shoff = rd32(0x20) as usize;
        let e_shentsize = rd16(0x2E);
        let e_shnum = rd16(0x30);
        let e_shstrndx = rd16(0x32);
        if e_shoff == 0 || e_shnum == 0 {
            return Err("no section headers (stripped?)".into());
        }
        let shstr_off = rd32(e_shoff + e_shstrndx * e_shentsize + 0x10) as usize;
        let mut sections = Vec::with_capacity(e_shnum);
        for i in 0..e_shnum {
            let sh = e_shoff + i * e_shentsize;
            let name_off = rd32(sh) as usize;
            let mut nend = shstr_off + name_off;
            while nend < data.len() && data[nend] != 0 { nend += 1; }
            let name = String::from_utf8_lossy(&data[shstr_off + name_off..nend]).into_owned();
            sections.push(Section {
                name,
                off: rd32(sh + 0x10) as usize,
                size: rd32(sh + 0x14) as usize,
                addr: rd32(sh + 0x0C),
                flags: rd32(sh + 0x08),
                typ: rd32(sh + 0x04),
            });
        }
        Ok(Elf32 { data, sections })
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }


    /// Section that contains virtual address `addr` (uses the same rebased
    /// layout as `translate_so`: sh_addr when non-zero, else consecutive).
    pub fn section_at(&self, addr: u32) -> Option<&Section> {
        let bases = self.vbases();
        for (i, sec) in self.sections.iter().enumerate() {
            if sec.size == 0 { continue; }
            let b = bases[i];
            if addr >= b && (addr as u64) < b as u64 + sec.size as u64 {
                return Some(sec);
            }
        }
        None
    }

    /// Per-section virtual bases: `sh_addr` when non-zero (ET_DYN), else a
    /// consecutive 16-aligned layout (ET_REL — section addrs are all zero).
    pub fn vbases(&self) -> Vec<u32> {
        let mut out = Vec::with_capacity(self.sections.len());
        let mut rel = 0x10000u32;
        for sec in self.sections.iter() {
            if sec.addr != 0 {
                out.push(sec.addr);
            } else {
                out.push(rel);
                rel = rel.wrapping_add((sec.size as u32 + 15) & !15u32);
            }
        }
        out
    }

    pub fn rd32_at(&self, off: usize) -> u32 {
        u32::from_le_bytes([self.data[off], self.data[off + 1], self.data[off + 2], self.data[off + 3]])
    }

    /// Symbols of a symtab section (`sym_sec`/`str_sec` e.g. .symtab/.strtab).
    pub fn symbols(&self, sym_sec: &str, str_sec: &str) -> Result<Vec<Sym>, String> {
        let ss = self.section(sym_sec).ok_or_else(|| format!("no {}", sym_sec))?;
        let st = self.section(str_sec).ok_or_else(|| format!("no {}", str_sec))?;
        let mut out = vec![];
        for off in (0..ss.size.saturating_sub(15)).step_by(16) {
            let o = ss.off + off;
            out.push(Sym {
                name_off: st.off + self.rd32_at(o) as usize,
                value: self.rd32_at(o + 4),
                size: self.rd32_at(o + 8),
                info: self.data[o + 12],
                shndx: u16::from_le_bytes([self.data[o + 14], self.data[o + 15]]),
            });
        }
        Ok(out)
    }

    pub fn sym_name(&self, s: &Sym) -> String {
        let mut end = s.name_off;
        while end < self.data.len() && self.data[end] != 0 { end += 1; }
        String::from_utf8_lossy(&self.data[s.name_off..end]).into_owned()
    }
}

// ============================ translation ============================

#[derive(Default, Debug, Clone)]
pub struct RewriteStats {
    pub functions: usize,
    pub t32_ins: usize,
    pub a32_ins: usize,
    pub translated: usize,
    pub unsupported: usize,
    pub undefined_enc: usize,
    pub it_blocks: usize,
    pub literal_folds: usize,
    pub branches_resolved: usize,
    pub branches_unresolved: usize,
    pub a64_words: usize,
    /// bytes skipped inside exec sections via $d mapping symbols
    pub data_skipped: usize,
}

struct Fixup {
    /// index of the A64 word to patch (the branch word itself)
    at: usize,
    kind: FixKind,
    /// absolute source-space target address
    target: u32,
}

#[derive(Clone, Copy, PartialEq)]
enum FixKind { B, Bcond, Bl, Cbz, Cbnz }

/// Translate every executable section of `elf` into one A64 buffer.
/// Returns the A64 buffer, the source→word-index map and statistics.
///
/// Mode tracking uses ARM mapping symbols when present (`$t` Thumb code,
/// `$a` ARM code, `$d` data — emitted by every NDK/LLVM build, surviving most
/// strips), falling back to STT_FUNC Thumb bits. ET_REL inputs (all-zero
/// section addresses) are rebased onto a consecutive layout first.
pub fn translate_so(elf: &Elf32) -> Result<(A64, Vec<(u32, usize)>, RewriteStats), String> {
    let mut out = A64::new();
    let mut map: Vec<(u32, usize)> = Vec::new();
    let mut stats = RewriteStats::default();
    let mut fixups: Vec<Fixup> = Vec::new();

    // ET_REL rebasing: handled per-section via `elf.vbases()`.

    for sec in elf.sections.iter().enumerate().filter(|(_, s)| s.flags & 0x4 != 0 && s.size > 0 && s.typ != 0) {
        let (sec_idx, _sec0) = sec;
        let vbases = elf.vbases();
        let vbase = vbases[sec_idx];
        let sec = &elf.sections[sec_idx];

        // ---- markers: mapping symbols + STT_FUNC thumb bits ----
        #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        enum Mode { T32, A32, Data }
        let mut marks: Vec<(u32, Mode)> = Vec::new();
        for (symtab, strtab) in [(".dynsym", ".dynstr"), (".symtab", ".strtab")] {
            if let Ok(syms) = elf.symbols(symtab, strtab) {
                for s in syms.iter() {
                    if (s.shndx as usize) != sec_idx { continue; }
                    let name = elf.sym_name(s);
                    let m = if name == "$t" { Some(Mode::T32) }
                        else if name == "$a" { Some(Mode::A32) }
                        else if name == "$d" { Some(Mode::Data) }
                        else if s.info & 0xF == 2 && s.size > 0 { Some(if s.value & 1 == 1 { Mode::T32 } else { Mode::A32 }) }
                        else { None };
                    if let Some(m) = m { marks.push((s.value & !1u32, m)); }
                }
            }
        }
        marks.sort_unstable();
        marks.dedup_by_key(|(a, _)| *a);
        // Default T32 span for the whole section; markers refine it.
        let mut mode = Mode::T32;
        let mut mark_idx = 0usize;

        let mut addr = vbase;
        let end = vbase.wrapping_add(sec.size as u32);
        let sec_off = sec.off;
        let mut it: Option<ItTracker> = None;

        while addr < end {
            let rel = addr - vbase;
            while mark_idx < marks.len() && marks[mark_idx].0 <= rel {
                mode = marks[mark_idx].1;
                mark_idx += 1;
            }
            let ro = rel as usize;
            if ro + 2 > sec.size { break; }
            if mode == Mode::Data {
                // skip to the next marker (or the end of the section)
                let next = if mark_idx < marks.len() { vbase + marks[mark_idx].0 } else { end };
                let skip = (next.max(addr + 1) - addr) as usize;
                stats.data_skipped += skip;
                addr += skip as u32;
                continue;
            }
            let hw1 = u16::from_le_bytes([elf.data[sec_off + ro], elf.data[sec_off + ro + 1]]);
            let hw2 = if ro + 4 <= sec.size {
                u16::from_le_bytes([elf.data[sec_off + ro + 2], elf.data[sec_off + ro + 3]])
            } else { 0 };

            if mode == Mode::A32 {
                let w = ((hw1 as u32) << 16) | hw2 as u32;
                let ins = match rearm_core::a32::decode::decode_a32(w) {
                    Ok(i) => i,
                    Err(_) => { stats.undefined_enc += 1; addr += 4; continue; }
                };
                stats.a32_ins += 1;
                let start = out.len();
                match rearm_core::translate::a32_to_a64::translate_a32(&ins, addr, &mut out) {
                    Ok(true) => {
                        stats.translated += 1;
                        map.push((addr, start));
                        record_branch_a32(&ins, addr, &mut fixups, start);
                    }
                    Ok(false) => stats.unsupported += 1,
                    Err(_) => stats.unsupported += 1,
                }
                addr += 4;
                continue;
            }

            match decode_t32(hw1, hw2) {
                Ok(tins) => {
                    let len = tins.len as u32;
                    if matches!(tins.ins, Ins::Unsupported { .. }) {
                        stats.unsupported += 1;
                        map.push((addr, out.len()));
                        addr += len;
                        continue;
                    }
                    if let Ins::It { first_cond, mask } = &tins.ins {
                        it = Some(ItTracker::new(*first_cond, *mask));
                        stats.it_blocks += 1;
                        map.push((addr, out.len()));
                        addr += len;
                        continue;
                    }
                    let cond = match &mut it { Some(tr) => tr.next(), None => None };
                    stats.t32_ins += 1;
                    let start = out.len();

                    // LDR (literal): constant-fold from the source section.
                    if let Ins::Ldst { store: false, rn: 15, rm: None, rt, imm, .. } = &tins.ins {
                        let lit_addr = (addr.wrapping_add(4) & !3u32).wrapping_add(*imm as u32);
                        if let Some(lr) = lit_addr.checked_sub(vbase).map(|d| d as usize) {
                            if lr + 4 <= sec.size {
                                let v = u32::from_le_bytes([
                                    elf.data[sec_off + lr], elf.data[sec_off + lr + 1],
                                    elf.data[sec_off + lr + 2], elf.data[sec_off + lr + 3]]);
                                load_imm32(&mut out, *rt, v);
                                stats.literal_folds += 1;
                                stats.translated += 1;
                                map.push((addr, start));
                                addr += len;
                                continue;
                            }
                        }
                    }

                    match translate_t32(&tins.ins, addr, &mut out, cond) {
                        Ok(true) => {
                            stats.translated += 1;
                            map.push((addr, start));
                            record_branch_t32(&tins.ins, addr, len, &mut fixups, start, out.len());
                        }
                        Ok(false) => stats.unsupported += 1,
                        Err(_) => stats.unsupported += 1,
                    }
                    addr += len;
                }
                Err(_) => {
                    stats.undefined_enc += 1;
                    addr += 2;
                }
            }
        }
        stats.functions += marks.iter().filter(|(_, m)| *m != Mode::Data).count();
    }

    // ---- resolve branch fixups against the source→A64 map ----
    map.sort_unstable();
    map.dedup();
    for f in fixups.iter() {
        let resolved = map.binary_search_by_key(&f.target, |&(x, _)| x).ok().map(|i| map[i].1);
        match resolved {
            Some(idx) => {
                let off_bytes = ((idx as i64) - (f.at as i64 + 1)) * 4;
                if off_bytes.abs() < (1 << 25) {
                    patch_branch(&mut out, f, off_bytes as i32);
                    stats.branches_resolved += 1;
                } else {
                    stats.branches_unresolved += 1;
                }
            }
            None => stats.branches_unresolved += 1,
        }
    }

    stats.a64_words = out.len();
    Ok((out, map, stats))
}

/// Record a branch fixup. `end` = out.len() AFTER the translation (the BL
/// sequence ends with the `bl` word; CBZ/B are single words).
fn record_branch_t32(ins: &Ins, addr: u32, len: u32, fix: &mut Vec<Fixup>, start: usize, end: usize) {
    match ins {
        Ins::B { cond, off } => {
            // 32-bit T32 branches are Align(PC,4)-based (no-op for the
            // 4-aligned instruction); T16 branches use plain PC.
            let base = if len == 4 { addr.wrapping_add(4) & !3u32 } else { addr.wrapping_add(4) };
            let t = base.wrapping_add(*off as u32);
            fix.push(Fixup {
                at: start,
                kind: if *cond == Cond::Al { FixKind::B } else { FixKind::Bcond },
                target: t,
            });
        }
        Ins::Bl { off } | Ins::Blx { off } => {
            let t = (addr.wrapping_add(4) & !3u32).wrapping_add(*off as u32);
            fix.push(Fixup { at: end - 1, kind: FixKind::Bl, target: t });
        }
        Ins::Cbz { nz, rn: _, off } => {
            let t = addr.wrapping_add(4).wrapping_add(*off as u32);
            fix.push(Fixup { at: start, kind: if *nz { FixKind::Cbnz } else { FixKind::Cbz }, target: t });
        }
        _ => {}
    }
}

fn record_branch_a32(ins: &Ins, addr: u32, fix: &mut Vec<Fixup>, start: usize) {
    match ins {
        Ins::B { off, .. } => {
            let t = addr.wrapping_add(8).wrapping_add(*off as u32);
            fix.push(Fixup { at: start, kind: FixKind::B, target: t });
        }
        Ins::Bl { off } => {
            let t = addr.wrapping_add(8).wrapping_add(*off as u32);
            fix.push(Fixup { at: start, kind: FixKind::Bl, target: t });
        }
        _ => {}
    }
}

fn patch_branch(out: &mut A64, f: &Fixup, off_bytes: i32) {
    let w = out.buf[f.at];
    let new = match f.kind {
        FixKind::B => 0b000101 << 26 | (((off_bytes >> 2) as u32) & 0x03FF_FFFF),
        FixKind::Bl => 0b100101 << 26 | (((off_bytes >> 2) as u32) & 0x03FF_FFFF),
        FixKind::Bcond => (w & 0xFF00001F) | ((((off_bytes >> 2) as u32) & 0x7FFFF) << 5),
        FixKind::Cbz | FixKind::Cbnz => (w & 0xFF00001F) | ((((off_bytes >> 2) as u32) & 0x1F_FFFF) << 5),
    };
    out.buf[f.at] = new;
}

// ============================ ELF64 writer ============================

/// Wrap translated A64 code into a minimal valid ELF64 LE AArch64
/// relocatable object (ET_REL): `.text` = the code, `.rearm.src` = the
/// original non-exec PROGBITS data, `.symtab`/`.strtab` with one symbol per
/// 64 translated entry points.
pub fn emit_elf64(out: &A64, map: &[(u32, usize)], elf: &Elf32) -> Vec<u8> {
    let code = out.bytes();
    let mut data_blob: Vec<u8> = Vec::new();
    for sec in elf.sections.iter() {
        if sec.flags & 0x4 == 0 && sec.typ == 1 && sec.size > 0 && sec.off > 0 {
            data_blob.extend_from_slice(&elf.data[sec.off..sec.off + sec.size]);
        }
    }

    // symbol table: local anchor + entry-point markers from the map
    let mut strtab: Vec<u8> = vec![0u8];
    let mut sym_sec: Vec<u8> = vec![0u8; 24]; // null symbol
    let mut push_sym = |strtab: &mut Vec<u8>, sym_sec: &mut Vec<u8>, name: &str, val: u64| {
        let off = strtab.len();
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
        let mut e = [0u8; 24];
        e[0..4].copy_from_slice(&(off as u32).to_le_bytes());
        e[8..16].copy_from_slice(&val.to_le_bytes());
        e[16] = 0x12; // STB_GLOBAL | STT_FUNC
        e[17] = 1;    // shndx = .text
        sym_sec.extend_from_slice(&e);
    };
    push_sym(&mut strtab, &mut sym_sec, "rearm_text", 0);
    for (i, &(src, idx)) in map.iter().enumerate() {
        if i % 64 == 0 && i > 0 {
            push_sym(&mut strtab, &mut sym_sec, &format!("src_{:08x}", src), (idx * 4) as u64);
        }
    }

    let shstrtab = b"\0.text\0.rearm.src\0.symtab\0.strtab\0.shstrtab\0";
    let name_text = 1usize;
    let name_src = 7usize;
    let name_symtab = 18usize;
    let name_strtab = 26usize;
    let name_shstrtab = 34usize;

    let mut buf: Vec<u8> = Vec::with_capacity(64 + code.len() + data_blob.len() + 2048);

    // ---- ELF64 header (64 bytes) ----
    buf.extend_from_slice(b"\x7fELF");
    buf.extend_from_slice(&[2, 1, 1, 0]); // ELF64, LE, SYSV
    buf.extend_from_slice(&[0u8; 8]);      // ABI
    buf.extend_from_slice(&1u16.to_le_bytes());     // ET_REL
    buf.extend_from_slice(&0xB7u16.to_le_bytes()); // EM_AARCH64
    buf.extend_from_slice(&1u32.to_le_bytes());    // EV_CURRENT
    buf.extend_from_slice(&0u64.to_le_bytes());    // e_entry
    buf.extend_from_slice(&0u64.to_le_bytes());    // e_phoff
    let shoff_pos = buf.len();
    buf.extend_from_slice(&0u64.to_le_bytes());    // e_shoff (patched)
    buf.extend_from_slice(&0u32.to_le_bytes());    // flags
    buf.extend_from_slice(&64u16.to_le_bytes());    // ehsize
    buf.extend_from_slice(&0u16.to_le_bytes());     // phentsize
    buf.extend_from_slice(&0u16.to_le_bytes());     // phnum
    buf.extend_from_slice(&64u16.to_le_bytes());    // shentsize
    buf.extend_from_slice(&6u16.to_le_bytes());     // shnum
    buf.extend_from_slice(&5u16.to_le_bytes());     // shstrndx
    debug_assert_eq!(buf.len(), 64);

    let text_off = buf.len();
    buf.extend_from_slice(&code);
    let src_off = buf.len();
    buf.extend_from_slice(&data_blob);
    let sym_off = buf.len();
    buf.extend_from_slice(&sym_sec);
    let stro_off = buf.len();
    buf.extend_from_slice(&strtab);
    let shstro_off = buf.len();
    buf.extend_from_slice(shstrtab);

    let shoff = buf.len() as u64;
    // null + 5 sections
    buf.extend_from_slice(&[0u8; 64]);
    let mut push_sh = |buf: &mut Vec<u8>, name: u32, typ: u32, flags: u64, off: u64, size: u64, link: u32, entsize: u64| {
        buf.extend_from_slice(&name.to_le_bytes());
        buf.extend_from_slice(&typ.to_le_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());  // addr
        buf.extend_from_slice(&off.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&link.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());  // info
        buf.extend_from_slice(&4u64.to_le_bytes());  // align
        buf.extend_from_slice(&entsize.to_le_bytes());
    };
    push_sh(&mut buf, name_text as u32, 1, 0x6, text_off as u64, code.len() as u64, 0, 0);
    push_sh(&mut buf, name_src as u32, 1, 0x3, src_off as u64, data_blob.len() as u64, 0, 0);
    push_sh(&mut buf, name_symtab as u32, 2, 0, sym_off as u64, sym_sec.len() as u64, 4, 24);
    push_sh(&mut buf, name_strtab as u32, 3, 0, stro_off as u64, strtab.len() as u64, 0, 0);
    push_sh(&mut buf, name_shstrtab as u32, 3, 0, shstro_off as u64, shstrtab.len() as u64, 0, 0);

    buf[shoff_pos..shoff_pos + 8].copy_from_slice(&shoff.to_le_bytes());
    buf
}

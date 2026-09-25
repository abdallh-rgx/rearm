//! rearm-elf v2 — payload builder (see module docs in `dynmeta.rs` and the
//! runtime `thunk.S`). Two/three-pass translation with far-conditional
//! expansion, PLT stubs, ADR-to-code fixups, loader relocation records.

use crate::dynmeta::*;
use crate::objread::Obj64;
use crate::{Elf32, RewriteStats};
use rearm_core::a64::encode::A64;
use rearm_core::a32::ins::*;
use rearm_core::common::Cond;
use rearm_core::t32::decode::decode_t32;
use rearm_core::translate::bias;
use rearm_core::translate::t32_to_a64::{translate_t32, ItTracker};

// loader relocation kinds
pub const REL_MAP32: u32 = 1;
pub const REL_IMPORT32: u32 = 2;

pub struct PReloc { pub kind: u32, pub off: u32, pub aux: u32 }

pub struct PExport {
    pub name: String,
    pub payload_off: u32,
    pub is_jni: bool,
}

pub struct Payload {
    pub bytes: Vec<u8>,
    pub map_off: u32,
    pub map_count: u32,
    pub reloc_off: u32,
    pub reloc_count: u32,
    pub got64_off: u32,
    pub imports: Vec<String>,
    pub exports: Vec<PExport>,
    pub shadow_off: u32,
    pub init: u32,
    pub init_array: (u32, u32),
    pub soname: String,
    pub needed: Vec<String>,
    pub stats: RewriteStats,
    pub tls_relocs: usize,
}

thread_local! {
    static UNSUP: std::cell::RefCell<std::collections::BTreeMap<String, usize>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

impl crate::RewriteStats {
    pub fn note_unsupported(&mut self, what: &str) {
        UNSUP.with(|m| *m.borrow_mut().entry(what.to_string()).or_insert(0) += 1);
    }
    pub fn print_unsupported_histogram(&self) {
        UNSUP.with(|m| {
            let mut v: Vec<(String, usize)> = m.borrow().iter().map(|(k, c)| (k.clone(), *c)).collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            for (k, c) in v.iter().take(28) {
                eprintln!("[rearm] unsupported: {:>9}x {}", c, k);
            }
        });
        UNSUPENC.with(|m| {
            let mut v: Vec<((u32, u32), usize)> = m.borrow().iter().map(|(k, c)| (*k, *c)).collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            for ((cond, op1), c) in v.iter().take(40) {
                eprintln!("[rearm] undec: cond={:X} op1={:02X} op2={:03X} => {}x",
                    cond, op1 & 0xFF, (op1 >> 0) & 0xFF, c / 2);
            }
        });
    }
}

thread_local! {
    static UNSUPENC: std::cell::RefCell<std::collections::BTreeMap<(u32, u32), usize>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

// ==================== fixups ====================

#[derive(Clone, Copy, PartialEq)]
#[derive(Debug)]
enum FixKind { B, Bcond, Bl, Cbz, Cbnz }

struct Fixup { at: usize, kind: FixKind, target: u32, src: u32 }

struct AdrFixup { at: usize, target: u32 }

/// The BRK trap word for holes (brk #0xF00D).
const TRAP: u32 = 0xD42A_01A0;

// ==================== the translation pass ====================

struct PassResult {
    out: A64,
    map: Vec<(u32, u32)>,
    fixups: Vec<Fixup>,
    adrfixups: Vec<AdrFixup>,
    stats: RewriteStats,
    plt_adrp_fixups: Vec<(usize, u32)>, // (word idx, import idx)
    imports: Vec<String>,
}

/// One full translation pass. `farset` = source addresses of conditional
/// branches that must use the range-unbounded 3-word form.
fn translate_pass(elf: &Elf32, dm: &DynMeta, farset: &[u32]) -> Result<PassResult, String> {
    bias::BIAS.store(true, std::sync::atomic::Ordering::Relaxed);
    bias::SHADOW.store(0, std::sync::atomic::Ordering::Relaxed);
    bias::THUNK.store(0, std::sync::atomic::Ordering::Relaxed);

    let mut out = A64::new();
    let mut stats = RewriteStats::default();
    let mut map: Vec<(u32, u32)> = Vec::new();
    let mut fixups: Vec<Fixup> = Vec::new();
    let mut adrfixups: Vec<AdrFixup> = Vec::new();

    // ---- thunk (word 0): assembled blob + its 4 relocations ----
    let thunk_obj = Obj64::parse(include_bytes!("../../../runtime/thunk.o"))
        .map_err(|e| format!("thunk.o: {e}"))?;
    let thunk = thunk_obj.text().map_err(|e| format!("thunk.o: {e}"))?;
    let thunk_words = thunk.bytes.len() / 4;
    let mut thunk_relocs: Vec<(usize, bool)> = Vec::new(); // (word idx, is_map)
    for r in thunk_obj.relas.iter().filter(|r| r.section == thunk_obj.sections.iter().position(|s| s.name == ".text").unwrap()) {
        let word = (r.off / 4) as usize;
        thunk_relocs.push((word, thunk_obj.symbols[r.sym].name.contains("MAP")));
    }
    for w in 0..thunk_words {
        out.e(u32::from_le_bytes([thunk.bytes[w * 4], thunk.bytes[w * 4 + 1], thunk.bytes[w * 4 + 2], thunk.bytes[w * 4 + 3]]));
    }

    // ---- imports: JUMP_SLOT + CALL/JUMP24-referenced undefined symbols ----
    let mut imports: Vec<String> = Vec::new();
    let mut import_idx = |name: &str, v: &mut Vec<String>| -> u32 {
        if let Some(i) = v.iter().position(|n| n == name) { return i as u32; }
        v.push(name.to_string());
        (v.len() - 1) as u32
    };
    for r in dm.rel_plt.iter().filter(|r| r.typ == R_ARM_JUMP_SLOT) {
        if let Some(sym) = dm.dynsyms.get(r.sym as usize) {
            if sym.is_undef && !sym.name.is_empty() {
                import_idx(&sym.name, &mut imports);
            }
        }
    }
    for r in dm.rel_dyn.iter().filter(|r| matches!(r.typ, R_ARM_CALL | R_ARM_JUMP24 | R_ARM_PC24)) {
        if let Some(sym) = dm.dynsyms.get(r.sym as usize) {
            if sym.is_undef && !sym.name.is_empty() {
                import_idx(&sym.name, &mut imports);
            }
        }
    }
    // GOT-referenced undefined symbols (GLOB_DAT / ABS32 undefined)
    for r in dm.rel_dyn.iter() {
        if let Some(sym) = dm.dynsyms.get(r.sym as usize) {
            if r.sym != 0 && sym.is_undef && !sym.name.is_empty()
                && matches!(r.typ, R_ARM_GLOB_DAT | R_ARM_ABS32 | R_ARM_TARGET1) {
                import_idx(&sym.name, &mut imports);
            }
        }
    }

    // ---- PLT stubs (one per import, uniform 5 words) ----
    //   movz w15, #(idx & 0xffff)
    //   movk w15, #(idx >> 16), lsl #16
    //   adrp x16, page(GOT64 + idx*8)      [patched post-layout]
    //   ldr  x17, [x16, #lo12(GOT64 + idx*8)]  [patched post-layout]
    //   br   x17
    let mut plt_adrp_fixups: Vec<(usize, u32)> = Vec::new();
    let mut plt_src_to_stub: Vec<(u32, u32)> = Vec::new();
    let n_stubs = imports.len() as u32;
    for (i, _) in imports.iter().enumerate() {
        let idx = i as u32;
        // pre-seed map: first PLT entry address → this stub (patched to the
        // real PLT addresses below once we know the GOT slots)
        let _ = n_stubs;
        let _ = idx;
        out.movz(false, 0, (idx & 0xFFFF) as u16, 15);
        out.movk(false, 1, ((idx >> 16) & 0xFFFF) as u16, 15);
        plt_adrp_fixups.push((out.len(), idx));
        out.adrp(16, 0);
        out.ldst_uimm(3, 1, 0, 16, 17);
        out.br(17);
    }

    // PLT source-address → stub offset (for bl fixups into the original PLT)
    for (plt_addr, got_slot) in dm.plt_to_got.iter() {
        let Some(&(_, sym_idx)) = dm.got_to_sym.iter().find(|(g, _)| g == got_slot) else { continue };
        let Some(sym) = dm.dynsyms.get(sym_idx as usize) else { continue };
        if let Some(pos) = imports.iter().position(|n| *n == sym.name) {
            let stub_off = (thunk_words as u32 + pos as u32 * 5) * 4;
            plt_src_to_stub.push((*plt_addr, stub_off));
        }
    }

    // ---- per-section translation ----
    for (sec_idx, _s0) in elf.sections.iter().enumerate()
        .filter(|(_, s)| s.flags & 0x4 != 0 && s.size > 0 && s.typ != 0 && s.name != ".plt")
    {
        let vbases = elf.vbases();
        let vbase = vbases[sec_idx];
        let sec = &elf.sections[sec_idx];

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
                    Ok(rearm_core::a32::ins::Ins::Unsupported { .. }) => {
                        stats.undefined_enc += 0;
                        UNSUPENC.with(|m| {
                            let e = m.borrow_mut().entry((w >> 28, (w >> 20) & 0xFF)).or_insert(0);
                            *e += 1;
                        });
                        stats.note_unsupported("EncUnsupported");
                        map.push((addr, (out.len() as u32) * 4));
                        out.e(TRAP);
                        addr += 4;
                        continue;
                    }
                    Ok(i) => i,
                    Err(_) => {
                        stats.undefined_enc += 1;
                        map.push((addr, (out.len() as u32) * 4));
                        out.e(TRAP);
                        addr += 4;
                        continue;
                    }
                };
                stats.a32_ins += 1;
                let start = out.len();
                // far conditional (B.cond): range-unbounded 2-word form
                if let Ins::B { cond: c, off } = &ins {
                    if *c != Cond::Al && farset.binary_search(&addr).is_ok() {
                        map.push((addr, (start as u32) * 4));
                        out.bcond(c.invert(), 8);
                        out.b(0).map_err(|e| e.to_string())?;
                        fixups.push(Fixup { at: start + 1, kind: FixKind::B,
                            target: addr.wrapping_add(8).wrapping_add(*off as u32), src: addr });
                        stats.translated += 1;
                        addr += 4;
                        continue;
                    }
                }
                // A32 ADR → code target: deferred-map adrp+add pair
                if let Ins::DpImm { op: DpOp::Add, s: false, rn: 15, rd, imm12 } = &ins {
                    let target = addr.wrapping_add(8).wrapping_add(arm_rot_imm(*imm12 as u32));
                    if *rd != 15 && target >= dm.text_range.0 && target < dm.text_range.1 {
                        adrfixups.push(AdrFixup { at: out.len(), target });
                        out.adrp(*rd, 0);
                        out.add_imm(true, *rd, *rd, 0);
                        stats.translated += 1;
                        map.push((addr, (start as u32) * 4));
                        addr += 4;
                        continue;
                    }
                }
                match rearm_core::translate::a32_to_a64::translate_a32(&ins, addr, &mut out) {
                    Ok(true) => {
                        stats.translated += 1;
                        map.push((addr, (start as u32) * 4));
                        record_branch_a32(&ins, addr, &mut fixups, start);
                    }
                    _ => {
                        stats.unsupported += 1;
                        let d = format!("{:?}", ins);
                        stats.note_unsupported(d.split(['{', ' ']).next().unwrap_or("?"));
                        map.push((addr, (out.len() as u32) * 4));
                        out.e(TRAP);
                    }
                }
                addr += 4;
                continue;
            }

            match decode_t32(hw1, hw2) {
                Ok(tins) => {
                    let len = tins.len as u32;
                    if matches!(tins.ins, Ins::Unsupported { .. }) {
                        stats.unsupported += 1;
                        map.push((addr, (out.len() as u32) * 4));
                        out.e(TRAP);
                        addr += len;
                        continue;
                    }
                    if let Ins::It { first_cond, mask } = &tins.ins {
                        it = Some(ItTracker::new(*first_cond, *mask));
                        stats.it_blocks += 1;
                        map.push((addr, (out.len() as u32) * 4));
                        addr += len;
                        continue;
                    }
                    let cond = match &mut it { Some(tr) => tr.next(), None => None };
                    stats.t32_ins += 1;
                    let start = out.len();

                    // far conditionals: range-unbounded 2-word form
                    if cond.is_none() && farset.binary_search(&addr).is_ok() {
                        let handled = match &tins.ins {
                            Ins::B { cond: c, off } if *c != Cond::Al => {
                                let base = addr.wrapping_add(4) & !3u32;
                                out.bcond(c.invert(), 8);
                                out.b(0).map_err(|e| e.to_string())?;
                                fixups.push(Fixup { at: start + 1, kind: FixKind::B,
                                    target: base.wrapping_add(*off as u32), src: addr });
                                true
                            }
                            Ins::Cbz { nz, rn, off } => {
                                if *nz { out.cbz(false, *rn, 0).map_err(|e| e.to_string())?; } else { out.cbnz(false, *rn, 0).map_err(|e| e.to_string())?; }
                                out.b(0).map_err(|e| e.to_string())?;
                                fixups.push(Fixup { at: start + 1, kind: FixKind::B,
                                    target: addr.wrapping_add(4).wrapping_add(*off as u32), src: addr });
                                true
                            }
                            _ => false,
                        };
                        if handled {
                            stats.translated += 1;
                            map.push((addr, (start as u32) * 4));
                            addr += len;
                            continue;
                        }
                    }

                    // T32 ADR → code target
                    if let Ins::DpImmT32 { op: DpOp::Add, s: false, rn: 15, rd, imm12, plain: true } = &tins.ins {
                        let target = (addr.wrapping_add(4) & !3u32).wrapping_add(*imm12 as u32);
                        if *rd != 15 && target >= dm.text_range.0 && target < dm.text_range.1 {
                            adrfixups.push(AdrFixup { at: out.len(), target });
                            out.adrp(*rd, 0);
                            out.add_imm(true, *rd, *rd, 0);
                            stats.translated += 1;
                            map.push((addr, (start as u32) * 4));
                            addr += len;
                            continue;
                        }
                    }

                    match translate_t32(&tins.ins, addr, &mut out, cond) {
                        Ok(true) => {
                            stats.translated += 1;
                            map.push((addr, (start as u32) * 4));
                            record_branch_t32(&tins.ins, addr, len, &mut fixups, start, out.len());
                        }
                        _ => {
                            stats.unsupported += 1;
                            let d = format!("{:?}", tins.ins);
                            stats.note_unsupported(d.split(['{', ' ']).next().unwrap_or("?"));
                            map.push((addr, (out.len() as u32) * 4));
                            out.e(TRAP);
                        }
                    }
                    addr += len;
                }
                Err(_) => {
                    stats.undefined_enc += 1;
                    map.push((addr, (out.len() as u32) * 4));
                    out.e(TRAP);
                    addr += 2;
                }
            }
        }
        stats.functions += marks.iter().filter(|(_, m)| *m != Mode::Data).count();
    }

    // merge PLT source addresses into the map
    for (src, off) in plt_src_to_stub.iter() {
        map.push((*src, *off));
    }
    map.sort_unstable();
    map.dedup();

    stats.a64_words = out.len();
    Ok(PassResult { out, map, fixups, adrfixups, stats, plt_adrp_fixups, imports })
}

fn is_far_branch(_ins: &Ins, _farset: &[u32]) -> bool { false } // superseded — see the section loop

/// ARM imm12 rotate: imm8 ror (rot*2).
fn arm_rot_imm(imm12: u32) -> u32 {
    let rot = ((imm12 >> 8) & 0xF) * 2;
    (imm12 & 0xFF).rotate_right(rot)
}

fn record_branch_t32(ins: &Ins, addr: u32, len: u32, fix: &mut Vec<Fixup>, start: usize, end: usize) {
    match ins {
        Ins::B { cond, off } => {
            let base = if len == 4 { addr.wrapping_add(4) & !3u32 } else { addr.wrapping_add(4) };
            fix.push(Fixup {
                at: start,
                kind: if *cond == Cond::Al { FixKind::B } else { FixKind::Bcond },
                target: base.wrapping_add(*off as u32),
                src: addr,
            });
        }
        Ins::Bl { off } | Ins::Blx { off } => {
            fix.push(Fixup { at: end - 1, kind: FixKind::Bl, target: (addr.wrapping_add(4) & !3u32).wrapping_add(*off as u32), src: addr });
        }
        Ins::Cbz { nz, off, .. } => {
            fix.push(Fixup {
                at: start,
                kind: if *nz { FixKind::Cbnz } else { FixKind::Cbz },
                target: addr.wrapping_add(4).wrapping_add(*off as u32),
                src: addr,
            });
        }
        _ => {}
    }
}

fn record_branch_a32(ins: &Ins, addr: u32, fix: &mut Vec<Fixup>, start: usize) {
    match ins {
        Ins::B { off, .. } => fix.push(Fixup { at: start, kind: FixKind::B, target: addr.wrapping_add(8).wrapping_add(*off as u32), src: addr }),
        Ins::Bl { off } => fix.push(Fixup { at: start, kind: FixKind::Bl, target: addr.wrapping_add(8).wrapping_add(*off as u32), src: addr }),
        _ => {}
    }
}

// ==================== the driver ====================

pub fn build_payload(elf: &Elf32) -> Result<Payload, String> {
    let dm = elf.dynmeta()?;

    // ---- iterate passes until the far-branch set is stable ----
    let mut farset: Vec<u32> = Vec::new();
    let mut result = None;
    for _iter in 0..8 {
        let t0 = std::time::Instant::now();
        let p = translate_pass(elf, &dm, &farset)?;
        let new_far = compute_farset(&p);
        eprintln!("[rearm] pass {} done in {:.1}s: {} words, {} map entries, farset {} + new {}",
            _iter, t0.elapsed().as_secs_f32(), p.out.len(), p.map.len(), farset.len(), new_far.len());
        // monotone union: expansion only — converges, never oscillates
        let mut merged = farset.clone();
        merged.extend_from_slice(&new_far);
        merged.sort_unstable();
        merged.dedup();
        if merged.len() == farset.len() {
            result = Some(p);
            break;
        }
        farset = merged;
    }
    let mut p = result.unwrap_or_else(|| translate_pass(elf, &dm, &farset).unwrap());
    p.stats.print_unsupported_histogram();

    // ---- resolve fixups ----
    resolve_fixups(&mut p);
    resolve_adr_fixups(&mut p);

    // ---- layout ----
    let code_len = (p.out.len() as u32) * 4;
    let map_off = (code_len + 0xFFF) & !0xFFF;
    let map_count = p.map.len() as u32;
    let relocs = collect_relocs(elf, &dm, &p.imports);
    let reloc_count = relocs.len() as u32;
    let reloc_off = (map_off + 4 + map_count * 8 + 0xFFF) & !0xFFF;
    let got64_off = (reloc_off + reloc_count * 12 + 0xFFF) & !0xFFF;
    let shadow_off = (got64_off + p.imports.len() as u32 * 8 + 0xFFF) & !0xFFF;

    // ---- patch the thunk + PLT adrp/add pairs for the final layout ----
    for (word, is_map) in thunk_relocs(p.out.len()).iter() {
        let target = if *is_map { map_off } else { shadow_off };
        patch_adrp_add(&mut p.out, *word, target);
    }
    for (word, idx) in p.plt_adrp_fixups.iter() {
        let target = got64_off + *idx * 8;
        patch_adrp_add(&mut p.out, *word, target);
    }

    // ---- shadow image ----
    let mut shadow_bytes: Vec<u8> = Vec::new();
    for seg in dm.segments.iter() {
        if seg.filesz == 0 { continue; }
        let start = seg.vaddr as usize;
        let end = start + seg.filesz as usize;
        if shadow_bytes.len() < end { shadow_bytes.resize(end, 0); }
        shadow_bytes[start..end].copy_from_slice(&elf.data[seg.off as usize..(seg.off + seg.filesz) as usize]);
    }

    // ---- assemble the payload bytes ----
    let mut bytes: Vec<u8> = Vec::with_capacity(shadow_off as usize + shadow_bytes.len());
    bytes.extend_from_slice(&p.out.bytes());
    bytes.resize(map_off as usize, 0);
    bytes.extend_from_slice(&map_count.to_le_bytes());
    for (src, off) in p.map.iter() {
        bytes.extend_from_slice(&src.to_le_bytes());
        bytes.extend_from_slice(&off.to_le_bytes());
    }
    bytes.resize(reloc_off as usize, 0);
    for r in relocs.iter() {
        bytes.extend_from_slice(&r.kind.to_le_bytes());
        bytes.extend_from_slice(&r.off.to_le_bytes());
        bytes.extend_from_slice(&r.aux.to_le_bytes());
    }
    bytes.resize(got64_off as usize, 0);
    bytes.resize(shadow_off as usize, 0);
    bytes.extend_from_slice(&shadow_bytes);

    // ---- exports ----
    let mut exports = Vec::new();
    for s in dm.dynsyms.iter() {
        if s.is_undef || !s.is_func || s.value == 0 { continue; }
        if s.value < dm.text_range.0 || s.value >= dm.text_range.1 { continue; }
        if let Some(&(_, off)) = p.map.iter().find(|&&(v, _)| v == (s.value & !1)) {
            exports.push(PExport {
                name: s.name.clone(),
                payload_off: off,
                is_jni: s.name.starts_with("Java_") || s.name == "JNI_OnLoad" || s.name == "JNI_OnUnload",
            });
        }
    }

    Ok(Payload {
        bytes,
        map_off,
        map_count,
        reloc_off,
        reloc_count,
        got64_off,
        imports: p.imports,
        exports,
        shadow_off,
        init: dm.init,
        init_array: dm.init_array,
        soname: dm.soname.clone(),
        needed: dm.needed.clone(),
        stats: p.stats,
        tls_relocs: dm.tls_relocs,
    })
}

/// Source addresses of conditional branches whose (previous-pass) fixup
/// distance exceeded the ±1 MiB A64 conditional-branch range — re-emitted in
/// the range-unbounded 2-word form (`b.<inv> +8; b target`).
fn compute_farset(p: &PassResult) -> Vec<u32> {
    let mut far: Vec<u32> = Vec::new();
    for f in p.fixups.iter() {
        if !matches!(f.kind, FixKind::Bcond | FixKind::Cbz | FixKind::Cbnz) { continue; }
        let Ok(i) = p.map.binary_search_by_key(&f.target, |&(x, _)| x) else { continue };
        let dist = (p.map[i].1 as i64) - (f.at as i64 * 4 + 4);
        if dist.abs() >= (1 << 19) - 256 {
            far.push(f.src);
        }
    }
    far.sort_unstable();
    far.dedup();
    far
}

/// Resolve branch fixups (B/BL ±128 MiB; conditionals must be near — the
/// farset expansion already handled the rest in a previous pass).
fn resolve_fixups(p: &mut PassResult) {
    let fixups = std::mem::take(&mut p.fixups);
    for f in fixups.iter() {
        let Ok(i) = p.map.binary_search_by_key(&f.target, |&(x, _)| x) else {
            p.stats.branches_unresolved += 1;
            if std::env::var_os("REARM_DBG").is_some() {
                eprintln!("UNRES @{:#x} kind={:?} -> {:#x}", f.src, f.kind, f.target);
            }
            continue;
        };
        let dst = p.map[i].1;
        let off_bytes = (dst as i64) - (f.at as i64 * 4 + 4);
        let in_range = match f.kind {
            FixKind::B | FixKind::Bl => off_bytes.abs() < (1 << 27),
            _ => off_bytes.abs() < (1 << 19),
        };
        if !in_range {
            p.stats.branches_unresolved += 1;
            continue;
        }
        let new = match f.kind {
            FixKind::B => 0b000101 << 26 | (((off_bytes >> 2) as u32) & 0x03FF_FFFF),
            FixKind::Bl => 0b100101 << 26 | (((off_bytes >> 2) as u32) & 0x03FF_FFFF),
            FixKind::Bcond => (p.out.buf[f.at] & 0xFF00001F) | ((((off_bytes >> 2) as u32) & 0x7FFFF) << 5),
            FixKind::Cbz | FixKind::Cbnz => (p.out.buf[f.at] & 0xFF00001F) | ((((off_bytes >> 2) as u32) & 0x1F_FFFF) << 5),
        };
        p.out.buf[f.at] = new;
        p.stats.branches_resolved += 1;
    }
}

/// Patch ADR-to-code pairs to their final mapped payload offsets.
fn resolve_adr_fixups(p: &mut PassResult) {
    let fixups = std::mem::take(&mut p.adrfixups);
    for f in fixups.iter() {
        if let Ok(i) = p.map.binary_search_by_key(&f.target, |&(x, _)| x) {
            patch_adrp_add(&mut p.out, f.at, p.map[i].1);
        }
    }
}

/// Patch an (adrp + add lo12) pair at word `at` to point at `target`.
fn patch_adrp_add(out: &mut A64, at: usize, target: u32) {
    let here = (at * 4) as i64;
    let tgt = target as i64;
    let dp = (((tgt & !0xFFF) - (here & !0xFFF)) >> 12) as i32;
    let v = (dp as u32) & 0x1F_FFFF;
    out.buf[at] = 0x9000_0000 | ((v & 3) << 29) | ((v >> 2) << 5) | (out.buf[at] & 0x1F);
    out.buf[at + 1] = (out.buf[at + 1] & !0x3F_FFC0) | (((tgt & 0xFFF) as u32) << 10);
}

/// The thunk's (word, is_map) relocation list.
fn thunk_relocs(_len: usize) -> Vec<(usize, bool)> {
    // offsets verified by llvm-readelf -r on runtime/thunk.o
    vec![(0, true), (1, true), (0x5C / 4, false), (0x60 / 4, false)]
}

// ==================== loader relocation records ====================

pub fn collect_relocs(elf: &Elf32, dm: &DynMeta, imports: &[String]) -> Vec<PReloc> {
    let mut out: Vec<PReloc> = Vec::new();
    let shadow = 0u32; // caller adds SHADOW_OFF — no: we pass offsets as SOURCE vaddrs and
    // the loader adds shadow_off itself. Slots are addressed in source space.
    let _ = shadow;
    let idx_of = |name: &str| imports.iter().position(|n| n == name).map(|i| i as u32);
    let mut push_import = |out: &mut Vec<PReloc>, name: &str, off: u32| {
        if let Some(i) = idx_of(name) {
            out.push(PReloc { kind: REL_IMPORT32, off, aux: i });
        } else {
            // symbol not in the import list (not PLT/CALL-referenced) — still
            // importable via its slot
            out.push(PReloc { kind: REL_IMPORT32, off, aux: 0xFFFF_FFFF });
        }
    };
    for r in dm.rel_dyn.iter().chain(dm.rel_plt.iter()) {
        let sym = if r.sym == 0 { None } else { dm.dynsyms.get(r.sym as usize) };
        match r.typ {
            R_ARM_RELATIVE => {
                let addend = elf.word_at_vaddr(r.off, dm);
                out.push(PReloc { kind: REL_MAP32, off: r.off, aux: addend });
            }
            R_ARM_GLOB_DAT | R_ARM_ABS32 | R_ARM_TARGET1 => {
                match sym {
                    Some(s) if !s.is_undef => out.push(PReloc { kind: REL_MAP32, off: r.off, aux: s.value & !1 }),
                    Some(s) if !s.name.is_empty() => push_import(&mut out, &s.name, r.off),
                    _ => {
                        let addend = elf.word_at_vaddr(r.off, dm);
                        out.push(PReloc { kind: REL_MAP32, off: r.off, aux: addend });
                    }
                }
            }
            R_ARM_JUMP_SLOT => {
                match sym {
                    Some(s) if !s.is_undef => out.push(PReloc { kind: REL_MAP32, off: r.off, aux: s.value & !1 }),
                    Some(s) if !s.name.is_empty() => push_import(&mut out, &s.name, r.off),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    out
}

impl Elf32 {
    /// Read the u32 at a source vaddr (RELATIVE addends are in-place).
    fn word_at_vaddr(&self, vaddr: u32, dm: &DynMeta) -> u32 {
        for seg in dm.segments.iter() {
            if vaddr >= seg.vaddr && vaddr + 4 <= seg.vaddr.wrapping_add(seg.filesz) {
                let o = (seg.off + (vaddr - seg.vaddr)) as usize;
                return u32::from_le_bytes([self.data[o], self.data[o + 1], self.data[o + 2], self.data[o + 3]]);
            }
        }
        0
    }
}

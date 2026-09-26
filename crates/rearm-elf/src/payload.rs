//! rearm-elf v2.1 — payload builder (low-world model).
//!
//! Produces a self-contained execution payload for a stripped ARM32 shared
//! library:
//!
//! * **Recursive-descent sweep** from every discoverable anchor (dynsym
//!   functions, relocation targets, DT_INIT/INIT_ARRAY, ADR-computed code
//!   pointers) — only reachable code is translated, data-in-text (literal
//!   pools, jump tables) is never decoded. Unvisited bytes stay data.
//! * **TBB/TBH jump tables** are discovered by scanning table entries while
//!   targets stay inside the executable sections and out of the table span;
//!   every entry seeds a new sweep so switch targets get translated. The
//!   runtime dispatch itself reads the table from the guest image and maps
//!   through the thunk, so entries missed at build time still work when
//!   their targets are in the map from other paths.
//! * **Far conditional branches** (b.cond/cbz ±1 MiB limit) are re-emitted in
//!   a range-unbounded 2-word form via an iterative fixpoint over the far
//!   set (monotone: expansion only).
//! * **PLT**: one 3-word stub per imported symbol (`w15 = idx; b adapter`),
//!   resolved through GOT64[idx] by the runtime adapter with AAPCS→AAPCS64
//!   marshaling. Original PLT entry addresses are seeded into the code map
//!   so translated `bl`s into the .plt land on the stubs.
//! * **Memory model**: everything the guest can name is a 32-bit low address
//!   (below 4 GiB) — translated code window C, guest image window W, stacks,
//!   heap and foreign-pointer bridge stubs. PC reads, ADR and literal pools
//!   materialize absolute low constants; R_ARM_RELATIVE relocs are pre-based
//!   (W + addend) at build time so the loader applies them with plain 32-bit
//!   stores.
//!
//! Payload layout (byte offsets):
//! ```text
//!   0x00  header (128 B) — see runtime/rearm_rt.S
//!   0x80  rearm_rt blob (glue @ 128, thunk @ 136, adapters)
//!         PLT stubs (3 words × imports)
//!         translated code (the sweep output)
//!         [4 KiB-aligned] map: u32 count + (u32 key, u32 off) pairs
//!         [4 KiB-aligned] relocs: (u32 kind, u32 off, u32 aux) triples
//!         [4 KiB-aligned] GOT64: u64 × imports
//!         [4 KiB-aligned] shadow blob: the source image (vaddr-indexed,
//!                            covering memsz incl. .bss)
//! ```

use crate::dynmeta::*;
use crate::objread::Obj64;
use crate::{Elf32, RewriteStats};
use rearm_core::a64::encode::A64;
use rearm_core::a32::ins::*;
use rearm_core::common::Cond;
use rearm_core::t32::decode::decode_t32;
use rearm_core::translate::bias;
use rearm_core::translate::t32_to_a64::{translate_t32, thumb_expand_imm, ItTracker};

// loader relocation kinds
pub const REL_MAP32: u32 = 1;
pub const REL_IMPORT32: u32 = 2;

/// The BRK trap word for undecodable holes (brk #0xF00D).
const TRAP: u32 = 0xD42A_01A0;

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
    pub shadow_len: u32,
    pub init: u32,
    pub init_array: (u32, u32),
    pub soname: String,
    pub needed: Vec<String>,
    pub stats: RewriteStats,
    pub tls_relocs: usize,
    /// guest-image window base (absolute low address W)
    pub window: u32,
    /// translated-code window base (absolute low address C)
    pub code_base: u32,
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
    }
}

// ==================== fixups ====================

#[derive(Clone, Copy, PartialEq, Debug)]
enum FixKind { B, Bcond, Bl, Cbz, Cbnz }

struct Fixup { at: usize, kind: FixKind, target: u32, src: u32 }

struct PassResult {
    out: A64,
    /// (guest key, payload off, priority) — priority 1 = trusted (runs that
    /// have not crossed a TRAP hole), 0 = suspect (post-hole fallthrough).
    map: Vec<(u32, u32, u8)>,
    fixups: Vec<Fixup>,
    stats: RewriteStats,
    plt_adrp_fixups: Vec<(usize, u32)>, // (word idx, import idx) — legacy, unused
    imports: Vec<String>,
    /// (source PLT addr, target function vaddr) for locally-defined symbols
    /// called through the PLT — resolved to translated code after the sweep.
    local_plt: Vec<(u32, u32)>,
    /// payload offset of rearm_plt_adapter (rt blob symbol)
    adapter_off: u32,
}

/// One full translation pass. `farset` = source addresses of conditional
/// branches that must use the range-unbounded 2-word form.
fn translate_pass(elf: &Elf32, dm: &DynMeta, farset: &[u32], window: u32) -> Result<PassResult, String> {
    bias::BIAS.store(true, std::sync::atomic::Ordering::Relaxed);
    bias::W.store(window, std::sync::atomic::Ordering::Relaxed);

    let reb = |a: u32| window.wrapping_add(a);

    let mut out = A64::new();
    let mut stats = RewriteStats::default();
    let mut map: Vec<(u32, u32, u8)> = Vec::new();
    let mut fixups: Vec<Fixup> = Vec::new();

    // ---- header space (32 words, patched by the driver) ----
    for _ in 0..32 { out.e(0); }

    // ---- runtime blob (glue @64, thunk @72, adapters) ----
    let rt_obj = Obj64::parse(include_bytes!("../../../runtime/rearm_rt.o"))
        .map_err(|e| format!("rearm_rt.o: {e}"))?;
    let rt = rt_obj.sections.iter().find(|s| s.name == ".text")
        .ok_or("rearm_rt.o: no .text")?;
    for w in 0..(rt.bytes.len() / 4) {
        out.e(u32::from_le_bytes([rt.bytes[w * 4], rt.bytes[w * 4 + 1], rt.bytes[w * 4 + 2], rt.bytes[w * 4 + 3]]));
    }
    let thunk_off = 128 + 8; // glue (2 words) precedes the thunk
    bias::THUNK.store(thunk_off, std::sync::atomic::Ordering::Relaxed);
    let adapter_off = rt_obj.symbols.iter()
        .find(|s| s.name == "rearm_plt_adapter" && s.typ == 2)
        .map(|s| 128 + s.value as u32)
        .ok_or("rearm_rt.o: no rearm_plt_adapter symbol")? as i32;

    // ---- imports: JUMP_SLOT + CALL/JUMP24 + GOT-referenced undefined syms ----
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
    for r in dm.rel_dyn.iter() {
        if let Some(sym) = dm.dynsyms.get(r.sym as usize) {
            if r.sym != 0 && sym.is_undef && !sym.name.is_empty()
                && matches!(r.typ, R_ARM_GLOB_DAT | R_ARM_ABS32 | R_ARM_TARGET1) {
                import_idx(&sym.name, &mut imports);
            }
        }
    }

    // ---- PLT stubs (3 words per import): w15 = idx; b adapter ----
    for (i, _) in imports.iter().enumerate() {
        let idx = i as u32;
        out.movz(false, 0, (idx & 0xFFFF) as u16, 15);
        out.movk(false, 1, ((idx >> 16) & 0xFFFF) as u16, 15);
        let here = (out.len() * 4) as i32;
        out.b(adapter_off - here).map_err(|_| "plt b range".to_string())?;
    }
    let plt_stub_base = 128 + rt.bytes.len() as u32; // byte offset of stub 0

    // ---- original PLT entry → stub / local target ----
    if std::env::var_os("REARM_DBG").is_some() {
        eprintln!("[dbg] plt_to_got={} got_to_sym={} imports={}", dm.plt_to_got.len(), dm.got_to_sym.len(), imports.len());
    }
    let mut local_plt: Vec<(u32, u32)> = Vec::new();
    for (plt_addr, got_slot) in dm.plt_to_got.iter() {
        let Some(&(_, sym_idx)) = dm.got_to_sym.iter().find(|(g, _)| g == got_slot) else { continue };
        let Some(sym) = dm.dynsyms.get(sym_idx as usize) else { continue };
        if sym.is_undef {
            if let Some(pos) = imports.iter().position(|n| *n == sym.name) {
                map.push((reb(*plt_addr), plt_stub_base + pos as u32 * 12, 1));
            }
        } else {
            // locally-defined symbol called through the PLT (interposition):
            // resolved to the translated function after the sweep
            local_plt.push((*plt_addr, sym.value & !1));
        }
    }

    // ---- executable section ranges (sorted) ----
    let mut exec_secs: Vec<(u32, u32, usize)> = Vec::new(); // (start, end, file off)
    for (i, sec) in elf.sections.iter().enumerate() {
        if sec.flags & 0x4 != 0 && sec.size > 0 && sec.typ != 0 && sec.name != ".plt" && sec.name != ".iplt" {
            let b = elf.vbases()[i];
            exec_secs.push((b, b.wrapping_add(sec.size as u32), sec.off));
        }
    }
    exec_secs.sort_unstable();
    let sec_of = |a: u32| -> Option<(u32, u32, usize)> {
        match exec_secs.binary_search_by(|&(s, e, _o)| {
            if a < s { std::cmp::Ordering::Greater } else if a >= e { std::cmp::Ordering::Less } else { std::cmp::Ordering::Equal }
        }) {
            Ok(i) => Some(exec_secs[i]),
            Err(_) => None,
        }
    };
    let in_exec = |a: u32| sec_of(a).is_some();
    let word_at = |a: u32| -> u32 {
        match sec_of(a) {
            Some((s, _e, off)) => {
                let o = off + (a - s) as usize;
                u32::from_le_bytes([elf.data[o], elf.data[o + 1], elf.data[o + 2], elf.data[o + 3]])
            }
            None => 0,
        }
    };

    // ---- dynsym function anchors (addr → thumb?) ----
    let mut anchors: Vec<(u32, bool)> = Vec::new();
    for sym in dm.dynsyms.iter() {
        if sym.is_undef || !sym.is_func || sym.value == 0 { continue; }
        if !in_exec(sym.value & !1) { continue; }
        anchors.push((sym.value & !1, sym.value & 1 == 1));
    }
    anchors.sort_unstable();
    anchors.dedup_by_key(|(a, _)| *a);
    let mode_at = |a: u32| -> bool {
        match anchors.binary_search_by_key(&a, |(x, _)| *x) {
            Ok(i) => anchors[i].1,
            Err(0) => true,
            Err(i) => anchors[i - 1].1,
        }
    };

    // ---- T32 immediate expansion for ADR-like ADD (register, PC) ----
    let t32_pc_aligned = |addr: u32| (addr.wrapping_add(4)) & !3u32;

    // ---- the sweep ----
    use std::collections::VecDeque;
    let mut queue: VecDeque<(u32, bool)> = VecDeque::new();
    let mut seed = |queue: &mut VecDeque<(u32, bool)>, a: u32, thumb: bool| {
        if in_exec(a & !1) { queue.push_back((a & !1, thumb)); }
    };
    for &(a, t) in anchors.iter() { seed(&mut queue, a, t); }
    for r in dm.rel_dyn.iter() {
        match r.typ {
            R_ARM_RELATIVE => {
                let addend = elf.word_at_vaddr(r.off, dm);
                if addend != 0 { seed(&mut queue, addend, addend & 1 == 1); }
            }
            R_ARM_GLOB_DAT | R_ARM_ABS32 | R_ARM_TARGET1 | R_ARM_CALL | R_ARM_JUMP24 | R_ARM_PC24 => {
                if r.sym != 0 {
                    if let Some(sym) = dm.dynsyms.get(r.sym as usize) {
                        if !sym.is_undef { seed(&mut queue, sym.value, sym.value & 1 == 1); }
                    }
                }
            }
            _ => {}
        }
    }
    if dm.init != 0 { seed(&mut queue, dm.init & !1, dm.init & 1 == 1); }
    if dm.init_array.0 != 0 && dm.init_array.1 > 0 {
        for i in 0..(dm.init_array.1 / 4) {
            let v = elf.word_at_vaddr(dm.init_array.0 + i * 4, dm);
            if v != 0 { seed(&mut queue, v, v & 1 == 1); }
        }
    }

    let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();
    // literal-pool addresses discovered from LDR (literal) targets — runs
    // must stop when they walk into a pool (data-in-text)
    let mut pools: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let is_far = |src: u32| farset.binary_search(&src).is_ok();

    while let Some((addr0, thumb0)) = queue.pop_front() {
        if !visited.insert(addr0) { continue; }
        let Some((sec_start, sec_end, sec_off)) = sec_of(addr0) else { continue };
        let mut thumb = thumb0;
        let mut a = addr0;
        let mut it: Option<ItTracker> = None;
        let mut degraded = false; // crossed a TRAP hole: later pushes are suspect

        while a + 4 <= sec_end {
            if a != addr0 {
                if visited.contains(&a) { break; } // merged path
                if anchors.binary_search_by_key(&a, |(x, _)| *x).is_ok() { break; } // function boundary
                if pools.contains(&a) { break; } // literal pool: data
            }
            let rel = (a - sec_start) as usize;
            let base_off = sec_off + rel;

            // ============ T32 (Thumb) ============
            if thumb {
                let hw1 = u16::from_le_bytes([elf.data[base_off], elf.data[base_off + 1]]);
                let hw2 = if base_off + 4 <= sec_off + (sec_end - sec_start) as usize {
                    u16::from_le_bytes([elf.data[base_off + 2], elf.data[base_off + 3]])
                } else { 0 };
                let Ok(tins) = decode_t32(hw1, hw2) else {
                    stats.undefined_enc += 1; break; // data
                };
                let len = tins.len as u32;

                if let Ins::It { first_cond, mask } = &tins.ins {
                    it = Some(ItTracker::new(*first_cond, *mask));
                    stats.it_blocks += 1;
                    map.push((reb(a), (out.len() as u32) * 4, if degraded {0} else {1}));
                    visited.insert(a);
                    a += len;
                    continue;
                }
                let cond = match &mut it { Some(tr) => tr.next(), None => None };
                stats.t32_ins += 1;
                let start = out.len();

                // ---- terminal / special forms ----
                match &tins.ins {
                    Ins::Unsupported { .. } => {
                        stats.unsupported += 1;
                        map.push((reb(a), (out.len() as u32) * 4, if degraded {0} else {1}));
                        out.e(TRAP);
                        visited.insert(a);
                        a += len;
                        continue;
                    }
                    Ins::Tbb { rn, rm, half } => {
                        // runtime dispatch is thunk-based; statically seed
                        // the table targets so they get translated
                        if *rn == 15 {
                            let pc_al = t32_pc_aligned(a);
                            let mut e = 0u32;
                            loop {
                                let to = pc_al + e; // table entry address (rel)
                                let Some((ss, se, so)) = sec_of(to) else { break };
                                if to + if *half { 2 } else { 1 } > se { break; }
                                let eo = so + (to - ss) as usize;
                                let v = if *half {
                                    u16::from_le_bytes([elf.data[eo], elf.data[eo + 1]]) as u32
                                } else {
                                    elf.data[eo] as u32
                                };
                                let target = pc_al.wrapping_add(2 * v);
                                if e > 0 && target >= pc_al && target < pc_al + e {
                                    break; // self-overlap: past the real table
                                }
                                if !in_exec(target) && !(target >= pc_al && target < pc_al + e) {
                                    break;
                                }
                                if in_exec(target & !1) {
                                    seed(&mut queue, target, mode_at(target & !1));
                                }
                                e += if *half { 2 } else { 1 };
                                if e > 4096 { break; } // sanity cap
                            }
                        } else {
                            stats.note_unsupported("tbb/tbh (reg base)");
                        }
                        let _ = rm;
                        let translated = translate_t32(&tins.ins, a, &mut out, cond).map_err(|e| e.0)?;
                        if translated { stats.translated += 1; }
                        map.push((reb(a), (start as u32) * 4, if degraded {0} else {1}));
                        visited.insert(a);
                        a += len;
                        break; // table follows
                    }
                    _ => {}
                }

                // ---- far conditional forms (range-unbounded 2-word) ----
                let far_here = it.is_none() && (is_far(a) || branch_too_long(&tins.ins));
                match (&tins.ins, far_here) {
                    (Ins::B { cond: c, off }, true) if *c != Cond::Al => {
                        out.bcond(c.invert(), 8).map_err(|_| "bcond".to_string())?; // skip the next word
                        let at = out.len();
                        out.e(0); // b placeholder
                        let base = if len == 4 { t32_pc_aligned(a) } else { a.wrapping_add(4) };
                        fixups.push(Fixup { at, kind: FixKind::B, target: reb(base.wrapping_add(*off as u32)), src: a });
                        stats.translated += 1;
                        map.push((reb(a), (start as u32) * 4, if degraded {0} else {1}));
                        visited.insert(a);
                        a += len;
                        continue;
                    }
                    (Ins::Cbz { nz, rn, off }, true) => {
                        if *nz { out.cbz(false, *rn, 8).map_err(|_| "cbz".to_string())?; }
                        else { out.cbnz(false, *rn, 8).map_err(|_| "cbnz".to_string())?; }
                        let at = out.len();
                        out.e(0);
                        let target = a.wrapping_add(4).wrapping_add(*off as u32);
                        fixups.push(Fixup {
                            at,
                            kind: FixKind::B,
                            target: reb(target),
                            src: a,
                        });
                        stats.translated += 1;
                        map.push((reb(a), (start as u32) * 4, if degraded {0} else {1}));
                        visited.insert(a);
                        a += len;
                        continue;
                    }
                    _ => {}
                }

                // ---- literal-pool discovery: LDR (literal) targets ----
                if let Ins::Ldst { store: false, rn: 15, imm, .. } = &tins.ins {
                    pools.insert(t32_pc_aligned(a).wrapping_add(*imm as u32));
                }

                // ---- ADR-like ADD (register, PC): seed code targets ----
                match &tins.ins {
                    Ins::DpImmT32 { op: DpOp::Add, rn: 15, imm12, plain, .. } => {
                        let base = if *plain { t32_pc_aligned(a) } else { a.wrapping_add(4) };
                        let imm = if *plain { *imm12 as u32 } else { thumb_expand_imm(*imm12).0 };
                        let target = base.wrapping_add(imm);
                        if in_exec(target & !1) {
                            seed(&mut queue, target & !1, mode_at(target & !1));
                        }
                    }
                    _ => {}
                }

                // ---- generic translation ----
                match translate_t32(&tins.ins, a, &mut out, cond) {
                    Ok(true) => {
                        stats.translated += 1;
                        let at = if it.is_some() { start + 1 } else { start };
                        record_branch_t32(&tins.ins, a, len, &mut fixups, at, out.len(), reb);
                        // seed branch targets so taken paths get translated
                        match &tins.ins {
                            Ins::B { off, .. } => {
                                let target = t32_branch_target(a, len, *off);
                                seed(&mut queue, target & !1, thumb);
                            }
                            Ins::Bl { off } | Ins::Blx { off } => {
                                let target = (a.wrapping_add(4) & !3u32).wrapping_add(*off as u32);
                                seed(&mut queue, target & !1, thumb);
                            }
                            Ins::Cbz { off, .. } => {
                                let target = a.wrapping_add(4).wrapping_add(*off as u32);
                                seed(&mut queue, target & !1, thumb);
                            }
                            _ => {}
                        }
                    }
                    Ok(false) => { stats.unsupported += 1; stats.note_unsupported(format!("{:?}", tins.ins).split('{').next().unwrap_or("?")); out.e(TRAP); degraded = true; }
                    Err(e) => { stats.unsupported += 1; stats.note_unsupported(&format!("ERR {} @ t32", e.0)); out.e(TRAP); degraded = true; }
                }
                map.push((reb(a), (start as u32) * 4, if degraded {0} else {1}));
                visited.insert(a);

                // ---- stop rules ----
                let stop = match &tins.ins {
                    Ins::B { cond: Cond::Al, .. } => true,
                    Ins::Bx { .. } | Ins::BlxReg { .. } => true,
                    Ins::Blx { off } => { // mode switch: flip and continue
                        let base = (a.wrapping_add(4) & !3u32).wrapping_add(*off as u32);
                        seed(&mut queue, base, !thumb);
                        false
                    }
                    Ins::LdmStm { load: true, list, .. } if list.0.contains(&15) => true,
                    Ins::Svc { .. } => true,
                    Ins::DpReg { op, s, rd: 15, .. }
                        if !matches!(op, DpOp::Cmp | DpOp::Cmn | DpOp::Tst | DpOp::Teq)
                            && !(*op == DpOp::Sub && *s) => {
                        stats.note_unsupported("write to pc (reg)"); true
                    }
                    _ => false,
                };
                if stop { break; }
                a += len;
                continue;
            }

            // ============ A32 (ARM) ============
            let w = u32::from_le_bytes([elf.data[base_off], elf.data[base_off + 1], elf.data[base_off + 2], elf.data[base_off + 3]]);
            let Ok(ins) = rearm_core::a32::decode::decode_a32(w) else {
                stats.undefined_enc += 1; break;
            };
            stats.a32_ins += 1;
            let start = out.len();
            match &ins {
                Ins::Unsupported { .. } => {
                    stats.unsupported += 1;
                    map.push((reb(a), (out.len() as u32) * 4, 1));
                    out.e(TRAP);
                    visited.insert(a);
                    degraded = true;
                    a += 4;
                    continue;
                }
                _ => {}
            }

            // far conditional (A32 B.cond)
            if let Ins::B { cond: c, off } = &ins {
                if *c != Cond::Al && (is_far(a) || (*off as i64).abs() >= 0xF0000) {
                    out.bcond(c.invert(), 8).map_err(|_| "bcond".to_string())?;
                    let at = out.len();
                    out.e(0);
                    let target = a.wrapping_add(8).wrapping_add(*off as u32);
                    fixups.push(Fixup { at, kind: FixKind::B, target: reb(target), src: a });
                    stats.translated += 1;
                    map.push((reb(a), (start as u32) * 4, if degraded {0} else {1}));
                    visited.insert(a);
                    a += 4;
                    continue;
                }
            }

            // literal-pool discovery (A32): LDR (literal)
            if let Ins::Ldst { store: false, rn: 15, imm, .. } = &ins {
                pools.insert(a.wrapping_add(8).wrapping_add(*imm as u32));
            }

            // ADR-like: ADD rd, PC, #imm (rot form)
            if let Ins::DpImm { op: DpOp::Add, rn: 15, imm12, .. } = &ins {
                let rot = (((*imm12 >> 8) & 0xF) * 2) as u32;
                let target = a.wrapping_add(8).wrapping_add((*imm12 as u32 & 0xFF).rotate_right(rot));
                if in_exec(target & !1) { seed(&mut queue, target & !1, mode_at(target & !1)); }
            }

            match rearm_core::translate::a32_to_a64::translate_a32(&ins, a, &mut out) {
                Ok(true) => {
                    stats.translated += 1;
                    record_branch_a32(&ins, a, &mut fixups, start, reb);
                    match &ins {
                        Ins::B { off, .. } | Ins::Bl { off } => {
                            let target = a.wrapping_add(8).wrapping_add(*off as u32);
                            seed(&mut queue, target & !1, false);
                        }
                        _ => {}
                    }
                }
                Ok(false) => { stats.unsupported += 1; stats.note_unsupported(format!("{:?}", ins).split('{').next().unwrap_or("?")); out.e(TRAP); degraded = true; }
                Err(e) => { stats.unsupported += 1; stats.note_unsupported(&format!("ERR {} @ a32", e.0)); out.e(TRAP); degraded = true; }
            }
            map.push((reb(a), (start as u32) * 4, if degraded {0} else {1}));
            visited.insert(a);

            let stop = match &ins {
                Ins::B { cond: Cond::Al, .. } => true,
                Ins::Bx { .. } | Ins::BlxReg { .. } => true,
                Ins::Blx { off } => {
                    let target = a.wrapping_add(8).wrapping_add(*off as u32);
                    seed(&mut queue, target, !thumb);
                    false
                }
                Ins::LdmStm { load: true, list, .. } if list.0.contains(&15) => true,
                Ins::Svc { .. } => true,
                Ins::DpReg { op, s, rd: 15, .. }
                    if !matches!(op, DpOp::Cmp | DpOp::Cmn | DpOp::Tst | DpOp::Teq)
                        && !(*op == DpOp::Sub && *s) => {
                    stats.note_unsupported("write to pc (reg)"); true
                }
                _ => false,
            };
            if stop { break; }
            a += 4;
        }
    }

    if std::env::var_os("REARM_DBG2").is_some() {
        let want = window.wrapping_add(0x2570); // compress2
        let mut hits = Vec::new();
        for (k, o, p) in map.iter() { if *k == want { hits.push((*o, *p)); } }
        eprintln!("[dbg2] post-sweep: out.len()={} rt_prefix_check={:08x} map[compress2] hits={:?}",
            out.len(), out.buf.get(0x88).copied().unwrap_or(0), hits);
        // count entries with offsets < stub area start
        let stub_end = 128 + 288 + imports.len() * 12; // bytes
        let bad = map.iter().filter(|(_, o, _)| (*o as usize) < stub_end && (*o as usize) >= 128 + 288).count();
        let inrt = map.iter().filter(|(_, o, _)| (*o as usize) < 128 + 288).count();
        eprintln!("[dbg2] stub_end={} entries-in-stub-range={} entries-in-rt={} total={}", stub_end, bad, inrt, map.len());
    }
    stats.functions = anchors.len();
    // priority-aware dedup: sort by (key asc, priority desc) then keep the
    // first entry per key — trusted translations win over suspect ones.
    map.sort_unstable_by(|x, y| x.0.cmp(&y.0).then(y.2.cmp(&x.2)));
    map.dedup_by_key(|e| e.0);
    // local PLT stubs → translated target functions (map is sorted now)
    let mut resolved_local = 0usize;
    for (plt_addr, target) in local_plt.iter() {
        if let Ok(i) = map.binary_search_by_key(&reb(*target), |e| e.0) {
            map.push((reb(*plt_addr), map[i].1, 1));
            resolved_local += 1;
        } else {
            stats.branches_unresolved += 1; // local PLT target not translated
        }
    }
    map.sort_unstable_by(|x, y| x.0.cmp(&y.0).then(y.2.cmp(&x.2)));
    map.dedup_by_key(|e| e.0);
    fixups.sort_unstable_by_key(|f| f.target);
    stats.a64_words = out.len();
    Ok(PassResult { out, map, fixups, stats, plt_adrp_fixups: Vec::new(), imports, local_plt, adapter_off: adapter_off as u32 })
}

// register helper for Ins::Cbz (rn is a plain u8 register number)

/** True when a conditional branch's raw source offset already exceeds the
 * ±1 MiB A64 b.cond/cbz range — emit the far form immediately. */
fn branch_too_long(ins: &Ins) -> bool {
    match ins {
        Ins::B { cond, off } if *cond != Cond::Al => (*off as i64).abs() >= 0xF0000,
        Ins::Cbz { off, .. } => (*off as i64).abs() >= 0xF0000,
        _ => false,
    }
}

/// T32 branch target (source-relative), same base rules as record_branch_t32.
fn t32_branch_target(addr: u32, len: u32, off: i32) -> u32 {
    let base = if len == 4 { (addr.wrapping_add(4)) & !3u32 } else { addr.wrapping_add(4) };
    base.wrapping_add(off as u32)
}

/// Record branch fixups (T32). `reb` rebases source addresses to the window.
fn record_branch_t32(ins: &Ins, addr: u32, len: u32, fix: &mut Vec<Fixup>, at: usize, end: usize, reb: impl Fn(u32) -> u32) {
    match ins {
        Ins::B { cond, off } => {
            let base = if len == 4 { (addr.wrapping_add(4)) & !3u32 } else { addr.wrapping_add(4) };
            fix.push(Fixup {
                at,
                kind: if *cond == Cond::Al { FixKind::B } else { FixKind::Bcond },
                target: reb(base.wrapping_add(*off as u32)),
                src: addr,
            });
        }
        Ins::Bl { off } | Ins::Blx { off } => {
            fix.push(Fixup { at: end - 1, kind: FixKind::Bl, target: reb((addr.wrapping_add(4) & !3u32).wrapping_add(*off as u32)), src: addr });
        }
        Ins::Cbz { nz, rn: _, off } => {
            fix.push(Fixup {
                at,
                kind: if *nz { FixKind::Cbnz } else { FixKind::Cbz },
                target: reb(addr.wrapping_add(4).wrapping_add(*off as u32)),
                src: addr,
            });
        }
        _ => {}
    }
}

fn record_branch_a32(ins: &Ins, addr: u32, fix: &mut Vec<Fixup>, start: usize, reb: impl Fn(u32) -> u32) {
    match ins {
        Ins::B { off, .. } => fix.push(Fixup { at: start, kind: FixKind::B, target: reb(addr.wrapping_add(8).wrapping_add(*off as u32)), src: addr }),
        Ins::Bl { off } => fix.push(Fixup { at: start, kind: FixKind::Bl, target: reb(addr.wrapping_add(8).wrapping_add(*off as u32)), src: addr }),
        _ => {}
    }
}

// ==================== the driver ====================

pub fn build_payload(elf: &Elf32, window: u32, code_base: u32) -> Result<Payload, String> {
    let dm = elf.dynmeta()?;

    // ---- iterate passes until the far-branch set is stable ----
    let mut farset: Vec<u32> = Vec::new();
    let mut result = None;
    for _iter in 0..8 {
        let t0 = std::time::Instant::now();
        let p = translate_pass(elf, &dm, &farset, window)?;
        let new_far = compute_farset(&p);
        eprintln!("[rearm] pass {} in {:.1}s: {} words, {} map entries, farset {} + new {}",
            _iter, t0.elapsed().as_secs_f32(), p.out.len(), p.map.len(), farset.len(), new_far.len());
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
    let mut p = result.unwrap_or_else(|| translate_pass(elf, &dm, &farset, window).unwrap());
    p.stats.print_unsupported_histogram();

    // ---- resolve fixups ----
    resolve_fixups(&mut p);

    // ---- layout ----
    let code_len = (p.out.len() as u32) * 4;
    let map_off = (code_len + 0xFFF) & !0xFFF;
    let map_count = p.map.len() as u32;
    let relocs = collect_relocs(elf, &dm, &p.imports, window);
    let reloc_count = relocs.len() as u32;
    let reloc_off = (map_off + 4 + map_count * 8 + 0xFFF) & !0xFFF;
    let got64_off = (reloc_off + reloc_count * 12 + 0xFFF) & !0xFFF;

    // ---- import names blob ----
    let mut names: Vec<u8> = Vec::new();
    let mut name_offs: Vec<u32> = Vec::new();
    for n in p.imports.iter() {
        name_offs.push(names.len() as u32);
        names.extend_from_slice(n.as_bytes());
        names.push(0);
    }
    let imports_off = (got64_off + p.imports.len() as u32 * 8 + 0xFFF) & !0xFFF;
    let imports_len = 4 + p.imports.len() as u32 * 4 + names.len() as u32;

    // ---- shadow blob (source image, vaddr-indexed, covering memsz) ----
    let mut shadow_len: u32 = 0;
    for seg in dm.segments.iter() {
        if seg.memsz == 0 { continue; }
        shadow_len = shadow_len.max(seg.vaddr.wrapping_add(seg.memsz));
    }
    let mut shadow_bytes: Vec<u8> = vec![0u8; shadow_len as usize];
    for seg in dm.segments.iter() {
        if seg.filesz == 0 { continue; }
        let start = seg.vaddr as usize;
        let end = start + seg.filesz as usize;
        if end > shadow_bytes.len() { shadow_bytes.resize(end, 0); }
        shadow_bytes[start..end].copy_from_slice(&elf.data[seg.off as usize..(seg.off + seg.filesz) as usize]);
    }
    let shadow_off = (imports_off + imports_len + 0xFFF) & !0xFFF;
    let payload_size = shadow_off + shadow_len;

    // ---- assemble the payload bytes ----
    let mut bytes: Vec<u8> = Vec::with_capacity(payload_size as usize);
    bytes.extend_from_slice(&p.out.bytes());
    bytes.resize(map_off as usize, 0);
    bytes.extend_from_slice(&map_count.to_le_bytes());
    for (src, off, _p) in p.map.iter() {
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
    bytes.resize(imports_off as usize, 0);
    bytes.extend_from_slice(&(p.imports.len() as u32).to_le_bytes());
    for o in name_offs.iter() {
        bytes.extend_from_slice(&o.to_le_bytes());
    }
    bytes.extend_from_slice(&names);
    bytes.resize(shadow_off as usize, 0);
    bytes.extend_from_slice(&shadow_bytes);

    // ---- header (128 B) ----
    let p_adapter = p.adapter_off;
    let hdr = &mut bytes[0..128];
    hdr.copy_from_slice(&[0u8; 128]);
    hdr[0..8].copy_from_slice(b"REARM1\0\0");
    let mut put = |o: usize, v: u32| hdr[o..o + 4].copy_from_slice(&v.to_le_bytes());
    put(8, map_off);
    put(12, map_count);
    put(16, reloc_off);
    put(20, reloc_count);
    put(24, got64_off);
    put(28, p.imports.len() as u32);
    put(32, if dm.init != 0 { window.wrapping_add(dm.init) } else { 0 });
    put(36, if dm.init_array.0 != 0 { window.wrapping_add(dm.init_array.0) } else { 0 });
    put(40, dm.init_array.1);
    put(44, shadow_off);
    put(48, shadow_len);
    put(52, payload_size);
    put(56, code_base);
    put(60, window);
    put(64, imports_off);
    put(68, imports_len);
    put(124, p_adapter);

    // ---- exports ----
    let mut exports = Vec::new();
    for s in dm.dynsyms.iter() {
        if s.is_undef || !s.is_func || s.value == 0 { continue; }
        let want = window.wrapping_add(s.value & !1);
        if let Ok(i) = p.map.binary_search_by_key(&want, |e| e.0) {
            exports.push(PExport {
                name: s.name.clone(),
                payload_off: p.map[i].1,
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
        shadow_len,
        init: if dm.init != 0 { window.wrapping_add(dm.init) } else { 0 },
        init_array: (
            if dm.init_array.0 != 0 { window.wrapping_add(dm.init_array.0) } else { 0 },
            dm.init_array.1,
        ),
        soname: dm.soname.clone(),
        needed: dm.needed.clone(),
        stats: p.stats,
        tls_relocs: dm.tls_relocs,
        window,
        code_base,
    })
}

/// Source addresses of conditional branches whose (previous-pass) fixup
/// distance exceeded the ±1 MiB A64 conditional-branch range — re-emitted in
/// the range-unbounded 2-word form (`b.<inv> skip; b target`).
fn compute_farset(p: &PassResult) -> Vec<u32> {
    let mut far: Vec<u32> = Vec::new();
    for f in p.fixups.iter() {
        if !matches!(f.kind, FixKind::Bcond | FixKind::Cbz | FixKind::Cbnz) { continue; }
        let Ok(i) = p.map.binary_search_by_key(&f.target, |e| e.0) else { continue };
        let dist = (p.map[i].1 as i64) - (f.at as i64 * 4);
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
        let Ok(i) = p.map.binary_search_by_key(&f.target, |e| e.0) else {
            p.stats.branches_unresolved += 1;
            if std::env::var_os("REARM_DBG").is_some() {
                eprintln!("UNRES @{:#x} kind={:?} -> {:#x}", f.src, f.kind, f.target);
            }
            continue;
        };
        let dst = p.map[i].1;
        let off_bytes = (dst as i64) - (f.at as i64 * 4); // A64: PC-relative, no +4
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

// ==================== loader relocation records ====================

pub fn collect_relocs(elf: &Elf32, dm: &DynMeta, imports: &[String], window: u32) -> Vec<PReloc> {
    let reb = |a: u32| window.wrapping_add(a);
    let mut out: Vec<PReloc> = Vec::new();
    let idx_of = |name: &str| imports.iter().position(|n| n == name).map(|i| i as u32);
    for r in dm.rel_dyn.iter().chain(dm.rel_plt.iter()) {
        let sym = if r.sym == 0 { None } else { dm.dynsyms.get(r.sym as usize) };
        match r.typ {
            R_ARM_RELATIVE => {
                let addend = elf.word_at_vaddr(r.off, dm);
                out.push(PReloc { kind: REL_MAP32, off: reb(r.off), aux: reb(addend) });
            }
            R_ARM_GLOB_DAT | R_ARM_ABS32 | R_ARM_TARGET1 => {
                match sym {
                    Some(s) if !s.is_undef => out.push(PReloc { kind: REL_MAP32, off: reb(r.off), aux: reb(s.value & !1) }),
                    Some(s) if !s.name.is_empty() => {
                        if let Some(i) = idx_of(&s.name) {
                            out.push(PReloc { kind: REL_IMPORT32, off: reb(r.off), aux: i });
                        } else {
                            out.push(PReloc { kind: REL_IMPORT32, off: reb(r.off), aux: 0xFFFF_FFFF });
                        }
                    }
                    _ => {
                        let addend = elf.word_at_vaddr(r.off, dm);
                        out.push(PReloc { kind: REL_MAP32, off: reb(r.off), aux: reb(addend) });
                    }
                }
            }
            R_ARM_JUMP_SLOT => {
                match sym {
                    Some(s) if !s.is_undef => out.push(PReloc { kind: REL_MAP32, off: reb(r.off), aux: reb(s.value & !1) }),
                    Some(s) if !s.name.is_empty() => {
                        if let Some(i) = idx_of(&s.name) {
                            out.push(PReloc { kind: REL_IMPORT32, off: reb(r.off), aux: i });
                        }
                    }
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

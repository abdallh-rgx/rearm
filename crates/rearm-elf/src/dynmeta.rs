//! rearm-elf v2 — dynamic metadata of the source ELF32 ARM image.
//!
//! Parses program headers, `PT_DYNAMIC` tags, the dynamic symbol table,
//! and both relocation streams (`.rel.dyn`, `.rel.plt`), plus the PLT
//! (classic 3-instruction ARM PLT stubs) — everything the payload builder
//! needs to weave imports, exports and relocations into the translated
//! image.

use crate::Elf32;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;

// ARM relocation types (DT_REL stream, Elf32_Rel — no explicit addend).
pub const R_ARM_NONE: u8 = 0;
pub const R_ARM_PC24: u8 = 1;
pub const R_ARM_ABS32: u8 = 2;
pub const R_ARM_GLOB_DAT: u8 = 21;
pub const R_ARM_JUMP_SLOT: u8 = 22;
pub const R_ARM_RELATIVE: u8 = 23;
pub const R_ARM_GOT_BREL: u8 = 26;
pub const R_ARM_CALL: u8 = 28;
pub const R_ARM_JUMP24: u8 = 29;
pub const R_ARM_TARGET1: u8 = 38;
pub const R_ARM_V4BX: u8 = 40;
pub const R_ARM_GOT_PREL: u8 = 96;
pub const R_ARM_TLS_SLOT: u8 = 17; // PLACEHOLDER (real 17/18 are TLS)

#[derive(Debug, Clone, Copy, Default)]
pub struct Segment {
    pub flags: u32,
    pub off: u32,
    pub vaddr: u32,
    pub filesz: u32,
    pub memsz: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Reloc {
    pub off: u32,    // r_offset (source vaddr of the slot)
    pub typ: u8,
    pub sym: u32,   // dynsym index (0 = none)
}

#[derive(Debug, Clone)]
pub struct DynSym {
    pub name: String,
    pub value: u32,
    pub size: u32,
    pub info: u8,
    pub shndx: u16,
    /// pre-resolved name of the section index (via shndx table when present)
    pub is_func: bool,
    pub is_weak: bool,
    pub is_undef: bool,
}

#[derive(Default)]
pub struct DynMeta {
    pub soname: String,
    pub needed: Vec<String>,
    pub init: u32,
    pub init_array: (u32, u32), // (vaddr, byte size)
    pub segments: Vec<Segment>,
    pub dynsyms: Vec<DynSym>,
    pub rel_dyn: Vec<Reloc>,
    pub rel_plt: Vec<Reloc>,
    pub pltgot: u32,
    /// PLT entry start address → resolved GOT slot vaddr
    pub plt_to_got: Vec<(u32, u32)>,
    /// GOT slot vaddr → dynsym index (from .rel.plt)
    pub got_to_sym: Vec<(u32, u32)>,
    pub text_range: (u32, u32), // union of SHF_EXECINSTR sections (vaddr space)
    pub tls_relocs: usize,
}

impl Elf32 {
    /// Parse every dynamic-structure the payload builder needs.
    pub fn dynmeta(&self) -> Result<DynMeta, String> {
        let rd16 = |o: usize| u16::from_le_bytes([self.data[o], self.data[o + 1]]) as usize;
        let rd32 = |o: usize| u32::from_le_bytes([self.data[o], self.data[o + 1], self.data[o + 2], self.data[o + 3]]);

        // ---- program headers ----
        let phoff = rd32(0x1C) as usize;
        let phentsize = rd16(0x2A);
        let phnum = rd16(0x2C);
        let mut segments = Vec::new();
        let mut dyn_off = None;
        for i in 0..phnum {
            let p = phoff + i * phentsize;
            if p + 32 > self.data.len() { break; }
            let typ = rd32(p);
            let seg = Segment {
                flags: rd32(p + 24),
                off: rd32(p + 4),
                vaddr: rd32(p + 8),
                filesz: rd32(p + 16),
                memsz: rd32(p + 20),
            };
            if typ == PT_LOAD {
                segments.push(seg);
            } else if typ == PT_DYNAMIC {
                dyn_off = Some((seg.off, seg.filesz));
            }
        }
        if segments.is_empty() {
            return Err("no PT_LOAD (ET_REL input: use section fallback)".into());
        }

        // ---- dynamic array ----
        let (dyn_off, dyn_sz) = dyn_off.ok_or("no PT_DYNAMIC")?;
        let mut tags: Vec<(u64, u32)> = Vec::new();
        let mut i = 0usize;
        while i + 8 <= dyn_sz as usize {
            let o = dyn_off as usize + i;
            if o + 8 > self.data.len() { break; }
            // Elf32_Dyn = { i32 d_tag; u32 d_val } — 8 bytes total
            let tag = i32::from_le_bytes([self.data[o], self.data[o + 1], self.data[o + 2], self.data[o + 3]]) as i64 as u64;
            let val = u32::from_le_bytes([self.data[o + 4], self.data[o + 5], self.data[o + 6], self.data[o + 7]]);
            let is_end = tag == 0;
            tags.push((tag, val));
            if is_end { break; }
            i += 8;
        }

        let tagv = |want: u64| -> Option<u32> {
            tags.iter().find(|(t, _)| *t == want).map(|(_, v)| *v)
        };

        // dynsym/dynstr addresses → file offsets via segments
        let v2o = |vaddr: u32| -> Option<usize> {
            for s in segments.iter() {
                if vaddr >= s.vaddr && vaddr < s.vaddr.wrapping_add(s.filesz) {
                    return Some((s.off + (vaddr - s.vaddr)) as usize);
                }
            }
            None
        };
        let strtab_off = v2o(tagv(5).ok_or("no DT_STRTAB")?).ok_or("DT_STRTAB unmapped")?;
        let symtab_off = v2o(tagv(6).ok_or("no DT_SYMTAB")?).ok_or("DT_SYMTAB unmapped")?;

        // soname + NEEDED from DT_STRTAB
        let soname = tagv(14)
            .and_then(|o| self.str_at_addr(strtab_off + o as usize))
            .unwrap_or_default();
        let needed = tags.iter().filter(|(t, _)| *t == 1)
            .filter_map(|(_, v)| self.str_at_addr(strtab_off + *v as usize))
            .collect::<Vec<_>>();

        // ---- dynsym ----
        // Symbol count: via DT_HASH (nchain) when present, else the section
        // header of .dynsym, else scan until strtab.
        let mut sym_count = 0usize;
        if let Some(h) = tagv(4) {
            if let Some(ho) = v2o(h) {
                sym_count = rd32(ho + 4) as usize; // nbucket, nchain
            }
        }
        if sym_count == 0 {
            if let Some(ss) = self.section(".dynsym") {
                sym_count = ss.size / 16;
            }
        }
        if sym_count == 0 {
            sym_count = (strtab_off - symtab_off) / 16;
        }
        let mut dynsyms = Vec::with_capacity(sym_count);
        for i in 0..sym_count {
            let o = symtab_off + i * 16;
            if o + 16 > self.data.len() { break; }
            let name_off = rd32(o) as usize;
            let value = rd32(o + 4);
            let size = rd32(o + 8);
            let info = self.data[o + 12];
            let shndx = u16::from_le_bytes([self.data[o + 14], self.data[o + 15]]);
            let mut name = String::new();
            let mut e = strtab_off + name_off;
            while e < self.data.len() && self.data[e] != 0 { e += 1; }
            if strtab_off + name_off <= self.data.len() {
                name = String::from_utf8_lossy(&self.data[strtab_off + name_off..e]).into_owned();
            }
            dynsyms.push(DynSym {
                name,
                value,
                size,
                info,
                shndx,
                is_func: info & 0xF == 2,
                is_weak: (info >> 4) == 2,
                is_undef: shndx == 0,
            });
        }

        // ---- relocations ----
        let rel_off = |vaddr: u32| -> Option<usize> { v2o(vaddr) };
        let mut read_rels = |start: Option<u32>, sz: Option<u32>| -> Vec<Reloc> {
            let mut out = Vec::new();
            let (Some(st), Some(n)) = (start, sz) else { return out; };
            let Some(mut o) = rel_off(st) else { return out };
            for _ in 0..(n / 8) {
                if o + 8 > self.data.len() { break; }
                out.push(Reloc { off: rd32(o), typ: (rd32(o + 4) & 0xFF) as u8, sym: rd32(o + 4) >> 8 });
                o += 8;
            }
            out
        };
        let rel_dyn = read_rels(tagv(17), tagv(18).or(Some(0)));
        let rel_plt = read_rels(tagv(23), tagv(2).or(Some(0)));
        let pltgot = tagv(3).unwrap_or(0);

        // ---- PLT → GOT slot mapping (classic ARM PLT) ----
        // Entry (12 bytes, after the 20-byte PLT0):
        //   add ip, pc, #X     ; e28fc600 + rot
        //   add ip, ip, #Y     ; e28cc000 + rot
        //   ldr pc, [ip, #Z]!  ; e5bcf000 + Z  (pre-indexed writeback)
        // GOT slot = plt_addr + 8 + X + Y + Z.
        let mut plt_to_got = Vec::new();
        if let Some(plt) = self.section(".plt") {
            let mut off = 20usize.min(plt.size); // skip PLT0
            while off + 12 <= plt.size {
                let a = plt.off + off;
                let w1 = rd32(a);
                let w2 = rd32(a + 4);
                let w3 = rd32(a + 8);
                let parse_add = |w: u32| -> Option<u32> {
                    if w & 0x0FE0_0000 != 0x0280_0000 { return None; }
                    let rot = ((w >> 8) & 0xF) as u32;
                    let imm8 = w & 0xFF;
                    Some(imm8.rotate_right(rot.wrapping_mul(2)))
                };
                // ldr pc, [ip, #Z]!  (and the no-writeback variant)
                let parse_ldr = |w: u32| -> Option<u32> {
                    let is_ldr_pc_ip = (w & 0x0FF0_0000 == 0x05B0_0000 || w & 0x0FF0_0000 == 0x0590_0000)
                        && (w & 0x000F_0000) == 0x000C_0000  // Rn = ip
                        && (w & 0xF000) == 0xF000;             // Rt = pc
                    if !is_ldr_pc_ip { return None; }
                    Some(w & 0xFFF)
                };
                let (Some(x), Some(y), Some(z)) = (parse_add(w1), parse_add(w2), parse_ldr(w3)) else { break; };
                let addr = plt.addr + off as u32;
                let got = addr.wrapping_add(8).wrapping_add(x).wrapping_add(y).wrapping_add(z);
                plt_to_got.push((addr, got));
                off += 12;
            }
        }

        // ---- text range (union of executable sections) ----
        let mut text_range = (u32::MAX, 0u32);
        for s in self.sections.iter() {
            if s.flags & 0x4 != 0 && s.size > 0 && s.typ != 0 {
                let b = s.addr;
                let e = b.wrapping_add(s.size as u32);
                text_range.0 = text_range.0.min(b);
                text_range.1 = text_range.1.max(e);
            }
        }
        if text_range.0 == u32::MAX { text_range = (0, 0); }

        // GOT slot → symbol (from JUMP_SLOT relocs)
        let got_to_sym = rel_plt.iter().filter(|r| r.typ == R_ARM_JUMP_SLOT)
            .map(|r| (r.off, r.sym)).collect();

        let tls_relocs = rel_dyn.iter().filter(|r| matches!(r.typ, 17..=21 | 43..=49 | 90..=93 | 160..=180)).count()
            + rel_plt.iter().filter(|r| matches!(r.typ, 17..=21 | 43..=49 | 90..=93 | 160..=180)).count();

        Ok(DynMeta {
            soname,
            needed,
            init: tagv(12).unwrap_or(0),
            init_array: (tagv(25).unwrap_or(0), tagv(27).unwrap_or(0)),
            segments,
            dynsyms,
            rel_dyn,
            rel_plt,
            pltgot,
            plt_to_got,
            got_to_sym,
            text_range,
            tls_relocs,
        })
    }

    fn str_at_addr(&self, off: usize) -> Option<String> {
        if off >= self.data.len() { return None; }
        let mut e = off;
        while e < self.data.len() && self.data[e] != 0 { e += 1; }
        Some(String::from_utf8_lossy(&self.data[off..e]).into_owned())
    }

    /// Read the ELF32 header's segment count directly (fallback).
    pub fn phnum(&self) -> usize {
        u16::from_le_bytes([self.data[0x2C], self.data[0x2D]]) as usize
    }
}

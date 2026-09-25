//! Minimal ELF64 relocatable-object reader (for embedding llvm-mc/clang
//! produced A64 blobs — the runtime thunk and native glue — into payloads
//! and emitted .so files).

#[derive(Debug, Clone)]
pub struct Obj64 {
    pub sections: Vec<ObjSection>,
    pub symbols: Vec<ObjSymbol>,
    pub relas: Vec<ObjRela>,
}

#[derive(Debug, Clone)]
pub struct ObjSection {
    pub name: String,
    pub typ: u32,
    pub flags: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ObjSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub shndx: u16,
    pub bind: u8,
    pub typ: u8,
}

#[derive(Debug, Clone)]
pub struct ObjRela {
    pub section: usize, // index of the section this applies to
    pub off: u64,
    pub typ: u32,
    pub sym: usize,
    pub addend: i64,
}

const SHT_PROGBITS: u32 = 1;
const SHT_RELA: u32 = 4;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_NOBITS: u32 = 8;

impl Obj64 {
    pub fn parse(data: &[u8]) -> Result<Obj64, String> {
        if data.len() < 64 || &data[0..4] != b"\x7fELF" {
            return Err("not an ELF".into());
        }
        if data[4] != 2 { return Err("not ELF64".into()); }
        if data[5] != 1 { return Err("not little-endian".into()); }
        let rd16 = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
        let rd32 = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let rd64 = |o: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[o..o + 8]);
            u64::from_le_bytes(b)
        };
        let e_shoff = rd64(0x28) as usize;
        let e_shentsize = rd16(0x3A);
        let e_shnum = rd16(0x3C);
        let e_shstrndx = rd16(0x3E);

        let mut raw: Vec<(u32, u32, u64, u64, u64, u32, u32)> = Vec::new(); // (name,typ,flags,off,size,link,info)
        for i in 0..e_shnum {
            let sh = e_shoff + i * e_shentsize;
            raw.push((
                rd32(sh),
                rd32(sh + 4),
                rd64(sh + 8),
                rd64(sh + 0x18),
                rd64(sh + 0x20),
                rd32(sh + 0x28),
                rd32(sh + 0x2C),
            ));
        }
        let shstr_off = raw.get(e_shstrndx).map(|s| s.3 as usize).unwrap_or(0);
        let name_of = |no: u32| -> String {
            let mut e = shstr_off + no as usize;
            while e < data.len() && data[e] != 0 { e += 1; }
            String::from_utf8_lossy(&data[shstr_off + no as usize..e]).into_owned()
        };

        let mut sections = Vec::with_capacity(e_shnum);
        for (i, &(name, typ, _flags, off, size, _link, _info)) in raw.iter().enumerate() {
            let bytes = if typ == SHT_NOBITS || typ == SHT_RELA || typ == SHT_SYMTAB || typ == SHT_STRTAB {
                Vec::new()
            } else if typ == SHT_PROGBITS {
                data.get(off as usize..(off + size) as usize)
                    .map(|s| s.to_vec())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            sections.push(ObjSection {
                name: name_of(name),
                typ,
                flags: _flags,
                bytes,
            });
            let _ = i;
        }

        // symbols
        let mut symbols = Vec::new();
        let mut symtabs: Vec<usize> = Vec::new();
        for (i, s) in sections.iter().enumerate() {
            if s.typ == SHT_SYMTAB { symtabs.push(i); }
        }
        for &st in symtabs.iter() {
            let (off, size, link) = {
                let r = &raw[st];
                (r.3 as usize, r.4 as usize, r.5 as usize)
            };
            let str_off = raw.get(link).map(|r| r.3 as usize).unwrap_or(0);
            for o in (0..size).step_by(24) {
                let p = off + o;
                if p + 24 > data.len() { break; }
                let no = rd32(p) as usize;
                let mut e = str_off + no;
                while e < data.len() && data[e] != 0 { e += 1; }
                let name = String::from_utf8_lossy(&data[str_off + no..e]).into_owned();
                symbols.push(ObjSymbol {
                    name,
                    value: rd64(p + 8),
                    size: rd64(p + 16),
                    shndx: u16::from_le_bytes([data[p + 6], data[p + 7]]),
                    bind: data[p + 4] >> 4,
                    typ: data[p + 4] & 0xF,
                });
            }
        }

        // relocations
        let mut relas = Vec::new();
        for (i, &(name, _typ, _f, _off, _size, link, info)) in raw.iter().enumerate() {
            let _ = name;
            if _typ != SHT_RELA { continue; }
            let target = info as usize; // sh_info = the section relocated
            let r_off = _off as usize;
            let r_size = _size as usize;
            for o in (0..r_size).step_by(24) {
                let p = r_off + o;
                if p + 24 > data.len() { break; }
                relas.push(ObjRela {
                    section: target,
                    off: rd64(p),
                    typ: (rd64(p + 8) & 0xFFFF_FFFF) as u32,
                    sym: (rd64(p + 8) >> 32) as usize,
                    addend: rd64(p + 16) as i64,
                });
            }
            let _ = link;
        }

        Ok(Obj64 { sections, symbols, relas })
    }

    pub fn text(&self) -> Result<&ObjSection, String> {
        self.sections.iter().find(|s| s.name == ".text" && !s.bytes.is_empty())
            .ok_or_else(|| "no .text".to_string())
    }
}

//! rearm-elf v2.1 — native ELF64 ET_DYN (.so) emitter.
//!
//! Pipeline for one library:
//!  1. `payload::build_payload` → the execution payload (translated code,
//!     map, relocs, GOT64, guest image).
//!  2. Emit `payload_data.o` — an ET_REL object with the payload in `.rodata`
//!     under the global symbol `payload_blob`.
//!  3. Generate `trampolines.S` — one stub per exported function (saves the
//!     A64 arg/return registers, calls `rearm_rt_enter` for a per-thread low
//!     ARM stack, builds the fake return frame, jumps into the payload),
//!     plus `.init_array` with `rearm_rt_init`.
//!  4. Assemble with llvm-mc and link everything with rust-lld:
//!     `ld.lld -shared loader.o trampolines.o payload_data.o`.
//!
//! Tool locations: env `LLVM_MC` / `LD_LLD` override; defaults look in
//! ~/bin/llvm-mc and the rustup toolchain's rust-lld.

use crate::payload::{build_payload, Payload};
use crate::Elf32;
use std::io::Write;
use std::process::Command;

pub struct SoToolPaths {
    pub llvm_mc: String,
    pub ld_lld: String,
}

impl SoToolPaths {
    pub fn find() -> Result<SoToolPaths, String> {
        let llvm_mc = std::env::var("LLVM_MC").ok()
            .filter(|p| std::path::Path::new(p).exists())
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/home/z".into());
                format!("{home}/bin/llvm-mc")
            });
        let ld_lld = std::env::var("LD_LLD").ok()
            .filter(|p| std::path::Path::new(p).exists())
            .unwrap_or_else(|| find_rust_lld());
        if !std::path::Path::new(&llvm_mc).exists() {
            return Err(format!("llvm-mc not found at {llvm_mc} (set LLVM_MC)"));
        }
        if !std::path::Path::new(&ld_lld).exists() {
            return Err(format!("rust-lld not found at {ld_lld} (set LD_LLD)"));
        }
        Ok(SoToolPaths { llvm_mc, ld_lld })
    }
}

fn find_rust_lld() -> String {
    if let Ok(home) = std::env::var("HOME") {
        // newest toolchain first
        let rustup = format!("{home}/.rustup/toolchains");
        if let Ok(mut dirs) = std::fs::read_dir(&rustup) {
            let mut paths: Vec<_> = dirs.flatten()
                .map(|d| d.path())
                .filter(|p| p.file_name().map(|n| n.to_string_lossy().contains("x86_64")).unwrap_or(false))
                .collect();
            paths.sort();
            for p in paths.iter().rev() {
                let c = p.join("lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld");
                if c.exists() { return c.to_string_lossy().into_owned(); }
            }
        }
    }
    "rust-lld".into()
}

// ==================== payload data object ====================

/// ET_REL ELF64 with the payload in `.rodata` as the global symbol
/// `payload_blob` (+ size).
pub fn emit_payload_obj(p: &Payload) -> Vec<u8> {
    let data = &p.bytes;
    let shstrtab: &[u8] = b"\0.rodata\0.symtab\0.strtab\0.shstrtab\0";
    let n_rodata = 1usize;
    let n_symtab = 9usize;
    let n_strtab = 17usize;
    let n_shstrtab = 25usize;

    let mut strtab: Vec<u8> = vec![0];
    let payload_blob_name = strtab.len() as u32;
    strtab.extend_from_slice(b"payload_blob");
    strtab.push(0);

    let mut buf: Vec<u8> = Vec::with_capacity(data.len() + 4096);

    // ELF64 header
    buf.extend_from_slice(b"\x7fELF");
    buf.extend_from_slice(&[2, 1, 1, 0]);
    buf.extend_from_slice(&[0u8; 8]);
    buf.extend_from_slice(&1u16.to_le_bytes());     // ET_REL
    buf.extend_from_slice(&0xB7u16.to_le_bytes());   // EM_AARCH64
    buf.extend_from_slice(&1u32.to_le_bytes());      // EV_CURRENT
    buf.extend_from_slice(&0u64.to_le_bytes());      // entry
    buf.extend_from_slice(&0u64.to_le_bytes());      // phoff
    let shoff_pos = buf.len();
    buf.extend_from_slice(&0u64.to_le_bytes());     // shoff (patch)
    buf.extend_from_slice(&0u32.to_le_bytes());     // flags
    buf.extend_from_slice(&64u16.to_le_bytes());    // ehsize
    buf.extend_from_slice(&0u16.to_le_bytes());     // phentsize
    buf.extend_from_slice(&0u16.to_le_bytes());     // phnum
    buf.extend_from_slice(&64u16.to_le_bytes());    // shentsize
    buf.extend_from_slice(&5u16.to_le_bytes());     // shnum
    buf.extend_from_slice(&4u16.to_le_bytes());     // shstrndx
    debug_assert_eq!(buf.len(), 64);

    let rodata_off = buf.len();
    buf.extend_from_slice(data);
    while buf.len() % 8 != 0 { buf.push(0); }
    let sym_off = buf.len();
    // null symbol + payload_blob
    let mut sym: Vec<u8> = vec![0u8; 48];
    let e = &mut sym[24..];
    e[0..4].copy_from_slice(&payload_blob_name.to_le_bytes());
    e[4] = 0x11; // STB_GLOBAL | STT_OBJECT
    e[5] = 0;    // st_other
    e[6..8].copy_from_slice(&1u16.to_le_bytes()); // shndx = .rodata
    e[8..16].copy_from_slice(&0u64.to_le_bytes()); // value 0 (ET_REL)
    e[16..24].copy_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(&sym);
    while buf.len() % 8 != 0 { buf.push(0); }
    let str_off = buf.len();
    buf.extend_from_slice(&strtab);
    let shstr_off = buf.len();
    buf.extend_from_slice(shstrtab);

    let shoff = buf.len() as u64;
    let push_sh = |buf: &mut Vec<u8>, name: u32, typ: u32, off: u64, size: u64, link: u32, entsize: u64| {
        buf.extend_from_slice(&name.to_le_bytes());
        buf.extend_from_slice(&typ.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());  // flags
        buf.extend_from_slice(&0u64.to_le_bytes());  // addr
        buf.extend_from_slice(&off.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&link.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());  // info
        buf.extend_from_slice(&1u64.to_le_bytes());  // align
        buf.extend_from_slice(&entsize.to_le_bytes());
    };
    buf.extend_from_slice(&[0u8; 64]); // null section
    push_sh(&mut buf, n_rodata as u32, 1, rodata_off as u64, data.len() as u64, 0, 0);
    // symtab: sh_link = strtab (3), sh_info = first non-local symbol (1)
    let mut sh: Vec<u8> = Vec::with_capacity(64);
    sh.extend_from_slice(&(n_symtab as u32).to_le_bytes());
    sh.extend_from_slice(&2u32.to_le_bytes());
    sh.extend_from_slice(&0u64.to_le_bytes());
    sh.extend_from_slice(&0u64.to_le_bytes());
    sh.extend_from_slice(&(sym_off as u64).to_le_bytes());
    sh.extend_from_slice(&48u64.to_le_bytes());
    sh.extend_from_slice(&3u32.to_le_bytes());
    sh.extend_from_slice(&1u32.to_le_bytes());
    sh.extend_from_slice(&8u64.to_le_bytes());
    sh.extend_from_slice(&24u64.to_le_bytes());
    buf.extend_from_slice(&sh);
    push_sh(&mut buf, n_strtab as u32, 3, str_off as u64, strtab.len() as u64, 0, 0);
    push_sh(&mut buf, n_shstrtab as u32, 3, shstr_off as u64, shstrtab.len() as u64, 0, 0);
    buf[shoff_pos..shoff_pos + 8].copy_from_slice(&shoff.to_le_bytes());
    buf
}

// ==================== trampolines ====================

fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

pub fn gen_trampoline_s(soname: &str, p: &Payload) -> String {
    let mut s = String::with_capacity(64 * 1024);
    s.push_str("// rearm-generated trampolines (per-export entry stubs)\n");
    s.push_str(".hidden rearm_rt_enter\n");
    s.push_str(".text\n");
    for e in p.exports.iter() {
        let sym = sanitize(&e.name);
        let off = e.payload_off as u32;
        s.push_str(&format!(
".globl {sym}\n.type {sym}, %function\n{sym}:\n\
    stp x29, x30, [sp, #-256]!\n\
    stp x19, x20, [sp, #16]\n\
    stp x21, x22, [sp, #32]\n\
    stp x23, x24, [sp, #48]\n\
    stp x25, x26, [sp, #64]\n\
    stp x27, x28, [sp, #80]\n\
    stp x0, x1, [sp, #96]\n\
    stp x2, x3, [sp, #112]\n\
    stp x4, x5, [sp, #128]\n\
    stp x6, x7, [sp, #144]\n\
    stp d0, d1, [sp, #160]\n\
    stp d2, d3, [sp, #176]\n\
    stp d4, d5, [sp, #192]\n\
    stp d6, d7, [sp, #208]\n\
    adrp x16, payload_base_slot\n\
    ldr x28, [x16, #:lo12:payload_base_slot]\n\
    mov x0, x13\n\
    mov x1, x30\n\
    bl rearm_rt_enter\n\
    mov x16, x0\n\
    str x4, [x16]\n\
    str x5, [x16, #4]\n\
    str x6, [x16, #8]\n\
    str x7, [x16, #0xc]\n\
    mov x15, sp\n\
    str x15, [x16, #16]\n\
    mov x13, x16\n\
    add x14, x28, #{glue}\n\
    mov x20, xzr\n\
    mov x21, xzr\n\
    movz w17, #{lo}\n\
    movk w17, #{hi}, lsl 16\n\
    add x17, x28, w17, uxtw\n\
    ldp x0, x1, [sp, #96]\n\
    ldp x2, x3, [sp, #112]\n\
    ldp x4, x5, [sp, #128]\n\
    ldp x6, x7, [sp, #144]\n\
    ldp d0, d1, [sp, #160]\n\
    ldp d2, d3, [sp, #176]\n\
    ldp d4, d5, [sp, #192]\n\
    ldp d6, d7, [sp, #208]\n\
    br x17\n\
.size {sym}, . - {sym}\n\n",
            sym = sym, lo = off & 0xFFFF, hi = (off >> 16) & 0xFFFF,
            glue = p.glue_off as i32,
        ));
    }
    // the payload base slot — defined HERE so trampoline references stay
    // local (direct adrp+ldr, no GOT indirection)
    s.push_str(".data\n");
    s.push_str(".hidden payload_base_slot\n");
    s.push_str(".globl payload_base_slot\n");
    s.push_str(".p2align 3\n");
    s.push_str("payload_base_slot:\n");
    s.push_str(".xword 0\n");
    // init_array: run the loader at dlopen
    s.push_str(".section .init_array,\"aw\"\n");
    s.push_str(".xword rearm_rt_init\n");
    let _ = soname;
    s
}

// ==================== driver ====================

pub fn build_so(
    elf: &Elf32,
    out_path: &str,
    window: u32,
    code_base: u32,
    tools: &SoToolPaths,
    keep_dir: Option<&str>,
) -> Result<Payload, String> {
    let p = build_payload(elf, window, code_base)?;

    let dir = match keep_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            let d = std::env::temp_dir().join(format!("rearm-so-{}", std::process::id()));
            std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
            d
        }
    };

    // 1. payload data object
    let po = dir.join("payload_data.o");
    std::fs::write(&po, emit_payload_obj(&p)).map_err(|e| e.to_string())?;

    // 2. trampolines
    let ts = dir.join("trampolines.S");
    std::fs::write(&ts, gen_trampoline_s(&p.soname, &p)).map_err(|e| e.to_string())?;
    let to = dir.join("trampolines.o");
    let out = Command::new(&tools.llvm_mc)
        .args(["--triple=aarch64-linux-gnu", "--filetype=obj", "-o"])
        .arg(&to)
        .arg(&ts)
        .output()
        .map_err(|e| format!("llvm-mc spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!("llvm-mc failed: {}", String::from_utf8_lossy(&out.stderr)));
    }

    // 3. loader object (embedded, written out)
    let lo = dir.join("loader.o");
    std::fs::write(&lo, include_bytes!("../../../runtime/loader.o"))
        .map_err(|e| e.to_string())?;

    // 3a. outlined-atomics runtime (embedded). loader.o's Rust atomics
    // (fetch_add/swap/compare_exchange) are lowered by LLVM to calls into
    // the compiler-rt __aarch64_{cas,swp,ldadd,ldclr,ldeor,ldset} family,
    // which no Android system library exports — without these the emitted
    // .so fails dlopen with "cannot locate symbol __aarch64_cas8_relax".
    let ao = dir.join("atomics_rt.o");
    std::fs::write(&ao, include_bytes!("../../../runtime/atomics_rt.o"))
        .map_err(|e| e.to_string())?;

    // 3b. stub shared libs: give lld DT_NEEDED targets it can link against.
    // The real resolution happens at runtime (dlsym) / on the device.
    let stubdir = dir.join("stubs");
    std::fs::create_dir_all(&stubdir).map_err(|e| e.to_string())?;
    let mut stub_names: Vec<String> = p.needed.clone();
    if !stub_names.iter().any(|n| n == "libc.so") {
        stub_names.push("libc.so".into());
    }
    let mut stub_paths = Vec::new();
    for n in stub_names.iter() {
        let sp = stubdir.join(n);
        if !sp.exists() {
            let mut asm = format!(".globl _rearm_stub\n_rearm_stub:\nret\n");
            if n == "libc.so" {
                // loader.o's undefined symbols live in libc
                for sym in ["mmap", "dlsym", "pthread_key_create",
                            "pthread_getspecific", "pthread_setspecific"] {
                    asm.push_str(&format!(".globl {sym}\n{sym}:\nret\n"));
                }
            }
            let so = stubdir.join(format!("{}.S", n));
            std::fs::write(&so, asm).map_err(|e| e.to_string())?;
            let obj = stubdir.join(format!("{}.o", n));
            let out = Command::new(&tools.llvm_mc)
                .args(["--triple=aarch64-linux-gnu", "--filetype=obj", "-o"])
                .arg(&obj).arg(&so).output()
                .map_err(|e| format!("llvm-mc spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("llvm-mc stub: {}", String::from_utf8_lossy(&out.stderr)));
            }
            let out = Command::new(&tools.ld_lld)
                .args(["-flavor", "gnu", "-shared", "--soname", n, "-o"]).arg(&sp).arg(&obj)
                .output().map_err(|e| format!("rust-lld stub spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("rust-lld stub: {}", String::from_utf8_lossy(&out.stderr)));
            }
        }
        stub_paths.push(sp);
    }

    // 4. link
    let mut cmd = Command::new(&tools.ld_lld);
    cmd.args(["-flavor", "gnu", "-shared", "-o", out_path]);
    if !p.soname.is_empty() {
        cmd.arg(format!("--soname={}", p.soname));
    }
    cmd.arg("--no-as-needed");
    cmd.arg("-Bsymbolic");
    cmd.arg("-z").arg("now");
    cmd.arg(&lo).arg(&ao).arg(&to).arg(&po);
    for sp in stub_paths.iter() {
        cmd.arg(sp);
    }
    let out = cmd.output().map_err(|e| format!("rust-lld spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!("rust-lld failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }

    // 5. post-link guard: the output must not carry any unresolved
    // outlined-atomics helper — that is the exact on-device dlopen failure
    // class this runtime exists to prevent.
    if let Ok(buf) = std::fs::read(out_path) {
        if let Some(sym) = undefined_aarch64_helpers(&buf).first() {
            return Err(format!(
                "emitted .so still references outlined-atomics helper `{sym}` \
                 (expected atomics_rt.o to resolve it)"));
        }
    }
    Ok(p)
}

/// Scan an emitted ELF64 .so's `.dynsym` for UNDEFINED symbols of the
/// outlined-atomics family (`__aarch64_{cas,swp,ldadd,ldclr,ldeor,ldset}` —
/// the compiler-rt helpers LLVM emits for atomics on non-LSE armv8 targets).
/// Returns every offender's name. Also used by the integration test
/// `tests/soemit_atomics.rs` to re-verify the final artifact.
pub fn undefined_aarch64_helpers(buf: &[u8]) -> Vec<String> {
    let mut bad = Vec::new();
    if buf.len() < 64 || &buf[0..4] != b"\x7fELF" || buf[4] != 2 {
        return bad; // not ELF64 — let other validation handle it
    }
    let rd16 = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);
    let rd32 = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
    let rd64 = |o: usize| {
        u64::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3],
                            buf[o + 4], buf[o + 5], buf[o + 6], buf[o + 7]])
    };
    let shoff = rd64(0x28) as usize;
    let shentsize = rd16(0x3a) as usize;
    let shnum = rd16(0x3c) as usize;
    if shoff == 0 || shentsize < 64 || shoff + shnum * shentsize > buf.len() {
        return bad;
    }
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if rd32(sh + 4) != 11 {
            continue; // SHT_DYNSYM = 11
        }
        let entsize = rd64(sh + 0x38) as usize;
        let size = rd64(sh + 0x20) as usize;
        let count = if entsize == 0 { 0 } else { size / entsize };
        let off = rd64(sh + 0x18) as usize;
        let link = rd32(sh + 0x28) as usize; // associated strtab section index
        if link >= shnum {
            continue;
        }
        let stroff = shoff + link * shentsize;
        let strdata = rd64(stroff + 0x18) as usize;
        let strsize = rd64(stroff + 0x20) as usize;
        if entsize != 24 || off + size > buf.len()
            || strdata + strsize > buf.len() {
            continue;
        }
        for j in 0..count {
            let e = off + j * entsize;
            if rd16(e + 6) != 0 {
                continue; // defined
            }
            let nameoff = strdata + rd32(e) as usize;
            if nameoff >= buf.len() {
                continue;
            }
            let end = buf[nameoff..].iter().position(|&b| b == 0)
                .map(|p| nameoff + p)
                .unwrap_or(buf.len());
            let name = String::from_utf8_lossy(&buf[nameoff..end]).into_owned();
            if name.starts_with("__aarch64_cas")
                || name.starts_with("__aarch64_swp")
                || name.starts_with("__aarch64_ldadd")
                || name.starts_with("__aarch64_ldclr")
                || name.starts_with("__aarch64_ldeor")
                || name.starts_with("__aarch64_ldset") {
                bad.push(name);
            }
        }
    }
    bad
}

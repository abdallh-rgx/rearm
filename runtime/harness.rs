//! rearm end-to-end test harness — loads a rearm-generated .so MANUALLY
//! (no dynamic linker), applies its dynamic relocations, runs .init_array,
//! and calls an exported translated function. Static musl binary, run under
//! qemu-aarch64.
//!
//! Usage: harness <lib.so> [args...]

use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: harness <lib.so>");
        std::process::exit(2);
    }
    let data = fs::read(&args[1]).expect("read .so");
    install_segv_debug();

    let so = So::parse(&data);
    println!("[harness] {} loaded: {} segments, {} dynsyms", args[1], so.segs.len(), so.syms.len());

    // ---- map segments (page-align vaddr/offset like a real loader) ----
    let bias = 0x7000_0000_0000u64;
    for s in so.segs.iter() {
        let lo = s.vaddr & !0xFFF;
        let hi = (s.vaddr + s.memsz + 0xFFF) & !0xFFF;
        let addr = bias + lo;
        let len = hi - lo;
        let r = sys_mmap(addr, len, 7, 0x8022, -1, 0); // RWX PRIVATE ANON FIXED
        if r != addr { panic!("mmap seg @ {:#x} failed ({:#x})", addr, r); }
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr().add(s.off as usize), (bias + s.vaddr) as *mut u8, s.filesz as usize);
            std::ptr::write_bytes((bias + s.vaddr + s.filesz) as *mut u8, 0, (s.memsz - s.filesz) as usize);
        }
    }

    // ---- dynamic relocations ----
    let mut resolved: Vec<&str> = Vec::new();
    let resolve = |name: &str| -> u64 {
        // 1. symbols defined in this .so (preemptible-global self references)
        if let Some(v) = so.find_sym(name) { return bias + v; }
        // 2. harness-provided
        resolve_foreign(name) as u64
    };
    for r in so.relas.iter() {
        match r.typ {
            1027 => { // R_AARCH64_RELATIVE
                unsafe { *(bias as *mut u8).add(r.off as usize).cast::<u64>() = bias + r.addend; }
            }
            1025 | 1026 => { // GLOB_DAT | JUMP_SLOT
                let name = so.sym_name(r.sym as usize);
                let addr = resolve(name);
                if addr == 0 {
                    if name.starts_with("_rearm_stub") { continue; }
                    eprintln!("[harness] WARNING: unresolved import: {}", name);
                    continue;
                }
                unsafe { *(bias as *mut u8).add(r.off as usize).cast::<u64>() = addr; }
                resolved.push(name);
            }
            257 | 258 => { // R_AARCH64_ABS64 | ABS32: symbol address + addend
                let name = so.sym_name(r.sym as usize);
                let addr = resolve(name);
                if addr == 0 {
                    eprintln!("[harness] WARNING: unresolved ABS64: {}", name);
                    continue;
                }
                unsafe { *(bias as *mut u8).add(r.off as usize).cast::<u64>() = addr + r.addend as u64; }
                resolved.push(name);
            }
            _ => {}
        }
    }
    println!("[harness] {} relocations applied ({} imports resolved)", so.relas.len(), resolved.len());

    // ---- .init_array ----
    eprintln!("[harness] init_array = {:?}", so.init_array);
    if let Some((off, len)) = so.init_array {
        let n = len / 8;
        for i in 0..n {
            let f = unsafe { *(bias as *const u8).add(off as usize).cast::<u64>().add(i as usize) };
            eprintln!("[harness] init[{i}] = {:#x}", f);
            if f != 0 {
                eprintln!("[harness] running init[{:#x}] …", f);
                unsafe { std::mem::transmute::<u64, extern "C" fn()>(f)(); }
            }
        }
    }

    // ---- first: adler32 (pure, small — bisection point) ----
    {
        let adler32 = so.find_sym("adler32").expect("adler32 export");
        let data: &[u8] = b"Wikipedia"; // canonical example: adler32 = 0x11E60398
        let tbuf2 = sys_mmap(0x9100_0000, 0x1000, 3, 0x8022, -1, 0);
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), tbuf2 as *mut u8, data.len()); }
        println!("[harness] adler32 @ {:#x}", bias + adler32);
        let r = unsafe {
            std::mem::transmute::<u64, extern "C" fn(u32, *const u8, u32) -> u32>(bias + adler32)(
                1, tbuf2 as *const u8, data.len() as u32,
            )
        };
        println!("[harness] adler32(Wikipedia) = {:#010x} (expected 0x11e60398) {}",
            r, if r == 0x11e60398 { "*** CORRECT ***" } else { "MISMATCH" });
    }

    // ---- call compress2 (zlib self-test) with LOW-WORLD buffers ----
    let src_bytes: &[u8] = b"Hello rearm! Hello rearm! Hello rearm! Hello rearm! 1234567890";
    // guest-visible buffers below 4 GiB (translated code does 32-bit pointer math!)
    let tbuf = sys_mmap(0x9000_0000, 0x10000, 3, 0x8022, -1, 0);
    if tbuf == 0 { panic!("test buffer mmap failed"); }
    unsafe {
        std::ptr::copy_nonoverlapping(src_bytes.as_ptr(), tbuf as *mut u8, src_bytes.len());
        std::ptr::write_bytes((tbuf + 0x8000) as *mut u8, 0, 0x1000);
        std::ptr::write_volatile((tbuf + 0x8000) as *mut u64, 0x1000); // dstLen = 4096
    }
    // sanity: payload header at C
    {
        let c = 0x4000_0000u64;
        let magic: u64 = unsafe { std::ptr::read_volatile(c as *const u64) };
        let map_off = unsafe { std::ptr::read_volatile((c + 8) as *const u32) };
        let map_count = unsafe { std::ptr::read_volatile((c + 12) as *const u32) };
        let window = unsafe { std::ptr::read_volatile((c + 60) as *const u32) };
        eprintln!("[harness] payload hdr: magic={:#018x} map_off={:#x} map_count={} window={:#x}",
            magic, map_off, map_count, window);
    }
    let compress2 = so.find_sym("compress2").expect("compress2 export");
    println!("[harness] compress2 @ {:#x} (bias {:#x}) buffers @ {:#x}", compress2, bias, tbuf);
    let rc = unsafe {
        std::mem::transmute::<u64, extern "C" fn(*mut u8, *mut u64, *const u8, u64, i32) -> i32>(bias + compress2)(
            tbuf as *mut u8, (tbuf + 0x8000) as *mut u64, tbuf as *const u8, src_bytes.len() as u64, 6,
        )
    };
    let out_len = unsafe { std::ptr::read_volatile((tbuf + 0x8000) as *const u64) };
    println!("[harness] compress2 rc={} out_len={}", rc, out_len);
    if rc == 0 {
        let out: Vec<u8> = unsafe { std::slice::from_raw_parts(tbuf as *const u8, out_len as usize) }.to_vec();
        println!("[harness] compressed hex: {:02x?}", &out[..out_len.min(48) as usize]);
        // verify against the harness's own deflate (host zlib via musl? not available) —
        // print a CRC for the python check instead
        let mut crc: u32 = 0xFFFFFFFF;
        for b in out.iter() { for k in (0..8).rev() { let bit = (crc ^ ((*b as u32 >> k) & 1)) & 1; crc = (crc >> 1) ^ (0xEDB8_8320u32).wrapping_mul(bit); } }
        println!("[harness] compressed crc32={:#010x} len={}", !crc, out_len);
        std::process::exit(0);
    }
    std::process::exit(1);
}


// ============================ SIGSEGV PC debug ============================

#[repr(C)]
struct KSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

extern "C" fn segv_handler(_sig: i32, info: *mut u8, ctx: *mut u8) {
    let fault = unsafe { *(ctx as *const u64).add(0x28 / 8) };      // uc_mcontext.fault_address? (regs start 0xE8)
    let pc = unsafe { *(ctx as *const u64).add(0x110 / 8) };        // uc_mcontext.pc
    let sp = unsafe { *(ctx as *const u64).add(0x108 / 8) };
    let fault2 = unsafe { *(info as *const u64).add(2) };           // siginfo.si_addr
    eprintln!("[SIGSEGV] pc={:#x} fault={:#x} si_addr={:#x} sp={:#x}", pc, fault, fault2, sp);
    std::process::exit(9);
}

extern "C" fn segv_ctx_handler(_sig: i32, _info: usize, ctx: usize) {
    // qemu aarch64 rt_sigframe ucontext: mcontext (regs) at +0xB8
    let uc = ctx as *const u64;
    unsafe {
        let x13 = *uc.add((0xB8 + 13*8) / 8);
        let x14 = *uc.add((0xB8 + 14*8) / 8);
        let x15 = *uc.add((0xB8 + 15*8) / 8);
        let x16 = *uc.add((0xB8 + 16*8) / 8);
        let x17 = *uc.add((0xB8 + 17*8) / 8);
        let x28 = *uc.add((0xB8 + 28*8) / 8);
        let sp = *uc.add((0xB8 + 31*8) / 8);
        let pc = *uc.add((0xB8 + 32*8) / 8);
        eprintln!("[SEGV-CTX] pc={:#x} x13={:#x} x14={:#x} x15={:#x} x16={:#x} x17={:#x} x28={:#x} sp={:#x}",
            pc, x13, x14, x15, x16, x17, x28, sp);
        // dump the guest stack frame area [x13-0x30, x13+0x20]
        // (only when x13 looks like a low-world pointer — the handler must not fault)
        let mut line = String::new();
        if x13 >= 0xC000_0000 && x13 < 0x1_0000_0000 {
        for i in 0..20u32 {
            let addr = x13 - 0x30 + (i as u64) * 4;
            let v = std::ptr::read_volatile(addr as *const u32);
            line.push_str(&format!(" {:09x}={:08x}", addr, v));
            if i % 5 == 4 { eprintln!("[stack]{}", line); line.clear(); }
        }
        if !line.is_empty() { eprintln!("[stack]{}", line); }
        }
    }
    std::process::exit(66);
}

extern "C" fn trap_ctx_handler(_sig: i32, _info: usize, ctx: usize) {
    // ultra-robust raw write first (no formatting/alloc) so we know we got here
    unsafe { raw_write(b"[TRAP] handler entered\n"); }
    let uc = ctx as *const u64;
    // dump 0x00..0x1D0 of the ucontext as hex — locate the register file by eye
    let mut buf = [0u8; 2048];
    let mut p = 0usize;
    let b = |d: &mut [u8], o: usize, c: u8| { d[o] = c; };
    for i in 0..58u32 {
        let v = unsafe { *uc.add(i as usize) };
        // write "XXXX_XXXX_XXXX_XXXX " without any formatting machinery
        let mut sh = 60u32;
        for _ in 0..16 {
            let nib = ((v >> sh) as u8) & 0xF;
            let ch = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
            b(&mut buf, p, ch);
            p += 1;
            sh = sh.saturating_sub(4);
        }
        b(&mut buf, p, b' ');
        p += 1;
        if (i & 3) == 3 { b(&mut buf, p, b'\n'); p += 1; }
    }
    unsafe { raw_write(&buf[..p]); }
    unsafe { raw_write(b"\n"); }
    std::process::exit(77);
}

/// Raw write(2) — safe inside any signal handler (no locks/alloc/format).
unsafe fn raw_write(b: &[u8]) {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 64u64, in("x0") 2i64, in("x1") b.as_ptr(), in("x2") b.len() as u64,
            lateout("x0") _,
        );
    }
}


// musl (aarch64) user-struct sigaction: handler, sa_mask(128), flags, restorer
#[repr(C)]
struct MSigAction {
    handler: u64,
    mask: [u64; 16],   // sigset_t = 128 bytes
    flags: i32,
    _pad: u32,
    restorer: u64,
}

extern "C" {
    fn sigaction(sig: i32, act: *const MSigAction, old: *mut MSigAction) -> i32;
}

fn install_segv_debug() {
    // qemu only passes (sig, info, ctx) when SA_SIGINFO is installed; plain
    // signal() leaves x1/x2 garbage. musl's sigaction() does the right
    // syscall (its internal kernel-struct conversion passes qemu cleanly).
    unsafe {
        let sa = Box::into_raw(Box::new(MSigAction {
            handler: trap_ctx_handler as usize as u64,
            mask: [0; 16],
            flags: 0x4 | 0x10000000, // SA_SIGINFO | SA_RESTART
            _pad: 0,
            restorer: 0,
        }));
        let r = sigaction(5, &*sa, core::ptr::null_mut());
        let sa2 = Box::into_raw(Box::new(MSigAction {
            handler: segv_ctx_handler as usize as u64,
            mask: [0; 16],
            flags: 0x4 | 0x10000000,
            _pad: 0,
            restorer: 0,
        }));
        let r2 = sigaction(11, &*sa2, core::ptr::null_mut());
        eprintln!("[harness] sigaction(SIGTRAP)={} sigaction(SIGSEGV)={}", r, r2);
    }
}

unsafe extern "C" fn sig_restorer() {
    unsafe {
        core::arch::asm!(
            "mov x8, #139",
            "svc #0",
            options(noreturn)
        );
    }
}

// ============================ ELF .so parsing ============================

struct Seg { vaddr: u64, off: u64, filesz: u64, memsz: u64 }
struct Rela { off: u64, typ: u32, sym: u32, addend: u64 }

struct So<'a> {
    data: &'a [u8],
    segs: Vec<Seg>,
    relas: Vec<Rela>,
    syms: Vec<(u32, u64)>, // (name_off, value)
    strtab_off: usize,
    init_array: Option<(u64, u64)>,
}

impl<'a> So<'a> {
    fn parse(d: &'a [u8]) -> So<'a> {
        let rd16 = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]) as usize;
        let rd32 = |o: usize| u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]);
        let rd64 = |o: usize| { let mut b = [0u8; 8]; b.copy_from_slice(&d[o..o + 8]); u64::from_le_bytes(b) };
        let phoff = rd64(0x20) as usize;
        let phentsize = rd16(0x36);
        let phnum = rd16(0x38);
        let shoff = rd64(0x28) as usize;
        let shentsize = rd16(0x3A);
        let shnum = rd16(0x3C);

        // segments
        let mut segs = Vec::new();
        let mut dyn_off = 0usize;
        for i in 0..phnum {
            let p = phoff + i * phentsize;
            let typ = rd32(p);
            if typ == 1 {
                segs.push(Seg { vaddr: rd64(p + 0x10), off: rd64(p + 0x08), filesz: rd64(p + 0x20), memsz: rd64(p + 0x28) });
            } else if typ == 2 { dyn_off = rd64(p + 0x08) as usize; }
        }

        // section headers (for symtab/rela offsets)
        let mut symtab = (0usize, 0usize);
        let mut strtab = (0usize, 0usize);
        let mut reladyn = (0usize, 0usize);
        let mut relaplt = (0usize, 0usize);
        let shstrndx = rd16(0x3E);
        let shstr_off = if shoff > 0 && shnum > 0 { rd64(shoff + shstrndx * shentsize + 0x18) as usize } else { 0 };
        let secname = |i: usize| -> String {
            let sh = shoff + i * shentsize;
            let no = rd32(sh) as usize;
            let mut e = shstr_off + no;
            while e < d.len() && d[e] != 0 { e += 1; }
            String::from_utf8_lossy(&d[shstr_off + no..e]).into_owned()
        };
        for i in 0..shnum {
            match secname(i).as_str() {
                ".dynsym" => symtab = (rd64(shoff + i * shentsize + 0x18) as usize, rd64(shoff + i * shentsize + 0x20) as usize),
                ".dynstr" => strtab = (rd64(shoff + i * shentsize + 0x18) as usize, rd64(shoff + i * shentsize + 0x20) as usize),
                ".rela.dyn" => reladyn = (rd64(shoff + i * shentsize + 0x18) as usize, rd64(shoff + i * shentsize + 0x20) as usize),
                ".rela.plt" => relaplt = (rd64(shoff + i * shentsize + 0x18) as usize, rd64(shoff + i * shentsize + 0x20) as usize),
                _ => {}
            }
        }

        let mut syms = Vec::new();
        for off in (0..symtab.1).step_by(24) {
            let o = symtab.0 + off;
            syms.push((rd32(o), rd64(o + 8)));
        }

        let mut relas = Vec::new();
        for (base, len) in [(reladyn, 0usize), (relaplt, 0usize)] {
            let _ = len;
            let (o, sz) = base;
            for off in (0..sz).step_by(24) {
                let p = o + off;
                let info = rd64(p + 8);
                relas.push(Rela { off: rd64(p), typ: (info & 0xFFFF_FFFF) as u32, sym: (info >> 32) as u32, addend: rd64(p + 16) });
            }
        }

        // DT_INIT_ARRAY from PT_DYNAMIC
        let mut init_array = None;
        if dyn_off > 0 {
            let mut p = dyn_off;
            loop {
                let tag = rd64(p);
                let val = rd64(p + 8);
                if tag == 0 { break; }
                if std::env::var_os("HARNESS_DBG").is_some() {
                    eprintln!("[dbg] DT {} = {:#x}", tag, val);
                }
                if tag == 25 { init_array = Some((val, 0)); }
                if tag == 27 { if let Some(x) = init_array.as_mut() { x.1 = val; } }
                p += 16;
            }
        }

        So { data: d, segs, relas, syms, strtab_off: strtab.0, init_array }
    }

    fn sym_name(&self, idx: usize) -> &str {
        let (no, _) = self.syms[idx];
        let start = self.strtab_off + no as usize;
        let d = &self.data[start..];
        let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
        std::str::from_utf8(&d[..end]).unwrap_or("?")
    }

    fn find_sym(&self, name: &str) -> Option<u64> {
        for (i, (_no, v)) in self.syms.iter().enumerate() {
            if *v == 0 { continue; }
            if self.sym_name(i) == name { return Some(*v); }
        }
        None
    }
}

// ============================ foreign resolution ============================

extern "C" {
    fn mmap(addr: u64, len: u64, prot: i32, flags: i32, fd: i32, off: u64) -> i64;
    fn signal(sig: i32, h: usize) -> usize;
}

#[allow(improper_ctypes_definitions)]
extern "C" {
    fn memcpy(d: *mut u8, s: *const u8, n: u64) -> *mut u8;
    fn memset(d: *mut u8, c: i32, n: u64) -> *mut u8;
    fn strlen(s: *const u8) -> u64;
    fn strcmp(a: *const u8, b: *const u8) -> i32;
}

/// Fake key storage for pthread-specific data (single-threaded harness).
static mut FAKE_KEY: u64 = 0;

extern "C" fn fake_pthread_key_create(key: *mut u32, _dtor: usize) -> i32 {
    unsafe { *key = 1; }
    0
}
extern "C" fn fake_pthread_getspecific(_k: u32) -> *mut u8 {
    unsafe { FAKE_KEY as *mut u8 }
}
extern "C" fn fake_pthread_setspecific(_k: u32, v: *mut u8) -> i32 {
    unsafe { FAKE_KEY = v as u64; }
    0
}

/// The rearm loader's dlsym: resolve translated-lib imports against the
/// harness's own (musl) symbols.
extern "C" fn fake_dlsym(_h: *mut u8, name: *const u8) -> *mut u8 {
    let n = unsafe {
        let mut e = 0usize;
        while *name.add(e) != 0 { e += 1; }
        std::str::from_utf8(std::slice::from_raw_parts(name, e)).unwrap_or("")
    };
    match n {
        "mmap" | "__mmap2" | "mmap64" => mmap as *mut u8,
        "dlsym" => fake_dlsym as *mut u8,
        "pthread_key_create" => fake_pthread_key_create as *mut u8,
        "pthread_getspecific" => fake_pthread_getspecific as *mut u8,
        "pthread_setspecific" => fake_pthread_setspecific as *mut u8,
        "memcpy" | "__memcpy_chk" | "__memcpy" => memcpy as *mut u8,
        "memset" | "__memset" | "__memset_chk" => memset as *mut u8,
        "strlen" | "__strlen" => strlen as *mut u8,
        "strcmp" | "__strcmp" => strcmp as *mut u8,
        "malloc" | "__libc_malloc" => fake_malloc as *mut u8,
        "free" | "__libc_free" => fake_free as *mut u8,
        "calloc" | "__libc_calloc" => fake_calloc as *mut u8,
        "realloc" => fake_realloc as *mut u8,
        "mprotect" => fake_mprotect as *mut u8,
        "munmap" => fake_munmap as *mut u8,
        "__android_log_print" => fake_log as *mut u8,
        // ARM EABI helpers
        "__aeabi_memcpy" | "__aeabi_memcpy4" | "__aeabi_memcpy8" => memcpy as *mut u8,
        "__aeabi_memclr" | "__aeabi_memclr4" | "__aeabi_memclr8" => memset as *mut u8,
        "__aeabi_memmove" | "__aeabi_memmove4" | "__aeabi_memmove8" => memcpy as *mut u8,
        // misc libc
        "memchr" => memchr_impl as *mut u8,
        "snprintf" | "vsnprintf" | "sprintf" => fake_snprintf as *mut u8,
        "strerror" => fake_strerror as *mut u8,
        "__errno" => fake_errno as *mut u8,
        "open" | "lseek" | "read" | "close" | "write" => fake_io_stub as *mut u8,
        "abort" => fake_abort as *mut u8,
        "__gnu_Unwind_Find_exidx" => fake_find_exidx as *mut u8,
        "__cxa_atexit" | "atexit" => fake_cxa_atexit as *mut u8,
        "__cxa_finalize" => fake_cxa_finalize as *mut u8,
        "__cxa_begin_cleanup" | "__cxa_type_match" | "__cxa_call_unexpected" => fake_cxa_stub as *mut u8,
        "__stack_chk_fail" => fake_stack_chk_fail as *mut u8,
        // data symbols
        "__stack_chk_guard" => std::ptr::addr_of_mut!(STACK_GUARD) as *mut u8,
        "environ" => 1 as *mut u8,
        _ => {
            eprintln!("[harness] fake_dlsym: MISS {}", n);
            std::ptr::null_mut()
        }
    }
}

static mut STACK_GUARD: u64 = 0xdead_beef_cafe_1234;

extern "C" fn memchr_impl(p: *const u8, c: i32, n: u64) -> *mut u8 {
    unsafe {
        for i in 0..n {
            if *p.add(i as usize) == c as u8 {
                return p.add(i as usize) as *mut u8;
            }
        }
    }
    std::ptr::null_mut()
}
extern "C" fn fake_snprintf() -> i32 { 0 }
extern "C" fn fake_strerror(_e: i32) -> *mut u8 { b"strerror\0".as_ptr() as *mut u8 }
extern "C" fn fake_errno() -> *mut u8 { static mut E: u32 = 0; unsafe { std::ptr::addr_of_mut!(E) as *mut u8 } }
extern "C" fn fake_io_stub() -> i64 { -1 }
extern "C" fn fake_abort() -> ! { std::process::abort() }
extern "C" fn fake_find_exidx() -> i64 { 0 }
extern "C" fn fake_cxa_atexit() -> i32 { 0 }
extern "C" fn fake_cxa_finalize() {}
extern "C" fn fake_cxa_stub() -> i32 { 0 }
extern "C" fn fake_stack_chk_fail() -> ! {
    eprintln!("[harness] *** stack smashing detected (translated code) ***");
    std::process::exit(99);
}

// simple bump allocator on a reserved region
static mut HEAP: u64 = 0;
const HEAP_BASE: u64 = 0x6000_0000_0000;

extern "C" fn fake_malloc(n: u64) -> *mut u8 {
    unsafe {
        if HEAP == 0 {
            let r = sys_mmap(HEAP_BASE, 0x1000_0000, 3, 0x8022, -1, 0);
            HEAP = r;
        }
        let p = HEAP;
        HEAP = (HEAP + n + 31) & !15;
        p as *mut u8
    }
}
extern "C" fn fake_free(_p: *mut u8) {}
extern "C" fn fake_calloc(n: u64, s: u64) -> *mut u8 {
    let p = fake_malloc(n * s);
    unsafe { std::ptr::write_bytes(p, 0, (n * s) as usize); }
    p
}
extern "C" fn fake_realloc(p: *mut u8, n: u64) -> *mut u8 {
    let np = fake_malloc(n);
    unsafe { std::ptr::copy(p, np, n as usize); }
    np
}
extern "C" fn fake_mprotect(_a: u64, _l: u64, _p: i32) -> i32 { 0 }
extern "C" fn fake_munmap(_a: u64, _l: u64) -> i32 { 0 }
extern "C" fn fake_log(_prio: i32, _tag: *const u8, _fmt: *const u8) -> i32 { 0 }

#[allow(improper_ctypes_definitions)]
extern "C" {
    fn __aarch64_cas8_relax(a: u64, b: *mut u8, c: *mut u8) -> *mut u8;
    fn __aarch64_swp4_acq_rel(a: u32, b: *mut u8) -> u32;
    fn __aarch64_swp4_relax(a: u32, b: *mut u8) -> u32;
    fn __aarch64_ldadd8_relax(a: u8, b: *mut u8) -> u8;
    fn __aarch64_ldadd4_relax(a: u32, b: *mut u8) -> u32;
}

fn resolve_foreign(name: &str) -> *mut u8 {
    match name {
        "mmap" => mmap as *mut u8,
        "dlsym" => fake_dlsym as *mut u8,
        "pthread_key_create" => fake_pthread_key_create as *mut u8,
        "pthread_getspecific" => fake_pthread_getspecific as *mut u8,
        "pthread_setspecific" => fake_pthread_setspecific as *mut u8,
        "memcpy" | "__memcpy_chk" | "__memcpy" => memcpy as *mut u8,
        "memset" | "__memset" | "__memset_chk" => memset as *mut u8,
        "strlen" | "__strlen" => strlen as *mut u8,
        "strcmp" | "__strcmp" => strcmp as *mut u8,
        "__aarch64_cas8_relax" => __aarch64_cas8_relax as *mut u8,
        "__aarch64_swp4_acq_rel" => __aarch64_swp4_acq_rel as *mut u8,
        "__aarch64_swp4_relax" => __aarch64_swp4_relax as *mut u8,
        "__aarch64_ldadd8_relax" => __aarch64_ldadd8_relax as *mut u8,
        "__aarch64_ldadd4_relax" => __aarch64_ldadd4_relax as *mut u8,
        _ => {
            eprintln!("[harness] resolve_foreign: MISS {}", name);
            std::ptr::null_mut()
        }
    }
}

// raw syscall mmap
fn sys_mmap(addr: u64, len: u64, prot: i32, flags: i32, fd: i32, off: u64) -> u64 {
    let r: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 222u64,
            inlateout("x0") addr => r,
            in("x1") len,
            in("x2") prot as u64,
            in("x3") flags as u64,
            in("x4") fd as u64,
            in("x5") off,
        );
    }
    if r < 0 { 0 } else { r as u64 }
}

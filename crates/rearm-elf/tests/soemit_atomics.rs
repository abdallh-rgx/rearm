//! `rearm so64` end-to-end regression: the emitted .so must be fully
//! self-contained w.r.t. the compiler-rt outlined-atomics family.
//!
//! Background: the embedded Rust runtime (runtime/loader.o) lowers its
//! `core::sync::atomic` operations (fetch_add / swap / compare_exchange)
//! to calls like `__aarch64_cas8_relax`. Bionic exports none of that
//! family, so an emitted .so that still references it fails dlopen
//! on-device with UnsatisfiedLinkError:
//! `dlopen failed: cannot locate symbol "__aarch64_cas8_relax" referenced
//!  by ".../lib/arm64/libXXX.so"`.
//!
//! `soemit::build_so` links in `runtime/atomics_rt.o` (96 hidden LL/SC
//! helpers covering cas/swp/ldadd/ldclr/ldeor/ldset x {1,2,4,8} x
//! {relax,acq,rel,acq_rel}) and guards the result post-link. This test
//! re-verifies the final artifact from a synthetic ARM32 fixture
//! (fixtures/atomics-fixture.{S,so} — pure hand-written test code).

use rearm_elf::soemit::{build_so, undefined_aarch64_helpers, SoToolPaths};
use rearm_elf::Elf32;

#[test]
fn so64_output_resolves_all_outlined_atomics() {
    let tools = match SoToolPaths::find() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skipping (tools unavailable): {e}");
            return;
        }
    };

    let fixture = format!(
        "{}/../../tests/fixtures/atomics-fixture.so",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(&fixture).expect("fixture .so missing (rebuild from atomics-fixture.S)");
    let elf = Elf32::parse(data).expect("parse fixture");

    let out_path = std::env::temp_dir()
        .join(format!("rearm-so-atomics-test-{}.so", std::process::id()));
    let out_path = out_path.to_str().unwrap().to_string();

    // build_so itself fails if any outlined-atomics symbol stays undefined.
    let p = build_so(&elf, &out_path, 0x0100_0000, 0x4000_0000, &tools, None)
        .expect("build_so must succeed (its post-link atomics guard must pass)");

    assert!(!p.exports.is_empty(), "fixture exports must survive translation");
    assert_eq!(p.stats.unsupported, 0, "fixture is fully translatable");

    // Independent re-verification of the final artifact (not trusting the
    // in-process guard alone): scan the emitted .so's .dynsym.
    let buf = std::fs::read(&out_path).expect("read emitted .so");
    assert_eq!(&buf[0..4], b"\x7fELF");
    assert_eq!(buf[4], 2, "ELF64");
    let bad = undefined_aarch64_helpers(&buf);
    assert!(
        bad.is_empty(),
        "emitted .so still references outlined-atomics helpers: {bad:?}"
    );

    // Sanity: the runtime helpers really are in there (hidden, so .symtab
    // — not .dynsym). Spot-check the four the loader actually references.
    let syms = read_static_symtab_names(&buf);
    for expected in [
        "__aarch64_cas8_relax",
        "__aarch64_ldadd8_relax",
        "__aarch64_swp4_acq_rel",
        "__aarch64_swp4_relax",
    ] {
        assert!(
            syms.iter().any(|s| s == expected),
            "helper `{expected}` missing from emitted .so"
        );
    }

    let _ = std::fs::remove_file(&out_path);
}

/// Names of all symbols in the first `.symtab` (SHT_SYMTAB = 2), if present.
fn read_static_symtab_names(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if buf.len() < 64 || &buf[0..4] != b"\x7fELF" || buf[4] != 2 {
        return out;
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
        return out;
    }
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if rd32(sh + 4) != 2 {
            continue; // SHT_SYMTAB
        }
        let entsize = rd64(sh + 0x38) as usize;
        let size = rd64(sh + 0x20) as usize;
        let count = if entsize == 0 { 0 } else { size / entsize };
        let off = rd64(sh + 0x18) as usize;
        let link = rd32(sh + 0x28) as usize;
        if link >= shnum {
            continue;
        }
        let stroff = shoff + link * shentsize;
        let strdata = rd64(stroff + 0x18) as usize;
        if entsize != 24 || off + size > buf.len() {
            continue;
        }
        for j in 0..count {
            let e = off + j * entsize;
            let nameoff = strdata + rd32(e) as usize;
            if nameoff >= buf.len() {
                continue;
            }
            let end = buf[nameoff..].iter().position(|&b| b == 0)
                .map(|p| nameoff + p)
                .unwrap_or(buf.len());
            out.push(String::from_utf8_lossy(&buf[nameoff..end]).into_owned());
        }
    }
    out
}

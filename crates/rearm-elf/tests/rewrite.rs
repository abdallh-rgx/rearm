//! rearm-elf rewrite test on a real assembled Thumb-2 object (llvm-mc fixture).

use rearm_elf::Elf32;

#[test]
fn rewrite_thumb_fixture() {
    let path = format!("{}/../../tests/fixtures/thumb-funcs.o", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read(&path).expect("fixture missing");
    let elf = Elf32::parse(data).expect("parse");
    let (out, map, st) = rearm_elf::translate_so(&elf).expect("translate");

    assert_eq!(st.undefined_enc, 0, "no undefined encodings");
    assert_eq!(st.unsupported, 0, "everything translated");
    assert!(st.t32_ins >= 18, "fixture has ~20 T32 instructions, got {}", st.t32_ins);
    assert_eq!(st.it_blocks, 1, "ITE hi block");
    assert_eq!(st.literal_folds, 1, "one literal fold");
    assert_eq!(st.branches_resolved, 3, "b.ge + cbz + bl");
    assert_eq!(st.branches_unresolved, 0);
    assert_eq!(st.data_skipped, 4, "literal pool skipped via $d");
    assert!(!map.is_empty());

    // emitted ELF64 parses and disassembles cleanly (checked by llvm-objdump
    // in the pipeline; here: header sanity)
    let elf64 = rearm_elf::emit_elf64(&out, &map, &elf);
    assert_eq!(&elf64[0..4], b"\x7fELF");
    assert_eq!(elf64[4], 2, "ELF64");
    assert_eq!(u16::from_le_bytes([elf64[18], elf64[19]]), 0xB7, "EM_AARCH64");
    let e_shoff = u64::from_le_bytes(elf64[0x28..0x30].try_into().unwrap());
    assert!(e_shoff > 0);
    let shnum = u16::from_le_bytes([elf64[0x3C], elf64[0x3D]]);
    assert_eq!(shnum, 6);
    // .text section header: type PROGBITS, flags ALLOC|EXEC
    let sh = e_shoff as usize + 64; // second section header (index 1 = .text)
    let sh_flags = u64::from_le_bytes(elf64[sh + 8..sh + 16].try_into().unwrap());
    assert_eq!(sh_flags, 0x6);
    let sh_size = u64::from_le_bytes(elf64[sh + 32..sh + 40].try_into().unwrap());
    assert_eq!(sh_size as usize, out.bytes().len());
}

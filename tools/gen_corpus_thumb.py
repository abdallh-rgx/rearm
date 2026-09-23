#!/usr/bin/env python3
"""Regenerate the T32 golden corpus as `hex32 text` lines.

llvm-objdump prints 32-bit Thumb instructions as two space-separated
halfwords ("ea5f 0108"), so the generic gen_corpus.py regex mangles them
(hex becomes only the first halfword). This script re-assembles the full
32-bit word: hex32 = hw1 (in memory first) followed by hw2.

Usage: gen_corpus_thumb.py <asm-file> <out-txt>
"""
import subprocess, sys, os, re, tempfile, glob

RUSTC = os.path.expanduser("~/.cargo/bin/rustc")
OBJDUMP = glob.glob(os.path.expanduser(
    "~/.rustup/toolchains/*/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump"))[0]

TARGET = "thumbv7neon-unknown-linux-gnueabihf"
FEATS = ["+div", "+mp"]

def main():
    asm_file, out_txt = sys.argv[1], sys.argv[2]
    asm = ".thumb\n.arch armv8-a\n" + open(asm_file).read()
    asm_esc = asm.replace("{", "{{").replace("}", "}}")
    rs = f"""#![no_std]
use core::arch::global_asm;
#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! {{ loop {{}} }}
global_asm!(r#"{asm_esc}"#);
"""
    with tempfile.TemporaryDirectory() as td:
        rs_path = os.path.join(td, "g.rs")
        obj_path = os.path.join(td, "g.o")
        open(rs_path, "w").write(rs)
        r = subprocess.run([RUSTC, "--target", TARGET, "--crate-type=staticlib",
                            "-C", "panic=abort", "-C", "opt-level=0"]
                           + sum((["-C", f"target-feature={f}"] for f in FEATS), [])
                           + ["--emit=obj", "-o", obj_path, rs_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr[:4000], file=sys.stderr)
            sys.exit(1)
        d = subprocess.run([OBJDUMP, "-d", "--triple=thumbv7-none-eabi", obj_path],
                           capture_output=True, text=True)
        out = []
        started = False
        for ln in d.stdout.splitlines():
            # bytes column is separated from the mnemonic by a TAB
            m = re.match(r'^\s*[0-9a-f]+:(.*?)\t(.*)$', ln)
            if m:
                started = True
                hws = m.group(1).split()
                text = m.group(2).strip()
                text = re.sub(r'//.*$', '', text).strip()
                text = re.sub(r'\s+', ' ', text)
                hex32 = "".join(h.rjust(4, "0") for h in hws)
                out.append(f"{hex32} {text}")
            elif started and re.match(r'^Disassembly of section', ln):
                break
    open(out_txt, "w").write("\n".join(out) + "\n")
    print(f"{len(out)} instructions written to {out_txt}")

if __name__ == "__main__":
    main()

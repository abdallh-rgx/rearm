#!/usr/bin/env python3
"""Generate golden (bytes, disasm) corpora for rearm differential testing.

Usage: gen_corpus.py <asm-file> <arch> <out.json>
  arch: arm | thumb | a64
Builds a Rust staticlib with global_asm! of the file contents, compiles with
rustc for the right target, disassembles with llvm-objdump, and emits JSON
[{ "hex": "e12fff1e", "text": "bx lr" }, ...]
"""
import json, subprocess, sys, os, re, tempfile, shutil

RUSTC = shutil.which("rustc") or os.path.expanduser("~/.cargo/bin/rustc")
OBJDUMP = None
for p in os.path.expanduser("~/.rustup/toolchains/*/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump").split():
    pass
import glob
cands = glob.glob(os.path.expanduser("~/.rustup/toolchains/*/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump"))
if cands: OBJDUMP = cands[0]

TARGETS = {"arm": ("armv7-unknown-linux-gnueabi", ["+neon", "+vfp3", "+div", "+mp"]),
           "thumb": ("thumbv7neon-unknown-linux-gnueabihf", ["+div", "+mp"]),
           "a64": ("aarch64-unknown-linux-gnu", [])}

def main():
    asm_file, arch, out_json = sys.argv[1], sys.argv[2], sys.argv[3]
    target, feats = TARGETS[arch]
    asm = open(asm_file).read()
    if arch == "thumb":
        asm = ".thumb\n.arch armv8-a\n" + asm
    elif arch == "arm":
        asm = ".arch armv8-a\n" + asm
    # escape braces for global_asm template
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
        r = subprocess.run([RUSTC, "--target", target, "--crate-type=staticlib",
                            "-C", "panic=abort", "-C", "opt-level=0"]
                           + sum((["-C", f"target-feature={f}"] for f in feats), [])
                           + ["--emit=obj", "-o", obj_path, rs_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr[:4000], file=sys.stderr)
            sys.exit(1)
        objdump_args = [OBJDUMP, "-d", obj_path]
        if arch == "thumb":
            objdump_args.insert(1, "--triple=thumbv7-none-eabi")
        d = subprocess.run(objdump_args, capture_output=True, text=True)
        out = []
        # take only the first .text section (our global_asm)
        lines = d.stdout.splitlines()
        started = False
        for ln in lines:
            m = re.match(r'^\s*[0-9a-f]+:\s+([0-9a-f]+)\s+(.*)$', ln)
            if m:
                if not started:
                    # check we're in the first global asm section
                    started = True
                hexw = m.group(1)
                text = m.group(2).strip()
                # strip comments
                text = re.sub(r'//.*$', '', text).strip()
                # normalize whitespace
                text = re.sub(r'\s+', ' ', text)
                out.append({"hex": hexw.zfill(8), "text": text})
            elif started and re.match(r'^Disassembly of section', ln):
                break
    json.dump(out, open(out_json, "w"), indent=0)
    print(f"{len(out)} instructions written to {out_json}")

if __name__ == "__main__":
    main()

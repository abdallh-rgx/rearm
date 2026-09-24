#!/usr/bin/env python3
"""T32 corpus generator: llvm-mc assemble + llvm-objdump disassemble.

Usage: tcorpus.py <asm-file> <out-txt>
Output lines: `hex32 text` — hex32 = halfwords in memory order (hw1 then hw2),
4 hex digits for 16-bit instructions, 8 for 32-bit. The disassembly text is
informational (used for debugging; the round-trip test checks bytes only).
"""
import sys, os
# tools/bisect.py shadows stdlib `bisect` (used by tempfile) — drop script dir.
sys.path = [p for p in sys.path
            if os.path.abspath(p or ".") != os.path.dirname(os.path.abspath(__file__))]
import subprocess, re, tempfile

MC = os.path.expanduser("~/bin/llvm-mc")
OBJDUMP = os.path.expanduser("~/bin/llvm-objdump")
ATTRS = "+v8,+neon,+hwdiv,+dsp,+crc"


def main():
    asm_file, out_txt = sys.argv[1], sys.argv[2]
    src = ".thumb\n.syntax unified\n.arch armv8-a\n" + open(asm_file).read()
    with tempfile.TemporaryDirectory() as td:
        obj = os.path.join(td, "g.o")
        r = subprocess.run([MC, "-triple=thumbv7-none-eabi", f"-mattr={ATTRS}",
                            "-filetype=obj", "-o", obj, "-"],
                           input=src, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr[:4000])
            sys.exit(1)
        d = subprocess.run([OBJDUMP, "-d", "--triple=thumbv7-none-eabi", f"-mattr={ATTRS}", obj],
                           capture_output=True, text=True)
        out = []
        started = False
        for ln in d.stdout.splitlines():
            m = re.match(r'^\s*[0-9a-f]+:(.*?)\t(.*)$', ln)
            if m:
                started = True
                hws = m.group(1).split()
                text = m.group(2).strip()
                text = re.sub(r'//.*$', '', text).strip()
                text = re.sub(r'\s+', ' ', text)
                text = re.sub(r'\s*@.*$', '', text).strip()  # drop "@ imm = …"
                if not text or text.startswith('.'):
                    continue  # data directives (.word) from .space padding
                hex32 = "".join(h.rjust(4, "0") for h in hws)
                out.append(f"{hex32} {text}")
            elif started and re.match(r'^Disassembly of section', ln):
                break
    open(out_txt, "w").write("\n".join(out) + "\n")
    print(f"{out_txt}: {len(out)} instructions")


if __name__ == "__main__":
    main()

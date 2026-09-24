#!/usr/bin/env python3
"""Probe T32 encodings: reads instruction text lines on stdin (or from file
arg), assembles each with llvm-mc -show-encoding, prints `hw1hw2 text`.
"""
import sys, os, subprocess

sys.path = [p for p in sys.path
            if os.path.abspath(p or ".") != os.path.dirname(os.path.abspath(__file__))]
MC = os.path.expanduser("~/bin/llvm-mc")
ATTRS = "+v8,+neon,+hwdiv,+dsp,+crc"

src = ".thumb\n.syntax unified\n.arch armv8-a\n" + (
    open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read())
r = subprocess.run([MC, "-triple=thumbv7-none-eabi", f"-mattr={ATTRS}",
                    "-show-encoding"],
                   input=src, capture_output=True, text=True)
for ln in r.stdout.splitlines():
    if "encoding:" in ln:
        pre = ln.split("@")[0].strip()
        enc = ln.split("encoding: [")[1].split("]")[0]
        bs = [b.strip() for b in enc.split(",")]
        print(" ".join(b[2:].rjust(2, "0") for b in bs), pre)
if r.returncode != 0:
    sys.stderr.write(r.stderr[:4000])
    sys.exit(1)

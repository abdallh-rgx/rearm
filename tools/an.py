#!/usr/bin/env python3
"""Decompose T32 corpus words into bit fields for pattern discovery."""
import sys

def bits(v, hi, lo):
    return (v >> lo) & ((1 << (hi - lo + 1)) - 1)

def binfmt(v, n=16):
    s = format(v, '0%db' % n)
    return ' '.join(s[i:i+4] for i in range(0, n, 4))

lines = [l.split(None, 1) for l in open(sys.argv[1] if len(sys.argv) > 1 else '/home/z/rearm/crates/rearm-core/tests/corpus/thumb-misc.txt').read().splitlines() if l.strip()]

pat = sys.argv[2] if len(sys.argv) > 2 else None
for hexw, text in lines:
    if pat and pat not in text:
        continue
    w = int(hexw, 16)
    hw1 = w & 0xFFFF       # first halfword in memory (low 16 of the file word)
    hw2 = (w >> 16) & 0xFFFF
    print(f"{hexw:>8} | hw1={binfmt(hw1)} ({hw1:04x}) hw2={binfmt(hw2)} ({hw2:04x}) | {text.strip()}")

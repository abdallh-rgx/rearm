#!/usr/bin/env python3
"""Tabulate T32 field layouts from the golden corpora: for each corpus line,
extract op-space fields and group by mnemonic family to reveal the bit maps."""
import sys, os, re
from collections import defaultdict

sys.path = [p for p in sys.path
            if os.path.abspath(p or ".") != os.path.dirname(os.path.abspath(__file__))]

BASE = os.path.expanduser("~/rearm/crates/rearm-core/tests/corpus")

rows = []

def fields(hw1, hw2):
    pass  # placeholder defined below
for name in ["thumb2-dp.txt", "thumb2-mem.txt", "thumb2-mul.txt", "thumb-misc.txt"]:
    for ln in open(os.path.join(BASE, name)):
        ln = ln.strip()
        if not ln:
            continue
        hex32, text = ln.split(" ", 1)
        text = re.sub(r"@.*$", "", text).strip()
        v = int(hex32, 16)
        if len(hex32) <= 4:
            continue  # 16-bit: skip here
        hw1, hw2 = v >> 16, v & 0xFFFF
        rows.append((hw1, hw2, text))

# group by hw1 top bits (15:9 → 7-bit space key)
groups = defaultdict(list)
for hw1, hw2, text in rows:
    key = (hw1 >> 9) & 0x7F  # bits 15:9
    groups[key].append((hw1, hw2, text))

for key in sorted(groups):
    fam = groups[key]
    print(f"\n===== space bits15:9 = {key:07b} (hw1 {fam[0][0]>>8:02x}xx) — {len(fam)} insns =====")
    seen = set()
    for hw1, hw2, text in fam:
        # per-space field extraction
        f = fields(hw1, hw2)
        line = f"{hw1:04x} {hw2:04x}  {text:<38} {f}"
        if line not in seen:
            seen.add(line)
            print(line)

def fields(hw1, hw2):
    w = (hw1 << 16) | hw2
    top = (hw1 >> 9) & 0x7F
    if top == 0b1110100:  # e8/e9
        return f"P={w>>24&1} U={w>>23&1} W={w>>21&1} L={w>>20&1} Rn={w>>16&0xF:x} hw2={hw2:04x}"
    if top == 0b1110101:  # ea
        return f"op={w>>21&0xF:x} S={w>>20&1} Rn={w>>16&0xF:x} imm3={w>>12&7} Rd={w>>8&0xF:x} imm2={w>>6&3} typ={w>>4&3} Rm={w&0xF:x}"
    if top in (0b1110110, 0b1110111):  # f0/f2
        return f"i={w>>26&1} op5={w>>21&0x1F:05b} S={w>>20&1} Rn={w>>16&0xF:x} imm3={w>>12&7} Rd={w>>8&0xF:x} imm8={w&0xFF:02x}"
    if top == 0b1111100:  # f8/f9
        return f"S={w>>24&1} U={w>>23&1} sz={(w>>21)&3:02b} L={w>>20&1} Rn={w>>16&0xF:x} Rt={hw2>>12&0xF:x} mode={hw2>>8&0xF:x} imm={hw2&0xFF:02x}"
    if top == 0b1111101:  # fa
        return f"op1={w>>20&0xF:x} Rn={w>>16&0xF:x} Rd={w>>8&0xF:x} op2={w>>4&0xF:x} Rm={w&0xF:x}"
    if top == 0b1111110:  # fb
        return f"op1={w>>21&7:03b} x={w>>20&1} Rn={w>>16&0xF:x} Ra={hw2>>12&0xF:x} Rd={hw2>>8&0xF:x} op2={hw2>>4&0xF:x} Rm={hw2&0xF:x}"
    return f"w={w:08x}"

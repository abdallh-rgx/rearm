#!/usr/bin/env python3
"""Wrap raw code bytes into a minimal ELF for llvm-objdump differential testing."""
import struct, sys

def mk_elf32_arm(code: bytes) -> bytes:
    ehsize, phentsize, phnum, shentsize, shnum, shstrndx = 52, 32, 1, 40, 3, 2
    shoff = ehsize + phentsize
    text_off = shoff + shnum*shentsize
    text_addr = 0x10000
    shstrtab = b"\0.text\0.shstrtab\0"
    shstr_off = text_off + len(code)
    def sh(name, typ, flags, addr, off, size, link=0, info=0, align=4, entsize=0):
        return struct.pack('<IIIIIIIIII', name, typ, flags, addr, off, size, link, info, align, entsize)
    shnull = sh(0, 0, 0, 0, 0, 0)
    shtext = sh(1, 1, 0x6, text_addr, text_off, len(code))
    shshstr = sh(7, 3, 0, 0, shstr_off, len(shstrtab))
    eh = struct.pack('<4s5B7xHHIIIIIHHHHHH', b'\x7fELF', 1, 1, 1, 0, 0,
                     2, 40, 1, text_addr, ehsize, shoff, 0x05000000,
                     ehsize, phentsize, phnum, shentsize, shnum, shstrndx)
    ph = struct.pack('<8I', 1, text_off, text_addr, text_addr, len(code), len(code), 7, 0x1000)
    return eh + ph + shnull + shtext + shshstr + code + shstrtab

def mk_elf64(code: bytes) -> bytes:
    ehsize, phentsize, phnum, shentsize, shnum, shstrndx = 64, 56, 1, 64, 3, 2
    shoff = ehsize + phentsize
    text_off = shoff + shnum*shentsize
    text_addr = 0x10000
    shstrtab = b"\0.text\0.shstrtab\0"
    shstr_off = text_off + len(code)
    def sh(name, typ, flags, addr, off, size, link=0, info=0, align=4, entsize=0):
        return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, off, size, link, info, align, entsize)
    shnull = sh(0, 0, 0, 0, 0, 0)
    shtext = sh(1, 1, 0x6, text_addr, text_off, len(code))
    shshstr = sh(7, 3, 0, 0, shstr_off, len(shstrtab))
    eh = struct.pack('<4s5B7xHHIQQQIHHHHHH', b'\x7fELF', 2, 1, 1, 0, 0,
                     2, 0xB7, 1, text_addr, ehsize, shoff, 0,
                     ehsize, phentsize, phnum, shentsize, shnum, shstrndx)
    ph = struct.pack('<IIQQQQQQ', 1, 5, text_off, text_addr, text_addr, len(code), len(code), 0x1000)
    return eh + ph + shnull + shtext + shshstr + code + shstrtab

if __name__ == '__main__':
    mode, inp, outp = sys.argv[1], sys.argv[2], sys.argv[3]
    data = open(inp, 'rb').read()
    if mode == 'arm32':
        open(outp, 'wb').write(mk_elf32_arm(data))
    elif mode == 'a64':
        open(outp, 'wb').write(mk_elf64(data))
    else:
        raise SystemExit('mode must be arm32|a64')

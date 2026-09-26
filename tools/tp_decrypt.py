#!/usr/bin/env python3
"""TP-decrypt: XOR-0xDE over .text and .rodata of PUBG 0.12.0 libUE4.so.

The Tencent TP protection on this build is a static per-byte XOR with 0xDE
applied to .text and .rodata (metadata — .plt/.ARM.exidx/.ARM.extab/.data*/
.got — is left plain so the Android dynamic linker still works; libtprt.so
decrypts at runtime before init_array runs).

Evidence for the key (see session logs):
  * function starts decode to STMFD push prologues (94.6% of 119k exidx funcs)
  * BL targets land on exidx function entries
  * .rodata decodes to clean UTF-16LE UE4 strings
  * float literal pools decode to sensible constants (200.0f, 1.0f, ...)
"""
import struct
import sys

def decrypt(data: bytes) -> bytes:
    out = bytearray(data)

    # parse section headers (ELF32 LE)
    e_shoff, = struct.unpack('<I', data[0x20:0x24])
    e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', data[0x2e:0x34])
    shstr_hdr = data[e_shoff + e_shstrndx*e_shentsize:]
    shstr_off, = struct.unpack('<I', shstr_hdr[16:20])

    targets = {'.text', '.rodata'}
    n = 0
    for i in range(e_shnum):
        sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
        if len(sh) < 40:
            break
        sh_name, = struct.unpack('<I', sh[0:4])
        sh_flags, = struct.unpack('<I', sh[8:12])
        sh_off, sh_size = struct.unpack('<II', sh[16:24])
        end = data.index(b'\0', shstr_off + sh_name)
        name = data[shstr_off + sh_name:end].decode()
        if name in targets and sh_size > 0:
            for j in range(sh_off, sh_off + sh_size):
                out[j] ^= 0xDE
            n += 1
            print(f"decrypted {name}: off={sh_off:#x} size={sh_size:#x}")
    print(f"sections decrypted: {n}")
    return bytes(out)


if __name__ == '__main__':
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, 'rb').read()
    open(dst, 'wb').write(decrypt(data))
    print(f"wrote {dst}")

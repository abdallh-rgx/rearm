#!/usr/bin/env python3
"""
apk_tool.py -- Repackage and sign Android APKs (rearm translation pipeline).

Subcommands
----------
  genkey   Generate a persistent self-signed RSA-4096 code-signing key/cert
           (O=rearm, CN=rearm, 25-year validity, SHA-256) via the openssl CLI.
           Idempotent: existing keys are left untouched.
  repack   Rebuild an APK replacing all 32-bit native libraries (and x86
           variants) with arm64-v8a *.so files taken from --lib-dir.  All
           lib/*/*.so entries are written STORED with 4096-byte data-offset
           alignment (via the zip extra-field padding technique) so that
           android:extractNativeLibs="false" page mapping works.  Old JAR
           signature files (META-INF/MANIFEST.MF, *.SF, *.RSA, *.DSA, *.EC)
           are dropped.  Every other entry is preserved, keeping its original
           compression method (deflated entries are recompressed at level 9;
           stored entries stay stored and keep 4-byte data alignment -- in
           particular resources.arsc).
  sign     Apply APK Signature Scheme v1 (JAR signing, SHA-256 digests) and
           APK Signature Scheme v2 (block id 0x7109871a, RSA PKCS#1 v1.5 with
           SHA-256, algorithm id 0x0103 per the AOSP implementation).  Signs in
           place unless --out is given.  Re-signing an already signed APK works:
           old signature entries and any old v2 signing block are replaced.
  verify   Self-verification: recompute v1 digests from the zip and compare
           against MANIFEST.MF / CERT.SF, verify the CERT.RSA PKCS#7
           signature (openssl), recompute the v2 content digest over the
           three zip regions and RSA-verify the v2 signature against the
           embedded public key.

All multi-byte zip integers are little-endian.  Only the Python standard
library is used for the zip work (zipfile for reading, manual struct-based
writing for full control of alignment and extra fields).  All cryptography is
deleg to the local openssl CLI (/usr/bin/openssl).

The v2 signing-block byte format implemented here is byte-for-byte the one
produced by AOSP apksig (tools/apksig, V2SchemeSigner.generateSignerBlock /
ApkSigningBlockUtils.computeOneMbChunkContentDigests / generateApkSigningBlock),
validated round-trip against ApkVerifier 8.x:

  signer record  = LP(signed data) || LP(signatures) || LP(public key SPKI DER)
  signed data    = LP(digests) || LP(certificates) || LP(attributes) || LP("")
      digests     = LP( u32le(alg id) || LP(content digest) ) ...
      certificates= LP( X.509 certificate DER ) ...
      attributes  = empty sequence (no v3 stripping protection)
  signatures     = LP( u32le(alg id) || LP(RSA signature) ) ...
  v2 pair value  = LP( LP(signer record) )

  content digest = SHA256( 0x5a || u32le(total chunk count) ||
                           concat( SHA256( 0xa5 || u32le(len) || chunk ) ) )
    over the three regions [zip entries][central directory][EOCD with the
    CD offset patched as if the signing block were absent], each region
    split into consecutive <=1 MiB chunks (empty regions contribute no
    chunks), in region order.
  RSA signature   = PKCS#1 v1.5 with SHA-256 over the RAW signed-data bytes
                   (WITHOUT the 4-byte length prefix).

  signing block  = u64(size) || pairs || u64(size) || "APK Sig Block 42"
    where size = block length - 8; the block is padded with the apksig
    verity padding pair (id 0x42726577) to a multiple of 4096 bytes.

JAR (v1) digest conventions (apksig ManifestWriter / V1SchemeSigner):
  * CRLF line terminators; lines longer than 72 bytes are folded, the
    continuation lines starting with a single space.
  * manifest sections are emitted in sorted entry-name order, each section
    being "Name: ...\r\n" + "SHA-256-Digest: ...\r\n" + "\r\n".
  * the per-entry digest in CERT.SF covers the manifest section bytes
    INCLUDING the trailing blank line.
  * META-INF/<file> directly in META-INF/ is not listed in the manifest;
    files in subdirectories of META-INF are; directories are not listed.
  * CERT.SF gets an extra trailing CRLF when its size is a multiple of 1024
    (Android <= 6.0 java.util.jar workaround).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import time
import zlib
import zipfile
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ZIP_LOCAL_SIG = 0x04034B50
ZIP_CENTRAL_SIG = 0x02014B50
ZIP_EOCD_SIG = 0x06054B50

METHOD_STORED = 0
METHOD_DEFLATED = 8

VERSION_NEEDED = 20              # 2.0: deflate / directories
VERSION_MADE_BY = (3 << 8) | 20  # unix, zip 2.0

SO_ALIGN = 4096                  # page alignment for uncompressed native libs
DEFAULT_ALIGN = 4                # alignment for other stored entries
EXTRA_FIELD_PADDING_ID = 0xD935  # extra-field id used by Android zipalign

CRLF = b"\r\n"
MANIFEST_LINE_LIMIT = 72         # max bytes of a manifest line (JAR spec)

# APK Signature Scheme v2
V2_BLOCK_ID = 0x7109871A
V2_MAGIC = b"APK Sig Block 42"
# RSA-PKCS1-v1.5 with SHA-256 content digest (CHUNKED_SHA256).  NOTE: the
# algorithm ID table that actually runs on Android devices (frameworks/base
# android.util.apk.ApkSigningBlockUtils and apksig SignatureAlgorithm) is:
#   0x0101 = RSASSA-PSS with SHA-256      0x0102 = RSASSA-PSS with SHA-512
#   0x0103 = RSASSA-PKCS1-v1_5 with SHA-256   0x0104 = ... with SHA-512
# (some public docs swap 0x0102/0x0103; the implementation is authoritative)
SIG_ALG_RSA_PKCS1_SHA256 = 0x0103  # RSASSA-PKCS1-v1_5 with SHA2-256
V2_CHUNK_SIZE = 1 << 20             # 1 MiB
V2_CHUNK_PREFIX = 0xA5              # per-chunk digest prefix byte
V2_TOP_PREFIX = 0x5A                # top-level digest prefix byte (NOT 0xa5!)
V2_PADDING_PAIR_ID = 0x42726577     # apksig verity padding pair id
PAGE_ALIGN = 4096                   # signing block padded to this multiple

# Native library architectures that are removed/replaced during repack.
DROP_LIB_PREFIXES = (
    "lib/armeabi-v7a/",
    "lib/armeabi/",
    "lib/arm64-v8a/",   # replaced wholesale by --lib-dir contents
    "lib/x86/",
    "lib/x86_64/",
)

OPENSSL = "/usr/bin/openssl"


class ToolError(Exception):
    """Fatal, user-facing error."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64(data: bytes) -> bytes:
    return base64.b64encode(data)


def run_openssl(openssl: str, args: List[str],
                input_bytes: Optional[bytes] = None) -> subprocess.CompletedProcess:
    """Run an openssl CLI command."""
    cmd = [openssl] + args
    try:
        proc = subprocess.run(cmd, input=input_bytes, capture_output=True)
    except FileNotFoundError:
        raise ToolError("openssl binary not found: %s" % openssl)
    return proc


def openssl_ok(openssl: str, args: List[str],
               input_bytes: Optional[bytes] = None) -> Tuple[bool, str]:
    proc = run_openssl(openssl, args, input_bytes)
    msg = (proc.stdout + proc.stderr).decode("utf-8", "replace").strip()
    return proc.returncode == 0, msg


def u32le(n: int) -> bytes:
    return struct.pack("<I", n)


def lp(data: bytes) -> bytes:
    """Length-prefix an element with a little-endian uint32 (v2 style)."""
    return u32le(len(data)) + data


def dos_datetime(dt: Tuple[int, int, int, int, int, int]) -> Tuple[int, int]:
    """Convert a (y, m, d, h, mi, s) tuple to MS-DOS (time, date) words."""
    year = max(1980, min(2107, dt[0]))
    date = ((year - 1980) << 9) | (dt[1] << 5) | dt[2]
    tim = (dt[3] << 11) | (dt[4] << 5) | (dt[5] // 2)
    return tim, date


def is_signature_file(name: str) -> bool:
    """True for JAR-signature entries that must be dropped (case-insensitive)."""
    if not name.startswith("META-INF/"):
        return False
    base = name[len("META-INF/"):]
    if base.upper() == "MANIFEST.MF":
        return True
    return base.upper().endswith((".SF", ".RSA", ".DSA", ".EC"))


def is_dir_entry(name: str) -> bool:
    return name.endswith("/")


def is_jar_digest_entry(name: str) -> bool:
    """
    True for zip entries that JAR signing must list in MANIFEST.MF
    (apksig V1SchemeSigner.isJarEntryDigestNeededInManifest):
      * directories are never listed;
      * entries outside META-INF/ are listed;
      * entries in subdirectories of META-INF are listed;
      * files directly in META-INF/ are not.
    """
    if is_dir_entry(name):
        return False
    if not name.startswith("META-INF/"):
        return True
    return name.find("/", len("META-INF/")) != -1


# ---------------------------------------------------------------------------
# Zip writing (manual, struct-based, alignment via extra field)
# ---------------------------------------------------------------------------

class ZipEntry:
    """A single zip entry to be written by ZipWriter."""

    __slots__ = ("name", "data", "method", "align", "date_time", "external_attr")

    def __init__(self, name: str, data: bytes, method: int,
                 align: int = 1,
                 date_time: Tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0),
                 external_attr: int = 0o100644 << 16) -> None:
        self.name = name
        self.data = data
        self.method = method
        self.align = align
        self.date_time = date_time
        self.external_attr = external_attr


def alignment_for(name: str, method: int) -> int:
    """Alignment rule for a stored entry's data offset."""
    if method != METHOD_STORED:
        return 1
    if name.startswith("lib/") and name.endswith(".so"):
        return SO_ALIGN
    return DEFAULT_ALIGN


def alignment_extra(data_start_if_no_extra: int, align: int) -> bytes:
    """
    Build a zip extra field so that the STORED entry's data begins at an
    offset that is a multiple of ``align``.

    ``data_start_if_no_extra`` is the offset the entry data would start at
    if the extra field were empty (local header offset + 30 + len(name)).
    The returned extra field has a total length congruent to the needed pad
    modulo ``align``; a well-formed (id, size) padding record (the same
    0xd935 technique zipalign uses) is emitted so that parsers skip it.
    """
    if align <= 1:
        return b""
    pad = (-data_start_if_no_extra) % align
    if pad == 0:
        return b""
    if pad < 4:
        # A valid extra field costs at least 4 bytes; wrap around one full
        # alignment period to stay congruent.
        pad += align
    return struct.pack("<HH", EXTRA_FIELD_PADDING_ID, pad - 4) + b"\x00" * (pad - 4)


class ZipWriter:
    """Sequential zip writer with control over per-entry alignment."""

    def __init__(self, entries: List[ZipEntry]) -> None:
        self.entries = entries

    def write(self, path: str) -> Dict[str, int]:
        """Write all entries; returns {'entries': n, 'cd_offset': off}."""
        central = bytearray()
        offset = 0
        count = 0
        with open(path, "wb") as f:
            for entry in self.entries:
                name = entry.name.encode("utf-8")
                data = entry.data
                crc = zlib.crc32(data) & 0xFFFFFFFF
                if entry.method == METHOD_DEFLATED:
                    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
                    blob = comp.compress(data) + comp.flush()
                elif entry.method == METHOD_STORED:
                    blob = data
                else:
                    raise ToolError("unsupported compression method %d for %s"
                                    % (entry.method, entry.name))
                tim, date = dos_datetime(entry.date_time)
                extra = alignment_extra(offset + 30 + len(name), entry.align)
                local = struct.pack(
                    "<IHHHHHIIIHH", ZIP_LOCAL_SIG, VERSION_NEEDED, 0,
                    entry.method, tim, date, crc, len(blob), len(data),
                    len(name), len(extra))
                f.write(local)
                f.write(name)
                f.write(extra)
                f.write(blob)
                central += struct.pack(
                    "<IHHHHHHIIIHHHHHII", ZIP_CENTRAL_SIG, VERSION_MADE_BY,
                    VERSION_NEEDED, 0, entry.method, tim, date, crc,
                    len(blob), len(data), len(name), 0, 0, 0, 0,
                    entry.external_attr, offset)
                central += name
                offset += 30 + len(name) + len(extra) + len(blob)
                count += 1
            cd_offset = offset
            f.write(central)
            f.write(struct.pack("<IHHHHIIH", ZIP_EOCD_SIG, 0, 0, count, count,
                                len(central), cd_offset, 0))
        return {"entries": count, "cd_offset": cd_offset}


def read_apk_entries(path: str) -> List[ZipEntry]:
    """Read every entry of an APK (decompressed), preserving method/metadata."""
    entries: List[ZipEntry] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                raise ToolError("entry is encrypted, refusing: %s" % info.filename)
            is_dir = is_dir_entry(info.filename)
            method = METHOD_STORED if is_dir else info.compress_type
            entries.append(ZipEntry(
                name=info.filename,
                data=zf.read(info.filename),
                method=method,
                align=alignment_for(info.filename, method),
                date_time=info.date_time,
                external_attr=info.external_attr))
    return entries


# ---------------------------------------------------------------------------
# Raw zip parsing (EOCD / signing block location)
# ---------------------------------------------------------------------------

def locate_eocd(data: bytes) -> Tuple[int, int, int]:
    """
    Locate the End-Of-Central-Directory record.

    Returns (eocd_offset, cd_size, cd_offset).  Raises ToolError if the zip
    uses ZIP64 or has an inconsistent EOCD comment length.
    """
    start = max(0, len(data) - (22 + 65535))
    eocd_off = data.rfind(struct.pack("<I", ZIP_EOCD_SIG), start)
    if eocd_off < 0:
        raise ToolError("EOCD record not found (not a zip file?)")
    (sig, disk, cd_disk, n_disk, n_total, cd_size, cd_off, clen) = struct.unpack_from(
        "<IHHHHIIH", data, eocd_off)
    if disk != 0 or cd_disk != 0 or n_disk != n_total or cd_size == 0xFFFFFFFF \
            or cd_off == 0xFFFFFFFF or n_total == 0xFFFF:
        raise ToolError("ZIP64 EOCD records are not supported")
    if eocd_off + 22 + clen != len(data):
        raise ToolError("EOCD comment length mismatch (file truncated?)")
    return eocd_off, cd_size, cd_off


def find_signing_block(data: bytes) -> Optional[Tuple[int, int]]:
    """
    Locate an APK signing block (if any).

    Returns (block_start, block_size_excluding_first_length_field) or None.
    """
    _, _, cd_off = locate_eocd(data)
    if cd_off < 32 or data[cd_off - 16:cd_off] != V2_MAGIC:
        return None
    (size,) = struct.unpack_from("<Q", data, cd_off - 24)
    block_start = cd_off - 8 - size
    if block_start < 0:
        raise ToolError("corrupt APK signing block (negative start)")
    (size2,) = struct.unpack_from("<Q", data, block_start)
    if size2 != size:
        raise ToolError("corrupt APK signing block (size fields differ)")
    return block_start, size


def iterate_block_pairs(data: bytes, block_start: int, block_size: int):
    """Yield (pair_id, value_bytes) for each pair of a signing block."""
    end = block_start + 8 + block_size - 24  # exclude trailing size + magic
    off = block_start + 8
    while off < end:
        if off + 12 > end:
            raise ToolError("corrupt APK signing block pair")
        (plen,) = struct.unpack_from("<Q", data, off)
        (pid,) = struct.unpack_from("<I", data, off + 8)
        value = data[off + 12: off + 8 + plen]
        if len(value) != plen - 4:
            raise ToolError("corrupt APK signing block pair length")
        yield pid, value
        off += 8 + plen


def read_lp(buf: bytes, off: int) -> Tuple[bytes, int]:
    """Read a little-endian uint32 length-prefixed element."""
    if off + 4 > len(buf):
        raise ToolError("truncated length prefix in v2 block")
    (length,) = struct.unpack_from("<I", buf, off)
    end = off + 4 + length
    if end > len(buf):
        raise ToolError("truncated length-prefixed element in v2 block")
    return buf[off + 4:end], end


# ---------------------------------------------------------------------------
# APK Signature Scheme v2
# ---------------------------------------------------------------------------

def compute_content_digest(data: bytes, block_start: int) -> Tuple[bytes, int]:
    """
    Compute the v2 content digest (SHA-256, algorithm id 0x0102).

    Follows apksig ApkSigningBlockUtils.computeOneMbChunkContentDigests:
    the three digested regions are
      1. zip entry contents:  data[0:block_start]
      2. central directory:   data[cd_off:eocd_off]
      3. EOCD:               bytes of the EOCD with the central-directory
         offset field set to ``block_start`` (i.e. as if no signing block
         were present).
    Each region is split into consecutive <=1 MiB chunks (empty regions
    contribute no chunks); the digest of each chunk is
    SHA256(0xa5 || u32le(chunk_len) || chunk).  The final digest is
    SHA256(0x5a || u32le(total_chunk_count) || concat(chunk digests)).
    """
    eocd_off, _, cd_off = locate_eocd(data)
    eocd = bytearray(data[eocd_off:])
    struct.pack_into("<I", eocd, 16, block_start)
    sections = (data[:block_start], data[cd_off:eocd_off], bytes(eocd))
    chunk_digests: List[bytes] = []
    for section in sections:
        for i in range(0, len(section), V2_CHUNK_SIZE):
            chunk = section[i:i + V2_CHUNK_SIZE]
            chunk_digests.append(
                sha256(bytes([V2_CHUNK_PREFIX]) + u32le(len(chunk)) + chunk))
    top = bytes([V2_TOP_PREFIX]) + u32le(len(chunk_digests)) + b"".join(chunk_digests)
    return sha256(top), len(chunk_digests)


def rsa_sign(openssl: str, key_path: str, payload: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 with SHA-256 via ``openssl dgst``."""
    with tempfile.TemporaryDirectory() as td:
        data_path = os.path.join(td, "data.bin")
        sig_path = os.path.join(td, "sig.bin")
        with open(data_path, "wb") as f:
            f.write(payload)
        proc = run_openssl(openssl, ["dgst", "-sha256", "-sign", key_path,
                                     "-out", sig_path, data_path])
        if proc.returncode != 0:
            raise ToolError("openssl dgst -sign failed: %s"
                            % proc.stderr.decode("utf-8", "replace"))
        with open(sig_path, "rb") as f:
            return f.read()


def rsa_verify(openssl: str, spki_der: bytes, payload: bytes,
               signature: bytes) -> Tuple[bool, str]:
    """Verify an RSASSA-PKCS1-v1_5 SHA-256 signature with the given SPKI."""
    with tempfile.TemporaryDirectory() as td:
        proc = run_openssl(openssl, ["pkey", "-pubin", "-outform", "PEM"],
                           input_bytes=spki_der)
        if proc.returncode != 0:
            return False, "openssl pkey: " + proc.stderr.decode("utf-8", "replace")
        pub_path = os.path.join(td, "pub.pem")
        data_path = os.path.join(td, "data.bin")
        sig_path = os.path.join(td, "sig.bin")
        with open(pub_path, "wb") as f:
            f.write(proc.stdout)
        with open(data_path, "wb") as f:
            f.write(payload)
        with open(sig_path, "wb") as f:
            f.write(signature)
        return openssl_ok(openssl, ["dgst", "-sha256", "-verify", pub_path,
                                    "-signature", sig_path, data_path])


def spki_of_cert(openssl: str, crt_path: str) -> bytes:
    """Extract the X.509 SubjectPublicKeyInfo DER of a PEM certificate."""
    proc = run_openssl(openssl, ["x509", "-in", crt_path, "-pubkey", "-noout"])
    if proc.returncode != 0:
        raise ToolError("openssl x509 -pubkey failed: %s"
                        % proc.stderr.decode("utf-8", "replace"))
    proc2 = run_openssl(openssl, ["pkey", "-pubin", "-outform", "DER"],
                        input_bytes=proc.stdout)
    if proc2.returncode != 0:
        raise ToolError("openssl pkey failed: %s"
                        % proc2.stderr.decode("utf-8", "replace"))
    return proc2.stdout


def cert_der_of(openssl: str, key_dir: str) -> bytes:
    """Load the DER form of <key_dir>/rearm.crt (from .crt.der or the PEM)."""
    der_path = os.path.join(key_dir, "rearm.crt.der")
    if os.path.isfile(der_path):
        with open(der_path, "rb") as f:
            return f.read()
    proc = run_openssl(openssl, ["x509", "-in", os.path.join(key_dir, "rearm.crt"),
                                 "-outform", "DER"])
    if proc.returncode != 0 or not proc.stdout:
        raise ToolError("failed to DER-encode %s" % os.path.join(key_dir, "rearm.crt"))
    return proc.stdout


def build_v2_block(openssl: str, key_path: str, cert_der: bytes, spki_der: bytes,
                   data: bytes, block_start: int) -> Tuple[bytes, bytes]:
    """
    Build the complete APK signing block for the zip image ``data`` whose
    contents region ends at ``block_start`` (== CD offset before insertion).

    Returns (block_bytes, content_digest).  The block is padded with the
    apksig verity padding pair so its total size is a multiple of 4096.
    """
    digest, _ = compute_content_digest(data, block_start)

    # --- signed data: digests || certificates || attributes || min/max sdk ---
    digests_seq = lp(u32le(SIG_ALG_RSA_PKCS1_SHA256) + lp(digest))
    certificates_seq = lp(cert_der)
    additional_attributes_seq = b""          # no v3 stripping protection
    sdk_range = b""                         # minSdkVersion/maxSdkVersion = 0/0
    signed_data = (lp(digests_seq) + lp(certificates_seq)
                   + lp(additional_attributes_seq) + lp(sdk_range))

    # --- RSA PKCS#1 v1.5 SHA-256 over the RAW signed-data bytes ---
    signature = rsa_sign(openssl, key_path, signed_data)
    signatures_seq = lp(u32le(SIG_ALG_RSA_PKCS1_SHA256) + lp(signature))

    # --- signer record: signed data || signatures || public key ---
    signer = lp(signed_data) + lp(signatures_seq) + lp(spki_der)
    pair_value = lp(lp(signer))

    # --- signing block: u64(size) pairs u64(size) magic, 4096-padded ---
    v2_pair = (struct.pack("<Q", 4 + len(pair_value))
               + struct.pack("<I", V2_BLOCK_ID) + pair_value)
    pairs = [v2_pair]
    result_size = 8 + len(v2_pair) + 8 + 16
    if result_size % PAGE_ALIGN:
        pad = PAGE_ALIGN - (result_size % PAGE_ALIGN)
        if pad < 12:                        # minimum ID-value pair size
            pad += PAGE_ALIGN
        padding_pair = (struct.pack("<Q", pad - 8)
                        + struct.pack("<I", V2_PADDING_PAIR_ID)
                        + b"\x00" * (pad - 12))
        pairs.append(padding_pair)
        result_size += pad
    size = result_size - 8
    block = (struct.pack("<Q", size) + b"".join(pairs)
             + struct.pack("<Q", size) + V2_MAGIC)
    assert len(block) == result_size
    return block, digest


def apply_v2_block(data: bytes, block: bytes, old_block_start: Optional[int]) -> bytes:
    """Insert/replace the signing block and fix the EOCD CD-offset field."""
    eocd_off, _, cd_off = locate_eocd(data)
    base = old_block_start if old_block_start is not None else cd_off
    new_cd_off = base + len(block)
    eocd = bytearray(data[eocd_off:])
    struct.pack_into("<I", eocd, 16, new_cd_off)
    return data[:base] + block + data[cd_off:eocd_off] + bytes(eocd)


class V2SignerInfo:
    """Parsed single-signer view of an APK Signature Scheme v2 block."""

    def __init__(self, signed_data: bytes, signatures_seq: bytes,
                 spki: bytes) -> None:
        """
        Parameters are the *contents* of the three signer-record fields.
        signed_data is the raw signed-data bytes (signature covers these);
        signatures_seq is the signatures sequence; spki the raw
        SubjectPublicKeyInfo DER.
        """
        # signed data = LP(digests) LP(certificates) LP(attributes) [LP(sdk)]
        digests_seq, off = read_lp(signed_data, 0)
        certificates_seq, off = read_lp(signed_data, off)
        self.attributes_seq, off = read_lp(signed_data, off)
        self.sdk_range, off = read_lp(signed_data, off)  # optional min/max sdk
        # (trailing bytes beyond the four fields, if any, are ignored --
        #  apksig only reads the first three.)
        digest_rec, consumed = read_lp(digests_seq, 0)
        if consumed != len(digests_seq):
            raise ToolError("multiple digests in v2 signer (unsupported)")
        (self.digest_alg_id,) = struct.unpack("<I", digest_rec[:4])
        self.digest, _ = read_lp(digest_rec, 4)
        # certificates
        self.cert_der, consumed = read_lp(certificates_seq, 0)
        if consumed != len(certificates_seq):
            raise ToolError("multiple certificates in v2 signer (unsupported)")
        # signatures sequence = LP( u32 alg || LP(sig) )
        sig_rec, consumed = read_lp(signatures_seq, 0)
        if consumed != len(signatures_seq):
            raise ToolError("multiple signatures in v2 signer (unsupported)")
        (self.sig_alg_id,) = struct.unpack("<I", sig_rec[:4])
        self.signature, _ = read_lp(sig_rec, 4)
        self.spki = spki
        # the signature is computed over the raw signed-data bytes
        self.signed_data = signed_data


def parse_v2_block(data: bytes) -> Tuple[int, int, V2SignerInfo]:
    """
    Find and parse the v2 signing block.

    Returns (block_start, block_size, signer_info).  Raises ToolError if no
    block exists or the block is malformed / has multiple signers.
    """
    found = find_signing_block(data)
    if found is None:
        raise ToolError("no APK signing block found in this APK")
    block_start, block_size = found
    value = None
    for pid, v in iterate_block_pairs(data, block_start, block_size):
        if pid == V2_BLOCK_ID:
            if value is not None:
                raise ToolError("multiple v2 blocks")
            value = v
    if value is None:
        raise ToolError("APK signing block present but has no v2 signature")
    signers_seq, off = read_lp(value, 0)
    if off != len(value):
        raise ToolError("trailing bytes after v2 signer sequence")
    signer, off = read_lp(signers_seq, 0)
    if off != len(signers_seq):
        raise ToolError("multiple v2 signers (unsupported)")
    signed_data, off = read_lp(signer, 0)
    signatures_seq, off = read_lp(signer, off)
    spki, off = read_lp(signer, off)
    if off != len(signer):
        raise ToolError("trailing bytes in v2 signer record")
    return block_start, block_size, V2SignerInfo(signed_data, signatures_seq, spki)


# ---------------------------------------------------------------------------
# APK Signature Scheme v1 (JAR signing)
# ---------------------------------------------------------------------------

def fold_line(line: bytes) -> bytes:
    """
    Fold a logical manifest line into physical lines of at most 72 bytes.

    Continuation lines start with a single space (not counted towards the
    72-byte limit of the first line; the space itself occupies one byte of
    the continuation line, keeping every physical line <= 72 bytes).
    """
    if len(line) <= MANIFEST_LINE_LIMIT:
        return line + CRLF
    parts = [line[:MANIFEST_LINE_LIMIT]]
    rest = line[MANIFEST_LINE_LIMIT:]
    while rest:
        parts.append(b" " + rest[:MANIFEST_LINE_LIMIT - 1])
        rest = rest[MANIFEST_LINE_LIMIT - 1:]
    return CRLF.join(parts) + CRLF


def attr_line(key: str, value: bytes) -> bytes:
    return fold_line(key.encode("ascii") + b": " + value)


def build_manifest(files: List[ZipEntry]) -> Tuple[bytes, Dict[str, bytes]]:
    """
    Generate META-INF/MANIFEST.MF (entries sorted by name, apksig style).

    Returns the manifest bytes and a map of entry name -> the exact section
    bytes (including the trailing blank line) as they appear in the manifest.
    """
    out = bytearray()
    out += attr_line("Manifest-Version", b"1.0")
    out += attr_line("Created-By", b"rearm apk_tool 1.0 (openssl)")
    out += CRLF
    sections: Dict[str, bytes] = {}
    for entry in sorted(files, key=lambda e: e.name):
        section = bytearray()
        section += attr_line("Name", entry.name.encode("utf-8"))
        section += attr_line("SHA-256-Digest", b64(sha256(entry.data)))
        sections[entry.name] = bytes(section) + CRLF  # + blank line
        out += section
        out += CRLF
    return bytes(out), sections


def build_signature_file(manifest: bytes,
                         sections: Dict[str, bytes]) -> bytes:
    """
    Generate META-INF/CERT.SF: SHA-256-Digest-Manifest over the whole
    manifest plus the SHA-256 digest of each manifest section (the section
    bytes including their trailing blank line).  A trailing CRLF is added
    when the file size is a multiple of 1024 (Android <= 6.0 workaround).
    """
    out = bytearray()
    out += attr_line("Signature-Version", b"1.0")
    out += attr_line("Created-By", b"rearm apk_tool 1.0 (openssl)")
    out += attr_line("SHA-256-Digest-Manifest", b64(sha256(manifest)))
    out += CRLF
    for name in sorted(sections):
        out += attr_line("Name", name.encode("utf-8"))
        out += attr_line("SHA-256-Digest", b64(sha256(sections[name])))
        out += CRLF
    if len(out) % 1024 == 0:
        out += CRLF
    return bytes(out)


def cms_sign(openssl: str, sf: bytes, key_path: str, crt_path: str) -> bytes:
    """
    Produce META-INF/CERT.RSA: a detached PKCS#7/CMS DER signature over the
    CERT.SF bytes (openssl smime -sign, sha256, no authenticated
    attributes, signer certificate included, detached by default).
    """
    with tempfile.TemporaryDirectory() as td:
        sf_path = os.path.join(td, "sf")
        out_path = os.path.join(td, "out.p7")
        with open(sf_path, "wb") as f:
            f.write(sf)
        proc = run_openssl(openssl, [
            "smime", "-sign", "-md", "sha256", "-binary", "-noattr",
            "-in", sf_path, "-signer", crt_path, "-inkey", key_path,
            "-outform", "DER", "-out", out_path])
        if proc.returncode != 0:
            raise ToolError("openssl smime -sign failed: %s"
                            % proc.stderr.decode("utf-8", "replace"))
        with open(out_path, "rb") as f:
            return f.read()


def cms_verify(openssl: str, cert_rsa: bytes, sf: bytes) -> Tuple[bool, str]:
    """Verify a detached CMS/CERT.RSA against the CERT.SF content."""
    with tempfile.TemporaryDirectory() as td:
        rsa_path = os.path.join(td, "cert.rsa")
        sf_path = os.path.join(td, "cert.sf")
        with open(rsa_path, "wb") as f:
            f.write(cert_rsa)
        with open(sf_path, "wb") as f:
            f.write(sf)
        return openssl_ok(openssl, [
            "smime", "-verify", "-binary", "-inform", "DER",
            "-in", rsa_path, "-content", sf_path, "-noverify"])


class ManifestSection:
    """One parsed per-entry section of a manifest file."""

    def __init__(self, name: str, attrs: Dict[bytes, bytes],
                 section_bytes: bytes) -> None:
        self.name = name
        self.attrs = attrs
        self.section_bytes = section_bytes


def logical_lines(data: bytes) -> List[Tuple[bytes, int, int]]:
    """
    Split raw manifest bytes into logical lines.

    Returns a list of (line_bytes, start_offset, end_offset) where
    end_offset is past the line terminator.  Continuation lines (leading
    single space) are joined with the space removed.
    """
    out: List[Tuple[bytes, int, int]] = []
    cur: Optional[bytes] = None
    start = pend = 0
    i = 0
    n = len(data)
    while i < n:
        j = data.find(b"\n", i)
        if j == -1:
            j = n
        raw = data[i:j]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if raw.startswith(b" ") and cur is not None:
            cur += raw[1:]
        else:
            if cur is not None:
                out.append((cur, start, pend))
            cur = raw
            start = i
        pend = j + 1 if j < n else n
        i = pend
    if cur is not None:
        out.append((cur, start, pend))
    return out


def parse_manifest(data: bytes) -> Tuple[Dict[bytes, bytes], List[ManifestSection]]:
    """
    Parse a MANIFEST.MF / .SF file into main attributes and sections.

    ``section_bytes`` runs from the first byte of the "Name:" line through
    the end of the terminating blank line (this is the byte range that is
    digested by the .SF file).
    """
    main_attrs: Dict[bytes, bytes] = {}
    sections: List[ManifestSection] = []
    cur_lines: List[bytes] = []
    cur_start = cur_end = 0
    blank_end: Optional[int] = None

    def flush() -> None:
        nonlocal cur_lines, cur_start, cur_end, blank_end
        if not cur_lines:
            return
        attrs: Dict[bytes, bytes] = {}
        for ln in cur_lines:
            key, sep, value = ln.partition(b":")
            if sep:
                attrs[key.strip()] = value.strip()
        if attrs.get(b"Manifest-Version") or attrs.get(b"Signature-Version"):
            # main section has no Name attribute
            main_attrs.update(attrs)
        else:
            name = attrs.get(b"Name", b"").decode("utf-8")
            end = blank_end if blank_end is not None else cur_end
            sections.append(ManifestSection(name, attrs, data[cur_start:end]))
        cur_lines = []
        cur_start = cur_end = 0
        blank_end = None

    for ln, s, e in logical_lines(data):
        if ln == b"":
            if cur_lines:
                blank_end = e
                flush()
        else:
            if not cur_lines:
                cur_start = s
            cur_lines.append(ln)
            cur_end = e
    blank_end = None
    flush()
    return main_attrs, sections


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_genkey(args: argparse.Namespace) -> int:
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    key_path = os.path.join(out_dir, "rearm.key")
    crt_path = os.path.join(out_dir, "rearm.crt")
    der_path = os.path.join(out_dir, "rearm.crt.der")

    if os.path.exists(key_path) and os.path.exists(crt_path):
        print("[=] %s already exists -- keeping existing key (idempotent)" % key_path)
    else:
        print("[+] generating RSA-4096 self-signed certificate (25 years, SHA-256)")
        proc = run_openssl(args.openssl, [
            "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "9125",
            "-nodes", "-subj", "/O=rearm/CN=rearm",
            "-keyout", key_path, "-out", crt_path])
        if proc.returncode != 0:
            raise ToolError("openssl req failed: %s"
                            % proc.stderr.decode("utf-8", "replace"))
        os.chmod(key_path, 0o600)
        print("[+] wrote %s (private key, 0600)" % key_path)
        print("[+] wrote %s (certificate, PEM)" % crt_path)

    if not os.path.exists(der_path):
        proc = run_openssl(args.openssl, ["x509", "-in", crt_path,
                                          "-outform", "DER", "-out", der_path])
        if proc.returncode != 0:
            raise ToolError("openssl x509 (DER) failed: %s"
                            % proc.stderr.decode("utf-8", "replace"))
        print("[+] wrote %s (certificate, DER)" % der_path)
    else:
        print("[=] %s already exists" % der_path)

    ok, msg = openssl_ok(args.openssl, ["x509", "-in", crt_path, "-noout",
                                        "-subject", "-fingerprint", "-sha256"])
    if ok:
        print("[i] %s" % msg.replace("\n", " | "))
    return 0


def cmd_repack(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.in_apk):
        raise ToolError("input APK not found: %s" % args.in_apk)
    if not os.path.isdir(args.lib_dir):
        raise ToolError("lib dir not found: %s" % args.lib_dir)

    so_files = sorted(f for f in os.listdir(args.lib_dir)
                      if f.endswith(".so")
                      and os.path.isfile(os.path.join(args.lib_dir, f)))
    if not so_files:
        print("[!] warning: no *.so files found in %s" % args.lib_dir)

    entries = read_apk_entries(args.in_apk)
    kept: List[ZipEntry] = []
    dropped_lib = dropped_sig = 0
    for entry in entries:
        if any(entry.name.startswith(p) for p in DROP_LIB_PREFIXES):
            dropped_lib += 1
            continue
        if is_signature_file(entry.name):
            dropped_sig += 1
            continue
        kept.append(entry)

    added = 0
    for so in so_files:
        path = os.path.join(args.lib_dir, so)
        with open(path, "rb") as f:
            data = f.read()
        st = os.stat(path)
        kept.append(ZipEntry(
            name="lib/arm64-v8a/" + so,
            data=data,
            method=METHOD_STORED,
            align=SO_ALIGN,
            date_time=time.localtime(st.st_mtime)[:6],
            external_attr=0o100644 << 16))
        added += 1

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    tmp_out = args.out + ".tmp"
    info = ZipWriter(kept).write(tmp_out)
    os.replace(tmp_out, args.out)

    print("[+] repacked %s -> %s" % (args.in_apk, args.out))
    print("[i] input entries: %d | dropped native libs: %d | dropped signature files: %d"
          % (len(entries), dropped_lib, dropped_sig))
    print("[i] kept entries: %d | added arm64-v8a libs: %d | output entries: %d"
          % (len(kept) - added, added, info["entries"]))
    print("[i] output size: %d bytes" % os.path.getsize(args.out))
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    apk = args.apk
    if not os.path.isfile(apk):
        raise ToolError("APK not found: %s" % apk)
    key_path = os.path.join(args.key_dir, "rearm.key")
    crt_path = os.path.join(args.key_dir, "rearm.crt")
    if not os.path.isfile(key_path) or not os.path.isfile(crt_path):
        raise ToolError("rearm.key/rearm.crt not found in %s (run genkey first)"
                        % args.key_dir)
    cert_der = cert_der_of(args.openssl, args.key_dir)
    spki_der = spki_of_cert(args.openssl, crt_path)

    entries = read_apk_entries(apk)
    had_sig = sum(1 for e in entries if is_signature_file(e.name))
    entries = [e for e in entries if not is_signature_file(e.name)]

    digestable = [e for e in entries if is_jar_digest_entry(e.name)]
    print("[i] signing %d files with v1 (JAR/SHA-256)" % len(digestable))

    manifest, sections = build_manifest(digestable)
    sf = build_signature_file(manifest, sections)
    cert_rsa = cms_sign(args.openssl, sf, key_path, crt_path)

    now = time.localtime()
    date_time = (now.tm_year, now.tm_mon, now.tm_mday,
                 now.tm_hour, now.tm_min, now.tm_sec)
    meta_attr = 0o100644 << 16
    entries.append(ZipEntry("META-INF/MANIFEST.MF", manifest, METHOD_DEFLATED,
                            1, date_time, meta_attr))
    entries.append(ZipEntry("META-INF/CERT.SF", sf, METHOD_DEFLATED,
                            1, date_time, meta_attr))
    entries.append(ZipEntry("META-INF/CERT.RSA", cert_rsa, METHOD_DEFLATED,
                            1, date_time, meta_attr))

    with tempfile.TemporaryDirectory() as td:
        unsigned = os.path.join(td, "unsigned.apk")
        ZipWriter(entries).write(unsigned)
        with open(unsigned, "rb") as f:
            data = f.read()

        found = find_signing_block(data)
        block_start = found[0] if found is not None else locate_eocd(data)[2]
        block, digest = build_v2_block(args.openssl, key_path, cert_der,
                                      spki_der, data, block_start)
        final = apply_v2_block(data, block, found[0] if found else None)

        out = args.out or apk
        tmp_out = out + ".tmp"
        with open(tmp_out, "wb") as f:
            f.write(final)
        os.replace(tmp_out, out)

    print("[+] v1: MANIFEST.MF (%d entries), CERT.SF, CERT.RSA (%d-byte CMS)"
          % (len(sections), len(cert_rsa)))
    print("[+] v2: signing block inserted (%d bytes, %s%% 4096, alg 0x%04x, "
          "digest %s...)"
          % (len(block), "multiple-of" if len(block) % PAGE_ALIGN == 0 else "NOT",
             SIG_ALG_RSA_PKCS1_SHA256, digest.hex()[:16]))
    if had_sig:
        print("[i] replaced %d pre-existing signature file(s)" % had_sig)
    print("[+] signed %s" % (args.out or apk + " (in place)"))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.apk):
        raise ToolError("APK not found: %s" % args.apk)
    openssl = args.openssl
    with open(args.apk, "rb") as f:
        data = f.read()

    zip_err: Optional[str] = None
    entries: List[ZipEntry] = []
    try:
        entries = read_apk_entries(args.apk)
    except (ToolError, zipfile.BadZipFile, zlib.error) as exc:
        zip_err = "%s: %s" % (type(exc).__name__, exc)
    files = [e for e in entries if is_jar_digest_entry(e.name)]
    by_name = {e.name: e for e in entries}
    if zip_err is None:
        print("[i] %s: %d entries (%d content files to digest)"
              % (args.apk, len(entries), len(files)))
    else:
        print("[i] %s: zip is UNREADABLE (%s) -- v1 cannot be checked" % (args.apk, zip_err))

    expect_cert: Optional[bytes] = None
    if args.expect_key_dir:
        der_path = os.path.join(args.expect_key_dir, "rearm.crt.der")
        if not os.path.isfile(der_path):
            raise ToolError("rearm.crt.der not found in %s" % args.expect_key_dir)
        with open(der_path, "rb") as f:
            expect_cert = f.read()

    all_ok = True

    # ---------------- v1 ----------------
    v1_ok = True
    if zip_err is not None:
        print("[-] v1: FAIL (zip unreadable: %s)" % zip_err)
        v1_ok = all_ok = False
    else:
        try:
            manifest = by_name["META-INF/MANIFEST.MF"].data
            sf = by_name["META-INF/CERT.SF"].data
            cert_rsa = by_name["META-INF/CERT.RSA"].data
        except KeyError as exc:
            print("[-] v1: FAIL (missing %s)" % exc)
            v1_ok = all_ok = False
        else:
            _, msections = parse_manifest(manifest)
            mby_name = {s.name: s for s in msections}
            bad_digest = missing = 0
            for e in files:
                sec = mby_name.get(e.name)
                if sec is None or b"SHA-256-Digest" not in sec.attrs:
                    missing += 1
                    continue
                if b64(sha256(e.data)) != sec.attrs[b"SHA-256-Digest"]:
                    bad_digest += 1
            if bad_digest or missing:
                print("[-] v1: MANIFEST.MF FAIL (%d bad digests, %d files without "
                      "a section)" % (bad_digest, missing))
                v1_ok = all_ok = False
            else:
                print("[+] v1: MANIFEST.MF PASS (%d file digests recomputed)"
                      % len(files))

            sf_main, sf_sections = parse_manifest(sf)
            sf_by_name = {s.name: s for s in sf_sections}
            exp = sf_main.get(b"SHA-256-Digest-Manifest")
            if exp is not None and b64(sha256(manifest)) == exp:
                print("[+] v1: CERT.SF SHA-256-Digest-Manifest PASS")
            else:
                print("[-] v1: CERT.SF SHA-256-Digest-Manifest FAIL")
                v1_ok = all_ok = False
            bad_sf = sf_missing = 0
            for s in msections:
                sfs = sf_by_name.get(s.name)
                if sfs is None or b"SHA-256-Digest" not in sfs.attrs:
                    sf_missing += 1
                    continue
                if b64(sha256(s.section_bytes)) != sfs.attrs[b"SHA-256-Digest"]:
                    bad_sf += 1
            if bad_sf or sf_missing:
                print("[-] v1: CERT.SF per-section digests FAIL (%d bad, %d missing)"
                      % (bad_sf, sf_missing))
                v1_ok = all_ok = False
            else:
                print("[+] v1: CERT.SF per-section digests PASS (%d sections)"
                      % len(msections))

            ok, msg = cms_verify(openssl, cert_rsa, sf)
            if ok:
                print("[+] v1: CERT.RSA PKCS#7 signature over CERT.SF PASS (openssl)")
            else:
                print("[-] v1: CERT.RSA PKCS#7 verification FAIL: %s" % msg)
                v1_ok = all_ok = False

            if expect_cert is not None:
                ok, msg = _cms_signer_matches(openssl, cert_rsa, expect_cert)
                if ok:
                    print("[+] v1: signer certificate matches %s" %
                          os.path.join(args.expect_key_dir, "rearm.crt"))
                else:
                    print("[-] v1: signer certificate does NOT match expected key: %s"
                          % msg)
                    v1_ok = all_ok = False

    # ---------------- v2 ----------------
    v2_ok = True
    try:
        block_start, block_size, signer = parse_v2_block(data)
    except ToolError as exc:
        print("[-] v2: FAIL (%s)" % exc)
        v2_ok = all_ok = False
    else:
        _, _, cd_off = locate_eocd(data)
        if cd_off != block_start + 8 + block_size:
            print("[-] v2: EOCD central-directory offset inconsistent with block")
            v2_ok = all_ok = False
        if signer.digest_alg_id != SIG_ALG_RSA_PKCS1_SHA256 \
                or signer.sig_alg_id != SIG_ALG_RSA_PKCS1_SHA256:
            print("[-] v2: unexpected algorithm id(s): digest 0x%04x sig 0x%04x"
                  % (signer.digest_alg_id, signer.sig_alg_id))
            v2_ok = all_ok = False

        calc, nchunks = compute_content_digest(data, block_start)
        if calc == signer.digest:
            print("[+] v2: content digest PASS (%d chunks, %d bytes)"
                  % (nchunks, len(data)))
        else:
            print("[-] v2: content digest FAIL (recomputed %s, stored %s)"
                  % (calc.hex()[:16], signer.digest.hex()[:16]))
            v2_ok = all_ok = False

        # the signer certificate embedded in the signed data must carry the
        # same public key as the signer record (apksig does the same check)
        ok, msg = _spki_matches(openssl, signer.cert_der, signer.spki)
        if ok:
            print("[+] v2: certificate in signed data matches signer public key")
        else:
            print("[-] v2: certificate/public key mismatch: %s" % msg)
            v2_ok = all_ok = False

        ok, msg = rsa_verify(openssl, signer.spki, signer.signed_data,
                             signer.signature)
        if ok:
            print("[+] v2: RSA signature over signed data PASS (openssl, %d bytes)"
                  % len(signer.signature))
        else:
            print("[-] v2: RSA signature verification FAIL: %s" % msg)
            v2_ok = all_ok = False

        if expect_cert is not None:
            ok, msg = _spki_matches(openssl, expect_cert, signer.spki)
            if ok:
                print("[+] v2: embedded public key matches %s" %
                      os.path.join(args.expect_key_dir, "rearm.crt"))
            else:
                print("[-] v2: embedded public key does NOT match expected key")
                v2_ok = all_ok = False

    print("RESULT: v1 %s | v2 %s" % ("PASS" if v1_ok else "FAIL",
                                     "PASS" if v2_ok else "FAIL"))
    return 0 if all_ok else 1


def _cms_signer_matches(openssl: str, cert_rsa: bytes,
                        expect_der: bytes) -> Tuple[bool, str]:
    """Check that the CMS contains the expected certificate (DER-compare)."""
    proc = run_openssl(openssl, ["pkcs7", "-inform", "DER", "-print_certs"],
                       input_bytes=cert_rsa)
    if proc.returncode != 0:
        return False, "openssl pkcs7 failed"
    pem = proc.stdout
    with tempfile.TemporaryDirectory() as td:
        pem_path = os.path.join(td, "c.pem")
        with open(pem_path, "wb") as f:
            f.write(pem)
        proc = run_openssl(openssl, ["x509", "-in", pem_path, "-outform", "DER"])
        if proc.returncode != 0:
            return False, "no certificate in CMS"
        if proc.stdout == expect_der:
            return True, ""
        return False, "different signer certificate"


def _spki_matches(openssl: str, cert_der: bytes, spki: bytes) -> Tuple[bool, str]:
    """Compare an embedded v2 SPKI with the SPKI of a DER certificate."""
    proc = run_openssl(openssl, ["x509", "-inform", "DER", "-pubkey", "-noout"],
                       input_bytes=cert_der)
    if proc.returncode != 0:
        return False, "openssl x509 failed"
    proc2 = run_openssl(openssl, ["pkey", "-pubin", "-outform", "DER"],
                        input_bytes=proc.stdout)
    if proc2.returncode != 0:
        return False, "openssl pkey failed"
    return proc2.stdout == spki, ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apk_tool.py",
        description="Repack and sign Android APKs (v1 + v2 schemes).")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("genkey", help="generate persistent RSA-4096 signing key")
    p.add_argument("--out", required=True, metavar="DIR",
                   help="directory for rearm.key / rearm.crt / rearm.crt.der")
    p.add_argument("--openssl", default=OPENSSL, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_genkey)

    p = sub.add_parser("repack", help="rebuild APK with arm64-v8a libraries")
    p.add_argument("--in-apk", required=True, metavar="APK")
    p.add_argument("--lib-dir", required=True, metavar="DIR",
                   help="directory containing *.so files to add as "
                        "lib/arm64-v8a/")
    p.add_argument("--out", required=True, metavar="APK")
    p.set_defaults(func=cmd_repack)

    p = sub.add_parser("sign", help="apply v1 + v2 signatures (in place by default)")
    p.add_argument("--apk", required=True, metavar="APK")
    p.add_argument("--key-dir", required=True, metavar="DIR",
                   help="directory containing rearm.key and rearm.crt")
    p.add_argument("--out", metavar="APK",
                   help="output path (default: sign in place)")
    p.add_argument("--openssl", default=OPENSSL, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="self-verify signatures of an APK")
    p.add_argument("--apk", required=True, metavar="APK")
    p.add_argument("--expect-key-dir", metavar="DIR",
                   help="also check that the signer matches rearm.crt in DIR")
    p.add_argument("--openssl", default=OPENSSL, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_verify)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ToolError as exc:
        print("[!] error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

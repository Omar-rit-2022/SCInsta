#!/usr/bin/env python3
"""Make a sideload IPA's binaries acceptable to AltStore's signer.

AltStore signs on-device with AltSign, which bundles an older ldid. Its
Allocate() asserts that the symbol string table ends right where the code
signature starts (within 0x10 bytes):

    ldid.cpp(1461): _assert(): end >= size - 0x10

When a binary is re-signed by appending a new signature after the old one
instead of replacing it, the stale App Store signature is left in between
and AltStore refuses to install the IPA.

For every Mach-O slice that fails that check, this script removes the
unreferenced bytes between the string table and the current signature,
moves the current signature down into place, and updates LC_CODE_SIGNATURE
and the __LINKEDIT segment to match. Slices where anything the load
commands reference lives in that gap are left alone and reported.

Usage: fix_altstore_layout.py input.ipa [-o output.ipa]
       (without -o the IPA is rewritten in place)
"""
import argparse
import os
import shutil
import struct
import sys
import tempfile
import zipfile

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_NOTE = 0x31
LINKEDIT_DATA = {0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x36, 0x37, 0x38, 0x80000033, 0x80000034}


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def is_macho(head):
    if len(head) < 4:
        return False
    return (struct.unpack(">I", head[:4])[0] in (FAT_MAGIC, FAT_MAGIC_64)
            or struct.unpack("<I", head[:4])[0] in (MH_MAGIC, MH_MAGIC_64))


def parse(buf):
    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic not in (MH_MAGIC, MH_MAGIC_64):
        return None
    is64 = magic == MH_MAGIC_64
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    p = 32 if is64 else 28
    info = {"is64": is64, "blobs": [], "segments": []}
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, p)
        if cmd == LC_SEGMENT_64:
            name = buf[p + 8:p + 24].rstrip(b"\0")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", buf, p + 24)
            info["segments"].append({"name": name, "p": p, "is64": True, "vmaddr": vmaddr,
                                     "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize})
        elif cmd == LC_SEGMENT:
            name = buf[p + 8:p + 24].rstrip(b"\0")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<IIII", buf, p + 24)
            info["segments"].append({"name": name, "p": p, "is64": False, "vmaddr": vmaddr,
                                     "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize})
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", buf, p + 8)
            info["symtab"] = (stroff, strsize)
            info["blobs"].append((symoff, nsyms * (16 if is64 else 12)))
        elif cmd == LC_DYSYMTAB:
            f = struct.unpack_from("<18I", buf, p + 8)
            info["blobs"] += [(f[6], f[7] * 8), (f[8], f[9] * (56 if is64 else 52)),
                              (f[10], f[11] * 4), (f[12], f[13] * 4),
                              (f[14], f[15] * 8), (f[16], f[17] * 8)]
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            f = struct.unpack_from("<10I", buf, p + 8)
            info["blobs"] += [(f[i], f[i + 1]) for i in range(0, 10, 2)]
        elif cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from("<II", buf, p + 8)
            info["sig"] = {"p": p, "dataoff": dataoff, "datasize": datasize}
        elif cmd in LINKEDIT_DATA:
            info["blobs"].append(struct.unpack_from("<II", buf, p + 8))
        elif cmd == LC_NOTE:
            offset, size = struct.unpack_from("<QQ", buf, p + 24)
            info["blobs"].append((offset, size))
        p += cmdsize
    info["blobs"] = [b for b in info["blobs"] if b[1] > 0]
    return info


def fix_slice(buf, label):
    """Return a fixed copy of a thin Mach-O, or None if nothing to do."""
    info = parse(buf)
    if not info or "symtab" not in info:
        return None
    stroff, strsize = info["symtab"]
    if stroff == 0 and strsize == 0:
        return None
    sig = info.get("sig")
    limit = sig["dataoff"] if sig else len(buf)
    end = stroff + strsize
    if end <= limit and end >= limit - 0x10:
        return None
    if end > limit:
        print(f"  ! {label}: string table runs past the signature, leaving it alone")
        return None
    in_gap = [b for b in info["blobs"] if b[0] < limit and b[0] + b[1] > end]
    if in_gap:
        print(f"  ! {label}: referenced data sits in the gap, leaving it alone")
        return None

    new_off = align(end, 0x10)
    out = bytearray(buf[:new_off])
    out[end:new_off] = b"\0" * (new_off - end)
    if sig:
        sig_end = sig["dataoff"] + sig["datasize"]
        out += buf[sig["dataoff"]:sig_end]
        struct.pack_into("<I", out, sig["p"] + 8, new_off)
        removed = sig["dataoff"] - new_off
    else:
        removed = len(buf) - new_off

    for seg in info["segments"]:
        if seg["name"] != b"__LINKEDIT":
            if seg["fileoff"] + seg["filesize"] > len(out):
                print(f"  ! {label}: segment {seg['name'].decode()} would be cut, leaving it alone")
                return None
            continue
        filesize = len(out) - seg["fileoff"]
        vmsize = max(seg["vmsize"], align(filesize, 0x4000))
        if seg["is64"]:
            struct.pack_into("<QQ", out, seg["p"] + 32, vmsize, seg["fileoff"])
            struct.pack_into("<Q", out, seg["p"] + 48, filesize)
        else:
            struct.pack_into("<II", out, seg["p"] + 28, vmsize, seg["fileoff"])
            struct.pack_into("<I", out, seg["p"] + 36, filesize)

    print(f"  fixed {label}: removed {removed} stale bytes before the signature")
    return bytes(out)


def fix_binary(data, label):
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return fix_slice(data, label)

    is64 = magic == FAT_MAGIC_64
    n = struct.unpack_from(">I", data, 4)[0]
    entry = 32 if is64 else 20
    archs = []
    for i in range(n):
        if is64:
            cpu, sub, off, size, algn, res = struct.unpack_from(">iiQQII", data, 8 + i * entry)
        else:
            cpu, sub, off, size, algn = struct.unpack_from(">iiIII", data, 8 + i * entry)
            res = 0
        archs.append([cpu, sub, off, size, algn, res])

    changed = False
    bodies = []
    for a in archs:
        body = data[a[2]:a[2] + a[3]]
        fixed = fix_slice(body, f"{label} (cpu {a[0]})")
        if fixed is not None:
            changed = True
            body = fixed
        bodies.append(body)
    if not changed:
        return None

    out = bytearray(data[:8 + n * entry])
    for a, body in zip(archs, bodies):
        start = align(len(out), 1 << a[4])
        out += b"\0" * (start - len(out))
        a[2], a[3] = start, len(body)
        out += body
    for i, a in enumerate(archs):
        if is64:
            struct.pack_into(">iiQQII", out, 8 + i * entry, *a)
        else:
            struct.pack_into(">iiIII", out, 8 + i * entry, *a[:5])
    return bytes(out)


def fix_ipa(src, dst):
    fixed_count = 0
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".ipa", dir=os.path.dirname(os.path.abspath(dst)))
    os.close(tmp_fd)
    try:
        with zipfile.ZipFile(src) as zin, \
                zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zout:
            for item in zin.infolist():
                data = zin.read(item)
                is_link = (item.external_attr >> 16) & 0o170000 == 0o120000
                if not item.is_dir() and not is_link and len(data) > 4096 and is_macho(data[:4]):
                    fixed = fix_binary(data, item.filename)
                    if fixed is not None:
                        data = fixed
                        fixed_count += 1
                zout.writestr(item, data, compress_type=item.compress_type)
        shutil.move(tmp_path, dst)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return fixed_count


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ipa")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    dst = args.output or args.ipa
    print(f"Checking {args.ipa} for binaries AltStore can't sign")
    count = fix_ipa(args.ipa, dst)
    print(f"Done: {count} binar{'y' if count == 1 else 'ies'} fixed, wrote {dst}")


if __name__ == "__main__":
    sys.exit(main())

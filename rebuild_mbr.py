"""
rebuild_mbr.py -- Rebuild a destroyed MBR partition table from surviving
NTFS structures, so Windows can finally see the volumes.

WHY THIS IS NEEDED
    Repairing a volume's NTFS boot sector is not enough. Sector 0 of the
    disk holds the partition table, and it was inside the 520 MiB that the
    ransomware overwrote. Without it Windows reports the whole disk as
    "unallocated" even though every byte of the filesystem is intact.

    This tool finds the real partitions by reading the NTFS backup boot
    sectors that survived at the end of each partition, works out the exact
    layout, and writes a correct MBR.

SAFETY
    * dry run by default -- shows the proposed table and writes nothing
    * --apply writes ONLY sector 0 (512 bytes). No filesystem data is touched.
    * the sector it replaces is saved to <disk>.mbr.bak first
    * refuses to run on a file whose size is not a whole number of sectors

USAGE
    python rebuild_mbr.py <disk-flat.vmdk>
    python rebuild_mbr.py <disk-flat.vmdk> --apply
    python rebuild_mbr.py <disk-flat.vmdk> --apply --boot 2
"""

import os
import sys
import struct

SECTOR = 512
_B = 10 * 1024 * 1024
_w = 0
while True:
    _w += _B
    if not (_w < 0x20000000):
        break
DAMAGE = _w


def human(x):
    x = float(x)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(x) < 1024.0:
            return "%.2f %s" % (x, u)
        x /= 1024.0
    return "%.2f PiB" % x


def read_at(f, off, n):
    try:
        f.seek(off)
        return f.read(n)
    except Exception:
        return b""


def parse_bpb(sec):
    if len(sec) < 512 or sec[3:11] != b"NTFS    ":
        return None
    bps = struct.unpack_from("<H", sec, 11)[0]
    spc = sec[13] if isinstance(sec[13], int) else ord(sec[13])
    total = struct.unpack_from("<Q", sec, 40)[0]
    mft = struct.unpack_from("<Q", sec, 48)[0]
    mftmirr = struct.unpack_from("<Q", sec, 56)[0]
    serial = struct.unpack_from("<Q", sec, 72)[0]
    if bps not in (512, 1024, 2048, 4096):
        return None
    if spc not in (1, 2, 4, 8, 16, 32, 64, 128):
        return None
    if total == 0 or total > (1 << 44):
        return None
    if mft == 0 or mft > total or mftmirr == 0 or mftmirr > total:
        return None
    return dict(bps=bps, spc=spc, total=total, mft=mft, mftmirr=mftmirr,
                serial=serial, cluster=bps * spc,
                vol_bytes=(total + 1) * bps)


def mft_alive(f, part_off, bpb):
    off = part_off + bpb["mft"] * bpb["cluster"]
    good = 0
    for i in range(8):
        if read_at(f, off + i * 1024, 4) == b"FILE":
            good += 1
    return good, off


def scan_ntfs(f, data_end):
    """Find every NTFS boot sector on the disk (tail-heavy, plus post-damage)."""
    hits = []
    regions = []
    # the head, including the damaged window: a boot sector restored there by
    # an earlier repair must be seen, otherwise we would rebuild the table
    # from a stale copy instead of the live one
    regions.append((0, min(2 << 30, data_end)))
    if data_end > (2 << 30):
        regions.append((max(0, data_end - (3 << 30)), data_end))
    WINDOW = 8 * 1024 * 1024
    for start, end in regions:
        pos = start
        while pos < end:
            buf = read_at(f, pos, min(WINDOW, end - pos))
            if not buf:
                break
            idx = 0
            while True:
                j = buf.find(b"NTFS    ", idx)
                if j < 0:
                    break
                base = pos + j - 3
                if base >= 0 and base % SECTOR == 0:
                    b = parse_bpb(read_at(f, base, 512))
                    if b:
                        hits.append((base, b))
                idx = j + 1
            pos += WINDOW - 16
    seen = set()
    out = []
    for off, b in sorted(hits):
        if off in seen:
            continue
        seen.add(off)
        out.append((off, b))
    return out


def find_partitions(f, data_end):
    """Return confirmed [(start, size, bpb, how)] using live-$MFT as the test."""
    hits = scan_ntfs(f, data_end)
    found = []

    for off, b in hits:
        # case A: this sector IS the primary boot sector of a partition
        good, mft_off = mft_alive(f, off, b)
        if good >= 4:
            found.append(dict(start=off, size=b["vol_bytes"], bpb=b,
                              how="primary boot sector present",
                              mft=mft_off, records=good))
            continue

        # case B: this is a BACKUP copy sitting at the end of its partition
        implied = off - b["total"] * b["bps"]
        if implied < 0 or implied >= off:
            continue
        good2, mft_off2 = mft_alive(f, implied, b)
        if good2 >= 4:
            found.append(dict(start=implied, size=b["vol_bytes"], bpb=b,
                              how="recovered from backup boot sector at %d" % off,
                              mft=mft_off2, records=good2, backup=off))

    # Prefer, for each start offset, the SMALLEST volume size. A larger
    # variant with the same serial is a leftover from an earlier layout of
    # this disk; trusting it would overlap and hide the partition that comes
    # after it.
    found.sort(key=lambda p: (p["start"], p["size"]))
    bystart = {}
    for p in found:
        prev = bystart.get(p["start"])
        if prev is None:
            bystart[p["start"]] = p
        else:
            prev.setdefault("alternates", []).append(p["size"])
    cands = sorted(bystart.values(), key=lambda p: p["start"])

    # greedily keep non-overlapping partitions, earliest first
    clean = []
    for p in cands:
        clash = None
        for q in clean:
            if p["start"] < q["start"] + q["size"] and \
               q["start"] < p["start"] + p["size"]:
                clash = q
                break
        if clash is None:
            clean.append(p)
        else:
            p["dropped_because"] = clash["start"]
    return clean


def chs_for(lba):
    """Classic CHS triple. Anything past the limit gets the max marker."""
    if lba >= 1024 * 255 * 63:
        return b"\xfe\xff\xff"
    c = lba // (255 * 63)
    h = (lba // 63) % 255
    s = (lba % 63) + 1
    return struct.pack("<BBB", h, ((c >> 2) & 0xC0) | s, c & 0xFF)


def build_mbr(parts, boot_idx, disk_sectors, old_sig=None):
    mbr = bytearray(512)
    # keep the original disk signature if there was one, else make one up
    if old_sig and old_sig != b"\x00\x00\x00\x00":
        mbr[440:444] = old_sig
    else:
        mbr[440:444] = struct.pack("<I", 0xA1B2C3D4)

    for i, p in enumerate(parts[:4]):
        first_lba = p["start"] // SECTOR
        count = p["size"] // SECTOR
        if first_lba + count > disk_sectors:
            count = disk_sectors - first_lba
        e = bytearray(16)
        e[0] = 0x80 if (i + 1) == boot_idx else 0x00
        e[1:4] = chs_for(first_lba)
        e[4] = 0x07                       # NTFS / exFAT
        e[5:8] = chs_for(first_lba + count - 1)
        struct.pack_into("<I", e, 8, first_lba)
        struct.pack_into("<I", e, 12, count)
        mbr[446 + i * 16: 462 + i * 16] = bytes(e)

    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return
    apply = "--apply" in a
    boot_idx = 1
    if "--boot" in a:
        i = a.index("--boot")
        if i + 1 < len(a):
            boot_idx = int(a[i + 1])
    pos = [x for x in a if not x.startswith("--")]
    pos = [x for x in pos if x != str(boot_idx)]
    if not pos:
        print(__doc__)
        return
    path = pos[0]

    size = os.path.getsize(path)
    print("=" * 70)
    print("MBR REBUILD")
    print("=" * 70)
    print("")
    print("disk : %s" % path)
    print("size : %d (%s)" % (size, human(size)))

    if size % SECTOR:
        print("")
        print("REFUSING: size is not a whole number of 512-byte sectors.")
        print("There are %d leftover byte(s) - ransomware trailers." % (size % SECTOR))
        print("Strip them first, then run this again.")
        return

    disk_sectors = size // SECTOR
    f = open(path, "rb")
    try:
        old = read_at(f, 0, 512)
        old_sig = old[440:444] if len(old) >= 444 else None
        has_mbr = len(old) >= 512 and old[510:512] == b"\x55\xaa"
        print("current sector 0 : %s" %
              ("has a 55AA signature" if has_mbr else "no valid MBR signature"))
        print("")
        print("scanning for surviving NTFS structures ...")
        parts = find_partitions(f, size)
    finally:
        f.close()

    if not parts:
        print("")
        print("No partitions with a live $MFT were found.")
        print("Nothing safe to write. Use carving instead.")
        return

    print("")
    print("-" * 70)
    print("PARTITIONS FOUND (each one verified by reading its $MFT)")
    print("-" * 70)
    for i, p in enumerate(parts, 1):
        print("")
        print("  [%d] start %d  (%s)" % (i, p["start"], human(p["start"])))
        print("      size        : %s" % human(p["size"]))
        print("      ends at     : %d (%s)"
              % (p["start"] + p["size"], human(p["start"] + p["size"])))
        print("      serial      : %016x" % p["bpb"]["serial"])
        print("      cluster     : %d" % p["bpb"]["cluster"])
        print("      $MFT        : %d (%s)  %d of 8 records valid"
              % (p["mft"], human(p["mft"]), p["records"]))
        print("      how found   : %s" % p["how"])

    if len(parts) > 4:
        print("")
        print("NOTE: MBR holds only 4 entries; the first 4 will be written.")

    print("")
    print("-" * 70)
    print("PROPOSED MBR")
    print("-" * 70)
    print("")
    print("  %-4s %-14s %-14s %-12s %s"
          % ("#", "first LBA", "sectors", "size", "boot"))
    for i, p in enumerate(parts[:4], 1):
        print("  %-4d %-14d %-14d %-12s %s"
              % (i, p["start"] // SECTOR, p["size"] // SECTOR,
                 human(p["size"]), "YES" if i == boot_idx else ""))
    print("")
    print("  partition type for all entries : 0x07 (NTFS)")
    print("  active/boot flag on entry      : %d" % boot_idx)

    gap = parts[0]["start"]
    if gap > 1024 * 1024:
        print("")
        print("  NOTE: %s before the first partition is not covered by any"
              % human(gap))
        print("  entry. On a Windows disk that space held System Reserved,")
        print("  which lives entirely inside the destroyed 520 MiB. Its")
        print("  boot files (BCD, bootmgr) are gone, so this disk will not")
        print("  boot on its own. Attach it as a SECOND disk to a working")
        print("  VM to read the data, or rebuild the boot files afterwards.")

    if not apply:
        print("")
        print("Dry run. Nothing was written.")
        print("Re-run with --apply to write sector 0.")
        print("=" * 70)
        return

    mbr = build_mbr(parts, boot_idx, disk_sectors, old_sig)

    bak = path + ".mbr.bak"
    g = open(bak, "wb")
    g.write(old)
    g.close()
    print("")
    print("saved old sector 0 to %s" % os.path.basename(bak))

    f = open(path, "r+b")
    try:
        f.seek(0)
        f.write(mbr)
    finally:
        f.close()
    print("wrote new MBR (512 bytes at offset 0)")
    print("")
    print("No filesystem data was modified.")
    print("")
    print("Next: attach this disk to a VM. Windows Disk Management should")
    print("now show the partition(s). If a volume shows as RAW, run")
    print("  chkdsk <letter>: /f")
    print("=" * 70)


main()

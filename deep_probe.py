"""
deep_probe.py -- READ ONLY forensic profile of a Babuk-damaged VMDK.

Writes NOTHING. Ever. Safe to run on live/attached disks.

What it does that the wizard did not:
  * measures the REAL damage boundary by entropy, instead of assuming it
  * scans the WHOLE disk for filesystem signatures, not just the tail
  * for every NTFS candidate it actually READS $MFT record 0 and checks
    for the 'FILE' magic -- this is the only true test of whether a
    volume can be mounted
  * detects Linux structures too (ext2/3/4, XFS, LVM2, swap)
  * reads any partition table that currently exists (MBR and GPT)

Usage:
    python deep_probe.py <disk.vmdk or .babyk>            one disk
    python deep_probe.py --all /vmfs/volumes              every disk found
    python deep_probe.py <disk> --full                    full-disk sig scan
                                                          (slow, thorough)
"""

import os
import sys
import struct
import math

SECTOR = 512
_BLOCK = 10 * 1024 * 1024
_w = 0
while True:
    _w += _BLOCK
    if not (_w < 0x20000000):
        break
NOMINAL_DAMAGE = _w          # 545,259,520


def human(x):
    x = float(x)
    for u in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(x) < 1024.0:
            return "%.2f %s" % (x, u)
        x /= 1024.0
    return "%.2f EiB" % x


def entropy(buf):
    if not buf:
        return 0.0
    counts = {}
    for b in buf:
        if not isinstance(b, int):
            b = ord(b)
        counts[b] = counts.get(b, 0) + 1
    n = float(len(buf))
    e = 0.0
    for v in counts.values():
        p = v / n
        e -= p * math.log(p, 2)
    return e


def read_at(f, off, n):
    try:
        f.seek(off)
        return f.read(n)
    except Exception:
        return b""


# ------------------------------------------------------------------ NTFS

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


def check_mft(f, part_off, bpb, damage_end):
    """THE decisive test: does $MFT actually contain valid FILE records?"""
    cl = bpb["cluster"]
    mft_off = part_off + bpb["mft"] * cl
    mirr_off = part_off + bpb["mftmirr"] * cl

    out = dict(mft_off=mft_off, mirr_off=mirr_off)

    rec = read_at(f, mft_off, 1024)
    out["mft_magic"] = rec[0:4] if len(rec) >= 4 else b""
    out["mft_ok"] = (out["mft_magic"] == b"FILE")

    rec2 = read_at(f, mirr_off, 1024)
    out["mirr_magic"] = rec2[0:4] if len(rec2) >= 4 else b""
    out["mirr_ok"] = (out["mirr_magic"] == b"FILE")

    out["mft_in_damage"] = mft_off < damage_end
    out["mirr_in_damage"] = mirr_off < damage_end

    # try to read a handful of records to be sure it is a real table
    good = 0
    for i in range(8):
        r = read_at(f, mft_off + i * 1024, 4)
        if r == b"FILE":
            good += 1
    out["records_found"] = good
    return out


# ------------------------------------------------- other filesystem probes

def probe_ext(f, off):
    """ext2/3/4 superblock lives 1024 bytes into the partition."""
    sb = read_at(f, off + 1024, 1024)
    if len(sb) < 264:
        return None
    magic = struct.unpack_from("<H", sb, 56)[0]
    if magic != 0xEF53:
        return None
    log_bs = struct.unpack_from("<I", sb, 24)[0]
    if log_bs > 6:
        return None
    blocks = struct.unpack_from("<I", sb, 4)[0]
    bsize = 1024 << log_bs
    name = sb[120:136].rstrip(b"\x00").decode("ascii", "ignore")
    return dict(block_size=bsize, blocks=blocks,
                size=blocks * bsize, label=name)


def probe_xfs(f, off):
    sb = read_at(f, off, 512)
    if len(sb) < 128 or sb[0:4] != b"XFSB":
        return None
    bsize = struct.unpack_from(">I", sb, 4)[0]
    blocks = struct.unpack_from(">Q", sb, 8)[0]
    if bsize == 0 or bsize > (1 << 20):
        return None
    return dict(block_size=bsize, blocks=blocks, size=blocks * bsize)


def probe_lvm(f, off):
    """LVM2 puts LABELONE in one of the first 4 sectors."""
    for s in range(4):
        sec = read_at(f, off + s * SECTOR, SECTOR)
        if len(sec) >= 8 and sec[0:8] == b"LABELONE":
            return dict(label_sector=s)
    return None


def probe_swap(f, off):
    sec = read_at(f, off + 4086, 10)
    if sec[:10] in (b"SWAPSPACE2", b"SWAP-SPACE"):
        return dict(kind=sec[:10].decode("ascii", "ignore"))
    return None


# ------------------------------------------------------- partition tables

def read_mbr(f):
    mbr = read_at(f, 0, 512)
    if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
        return None
    parts = []
    for i in range(4):
        e = mbr[446 + i * 16: 462 + i * 16]
        ptype = e[4] if isinstance(e[4], int) else ord(e[4])
        if ptype == 0:
            continue
        first = struct.unpack_from("<I", e, 8)[0]
        count = struct.unpack_from("<I", e, 12)[0]
        if first == 0 or count == 0:
            continue
        parts.append(dict(idx=i + 1, type=ptype,
                          off=first * SECTOR, size=count * SECTOR))
    return parts


def read_gpt(f, data_end, where):
    """where = 'primary' or 'backup'"""
    if where == "primary":
        hdr_off = SECTOR
    else:
        hdr_off = data_end - SECTOR
    b = read_at(f, hdr_off, SECTOR)
    if len(b) < 92 or b[0:8] != b"EFI PART":
        return None
    entries_lba = struct.unpack_from("<Q", b, 72)[0]
    num = struct.unpack_from("<I", b, 80)[0]
    esz = struct.unpack_from("<I", b, 84)[0]
    if num == 0 or num > 512 or esz < 128 or esz > 1024:
        return None
    arr_off = entries_lba * SECTOR
    if not (0 < arr_off and arr_off + num * esz <= data_end):
        arr_off = hdr_off - num * esz
    arr = read_at(f, arr_off, num * esz)
    parts = []
    for i in range(num):
        e = arr[i * esz:(i + 1) * esz]
        if len(e) < 128 or e[0:16] == b"\x00" * 16:
            continue
        first = struct.unpack_from("<Q", e, 32)[0]
        last = struct.unpack_from("<Q", e, 40)[0]
        name = e[56:128].decode("utf-16-le", "ignore").rstrip("\x00")
        parts.append(dict(idx=i + 1, off=first * SECTOR,
                          size=(last - first + 1) * SECTOR, name=name))
    return parts


# ------------------------------------------------------------ entropy map

def find_real_boundary(f, data_end):
    """Locate where random (encrypted) data stops, by entropy."""
    lo = 0
    hi = min(NOMINAL_DAMAGE * 2, data_end)
    step = 2 * 1024 * 1024
    last_enc = -1
    first_clean = -1
    off = 0
    while off < hi:
        buf = read_at(f, off, 65536)
        if not buf:
            break
        e = entropy(buf)
        zr = buf.count(0) / float(len(buf))
        if e > 7.9 and zr < 0.02:
            last_enc = off
        elif last_enc >= 0 and first_clean < 0:
            first_clean = off
        off += step
    return last_enc, first_clean


def entropy_profile(f, data_end):
    pts = []
    marks = [0, 1 << 20, 64 << 20, 256 << 20,
             NOMINAL_DAMAGE - (2 << 20),
             NOMINAL_DAMAGE - 65536,
             NOMINAL_DAMAGE,
             NOMINAL_DAMAGE + (2 << 20),
             NOMINAL_DAMAGE + (64 << 20)]
    if data_end > (4 << 30):
        marks.append(data_end // 4)
        marks.append(data_end // 2)
    marks.append(max(0, data_end - (64 << 20)))
    marks.append(max(0, data_end - 65536))
    for off in sorted(set(m for m in marks if 0 <= m < data_end)):
        buf = read_at(f, off, 65536)
        if not buf:
            continue
        e = entropy(buf)
        zr = 100.0 * buf.count(0) / len(buf)
        if zr > 99.0:
            tag = "ZERO/SPARSE"
        elif e > 7.9:
            tag = "ENCRYPTED"
        elif e < 1.0:
            tag = "mostly zero"
        else:
            tag = "REAL DATA"
        pts.append((off, e, zr, tag))
    return pts


# --------------------------------------------------------- signature scan

SIGNATURES = [
    ("NTFS", b"NTFS    ", -3),
    ("ext",  b"\x53\xef", -1080),     # magic at sb+56, sb at part+1024
    ("XFS",  b"XFSB", 0),
    ("LVM2", b"LABELONE", 0),
    ("GPT",  b"EFI PART", 0),
]


def signature_scan(f, data_end, full=False, progress=True):
    """Scan for filesystem signatures. Tail-only by default."""
    hits = []
    if full:
        regions = [(0, data_end)]
    else:
        # head (past damage) + tail
        regions = []
        if data_end > NOMINAL_DAMAGE:
            regions.append((NOMINAL_DAMAGE, min(NOMINAL_DAMAGE + (2 << 30), data_end)))
        regions.append((max(0, data_end - (2 << 30)), data_end))

    WINDOW = 8 * 1024 * 1024
    for start, end in regions:
        pos = start
        while pos < end:
            buf = read_at(f, pos, min(WINDOW, end - pos))
            if not buf:
                break
            for name, sig, delta in SIGNATURES:
                idx = 0
                while True:
                    j = buf.find(sig, idx)
                    if j < 0:
                        break
                    base = pos + j + delta
                    if base >= 0 and base % SECTOR == 0:
                        hits.append((base, name))
                    idx = j + 1
            pos += WINDOW - 16
            if progress and (pos - start) % (512 * 1024 * 1024) < WINDOW:
                sys.stdout.write("      ... %s\n" % human(pos))
                sys.stdout.flush()

    # dedupe
    seen = set()
    out = []
    for off, name in sorted(hits):
        k = (off // SECTOR, name)
        if k in seen:
            continue
        seen.add(k)
        out.append((off, name))
    return out


# ------------------------------------------------------------------ main

def profile(path, full=False):
    print("")
    print("=" * 72)
    print("DEEP PROBE (read only)")
    print("=" * 72)
    print("")
    print("file : " + path)

    try:
        size = os.path.getsize(path)
    except OSError as e:
        print("cannot stat: %s" % e)
        return
    # A real virtual disk is always a whole number of 512-byte sectors.
    # Babuk appends a 32-byte trailer each time it runs. Some files here
    # were hit TWICE, so they carry 64 bytes of junk, not 32. Rather than
    # assuming one trailer, cut back to the nearest sector boundary.
    tail = size % SECTOR
    data_end = size - tail
    n_trailers = tail // 32 if tail % 32 == 0 else 0

    print("size : %d bytes  (%s)" % (size, human(size)))
    if tail:
        extra = ""
        if n_trailers:
            extra = "  = %d x 32-byte ransomware trailer%s" % (
                n_trailers, "s" if n_trailers > 1 else "")
            if n_trailers > 1:
                extra += "   <-- THIS FILE WAS ENCRYPTED %d TIMES" % n_trailers
        print("       %d trailing byte(s) beyond the last full sector%s"
              % (tail, extra))
    else:
        print("       already sector aligned, no trailer present")
    print("data : %d bytes usable" % data_end)
    print("")

    try:
        f = open(path, "rb")
    except (IOError, OSError) as e:
        print("CANNOT OPEN: %s" % e)
        print("If this says 'Device or resource busy', the disk is attached to")
        print("a running VM. Power that VM off to inspect the disk.")
        return

    try:
        # 1. entropy profile
        print("-" * 72)
        print("1. ENTROPY PROFILE  (8.0 = random/encrypted, low = structured)")
        print("-" * 72)
        for off, e, zr, tag in entropy_profile(f, data_end):
            mark = ""
            if off == NOMINAL_DAMAGE:
                mark = "   <== expected damage boundary"
            print("   %14d  H=%5.3f  zero=%6.2f%%  %-12s%s"
                  % (off, e, zr, tag, mark))
        print("")

        last_enc, first_clean = find_real_boundary(f, data_end)
        print("   last encrypted-looking sample : %s" %
              (str(last_enc) if last_enc >= 0 else "none"))
        print("   first clean sample after it   : %s" %
              (str(first_clean) if first_clean >= 0 else "none"))
        print("   nominal boundary              : %d" % NOMINAL_DAMAGE)
        print("")

        # 2. partition tables
        print("-" * 72)
        print("2. PARTITION TABLES CURRENTLY ON DISK")
        print("-" * 72)
        mbr = read_mbr(f)
        if mbr is None:
            print("   MBR at sector 0 : ABSENT or invalid")
        elif not mbr:
            print("   MBR at sector 0 : present but no partition entries")
        else:
            print("   MBR at sector 0 : %d entry(s)" % len(mbr))
            for p in mbr:
                print("     [%d] type 0x%02x  offset %d (%s)  size %s"
                      % (p["idx"], p["type"], p["off"],
                         human(p["off"]), human(p["size"])))

        gp = read_gpt(f, data_end, "primary")
        gb = read_gpt(f, data_end, "backup")
        print("   primary GPT     : %s" %
              ("%d partition(s)" % len(gp) if gp else "ABSENT"))
        if gp:
            for p in gp:
                print("     [%d] %-26s offset %d (%s)  size %s"
                      % (p["idx"], p["name"][:26] or "(unnamed)",
                         p["off"], human(p["off"]), human(p["size"])))
        print("   backup GPT      : %s" %
              ("%d partition(s)" % len(gb) if gb else "ABSENT"))
        if gb and not gp:
            for p in gb:
                print("     [%d] %-26s offset %d (%s)  size %s"
                      % (p["idx"], p["name"][:26] or "(unnamed)",
                         p["off"], human(p["off"]), human(p["size"])))
        print("")

        # 3. signature scan
        print("-" * 72)
        print("3. FILESYSTEM SIGNATURE SCAN %s"
              % ("(FULL DISK)" if full else "(head after damage + tail)"))
        print("-" * 72)
        hits = signature_scan(f, data_end, full=full)
        if not hits:
            print("   no filesystem signatures found")
        else:
            for off, name in hits:
                zone = "DAMAGED" if off < NOMINAL_DAMAGE else "intact"
                print("   %-6s at %14d (%s)  [%s]"
                      % (name, off, human(off), zone))
        print("")

        # 4. candidate volumes, with the decisive MFT test
        print("-" * 72)
        print("4. VOLUME ANALYSIS  ($MFT is actually read, not assumed)")
        print("-" * 72)

        candidates = []
        # from partition tables
        for src, plist in (("MBR", mbr or []), ("GPT-primary", gp or []),
                           ("GPT-backup", gb or [])):
            for p in plist:
                candidates.append((src, p["off"], p.get("size", 0)))
        # from NTFS signatures: both as primary and as implied-by-backup
        for off, name in hits:
            if name != "NTFS":
                continue
            b = parse_bpb(read_at(f, off, 512))
            if not b:
                continue
            candidates.append(("NTFS-sig-primary", off, b["vol_bytes"]))
            implied = off - b["total"] * b["bps"]
            if 0 <= implied < off:
                candidates.append(("NTFS-sig-backup", implied, b["vol_bytes"]))

        seen = set()
        uniq = []
        for src, off, sz in candidates:
            if off in seen:
                continue
            seen.add(off)
            uniq.append((src, off, sz))
        uniq.sort(key=lambda t: t[1])

        if not uniq:
            print("   no candidate volume start offsets found")

        verdicts = []
        for src, off, sz in uniq:
            print("")
            print("   candidate start %d (%s)   [found via %s]"
                  % (off, human(off), src))

            sec = read_at(f, off, 512)
            b = parse_bpb(sec)

            # If the primary boot sector is gone, fall back to the BPB from
            # the surviving backup copy. This is the decisive case: it lets us
            # locate and TEST $MFT even though sector 0 of the volume is dead.
            from_backup = False
            if b is None:
                for boff, bname in hits:
                    if bname != "NTFS":
                        continue
                    cand = parse_bpb(read_at(f, boff, 512))
                    if not cand:
                        continue
                    implied = boff - cand["total"] * cand["bps"]
                    if abs(implied - off) <= SECTOR:
                        b = cand
                        from_backup = True
                        print("     primary boot sector : DESTROYED")
                        print("     using backup copy at %d (%s)"
                              % (boff, human(boff)))
                        break

            if b:
                if not from_backup:
                    print("     NTFS boot sector : PRESENT")
                print("       cluster size   : %d" % b["cluster"])
                print("       volume size    : %s" % human(b["vol_bytes"]))
                print("       serial         : %016x" % b["serial"])
                m = check_mft(f, off, b, NOMINAL_DAMAGE)
                print("       $MFT offset    : %d (%s) %s"
                      % (m["mft_off"], human(m["mft_off"]),
                         "INSIDE DAMAGE" if m["mft_in_damage"] else "past damage"))
                print("       $MFT magic     : %s   %s"
                      % (repr(m["mft_magic"]),
                         "VALID" if m["mft_ok"] else "*** NOT A FILE RECORD ***"))
                print("       $MFTMirr magic : %s   %s"
                      % (repr(m["mirr_magic"]),
                         "VALID" if m["mirr_ok"] else "invalid"))
                print("       FILE records   : %d of first 8" % m["records_found"])
                if m["mft_ok"] and m["records_found"] >= 4:
                    if from_backup:
                        v = ("MOUNTABLE after boot-sector repair - "
                             "$MFT is alive")
                    else:
                        v = "MOUNTABLE - filesystem index is alive"
                elif m["mirr_ok"]:
                    v = "REPAIRABLE via $MFTMirr - needs chkdsk"
                else:
                    v = "NOT MOUNTABLE - $MFT destroyed, needs carving"
                print("       VERDICT        : %s" % v)
                verdicts.append((off, v))
            else:
                print("     NTFS boot sector : absent")
                e = probe_ext(f, off)
                if e:
                    print("     ext2/3/4 superblock PRESENT")
                    print("       block size : %d" % e["block_size"])
                    print("       fs size    : %s" % human(e["size"]))
                    print("       label      : %s" % (e["label"] or "(none)"))
                    print("       VERDICT    : Linux ext filesystem")
                    verdicts.append((off, "ext filesystem"))
                    continue
                x = probe_xfs(f, off)
                if x:
                    print("     XFS superblock PRESENT  size %s" % human(x["size"]))
                    verdicts.append((off, "XFS filesystem"))
                    continue
                l = probe_lvm(f, off)
                if l:
                    print("     LVM2 label PRESENT (sector %d)" % l["label_sector"])
                    print("       VERDICT : Linux LVM physical volume")
                    verdicts.append((off, "LVM PV"))
                    continue
                s = probe_swap(f, off)
                if s:
                    print("     Linux swap signature (%s)" % s["kind"])
                    verdicts.append((off, "swap"))
                    continue
                raw = read_at(f, off, 64)
                print("     first 32 bytes : %s" % raw[:32].hex())
                print("     VERDICT        : unknown / no filesystem here")
                verdicts.append((off, "unknown"))

        print("")
        print("-" * 72)
        print("5. BOTTOM LINE")
        print("-" * 72)
        mountable = [v for v in verdicts if v[1].startswith("MOUNTABLE")]
        needs_bs = [v for v in verdicts if "after boot-sector repair" in v[1]]
        chkdsk = [v for v in verdicts if "MFTMirr" in v[1]]
        dead = [v for v in verdicts if "NOT MOUNTABLE" in v[1]]
        linux = [v for v in verdicts if v[1] in ("ext filesystem", "XFS filesystem", "LVM PV", "swap")]

        ready_now = [v for v in mountable if "after boot-sector" not in v[1]]
        if ready_now:
            print("   ALREADY MOUNTABLE (live $MFT, boot sector present):")
            for off, v in ready_now:
                print("     offset %d  (%s)" % (off, human(off)))
        if needs_bs:
            print("   RECOVERABLE - $MFT is alive, only the boot sector needs")
            print("   restoring from its surviving backup copy:")
            for off, v in needs_bs:
                print("     offset %d  (%s)" % (off, human(off)))
        if chkdsk:
            print("   $MFT damaged but $MFTMirr alive -- run chkdsk after repair:")
            for off, v in chkdsk:
                print("     offset %d  (%s)" % (off, human(off)))
        if linux:
            print("   Linux filesystem(s) found -- this is NOT a Windows disk:")
            for off, v in linux:
                print("     offset %d  (%s)  %s" % (off, human(off), v))
        if dead:
            print("   $MFT destroyed at these offsets -- carving only:")
            for off, v in dead:
                print("     offset %d  (%s)" % (off, human(off)))
        if not verdicts:
            print("   nothing conclusive found")
        print("")
        print("   NOTE: this tool wrote nothing. No changes were made.")
        print("=" * 72)

    finally:
        f.close()


def find_all(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            low = fn.lower()
            if "-flat.vmdk" in low or "-sesparse.vmdk" in low:
                out.append(os.path.join(dirpath, fn))
    return out


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return
    full = "--full" in a
    a = [x for x in a if not x.startswith("--")]

    if not a:
        print(__doc__)
        return

    if sys.argv[1] == "--all":
        root = a[0] if a else "/vmfs/volumes"
        disks = find_all(root)
        disks.sort(key=lambda p: -os.path.getsize(p))
        print("found %d disk(s)" % len(disks))
        for d in disks:
            profile(d, full)
    else:
        profile(a[0], full)


main()

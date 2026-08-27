#!/usr/bin/env python3
"""
refs_veeam.py -- Find Veeam backup files on a damaged ReFS volume.

READ ONLY. Writes nothing to the disk it scans.

WHY A SEPARATE TOOL
    Veeam repositories are usually formatted ReFS, and ReFS keeps its
    filenames in metadata pages as UTF-16 text. When the first 520 MiB of
    the disk is destroyed the ReFS superblock dies with it, so Windows
    cannot mount the volume and ordinary carving finds nothing useful --
    .vbk files have no fixed magic bytes to carve on.

    But the directory entries deeper in the volume are untouched. This tool
    reads those directly: it sweeps the raw disk for UTF-16 filenames
    ending in .vbk / .vib / .vbm, which tells you exactly which backups
    exist, how they are named, and where their records live.

COMMANDS
    names   <disk>            list every Veeam filename found on the disk
    refs    <disk>            find ReFS structures (superblock copies etc.)
    around  <disk> <offset>   hex dump around one offset, to inspect a hit
    vbr     <disk> <offset>   read and decode a ReFS boot record found by
                              'refs', and check whether it is usable
    supb    <disk> <backup-offset> --to <primary-offset>
                              compare a surviving superblock copy against
                              the primary location and, with --apply, put
                              it back. Add --size N to copy N bytes
                              (default 65536, one cluster).
    restore <disk> <offset> --to <partition-start>
                              copy that boot record onto the start of the
                              partition so Windows can mount the volume
                              again. Saves what it overwrites first.

OPTIONS
    --start N     begin at byte N (resume a long scan)
    --end N       stop at byte N
    --window N    read buffer in MiB            (default 64)
    --quiet       progress only every 10 GiB
    --out FILE    also write results to FILE

EXAMPLES
    python3 refs_veeam.py names "/vmfs/volumes/.../Veeam-flat.vmdk"
    python3 refs_veeam.py names <disk> --start 1099511627776 --out /tmp/n.txt
"""

import os
import sys
import struct

if sys.version_info[0] < 3:
    sys.stderr.write("Needs Python 3. Try: python3 %s\n" % " ".join(sys.argv))
    sys.exit(1)

SECTOR = 512
DAMAGE = 545259520

# Veeam extensions, encoded the way ReFS stores them: UTF-16 little endian
EXTS = {
    ".vbk": b"\x2e\x00\x76\x00\x62\x00\x6b\x00",
    ".vib": b"\x2e\x00\x76\x00\x69\x00\x62\x00",
    ".vbm": b"\x2e\x00\x76\x00\x62\x00\x6d\x00",
    ".vrb": b"\x2e\x00\x76\x00\x72\x00\x62\x00",
    ".vlb": b"\x2e\x00\x76\x00\x6c\x00\x62\x00",
    ".vsb": b"\x2e\x00\x76\x00\x73\x00\x62\x00",
}

# ReFS on-disk structures worth knowing about
REFS_SIGS = {
    b"ReFS": "volume boot record",
    b"FSRS": "boot record, second magic",
    b"SUPB": "superblock",
    b"CHKP": "checkpoint",
    b"MSB+": "metadata B+ tree node",
    b"OBJT": "object table",
}


def human(x):
    x = float(x)
    for u in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(x) < 1024.0:
            return "%.2f %s" % (x, u)
        x /= 1024.0
    return "%.2f EiB" % x


OUT = [None]


def emit(msg=""):
    print(msg)
    if OUT[0]:
        try:
            OUT[0].write(msg + "\n")
            OUT[0].flush()
        except Exception:
            pass


def rule(c="-", n=72):
    emit(c * n)


def decode_name(buf, ext_pos, ext_len):
    """Walk backwards from the extension to recover the whole filename.

    ReFS stores names as plain UTF-16LE with no length prefix right before
    the text, so the reliable way to find the start is to walk back while
    the bytes still look like printable UTF-16 characters.
    """
    start = ext_pos
    limit = max(0, ext_pos - 512)
    while start - 2 >= limit:
        lo = buf[start - 2]
        hi = buf[start - 1]
        if hi != 0:
            break
        if lo < 0x20 or lo == 0x7F:
            break
        if lo in (0x2F, 0x5C, 0x3A, 0x2A, 0x3F, 0x22, 0x3C, 0x3E, 0x7C):
            break
        start -= 2
    raw = buf[start:ext_pos + ext_len]
    try:
        name = raw.decode("utf-16-le", "ignore")
    except Exception:
        return None, start
    name = name.replace("\x00", "").strip()
    if len(name) < 5:
        return None, start
    return name, start


def scan_names(path, start, end, window, quiet):
    size = os.path.getsize(path)
    if end is None or end > size:
        end = size
    emit("disk  : %s" % path)
    emit("size  : %d (%s)" % (size, human(size)))
    emit("range : %d -> %d" % (start, end))
    emit("")
    emit("Sweeping for UTF-16 filenames ending in .vbk .vib .vbm .vrb ...")
    emit("")

    f = open(path, "rb")
    found = {}
    order = []
    pos = start
    maxlen = max(len(v) for v in EXTS.values())
    step = 10 * 1024 ** 3 if quiet else 2 * 1024 ** 3
    next_report = pos + step
    try:
        while pos < end:
            f.seek(pos)
            buf = f.read(min(window, end - pos))
            if not buf:
                break
            for ext, pat in EXTS.items():
                idx = 0
                while True:
                    j = buf.find(pat, idx)
                    if j < 0:
                        break
                    name, nstart = decode_name(buf, j, len(pat))
                    if name and name.lower().endswith(ext):
                        abs_off = pos + nstart
                        key = name.lower()
                        if key not in found:
                            found[key] = dict(name=name, off=abs_off,
                                              ext=ext, count=1)
                            order.append(key)
                            emit("  %-13d %s" % (abs_off, name))
                        else:
                            found[key]["count"] += 1
                    idx = j + 2
            if pos >= next_report:
                sys.stdout.write("      ... %s scanned, %d name(s) so far\n"
                                 % (human(pos - start), len(found)))
                sys.stdout.flush()
                next_report = pos + step
            pos += len(buf) - maxlen
            if len(buf) <= maxlen:
                break
    except KeyboardInterrupt:
        emit("")
        emit("  interrupted at offset %d" % pos)
        emit("  resume with:  --start %d" % pos)
    finally:
        f.close()

    emit("")
    rule("=")
    emit("RESULT")
    rule("=")
    emit("")
    if not found:
        emit("  No Veeam filenames were found in that range.")
        emit("")
        emit("  That usually means one of:")
        emit("    - the range scanned does not contain the directory")
        emit("      metadata yet (try scanning further in, or the whole disk)")
        emit("    - this disk holds only backup DATA and the names live on a")
        emit("      different disk of the same repository")
        emit("    - the volume is not ReFS/NTFS but something else")
        return found, order

    bykind = {}
    for k in order:
        bykind.setdefault(found[k]["ext"], []).append(found[k])
    for ext in sorted(bykind):
        emit("  %s : %d distinct name(s)" % (ext, len(bykind[ext])))
    emit("")
    emit("  Full list, sorted by name:")
    emit("")
    for k in sorted(found):
        d = found[k]
        emit("    %-13d  x%-4d  %s" % (d["off"], d["count"], d["name"]))
    emit("")
    emit("  The offset is where the NAME sits, which is inside the ReFS")
    emit("  directory metadata -- not where the file contents start.")
    emit("  Use it with:  refs_veeam.py around <disk> <offset>")
    return found, order


def scan_refs(path, start, end, window):
    size = os.path.getsize(path)
    if end is None or end > size:
        end = size
    emit("disk  : %s" % path)
    emit("size  : %d (%s)" % (size, human(size)))
    emit("")
    emit("Looking for ReFS structures ...")
    emit("")
    f = open(path, "rb")
    hits = {}
    pos = start
    try:
        while pos < end:
            f.seek(pos)
            buf = f.read(min(window, end - pos))
            if not buf:
                break
            for sig, what in REFS_SIGS.items():
                idx = 0
                n = 0
                while True:
                    j = buf.find(sig, idx)
                    if j < 0:
                        break
                    off = pos + j
                    if off % SECTOR in (0, 3, 4, 8):
                        hits.setdefault(sig, [])
                        if len(hits[sig]) < 12:
                            hits[sig].append(off)
                        n += 1
                    idx = j + 1
            pos += len(buf) - 8
            if len(buf) <= 8:
                break
    except KeyboardInterrupt:
        emit("  interrupted at %d" % pos)
    finally:
        f.close()

    emit("")
    rule("=")
    emit("ReFS STRUCTURES")
    rule("=")
    emit("")
    if not hits:
        emit("  none found in that range")
        return
    for sig in sorted(hits):
        emit("  %s  (%s)" % (sig.decode("ascii", "ignore"), REFS_SIGS[sig]))
        for off in hits[sig]:
            zone = "DESTROYED" if off < DAMAGE else "intact"
            emit("      %-14d %-12s [%s]" % (off, human(off), zone))
        emit("")


def dump_around(path, off, before=512, after=1536):
    start = max(0, off - before)
    f = open(path, "rb")
    f.seek(start)
    buf = f.read(before + after)
    f.close()
    emit("hex dump around %d" % off)
    emit("")
    for i in range(0, len(buf), 16):
        chunk = buf[i:i + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        u16 = ""
        for k in range(0, len(chunk) - 1, 2):
            if chunk[k + 1] == 0 and 32 <= chunk[k] < 127:
                u16 += chr(chunk[k])
            else:
                u16 += "."
        mark = " <<<" if start + i <= off < start + i + 16 else ""
        emit("  %12d  %-47s  |%-16s| %-8s%s"
             % (start + i, hexs, txt, u16, mark))


def parse_vbr(b):
    """Recognise a ReFS volume boot record.

    The two magic strings are the only part of the ReFS VBR format that is
    publicly documented with confidence: "ReFS" at byte offset 3 and "FSRS"
    at byte offset 16 (NOT byte 8 -- an earlier version of this tool assumed
    that by analogy with NTFS and was wrong; verified against a real disk).

    Everything past that (version numbers, sector counts, serials) sits at
    offsets that are not reliably documented anywhere public, so this
    function does not try to decode them for correctness -- it best-effort
    reads a couple of plausible fields for display only, clearly marked as
    such, and never gates a restore decision on them. The partition size
    used for the actual restore comes from the GPT table, which IS fully
    documented and was already parsed with confidence elsewhere in this
    toolset.
    """
    if len(b) < 32:
        return None
    if b[3:7] != b"ReFS" or b[16:20] != b"FSRS":
        return None
    out = dict(magic_ok=True)
    # Best-effort, informational only -- do not trust for decisions.
    try:
        out["maybe_version"] = (b[20], b[21])
    except Exception:
        pass
    return out


def show_vbr(path, off):
    """Read a boot record at off, decode it, and say whether it looks sane."""
    sector_start = off - (off % SECTOR)
    b = b""
    f = open(path, "rb")
    try:
        f.seek(sector_start)
        b = f.read(SECTOR)
    finally:
        f.close()

    emit("disk        : %s" % path)
    emit("found at    : %d" % off)
    emit("sector start: %d" % sector_start)
    emit("")

    v = parse_vbr(b)
    if v is None:
        emit("  That sector is not a ReFS boot record.")
        emit("  The 'ReFS' magic must sit at byte 3 and 'FSRS' at byte 8 of")
        emit("  the sector. Try the offset exactly as 'refs' reported it.")
        return None, sector_start, b

    emit("  ReFS boot record recognised:")
    emit("")
    emit("    'ReFS' magic at byte 3   : present")
    emit("    'FSRS' magic at byte 16  : present")
    if "maybe_version" in v:
        emit("    bytes at offset 20-21    : %d.%d  (position not confirmed,"
             % v["maybe_version"])
        emit("                               shown for reference only)")
    emit("")
    emit("  This tool only trusts the two magic strings above -- the rest of")
    emit("  the ReFS boot record layout is not reliably documented, so no")
    emit("  other field is decoded or used to decide whether to restore.")
    emit("  The partition size used below comes from the GPT table instead,")
    emit("  which is fully documented and already verified.")
    return v, sector_start, b


def restore_vbr(path, off, to, apply, part_size=None):
    v, sector_start, b = show_vbr(path, off)
    if v is None:
        return
    emit("")
    rule("=")
    emit("RESTORE PLAN")
    rule("=")
    emit("")

    size = os.path.getsize(path)
    emit("  copy 512 bytes")
    emit("    from : %d   (the surviving copy, magic-verified)" % sector_start)
    emit("    to   : %d   (the start of the partition)" % to)
    emit("")

    cur = b""
    f = open(path, "rb")
    try:
        f.seek(to)
        cur = f.read(SECTOR)
    finally:
        f.close()

    curv = parse_vbr(cur)
    if curv is not None:
        emit("  There is ALREADY a valid ReFS boot record at %d." % to)
        emit("  Nothing needs restoring. Stopping.")
        return

    zero = cur.count(0) == len(cur)
    emit("  what is at the destination now:")
    emit("    first 16 bytes : %s"
         % " ".join("%02x" % c for c in cur[:16]))
    emit("    %s" % ("all zeroes" if zero else "random - overwritten by the ransomware"))
    emit("")

    emit("  cross-check:")
    emit("    partition start  : %d" % to)
    if part_size:
        expected_end = to + part_size
        emit("    partition size   : %s  (from the GPT table, --part-size)"
             % human(part_size))
        emit("    implied end      : %d" % expected_end)
        emit("    disk size        : %d" % size)
        if expected_end > size:
            emit("")
            emit("    The partition would run past the end of the disk.")
            emit("    Check --to and --part-size before applying.")
            return
        slack = size - expected_end
        emit("    slack after      : %s" % human(slack))
    else:
        emit("    (no --part-size given -- pass the GPT partition size, e.g.")
        emit("     from rebuild_mbr.py or deep_probe.py, to cross-check the")
        emit("     offset before writing)")
    emit("")

    if not apply:
        emit("  Dry run. Nothing was written.")
        emit("  Re-run with --apply to write the boot record.")
        return

    bak = path + ".refs-vbr.bak"
    try:
        g = open(bak, "wb")
        g.write(cur)
        g.close()
        emit("  saved the old sector to %s" % os.path.basename(bak))
    except Exception as e:
        emit("  could not save a backup (%s) - stopping" % e)
        return

    try:
        f = open(path, "r+b")
        f.seek(to)
        f.write(b)
        f.close()
    except Exception as e:
        emit("  write failed: %s" % e)
        return

    emit("  wrote 512 bytes at %d" % to)
    emit("")
    chk = b""
    f = open(path, "rb")
    try:
        f.seek(to)
        chk = f.read(SECTOR)
    finally:
        f.close()
    if parse_vbr(chk) is not None:
        emit("  verified: a valid ReFS boot record now sits at the start")
        emit("  of the partition.")
        emit("")
        emit("  Next: rescan the disk in Windows.")
        emit("    - in the VM, open Disk Management, or run:")
        emit("        diskpart  ->  rescan")
        emit("    - if the volume still shows RAW, run in PowerShell:")
        emit("        Repair-Volume -DriveLetter <X> -OfflineScanAndFix")
    else:
        emit("  the sector did not read back as expected")


def sig_at(path, off, sig=b"SUPB"):
    b = b""
    f = open(path, "rb")
    try:
        f.seek(off)
        b = f.read(len(sig))
    finally:
        f.close()
    return b == sig


def read_block(path, off, n):
    f = open(path, "rb")
    try:
        f.seek(off)
        return f.read(n)
    finally:
        f.close()


def entropy_of(buf):
    if not buf:
        return 0.0
    import math
    counts = {}
    for b in buf:
        counts[b] = counts.get(b, 0) + 1
    n = float(len(buf))
    e = 0.0
    for v in counts.values():
        pr = v / n
        e -= pr * math.log(pr, 2)
    return e


def describe(buf, label):
    z = 100.0 * buf.count(0) / len(buf) if buf else 0.0
    e = entropy_of(buf[:65536])
    emit("    %s" % label)
    emit("      first 16 bytes : %s"
         % " ".join("%02x" % c for c in buf[:16]))
    emit("      zero bytes     : %.1f%%" % z)
    emit("      entropy        : %.3f  %s"
         % (e, "(random - ransomware overwrote this)" if e > 7.9
            else "(structured)" if e < 6.0 else "(mixed)"))


def supb_restore(path, src, to, size, apply):
    emit("disk : %s" % path)
    emit("")
    rule("=")
    emit("SUPERBLOCK COMPARISON")
    rule("=")
    emit("")

    if not sig_at(path, src):
        emit("  The source at %d does not start with 'SUPB'." % src)
        emit("  Use the offset exactly as the 'refs' command reported it.")
        return

    srcbuf = read_block(path, src, size)
    dstbuf = read_block(path, to, size)

    emit("  copying %s (one cluster) unless --size says otherwise" % human(size))
    emit("")
    describe(srcbuf, "SOURCE  at %d  (surviving copy)" % src)
    emit("")
    describe(dstbuf, "TARGET  at %d  (where ReFS looks for it)" % to)
    emit("")

    dst_ok = dstbuf[:4] == b"SUPB"
    if dst_ok and srcbuf == dstbuf:
        emit("  The target already holds an identical superblock.")
        emit("  Nothing to do.")
        return
    if dst_ok:
        emit("  NOTE: the target already begins with 'SUPB' but differs from")
        emit("  the source. That can mean the primary partly survived, or")
        emit("  that the two copies are simply from different checkpoints.")
        emit("  Overwriting is still usually right, but the old bytes are")
        emit("  saved so it can be undone.")
        emit("")

    if not apply:
        emit("  Dry run. Nothing was written.")
        emit("  Re-run with --apply to write the superblock.")
        return

    bak = path + ".refs-supb.bak"
    try:
        g = open(bak, "wb")
        g.write(dstbuf)
        g.close()
        emit("  saved the old %s to %s" % (human(len(dstbuf)),
                                           os.path.basename(bak)))
    except Exception as e:
        emit("  could not save a backup (%s) - stopping" % e)
        return

    try:
        f = open(path, "r+b")
        f.seek(to)
        f.write(srcbuf)
        f.close()
    except Exception as e:
        emit("  write failed: %s" % e)
        return

    emit("  wrote %s at %d" % (human(len(srcbuf)), to))
    chk = read_block(path, to, 4)
    if chk == b"SUPB":
        emit("  verified: 'SUPB' now reads back at the primary location")
        emit("")
        emit("  Next, in the Windows VM:")
        emit("      diskpart  ->  rescan  ->  list volume")
        emit("  and if it still will not mount:")
        emit("      Repair-Volume -DriveLetter <X> -OfflineScanAndFix")
    else:
        emit("  the target did not read back as expected")


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return

    def opt(name, cast=str, default=None):
        if name in a:
            i = a.index(name)
            if i + 1 < len(a):
                return cast(a[i + 1])
        return default

    start = opt("--start", int, 0)
    end = opt("--end", int, None)
    window = opt("--window", int, 64) * 1024 * 1024
    quiet = "--quiet" in a
    outfile = opt("--out", str, None)
    if outfile:
        try:
            OUT[0] = open(outfile, "w")
        except Exception:
            OUT[0] = None

    pos = [x for x in a if not x.startswith("--")]
    skip = set()
    for flag in ("--start", "--end", "--window", "--out", "--to", "--part-size", "--size"):
        if flag in a:
            i = a.index(flag)
            if i + 1 < len(a):
                skip.add(a[i + 1])
    pos = [x for x in pos if x not in skip]

    if len(pos) < 2:
        print(__doc__)
        return
    cmd, path = pos[0], pos[1]

    if not os.path.exists(path):
        emit("no such file: %s" % path)
        return

    rule("=")
    emit("REFS / VEEAM SCANNER  (read only)")
    rule("=")
    emit("")

    if cmd == "names":
        scan_names(path, start, end, window, quiet)
    elif cmd == "refs":
        scan_refs(path, start, end, window)
    elif cmd == "around":
        if len(pos) < 3:
            emit("usage: around <disk> <offset>")
            return
        dump_around(path, int(pos[2]))
    elif cmd == "vbr":
        if len(pos) < 3:
            emit("usage: vbr <disk> <offset>")
            return
        show_vbr(path, int(pos[2]))
    elif cmd == "supb":
        if len(pos) < 3:
            emit("usage: supb <disk> <backup-offset> --to <primary-offset> "
                 "[--size N] [--apply]")
            return
        to = opt("--to", int, None)
        if to is None:
            emit("give the primary superblock offset with --to")
            return
        supb_restore(path, int(pos[2]), to, opt("--size", int, 65536),
                     "--apply" in a)
    elif cmd == "restore":
        if len(pos) < 3:
            emit("usage: restore <disk> <offset> --to <partition-start> "
                "[--part-size N] [--apply]")
            return
        to = opt("--to", int, None)
        if to is None:
            emit("give the partition start with --to, for example --to 16777216")
            return
        part_size = opt("--part-size", int, None)
        restore_vbr(path, int(pos[2]), to, "--apply" in a, part_size)
    else:
        print(__doc__)

    if OUT[0]:
        OUT[0].close()


main()

#!/usr/bin/env python
"""
babuk_recover.py -- Complete guided recovery for Babuk-encrypted VMware disks.

ONE file. Run it with no arguments on an ESXi host:

    python3 /tmp/babuk_recover.py

WHAT IT DOES, IN ORDER
    0. checks the host: ESXi version, which Python interpreters exist, and
       whether every feature it needs is actually available here
    1. finds every datastore and every virtual disk on them
    2. finds any repair backups left by earlier runs, and offers to roll
       them back if a previous attempt went wrong
    3. deep-scans each disk: real damage boundary, partition tables, and
       every NTFS volume -- verifying each by actually READING $MFT
    4. reports the findings grouped by virtual machine
    5. lets you pick machines one at a time
    6. asks for confirmation before touching anything
    7. repairs, then verifies the repair immediately
    8. prints what to do next for each machine

WHAT IT KNOWS (learned the hard way)
    * Babuk overwrites the first 52 x 10 MiB = 520 MiB, not 512 MiB
    * it appends a 32-byte trailer PER RUN; disks hit twice carry 64 bytes,
      so the tool trims back to the nearest whole sector instead of assuming
    * a valid-looking boot sector proves nothing: $MFT must be read and
      checked for FILE records, or you can end up writing a boot sector on
      top of live data
    * a disk often carries a STALE oversized backup boot sector from an
      earlier layout; trusting it silently swallows the partition that
      follows, so the smallest candidate at a given start wins
    * EFI / MSR / Recovery partitions have no NTFS backup sector and that
      is normal -- they must not block the rest of the disk
    * repairing the volume boot sector is not enough: sector 0 of the disk
      (the partition table) also died and must be rebuilt, otherwise
      Windows shows the disk as unallocated

SAFETY
    * nothing is written until you type 'y' for that specific machine
    * every sector overwritten is saved first, and a manifest is written so
      the change can be rolled back exactly
    * a disk attached to a running VM is skipped with a clear message
    * running it twice is safe; already-repaired disks are reported as such

Options:
    --root PATH   where to look                (default /vmfs/volumes)
    --log PATH    log file                     (default /tmp/babuk_recover.log)
    --tail MB     tail scan window             (default 2048)
    --restore     go straight to rollback mode
    --skip-env    skip the environment check
"""

import os
import sys
import struct
import time

# --------------------------------------------------------------------------
# Compatibility guard.
# This block is deliberately written so that even Python 2 can parse and run
# it -- otherwise the user just gets a SyntaxError with no explanation.
# --------------------------------------------------------------------------
if sys.version_info[0] < 3:
    sys.stderr.write(
        "\nThis tool needs Python 3. You ran it with Python %d.%d.\n\n"
        % (sys.version_info[0], sys.version_info[1]))
    sys.stderr.write("On an ESXi host try one of these instead:\n")
    sys.stderr.write("    python3 %s\n" % " ".join(sys.argv))
    sys.stderr.write("    /bin/python3 %s\n" % " ".join(sys.argv))
    sys.stderr.write("\nTo see what is available:  ls -la /bin/python*\n\n")
    sys.exit(1)

# ------------------------------------------------------------------ constants

SECTOR = 512
_BLOCK = 10 * 1024 * 1024
_w = 0
while True:
    _w += _BLOCK
    if not (_w < 0x20000000):
        break
DAMAGE = _w                       # 545,259,520
MANIFEST_SUFFIX = ".babuk-manifest"

SKIP_DS_PREFIX = ("BOOTBANK", "OSDATA", "esx-", ".vSphere", "vmkdump",
                  "scratch", ".locker")

EFI_GUID = b"\x28\x73\x2a\xc1\x1f\xf8\xd2\x11\xba\x4b\x00\xa0\xc9\x3e\xc9\x3b"
MSR_GUID = b"\x16\xe3\xc9\xe3\x5c\x0b\xb8\x4d\x81\x7d\xf9\x2d\xf0\x02\x15\xae"
REC_GUID = b"\xa4\xbb\x94\xde\xd1\x06\x40\x4d\xa1\x6a\xbf\xd5\x01\x79\xd6\xac"
STRUCTURAL = (EFI_GUID, MSR_GUID, REC_GUID)


def human(x):
    x = float(x)
    for u in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(x) < 1024.0:
            return "%.2f %s" % (x, u)
        x /= 1024.0
    return "%.2f EiB" % x


def hexs(b):
    return "".join("%02x" % (c if isinstance(c, int) else ord(c)) for c in b)


LOG = [None]


def log(msg=""):
    print(msg)
    if LOG[0]:
        try:
            LOG[0].write(msg + "\n")
            LOG[0].flush()
        except Exception:
            pass


def rule(c="-", n=72):
    log(c * n)


def ask(prompt, choices, default=None):
    """EOF always means quit -- absence of input is never consent."""
    ch = "/".join(choices)
    while True:
        try:
            sys.stdout.write("%s [%s]%s " %
                             (prompt, ch,
                              ("(default %s)" % default) if default else ""))
            sys.stdout.flush()
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            print("")
            return "q"
        except Exception:
            return "q"
        if line == "":
            print("")
            print("    (no input available - stopping without changes)")
            return "q"
        line = line.strip().lower()
        if line == "" and default:
            return default
        if line in choices:
            if LOG[0]:
                LOG[0].write(">>> answered: %s\n" % line)
            return line
        print("    please answer one of: %s" % ch)


# ---------------------------------------------------------------------- io

def read_at(path, off, n):
    try:
        f = open(path, "rb")
    except (IOError, OSError):
        return b""
    try:
        f.seek(off)
        return f.read(n)
    except Exception:
        return b""
    finally:
        f.close()


def busy(path):
    """True if the file cannot be opened because a VM holds it."""
    try:
        f = open(path, "rb")
        f.close()
        return False
    except (IOError, OSError) as e:
        return "busy" in str(e).lower() or getattr(e, "errno", 0) == 16


# -------------------------------------------------------------------- ntfs

def parse_bpb(sec):
    if len(sec) < 512 or sec[3:11] != b"NTFS    ":
        return None
    bps = struct.unpack_from("<H", sec, 11)[0]
    spc = sec[13] if isinstance(sec[13], int) else ord(sec[13])
    total = struct.unpack_from("<Q", sec, 40)[0]
    mft = struct.unpack_from("<Q", sec, 48)[0]
    mirr = struct.unpack_from("<Q", sec, 56)[0]
    serial = struct.unpack_from("<Q", sec, 72)[0]
    if bps not in (512, 1024, 2048, 4096):
        return None
    if spc not in (1, 2, 4, 8, 16, 32, 64, 128):
        return None
    if total == 0 or total > (1 << 44):
        return None
    if mft == 0 or mft > total or mirr == 0 or mirr > total:
        return None
    return dict(bps=bps, spc=spc, total=total, mft=mft, mirr=mirr,
                serial=serial, cluster=bps * spc,
                vol_bytes=(total + 1) * bps)


def mft_alive(path, part_off, bpb, n=8):
    """Count FILE records at $MFT. This is the decisive test."""
    off = part_off + bpb["mft"] * bpb["cluster"]
    good = 0
    try:
        f = open(path, "rb")
    except (IOError, OSError):
        return 0, off, 0
    try:
        for i in range(n):
            f.seek(off + i * 1024)
            if f.read(4) == b"FILE":
                good += 1
        moff = part_off + bpb["mirr"] * bpb["cluster"]
        f.seek(moff)
        mirr_ok = 1 if f.read(4) == b"FILE" else 0
    except Exception:
        mirr_ok = 0
    finally:
        f.close()
    return good, off, mirr_ok


def scan_ntfs(path, data_end, tail_mb):
    """Find NTFS boot sectors: head (incl. damaged window) plus tail."""
    hits = []
    regions = [(0, min(2 << 30, data_end))]
    tail = tail_mb * 1024 * 1024
    if data_end > tail:
        regions.append((max(0, data_end - tail), data_end))
    WIN = 8 * 1024 * 1024
    try:
        f = open(path, "rb")
    except (IOError, OSError):
        return hits
    try:
        for start, end in regions:
            pos = start
            while pos < end:
                f.seek(pos)
                buf = f.read(min(WIN, end - pos))
                if not buf:
                    break
                idx = 0
                while True:
                    j = buf.find(b"NTFS    ", idx)
                    if j < 0:
                        break
                    base = pos + j - 3
                    if base >= 0 and base % SECTOR == 0:
                        f.seek(base)
                        b = parse_bpb(f.read(512))
                        if b:
                            hits.append((base, b))
                        f.seek(pos + len(buf))
                    idx = j + 1
                pos += WIN - 16
    finally:
        f.close()
    seen = set()
    out = []
    for off, b in sorted(hits):
        if off in seen:
            continue
        seen.add(off)
        out.append((off, b))
    return out


# --------------------------------------------------------------------- gpt

def _crc32(b):
    try:
        import zlib
        return zlib.crc32(b) & 0xFFFFFFFF
    except ImportError:
        import binascii
        return binascii.crc32(b) & 0xFFFFFFFF


def read_gpt(path, data_end, where="backup"):
    hdr_off = SECTOR if where == "primary" else data_end - SECTOR
    b = read_at(path, hdr_off, SECTOR)
    if len(b) < 92 or b[0:8] != b"EFI PART":
        return None, None, None
    hdr = dict(
        revision=struct.unpack_from("<I", b, 8)[0],
        first_usable=struct.unpack_from("<Q", b, 40)[0],
        last_usable=struct.unpack_from("<Q", b, 48)[0],
        disk_guid=b[56:72],
        entries_lba=struct.unpack_from("<Q", b, 72)[0],
        num=struct.unpack_from("<I", b, 80)[0],
        esz=struct.unpack_from("<I", b, 84)[0],
        arr_crc=struct.unpack_from("<I", b, 88)[0])
    if hdr["num"] == 0 or hdr["num"] > 512 or hdr["esz"] < 128:
        return None, None, None
    arr_off = hdr["entries_lba"] * SECTOR
    ln = hdr["num"] * hdr["esz"]
    if not (0 < arr_off and arr_off + ln <= data_end):
        arr_off = hdr_off - ln
    arr = read_at(path, arr_off, ln)
    parts = []
    for i in range(hdr["num"]):
        e = arr[i * hdr["esz"]:(i + 1) * hdr["esz"]]
        if len(e) < 128 or e[0:16] == b"\x00" * 16:
            continue
        first = struct.unpack_from("<Q", e, 32)[0]
        last = struct.unpack_from("<Q", e, 40)[0]
        name = e[56:128].decode("utf-16-le", "ignore").rstrip("\x00")
        parts.append(dict(idx=i + 1, off=first * SECTOR,
                          size=(last - first + 1) * SECTOR, name=name,
                          structural=(e[0:16] in STRUCTURAL)))
    return hdr, arr, parts


def build_primary_gpt(hdr, arr, disk_sectors):
    mbr = bytearray(512)
    e = bytearray(16)
    e[2] = 0x02
    e[4] = 0xEE
    struct.pack_into("<I", e, 8, 1)
    struct.pack_into("<I", e, 12, min(disk_sectors - 1, 0xFFFFFFFF))
    mbr[446:462] = bytes(e)
    mbr[510:512] = b"\x55\xaa"
    h = bytearray(512)
    h[0:8] = b"EFI PART"
    struct.pack_into("<I", h, 8, hdr["revision"])
    struct.pack_into("<I", h, 12, 92)
    struct.pack_into("<Q", h, 24, 1)
    struct.pack_into("<Q", h, 32, disk_sectors - 1)
    struct.pack_into("<Q", h, 40, hdr["first_usable"])
    struct.pack_into("<Q", h, 48, hdr["last_usable"])
    h[56:72] = hdr["disk_guid"]
    struct.pack_into("<Q", h, 72, 2)
    struct.pack_into("<I", h, 80, hdr["num"])
    struct.pack_into("<I", h, 84, hdr["esz"])
    struct.pack_into("<I", h, 88, _crc32(arr))
    struct.pack_into("<I", h, 16, 0)
    struct.pack_into("<I", h, 16, _crc32(bytes(h[0:92])))
    return bytes(mbr), bytes(h), arr


def read_mbr(path):
    m = read_at(path, 0, 512)
    if len(m) < 512 or m[510:512] != b"\x55\xaa":
        return None
    out = []
    for i in range(4):
        e = m[446 + i * 16:462 + i * 16]
        t = e[4] if isinstance(e[4], int) else ord(e[4])
        if t == 0:
            continue
        first = struct.unpack_from("<I", e, 8)[0]
        cnt = struct.unpack_from("<I", e, 12)[0]
        if first == 0 or cnt == 0:
            continue
        out.append(dict(idx=i + 1, type=t, off=first * SECTOR,
                        size=cnt * SECTOR))
    return out


def chs(lba):
    if lba >= 1024 * 255 * 63:
        return b"\xfe\xff\xff"
    c = lba // (255 * 63)
    h = (lba // 63) % 255
    s = (lba % 63) + 1
    return struct.pack("<BBB", h, ((c >> 2) & 0xC0) | s, c & 0xFF)


def build_mbr(parts, boot_idx, disk_sectors, old_sig=None):
    m = bytearray(512)
    if old_sig and old_sig != b"\x00\x00\x00\x00":
        m[440:444] = old_sig
    else:
        m[440:444] = struct.pack("<I", 0xA1B2C3D4)
    for i, p in enumerate(parts[:4]):
        first = p["off"] // SECTOR
        cnt = p["size"] // SECTOR
        if first + cnt > disk_sectors:
            cnt = disk_sectors - first
        e = bytearray(16)
        e[0] = 0x80 if (i + 1) == boot_idx else 0x00
        e[1:4] = chs(first)
        e[4] = 0x07
        e[5:8] = chs(first + cnt - 1)
        struct.pack_into("<I", e, 8, first)
        struct.pack_into("<I", e, 12, cnt)
        m[446 + i * 16:462 + i * 16] = bytes(e)
    m[510:512] = b"\x55\xaa"
    return bytes(m)


# ---------------------------------------------------------------- manifest

def manifest_path(disk):
    return disk + MANIFEST_SUFFIX


def manifest_write(disk, entries):
    """entries = [(offset, length, backup_filename, note)]"""
    p = manifest_path(disk)
    try:
        f = open(p, "a")
        for off, ln, bak, note in entries:
            f.write("%d\t%d\t%s\t%s\t%s\n"
                    % (off, ln, os.path.basename(bak),
                       time.strftime("%Y-%m-%d %H:%M:%S"), note))
        f.close()
    except Exception as e:
        log("      (could not write manifest: %s)" % e)


def manifest_read(disk):
    p = manifest_path(disk)
    out = []
    if not os.path.exists(p):
        return out
    try:
        for line in open(p):
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 4:
                out.append(dict(off=int(parts[0]), len=int(parts[1]),
                                bak=parts[2], when=parts[3],
                                note=parts[4] if len(parts) > 4 else ""))
    except Exception:
        pass
    return out


def save_and_write(disk, off, data, tag, notes):
    """Back up the region, write new bytes, record it in the manifest."""
    old = read_at(disk, off, len(data))
    bak = disk + "." + tag + ".bak"
    try:
        g = open(bak, "wb")
        g.write(old)
        g.close()
    except Exception as e:
        return False, "could not save backup: %s" % e
    try:
        f = open(disk, "r+b")
        f.seek(off)
        f.write(data)
        f.close()
    except Exception as e:
        return False, "write failed: %s" % e
    manifest_write(disk, [(off, len(data), bak, notes)])
    return True, "wrote %d bytes at %d (old saved to %s)" % (
        len(data), off, os.path.basename(bak))


# ---------------------------------------------------------------- discovery

def find_datastores(root):
    out = []
    try:
        names = sorted(os.listdir(root))
    except OSError as e:
        log("cannot read %s: %s" % (root, e))
        return out
    seen = set()
    for n in names:
        if any(n.startswith(p) for p in SKIP_DS_PREFIX):
            continue
        p = os.path.join(root, n)
        if not os.path.isdir(p):
            continue
        try:
            real = os.path.realpath(p)
        except OSError:
            continue
        if real in seen:
            continue
        seen.add(real)
        total = free = None
        try:
            st = os.statvfs(p)
            total = st.f_frsize * st.f_blocks
            free = st.f_frsize * st.f_bavail
        except Exception:
            pass
        out.append(dict(name=n, path=p, total=total, free=free))
    return out


def find_disks(ds_path):
    """Group disk files by the VM folder that holds them."""
    vms = {}
    for dirpath, dirnames, filenames in os.walk(ds_path):
        fset = set(filenames)
        for fn in filenames:
            low = fn.lower()
            if not ("-flat.vmdk" in low or "-sesparse.vmdk" in low):
                continue
            if "-ctk." in low:
                continue
            if low.endswith(".bak") or MANIFEST_SUFFIX in low:
                continue
            if not (low.endswith(".babyk") or low.endswith(".vmdk")):
                continue
            if low.endswith(".vmdk") and (fn + ".babyk") in fset:
                continue
            vm = os.path.basename(dirpath)
            vms.setdefault(vm, dict(name=vm, dir=dirpath, disks=[]))
            vms[vm]["disks"].append(os.path.join(dirpath, fn))
    for v in vms.values():
        v["disks"].sort()
    return vms


def find_leftovers(ds_path):
    """Backup files left by earlier repair attempts."""
    out = []
    for dirpath, dirnames, filenames in os.walk(ds_path):
        for fn in filenames:
            if fn.endswith(".bak") and (".sector0" in fn or ".mbr." in fn
                                        or ".gpt-head." in fn
                                        or ".trailer." in fn):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


# ----------------------------------------------------------------- analysis

def analyse(disk, tail_mb):
    """Read-only. Returns a full picture of one disk."""
    r = dict(path=disk, actions=[], notes=[], volumes=[], verdict="",
             severity="", kind="?", busy=False)

    if busy(disk):
        r["busy"] = True
        r["verdict"] = "IN USE"
        r["severity"] = "busy"
        r["notes"].append(
            "This disk is attached to a running virtual machine. Power that "
            "machine off to inspect or repair the disk.")
        return r

    size = os.path.getsize(disk)
    r["size"] = size
    is_babyk = disk.lower().endswith(".babyk")
    r["is_babyk"] = is_babyk

    tail = size % SECTOR
    data_end = size - tail
    r["data_end"] = data_end
    r["tail_bytes"] = tail

    if tail:
        n = tail // 32 if tail % 32 == 0 else 0
        r["trailer_hex"] = hexs(read_at(disk, data_end, min(tail, 32)))
        if n > 1:
            r["notes"].append(
                "%d bytes of ransomware trailer are present, which is %d "
                "separate trailers -- this file was encrypted %d times."
                % (tail, n, n))
        else:
            r["notes"].append(
                "%d bytes of ransomware trailer are present." % tail)
        desc = "trim %d trailing byte(s) so the disk is a whole number of sectors" % tail
        if is_babyk:
            desc += ", and rename the file back to .vmdk"
        r["actions"].append(("trailer", desc))
    elif is_babyk:
        r["actions"].append(("trailer", "rename the file back to .vmdk"))

    if data_end <= DAMAGE:
        r["kind"] = "small"
        r["verdict"] = "TOTAL LOSS"
        r["severity"] = "loss"
        r["actions"] = []
        r["notes"].append(
            "The whole file (%s) fits inside the %s the ransomware "
            "overwrote. Nothing survives in it."
            % (human(data_end), human(DAMAGE)))
        return r

    r["intact"] = data_end - DAMAGE

    # -- partition tables currently present
    mbr = read_mbr(disk)
    ghdr, garr, gparts = read_gpt(disk, data_end, "backup")
    phdr, parr, pparts = read_gpt(disk, data_end, "primary")
    r["has_mbr"] = bool(mbr)
    r["has_primary_gpt"] = phdr is not None
    r["has_backup_gpt"] = ghdr is not None

    # -- find real volumes, verified by $MFT
    hits = scan_ntfs(disk, data_end, tail_mb)
    cands = []
    for off, b in hits:
        good, moff, mirr = mft_alive(disk, off, b)
        if good >= 4:
            cands.append(dict(start=off, size=b["vol_bytes"], bpb=b,
                              mft=moff, records=good, mirr=mirr,
                              how="its own boot sector is in place",
                              backup=None))
        implied = off - b["total"] * b["bps"]
        if 0 <= implied < off:
            good2, moff2, mirr2 = mft_alive(disk, implied, b)
            if good2 >= 4:
                already = parse_bpb(read_at(disk, implied, 512)) is not None
                cands.append(dict(start=implied, size=b["vol_bytes"], bpb=b,
                                  mft=moff2, records=good2, mirr=mirr2,
                                  how=("its own boot sector is in place"
                                       if already else
                                       "recovered from the backup copy at %d" % off),
                                  backup=off, needs_boot=not already))

    # smallest size wins at a given start: a bigger twin is a stale leftover
    cands.sort(key=lambda c: (c["start"], c["size"]))
    bystart = {}
    for c in cands:
        if c["start"] not in bystart:
            bystart[c["start"]] = c
        else:
            keep0 = bystart[c["start"]]
            if c["size"] != keep0["size"]:
                keep0.setdefault("alt_sizes", []).append(c["size"])
    vols = sorted(bystart.values(), key=lambda c: c["start"])

    # drop volumes contained inside another
    keep = []
    for c in vols:
        inside = False
        for k in keep:
            if c["start"] >= k["start"] and \
               c["start"] + c["size"] <= k["start"] + k["size"]:
                inside = True
                break
        if not inside:
            keep.append(c)
    vols = keep
    for i, v in enumerate(vols, 1):
        v["idx"] = i
    r["volumes"] = vols

    if ghdr is not None:
        r["kind"] = "GPT"
        r["notes"].append(
            "A backup GPT survives at the end of the disk, so the exact "
            "partition layout is known.")
        if phdr is None:
            r["actions"].append((
                "gpt",
                "rebuild the protective MBR and the primary GPT at the start "
                "of the disk from the surviving backup GPT"))
    else:
        r["kind"] = "MBR"
        if not mbr:
            r["notes"].append(
                "There is no partition table at sector 0 -- it was inside the "
                "destroyed region. Without it Windows sees the disk as "
                "unallocated even though the filesystem is fine.")

    # boot sectors that need restoring
    for v in vols:
        if v.get("needs_boot"):
            r["actions"].append((
                "boot:%d" % v["idx"],
                "restore the NTFS boot sector of the %s volume at %d from its "
                "surviving backup copy at %d"
                % (human(v["size"]), v["start"], v["backup"])))

    # MBR rebuild when there is no GPT
    if ghdr is None and vols:
        need = (not mbr) or \
               (not any(abs(m["off"] - v["start"]) <= SECTOR
                        for m in (mbr or []) for v in vols))
        if need:
            r["actions"].append((
                "mbr",
                "rebuild the partition table at sector 0 so the volumes "
                "become visible"))

    if not vols:
        r["verdict"] = "NEEDS MANUAL WORK"
        r["severity"] = "manual"
        r["notes"].append(
            "No NTFS volume with a readable $MFT was found. This guest is "
            "probably not Windows, or its file index did not survive. "
            "Recover it with a carving tool such as R-Studio.")
    elif any(a[0] != "trailer" for a in r["actions"]):
        r["verdict"] = "REPAIRABLE"
        r["severity"] = "fix"
    elif r["actions"]:
        r["verdict"] = "NEEDS TIDYING"
        r["severity"] = "fix"
    else:
        r["verdict"] = "READY"
        r["severity"] = "ok"
    return r


# ------------------------------------------------------------------ descriptor

DESC = '''# Disk DescriptorFile
version=1
encoding="UTF-8"
CID=fffffffe
parentCID=ffffffff
createType="vmfs"

# Extent description
RW %(sectors)d VMFS "%(flat)s"

# The Disk Data Base
#DDB

ddb.adapterType = "%(adapter)s"
ddb.geometry.cylinders = "%(cyl)d"
ddb.geometry.heads = "255"
ddb.geometry.sectors = "63"
ddb.virtualHWVersion = "11"
'''


def descriptor_for(flat):
    base = flat
    for suf in ("-flat.vmdk", "-sesparse.vmdk"):
        if base.lower().endswith(suf):
            return base[:-len(suf)] + ".vmdk"
    return None


def write_descriptor(flat, adapter="lsilogic"):
    d = descriptor_for(flat)
    if not d:
        return None
    size = os.path.getsize(flat)
    sectors = size // SECTOR
    text = DESC % dict(sectors=sectors, flat=os.path.basename(flat),
                       adapter=adapter, cyl=sectors // (255 * 63))
    f = open(d, "w")
    f.write(text)
    f.close()
    return d


# ---------------------------------------------------------------------- repair

def repair(r, adapter="lsilogic"):
    msgs = []
    disk = r["path"]
    data_end = r["data_end"]

    # 1. trailer + rename
    if r.get("tail_bytes"):
        try:
            raw = read_at(disk, data_end, r["tail_bytes"])
            g = open(disk + ".trailer.bak", "wb")
            g.write(raw)
            g.close()
            f = open(disk, "r+b")
            f.truncate(data_end)
            f.close()
            manifest_write(disk, [(data_end, r["tail_bytes"],
                                   disk + ".trailer.bak", "trailer trimmed")])
            msgs.append("trimmed %d trailing byte(s): %d -> %d"
                        % (r["tail_bytes"], r["size"], data_end))
        except Exception as e:
            msgs.append("could not trim trailer: %s" % e)
            return msgs
    if disk.lower().endswith(".babyk"):
        newp = disk[:-6]
        if os.path.exists(newp):
            msgs.append("cannot rename: %s already exists"
                        % os.path.basename(newp))
        else:
            try:
                os.rename(disk, newp)
                mp = manifest_path(disk)
                if os.path.exists(mp):
                    os.rename(mp, manifest_path(newp))
                msgs.append("renamed to %s" % os.path.basename(newp))
                disk = newp
            except Exception as e:
                msgs.append("rename failed: %s" % e)
    r["final"] = disk

    keys = [a[0] for a in r["actions"]]

    # 2. boot sectors -- re-verify $MFT right before writing
    for v in r["volumes"]:
        if ("boot:%d" % v["idx"]) not in keys:
            continue
        sec = read_at(disk, v["backup"], SECTOR)
        b = parse_bpb(sec)
        if b is None:
            msgs.append("volume %d: backup boot sector no longer valid, skipped"
                        % v["idx"])
            continue
        good, _o, _m = mft_alive(disk, v["start"], b)
        if good < 4:
            msgs.append("volume %d: $MFT check failed just before writing "
                        "(%d/8) -- refused, nothing written" % (v["idx"], good))
            continue
        ok, m = save_and_write(disk, v["start"], sec,
                               "vol%d.bootsector" % v["idx"],
                               "NTFS boot sector restored from %d" % v["backup"])
        msgs.append("volume %d: %s" % (v["idx"], m))

    # 3. partition table
    disk_sectors = os.path.getsize(disk) // SECTOR
    if "gpt" in keys:
        ghdr, garr, gparts = read_gpt(disk, os.path.getsize(disk), "backup")
        if ghdr:
            mbr, phdr, parr = build_primary_gpt(ghdr, garr, disk_sectors)
            blob = mbr + phdr + parr
            ok, m = save_and_write(disk, 0, blob, "gpthead",
                                   "protective MBR + primary GPT rebuilt")
            msgs.append(m)
    elif "mbr" in keys:
        old = read_at(disk, 0, 512)
        sig = old[440:444] if len(old) >= 444 else None
        parts = [dict(off=v["start"], size=v["size"]) for v in r["volumes"]]
        parts.sort(key=lambda p: p["off"])
        boot_idx = 1
        big = max(range(len(parts)), key=lambda i: parts[i]["size"])
        boot_idx = big + 1
        newmbr = build_mbr(parts, boot_idx, disk_sectors, sig)
        ok, m = save_and_write(disk, 0, newmbr, "mbr",
                               "partition table rebuilt from %d volume(s)"
                               % len(parts))
        msgs.append(m)

    # 4. descriptor
    d = descriptor_for(disk)
    if d:
        enc = d + ".babyk"
        if os.path.exists(d):
            msgs.append("descriptor already present, left alone")
        else:
            try:
                if os.path.exists(enc):
                    os.remove(enc)
                w = write_descriptor(disk, adapter)
                msgs.append("descriptor regenerated: %s" % os.path.basename(w))
            except Exception as e:
                msgs.append("descriptor could not be written: %s" % e)
    return msgs


def verify(r):
    disk = r.get("final", r["path"])
    out = []
    ok = True
    size = os.path.getsize(disk)
    if size % SECTOR:
        out.append("size is still not sector aligned (%d spare bytes)"
                   % (size % SECTOR))
        ok = False
    else:
        out.append("size is a whole number of sectors")

    for v in r["volumes"]:
        b = parse_bpb(read_at(disk, v["start"], SECTOR))
        if b is None:
            out.append("volume at %s: boot sector still missing"
                       % human(v["start"]))
            ok = False
            continue
        good, _o, _m = mft_alive(disk, v["start"], b)
        out.append("volume at %s: boot sector valid, $MFT %d/8 records"
                   % (human(v["start"]), good))
        if good < 4:
            ok = False

    mbr = read_mbr(disk)
    phdr, _a, _p = read_gpt(disk, size, "primary")
    if phdr:
        out.append("primary GPT reads back correctly")
    elif mbr:
        out.append("partition table at sector 0 lists %d partition(s)"
                   % len(mbr))
    else:
        out.append("still no partition table at sector 0")
        ok = False
    return ok, out


# ----------------------------------------------------------------- rollback

def rollback(disks):
    log("")
    rule("=")
    log("STEP 2   Earlier repair attempts")
    rule("=")
    log("")
    found = []
    seen = set()
    for d in disks:
        base = d[:-6] if d.lower().endswith(".babyk") else d
        for cand in (base, d):
            if not os.path.exists(cand):
                continue
            for e in manifest_read(cand):
                key = (os.path.realpath(cand), e["off"], e["len"], e["bak"])
                if key in seen:
                    continue
                seen.add(key)
                bak = os.path.join(os.path.dirname(cand), e["bak"])
                if os.path.exists(bak):
                    found.append((cand, e, bak))
    if not found:
        log("  No manifest from an earlier run of this tool was found.")
        legacy = []
        for d in disks:
            base = d[:-6] if d.lower().endswith(".babyk") else d
            for suf in (".mbr.bak", ".gpt-head.bak", ".sector0.bak",
                        ".trailer.bak", ".part1.sector0.bak"):
                p = base + suf
                if os.path.exists(p):
                    legacy.append(p)
        if legacy:
            log("")
            log("  However these backup files from older tools are present:")
            for p in legacy:
                log("    %s  (%d bytes)" % (os.path.basename(p),
                                            os.path.getsize(p)))
            log("")
            log("  They record only the bytes that were replaced, not where.")
            log("  The scan below re-derives everything from the disk itself,")
            log("  so they are not needed; they are left untouched.")
        log("")
        return

    log("  Changes made by an earlier run of this tool:")
    log("")
    for disk, e, bak in found:
        log("    %s" % os.path.basename(disk))
        log("      %s at offset %d, %d byte(s)   [%s]"
            % (e["note"] or "change", e["off"], e["len"], e["when"]))
    log("")
    log("  Rolling back puts those exact bytes back and undoes the repair.")
    log("  Only do this if a previous attempt made things worse.")
    log("")
    a = ask("  Roll any of these back?", ["y", "n"], "n")
    if a != "y":
        log("  Leaving them in place.")
        log("")
        return

    for disk, e, bak in found:
        log("")
        log("  %s" % os.path.basename(disk))
        log("    %s at %d (%d bytes)" % (e["note"] or "change", e["off"], e["len"]))
        c = ask("    restore this one?", ["y", "n", "q"], "n")
        if c == "q":
            break
        if c != "y":
            continue
        if busy(disk):
            log("    disk is in use by a running VM -- skipped")
            continue
        try:
            data = open(bak, "rb").read()
            f = open(disk, "r+b")
            f.seek(e["off"])
            f.write(data)
            f.close()
            log("    restored %d bytes at %d" % (len(data), e["off"]))
        except Exception as ex:
            log("    restore failed: %s" % ex)
    log("")


# -------------------------------------------------------------------- report

def show(r, n, total, vmname):
    rule("=")
    log("[%d/%d]  %s" % (n, total, vmname))
    log("        %s" % os.path.basename(r["path"]))
    rule("=")
    log("")
    if r.get("busy"):
        for t in r["notes"]:
            log("  %s" % t)
        log("")
        log("  VERDICT: %s" % r["verdict"])
        log("")
        return

    log("  size          : %s" % human(r["size"]))
    log("  table type    : %s" % r["kind"])
    if r.get("trailer_hex"):
        log("  trailer bytes : %s..." % r["trailer_hex"][:32])
    if "intact" in r:
        pct = 100.0 * r["intact"] / r["data_end"]
        log("  destroyed     : first %s" % human(min(DAMAGE, r["data_end"])))
        log("  untouched     : %s  (%.2f%% of the disk)"
            % (human(r["intact"]), pct))
    log("")
    for t in r["notes"]:
        log("  * %s" % t)
    if r["notes"]:
        log("")

    if r["volumes"]:
        log("  VOLUMES FOUND (each confirmed by reading its $MFT):")
        for v in r["volumes"]:
            log("")
            log("    [%d] starts at %d (%s), %s"
                % (v["idx"], v["start"], human(v["start"]), human(v["size"])))
            log("        $MFT at %s -- %d of 8 records valid%s"
                % (human(v["mft"]), v["records"],
                   ", $MFTMirr also valid" if v.get("mirr") else ""))
            log("        %s" % v["how"])
            alts = [s for s in v.get("alt_sizes", []) if s != v["size"]]
            if alts:
                log("        (ignored a stale copy of this volume claiming %s"
                    % ", ".join(human(s) for s in alts))
                log("         -- trusting it would overlap the next partition)")
        log("")

    log("  VERDICT: %s" % r["verdict"])
    log("")
    if r["actions"]:
        log("  WHAT I PROPOSE TO DO:")
        for i, (k, d) in enumerate(r["actions"], 1):
            log("    %d. %s" % (i, d))
        log("")
        log("  Every byte replaced is saved first and recorded so it can be")
        log("  rolled back exactly.")
    else:
        if r["severity"] == "ok":
            log("  Nothing to do -- this disk is already in working order.")
        elif r["severity"] == "loss":
            log("  Nothing can be recovered from this file.")
        else:
            log("  No safe automatic repair exists for this disk.")
    log("")


def next_steps(results):
    rule("=")
    log("WHAT TO DO NEXT")
    rule("=")
    log("")
    fixed = [r for r in results if r.get("done")]
    if fixed:
        log("  For each machine you repaired:")
        log("")
        log("  1. Register it if it is not in the inventory:")
        log("       vim-cmd solo/registervm \"/vmfs/volumes/<ds>/<VM>/<VM>.vmx\"")
        log("")
        log("  2. Power it on:")
        log("       vim-cmd vmsvc/power.on <VMID>")
        log("")
        log("  3. If a volume shows as RAW in Windows, that is expected --")
        log("     run this once from a Windows PE command prompt:")
        log("       chkdsk <letter>: /f")
        log("")
        log("  4. If the machine will not boot at all, its System Reserved")
        log("     partition was inside the destroyed region, so the boot")
        log("     files are gone. The data is still fine. Either:")
        log("       - attach the disk as a SECOND disk to a working Windows")
        log("         VM and copy the data off, or")
        log("       - boot the Windows installer ISO, open Command Prompt,")
        log("         give the system volume a letter with diskpart, then:")
        log("           bcdboot C:\\Windows /s C: /f BIOS")
        log("         (use /f UEFI on a GPT disk)")
        log("")
    manual = [r for r in results if r.get("severity") == "manual"]
    if manual:
        log("  These need a carving tool (R-Studio, photorec) instead:")
        for r in manual:
            log("    %s" % r["path"])
        log("")
    busyl = [r for r in results if r.get("busy")]
    if busyl:
        log("  These were skipped because a VM is running on them.")
        log("  Power the VM off and run this tool again:")
        for r in busyl:
            log("    %s" % r["path"])
        log("")


# ----------------------------------------------------------- environment

def run_cmd(cmd):
    """Run a shell command, return its first line of output, or ''."""
    try:
        import subprocess
        try:
            out = subprocess.check_output(cmd, shell=True,
                                          stderr=subprocess.STDOUT)
        except Exception:
            return ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "ignore")
        for line in out.splitlines():
            line = line.strip()
            if line:
                return line
        return ""
    except Exception:
        return ""


def find_pythons():
    """List every python interpreter on the box, with its version."""
    found = []
    seen = set()
    dirs = ("/bin", "/usr/bin", "/usr/lib/vmware/site-packages/../../bin")
    names = ("python", "python3", "python3.5", "python3.8", "python3.9",
             "python3.10", "python3.11", "python3.12")
    for d in dirs:
        for n in names:
            p = os.path.join(d, n)
            try:
                if not os.path.exists(p):
                    continue
                real = os.path.realpath(p)
            except Exception:
                continue
            if real in seen:
                continue
            seen.add(real)
            v = run_cmd("%s -c 'import sys;print(\"%%d.%%d\" %% sys.version_info[:2])' 2>&1" % p)
            found.append((p, v or "?"))
    return found


def environment_check():
    """STEP 0 -- show what we are running on and confirm it will work."""
    rule("=")
    log("STEP 0   Environment")
    rule("=")
    log("")

    # -- ESXi version
    ver = run_cmd("vmware -v")
    if not ver:
        ver = run_cmd("esxcli system version get | grep -i version")
    build = run_cmd("esxcli system version get | grep -i build")
    host = run_cmd("hostname")

    if ver:
        log("  ESXi          : %s" % ver)
    else:
        log("  ESXi          : not detected (are we on an ESXi host?)")
    if build:
        log("  %s" % build.strip())
    if host:
        log("  host name     : %s" % host)

    # -- python actually running us
    pv = "%d.%d.%d" % sys.version_info[:3]
    log("  running python: %s   (%s)" % (pv, sys.executable or "?"))

    ok = True
    if sys.version_info[0] == 3 and sys.version_info[1] < 5:
        log("")
        log("  WARNING: this tool is written for Python 3.5 or newer.")
        ok = False

    # -- other interpreters available
    others = find_pythons()
    if others:
        log("")
        log("  interpreters found on this host:")
        for p, v in others:
            mark = "  <- currently running" if os.path.realpath(p) == \
                   os.path.realpath(sys.executable or "") else ""
            log("    %-24s python %s%s" % (p, v, mark))

    # -- capability probes, so surprises show up here and not mid-repair
    log("")
    log("  capability check:")
    caps_ok = True
    try:
        import zlib
        zlib.crc32(b"x")
        log("    zlib (GPT checksums)          : available")
    except Exception:
        try:
            import binascii
            binascii.crc32(b"x")
            log("    zlib missing, binascii used   : available")
        except Exception:
            log("    CRC32 support                 : MISSING -- GPT rebuild "
                "will not work")
            caps_ok = False
    try:
        struct.unpack_from("<Q", b"\x00" * 8, 0)
        log("    struct 64-bit unpack          : available")
    except Exception:
        log("    struct 64-bit unpack          : MISSING")
        caps_ok = False
    try:
        os.statvfs("/")
        log("    statvfs (datastore sizes)     : available")
    except Exception:
        log("    statvfs                       : not available "
            "(sizes will show blank, harmless)")

    log("")
    if not ok or not caps_ok:
        log("  Something above is not right. Continuing may fail.")
        c = ask("  Continue anyway?", ["y", "q"], "q")
        if c != "y":
            return False
    else:
        log("  This host can run every part of the tool.")
    log("")
    return True


# ---------------------------------------------------------------------- main

def main():
    a = sys.argv[1:]

    def opt(name, cast=str, default=None):
        if name in a:
            i = a.index(name)
            if i + 1 < len(a):
                return cast(a[i + 1])
        return default

    if "-h" in a or "--help" in a:
        print(__doc__)
        return

    root = opt("--root", str, "/vmfs/volumes")
    logpath = opt("--log", str, "/tmp/babuk_recover.log")
    tail_mb = opt("--tail", int, 2048)
    adapter = opt("--adapter", str, "lsilogic")

    try:
        LOG[0] = open(logpath, "a")
        LOG[0].write("\n\n===== run %s =====\n"
                     % time.strftime("%Y-%m-%d %H:%M:%S"))
    except Exception:
        LOG[0] = None

    rule("=")
    log("BABUK RECOVERY")
    rule("=")
    log("")
    log("The ransomware overwrote the first %s of each disk it touched and"
        % human(DAMAGE))
    log("appended a short trailer. Everything past that point is original.")
    log("This tool finds what survived, explains each case, and asks before")
    log("changing anything.")
    log("")
    log("Log file: %s" % logpath)
    log("")

    # ---- step 0: environment
    if "--skip-env" not in a:
        if not environment_check():
            log("Stopped at the environment check. Nothing was changed.")
            return

    # ---- step 1: datastores and disks
    rule("=")
    log("STEP 1   Datastores and disks")
    rule("=")
    log("")
    ds = find_datastores(root)
    if not ds:
        log("No datastores found under %s" % root)
        return
    for d in ds:
        log("  %-38s %s" % (d["name"],
                            human(d["total"]) if d["total"] else ""))
    log("")

    allvms = {}
    for d in ds:
        for name, vm in find_disks(d["path"]).items():
            key = d["name"] + "/" + name
            vm["ds"] = d["name"]
            allvms[key] = vm

    if not allvms:
        log("No virtual disks found. If you expected some, check the path.")
        return

    log("  Virtual machines with disks on these datastores:")
    log("")
    for k in sorted(allvms):
        vm = allvms[k]
        tot = 0
        for p in vm["disks"]:
            try:
                tot += os.path.getsize(p)
            except OSError:
                pass
        log("    %-46s %d disk(s)  %s" % (k, len(vm["disks"]), human(tot)))
    log("")

    alldisks = []
    for k in sorted(allvms):
        alldisks.extend(allvms[k]["disks"])

    # ---- step 2: previous attempts
    rollback(alldisks)

    # ---- step 3: scan
    rule("=")
    log("STEP 3   Scanning")
    rule("=")
    log("")
    log("  Reading each disk. Nothing is written in this step.")
    log("")
    results = {}
    for k in sorted(allvms):
        vm = allvms[k]
        for p in vm["disks"]:
            log("  scanning %s ..." % os.path.basename(p))
            sys.stdout.flush()
            try:
                results[p] = analyse(p, tail_mb)
            except Exception as e:
                results[p] = dict(path=p, verdict="ERROR", severity="manual",
                                  notes=["scan failed: %s" % e], actions=[],
                                  volumes=[], busy=False)
    log("")

    # ---- step 4: overview
    rule("=")
    log("STEP 4   What was found")
    rule("=")
    log("")
    log("  %-46s %s" % ("machine / disk", "verdict"))
    rule("-")
    for k in sorted(allvms):
        for p in allvms[k]["disks"]:
            r = results[p]
            log("  %-46s %s" % (os.path.basename(p)[:46], r["verdict"]))
    log("")

    # ---- step 5: per machine
    rule("=")
    log("STEP 5   Machine by machine")
    rule("=")
    log("")
    log("  For each machine:  y = repair it   n = skip it")
    log("                     a = repair this and every remaining one")
    log("                     q = stop")
    log("")

    auto = False
    order = sorted(allvms)
    for i, k in enumerate(order, 1):
        vm = allvms[k]
        rule("#")
        log("MACHINE %d of %d:  %s" % (i, len(order), k))
        rule("#")
        log("")

        actionable = []
        for j, p in enumerate(vm["disks"], 1):
            r = results[p]
            show(r, j, len(vm["disks"]), k)
            if r.get("actions") and not r.get("busy"):
                actionable.append(r)

        if not actionable:
            log("  Nothing to do for this machine.")
            log("")
            continue

        if auto:
            choice = "y"
            log("  (repairing every remaining machine)")
        else:
            choice = ask("  Repair this machine now?", ["y", "n", "a", "q"], "n")
            if choice == "a":
                auto = True
                choice = "y"
            elif choice == "q":
                log("")
                log("  Stopped at your request. Nothing further was changed.")
                break
        if choice != "y":
            log("  skipped.")
            log("")
            continue

        for r in actionable:
            log("")
            log("  working on %s ..." % os.path.basename(r["path"]))
            try:
                for m in repair(r, adapter):
                    log("    - %s" % m)
            except Exception as e:
                log("    repair failed: %s" % e)
                continue
            ok, vmsgs = verify(r)
            log("")
            log("    verification:")
            for m in vmsgs:
                log("      %s" % m)
            if ok:
                r["done"] = True
                log("    RESULT: this disk is now in working order.")
            else:
                log("    RESULT: partially repaired, see the warnings above.")
        log("")

    # ---- step 6: summary
    log("")
    rule("=")
    log("SUMMARY")
    rule("=")
    log("")
    done = [r for r in results.values() if r.get("done")]
    ready = [r for r in results.values()
             if r.get("severity") == "ok" and not r.get("done")]
    manual = [r for r in results.values() if r.get("severity") == "manual"]
    loss = [r for r in results.values() if r.get("severity") == "loss"]
    busyl = [r for r in results.values() if r.get("busy")]
    log("  repaired in this run : %d" % len(done))
    log("  already in order     : %d" % len(ready))
    log("  need manual recovery : %d" % len(manual))
    log("  unrecoverable        : %d" % len(loss))
    log("  skipped, VM running  : %d" % len(busyl))
    log("")
    if done or ready:
        log("  USABLE DISKS:")
        for r in done + ready:
            log("    %s" % r.get("final", r["path"]))
        log("")

    next_steps(list(results.values()))

    log("  Full log: %s" % logpath)
    log("  Running this tool again is safe.")
    rule("=")
    if LOG[0]:
        LOG[0].close()


main()

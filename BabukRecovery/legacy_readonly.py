# Verbatim read-only/build helpers extracted from the production reference.
# No legacy repair, descriptor writer, rollback, or main is imported.
import os
import sys
import struct
import time
SECTOR = 512
DAMAGE = 520 * 1024 * 1024
MANIFEST_SUFFIX = ".babuk-manifest"
SKIP_DS_PREFIX = ("BOOTBANK", "OSDATA", "esx-", ".vSphere", "vmkdump", "scratch", ".locker")
LOG = [None]
def log(msg=""):
    print(msg)
def human(x):
    x = float(x)
    for u in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(x) < 1024.0:
            return "%.2f %s" % (x, u)
        x /= 1024.0
    return "%.2f EiB" % x


def hexs(b):
    return "".join("%02x" % (c if isinstance(c, int) else ord(c)) for c in b)


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


def _crc32(b):
    try:
        import zlib
        return zlib.crc32(b) & 0xFFFFFFFF
    except ImportError:
        import binascii
        return binascii.crc32(b) & 0xFFFFFFFF


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

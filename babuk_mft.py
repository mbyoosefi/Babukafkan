r"""
babuk_mft.py -- Read NTFS directly from a Babuk-damaged image, without mounting.

Parses the boot sector, walks $MFT, resolves full paths, and reports whether
each file's data actually survived the encrypted region. Can extract files
byte-for-byte straight out of the image.

This matters because mounting a repaired volume can fail for unrelated
reasons, and Windows may try to "fix" things. Reading the MFT directly proves
what is recoverable before you touch anything.

USAGE
  py babuk_mft.py info    <image> <part_offset>
        boot sector + $MFT geometry, and whether $MFT survived

  py babuk_mft.py find    <image> <part_offset> <substring> [--max N]
        search all filenames for a substring (case-insensitive)

  py babuk_mft.py ad      <image> <part_offset>
        locate the Active Directory files (ntds.dit, logs, SYSTEM hive)
        and report byte-level damage overlap for each

  py babuk_mft.py dump    <image> <part_offset> <out.csv>
        walk the MFT ONCE and write a complete inventory of every file:
        full path, size, extent count, and exact damaged byte count.
        Do this instead of repeated slow searches.

  py babuk_mft.py extract <image> <part_offset> <mft_ref> <outfile>
        extract one file by its MFT record number

EXAMPLE
  py babuk_mft.py ad "D:\rec\AD.img" 368050176
"""

import os
import sys
import struct

BLOCK = 10 * 1024 * 1024
_w = 0
while True:
    _w += BLOCK
    if not (_w < 0x20000000):
        break
DAMAGE_END = _w              # 545,259,520

FILE_SIG = b"FILE"

ATTR_STANDARD_INFO = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90


def human(x):
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(x) < 1024:
            return f"{x:.2f} {u}"
        x /= 1024
    return f"{x:.2f} PiB"


class NTFS:
    def __init__(self, path, part_off):
        self.path = path
        self.base = part_off
        self.f = open(path, "rb")
        self._read_boot()
        self._read_mft_map()

    def _read_boot(self):
        self.f.seek(self.base)
        b = self.f.read(512)
        if b[3:11] != b"NTFS    ":
            raise RuntimeError(
                f"No NTFS boot sector at offset {self.base}. "
                "Run babuk_ntfs.py repair first.")
        self.bps = struct.unpack("<H", b[11:13])[0]
        self.spc = b[13]
        self.total_sectors = struct.unpack("<Q", b[40:48])[0]
        self.mft_cluster = struct.unpack("<Q", b[48:56])[0]
        self.mftmirr_cluster = struct.unpack("<Q", b[56:64])[0]
        self.cluster = self.bps * self.spc

        raw = struct.unpack("<b", b[64:65])[0]
        if raw > 0:
            self.rec_size = raw * self.cluster
        else:
            self.rec_size = 1 << (-raw)

        self.mft_off = self.base + self.mft_cluster * self.cluster

    def _decode_runs(self, data, start):
        """Decode an NTFS data-run list into [(lcn, length_in_clusters)]."""
        runs = []
        i = start
        lcn = 0
        while i < len(data):
            hdr = data[i]
            if hdr == 0:
                break
            lenb = hdr & 0x0F
            offb = (hdr >> 4) & 0x0F
            i += 1
            if lenb == 0 or i + lenb + offb > len(data):
                break
            length = int.from_bytes(data[i:i + lenb], "little", signed=False)
            i += lenb
            if offb:
                delta = int.from_bytes(data[i:i + offb], "little", signed=True)
                i += offb
                lcn += delta
                runs.append((lcn, length))
            else:
                runs.append((None, length))   # sparse
            if offb == 0:
                pass
        return runs

    def _fixup(self, rec):
        """Apply NTFS update-sequence-array fixups."""
        if len(rec) < 48 or rec[0:4] != FILE_SIG:
            return rec
        usa_off = struct.unpack("<H", rec[4:6])[0]
        usa_cnt = struct.unpack("<H", rec[6:8])[0]
        if usa_cnt == 0 or usa_off + usa_cnt * 2 > len(rec):
            return rec
        rec = bytearray(rec)
        usn = rec[usa_off:usa_off + 2]
        for i in range(1, usa_cnt):
            pos = i * self.bps - 2
            if pos + 2 > len(rec):
                break
            fix = rec[usa_off + i * 2: usa_off + i * 2 + 2]
            if bytes(rec[pos:pos + 2]) != bytes(usn):
                pass  # mismatch tolerated; damaged image
            rec[pos:pos + 2] = fix
        return bytes(rec)

    def _read_mft_map(self):
        """Read $MFT's own record to get the full MFT extent list."""
        self.f.seek(self.mft_off)
        rec = self._fixup(self.f.read(max(self.rec_size, 1024)))
        self.mft_runs = None
        for a in self._attrs(rec):
            if a["type"] == ATTR_DATA and not a["resident"]:
                self.mft_runs = a["runs"]
                self.mft_alloc = a["alloc"]
                break
        if not self.mft_runs:
            # fall back: assume MFT is contiguous from its start cluster
            self.mft_runs = [(self.mft_cluster, 1 << 20)]
            self.mft_alloc = None

    def _attrs(self, rec):
        """Yield parsed attributes from an MFT record."""
        if len(rec) < 56 or rec[0:4] != FILE_SIG:
            return
        first = struct.unpack("<H", rec[20:22])[0]
        off = first
        while off + 24 <= len(rec):
            atype = struct.unpack("<I", rec[off:off + 4])[0]
            if atype == 0xFFFFFFFF:
                break
            alen = struct.unpack("<I", rec[off + 4:off + 8])[0]
            if alen == 0 or off + alen > len(rec):
                break
            nonres = rec[off + 8]
            out = dict(type=atype, resident=(nonres == 0), off=off, len=alen,
                       runs=[], alloc=None, real=None, content=b"")
            if nonres == 0:
                clen = struct.unpack("<I", rec[off + 16:off + 20])[0]
                coff = struct.unpack("<H", rec[off + 20:off + 22])[0]
                out["content"] = rec[off + coff: off + coff + clen]
            else:
                out["alloc"] = struct.unpack("<Q", rec[off + 40:off + 48])[0]
                out["real"] = struct.unpack("<Q", rec[off + 48:off + 56])[0]
                roff = struct.unpack("<H", rec[off + 32:off + 34])[0]
                out["runs"] = self._decode_runs(rec, off + roff)
            yield out
            off += alen

    def mft_record_offset(self, n):
        """Map MFT record number -> absolute byte offset via the run list."""
        target = n * self.rec_size
        seen = 0
        for lcn, cnt in self.mft_runs:
            span = cnt * self.cluster
            if lcn is None:
                seen += span
                continue
            if seen + span > target:
                return self.base + lcn * self.cluster + (target - seen)
            seen += span
        return None

    def read_record(self, n):
        off = self.mft_record_offset(n)
        if off is None:
            return None
        self.f.seek(off)
        rec = self.f.read(self.rec_size)
        if len(rec) < 48 or rec[0:4] != FILE_SIG:
            return None
        return self._fixup(rec)

    def record_count(self):
        total = 0
        for lcn, cnt in self.mft_runs:
            total += cnt * self.cluster
        return total // self.rec_size

    def names(self, rec):
        """Return list of (parent_ref, name, namespace)."""
        out = []
        for a in self._attrs(rec):
            if a["type"] != ATTR_FILE_NAME or not a["resident"]:
                continue
            c = a["content"]
            if len(c) < 66:
                continue
            parent = struct.unpack("<Q", c[0:8])[0] & 0x0000FFFFFFFFFFFF
            nlen = c[64]
            ns = c[65]
            nm = c[66:66 + nlen * 2].decode("utf-16-le", "ignore")
            out.append((parent, nm, ns))
        return out

    def is_dir(self, rec):
        flags = struct.unpack("<H", rec[22:24])[0]
        return bool(flags & 0x0002)

    def in_use(self, rec):
        flags = struct.unpack("<H", rec[22:24])[0]
        return bool(flags & 0x0001)

    def data_attr(self, rec):
        """Return the unnamed $DATA attribute."""
        for a in self._attrs(rec):
            if a["type"] != ATTR_DATA:
                continue
            # check for a name (named streams are ADS -- skip)
            nlen = rec[a["off"] + 9]
            if nlen != 0:
                continue
            return a
        return None

    def data_extents(self, a):
        """Absolute byte extents of a non-resident $DATA attribute."""
        ext = []
        for lcn, cnt in a["runs"]:
            if lcn is None:
                continue
            ext.append((self.base + lcn * self.cluster, cnt * self.cluster))
        return ext

    def extract(self, n, outpath):
        rec = self.read_record(n)
        if rec is None:
            raise RuntimeError(f"MFT record {n} unreadable")
        a = self.data_attr(rec)
        if a is None:
            raise RuntimeError("no unnamed $DATA attribute")
        if a["resident"]:
            with open(outpath, "wb") as o:
                o.write(a["content"])
            return len(a["content"]), 0

        size = a["real"]
        written = 0
        damaged = 0
        with open(outpath, "wb") as o:
            for lcn, cnt in a["runs"]:
                span = cnt * self.cluster
                if lcn is None:
                    n2 = min(span, size - written)
                    o.write(b"\x00" * n2)
                    written += n2
                    continue
                start = self.base + lcn * self.cluster
                if start < DAMAGE_END:
                    damaged += min(span, max(0, DAMAGE_END - start))
                remaining = span
                pos = start
                while remaining > 0 and written < size:
                    chunk = min(1 << 20, remaining, size - written)
                    self.f.seek(pos)
                    buf = self.f.read(chunk)
                    if len(buf) < chunk:
                        buf += b"\x00" * (chunk - len(buf))
                    o.write(buf)
                    pos += chunk
                    remaining -= chunk
                    written += chunk
        return written, damaged


def build_paths(fs, limit=None):
    """Walk the MFT and return {ref: (name, parent)} for in-use records."""
    total = fs.record_count()
    if limit:
        total = min(total, limit)
    ents = {}
    print(f"  walking {total:,} MFT records ...")
    step = max(1, total // 20)
    for n in range(total):
        if n % step == 0 and n:
            print(f"    {100*n//total}%")
        rec = fs.read_record(n)
        if rec is None or not fs.in_use(rec):
            continue
        nms = fs.names(rec)
        if not nms:
            continue
        # prefer Win32 namespace (1) or Win32+DOS (3) over DOS (2)
        nms.sort(key=lambda t: 0 if t[2] in (1, 3) else 1)
        parent, name, _ = nms[0]
        ents[n] = (name, parent, fs.is_dir(rec))
    return ents


def resolve(ents, ref, cache=None):
    if cache is None:
        cache = {}
    parts = []
    seen = set()
    cur = ref
    while cur in ents and cur not in seen:
        seen.add(cur)
        name, parent, _ = ents[cur]
        if cur == 5:
            break
        parts.append(name)
        if parent == cur:
            break
        cur = parent
    return "\\" + "\\".join(reversed(parts))


def cmd_info(path, base):
    fs = NTFS(path, base)
    print("=" * 70)
    print("NTFS GEOMETRY")
    print("=" * 70)
    print(f"\nImage            : {path}")
    print(f"Partition offset : {base:,}")
    print(f"Bytes/sector     : {fs.bps}")
    print(f"Sectors/cluster  : {fs.spc}   (cluster = {fs.cluster} bytes)")
    print(f"Total sectors    : {fs.total_sectors:,}")
    print(f"Volume size      : {human((fs.total_sectors+1)*fs.bps)}")
    print(f"MFT record size  : {fs.rec_size} bytes")
    print(f"$MFT cluster     : {fs.mft_cluster:,}")
    print(f"$MFT byte offset : {fs.mft_off:,}")
    dmg = "DAMAGED" if fs.mft_off < DAMAGE_END else "INTACT"
    print(f"$MFT status      : {dmg}")
    print(f"\nDamage boundary  : {DAMAGE_END:,}")
    print(f"\n$MFT extents ({len(fs.mft_runs)} run(s)):")
    tot = 0
    for lcn, cnt in fs.mft_runs[:12]:
        if lcn is None:
            print(f"  sparse, {cnt:,} clusters")
            continue
        o = fs.base + lcn * fs.cluster
        tot += cnt * fs.cluster
        st = "DAMAGED" if o < DAMAGE_END else "intact"
        print(f"  offset {o:,}  size {human(cnt*fs.cluster)}  [{st}]")
    print(f"\nMFT total size   : {human(tot)}")
    print(f"MFT records      : {fs.record_count():,}")
    print("\n" + "=" * 70)


def report_file(fs, ref, label, ents=None):
    rec = fs.read_record(ref)
    if rec is None:
        print(f"  {label}: MFT record {ref} unreadable")
        return
    a = fs.data_attr(rec)
    if a is None:
        print(f"  {label}: no $DATA")
        return
    if a["resident"]:
        print(f"  {label}")
        print(f"    MFT ref  : {ref}")
        print(f"    size     : {len(a['content'])} bytes (resident, in MFT)")
        print(f"    status   : INTACT (stored inside the MFT record)")
        return
    exts = fs.data_extents(a)
    dmg = 0
    for off, span in exts:
        if off < DAMAGE_END:
            dmg += min(span, DAMAGE_END - off)
    print(f"  {label}")
    print(f"    MFT ref  : {ref}")
    print(f"    size     : {a['real']:,} bytes ({human(a['real'])})")
    print(f"    extents  : {len(exts)}")
    print(f"    first at : {exts[0][0]:,}" if exts else "    no extents")
    print(f"    damaged  : {dmg:,} bytes"
          + ("  <-- FULLY RECOVERABLE" if dmg == 0 else "  <-- PARTIAL LOSS"))


AD_PATH_PATTERNS = [
    ('ntds.dit', '/windows/ntds/ntds.dit', 'exact'),
    ('ntds.jfm', '/windows/ntds/ntds.jfm', 'exact'),
    ('NTDS logs', '/windows/ntds/edb', 'prefix'),
    ('NTDS temp', '/windows/ntds/temp.edb', 'exact'),
    ('SYSTEM hive', '/windows/system32/config/system', 'exact'),
    ('SECURITY hive', '/windows/system32/config/security', 'exact'),
    ('SAM hive', '/windows/system32/config/sam', 'exact'),
    ('SYSVOL', '/windows/sysvol', 'prefix'),
]


def cmd_ad(path, base):
    fs = NTFS(path, base)
    print("=" * 70)
    print("ACTIVE DIRECTORY FILE RECOVERY CHECK")
    print("=" * 70)
    print()
    ents = build_paths(fs)
    print(f"\n  resolved {len(ents):,} in-use records")
    print("  resolving full paths ...")

    # resolve every path once
    paths = {}
    for ref in ents:
        paths[ref] = resolve(ents, ref)

    print("\n" + "=" * 70)

    def norm(x):
        return x.replace("\\", "/").lower()

    for label, pat, mode in AD_PATH_PATTERNS:
        hits = []
        for ref, p in paths.items():
            pl = norm(p)
            isdir = ents[ref][2]
            if mode == "prefix":
                if pl.startswith(pat):
                    hits.append(ref)
            else:
                if pl == pat and not isdir:
                    hits.append(ref)
        print(f"\n[{label}]  {len(hits)} match(es)")
        if not hits:
            print("  NOT FOUND")
            continue
        for ref in hits[:40]:
            if ents[ref][2]:
                print(f"\n  DIR  {paths[ref]}   (ref {ref})")
                continue
            print(f"\n  path: {paths[ref]}")
            report_file(fs, ref, f"  -> {ents[ref][0]}")
        if len(hits) > 40:
            print(f"\n  ... {len(hits)-40} more (use dump for the full list)")

    print("\n" + "=" * 70)
    print("\nTo extract, use the MFT ref shown above:")
    print(f'  py babuk_mft.py extract "{path}" {base} <ref> <outfile>')


def cmd_dump(path, base, outcsv):
    """Walk the MFT once and write a complete inventory to CSV."""
    import csv
    fs = NTFS(path, base)
    print("=" * 70)
    print("FULL MFT INVENTORY")
    print("=" * 70)
    print()
    ents = build_paths(fs)
    print(f"\n  resolved {len(ents):,} in-use records")
    print("  resolving paths and measuring damage ...")

    total = len(ents)
    step = max(1, total // 20)
    nclean = ndmg = 0
    with open(outcsv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["mft_ref", "path", "is_dir", "size_bytes",
                    "extents", "first_offset", "damaged_bytes", "status"])
        for i, ref in enumerate(sorted(ents)):
            if i % step == 0 and i:
                print(f"    {100*i//total}%")
            name, parent, isdir = ents[ref]
            p = resolve(ents, ref)
            if isdir:
                w.writerow([ref, p, 1, "", "", "", "", "dir"])
                continue
            rec = fs.read_record(ref)
            if rec is None:
                w.writerow([ref, p, 0, "", "", "", "", "unreadable"])
                continue
            a = fs.data_attr(rec)
            if a is None:
                w.writerow([ref, p, 0, "", "", "", "", "no_data"])
                continue
            if a["resident"]:
                w.writerow([ref, p, 0, len(a["content"]), 0, "", 0, "resident"])
                nclean += 1
                continue
            exts = fs.data_extents(a)
            dmg = 0
            for off, span in exts:
                if off < DAMAGE_END:
                    dmg += min(span, DAMAGE_END - off)
            st = "clean" if dmg == 0 else "partial_loss"
            if dmg == 0:
                nclean += 1
            else:
                ndmg += 1
            w.writerow([ref, p, 0, a["real"], len(exts),
                        exts[0][0] if exts else "", dmg, st])

    print(f"\nWrote {outcsv}")
    print(f"  clean files        : {nclean:,}")
    print(f"  files with damage  : {ndmg:,}")
    print("\nSearch it with PowerShell, e.g.:")
    print(f'  Import-Csv {outcsv} | Where-Object {{ $_.path -like "*\\NTDS\\*" }} |'
          ' Format-Table mft_ref,path,size_bytes,status')


def cmd_find(path, base, needle, maxn=60):
    fs = NTFS(path, base)
    ents = build_paths(fs)
    needle = needle.lower()
    print(f"\nmatches for '{needle}':\n")
    cnt = 0
    for ref, (name, parent, isdir) in ents.items():
        if needle in name.lower():
            p = resolve(ents, ref)
            kind = "DIR " if isdir else "FILE"
            print(f"  [{kind}] ref={ref:<8} {p}")
            cnt += 1
            if cnt >= maxn:
                print(f"\n  (stopped at {maxn})")
                break
    if cnt == 0:
        print("  none")


def cmd_extract(path, base, ref, out):
    fs = NTFS(path, base)
    ref = int(ref)
    written, damaged = fs.extract(ref, out)
    print(f"Wrote {out}")
    print(f"  bytes written : {written:,} ({human(written)})")
    print(f"  bytes from damaged region : {damaged:,}")
    if damaged == 0:
        print("  status: CLEAN -- no part of this file was in the encrypted zone")
    else:
        print("  status: PARTIAL -- some clusters were inside the encrypted zone")


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return
    try:
        if a[0] == "info" and len(a) == 3:
            cmd_info(a[1], int(a[2]))
        elif a[0] == "ad" and len(a) == 3:
            cmd_ad(a[1], int(a[2]))
        elif a[0] == "dump" and len(a) == 4:
            cmd_dump(a[1], int(a[2]), a[3])
        elif a[0] == "find" and len(a) >= 4:
            mx = 60
            if "--max" in a:
                mx = int(a[a.index("--max") + 1])
            cmd_find(a[1], int(a[2]), a[3], mx)
        elif a[0] == "extract" and len(a) == 5:
            cmd_extract(a[1], int(a[2]), a[3], a[4])
        else:
            print(__doc__)
    except RuntimeError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

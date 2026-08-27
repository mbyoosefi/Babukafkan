import struct
import os
import sys

if len(sys.argv) < 2:
    print("usage: python3 gpt_info.py <disk>")
    sys.exit(1)

p = sys.argv[1]
size = os.path.getsize(p)
data_end = size - (size % 512)

print("disk      : " + p)
print("size      : %d" % size)
print("data end  : %d  (trailer trimmed for reading)" % data_end)
print("")

f = open(p, "rb")
try:
    f.seek(data_end - 512)
    h = f.read(512)
    print("backup GPT header magic: %s" % h[0:8])
    if h[0:8] != b"EFI PART":
        print("no backup GPT found at the end of the disk")
        sys.exit(0)

    ents = struct.unpack_from("<Q", h, 72)[0]
    num = struct.unpack_from("<I", h, 80)[0]
    esz = struct.unpack_from("<I", h, 84)[0]
    print("entries lba: %d   count: %d   entry size: %d" % (ents, num, esz))
    print("")

    arr_off = ents * 512
    if not (0 < arr_off and arr_off + num * esz <= data_end):
        arr_off = (data_end - 512) - num * esz
        print("(entry array not at the header's LBA; reading it from %d)"
              % arr_off)
        print("")

    f.seek(arr_off)
    arr = f.read(num * esz)

    found = 0
    for i in range(num):
        e = arr[i * esz:(i + 1) * esz]
        if len(e) < 128 or e[0:16] == b"\x00" * 16:
            continue
        first = struct.unpack_from("<Q", e, 32)[0]
        last = struct.unpack_from("<Q", e, 40)[0]
        name = e[56:128].decode("utf-16-le", "ignore").rstrip("\x00")
        start = first * 512
        sz = (last - first + 1) * 512
        found += 1
        print("partition %d" % (i + 1))
        print("    start bytes : %d" % start)
        print("    size  bytes : %d   (%.2f GiB)" % (sz, sz / 1024.0 ** 3))
        print("    ends at     : %d" % (start + sz))
        print("    name        : %s" % (name if name else "(unnamed)"))
        print("")
    if found == 0:
        print("no partition entries present")
finally:
    f.close()

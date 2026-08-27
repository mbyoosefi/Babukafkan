# Babuk ESXi Recovery Toolkit

Recover VMware virtual disks encrypted by **Babuk / Babyk** ESXi ransomware —
without paying, without the attacker's key.

بازیابی دیسک‌های مجازی VMware که با باج‌افزار **Babuk / Babyk** روی ESXi رمز
شده‌اند — بدون پرداخت باج و بدون کلید مهاجم.

---

## Why this works · چرا این کار می‌کند

**EN.** Babuk's ESXi variant does not encrypt whole files. It runs a loop that
writes 52 blocks of 10 MiB and then stops, so exactly **545,259,520 bytes
(520 MiB)** at the head of every targeted file is destroyed. It then appends a
32-byte trailer. On a 1 TB virtual disk that is **99.95 % of the data left
untouched** — the file system itself is fine, only its head is gone.

Everything in this toolkit is about rebuilding that head from copies the
file system kept elsewhere on the disk.

**FA.** نسخه ESXi باج‌افزار Babuk کل فایل را رمز نمی‌کند. حلقه‌ای دارد که ۵۲ بلوک
۱۰ مگابایتی می‌نویسد و متوقف می‌شود، پس دقیقاً **۵۴۵٬۲۵۹٬۵۲۰ بایت (۵۲۰ مگابایت)**
از ابتدای هر فایل نابود می‌شود، و ۳۲ بایت trailer به انتها اضافه می‌کند. روی یک
دیسک ۱ ترابایتی یعنی **۹۹٫۹۵٪ داده دست‌نخورده** — فایل‌سیستم سالم است، فقط سرش
رفته.

کل این جعبه‌ابزار درباره بازسازی همان سر، از روی نسخه‌هایی است که خود فایل‌سیستم
جای دیگری روی دیسک نگه داشته.

---

## Quick start · شروع سریع

```bash
scp tools/babuk_recover.py root@<esxi-host>:/tmp/
ssh root@<esxi-host>
python3 /tmp/babuk_recover.py
```

That is the whole thing. It finds every datastore, scans every disk, explains
each case in plain words, and asks before it writes anything.

همین. همه دیتااستورها را پیدا می‌کند، هر دیسک را اسکن می‌کند، هر مورد را ساده
توضیح می‌دهد، و قبل از هر نوشتنی تأیید می‌گیرد.

---

## The main tool · ابزار اصلی

### `babuk_recover.py`

An interactive wizard. Eight steps, nothing written without your confirmation.

یک ویزارد تعاملی. هشت مرحله، هیچ نوشتنی بدون تأیید شما.

| Step | EN | FA |
|---|---|---|
| 0 | Environment check — ESXi version, available Python interpreters, feature probe | بررسی محیط — نسخه ESXi، مفسرهای پایتون، تست قابلیت‌ها |
| 1 | Find datastores and disks, grouped by VM | یافتن دیتااستورها و دیسک‌ها، گروه‌بندی بر اساس ماشین |
| 2 | Detect earlier repair attempts and offer exact rollback | تشخیص تلاش‌های قبلی و امکان بازگردانی دقیق |
| 3 | Deep scan — damage boundary, partition tables, real `$MFT` read | اسکن عمیق — مرز خرابی، جدول پارتیشن، خواندن واقعی `$MFT` |
| 4 | Overview table of every disk | جدول کلی وضعیت همه دیسک‌ها |
| 5 | Machine by machine, `y` / `n` / `a` / `q` | ماشین به ماشین، `y` / `n` / `a` / `q` |
| 6 | Repair — trailer, boot sector, partition table, descriptor | تعمیر — trailer، boot sector، جدول پارتیشن، descriptor |
| 7 | Verify immediately, then print next steps | تأیید فوری و دستورالعمل بعدی |

**Options**

```
--root PATH     where to look                (default /vmfs/volumes)
--log PATH      log file                     (default /tmp/babuk_recover.log)
--tail MB       tail scan window             (default 2048)
--skip-env      skip the environment check
```

**Verdicts · نتایج**

| Verdict | EN | FA |
|---|---|---|
| `READY` | Already usable | از قبل قابل استفاده |
| `REPAIRABLE` | Can be fixed automatically | قابل تعمیر خودکار |
| `NEEDS MANUAL WORK` | `$MFT` gone or non-NTFS — use a carving tool | `$MFT` نابود یا غیر NTFS — ابزار carving لازم است |
| `TOTAL LOSS` | Whole file fits inside the 520 MiB | کل فایل داخل ۵۲۰ مگابایت بوده |
| `IN USE` | A running VM holds the disk — power it off | یک VM روشن دیسک را گرفته — خاموشش کن |

---

## Supporting tools · ابزارهای کمکی

| Tool | EN | FA |
|---|---|---|
| `deep_probe.py` | Read-only forensic profile: entropy map, partition tables, every NTFS volume verified by reading `$MFT` | پروفایل کاملاً read-only: نقشه آنتروپی، جدول پارتیشن، تأیید هر ولوم NTFS با خواندن `$MFT` |
| `rebuild_mbr.py` | Rebuild a destroyed MBR from surviving NTFS boot sectors | بازسازی MBR نابودشده از boot sector های بازمانده |
| `gpt_info.py` | Print the GPT partition table from the backup copy at the end of the disk | چاپ جدول پارتیشن GPT از نسخه پشتیبان انتهای دیسک |
| `babuk_mft.py` | Read `$MFT` directly, list files, extract them without mounting (needs Python 3.6+) | خواندن مستقیم `$MFT`، فهرست و استخراج فایل بدون mount (نیازمند پایتون ۳٫۶+) |
| `refs_veeam.py` | For **ReFS** volumes (Veeam repositories): find backup filenames, ReFS structures, restore the boot record | برای ولوم‌های **ReFS** (مخازن Veeam): یافتن نام بکاپ‌ها، ساختارهای ReFS، بازگردانی boot record |

---

## What this toolkit learned the hard way · درس‌هایی که به سختی به دست آمد

These are real bugs found and fixed during an actual multi-host recovery.
Each one silently produced wrong results before it was caught.

این‌ها باگ‌های واقعی هستند که در جریان یک بازیابی چندهاستی واقعی پیدا و رفع
شدند. هرکدام قبل از کشف، بی‌سروصدا نتیجه غلط می‌داد.

### 1. The boundary is 520 MiB, not 512 · مرز ۵۲۰ مگابایت است نه ۵۱۲

The encryptor uses a `do/while` loop with a 10 MiB block, so it writes 52
blocks before the counter passes 512 MiB. Assuming 512 leaves 8 MiB of
destroyed data treated as good.

انکریپتور حلقه `do/while` با بلوک ۱۰ مگابایتی دارد، پس ۵۲ بلوک می‌نویسد تا شمارنده
از ۵۱۲ مگابایت رد شود. فرض ۵۱۲، هشت مگابایت داده نابود را سالم فرض می‌کند.

### 2. Some disks were encrypted more than once · بعضی دیسک‌ها چند بار رمز شدند

Each run appends its own 32-byte trailer. Disks hit twice carry **64 bytes**.
Trimming a fixed 32 leaves the file misaligned and Windows reports the wrong
disk size. The tool trims back to the nearest whole sector instead.

هر اجرا trailer ۳۲ بایتی خودش را اضافه می‌کند. دیسک‌هایی که دو بار خورده‌اند
**۶۴ بایت** دارند. بریدن ثابتِ ۳۲ بایت فایل را ناهم‌تراز می‌گذارد و ویندوز اندازه
غلط می‌بیند. ابزار به‌جایش تا نزدیک‌ترین سکتور کامل برش می‌زند.

### 3. A valid boot sector proves nothing · boot sector سالم هیچ چیزی را ثابت نمی‌کند

**This one was dangerous.** An early version found a Recovery partition's boot
sector, mistook it for a backup copy, and wrote a boot sector *into the middle
of the C: drive's data*. Now `$MFT` is actually read and checked for `FILE`
records before any write, and the write is refused if fewer than 4 of the first
8 records are valid.

**این یکی خطرناک بود.** نسخه اولیه boot sector یک پارتیشن Recovery را پیدا کرد،
آن را نسخه پشتیبان فرض کرد، و boot sector را *وسط داده‌های درایو C:* نوشت. حالا
قبل از هر نوشتنی `$MFT` واقعاً خوانده و رکوردهای `FILE` بررسی می‌شود، و اگر کمتر
از ۴ رکورد از ۸ رکورد اول معتبر باشد نوشتن رد می‌شود.

### 4. Stale oversized backup copies · نسخه‌های پشتیبان کهنه و بزرگ‌تر

Disks that were resized carry an **older, larger** NTFS backup boot sector from
the previous layout. Trusting it silently swallows the partition that follows —
in one case it hid the entire Recovery partition. When two candidates share a
start offset, the **smaller** one wins.

دیسک‌هایی که resize شده‌اند یک boot sector پشتیبان **قدیمی‌تر و بزرگ‌تر** از چیدمان
قبلی دارند. اعتماد به آن، پارتیشن بعدی را بی‌صدا می‌بلعد — در یک مورد کل پارتیشن
Recovery را پنهان کرد. وقتی دو کاندید یک آفست شروع دارند، **کوچک‌تر** برنده است.

### 5. Repairing the boot sector is not enough · تعمیر boot sector کافی نیست

Sector 0 of the disk — the partition table — also died. Without it Windows
shows the whole disk as **unallocated** even when every byte of the file system
is intact. This was the single most common reason a "successful" repair still
looked like a failure.

سکتور صفر دیسک — جدول پارتیشن — هم مرده است. بدون آن، ویندوز کل دیسک را
**Unallocated** نشان می‌دهد حتی وقتی تمام بایت‌های فایل‌سیستم سالم است. این
شایع‌ترین دلیلی بود که یک تعمیر «موفق» باز هم شکست‌خورده به نظر می‌رسید.

### 6. EFI / MSR / Recovery partitions have no NTFS backup · طبیعی است

That is normal and must not block the rest of the disk. An early version marked
whole disks unrecoverable because the 100 MB EFI partition had no NTFS backup
sector.

این طبیعی است و نباید بقیه دیسک را متوقف کند. نسخه اولیه، دیسک‌های کامل را
غیرقابل‌بازیابی علامت می‌زد چون پارتیشن ۱۰۰ مگابایتی EFI نسخه پشتیبان NTFS نداشت.

### 7. Absence of input is not consent · نبود ورودی یعنی رضایت نیست

Piping from a file or losing the terminal used to fall through to the default
answer and write to disk. EOF now always means quit.

pipe کردن از فایل یا قطع شدن ترمینال، قبلاً به جواب پیش‌فرض می‌افتاد و روی دیسک
می‌نوشت. حالا EOF همیشه یعنی خروج.

---

## Safety · ایمنی

**EN**

- Nothing is written until you type `y` for that specific machine
- Every byte replaced is saved to a `.bak` file **first**
- A `.babuk-manifest` records offset, length and backup name, so any change can
  be rolled back exactly — step 2 does this for you
- Disks attached to a running VM are skipped with a clear message
- Running the tool twice is safe; repaired disks report as already usable
- `deep_probe.py`, `gpt_info.py` and `refs_veeam.py` (except `--apply`) never
  write at all

**FA**

- تا برای همان ماشین `y` تایپ نکنی چیزی نوشته نمی‌شود
- هر بایتی که جایگزین شود **اول** در فایل `.bak` ذخیره می‌شود
- فایل `.babuk-manifest` آفست، طول و نام بکاپ را ثبت می‌کند تا هر تغییری دقیقاً
  برگردد — مرحله ۲ همین کار را می‌کند
- دیسک‌های وصل به VM روشن با پیام روشن رد می‌شوند
- اجرای دوباره امن است؛ دیسک‌های تعمیرشده «از قبل قابل استفاده» گزارش می‌شوند
- `deep_probe.py`، `gpt_info.py` و `refs_veeam.py` (به‌جز `--apply`) اصلاً
  نمی‌نویسند

---

## After the repair · بعد از تعمیر

```bash
vim-cmd solo/registervm "/vmfs/volumes/<ds>/<VM>/<VM>.vmx"
vim-cmd vmsvc/getallvms
vim-cmd vmsvc/power.on <VMID>
```

**Volume shows as RAW in Windows** — expected. From a Windows PE prompt:

```cmd
chkdsk C: /f
```

**Machine will not boot at all** — its System Reserved partition was inside the
destroyed region, so the boot files are gone. The data is still fine. Either
attach the disk as a *second* disk to a working Windows VM and copy the data
off, or rebuild the boot files:

```cmd
diskpart
list volume
select volume <the large NTFS one>
assign letter=W
exit
bcdboot W:\Windows /s W: /f BIOS
```

Use `/f UEFI` on a GPT disk. `bootrec /fixboot` often returns *access denied*
in Windows PE — that is normal and does not matter once `bcdboot` succeeded.

**ولوم در ویندوز RAW است** — طبیعی است، `chkdsk` درستش می‌کند.
**ماشین اصلاً بوت نمی‌شود** — پارتیشن System Reserved داخل ناحیه نابودشده بوده.
داده سالم است؛ یا دیسک را به‌عنوان دیسک *دوم* به یک ویندوز سالم وصل کن، یا با
`bcdboot` بوت را بازسازی کن.

---

## ReFS and Veeam repositories · ReFS و مخازن Veeam

Veeam repositories are usually **ReFS**, which this wizard cannot repair —
`.vbk` files have no fixed magic bytes, so ordinary carving finds nothing.
`refs_veeam.py` takes a different route: ReFS stores filenames as UTF-16 in
metadata pages deep in the volume, far past the damaged head.

مخازن Veeam معمولاً **ReFS** هستند که این ویزارد تعمیرشان نمی‌کند — فایل‌های
`.vbk` امضای ثابت ندارند، پس carving معمولی چیزی پیدا نمی‌کند. ابزار
`refs_veeam.py` راه دیگری می‌رود: ReFS نام فایل‌ها را به‌صورت UTF-16 در صفحات
متادیتای عمق ولوم نگه می‌دارد، خیلی دورتر از سر نابودشده.

```bash
# list every Veeam backup filename on the disk
python3 tools/refs_veeam.py names <disk> --out /tmp/names.txt

# find ReFS structures (boot record, superblock copies)
python3 tools/refs_veeam.py refs <disk> --start <near-the-end>

# inspect one hit
python3 tools/refs_veeam.py around <disk> <offset>

# put a surviving boot record back (dry run without --apply)
python3 tools/refs_veeam.py restore <disk> <offset> \
        --to <partition-start> --part-size <from gpt_info.py> --apply
```

**Known limit · محدودیت شناخته‌شده.** Restoring the ReFS boot record makes
Windows recognise the volume, but ReFS also needs the metadata trees the
checkpoint points to. If those clusters fell inside the destroyed 520 MiB, the
volume still will not mount and Windows reports *"the file system structure
cannot be corrected"*. In that case the filenames recovered by `names` tell you
exactly what existed, and a commercial ReFS-aware tool (UFS Explorer) is the
next step.

بازگرداندن boot record باعث می‌شود ویندوز ولوم را بشناسد، اما ReFS به درخت‌های
متادیتایی که checkpoint به آن‌ها اشاره می‌کند هم نیاز دارد. اگر آن cluster ها
داخل ۵۲۰ مگابایت نابودشده افتاده باشند، ولوم باز هم mount نمی‌شود. در آن حالت،
نام فایل‌هایی که `names` پیدا کرده دقیقاً می‌گوید چه چیزی وجود داشته، و قدم بعدی
یک ابزار تجاری ReFS-آگاه است.

---

## Requirements · پیش‌نیازها

- ESXi host shell access (`root`)
- Python 3.5+ for every tool except `babuk_mft.py`, which needs 3.6+
- Standard library only — nothing to install
- ESXi 6.x, 7.x and 8.x tested

Step 0 of the wizard reports the ESXi build, every Python interpreter on the
host, and whether each required feature is available.

---

## Order of work · ترتیب کار

1. `deep_probe.py` on one disk — understand what you are dealing with
2. `babuk_recover.py` — the guided repair
3. `gpt_info.py` / `rebuild_mbr.py` — if the partition table needs attention
4. `babuk_mft.py` — extract files without mounting, if a VM will not boot
5. `refs_veeam.py` — only for ReFS / Veeam repositories

---

## Disclaimer · سلب مسئولیت

Provided as is, with no warranty. **Work on copies or snapshots whenever you
can.** Verify every dry run before using `--apply`. The authors are not
responsible for data loss.

بدون هیچ ضمانتی ارائه می‌شود. **هر وقت می‌توانی روی کپی یا snapshot کار کن.** هر
dry run را قبل از `--apply` بررسی کن. مسئولیت از دست رفتن داده بر عهده نویسندگان
نیست.

---

## Author · نویسنده

**Mbyoosefi**

Built during a live multi-host Babuk recovery. Every lesson in the section
above came from a real failure caught mid-incident.

ساخته‌شده در جریان یک بازیابی واقعی Babuk روی چند هاست. هر درسی که در بخش بالا
آمده، از یک شکست واقعی در میانه حادثه به دست آمده.

## License

MIT — Copyright (c) 2026 Mbyoosefi. See [LICENSE](LICENSE).

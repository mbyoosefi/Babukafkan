# Babukafkan

## Babuk ESXi Recovery Toolkit

**v3.0.1**

<div dir="rtl" align="right">

**بازیابی ساختار دیسک‌های مجازی آسیب‌دیده، بر پایهٔ شواهد و با امکان بازگشت دقیق.**

این پروژه از تجربهٔ بازیابی واقعی پس از حملهٔ باج‌افزار بابوک ساخته شده است. نسخهٔ جدید، منطق بازیابی قبلی را حفظ می‌کند و ثبت پایدار تراکنش، پشتیبان اختصاصی، بازخوانی دقیق، اعتبارسنجی مستقل و گزارش قابل بررسی به آن اضافه می‌کند.

اصل ابزار ساده است: **بدون شواهد کافی و یکتا، هیچ تغییری روی منبع اعمال نمی‌شود.**

[راهنمای کامل فارسی](DOCS.md)

[تاریخچهٔ تغییرات](CHANGELOG.md)

[شرح این انتشار](releases/v3.0.1.md)

[گزارش آزمون‌ها](BabukRecovery/tests/RESULTS.json)

### چه چیزی بازیابی می‌شود؟

در نمونهٔ شناخته‌شدهٔ این رخداد، باج‌افزار ۵۲ بلوک ده‌مگابایتی از ابتدای فایل هدف را بازنویسی می‌کند و دنباله‌ای ۳۲ بایتی می‌افزاید. مرز شناخته‌شدهٔ تخریب ۵۲۰ مگابایت دودویی است. تکرار حمله می‌تواند چند دنباله ایجاد کند.

باقی‌ماندن بایت‌های داده به معنی قابل استفاده بودن دیسک نیست. جدول پارتیشن، ساختار آغازین فایل‌سیستم یا توصیفگر دیسک ممکن است آسیب دیده باشد. ابزار، ساختارهای قابل اثبات را از نسخه‌های سالم باقی‌مانده بازسازی می‌کند؛ بایت‌هایی را که واقعاً از بین رفته‌اند رمزگشایی یا بازتولید نمی‌کند.

### امکانات نسخهٔ جدید

- شناسایی مخازن و دیسک‌ها و گزارش ارتباط آن‌ها با ماشین‌های مجازی.
- کشف فایل‌سیستم از بخش‌های آغازین و انتهایی منبع، با نگهداری نامزدهای ردشده و محدودهٔ واقعی جست‌وجو.
- بررسی چند رکورد واقعی جدول فایل‌ها، اصلاحات سکتوری و سازگاری نسخهٔ آینه در صورت قابل استفاده بودن.
- بازسازی جدول پارتیشن از نسخهٔ پشتیبان معتبر، همراه با بررسی صحت، حدود و هم‌پوشانی.
- بازسازی هندسهٔ پارتیشن‌های قابل اثبات، بدون اختراع وضعیت فعال بر اساس اندازه.
- تراکنش اختصاصی برای تغییر بایت‌ها، کوتاه‌سازی دنباله، تغییر نام و ساخت توصیفگر.
- ثبت و همگام‌سازی سابقه پیش از تغییر منبع، پشتیبان اختصاصی و بازخوانی دقیق پس از نوشتن.
- اثرانگشت منبع، ادامهٔ اسکن متوقف‌شده، بازگشت مبتنی بر شناسهٔ تراکنش و گزارش انسانی و ماشینی.
- توقف روی شواهد متناقض، منبع در حال استفاده یا چیدمان ناشناختهٔ دیسک.

### شروع سریع

پوشهٔ نسخهٔ جدید را کامل منتقل کنید؛ اجرای یک فایلِ جداشده از پوشه کافی نیست. محل وضعیت و تراکنش‌ها باید روی فضای پایدار و خارج از منابع تحت بازیابی باشد. در نمونهٔ زیر، نام مخزن بازیابی را با مخزن موجود و مناسب خود جایگزین کنید.

</div>

```bash
scp -r BabukRecovery root@<esxi-host>:/tmp/
ssh root@<esxi-host>
python3 /tmp/BabukRecovery/babuk_recovery.py --self-test
python3 /tmp/BabukRecovery/babuk_recovery.py --dry-run \
  --source /vmfs/volumes/DS/VM/VM-flat.vmdk.babyk \
  --adapter lsilogic \
  --work-dir /vmfs/volumes/RECOVERY/BabukRecovery
```

<div dir="rtl" align="right">

ابتدا گزارش و بایت‌های پیشنهادی را بررسی کنید. نوع کنترلر در نمونه صرفاً یک مثال است و باید مطابق ماشین واقعی انتخاب شود. پیش‌نمایش، گزارش و نقطهٔ ادامه ایجاد می‌کند، اما بایت‌ها، اندازه، نام و توصیفگر منبع را تغییر نمی‌دهد.

برای تعمیرِ تأییدشده، مجوز نوشتن باید صریح باشد:

</div>

```bash
python3 /tmp/BabukRecovery/babuk_recovery.py --repair --authorize-repair \
  --source /vmfs/volumes/DS/VM/VM-flat.vmdk.babyk \
  --adapter lsilogic \
  --work-dir /vmfs/volumes/RECOVERY/BabukRecovery
```

<div dir="rtl" align="right">

اجرای بدون انتخاب حالت، تأیید تعاملی برای هر دیسک دارد. نبود ورودی یا پایان ورودی به معنی رضایت نیست. پیام‌های محیط خط فرمان نسخهٔ فعلی انگلیسی هستند؛ فارسی بودن مستندات به معنی وجود رابط فارسی یا گزینهٔ تغییر زبان نیست.

### ابزارهای مجموعه

[بازیابی تراکنشی و راهنمای فرمان‌ها](DOCS.md#ابزار-اصلی-نسخه-جدید)

ورودی اصلی نسخهٔ جدید:

</div>

```text
BabukRecovery/babuk_recovery.py
```

<div dir="rtl" align="right">

[پروفایل جرم‌یابی فقط‌خواندنی](DOCS.md#پروفایل-جرمیابی)

</div>

```text
tools/deep_probe.py
```

<div dir="rtl" align="right">

[بازرسی جدول پارتیشن پشتیبان](DOCS.md#بازرسی-جدول-پارتیشن-پشتیبان)

</div>

```text
tools/gpt_info.py
```

<div dir="rtl" align="right">

[فهرست و استخراج فایل بدون اتصال فایل‌سیستم](DOCS.md#فهرست-و-استخراج-فایل)

</div>

```text
tools/babuk_mft.py
```

<div dir="rtl" align="right">

[بررسی مخازن پشتیبان و ساختارهای فایل‌سیستم](DOCS.md#بررسی-مخازن-پشتیبان)

</div>

```text
tools/refs_veeam.py
```

<div dir="rtl" align="right">

[ابزارهای تاریخی و محدودیت ایمنی آن‌ها](DOCS.md#ابزارهای-تاریخی)

</div>

```text
tools/babuk_recover.py
tools/rebuild_mbr.py
```

<div dir="rtl" align="right">

ابزارهای قدیمی به‌عنوان مرجع و ابزار مکمل نگهداری شده‌اند. مسیرهای نوشتن آن‌ها خودبه‌خود زیر پوشش موتور تراکنش جدید قرار نگرفته‌اند. برای تعمیر ساختاریِ پشتیبانی‌شده، از ورودی نسخهٔ جدید استفاده کنید.

### سازگاری و وضعیت اعتبارسنجی

اجرای عملیاتی برای میزبان مجازی‌سازی طراحی شده است و به مفسر پایتون نسخهٔ ۳٫۵ یا جدیدتر و کتابخانهٔ استاندارد نیاز دارد. مجموعهٔ آزمون‌های نسخهٔ جدید به نسخهٔ ۳٫۸ یا جدیدتر نیاز دارد. ابزار استخراج فایل به نسخهٔ ۳٫۶ یا جدیدتر نیاز دارد.

در این انتشار، ۷۵ آزمون مصنوعی موفق بوده‌اند؛ سازگاری نحوی کد اصلی با نسخهٔ ۳٫۵ بررسی شده است. اجرای عملیاتی نسخهٔ جدید روی میزبان واقعی در این دور اعتبارسنجی نشده است. موفقیت این آزمون‌ها، تضمین بازیابی تمام فایل‌ها یا راه‌اندازی سیستم‌عامل مهمان نیست.

دیسک‌های پایهٔ تخت با سکتور ۵۱۲ بایتی در دامنهٔ پشتیبانی هستند. دیسک‌های پراکنده، زنجیره‌های تغییرات، عکس‌های لحظه‌ای و هندسه‌های مبهم مسدود می‌شوند. تغییر نام ایمن به پشتیبانی سامانهٔ فایل میزبان از ایجاد پیوند سخت وابسته است؛ نبود این قابلیت به توقفِ ثبت‌شده منجر می‌شود.

### مسئولیت استفاده

این پروژه مطابق مجوز، بدون ضمانت ارائه می‌شود. عملیات بازیابی را روی نسخهٔ مستقل منبع انجام دهید و ماشین‌های مرتبط را خاموش نگه دارید. پشتیبان محدودهٔ تغییر، جایگزین تصویر کامل دیسک نیست. پس از بازیابی، اتصال فایل‌سیستم و تعمیر سیستم‌عامل می‌تواند تغییرات دیگری ایجاد کند؛ آن مراحل را جداگانه برنامه‌ریزی کنید.

</div>

---

## English

**Evidence-based recovery for Babuk-damaged VMware disks, with journal-first mutations and exact rollback.**

Babukafkan preserves the existing field-tested recovery reference and adds a separate transactional implementation in `BabukRecovery/`. It repairs evidenced disk structures; it does not decrypt or recreate overwritten payload data.

The observed ransomware variant overwrites 52 × 10 MiB, approximately 520 MiB, and appends a 32-byte trailer per run. The tool distinguishes surviving bytes from usable disk structure and rejects ambiguous reconstructions.

### Highlights

- Read-only analysis and exact planning; explicit repair and rollback authorization.
- Exclusive transaction-specific backups, independent backup hash readback and durable prewrite journals.
- Exact write readback, bounded NTFS FILE-record checks, MFTMirr consistency where usable, and GPT/MBR structural validation.
- Source fingerprints, resumable scan checkpoints, immutable journal events, rejected alternatives and JSON/text reports.
- Base-flat VMDK descriptor handling, read-only VMware-native chain validation where available, and fail-closed unsupported layouts.
- Original tools retained unchanged; their legacy write paths do not inherit the new transaction engine.

[Complete English manual](DOCS.en.md)

[راهنمای کامل فارسی](DOCS.md)

[Changes](CHANGELOG.md)

[Release notes](releases/v3.0.1.md)

### Validation and scope

75 synthetic tests pass on Python 3.10. Production modules pass Python 3.5 syntax checks; the new release has not been validated on a live ESXi host in this environment. Self-tests require Python 3.8+. Production writes require ESXi, native lock inspection and advisory locking. Missing independent VMware validation prevents a whole-disk verified verdict.

Sparse/snapshot/delta layouts, non-512-byte NTFS sectors and conflicting geometry are blocked. Safe namespace restoration uses exclusive hardlinks; VMFS hardlink support remains a deployment capability to validate. Transaction backups are application-immutable, not hardware WORM or signed forensic attestations.

CLI messages currently use English. See the manuals for all tools, flags, result states, migration, crash handling, extraction limitations and operator workflows.

### License and author

[MIT License](LICENSE)

**Mbyoosefi**

This project grew out of real incident recovery. No Disk Doctor code or documentation is changed by this release.

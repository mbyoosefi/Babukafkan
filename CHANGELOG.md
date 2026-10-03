# Changelog

## v3.0.0

2026-10-03

<div dir="rtl" align="right">

### مسئله و نتیجهٔ نسخهٔ جدید

در نسخهٔ تاریخی، ممکن بود تغییر دیسک پیش از ثبت سابقهٔ آن انجام شود. نام پشتیبان‌ها نیز قابل تکرار بود و بعضی تصمیم‌ها، مانند فعال‌کردن بزرگ‌ترین پارتیشن یا ساخت توصیفگر تخت برای چیدمان پراکنده، شواهد کافی نداشتند. نسخهٔ جدید این مسیرها را با تراکنشِ ثبت‌شده پیش از نوشتن، پشتیبان اختصاصی و اعتبارسنجی مستقل جایگزین می‌کند.

### افزوده‌شده

- لایه‌های صریح شواهد، نامزد، تشخیص، برنامهٔ تعمیر، دروازهٔ نوشتن، تراکنش و اعتبارسنجی.
- اثرانگشت نمونه‌ای منبع، گزینهٔ هش کامل و وابستگی نقاط ادامه به همان منبع.
- سابقهٔ اختصاصی هر تراکنش با رویدادهای شماره‌دار و زنجیرهٔ هش؛ ثبت پایدار پیش از تغییر منبع.
- ذخیره و بازخوانی بایت‌های اصلی و پیشنهادی و ثبت نتیجهٔ واقعی بازخوانی، حتی در شکست.
- تحلیل و پیش‌نمایش بدون تغییر منبع، مجوزهای صریح تعمیر و بازگشت و بازرسی تراکنش‌های ناقص.
- بررسی چند رکورد واقعی فایل‌سیستم، اصلاحات سکتوری، حدود ویژگی‌ها و نسخهٔ آینه در صورت قابل استفاده بودن.
- بررسی صحت سربرگ‌ها و آرایهٔ پارتیشن، ارتباط دوسویهٔ جدول‌ها، حدود و هم‌پوشانی.
- گزارش‌های انسانی و ماشینی، نگهداری نامزدهای ردشده و دسته‌بندی شکست.
- ۷۵ آزمون مصنوعی، شامل مقایسه با مرجع تاریخی و بازگشت کامل یک زنجیرهٔ تعمیر.
- معرفی دو‌زبانه، راهنمای کامل فارسی و انگلیسی و شرح فایل‌ها، امکانات و گردش کار.

### سخت‌گیری‌های ایمنی

- فعال‌کردن پارتیشن بر اساس بزرگی حذف شد؛ وضعیت نامعلوم از هندسه جدا می‌ماند.
- انتخاب «کوچک‌ترین نامزد» به‌تنهایی دلیل صحت نیست؛ شواهد مستقل باید گزینهٔ قدیمی یا متناقض را رد کنند.
- چیدمان پراکنده یا زنجیرهٔ ناشناخته به‌عنوان دیسک تخت بازسازی نمی‌شود.
- فایل توصیفگر رمز‌شده برای ساخت توصیفگر جدید حذف نمی‌شود.
- پایان ورودی به معنی تأیید نیست؛ میان‌بری برای عبور اجباری از شواهد، محیط یا بازگشت اضافه نشده است.
- عدم کشف در محدودهٔ اسکن به معنی نبودن در کل دیسک یا ازبین‌رفتن کامل داده‌ها نیست.
- نتیجهٔ موفق یک فرمان به‌تنهایی به معنی بازیابی تأییدشده نیست.

### حفظ‌شده

مرز شناخته‌شدهٔ ۵۲۰ مگابایت دودویی، کشف فایل‌های تغییرنام‌یافته، مشاهدهٔ دنباله‌های متعدد، هم‌ترازی سکتوری، استفاده از نسخهٔ پشتیبان فایل‌سیستم و جدول پارتیشن، خواندن واقعی جدول فایل‌ها، پشتیبان‌گیری، بازگشت و رفتار بدون تغییر در اجرای دوبارهٔ دیسک تعمیرشده، با آزمون یا سخت‌گیری بیشتر حفظ شده‌اند.

### دامنهٔ تغییر فایل‌ها

پیاده‌سازی نسخهٔ جدید، آزمون‌ها و راهنمای فنی در پوشهٔ زیر افزوده شده‌اند:

</div>

```text
BabukRecovery/
```

<div dir="rtl" align="right">

معرفی اصلی بازنویسی شده و مستندات انتشار افزوده شده‌اند:

</div>

```text
README.md
DOCS.md
DOCS.en.md
CHANGELOG.md
releases/v3.0.0.md
.github/workflows/recovery-tests.yml
```

<div dir="rtl" align="right">

کدهای تاریخی در پوشهٔ ابزارها تغییر نکرده‌اند. ابزار دیسک‌دکتر در این انتشار تغییر نکرده است. گزارش‌های وضعیت، تراکنش‌ها و داده‌های عملیاتی کاربر، فایل‌های انتشار نیستند و نباید در مخزن عمومی قرار بگیرند.

### وضعیت آزمون و محدودیت

۷۵ آزمون مصنوعی موفق و بررسی نحو کد اصلی برای نگارش قدیمی انجام شده است. اجرای واقعی نسخهٔ جدید روی میزبان مجازی‌سازی در این دور بررسی نشده؛ توانایی تغییر نام با پیوند سخت و تضمین‌های همگام‌سازی فضای ذخیره‌سازی باید در محیط مقصد بررسی شوند. بررسی ساختار دیسک، تضمین کامل‌بودن محتوای فایل‌ها یا قابلیت راه‌اندازی مهمان نیست.

</div>

### English

- Added a separate journal-first recovery core, explicit evidence/planning/write-gate layers, source fingerprints, resumable checkpoints and JSON/text reports.
- Added transaction-specific exclusive backup artifacts, independently verified backup hashes, exact readback, immutable event history and transaction-ID rollback.
- Strengthened NTFS record/USA/attribute checks, usable MFTMirr consistency, GPT CRC/reciprocity/bounds validation and MBR overlap/geometry verification.
- Removed the largest-partition active heuristic; blocked unsupported sparse/snapshot layouts, ambiguous geometry and changed rollback states.
- Preserved the original production reference and all historical utility scripts unchanged. Their mutation paths remain legacy and are not covered by the new core.
- Added 75 synthetic regressions, including complete repair/rollback against the quarantined historical reference, and automated CI.
- Replaced the project introduction and added complete Persian/English operator manuals, file inventory and release notes.
- No live ESXi validation is claimed. Safe rename hardlink support, deployment durability and independent native chain validation remain environment-specific requirements.

## Historical reference

The existing recovery implementation did not declare a release version. It remains at `tools/babuk_recover.py`; v3.0.0 is the version declared by the new recovery core. This changelog does not invent earlier version numbers or claim previously unrecorded tests.

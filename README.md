# Xfinder — نسخه اصلاح‌شده

Xfinder یک collector و وب‌سایت است که کانفیگ‌های عمومی را جمع‌آوری می‌کند، ابتدا endpoint آن‌ها را بررسی می‌کند، سپس **خود پروتکل را با Xray-core از طریق یک درخواست HTTPS واقعی** تست می‌کند و فقط موارد تأییدشده را منتشر می‌کند.

## Pipeline

```text
Public sources
   ↓
Normalize / deduplicate
   ↓
TCP reachability
   ↓
Xray protocol + HTTPS canary
   ↓
Verified base configs
   ↓
Clean-IP source
   ↓
TCP scan فقط روی IPهای همان منبع و پورت‌های موردنیاز
   ↓
IP + config remix
   ↓
Xray protocol + HTTPS canary دوباره
   ↓
Verified output
   ↓
GitHub Pages
```

### نکته مهم درباره اسکن IP
اسکنر **CIDR یا اینترنت تصادفی را اسکن نمی‌کند**. فقط IPهایی را که در `CLEAN_IPS_URL` آمده‌اند، روی تعداد محدودی از پورت‌هایی که در کانفیگ‌های تأییدشده استفاده شده‌اند بررسی می‌کند.

## جلوگیری از Merge Conflict

فایل‌های زیر generated هستند و دیگر توسط GitHub Actions commit نمی‌شوند:

- `data/configs.json`
- `data/raw_configs.json`
- `data/validated.json`
- `data/remixed.json`
- `data/scan.json`
- `output/*.txt`
- `sources.db`
- `data/warp_accounts.json`

Workflow به‌جای `git add → commit → push`، نتیجه را به‌عنوان **GitHub Pages artifact** منتشر می‌کند. بنابراین اجرای خودکار Xfinder باعث تغییر فایل‌های محلی GitHub Desktop و ایجاد Merge Conflict نمی‌شود.

## راه‌اندازی GitHub Pages

1. Repository را روی GitHub قرار دهید.
2. در **Settings → Pages**، Source را روی **GitHub Actions** قرار دهید.
3. از **Actions → Xfinder Auto Update → Run workflow** یک بار دستی اجرا کنید.
4. بعد از موفقیت اولین اجرا، سایت Pages منتشر می‌شود.
5. سپس Workflow هر ۱۰ دقیقه اجرا می‌شود.

## تست واقعی

برای VLESS، VMess، Trojan و Shadowsocks، collector یک instance موقت Xray می‌سازد و از طریق SOCKS محلی یک HTTPS canary را درخواست می‌کند. بنابراین «باز بودن TCP» به‌تنهایی برای انتشار کافی نیست.

کانفیگ‌های ناقص، URIهای خراب و transportهای ناشناخته منتشر نمی‌شوند.

## WireGuard

ساخت خودکار WARP در backend منتشر نمی‌شود، چون یک GitHub Runner بدون فعال‌سازی تونل WireGuard نمی‌تواند آن را end-to-end مانند VLESS/Trojan تست کند. سازنده شخصی WARP در رابط سایت مستقل است و کلید خصوصی backend در repository ذخیره نمی‌شود.

## اجرای محلی

```bash
python -m compileall src
XRAY_BIN=/path/to/xray python -m src.main
```

برای اجرای کامل محلی باید `xray` و `curl` نصب باشند.

# Xfinder

Xfinder یک جمع‌آورنده و **اعتبارسنج شبکه‌ای** برای کانفیگ‌های عمومی است.
Pipeline هر اجرا:

1. کانفیگ‌ها را از منابع تعریف‌شده دریافت می‌کند.
2. موارد تکراری و لینک‌های ناقص را حذف می‌کند.
3. **تمام کانفیگ‌های جمع‌آوری‌شده را تست می‌کند**؛ TCP و برای TLS/HTTP، handshake/transport probe هم انجام می‌شود.
4. فقط مواردی که تست را پاس کرده‌اند وارد خروجی اصلی می‌شوند.
5. IPهای موجود در منبع Clean IP را با یک اسکنر محدود و فقط روی IPهای همان منبع و پورت‌های موردنیاز پروژه بررسی می‌کند.
6. کانفیگ‌های VLESS/VMess/Trojan با IPهایی که واقعاً روی همان پورت پاسخ داده‌اند ترکیب می‌شوند.
7. **هر کانفیگ Remix بعد از ترکیب دوباره تست می‌شود** و فقط Remixهای تأییدشده منتشر می‌شوند.
8. خروجی‌های `output/*.txt` و `data/configs.json` به‌روزرسانی می‌شوند.

> نکته: تست فعلی «تست transport/endpoint» است و ادعا نمی‌کند که با خود Xray تمام مراحل احراز هویت هر پروتکل را شبیه‌سازی کرده است. برای VLESS/VMess/Trojan، TCP/TLS و در صورت وجود WebSocket/HTTP transport بررسی می‌شود.

## امنیت بالا

- اسکنر فقط IPهایی را بررسی می‌کند که از `CLEAN_IPS_URL` دریافت شده‌اند؛ CIDR یا رنج دلخواه از کاربر نمی‌گیرد.
- کلید خصوصی WARP در مخزن عمومی ذخیره یا منتشر نمی‌شود.
- `data/warp_accounts.json` در `.gitignore` است.
- WireGuard/WARP سروری به‌صورت خودکار در خروجی عمومی ساخته نمی‌شود تا private key منتشر نشود.

## GitHub Actions

Workflow هر ۱۰ دقیقه اجرا می‌شود و برای اجرای دستی نیز `workflow_dispatch` دارد.

```text
python -m compileall -q src
python -m src.main
```

برای تست محلی:

```bash
python -m src.main
```

خروجی‌ها:

```text
output/all.txt
output/vless.txt
output/vmess.txt
output/trojan.txt
output/ss.txt
output/hysteria2.txt
output/wireguard.txt

data/configs.json
data/raw_configs.json
data/validated.json
data/remixed.json
data/scanned_clean_ips.json
```

## نکته

کانفیگ‌های عمومی ممکن است هر لحظه از کار بیفتند. Xfinder فقط مواردی را که در زمان اجرای Pipeline تست شده‌اند منتشر می‌کند و تضمین دائمی برای اتصال ارائه نمی‌دهد.

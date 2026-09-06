# Prism Panel v4 (Xray-core)

پنل حرفه‌ای Railway با موتور واقعی **Xray-core**

## چرا این نسخه؟
نسخه‌های قبلی رله پایتونی بودند و پینگ واقعی نمی‌دادند.
این نسخه Xray-core را داخل Docker اجرا می‌کند و ترافیک WebSocket را به آن پروکسی می‌کند.

## معماری
```
Client (Hiddify/v2rayNG)
   │  VLESS + WS + TLS :443
   ▼
Railway Edge (TLS)
   │  WS /ws
   ▼
Prism Panel (FastAPI)
   │  proxy WS
   ▼
Xray-core 127.0.0.1:10000  (VLESS+WS)
   │
   ▼
Internet
```

## دیپلوی
1. این پوشه را روی GitHub بگذار
2. Railway → Deploy from GitHub
3. Volume: `/app/data`
4. `ADMIN_PASSWORD=رمز-قوی`
5. Generate Domain

ورود: `/login` (پیش‌فرض: admin)

## ⚠️ اگر از ایران پینگ نمی‌دهد (مهم)
دامنه‌ی پیش‌فرض `xxx.up.railway.app` **از ایران فیلتر است** — کلاینت اصلاً نمی‌تواند به سرور وصل شود و تست تأخیر `-1` می‌دهد. هیچ تنظیمی روی خود پنل این را حل نمی‌کند. راه‌حل: **دامنه‌ی اختصاصی پشت Cloudflare**:

1. یک دامنه بخر (ارزان، مثلاً از Namecheap/… ) و در Cloudflare ثبت کن
2. در Cloudflare → DNS: یک رکورد `A` (یا CNAME به `xxx.up.railway.app`) بساز و **Proxy را روشن کن (ابر نارنجی)** — WebSockets هم باید فعال بماند (پیش‌فرض فعال است)
3. در Cloudflare → SSL/TLS → حالت را روی **Full** بگذار (برای Railway، گزینه‌ی Full (Strict) کار نمی‌کند)
4. در Railway → Settings → Networking → Custom Domain → همان دامنه را اضافه کن و رکوردهای TXT/CNAME که می‌دهد را در Cloudflare وارد کن
5. در Railway → Variables → این را اضافه کن:
   ```
   PUBLIC_DOMAIN = my.example.com
   ```
   (این متغیر حالا بر دامنه‌ی خودکار Railway اولویت دارد) و ری‌دپلوی کن
6. در پنل، لینک/ساب جدید کاربر را دوباره در کلاینت به‌روزرسانی کن (لینک‌ها با دامنه‌ی جدید ساخته می‌شوند)

نکته: در کلاینت همیشه **لینک همین نسخه‌ی فعلی پنل** را استفاده کن (یا ساب `/sub/{uid}` را آپدیت کن) — لینک‌های قدیمی از نسخه‌های قبل کار نمی‌کنند.

## ساخت کانفیگ
- پروتکل: VLESS
- Fingerprint: chrome
- ALPN: http/1.1
- مسیر: `/ws`

## کلاینت
Hiddify / v2rayNG / NekoBox / Streisand — آخرین نسخه

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

## ساخت کانفیگ
- پروتکل: VLESS
- Fingerprint: chrome
- ALPN: http/1.1
- مسیر: `/ws`

## کلاینت
Hiddify / v2rayNG / NekoBox / Streisand — آخرین نسخه

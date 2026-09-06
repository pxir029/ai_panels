#!/usr/bin/env python3
"""
Prism Panel v4 — Professional Railway panel powered by real Xray-core
VLESS-WS works with real client ping (Hiddify / v2rayNG / NekoBox)
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import subprocess
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import qrcode
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from jinja2 import DictLoader, Environment, select_autoescape
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from templates_data import INDEX, LOGIN, DASHBOARD, PORTAL

# ── Config ──────────────────────────────────────────────────
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_FILE = DATA_DIR / "prism.json"
XRAY_CONFIG = DATA_DIR / "xray.json"
XRAY_BIN = os.getenv("XRAY_BIN", "/usr/local/bin/xray")
XRAY_PORT = int(os.getenv("XRAY_PORT", "10000"))  # internal only
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
PORT = int(os.getenv("PORT", "8080"))
PUBLIC_DOMAIN = os.getenv("RAILWAY_PUBLIC_DOMAIN") or os.getenv("PUBLIC_DOMAIN") or "localhost"
PUBLIC_URL = f"https://{PUBLIC_DOMAIN}" if "localhost" not in PUBLIC_DOMAIN else f"http://{PUBLIC_DOMAIN}:{PORT}"
WS_PATH = "/ws"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prism")

def utcnow():
    return datetime.now(timezone.utc)

# ── Password ────────────────────────────────────────────────
def _hash_password(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return f"{salt}${dk.hex()}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, hashed = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
        return hmac.compare_digest(dk.hex(), hashed)
    except Exception:
        return False

# ── Models ──────────────────────────────────────────────────
class UserCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    protocol: str = Field(default="vless", pattern="^(vless|both)$")  # xray: vless primary
    fingerprint: str = Field(default="chrome")
    alpn: str = Field(default="http/1.1")
    traffic_gb: float = Field(default=0, ge=0)
    expire_days: int = Field(default=0, ge=0)
    max_conn: int = Field(default=0, ge=0)
    note: str = Field(default="", max_length=200)
    enabled: bool = True

class ChangePassword(BaseModel):
    current: str
    new_password: str = Field(..., min_length=4, max_length=128)

class LoginRequest(BaseModel):
    password: str

# ── DB ──────────────────────────────────────────────────────
def load_db() -> Dict[str, Any]:
    if DB_FILE.exists():
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if str(data.get("admin_hash", "")).startswith("$2"):
                data["admin_hash"] = _hash_password(ADMIN_PASSWORD)
                save_db(data)
            return data
        except Exception as e:
            logger.error(f"DB load: {e}")
    return {"admin_hash": _hash_password(ADMIN_PASSWORD), "users": {}, "stats": {"up": 0, "down": 0}}

def save_db(data: Dict[str, Any]):
    try:
        tmp = DB_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        tmp.replace(DB_FILE)
    except Exception as e:
        logger.error(f"DB save: {e}")

db = load_db()

def get_user(uid: str) -> Optional[Dict]:
    return db.get("users", {}).get(uid)

def is_valid(uid: str) -> bool:
    u = get_user(uid)
    if not u or not u.get("enabled", True):
        return False
    if u.get("expire_at"):
        try:
            exp = datetime.fromisoformat(u["expire_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < utcnow():
                return False
        except Exception:
            pass
    limit = u.get("limit_bytes", 0)
    if limit > 0 and u.get("used_bytes", 0) >= limit:
        return False
    return True

def fmt_bytes(n: int) -> str:
    if n >= 1024 ** 3: return f"{n/1024**3:.2f} GB"
    if n >= 1024 ** 2: return f"{n/1024**2:.1f} MB"
    if n >= 1024: return f"{n/1024:.0f} KB"
    return f"{n} B"

# ── Link builder ────────────────────────────────────────────
def refresh_links(user: Dict) -> Dict:
    uid = user["uuid"]
    name = user.get("name", "user")
    fp = (user.get("fingerprint") or "chrome").strip().lower()
    alpn = (user.get("alpn") or "http/1.1").strip()
    host = PUBLIC_DOMAIN
    label = quote(str(name), safe="")

    def qjoin(params: dict) -> str:
        return "&".join(f"{k}={quote(str(v), safe=',/')}" for k, v in params.items())

    # Single shared path /ws — UUID identifies user inside VLESS (Xray-style)
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": WS_PATH,
        "sni": host,
        "fp": fp,
        "alpn": alpn,
    }
    user["vless"] = f"vless://{uid}@{host}:443?{qjoin(params)}#{label}"
    user["trojan"] = None  # focus on working VLESS via Xray
    return user

# ── Xray management ─────────────────────────────────────────
xray_proc: Optional[subprocess.Popen] = None

def build_xray_config() -> dict:
    clients = []
    for u in db.get("users", {}).values():
        if not u.get("enabled", True):
            continue
        # still include expired? no - skip invalid
        if not is_valid(u["uuid"]):
            # allow enabled but expired skip
            if u.get("expire_at"):
                try:
                    exp = datetime.fromisoformat(u["expire_at"])
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    if exp < utcnow():
                        continue
                except Exception:
                    pass
        clients.append({"id": u["uuid"], "email": u.get("name", u["uuid"][:8]), "level": 0})

    if not clients:
        # Xray needs at least one client
        clients.append({"id": str(uuid.uuid4()), "email": "placeholder", "level": 0})

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": XRAY_PORT,
                "protocol": "vless",
                "settings": {
                    "clients": clients,
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": WS_PATH,
                        "acceptProxyProtocol": False,
                    },
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "AsIs"}},
            {"protocol": "blackhole", "tag": "block"},
        ],
    }

def write_xray_config():
    cfg = build_xray_config()
    XRAY_CONFIG.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg

def start_xray():
    global xray_proc
    write_xray_config()
    if not Path(XRAY_BIN).exists():
        logger.error(f"Xray binary not found at {XRAY_BIN}")
        return False
    # stop old
    stop_xray()
    xray_proc = subprocess.Popen(
        [XRAY_BIN, "run", "-c", str(XRAY_CONFIG)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    logger.info(f"Xray started pid={xray_proc.pid} on 127.0.0.1:{XRAY_PORT} path={WS_PATH}")
    return True

def stop_xray():
    global xray_proc
    if xray_proc and xray_proc.poll() is None:
        xray_proc.send_signal(signal.SIGTERM)
        try:
            xray_proc.wait(timeout=5)
        except Exception:
            xray_proc.kill()
    xray_proc = None

def reload_xray():
    """Regenerate config and restart xray (simple & reliable)."""
    start_xray()

# ── Auth ────────────────────────────────────────────────────
def make_token(data: dict) -> str:
    payload = {**data, "exp": utcnow() + timedelta(hours=48)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

async def require_admin(request: Request):
    token = request.session.get("token")
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("role") != "admin":
            raise HTTPException(403)
        return payload
    except JWTError:
        raise HTTPException(401, "Invalid session")

# ── App ─────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Prism Panel v4 (Xray) | domain={PUBLIC_DOMAIN}")
    for u in db.get("users", {}).values():
        refresh_links(u)
    save_db(db)
    ok = start_xray()
    if not ok:
        logger.error("Xray failed to start — configs will not work")
    yield
    stop_xray()
    save_db(db)

app = FastAPI(title="Prism Panel", version="4.0-xray", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

_env = Environment(
    loader=DictLoader({
        "index.html": INDEX, "login.html": LOGIN,
        "dashboard.html": DASHBOARD, "portal.html": PORTAL,
    }),
    autoescape=select_autoescape(["html"]),
)
templates = Jinja2Templates(env=_env)

# ── WebSocket proxy: client → panel → Xray ──────────────────
@app.websocket(WS_PATH)
async def ws_proxy(websocket: WebSocket):
    """
    Transparent WebSocket reverse-proxy to local Xray.
    Client connects to wss://domain/ws  (TLS by Railway)
    We forward to ws://127.0.0.1:10000/ws  (Xray, no TLS)
    """
    await websocket.accept()
    reader = writer = None
    try:
        # Raw TCP connect to Xray's WS listener and perform WS upgrade manually is hard.
        # Use asyncio open_connection + websockets library to Xray.
        import websockets
        from websockets.client import connect as ws_connect

        xray_url = f"ws://127.0.0.1:{XRAY_PORT}{WS_PATH}"
        async with ws_connect(
            xray_url,
            max_size=None,
            ping_interval=None,
            open_timeout=10,
        ) as xray_ws:

            async def client_to_xray():
                try:
                    while True:
                        msg = await websocket.receive()
                        if msg["type"] == "websocket.disconnect":
                            break
                        data = msg.get("bytes")
                        text = msg.get("text")
                        if data is not None:
                            await xray_ws.send(data)
                        elif text is not None:
                            await xray_ws.send(text)
                except Exception:
                    pass

            async def xray_to_client():
                try:
                    async for message in xray_ws:
                        if isinstance(message, bytes):
                            await websocket.send_bytes(message)
                        else:
                            await websocket.send_text(message)
                except Exception:
                    pass

            done, pending = await asyncio.wait(
                {asyncio.create_task(client_to_xray()), asyncio.create_task(xray_to_client())},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WS proxy error: {e}")
        try:
            await websocket.close()
        except Exception:
            pass

# ── Pages ───────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "domain": PUBLIC_DOMAIN, "url": PUBLIC_URL})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, admin=Depends(require_admin)):
    users = sorted(db.get("users", {}).values(), key=lambda x: x.get("created", ""), reverse=True)
    for u in users:
        u["_used"] = fmt_bytes(u.get("used_bytes", 0))
        u["_limit"] = fmt_bytes(u["limit_bytes"]) if u.get("limit_bytes", 0) > 0 else "∞"
        u["_expire"] = (u.get("expire_at") or "")[:10] if u.get("expire_at") else None
    xray_ok = xray_proc is not None and xray_proc.poll() is None
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "users": users, "domain": PUBLIC_DOMAIN, "url": PUBLIC_URL,
        "stats": db.get("stats", {}), "active": 0,
        "vless_path": WS_PATH, "trojan_path": "-",
        "total_traffic": fmt_bytes(db.get("stats", {}).get("up", 0) + db.get("stats", {}).get("down", 0)),
        "xray_status": "آنلاین" if xray_ok else "آفلاین",
    })

@app.get("/u/{uid}", response_class=HTMLResponse)
async def user_portal(request: Request, uid: str):
    user = get_user(uid)
    if not user:
        raise HTTPException(404)
    remaining_str, pct = "نامحدود", 0
    if user.get("limit_bytes", 0) > 0:
        rem = max(0, user["limit_bytes"] - user.get("used_bytes", 0))
        remaining_str = fmt_bytes(rem)
        pct = min(100, int(user.get("used_bytes", 0) / max(1, user["limit_bytes"]) * 100))
    expire_str = "نامحدود"
    if user.get("expire_at"):
        try:
            expire_str = datetime.fromisoformat(user["expire_at"]).strftime("%Y-%m-%d %H:%M")
        except Exception:
            pass
    return templates.TemplateResponse("portal.html", {
        "request": request, "user": user, "domain": PUBLIC_DOMAIN, "url": PUBLIC_URL,
        "sub_url": f"{PUBLIC_URL}/sub/{uid}",
        "used_str": fmt_bytes(user.get("used_bytes", 0)),
        "limit_str": fmt_bytes(user["limit_bytes"]) if user.get("limit_bytes", 0) > 0 else "نامحدود",
        "remaining_str": remaining_str, "pct": pct, "expire_str": expire_str,
        "valid": is_valid(uid), "active": 0,
    })

# ── API ─────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(req: LoginRequest, request: Request):
    if not _verify_password(req.password, db.get("admin_hash", "")):
        if req.password != ADMIN_PASSWORD:
            raise HTTPException(401, "رمز اشتباه است")
    request.session["token"] = make_token({"role": "admin", "sub": "admin"})
    return {"ok": True}

@app.post("/api/logout")
async def api_logout(request: Request):
    request.session.clear()
    return {"ok": True}

@app.post("/api/change-password")
async def api_change_password(data: ChangePassword, admin=Depends(require_admin)):
    if not _verify_password(data.current, db.get("admin_hash", "")):
        if data.current != ADMIN_PASSWORD:
            raise HTTPException(400, "رمز فعلی اشتباه است")
    db["admin_hash"] = _hash_password(data.new_password)
    save_db(db)
    return {"ok": True}

@app.post("/api/users")
async def api_create(data: UserCreate, admin=Depends(require_admin)):
    uid = str(uuid.uuid4())
    expire_at = (utcnow() + timedelta(days=data.expire_days)).isoformat() if data.expire_days > 0 else None
    user = {
        "uuid": uid, "name": data.name.strip(), "protocol": "vless",
        "fingerprint": data.fingerprint or "chrome", "alpn": data.alpn or "http/1.1",
        "enabled": True,
        "limit_bytes": int(data.traffic_gb * 1024**3) if data.traffic_gb > 0 else 0,
        "used_bytes": 0, "max_conn": data.max_conn, "expire_at": expire_at,
        "note": data.note.strip(), "created": utcnow().isoformat(),
    }
    refresh_links(user)
    db.setdefault("users", {})[uid] = user
    save_db(db)
    reload_xray()
    return user

@app.delete("/api/users/{uid}")
async def api_delete(uid: str, admin=Depends(require_admin)):
    db.get("users", {}).pop(uid, None)
    save_db(db)
    reload_xray()
    return {"ok": True}

@app.get("/sub/{uid}")
async def subscription(uid: str):
    user = get_user(uid)
    if not user or not is_valid(uid):
        raise HTTPException(404, "not found or inactive")
    lines = [user["vless"]] if user.get("vless") else []
    if not lines:
        raise HTTPException(404, "no configs")
    content = base64.b64encode("\n".join(lines).encode()).decode()
    used = int(user.get("used_bytes", 0) or 0)
    total = int(user.get("limit_bytes", 0) or 0)
    expire = 0
    if user.get("expire_at"):
        try:
            expire = int(datetime.fromisoformat(user["expire_at"]).timestamp())
        except Exception:
            pass
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={
            "subscription-userinfo": f"upload=0; download={used}; total={total}; expire={expire}",
            "profile-update-interval": "12",
            "profile-title": quote(user.get("name", "Prism")),
            "content-disposition": 'inline; filename="subscription.txt"',
        },
    )

@app.get("/qr/{uid}")
async def qr(uid: str):
    user = get_user(uid)
    if not user or not user.get("vless"):
        raise HTTPException(404)
    img = qrcode.make(user["vless"])
    from io import BytesIO
    buf = BytesIO(); img.save(buf, format="PNG"); buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")

@app.get("/api/ping-test/{uid}")
async def ping_test(uid: str):
    """Real check: Xray process + local WS path + user validity"""
    user = get_user(uid)
    if not user:
        raise HTTPException(404)
    xray_ok = xray_proc is not None and xray_proc.poll() is None
    # Try local connect to xray port
    local_ok = False
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", XRAY_PORT), 2.0)
        w.close()
        local_ok = True
    except Exception:
        pass
    return {
        "ok": xray_ok and local_ok and is_valid(uid),
        "xray_running": xray_ok,
        "xray_port_open": local_ok,
        "user_enabled": is_valid(uid),
        "path": WS_PATH,
        "link": user.get("vless"),
        "engine": "xray-core",
    }

@app.get("/health")
async def health():
    xray_ok = xray_proc is not None and xray_proc.poll() is None
    return {
        "status": "ok" if xray_ok else "degraded",
        "version": "4.0-xray",
        "domain": PUBLIC_DOMAIN,
        "xray": xray_ok,
        "ws_path": WS_PATH,
    }

if __name__ == "__main__":
    if not db.get("users"):
        uid = str(uuid.uuid4())
        user = {
            "uuid": uid, "name": "Default", "protocol": "vless",
            "fingerprint": "chrome", "alpn": "http/1.1", "enabled": True,
            "limit_bytes": 0, "used_bytes": 0, "max_conn": 0, "expire_at": None,
            "note": "", "created": utcnow().isoformat(),
        }
        refresh_links(user)
        db.setdefault("users", {})[uid] = user
        save_db(db)
        logger.info(f"Default user: {uid}")
        logger.info(f"Link: {user['vless']}")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info", ws="websockets")

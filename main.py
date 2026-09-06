#!/usr/bin/env python3
"""Prism Panel — pxpanel-compatible VLESS-WS relay for Railway"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import struct
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional
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
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
PORT = int(os.getenv("PORT", "8080"))
PUBLIC_DOMAIN = os.getenv("RAILWAY_PUBLIC_DOMAIN") or os.getenv("PUBLIC_DOMAIN") or "localhost"
PUBLIC_URL = f"https://{PUBLIC_DOMAIN}" if "localhost" not in PUBLIC_DOMAIN else f"http://{PUBLIC_DOMAIN}:{PORT}"
RELAY_BUF = 256 * 1024

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
    protocol: str = Field(default="vless", pattern="^(vless|trojan|both)$")
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
active_conn: Dict[str, int] = {}
traffic_buf: Dict[str, Dict[str, int]] = {}

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
    maxc = u.get("max_conn", 0)
    if maxc > 0 and active_conn.get(uid, 0) >= maxc:
        return False
    return True

def fmt_bytes(n: int) -> str:
    if n >= 1024 ** 3: return f"{n/1024**3:.2f} GB"
    if n >= 1024 ** 2: return f"{n/1024**2:.1f} MB"
    if n >= 1024: return f"{n/1024:.0f} KB"
    return f"{n} B"

# ── Link builder (pxpanel-exact quote rules) ────────────────
def refresh_links(user: Dict) -> Dict:
    uid = user["uuid"]
    name = user.get("name", "user")
    proto = user.get("protocol", "vless")
    fp = (user.get("fingerprint") or "chrome").strip().lower()
    alpn = (user.get("alpn") or "http/1.1").strip()
    host = PUBLIC_DOMAIN
    label = quote(str(name), safe="")

    def qjoin(params: dict) -> str:
        return "&".join(f"{k}={quote(str(v), safe=',/')}" for k, v in params.items())

    if proto in ("vless", "both"):
        params = {
            "encryption": "none", "security": "tls", "type": "ws",
            "host": host, "path": f"/ws/{uid}", "sni": host,
            "fp": fp, "alpn": alpn,
        }
        user["vless"] = f"vless://{uid}@{host}:443?{qjoin(params)}#{label}"
    else:
        user["vless"] = None

    if proto in ("trojan", "both"):
        # Same /ws/{uuid} path as pxpanel trojan-ws
        params = {
            "security": "tls", "type": "ws", "host": host,
            "path": f"/ws/{uid}", "sni": host, "fp": fp, "alpn": alpn,
        }
        user["trojan"] = f"trojan://{uid}@{host}:443?{qjoin(params)}#{label}"
    else:
        user["trojan"] = None
    return user

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

# ── Relay (pxpanel-faithful) ────────────────────────────────
async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1 + 16
    addon_len = chunk[pos]
    pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    atyp = chunk[pos]; pos += 1
    if atyp == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif atyp == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif atyp == 3:
        address = socket.inet_ntop(socket.AF_INET6, chunk[pos:pos+16]); pos += 16
    else:
        raise ValueError("bad atyp")
    return command, address, port, chunk[pos:]

async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, uid: str):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
            traffic_buf.setdefault(uid, {"up": 0, "down": 0})["up"] += len(data)
    except Exception:
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            payload = (b"\x00\x00" + data) if first else data
            first = False
            await ws.send_bytes(payload)
            traffic_buf.setdefault(uid, {"up": 0, "down": 0})["down"] += len(data)
    except Exception:
        pass

async def websocket_tunnel(ws: WebSocket, uuid: str):
    """Single entry for /ws/{uuid} — VLESS (and trojan clients using same path)"""
    if not is_valid(uuid):
        await ws.close(code=1008, reason="not authorized")
        return
    await ws.accept()
    active_conn[uuid] = active_conn.get(uuid, 0) + 1
    writer = None
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        # Detect Trojan (starts with hex password) vs VLESS
        is_trojan = False
        if b"\r\n" in first_chunk[:80]:
            # Possible trojan
            try:
                crlf = first_chunk.index(b"\r\n")
                if crlf >= 56:
                    is_trojan = True
            except ValueError:
                pass

        if is_trojan:
            crlf = first_chunk.index(b"\r\n")
            req = first_chunk[crlf + 2:]
            if len(req) < 7 or req[0] != 1:
                await ws.close(); return
            atyp = req[1]; pos = 2
            if atyp == 1:
                host = socket.inet_ntoa(req[pos:pos+4]); pos += 4
            elif atyp == 3:
                dlen = req[pos]; pos += 1
                host = req[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, req[pos:pos+16]); pos += 16
            else:
                await ws.close(); return
            port = struct.unpack("!H", req[pos:pos+2])[0]; pos += 2
            payload = req[pos:] if pos < len(req) else b""
            command = 1
            address = host
        else:
            command, address, port, payload = await parse_vless_header(first_chunk)
            if command != 1:
                await ws.close(); return

        logger.info(f"→ {address}:{port} uid={uuid[:8]}")
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), 10.0)
        sock = writer.transport.get_extra_info("socket")
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
        if payload:
            writer.write(payload)
            await writer.drain()
            traffic_buf.setdefault(uuid, {"up": 0, "down": 0})["up"] += len(payload)

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, uuid)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, uuid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"tunnel error: {e}")
    finally:
        active_conn[uuid] = max(0, active_conn.get(uuid, 1) - 1)
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

# ── App ─────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Prism Panel | domain={PUBLIC_DOMAIN}")
    for u in db.get("users", {}).values():
        refresh_links(u)
    save_db(db)
    async def flusher():
        while True:
            await asyncio.sleep(20)
            changed = False
            for uid, tr in list(traffic_buf.items()):
                if uid in db.get("users", {}) and (tr["up"] or tr["down"]):
                    db["users"][uid]["used_bytes"] = db["users"][uid].get("used_bytes", 0) + tr["up"] + tr["down"]
                    db["stats"]["up"] = db["stats"].get("up", 0) + tr["up"]
                    db["stats"]["down"] = db["stats"].get("down", 0) + tr["down"]
                    traffic_buf[uid] = {"up": 0, "down": 0}
                    changed = True
            if changed:
                save_db(db)
    task = asyncio.create_task(flusher())
    yield
    task.cancel()
    save_db(db)

app = FastAPI(title="Prism Panel", version="3.0", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

_env = Environment(loader=DictLoader({
    "index.html": INDEX, "login.html": LOGIN,
    "dashboard.html": DASHBOARD, "portal.html": PORTAL,
}), autoescape=select_autoescape(["html"]))
templates = Jinja2Templates(env=_env)

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
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "users": users, "domain": PUBLIC_DOMAIN, "url": PUBLIC_URL,
        "stats": db.get("stats", {}), "active": sum(active_conn.values()),
        "vless_path": "/ws/{uuid}", "trojan_path": "/ws/{uuid}",
        "total_traffic": fmt_bytes(db.get("stats", {}).get("up", 0) + db.get("stats", {}).get("down", 0)),
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
        pct = min(100, int(user.get("used_bytes", 0) / user["limit_bytes"] * 100))
    expire_str = "نامحدود"
    if user.get("expire_at"):
        try:
            exp = datetime.fromisoformat(user["expire_at"])
            expire_str = exp.strftime("%Y-%m-%d %H:%M")
        except Exception:
            pass
    return templates.TemplateResponse("portal.html", {
        "request": request, "user": user, "domain": PUBLIC_DOMAIN, "url": PUBLIC_URL,
        "sub_url": f"{PUBLIC_URL}/sub/{uid}",
        "used_str": fmt_bytes(user.get("used_bytes", 0)),
        "limit_str": fmt_bytes(user["limit_bytes"]) if user.get("limit_bytes", 0) > 0 else "نامحدود",
        "remaining_str": remaining_str, "pct": pct, "expire_str": expire_str,
        "valid": is_valid(uid), "active": active_conn.get(uid, 0),
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
        "uuid": uid, "name": data.name.strip(), "protocol": data.protocol,
        "fingerprint": data.fingerprint or "chrome", "alpn": data.alpn or "http/1.1",
        "enabled": data.enabled,
        "limit_bytes": int(data.traffic_gb * 1024**3) if data.traffic_gb > 0 else 0,
        "used_bytes": 0, "max_conn": data.max_conn, "expire_at": expire_at,
        "note": data.note.strip(), "created": utcnow().isoformat(),
    }
    refresh_links(user)
    db.setdefault("users", {})[uid] = user
    save_db(db)
    return user

@app.delete("/api/users/{uid}")
async def api_delete(uid: str, admin=Depends(require_admin)):
    db.get("users", {}).pop(uid, None)
    save_db(db)
    return {"ok": True}

@app.get("/sub/{uid}")
async def subscription(uid: str):
    user = get_user(uid)
    if not user or not is_valid(uid):
        raise HTTPException(404, "not found or inactive")
    lines = [x for x in (user.get("vless"), user.get("trojan")) if x]
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
async def qr(uid: str, proto: str = "vless"):
    user = get_user(uid)
    if not user:
        raise HTTPException(404)
    link = user.get("vless") if proto == "vless" else user.get("trojan")
    if not link:
        raise HTTPException(404)
    img = qrcode.make(link)
    from io import BytesIO
    buf = BytesIO(); img.save(buf, format="PNG"); buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")

@app.get("/api/ping-test/{uid}")
async def ping_test(uid: str):
    user = get_user(uid)
    if not user:
        raise HTTPException(404)
    import time
    t0 = time.perf_counter()
    ok, err = False, ""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(PUBLIC_DOMAIN, 443), 5.0)
        w.close()
        try: await w.wait_closed()
        except Exception: pass
        ok = True
    except Exception as e:
        err = str(e)
    ms = int((time.perf_counter() - t0) * 1000)
    return {"ok": ok, "latency_ms": ms if ok else None, "path": f"/ws/{uid}",
            "user_enabled": is_valid(uid), "link": user.get("vless"), "error": err or None}

# CRITICAL: register websocket like pxpanel
@app.websocket("/ws/{uuid}")
async def ws_route(websocket: WebSocket, uuid: str):
    await websocket_tunnel(websocket, uuid)

@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.0", "domain": PUBLIC_DOMAIN}

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
        logger.info(f"Default user {uid}")
        logger.info(f"Sample link: {user.get('vless')}")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info", ws="websockets")

#!/usr/bin/env python3
"""
Prism Panel v2 — Professional Multi-User Proxy Panel for Railway
Real VLESS-WS-TLS + Trojan-WS-TLS | Light Theme | User Portal
"""

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

def utcnow():
    return datetime.now(timezone.utc)

from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import qrcode
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, StreamingResponse
from jinja2 import DictLoader, Environment, select_autoescape
from templates_data import INDEX, LOGIN, DASHBOARD, PORTAL
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

# ───────────────────────────── Config ─────────────────────────────
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_FILE = DATA_DIR / "prism.json"

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
PORT = int(os.getenv("PORT", "8080"))
HOST = "0.0.0.0"

PUBLIC_DOMAIN = (
    os.getenv("RAILWAY_PUBLIC_DOMAIN")
    or os.getenv("PUBLIC_DOMAIN")
    or "localhost"
)
PUBLIC_URL = (
    f"https://{PUBLIC_DOMAIN}"
    if "localhost" not in PUBLIC_DOMAIN
    else f"http://{PUBLIC_DOMAIN}:{PORT}"
)

WS_PATH_VLESS = os.getenv("WS_PATH_VLESS", "/prism-vless")
WS_PATH_TROJAN = os.getenv("WS_PATH_TROJAN", "/prism-trojan")

ALGORITHM = "HS256"
TOKEN_HOURS = 48

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prism")

# ───────────────────────────── Simple Secure Hash (no bcrypt issues) ─────────────────────────────
def _hash_password(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"{salt}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, hashed = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
        return hmac.compare_digest(dk.hex(), hashed)
    except Exception:
        return False


# ───────────────────────────── Models ─────────────────────────────
class UserCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    protocol: str = Field(default="both", pattern="^(vless|trojan|both)$")
    traffic_gb: float = Field(default=0, ge=0)
    expire_days: int = Field(default=0, ge=0)
    max_conn: int = Field(default=0, ge=0)
    note: str = Field(default="", max_length=200)
    enabled: bool = True


class UserUpdate(BaseModel):
    name: Optional[str] = None
    protocol: Optional[str] = None
    traffic_gb: Optional[float] = None
    expire_days: Optional[int] = None
    max_conn: Optional[int] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None


class LoginRequest(BaseModel):
    password: str


# ───────────────────────────── Storage ─────────────────────────────
def load_db() -> Dict[str, Any]:
    if DB_FILE.exists():
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("admin_hash", "").startswith("$2"):
                    data["admin_hash"] = _hash_password(ADMIN_PASSWORD)
                    save_db(data)
                return data
        except Exception as e:
            logger.error(f"DB load error: {e}")
    return {
        "admin_hash": _hash_password(ADMIN_PASSWORD),
        "users": {},
        "stats": {"up": 0, "down": 0},
        "created": utcnow().isoformat(),
    }


def save_db(data: Dict[str, Any]):
    try:
        tmp = DB_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        tmp.replace(DB_FILE)
    except Exception as e:
        logger.error(f"DB save error: {e}")


db = load_db()
if "admin_hash" not in db:
    db["admin_hash"] = _hash_password(ADMIN_PASSWORD)
    save_db(db)

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
            if datetime.fromisoformat(u["expire_at"]) < utcnow():
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


def refresh_links(user: Dict):
    uid = user["uuid"]
    name = user.get("name", "user")
    proto = user.get("protocol", "both")
    path_v = quote(WS_PATH_VLESS)
    path_t = quote(WS_PATH_TROJAN)
    if proto in ("vless", "both"):
        user["vless"] = (
            f"vless://{uid}@{PUBLIC_DOMAIN}:443"
            f"?encryption=none&security=tls&type=ws&host={PUBLIC_DOMAIN}"
            f"&path={path_v}&fp=chrome&sni={PUBLIC_DOMAIN}"
            f"#{quote(name + '-VLESS')}"
        )
    else:
        user["vless"] = None
    if proto in ("trojan", "both"):
        user["trojan"] = (
            f"trojan://{uid}@{PUBLIC_DOMAIN}:443"
            f"?security=tls&type=ws&host={PUBLIC_DOMAIN}"
            f"&path={path_t}&fp=chrome&sni={PUBLIC_DOMAIN}"
            f"#{quote(name + '-Trojan')}"
        )
    else:
        user["trojan"] = None
    return user


def make_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = utcnow() + timedelta(hours=TOKEN_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def require_admin(request: Request):
    token = request.session.get("token")
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") != "admin":
            raise HTTPException(403)
        return payload
    except JWTError:
        raise HTTPException(401, "Invalid session")


# ───────────────────────────── Relay ─────────────────────────────
async def handle_vless(websocket: WebSocket):
    await websocket.accept()
    uid = None
    try:
        first = await websocket.receive_bytes()
        if len(first) < 18:
            await websocket.close()
            return
        try:
            uid = str(uuid.UUID(bytes=first[1:17]))
        except Exception:
            await websocket.close()
            return
        if not is_valid(uid):
            await websocket.close(code=1008)
            return

        active_conn[uid] = active_conn.get(uid, 0) + 1
        pos = 17
        addon = first[pos]
        pos += 1 + addon
        if pos >= len(first) or first[pos] != 1:
            await websocket.close()
            return
        pos += 1
        port = struct.unpack("!H", first[pos:pos + 2])[0]
        pos += 2
        atyp = first[pos]
        pos += 1
        if atyp == 1:
            host = socket.inet_ntoa(first[pos:pos + 4])
            pos += 4
        elif atyp == 2:
            dlen = first[pos]
            pos += 1
            host = first[pos:pos + dlen].decode("utf-8", errors="ignore")
            pos += dlen
        elif atyp == 3:
            host = socket.inet_ntop(socket.AF_INET6, first[pos:pos + 16])
            pos += 16
        else:
            await websocket.close()
            return

        early = first[pos:] if pos < len(first) else b""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 12)
        except Exception:
            await websocket.close()
            return

        if early:
            writer.write(early)
            await writer.drain()
            traffic_buf.setdefault(uid, {"up": 0, "down": 0})["up"] += len(early)

        async def up():
            try:
                while True:
                    data = await websocket.receive_bytes()
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
                    traffic_buf.setdefault(uid, {"up": 0, "down": 0})["up"] += len(data)
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        async def down():
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    await websocket.send_bytes(data)
                    traffic_buf.setdefault(uid, {"up": 0, "down": 0})["down"] += len(data)
            except Exception:
                pass

        await asyncio.gather(up(), down())
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"VLESS: {e}")
    finally:
        if uid:
            active_conn[uid] = max(0, active_conn.get(uid, 1) - 1)


async def handle_trojan(websocket: WebSocket):
    await websocket.accept()
    uid = None
    try:
        first = await websocket.receive_bytes()
        if len(first) < 58:
            await websocket.close()
            return
        try:
            crlf = first.index(b"\r\n")
            pwd = first[:crlf].decode("ascii", errors="ignore")
            req = first[crlf + 2:]
        except ValueError:
            await websocket.close()
            return

        matched = None
        for u in db.get("users", {}).values():
            uhash = hashlib.sha224(u["uuid"].encode()).hexdigest()
            if u["uuid"] == pwd or uhash == pwd:
                matched = u["uuid"]
                break
        if not matched or not is_valid(matched):
            await websocket.close(code=1008)
            return
        uid = matched
        active_conn[uid] = active_conn.get(uid, 0) + 1

        if len(req) < 7 or req[0] != 1:
            await websocket.close()
            return
        atyp = req[1]
        pos = 2
        if atyp == 1:
            host = socket.inet_ntoa(req[pos:pos + 4])
            pos += 4
        elif atyp == 3:
            dlen = req[pos]
            pos += 1
            host = req[pos:pos + dlen].decode("utf-8", errors="ignore")
            pos += dlen
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, req[pos:pos + 16])
            pos += 16
        else:
            await websocket.close()
            return
        port = struct.unpack("!H", req[pos:pos + 2])[0]
        pos += 2
        early = req[pos:] if pos < len(req) else b""

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 12)
        except Exception:
            await websocket.close()
            return
        if early:
            writer.write(early)
            await writer.drain()

        async def up():
            try:
                while True:
                    data = await websocket.receive_bytes()
                    writer.write(data)
                    await writer.drain()
                    traffic_buf.setdefault(uid, {"up": 0, "down": 0})["up"] += len(data)
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        async def down():
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    await websocket.send_bytes(data)
                    traffic_buf.setdefault(uid, {"up": 0, "down": 0})["down"] += len(data)
            except Exception:
                pass

        await asyncio.gather(up(), down())
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"Trojan: {e}")
    finally:
        if uid:
            active_conn[uid] = max(0, active_conn.get(uid, 1) - 1)


# ───────────────────────────── App ─────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Prism Panel v2 starting | domain={PUBLIC_DOMAIN}")

    async def flusher():
        while True:
            await asyncio.sleep(20)
            changed = False
            for uid, t in list(traffic_buf.items()):
                if uid in db.get("users", {}) and (t["up"] or t["down"]):
                    db["users"][uid]["used_bytes"] = db["users"][uid].get("used_bytes", 0) + t["up"] + t["down"]
                    db["stats"]["up"] = db["stats"].get("up", 0) + t["up"]
                    db["stats"]["down"] = db["stats"].get("down", 0) + t["down"]
                    traffic_buf[uid] = {"up": 0, "down": 0}
                    changed = True
            if changed:
                save_db(db)

    task = asyncio.create_task(flusher())
    yield
    task.cancel()
    save_db(db)


app = FastAPI(title="Prism Panel", version="2.0", lifespan=lifespan)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    from fastapi.exceptions import HTTPException as FHTTP
    from starlette.exceptions import HTTPException as SHTTP
    if isinstance(exc, (FHTTP, SHTTP, HTTPException)):
        raise exc
    import traceback
    tb = traceback.format_exc()
    logger.error(f"Unhandled error on {request.url.path}: {exc}\n{tb}")
    return HTMLResponse(
        content=f"<h2>Server Error</h2><pre style=\"direction:ltr;text-align:left;white-space:pre-wrap\">{exc}\n\n{tb}</pre>",
        status_code=500
    )
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
# Embedded templates (no filesystem dependency — works reliably on Railway)

_jinja_env = Environment(
    loader=DictLoader({
        "index.html": INDEX,
        "login.html": LOGIN,
        "dashboard.html": DASHBOARD,
        "portal.html": PORTAL,
    }),
    autoescape=select_autoescape(["html", "xml"]),
)
templates = Jinja2Templates(env=_jinja_env)


def fmt_bytes(n: int) -> str:
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.2f} GB"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n} B"


# ───────────────────────────── Pages ─────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "domain": PUBLIC_DOMAIN,
        "url": PUBLIC_URL,
    })


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
        "request": request,
        "users": users,
        "domain": PUBLIC_DOMAIN,
        "url": PUBLIC_URL,
        "stats": db.get("stats", {}),
        "active": sum(active_conn.values()),
        "vless_path": WS_PATH_VLESS,
        "trojan_path": WS_PATH_TROJAN,
        "total_traffic": fmt_bytes(db.get("stats", {}).get("up", 0) + db.get("stats", {}).get("down", 0)),
    })


@app.get("/u/{uid}", response_class=HTMLResponse)
async def user_portal(request: Request, uid: str):
    user = get_user(uid)
    if not user:
        raise HTTPException(404, "User not found")
    remaining = None
    remaining_str = "نامحدود"
    pct = 0
    if user.get("limit_bytes", 0) > 0:
        remaining = max(0, user["limit_bytes"] - user.get("used_bytes", 0))
        remaining_str = fmt_bytes(remaining)
        pct = min(100, int((user.get("used_bytes", 0) / user["limit_bytes"]) * 100))
    expire_str = "نامحدود"
    if user.get("expire_at"):
        try:
            exp = datetime.fromisoformat(user["expire_at"])
            expire_str = exp.strftime("%Y-%m-%d %H:%M")
            if exp < utcnow():
                expire_str += " (منقضی)"
        except Exception:
            pass
    return templates.TemplateResponse("portal.html", {
        "request": request,
        "user": user,
        "domain": PUBLIC_DOMAIN,
        "url": PUBLIC_URL,
        "sub_url": f"{PUBLIC_URL}/sub/{uid}",
        "used_str": fmt_bytes(user.get("used_bytes", 0)),
        "limit_str": fmt_bytes(user["limit_bytes"]) if user.get("limit_bytes", 0) > 0 else "نامحدود",
        "remaining_str": remaining_str,
        "pct": pct,
        "expire_str": expire_str,
        "valid": is_valid(uid),
        "active": active_conn.get(uid, 0),
    })


# ───────────────────────────── API ─────────────────────────────
@app.post("/api/login")
async def api_login(req: LoginRequest, request: Request):
    if not _verify_password(req.password, db.get("admin_hash", "")):
        if req.password != ADMIN_PASSWORD:
            raise HTTPException(401, "رمز اشتباه است")
    token = make_token({"role": "admin", "sub": "admin"})
    request.session["token"] = token
    return {"ok": True}


@app.post("/api/logout")
async def api_logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/api/users")
async def api_users(admin=Depends(require_admin)):
    return list(db.get("users", {}).values())


@app.post("/api/users")
async def api_create(data: UserCreate, admin=Depends(require_admin)):
    uid = str(uuid.uuid4())
    expire_at = None
    if data.expire_days > 0:
        expire_at = (utcnow() + timedelta(days=data.expire_days)).isoformat()
    user = {
        "uuid": uid,
        "name": data.name.strip(),
        "protocol": data.protocol,
        "enabled": data.enabled,
        "limit_bytes": int(data.traffic_gb * 1024 ** 3) if data.traffic_gb > 0 else 0,
        "used_bytes": 0,
        "max_conn": data.max_conn,
        "expire_at": expire_at,
        "note": data.note.strip(),
        "created": utcnow().isoformat(),
    }
    refresh_links(user)
    db.setdefault("users", {})[uid] = user
    save_db(db)
    return user


@app.patch("/api/users/{uid}")
async def api_update(uid: str, data: UserUpdate, admin=Depends(require_admin)):
    user = get_user(uid)
    if not user:
        raise HTTPException(404)
    if data.name is not None:
        user["name"] = data.name.strip()
    if data.protocol is not None:
        user["protocol"] = data.protocol
    if data.traffic_gb is not None:
        user["limit_bytes"] = int(data.traffic_gb * 1024 ** 3) if data.traffic_gb > 0 else 0
    if data.expire_days is not None:
        if data.expire_days > 0:
            user["expire_at"] = (utcnow() + timedelta(days=data.expire_days)).isoformat()
        else:
            user["expire_at"] = None
    if data.max_conn is not None:
        user["max_conn"] = data.max_conn
    if data.note is not None:
        user["note"] = data.note.strip()
    if data.enabled is not None:
        user["enabled"] = data.enabled
    refresh_links(user)
    save_db(db)
    return user


@app.delete("/api/users/{uid}")
async def api_delete(uid: str, admin=Depends(require_admin)):
    if uid in db.get("users", {}):
        del db["users"][uid]
        save_db(db)
    return {"ok": True}


@app.post("/api/users/{uid}/reset")
async def api_reset_traffic(uid: str, admin=Depends(require_admin)):
    user = get_user(uid)
    if not user:
        raise HTTPException(404)
    user["used_bytes"] = 0
    save_db(db)
    return {"ok": True}


@app.get("/sub/{uid}")
async def subscription(uid: str):
    user = get_user(uid)
    if not user or not is_valid(uid):
        raise HTTPException(404)
    lines = []
    if user.get("vless"):
        lines.append(user["vless"])
    if user.get("trojan"):
        lines.append(user["trojan"])
    content = base64.b64encode("\n".join(lines).encode()).decode()
    used = user.get("used_bytes", 0)
    total = user.get("limit_bytes", 0)
    expire = 0
    if user.get("expire_at"):
        try:
            expire = int(datetime.fromisoformat(user["expire_at"]).timestamp())
        except Exception:
            pass
    headers = {
        "subscription-userinfo": f"upload=0; download={used}; total={total}; expire={expire}",
        "profile-update-interval": "12",
        "content-disposition": f'attachment; filename="{user.get("name", "prism")}.txt"',
    }
    return Response(content=content, media_type="text/plain; charset=utf-8", headers=headers)


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
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/api/stats")
async def api_stats(admin=Depends(require_admin)):
    return {
        "users": len(db.get("users", {})),
        "active": sum(active_conn.values()),
        "up": db.get("stats", {}).get("up", 0),
        "down": db.get("stats", {}).get("down", 0),
        "domain": PUBLIC_DOMAIN,
    }


@app.websocket(WS_PATH_VLESS)
async def ws_vless(websocket: WebSocket):
    await handle_vless(websocket)


@app.websocket(WS_PATH_TROJAN)
async def ws_trojan(websocket: WebSocket):
    await handle_trojan(websocket)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0", "domain": PUBLIC_DOMAIN}


if __name__ == "__main__":
    if not db.get("users"):
        uid = str(uuid.uuid4())
        user = {
            "uuid": uid,
            "name": "Default",
            "protocol": "both",
            "enabled": True,
            "limit_bytes": 0,
            "used_bytes": 0,
            "max_conn": 0,
            "expire_at": None,
            "note": "کاربر پیش‌فرض",
            "created": utcnow().isoformat(),
        }
        refresh_links(user)
        db["users"][uid] = user
        save_db(db)
        logger.info(f"Default user created: {uid}")

    logger.info(f"Admin password via ADMIN_PASSWORD (default=admin)")
    logger.info(f"Panel → {PUBLIC_URL}/login")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info", ws="websockets")

"""
SIEM Authentication & RBAC — v3.1
JWT-based auth + Google Authenticator (TOTP/RFC-6238) MFA.

MFA Flow:
  Step 1 — POST /api/auth/login        { username, password }
           → { ok, mfa_required, mfa_token }   (if MFA enabled for user)
           → { ok, token, role }               (if MFA not yet enabled)

  Step 2 — POST /api/auth/mfa/verify   { mfa_token, totp_code }
           → { ok, token, role }

MFA Setup (per user, after login):
  GET  /api/auth/mfa/setup             → { secret, qr_uri, qr_svg, qr_png_b64 }
  POST /api/auth/mfa/enable            { totp_code }  → activates MFA
  POST /api/auth/mfa/disable           { totp_code }  → deactivates MFA
  GET  /api/auth/mfa/status            → { mfa_enabled }
  POST /api/auth/mfa/reset/<username>  (admin only)   → wipes MFA (lost phone)

Roles:
  admin   — full access
  analyst — read alerts, run reports, acknowledge/resolve
  viewer  — read-only

No PyJWT or pyotp dependency — everything is pure Python stdlib.
"""

import json
import hmac
import hashlib
import secrets
import struct
import time
import base64
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from typing import Optional, Dict

from flask import Blueprint, request, jsonify, g

# ─────────────────────────────────────────────
# Module config  (overridden by init_auth)
# ─────────────────────────────────────────────

_SECRET_KEY = "change-this-secret-in-production"
_TOKEN_TTL  = 8 * 3600          # 8 h  — full session JWT
_MFA_TTL    = 5 * 60            # 5 min — short-lived step-up token
_USERS_FILE = Path("./siem_data/users.json")
_ISSUER     = "TysonicSIEM"

auth_bp = Blueprint("auth", __name__)

# ─────────────────────────────────────────────
# Default users & roles
# ─────────────────────────────────────────────

DEFAULT_USERS = {
    "admin":   {"role": "admin"},
    "analyst": {"role": "analyst"},
    "viewer":  {"role": "viewer"},
}
DEFAULT_PASSWORDS = {
    "admin":   "Admin@SIEM2025!",
    "analyst": "Analyst@SIEM2025!",
    "viewer":  "Viewer@SIEM2025!",
}

ROLE_PERMISSIONS = {
    "viewer":  {
        "GET":    ["/api/health", "/api/alerts", "/api/stats", "/api/config",
                   "/api/geo/alerts", "/api/mitre", "/api/risk", "/api/anomalies",
                   "/api/timeline", "/api/top-attackers", "/api/detection-rules",
                   "/api/reports/list", "/api/stream", "/"],
        "POST":   [], "PUT": [], "DELETE": [],
    },
    "analyst": {
        "GET":    ["*"],
        "POST":   ["/api/alerts/*/report", "/api/ingest", "/api/reports/bulk"],
        "PUT":    ["/api/alerts/*/status"],
        "DELETE": [],
    },
    "admin":   {"GET": ["*"], "POST": ["*"], "PUT": ["*"], "DELETE": ["*"]},
}


# ═════════════════════════════════════════════
# TOTP — RFC 6238 / RFC 4226 (pure Python stdlib)
# ═════════════════════════════════════════════

def _totp_generate_secret() -> str:
    """Generate a 20-byte random secret, base32-encoded (no padding)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_hotp(secret_b32: str, counter: int) -> str:
    """Compute HOTP value (6 digits) for a given counter."""
    secret_b32 = secret_b32.upper()
    pad = (8 - len(secret_b32) % 8) % 8
    key = base64.b32decode(secret_b32 + "=" * pad)
    msg = struct.pack(">Q", counter)
    h   = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code   = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)


def _totp_valid_codes(secret_b32: str, window: int = 1) -> list:
    """Return valid TOTP codes for current time ± window * 30s steps."""
    t = int(time.time()) // 30
    return [_totp_hotp(secret_b32, t + i) for i in range(-window, window + 1)]


def totp_verify(secret_b32: str, code: str) -> bool:
    """Verify a 6-digit TOTP code. Allows ±1 step (30 s) clock drift."""
    return str(code).strip() in _totp_valid_codes(secret_b32, window=1)


def totp_uri(secret_b32: str, username: str) -> str:
    """Build the otpauth:// URI that Google Authenticator reads from QR."""
    from urllib.parse import quote
    label = quote(f"{_ISSUER}:{username}")
    return (f"otpauth://totp/{label}"
            f"?secret={secret_b32}&issuer={quote(_ISSUER)}"
            f"&algorithm=SHA1&digits=6&period=30")


# ─────────────────────────────────────────────
# QR Code generation
# Uses `qrcode` library if installed:
#   pip install qrcode[pil]
# Falls back to an SVG instruction card if not.
# ─────────────────────────────────────────────

def _make_qr_png_b64(uri: str) -> str:
    """Return base64-encoded PNG QR code, or '' if qrcode not installed."""
    try:
        import qrcode, io
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=6, border=2
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return ""


def _make_qr_svg(uri: str) -> str:
    """Return SVG QR code string, or fallback instruction SVG."""
    try:
        import qrcode
        import qrcode.image.svg
        import io
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=4, border=2
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode()
    except Exception:
        # Fallback SVG — tells user to enter the secret manually
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="220" height="80">'
            '<rect width="220" height="80" fill="#fff"/>'
            '<text x="10" y="18" font-size="12" font-family="monospace" fill="#c00">'
            'Install: pip install qrcode[pil]</text>'
            '<text x="10" y="36" font-size="11" font-family="monospace" fill="#333">'
            'Then restart the server to get QR code.</text>'
            '<text x="10" y="56" font-size="11" font-family="monospace" fill="#000">'
            'For now, enter the secret manually.</text>'
            '</svg>'
        )


# ═════════════════════════════════════════════
# Password hashing  (SHA-256 HMAC + random salt)
# ═════════════════════════════════════════════

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h    = hmac.new(_SECRET_KEY.encode(), (salt + password).encode(), hashlib.sha256).hexdigest()
    return f"{salt}${h}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
        expected = hmac.new(_SECRET_KEY.encode(), (salt + password).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(h, expected)
    except Exception:
        return False


# ═════════════════════════════════════════════
# JWT  (HS256 — pure stdlib, no PyJWT)
# ═════════════════════════════════════════════

def _b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))


def _create_token(username: str, role: str, ttl: int = None, extra: dict = None) -> str:
    ttl = ttl or _TOKEN_TTL
    hdr = _b64url_enc(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pay = {"sub": username, "role": role,
           "iat": int(time.time()), "exp": int(time.time()) + ttl}
    if extra:
        pay.update(extra)
    pay_b64 = _b64url_enc(json.dumps(pay).encode())
    sig = _b64url_enc(
        hmac.new(_SECRET_KEY.encode(), f"{hdr}.{pay_b64}".encode(), hashlib.sha256).digest()
    )
    return f"{hdr}.{pay_b64}.{sig}"


def _verify_token(token: str) -> Optional[Dict]:
    try:
        hdr, pay_b64, sig = token.split(".")
        expected = _b64url_enc(
            hmac.new(_SECRET_KEY.encode(), f"{hdr}.{pay_b64}".encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(sig, expected):
            return None
        pay = json.loads(_b64url_dec(pay_b64))
        if pay.get("exp", 0) < time.time():
            return None
        return pay
    except Exception:
        return None


# ═════════════════════════════════════════════
# User store
# ═════════════════════════════════════════════

def _load_users() -> Dict:
    if _USERS_FILE.exists():
        try:
            with open(_USERS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_users(users: Dict):
    _USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def _get_user(username: str) -> Optional[Dict]:
    return _load_users().get(username)


# ═════════════════════════════════════════════
# Init
# ═════════════════════════════════════════════

def init_auth(app, secret_key: str = "", data_dir: str = "./siem_data"):
    global _SECRET_KEY, _USERS_FILE
    if secret_key:
        _SECRET_KEY = secret_key
    _USERS_FILE = Path(data_dir) / "users.json"

    if not _USERS_FILE.exists():
        # First run — create default users with MFA fields
        users = {}
        now   = datetime.now(timezone.utc).isoformat()
        for uname, meta in DEFAULT_USERS.items():
            users[uname] = {
                "password_hash": _hash_password(DEFAULT_PASSWORDS[uname]),
                "role":          meta["role"],
                "created_at":    now,
                "last_login":    None,
                "mfa_enabled":   False,
                "mfa_secret":    None,
                "mfa_pending":   None,
            }
        _save_users(users)
        print("[Auth] Default users created. CHANGE PASSWORDS IMMEDIATELY.")
        for u, p in DEFAULT_PASSWORDS.items():
            print(f"       {u:10s} / {p}")
    else:
        # Migrate existing users — add MFA fields if absent
        users   = _load_users()
        changed = False
        for d in users.values():
            if "mfa_enabled" not in d:
                d.update({"mfa_enabled": False, "mfa_secret": None, "mfa_pending": None})
                changed = True
        if changed:
            _save_users(users)
            print("[Auth] Existing users migrated — MFA fields added.")

    print("[Auth] v3.1 ready — Google Authenticator MFA supported.")


# ═════════════════════════════════════════════
# Decorators
# ═════════════════════════════════════════════


def _gettoken_from_request() -> str:
    """Extract JWT from Authorization header or cookie."""
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Bearer "):
        return hdr[7:]
    return request.cookies.get("siem_token", "")

def require_auth(f):
    """Require a valid full-session JWT. Rejects MFA step-up tokens."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        hdr   = request.headers.get("Authorization", "")
        if hdr.startswith("Bearer "):
            token = hdr[7:]
        if not token:
            token = request.cookies.get("siem_token")
        if not token:
            return jsonify({"error": "Authentication required", "code": 401}), 401
        payload = _verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token", "code": 401}), 401
        if payload.get("type") == "mfa_pending":
            return jsonify({"error": "MFA verification required — call /api/auth/mfa/verify", "code": 401}), 401
        # setup_required tokens are only valid for /api/auth/mfa/* endpoints
        if payload.get("type") == "setup_required":
            allowed_paths = ["/api/auth/mfa/setup", "/api/auth/mfa/enable", "/api/auth/mfa/status", "/api/auth/me"]
            if not any(request.path.startswith(p) for p in allowed_paths):
                return jsonify({"error": "MFA setup required before accessing the dashboard", "code": 403, "setup_required": True}), 403
        g.user = payload["sub"]
        g.role = payload["role"]
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    """Require auth + membership in one of the specified roles."""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated(*args, **kwargs):
            if g.role not in roles:
                return jsonify({
                    "error": f"Insufficient permissions. Required: {list(roles)}, your role: {g.role}",
                    "code":  403,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ═════════════════════════════════════════════
# Internal helper
# ═════════════════════════════════════════════

def _issue_session(username: str, user: dict):
    """Issue full-session JWT, update last_login, set httponly cookie."""
    token = _create_token(username, user["role"])
    users = _load_users()
    if username in users:
        users[username]["last_login"] = datetime.now(timezone.utc).isoformat()
        _save_users(users)
    resp = jsonify({
        "ok":          True,
        "token":       token,
        "username":    username,
        "role":        user["role"],
        "mfa_enabled": bool(user.get("mfa_enabled")),
        "expires_in":  _TOKEN_TTL,
    })
    resp.set_cookie("siem_token", token, httponly=True, samesite="Lax", max_age=_TOKEN_TTL)
    return resp


# ═════════════════════════════════════════════
# Auth routes
# ═════════════════════════════════════════════

# ── Step 1: password ──────────────────────────

@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    body     = request.get_json(force=True)
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = _get_user(username)
    if not user or not _verify_password(password, user["password_hash"]):
        time.sleep(0.3)   # constant-time delay — prevents user enumeration
        return jsonify({"error": "Invalid credentials"}), 401

    # MFA enabled → issue short-lived step-up token
    if user.get("mfa_enabled") and user.get("mfa_secret"):
        mfa_token = _create_token(
            username, user["role"],
            ttl=_MFA_TTL,
            extra={"type": "mfa_pending"}
        )
        return jsonify({
            "ok":           True,
            "mfa_required": True,
            "mfa_token":    mfa_token,
            "message":      "Password accepted. Enter the 6-digit code from Google Authenticator.",
        })

    # MFA not yet set up → issue a temporary setup token
    # The registration flow uses this to call /api/auth/mfa/setup immediately after account creation
    # On normal login, the frontend should redirect to MFA setup page
    setup_token = _create_token(username, user["role"], ttl=30*60, extra={"type": "setup_required"})
    return jsonify({
        "ok":             True,
        "setup_required": True,
        "setup_token":    setup_token,
        "message":        "MFA not configured. Complete Google Authenticator setup to continue.",
    })


# ── Step 2: TOTP code ────────────────────────

@auth_bp.route("/api/auth/mfa/verify", methods=["POST"])
def mfa_verify():
    body      = request.get_json(force=True)
    mfa_token = body.get("mfa_token", "")
    totp_code = str(body.get("totp_code", "")).strip()

    if not mfa_token or not totp_code:
        return jsonify({"error": "mfa_token and totp_code required"}), 400

    payload = _verify_token(mfa_token)
    if not payload or payload.get("type") != "mfa_pending":
        return jsonify({"error": "Invalid or expired MFA token. Please log in again."}), 401

    username = payload["sub"]
    user     = _get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 401

    if not totp_verify(user.get("mfa_secret", ""), totp_code):
        time.sleep(0.3)
        return jsonify({"error": "Invalid TOTP code. Check your Google Authenticator app."}), 401

    return _issue_session(username, user)


# ── MFA Setup: generate secret + QR ─────────

@auth_bp.route("/api/auth/mfa/setup", methods=["GET"])
@require_auth
def mfa_setup():
    """
    Generate a new TOTP secret for the authenticated user.
    Saves it as mfa_pending (not active) until confirmed with /mfa/enable.
    Returns: secret (for manual entry), otpauth URI, SVG QR, PNG QR (b64).
    """
    users = _load_users()
    if g.user not in users:
        return jsonify({"error": "User not found"}), 404

    secret  = _totp_generate_secret()
    uri     = totp_uri(secret, g.user)
    svg     = _make_qr_svg(uri)
    png_b64 = _make_qr_png_b64(uri)

    # Save as pending — not active until /mfa/enable is called with a valid code
    users[g.user]["mfa_pending"] = secret
    _save_users(users)

    return jsonify({
        "ok":          True,
        "username":    g.user,
        "secret":      secret,
        "otpauth_uri": uri,
        "qr_svg":      svg,
        "qr_png_b64":  png_b64,   # data:image/png;base64,<this value>
        "instructions": [
            "1. Open Google Authenticator on your phone.",
            "2. Tap  +  →  Scan a QR code  (or  Enter a setup key ).",
            f"3. Manual entry → Account: {g.user}   Key: {secret}",
            "4. POST /api/auth/mfa/enable with { \"totp_code\": \"123456\" } to confirm.",
        ],
    })


# ── MFA Enable: confirm + activate ──────────

@auth_bp.route("/api/auth/mfa/enable", methods=["POST"])
@require_auth
def mfa_enable():
    """Confirm the TOTP setup by providing the first valid code."""
    body      = request.get_json(force=True)
    totp_code = str(body.get("totp_code", "")).strip()

    if not totp_code:
        return jsonify({"error": "totp_code required"}), 400

    users = _load_users()
    user  = users.get(g.user)
    if not user:
        return jsonify({"error": "User not found"}), 404

    pending = user.get("mfa_pending")
    if not pending:
        return jsonify({"error": "No pending setup. Call GET /api/auth/mfa/setup first."}), 400

    if not totp_verify(pending, totp_code):
        return jsonify({
            "error": "Invalid TOTP code. Make sure you scanned / entered the latest secret.",
        }), 401

    # Promote pending secret → active
    users[g.user]["mfa_secret"]  = pending
    users[g.user]["mfa_pending"] = None
    users[g.user]["mfa_enabled"] = True
    _save_users(users)

    return jsonify({
        "ok":      True,
        "message": f"Google Authenticator MFA is now ENABLED for '{g.user}'.",
    })


# ── MFA Disable ──────────────────────────────

@auth_bp.route("/api/auth/mfa/disable", methods=["POST"])
@require_auth
def mfa_disable():
    """Disable MFA. Requires a valid current TOTP code as proof of possession."""
    body      = request.get_json(force=True)
    totp_code = str(body.get("totp_code", "")).strip()

    users = _load_users()
    user  = users.get(g.user)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if not user.get("mfa_enabled"):
        return jsonify({"error": "MFA is not currently enabled for this account."}), 400
    if not totp_verify(user["mfa_secret"], totp_code):
        return jsonify({"error": "Invalid TOTP code"}), 401

    users[g.user]["mfa_enabled"] = False
    users[g.user]["mfa_secret"]  = None
    users[g.user]["mfa_pending"] = None
    _save_users(users)

    return jsonify({"ok": True, "message": "MFA disabled."})


# ── MFA Status ───────────────────────────────

@auth_bp.route("/api/auth/mfa/status", methods=["GET"])
@require_auth
def mfa_status():
    user = _get_user(g.user)
    return jsonify({
        "ok":          True,
        "username":    g.user,
        "mfa_enabled": bool(user.get("mfa_enabled")) if user else False,
    })


# ── Admin: reset another user's MFA ─────────

@auth_bp.route("/api/auth/mfa/reset/<target_user>", methods=["POST"])
@require_role("admin")
def mfa_reset(target_user):
    """
    Admin-only endpoint to wipe MFA for any user.
    Use when a user loses access to their authenticator app.
    """
    users = _load_users()
    if target_user not in users:
        return jsonify({"error": "User not found"}), 404
    users[target_user]["mfa_enabled"] = False
    users[target_user]["mfa_secret"]  = None
    users[target_user]["mfa_pending"] = None
    _save_users(users)
    return jsonify({"ok": True, "message": f"MFA reset for '{target_user}'. They can re-enrol at /api/auth/mfa/setup."})


# ── Standard endpoints ────────────────────────

@auth_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    resp = jsonify({"ok": True, "message": "Logged out"})
    resp.delete_cookie("siem_token")
    return resp


@auth_bp.route("/api/auth/me")
@require_auth
def me():
    user = _get_user(g.user)
    payload = _verify_token(_gettoken_from_request())
    setup_required = payload.get("type") == "setup_required" if payload else False
    return jsonify({
        "ok":            True,
        "username":      g.user,
        "role":          g.role,
        "mfa_enabled":   bool(user.get("mfa_enabled")) if user else False,
        "setup_required": setup_required,
        "last_login":    user.get("last_login") if user else None,
    })


@auth_bp.route("/api/auth/change-password", methods=["POST"])
@require_auth
def change_password():
    body        = request.get_json(force=True)
    current_pwd = body.get("current_password", "")
    new_pwd     = body.get("new_password", "")
    if len(new_pwd) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400
    users = _load_users()
    user  = users.get(g.user)
    if not user or not _verify_password(current_pwd, user["password_hash"]):
        return jsonify({"error": "Current password incorrect"}), 401
    users[g.user]["password_hash"] = _hash_password(new_pwd)
    _save_users(users)
    return jsonify({"ok": True, "message": "Password changed"})


@auth_bp.route("/api/auth/users", methods=["GET"])
@require_role("admin")
def list_users():
    users = _load_users()
    return jsonify({"ok": True, "data": [
        {
            "username":    u,
            "role":        d["role"],
            "mfa_enabled": bool(d.get("mfa_enabled")),
            "last_login":  d.get("last_login"),
            "created_at":  d.get("created_at"),
        }
        for u, d in users.items()
    ]})


@auth_bp.route("/api/auth/users", methods=["POST"])
@require_role("admin")
def create_user():
    body     = request.get_json(force=True)
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")
    role     = body.get("role", "viewer")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if role not in ("admin", "analyst", "viewer"):
        return jsonify({"error": "role must be admin, analyst, or viewer"}), 400
    if len(password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400
    users = _load_users()
    if username in users:
        return jsonify({"error": f"User '{username}' already exists"}), 409
    users[username] = {
        "password_hash": _hash_password(password),
        "role":          role,
        "created_at":    datetime.now(timezone.utc).isoformat(),
        "last_login":    None,
        "mfa_enabled":   False,
        "mfa_secret":    None,
        "mfa_pending":   None,
    }
    _save_users(users)
    return jsonify({
        "ok":       True,
        "username": username,
        "role":     role,
        "message":  "Account created. Login and complete Google Authenticator setup to activate.",
    }), 201


@auth_bp.route("/api/auth/users/<username>", methods=["DELETE"])
@require_role("admin")
def delete_user(username):
    if username == g.user:
        return jsonify({"error": "Cannot delete your own account"}), 400
    users = _load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    del users[username]
    _save_users(users)
    return jsonify({"ok": True})


print("[Auth] auth.py v3.1 loaded — Google Authenticator TOTP MFA ready.")
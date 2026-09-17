from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import time
from dataclasses import asdict, dataclass
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .core import CaddyClient, Route, RouteManager, password_hash_is_valid, secure_compare_password


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    username: str
    password_hash: str
    session_secret: bytes
    caddy_api_url: str
    caddyfile_path: Path
    sites_dir: Path
    backup_dir: Path
    audit_path: Path
    cookie_secure: bool

    @classmethod
    def from_env(cls) -> "Settings":
        password_hash = os.environ.get("ADMIN_PASSWORD_HASH", "").strip()
        session_secret = os.environ.get("SESSION_SECRET", "").encode()
        if not password_hash_is_valid(password_hash):
            raise RuntimeError("ADMIN_PASSWORD_HASH no tiene un formato PBKDF2 válido.")
        if len(session_secret) < 32:
            raise RuntimeError("SESSION_SECRET debe tener al menos 32 caracteres.")
        return cls(
            host=os.environ.get("LISTEN_HOST", "0.0.0.0"),
            port=int(os.environ.get("LISTEN_PORT", "8080")),
            username=os.environ.get("ADMIN_USERNAME", "admin"),
            password_hash=password_hash,
            session_secret=session_secret,
            caddy_api_url=os.environ.get("CADDY_API_URL", "http://caddy:2019"),
            caddyfile_path=Path(os.environ.get("CADDYFILE_PATH", "/config/Caddyfile")),
            sites_dir=Path(os.environ.get("SITES_DIR", "/config/sites.d")),
            backup_dir=Path(os.environ.get("BACKUP_DIR", "/data/backups")),
            audit_path=Path(os.environ.get("AUDIT_PATH", "/data/audit.jsonl")),
            cookie_secure=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
        )


class Application:
    def __init__(self, settings: Settings, manager: RouteManager):
        self.settings = settings
        self.manager = manager

    def make_session(self, username: str) -> str:
        payload = json.dumps(
            {"u": username, "exp": int(time.time()) + 12 * 3600, "n": secrets.token_hex(8)},
            separators=(",", ":"),
        ).encode()
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
        signature = hmac.new(self.settings.session_secret, encoded, hashlib.sha256).hexdigest().encode()
        return (encoded + b"." + signature).decode()

    def read_session(self, value: str | None) -> dict | None:
        if not value or "." not in value:
            return None
        encoded, signature = value.rsplit(".", 1)
        expected = hmac.new(self.settings.session_secret, encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            data = json.loads(raw)
            if int(data["exp"]) < int(time.time()):
                return None
            return data
        except (ValueError, KeyError, json.JSONDecodeError):
            return None

    def csrf(self, session_value: str) -> str:
        return hmac.new(self.settings.session_secret, ("csrf:" + session_value).encode(), hashlib.sha256).hexdigest()


class Handler(BaseHTTPRequestHandler):
    server_version = "CaddyControl/0.1"

    @property
    def app(self) -> Application:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _cookies(self) -> cookies.SimpleCookie:
        jar = cookies.SimpleCookie()
        jar.load(self.headers.get("Cookie", ""))
        return jar

    def _session_value(self) -> str | None:
        morsel = self._cookies().get("cc_session")
        return morsel.value if morsel else None

    def _session(self) -> dict | None:
        return self.app.read_session(self._session_value())

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > 32_768:
            raise ValueError("Cuerpo de petición no válido.")
        return json.loads(self.rfile.read(length))

    def _json(self, status: int, body: dict | list) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def _serve_file(self, path: Path, content_type: str | None = None) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type or mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _require_auth(self) -> tuple[dict, str] | None:
        value = self._session_value()
        session = self.app.read_session(value)
        if not value or not session:
            self._json(401, {"error": "Sesión no válida."})
            return None
        return session, value

    def _require_csrf(self, session_value: str) -> bool:
        received = self.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(received, self.app.csrf(session_value)):
            self._json(403, {"error": "Token CSRF no válido."})
            return False
        return True

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/healthz":
            self._json(200, {"status": "ok"})
        elif path == "/login":
            if self._session():
                self._redirect("/")
            else:
                self._serve_file(STATIC / "login.html", "text/html; charset=utf-8")
        elif path == "/":
            value = self._session_value()
            if not value or not self.app.read_session(value):
                self._redirect("/login")
                return
            html = (STATIC / "index.html").read_text(encoding="utf-8")
            html = html.replace("__CSRF_TOKEN__", self.app.csrf(value))
            data = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path.startswith("/static/") and ".." not in path:
            self._serve_file(STATIC / path.removeprefix("/static/"))
        elif path == "/api/routes":
            if not self._require_auth():
                return
            self._json(200, [asdict(route) for route in self.app.manager.list_routes()])
        elif path == "/api/status":
            if not self._require_auth():
                return
            try:
                import_present = "sites.d/*.caddy" in self.app.manager.caddyfile_path.read_text(encoding="utf-8")
            except OSError:
                import_present = False
            self._json(200, {"managed_routes": len(self.app.manager.list_routes()), "import_present": import_present})
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/login":
            length = min(int(self.headers.get("Content-Length", "0")), 8192)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            if username != self.app.settings.username or not secure_compare_password(password, self.app.settings.password_hash):
                time.sleep(0.35)
                self._redirect("/login?error=1")
                return
            value = self.app.make_session(username)
            self.send_response(303)
            self.send_header("Location", "/")
            options = f"cc_session={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200"
            if self.app.settings.cookie_secure:
                options += "; Secure"
            self.send_header("Set-Cookie", options)
            self.end_headers()
            return
        auth = self._require_auth()
        if not auth:
            return
        session, value = auth
        if not self._require_csrf(value):
            return
        if path == "/logout":
            self.send_response(303)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "cc_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
            self.end_headers()
        elif path == "/api/routes":
            try:
                route = Route.from_mapping(self._read_json())
                self.app.manager.save(route, str(session["u"]))
                self._json(200, asdict(route))
            except (ValueError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})
            except Exception as exc:
                self._json(502, {"error": str(exc)})
        else:
            self.send_error(404)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        auth = self._require_auth()
        if not auth:
            return
        session, value = auth
        if not self._require_csrf(value):
            return
        if not path.startswith("/api/routes/"):
            self.send_error(404)
            return
        route_id = path.removeprefix("/api/routes/")
        try:
            self.app.manager.delete(route_id, str(session["u"]))
            self._json(200, {"deleted": route_id})
        except FileNotFoundError:
            self._json(404, {"error": "La ruta no existe."})
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(502, {"error": str(exc)})


def main() -> None:
    settings = Settings.from_env()
    manager = RouteManager(
        settings.sites_dir,
        settings.caddyfile_path,
        settings.backup_dir,
        settings.audit_path,
        CaddyClient(settings.caddy_api_url),
    )
    server = ThreadingHTTPServer((settings.host, settings.port), Handler)
    server.app = Application(settings, manager)  # type: ignore[attr-defined]
    print(f"Caddy Control escuchando en {settings.host}:{settings.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

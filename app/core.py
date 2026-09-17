from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol


ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-zA-Z0-9._-]+$")
META_PREFIX = "# caddy-control: "


@dataclass(frozen=True)
class Route:
    id: str
    name: str
    domain: str
    scheme: str
    upstream_host: str
    upstream_port: int
    tls_insecure_skip_verify: bool = False

    @classmethod
    def from_mapping(cls, value: dict) -> "Route":
        route = cls(
            id=str(value.get("id", "")).strip().lower(),
            name=str(value.get("name", "")).strip(),
            domain=str(value.get("domain", "")).strip().lower().rstrip("."),
            scheme=str(value.get("scheme", "http")).strip().lower(),
            upstream_host=str(value.get("upstream_host", "")).strip(),
            upstream_port=int(value.get("upstream_port", 0)),
            tls_insecure_skip_verify=bool(value.get("tls_insecure_skip_verify", False)),
        )
        route.validate()
        return route

    def validate(self) -> None:
        if not ID_RE.fullmatch(self.id):
            raise ValueError("El identificador debe usar minúsculas, números y guiones (máximo 48).")
        if not self.name or len(self.name) > 80 or any(c in self.name for c in "\r\n"):
            raise ValueError("El nombre es obligatorio y debe tener como máximo 80 caracteres.")
        if not DOMAIN_RE.fullmatch(self.domain):
            raise ValueError("El dominio no es válido.")
        if self.scheme not in {"http", "https"}:
            raise ValueError("El esquema debe ser http o https.")
        if not 1 <= self.upstream_port <= 65535:
            raise ValueError("El puerto debe estar entre 1 y 65535.")
        try:
            ipaddress.ip_address(self.upstream_host.strip("[]"))
        except ValueError:
            if not HOST_RE.fullmatch(self.upstream_host):
                raise ValueError("El host de destino no es válido.")

    def render(self) -> str:
        matcher = self.id.replace("-", "_")
        host = self.upstream_host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        lines = [
            "# Managed by Caddy Control. Manual changes may be overwritten.",
            META_PREFIX + json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":")),
            f"@cc_{matcher} host {self.domain}",
            f"handle @cc_{matcher} {{",
            f"    reverse_proxy {self.scheme}://{host}:{self.upstream_port} {{",
        ]
        if self.scheme == "https" and self.tls_insecure_skip_verify:
            lines.extend([
                "        transport http {",
                "            tls_insecure_skip_verify",
                "        }",
            ])
        lines.extend(["    }", "}", ""])
        return "\n".join(lines)


class CaddyAPI(Protocol):
    def validate_and_load(self, caddyfile: str) -> None: ...


class CaddyClient:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _post(self, path: str, body: bytes, content_type: str) -> bytes:
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            method="POST",
            headers={"Content-Type": content_type},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:1000]
            raise RuntimeError(f"Caddy rechazó la configuración ({exc.code}): {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"No se pudo conectar con la API de Caddy: {exc.reason}") from exc

    def validate_and_load(self, caddyfile: str) -> None:
        adapted = self._post("/adapt", caddyfile.encode(), "text/caddyfile")
        try:
            json.loads(adapted)
        except json.JSONDecodeError as exc:
            raise RuntimeError("La API de Caddy devolvió una configuración no válida.") from exc
        self._post("/load", adapted, "application/json")


class RouteManager:
    def __init__(
        self,
        sites_dir: Path,
        caddyfile_path: Path,
        backup_dir: Path,
        audit_path: Path,
        caddy: CaddyAPI,
        max_backups: int = 20,
    ):
        self.sites_dir = sites_dir
        self.caddyfile_path = caddyfile_path
        self.backup_dir = backup_dir
        self.audit_path = audit_path
        self.caddy = caddy
        self.max_backups = max_backups
        self.lock = threading.Lock()
        self.sites_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

    def list_routes(self) -> list[Route]:
        routes: list[Route] = []
        for path in sorted(self.sites_dir.glob("*.caddy")):
            try:
                for line in path.read_text(encoding="utf-8").splitlines()[:5]:
                    if line.startswith(META_PREFIX):
                        routes.append(Route.from_mapping(json.loads(line[len(META_PREFIX) :])))
                        break
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        return routes

    def _route_path(self, route_id: str) -> Path:
        if not ID_RE.fullmatch(route_id):
            raise ValueError("Identificador de ruta no válido.")
        return self.sites_dir / f"{route_id}.caddy"

    def _atomic_write(self, path: Path, content: str) -> None:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o640)
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def _backup(self) -> Path:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        destination = self.backup_dir / stamp
        destination.mkdir()
        if self.caddyfile_path.exists():
            shutil.copy2(self.caddyfile_path, destination / "Caddyfile")
        if self.sites_dir.exists():
            shutil.copytree(self.sites_dir, destination / "sites.d")
        backups = sorted((p for p in self.backup_dir.iterdir() if p.is_dir()), reverse=True)
        for stale in backups[self.max_backups :]:
            shutil.rmtree(stale, ignore_errors=True)
        return destination

    def _reload(self) -> None:
        try:
            caddyfile = self.caddyfile_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"No se puede leer el Caddyfile: {exc}") from exc
        self.caddy.validate_and_load(caddyfile)

    def _audit(self, user: str, action: str, route_id: str, success: bool, detail: str = "") -> None:
        record = {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "user": user,
            "action": action,
            "route_id": route_id,
            "success": success,
            "detail": detail[:500],
        }
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def save(self, route: Route, user: str) -> Route:
        route.validate()
        path = self._route_path(route.id)
        with self.lock:
            previous = path.read_bytes() if path.exists() else None
            self._backup()
            try:
                self._atomic_write(path, route.render())
                self._reload()
            except Exception as exc:
                if previous is None:
                    path.unlink(missing_ok=True)
                else:
                    self._atomic_write(path, previous.decode("utf-8"))
                self._audit(user, "save", route.id, False, str(exc))
                raise
            self._audit(user, "save", route.id, True)
            return route

    def delete(self, route_id: str, user: str) -> None:
        path = self._route_path(route_id)
        with self.lock:
            if not path.exists():
                raise FileNotFoundError(route_id)
            previous = path.read_bytes()
            self._backup()
            path.unlink()
            try:
                self._reload()
            except Exception as exc:
                self._atomic_write(path, previous.decode("utf-8"))
                self._audit(user, "delete", route_id, False, str(exc))
                raise
            self._audit(user, "delete", route_id, True)


def password_digest(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def secure_compare_password(password: str, expected_hex: str) -> bool:
    return hmac.compare_digest(password_digest(password), expected_hex.lower())

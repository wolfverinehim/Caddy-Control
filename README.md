# Caddy Control

Panel web ligero para gestionar de forma segura rutas `reverse_proxy` de Caddy. Está pensado para servidores domésticos, Raspberry Pi y despliegues Docker reutilizables.

![Estado](https://img.shields.io/badge/estado-MVP-39d98a) ![Arquitecturas](https://img.shields.io/badge/arquitecturas-amd64%20%7C%20arm64-4da3ff)

## Qué incluye

- Alta, edición y eliminación de rutas desde una interfaz web.
- Inventario de las rutas `reverse_proxy` de la configuración activa de Caddy, incluidas las creadas manualmente.
- Distinción visual entre rutas gestionadas por el panel y rutas detectadas de solo lectura.
- Validación mediante la API nativa de Caddy antes de cargar cambios.
- Escritura atómica, copias automáticas y rollback si Caddy rechaza el cambio.
- Sesiones firmadas, protección CSRF y validación estricta de entradas.
- Registro de auditoría JSON Lines.
- Contenedor sin privilegios, sistema de archivos de solo lectura y sin acceso a `docker.sock`.
- Imágenes multi-arquitectura para `linux/amd64` y `linux/arm64`.

## Modelo de configuración

Caddy Control no reescribe todo el `Caddyfile`. Cada ruta se guarda como un fragmento propio en `sites.d/`, y el `Caddyfile` principal lo importa dentro del bloque wildcard:

```caddyfile
{
    admin 0.0.0.0:2019
}

*.home.example.com {
    tls {
        dns duckdns {env.DUCKDNS_API_TOKEN}
    }

    import /etc/caddy/sites.d/*.caddy
    respond "Servicio no encontrado" 404
}
```

La API administrativa (`2019`) debe estar disponible **solo** en una red Docker privada. Nunca publiques ese puerto en el host.

## Instalación junto a un Caddy existente

### 1. Prepara la configuración de Caddy

En el servicio `caddy` de tu Compose:

```yaml
services:
  caddy:
    networks:
      - default
      - caddy-admin
    volumes:
      - /srv/caddy:/etc/caddy

networks:
  caddy-admin:
    external: true
```

Crea la red una vez:

```bash
docker network create --internal caddy-admin
mkdir -p /srv/caddy/sites.d
```

Añade `admin 0.0.0.0:2019` al bloque global y `import /etc/caddy/sites.d/*.caddy` dentro de tu bloque wildcard, como en el ejemplo anterior. Conserva tu imagen personalizada con el módulo DNS que ya utilices.

> La directiva `admin 0.0.0.0:2019` es segura únicamente si el puerto 2019 no se publica y la red `caddy-admin` permanece privada.

### 2. Configura Caddy Control

```bash
git clone https://github.com/wolfverinehim/Caddy-Control.git
cd Caddy-Control
cp .env.example .env

docker build -t caddy-control:local .
docker run --rm -it caddy-control:local python -m app.password
openssl rand -hex 32
```

Copia ambos resultados en `.env`. Para permitir acceso únicamente desde la LAN, indica la IP privada de tu servidor:

```dotenv
CADDY_CONTROL_BIND=192.168.1.10
CADDY_CONFIG_DIR=/srv/caddy
CADDY_CONTROL_DATA_DIR=./data
```

### 3. Arranca el panel

```bash
docker compose up -d --build
docker compose ps
```

Abre `http://IP_DEL_SERVIDOR:8090`. El servicio se puede publicar posteriormente detrás del propio Caddy; en ese caso usa HTTPS y `COOKIE_SECURE=true`.

## Crear la ruta de Plex

En **Nueva ruta**, introduce:

| Campo | Valor |
|---|---|
| Identificador | `plex` |
| Nombre | `Plex` |
| Dominio | `plex.home.example.com` |
| Protocolo | `http` |
| Destino | `192.168.1.20` |
| Puerto | `32400` |

En Windows, permite el acceso desde la Raspberry Pi ejecutando PowerShell **como administrador**:

```powershell
New-NetFirewallRule `
  -DisplayName "Plex desde Caddy Raspberry" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 32400 `
  -RemoteAddress 192.168.1.10
```

## Variables

| Variable | Uso | Valor predeterminado |
|---|---|---|
| `ADMIN_USERNAME` | Usuario del panel | `admin` |
| `ADMIN_PASSWORD_HASH` | Hash PBKDF2-SHA256 con sal | obligatorio |
| `SESSION_SECRET` | Firma de sesiones, mínimo 32 caracteres | obligatorio |
| `CADDY_API_URL` | API privada de Caddy | `http://caddy:2019` |
| `CADDYFILE_PATH` | Caddyfile compartido | `/config/Caddyfile` |
| `SITES_DIR` | Fragmentos gestionados | `/config/sites.d` |
| `BACKUP_DIR` | Últimas 20 copias | `/data/backups` |
| `AUDIT_PATH` | Registro de operaciones | `/data/audit.jsonl` |
| `COOKIE_SECURE` | Cookie solo HTTPS | `false` |

El directorio indicado en `CADDY_CONTROL_DATA_DIR` debe pertenecer al UID/GID `1000`, utilizado por el contenedor sin privilegios.

## Desarrollo y pruebas

No hay dependencias Python externas:

```bash
python -m unittest discover -s tests -v
python -m compileall -q app
```

## Límites del MVP

- Gestiona rutas simples HTTP/HTTPS importadas dentro de un bloque wildcard.
- Las rutas existentes fuera de `sites.d` se muestran como inventario de solo lectura para evitar reescribir configuraciones manuales.
- No edita directivas arbitrarias ni el bloque TLS principal.
- El historial se conserva como copias en disco; todavía no tiene restauración visual.
- La autenticación es local; todavía no incorpora usuarios múltiples ni SSO/OIDC.

## Licencia

MIT. Consulta [LICENSE](LICENSE).

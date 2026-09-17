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

El contenedor utiliza dos redes con finalidades diferentes:

- `caddy-admin`: red interna compartida exclusivamente con Caddy para acceder a su API y a los servicios por nombre Docker.
- `caddy-control-lan`: red bridge normal que permite publicar temporalmente el panel en el puerto `8090` de la LAN.

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

La salida de `docker ps` debe mostrar una publicación similar a `192.168.1.10:8090->8080/tcp`. Si solo aparece `8080/tcp`, comprueba que el servicio está conectado tanto a `caddy-admin` como a `caddy-control-lan`.

## Publicar el propio panel detrás de Caddy

Una vez que Caddy Control está operativo, puede crear su propia ruta. Como Caddy y el panel comparten `caddy-admin`, utiliza el nombre Docker del servicio y no la IP o el puerto publicado del host:

| Campo | Valor de ejemplo |
|---|---|
| Identificador | `caddy-control` |
| Nombre | `Caddy Control` |
| Dominio | `caddy-control.home.example.com` |
| Protocolo | `http` |
| Destino | `caddy-control` |
| Puerto | `8080` |

Añade también una reescritura en el DNS interno para que el dominio resuelva hacia la dirección LAN de Caddy. Después de verificar el acceso por HTTPS, configura `COOKIE_SECURE=true` y reconstruye el contenedor.

El campo **Destino** acepta solamente un nombre de host o una dirección IP. No introduzcas `http://`, `https://`, barras finales ni un puerto dentro de ese campo.

## Rutas gestionadas y rutas detectadas

El panel separa dos orígenes:

- **Rutas gestionadas**: fragmentos con metadatos creados en `sites.d`; se pueden editar y eliminar desde la interfaz.
- **Configuración activa de Caddy**: rutas `reverse_proxy` leídas de la API administrativa. Las rutas creadas manualmente se muestran como solo lectura para evitar reescribir accidentalmente el `Caddyfile` principal.

El contador de rutas activas representa destinos detectados. Una ruta con varios upstreams puede generar más de una entrada.

## Acceso desde una VPN

Para administrar el panel mediante WireGuard:

1. El cliente debe poder alcanzar la LAN del servidor.
2. El DNS entregado por WireGuard debe resolver el dominio interno hacia Caddy.
3. Solo es necesario publicar HTTPS de Caddy dentro de la LAN/VPN; la API `2019` nunca debe publicarse.
4. Si el dominio también resuelve públicamente, limita el acceso por IP de origen o mediante una política de autenticación adicional. La autenticación local del panel no sustituye el aislamiento de red.

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

## Diagnóstico

### El puerto 8090 no está publicado

Comprueba las redes y los puertos activos:

```bash
docker inspect caddy-control --format \
'ModoRed={{.HostConfig.NetworkMode}} Puertos={{json .NetworkSettings.Ports}}'
docker port caddy-control
```

Una red creada con `--internal` no debe ser la única red del contenedor que publica el panel. Mantén `caddy-admin` para la API privada y `caddy-control-lan` para el acceso LAN.

### Caddy responde unknown field result

Las versiones actuales de Caddy devuelven `/adapt` con los campos `result` y `warnings`; `/load` acepta únicamente el contenido de `result`. Este caso está corregido desde el commit `55da560`. Actualiza y reconstruye:

```bash
git pull
docker compose up -d --build --force-recreate
```

### La ruta no aparece después de aplicarla

Si Caddy rechaza la carga, Caddy Control restaura la configuración anterior y elimina el fragmento nuevo. Consulta el mensaje mostrado por el panel y los registros:

```bash
docker logs caddy-control --tail 100
docker logs caddy --since 10m --tail 100
docker exec caddy caddy validate --config /etc/caddy/Caddyfile
```

## Licencia

MIT. Consulta [LICENSE](LICENSE).

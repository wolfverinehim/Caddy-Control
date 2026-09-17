# Seguridad

## Recomendaciones de despliegue

- No publiques el puerto administrativo `2019` de Caddy.
- Usa una red Docker interna compartida exclusivamente por Caddy y Caddy Control.
- No montes `/var/run/docker.sock` en el panel.
- Limita el puerto `8090` a la IP LAN del servidor o publica el panel detrás de HTTPS.
- Usa una contraseña única, un `SESSION_SECRET` aleatorio y `COOKIE_SECURE=true` bajo HTTPS.
- Protege los permisos del directorio que contiene `.env`, el Caddyfile, las copias y la auditoría.

## Informar de un problema

No publiques vulnerabilidades explotables en un issue. Utiliza un aviso privado de seguridad del repositorio de GitHub e incluye versión, impacto y pasos mínimos de reproducción.

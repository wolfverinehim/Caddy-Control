FROM python:3.13-alpine AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/caddy-control
RUN addgroup -g 1000 caddy-control && adduser -D -u 1000 -G caddy-control caddy-control

COPY --chown=caddy-control:caddy-control app ./app
USER caddy-control
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)" || exit 1

CMD ["python", "-m", "app"]
